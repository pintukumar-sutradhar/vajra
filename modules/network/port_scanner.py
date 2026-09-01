"""Vajra - high-performance asynchronous TCP connect port scanner.

For very large port sets (full 65535 sweeps) and when a fast external
scanner is installed, the scan is delegated to masscan (or nmap) so a
full-range sweep completes orders of magnitude faster; otherwise the native
async connect scanner is used."""
import asyncio
import os
import re
import shutil
import subprocess
import tempfile
import time

from core.database import Finding
from core.utils import parse_ports


def _has_external():
    for bin_ in ("masscan", "nmap"):
        if shutil.which(bin_):
            return True
    return False


def _masscan_scan(host, ports, timeout=4.0):
    """Delegate a full-range sweep to masscan for raw speed. Returns
    {port: latency_ms}. masscan must be run as root for raw SYN."""
    if not shutil.which("masscan"):
        return None
    with tempfile.NamedTemporaryFile("w", suffix=".txt") as fw:
        fw.write(",".join(str(p) for p in ports))
        fw.flush()
        outfile = fw.name + ".out"
        try:
            subprocess.run(
                ["masscan", host, "-p", ",".join(str(p) for p in ports),
                 "--rate", "10000", "--wait", "3", "-oG", outfile],
                timeout=max(timeout, 8), capture_output=True)
        except Exception:
            return None
        results = {}
        try:
            with open(outfile) as f:
                for line in f:
                    m = re.search(r"Host: \S+ \(\)\s+Ports: (\d+)/open", line)
                    if not m:
                        m = re.search(r"(\d+)/open/tcp", line)
                    if m:
                        results[int(m.group(1))] = 1.0
        except Exception:
            return None
        return dict(sorted(results.items()))


def _nmap_scan(host, ports, timeout=4.0):
    """Delegate to nmap -sT (fast parallel connect) for large sets. Returns
    {port: latency_ms} from XML output."""
    if not shutil.which("nmap"):
        return None
    with tempfile.NamedTemporaryFile("w", suffix=".xml") as fw:
        outfile = fw.name + ".xml"
        try:
            subprocess.run(
                ["nmap", "-sT", "-Pn", "--min-rate", "2000",
                 "-p", ",".join(str(p) for p in ports),
                 "-oX", outfile, host],
                timeout=max(timeout, 15), capture_output=True)
        except Exception:
            return None
        results = {}
        try:
            text = open(outfile).read()
            for m in re.finditer(r'portid="(\d+)"[^>]*state="open"', text):
                results[int(m.group(1))] = 1.0
        except Exception:
            return None
        return dict(sorted(results.items()))


def _scan_external(host, ports, timeout, use_syn):
    """Prefer masscan for a full-range SYN-style sweep; fall back to nmap
    connect for very large sets when the native scanner would be slow."""
    if use_syn and shutil.which("masscan"):
        return _masscan_scan(host, ports, timeout)
    if shutil.which("nmap") and len(ports) >= 20000:
        return _nmap_scan(host, ports, timeout)
    return None



async def _probe(ip, port, timeout, sem):
    t0 = time.time()
    try:
        async with sem:
            fut = asyncio.open_connection(ip, port)
            reader, writer = await asyncio.wait_for(fut, timeout=timeout)
            latency = time.time() - t0
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass
            return port, round(latency * 1000.0, 1)
    except Exception:
        return None


async def scan_host(ip, ports, timeout=2.5, concurrency=600, progress=None):
    sem = asyncio.Semaphore(concurrency)
    tasks = [_probe(ip, p, timeout, sem) for p in ports]
    open_ports = {}
    done = 0
    total = len(tasks)
    for coro in asyncio.as_completed(tasks):
        res = await coro
        done += 1
        if progress and (done % max(1, total // 10) == 0 or done == total):
            progress(done, total)
        if res:
            open_ports[res[0]] = res[1]
    return dict(sorted(open_ports.items()))


def _syn_scan(host, ports, timeout=2.0):
    """Root-only raw SYN sweep via scapy. Returns {port: latency_ms}."""
    from scapy.all import IP, TCP, sr1, conf
    conf.verb = 0
    results = {}
    chunk = 512
    for i in range(0, len(ports), chunk):
        batch = ports[i:i + chunk]
        for p in batch:
            t0 = time.time()
            pkt = sr1(IP(dst=host) / TCP(flags="S", dport=p),
                      timeout=timeout, verbose=0)
            if pkt is None:
                continue
            flags = int(pkt[TCP].flags) if pkt.haslayer(TCP) else 0
            if flags & 0x12:
                rst = sr1(IP(dst=host) / TCP(flags="R",
                                             dport=p, seq=pkt[TCP].ack + 1),
                          timeout=0.5, verbose=0)
                del rst
                results[p] = round((time.time() - t0) * 1000.0, 1)
    return results


def run(engine):
    t = engine.target
    host = t.scan_host()
    use_syn = getattr(engine.args, "syn", False)
    if use_syn and not hasattr(os, "geteuid"):
        use_syn = False
    if use_syn and os.geteuid() != 0:
        engine.log.warn("--syn needs root; falling back to connect scan")
        use_syn = False
    if use_syn:
        try:
            import scapy  # noqa
        except Exception:
            engine.log.warn("--syn requested but scapy missing "
                            "(pip install scapy); connect scan used")
            use_syn = False
    spec = engine.args.ports or engine.profile_cfg("ports", "top100")
    if t.kind == "url" and t.port:
        base = parse_ports(spec)
        if t.port not in base:
            base.append(t.port)
            base.sort()
        ports = base
    else:
        ports = parse_ports(spec)
    engine.log.info("Scanning %s (%d ports, concurrency=%d) ..." %
                    (host, len(ports), engine.cfg("scan_concurrency", 600)))
    t0 = time.time()

    def progress(done, total):
        # Feed the single run-level meter: live sub-progress with a friendly
        # detail, so the bar % + ETA move as ports actually get scanned.
        engine.progress(done, total, detail="%d/%d ports" % (done, total))

    # Fast external delegation: a full-range sweep (or --syn with masscan)
    # completes far faster through the raw packet scanner than the native
    # async connect scanner when such tooling is installed.
    if use_syn or len(ports) >= 20000:
        ext = _scan_external(host, ports,
                             float(engine.cfg("scan_timeout", 2.0)), use_syn)
        if ext is not None:
            dur = time.time() - t0
            tool = "masscan" if shutil.which("masscan") else "nmap"
            engine.log.info("external scanner used (%s)" % tool)
            engine.state["open_ports"] = dict(sorted(ext.items()))
            engine.log.success("External port scan done in %.1fs: %d open "
                               "port(s) (%s)" % (dur, len(ext), tool))
            if not ext:
                engine.db.add_finding(Finding(
                    t.display, "network.portscan", "network", "info",
                    "No TCP ports responded from scanned set",
                    detail="Host may be filtered/down. Tool: external scanner.",
                    confidence="possible"))
            return
        if use_syn and shutil.which("masscan"):
            engine.log.warn("masscan delegation failed; falling back to "
                            "native scan")

    if use_syn:
        engine.log.info("SYN scan mode (%d ports, root)" % len(ports))
        result = _syn_scan(host, ports,
                           timeout=float(engine.cfg("scan_timeout", 2.0)))
        dur = time.time() - t0
        engine.progress(len(ports), len(ports),
                        detail="%d/%d ports" % (len(ports), len(ports)))
        engine.state["open_ports"] = dict(sorted(result.items()))
        engine.log.success("SYN scan done: %d open port(s)" % len(result))
        return
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        result = loop.run_until_complete(
            scan_host(host, ports,
                      timeout=float(engine.cfg("scan_timeout", 2.5)),
                      concurrency=int(engine.cfg("scan_concurrency", 600)),
                      progress=progress))
    except KeyboardInterrupt:
        raise
    finally:
        loop.close()
    engine.progress(len(ports), len(ports),
                    detail="%d/%d ports" % (len(ports), len(ports)))
    dur = time.time() - t0
    engine.state["open_ports"] = {p: l for p, l in result.items()}
    engine.log.success("Port scan finished in %.1fs: %d open port(s)%s" %
                       (dur, len(result),
                        " -> " + ",".join(str(p) for p in list(result)[:20]) if result else ""))
    if not result:
        engine.db.add_finding(Finding(
            t.display, "network.portscan", "network", "info",
            "No TCP ports responded from scanned set",
            detail="Host may be filtered/down or uses non-scanned ports. "
                   "Consider --profile full for all 65535 ports.",
            confidence="possible"))
