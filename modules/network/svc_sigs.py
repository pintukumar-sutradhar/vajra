"""VAJRA native service signature database — regex banner fingerprints used
to positively identify services when nmap is not available, mirroring the
top of nmap's service table (nmap-services) so detection stays accurate.

Each entry: (regex, service, product, version_capture). The regex is matched
against the concatenated banner + headers. version_capture is either an int
(group index) holding the version, or None."""
import re

SIGS = [
    # --- SSH ---
    (re.compile(r"SSH-2\.0-OpenSSH_([\d.]+p?\d*)", re.I), "ssh", "OpenSSH", 1),
    (re.compile(r"SSH-2\.0-SSH_([\d.]+)", re.I), "ssh", "Bitvise SSH", 1),
    (re.compile(r"SSH-2\.0-(dropbear_?[\d.]+)", re.I), "ssh", "Dropbear", 1),
    (re.compile(r"SSH-1\.99-OpenSSH", re.I), "ssh", "OpenSSH", None),
    (re.compile(r"SSH-", re.I), "ssh", None, None),

    # --- FTP ---
    (re.compile(r"(Pure-FTPd)[^\r\n]*\(?([\d.]+)?", re.I), "ftp", "Pure-FTPd", 2),
    (re.compile(r"(vsftpd)[ _]([\d.]+)", re.I), "ftp", "vsftpd", 2),
    (re.compile(r"(ProFTPD)[^\r\n]*([\d.]+)", re.I), "ftp", "ProFTPD", 2),
    (re.compile(r"(FileZilla Server)[^\r\n]*([\d.]+)", re.I), "ftp", "FileZilla", 2),
    (re.compile(r"(Microsoft FTP Service)", re.I), "ftp", "Microsoft FTP", None),
    (re.compile(r"Welcome to the (vs-FTPd)", re.I), "ftp", "vsftpd", None),
    (re.compile(r"220[- ]", re.I), "ftp", None, None),

    # --- SMTP ---
    (re.compile(r"(Postfix)", re.I), "smtp", "Postfix", None),
    (re.compile(r"(Exim)[^\s]*\s*([\d.]+)", re.I), "smtp", "Exim", 2),
    (re.compile(r"(Sendmail)", re.I), "smtp", "Sendmail", None),
    (re.compile(r"(Microsoft ESMTP MAIL Service)", re.I), "smtp", "MS Exchange SMTP", None),
    (re.compile(r"(hMailServer)", re.I), "smtp", "hMailServer", None),
    (re.compile(r"220[- ]", re.I), "smtp", None, None),

    # --- HTTP / web ---
    (re.compile(r"Server:\s*nginx/([\d.]+)", re.I), "http", "nginx", 1),
    (re.compile(r"Server:\s*Apache(?:/([\d.]+))?", re.I), "http", "Apache httpd", 1),
    (re.compile(r"Server:\s*Microsoft-IIS/([\d.]+)", re.I), "http", "Microsoft IIS", 1),
    (re.compile(r"Server:\s*(Caddy)", re.I), "http", "Caddy", None),
    (re.compile(r"Server:\s*(Apache-Coyote/[\d.]+)", re.I), "http", "Apache Tomcat", 1),
    (re.compile(r"Server:\s*(Werkzeug/[\d.]+)", re.I), "http", "Werkzeug", 1),
    (re.compile(r"Server:\s*(gunicorn/[\d.]+)", re.I), "http", "gunicorn", 1),
    (re.compile(r"Server:\s*(lighttpd/[\d.]+)", re.I), "http", "lighttpd", 1),
    (re.compile(r"Server:\s*(Jetty\([\d.]+)", re.I), "http", "Jetty", 1),
    (re.compile(r"Server:\s*(thttpd/[\d.]+)", re.I), "http", "thttpd", 1),
    (re.compile(r"Server:\s*(nginx)", re.I), "http", "nginx", None),
    (re.compile(r"Server:\s*(Apache)", re.I), "http", "Apache httpd", None),
    (re.compile(r"X-Powered-By:\s*PHP/([\d.]+)", re.I), "http", "PHP", 1),
    (re.compile(r"Set-Cookie:\s*PHPSESSID", re.I), "http", "PHP", None),
    (re.compile(r"(SimpleHTTP/[\d.]+)", re.I), "http", "Python http.server", 1),
    (re.compile(r"^HTTP/1\.[01]\s", re.I), "http", None, None),

    # --- TLS/HTTPS via cert is handled separately ---

    # --- Databases ---
    (re.compile(r"[\x00-\x7f]*MySQL[\x00]([\d.]+)", re.I), "mysql", "MySQL", 1),
    (re.compile(r"(MySQL)[\x00]", re.I), "mysql", "MySQL", None),
    (re.compile(r"(MariaDB)", re.I), "mysql", "MariaDB", None),
    (re.compile(r"(PostgreSQL) ([0-9.]+)", re.I), "postgresql", "PostgreSQL", 2),
    (re.compile(r"(PostgreSQL)", re.I), "postgresql", "PostgreSQL", None),
    (re.compile(r"(Redis server) v=([0-9.]+)", re.I), "redis", "Redis", 2),
    (re.compile(r"(redis_version)", re.I), "redis", "Redis", None),
    (re.compile(r"\$[0-9]+", re.I), "redis", "Redis", None),
    (re.compile(r"(MongoDB)", re.I), "mongodb", "MongoDB", None),
    (re.compile(r"(Memcached)", re.I), "memcached", "Memcached", None),
    (re.compile(r"(Elasticsearch)", re.I), "elasticsearch", "Elasticsearch", None),
    (re.compile(r"(Couchbase)", re.I), "couchbase", "Couchbase", None),
    (re.compile(r"(Cassandra)", re.I), "cassandra", "Cassandra", None),

    # --- Remote access / management ---
    (re.compile(r"^RFB [0-9.]+", re.I), "vnc", "VNC", None),
    (re.compile(r"(RealVNC)", re.I), "vnc", "RealVNC", None),
    (re.compile(r"(TightVNC)", re.I), "vnc", "TightVNC", None),
    (re.compile(r"(x11vnc)", re.I), "vnc", "x11vnc", None),
    (re.compile(r"Microsoft Terminal Services", re.I), "ms-wbt-server", "Microsoft RDP", None),
    (re.compile(r"^\.{4}", re.I), "msrpc", "MS RPC", None),
    (re.compile(r"(DCE RPC)", re.I), "msrpc", "MSRPC", None),

    # --- Directories / key-value ---
    (re.compile(r"(ZooKeeper)", re.I), "zookeeper", "Apache ZooKeeper", None),
    (re.compile(r"(RabbitMQ)", re.I), "amqp", "RabbitMQ", None),
    (re.compile(r"(Apache Kafka)", re.I), "kafka", "Apache Kafka", None),
    (re.compile(r"(MinIO)", re.I), "s3", "MinIO", None),
    (re.compile(r"(Ceph)", re.I), "ceph", "Ceph", None),
    (re.compile(r"(Docker)", re.I), "docker", "Docker", None),

    # --- Network / infra ---
    (re.compile(r"(OpenVPN)", re.I), "openvpn", "OpenVPN", None),
    (re.compile(r"(OpenAFS)", re.I), "afs", "OpenAFS", None),
    (re.compile(r"(Kerberos)", re.I), "kerberos", "Kerberos", None),
    (re.compile(r"(LDAP)", re.I), "ldap", "LDAP", None),
    (re.compile(r"(DNS)", re.I), "domain", "DNS", None),

    # --- Mail retrieval ---
    (re.compile(r"\* OK.*(IMAP)", re.I), "imap", "IMAP", None),
    (re.compile(r"(Dovecot)", re.I), "imap", "Dovecot", None),
    (re.compile(r"\+OK.*(POP3)", re.I), "pop3", "POP3", None),
    (re.compile(r"(Microsoft POP3 Service)", re.I), "pop3", "MS POP3", None),

    # --- Industrial / misc ---
    (re.compile(r"(Rockwell)", re.I), "industrial", "Rockwell", None),
    (re.compile(r"(Siemens)", re.I), "industrial", "Siemens", None),
]

# Deep-protocol ports (multi-step handshake is the only reliable way).
DEEP_PROBES = {
    3306: "MySQL greeting", 5900: "VNC handshake", 5432: "PostgreSQL",
    1433: "MSSQL prelogin", 27017: "MongoDB isMaster", 3379: None,
    6379: "Redis PING/INFO", 11211: "Memcached stats", 445: "SMB negotiate",
    139: "SMB/NetBIOS", 3389: "RDP X.224", 111: "RPC portmap",
    2181: "ZooKeeper", 61616: "ActiveMQ", 1883: "MQTT CONNECT",
    5672: "AMQP", 15672: "RabbitMQ mgmt", 9200: "Elasticsearch",
    2375: "Docker API", 2049: "NFS/RPC", 3128: "HTTP proxy",
}
