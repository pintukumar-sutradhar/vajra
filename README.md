<div align="center">

```
    ██╗   ██╗ █████╗      ██╗██████╗  █████╗
    ██║   ██║██╔══██╗     ██║██╔══██╗██╔══██╗
    ██║   ██║███████║ ██  ██║██████╔╝███████║
    ╚██╗ ██╔╝██╔══██║ ╚██╗██╔╝██╔══██╗██╔══██║
     ╚████╔╝ ██║  ██║  ╚███╔╝ ██║  ██║██║  ██║
      ╚═══╝  ╚═╝  ╚═╝   ╚══╝  ╚═╝  ╚═╝╚═╝  ╚═╝
```

# ⚡ V A J R A

### Automated Penetration Testing Framework

`recon` · `network` · `web` · `exploitation` · `post-exploitation`

![platform](https://img.shields.io/badge/platform-Linux-blue)
![python](https://img.shields.io/badge/python-3.9%2B-informational)
![deps](https://img.shields.io/badge/core%20deps-zero-success)
![ports](https://img.shields.io/badge/sweep-65535%20ports-critical)
![payloads](https://img.shields.io/badge/payloads-3.8k-orange)

</div>

---

> ⚠️ **Authorized use only.** VAJRA is a professional security assessment
> tool. Running it against systems you do not own or lack written permission
> to test is illegal. An authorization gate is enforced on every run.

---

## Highlights

- **Full-spectrum network testing** — asynchronous sweep of all 65,535 TCP
  ports with raw-SYN mode, deep binary handshakes (MySQL, MSSQL, SMB2, RDP,
  VNC, PostgreSQL, MongoDB, Redis, memcached, LDAP, SMTP), TLS certificate
  auditing and optional UDP probes.
- **Adaptive web attack engine** — 3,800+ payloads across 16 injection
  classes; when a WAF blocks the standard arsenal, fingerprint-specific
  mutation chains (and optionally a local LLM) generate evasions until the
  objective is met.
- **Real exploitation, not just detection** — UNION-based SQL injection data
  extraction, live command-execution channels with reverse-session support,
  JWT forgery, SQLi auth bypass, credential spraying, default-credential
  attacks against 20+ platforms.
- **Post-exploitation** — system situational awareness through established
  channels, including automated privilege-escalation path analysis.
- **Intelligence built in** — offline banner→CVE correlation across 133
  products, an intel knowledge base (`intel/`: ports · services · default
  creds · login surfaces · leak paths · cloud · os), MITRE ATT&CK tagging on
  every finding, risk scoring with letter grades, and an AI campaign planner
  (opt-in).
- **Workspaces & retest deltas** — every run is snapshotted (auto per-target,
  or `--workspace NAME`). Re-running a target surfaces a **new / fixed /
  still-open** delta vs the previous snapshot, logs a running
  **`workspace_report.md`**
  narrative, and lets you export or import findings as JSON for collaboration.
- **Pivoting & multi-hop egress** — SOCKS5 and HTTP CONNECT hop chains
  (`tools/pivot.py`, `--socks5`, `rawhttp --connect-proxy`); local SOCKS5
  pivot servers, reverse/direct tunnels, and chain probing between segments.
- **Command & control** — standalone multi-session listener with **staged
  payloads**, TLS stagers, payload obfuscation, file exfil/upload markers and
  per-session transcripts.
- **AD privileged depth** — beyond hashes: a self-relative **DACL parser**
  (BloodHound-lite) flags WRITE_DAC/WRITE_OWNER/GENERIC_ALL grants and
  dangerous trustees (Everyone, Anonymous, Domain Users…), plus golden /
  silver-ticket forge playbooks.
- **Post-exploitation loot survey** — over SSH/every established channel,
  breadcrumb hunting for private keys, cloud creds, kube configs, netrc /
  history and password-adjacent notes (read-only, never downloads).
- **Compliance & synthesis in reports** — findings map to **CIS / NIST CSF /
  PCI DSS** controls with a prioritized remediation playbook, an auto-written
  executive narrative, and cross-host campaign ("spread") correlation.
- **Operator toolkit** — `tools/` ships 11 standalone stdlib utilities
  (soft-404-aware fuzzer, offline CVE lookups, hash forensics, DNS recon,
  raw HTTP, PoC generator, tooling matrix — see `docs/TOOLKIT.md`) plus
  `examples/` for mission playbooks.
- **Zero-mandatory-dependency core** — pure standard library operation;
  optional accelerators install cleanly.

---

## Installation

```bash
git clone https://github.com/<you>/vajra.git && cd vajra
./setup.sh                     # deps + wordlists + QA suite
python3 vajra.py --selftest    # 37-point verification
```

Runs on stock Python ≥ 3.9. Optional extras (`requests`, `paramiko`,
`scapy`, `dnspython`, `ollama`) are listed in `requirements.txt`; every one
has a stdlib fallback.

---

## Usage

```bash
python3 vajra.py -t <target> [options]
```

| Example | What it does |
|---|---|
| `vajra -t 10.10.10.5 --profile full --aggressive --yes` | complete engagement: all ports, deep tiers, active exploitation |
| `vajra -t https://app.local --yes` | fast application triage |
| `vajra -t 192.168.1.0/24 --udp --syn --yes` | subnet discovery incl. raw SYN + UDP |
| `vajra -t @targets.txt --profile stealth --yes` | low-and-slow batch |
| `vajra -t http://app.local --proxy http://127.0.0.1:8080 --yes` | through Burp |
| `vajra -t 10.0.0.5 --socks5 127.0.0.1:9050 --yes` | egress via SOCKS5 (Tor etc.) |
| `vajra -t https://app.local --workspace app1 --yes` | named workspace for retest deltas |
| `vajra --export-findings findings.json -t 10.0.0.5 --yes` | export merged workspace findings |
| `vajra --import-findings findings.json -t 10.0.0.5 --yes` | import findings → full reports |
| `vajra --listener` | standalone multi-session handler |

Targets: IP · CIDR · URL · comma list · `@file`.

Reverse stages (`--aggressive`) request your callback endpoint interactively
at the moment they're needed — pre-fill via `--lhost <ip> --lport <n>` to skip
the prompt.

---

## Profiles

| | ports | wordlists | mutation budget | notes |
|---|---|---|---|---|
| `quick` *(default)* | top-100 | fast tier | 60 / 10 | triage |
| `full` | all 65535 | **complete tiers** | 160 / 28 | time-based blind SQLi |
| `vast` | all 65535 + UDP | **complete tiers** | 320 / 48 | maximum coverage: 400-page crawl, heightened concurrency |
| `stealth` | top-100 | fast | reduced | delays + UA rotation |
| `webonly` | context | fast | standard | application-focused |
| `recon` | top-100 | – | – | intelligence only |

---

## Modules

**Recon** — DNS records (+ **AXFR zone-transfer attempt** from authoritative
NS via dig or raw DNS-over-TCP) · WHOIS (raw protocol fallback) · subdomain
enum · email harvest

**Network** — async/SYN port scanner · service & version detection · deep
handshake probes · LDAP rootDSE · **SMTP audit** (open-relay envelope check
without sending mail + VRFY/EXPN user enumeration) · **SMB/NFS share
enumeration** (read-only nmap `smb-enum-shares` / `smbclient -L` /
`showmount -e`, risky NFS-export flagging; pure-stdlib anonymous SMBv1 RAP
NetShareEnum fallback when no SMB tooling is installed — never writes,
read-only level-1 walk) · **SNMPv1 community sweep** (pure BER GET for
sysDescr/sysName/sysUpTime against a closed wordlist, triggered by a live
161/udp response, read-only — no SETs) · OS fingerprint ·
UDP probes (DNS CHAOS / NTP / SNMP) · FTP/SSH/HTTP brute-force ·
**data-driven unauth-exposure sweeps** covering no-auth Redis, raw Docker API
+ Docker Swarm, Memcached stats, Elasticsearch / InfluxDB / CouchDB without
auth, ZooKeeper / Consul / etcd open, Kafka, k8s/kubelet consoles, SMTP
banner leaks (probes catalogued in `intel/services.json`)

**Active Directory** — compact SMB exploitation folds SMBv1 dialect +
MS17-010 (EternalBlue) verdict + NTLM challenge fingerprint + pass-the-hash
auth check into one module gated on port 445. Kerberos runs an unauthenticated
pass (KDC user enum + AS-REP roasting) and, with any supplied credentials, an
authenticated pass (real kerberoasting via impacket → hashcat -m 13100).
LDAP mining is dual-pass too: anonymous enumeration always, then a deeper
authenticated pass (adminCount / delegation / no-preauth / computers /
forest trusts) whose LDAP bind result is reported explicitly.

Active chain (`--aggressive` + `--ad-user/--ad-pass/--nthash`): credential
verification unlocks **lateral movement** — an impacket psexec → wmiexec →
smbexec → atexec command-execution channel on the target that makes
post-exploitation genuinely reachable — plus **privilege-scalation ops**:
SYSVOL/GPP `cpassword` theft, an nmap ZeroLogon verdict, DC-Sync NTDS NTLM
dump (hashcat -m 1000, golden-ticket guidance) and a **bounded offline
hashcat crack** of every dumped hash set, reporting recovered plaintext
credentials back into findings. NTLM-relay resources (impacket-ntlmrelayx)
and potato/RDP/delegation hints are dropped for operator run. All of it is
step-and-gated — nothing executes without a prior verified signal.

`ad.power` (when a DC's LDAP reach is confirmed) dives one layer deeper:
it pulls raw `nTSecurityDescriptor` blobs for computers, users and groups,
parses each **self-relative DACL**, and flags dangerous grants — WRITE_DAC /
WRITE_OWNER / GENERIC_ALL / control-access masks, and risky trustees
(Everyone, Anonymous, Authenticated Users, Domain Users) plus their
discovered object. It never touches ACLs; with NTDS hashes already in state
(from DC-Sync) it emits the exact golden / silver-ticket `ticketer` +
`secretsdump` command lines instead of inventing delegation (`--aggressive`
required).

**Web** — crawler (robots + sitemap.xml aware) · dirbuster (soft-404 aware) ·
login-form auth (auto-discovers the form — driven by the `intel/login_surfaces`
candidate list — handles CSRF + session-cookie
adoption, and drives the whole crawl authenticated — see `--web-*` flags) ·
injection suite routed per parameter/body kind — **form, query, JSON and XML
bodies** — covering XSS · SQLi (error-based + **boolean/time-blind
differential**) · LFI · command injection · **blind RCE via OOB callback** ·
SSTI · NoSQL · **XXE whole-body** · LDAP/XPath · HTTP parameter pollution ·
open redirect · CRLF/header injection · **Host-header / web-cache poisoning** ·
stored-XSS deposit sweep · **API surface** (OpenAPI/Swagger discovery,
endpoint inventory, **unauthenticated + base-ID authz sweep catching
BOLA/IDOR and token-less CSRF surfaces**, JWKS algorithm-confusion +
`alg:none`, OAuth/OIDC metadata audit) · **blind SSRF + cloud metadata
(OOB-confirmed)** — and **`web.ssrf_pivot`: once an SSRF is confirmed, it is
drilled into an internal loopback port scan** (latency + response-differential
heuristic, no exploitation) · **`web.race`: TOCTOU / race-condition checks** on
coupon/promo/transfer/0x registration surfaces (near-simultaneous POST bursts,
no burned transaction) · **domain-takeover probe** (raw DNS CNAME → dangling) ·
**rate-limit / account-lockout policy checks** (burn-user bursts) ·
**upload handling** (traversal / double-ext / null-byte / stored-marker
retrievability) · **wire tests** (WebSocket upgrade, CL.TE/TE.CL smuggling
signal, deserialization markers) · **cloud exposure** (read-only S3 / GCS /
Azure-Blob bucket listing probes from domain + subdomain candidates) · JWT
auditor · GraphQL prober · prototype pollution · WAF fingerprinting · tech
stack + version → **built-in CVE correlation** (or `--cve-update` for a live
CIRCL lookup when the offline KB misses) · security headers (+ full
CORS matrix, HSTS, cookie SameSite) · **TLS audit incl. cert expiry /
self-signed / SAN coverage** · DOM-XSS JS sink/source hunting · sitemap-consume
crawling · JS secret hunting

Blind detections (SSRF, RCE) use an embedded OOB callback listener — auto-on
in `full`/`vast`, or `--oob`.

A **sensitive-file checklist** (`web.loot`, driven by `intel/loot_paths.json`)
sweeps classic leak locations — `.git/HEAD`+config, `.env*`, backup archives,
`phpinfo.php`, Spring actuator, admin panels — with marker-led heuristics and
soft-404 filtering so checked paths are not confused with template 404s.

**Exploitation** — SQLi extractor (columns → echo position → version/db/user/
tables) · execution-channel negotiation (unix/windows) · reverse sessions ·
full auth-bypass family (25 SQLi/comment/tautology/default pairs + OTP tricks:
drop, weak-code, injection) · login-form brute-force (aggressive-gated, caps +
delay, reveals leaks against OTP-protected forms) · **catalog-driven default
credentials** (basic-auth panels run read-only; form/service default-cred
tries gated behind `--aggressive`; `intel/creds_default.json` covers Tomcat,
JBoss, WebLogic, WildFly, Jenkins, Grafana, routers, cameras, DBs…) ·
password spray · CVE exposure probes

**Post** — identity/kernel/network/logins/accounts/sudo/SUID/cron/env/SSH
material/container hints + privesc candidate analysis — runs against every
established channel: injected RCE channels, impacket lateral channels and
reverse sessions.

`post.loot` adds a read-only high-value file survey over any SSH session
(paramiko with discovered creds): private keys, cloud provider creds, kube
configs, netrc / shell history / docker config and password-adjacent notes —
reports what is *present and readable* without downloading or modifying
anything; without an SSH transport or creds it logs an info finding instead
of pretending.

---

## Adaptive evasion

```
direct ──blocked?──► fingerprint guard (Cloudflare · Akamai · Imperva ·
                                          ModSec · AWS WAF · F5 · Sucuri…)
        ▲                          │
        │            escalate operator chains: inline-comments · case-swap
        │            double-encode · utf8-overlong · null-byte · HPP …
        └──── mutant achieves motive? ──► logged per attempt (--ai adds
                                          model-crafted variants)
```

---

## Intelligence

- **CVE knowledge base** — 133 products / 183 operator-parsed version ranges
  matched directly against harvested banners (Heartbleed → Log4Shell,
  EternalBlue, ProxyLogon, BIG-IP TMUI, FortiOS, vCenter, Confluence OGNL…).
- **MITRE ATT&CK** — every finding auto-tagged with technique IDs.
- **Campaign planner** — mid-run next-best-action list combining rule-based
  logic with findings context.
- **Optional AI brain** — add `--ai` to involve a local Ollama + **Qwen3 8B**
  (auto-installs; fully offline once pulled). Use `--ai-select` to hand the
  mission to the operator-agent: Qwen3 inspects each target's live state
  (ports, services, web targets, findings) and picks and executes the best
  next action from a closed tool set — deeper port probes, re-running
  modules, path fuzzing, PoC crafting, brute force and exploit routing.
  Exploration is always safe; exploitation stays behind `--aggressive`;
  every step is logged to `evidence/ai_mission_log.md`.

---

## Toolkit & knowledge base

`tools/` (stdlib-only, runnable standalone — see `docs/TOOLKIT.md`):
`netkit` (async port scan + risk table) · `fuzzurl` (soft-404-aware fuzzer) ·
`cve` (offline CVE lookup) · `hashid` · `listener` (reverse-session handler;
`--staged/--tls/--obfuscate`) · `dnsrecon` (raw-DNS recon + subdomains) ·
`pivot` (SOCKS5 servers, reverse/direct tunnels, hop-chain probing) ·
`envcheck` (read-only tooling
matrix vs `config/tooling.json`) · `pocgen` (inert PoC evidence templates) ·
`rawhttp` (raw request builder + `--connect-proxy`) ·
`wordlists` (inspect/filter/merge).

`intel/` data drives module behavior: `ports.json` (476 ports + risk notes) ·
`services.json` (probe catalog for `network.service_exposure`) ·
`creds_default.json` (default-credential catalog for `exploit.creds`) ·
`login_surfaces.json` (crawler + policy routing) · `loot_paths.json`
(`web.loot`) · `os.json` · `cloud.json` · `community_strings.json` (wordlist
for the SNMPv1 sweep) · plus `cve_db.json` and `signatures.json`.

`examples/` contains a command cheat-sheet, an end-to-end pentest scenario
playbook and a runtime `example_config.json`.

---

## Wordlists

Deterministically forged (~303k entries, regenerate:
`python3 tools/gen_wordlists.py`):

| Tier | users | passwords | dirs | subs |
|---|---|---|---|---|
| fast (always) | 600 | 2,500 | 1,200 | 1,500 |
| **complete** (`full`/`--aggressive`) | 115,000 | 148,000 | 16,000 | 18,193 |

---

## Output

Results land in `Outputs/<run>/<target>/` — reports (HTML dashboard, JSON,
Markdown, **PDF** — clean stdlib PDF writer, paginated + per-severity colour),
SQLite store, full transcript log and an `evidence/` folder of
raw proof dumps per target, plus a run-wide `summary.json`.

Each report now carries the full narrative stack: an auto-written **executive
synthesis** (attack surface, priority signal, exposed web tier), a
**compliance remediation playbook** (every finding cross-referenced to CIS
Benchmark / NIST CSF / PCI DSS 4.0, grouped by severity), a **retest delta**
`vs` the previous workspace snapshot, and cross-host campaign ("spread")
patterns. Workspaces live under `Outputs/workspaces/<target>/` (or your
`--workspace` name) — latest snapshot, run history, per-target state and a
running `workspace_report.md`.

## Workspaces, retests & collaboration

- Snapshots are taken automatically at run end. Re-running the same target
  produces a delta report (new / fixed / still-open) so an engagement's
  progress is trackable across sessions.
- If you kill a running scan, the workspace snapshot + reports for whatever
  was found are still persisted for already-reported targets, and the run
  summary is written.
- `--export-findings FILE -t <target>` merges every finding across that
  target's snapshots into one JSON file (finding fields, import-safe).
- `--import-findings FILE -t <target>` ingests findings from a peer/JSON
  export and renders complete reports (HTML/JSON/MD) without re-scanning —
  handy for merging results from another operator or an earlier engagement.

## Pivoting & egress

- `--socks5 HOST:PORT` routes web + raw probes through a SOCKS5 proxy;
  `--proxy URL` does the same for plain HTTP.
- `tools/rawhttp.py --connect-proxy HOST:PORT` walks an HTTP CONNECT
  tunnel for arbitrary raw requests.
- `tools/pivot.py` (stdlib) gives you a full pivot toolbox: local SOCKS5
  servers, reverse/direct tunnels between segments, multi-hop chain probing
  (`socks5://…,http://…`), and a `--probe` mode to validate reachability
  hop by hop. Chain resolution shares the same engine the framework itself
  uses.

## Command & control

`tools/listener.py` / `--listener` is a standalone handler for reverse
sessions: interactive shells, `getfile` / `upload` file transfer commands,
multi-session selection, and **staged payloads** (`--staged`) that shrink the
initial connect payload to a bootstrap that pulls the full stage over the
socket, with TLS stagers (`--tls`) and `--obfuscate` (packed payloads) —
`python3 -c "…"` one-liners you can paste directly.

---

## CLI reference

```text
-t, --target          IP | CIDR | URL | comma list | @file
-p, --ports           80 | 22-1000 | top100 | top1000 | extended | all
    --profile         quick | full | vast | stealth | webonly | recon
    --aggressive      deep tiers + intrusive exploitation + reverse stages
    --lhost/--lport   pre-set callback endpoint for reverse stages
    --listener        standalone multi-session handler
    --ai              enable local Ollama+Qwen3 8B brain (opt-in)
    --ai-select       mission mode: Qwen3 picks next actions per target
    --udp             UDP service probes (DNS/NTP/SNMP)
    --syn             raw SYN scanning (root)
    --no-brute        disable credential attacks
    --ad-user/--ad-pass/--nthash   AD creds → authenticated LDAP + real kerberoasting
    --web-user/--web-pass   webapp creds → AUTHENTICATED crawl/scan of the app
    --web-login       explicit login URL (form is auto-discovered otherwise)
    --web-otp         static OTP code for the login flow
    --web-totp-secret base32 TOTP secret — RFC 6238 code generated at login
    --import-findings FILE   import findings from JSON file and generate reports
    --export-findings FILE   export findings from workspace to JSON file
-o, --output          output root (default: Outputs/)
    --workspace       name the workspace (default: auto per-target)
    --format          html | json | md | pdf | all
    --socks5 HOST:PORT  egress via a SOCKS5 proxy (web + raw probes route through)
    --cve-update      when the offline KB misses a product:version, query the
                       live CIRCL CVE API (cached in intel/cve_online_cache.json)
    --modules         run only listed modules
    --exclude-modules skip listed modules
    --proxy           HTTP proxy
    --oob             run an OOB HTTP callback listener for blind detections
    --oob-port PORT   fixed local port for the OOB listener (default: ephemeral)
-v/-vv                verbose / trace
    --selftest        internal QA suite
```

## AI-select mission mode

When you add `--ai --ai-select`, VAJRA hands each target to the operator-agent
after the normal phases complete. Qwen3 8B receives a live snapshot — open
ports, banners, web targets, API endpoint count, current findings, whether
exploitation is armed — **plus the full module catalog** so it can pick any
capability by id. It returns one JSON action from a closed tool set:

`scan_more` (extra TCP probes) · `run_module` (any module id) · `web_fuzz`
(path hunting; keeps the primary target so sensitive-path checks still run) ·
`craft_exploit` (PoC generation, saved to evidence) · `exploit` (routes routed
to the matching exploit path) · `brute` (credential attacks) · `ad_chain`
(validated-credential AD movement + DC-Sync / GPP / crack sequence) · `assess`
(narrative) · `done` (stop).

The free-text fallback understands intent keywords (ssrf, xxe, jwt, api,
idos, buckets, takeover, rate-limit, smuggling, ssti, upload …) and routes
them to the matching module — so brief directives are enough. Read-only
triage (CVE exposure probes) is not gated behind `--aggressive`.

Everything is executed by the framework's own safe adapters — model text is
never run as code. Exploit/brute/intrusive actions require `--aggressive`;
without it, the agent produces verified read-only plans and reviewable PoCs.
Like the MS17-010 decision earlier in this project, agency stays observable:
each step's rationale, arguments and result land in
`evidence/ai_mission_log.md`, and a fetched reverse session is only delivered
through the existing gated listener.

## Authenticated web scans

Pass `--web-user USER --web-pass PASS` (optionally `--web-login URL`, `--web-otp
CODE` or `--web-totp-secret B32SECRET`) and `web.auth_login` runs *before* the
crawler: it auto-discovers the login form (or uses your explicit URL), pulls a
CSRF token, supplies the OTP/TOTP along with credentials, adopts the returned
session cookie into the HTTP client, and only then hands the site to the crawl
and module stack — so every module (dirbuster, injections, JWT, SSRF…) exercises
the authenticated surface. Without credentials, the site is scanned
unauthenticated and the exploit layer still attacks whatever auth systems it
finds: the full 25-pair auth-bypass family plus OTP tricks and aggressive-gated
login brute-force (cap/delay/stop-on-success) that also reports leaks against
OTP-protected forms.

---

## FAQ

**Web-only?** No — network services are first-class: full sweeps, binary
handshakes, relay checks, credential attacks across protocols.

**Root required?** No; connect scans work unprivileged. `--syn` needs root.

**Is the AI mandatory?** No — fully off unless you pass `--ai`. Everything
else works without it.

**Slow with big wordlists?** Complete tiers only engage under
`full`/`vast`/`--aggressive`, HTTP attacks are threaded with stop-on-success.

---

<div align="center">

**Validate every finding before acting. Own everything you test.** ⚡

</div>
