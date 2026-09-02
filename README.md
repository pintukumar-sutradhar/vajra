<div align="center">

<pre align="center">
    ██╗   ██╗ █████╗      ██╗██████╗  █████╗
    ██║   ██║██╔══██╗     ██║██╔══██╗██╔══██╗
    ██║   ██║███████║ ██  ██║██████╔╝███████║
    ╚██╗ ██╔╝██╔══██║ ╚██╗██╔╝██╔══██╗██╔══██║
     ╚████╔╝ ██║  ██║  ╚███╔╝ ██║  ██║██║  ██║
      ╚═══╝  ╚═╝  ╚═╝   ╚══╝  ╚═╝  ╚═╝╚═╝  ╚═╝
</pre>

# ⚡ V A J R A

### Automated Penetration Testing Framework

[![license](https://img.shields.io/badge/license-Custom-blue.svg)](LICENSE)

`recon` · `network` · `web` · `exploitation` · `post-exploitation`

![Python](https://img.shields.io/badge/Python-3.9%2B-2b7fbf)
![Core deps](https://img.shields.io/badge/Core%20deps-zero-success)
![License](https://img.shields.io/badge/License-All%20rights%20reserved-orange)
![Architecture](https://img.shields.io/badge/Architecture-modular-blue)

</div>

---

> ⚠️ **Authorized use only.** VAJRA is a professional security assessment
> tool. Running it against systems you do not own or lack written permission
> to test is illegal. An authorization gate is enforced on every run.

---

## Contents

- [About](#about)
- [Highlights](#highlights)
- [Installation](#installation)
- [Usage](#usage)
- [Profiles](#profiles)
- [Modules](#modules)
- [Adaptive evasion](#adaptive-evasion)
- [Intelligence](#intelligence)
- [Workspaces, retests & collaboration](#workspaces-retests--collaboration)
- [Pivoting & egress](#pivoting--egress)
- [Command & control](#command--control)
- [Output](#output)
- [Toolkit & knowledge base](#toolkit--knowledge-base)
- [Wordlists](#wordlists)
- [Live progress meter](#live-progress-meter)
- [CLI reference](#cli-reference)
 - [AI & model selection](#ai--model-selection)
 - [AI-select mission mode](#ai-select-mission-mode)
- [Authenticated web scans](#authenticated-web-scans)
- [FAQ](#faq)
- [License & author](#license--author)

---

## About

VAJRA is a self-contained penetration-testing framework that moves from
discovery to exploitation and remediation advice in a single run. It executes
cleanly on stock Python — no mandatory third-party dependencies — and pairs
classic technique catalogs with modern capabilities: adaptive WAF evasion, an
opt-in AI agent that plans and executes follow-up actions, and persistent
workspaces that turn every re-run into a measurable retest.

| Capability | Delivered by |
|---|---|
| **Discovery** | async / SYN port sweep · service & version fingerprinting · UDP probes · OS detection |
| **Web applications** | adaptive injection engine · WAF-aware mutation · authenticated crawling |
| **Exploitation** | SQLi extraction · RCE channels · JWT forgery · credential attacks · CVE exposure probes |
| **Active Directory** | Kerberos / LDAP mining · DACL analysis · DC-Sync · lateral movement |
| **Post-exploitation** | privilege-escalation path analysis · read-only loot survey over established channels |
| **Operations** | SOCKS5 / HTTP-CONNECT pivoting · staged & TLS C2 · workspaces with retest deltas |

---

## Highlights

- **Full-spectrum network testing** — asynchronous sweep of the full TCP port
  range with raw-SYN mode, deep binary handshakes (MySQL, MSSQL, SMB2, RDP,
  VNC, PostgreSQL, MongoDB, Redis, memcached, LDAP, SMTP), TLS certificate
  auditing and optional UDP probes.
- **Adaptive web attack engine** — 16 injection classes; when a WAF blocks
  the standard arsenal, fingerprint-specific mutation chains (and optionally
  a local LLM) generate evasions until the objective is met.
- **Real exploitation, not just detection** — UNION-based SQL injection data
  extraction, live command-execution channels with reverse-session support,
  JWT forgery, SQLi auth bypass, credential spraying, default-credential
  attacks against 20+ platforms.
- **Post-exploitation** — system situational awareness through established
  channels, including automated privilege-escalation path analysis.
- **Intelligence built in** — offline banner→CVE correlation across
  12,800+ packaged products (GitHub Advisory Database, built by
  `tools/build_cve_db.py`) plus an intel knowledge base (`intel/`: ports ·
  services · default creds · login surfaces · leak paths · cloud · os),
  MITRE ATT&CK tagging on
  every finding, numeric risk scoring (0–100), MITRE ATT&CK tagging on
  every finding, and an AI campaign planner
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
git clone https://github.com/pintukumar-sutradhar/vajra && cd vajra
./setup.sh                     # deps + wordlists + QA suite
python3 vajra.py --selftest    # 55-point verification (54 core + attack-path/finding correlation + DNS concurrency)
python3 vajra.py --version     # VAJRA v1.3-beta
python3 vajra.py --update      # pull the latest build from GitHub
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
| `vajra -t 10.10.10.5 --profile full --yes` | complete engagement: all ports, deep tiers, active exploitation |
| `vajra -t https://app.local --yes` | fast application triage |
| `vajra -t 192.168.1.0/24 --udp --syn --yes` | subnet discovery incl. raw SYN + UDP |
| `vajra -t @targets.txt --profile stealth --yes` | low-and-slow batch |
| `vajra -t http://app.local --profile webonly --yes` | web-application only (no port scan) |
| `vajra -t 10.0.0.5 --profile full --stealth --yes` | full coverage *but* throttled/UA-rotated (if the target blocks you) |
| `vajra -t https://app.local --aggressive --yes` | deep wordlists + intrusive exploitation on the default profile |
| `vajra -t http://app.local --proxy http://127.0.0.1:8080 --yes` | through Burp |
| `vajra -t 10.0.0.5 --socks5 127.0.0.1:9050 --yes` | egress via SOCKS5 (Tor etc.) |
| `vajra -t https://app.local --workspace app1 --yes` | named workspace for retest deltas |
| `vajra --export-findings findings.json -t 10.0.0.5 --yes` | export merged workspace findings |
| `vajra --import-findings findings.json -t 10.0.0.5 --yes` | import findings → full reports |
| `vajra --listener` | standalone multi-session handler |

Targets: IP · CIDR · URL · comma list · `@file`.

### Profile modifiers (`--stealth`, `--aggressive`)

These are **flags** you can combine with *any* profile — you do not have to
switch profiles just to change noise level or depth:

- **`--stealth`** — low-noise modifier for any profile. Throttles requests
  (0.4 s delay), cuts dir-buster / port-scan concurrency, and keeps per-request
  User-Agent rotation on. Ideal when the target starts blocking or rate-limiting
  a `full` / `aggressive` / `webonly` scan. Example: `--profile full --stealth`.
- **`--aggressive`** — deep wordlists (115k users / 148k passwords / 16k dirs)
  plus intrusive exploitation (reverse-session delivery, app-server code
  deploy, ticketing). Already implied by the `aggressive` profile.

Both can be combined, e.g. `--profile aggressive --stealth` for maximum depth
that stays quiet.

Reverse stages (intrusive exploitation) request your callback endpoint
interactively at the moment they're needed — pre-fill via
`--lhost <ip> --lport <n>` to skip the prompt.

---

## Profiles

| | ports | wordlists | mutation budget | notes |
|---|---|---|---|---|
| `quick` *(default)* | top-100 | fast tier | 60 / 10 | triage |
| `full` | all 65535 | **complete tiers** | 160 / 28 | time-based blind SQLi |
| `deep` | all 65535 + UDP | **complete tiers** | 320 / 48 | maximum coverage: 400-page crawl, heightened concurrency |
| `stealth` | top-100 | fast | reduced | delays + UA rotation |
| `aggressive` | all 65535 + UDP | **complete tiers** | 300 / 42 | intrusive exploitation incl. reverse-session delivery; implies `--aggressive` |
| `webonly` | context | fast | standard | application-focused |
| `recon` | top-100 | – | – | intelligence only |

Any of the above can be combined with the **`--stealth`** (lower-noise) or
**`--aggressive`** (deeper) modifiers — see *Profile modifiers* above.

---

## Modules

**Recon** — DNS records (+ **AXFR zone-transfer attempt** from authoritative
 NS via dig or raw DNS-over-TCP) · WHOIS (raw protocol fallback) · subdomain
 enum (dedicated high-concurrency DNS pool, incl. Certificate-Transparency
 log harvesting, fast-fail lookups, wildcard detection — see
 `dns_threads` under Tuning) · email harvest

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
OSV exact-match lookup when the offline KB misses; only confirmed
version-range hits are reported) · security headers (+ full
CORS matrix, HSTS, cookie SameSite) · **TLS audit incl. cert expiry /
self-signed / SAN coverage** · DOM-XSS JS sink/source hunting · sitemap-consume
crawling · JS secret hunting

Blind detections (SSRF, RCE) use an embedded OOB callback listener — auto-on
in `full`/`deep`, or `--oob`.

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
 password spray · CVE exposure probes · **verified-exposure triage
 (`exploit.verify`, read-only)**: Apache path-traversal → RCE, Grafana plugin
 traversal, PHPUnit eval-stdin, WP user/REST & XML-RPC, Spring Boot Actuator,
 WAF/debug pages, FortiGate SSL-VPN disclosure, Cisco ASA/FTD file read,
 Openfire admin bypass, WebLogic/Sitecore console reachability — each gated on
 a real response marker (never payload-driven, zero false positives)

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

`post.persistence` is **active persistence deployment, not read-only**. Over
any confirmed execution channel (RCE / SSH / lateral) it lands a lightweight,
reversible, marker-gated implant via cron-user / cron-root / systemd unit /
SSH authorized-key (Linux) or scheduled task / registry-run / startup folder
(Windows), verifies the hook registers, emits the matching cleanup recipe, and
saves the full plant/verify/cleanup sequence as the PoC in evidence. It is
gated behind `--aggressive` (or the `aggressive` profile) so it never runs
silently, and it can also prove a web-root web-shell drop when a web root is
confirmed.

`post.cloud` runs **only when a target is cloud-backed** (Cloud/CDN tech or a
confirmed cloud identity is detected; otherwise it logs a skip). It validates
any on-host cloud credentials against the provider (live STS identity call),
actively lists confirmed public bucket URLs to flag secret-adjacent object
keys, and re-hydrates the provider CLI — with each identity/read captured as
the PoC. It is intentionally inert-safe: it reads/validates, and only probes
ACL capability behind `--aggressive`; it never changes cloud data silently.

`post.lateral` is **cross-host lateral movement**: through a live channel it
discovers the internal subnet, probes internal hosts for SMB/WinRM/SSH, sprays
every harvested/validated credential set, and on a hit opens a real execution
channel into that internal host (`channels` grows) so loot/recon/persistence
run on it next. Strictly `--aggressive` gated.

`post.exfil` stages sensitive loot (cloud creds, keys, hashes, hidden files)
into a single obfuscated (XOR+base64 — **not strong crypto**, pair with
HTTPS/TOR) blob and emits ready-to-run HTTP/DNS-TXT/TOR exfil recipes aimed
back at your `--lhost/--lport` callback, with an active beacon proof when a
listener is reachable. `--aggressive` gated.

`ad.escalation` and `exploit.cve_runner` complete the chain: the former audits
**AD Certificate Services ESC1–ESC8** (active `certipy find` when installed,
else a ready-to-run playbook) plus cross-forest trust-jump maps; the latter
turns correlated critical **CVEs into active exploitation** — firing the real
RCE payload and capturing live command output as PoC (curated, sound PC set),
and honestly reports when a correlated CVE has no embedded PC instead of
faking it. Both are `--aggressive` gated.

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

- **CVE knowledge base** — 12,800+ products / 51,000+ operator-parsed version
  ranges matched directly against harvested banners (Heartbleed → Log4Shell,
  EternalBlue, ProxyLogon, BIG-IP TMUI, FortiOS, vCenter, Confluence OGNL…),
  rebuilt from the GitHub Advisory Database with `tools/build_cve_db.py`.
- **MITRE ATT&CK** — every finding auto-tagged with technique IDs.
 - **Campaign planner** — mid-run next-best-action list combining rule-based
   logic with findings context.
 - **AI remediation assist** — `web.ai_assist` (advisory only, offline-safe):
   when `--ai` is on and a local model is reachable it writes per-finding
   remediation drafts and a next-attack plan to `ai_assist.json`; with no
   model it stays silent and adds no findings (zero false positives).
 - **Optional AI** — add `--ai` to involve a local Ollama + **Qwen3 8B**
  (auto-installs; fully offline once pulled; swap models via
  [`config/config.json`](#ai--model-selection)). Use `--ai-select` to hand
  the mission to the operator-agent: Qwen3 inspects each target's live state
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
`depcheck` (honest capability matrix: which optional deps / binaries unlock
which intrusive modules here, so nothing silently under-delivers) ·
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

## Live progress meter

As a scan runs you get a **live percentage + ETA** readout on the console —
both at the per-module level and on the overall run:

- Port scan: `port scan 127.0.0.1  100/100  100.0%  ETA 00:00`
- Module / run level: `run 127.0.0.1  52/52  (100.0%)  ETA 00:00`

On a TTY it renders as a self-refreshing percentage bar (`█`/`░`) with
`done/total`, **ETA (remaining time)** and elapsed seconds; when output is
redirected (no TTY) it degrades to a plain one-line log message per step so
nothing is lost. This lets you judge how long a port/word/dir sweep will take
before it finishes.

The ETA is deliberately **non-exact and monotonic**: it is rounded to 5s
granularity, capped, and never allowed to climb once shown — early slow steps
(say the first port of a sweep) can't make the "time remaining" balloon and
read as a bug. It's a stable, reassuring countdown that trends toward the
finish rather than a precise prediction.

---

## Output

Results land in `Outputs/<run>/<target>/` — reports (**HTML dashboard**,
**Markdown**, **Excel / XLSX** — stdlib-only spreadsheet with Summary +
Findings sheets; default `--format all` emits exactly these three), SQLite
store, full transcript log and an `evidence/` folder of raw proof material per
target, plus a run-wide `summary.json`. Evidence is never left empty: every
finding gets a `f###_<issue-slug>.txt` proof dump, and a headless-Chromium
**screenshot** `f###_<issue-slug>.png` is captured per confirmed web issue
(URL auto-derived from the finding's evidence) so the report is backed by a
visual PoC named after the issue. Screenshots are best-effort — if Playwright
or a browser is unavailable, or with `--no-screenshots`, text evidence is kept
and the scan is never blocked.

Each report now carries the full narrative stack: an auto-written **executive
synthesis** (attack surface, priority signal, exposed web tier), a
**proof-of-compromise / objectives summary** (which red-team mission
objectives — RCE, credentials, AD compromise, persistence, cloud compromise,
data exfiltration, web pwnage, pivoting — were actually achieved, derived only
from proof-tested findings with captured evidence), a **compliance remediation
playbook** (every finding cross-referenced to CIS
Benchmark / NIST CSF / PCI DSS 4.0, grouped by severity), a **retest delta**
`vs` the previous workspace snapshot, and cross-host campaign ("spread")
patterns. Workspaces live under `Outputs/workspaces/<target>/` (or your
`--workspace` name) — latest snapshot, run history, per-target state and a
running `workspace_report.md`.

Reports also carry an **attack-path & finding-correlation** view. Findings
describing the *same underlying issue* on a target are merged into one
correlated cluster (all detection sources plus evidence kept, so Nmap + web
scanner + CVE scanner never flood the report with duplicates), and the
framework chains the collected facts into **evidence-grounded attack paths** —
a start point, intermediate steps, prerequisites, the supporting evidence for
every step, confidence, privilege gained, severity and a MITRE technique.
Paths are built **only from assets, services, credentials and findings VAJRA
actually collected**; it never invents a step that is not backed by evidence.

## Fast external port scanning & fresh CVE DB

- **masscan / nmap delegation** — for `--syn` (masscan) or very large port
  sets (nmap, ≥20k ports) the scan is handed off to those fast external
  scanners when installed, then parsed back into VAJRA state; otherwise the
  native async connect scanner is used. `nmap|masscan` are optional — no
  dependency, pure speed-up.
- **CVE DB freshness automation** — `tools/build_cve_db.py --auto` fetches
  the latest `github/advisory-database` tree via git and rebuilds
  `intel/cve_db.json` automatically, with no manual download:
  `python tools/build_cve_db.py --auto`.

## Workspaces, retests & collaboration

- Snapshots are taken automatically at run end. Re-running the same target
  produces a delta report (new / fixed / still-open) so an engagement's
  progress is trackable across sessions.
- If you kill a running scan, the workspace snapshot + reports for whatever
  was found are still persisted for already-reported targets, and the run
  summary is written. Re-run with `--resume` to pick up an interrupted
  workspace: completed modules are skipped (tracked per-snapshot), already
  discovered intel (open ports, services, subdomains, tech, creds, channels,
  loot) is re-seeded into the target, and only unfinished work continues —
  rate limits, dropped sessions and Ctrl-C no longer forfeit prior progress.
- `--export-findings FILE -t <target>` merges every finding across that
  target's snapshots into one JSON file (finding fields, import-safe).
- `--import-findings FILE -t <target>` ingests findings from a peer/JSON
  export and renders complete reports (HTML/MD/XLSX) without re-scanning —
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
    --profile         quick | full | deep | stealth | aggressive | webonly | recon
    --aggressive      modifier: deep tiers + intrusive exploitation on any profile
    --stealth         modifier: low-noise (throttled, UA-rotated, fewer threads)
                       on any profile — use if the target blocks/throttles you
    --lhost/--lport   pre-set callback endpoint for reverse stages
    --listener        standalone multi-session handler
    --ai              enable local Ollama AI (model set in config/config.json)
    --ai-select       mission mode: the model picks next actions per target
    --udp             UDP service probes (DNS/NTP/SNMP)
    --syn             raw SYN scanning (root)
    --no-brute        disable credential attacks
    --skip-phases     comma list of phases to skip entirely (recon,net,web,exploit,ad,post)
    --format          report formats: html | md | xlsx | all (default: all = the three above)
    --no-screenshots  disable per-issue PoC screenshots (text-only evidence)
    --no-autoreg      don't auto-register/auto-login on sites with a signup form
    --ad-user/--ad-pass/--nthash   AD creds → authenticated LDAP + real kerberoasting
    --web-user/--web-pass   webapp creds → AUTHENTICATED crawl/scan of the app
    --web-login       explicit login URL (form is auto-discovered otherwise)
    --web-otp         static OTP code for the login flow
    --web-totp-secret base32 TOTP secret — RFC 6238 code generated at login
    --import-findings FILE   import findings from JSON file and generate reports
    --export-findings FILE   export findings from workspace to JSON file
-o, --output          output root (default: Outputs/)
    --workspace       name the workspace (default: auto per-target)
    --format          html | json | md | pdf | sarif | xlsx | all
    --resume          pick up an interrupted workspace from its last saved
                       snapshot (skips modules already proven-done, reseeds intel)
    --socks5 HOST:PORT  egress via a SOCKS5 proxy (web + raw probes route through)
    --cve-update      when the offline KB misses a product:version, query the
                       live OSV API — exact version-range match, no fuzzy
                       results (cached in intel/cve_online_cache.json)
    --modules         run only listed modules
    --exclude-modules skip listed modules
    --proxy           HTTP proxy
    --oob             run an OOB HTTP callback listener for blind detections
    --oob-port PORT   fixed local port for the OOB listener (default: ephemeral)
-v/-vv                verbose / trace
    --selftest        internal QA suite
    --version         show VAJRA v1.3-beta and exit
    --update          self-update from GitHub upstream and exit (git checkout:
                      fast-forward pull; archive install: in-place tarball
                      replacement keeping Outputs/ + config/config.json)
```

## AI & model selection

The AI runs on a **local** Ollama server (default endpoint `127.0.0.1:11434`,
Ollama's native `/api/generate` API) serving any model you choose. It is
entirely optional (`--ai`), fully offline once the model is pulled, and every
call is time-boxed — if the model is missing or unreachable, VAJRA reports
`[ai] Qwen3 not reachable` and keeps scanning normally (nothing breaks, no
false positives are produced).

Which model is used, and how to change it, is controlled by `config/config.json`:

| Key | Default | Meaning |
|---|---|---|
| `ai_model` | `qwen3:8b` | exact Ollama model tag sent to `/api/generate` |
| `ai_timeout` | `12` | per-request timeout (s); calls are never allowed to stall the scan |
| `ai_max_tokens` | `512` | generated-token cap per reply |
| `ai_autosetup` | `true` | install Ollama + pull the configured model on first `--ai` run (needs internet once) |
| `ai_select` | `false` | behave as if `--ai-select` was passed |
| `ai_enabled` | `false` | behave as if `--ai` was passed |

### Scenario A — default model, nothing to change

```
ollama pull qwen3:8b   # ~4.9 GB, one-time, any internet-capable machine
vajra -t https://your-authorized-target --ai
```

That is it. VAJRA asks Ollama for exactly `qwen3:8b` and, once pulled, logs
`[ai] Qwen3 online via Ollama (qwen3:8b)`. If you prefer not to run
`ollama pull` yourself, leave `ai_autosetup: true` and the first `--ai` run
installs the server and pulls the model automatically while you wait.

### Scenario B — use any other model (the exact steps)

1. **Pull the exact tag you want** (any model on the Ollama library, or a custom
   GGUF). `NAME` here is literal — the exact string you pull:

   ```
   ollama pull qwen3:4b      # lighter — good for 4–8 GB RAM laptops
   ollama pull qwen3:14b     # heavier, needs ~16 GB RAM
   ollama pull llama3.1:8b   # any other model works too
   ```

2. **Point VAJRA at that exact name.** Edit `config/config.json` and set:

   ```json
   "ai_model": "qwen3:4b"
   ```

   It is a case-and-colon sensitive match: the string must equal the `NAME`
   column shown by `ollama list` (e.g. `qwen3:4b`, **not** just `qwen3`).

3. **Run with `--ai` as usual:**

   ```
   vajra -t https://your-authorized-target --ai
   ```

   VAJRA will find the model name prefix (`qwen3*`) in `ollama list` during
   warm-start and therefore **skip its own auto-pull**, then use your
   configured name for every generation call.

### Scenario C — what happens when the name does not match

Ollama labels a bare `ollama pull qwen3` as **`qwen3:latest`**, and a typo like
`ai_model: "qwen3:14B"` (wrong case) names a model that does not exist. VAJRA
never errors or fabricates output: the call quietly returns empty, the payload
suggestions are simply absent, and the scan completes normally. The symptom is
silent — so always verify with:

```
ollama list                 # note the exact NAME column
vajra -t <target> --ai 2>&1 | grep -i "\[ai\]"
```

You should see `[ai] Qwen3 online via Ollama (<your-model>)`. If you see only
`[ai] disabled` or `not reachable`, check the model name and that Ollama is
running (`curl -s http://127.0.0.1:11434/api/tags`).

### What the AI is used for

The configured model powers three things the moment `--ai` is active:

- **WAF evasion**: when a WAF defeats the standard payload bank,
  `suggest_payloads()` has the model craft 5 alternate payloads for that
  injection class (XSS, SQLi, SSTI…) and VAJRA fires them under the `ai.*`
  technique.
- **SQL craftsmanship**: `alternate_sql()` composes dialect-correct UNION
  SELECT expressions keyed to the detected column count.
- **Mission planning** (with `--ai-select`): the operator-agent inspects each
  target's live state and picks the next action — see the next section.

All generated payloads are real payload text in real HTTP requests, never code
executed on your machine. Findings produced via the AI still pass through
the same proof + confidence pipeline (`Certain`/`Firm`/`Tentative`) as every
other finding.

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
the authenticated surface.

### Auto-registration (no credentials needed)

When the app publishes a **registration/signup form** and you do *not* pass
`--web-user`, Vajra **auto-registers a throwaway account** (random
`vjr_…` username, e-mail on the `.local` domain, strong generated password),
fills every field it can recognise on the form — username, e-mail, password +
confirm-password, CSRF token (from `<meta>` or the hidden input) and the terms
checkbox — and adopts whatever session the site grants. If the site still
requires an explicit login after signup, it logs in with the generated
identity. The credential row is written into the finding's detail so an
authorized operator can re-use it. The crawler then runs *authenticated*, so
membership/account pages, user-specific endpoints and all of their parameters
are exercised in context. Disable this with `--no-autoreg` (e.g. when you must
not create accounts, or you prefer to pass real creds).

### Post-auth escalation (`web.escalate`)

Runs automatically once an authenticated session exists (auto-registered or
`--web-user`):

- **Horizontal / IDOR:** mints a *second* throwaway identity, discovers the
  object id the app assigns it (via `.local`/`/me`-style endpoints), then
  requests that resource with the first account's session. A cross-user read is
  reported **only** when the response carries the second user's private marker
  (e-mail/username) *and* an anonymous baseline does **not** leak it — public
  data can never trigger a false positive. Screenshot + raw response are saved
  to `evidence/`.
- **Vertical / admin surface:** probes administrative routes with the low-priv
  session and diffs against the anonymous baseline. Reported as info-grade
  *recon only* (never claimed as a confirmed escalation without a role oracle),
  keeping the report free of false positives.

Everything after auth — crawl, injections, JWT, SSRF, loot sweeps — runs
against the authenticated surface, and all form/query/JSON/XML parameters are
tested in that context. **Registration/login discovery crawls seed pages AND
same-host pages reached by following links** (a sign-up form often lives only
behind a navigation link, not inline on the seed page). The injection suite is
**coverage-first**: it builds one attack point per form carrying *all* of that
form's fields, so **every form on every crawled endpoint has every parameter
tested**; the `max_injection_points` budget only trims additional API/query
surfaces, never whole forms or form parameters.

Without any of the above, the site is scanned unauthenticated and the exploit
layer still attacks whatever auth systems it finds: the full auth-bypass family
plus OTP tricks and aggressive-gated login brute-force (cap/delay/stop-on-
success) that also reports leaks against OTP-protected forms.

---

## FAQ

**Web-only?** No — network services are first-class: full sweeps, binary
handshakes, relay checks, credential attacks across protocols.

**Root required?** No; connect scans work unprivileged. `--syn` needs root.

**Is the AI mandatory?** No — fully off unless you pass `--ai`. Everything
else works without it.

**How do I change the AI model?** See [AI & model selection](#ai--model-selection):
pull any Ollama tag, then set the *exact* tag name as `ai_model` in
`config/config.json`. Default is `qwen3:8b` with nothing to change.

**Slow with big wordlists?** Complete tiers only engage under
`full`/`deep`/`--aggressive`, HTTP attacks are threaded with stop-on-success.

---

## License & author

**VAJRA — Automated Penetration Testing Framework**

Copyright © 2026 **Pintu Kumar Sutradhar** — all rights reserved.


Intended solely for **authorized** security testing. Unauthorized use is
prohibited.

**Validate every finding before acting. Own everything you test.** ⚡

