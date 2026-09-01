# VAJRA — command cheat-sheet

## Quick starts

```bash
# Fast triage against a single target
python3 vajra.py -t https://app.local --yes -o Outputs

# Full engagement (all ports, deep payload tiers, active exploitation)
python3 vajra.py -t 10.10.10.5 --profile full --aggressive --yes

# Subnet sweep incl. UDP probes
python3 vajra.py -t 192.168.1.0/24 --udp --syn --yes

# Stealth batch from a file
python3 vajra.py -t @targets.txt --profile stealth --yes

# Webapp with credentials: authenticated crawl + scan of the whole surface
python3 vajra.py -t http://app.local --web-user bob --web-pass 's3cret!' \
    --web-login /login --web-totp-secret JBSWY3DPEHPK3PXP --yes

# Active Directory engagement
python3 vajra.py -t dc01.corp.local --profile full \
    --ad-user svc.audit --ad-pass 'P@ssw0rd' --aggressive --yes

# Route everything through Burp
python3 vajra.py -t http://app.local --proxy http://127.0.0.1:8080 --yes
```

## Give the operator-agent the wheel

```bash
python3 vajra.py -t http://app.local --ai --ai-select --aggressive --yes
# Qwen3 picks next actions per target; every step logged to
# evidence/ai_mission_log.md. Without --aggressive it plans + writes
# reviewable PoCs only.
```

## Module-scoped runs

```bash
# Only see it's open + banner
python3 vajra.py -t 10.0.0.5 --modules network.portscan,network.services --yes

# Skip loud/brute stages
python3 vajra.py -t 10.0.0.5 --profile full --exclude-modules network.brute,exploit.spray --yes

# Deep-scan only the API/auth surface of a web app
python3 vajra.py -t https://api.local --modules web.api,web.crawl,web.headers --yes
```

## OOB listener (blind detections)

```bash
# Auto-on in full/deep; force it on any profile, fixed port:
python3 vajra.py -t http://app.local --oob --oob-port 45678 --yes
```

## Toolkit commands

```bash
tools/envcheck.py                 # what external tools are installed here
tools/netkit.py scan 10.0.0.5     # async port scan + banners
tools/fuzzurl.py http://app.local/ -w wordlists -t 8
tools/cve.py apache 2.4.49        # offline CVE correlation
tools/pocgen.py xss -u http://app.local/search -p q -P '<svg/onload=1>'
tools/rawhttp.py -t app.local -P 80 -m GET /admin -H 'Host: evil.example'
tools/dnsrecon.py example.com -w wordlists/subs.fast.txt
tools/hashid.py 'NT_HASH_OR_SHA_OR_BCRYPT...'
tools/listener.py --render-only --lhost 10.0.0.5 --lport 4444
tools/wordlists.py info passwords
```

## Output

```text
Outputs/<run>/<target>/
  report.html  report.json  report.md   findings dashboard
  findings.sqlite                       full SQLite store
  vajra.log                            transcript
  evidence/                             raw proofs + PoCs
```

## Flags cheat-sheet

| flag | meaning |
|---|---|
| `-t/--target` | IP · CIDR · URL · comma list · `@file` |
| `-p/--ports` | `80` · `22-1000` · `top100/top1000/extended/all` |
| `--profile` | `quick`·`full`·`deep`·`stealth`·`aggressive`·`webonly`·`recon` |
| `--aggressive` | intrusive: deep tiers, brute, exploitation, reverse stages |
| `--lhost/--lport` | pre-set callback endpoint for reverse stages |
| `--listener` | standalone multi-session handler |
| `--ai / --ai-select` | local Ollama AI / operator-agent mission mode |
| `--udp / --syn` | UDP probes / raw SYN scans (root) |
| `--no-brute` | skip credential attacks |
| `--ad-*` | AD creds → authenticated LDAP + kerberoasting + movement |
| `--web-*` | webapp creds → authenticated crawl/scan |
| `--oob / --oob-port` | OOB callback listener for blind SSRF/RCE |
| `--socks5` | route web + raw probes through a SOCKS5 proxy (egress) |
| `--cve-update` | live CIRCL CVE lookup when the offline KB misses |
| `--format pdf` | PDF report export alongside html/json/md |
| `--udp` | enables UDP probes incl. the SNMPv1 community sweep (161) |
| `--proxy` | HTTP proxy |
| `--modules / --exclude-modules` | scope which modules run |
| `--selftest` | internal QA suite |