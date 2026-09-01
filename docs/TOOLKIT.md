# VAJRA Toolkit

Standalone utilities under `tools/` — stdlib only, runnable outside the
framework (each is a normal CLI script with `-h`). Everything is read-only
by default; nothing here executes attacker-supplied payloads.

## tools/_core.py

Shared helpers (colors, JSON loading, project-root discovery). Imported by the
other tools; not a CLI itself.

## tools/netkit.py — network recon

```
netkit.py scan 10.0.0.5           # async TCP port scan + banner
netkit.py scan 10.0.0.5 -p 22,80,443
netkit.py ports 80                # intel table: what this port usually is
```

Read-only TCP connect + a single recv for banners. Annotates results with the
risk/notes table from `intel/ports.json`.

## tools/fuzzurl.py — web path fuzzer

```
fuzzurl.py http://app.local/ -w dirs.fast.txt -H user.txt 2 -t 8 --stop-on-codes 200,301
fuzzurl.py http://app.local/ -w dirs.txt --prev out.json --diff-codes     # self-divergence
```

Threaded GET fuzzer with **soft-404 filtering** (ignores template 404 pages)
and an optional **self-divergence pass** — a response is only reported if a
second, identical request further into the run matches, killing flaky hits.

## tools/cve.py — offline CVE lookup

```
cve.py apache 2.4.49              # version -> parsed CVE matches
cve.py search log4shell           # keyword search across the knowledge base
```

Uses the same `intel/cve_db.json` CVE knowledge base the engine's banner→CVE
correlation uses — no network needed.

## tools/hashid.py — hash format identifier

```
hashid.py '5f4dcc3b5aa765d61d8327deb882cf99'
hashid.py --file hashes.txt
```

Scores candidate formats (NTLM, LM, MD5, SHA-1/256/512, bcrypt, argon2,
DCC2, AP, bbencode, MySQL3/5, …). Good for triaging dumped NTDS/SAM hashes
before pointing hashcat at them.

## tools/listener.py — reverse-session handler + payload render

```
listener.py --lhost 10.0.0.5 --lport 4444        # interactive handler
listener.py --render-only --lhost 10.0.0.5 --lport 4444
listener.py --interactive-eval
```

Decodes and prints attacker-selectable payload snippets **without executing
them**; the handler accepts a single TCP session and streams output.
`--interactive-eval` is a separate explicit mode (off by default).

## tools/dnsrecon.py — DNS recon (raw DNS over TCP)

```
dnsrecon.py example.com                          # A/AAAA/MX/NS/TXT/SOA
dnsrecon.py example.com -w names.txt             # subdomain brute
```

No third-party DNS dependency — builds and parses DNS messages on the wire.
Parser is best-effort on unusual responses.

## tools/envcheck.py — tooling matrix

```
envcheck.py              # summary table for the host
envcheck.py -m           # markdown
envcheck.py -c ad        # single category
```

Reads `config/tooling.json` and reports which external tools the framework
can orchestrate (nmap, ffuf, impacket suite, hashcat, crackmapexec, …) and
which are missing.

## tools/depcheck.py — dependency / capability matrix

```
depcheck.py              # which optional deps + binaries unlock which modules here
```

Setup is a single `setup.sh` (venv + symlink `vajra` globally — no
`pip install .` needed). `depcheck` goes one step further and tells you, for
the current environment, exactly which intrusive modules have their optional
backends (scapy/paramiko/impacket/certipy/cloud CLIs/masscan/nmap) available
and which fall back to stdlib — so a module never silently under-delivers on
an engagement.

## tools/pocgen.py — reviewable PoC evidence

```
pocgen.py xss -u http://app.local/search -p q -P '<svg onload=...>'
pocgen.py lfi -u http://app.local/file -p doc
```

Writes an inert, reviewable **PoC markdown template** (with the payload
quoted, not executed) into a dated file under `Outputs/`.

## tools/rawhttp.py — raw HTTP crafting

```
rawhttp.py -t app.local -P 80 -m GET /admin -H 'Host: evil.example'
rawhttp.py -t app.local -P 443 --tls -m POST /login -b 'user=x&pass=y'
rawhttp.py -t app.local -P 80 --raw 'GET / HTTP/1.1\r\nHost: x'
rawhttp.py -t app.local -P 80 --socks5 127.0.0.1:1080 /admin
```

Host-header override, HTTP/1.0, arbitrary headers, full raw request blocks
and optional egress through a SOCKS5 proxy (`--socks5 host:port`) — the
debugging aid for Host-injection, tunneling and egress tests.

## tools/wordlists.py — wordlist ops

```
wordlists.py list                  # catalog what ships
wordlists.py info passwords        # stats on a shipped or absolute list
wordlists.py filter -i dirs.txt -o small.txt -l 4-12 -r '^[a-z]'
wordlists.py merge -i users -i more -o all.txt     # unique lines
```

Inspects/filters/merges the framework wordlists; the generator itself is
`tools/gen_wordlists.py`.

## layout

```
tools/
  _core.py           shared helpers
  netkit.py          port scan + banner + intel risk table
  fuzzurl.py         soft-404-aware path fuzzer
  cve.py             offline CVE lookups
  hashid.py          hash format identifier
  listener.py        reverse-session handler (no auto-exec)
  dnsrecon.py        raw-DNS recon + subdomain brute
  envcheck.py        host tooling matrix vs config/tooling.json
  pocgen.py          inert PoC templates to evidence/
  rawhttp.py         raw request crafting
  wordlists.py       inspect/filter/merge wordlists
  gen_wordlists.py   deterministic list generator (framework)
```