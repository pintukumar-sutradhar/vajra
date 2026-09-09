<div align="center">

<pre align="center">
    ██╗   ██╗ █████╗      ██╗██████╗  █████╗
    ██║   ██║██╔══██╗     ██║██╔══██╗██╔══██╗
    ██║   ██║██║██║██║ ██  ██║██████╔╝███████║
    ╚██╗ ██╔╝██╔══██║ ╚██╗██╔╝██╔══██╗██╔══██║
     ╚████╔╝ ██║  ██║  ╚███╔╝ ██║  ██║██║  ██║
      ╚═══╝  ╚═╝  ╚═╝   ╚══╝  ╚═╝  ╚═╝╚═╝  ╚═╝
</pre>

# ⚡ V A J R A

### Offensive Security Platform — Automated Penetration Testing, Fully in the Browser

[![license](https://img.shields.io/badge/license-Custom-blue.svg)](LICENSE)

`web applications` · `APIs` · `infrastructure` · `active directory` · `external attack surface`

![UI](https://img.shields.io/badge/Interface-100%25%20UI%2FUX-orange)
![Engine](https://img.shields.io/badge/Engine-Automated%20Pentest-success)
![Reporting](https://img.shields.io/badge/Reports-HTML%20%2B%20PDF-blue)
![License](https://img.shields.io/badge/License-All%20rights%20reserved-orange)

</div>

---

> ⚠️ **Authorized use only.** VAJRA is an offensive security assessment
> platform. Running it against systems you do not own or lack written
> permission to test is illegal.

---

## Contents

- [Overview](#overview)
- [Scan types](#scan-types)
- [Credentials — with or without](#credentials--with-or-without)
- [Quickstart](#quickstart)
- [The platform](#the-platform)
- [Reporting](#reporting)
- [Capabilities](#capabilities)
- [API](#api)
- [Architecture](#architecture)
- [CLI status (deprecated)](#cli-status-deprecated)
- [Engine capability](#engine-capability)
- [Configuration](#configuration)
- [FAQ](#faq)
- [License & author](#license--author)

---

## Overview

VAJRA is a **fully automated penetration-testing platform**, delivered
entirely through a modern web interface.

Every capability — creating targets, configuring and launching scans,
choosing credentialed or unauthenticated operation, watching scans run live,
triaging findings, and exporting branded HTML / PDF reports — happens in the
UI. **There is no terminal workflow.**

| Capability class | What the platform does |
|---|---|
| **Scan orchestration** | Pick an engine · pick a profile · run with or without credentials · watch live progress over SSE |
| **All scan types** | Web apps · APIs · infrastructure · Active Directory · external attack surface |
| **Automated exploitation** | Proof-gated, profile-driven exploitation of confirmed issues with PoC evidence |
| **Evidence** | Per-finding text proof + headless-browser **screenshots** of the compromised surface |
| **Reporting** | Branded **HTML** and **PDF** export, executive summary, compliance playbook, remediation guidance |
| **Findings lifecycle** | Open → triaged → false positive → accepted risk → fixed, per finding |

---

## Scan types

All scan types are launched from the **Engines** page in the UI. Each engine
accepts a set of target kinds and profiles; every engine supports multiple
profiles and can run **credentialed or unauthenticated** (see below).

| Engine | Target kinds | Profiles | Credentials |
|---|---|---|---|
| **Web Application** | URL | quick · full · deep | Optional (web login: user / pass / OTP / TOTP) |
| **API & Microservice** | URL | quick · full · deep | Optional (API login: user / pass / OTP / TOTP) |
| **Infrastructure** | IP · CIDR · hostname · domain | quick · full | Runs unauthenticated; optional UDP / SYN / brute / aggressive toggles |
| **Active Directory** | domain · hostname · IP | full · deep | Optional (domain user / pass / NT hash) — unauthenticated pass always runs |
| **External Attack Surface** | domain · URL | recon | Unauthenticated recon module |

Each grid card shows the engine's exact profiles and target kinds, and the
launch dialog reflects the real engine surface — no fake options.

---

## Credentials — with or without

Every scan type runs **with or without credentials**. The launch dialog makes
this an explicit choice:

- **Without credentials** — the default. The engine runs unauthenticated and
  still performs full discovery, injection and exploitation of exposed
  surfaces (including auto-registration on web apps that publish a signup
  form).
- **With credentials** — reveal the credential fields and supply them:

  - Web / API: `web_user`, `web_pass`, optional login URL, OTP or TOTP secret.
  - Active Directory: domain user, password and/or NT hash — unlocks the
    authenticated pass (real kerberoasting, LDAP mining, lateral-movement
    chains).
  - If the credential box is left blank the scan proceeds unauthenticated.

Credentials are stored with the scan request only — they are never returned
by findings or report endpoints.

---

## Quickstart

Requirements: Python 3.9+, Node 18+, and the repo's `server` + `webapp`
directories.

## Run — one command

Clone the repo, then run the single launcher file. On the first run it
installs everything (Python venv + platform deps, builds the web UI, forges
the wordlists, symlinks the `vajra` command to `~/.local/bin`), starts the API
+ scan worker, and opens the browser:

```bash
git clone <your-repo-url> && cd vajra
./vajra-launcher         # one file — installs once, starts platform, opens browser
```

From then on every session is an even shorter one command:

```bash
vajra                   # opens http://127.0.0.1:8000 (auto port) in your browser
```

For development (hot-reload UI against a running API):

```bash
# API + worker as above; then, in another terminal:
cd webapp && VITE_API_TARGET=http://127.0.0.1:8000 npm run dev   # UI on :5173
```

The UI is served by the API on a single origin — one process, one URL, no
proxy needed. The active port is remembered (`server/var/port`); the launcher
auto-picks from `8000 / 8130 / 8080 / 9000`.

> Default login: `admin` / `admin` (override with `VAJRA_ADMIN_PASSWORD` before
> first boot).

### Launcher commands

```text
vajra                        start platform + open browser
vajra --no-browser           start without opening the browser
vajra --link                 install/symlink ~/.local/bin/vajra and exit
vajra --update               git pull --ff-only, reinstall + rebuild
vajra --stop                 stop the API + worker
vajra --check                print status / exit code
vajra --version              version + toolchain check
```

**End-to-end verification** (standalone harness — spins up a local web app and
runs a real engine scan through the full API → queue → worker → harvest →
report path):

```bash
cd server
.venv/bin/python smoke.py        # 34 checks, green exit 0
```

---

## The platform

| Page | What it does |
|---|---|
| **Dashboard** | Risk posture, findings by severity, latest scans and targets |
| **Targets** | Asset inventory under test |
| **Engines** | Scan-type catalog; launch any scan with your choice of profile and credentials |
| **Scans** | Live queue with SSE progress; open any scan to watch events, findings and the report |
| **Findings** | Cross-scan triage: severity, confidence, status workflow, PoC screenshots |
| **Audit** | Immutable activity log |
| **Reports** | Branded HTML (in-app preview) and PDF download from any completed scan |

Scan detail shows:
- live progress and engine event stream (SSE) while running
- the full findings register after completion, each with evidence and
  screenshot thumbnails
- the generated HTML report in a browser frame
- **Download HTML** and **Download PDF** buttons

---

## Reporting

Every completed scan produces a branded report:

- Assessment summary with an executive narrative and severity matrix
- Per-finding detail: description, evidence, request/response, screenshots,
  remediation and current triage status
- Compliance mapping (CIS / NIST CSF / PCI DSS) and prioritized remediation
  playbook
- Export as **HTML** (ISO-styled, opened in-app or downloaded) and **PDF**
  (paginated, header/footer with page numbers, PoC screenshots embedded)

Screenshots are captured by a headless Chromium engine per confirmed web
issue (URL auto-derived from evidence) and embedded in both exports.

---

## Capabilities

- **Multi-engine coverage** — web, API, infrastructure, Active Directory,
  external attack surface under one console.
- **Credentialed & unauthenticated** operation for every scan type.
- **Automated exploitation with proof** — confirmed issues are exploited and
  the capture is kept as evidence.
- **Real PoC screenshots** rendered into HTML and PDF reports.
- **Live streaming** of scan events over SSE (no page polling).
- **Findings lifecycle** and triage workflow (table + Kanban views).
- **Branded reports** with executive and technical sections.
- **Audit trail** (`/api/v1/audit`) for governance.
- **Command palette + hotkeys** (`Ctrl+K`, `g d/t/s/e/f/a`, `n t/s`, `?`, `Esc`).

---

## API

The UI speaks to a FastAPI control plane. Quick reference:

| Resource | Method | Purpose |
|---|---|---|
| `/api/v1/auth/login` | POST | Bearer token (default `admin` / `admin`) |
| `/api/v1/engines` | GET | Scan-type catalog with profiles + params schema |
| `/api/v1/targets` | GET/POST | Asset inventory |
| `/api/v1/scans` | POST | Launch a scan (engine, profile, params/creds) |
| `/api/v1/scans/{id}` | GET | Status + progress + findings count |
| `/api/v1/scans/{id}/events` | GET | SSE live event stream |
| `/api/v1/scans/{id}/findings` | GET | Finding register (evidence + screenshots) |
| `/api/v1/findings/{id}` | PATCH | Triage status transitions |
| `/api/v1/reports/{id}/html` | GET | HTML report |
| `/api/v1/reports/{id}/pdf` | GET | PDF report download |
| `/api/v1/reports/{id}/static/{path}` | GET | Report + evidence assets (auth-gated) |

---

## Architecture

```
┌──────────────────────┐    ┌───────────────────────────┐
│  React UI (webapp)   │    │  FastAPI control plane    │
│  single page app     │ ──►│  auth · targets · scans    │
│  SSE live progress   │    │  engines · findings ·      │
└──────────────────────┘    │  reports · audit           │
                            └───────────┬───────────────┘
                                        │ job queue (SQLite/Postgres)
                            ┌───────────▼───────────────┐
                            │  Scan worker(s)           │
                            │  run core engine as a     │
                            │  constrained subprocess,  │
                            │  harvest findings +       │
                            │  evidence + screenshots   │
                            └───────────────────────────┘
```

The scan worker runs the (embedded) engine kernel as a constrained,
non-interactive subprocess per scan, then harvests each target's SQLite store,
evidence text and PoC screenshots into the platform database. Reports are
regenerated server-side from the harvested data.

Storage: SQLite by default (`server/var/platform.db`). For Postgres set
`VAJRA_DB_URL=postgresql+psycopg2://...` (see `deploy/compose.db.yml`).

---

## CLI status (deprecated)

The legacy `vajra.py` command-line interface is **deprecated**. The engine
kernel still exists as the execution layer, but it is now driven exclusively
through the platform (scan worker → engine subprocess). No CLI workflow is
supported for day-to-day use — everything is done from the browser.

Platform maintainers may still use `python vajra.py --selftest` as an engine
release gate; it is not a user workflow.

---

## Engine capability

The engine behind the platform is a full attack framework covering web, API,
infrastructure, Active Directory and external attack surface: discovery and
crawling, vulnerability detection across application, network, wire and cloud
surfaces, proof-gated exploitation, post-exploitation paths and offline CVE
intelligence.

Every finding is proof-tested (Certain / Firm / Tentative) before it appears in
a report, and every scan ends with an evidence folder of text proofs + PoC
screenshots.

---

## Configuration

Environment variables:

| Variable | Default | Meaning |
|---|---|---|
| `VAJRA_API_HOST` / `VAJRA_API_PORT` | `0.0.0.0` / `8000` | API bind |
| `VAJRA_ADMIN_PASSWORD` | `admin` | initial admin password |
| `VAJRA_DB_URL` | `sqlite:///server/var/platform.db` | platform database |
| `VAJRA_PLATFORM_VAR` | `server/var` | runtime directory (runs + artifacts) |
| `VAJRA_TOKEN_TTL_HOURS` | `12` | bearer-token lifetime |
| `VAJRA_CORS_ORIGINS` | `*` | allowed origins (comma list) |
| `VITE_API_TARGET` *(webapp)* | `http://127.0.0.1:8000` | dev proxy target for the UI |

---

## FAQ

**What is VAJRA?** A fully automated, browser-first penetration-testing
platform covering web apps, APIs, infrastructure, Active Directory and
external attack surface, with automated exploitation, PoC screenshots and
branded HTML/PDF reporting.

**Do I need credentials?** No. Every scan type runs unauthenticated by
default; credentials are optional for a deeper, authenticated pass.

**Root required?** No. Connect scans run unprivileged; raw-SYN mode (if ever
enabled for an infra scan) requires root.

**Where do scans run?** A worker process on the platform host runs the scan
engine as an isolated subprocess per job. The UI streams the worker's live
event log over SSE.

**Is the AI mandatory?** No — AI-assisted remediation is optional and only
engages when enabled.

**Can I export reports?** Yes — branded HTML and PDF, per completed scan, from
the scan-detail page.

---

## License & author

**VAJRA — Offensive Security Platform**

Copyright © 2026 **Pintu Kumar Sutradhar** — all rights reserved.

Intended solely for **authorized** security testing. Unauthorized use is
prohibited.

**Validate every finding before acting. Own everything you test.** ⚡