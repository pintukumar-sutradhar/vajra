# VAJRA Platform — Commercial Pentest Platform (Plan)

Status: v0.1 draft — approved direction (2026-09-08)
Goal: turn the currently CLI-only VAJRA core into a commercial, branded,
multi-engine penetration testing platform in the class of Acunetix, Tenable
and Qualys — with proper PoC, triage and retest, not "just a vuln scanner".

---

## 1. Product vision

VAJRA sells itself as a **penetration testing platform**, not a checker:

- multiple **scanning engines**: Web Application, Active Directory,
  Infrastructure / Server, External Surface (recon-first);
- every finding ships with a **proof of concept** (reproduction steps,
  observed proof, screenshot where meaningful) — this is VAJRA's differentiator
  and already exists in `core/`;
- a **triage / vulnerability-management loop**: open -> triaged ->
  false-positive / accepted-risk / fixed, with re-test evidence, so the product
  supports the whole fix lifecycle, not just "scan and dump".

## 2. Current state (verified baseline)

| Area | State |
|---|---|
| Scan core | `core/engine.py` runs a full scan on one target; module sets in `modules/{web,ad,network,exploit,post,recon}` (~73 files) |
| Reports | `core/report.py` renders professional HTML/MD/XLSX with PoC blocks, VULN refs, CVE-per-tech, screenshots |
| Data | Per-target SQLite + workspace JSON |
| Server/API/UI | None |
| Self-test | `core/selftest.py`, 56/56 green — must stay green during platform work |

Baseline rule: the existing core is the **engine kernel** and stays intact
during Phase 1-2. The platform is a control plane + workers around it.

## 3. Target architecture

```
┌──────────────────────────────────────────────────────────┐
│  React + Vite SPA  (dashboard, branding/logo themable)   │
│  Login · Targets · Scans · Findings triage · Reports ·   │
│  Engine library · Schedules · Activity · POC viewer      │
└───────────────────────────────┬──────────────────────────┘
                                │ HTTPS  (REST + SSE progress)
┌───────────────────────────────▼──────────────────────────┐
│  FastAPI control plane (Postgres, SQLAlchemy 2.0)        │
│  - auth: local users, roles, sessions (JWT), API keys    │
│  - org/tenant model (single-tenant now, SaaS-ready)      │
│  - targets/assets CRUD · engine definitions · scan       │
│    scheduler · findings store + triage + retest          │
│  - reports (reuse core.report) + download/export         │
│  - audit log · scan identity (authorization gate)        │
└────┬───────┬─────────┬──────────┬────────────────────────┘
     │ enqueue (DB job queue)
┌────▼─────┐ │ ┌───────▼──────┐  ┌─▼───────────────────────┐
│ Worker   │ │ │ Worker       │  │ Worker                  │
│ web      │ │ │ AD           │  │ infrastructure          │
└──────────┘ │ └──┬───────────┘  └─────────────────────────┘
             │    └─ execute engine template against target
             ▼
   core.engine + selected module groups (headless driver)
   streams progress/events -> platform DB -> SSE to UI
   findings/evidence/reports persisted to Postgres
```

Decisions (approved):
- API: **FastAPI**; platform DB: **Postgres**; queue: **DB-backed jobs**
  first (no Redis dependency), worker polls claimable scans; interface
  broken out so a Redis/Celery swap is easy later.
- Frontend: **React + Vite** SPA.
- Tenancy: **single-tenant now, org model present** (orgs/users/roles so the
  SaaS step is additive, not a rewrite).
- Engines: **all three** (web, AD, infra) exposed in the first release;
  web is the most mature and drives the first end-to-end milestone.

## 4. The "scan engine" abstraction

Each engine is a declarative template (mirrors Acunetix "scan templates"):

```yaml
id: webapp
label: Web Application
target_kinds: [url]
module_groups: [web, exploit.web_gated]   # implemented by module dirs
profiles: [quick, full, deep]
params: { auth: {type: form|header|none}, ... }
default_rps: 20
risk: "active but safe by default; exploit needs authorization flag"
```

- `id: webapp`   — crawl + vuln + PoC + WAF (Acunetix-style)
- `id: infrastructure` — ports/services/CVE/config/credentials (Tenable-style)
- `id: active_directory` — AD recon, chain, DACL, privesc, lateral (hallmark
  differentiator; needs domain-member/credential inputs)
- `id: external` — DNS/subdomains/WHOIS/attack-surface first pass (fast, cheap)

Workers load an engine template -> build the module list -> run the headless
scan driver (new: `core/driver.py` or a thin CLI subprocess) -> write
findings/evidence/events into Postgres.

## 5. Findings model (commercial-grade)

- identity: id, org, target, engine, source module, checkpoint
- severity/confidence (existing anti-FP cap retained: critical only on
  certain, etc.)
- `cwe`, optional CVSS-vector/WADL link for portability
- evidence JSON + PoC (steps + command + observed proof + screenshot path)
- lifecycle: `open → triaged → false-positive | accepted-risk | fixed`
  with per-status `note`, `changed_by`, `timestamp`
- `retest`: link to the scan run that re-confirmed or cleared the issue
- first_seen / last_seen, dedup key (target+module+title hash) for re-scans

## 6. API surface (REST, versioned `/api/v1`)

- `auth/login`, `auth/refresh`, `me`; API keys (org-level)
- `targets` CRUD + authorization proof field (scope statement / ticket)
- `engines` (list templates, params)
- `scans` create/list/get/cancel; SSE stream `/scans/{id}/events`; schedules CRUD
- `findings` list/filter/export; lifecycle transitions; comments
- `reports` generate (reuse core.report renderers: HTML/MD/XLSX) + download
- `dashboard` counts (open by severity, fixed rate, scan activity)
- `audit` trail

## 7. Branding & identity

- working name **VAJRA**; brand strings live in one config object
  (`server/config/brand.json` + frontend theme tokens) so a rename/logo swap
  touches one place. Logo SVG + palette injected into the SPA and into the
  printed HTML report header/footer.
- engine cards carry their own icon/badge in the Library page.

## 8. Security & ethics guardrails (non-negotiable for a commercial product)

- every scan records a **scan identity**: who started it, why (scope proof),
  target, engine, timestamp; the authorization-gate stays mandatory.
- platform creds (timers/creds/golden tickets) are never stored in logs;
  findings surfaced through UI only.
- workers are sandboxed processes (own containers in deployment) with
  rate-limiting per target; no cross-tenant bleed even in single-tenant mode.
- default-profile scans stay read-only; exploitation requires the
  authorization flag (same as `--aggressive` today).

## 9. Repo layout (additive)

```
server/            FastAPI control plane (app, api, models, schemas, jobs)
server/app/        config, db, models, security, audit + api/* routers, main
server/worker/     headless scan driver + engine templates + queue intake
server/var/        runtime data (sqlite, encrypted secret key, scan runs) - gitignored
server/run_api.py / run_worker.py   entry points
server/smoke.py    end-to-end Phase-1 verification (real engine scan)
webapp/            React + Vite SPA            (Phase 2)
deploy/            compose.db.yml (optional Postgres); app containers (Phase 4)
docs/PLATFORM.md   this plan
core/              UNCHANGED during Phase 1-2 (engine kernel)
```

## 10. Roadmap

### Phase 1 — Platform skeleton (end-to-end API scan)
DB + migrations (orgs/users/targets/scans/jobs/findings/evidence,
scheduler); auth; targets+engines+scans REST; DB job queue; headless scan
driver wrapping `core.engine` with engine templates (web/infra/AD);
findings+events+reports persisted; SSE progress; authorization gate.
**Milestone:** start a web scan via API on a target and read back findings +
report. selftest stays 56/56.

**STATUS: DONE (2026-09-08)** — verified end-to-end by `server/smoke.py`
(20 checks, real engine scan of a local target: findings harvested,
triage transitions, report served). Core selftest still 56/56.

Delivered:
- FastAPI control plane (`server/app/`): org/user/session/API-key auth
  (PBKDF2 + Fernet-encrypted stored creds), targets with mandatory
  authorization-proof gate, scan lifecycle (pending/running/completed/
  failed/canceled), SSE live events, findings triage lifecycle
  (open -> triaged -> false-positive/accepted-risk/fixed with guards),
  dashboard + audit trail, report + artifact serving from the engine bundle.
- Scan workers (`server/worker/`): declarative engine templates
  (webapp, infrastructure, active_directory, external) -> constrained
  `vajra.py` subprocess runs -> harvest findings/evidence/report into
  Postgres-compatible tables. Cancellation handled (queued immediate,
  running polled).
- Brand endpoint (`/api/v1/auth/brand`) + `server/app/config.py BRAND`
  (single place for product/logo/colors used by the future UI).

Phase-1 limitations (intentional):
- Default DB is SQLite (schema auto-create via SQLAlchemy metadata). The
  production Postgres path is ready via `VAJRA_DB_URL` +
  `psycopg2-binary` (`deploy/compose.db.yml`). Alembic migrations deferred
  until the schema stabilizes (Phase 3/4).
- Scheduler, cross-scan dedup/retest, PDF export and report regeneration
  are Phase 3.
- The worker runs one scan at a time; `VAJRA_WORKERS` scaling and split
  worker images land in Phase 4.

### Phase 2 — Commercial UI (React + Vite)
Branding/login/logo theme; targets; scans list + live progress; engine
library cards; findings triage table (severity/confidence/status + PoC
viewer + screenshot); report download; first real dashboards (open by
severity, engines activity).

**STATUS: DONE (2026-09-08)** — React 18 + Vite 5 SPA in `webapp/`.
Built: branded login + app shell (dark commercial theme, design tokens in
`webapp/src/theme.css`), dashboard (counts + severity split + recent
scans), targets (create with mandatory authorization-proof), engine cards
(4 templates), scans list with live progress pills, scan detail with live
SSE event log streamed to completion + branded report iframe, findings
triage table (filter by severity/status, modal with evidence/PoC, guards
enforced server-side). `VITE_API_TARGET` for the API base in dev,
`/api` proxy in `vite.config.js`. Production build verified
(`npm run build`); full local e2e verified over live HTTP (uvicorn +
worker subprocess): scan streamed 105s, `event: done`, report + findings
read back, dashboard counts.

### Phase 3 — Engine depth + lifecycle
scan templates/profiles/scheduling/retest; infra + AD engines parity with
web; dedup + asset correlation; CVSS normalization; false-positive and
accepted-risk workflow end-to-end; PDF export via report pipeline.

### Phase 4 — Product polish for commercial release
usage/KPI dashboards, e-mail notifications, API docs portal, audit exports;
pack full docker-compose (api/workers/migrations/web/nginx) + one-command
installer; edition gating (Community vs Pro) via license key.

### Phase 5 — SaaS readiness (additive)
tenant isolation on the existing org model; per-tenant scans/quotas; SSO
(OIDC/SAML); usage billing hooks; remote agent option for on-prem AD/INFRA
engines (scanner node in the customer network talking back over TLS).

## 11. What we will NOT do in Phase 1-2
- no rewrite of `core/*` (kernel stays); platform consumes it
- no Redis/Celery (DB queue; interface swappable)
- no billing/full multitenancy (model exists, activation later)
- no AI-synthesis in the client UI beyond what exists in reports

## 12. Open questions to resolve at Phase 2 start
- product display name / logo asset (we need real branding input)
- supported deployment (single-node docker-compose assumed)
- which AD engagement details (Python client vs impacket) for non-domain scans