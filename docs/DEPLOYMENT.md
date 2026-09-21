# VAJRA — Deployment

This guide covers running the platform in production. The platform consists of
two processes sharing one data directory:

- **API** (`server/run_api.py`) — REST control plane, serves the webapp, runs
  reports (HTML/PDF).
- **Worker** (`server/run_worker.py`) — claims scan jobs from the queue and
  runs the scanner engine. Scale it with `VAJRA_WORKERS` (default 3) on one
  host; for multiple hosts, point all processes at the same database.

Everything below defaults to **safe** behavior: the API binds loopback only,
requires a login, and locks an account after repeated failed logins.

## Quick start (native)

```bash
./setup.sh                      # venv + engine + webapp deps
VAJRA_ADMIN_PASSWORD='…' .venv/bin/python server/run_api.py &
VAJRA_ADMIN_PASSWORD='…' .venv/bin/python server/run_worker.py &
```

## Quick start (Docker)

```bash
docker compose -f deploy/compose.yml up -d --build
```

The API is published on `127.0.0.1:8130`; the webapp is served from the same
origin, so no CORS configuration is needed in the default single-origin
layout.

## First login & initial hardening

1. Open `http://127.0.0.1:8130/`.
2. Sign in as **admin** with the password from `VAJRA_ADMIN_PASSWORD`
   (or the default `admin` when unset). Because the default build boots with a
   known password, **the first sign-in forces a password change** before the
   workspace unlocks.
3. Then, in **Users**, add real members with the smallest role that fits:
   - `admin` — users, targets, scans, settings
   - `analyst` — run scans and triage findings
   - `auditor` — read-only (reports, findings, audit ledger)
4. Create API keys for scripts instead of sharing passwords. Keys are
   admin-managed and visible in **Users → (create) → keys**, or
   `POST /api/v1/auth/keys`.

Security settings are env-tunable:

| Variable | Default | Meaning |
|---|---|---|
| `VAJRA_API_HOST` | `127.0.0.1` | Bind address. Loopback by default; set to `0.0.0.0` only behind a firewall/proxy. |
| `VAJRA_SESSION_SECURE` | `0` | Set `1` when serving over HTTPS (marks the session cookie `Secure`). |
| `VAJRA_CORS_ORIGINS` | `*` | Comma-separated allowed origins. Same-origin deployments ignore this. |
| `VAJRA_LOGIN_MAX_ATTEMPTS` | `5` | Failed logins before a temporary lockout. |
| `VAJRA_LOGIN_LOCKOUT_SECONDS` | `900` | Lockout window. |
| `VAJRA_PASSWORD_MIN_LENGTH` | `10` | Minimum password length. |
| `VAJRA_TOKEN_TTL_HOURS` | `12` | Session lifetime. |
| `VAJRA_WORKERS` | `3` | Concurrent scans per worker. |
| `VAJRA_DB_URL` | sqlite | `postgresql+psycopg2://…` for the multi-host path. |

## Reverse proxy with TLS

Terminate TLS in front of the API (loopback-published or container-published).
Example Nginx:

```nginx
server {
  listen 443 ssl;
  server_name vajra.example.com;
  ssl_certificate     /etc/ssl/vajra/fullchain.pem;
  ssl_certificate_key /etc/ssl/vajra/privkey.pem;

  location / {
    proxy_pass http://127.0.0.1:8130;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    # SSE / long-lived scan streams
    proxy_read_timeout 3600s;
    proxy_buffering off;
  }
}
```

With TLS in place set `VAJRA_SESSION_SECURE=1` and, if you serve the webapp
from any other origin, `VAJRA_CORS_ORIGINS=https://app.example.com`.

A systemd unit for the native install (mirror for the worker):

```ini
[Unit]
Description=VAJRA API
After=network.target

[Service]
User=vajra
WorkingDirectory=/opt/vajra
EnvironmentFile=/etc/vajra/env
ExecStart=/opt/vajra/.venv/bin/python server/run_api.py
Restart=on-failure

[Install]
WantedBy=multi-user.target
```

## Postgres

Optional; SQLite (single host) is the default and is adequate for most
installations.

```bash
docker compose -f deploy/compose.db.yml up -d        # local Postgres
# install the adapter
.venv/bin/pip install 'psycopg2-binary>=2.9'
VAJRA_DB_URL='postgresql+psycopg2://vajra:vajra@127.0.0.1:5432/vajra' \
  python server/run_api.py
```

## Backups

The platform state is the **database + scan run artifacts + the encryption
key**. Back up all three together (`server/var` as a whole, or):

```bash
./scripts/backup.sh /srv/backups          # → /srv/backups/vajra-<stamp>.tar.gz
```

Restore (services stopped):

```bash
./scripts/restore.sh /srv/backups/vajra-<stamp>.tar.gz
```

Schedule it — the archive round-trips cleanly and survives a fresh install.

## Upgrades

1. `git pull` (or swap the image tag).
2. Run `bash ./verify.sh` on a checkout before applying to the live host.
3. Restart both processes. New columns are added automatically on startup
   (additive-only migration; it never drops anything).
4. Confirm `/health` is green and run one scan end-to-end.

## Hardening checklist

- [ ] `VAJRA_ADMIN_PASSWORD` set out-of-band on first boot; default admin
      password changed at the forced first login.
- [ ] One user per operator, least-privilege roles; auditors separate.
- [ ] API keys in scripts, not shared passwords.
- [ ] TLS in front of the API; `VAJRA_SESSION_SECURE=1`.
- [ ] Locked-down `VAJRA_CORS_ORIGINS`; API not reachable from the internet.
- [ ] Backups scheduled and tested by a restore drill.
- [ ] Authorization proofs recorded on targets (the scan engine refuses to
      run without one).
- [ ] Logs shipped off-host; the audit ledger (`/api/v1/audit`, UI: Audit)
      is append-only.