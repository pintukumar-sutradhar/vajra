"""VAJRA platform configuration."""

import os
from pathlib import Path

SERVER = Path(__file__).resolve().parents[1]
REPO = Path(__file__).resolve().parents[2]
VAR_DIR = Path(os.environ.get("VAJRA_PLATFORM_VAR", SERVER / "var"))


class Settings:
    def __init__(self):
        self.var_dir = VAR_DIR
        self.runs_dir = VAR_DIR / "runs"
        self.var_dir.mkdir(parents=True, exist_ok=True)
        self.runs_dir.mkdir(parents=True, exist_ok=True)
        self.db_url = os.environ.get(
            "VAJRA_DB_URL",
            "sqlite:///%s" % (VAR_DIR / "platform.db"))
        self.token_ttl_hours = int(os.environ.get("VAJRA_TOKEN_TTL_HOURS", 12))
        self.secret_key_path = VAR_DIR / "secret.key"
        self.admin_password = os.environ.get("VAJRA_ADMIN_PASSWORD",
                                             "admin")
        self.cors_origins = [o.strip() for o in
                             os.environ.get("VAJRA_CORS_ORIGINS",
                                            "*").split(",")]
        self.worker_interval = float(
            os.environ.get("VAJRA_WORKER_INTERVAL", "2.0"))
        self.max_workers = int(os.environ.get("VAJRA_WORKERS", "3"))
        # Login hardening: per-account brute-force lockout.
        self.login_max_attempts = int(
            os.environ.get("VAJRA_LOGIN_MAX_ATTEMPTS", "5"))
        self.login_lockout_seconds = int(
            os.environ.get("VAJRA_LOGIN_LOCKOUT_SECONDS", "900"))
        self.password_min_length = int(
            os.environ.get("VAJRA_PASSWORD_MIN_LENGTH", "10"))
        # Session cookie Secure flag (set VAJRA_SESSION_SECURE=1 behind TLS).
        self.session_cookie_secure = \
            os.environ.get("VAJRA_SESSION_SECURE", "0") == "1"
        # API bind address. Defaults to loopback; set VAJRA_API_HOST=0.0.0.0
        # (or an explicit interface) to expose beyond the local host.
        self.api_host = os.environ.get("VAJRA_API_HOST", "127.0.0.1")

    def db_is_sqlite(self):
        return self.db_url.startswith("sqlite")


settings = Settings()

BRAND = {
    "product": "VAJRA",
    "tagline": "Offensive security platform",
    "edition": "",
    "company": "",
    "logo_svg": (
        "<svg width='64' height='64' viewBox='0 0 64 64' "
        "xmlns='http://www.w3.org/2000/svg'><defs><linearGradient id='vg' "
        "x1='0' y1='0' x2='1' y2='1'>"
        "<stop offset='0' stop-color='#0f2b52'/><stop offset='1' "
        "stop-color='#0073ff'/></linearGradient></defs>"
        "<path fill='url(#vg)' d='M32 4 8 16v16c0 15 10 26 24 30 "
        "14-4 24-15 24-30V16z'/><path fill='#fff' d='M32 16 22 40h7l3-9 "
        "3 9h7z'/></svg>"),
    "colors": {
        "primary": "#0f2b52",
        "accent": "#0073ff",
        "danger": "#e11d48",
        "bg": "#0b1220",
        "surface": "#111a2e",
    },
}