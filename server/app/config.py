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
                                             "admin123")
        self.cors_origins = [o.strip() for o in
                             os.environ.get("VAJRA_CORS_ORIGINS",
                                            "*").split(",")]
        self.worker_interval = float(
            os.environ.get("VAJRA_WORKER_INTERVAL", "2.0"))
        self.max_workers = int(os.environ.get("VAJRA_WORKERS", "1"))

    def db_is_sqlite(self):
        return self.db_url.startswith("sqlite")


settings = Settings()

BRAND = {
    "product": "VAJRA",
    "tagline": "Offensive security platform",
    "edition": "Community",
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