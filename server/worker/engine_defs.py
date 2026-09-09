"""Scanning engine templates.

Each engine maps to the existing VAJRA CLI surface: a profile, an
exclusion list (module groups the engine does not run) and optional flags
(--ad, UDP, SYN, brute). Target kinds gate which assets each engine accepts.
"""

ENGINES = {
    "webapp": {
        "label": "Web Application",
        "icon": "app-web",
        "description": "Web application security scanning with automated exploitation and PoC evidence.",
        "target_kinds": ["url"],
        "profiles": ["quick", "full", "deep"],
        "params_schema": {
            "auth": {"label": "Authenticated scanning",
                     "type": "object",
                     "fields": ["web_user", "web_pass", "web_login",
                                "web_otp", "web_totp_secret"]},
            "aggressive": {"label": "Intrusive exploits", "type": "bool", "default": False},
            "external_intel": {"label": "Live CVE intel lookups", "type": "bool", "default": False},
        },
        "cfg": {
            "default_profile": "deep",
            "exclude_modules": ["ad.", "post."],
            "oob": True,
            "no_brute": True,
        },
    },
    "api": {
        "label": "API & Microservice",
        "icon": "app-api",
        "description": "API and microservice security scanning with automated exploitation.",
        "target_kinds": ["url"],
        "profiles": ["quick", "full", "deep"],
        "params_schema": {
            "auth": {"label": "Authenticated scanning",
                     "type": "object",
                     "fields": ["web_user", "web_pass", "web_login",
                                "web_otp", "web_totp_secret"]},
            "aggressive": {"label": "Intrusive exploits", "type": "bool", "default": False},
            "external_intel": {"label": "Live CVE intel lookups", "type": "bool", "default": False},
        },
        "cfg": {
            "default_profile": "full",
            "exclude_modules": ["ad.", "post."],
            "oob": True,
            "no_brute": True,
        },
    },
    "infrastructure": {
        "label": "Infrastructure",
        "icon": "app-infra",
        "description": "Network, host and service security assessment.",
        "target_kinds": ["ip", "cidr", "hostname", "domain"],
        "profiles": ["quick", "full"],
        "params_schema": {
            "udp": {"label": "UDP service probes", "type": "bool", "default": False},
            "syn": {"label": "Raw SYN scan (root)", "type": "bool", "default": False},
            "brute": {"label": "Service credential brute force", "type": "bool", "default": False},
            "aggressive": {"label": "Intrusive exploits", "type": "bool", "default": False},
            "external_intel": {"label": "Live CVE intel lookups", "type": "bool", "default": False},
        },
        "cfg": {
            "default_profile": "full",
            "exclude_modules": ["web.", "ad.", "post."],
            "oob": False,
        },
    },
    "active_directory": {
        "label": "Active Directory",
        "icon": "app-ad",
        "description": "Active Directory security assessment.",
        "target_kinds": ["domain", "hostname", "ip"],
        "profiles": ["full", "deep"],
        "params_schema": {
            "ad_user": {"label": "Domain username", "type": "string", "secret": True},
            "ad_pass": {"label": "Password", "type": "string", "secret": True},
            "nthash": {"label": "NT hash (LM:NT or bare)", "type": "string", "secret": True},
            "aggressive": {"label": "Intrusive AD exploitation", "type": "bool", "default": False},
        },
        "cfg": {
            "default_profile": "full",
            "exclude_modules": ["post."],
            "ad": True,
            "oob": False,
        },
    },
    "external": {
        "label": "External Attack Surface",
        "icon": "app-external",
        "description": "External attack-surface reconnaissance.",
        "target_kinds": ["domain", "url"],
        "profiles": ["recon"],
        "params_schema": {
            "external_intel": {"label": "Live intel lookups", "type": "bool", "default": False},
        },
        "cfg": {
            "default_profile": "recon",
            "exclude_modules": ["net.", "web.", "exploit.", "ad.", "post."],
            "oob": False,
            "no_brute": True,
        },
    },
}


def get_engine(engine_id):
    return ENGINES.get(engine_id)