"""VAJRA platform security: passwords, session tokens, API keys, cred crypto."""

import base64
import datetime
import hashlib
import hmac
import os
import secrets

from cryptography.fernet import Fernet

from .config import settings

_ITER = 260000
_ALGO = "pbkdf2_sha256"


def hash_password(password):
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(),
                             salt, _ITER)
    return "%s:%d$%s$%s" % (
        _ALGO, _ITER, base64.b64encode(salt).decode(),
        dk.hex())


def verify_password(password, stored):
    try:
        algo, salt_b64, hex_digest = stored.split("$")
        algo_id, iters_n = algo.split(":")
        if algo_id != "pbkdf2_sha256":
            return False
        salt = base64.b64decode(salt_b64)
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(),
                                 salt, int(iters_n))
        return hmac.compare_digest(dk.hex(), hex_digest)
    except Exception:
        return False


def _sha256(token):
    return hashlib.sha256(token.encode()).hexdigest()


def issue_session_token():
    return secrets.token_urlsafe(32)


def session_hash(token):
    return _sha256(token)


def issue_api_key():
    return "vaj_" + secrets.token_urlsafe(32)


def api_public(key):
    return "vaj_" + key[4:14]


def _fernet():
    key_file = settings.secret_key_path
    if not key_file.exists():
        key_file.write_text(Fernet.generate_key().decode())
        try:
            os.chmod(key_file, 0o600)
        except OSError:
            pass
    return Fernet(settings.secret_key_path.read_text().strip().encode())


def encrypt_creds(payload: dict) -> str:
    raw = __import__("json").dumps(payload).encode()
    return _fernet().encrypt(raw).decode()


def decrypt_creds(token: str) -> dict:
    raw = _fernet().decrypt(token.encode())
    return __import__("json").loads(raw.decode())


def now_utc():
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


def expires_after(hours=None):
    return now_utc() + datetime.timedelta(
        hours=hours or settings.token_ttl_hours)