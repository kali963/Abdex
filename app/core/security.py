"""Cryptographic helpers: password hashing, one-time codes, TOTP, signed URLs.

SEC-AUT-01 argon2id hashing; SEC-AUT-02 password policy; SEC-AUT-04 one-time codes;
SEC-APP-11 CSPRNG everywhere (the `secrets` module).
"""
from __future__ import annotations

import hashlib
from datetime import datetime
import hmac
import secrets
import time

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from app.config import settings

_hasher = PasswordHasher(time_cost=3, memory_cost=64 * 1024, parallelism=2)

# A short excerpt of the most common leaked passwords. In production this is replaced by a
# k-anonymity lookup or a full offline list (SEC-AUT-02).
_COMMON_PASSWORDS = {
    "123456789012", "password1234", "qwerty123456", "111111111111", "000000000000",
    "1234567890qwe", "qwertyuiop12", "passwordpassword", "abdex1234567", "admin1234567",
    "iloveyou1234", "123123123123", "qwerty1234567", "1q2w3e4r5t6y", "zaq12wsxcde3",
}

MIN_PASSWORD_LENGTH = 12


def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(password_hash: str | None, password: str) -> bool:
    if not password_hash:
        # Keep timing similar for unknown accounts.
        _hasher.hash(password)
        return False
    try:
        return _hasher.verify(password_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def password_problems(password: str, *, identifiers: tuple[str, ...] = ()) -> list[str]:
    problems: list[str] = []
    if len(password) < MIN_PASSWORD_LENGTH:
        problems.append("password.too_short")
    lowered = password.lower()
    if lowered in _COMMON_PASSWORDS or len(set(password)) < 4:
        problems.append("password.too_common")
    for ident in identifiers:
        if ident and len(ident) >= 4 and ident.lower() in lowered:
            problems.append("password.contains_identifier")
            break
    return problems


def token(nbytes: int = 32) -> str:
    return secrets.token_urlsafe(nbytes)


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode()
    return hashlib.sha256(data).hexdigest()


def hash_token(raw: str) -> str:
    """Tokens are stored hashed; a DB leak does not reveal live sessions."""
    return hmac.new(settings.secret_key.encode(), raw.encode(), hashlib.sha256).hexdigest()


def generate_otp_code(length: int = 6) -> str:
    return "".join(str(secrets.randbelow(10)) for _ in range(length))


def new_totp_secret() -> str:
    return pyotp.random_base32()


def totp_uri(secret: str, account: str) -> str:
    return pyotp.TOTP(secret).provisioning_uri(name=account, issuer_name="AbdEX")


def verify_totp(secret: str | None, code: str, *, last_step: int = 0) -> int | None:
    """Returns the matched time step (to be stored), or None. A step already used is rejected,
    so an intercepted code cannot be replayed within its validity window."""
    code = (code or "").strip().replace(" ", "")
    if not secret or not code.isdigit():
        return None
    totp = pyotp.TOTP(secret)
    now_step = totp.timecode(datetime.now())
    for step in (now_step - 1, now_step, now_step + 1):
        if step > last_step and hmac.compare_digest(totp.generate_otp(step), code):
            return step
    return None


def sign_payload(payload: str, ttl_seconds: int = 300) -> str:
    """Short-lived signed link token (FR-DOC-08, SEC-FIL-04)."""
    expires = int(time.time()) + ttl_seconds
    msg = f"{payload}|{expires}"
    sig = hmac.new(settings.secret_key.encode(), msg.encode(), hashlib.sha256).hexdigest()[:32]
    return f"{expires}.{sig}"


def verify_signed_payload(payload: str, signature: str) -> bool:
    try:
        expires_s, sig = signature.split(".", 1)
        expires = int(expires_s)
    except ValueError:
        return False
    if expires < time.time():
        return False
    expected = hmac.new(settings.secret_key.encode(), f"{payload}|{expires}".encode(), hashlib.sha256).hexdigest()[:32]
    return hmac.compare_digest(expected, sig)


def mask_phone(phone: str | None) -> str:
    if not phone:
        return ""
    return phone[:4] + "•" * max(0, len(phone) - 6) + phone[-2:]


def mask_email(email: str | None) -> str:
    if not email or "@" not in email:
        return ""
    name, domain = email.split("@", 1)
    return (name[:1] + "•••") + "@" + domain
