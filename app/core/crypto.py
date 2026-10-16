"""Application-level encryption of personal-data fields (SEC-DAT-02/03, NFR-DB-08).

* AES-256-GCM with a random nonce per value; the column name is bound as associated data, so a value copied
  into another column does not decrypt.
* Stored form: ``enc:v<key version>:<base64url(nonce || ciphertext)>``. Several key versions can be loaded at
  once; new values use the highest version, old ones stay readable until ``python -m app.cli rotate-keys``
  re-encrypts them (rotation at least yearly and on suspicion of compromise).
* Lookups by value (duplicate IIN / IBAN checks) use a blind index: HMAC-SHA256 with a separate index key,
  so equality search works without decrypting and without storing the plain value.
* Keys come from the secret store: the file named by FIELD_ENCRYPTION_KEYS_FILE (a mounted secret) or, as a
  fallback, the FIELD_ENCRYPTION_KEYS variable — never from code. Format: ``1:<base64 32 bytes>,2:<...>``.
  Outside production a fixed development key is used so that local data survives restarts.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import logging
import os
import secrets
from functools import lru_cache

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PREFIX = "enc:v"
log = logging.getLogger("abdex.crypto")


class KeyringError(RuntimeError):
    pass


def _b64d(text: str) -> bytes:
    text = text.strip()
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def _parse(raw: str) -> dict[int, bytes]:
    keys: dict[int, bytes] = {}
    for part in raw.replace("\n", ",").split(","):
        part = part.strip()
        if not part:
            continue
        version, _, key = part.partition(":")
        k = _b64d(key)
        if len(k) != 32:
            raise KeyringError("field encryption keys must be 32 bytes")
        keys[int(version)] = k
    return keys


@lru_cache(maxsize=1)
def keyring() -> tuple[dict[int, bytes], bytes]:
    from app.config import settings

    raw = ""
    path = os.getenv("FIELD_ENCRYPTION_KEYS_FILE", "")
    if path:
        with open(path, encoding="utf-8") as fh:
            raw = fh.read()
    raw = raw or os.getenv("FIELD_ENCRYPTION_KEYS", "")
    if raw:
        keys = _parse(raw)
    elif settings.is_production:
        raise KeyringError("FIELD_ENCRYPTION_KEYS_FILE (or FIELD_ENCRYPTION_KEYS) must be set in production")
    else:
        log.warning("field encryption uses the development key; set FIELD_ENCRYPTION_KEYS_FILE in production")
        keys = {1: hashlib.sha256(b"abdex-development-field-key").digest()}
    index_raw = os.getenv("FIELD_INDEX_KEY", "")
    index_key = _b64d(index_raw) if index_raw else hmac.new(keys[min(keys)], b"blind-index", hashlib.sha256).digest()
    return keys, index_key


def reset_keyring() -> None:
    keyring.cache_clear()


def current_version() -> int:
    return max(keyring()[0])


def encrypt(value: str | None, column: str) -> str | None:
    if value is None or value == "" or str(value).startswith(PREFIX):
        return value
    keys, _ = keyring()
    version = max(keys)
    nonce = secrets.token_bytes(12)
    ct = AESGCM(keys[version]).encrypt(nonce, str(value).encode(), column.encode())
    return f"{PREFIX}{version}:{base64.urlsafe_b64encode(nonce + ct).decode().rstrip('=')}"


def decrypt(stored: str | None, column: str) -> str | None:
    if not stored or not stored.startswith(PREFIX):
        return stored  # empty, or a legacy plain value not migrated yet
    head, _, body = stored.partition(":")[2].partition(":")
    keys, _ = keyring()
    key = keys.get(int(head.lstrip("v")))
    if key is None:
        raise KeyringError(f"field key version {head} is not loaded")
    raw = _b64d(body)
    return AESGCM(key).decrypt(raw[:12], raw[12:], column.encode()).decode()


def key_version(stored: str | None) -> int | None:
    if not stored or not stored.startswith(PREFIX):
        return None
    return int(stored[len(PREFIX):].split(":", 1)[0])


def blind_index(value: str | None, purpose: str) -> str:
    if not value:
        return ""
    normalized = "".join(str(value).split()).upper()
    return hmac.new(keyring()[1], f"{purpose}:{normalized}".encode(), hashlib.sha256).hexdigest()[:40]
