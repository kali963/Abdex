"""Web Push (FR-MOB-02): VAPID (RFC 8292) and message encryption aes128gcm (RFC 8291), implemented with the
``cryptography`` package — no third-party push library.

* VAPID keys: ``VAPID_PRIVATE_KEY`` (PEM, from the secret store) and ``VAPID_SUBJECT`` (mailto: or https:). In
  development a key pair is generated once and kept in the storage directory.
* A browser subscription is accepted only for the endpoints of the known push services (SSRF protection).
* A subscription answered with 404/410 is removed (the user revoked it or reinstalled the browser).
"""
from __future__ import annotations

import base64
import json
import os
import struct
import time
from functools import lru_cache
from urllib.parse import urlparse

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.core.secrets import secret
from app.config import settings

PUSH_HOSTS = ("fcm.googleapis.com", "updates.push.services.mozilla.com", "push.services.mozilla.com",
              "web.push.apple.com", ".notify.windows.com", "push.api.chrome.google.com")
TTL = 24 * 3600
RECORD_SIZE = 4096


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64u_dec(text: str) -> bytes:
    text = (text or "").strip()
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


@lru_cache(maxsize=1)
def _private_key() -> ec.EllipticCurvePrivateKey:
    pem = secret("VAPID_PRIVATE_KEY")
    if pem:
        return serialization.load_pem_private_key(pem.replace("\\n", "\n").encode(), password=None)
    if settings.is_production:
        raise RuntimeError("VAPID_PRIVATE_KEY must be set in production")
    path = settings.storage_dir / "dev-vapid.pem"
    if path.exists():
        return serialization.load_pem_private_key(path.read_bytes(), password=None)
    key = ec.generate_private_key(ec.SECP256R1())
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
    return key


def enabled() -> bool:
    return bool(secret("VAPID_PRIVATE_KEY")) or not settings.is_production


def public_key() -> str:
    """Application server key for PushManager.subscribe (uncompressed point, base64url)."""
    return b64u(_private_key().public_key().public_bytes(serialization.Encoding.X962,
                                                         serialization.PublicFormat.UncompressedPoint))


def endpoint_allowed(endpoint: str) -> bool:
    u = urlparse(endpoint or "")
    host = (u.hostname or "").lower()
    return (u.scheme == "https" and not u.username and not u.password and u.port in (None, 443)
            and any(host == h or (h.startswith(".") and host.endswith(h)) for h in PUSH_HOSTS))


def vapid_headers(endpoint: str) -> dict:
    u = urlparse(endpoint)
    claims = {"aud": f"{u.scheme}://{u.netloc}", "exp": int(time.time()) + 12 * 3600,
              "sub": os.getenv("VAPID_SUBJECT", "mailto:support@abdex.kz")}
    header = b64u(json.dumps({"typ": "JWT", "alg": "ES256"}).encode())
    payload = b64u(json.dumps(claims, separators=(",", ":")).encode())
    der = _private_key().sign(f"{header}.{payload}".encode(), ec.ECDSA(hashes.SHA256()))
    r, s = decode_dss_signature(der)
    jwt = f"{header}.{payload}.{b64u(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"
    return {"Authorization": f"vapid t={jwt}, k={public_key()}"}


def encrypt(plaintext: bytes, p256dh: str, auth: str) -> bytes:
    """RFC 8291 / RFC 8188 aes128gcm, a single record."""
    ua_public = b64u_dec(p256dh)
    auth_secret = b64u_dec(auth)
    ua_key = ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), ua_public)
    as_private = ec.generate_private_key(ec.SECP256R1())
    as_public = as_private.public_key().public_bytes(serialization.Encoding.X962,
                                                    serialization.PublicFormat.UncompressedPoint)
    shared = as_private.exchange(ec.ECDH(), ua_key)
    ikm = HKDF(algorithm=hashes.SHA256(), length=32, salt=auth_secret,
               info=b"WebPush: info\x00" + ua_public + as_public).derive(shared)
    salt = os.urandom(16)
    cek = HKDF(algorithm=hashes.SHA256(), length=16, salt=salt, info=b"Content-Encoding: aes128gcm\x00").derive(ikm)
    nonce = HKDF(algorithm=hashes.SHA256(), length=12, salt=salt, info=b"Content-Encoding: nonce\x00").derive(ikm)
    if len(plaintext) > RECORD_SIZE - 17 - 100:
        plaintext = plaintext[: RECORD_SIZE - 17 - 100]
    body = AESGCM(cek).encrypt(nonce, plaintext + b"\x02", None)
    return salt + struct.pack("!IB", RECORD_SIZE, len(as_public)) + as_public + body


def send(endpoint: str, p256dh: str, auth: str, payload: dict, *, timeout: float = 10.0) -> int:
    """Returns the HTTP status of the push service (201 = accepted)."""
    import urllib.error
    import urllib.request

    if not endpoint_allowed(endpoint):
        raise ValueError("push endpoint not allowed")
    data = encrypt(json.dumps(payload, ensure_ascii=False).encode(), p256dh, auth)
    headers = {"Content-Encoding": "aes128gcm", "Content-Type": "application/octet-stream", "TTL": str(TTL),
               "Urgency": "normal", **vapid_headers(endpoint)}
    req = urllib.request.Request(endpoint, data=data, headers=headers, method="POST")  # noqa: S310 — allow-listed https
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 — allow-listed https push host
            return resp.status
    except urllib.error.HTTPError as exc:
        return exc.code
