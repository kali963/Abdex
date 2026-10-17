"""Qualified electronic signature (FR-DOC-07, GOV-DS-01..07).

The user signs in the browser: the private key never reaches the server (GOV-DS-06). The server verifies the
signature itself (GOV-DS-02) and checks (GOV-DS-03):

* integrity — the signature covers exactly the stored document bytes;
* validity — the certificate was valid at the time of signing;
* chain — the certificate chains to a trusted root;
* revocation — the certificate is not revoked;
* owner — the BIN/IIN in the certificate is the signer's company.

Two verifiers sit behind one interface:

* ``NcaNodeVerifier`` — production: certificates of the National Certification Centre of Kazakhstan, signed in
  NCALayer (CMS), verified by an NCANode service (``EDS_NCANODE_URL``) with OCSP and a TSP time stamp;
* ``DevVerifier`` — development and tests: a local test CA issues ECDSA P-256 certificates to keys generated
  in the browser by WebCrypto (the private key stays in the browser too). Never enabled in production.

Re-verification is available at any time (GOV-DS-05): validity is judged at the stored signing time, so a
certificate that expires later does not invalidate an earlier signature.
"""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from functools import lru_cache

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature
from cryptography.x509.oid import NameOID

from app.config import settings
from app.modules.integrations.base import Adapter


@dataclass
class VerifyResult:
    valid: bool
    checks: dict = field(default_factory=dict)
    signer: dict = field(default_factory=dict)
    signed_at: datetime | None = None
    provider: str = ""
    error: str = ""

    def as_dict(self) -> dict:
        return {"valid": self.valid, "checks": self.checks, "signer": self.signer, "provider": self.provider,
                "signed_at": self.signed_at.isoformat() if self.signed_at else None, "error": self.error}


def _b64d(text: str) -> bytes:
    text = (text or "").strip()
    return base64.b64decode(text + "=" * (-len(text) % 4))


# ------------------------------------------------------------------ development CA (never in production)


def _dev_dir():
    d = settings.storage_dir / "dev-eds"
    d.mkdir(parents=True, exist_ok=True)
    return d


@lru_cache(maxsize=1)
def dev_ca() -> tuple[ec.EllipticCurvePrivateKey, x509.Certificate]:
    if settings.is_production:
        raise RuntimeError("the development CA is not available in production")
    key_path, cert_path = _dev_dir() / "ca.key", _dev_dir() / "ca.pem"
    if key_path.exists() and cert_path.exists():
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
        return key, x509.load_pem_x509_certificate(cert_path.read_bytes())
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "AbdEX DEV Root CA (test only)"),
                      x509.NameAttribute(NameOID.COUNTRY_NAME, "KZ")])
    now = datetime.now(timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(days=1))
            .not_valid_after(now + timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True).sign(key, hashes.SHA256()))
    key_path.write_bytes(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                           serialization.NoEncryption()))
    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return key, cert


def dev_issue(public_key_spki_b64: str, *, full_name: str, iin: str, bin_iin: str, days: int = 365,
              not_before: datetime | None = None) -> str:
    """Issue a test certificate for a browser-generated public key. KZ certificates carry the IIN in the
    serialNumber attribute and the organisation BIN in OU; the test certificates follow the same layout."""
    ca_key, ca_cert = dev_ca()
    public = serialization.load_der_public_key(_b64d(public_key_spki_b64))
    if not isinstance(public, ec.EllipticCurvePublicKey):
        raise ValueError("ECDSA P-256 public key expected")
    nb = not_before or datetime.now(timezone.utc) - timedelta(minutes=5)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, full_name[:60] or "Signer"),
                         x509.NameAttribute(NameOID.SERIAL_NUMBER, f"IIN{iin}"),
                         x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, f"BIN{bin_iin}"),
                         x509.NameAttribute(NameOID.COUNTRY_NAME, "KZ")])
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(ca_cert.subject).public_key(public)
            .serial_number(x509.random_serial_number()).not_valid_before(nb).not_valid_after(nb + timedelta(days=days))
            .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=True, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False, key_cert_sign=False,
                                         crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
            .sign(ca_key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _attr(name: x509.Name, oid, prefix: str = "") -> str:
    values = name.get_attributes_for_oid(oid)
    v = values[0].value if values else ""
    return v[len(prefix):] if prefix and v.startswith(prefix) else v


class DevVerifier(Adapter):
    name = "eds"
    provider = "abdex-dev-ca"
    retries = 0

    def verify(self, package: str, data: bytes, *, signed_at: datetime, expected_bin: str,
               revoked: set[str]) -> VerifyResult:
        return self.call("verify", lambda: self._verify(package, data, signed_at, expected_bin, revoked),
                         summary="cms-verify")

    def _verify(self, package, data, signed_at, expected_bin, revoked) -> VerifyResult:
        res = VerifyResult(valid=False, provider=self.provider, signed_at=signed_at)
        try:
            p = json.loads(package)
            cert = x509.load_pem_x509_certificate(p["cert"].encode())
            raw = _b64d(p["sig"])
        except (ValueError, KeyError, TypeError):
            res.error = "malformed_package"
            return res
        _, ca_cert = dev_ca()
        checks = res.checks
        # integrity: WebCrypto gives r||s (IEEE P1363); X.509 libraries expect DER
        try:
            half = len(raw) // 2
            der = encode_dss_signature(int.from_bytes(raw[:half], "big"), int.from_bytes(raw[half:], "big")) \
                if len(raw) == 64 else raw
            cert.public_key().verify(der, data, ec.ECDSA(hashes.SHA256()))
            checks["integrity"] = True
        except (InvalidSignature, ValueError):
            checks["integrity"] = False
        try:
            ca_cert.public_key().verify(cert.signature, cert.tbs_certificate_bytes, ec.ECDSA(hashes.SHA256()))
            checks["chain"] = cert.issuer == ca_cert.subject
        except InvalidSignature:
            checks["chain"] = False
        checks["validity"] = cert.not_valid_before_utc <= signed_at <= cert.not_valid_after_utc
        serial = format(cert.serial_number, "x")
        checks["revocation"] = serial not in revoked
        signer_bin = _attr(cert.subject, NameOID.ORGANIZATIONAL_UNIT_NAME, "BIN")
        signer_iin = _attr(cert.subject, NameOID.SERIAL_NUMBER, "IIN")
        checks["owner"] = bool(expected_bin) and expected_bin in (signer_bin, signer_iin)
        res.signer = {"iin": signer_iin, "bin": signer_bin, "name": _attr(cert.subject, NameOID.COMMON_NAME),
                      "serial": serial, "issuer": cert.issuer.rfc4514_string(),
                      "not_after": cert.not_valid_after_utc.isoformat()}
        res.valid = all(checks.values())
        return res


class NcaNodeVerifier(Adapter):
    """Production verifier: NCANode (CMS, OCSP, TSP) for certificates of NCA RK. The response mapping follows
    NCANode 3.x `/cms/verify`; the exact contract is confirmed when the service is deployed (INT-GEN)."""

    name = "eds"
    provider = "ncanode"
    timeout = 15.0
    retries = 1

    def verify(self, package: str, data: bytes, *, signed_at: datetime, expected_bin: str,
               revoked: set[str]) -> VerifyResult:
        return self.call("verify", lambda: self._verify(package, data, signed_at, expected_bin, revoked),
                         summary="cms-verify")

    def _verify(self, package, data, signed_at, expected_bin, revoked=frozenset()) -> VerifyResult:
        import urllib.request

        body = json.dumps({"cms": package, "data": base64.b64encode(data).decode(), "revocationCheck": ["OCSP"]}).encode()
        req = urllib.request.Request(settings.eds_ncanode_url.rstrip("/") + "/cms/verify", data=body,  # noqa: S310 — scheme checked in config
                                     headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310 — configured internal URL
            out = json.loads(resp.read())
        signer = (out.get("signers") or [{}])[0]
        cert = signer.get("certificates", [{}])[0] if signer.get("certificates") else signer.get("certificate", {})
        subject = cert.get("subject", {})
        tsp = (signer.get("tsp") or {}).get("genTime")
        res = VerifyResult(valid=False, provider=self.provider,
                           signed_at=datetime.fromisoformat(tsp.replace("Z", "+00:00")) if tsp else signed_at)
        revocations = cert.get("revocations") or []
        serial = str(cert.get("serialNumber", ""))
        at = res.signed_at or signed_at

        def _ts(v):
            try:
                return datetime.fromisoformat(str(v).replace("Z", "+00:00"))
            except ValueError:
                return None

        nb, na = _ts(cert.get("notBefore", "")), _ts(cert.get("notAfter", ""))
        res.checks = {"integrity": bool(out.get("valid")), "chain": bool(cert.get("valid", out.get("valid"))),
                      # validity at the signing time; no dates in the answer means not proven
                      "validity": bool(nb and na and nb <= at <= na),
                      # an OCSP answer must exist and say "not revoked"; the platform's own list is checked too
                      "revocation": bool(revocations) and all(r.get("revoked") is False for r in revocations)
                      and serial.lower() not in {str(x).lower() for x in revoked},
                      "owner": bool(expected_bin) and expected_bin in (subject.get("bin", ""), subject.get("iin", ""))}
        res.signer = {"iin": subject.get("iin", ""), "bin": subject.get("bin", ""),
                      "name": subject.get("commonName", ""), "serial": cert.get("serialNumber", ""),
                      "issuer": (cert.get("issuer") or {}).get("commonName", ""), "not_after": cert.get("notAfter", "")}
        res.valid = all(res.checks.values())
        return res


_verifiers: dict[str, Adapter] = {}


def verifier() -> Adapter:
    if settings.eds_ncanode_url:
        return _verifiers.setdefault("ncanode", NcaNodeVerifier())
    if settings.is_production:
        raise RuntimeError("EDS_NCANODE_URL must be set to verify qualified signatures in production")
    return _verifiers.setdefault("dev", DevVerifier())


def is_dev_signer() -> bool:
    return not settings.eds_ncanode_url and not settings.is_production
