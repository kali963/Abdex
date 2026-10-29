"""EDS login against the real formats: the answer of NCANode (recorded from malikzh/ncanode for a test
certificate built like an NCA RK one) and the eGov mobile flow through SIGEX (link the EDS, then sign in)."""
from __future__ import annotations

import base64
import copy
import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import select

from app.db import SessionLocal
from tests.conftest import csrf_from

RECORDED = json.loads((Path(__file__).parent / "ncanode_verify_response.json").read_text(encoding="utf-8"))


class _Resp:
    def __init__(self, body: dict):
        self.body = json.dumps(body).encode()

    def read(self, *a):
        return self.body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _verify_with(monkeypatch, answer: dict):
    import urllib.request

    from app.config import settings
    from app.modules.documents.eds import NcaNodeVerifier

    monkeypatch.setattr(urllib.request, "urlopen", lambda req, timeout=None: _Resp(answer))
    old = settings.eds_ncanode_url
    object.__setattr__(settings, "eds_ncanode_url", "http://ncanode:14579")
    try:
        return NcaNodeVerifier()._verify("MIIB", b"AbdEX login", datetime.now(timezone.utc), "", set())
    finally:
        object.__setattr__(settings, "eds_ncanode_url", old)


def test_recorded_ncanode_answer_untrusted_chain(monkeypatch):
    """A certificate NCANode does not trust: chain fails; revocation is not proven although NCANode says
    revoked=false (OCSP could not be asked — the reason field says why); the signer is still read correctly."""
    res = _verify_with(monkeypatch, RECORDED)
    assert not res.valid
    assert res.checks["chain"] is False and res.checks["revocation"] is False
    assert res.signer["iin"] == "123456789012" and res.signer["bin"] == "123456789021"
    assert res.signer["name"] == "ТЕСТОВ ТЕСТ"
    assert "root certificate" in res.error or "trusted issuer" in res.error


def test_recorded_ncanode_answer_valid_signature(monkeypatch):
    """The same answer as NCANode gives for a trusted NCA RK certificate with a good OCSP status."""
    good = copy.deepcopy(RECORDED)
    now = datetime.now(timezone.utc)
    good["valid"] = True
    signer = good["signers"][0]
    signer.update({"status": "TOTAL_PASSED", "subIndication": None, "message": None})
    cert = signer["certificates"][0]
    cert["valid"] = True
    cert["revocations"] = [{"revoked": False, "by": "OCSP", "revocationTime": None, "reason": None}]
    cert["notBefore"] = (now - timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%S.000+00:00")
    cert["notAfter"] = (now + timedelta(days=300)).strftime("%Y-%m-%dT%H:%M:%S.000+00:00")
    res = _verify_with(monkeypatch, good)
    assert all(v for k, v in res.checks.items() if k != "owner"), res.checks
    assert res.signer["iin"] == "123456789012"


@pytest.fixture
def sigex(monkeypatch):
    """SIGEX answers as https://sigex.kz/api/egovQr does; eGov mobile "signs" the data it got."""
    from app.modules.accounts import egov_mobile
    from app.modules.documents import eds

    monkeypatch.setenv("EGOV_PROVIDER", "sigex")
    png = base64.b64encode(b"\x89PNG\r\n\x1a\nfake").decode()

    class FakeSigex:
        def register(self, description):
            return {"dataURL": "https://sigex.kz/api/egovQr/x", "signURL": "https://sigex.kz/api/egovQr/x",
                    "qrCode": png, "eGovMobileLaunchLink": "https://m.egov.kz/mobileSign/?link=https://sigex.kz/x",
                    "eGovBusinessLaunchLink": "https://evil.example/x"}

        def exchange(self, reg, documents, wait):
            out = copy.deepcopy(documents)
            challenge = base64.b64decode(out[0]["document"]["file"]["data"])
            out[0]["document"]["file"]["data"] = base64.b64encode(b"CMS-OVER:" + challenge).decode()
            return {"documentsToSign": out}

    class FakeVerifier:
        iin = "880101300011"

        def verify(self, package, data, *, signed_at, expected_bin, revoked):
            ok = package.startswith("CMS-OVER:") and package.endswith(data.decode())
            return eds.VerifyResult(valid=ok, provider="test", signed_at=signed_at,
                                    checks={"integrity": ok, "chain": True, "validity": True, "revocation": True},
                                    signer={"iin": self.iin, "name": "ТЕСТОВ ТЕСТ", "serial": "abc"})

    monkeypatch.setattr(egov_mobile, "_sigex", lambda: FakeSigex())
    monkeypatch.setattr(egov_mobile, "_package", lambda data_b64: base64.b64decode(data_b64).decode())
    monkeypatch.setattr(eds, "verifier", lambda: FakeVerifier())
    return FakeVerifier


def _wait(client, url, *, want="signed"):
    for _ in range(50):
        j = client.get(url).json()
        if j["status"] in (want, "failed"):
            return j
        time.sleep(0.1)
    return j


def test_link_with_egov_mobile_then_sign_in(login, client_app, sigex):
    from fastapi.testclient import TestClient

    from app.main import app
    from app.modules.accounts.models import User

    s = login("+77010000002")
    page = s.c.get("/account/security").text
    assert "Привязать через eGov mobile" in page
    j = s.c.post("/account/egov/link/start", headers={"X-CSRF-Token": csrf_from(page)}).json()
    assert j["qr"].startswith("data:image/png;base64,")
    assert j["deeplinks"] == {"mgov": "https://m.egov.kz/mobileSign/?link=https://sigex.kz/x"}  # only m.egov.kz
    done = _wait(s.c, j["status"])
    assert done["status"] == "signed" and done["redirect"].startswith("/account/security")
    db = SessionLocal()
    try:
        user = db.execute(select(User).where(User.phone == "+77010000002")).scalar_one()
        assert user.eds_linked_at and user.iin == sigex.iin
    finally:
        db.close()

    # now the same EDS signs in from a fresh browser, without the password
    with TestClient(app) as anon:
        tok = csrf_from(anon.get("/login").text)
        j = anon.post("/login/egov/start", headers={"X-CSRF-Token": tok}).json()
        done = _wait(anon, j["status"])
        assert done["status"] == "signed", done
        assert anon.get(done["redirect"]).status_code == 200
        assert "+7 701" in anon.get("/account").text or anon.get("/dashboard").status_code == 200

    # another account cannot take the same IIN
    other = login("+77010000001")
    page = other.c.get("/account/security").text
    j = other.c.post("/account/egov/link/start", headers={"X-CSRF-Token": csrf_from(page)}).json()
    done = _wait(other.c, j["status"])
    assert done["status"] == "failed" and "другому аккаунту" in done["message"]
    # the status of someone else's attempt is invisible
    assert s.c.get(j["status"]).status_code == 404
    db = SessionLocal()
    try:
        user = db.execute(select(User).where(User.phone == "+77010000002")).scalar_one()
        user.iin, user.eds_linked_at = "", None
        db.commit()
    finally:
        db.close()
