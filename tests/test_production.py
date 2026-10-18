"""Launch readiness: production configuration check, real SMS providers, shared rate limits, antivirus,
simulators that never pretend in production, the first administrator, password reset links."""
from __future__ import annotations

import json
import socket
import struct
import threading

import pytest
from sqlalchemy import select

from app.config import settings


@pytest.fixture
def production():
    object.__setattr__(settings, "app_env", "production")
    yield
    object.__setattr__(settings, "app_env", "test")


def test_overload_answers_busy_without_the_database(client_app, monkeypatch):
    """An exhausted connection pool gives a short 503 "try again", not a 500 (and needs no connection itself)."""
    from sqlalchemy.exc import TimeoutError as PoolTimeout

    from app.web import routes_public

    def exhausted(*a, **k):
        raise PoolTimeout("QueuePool limit reached")

    monkeypatch.setattr(routes_public, "render", exhausted)
    r = client_app.get("/help")
    assert r.status_code == 503 and r.headers["retry-after"] == "5" and "перегружен" in r.text
    r = client_app.get("/help", headers={"Accept": "application/json"})
    assert r.status_code == 503 and r.json()["error"]["code"] == "busy"


def test_request_and_page_share_one_connection(login, monkeypatch):
    """A signed-in page (with the unread counter and company switcher) opens one session, not two."""
    from app import db as dbmod

    owner = login("+77010000001")
    opened = []
    real = dbmod.SessionLocal

    def counting():
        s = real()
        opened.append(s)
        return s

    monkeypatch.setattr(dbmod, "SessionLocal", counting)
    assert owner.get("/help").status_code == 200
    assert len(opened) == 1, len(opened)


def test_preflight_blocks_a_half_configured_production(monkeypatch, production):
    from app.core import preflight

    for name in ("MOBIZON_API_KEY", "SMSC_LOGIN", "SMS_GATEWAY_URL", "SMS_PROVIDER", "CLAMAV_HOST"):
        monkeypatch.delenv(name, raising=False)
    codes = {i.code for i in preflight.check_env() if i.level == preflight.ERROR}
    assert {"sms", "public_url", "antivirus"} <= codes
    with pytest.raises(RuntimeError, match="not ready"):
        preflight.enforce()


def test_preflight_report_and_db_checks(client_app):
    from app.core import preflight
    from app.db import SessionLocal

    db = SessionLocal()
    try:
        items = preflight.report(db)
    finally:
        db.close()
    codes = {i.code: i.level for i in items}
    assert codes["admin"] == preflight.OK  # the demo has an administrator
    assert "eds" in codes  # the demo switches the e-signature on
    preflight.enforce()  # not production: never blocks


def test_simulators_refuse_in_production(production):
    from app.modules.documents.transport import etd
    from app.modules.integrations.adapters import biometrics, registry
    from app.modules.integrations.base import IntegrationUnavailable

    with pytest.raises(IntegrationUnavailable):
        registry.check_company("123456789012", basis="test")
    with pytest.raises(IntegrationUnavailable):
        biometrics.compare(b"a", b"b", b"c")
    with pytest.raises(IntegrationUnavailable):
        etd.register({"number": "X"})


class _Resp:
    def __init__(self, body: dict, status: int = 200):
        self.status, self._body = status, json.dumps(body).encode()

    def read(self, *_):
        return self._body

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


@pytest.mark.parametrize("provider,env,answer,check", [
    ("mobizon", {"MOBIZON_API_KEY": "k1", "SMS_SENDER": "AbdEX"}, {"code": 0, "data": {"messageId": "1"}},
     lambda url, body: "api.mobizon.kz/service/message/sendsmsmessage" in url and "apiKey=k1" in url
     and "recipient=77011234567" in body and "from=AbdEX" in body),
    ("smsc", {"SMSC_LOGIN": "abdex", "SMSC_PASSWORD": "pw"}, {"id": 5, "cnt": 1},
     lambda url, body: url == "https://smsc.kz/sys/send.php" and "phones=77011234567" in body and "fmt=3" in body),
    ("http", {"SMS_GATEWAY_URL": "https://sms.example/send", "SMS_GATEWAY_TOKEN": "t"}, {},
     lambda url, body: url == "https://sms.example/send" and json.loads(body)["to"] == "+77011234567"),
])
def test_sms_providers(monkeypatch, provider, env, answer, check):
    import urllib.request

    from app.modules.integrations.adapters import SmsAdapter, sms_provider

    for name in ("MOBIZON_API_KEY", "SMSC_LOGIN", "SMS_GATEWAY_URL", "SMS_PROVIDER", "SMS_SENDER"):
        monkeypatch.delenv(name, raising=False)
    for k, v in env.items():
        monkeypatch.setenv(k, v)
    assert sms_provider() == provider
    seen = {}

    def fake_urlopen(req, timeout=0):
        seen["url"], seen["body"] = req.full_url, req.data.decode()
        return _Resp(answer)

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    SmsAdapter()._deliver("+7 701 123-45-67", "AbdEX: код 123456")
    assert check(seen["url"], seen["body"])


def test_sms_provider_error_is_raised(monkeypatch):
    import urllib.request

    from app.modules.integrations.adapters import SmsAdapter

    monkeypatch.setenv("SMS_PROVIDER", "mobizon")
    monkeypatch.setenv("MOBIZON_API_KEY", "k")
    monkeypatch.setattr(urllib.request, "urlopen", lambda req, timeout=0: _Resp({"code": 2, "message": "balance"}))
    with pytest.raises(RuntimeError, match="mobizon"):
        SmsAdapter()._deliver("+77011234567", "x")


def _fake_clamd(reply: bytes):
    srv = socket.socket()
    srv.bind(("127.0.0.1", 0))
    srv.listen(1)
    got = {}

    def serve():
        conn, _ = srv.accept()
        with conn:
            buf = b""
            while not buf.startswith(b"zINSTREAM\0"):
                buf += conn.recv(1024)
            buf = buf[len(b"zINSTREAM\0"):]
            data = b""
            while True:
                while len(buf) < 4:
                    buf += conn.recv(65536)
                (n,) = struct.unpack("!L", buf[:4])
                buf = buf[4:]
                if n == 0:
                    break
                while len(buf) < n:
                    buf += conn.recv(65536)
                data += buf[:n]
                buf = buf[n:]
            got["data"] = data
            conn.sendall(reply)
        srv.close()

    threading.Thread(target=serve, daemon=True).start()
    return srv.getsockname()[1], got


def test_clamav_scan(monkeypatch):
    from app.core.errors import AppError
    from app.core.storage import AntivirusAdapter

    av = AntivirusAdapter()
    port, got = _fake_clamd(b"stream: OK\0")
    monkeypatch.setenv("CLAMAV_HOST", "127.0.0.1")
    monkeypatch.setenv("CLAMAV_PORT", str(port))
    payload = b"%PDF-1.4 " + b"x" * 150_000  # several INSTREAM chunks
    assert av.scan(payload) == "clean" and got["data"] == payload
    port, _ = _fake_clamd(b"stream: Win.Test.EICAR_HDB-1 FOUND\0")
    monkeypatch.setenv("CLAMAV_PORT", str(port))
    assert av.scan(b"%PDF-1.4 bad") == "infected"
    # clamd down: the upload is refused, never stored unchecked
    free = socket.socket()
    free.bind(("127.0.0.1", 0))
    dead_port = free.getsockname()[1]
    free.close()
    monkeypatch.setenv("CLAMAV_PORT", str(dead_port))
    with pytest.raises(AppError) as exc:
        av.scan(b"%PDF-1.4 x")
    assert exc.value.code == "antivirus_unavailable"


def test_shared_rate_limits_in_redis(monkeypatch):
    redis = pytest.importorskip("redis")
    try:
        redis.Redis(socket_timeout=0.3).ping()
    except Exception:  # noqa: BLE001
        pytest.skip("no local redis")
    from app.core import ratelimit
    from app.core.errors import RateLimited

    monkeypatch.setenv("REDIS_URL", "redis://localhost:6379/15")
    monkeypatch.setattr(ratelimit, "_redis", None)
    monkeypatch.setattr(ratelimit, "_redis_down_until", 0.0)
    ratelimit.reset_all()
    for _ in range(3):
        assert ratelimit.hit("login", "redis-test", limit=3, window=60)
    with pytest.raises(RateLimited):
        ratelimit.hit("login", "redis-test", limit=3, window=60)
    assert ratelimit.count("login", "redis-test") == 3
    # another process sees the same counters
    other = redis.Redis.from_url("redis://localhost:6379/15")
    assert other.zcard("abdex:rl:login:redis-test") == 3
    ratelimit.reset_all()
    monkeypatch.setattr(ratelimit, "_redis", None)


def test_rate_limits_fall_back_when_redis_is_down(monkeypatch):
    from app.core import ratelimit

    monkeypatch.setenv("REDIS_URL", "redis://127.0.0.1:1/0")  # nothing listens there
    monkeypatch.setattr(ratelimit, "_redis", None)
    monkeypatch.setattr(ratelimit, "_redis_down_until", 0.0)
    assert ratelimit.hit("login", "fallback-test", limit=5, window=60)  # served from memory, no error
    assert ratelimit._redis_down_until > 0
    monkeypatch.setattr(ratelimit, "_redis", None)
    monkeypatch.setattr(ratelimit, "_redis_down_until", 0.0)


def test_create_staff_cli(client_app):
    from app import cli
    from app.core.security import verify_password
    from app.db import SessionLocal
    from app.modules.accounts.models import User

    password = cli.create_staff("+7 705 000 99 01", "Первый Администратор", "admin", "first.admin@abdex.kz")
    assert len(password) >= 12
    db = SessionLocal()
    try:
        u = db.execute(select(User).where(User.phone == "+77050009901")).scalar_one()
        assert u.staff_role == "admin" and verify_password(u.password_hash, password)
        # an existing user keeps the password and gets the role
        assert cli.create_staff("+77050009901", "", "moderator") == ""
        db.expire_all()
        assert db.get(User, u.id).staff_role == "moderator"
    finally:
        db.close()
    with pytest.raises(SystemExit):
        cli.create_staff("+77050009902", "X", "superuser")


def test_password_reset_link_is_absolute_and_sent_after_response(client_app, monkeypatch):
    from fastapi.testclient import TestClient

    from app.main import app
    from app.modules.integrations.adapters import _OutboundAdapter

    object.__setattr__(settings, "public_base_url", "https://abdex.kz")
    try:
        _OutboundAdapter.sent.clear()
        c = TestClient(app)
        from conftest import csrf_from

        token = csrf_from(c.get("/forgot-password").text)
        r = c.post("/forgot-password", data={"login": "+77010000001", "csrf_token": token})
        assert r.status_code == 200
        texts = [m["body"] for m in _OutboundAdapter.sent if m["channel"] == "sms"]
        assert texts and "https://abdex.kz/reset-password?u=" in texts[-1]
        _OutboundAdapter.sent.clear()
        r = c.post("/forgot-password", data={"login": "+77019999999", "csrf_token": token})
        assert r.status_code == 200 and not _OutboundAdapter.sent  # unknown account: same page, nothing sent
    finally:
        object.__setattr__(settings, "public_base_url", "http://localhost:8000")


def test_eds_challenge_is_bound_to_the_browser(login):
    """A nonce signed elsewhere cannot be used from another browser (phishing relay), and a failed attempt
    burns it."""
    from fastapi.testclient import TestClient
    from test_cycle3 import _challenge, _key, _package

    from app.main import app

    owner = login("+77010000001")
    key, spki = _key()
    cert = owner.post("/dev/eds/login-certificate", data={"public_key": spki}).json()["certificate"]
    ch = _challenge(owner.post)
    assert owner.post("/account/eds/link", data={"package": _package(key, cert, ch), "challenge": ch}).status_code == 303
    try:
        from conftest import csrf_from

        def browser():
            c = TestClient(app)
            token = csrf_from(c.get("/login").text)
            return c, lambda url, data=None: c.post(url, data={**(data or {}), "csrf_token": token},
                                                    follow_redirects=False)

        victim, victim_post = browser()
        attacker, attacker_post = browser()
        ch = _challenge(attacker_post)  # the attacker's nonce, signed by the victim
        r = victim_post("/login/eds", {"package": _package(key, cert, ch), "challenge": ch})
        assert r.headers["location"] == "/login"  # not this browser's nonce
        r = attacker_post("/login/eds", {"package": _package(key, cert, ch), "challenge": ch})
        assert r.headers["location"] == "/login"  # burned by the failed attempt
        ch = _challenge(victim_post)
        r = victim_post("/login/eds", {"package": _package(key, cert, ch), "challenge": ch})
        assert r.status_code == 303 and r.headers["location"] != "/login"
    finally:
        assert owner.post("/account/eds/unlink").status_code == 303


def test_egov_links_and_organisation(monkeypatch):
    from app.modules.accounts import egov_mobile

    lk = egov_mobile.links("https://abdex.kz", "tok123")
    assert lk["qr"] == "mobileSign:https://abdex.kz/egov/mgov/tok123"
    assert lk["deeplinks"]["mgov"] == "https://m.egov.kz/mobileSign/?link=https://abdex.kz/egov/mgov/tok123?mgovSign"
    assert lk["deeplinks"]["business"] == "https://m.egov.kz/businessSign/?link=https://abdex.kz/egov/mgov/tok123?mgovSign"
    monkeypatch.setenv("EGOV_DEEPLINK_MGOV", "")  # switched off
    monkeypatch.setenv("EGOV_ORG_BIN", "123456789012")
    assert "mgov" not in egov_mobile.links("https://abdex.kz", "t")["deeplinks"]
    assert egov_mobile._organisation()["bin"] == "123456789012"


def _fake_sigex(monkeypatch, behaviour):
    """SIGEX API stand-in: register → urls; data POST → accepted; sign GET → behaviour(documents)."""
    from app.modules.accounts import egov_mobile

    calls = []

    def http(self, method, url, body, timeout):
        calls.append((method, url))
        assert url.startswith("https://sigex.kz/")
        if url.endswith("/api/egovQr"):
            return {"dataURL": "https://sigex.kz/api/egovQr/ID1", "signURL": "https://sigex.kz/api/egovQr/ID1",
                    "qrCode": "iVBORw0KGgo=", "eGovMobileLaunchLink": "https://m.egov.kz/mobileSign/?link=x",
                    "eGovBusinessLaunchLink": "https://m.egov.kz/businessSign/?link=x", "expireAt": 0}
        if method == "POST":
            calls.append(("docs", body))
            return {}
        return behaviour(calls[-2][1]["documentsToSign"])

    monkeypatch.setenv("EGOV_PROVIDER", "sigex")
    monkeypatch.setattr(egov_mobile.SigexAdapter, "_http", http)
    return calls


def _poll(c, url, want=("signed", "failed"), seconds=10):
    import time

    for _ in range(seconds * 10):
        j = c.get(url).json()
        if j["status"] in want:
            return j
        time.sleep(0.1)
    return j


def test_egov_login_through_sigex(monkeypatch):
    import base64 as b64

    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from fastapi.testclient import TestClient

    from app.db import SessionLocal, utcnow
    from app.main import app
    from app.modules.accounts.models import User
    from app.modules.documents import eds
    from app.modules.platform.models import FeatureFlag

    db = SessionLocal()
    flag = db.execute(select(FeatureFlag).where(FeatureFlag.key == "auth.egov_mobile")).scalar_one()
    was = flag.enabled
    flag.enabled = True
    key = ec.generate_private_key(ec.SECP256R1())
    spki = b64.b64encode(key.public_key().public_bytes(serialization.Encoding.DER,
                                                       serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
    user = db.execute(select(User).where(User.phone == "+77010000003")).scalar_one()
    iin = "990101300777"
    pem = eds.dev_issue(spki, full_name=user.full_name, iin=iin, bin_iin="")
    user.iin, user.eds_linked_at = iin, utcnow()
    db.commit()

    def signs(documents):
        challenge = b64.b64decode(documents[0]["document"]["file"]["data"])
        sig = b64.b64encode(key.sign(challenge, ec.ECDSA(hashes.SHA256()))).decode()
        pkg = json.dumps({"cert": pem, "sig": sig})
        return {"documentsToSign": [{"id": 1, "document": {"file": {"data": b64.b64encode(pkg.encode()).decode()}}}]}

    try:
        calls = _fake_sigex(monkeypatch, signs)
        from conftest import csrf_from

        browser = TestClient(app)
        tok = csrf_from(browser.get("/login").text)
        r = browser.post("/login/egov/start", headers={"X-CSRF-Token": tok})
        assert r.status_code == 200, r.text
        start = r.json()
        assert start["qr"].startswith("data:image/png;base64,") and "dev_api" not in start
        assert start["deeplinks"]["mgov"].startswith("https://m.egov.kz/mobileSign/")
        res = _poll(browser, start["status"])
        assert res["status"] == "signed", res
        assert browser.get("/account").status_code == 200
        sent = [c for c in calls if c[0] == "docs"][0][1]
        assert sent["signMethod"] == "CMS_SIGN_ONLY" and sent["version"] == 1

        # cancelled in the app
        _fake_sigex(monkeypatch, lambda documents: {"status": "CANCELED"})
        other = TestClient(app)
        tok = csrf_from(other.get("/login").text)
        start = other.post("/login/egov/start", headers={"X-CSRF-Token": tok}).json()
        res = _poll(other, start["status"])
        assert res["status"] == "failed" and "отменено" in res["message"]

        # SIGEX down at the start: a clear refusal, nothing half-made
        def down(self, method, url, body, timeout):
            raise OSError("down")

        from app.modules.accounts import egov_mobile

        monkeypatch.setattr(egov_mobile.SigexAdapter, "_http", down)
        egov_mobile._sigex().breaker.failures = 0
        r = other.post("/login/egov/start", headers={"X-CSRF-Token": tok, "Accept": "application/json"})
        assert r.status_code == 503
    finally:
        user.iin, user.eds_linked_at = "", None
        flag.enabled = was
        db.commit()
        db.close()


def test_lost_session_leads_to_login_not_a_dead_end(client_app):
    """A form sent with a session the server no longer knows (expired, another server's) is not a "forged form":
    the user goes back, then to the sign-in page, with a clear message; the error page carries the support code."""
    from fastapi.testclient import TestClient

    from app.main import app
    from app.web.deps import SESSION_COOKIE

    c = TestClient(app)
    c.cookies.set(SESSION_COOKIE, "no-such-session")
    r = c.post("/support/new", data={"csrf_token": "whatever", "subject": "x"},
               headers={"referer": "http://testserver/support"}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/support"
    page = c.get("/login").text
    assert "Сессия истекла" in page
    # a real CSRF failure (no session at all) stays a 403 with the support code shown
    anon = TestClient(app)
    r = anon.post("/support/new", data={"csrf_token": "forged"}, headers={"X-Request-ID": "abc123"})
    assert r.status_code == 403 and "abc123" in r.text
