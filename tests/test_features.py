"""SMS 2FA, security hardening and new ТЗ features."""
from __future__ import annotations

import io
import re

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.db import SessionLocal
from app.main import app
from app.modules.accounts.models import User
from app.modules.orders.models import Order
from conftest import PASSWORD, csrf_from


def _code_for(target: str) -> str:
    from app.modules.integrations.adapters import _OutboundAdapter

    for m in reversed(_OutboundAdapter.sent):
        if m["to"] == target:
            found = re.search(r"(\d{6})", m["body"])
            if found:
                return found.group(1)
    raise AssertionError("no code")


def _login(c: TestClient, who: str):
    return c.post("/login", data={"login": who, "password": PASSWORD, "csrf_token": csrf_from(c.get("/login").text)},
                  follow_redirects=False)


def test_sms_two_factor_full_cycle(client_app):
    phone = "+77010000003"  # accountant: not used by other tests for login state
    c = TestClient(app)
    assert _login(c, phone).headers["location"] == "/dashboard"
    tok = csrf_from(c.get("/account/security").text)
    # enable: code to the phone proves possession
    c.post("/account/2fa/sms/code", data={"csrf_token": tok, "action": "enable"})
    assert c.post("/account/2fa/sms/confirm", data={"csrf_token": tok, "action": "enable", "code": "000000"},
                  follow_redirects=False).status_code == 303
    db = SessionLocal()
    assert not db.execute(select(User).where(User.phone == phone)).scalar_one().sms_2fa_enabled
    c.post("/account/2fa/sms/confirm", data={"csrf_token": tok, "action": "enable", "code": _code_for(phone)})
    db.expire_all()
    assert db.execute(select(User).where(User.phone == phone)).scalar_one().sms_2fa_enabled

    # a new login now stops at the second factor and the code is sent automatically
    c2 = TestClient(app)
    r = _login(c2, phone)
    assert r.headers["location"] == "/login/2fa"
    assert c2.get("/dashboard", follow_redirects=False).headers["location"] == "/login/2fa"
    tok2 = csrf_from(c2.get("/login/2fa").text)
    assert c2.post("/login/2fa", data={"csrf_token": tok2, "code": "123456"}).status_code == 400
    r = c2.post("/login/2fa", data={"csrf_token": tok2, "code": _code_for(phone)}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/dashboard"
    assert c2.get("/dashboard").status_code == 200

    # disable again (also by SMS code) so the account stays usable for other tests
    tok3 = csrf_from(c2.get("/account/security").text)
    c2.post("/account/2fa/sms/code", data={"csrf_token": tok3, "action": "disable"})
    c2.post("/account/2fa/sms/confirm", data={"csrf_token": tok3, "action": "disable", "code": _code_for(phone)})
    db.expire_all()
    assert not db.execute(select(User).where(User.phone == phone)).scalar_one().sms_2fa_enabled
    db.close()


def test_totp_code_cannot_be_replayed():
    import pyotp

    from app.core.security import verify_totp

    secret = pyotp.random_base32()
    code = pyotp.TOTP(secret).now()
    step = verify_totp(secret, code)
    assert step is not None
    assert verify_totp(secret, code, last_step=step) is None


def test_dev_outbox_shows_only_own_messages(login):
    anon = TestClient(app)
    assert "code" not in anon.get("/dev/outbox").text.lower() or "+7701" not in anon.get("/dev/outbox").text
    s = login("+77020000002")
    page = s.get("/dev/outbox").text
    for other in ("+77010000001", "+77010000002", "+77030000001"):
        assert other not in page


def test_spoofed_forwarded_for_is_ignored(client_app):
    from app.core import ratelimit

    ratelimit.reset_all()
    c = TestClient(app)
    tok = csrf_from(c.get("/login").text)
    codes = []
    limit = ratelimit.LIMITS["login"][0]
    for i in range(limit + 2):  # a new fake IP every time must not reset the per-IP counter
        codes.append(c.post("/login", data={"login": f"+779990{i:05d}", "password": "x" * 12, "csrf_token": tok},
                            headers={"X-Forwarded-For": f"10.0.{i // 250}.{i % 250}"}).status_code)
    assert 429 in codes
    ratelimit.reset_all()


def test_request_id_is_sanitised(client_app):
    r = client_app.get("/", headers={"X-Request-ID": "abc\nInjected: 1<script>"})
    assert r.headers["x-request-id"] == "abcInjected1script"


def test_oversized_body_rejected(client_app):
    r = client_app.post("/login", content=b"x", headers={"content-length": str(500 * 1024 * 1024)})
    assert r.status_code == 413


def test_staff_cannot_open_deal_outside_admin(login):
    from app.modules.deals.models import Deal

    db = SessionLocal()
    deal = db.execute(select(Deal)).scalars().first()
    db.close()
    mgr = login("manager@abdex.kz")
    assert mgr.get(f"/deals/{deal.id}").status_code == 404
    assert mgr.get(f"/admin/deals/{deal.id}").status_code == 200


def test_order_import_all_or_nothing(login):
    from openpyxl import Workbook

    from app.modules.orders.importer import COLUMNS, EXAMPLE

    s = login("+77010000002")

    def xlsx(rows):
        wb = Workbook()
        ws = wb.active
        ws.append(list(COLUMNS))
        for row in rows:
            ws.append(list(row))
        buf = io.BytesIO()
        wb.save(buf)
        return buf.getvalue()

    db = SessionLocal()
    before = db.query(Order).count()
    bad = list(EXAMPLE)
    bad[5] = "не число"
    r = s.post("/orders/import", files={"file": ("o.xlsx", xlsx([EXAMPLE, bad]), "application/octet-stream")})
    assert r.status_code == 422 and "weight_kg" in r.text
    assert db.query(Order).count() == before  # nothing created
    r = s.post("/orders/import", files={"file": ("o.xlsx", xlsx([EXAMPLE, EXAMPLE]), "application/octet-stream")})
    assert r.status_code == 200
    db.expire_all()
    assert db.query(Order).count() == before + 2
    assert s.get("/orders/import/template.xlsx").content[:2] == b"PK"
    db.close()


def test_account_deletion_anonymises(client_app):
    from app.demo import make_bin

    c = TestClient(app)
    tok = csrf_from(c.get("/register").text)
    c.post("/register", data={"csrf_token": tok, "account_type": "driver", "full_name": "Временный Водитель",
                              "phone": "+7 707 000 11 22", "password": "Very-Strong-Pass-2026",
                              "bin_iin": make_bin("90010130012"), "consent_registration": "on"})
    tok = csrf_from(c.get("/account").text)
    r = c.post("/account/delete", data={"csrf_token": tok, "password": "Very-Strong-Pass-2026", "confirm": "on"},
               follow_redirects=False)
    assert r.status_code == 303
    db = SessionLocal()
    assert db.execute(select(User).where(User.phone == "+77070001122")).scalar_one_or_none() is None
    gone = db.execute(select(User).where(User.full_name == "Удалённый пользователь")).scalars().first()
    assert gone is not None and gone.email is None and gone.password_hash is None
    db.close()
    page = c.get("/login").text
    r = c.post("/login", data={"login": "+77070001122", "password": "Very-Strong-Pass-2026", "csrf_token": csrf_from(page)})
    assert r.status_code == 401


def test_telegram_webhook_requires_secret(client_app):
    r = client_app.post("/hooks/telegram", json={"message": {"text": "/start ABC", "chat": {"id": 1}}})
    assert r.status_code == 404
