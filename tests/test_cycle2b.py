"""Cycle 2, part 2: second-person approval, antifraud rules and velocity, device marks, retention, security
correlation and report, metrics, configurable limits, plan/fact upload, product funnels, webhook replay."""
from __future__ import annotations

import io
import json
import time
from datetime import timedelta

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core import ratelimit
from app.core.context import RequestContext, reset_ctx, set_ctx
from app.core.errors import RateLimited
from app.db import SessionLocal, utcnow
from app.main import app
from app.modules.accounts.models import AuditLog, Company, User
from app.modules.orders.models import Order
from app.modules.platform.models import AntifraudAlert, ApprovalRequest, Restriction, SecurityAlert
from conftest import PASSWORD, csrf_from


@pytest.fixture
def set_setting_attr():
    """settings is a frozen dataclass: patch attributes explicitly and restore them."""
    from app.config import settings

    saved = {}

    def _set(name, value):
        saved.setdefault(name, getattr(settings, name))
        object.__setattr__(settings, name, value)

    yield _set
    for name, value in saved.items():
        object.__setattr__(settings, name, value)


@pytest.fixture
def db(client_app):
    s = SessionLocal()
    yield s
    s.rollback()
    s.close()


def _ctx(**kw):
    return set_ctx(RequestContext(request_id="test", ip=kw.pop("ip", "127.0.0.1"), **kw))


def _company(db, name: str, kind: str = "carrier", level: int = 1) -> Company:
    from app.demo import make_bin

    c = Company(kind=kind, name=name, bin_iin=make_bin(str(abs(hash(name)) % 10**11).zfill(11)), verification_level=level)
    db.add(c)
    db.commit()
    return c


def _pending(db, kind):
    db.expire_all()
    return db.execute(select(ApprovalRequest).where(ApprovalRequest.kind == kind, ApprovalRequest.status == "pending")
                      .order_by(ApprovalRequest.created_at.desc())).scalars().first()


# ------------------------------------------------------------------ SEC-AZ-05


def test_company_block_needs_second_person(login, db):
    target = _company(db, "ТОО Блокировка Тест")
    mod = login("moderator@abdex.kz")
    r = mod.post(f"/admin/companies/{target.id}/restrict", data={"kind": "block", "reason": "Подозрение на мошенничество"})
    assert r.status_code == 303
    db.expire_all()
    assert not db.get(Company, target.id).is_blocked  # nothing happened yet
    req = _pending(db, "company_block")
    assert req and req.object_id == str(target.id)
    assert mod.post(f"/admin/approvals/{req.id}", data={"decision": "approve"}).status_code == 403  # same person
    fin = login("finance@abdex.kz")
    assert fin.post(f"/admin/approvals/{req.id}", data={"decision": "approve"}).status_code == 403  # no right
    admin = login("admin@abdex.kz")
    assert "Подозрение на мошенничество" in admin.get("/admin/approvals").text
    assert admin.post(f"/admin/approvals/{req.id}", data={"decision": "approve"}).status_code == 303
    db.expire_all()
    assert db.get(Company, target.id).is_blocked
    assert db.get(ApprovalRequest, req.id).status == "executed"
    assert db.execute(select(Restriction).where(Restriction.company_id == target.id, Restriction.kind == "block")).first()
    assert admin.post(f"/admin/approvals/{req.id}", data={"decision": "approve"}).status_code == 303  # already decided


def test_tariff_and_rollback_go_through_approval(login, db):
    from app.modules.billing.models import Tariff
    from app.modules.orders import service as orders

    fin = login("finance@abdex.kz")
    before = db.query(Tariff).count()
    fin.post("/admin/finance/tariffs", data={"name": "Пилот 2027", "model": "fixed", "fixed": "30000", "percent": "0",
                                             "min": "0", "max": "0", "deal_type": "any", "valid_from": "2027-01-01",
                                             "reason": "Решение правления №5"})
    assert db.query(Tariff).count() == before
    req = _pending(db, "tariff_change")
    admin = login("admin@abdex.kz")
    admin.post(f"/admin/approvals/{req.id}", data={"decision": "approve"})
    db.expire_all()
    assert db.query(Tariff).count() == before + 1

    client = db.execute(select(Company).where(Company.kind == "client")).scalars().first()
    tok = _ctx(company_id=client.id)
    from app.demo import _form

    order = orders.create_order(db, client, _form([("Алматы", ""), ("Астана", "")], "Тест отката", 1000, 0, 5),
                                rate_limited=False)
    orders.submit(db, order)
    db.commit()
    reset_ctx(tok)
    assert order.status == "published"
    mgr = login("manager@abdex.kz")
    mgr.post(f"/admin/orders/{order.id}/rollback", data={"to": "moderation", "reason": "Ошибка модерации"})
    db.expire_all()
    assert db.get(Order, order.id).status == "published"
    req = _pending(db, "status_rollback")
    r = admin.post(f"/admin/approvals/{req.id}", data={"decision": "approve", "note": "ok"})
    assert r.status_code == 303
    db.expire_all()
    assert db.get(Order, order.id).status == "moderation"
    # an invalid target is refused at request time
    r = mgr.post(f"/admin/orders/{order.id}/rollback", data={"to": "completed", "reason": "x"})
    assert r.status_code == 303 and _pending(db, "status_rollback") is None


# ------------------------------------------------------------------ SEC-FRD-01..03, SEC-APP-07


def test_antifraud_rules_are_configurable(login, db):
    from app.modules.platform.antifraud import track
    from app.modules.platform.models import AntifraudRule
    from app.modules.platform.service import raise_alert

    admin = login("admin@abdex.kz")
    assert admin.get("/admin/antifraud/rules").status_code == 200
    leak = db.execute(select(AntifraudRule).where(AntifraudRule.code == "contact_leak_attempt")).scalar_one()
    admin.post(f"/admin/antifraud/rules/{leak.id}", data={"action": "allow", "severity": "low"})  # disabled + allow
    db.expire_all()
    carrier = _company(db, "ТОО Скорость Тест")
    tok = _ctx(company_id=carrier.id)
    try:
        assert raise_alert(db, "contact_leak_attempt", company_id=carrier.id) is None
        rule = db.execute(select(AntifraudRule).where(AntifraudRule.code == "velocity_bids")).scalar_one()
        admin.post(f"/admin/antifraud/rules/{rule.id}", data={"enabled": "on", "action": "restrict", "severity": "high",
                                                              "threshold": "2", "window_minutes": "60"})
        db.expire_all()
        for _ in range(3):
            track(db, "bid", company_id=carrier.id)
        alert = db.execute(select(AntifraudAlert).where(AntifraudAlert.company_id == carrier.id,
                                                        AntifraudAlert.kind == "velocity_bids")).scalar_one()
        assert alert.severity == "high"
        assert db.execute(select(Restriction).where(Restriction.company_id == carrier.id,
                                                    Restriction.kind == "no_bids")).first()  # action "restrict"
        db.commit()
    finally:
        reset_ctx(tok)
    admin.post(f"/admin/antifraud/rules/{rule.id}", data={"enabled": "on", "action": "flag", "severity": "medium",
                                                          "threshold": "40", "window_minutes": "60"})
    admin.post(f"/admin/antifraud/rules/{leak.id}", data={"enabled": "on", "action": "flag", "severity": "low"})
    assert db.execute(select(AuditLog).where(AuditLog.action == "antifraud.rule_changed")).first()


def test_shared_device_between_unrelated_companies(client_app, db):
    from app.web.deps import DEVICE_COOKIE

    device = "test-device-shared-01"
    for who in ("+77010000003", "+77030000001"):
        c = TestClient(app)
        c.cookies.set(DEVICE_COOKIE, device)
        tok = csrf_from(c.get("/login").text)
        assert c.post("/login", data={"login": who, "password": PASSWORD, "csrf_token": tok},
                      follow_redirects=False).status_code == 303
    db.expire_all()
    assert db.execute(select(AntifraudAlert).where(AntifraudAlert.kind == "shared_device")).first()


def test_rate_limits_come_from_settings():
    ratelimit.configure({"bid": [1, 3600], "unknown": [1, 1], "export": "bad"})
    try:
        ratelimit.hit("bid", "x")
        with pytest.raises(RateLimited):
            ratelimit.hit("bid", "x")
        assert ratelimit._limits("export") == ratelimit.DEFAULTS["export"]
    finally:
        ratelimit.configure({})
        ratelimit.reset_all()


# ------------------------------------------------------------------ SEC-DAT-06


def test_retention_purges_expired_rows(db):
    from app.modules.accounts.models import OtpCode
    from app.modules.platform.models import DeviceEvent
    from app.modules.platform.retention import run

    old = utcnow() - timedelta(days=400)
    db.add(OtpCode(target="+70000000000", purpose="x", code_hash="0" * 64, expires_at=old, created_at=old))
    db.add(DeviceEvent(action="login", device_id="old", created_at=old))
    fresh = DeviceEvent(action="login", device_id="fresh")
    db.add(fresh)
    db.commit()
    counts = run(SessionLocal())
    assert counts["otp_codes"] >= 1 and counts["device_events"] >= 1
    db.expire_all()
    assert db.execute(select(DeviceEvent).where(DeviceEvent.device_id == "old")).first() is None
    assert db.get(DeviceEvent, fresh.id) is not None
    entry = db.execute(select(AuditLog).where(AuditLog.action == "retention.purged")).scalars().first()
    assert dict(json.loads(entry.details)["purged"])["otp_codes"] >= 1


# ------------------------------------------------------------------ SEC-LOG-06/08, access journal


def test_security_correlation_and_report(login, db):
    from app.modules.platform.security import scan

    c = TestClient(app)
    for _ in range(6):
        tok = csrf_from(c.get("/login").text)
        c.post("/login", data={"login": "+77020000003", "password": "wrong-password", "csrf_token": tok})
        ratelimit.reset_all()
    logist = login("+77010000002")
    assert logist.get("/finance").status_code == 403
    db.expire_all()
    assert db.execute(select(AuditLog).where(AuditLog.action == "access.denied")).first()
    scan(SessionLocal())
    db.expire_all()
    kinds = {a.kind for a in db.execute(select(SecurityAlert)).scalars()}
    assert "failed_logins" in kinds
    auditor = login("auditor@abdex.kz")
    page = auditor.get("/admin/security").text
    assert "Отчет по безопасности" in page
    r = auditor.get("/admin/security/report.pdf")
    assert r.status_code == 200 and r.content[:4] == b"%PDF"
    alert = db.execute(select(SecurityAlert).where(SecurityAlert.status == "open")).scalars().first()
    assert auditor.post(f"/admin/security/{alert.id}/close").status_code == 303
    assert login("+77010000001").get("/admin/security").status_code == 404


# ------------------------------------------------------------------ NFR-OBS-01/02


def test_metrics_endpoint(client_app, set_setting_attr):
    assert client_app.get("/metrics").status_code == 404
    set_setting_attr("metrics_token", "t0ken-for-tests")
    assert client_app.get("/metrics", headers={"Authorization": "Bearer nope"}).status_code == 404
    r = client_app.get("/metrics", headers={"Authorization": "Bearer t0ken-for-tests"})
    assert r.status_code == 200
    body = r.text
    for metric in ("abdex_http_requests_total", "abdex_orders{", "abdex_moderation_queue", "abdex_notification_delay_seconds",
                   "abdex_deals_created_last_hour", "abdex_http_request_seconds_bucket"):
        assert metric in body, metric


# ------------------------------------------------------------------ FR-PLAN-03


def test_plan_upload_and_fact(login, db):
    from openpyxl import Workbook

    s = login("+77010000002")

    def xlsx(rows):
        wb = Workbook()
        ws = wb.active
        ws.append(["from_city", "to_city", "trips", "weight_kg"])
        for row in rows:
            ws.append(list(row))
        buf = io.BytesIO()
        wb.save(buf)
        return buf.getvalue()

    today = utcnow().date()
    period = {"name": "План месяца", "period_from": (today - timedelta(days=10)).isoformat(),
              "period_to": (today + timedelta(days=30)).isoformat()}
    bad = s.post("/plan/periods", data=period,
                 files={"file": ("p.xlsx", xlsx([("Алматы", "Астана", "много", 1)]), "application/octet-stream")})
    assert bad.status_code == 422 and "trips" in bad.text
    r = s.post("/plan/periods", data=period, files={"file": ("p.xlsx", xlsx([("Алматы", "Караганда", 3, 45000),
                                                                             ("Хоргос", "Алматы", 2, 0),
                                                                             ("Алматы", "Тараз", 1, 0)]),
                                                             "application/octet-stream")})
    assert r.status_code == 303
    page = s.get(r.headers["location"]).text
    assert "План месяца" in page and "Караганда" in page
    from app.modules.orders.models import ShipmentPlan
    from app.modules.orders.plan import plan_vs_fact

    plan = db.execute(select(ShipmentPlan).where(ShipmentPlan.name == "План месяца")).scalar_one()
    pf = plan_vs_fact(db, plan)
    assert pf["total_plan"] == 6
    by_dir = {(r.line.from_city, r.line.to_city): r for r in pf["lines"]}
    assert by_dir[("Алматы", "Тараз")].fact_trips == 0 and by_dir[("Алматы", "Тараз")].deviation == -1
    assert pf["total_fact"] >= 1  # the demo deal Almaty -> Karaganda is in the period
    assert s.get("/plan/periods/template.xlsx").content[:2] == b"PK"


# ------------------------------------------------------------------ FR-BI-07


def test_product_funnels(login, client_app, db):
    from app.modules.platform.models import ProductEvent

    before = db.query(ProductEvent).filter(ProductEvent.name == "register_view").count()
    client_app.get("/register?type=carrier")
    db.expire_all()
    assert db.query(ProductEvent).filter(ProductEvent.name == "register_view").count() == before + 1
    ev = db.execute(select(ProductEvent).order_by(ProductEvent.created_at.desc())).scalars().first()
    assert len(ev.anon_id) == 16 and ev.role == "carrier"  # no personal data in events
    page = login("manager@abdex.kz").get("/admin/funnels").text
    assert "Регистрация" in page


# ------------------------------------------------------------------ SEC-APP-12


def test_telegram_hook_rejects_old_and_replayed_updates(client_app, db, set_setting_attr):
    from app.modules.notifications.models import ChannelLink

    set_setting_attr("telegram_webhook_secret", "hook-secret")
    user = db.execute(select(User).where(User.phone == "+77010000003")).scalar_one()
    link = ChannelLink(user_id=user.id, channel="telegram", link_code="REPLAY01")
    db.add(link)
    db.commit()
    h = {"X-Telegram-Bot-Api-Secret-Token": "hook-secret"}
    old = {"update_id": 9001, "message": {"text": "/start REPLAY01", "chat": {"id": 555}, "date": int(time.time()) - 3600}}
    client_app.post("/hooks/telegram", json=old, headers=h)
    db.expire_all()
    assert db.get(ChannelLink, link.id).address == ""
    fresh = {"update_id": 9002, "message": {"text": "/start REPLAY01", "chat": {"id": 555}, "date": int(time.time())}}
    link_obj = db.get(ChannelLink, link.id)
    client_app.post("/hooks/telegram", json=fresh, headers=h)
    db.expire_all()
    assert db.get(ChannelLink, link.id).address == "555"
    # the same update again is ignored even if the code were reissued
    link_obj = db.get(ChannelLink, link.id)
    link_obj.address, link_obj.link_code = "", "REPLAY01"
    db.commit()
    client_app.post("/hooks/telegram", json=fresh, headers=h)
    db.expire_all()
    assert db.get(ChannelLink, link.id).address == ""
