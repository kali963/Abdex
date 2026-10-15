"""Cycle-2 requirements: rating & breakdowns, matching, occupancy, series, webhooks, notification schedule,
bulk document export, promo codes, editable permission matrix, support sessions and the trip map."""
from __future__ import annotations

import io
import json
import zipfile
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from app.core.context import RequestContext, reset_ctx, set_ctx
from app.core.errors import AppError, Forbidden, ValidationFailed
from app.db import SessionLocal, utcnow
from app.modules.accounts.models import AuditLog, Company, User
from app.modules.deals.models import Deal
from app.modules.orders.models import Order


@pytest.fixture
def db(client_app):
    s = SessionLocal()
    yield s
    s.rollback()
    s.close()


def _ctx(user_id=None, company_id=None):
    return set_ctx(RequestContext(request_id="test", ip="127.0.0.1", user_id=user_id, company_id=company_id))


def _company(db, name: str, kind: str = "carrier", level: int = 1) -> Company:
    from app.demo import make_bin

    c = Company(kind=kind, name=name, bin_iin=make_bin(str(abs(hash(name)) % 10**11).zfill(11)), verification_level=level)
    db.add(c)
    db.flush()
    return c


def _order(db, number_part: str) -> Order:
    return db.execute(select(Order).where(Order.cargo_name.contains(number_part))).scalars().first()


# ------------------------------------------------------------------ rating & breakdowns (FR-RAT-01/02, FR-BID-08)


def test_breakdowns_restrict_bidding_and_feed_rating(db):
    from app.modules.bids.service import place_bid
    from app.modules.platform.service import has_restriction
    from app.modules.rating import service as rating

    tok = _ctx()
    try:
        carrier = _company(db, "ТОО Срывы Тест")
        deal = db.execute(select(Deal)).scalars().first()
        assert rating.compute(db, carrier.id)["is_new"]
        fake = SimpleNamespace(id=deal.id, carrier_company_id=carrier.id, client_company_id=deal.client_company_id)
        rating.on_dispute_resolved(db, fake, outcome="cancelled", fault="carrier")
        rating.on_dispute_resolved(db, fake, outcome="cancelled", fault="carrier")  # idempotent per deal
        r = rating.compute(db, carrier.id)
        assert r["counts"]["breakdown"] == 1 and r["counts"]["dispute_lost"] == 1
        assert r["value"] is not None and r["value"] < 4.0
        assert not has_restriction(db, carrier.id, ("no_bids",))
        for _ in range(2):  # breakdowns without a deal reference (e.g. after manual review) count too
            rating.record(db, carrier.id, "breakdown", reason="test")
        assert has_restriction(db, carrier.id, ("no_bids",))
        order = _order(db, "Мука")
        with pytest.raises(Forbidden):
            place_bid(db, order.id, carrier, {"price": "500000"})
        # rating is never edited: corrections are events with a reason
        with pytest.raises(ValidationFailed):
            rating.correct(db, carrier.id, 0.5, "")
        before = rating.compute(db, carrier.id)["value"]
        rating.correct(db, carrier.id, 0.5, "Ошибка в оценке спора")
        assert rating.compute(db, carrier.id)["value"] == pytest.approx(min(5.0, before + 0.5), abs=0.011)
    finally:
        db.rollback()
        reset_ctx(tok)


def test_rating_page_explains_formula(login):
    s = login("+77020000001")
    html = s.get("/rating").text
    assert "Как считается рейтинг" in html and "Надежность" in html and "Как подбираются перевозчики" in html


# ------------------------------------------------------------------ matching (FR-BID-04)


def test_matching_ranks_and_invites(login, db):
    from app.modules.bids import matching
    from app.modules.notifications.models import Notification
    from app.modules.platform.service import set_setting

    order = _order(db, "Мука")
    ranked = matching.rank(db, order)
    names = [m.company.name for m in ranked]
    assert any("Жол Транс" in n for n in names)
    top = next(m for m in ranked if "Жол Транс" in m.company.name)
    assert top.parts["body"] == 100 and 0 < top.score <= 100
    # weights live in a setting: zeroing everything but "level" makes the score the verification level only
    tok = _ctx()
    set_setting(db, "matching.weights", {"body": 0, "geo": 0, "history": 0, "rating": 0, "level": 1, "load": 0})
    db.flush()
    assert next(m for m in matching.rank(db, order) if m.company.id == top.company.id).score == round(100 * 2 / 3)
    db.rollback()
    reset_ctx(tok)

    s = login("+77010000002")
    page = s.get(f"/orders/{order.id}").text
    assert "Рекомендованные перевозчики" in page
    r = s.post(f"/orders/{order.id}/invite/{top.company.id}")
    assert r.status_code == 303
    db.expire_all()
    owner = db.execute(select(User).where(User.phone == "+77020000001")).scalar_one()
    assert db.execute(select(Notification).where(Notification.user_id == owner.id,
                                                 Notification.event == "order.invited")).first()
    r = s.post(f"/orders/{order.id}/invite/{top.company.id}")  # second invitation is refused
    assert r.status_code == 303 and "flash" in r.headers.get("set-cookie", "")


# ------------------------------------------------------------------ occupancy (FR-PLAN-04)


def test_busy_vehicle_cannot_be_offered_for_overlapping_trip(db, login):
    from app.modules.bids.service import place_bid
    from app.modules.fleet.models import Vehicle

    carrier = db.execute(select(Company).where(Company.name.contains("Жол Транс"))).scalar_one()
    busy = db.execute(select(Vehicle).where(Vehicle.plate == "888TNT03")).scalar_one()  # on the in-transit deal
    free = db.execute(select(Vehicle).where(Vehicle.plate == "555REF02")).scalar_one()
    order = _order(db, "Мука")  # loads the day after that deal: intervals overlap
    tok = _ctx(company_id=carrier.id)
    try:
        with pytest.raises(ValidationFailed) as exc:
            place_bid(db, order.id, carrier, {"price": "600000", "vehicle_id": str(busy.id)})
        assert exc.value.fields == {"vehicle_id": "error.executor_busy"}
        bid = place_bid(db, order.id, carrier, {"price": "600000", "vehicle_id": str(free.id)})
        assert bid.vehicle_id == free.id
    finally:
        db.rollback()
        reset_ctx(tok)
    page = login("+77020000002").get("/fleet/schedule").text
    assert "888TNT03" in page and "slot busy" in page


# ------------------------------------------------------------------ series (FR-ORD-05)


def test_order_series_generates_once(login, db):
    from app.modules.orders.models import OrderSeries
    from app.modules.orders.series import generate_due

    s = login("+77010000002")
    order = _order(db, "Мука")
    start = (utcnow() + timedelta(days=1)).date()
    r = s.post(f"/orders/{order.id}/series", data={"name": "Мука еженедельно", "weekdays": ["1", "2", "3", "4", "5", "6", "7"],
                                                   "start_date": start.isoformat(), "lead_days": "2"})
    assert r.status_code == 303 and r.headers["location"] == "/orders/series"
    before = db.query(Order).count()
    created = generate_due(SessionLocal())
    assert created == 2  # tomorrow and the day after fall within the 2-day lead time
    db.expire_all()
    assert db.query(Order).count() == before + 2
    assert generate_due(SessionLocal()) == 0  # idempotent
    series = db.execute(select(OrderSeries).where(OrderSeries.name == "Мука еженедельно")).scalar_one()
    assert series.created_count == 2
    assert "Мука еженедельно" in s.get("/orders/series").text
    assert s.post(f"/orders/series/{series.id}/delete").status_code == 303


# ------------------------------------------------------------------ webhooks (FR-API-03)


def test_webhook_url_validation():
    from app.modules.webhooks.service import validate_url

    for bad in ("http://example.com/h", "https://localhost/h", "https://10.0.0.5/h", "https://169.254.169.254/x",
                "https://user:pass@example.com/", "https://example.com:22/", "ftp://example.com"):
        with pytest.raises(ValidationFailed):
            validate_url(bad)
    assert validate_url("https://hooks.example.com/abdex") == "https://hooks.example.com/abdex"


def test_webhooks_signed_retried_and_journaled(login, db, monkeypatch):
    from app.modules.webhooks import service as webhooks
    from app.modules.webhooks.models import WebhookDelivery, WebhookEndpoint

    s = login("+77020000001")
    r = s.post("/company/webhooks", data={"url": "https://hooks.example.com/abdex", "events": ["deal.status_changed"]})
    assert r.status_code == 303
    page = s.get("/company/webhooks").text
    assert "hooks.example.com" in page and "Секрет" in page
    ep = db.execute(select(WebhookEndpoint).where(WebhookEndpoint.url == "https://hooks.example.com/abdex")).scalar_one()

    deal = db.execute(select(Deal).where(Deal.carrier_company_id == ep.company_id)).scalars().first()
    tok = _ctx()
    webhooks.enqueue(db, [deal.carrier_company_id], "deal.status_changed", {"deal_id": str(deal.id), "to": "x"})
    webhooks.enqueue(db, [deal.carrier_company_id], "deal.checkpoint", {"deal_id": str(deal.id)})  # not subscribed
    db.commit()
    reset_ctx(tok)

    calls = []

    def fake_post(url, body, headers):
        calls.append((url, body, headers))
        return 500 if len(calls) == 1 else 204

    monkeypatch.setattr(webhooks, "_post", fake_post)
    webhooks.process(SessionLocal())
    db.expire_all()
    d = db.execute(select(WebhookDelivery).where(WebhookDelivery.endpoint_id == ep.id)).scalars().all()
    assert len(d) == 1 and d[0].status == "pending" and d[0].attempts == 1 and d[0].last_status_code == 500
    assert d[0].next_attempt_at > utcnow() + timedelta(seconds=50)  # growing pause
    url, body, headers = calls[0]
    assert webhooks.verify(ep.secret, body, headers["X-AbdEX-Signature"])
    assert not webhooks.verify("wrong", body, headers["X-AbdEX-Signature"])
    assert json.loads(body)["data"]["deal_id"] == str(deal.id)
    # due again: delivered
    d[0].next_attempt_at = utcnow() - timedelta(seconds=1)
    db.commit()
    webhooks.process(SessionLocal())
    db.expire_all()
    assert db.get(WebhookDelivery, d[0].id).status == "delivered"
    assert s.post(f"/company/webhooks/{ep.id}/delete").status_code == 303


def test_webhook_signature_rejects_replay():
    from app.modules.webhooks.service import sign, verify

    old = 1_700_000_000
    header = sign("s3cret", b"{}", old)
    assert verify("s3cret", b"{}", header, now=old + 10)
    assert not verify("s3cret", b"{}", header, now=old + 3600)


# ------------------------------------------------------------------ notifications schedule (FR-NTF-04)


def test_quiet_hours_cross_midnight():
    from app.modules.notifications.models import NotificationPrefs
    from app.modules.notifications.service import quiet_until

    p = NotificationPrefs(quiet_enabled=True, quiet_from="22:00", quiet_to="08:00")
    almaty_23 = datetime(2026, 10, 15, 18, 0, tzinfo=timezone.utc)  # 23:00 in Asia/Almaty (UTC+5)
    end = quiet_until(p, "Asia/Almaty", almaty_23)
    assert end == datetime(2026, 10, 16, 3, 0, tzinfo=timezone.utc)  # 08:00 local
    assert quiet_until(p, "Asia/Almaty", datetime(2026, 10, 15, 7, 0, tzinfo=timezone.utc)) is None  # 12:00 local
    p.quiet_enabled = False
    assert quiet_until(p, "Asia/Almaty", almaty_23) is None


def test_digest_collects_and_security_bypasses(login, db):
    from app.modules.notifications.models import NotificationPrefs, OutboxMessage
    from app.modules.notifications.service import notify_user, process_digests

    s = login("+77020000002")
    r = s.post("/account/notifications/schedule", data={"quiet_from": "22:00", "quiet_to": "08:00", "digest": "hourly",
                                                        "digest_hour": "9"})
    assert r.status_code == 303
    assert s.post("/account/notifications/schedule", data={"quiet_from": "25:00", "quiet_to": "08:00",
                                                           "digest": "off"}).status_code == 303  # rejected, flash
    user = db.execute(select(User).where(User.phone == "+77020000002")).scalar_one()
    prefs = db.execute(select(NotificationPrefs).where(NotificationPrefs.user_id == user.id)).scalar_one()
    assert prefs.digest == "hourly"
    tok = _ctx()
    for i in range(3):
        notify_user(db, user.id, "order.matching", {"number": f"T{i}", "route": "a → b"}, channels=["web", "push"],
                    dedup=f"digest-test-{i}")
    notify_user(db, user.id, "security.new_device", {"ip": "1.2.3.4"}, critical=True, dedup="digest-sec")
    db.commit()
    reset_ctx(tok)
    pending = db.execute(select(OutboxMessage).where(OutboxMessage.user_id == user.id,
                                                     OutboxMessage.status == "digest")).scalars().all()
    assert len(pending) == 3
    assert db.execute(select(OutboxMessage).where(OutboxMessage.user_id == user.id, OutboxMessage.event == "security.new_device",
                                                  OutboxMessage.status == "queued")).first()
    assert process_digests(SessionLocal()) >= 1
    db.expire_all()
    summary = db.execute(select(OutboxMessage).where(OutboxMessage.user_id == user.id, OutboxMessage.event == "digest")
                         ).scalars().all()
    assert summary and "3" in summary[0].body
    s.post("/account/notifications/schedule", data={"quiet_from": "22:00", "quiet_to": "08:00", "digest": "off"})


def test_notification_matrix_per_channel(login, db):
    from app.modules.notifications.models import ChannelLink

    s = login("+77020000002")
    assert "Тихие часы" in s.get("/account/notifications").text
    s.post("/account/notifications/prefs", data={"on:push:order.matching": "on", "on:email:chat.message": "on"})
    user = db.execute(select(User).where(User.phone == "+77020000002")).scalar_one()
    links = {cl.channel: cl for cl in db.execute(select(ChannelLink).where(ChannelLink.user_id == user.id)).scalars()}
    assert "order.matching" not in links["push"].disabled_events.split(",")
    assert "order.matching" in links["telegram"].disabled_events.split(",")
    assert "chat.message" not in links["email"].disabled_events.split(",")


# ------------------------------------------------------------------ documents by period (FR-DOC-09)


def test_documents_zip_by_period(login):
    s = login("+77010000001")
    today = utcnow().date()
    r = s.get(f"/documents/export.zip?date_from={(today - timedelta(days=30)).isoformat()}&date_to={today.isoformat()}")
    assert r.status_code == 200 and r.headers["content-type"] == "application/zip"
    z = zipfile.ZipFile(io.BytesIO(r.content))
    names = z.namelist()
    assert "inventory.csv" in names and any(n.endswith(".pdf") for n in names)
    inventory = z.read("inventory.csv").decode("utf-8-sig")
    assert "SHA-256" in inventory
    # a carrier never receives the client's platform fee invoices
    c = login("+77020000001")
    z2 = zipfile.ZipFile(io.BytesIO(c.get(f"/documents/export.zip?date_from={(today - timedelta(days=30)).isoformat()}").content))
    assert not any("fee_invoice" in n or "fee_act" in n for n in z2.namelist())
    # logist has no bulk export right (FR-ACL-07)
    assert login("+77010000002").get("/documents/export.zip").status_code == 403


# ------------------------------------------------------------------ promo codes (FR-BIL-09)


def test_promo_codes(login, db):
    from app.modules.billing.models import PromoCode
    from app.modules.billing.service import apply_promo

    admin = login("finance@abdex.kz")
    r = admin.post("/admin/promo", data={"code": "start-50", "kind": "percent", "value": "50", "max_uses": "1",
                                         "deals_per_company": "1"})
    assert r.status_code == 303
    promo = db.execute(select(PromoCode).where(PromoCode.code == "START-50")).scalar_one()
    client = login("+77010000001")
    assert client.post("/finance/promo", data={"code": "start-50"}).status_code == 303
    db.expire_all()
    assert db.get(PromoCode, promo.id).uses == 1
    client_co = db.execute(select(Company).where(Company.name.contains("Агро"))).scalars().first() or \
        db.execute(select(Company).where(Company.kind == "client")).scalars().first()
    tok = _ctx()
    amount, calc = apply_promo(db, client_co.id, utcnow().date(), 3_500_000, {"result_minor": 3_500_000})
    assert amount == 1_750_000 and calc["discount_minor"] == 1_750_000 and calc["promo"] == "START-50"
    amount2, _ = apply_promo(db, client_co.id, utcnow().date(), 3_500_000, {})
    assert amount2 == 3_500_000  # one discounted deal per company
    db.rollback()
    reset_ctx(tok)
    # exhausted: nobody else can redeem it
    tok = _ctx()
    with pytest.raises(ValidationFailed):
        from app.modules.billing.service import redeem_promo

        redeem_promo(db, _company(db, "ТОО Второй клиент", kind="client"), "START-50")
    db.rollback()
    reset_ctx(tok)
    # leave the demo client without a discount for the other end-to-end tests
    from sqlalchemy import delete

    from app.modules.billing.models import PromoRedemption

    db.execute(delete(PromoRedemption).where(PromoRedemption.promo_id == promo.id))
    db.commit()


# ------------------------------------------------------------------ permission matrix (FR-ACL-06)


def test_permission_matrix_is_editable(login, db):
    from app.modules.accounts import acl
    from app.modules.accounts import permissions as P

    logist = login("+77010000002")
    assert logist.get("/calc").status_code == 200
    admin = login("admin@abdex.kz")
    assert admin.get("/admin/permissions?scope=client").status_code == 200
    grants = {(r, p) for r, p in acl.grants(db) if p in P.COMPANY_PERMISSIONS and r in ("owner", "logist", "accountant")}
    keep = {f"g:{r}:{p}": "on" for r, p in grants if (r, p) != ("logist", "calc.use")}
    keep.pop("g:owner:company.manage", None)  # locked grant survives even if the form omits it
    assert admin.post("/admin/permissions", data={"scope": "client", **keep}).status_code == 303
    assert logist.get("/calc").status_code == 403
    assert P.company_can("owner", "company.manage")
    assert db.execute(select(AuditLog).where(AuditLog.action == "acl.matrix_changed")).first()
    admin.post("/admin/permissions", data={"scope": "client", **keep, "g:logist:calc.use": "on"})
    assert logist.get("/calc").status_code == 200

    r = admin.post("/admin/permissions/roles", data={"code": "senior_logist", "scope": "client", "name_ru": "Старший логист"})
    assert r.status_code == 303
    assert "senior_logist" in P.roles_in_scope("client")
    assert admin.post("/admin/permissions/roles", data={"code": "X!", "scope": "client", "name_ru": "x"}).status_code == 303
    assert "x!" not in P.roles_in_scope("client")


# ------------------------------------------------------------------ support session (FR-ADM-05)


def test_impersonation_needs_consent_and_is_journaled(login, db):
    from fastapi.testclient import TestClient

    from app.main import app
    from conftest import PASSWORD, csrf_from

    target = db.execute(select(User).where(User.phone == "+77010000002")).scalar_one()
    mgr = login("manager@abdex.kz")
    r = mgr.post(f"/admin/users/{target.id}/impersonate", data={"reason": "Проверка обращения AX-1"})
    assert r.status_code == 403  # no consent, manager cannot use the regulation basis

    user = login("+77010000002")
    assert user.post("/account/support-access", data={"hours": "4"}).status_code == 303

    c = TestClient(app)
    page = c.get("/login").text
    c.post("/login", data={"login": "manager@abdex.kz", "password": PASSWORD, "csrf_token": csrf_from(page)})
    tok = csrf_from(c.get("/admin").text)
    r = c.post(f"/admin/users/{target.id}/impersonate", data={"csrf_token": tok, "reason": "Проверка обращения AX-1"},
               follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/dashboard"
    html = c.get("/dashboard").text
    assert "Сеанс поддержки" in html
    tok = csrf_from(html)
    r = c.post("/account/password", data={"csrf_token": tok, "current_password": PASSWORD, "new_password": "x" * 14},
               follow_redirects=False)
    assert r.status_code == 403
    assert "otpauth" not in c.get("/account/security").text  # no authenticator secret for support
    db.expire_all()
    rows = db.execute(select(AuditLog).where(AuditLog.action == "impersonation.request")).scalars().all()
    assert any(json.loads(a.details)["path"] == "/account/password" and a.result == "denied" for a in rows)
    r = c.post("/impersonation/end", data={"csrf_token": tok}, follow_redirects=False)
    assert r.headers["location"] == "/admin/users"
    assert c.get("/admin").status_code == 200  # staff session restored
    user.post("/account/support-access/revoke")


# ------------------------------------------------------------------ trip map (FR-TRK-04)


def test_trip_map_on_deal_card(login, db):
    from app.modules.deals.tracking import trip_map

    deal = db.execute(select(Deal).join(Order, Order.id == Deal.order_id).where(Order.status == "in_transit")
                      ).scalars().first()
    order = db.get(Order, deal.order_id)
    from app.modules.deals.service import checkpoints

    m = trip_map(deal, order, checkpoints(db, deal.id))
    assert m and m["current"] and m["planned"] and m["eta"] is not None
    html = login("+77010000001").get(f"/deals/{deal.id}").text
    assert "Карта рейса" in html and "<svg" in html and "route-track" in html


def test_app_error_codes_have_texts():
    import re
    from pathlib import Path

    ru = json.loads(Path("app/i18n/ru.json").read_text())
    kk = json.loads(Path("app/i18n/kk.json").read_text())
    code = "\n".join(p.read_text() for p in Path("app").rglob("*.py"))
    codes = set(re.findall(r'(?:Forbidden|Conflict|AppError)\(\s*"([a-z0-9_]+)"', code))
    missing = sorted(c for c in codes if f"error.{c}" not in ru)
    assert not missing, missing
    # FR-LOC-01: the whole interface exists in Kazakh, with the same placeholders
    assert not [k for k in ru if k not in kk]
    ph = re.compile(r"\{(\w+)\}")
    assert not [k for k in ru if set(ph.findall(ru[k])) != set(ph.findall(kk[k]))]
    assert AppError  # imported for the error classes above
