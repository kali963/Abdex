"""Verification level L3 (section 8), driver re-verification (FR-KYC-09), exchange rates and multi-currency
(FR-LOC-04), Kazakh financial documents (FR-LOC-05)."""
from __future__ import annotations

import base64
import json
from datetime import timedelta
from decimal import Decimal

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy import select

from app.core.context import RequestContext, reset_ctx, set_ctx
from app.core.errors import AppError, Conflict, Forbidden
from app.core.timeutil import local_today
from app.db import SessionLocal, utcnow
from app.modules.accounts.models import Company, User
from app.modules.fleet.models import BiometricCheck, Driver, Vehicle, VerificationDocument
from app.modules.orders.models import Order


@pytest.fixture
def db(client_app):
    s = SessionLocal()
    tok = set_ctx(RequestContext(request_id="", extra={"rls_bypass": True}))
    yield s
    s.rollback()
    s.close()
    reset_ctx(tok)


def _company_package(company: Company, challenge: str, *, bin_iin: str | None = None) -> str:
    from app.modules.documents import eds

    key = ec.generate_private_key(ec.SECP256R1())
    spki = base64.b64encode(key.public_key().public_bytes(serialization.Encoding.DER,
                                                          serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
    pem = eds.dev_issue(spki, full_name="Директор", iin="000000000000", bin_iin=bin_iin or company.bin_iin)
    return json.dumps({"cert": pem, "sig": base64.b64encode(key.sign(challenge.encode(), ec.ECDSA(hashes.SHA256()))).decode()})


def _carrier_l2(db, name: str) -> tuple[Company, Vehicle, Driver]:
    from app.demo import make_bin

    c = Company(kind="carrier", name=name, bin_iin=make_bin(str(abs(hash(name)) % 10**11).zfill(11)), verification_level=2)
    db.add(c)
    db.flush()
    v = Vehicle(company_id=c.id, plate=f"{abs(hash(name)) % 900 + 100}KZ01", status="approved")
    d = Driver(company_id=c.id, full_name="Тестовый водитель", status="approved")
    db.add_all([v, d])
    db.flush()
    return c, v, d


# ------------------------------------------------------------------ section 8: L3


def test_level3_requirements_and_gate(login, db):
    from app.core.storage import save_generated
    from app.modules.accounts.eds_login import new_challenge
    from app.modules.bids.service import place_bid
    from app.modules.fleet import level3

    c, v, d = _carrier_l2(db, "ТОО «Усиленный тест»")
    items = {i["code"]: i for i in level3.requirements(db, c)}
    assert items["l2"]["ok"] and not items["eds"]["ok"] and not items["vehicles"]["ok"] and not items["biometrics"]["ok"]
    assert items["vehicles"]["missing"] == [v.plate]

    # the company EDS: a certificate of another BIN is refused, the company's own is accepted
    ch = new_challenge(db)
    with pytest.raises(AppError) as exc:
        level3.confirm_eds(db, c, _company_package(c, ch, bin_iin="990540001111"), ch)
    assert "owner" in exc.value.params["checks"]
    ch = new_challenge(db)
    with pytest.raises(AppError):  # a challenge is single-use
        level3.confirm_eds(db, c, _company_package(c, ch), ch + "x")
    ch = new_challenge(db)
    level3.confirm_eds(db, c, _company_package(c, ch), ch)
    assert c.eds_confirmed_at and c.verification_level == 2  # vehicles and drivers are still missing

    f = save_generated(db, data=b"%PDF-1.4 test", name="tp.pdf", content_type="application/pdf", company_id=c.id)
    db.add(VerificationDocument(company_id=c.id, subject_type="vehicle", subject_id=v.id, doc_type="tech_passport",
                                file_id=f.id, status="approved"))
    db.add(BiometricCheck(driver_id=d.id, company_id=c.id, provider="test", match=True, liveness=True, score=95,
                          status="passed", valid_until=local_today() + timedelta(days=30)))
    db.flush()
    assert level3.evaluate(db, c) == 3
    # a new vehicle without a passport takes L3 away again
    db.add(Vehicle(company_id=c.id, plate="000NEW01", status="approved"))
    db.flush()
    assert level3.evaluate(db, c) == 2

    # international cargo is for L3 carriers only
    intl = db.execute(select(Order).where(Order.cargo_name.contains("импорт КНР"))).scalar_one()
    if intl.status in ("published", "bidding"):
        with pytest.raises(Forbidden) as exc:
            place_bid(db, intl.id, c, {"price": "300000"})
        assert exc.value.code == "l3_required"
    assert level3.required_for(db, intl)
    db.rollback()

    owner = login("+77020000001")
    page = owner.get("/company/verification").text
    assert 'id="l3"' in page and "L3" in page


# ------------------------------------------------------------------ FR-KYC-09


def test_driver_reverification_signs(login, db):
    from app.modules.bids.service import place_bid
    from app.modules.deals.models import Deal
    from app.modules.fleet import reverify
    from app.modules.platform.models import AntifraudAlert, DeviceEvent

    c, v, d = _carrier_l2(db, "ТОО «Проверка водителя»")
    u = User(phone="+77059990011", full_name="Водитель Тест")
    db.add(u)
    db.flush()
    d.user_id = u.id
    # new device: the account has known devices and this one was never seen
    db.add(DeviceEvent(action="login", device_id="old-device", user_id=u.id, company_id=c.id))
    db.add(DeviceEvent(action="login", device_id="new-device", user_id=u.id, company_id=c.id))
    db.flush()
    reverify.on_login(db, u.id, "new-device")
    assert d.reverify_reason == "new_device" and d.reverify_since
    assert db.execute(select(AntifraudAlert).where(AntifraudAlert.kind == "driver_reverify",
                                                   AntifraudAlert.company_id == c.id)).first()
    with pytest.raises(Conflict):
        reverify.ensure_allowed(db, d.id)
    order = db.execute(select(Order).where(Order.status == "bidding", Order.is_international.is_(False))).scalars().first()
    if order is not None:
        c.verification_level = 1
        with pytest.raises(AppError) as exc:
            place_bid(db, order.id, c, {"price": "100000", "driver_id": str(d.id)})
        assert exc.value.fields.get("driver_id") == "error.driver_reverify_required"
    # a known device does not flag anyone
    d.reverify_reason, d.reverify_since = "", None
    db.add(DeviceEvent(action="login", device_id="old-device", user_id=u.id, company_id=c.id))  # this login's mark
    db.flush()
    reverify.on_login(db, u.id, "old-device")
    assert d.reverify_reason == ""

    # anomalous geography: a checkpoint near Moscow on an Almaty — Karaganda trip
    deal = db.execute(select(Deal).join(Order, Order.id == Deal.order_id)
                      .where(Deal.driver_id.is_not(None))).scalars().first()
    o = db.get(Order, deal.order_id)
    drv = db.get(Driver, deal.driver_id)
    drv.reverify_reason = ""
    reverify.on_checkpoint(db, deal, o, 43.3, 77.0)  # near Almaty — fine
    assert drv.reverify_reason == ""
    reverify.on_checkpoint(db, deal, o, 55.75, 37.62)
    assert drv.reverify_reason == "geo_anomaly"

    # long break: the previous deal of the driver is older than the threshold
    drv.reverify_reason = ""
    for old in db.execute(select(Deal).where(Deal.driver_id == drv.id)).scalars():
        old.created_at = utcnow() - timedelta(days=200)
    db.flush()
    reverify.on_assignment(db, drv.id)
    assert drv.reverify_reason == "long_break"
    db.rollback()

    # the driver sees why the repeated check is needed
    s = login("+77020000003")
    dbs = SessionLocal()
    d1 = dbs.execute(select(Driver).join(User, User.id == Driver.user_id).where(User.phone == "+77020000003")).scalar_one()
    d1.reverify_reason, d1.reverify_since = "new_device", utcnow()
    dbs.commit()
    try:
        assert "повторн" in s.get("/trips/biometrics").text.lower()
    finally:
        d1.reverify_reason, d1.reverify_since = "", None
        dbs.commit()
        dbs.close()


# ------------------------------------------------------------------ FR-LOC-04


def test_exchange_rates_and_foreign_currency_deal(login, db):
    from app.demo import _form
    from app.modules.analytics.service import client_analytics
    from app.modules.bids.service import accept, place_bid
    from app.modules.orders.service import create_order, submit
    from app.modules.platform import fx

    today = local_today()
    assert fx.rate_on(db, "KZT", today) == 1
    usd = fx.rate_on(db, "USD", today)
    assert usd == Decimal("478.50")  # development simulator
    # a manual rate (source unavailable) is kept and not overwritten by the feed
    fx.set_manual(db, today, "CNY", "67,10")
    db.commit()
    fx.load(db, today)
    assert fx.rate_on(db, "CNY", today) == Decimal("67.10")

    client = db.execute(select(Company).where(Company.name.contains("Агро Трейд"))).scalar_one()
    carrier = db.execute(select(Company).where(Company.name.contains("Жол Транс"))).scalar_one()
    before = client_analytics(db, client.id)["spend_minor"]
    form = _form([("Алматы", "ул. 1"), ("Тараз", "ул. 2")], "Валютная сделка", 5000, 0, 4)
    form["currency"] = "USD"
    order = create_order(db, client, form, rate_limited=False)
    submit(db, order)
    bid = place_bid(db, order.id, carrier, {"price": "1000"})
    deal = accept(db, bid.id, client)
    db.commit()
    assert deal.currency == "USD" and Decimal(deal.fx_rate) == usd and deal.fx_date == today
    assert fx.deal_kzt(deal) == 100_000 * 478.5  # 1 000.00 USD in tiyn
    after = client_analytics(db, client.id)["spend_minor"]
    assert after - before == fx.deal_kzt(deal)

    owner = login("+77010000001")
    assert "478.50" in owner.get(f"/deals/{deal.id}").text
    fin = login("finance@abdex.kz")
    page = fin.get("/admin/fx").text
    assert "USD" in page and "67.10" in page
    r = fin.post("/admin/fx", data={"on_date": today.isoformat(), "code": "EUR", "rate": "530.5"})
    assert r.status_code == 303
    assert owner.get("/admin/fx").status_code in (403, 404)


def test_percent_fee_on_foreign_currency_deal(db):
    from types import SimpleNamespace

    from app.modules.billing.service import compute_fee
    from app.modules.platform.fx import to_kzt_minor

    tariff = SimpleNamespace(model="percent", fixed_minor=0, percent_bp=300, min_minor=0, max_minor=0)
    base = to_kzt_minor(100_000, "USD", "478.50")
    amount, income, calc = compute_fee(tariff, base)
    assert amount == 1_435_500 and income == "platform_fee_variable"
    assert to_kzt_minor(100_000, "USD", "") is None and to_kzt_minor(5, "KZT", None) == 5


# ------------------------------------------------------------------ FR-LOC-05


def test_kazakh_financial_documents(db):
    from app.modules.billing.service import FEE_SUBJECT_KK
    from app.modules.documents.models import Document
    from app.modules.documents.service import generate, validate_template_body

    validate_template_body("fee_invoice", FEE_SUBJECT_KK.format(deal="SD-1"))  # no forbidden wording
    ctx = {"client_name": "ЖШС Тест", "client_bin": "123456789012", "subject": FEE_SUBJECT_KK.format(deal="SD-1"),
           "amount": "35 000 ₸", "deal_number": "SD-1", "due_date": "01.12.2026", "vat_note": "ҚҚС-сыз"}
    doc = generate(db, "fee_invoice", ctx, locale="kk")
    assert isinstance(doc, Document) and doc.title.startswith("Төлем шоты")
    act = generate(db, "fee_act", ctx, locale="kk")
    assert act.title.startswith("Көрсетілген қызметтер актісі")
    ru = generate(db, "fee_invoice", ctx, locale="ru")
    assert ru.title.startswith("Счет на оплату")
    db.rollback()
