"""Cycle 3 items: EDS login (FR-AUTH-09), paid modules and subscriptions (FR-BIL-08, FR-PVD-07),
cost forecast by direction (FR-CALC-06), link graph for the moderator (SEC-FRD-04)."""
from __future__ import annotations

import base64
import json
from datetime import timedelta

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.context import RequestContext, reset_ctx, set_ctx
from app.core.timeutil import local_today
from app.db import SessionLocal
from app.modules.accounts.models import BankAccount, Company, User
from app.modules.billing.models import Accrual, DigitalModule, Invoice, Subscription
from tests.conftest import csrf_from


@pytest.fixture
def db(client_app):
    s = SessionLocal()
    yield s
    s.rollback()
    s.close()


def _key():
    key = ec.generate_private_key(ec.SECP256R1())
    spki = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    return key, base64.b64encode(spki).decode()


def _package(key, cert: str, text: str) -> str:
    """What eds.js does with the WebCrypto key kept in IndexedDB: an r||s signature over the challenge."""
    r, s = decode_dss_signature(key.sign(text.encode(), ec.ECDSA(hashes.SHA256())))
    return json.dumps({"cert": cert, "sig": base64.b64encode(r.to_bytes(32, "big") + s.to_bytes(32, "big")).decode()})


def _challenge(post) -> str:
    r = post("/login/eds/challenge")
    assert r.status_code == 200, r.text
    return r.json()["challenge"]


# ------------------------------------------------------------------ FR-AUTH-09


def test_eds_login(login, db):
    owner = login("+77010000001")
    page = owner.get("/account/security").text
    assert "data-eds-auth" in page and "/account/eds/link" in page
    key, spki = _key()
    cert = owner.post("/dev/eds/login-certificate", data={"public_key": spki}).json()["certificate"]

    # binding needs a valid signature over a fresh challenge
    ch = _challenge(owner.post)
    bad = owner.post("/account/eds/link", data={"package": _package(key, cert, ch + "x"), "challenge": ch})
    assert bad.status_code == 303
    db.expire_all()
    user = db.execute(select(User).where(User.phone == "+77010000001")).scalar_one()
    assert user.eds_linked_at is None
    ch = _challenge(owner.post)
    r = owner.post("/account/eds/link", data={"package": _package(key, cert, ch), "challenge": ch})
    assert r.status_code == 303
    db.expire_all()
    user = db.get(User, user.id)
    assert user.eds_linked_at is not None and len(user.iin) == 12 and user.iin_index

    # anonymous browser: login page offers the EDS button; the signature logs the user in
    anon = TestClient(__import__("app.main", fromlist=["app"]).app)
    with anon:
        page = anon.get("/login").text
        assert "data-eds-auth" in page
        token = csrf_from(page)

        def post(url, data=None):
            return anon.post(url, data={**(data or {}), "csrf_token": token}, follow_redirects=False)

        ch = _challenge(post)
        r = post("/login/eds", {"package": _package(key, cert, ch), "challenge": ch, "next": "/finance"})
        assert r.status_code == 303 and r.headers["location"] != "/login", r.headers
        assert anon.get("/account").status_code == 200
        # the same challenge cannot be replayed
        anon.cookies.clear()
        page = anon.get("/login").text
        token = csrf_from(page)
        r = post("/login/eds", {"package": _package(key, cert, ch), "challenge": ch})
        assert r.headers["location"] == "/login"
        assert anon.get("/account", follow_redirects=False).status_code in (303, 401)
        # a certificate of a person without a bound EDS does not log anybody in
        other_key, other_spki = _key()
        logist = login("+77010000002")
        other_cert = logist.post("/dev/eds/login-certificate", data={"public_key": other_spki}).json()["certificate"]
        ch = _challenge(post)
        r = post("/login/eds", {"package": _package(other_key, other_cert, ch), "challenge": ch})
        assert r.headers["location"] == "/login"

    # unbinding; deleted accounts lose the IIN as well (FR-AUTH-10)
    assert owner.post("/account/eds/unlink").status_code == 303
    db.expire_all()
    assert db.get(User, user.id).iin == "" and db.get(User, user.id).iin_index == ""


# ------------------------------------------------------------------ FR-BIL-08, FR-PVD-07, FR-CALC-06


def _make_deals(cities, plan):
    """plan: [(company, price_kzt)]; returns created deal ids."""
    from tests.demo_data import _form
    from app.modules.bids.service import accept, place_bid
    from app.modules.orders.service import create_order, submit

    s = SessionLocal()
    carrier = s.execute(select(Company).where(Company.name.contains("Жол Транс"))).scalar_one()
    out = []
    try:
        for company_id, price in plan:
            client = s.get(Company, company_id)
            tok = set_ctx(RequestContext(request_id="test-setup", company_id=client.id, extra={"rls_bypass": True}))
            try:
                order = create_order(s, client, _form(cities, "Прогноз", 10000, 0, 5), rate_limited=False)
                submit(s, order)
                bid = place_bid(s, order.id, carrier, {"price": str(price)})
                out.append(accept(s, bid.id, client).id)
                s.commit()
            finally:
                reset_ctx(tok)
    finally:
        s.close()
    return out


def test_modules_subscription_and_forecast(login, db):
    from app.modules.billing import subscriptions
    from app.modules.billing.service import pvd_report
    from app.modules.platform.service import flag_enabled

    client = db.execute(select(Company).where(Company.name.contains("Агро Трейд"))).scalar_one()
    second = Company(kind="client", name="ТОО «Второй заказчик»", bin_iin="990540001234", verification_level=2,
                     legal_address="г. Караганда, ул. Ерубаева, 1")
    db.add(second)
    db.commit()
    cities = [("Аральск", "ул. Портовая, 1"), ("Жезказган", "ул. Металлургов, 2")]
    _make_deals(cities, [(client.id, 200000), (client.id, 220000), (second.id, 240000)])

    owner = login("+77010000001")
    page = owner.get("/calc/forecast").text
    assert "/modules" in page and "Медиана" not in page  # the module is not connected yet
    page = owner.get("/modules").text
    assert "Прогноз стоимости по направлениям" in page
    module = db.execute(select(DigitalModule).where(DigitalModule.code == "forecast")).scalar_one()

    logist = login("+77010000002")
    assert logist.post(f"/modules/{module.id}/subscribe").status_code == 403  # only the owner connects modules

    r = owner.post(f"/modules/{module.id}/subscribe")
    assert r.status_code == 303
    db.expire_all()
    sub = db.execute(select(Subscription).where(Subscription.company_id == client.id)).scalar_one()
    assert sub.status == "active" and sub.auto_renew
    acc = db.execute(select(Accrual).where(Accrual.event == f"subscription:{sub.id}:{sub.period_start.isoformat()}")).scalar_one()
    assert acc.income_type == "digital_modules" and acc.amount_minor == module.price_minor
    inv = db.get(Invoice, acc.invoice_id)
    assert inv.company_id == client.id and inv.deal_id is None and inv.document_id
    assert flag_enabled(db, "calc.forecast", client.id) and not flag_enabled(db, "calc.forecast", second.id)
    owner.post(f"/modules/{module.id}/subscribe")  # already active: refused, nothing charged twice
    db.expire_all()
    assert len(db.execute(select(Accrual).where(Accrual.event.like(f"subscription:{sub.id}:%"))).scalars().all()) == 1

    page = owner.get("/calc/forecast?from_city=аральск&to_city=Жезказган&distance_km=").text
    assert "Медиана" in page and "220" in page  # median of 200/220/240 thousand
    page = owner.get("/calc/forecast?from_city=Аральск&to_city=Атырау").text
    assert "недостаточно" in page.lower()

    # revenue is accounted separately in the PVD report
    today = local_today()
    rep = pvd_report(db, today - timedelta(days=1), today)
    assert rep["by_type"].get("digital_modules", 0) >= module.price_minor

    # switching off keeps the paid period; at its end the module expires
    assert owner.post(f"/modules/subscriptions/{sub.id}/auto-renew", data={"on": "0"}).status_code == 303
    db.expire_all()
    sub = db.get(Subscription, sub.id)
    assert sub.status == "cancelled" and flag_enabled(db, "calc.forecast", client.id)
    sub.period_start, sub.period_end = today - timedelta(days=30), today - timedelta(days=1)
    db.commit()
    subscriptions.renew_due(SessionLocal())
    db.expire_all()
    assert db.get(Subscription, sub.id).status == "expired" and not flag_enabled(db, "calc.forecast", client.id)

    # connected again with auto-renewal: the next period is charged by the worker
    owner.post(f"/modules/{module.id}/subscribe")
    db.expire_all()
    sub = db.get(Subscription, sub.id)
    sub.period_start, sub.period_end = today - timedelta(days=31), today - timedelta(days=2)
    db.commit()
    n_before = len(db.execute(select(Accrual).where(Accrual.event.like(f"subscription:{sub.id}:%"))).scalars().all())
    subscriptions.renew_due(SessionLocal())
    db.expire_all()
    sub = db.get(Subscription, sub.id)
    assert sub.status == "active" and sub.period_start == today - timedelta(days=1) and sub.period_end >= today
    n_after = len(db.execute(select(Accrual).where(Accrual.event.like(f"subscription:{sub.id}:%"))).scalars().all())
    assert n_after == n_before + 1
    subscriptions.renew_due(SessionLocal())  # idempotent
    db.expire_all()
    assert len(db.execute(select(Accrual).where(Accrual.event.like(f"subscription:{sub.id}:%"))).scalars().all()) == n_after

    # ESF of a module invoice names the module, not a deal
    from app.modules.billing.accounting import esf_xml

    assert "цифровому модулю" in esf_xml(db, inv).decode()

    # admin catalogue: price change applies to the next periods
    fin = login("finance@abdex.kz")
    assert "Прогноз стоимости" in fin.get("/admin/modules").text
    r = fin.post(f"/admin/modules/{module.id}", data={"name": module.name, "flag_key": "calc.forecast", "price": "6000",
                                                      "period_days": "30", "income_type": "digital_modules",
                                                      "audience": "any", "active": "1"})
    assert r.status_code == 303
    db.expire_all()
    assert db.get(DigitalModule, module.id).price_minor == 600_000
    assert owner.get("/admin/modules").status_code in (403, 404)


# ------------------------------------------------------------------ SEC-FRD-04


def test_link_graph(login, db):
    from app.modules.platform import linkgraph
    from app.modules.platform.models import DeviceEvent

    client = db.execute(select(Company).where(Company.name.contains("Агро Трейд"))).scalar_one()
    carrier2 = db.execute(select(Company).where(Company.name.contains("Сапаров"))).scalar_one()
    shell = Company(kind="carrier", name="ТОО «Подставная фирма»", bin_iin="990540009999", verification_level=1)
    db.add(shell)
    db.flush()
    db.add_all([DeviceEvent(action="login", device_id="dev-graph-1", ip="10.0.0.1", company_id=client.id),
                DeviceEvent(action="login", device_id="dev-graph-1", ip="10.0.0.2", company_id=carrier2.id)])
    iban = "KZ75125KZT2069100777"
    db.add_all([BankAccount(company_id=carrier2.id, iban=iban, status="active"),
                BankAccount(company_id=shell.id, iban=iban, status="active")])
    db.commit()

    g = linkgraph.build(db, client.id, depth=2)
    assert carrier2.id in g.nodes and shell.id in g.nodes  # shell is two steps away
    assert g.depth_of[shell.id] == 2
    edge = g.edges[tuple(sorted((carrier2.id, shell.id), key=str))]
    assert "iban" in edge
    assert shell.id not in linkgraph.build(db, client.id, depth=1).nodes

    mod = login("moderator@abdex.kz")
    page = mod.get(f"/admin/antifraud/graph?company={client.id}&depth=2").text
    assert "<svg" in page and "Подставная фирма" in page and "Сапаров" in page
    assert iban not in page and "dev-graph-1" not in page  # the link is shown, not the data
    assert "Подставная фирма" in mod.get("/admin/antifraud/graph?q=990540009999").text
    owner = login("+77010000001")
    assert owner.get(f"/admin/antifraud/graph?company={client.id}").status_code in (403, 404)
