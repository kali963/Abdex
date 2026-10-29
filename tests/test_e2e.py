"""End-to-end and security acceptance tests (OPS-21, SEC-TST-02/03)."""
from __future__ import annotations

import re
from datetime import timedelta

from sqlalchemy import select

from app.core.i18n import to_local_input
from app.db import SessionLocal, utcnow
from app.modules.accounts.models import AuditLog, Company, User
from app.modules.billing.models import Accrual, Invoice
from app.modules.deals.models import Deal, DealSnapshot
from app.modules.documents.models import Document
from app.modules.orders.models import Order

CLIENT_OWNER = "+77010000001"
CLIENT_LOGIST = "+77010000002"
CARRIER_OWNER = "+77020000001"
CARRIER2_OWNER = "+77030000001"
DRIVER = "+77020000003"


def _order_form(city_from="Алматы", city_to="Астана", rate="500000"):
    load = utcnow() + timedelta(days=2)
    return {"cargo_name": "Тестовый груз", "cargo_type": "general", "weight_kg": "10000", "body_type": "tent",
            "desired_rate": rate, "currency": "KZT", "payment_terms": "on_unload", "vat_included": "on",
            "load_from": to_local_input(load), "unload_to": to_local_input(load + timedelta(days=3)),
            "point_kind": ["load", "unload"], "point_city": [city_from, city_to],
            "point_address": ["ул. Секретная, 1", "пр. Тайный, 2"], "point_contact_name": ["Иван", "Петр"],
            "point_contact_phone": ["+77011111111", "+77022222222"], "action": "publish"}


def _db():
    return SessionLocal()


def _latest_otp_code(target_hint: str) -> str:
    from app.modules.integrations.adapters import _OutboundAdapter

    for m in reversed(_OutboundAdapter.sent):
        if m["to"] == target_hint:
            found = re.search(r"код (\d{6})", m["body"])
            if found:
                return found.group(1)
    raise AssertionError("no code sent")


def test_security_headers_and_error_format(client_app):
    r = client_app.get("/")
    assert r.status_code == 200
    for h in ("content-security-policy", "x-content-type-options", "referrer-policy", "x-frame-options", "x-request-id"):
        assert h in r.headers
    assert "unsafe-inline" not in r.headers["content-security-policy"].split("script-src")[1].split(";")[0]
    r = client_app.get("/api/v1/orders")
    assert r.status_code == 401
    body = r.json()["error"]
    assert set(body) == {"code", "message", "fields", "request_id"}


def test_csrf_required(login):
    s = login(CLIENT_LOGIST)
    r = s.c.post("/orders/new", data=_order_form(), follow_redirects=False)
    assert r.status_code == 403


def test_login_failure_is_generic_and_throttled(client_app):
    page = client_app.get("/login").text
    tok = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
    r1 = client_app.post("/login", data={"login": "+77010000001", "password": "wrong-password!", "csrf_token": tok})
    r2 = client_app.post("/login", data={"login": "+77999999999", "password": "wrong-password!", "csrf_token": tok})
    assert r1.status_code == r2.status_code == 401
    codes = [client_app.post("/login", data={"login": "+77010000001", "password": "x" * 12, "csrf_token": tok}).status_code
             for _ in range(8)]
    assert 429 in codes


def test_full_deal_lifecycle(login):
    client = login(CLIENT_LOGIST)
    r = client.post("/orders/new", data=_order_form())
    assert r.status_code == 303
    order_id = r.headers["location"].rsplit("/", 1)[1]
    db = _db()
    order = db.get(Order, __import__("uuid").UUID(order_id))
    assert order.status == "published" and order.distance_km > 0

    # carrier sees a limited card: no exact addresses / contacts (FR-ACL-02)
    carrier = login(CARRIER_OWNER)
    card = carrier.get(f"/market/{order_id}")
    assert card.status_code == 200
    assert "ул. Секретная" not in card.text and "+77011111111" not in card.text
    api = carrier.get("/api/v1/market", headers={"x-csrf-token": carrier.csrf})
    assert all(p["address"] is None for o in api.json()["items"] for p in o["points"])

    # bid (first bid moves to bidding) — contacts in comment are masked
    r = carrier.post(f"/market/{order_id}/bid", {"price": "480000", "comment": "мой номер +7 701 555 44 33"})
    assert r.status_code == 303
    db.expire_all()
    assert db.get(Order, order.id).status == "bidding"
    from app.modules.bids.models import Bid

    bid = db.execute(select(Bid).where(Bid.order_id == order.id)).scalar_one()
    assert "555" not in bid.comment

    # carrier of another company cannot see the client's order card
    other = login(CARRIER2_OWNER)
    assert other.get(f"/orders/{order_id}").status_code in (403, 404)

    # accept twice with the same idempotency key -> one deal
    r = client.post(f"/bids/{bid.id}/accept", {"idem": "k-1"})
    assert r.status_code == 303
    r2 = client.post(f"/bids/{bid.id}/accept", {"idem": "k-1"})
    assert r2.status_code == 303
    db.expire_all()
    deals = db.execute(select(Deal).where(Deal.order_id == order.id)).scalars().all()
    assert len(deals) == 1
    deal = deals[0]
    snap = db.execute(select(DealSnapshot).where(DealSnapshot.deal_id == deal.id)).scalar_one()
    assert len(snap.content_hash) == 64

    # now the carrier sees exact addresses in the deal card
    assert "ул. Секретная" in carrier.get(f"/deals/{deal.id}").text
    # a foreign carrier does not
    assert other.get(f"/deals/{deal.id}").status_code == 404

    # sign contract by both sides with SMS codes (FR-DOC-06)
    contract = db.execute(select(Document).where(Document.deal_id == deal.id,
                                                 Document.doc_type == "contract_order")).scalar_one()
    for sess, phone in ((client, CLIENT_LOGIST), (carrier, CARRIER_OWNER)):
        assert sess.post(f"/deals/{deal.id}/docs/{contract.id}/sign-code").status_code == 303
        code = _latest_otp_code(phone)
        assert sess.post(f"/deals/{deal.id}/docs/{contract.id}/sign", {"code": code}).status_code == 303
    db.expire_all()
    assert db.get(Order, order.id).status == "docs_signed"
    assert db.get(Deal, deal.id).formalized_via_platform

    # price change only via supplement accepted by the other side (FR-DEAL-02)
    carrier.post(f"/deals/{deal.id}/supplement", {"price": "500000", "reason": "простой"})
    from app.modules.deals.models import Supplement

    sup = db.execute(select(Supplement).where(Supplement.deal_id == deal.id)).scalar_one()
    assert carrier.post(f"/deals/{deal.id}/supplement/{sup.id}", {"accept": "1"}).status_code in (403, 404)
    assert client.post(f"/deals/{deal.id}/supplement/{sup.id}", {"accept": "1"}).status_code == 303
    db.expire_all()
    assert db.get(Deal, deal.id).price_minor == 50_000_000 and db.get(Deal, deal.id).snapshot_version == 2

    # trip checkpoints; offline duplicate is ignored (FR-TRK-07)
    for kind in ("arrived_load", "loaded", "loaded", "departed", "arrived_unload", "unloaded"):
        carrier.post(f"/deals/{deal.id}/checkpoint", {"kind": kind, "offline_id": f"x-{kind}"})
    db.expire_all()
    assert db.get(Order, order.id).status == "unloaded"

    # closing document -> closed_docs -> fee accrued & invoiced automatically
    pdf = b"%PDF-1.4\n%test\n1 0 obj<<>>endobj\ntrailer<<>>\n%%EOF"
    r = carrier.post(f"/deals/{deal.id}/docs/upload", {"doc_type": "cmr"}, files={"file": ("cmr.pdf", pdf, "application/pdf")})
    assert r.status_code == 303
    db.expire_all()
    assert db.get(Order, order.id).status == "fee_invoiced"
    accrual = db.execute(select(Accrual).where(Accrual.deal_id == deal.id)).scalar_one()
    assert accrual.amount_minor == 3_500_000 and accrual.income_type == "platform_fee_fixed"
    inv = db.execute(select(Invoice).where(Invoice.deal_id == deal.id)).scalar_one()
    fee_docs = db.execute(select(Document).where(Document.deal_id == deal.id,
                                                 Document.doc_type.in_(("fee_invoice", "fee_act")))).scalars().all()
    assert len(fee_docs) == 2

    # the carrier never gets the client's fee invoice file
    assert "fee_invoice" not in carrier.get(f"/deals/{deal.id}").text

    # finance registers payment -> completed
    fin = login("finance@abdex.kz")
    r = fin.post(f"/admin/finance/invoices/{inv.id}/pay", {"amount": "35000", "reference": "п/п 1"})
    assert r.status_code == 303
    db.expire_all()
    assert db.get(Order, order.id).status == "completed"

    # dossier is downloadable
    r = client.get(f"/deals/{deal.id}/dossier.zip")
    assert r.status_code == 200 and r.content[:2] == b"PK"
    db.close()


def test_driver_sees_only_own_trips_without_finance(login):
    driver = login(DRIVER)
    trips = driver.get("/trips")
    assert trips.status_code == 200
    db = _db()
    driver_user = db.execute(select(User).where(User.phone == DRIVER)).scalar_one()
    from app.modules.fleet.models import Driver

    own = set(db.execute(select(Driver.id).where(Driver.user_id == driver_user.id)).scalars())
    for deal in db.execute(select(Deal)).scalars():
        r = driver.get(f"/deals/{deal.id}")
        if deal.driver_id in own:
            assert r.status_code == 200
            assert "Стоимость перевозки" not in r.text  # FR-ACL-03
        else:
            assert r.status_code == 404
    # drivers have no access to marketplace or orders
    assert driver.get("/market").status_code == 403
    db.close()


def test_status_rules_reject_invalid_transition(login):
    client = login(CLIENT_LOGIST)
    db = _db()
    order = db.execute(select(Order).where(Order.status == "in_transit")).scalars().first()
    r = client.post(f"/orders/{order.id}/cancel", {"reason": "передумали"})
    assert r.status_code == 303  # redirected back with an error flash
    db.expire_all()
    assert db.get(Order, order.id).status == "in_transit"
    db.close()


def test_append_only_tables():
    import pytest

    from app.db import AppendOnlyError

    db = _db()
    log = db.execute(select(AuditLog)).scalars().first()
    log.action = "tampered"
    with pytest.raises(AppendOnlyError):
        db.flush()
    db.rollback()
    snap = db.execute(select(DealSnapshot)).scalars().first()
    db.delete(snap)
    with pytest.raises(AppendOnlyError):
        db.flush()
    db.rollback()
    db.close()


def test_admin_requires_staff_and_auditor_sees_no_deal_content(login):
    client = login(CLIENT_OWNER)
    assert client.get("/admin").status_code == 404
    auditor = login("auditor@abdex.kz")
    assert auditor.get("/admin/audit").status_code == 200
    db = _db()
    deal = db.execute(select(Deal)).scalars().first()
    assert auditor.get(f"/admin/deals/{deal.id}").status_code == 404
    db.close()


def test_pvd_report_and_kpi(login):
    fin = login("finance@abdex.kz")
    r = fin.get("/admin/reports/pvd.xlsx?date_from=2020-01-01")
    assert r.status_code == 200 and r.content[:2] == b"PK"
    r = fin.get("/admin/reports/pvd?date_from=2020-01-01")
    assert "100.0%" in r.text or "100%" in r.text  # all demo income is priority income
    mgr = login("manager@abdex.kz")
    assert mgr.get("/admin/kpi").status_code == 200


def test_api_key_flow_and_idempotency(login):
    owner = login(CLIENT_OWNER)
    r = owner.post("/company/api-keys", {"name": "ERP", "scopes": ["orders:read", "orders:write"], "days": "30"},
                   follow_redirects=True)
    key = re.search(r"(abx_[A-Za-z0-9\-]+_[A-Za-z0-9\-]+)", r.text).group(1)
    from fastapi.testclient import TestClient

    from app.main import app

    api = TestClient(app)
    body = {"cargo_name": "API груз", "weight_kg": 5000, "load_from": (utcnow() + timedelta(days=3)).isoformat(),
            "points": [{"kind": "load", "city": "Алматы"}, {"kind": "unload", "city": "Тараз"}], "publish": True}
    h = {"X-API-Key": key, "Idempotency-Key": "erp-42"}
    r1 = api.post("/api/v1/orders", json=body, headers=h)
    r2 = api.post("/api/v1/orders", json=body, headers=h)
    assert r1.status_code == 201 and r1.json()["id"] == r2.json()["id"]
    assert api.post("/api/v1/orders", json={**body, "hack": 1}, headers={"X-API-Key": key}).status_code == 422
    assert api.get("/api/v1/market", headers={"X-API-Key": key}).status_code == 403  # scope + role
    page = api.get("/api/v1/orders?limit=1", headers={"X-API-Key": key}).json()
    assert len(page["items"]) == 1 and page["next_cursor"]


def test_registration_with_otp(client_app):
    from fastapi.testclient import TestClient

    from app.main import app
    from conftest import csrf_from

    c = TestClient(app)
    tok = csrf_from(c.get("/register").text)
    from tests.demo_data import make_bin

    data = {"csrf_token": tok, "account_type": "carrier", "full_name": "Новый Перевозчик", "phone": "+7 705 123 45 67",
            "email": "new@carrier.kz", "password": "Very-Strong-Pass-2026", "company_name": "ТОО Новый",
            "bin_iin": make_bin("22014000999"), "consent_registration": "on"}
    r = c.post("/register", data=data, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/verify-phone"
    code = _latest_otp_code("+77051234567")
    tok = csrf_from(c.get("/verify-phone").text)
    assert c.post("/verify-phone", data={"csrf_token": tok, "code": code}, follow_redirects=False).status_code == 303
    # a new carrier (L0) cannot bid
    db = _db()
    order = db.execute(select(Order).where(Order.status.in_(("published", "bidding")))).scalars().first()
    tok = csrf_from(c.get("/market").text)
    r = c.post(f"/market/{order.id}/bid", data={"csrf_token": tok, "price": "100000"}, follow_redirects=False)
    assert r.status_code == 403
    company = db.execute(select(Company).where(Company.name == "ТОО Новый")).scalar_one()
    assert company.verification_level == 0
    db.close()


def test_upload_rejects_disguised_files(login):
    owner = login(CARRIER_OWNER)
    r = owner.post("/company/verification/upload", {"doc_type": "charter", "subject": "company"},
                   files={"file": ("doc.pdf", b"MZ\x90\x00 not a pdf", "application/pdf")})
    assert r.status_code == 303
    assert "abdex_flash" in r.headers.get("set-cookie", "")
