"""Integrations prepared as adapters: qualified e-signature (section 50), online payment (FR-BIL-06),
accounting export and ESF/AWP XML (FR-BIL-07), electronic transport documents (section 51)."""
from __future__ import annotations

import base64
import io
import json
import zipfile
from datetime import datetime, timedelta, timezone
from xml.etree import ElementTree as ET  # noqa: S405 — parses our own output in tests

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from sqlalchemy import select

from app.core.context import RequestContext, reset_ctx, set_ctx
from app.db import SessionLocal
from app.modules.accounts.models import Company
from app.modules.billing.models import Invoice, Payment, PaymentIntent
from app.modules.documents.models import Document, QualifiedSignature, Signature, TransportDocRegistration


@pytest.fixture
def db(client_app):
    s = SessionLocal()
    yield s
    s.rollback()
    s.close()


@pytest.fixture(scope="module")
def fresh_deal(client_app):
    """A new deal with an unsigned contract, so the demo deals stay untouched."""
    from app.demo import _form
    from app.modules.bids.service import accept, place_bid
    from app.modules.orders.service import create_order, submit

    db = SessionLocal()
    client = db.execute(select(Company).where(Company.kind == "client")).scalars().first()
    carrier = db.execute(select(Company).where(Company.name.contains("Жол Транс"))).scalar_one()
    tok = set_ctx(RequestContext(request_id="test-setup", company_id=client.id, extra={"rls_bypass": True}))
    try:
        order = create_order(db, client, _form([("Алматы", "ул. Тестовая, 1"), ("Астана", "ул. Приемная, 2")],
                                               "Интеграционный тест", 5000, 0, 6), rate_limited=False)
        submit(db, order)
        bid = place_bid(db, order.id, carrier, {"price": "250000"})
        deal = accept(db, bid.id, client)
        db.commit()
        return deal.id
    finally:
        reset_ctx(tok)
        db.close()


def _contract(db, deal_id) -> Document:
    return db.execute(select(Document).where(Document.deal_id == deal_id, Document.doc_type == "contract_order")
                      ).scalars().first()


def _sign_like_browser(s, data: bytes, *, tamper: bool = False) -> str:
    """What eds.js does in development: a WebCrypto key, a test certificate, an r||s signature."""
    key = ec.generate_private_key(ec.SECP256R1())
    spki = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    r = s.post("/dev/eds/certificate", data={"public_key": base64.b64encode(spki).decode()})
    assert r.status_code == 200, r.text
    der = key.sign(data + (b"x" if tamper else b""), ec.ECDSA(hashes.SHA256()))
    rr, ss = decode_dss_signature(der)
    raw = rr.to_bytes(32, "big") + ss.to_bytes(32, "big")
    return json.dumps({"cert": r.json()["certificate"], "sig": base64.b64encode(raw).decode()})


# ------------------------------------------------------------------ section 50


def test_qualified_signature_verified_on_server(login, db, fresh_deal):
    from app.core.storage import storage
    from app.modules.documents.models import StoredFile

    doc = _contract(db, fresh_deal)
    data = storage.get(db.get(StoredFile, doc.file_id).storage_key)
    owner = login("+77010000001")
    assert "data-eds-sign" in owner.get(f"/deals/{fresh_deal}").text

    bad = owner.post(f"/deals/{fresh_deal}/docs/{doc.id}/sign-eds", data={"package": _sign_like_browser(owner, data, tamper=True)})
    assert bad.status_code == 303  # refused with a message; nothing stored
    db.expire_all()
    assert not db.execute(select(Signature).where(Signature.document_id == doc.id)).first()

    r = owner.post(f"/deals/{fresh_deal}/docs/{doc.id}/sign-eds", data={"package": _sign_like_browser(owner, data)})
    assert r.status_code == 303 and r.headers["location"].endswith("/signatures")
    db.expire_all()
    sig = db.execute(select(Signature).where(Signature.document_id == doc.id)).scalar_one()
    assert sig.kind == "qualified" and sig.document_hash == doc.sha256
    q = db.execute(select(QualifiedSignature).where(QualifiedSignature.signature_id == sig.id)).scalar_one()
    checks = json.loads(q.verify_result)["checks"]
    assert checks == {"integrity": True, "chain": True, "validity": True, "revocation": True, "owner": True}
    client = db.get(Company, sig.company_id)
    assert q.signer_bin == client.bin_iin

    page = owner.post(f"/deals/{fresh_deal}/docs/{doc.id}/signatures").text  # re-verification at any time
    assert "✓" in page and "✗" not in page
    manager = login("manager@abdex.kz")
    assert f"/admin/deals/{fresh_deal}/docs/{doc.id}/signatures" in manager.get(f"/admin/deals/{fresh_deal}").text
    assert manager.get(f"/admin/deals/{fresh_deal}/docs/{doc.id}/signatures").status_code == 200

    # the other side cannot pass with a certificate of a different company (owner check)
    carrier = login("+77020000001")
    pkg = _sign_like_browser(owner, data)  # certificate issued to the client's company
    carrier.post(f"/deals/{fresh_deal}/docs/{doc.id}/sign-eds", data={"package": pkg})
    db.expire_all()
    assert db.execute(select(Signature).where(Signature.document_id == doc.id)).scalars().all() == [sig]
    carrier.post(f"/deals/{fresh_deal}/docs/{doc.id}/sign-eds", data={"package": _sign_like_browser(carrier, data)})
    db.expire_all()
    assert len(db.execute(select(Signature).where(Signature.document_id == doc.id)).scalars().all()) == 2


def test_revoked_and_expired_certificates(client_app):
    from app.modules.documents import eds

    key = ec.generate_private_key(ec.SECP256R1())
    spki = base64.b64encode(key.public_key().public_bytes(serialization.Encoding.DER,
                                                          serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
    start = datetime.now(timezone.utc) - timedelta(days=400)
    pem = eds.dev_issue(spki, full_name="Тест", iin="000000000000", bin_iin="123456789012", days=30, not_before=start)
    data = b"document"
    raw = key.sign(data, ec.ECDSA(hashes.SHA256()))
    pkg = json.dumps({"cert": pem, "sig": base64.b64encode(raw).decode()})
    v = eds.DevVerifier()
    signed_then = start + timedelta(days=1)
    ok = v.verify(pkg, data, signed_at=signed_then, expected_bin="123456789012", revoked=set())
    assert ok.valid  # expired today, but valid when it was signed (GOV-DS-05)
    late = v.verify(pkg, data, signed_at=datetime.now(timezone.utc), expected_bin="123456789012", revoked=set())
    assert not late.valid and late.checks["validity"] is False
    revoked = v.verify(pkg, data, signed_at=signed_then, expected_bin="123456789012", revoked={ok.signer["serial"]})
    assert not revoked.valid and revoked.checks["revocation"] is False


# ------------------------------------------------------------------ FR-BIL-06


def test_online_payment_through_provider(login, db):
    from app.modules.billing import payments

    client = db.execute(select(Company).where(Company.kind == "client")).scalars().first()
    inv = Invoice(number="СЧ-TEST-000001", company_id=client.id, amount_minor=3_500_000, currency="KZT", status="issued")
    db.add(inv)
    db.commit()
    owner = login("+77010000001")
    assert "Оплатить онлайн" in owner.get("/finance").text
    r = owner.post(f"/finance/invoices/{inv.id}/pay")
    assert r.status_code == 303 and r.headers["location"].startswith("/dev/pay/")
    ref = r.headers["location"].rsplit("/", 1)[1]
    assert "4111" not in owner.get(r.headers["location"]).text  # no card fields on the platform at all
    r = owner.post(f"/dev/pay/{ref}", data={"decision": "pay"})
    assert r.status_code == 303
    db.expire_all()
    assert db.get(Invoice, inv.id).status == "paid"
    pay = db.execute(select(Payment).where(Payment.invoice_id == inv.id)).scalar_one()
    assert pay.source == "provider" and pay.reference == ref
    # the same callback again changes nothing; a forged one is rejected
    intent = db.execute(select(PaymentIntent).where(PaymentIntent.provider_ref == ref)).scalar_one()
    body = json.dumps({"ref": ref, "status": "succeeded", "amount": intent.amount_minor, "currency": "KZT"}).encode()
    assert payments.handle_callback(SessionLocal(), body, payments.sign(body)) == "duplicate"
    assert client_app_post(body, "t=1,v1=00").status_code == 404
    assert client_app_post(body, payments.sign(body, ts=1)).status_code == 404  # stale time stamp
    db.expire_all()
    assert len(db.execute(select(Payment).where(Payment.invoice_id == inv.id)).scalars().all()) == 1


def client_app_post(body: bytes, signature: str):
    from fastapi.testclient import TestClient

    from app.main import app

    return TestClient(app).post("/hooks/payments", content=body, headers={"X-AbdEX-Pay-Signature": signature,
                                                                           "Content-Type": "application/json"})


# ------------------------------------------------------------------ FR-BIL-07


def test_accounting_export_and_esf(login, db):
    owner = login("+77010000001")
    today = datetime.now(timezone.utc).date()
    r = owner.get(f"/finance/export.xlsx?date_from={(today - timedelta(days=30)).isoformat()}&date_to={today.isoformat()}")
    assert r.status_code == 200 and r.content[:2] == b"PK"
    fin = login("finance@abdex.kz")
    r = fin.get(f"/admin/finance/esf.zip?date_from={(today - timedelta(days=30)).isoformat()}&date_to={today.isoformat()}")
    assert r.status_code == 200
    z = zipfile.ZipFile(io.BytesIO(r.content))
    names = z.namelist()
    assert any(n.startswith("esf/") for n in names) and any(n.startswith("awp/") for n in names)
    root = ET.fromstring(z.read(next(n for n in names if n.startswith("esf/"))))  # noqa: S314 — own output
    inv_num = root.attrib["num"]
    inv = db.execute(select(Invoice).where(Invoice.number == inv_num)).scalar_one()
    buyer = db.get(Company, inv.company_id)
    assert root.find("customers/customer/tin").text == buyer.bin_iin
    assert "программно-технических возможностей" in root.find("productSet/product/description").text
    assert owner.get("/admin/finance/esf.zip").status_code == 404


# ------------------------------------------------------------------ section 51


def test_transport_documents(login, db, fresh_deal):
    from app.modules.documents import transport
    from app.modules.platform.models import FeatureFlag

    carrier = login("+77020000001")
    page = carrier.get(f"/deals/{fresh_deal}").text
    assert "Транспортные документы" in page
    r = carrier.post(f"/deals/{fresh_deal}/transport-docs", data={"mode": "electronic"})
    assert r.status_code == 303
    db.expire_all()
    regs = transport.registrations(db, fresh_deal)
    assert [d.doc_type for d, _ in regs] == ["e_waybill"]  # domestic trip: the rule asks for the ТТН only
    doc, reg = regs[0]
    assert reg.status == "local"  # the state exchange is switched off
    xml = carrier.get(f"/deals/{fresh_deal}/transport-docs/{reg.id}.xml")
    assert xml.status_code == 200 and b"<shipper_bin>" in xml.content
    manager = login("manager@abdex.kz")  # staff open deal documents only through the audited admin routes
    assert manager.get(f"/admin/deals/{fresh_deal}/transport-docs/{reg.id}.xml").status_code == 200
    flag = db.execute(select(FeatureFlag).where(FeatureFlag.key == "gov.etd")).scalar_one()
    flag.enabled = True
    db.commit()
    try:
        carrier.post(f"/deals/{fresh_deal}/transport-docs/{reg.id}/submit")
        db.expire_all()
        assert db.get(TransportDocRegistration, reg.id).status == "pending"
        transport.process(SessionLocal())
        db.expire_all()
        reg = db.get(TransportDocRegistration, reg.id)
        # no vehicle and driver were assigned to this deal: the state system rejects it, visibly
        assert reg.status == "error" and "vehicle" in reg.last_error
        assert "vehicle" in carrier.get(f"/deals/{fresh_deal}").text
    finally:
        flag.enabled = False
        db.commit()
    # paper mode needs the paper number; the document already formed is not duplicated
    r = carrier.post(f"/deals/{fresh_deal}/transport-docs", data={"mode": "paper"})
    assert r.status_code == 303
    db.expire_all()
    assert len(transport.registrations(db, fresh_deal)) == 1
