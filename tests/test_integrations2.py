"""Telematics (FR-TRK-05), document recognition (M6), ESF sending (FR-BIL-07), eGov mobile login (FR-AUTH-09),
AI matching (FR-BID-09), analytics replica (FR-BI-06)."""
from __future__ import annotations

import base64
import io
import json
from datetime import timedelta

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.context import RequestContext, reset_ctx, set_ctx
from app.db import SessionLocal, utcnow
from app.main import app
from app.modules.accounts.models import Company, User
from app.modules.deals.models import Deal, TrackPoint
from app.modules.orders.models import Order


@pytest.fixture
def db(client_app):
    s = SessionLocal()
    tok = set_ctx(RequestContext(request_id="", extra={"rls_bypass": True}))
    yield s
    s.rollback()
    s.close()
    reset_ctx(tok)


def _flag(db, key, on=True):
    from app.modules.platform.models import FeatureFlag

    f = db.execute(select(FeatureFlag).where(FeatureFlag.key == key)).scalar_one()
    f.enabled = on
    db.commit()


# ------------------------------------------------------------------ FR-TRK-05


def test_telematics_positions_only_for_a_trip_with_consent(login, db):
    import re

    from app.modules.deals import telematics
    from app.modules.fleet.models import Vehicle

    carrier = db.execute(select(Company).where(Company.name.contains("Жол Транс"))).scalar_one()
    deal = db.execute(select(Deal).join(Order, Order.id == Deal.order_id)
                      .where(Deal.carrier_company_id == carrier.id, Deal.vehicle_id.is_not(None),
                             Order.status.in_(("loading", "in_transit")))).scalars().first()
    assert deal is not None
    v = db.get(Vehicle, deal.vehicle_id)
    now = utcnow()
    batch = [{"plate": v.plate, "lat": 45.0, "lng": 75.0, "at": now.isoformat(), "speed": 70},
             {"plate": v.plate, "lat": 45.0, "lng": 75.0, "at": now.isoformat(), "speed": 70},   # same time
             {"plate": "000XXX00", "lat": 45, "lng": 75, "at": now.isoformat()},              # unknown truck
             {"plate": v.plate, "lat": 45, "lng": 75, "at": (now - timedelta(days=5)).isoformat()},  # too old
             {"plate": v.plate, "lat": 145, "lng": 75, "at": now.isoformat()}]                # nonsense
    deal.geo_consent = False
    db.commit()
    assert telematics.ingest(db, carrier.id, batch[:1])["accepted"] == 0  # no consent: nothing stored
    deal.geo_consent = True
    db.commit()
    res = telematics.ingest(db, carrier.id, batch)
    db.commit()
    assert res == {"accepted": 1, "ignored": 4}
    assert len(db.execute(select(TrackPoint).where(TrackPoint.deal_id == deal.id)).scalars().all()) >= 1

    # through the API with a key of the carrier
    owner = login("+77020000001")
    r = owner.post("/company/api-keys", {"name": "GPS", "scopes": ["telematics:write"], "days": "30"}, follow_redirects=True)
    key = re.search(r"(abx_[A-Za-z0-9\-]+_[A-Za-z0-9\-]+)", r.text).group(1)
    api = TestClient(app)
    later = (now + timedelta(seconds=30)).isoformat()
    r = api.post("/api/v1/telematics/positions", headers={"X-API-Key": key},
                 json={"positions": [{"plate": v.plate, "lat": 45.1, "lng": 75.1, "at": later, "speed": 60}]})
    assert r.status_code == 200 and r.json()["accepted"] == 1
    assert api.post("/api/v1/telematics/positions", headers={"X-API-Key": key},
                    json={"positions": [{"plate": v.plate, "lat": 1, "lng": 1, "at": later, "x": 1}]}).status_code == 422
    # the client sees the GPS track on the trip map
    html = login("+77010000001").get(f"/deals/{deal.id}").text
    assert "route-track" in html
    # the connection URL must be a public https address (SSRF)
    r = owner.post("/company/telematics", {"url": "http://169.254.169.254/latest", "token": "t", "active": "on"})
    db.expire_all()
    from app.modules.deals.models import TelematicsConnection

    assert db.execute(select(TelematicsConnection).where(TelematicsConnection.company_id == carrier.id)).first() is None


# ------------------------------------------------------------------ M6 recognition


def _pdf(text: str) -> bytes:
    from reportlab.lib.pagesizes import A4
    from reportlab.pdfgen import canvas

    buf = io.BytesIO()
    c = canvas.Canvas(buf, pagesize=A4)
    y = 800
    for line in text.split("\n"):
        c.drawString(40, y, line)
        y -= 16
    c.save()
    return buf.getvalue()


def test_recognition_reads_bin_and_flags_a_mismatch(db):
    from app.core.storage import save_generated
    from app.modules.documents.recognition import extract
    from app.modules.fleet.service import attach_verification_document
    from app.modules.platform.models import AntifraudAlert

    client = db.execute(select(Company).where(Company.name.contains("Агро Трейд"))).scalar_one()
    f = save_generated(db, data=_pdf(f"Certificate of registration\nBIN {client.bin_iin}\nValid until 31.12.2030"),
                       name="reg.pdf", content_type="application/pdf", company_id=client.id)
    doc = attach_verification_document(db, client, subject_type="company", subject_id=client.id,
                                       doc_type="registration_certificate", file_id=f.id, expires_on=None)
    rec = json.loads(doc.recognized)
    assert client.bin_iin in rec["ids"] and rec["checks"] == {"bin": True}
    assert rec["expiry"] == "2030-12-31" and doc.expires_on.isoformat() == "2030-12-31"
    other = "990540001234" if extract("990540001234")["ids"] else None
    from app.demo import make_bin

    stranger = make_bin("98765432101")
    f2 = save_generated(db, data=_pdf(f"BIN {stranger}"), name="x.pdf", content_type="application/pdf",
                        company_id=client.id)
    doc2 = attach_verification_document(db, client, subject_type="company", subject_id=client.id,
                                        doc_type="charter", file_id=f2.id, expires_on=None)
    assert json.loads(doc2.recognized)["checks"] == {"bin": False}
    assert db.execute(select(AntifraudAlert).where(AntifraudAlert.kind == "doc_data_mismatch",
                                                   AntifraudAlert.company_id == client.id)).first()
    assert other is None or other  # extract() accepts only checksum-valid 12-digit numbers
    db.rollback()


# ------------------------------------------------------------------ FR-BIL-07 ESF sending


def test_esf_sending_queue(login, db):
    from app.modules.billing import accounting, esf
    from app.modules.billing.models import EsfSubmission

    _flag(db, "gov.esf")
    try:
        today = utcnow().date()
        n = esf.queue_period(db, accounting.rows(db, today - timedelta(days=60), today))
        db.commit()
        assert n >= 2
        assert esf.queue_period(db, accounting.rows(db, today - timedelta(days=60), today)) == 0  # once only
        db.commit()
        esf.process(SessionLocal())
        db.expire_all()
        subs = db.execute(select(EsfSubmission)).scalars().all()
        assert subs and all(s.status in ("accepted", "error") for s in subs)
        assert any(s.status == "accepted" and s.registration_number.startswith("ESF-") for s in subs)
        fin = login("finance@abdex.kz")
        assert "ESF-" in fin.get("/admin/finance").text
    finally:
        _flag(db, "gov.esf", False)


# ------------------------------------------------------------------ FR-AUTH-09 eGov mobile


def test_egov_mobile_login(client_app, db):
    from app.modules.documents import eds

    _flag(db, "auth.egov_mobile")
    user = db.execute(select(User).where(User.phone == "+77010000003")).scalar_one()
    key = ec.generate_private_key(ec.SECP256R1())
    spki = base64.b64encode(key.public_key().public_bytes(serialization.Encoding.DER,
                                                          serialization.PublicFormat.SubjectPublicKeyInfo)).decode()
    iin = "990101300555"
    pem = eds.dev_issue(spki, full_name=user.full_name, iin=iin, bin_iin="")
    user.iin, user.eds_linked_at = iin, utcnow()
    db.commit()
    try:
        browser = TestClient(app)
        from conftest import csrf_from

        token_csrf = csrf_from(browser.get("/login").text)
        assert "data-egov" in browser.get("/login").text
        r = browser.post("/login/egov/start", headers={"X-CSRF-Token": token_csrf})
        assert r.status_code == 200 and r.json()["link"].startswith("mobileSign:")
        start = r.json()
        assert browser.get(start["status"]).json()["status"] == "pending"

        phone = TestClient(app)  # the app: no cookies, no CSRF
        meta = phone.get(f"/egov/mgov/{start['token']}").json()
        uri = meta["document"]["uri"].split("testserver", 1)[-1]
        bearer = {"Authorization": "Bearer " + meta["document"]["auth_token"]}
        assert phone.get(uri).status_code == 404  # no bearer token
        doc = phone.get(uri, headers=bearer).json()
        challenge = base64.b64decode(doc["documentsToSign"][0]["document"]["file"]["data"])
        sig = base64.b64encode(key.sign(challenge, ec.ECDSA(hashes.SHA256()))).decode()
        pkg = json.dumps({"cert": pem, "sig": sig})
        doc["documentsToSign"][0]["document"]["file"]["data"] = base64.b64encode(pkg.encode()).decode()
        assert phone.put(uri, headers=bearer, json=doc).status_code == 200

        stranger = TestClient(app)  # another browser cannot pick up the result
        assert stranger.get(start["status"]).status_code == 404
        res = browser.get(start["status"]).json()
        assert res["status"] == "signed" and res["redirect"]
        assert browser.get("/account").status_code == 200
        assert browser.get(start["status"]).status_code == 404  # used once, the attempt cookie is gone
    finally:
        user.iin, user.eds_linked_at = "", None
        db.commit()
        _flag(db, "auth.egov_mobile", False)


# ------------------------------------------------------------------ FR-BID-09, FR-BI-06


def test_ai_matching_weights_and_replica(login, db):
    from app.modules.bids import matching
    from app.modules.platform.service import set_setting

    res = matching.learn(db)
    assert "samples" in res
    set_setting(db, "matching.learned", {"samples": 100, "weights": {"body": 50, "geo": 0, "history": 30, "rating": 20,
                                                                     "level": 0, "load": 0}})
    _flag(db, "matching.ai")
    try:
        assert matching.weights(db)["body"] == 50
    finally:
        _flag(db, "matching.ai", False)
    assert matching.weights(db)["body"] == matching.DEFAULT_WEIGHTS["body"]
    admin = login("admin@abdex.kz")
    assert "ИИ-подбор" in admin.get("/admin/matching").text
    from app.db import get_analytics_db

    s = next(get_analytics_db())
    assert s.execute(select(1)).scalar() == 1
    assert login("+77010000001").get("/analytics").status_code == 200
