"""Cycle 2, part 3: field encryption and key rotation, row-level security, processing register and
cross-border transfers, driver biometrics, anonymised copies of the database."""
from __future__ import annotations

import base64
import io
import os
import re
import sqlite3
import subprocess
import sys
import tempfile

import pytest
from PIL import Image
from sqlalchemy import func, select, text

from app.core import crypto
from app.core.context import RequestContext, reset_ctx, set_ctx
from app.db import SessionLocal, engine, utcnow
from app.modules.accounts.models import BankAccount, Company, User
from tests.conftest import csrf_from

PG = engine.dialect.name == "postgresql"


@pytest.fixture
def db(client_app):
    s = SessionLocal()
    yield s
    s.rollback()
    s.close()


def _png(color) -> bytes:
    buf = io.BytesIO()
    Image.new("RGB", (64, 64), color).save(buf, "PNG")
    return buf.getvalue()


# ------------------------------------------------------------------ NFR-DB-08, SEC-DAT-02/03


def test_field_encryption_and_blind_index(db):
    stored = crypto.encrypt("850401300120", "drivers.iin")
    assert stored.startswith("enc:v") and "850401300120" not in stored
    assert crypto.decrypt(stored, "drivers.iin") == "850401300120"
    with pytest.raises(Exception):  # noqa: B017 — bound to its column: no decryption elsewhere
        crypto.decrypt(stored, "drivers.phone")
    assert crypto.encrypt("850401300120", "drivers.iin") != stored  # random nonce
    assert crypto.blind_index("8504 0130 0120", "iin") == crypto.blind_index("850401300120", "iin")
    raw = db.execute(text("SELECT iin, iin_index FROM drivers WHERE iin <> '' LIMIT 1")).one()
    assert raw[0].startswith("enc:v") and len(raw[1]) == 40
    raw_iban = db.execute(text("SELECT iban FROM bank_accounts LIMIT 1")).scalar_one()
    assert raw_iban.startswith("enc:v")
    assert db.execute(select(BankAccount)).scalars().first().iban.startswith("KZ")


def test_key_rotation(db, monkeypatch):
    from app.cli import rotate_keys
    from app.modules.fleet.models import Driver

    old = crypto.keyring()[0]
    v1 = base64.urlsafe_b64encode(old[max(old)]).decode()
    v2 = base64.urlsafe_b64encode(os.urandom(32)).decode()
    monkeypatch.setenv("FIELD_ENCRYPTION_KEYS", f"{max(old)}:{v1},{max(old) + 1}:{v2}")
    crypto.reset_keyring()
    # The keyring stays cached with both versions for the rest of the run: data is now under the new key.
    counts = rotate_keys()
    assert counts["drivers"] >= 1 and counts["bank_accounts"] >= 1
    raw = db.execute(text("SELECT iin FROM drivers WHERE iin <> '' LIMIT 1")).scalar_one()
    assert crypto.key_version(raw) == max(old) + 1
    db.expire_all()
    assert db.execute(select(Driver).where(Driver.iin != "")).scalars().first().iin.isdigit()
    assert rotate_keys() == {"drivers": 0, "bank_accounts": 0}  # nothing left to re-encrypt


# ------------------------------------------------------------------ NFR-DB-07


@pytest.mark.skipif(not PG, reason="row-level security exists only in PostgreSQL")
def test_row_level_security(db):
    me = db.execute(text("SELECT current_user, (SELECT rolsuper FROM pg_roles WHERE rolname = current_user), "
                         "(SELECT rolbypassrls FROM pg_roles WHERE rolname = current_user)")).one()
    assert me[1] is False and me[2] is False  # the application runs as a plain role
    total = db.execute(select(BankAccount)).scalars().all()  # this transaction has no request: system bypass
    assert len({b.company_id for b in total}) >= 1
    company = db.get(Company, total[0].company_id)
    other = db.execute(select(Company).where(Company.id != company.id)).scalars().first()
    db.rollback()
    for cid, expect_own in ((company.id, True), (other.id, False)):
        tok = set_ctx(RequestContext(request_id="rls-test", company_id=cid, role="owner"))
        s = SessionLocal()
        try:
            rows = s.execute(select(BankAccount)).scalars().all()
            assert all(r.company_id == cid for r in rows)
            assert (company.id in {r.company_id for r in rows}) is expect_own
            invoices = s.execute(text("SELECT company_id FROM invoices")).all()
            assert all(r[0] == cid for r in invoices)
        finally:
            s.close()
            reset_ctx(tok)


# ------------------------------------------------------------------ SEC-DAT-10/11


def test_processing_register_gates_transfers(login, db):
    from app.modules.integrations.adapters import sms
    from app.modules.integrations.base import NotRegistered
    from app.modules.platform.models import ProcessingRecord
    from app.modules.platform.processing import invalidate

    page = login("+77010000001").get("/legal/privacy").text
    assert "Telegram Messenger Inc." in page
    admin = login("admin@abdex.kz")
    assert admin.get("/admin/processing").status_code == 200
    rec = db.execute(select(ProcessingRecord).where(ProcessingRecord.code == "sms")).scalar_one()
    admin.post(f"/admin/processing/{rec.id}/toggle")
    try:
        invalidate()
        with pytest.raises(NotRegistered):
            sms.send("+77010000001", "test")
    finally:
        admin.post(f"/admin/processing/{rec.id}/toggle")
        invalidate()
    sms.send("+77010000001", "test")  # registered again
    # a cross-border record without countries and safeguards is refused
    r = admin.post("/admin/processing", data={"code": "abroad_x", "purpose": "x", "data_categories": "x",
                                              "legal_basis": "x", "cross_border": "on"})
    assert r.status_code == 303
    db.expire_all()
    assert db.execute(select(ProcessingRecord).where(ProcessingRecord.code == "abroad_x")).first() is None


def test_driver_biometrics_decided_by_moderator(login, db):
    """FR-KYC-08: nothing passes automatically — a moderator compares the photos; SEC-DAT-10 storage rules."""
    from datetime import timedelta

    from app.core.storage import storage
    from app.modules.documents.models import StoredFile
    from app.modules.fleet.biometrics import purge_images
    from app.modules.fleet.models import BiometricCheck

    s = login("+77020000003")
    files = {"selfie": ("a.png", _png((200, 150, 120)), "image/png"), "selfie2": ("b.png", _png((190, 140, 110)), "image/png"),
             "document": ("d.png", _png((20, 40, 200)), "image/png")}
    assert s.post("/trips/biometrics", files=files).status_code == 403  # no separate consent yet
    s.post("/account/consents/biometrics", data={"grant": "1"})
    before = db.execute(select(func.count(BiometricCheck.id))).scalar_one()
    # the same picture twice is refused at once, nothing is stored
    s.post("/trips/biometrics", files=dict(files, selfie2=files["selfie"]))
    db.expire_all()
    assert db.execute(select(func.count(BiometricCheck.id))).scalar_one() == before

    assert s.post("/trips/biometrics", files=files).status_code == 303
    db.expire_all()
    check = db.execute(select(BiometricCheck).order_by(BiometricCheck.created_at.desc())).scalars().first()
    assert check.status == "pending" and not check.match and check.valid_until is None
    assert check.selfie2_file_id and check.images_delete_after is None  # kept for the moderator
    assert "на проверке у модератора" in s.get("/trips/biometrics").text.lower()
    s.post("/trips/biometrics", files=files)  # no second check while one waits
    db.expire_all()
    assert db.execute(select(func.count(BiometricCheck.id)).where(BiometricCheck.status == "pending")).scalar_one() == 1
    # images of a waiting check are not purged by time
    purge_images(db, now=utcnow() + timedelta(days=3))
    db.commit()
    db.expire_all()
    assert db.get(BiometricCheck, check.id).selfie_file_id is not None

    mod = login("moderator@abdex.kz")
    assert "Ждут проверки" in mod.c.get("/admin/biometrics").text
    page = mod.c.get(f"/admin/biometrics/{check.id}").text
    photos = re.findall(r'<figure class="card"><a href="[^"]+" target="_blank" rel="noopener"><img src="([^"]+)"', page)
    assert len(photos) == 3  # both selfies and the document
    img = photos[0].replace("&amp;", "&")
    assert mod.c.get(img).status_code == 200  # the moderator sees the photos
    token = csrf_from(page)
    # approval needs all three confirmations
    mod.c.post(f"/admin/biometrics/{check.id}", data={"csrf_token": token, "decision": "approve", "face_match": "on"})
    db.expire_all()
    assert db.get(BiometricCheck, check.id).status == "pending"
    mod.c.post(f"/admin/biometrics/{check.id}", data={"csrf_token": token, "decision": "approve", "face_match": "on",
                                                      "live": "on", "document_ok": "on"})
    db.expire_all()
    done = db.get(BiometricCheck, check.id)
    assert done.status == "passed" and done.match and done.liveness and done.valid_until and done.reviewed_by
    assert done.images_delete_after is not None
    selfie = db.get(StoredFile, done.selfie_file_id)
    # images disappear after the short period, the result stays
    purge_images(db, now=utcnow() + timedelta(hours=25))
    db.commit()
    db.expire_all()
    with pytest.raises(FileNotFoundError):
        storage.get(selfie.storage_key)
    kept = db.get(BiometricCheck, check.id)
    assert kept.images_deleted_at and kept.selfie_file_id is None and kept.selfie2_file_id is None
    assert kept.status == "passed"

    # a rejection carries the reason to the driver
    s.post("/trips/biometrics", files={k: (n, _png((i * 40, 90, 60)), t) for i, (k, (n, _, t)) in enumerate(files.items(), 1)})
    db.expire_all()
    second = db.execute(select(BiometricCheck).order_by(BiometricCheck.created_at.desc())).scalars().first()
    page = mod.c.get(f"/admin/biometrics/{second.id}").text
    mod.c.post(f"/admin/biometrics/{second.id}", data={"csrf_token": csrf_from(page), "decision": "reject",
                                                       "reason": "not_a_document"})
    db.expire_all()
    assert db.get(BiometricCheck, second.id).status == "failed"
    assert "не удостоверение" in s.get("/trips/biometrics").text

    # revoking the consent while a check waits: images deleted at once, the check is withdrawn
    s.post("/trips/biometrics", files={k: (n, _png((i * 30, 20, 99)), t) for i, (k, (n, _, t)) in enumerate(files.items(), 1)})
    s.post("/account/consents/biometrics", data={})
    db.expire_all()
    latest = db.execute(select(BiometricCheck).order_by(BiometricCheck.created_at.desc())).scalars().first()
    assert latest.images_deleted_at is not None and latest.status == "withdrawn"


# ------------------------------------------------------------------ SEC-DAT-09


def test_production_copy_must_be_anonymised(db):
    from app.cli import check_data_origin
    from app.modules.platform.service import get_setting, set_setting

    before = get_setting(db, "platform.data_origin")
    set_setting(db, "platform.data_origin", "production")
    with pytest.raises(RuntimeError):
        check_data_origin(db)
    set_setting(db, "platform.data_origin", before)
    db.commit()


@pytest.mark.skipif(PG, reason="runs on a throwaway SQLite copy")
def test_anonymize_command_on_a_copy():
    root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    tmp = tempfile.mkdtemp(prefix="abdex-anon-")
    env = {**os.environ, "APP_ENV": "test", "DATABASE_URL": f"sqlite:///{tmp}/copy.db", "STORAGE_DIR": f"{tmp}/st",
           "RUN_BACKGROUND_WORKER": "false"}
    subprocess.run([sys.executable, "-c", "from app.bootstrap import ensure_initialized; ensure_initialized(); "  # noqa: S603
                    "from app.db import SessionLocal; from tests.demo_data import seed_demo; seed_demo(SessionLocal())"],
                   cwd=root, env=env, check=True, capture_output=True)
    out = subprocess.run([sys.executable, "-m", "app.cli", "anonymize", "--confirm"], cwd=root, env=env,  # noqa: S603
                         check=True, capture_output=True, text=True)
    assert "users" in out.stdout
    con = sqlite3.connect(f"{tmp}/copy.db")
    phones = [r[0] for r in con.execute("SELECT phone FROM users")]
    assert phones and all(p.startswith("+7999") for p in phones)
    assert con.execute("SELECT count(*) FROM user_sessions").fetchone()[0] == 0
    assert all(r[0] == "" for r in con.execute("SELECT contact_phone FROM companies"))
    assert con.execute("SELECT value FROM platform_settings WHERE key = 'platform.data_origin'").fetchone()[0] == '"anonymized"'
    con.close()
    assert User  # noqa: B018 — imported model used by the other tests in this module
