"""Driver biometric check (FR-KYC-08) with the storage rules of SEC-DAT-10.

* Only after the separate "biometrics" consent; revoking it deletes any images still kept at once.
* Two selfie frames (liveness: the driver turns the head) and a photo of the ID document go to the provider
  adapter; only the result (match, liveness, score, provider, validity) is stored for long.
* The images are deleted after ``biometrics.image_ttl_hours`` (24 h by default) by the retention job.
* The provider receives data only while the processing register has an active record for it (SEC-DAT-11);
  when the provider is unavailable the check is recorded as such and the driver is verified manually.
"""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.audit import audit
from app.core.errors import Forbidden, NotFound, ValidationFailed
from app.core.storage import IMAGE_TYPES, save_upload, storage
from app.db import utcnow
from app.modules.accounts.models import User
from app.modules.documents.models import StoredFile
from app.modules.fleet.models import BiometricCheck, Driver
from app.modules.integrations.base import IntegrationUnavailable


def driver_of(db: Session, user: User) -> Driver:
    d = db.execute(select(Driver).where(Driver.user_id == user.id, Driver.is_deleted.is_(False))
                   .order_by(Driver.created_at.desc())).scalars().first()
    if d is None:
        raise NotFound()
    return d


def latest(db: Session, driver_id) -> BiometricCheck | None:
    return db.execute(select(BiometricCheck).where(BiometricCheck.driver_id == driver_id)
                      .order_by(BiometricCheck.created_at.desc())).scalars().first()


def run_check(db: Session, user: User, *, selfie: bytes, selfie2: bytes, document: bytes) -> BiometricCheck:
    from app.modules.accounts.service import has_consent
    from app.modules.integrations.adapters import biometrics
    from app.modules.platform.service import get_setting

    if not has_consent(db, user.id, "biometrics"):
        raise Forbidden("biometrics_consent_required")
    driver = driver_of(db, user)
    if not (selfie and selfie2 and document):
        raise ValidationFailed({"selfie": "error.required"})
    files = [save_upload(db, data=data, original_name=name, company_id=driver.company_id, user_id=user.id,
                         allowed=IMAGE_TYPES) for data, name in ((selfie, "selfie.jpg"), (selfie2, "selfie2.jpg"),
                                                                 (document, "document.jpg"))]
    ttl = int(get_setting(db, "biometrics.image_ttl_hours", 24))
    check = BiometricCheck(driver_id=driver.id, company_id=driver.company_id, provider=biometrics.provider,
                           selfie_file_id=files[0].id, document_file_id=files[2].id,
                           images_delete_after=utcnow() + timedelta(hours=ttl), created_by=user.id)
    try:
        res = biometrics.compare(storage.get(files[0].storage_key), storage.get(files[1].storage_key),
                                 storage.get(files[2].storage_key), initiator=user.id)
        check.match, check.liveness, check.score = bool(res["match"]), bool(res["liveness"]), int(res["score"])
        check.status = "passed" if check.match and check.liveness else "failed"
        if check.status == "passed":
            check.valid_until = utcnow().date() + timedelta(days=365)
    except IntegrationUnavailable:
        check.status = "unavailable"  # fallback: the moderator verifies the driver by documents
    # the second frame is only needed for liveness: delete it right away
    _delete_file(db, files[1])
    db.add(check)
    db.flush()
    audit(db, "kyc.biometric_check", object_type="driver", object_id=driver.id,
          details={"status": check.status, "score": check.score, "provider": check.provider})
    if check.status == "passed" and driver.reverify_reason:
        audit(db, "kyc.reverify_passed", object_type="driver", object_id=driver.id,
              details={"reason": driver.reverify_reason})
        driver.reverify_reason, driver.reverify_since = "", None  # FR-KYC-09: the repeated check is done
    if driver.company_id:
        from app.modules.accounts.models import Company
        from app.modules.fleet.level3 import evaluate

        evaluate(db, db.get(Company, driver.company_id))  # L3 depends on the drivers' biometrics
    return check


def _delete_file(db: Session, f: StoredFile | None) -> None:
    if f is None or f.is_deleted:
        return
    storage.delete(f.storage_key)
    f.is_deleted = True
    f.scan_status = "deleted"


def purge_images(db: Session, *, user_id=None, now=None) -> int:
    """Delete source images whose time is up (or all of a user's on consent withdrawal)."""
    now = now or utcnow()
    q = select(BiometricCheck).where(BiometricCheck.images_deleted_at.is_(None))
    if user_id is None:
        q = q.where(BiometricCheck.images_delete_after <= now)
    else:
        q = q.where(BiometricCheck.driver_id.in_(select(Driver.id).where(Driver.user_id == user_id)))
    n = 0
    for c in db.execute(q).scalars().all():
        for fid in (c.selfie_file_id, c.document_file_id):
            _delete_file(db, db.get(StoredFile, fid) if fid else None)
        c.selfie_file_id = c.document_file_id = None
        c.images_deleted_at = now
        n += 1
    if n:
        audit(db, "kyc.biometric_images_deleted", object_type="biometrics", object_id=str(user_id or "expired"),
              role="system" if user_id is None else None, details={"checks": n})
    return n
