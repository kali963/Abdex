"""Driver biometric check (FR-KYC-08) with the storage rules of SEC-DAT-10.

* Only after the separate "biometrics" consent; revoking it deletes any images still kept at once (a check
  still waiting for the moderator becomes "withdrawn").
* The driver sends two selfie frames (the second with the head turned — a live person, not a photo) and a photo
  of the ID document. Nothing is approved automatically: the check waits for a moderator (/admin/biometrics),
  who compares the face with the document photo, looks at the head turn and the document, and approves or
  rejects with a reason. Obvious junk (the same picture twice, a non-image) is refused at once.
* Only the result (decision, who and when, reason, validity) is kept for long; the images are kept until the
  decision and then deleted after ``biometrics.image_ttl_hours`` (24 h by default) by the retention job.
* An automatic provider (BIOMETRICS_MODE=provider) can replace the moderator once a licensed provider is
  connected; it receives data only while the processing register has an active record for it (SEC-DAT-11).
"""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.timeutil import local_today
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


def mode() -> str:
    """"manual" (default): every check is decided by a moderator. "provider": the provider adapter decides."""
    import os

    return "provider" if os.getenv("BIOMETRICS_MODE", "").strip().lower() == "provider" else "manual"


def pending_for(db: Session, driver_id) -> BiometricCheck | None:
    return db.execute(select(BiometricCheck).where(BiometricCheck.driver_id == driver_id,
                                                   BiometricCheck.status == "pending")).scalars().first()


def run_check(db: Session, user: User, *, selfie: bytes, selfie2: bytes, document: bytes) -> BiometricCheck:
    import hashlib

    from app.modules.accounts.service import has_consent
    from app.modules.integrations.adapters import biometrics
    from app.modules.platform.service import get_setting

    if not has_consent(db, user.id, "biometrics"):
        raise Forbidden("biometrics_consent_required")
    driver = driver_of(db, user)
    if not (selfie and selfie2 and document):
        raise ValidationFailed({"selfie": "error.required"})
    if pending_for(db, driver.id) is not None:
        raise ValidationFailed({"selfie": "error.bio_already_pending"})
    digests = {hashlib.sha256(x).hexdigest() for x in (selfie, selfie2, document)}
    if len(digests) < 3:  # the same picture sent twice: not a live person, not a document
        raise ValidationFailed({"selfie2": "error.bio_same_photo"})
    files = [save_upload(db, data=data, original_name=name, company_id=driver.company_id, user_id=user.id,
                         allowed=IMAGE_TYPES) for data, name in ((selfie, "selfie.jpg"), (selfie2, "selfie2.jpg"),
                                                                 (document, "document.jpg"))]
    ttl = int(get_setting(db, "biometrics.image_ttl_hours", 24))
    check = BiometricCheck(driver_id=driver.id, company_id=driver.company_id, selfie_file_id=files[0].id,
                           selfie2_file_id=files[1].id, document_file_id=files[2].id, created_by=user.id)
    if mode() == "manual":
        check.provider, check.status = "moderator", "pending"  # images kept until the decision
    else:
        check.provider = biometrics.provider
        check.images_delete_after = utcnow() + timedelta(hours=ttl)
        try:
            res = biometrics.compare(storage.get(files[0].storage_key), storage.get(files[1].storage_key),
                                     storage.get(files[2].storage_key), initiator=user.id)
            check.match, check.liveness, check.score = bool(res["match"]), bool(res["liveness"]), int(res["score"])
            check.status = "passed" if check.match and check.liveness else "failed"
            if check.status == "passed":
                check.valid_until = local_today() + timedelta(days=365)
        except IntegrationUnavailable:
            check.status = "pending"  # the provider is down: the moderator decides
            check.images_delete_after = None
        if check.status != "pending":  # the second frame was only needed for liveness
            _delete_file(db, files[1])
            check.selfie2_file_id = None
    db.add(check)
    db.flush()
    audit(db, "kyc.biometric_check", object_type="driver", object_id=driver.id,
          details={"status": check.status, "score": check.score, "provider": check.provider})
    if check.status == "passed":
        _after_pass(db, driver)
    return check


def _after_pass(db: Session, driver: Driver) -> None:
    if driver.reverify_reason:
        audit(db, "kyc.reverify_passed", object_type="driver", object_id=driver.id,
              details={"reason": driver.reverify_reason})
        driver.reverify_reason, driver.reverify_since = "", None  # FR-KYC-09: the repeated check is done
    if driver.company_id:
        from app.modules.accounts.models import Company
        from app.modules.fleet.level3 import evaluate

        evaluate(db, db.get(Company, driver.company_id))  # L3 depends on the drivers' biometrics


REJECT_REASONS = ("face_mismatch", "not_live", "not_a_document", "unreadable", "document_expired", "other")


def review(db: Session, check: BiometricCheck, *, moderator: User, approve: bool, face_match: bool = False,
           live: bool = False, document_ok: bool = False, reason: str = "", comment: str = "") -> None:
    """The moderator's decision. Approval needs all three confirmations; a rejection needs a reason."""
    from app.modules.notifications.service import notify_user
    from app.modules.platform.service import get_setting

    if check.status != "pending":
        raise ValidationFailed({"decision": "error.already_decided"})
    if approve and not (face_match and live and document_ok):
        raise ValidationFailed({"decision": "error.bio_confirm_all"})
    if not approve and reason not in REJECT_REASONS:
        raise ValidationFailed({"reason": "error.required"})
    if not approve and reason == "other" and not comment.strip():
        raise ValidationFailed({"comment": "error.required"})
    driver = db.get(Driver, check.driver_id)
    now = utcnow()
    check.reviewed_by, check.reviewed_at = moderator.id, now
    check.review_reason = "" if approve else reason
    check.review_comment = comment.strip()[:500]
    check.match, check.liveness = (face_match, live) if approve else (False, False)
    check.score = 100 if approve else 0
    check.status = "passed" if approve else "failed"
    if approve:
        check.valid_until = local_today() + timedelta(days=365)
    ttl = int(get_setting(db, "biometrics.image_ttl_hours", 24))
    check.images_delete_after = now + timedelta(hours=ttl)  # SEC-DAT-10: images go soon after the decision
    audit(db, "kyc.biometric_reviewed", object_type="driver", object_id=check.driver_id,
          result="ok" if approve else "rejected", reason=reason,
          details={"check": str(check.id), "approve": approve})
    if approve and driver is not None:
        _after_pass(db, driver)
    if driver is not None and driver.user_id:
        notify_user(db, driver.user_id, "biometrics.approved" if approve else "biometrics.rejected",
                    {"reason": reason}, link="/trips/biometrics", channels=["web", "push", "telegram"])
    db.flush()


def queue(db: Session, *, status: str = "pending", limit: int = 200) -> list[tuple[BiometricCheck, Driver]]:
    q = (select(BiometricCheck, Driver).join(Driver, Driver.id == BiometricCheck.driver_id)
         .order_by(BiometricCheck.created_at if status == "pending" else BiometricCheck.created_at.desc())
         .limit(limit))
    if status == "pending":
        q = q.where(BiometricCheck.status == "pending")
    else:
        q = q.where(BiometricCheck.status != "pending")
    return list(db.execute(q).all())


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
        for fid in (c.selfie_file_id, c.selfie2_file_id, c.document_file_id):
            _delete_file(db, db.get(StoredFile, fid) if fid else None)
        c.selfie_file_id = c.selfie2_file_id = c.document_file_id = None
        if c.status == "pending":  # consent revoked before the decision: nothing left to review
            c.status = "withdrawn"
        c.images_deleted_at = now
        n += 1
    if n:
        audit(db, "kyc.biometric_images_deleted", object_type="biometrics", object_id=str(user_id or "expired"),
              role="system" if user_id is None else None, details={"checks": n})
    return n
