"""Object-level access checks shared by web and API routes (SEC-AZ-01/02, FR-ACL-05)."""
from __future__ import annotations

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from app.core.audit import audit
from app.core.errors import NotFound
from app.modules.accounts.permissions import company_can, staff_can
from app.modules.chat.models import Message
from app.modules.deals.models import Checkpoint, Deal
from app.modules.deals.service import get_access
from app.modules.documents.models import Document, StoredFile
from app.modules.fleet.models import VerificationDocument
from app.web.deps import Principal


def deal_access(db: Session, me: Principal, deal_id, *, staff: bool = False):
    """Staff see deals only through the audited admin route (staff=True); in the cabinet only the
    company sides and the assigned driver get access."""
    return get_access(db, deal_id, user=me.user, company_id=me.company.id if me.company else None, role=me.role,
                      allow_staff=staff and me.session.is_admin)


def assert_file_access(db: Session, me: Principal, file_id) -> None:
    f = db.get(StoredFile, file_id)
    if f is None:
        raise NotFound()
    if me.session.is_admin and me.user.staff_role:
        allowed = (staff_can(me.user.staff_role, "admin.deal_content")
                   or staff_can(me.user.staff_role, "admin.moderation"))
        if not allowed:
            raise NotFound()  # e.g. the security auditor never sees content
        audit(db, "staff.file_viewed", object_type="file", object_id=file_id, reason="admin access")
        return
    company_id = me.company.id if me.company else None
    from app.modules.documents.service import FINANCIAL_DOC_TYPES
    from app.modules.fleet.models import BiometricCheck, Driver

    bio = db.execute(select(BiometricCheck).where(or_(BiometricCheck.selfie_file_id == file_id,
                                                      BiometricCheck.document_file_id == file_id))).scalars().first()
    if bio is not None:
        # SEC-DAT-10: biometric images are seen by the driver alone (and the moderator above), not the employer
        drv = db.get(Driver, bio.driver_id)
        if drv is not None and drv.user_id == me.user.id:
            return
        raise NotFound()

    for doc in db.execute(select(Document).where(Document.file_id == file_id)).scalars():
        if doc.doc_type in FINANCIAL_DOC_TYPES:
            # platform fee documents belong to the payer only
            if company_id and doc.company_id == company_id and company_can(me.role, "finance.view"):
                return
            raise NotFound()
    deal_ids = set()
    for model, col in ((Document, Document.file_id), (Message, Message.attachment_file_id),
                       (Checkpoint, Checkpoint.photo_file_id)):
        deal_ids |= {d for d in db.execute(select(model.deal_id).where(col == file_id)).scalars() if d}
    for deal_id in deal_ids:
        try:
            deal_access(db, me, deal_id)
            return
        except Exception:  # noqa: BLE001, S112 — no access via this deal, try the next linkage
            continue
    if company_id and f.owner_company_id == company_id and not deal_ids:
        vd = db.execute(select(VerificationDocument.id).where(VerificationDocument.file_id == file_id,
                                                              VerificationDocument.company_id == company_id)).first()
        if me.role in ("owner", "fleet_owner", "accountant", "dispatcher", "logist") or (vd and me.role != "driver"):
            return
    raise NotFound()


def company_deal_ids(db: Session, company_id) -> list:
    return list(db.execute(select(Deal.id).where(or_(Deal.client_company_id == company_id,
                                                     Deal.carrier_company_id == company_id))).scalars())
