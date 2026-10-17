"""Verification of participants and fleet (M2): documents, moderation, duplicates, expiry."""
from __future__ import annotations

import json
from datetime import date, timedelta

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.core.audit import audit
from app.core.context import get_ctx
from app.core.crypto import blind_index
from app.core.errors import AppError, NotFound, ValidationFailed
from app.core.timeutil import local_today
from app.db import utcnow
from app.modules.accounts.models import BankAccount, Company, Membership, User
from app.modules.fleet.models import Driver, RegistryCheck, Vehicle, VerificationDocument, VerificationRequest
from app.modules.integrations.adapters import registry
from app.modules.integrations.base import IntegrationUnavailable
from app.modules.platform.service import get_setting, raise_alert

REQUIRED_COMPANY_DOCS = ("registration_certificate", "bank_details")
REQUIRED_DRIVER_DOCS = ("id_card", "driver_license")
REQUIRED_VEHICLE_DOCS = ("tech_passport", "insurance")


def add_vehicle(db: Session, company: Company, **fields) -> Vehicle:
    plate = (fields.get("plate") or "").replace(" ", "").upper()
    if not plate:
        raise ValidationFailed({"plate": "error.required"})
    v = Vehicle(company_id=company.id, plate=plate, vin=(fields.get("vin") or "").upper(),
                category=fields.get("category") or "C", body_type=fields.get("body_type") or "tent",
                capacity_kg=int(fields.get("capacity_kg") or 0), volume_m3=int(fields.get("volume_m3") or 0),
                dimensions=fields.get("dimensions") or "", insurance_until=fields.get("insurance_until"),
                has_tachograph=bool(fields.get("has_tachograph")), adr_allowed=bool(fields.get("adr_allowed")),
                international_permit=bool(fields.get("international_permit")), created_by=get_ctx().user_id)
    db.add(v)
    db.flush()
    detect_duplicates(db, company_id=company.id, plate=plate)
    audit(db, "fleet.vehicle_added", object_type="vehicle", object_id=v.id)
    return v


def add_driver(db: Session, company: Company, **fields) -> Driver:
    iin = (fields.get("iin") or "").strip()
    if not fields.get("full_name"):
        raise ValidationFailed({"full_name": "error.required"})
    d = Driver(company_id=company.id, full_name=fields["full_name"].strip(), iin=iin,
               phone=fields.get("phone") or "", license_number=fields.get("license_number") or "",
               license_categories=fields.get("license_categories") or "C,CE",
               license_until=fields.get("license_until"), adr_permit=bool(fields.get("adr_permit")),
               created_by=get_ctx().user_id)
    db.add(d)
    db.flush()
    if iin:
        detect_duplicates(db, company_id=company.id, iin=iin)
    audit(db, "fleet.driver_added", object_type="driver", object_id=d.id)
    return d


def company_vehicles(db: Session, company_id) -> list[Vehicle]:
    return list(db.execute(select(Vehicle).where(Vehicle.company_id == company_id, Vehicle.is_deleted.is_(False))
                           .order_by(Vehicle.plate)).scalars())


def company_drivers(db: Session, company_id) -> list[Driver]:
    return list(db.execute(select(Driver).where(Driver.company_id == company_id, Driver.is_deleted.is_(False))
                           .order_by(Driver.full_name)).scalars())


# --------------------------------------------------------------------- duplicates (FR-KYC-07)


def _other_companies(db: Session, company_id, ids) -> set:
    return {c for c in ids if c and c != company_id}


def detect_duplicates(db: Session, *, company_id, bin_iin: str = "", iin: str = "", plate: str = "",
                      iban: str = "") -> list:
    """One IIN / plate / IBAN cannot be active at unrelated companies at once.
    A conflict raises an alert into the antifraud queue — it does not block silently."""
    alerts = []
    checks = []
    if plate:
        ids = db.execute(select(Vehicle.company_id).where(Vehicle.plate == plate, Vehicle.is_deleted.is_(False))).scalars()
        checks.append(("duplicate_vehicle_plate", _other_companies(db, company_id, ids), {"plate": plate}))
    if iin:
        idx = blind_index(iin, "iin")
        ids = db.execute(select(Driver.company_id).where(Driver.iin_index == idx, Driver.is_deleted.is_(False))).scalars()
        # a driver legitimately exists in his own self-employed profile and in a fleet he joined
        own_user_ids = set(db.execute(select(Driver.user_id).where(Driver.iin_index == idx, Driver.user_id.is_not(None))).scalars())
        others = _other_companies(db, company_id, ids)
        if len(own_user_ids) == 1 and others:
            uid = next(iter(own_user_ids))
            linked = set(db.execute(select(Membership.company_id).where(Membership.user_id == uid)).scalars())
            others -= linked
        checks.append(("duplicate_driver_iin", others, {"iin_tail": iin[-4:]}))
    if iban:
        ids = db.execute(select(BankAccount.company_id).where(BankAccount.iban_index == blind_index(iban, "iban"),
                                                              BankAccount.status == "active")).scalars()
        checks.append(("duplicate_iban", _other_companies(db, company_id, ids), {"iban_tail": iban[-4:]}))
    if bin_iin:
        ids = db.execute(select(Company.id).where(Company.bin_iin == bin_iin, Company.is_deleted.is_(False))).scalars()
        checks.append(("duplicate_company_bin", _other_companies(db, company_id, ids), {"bin_tail": bin_iin[-4:]}))
    for kind, others, details in checks:
        if others:
            details["other_companies"] = [str(o) for o in others]
            alert = raise_alert(db, kind, severity="high", company_id=company_id, details=details)
            if alert is not None:
                alerts.append(alert)
    return alerts


# --------------------------------------------------------------------- documents & moderation


def attach_verification_document(db: Session, company: Company, *, subject_type: str, subject_id, doc_type: str,
                                 file_id, expires_on: date | None) -> VerificationDocument:
    if subject_type == "vehicle":
        v = db.get(Vehicle, subject_id)
        if v is None or v.company_id != company.id:
            raise NotFound()
    elif subject_type == "driver":
        d = db.get(Driver, subject_id)
        if d is None or d.company_id != company.id:
            raise NotFound()
    else:
        subject_type, subject_id = "company", company.id
    doc = VerificationDocument(company_id=company.id, subject_type=subject_type, subject_id=subject_id,
                               doc_type=doc_type, file_id=file_id, expires_on=expires_on, created_by=get_ctx().user_id)
    db.add(doc)
    db.flush()
    audit(db, "verification.document_uploaded", object_type="verification_document", object_id=doc.id,
          details={"doc_type": doc_type})
    return doc


def submit_for_verification(db: Session, company: Company) -> VerificationRequest:
    pending = db.execute(select(VerificationRequest).where(VerificationRequest.company_id == company.id,
                                                           VerificationRequest.status == "pending")).scalars().first()
    if pending:
        return pending
    docs = {d.doc_type for d in db.execute(select(VerificationDocument).where(
        VerificationDocument.company_id == company.id, VerificationDocument.subject_type == "company")).scalars()}
    missing = [d for d in REQUIRED_COMPANY_DOCS if d not in docs]
    if missing:
        raise AppError("verification_docs_missing", missing=", ".join(missing))
    sla_hours = int(get_setting(db, "sla.moderation_hours", 24))
    req = VerificationRequest(company_id=company.id, level_requested=max(1, company.verification_level + 1),
                              sla_due_at=utcnow() + timedelta(hours=sla_hours), created_by=get_ctx().user_id)
    db.add(req)
    db.flush()
    run_registry_check(db, company, basis="user_action")
    audit(db, "verification.submitted", object_type="company", object_id=company.id)
    return req


def run_registry_check(db: Session, company: Company, *, basis: str) -> RegistryCheck | None:
    """FR-KYC-06 / GOV-R-02/03: requires a basis; result saved with source, status and TTL.
    If the source is unavailable the moderator checks manually (INT-GEN-03, GOV-R-08)."""
    if basis not in ("consent", "user_action", "scheduled"):
        raise AppError("check_without_basis")
    try:
        res = registry.check_company(company.bin_iin, basis=basis, initiator=get_ctx().user_id)
    except IntegrationUnavailable:
        rc = RegistryCheck(subject_type="company", subject_key=company.bin_iin, company_id=company.id,
                           source=registry.source, basis=basis, status="unavailable", result="{}")
        db.add(rc)
        return rc
    from datetime import datetime as _dt

    rc = RegistryCheck(subject_type="company", subject_key=company.bin_iin, company_id=company.id,
                       source=res["source"], basis=basis, status=res["status"],
                       result=json.dumps(res.get("data", {}), ensure_ascii=False),
                       valid_until=_dt.fromisoformat(res["valid_until"]))
    db.add(rc)
    if res["status"] != "match":
        # GOV-R-06: a mismatch never blocks automatically — it becomes a moderator task
        raise_alert(db, "registry_mismatch", company_id=company.id, details={"source": res["source"]})
    return rc


def decide_verification(db: Session, req: VerificationRequest, *, approve: bool, reason_code: str, comment: str,
                        moderator: User) -> None:
    if req.status != "pending":
        raise AppError("already_decided")
    company = db.get(Company, req.company_id)
    req.status = "approved" if approve else "rejected"
    req.decided_by = moderator.id
    req.decided_at = utcnow()
    req.reason_code = reason_code
    req.comment = comment[:500]
    if approve:
        last_check = db.execute(select(RegistryCheck).where(RegistryCheck.company_id == company.id)
                                .order_by(RegistryCheck.created_at.desc())).scalars().first()
        level = req.level_requested
        if level >= 2 and not (last_check and last_check.status == "match"):
            level = 1
        company.verification_level = max(company.verification_level, level)
        if company.verification_level == 1 and company.deal_limit_minor is None:
            company.deal_limit_minor = int(get_setting(db, "kyc.l1_deal_limit_minor", 300_000_000))
        if company.verification_level >= 2:
            company.deal_limit_minor = None
            from app.modules.fleet.level3 import evaluate

            evaluate(db, company)  # L3 when the strengthened checks are already in place
        for doc in db.execute(select(VerificationDocument).where(VerificationDocument.company_id == company.id,
                                                                 VerificationDocument.status == "uploaded")).scalars():
            doc.status = "approved"
        for model in (Vehicle, Driver):
            for obj in db.execute(select(model).where(model.company_id == company.id, model.status == "pending")).scalars():
                obj.status = "approved"
    audit(db, "verification.decided", object_type="company", object_id=company.id,
          details={"approve": approve, "reason": reason_code})
    from app.modules.notifications.service import notify_company_owners

    notify_company_owners(db, company.id, "verification.approved" if approve else "verification.rejected",
                          {"reason": reason_code}, link="/company/verification")


def check_document_expiry(db: Session) -> int:
    """FR-KYC-05: notify 30/14/3 days before expiry and downgrade level on expiry."""
    today = local_today()
    count = 0
    from app.modules.notifications.service import notify_company_owners

    docs = db.execute(select(VerificationDocument).where(VerificationDocument.expires_on.is_not(None),
                                                         VerificationDocument.status == "approved")).scalars().all()
    for doc in docs:
        days = (doc.expires_on - today).days
        if days in (30, 14, 3):
            notify_company_owners(db, doc.company_id, "verification.doc_expiring",
                                  {"doc": doc.doc_type, "days": days}, link="/company/verification",
                                  dedup=f"exp:{doc.id}:{days}")
            count += 1
        elif days < 0:
            doc.status = "expired"
            company = db.get(Company, doc.company_id)
            if company and company.verification_level > 0:
                company.verification_level = 0
                audit(db, "verification.level_downgraded", object_type="company", object_id=company.id,
                      reason=f"document expired: {doc.doc_type}", user_id=None, company_id=company.id, role="system")
                notify_company_owners(db, company.id, "verification.downgraded", {"doc": doc.doc_type},
                                      link="/company/verification")
            count += 1
    return count


def company_stats(db: Session, company_id) -> dict:
    """FR-KYC-10: public card — no personal data or documents."""
    from app.modules.deals.models import Deal
    from app.modules.orders.models import Order

    company = db.get(Company, company_id)
    completed = db.execute(
        select(func.count(Deal.id)).join(Order, Order.id == Deal.order_id)
        .where(or_(Deal.carrier_company_id == company_id, Deal.client_company_id == company_id),
               Order.status == "completed")
    ).scalar_one()
    from app.modules.rating.service import compute

    r = compute(db, company_id)
    days = (utcnow() - company.created_at).days if company else 0
    return {"completed": completed, "rating": r["value"], "reviews_n": r["reviews_n"],
            "breakdowns": r["counts"]["breakdown"], "days_on_platform": days,
            "level": company.verification_level if company else 0}
