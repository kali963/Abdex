"""Verification level L3 "усиленный" (section 8 of the ТЗ).

L3 = L2 (registries) plus:
* the company's qualified e-signature: a challenge signed with a certificate issued to the company's BIN and
  verified on the server (chain, validity, revocation, owner);
* for carriers — confirmed ownership of the vehicles (an approved technical passport for every approved vehicle)
  and the drivers' biometrics (the latest check of every approved driver passed with liveness).

The level is computed from these facts: it is granted as soon as all are true and withdrawn back to L2 when one
stops being true (a new vehicle without a passport, a failed biometric re-check). L3 opens valuable and
international cargo (setting ``kyc.l3_required_for``) and gives priority in matching (the level weight).
"""
from __future__ import annotations

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.audit import audit
from app.core.errors import AppError, Forbidden
from app.core.timeutil import local_today
from app.db import utcnow
from app.modules.accounts.models import Company
from app.modules.fleet.models import BiometricCheck, Driver, Vehicle, VerificationDocument


def required_for(db: Session, order) -> bool:
    from app.modules.platform.service import get_setting

    kinds = set(get_setting(db, "kyc.l3_required_for", ["international", "valuable"]) or [])
    return ("international" in kinds and order.is_international) or ("valuable" in kinds and order.cargo_type == "valuable")


def check_bid_allowed(db: Session, order, carrier: Company) -> None:
    if required_for(db, order) and carrier.verification_level < 3:
        raise Forbidden("l3_required")


def requirements(db: Session, company: Company) -> list[dict]:
    items = [{"code": "l2", "ok": company.verification_level >= 2},
             {"code": "eds", "ok": bool(company.eds_confirmed_at)}]
    if company.kind == "carrier":
        vehicles = list(db.execute(select(Vehicle).where(Vehicle.company_id == company.id, Vehicle.status == "approved",
                                                         Vehicle.is_deleted.is_(False))).scalars())
        owned = set(db.execute(select(VerificationDocument.subject_id).where(
            VerificationDocument.company_id == company.id, VerificationDocument.subject_type == "vehicle",
            VerificationDocument.doc_type == "tech_passport", VerificationDocument.status == "approved")).scalars())
        missing_v = [v.plate for v in vehicles if v.id not in owned]
        items.append({"code": "vehicles", "ok": bool(vehicles) and not missing_v, "missing": missing_v})
        drivers = list(db.execute(select(Driver).where(Driver.company_id == company.id, Driver.status == "approved",
                                                       Driver.is_deleted.is_(False))).scalars())
        missing_d = []
        for d in drivers:
            last = db.execute(select(BiometricCheck).where(BiometricCheck.driver_id == d.id)
                              .order_by(BiometricCheck.created_at.desc())).scalars().first()
            fresh = last and (last.valid_until is None or last.valid_until >= local_today())
            if not (last and last.status == "passed" and last.match and last.liveness and fresh) or d.reverify_reason:
                missing_d.append(d.full_name)
        items.append({"code": "biometrics", "ok": bool(drivers) and not missing_d, "missing": missing_d})
    return items


def evaluate(db: Session, company: Company) -> int:
    """Grant or withdraw L3 according to the facts; returns the resulting level."""
    from app.modules.notifications.service import notify_company_owners

    ok = all(i["ok"] for i in requirements(db, company))
    if ok and company.verification_level == 2:
        company.verification_level = 3
        audit(db, "verification.level_l3", object_type="company", object_id=company.id, role="system")
        notify_company_owners(db, company.id, "verification.l3_granted", {}, link="/company/verification")
    elif not ok and company.verification_level == 3:
        company.verification_level = 2
        audit(db, "verification.level_downgraded", object_type="company", object_id=company.id, role="system",
              details={"to": 2, "missing": [i["code"] for i in requirements(db, company) if not i["ok"]]})
        notify_company_owners(db, company.id, "verification.l3_lost", {}, link="/company/verification")
    return company.verification_level


def confirm_eds(db: Session, company: Company, package: str, challenge: str) -> Company:
    """The challenge is signed with a certificate of the company: the owner check is the company's BIN."""
    from app.modules.accounts.eds_login import consume
    from app.modules.documents import eds
    from app.modules.platform.service import flag_enabled, get_setting

    if not flag_enabled(db, "qualified_signature", company.id):
        raise AppError("qualified_signature_off", status_code=403)
    if not package or len(package) > 200_000:
        raise AppError("eds_invalid", status_code=422, checks="package")
    consume(db, challenge)
    revoked = set(get_setting(db, "eds.revoked_serials", []) or [])
    res = eds.verifier().verify(package, challenge.encode(), signed_at=utcnow(), expected_bin=company.bin_iin,
                                revoked=revoked)
    audit(db, "company.eds_check", object_type="company", object_id=company.id,
          result="ok" if res.valid else "denied", details={"checks": res.checks})
    if not res.valid:
        failed = [k for k, v in res.checks.items() if not v] or [res.error or "invalid"]
        raise AppError("eds_invalid", status_code=422, checks=", ".join(failed))
    company.eds_confirmed_at, company.eds_cert_serial = utcnow(), str(res.signer.get("serial", ""))[:80]
    evaluate(db, company)
    return company


def evaluate_all(db: Session) -> int:
    """Worker job: L2/L3 companies are re-evaluated (a new vehicle, an expired biometric check...)."""
    from app.core import rls

    n = 0
    with rls.system(db):
        for c in db.execute(select(Company).where(Company.verification_level.in_((2, 3)))).scalars():
            before = c.verification_level
            if evaluate(db, c) != before:
                n += 1
    db.commit()
    return n
