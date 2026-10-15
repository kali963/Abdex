"""Second-person approval of privileged operations (SEC-AZ-05).

Blocking a company, creating or changing a tariff, rolling a status back and reversing an accrual are not
executed by the person who asks for them. The request waits in /admin/approvals until another staff member
with the right to approve it confirms; only then the operation runs, inside the approving transaction.
Requests expire after a day so that a forgotten request cannot be approved much later out of context.
"""
from __future__ import annotations

import json
from datetime import date, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.audit import audit
from app.core.errors import AppError, Conflict, Forbidden, NotFound, ValidationFailed
from app.db import utcnow
from app.modules.accounts.models import STAFF_ROLES, Company, User
from app.modules.accounts.permissions import staff_can
from app.modules.platform.models import ApprovalRequest, Restriction

TTL = timedelta(hours=24)
# kind -> permissions that allow approving it (any of them)
APPROVER_PERMS = {
    "company_block": ("admin.users",),
    "tariff_change": ("admin.finance",),
    "status_rollback": ("admin.rollback", "admin.orders"),
    "storno": ("admin.finance",),
}


def request(db: Session, kind: str, *, staff: User, payload: dict, object_id="", summary: str = "",
            reason: str = "") -> ApprovalRequest:
    if kind not in APPROVER_PERMS:
        raise ValidationFailed({"kind": "error.invalid_choice"})
    if not reason.strip():
        raise ValidationFailed({"reason": "error.reason_required"})
    req = ApprovalRequest(kind=kind, object_id=str(object_id or ""), payload=json.dumps(payload, ensure_ascii=False,
                                                                                      default=str),
                          summary=summary[:300], reason=reason.strip()[:500], requested_by=staff.id,
                          created_by=staff.id, expires_at=utcnow() + TTL)
    db.add(req)
    db.flush()
    audit(db, "approval.requested", object_type="approval", object_id=req.id, reason=reason,
          details={"kind": kind, "object": req.object_id})
    from app.modules.notifications.service import notify_user

    for uid in approvers(db, kind, exclude=staff.id):
        notify_user(db, uid, "approval.requested", {"summary": req.summary}, link="/admin/approvals",
                    dedup=f"approval:{req.id}:{uid}")
    return req


def approvers(db: Session, kind: str, *, exclude=None) -> list:
    users = db.execute(select(User).where(User.staff_role.in_(STAFF_ROLES), User.is_blocked.is_(False))).scalars()
    return [u.id for u in users if u.id != exclude and any(staff_can(u.staff_role, p) for p in APPROVER_PERMS[kind])]


def can_approve(user: User, req: ApprovalRequest) -> bool:
    return user.id != req.requested_by and any(staff_can(user.staff_role, p) for p in APPROVER_PERMS[req.kind])


def pending(db: Session) -> list[ApprovalRequest]:
    now = utcnow()
    rows = list(db.execute(select(ApprovalRequest).where(ApprovalRequest.status == "pending")
                           .order_by(ApprovalRequest.created_at)).scalars())
    for r in rows:
        if r.expires_at < now:
            r.status = "expired"
    return [r for r in rows if r.status == "pending"]


def recent(db: Session, limit: int = 50) -> list[ApprovalRequest]:
    return list(db.execute(select(ApprovalRequest).where(ApprovalRequest.status != "pending")
                           .order_by(ApprovalRequest.updated_at.desc()).limit(limit)).scalars())


def decide(db: Session, req_id, *, staff: User, approve: bool, note: str = "") -> ApprovalRequest:
    req = db.execute(select(ApprovalRequest).where(ApprovalRequest.id == req_id).with_for_update()).scalar_one_or_none()
    if req is None:
        raise NotFound()
    if req.status != "pending":
        raise Conflict("already_decided")
    if req.expires_at < utcnow():
        req.status = "expired"
        raise Conflict("approval_expired")
    if staff.id == req.requested_by:
        raise Forbidden("approval_same_person")  # the second person is the whole point
    if not can_approve(staff, req):
        raise Forbidden()
    req.decided_by, req.decided_at, req.decision_note = staff.id, utcnow(), note[:500]
    if not approve:
        req.status = "rejected"
        audit(db, "approval.rejected", object_type="approval", object_id=req.id, reason=note)
        return req
    try:
        with db.begin_nested():
            EXECUTORS[req.kind](db, json.loads(req.payload), requester=db.get(User, req.requested_by),
                                approver=staff, reason=req.reason)
    except AppError as exc:
        req.status = "failed"
        req.decision_note = f"{note[:300]} [{exc.code}]"
        audit(db, "approval.failed", object_type="approval", object_id=req.id, result="error",
              details={"code": exc.code})
        return req
    req.status = "executed"
    audit(db, "approval.executed", object_type="approval", object_id=req.id,
          details={"kind": req.kind, "requested_by": str(req.requested_by)})
    return req


# ------------------------------------------------------------------ executors


def _company_block(db: Session, p: dict, *, requester: User, approver: User, reason: str) -> None:
    import uuid

    company = db.get(Company, uuid.UUID(p["company_id"]))
    if company is None:
        raise AppError("object_missing")
    until = date.fromisoformat(p["until"]) if p.get("until") else None
    db.add(Restriction(company_id=company.id, kind="block", reason=reason, until=until, created_by=requester.id))
    company.is_blocked = True
    audit(db, "staff.company_restricted", object_type="company", object_id=company.id, reason=reason,
          details={"kind": "block", "approved_by": str(approver.id)}, user_id=requester.id)
    from app.modules.notifications.service import notify_company_owners

    notify_company_owners(db, company.id, "account.restricted", {"reason": reason}, link="/support", critical=True)


def _tariff_change(db: Session, p: dict, *, requester: User, approver: User, reason: str) -> None:
    import uuid

    from app.modules.billing.models import Tariff

    t = Tariff(name=p["name"], model=p["model"], fixed_minor=int(p["fixed_minor"]), percent_bp=int(p["percent_bp"]),
               min_minor=int(p["min_minor"]), max_minor=int(p["max_minor"]),
               company_id=uuid.UUID(p["company_id"]) if p.get("company_id") else None,
               deal_type=p.get("deal_type", "any"), valid_from=date.fromisoformat(p["valid_from"]),
               valid_to=date.fromisoformat(p["valid_to"]) if p.get("valid_to") else None, created_by=requester.id)
    db.add(t)
    db.flush()
    audit(db, "staff.tariff_created", object_type="tariff", object_id=t.id,
          details={"approved_by": str(approver.id)}, user_id=requester.id)


def _status_rollback(db: Session, p: dict, *, requester: User, approver: User, reason: str) -> None:
    import uuid

    from app.modules.deals.models import Deal
    from app.modules.notifications.service import notify_event
    from app.modules.orders import flow

    order = flow.lock_order(db, uuid.UUID(p["order_id"]))
    flow.rollback(db, order, p["to"], reason=reason, user_id=requester.id)
    deal = db.execute(select(Deal).where(Deal.order_id == order.id)).scalar_one_or_none()
    notify_event(db, "order.status", params={"number": order.number, "status": order.status},
                 link=f"/deals/{deal.id}" if deal else f"/orders/{order.id}", client_company_id=order.client_company_id,
                 carrier_company_id=deal.carrier_company_id if deal else None)
    audit(db, "staff.status_rollback", object_type="order", object_id=order.id, reason=reason,
          details={"approved_by": str(approver.id)}, user_id=requester.id)


def _storno(db: Session, p: dict, *, requester: User, approver: User, reason: str) -> None:
    import uuid

    from app.modules.billing.models import Accrual
    from app.modules.billing.service import storno

    accrual = db.get(Accrual, uuid.UUID(p["accrual_id"]))
    if accrual is None:
        raise AppError("object_missing")
    storno(db, accrual, reason)


EXECUTORS = {"company_block": _company_block, "tariff_change": _tariff_change,
             "status_rollback": _status_rollback, "storno": _storno}
