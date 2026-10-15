"""Support tickets (M14, FR-SUP-01/02/04)."""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.audit import audit
from app.core.context import get_ctx
from app.core.errors import ValidationFailed
from app.db import utcnow
from app.modules.chat.service import post
from app.modules.platform.models import Ticket
from app.modules.platform.service import dictionary_extra, next_number


def create_ticket(db: Session, *, category: str, subject: str, body: str, deal_id=None) -> Ticket:
    ctx = get_ctx()
    if not subject.strip() or not body.strip():
        raise ValidationFailed({"subject": "error.required"})
    cats = dictionary_extra(db, "support_categories")
    if category not in cats:
        raise ValidationFailed({"category": "error.invalid_choice"})
    sla_hours = int(cats[category].get("sla_hours", 24))
    priority = cats[category].get("priority", "normal")
    t = Ticket(number=next_number(db, "ticket", "TK"), company_id=ctx.company_id, user_id=ctx.user_id,
               deal_id=deal_id, category=category, priority=priority, subject=subject.strip()[:300],
               sla_due_at=utcnow() + timedelta(hours=sla_hours), created_by=ctx.user_id)
    db.add(t)
    db.flush()
    post(db, ticket_id=t.id, body=body)
    audit(db, "support.ticket_created", object_type="ticket", object_id=t.id)
    return t


def my_tickets(db: Session, user_id) -> list[Ticket]:
    return list(db.execute(select(Ticket).where(Ticket.user_id == user_id).order_by(Ticket.created_at.desc())).scalars())


def problem_report(db: Session) -> list[tuple[str, int, int]]:
    """FR-SUP-04: recurring problems grouped by category (count, overdue)."""
    now = utcnow()
    rows = db.execute(select(Ticket.category, func.count(Ticket.id)).group_by(Ticket.category)).all()
    out = []
    for cat, cnt in rows:
        overdue = db.execute(select(func.count(Ticket.id)).where(Ticket.category == cat, Ticket.status != "resolved",
                                                                 Ticket.sla_due_at < now)).scalar_one()
        out.append((cat, cnt, overdue))
    return sorted(out, key=lambda x: -x[1])
