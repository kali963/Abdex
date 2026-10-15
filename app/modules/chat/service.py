"""Deal chat and support threads (M7)."""
from __future__ import annotations

import json

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core import events, ratelimit
from app.core.audit import audit
from app.core.context import get_ctx
from app.core.errors import ValidationFailed
from app.modules.chat.leaks import mask_contacts
from app.modules.chat.models import Message, MessageHidden, MessageRead

MAX_LEN = 4000


def post(db: Session, *, deal_id=None, ticket_id=None, body: str, attachment_file_id=None, kind: str = "user") -> Message:
    ctx = get_ctx()
    ratelimit.hit("chat", str(ctx.user_id))
    body = (body or "").strip()
    if not body and not attachment_file_id:
        raise ValidationFailed({"body": "error.required"})
    flags = ""
    from app.modules.platform.service import get_setting

    # FR-CHAT-05: behaviour is configurable: warn / mask / moderate
    mode = get_setting(db, "chat.leak_mode", "flag")
    masked, leaked = mask_contacts(body)
    if leaked:
        flags = "contact_leak"
        if mode == "mask":
            body = masked
    msg = Message(deal_id=deal_id, ticket_id=ticket_id, author_user_id=ctx.user_id, author_company_id=ctx.company_id,
                  kind=kind, body=body[:MAX_LEN], attachment_file_id=attachment_file_id, flags=flags,
                  created_by=ctx.user_id)
    db.add(msg)
    db.flush()
    return msg


def post_system(db: Session, *, deal_id, key: str, **params) -> Message:
    msg = Message(deal_id=deal_id, kind="system", body=json.dumps({"key": key, "params": params}, ensure_ascii=False))
    db.add(msg)
    db.flush()
    return msg


def hide(db: Session, message_id, reason: str) -> None:
    """FR-CHAT-04: moderator hides a message; original content remains for the audit trail."""
    try:
        with db.begin_nested():
            db.add(MessageHidden(message_id=message_id, reason=reason[:300], created_by=get_ctx().user_id))
            db.flush()
    except IntegrityError:
        return
    audit(db, "chat.message_hidden", object_type="message", object_id=message_id, reason=reason)


def thread_messages(db: Session, *, deal_id=None, ticket_id=None, include_hidden: bool = False, after=None) -> list[Message]:
    stmt = select(Message)
    stmt = stmt.where(Message.deal_id == deal_id) if deal_id else stmt.where(Message.ticket_id == ticket_id)
    if after:
        stmt = stmt.where(Message.id > after)
    msgs = list(db.execute(stmt.order_by(Message.created_at, Message.id)).scalars())
    if include_hidden:
        return msgs
    hidden = set(db.execute(select(MessageHidden.message_id).where(
        MessageHidden.message_id.in_([m.id for m in msgs]))).scalars()) if msgs else set()
    return [m for m in msgs if m.id not in hidden]


def mark_read(db: Session, messages: list[Message], user_id) -> None:
    if not messages:
        return
    already = set(db.execute(select(MessageRead.message_id).where(MessageRead.user_id == user_id,
                                                                  MessageRead.message_id.in_([m.id for m in messages]))
                             ).scalars())
    for m in messages:
        if m.id not in already and m.author_user_id != user_id:
            db.add(MessageRead(message_id=m.id, user_id=user_id))


def read_by_others(db: Session, message_ids, author_id) -> set:
    if not message_ids:
        return set()
    return set(db.execute(select(MessageRead.message_id).where(MessageRead.message_id.in_(message_ids),
                                                               MessageRead.user_id != author_id)).scalars())


@events.subscribe("order.status_changed")
def _status_to_chat(db: Session, order, frm, to, actor, reason, rollback, **_):
    """FR-CHAT-02: one chronology of events and messages."""
    from app.modules.deals.models import Deal

    deal = db.execute(select(Deal).where(Deal.order_id == order.id)).scalar_one_or_none()
    if deal is None:
        return
    post_system(db, deal_id=deal.id, key="sys.status_changed", frm=frm, to=to, rollback=rollback)
