"""Audit logging (SEC-LOG-01..05). Sensitive values are masked before they reach the log."""
from __future__ import annotations

import json
import logging
import re

from sqlalchemy.orm import Session

from app.core.context import get_ctx
from app.modules.accounts.models import AuditLog

log = logging.getLogger("abdex.audit")

_SENSITIVE_KEYS = re.compile(r"(password|code|token|secret|otp|key|iban|iin|passport|document_number)", re.I)


def mask(value):
    if isinstance(value, dict):
        return {k: ("***" if _SENSITIVE_KEYS.search(k) else mask(v)) for k, v in value.items()}
    if isinstance(value, list):
        return [mask(v) for v in value]
    return value


def audit(db: Session, action: str, *, object_type: str = "", object_id=None, result: str = "ok",
          reason: str = "", details: dict | None = None, user_id=None, company_id=None, role: str | None = None) -> None:
    ctx = get_ctx()
    entry = AuditLog(
        user_id=user_id if user_id is not None else ctx.user_id,
        company_id=company_id if company_id is not None else ctx.company_id,
        role=role if role is not None else (ctx.role or ""),
        action=action,
        object_type=object_type,
        object_id=str(object_id or ""),
        result=result,
        ip=ctx.ip,
        device=ctx.device_id,
        request_id=ctx.request_id,
        reason=reason[:300],
        details=json.dumps(mask(details or {}), ensure_ascii=False, default=str),
    )
    db.add(entry)
    log.info(json.dumps({"audit": action, "object": object_type, "id": str(object_id or ""), "result": result,
                         "request_id": ctx.request_id}, ensure_ascii=False))
