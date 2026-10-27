"""Per-request context propagated to logs, audit, background jobs (NFR-API-07)."""
from __future__ import annotations

import contextvars
from dataclasses import dataclass, field


@dataclass
class RequestContext:
    request_id: str = ""
    trace_id: str = ""  # W3C trace id (app.core.tracing)
    ip: str = ""
    user_agent: str = ""
    device_id: str = ""
    locale: str = "ru"
    timezone: str = "Asia/Almaty"
    user_id: object | None = None
    company_id: object | None = None
    role: str = ""
    extra: dict = field(default_factory=dict)


_ctx: contextvars.ContextVar[RequestContext | None] = contextvars.ContextVar("abdex_ctx", default=None)


def get_ctx() -> RequestContext:
    ctx = _ctx.get()
    if ctx is None:  # outside a request (worker, CLI): a fresh context, never a shared default
        ctx = RequestContext()
        _ctx.set(ctx)
    return ctx


def set_ctx(ctx: RequestContext) -> contextvars.Token:
    return _ctx.set(ctx)


def reset_ctx(token: contextvars.Token) -> None:
    _ctx.reset(token)
