"""Request tracing across services (NFR-OBS-01), W3C Trace Context.

Every request gets a trace id: taken from an incoming ``traceparent`` header (a load balancer or a partner that
traces its own calls) or created here. It is written into every log line, returned in the ``traceresponse``
header, and sent on with every outgoing HTTP call of the integration adapters (NCANode, SIGEX, IS ESF, payment
provider, SMS gateway, OCR, …) as ``traceparent``, so one operation can be followed through all systems.
Background jobs get a trace id per job run.
"""
from __future__ import annotations

import re
import secrets
import urllib.request

_TRACEPARENT = re.compile(r"^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$")


def new_trace_id() -> str:
    return secrets.token_hex(16)


def new_span_id() -> str:
    return secrets.token_hex(8)


def parse(header: str) -> str:
    """The trace id of a valid ``traceparent`` header, or "" (all-zero ids are invalid by the standard)."""
    m = _TRACEPARENT.match((header or "").strip().lower())
    if not m or m.group(1) == "0" * 32 or m.group(2) == "0" * 16:
        return ""
    return m.group(1)


def current_trace_id() -> str:
    from app.core.context import get_ctx

    ctx = get_ctx()
    if not ctx.trace_id:
        ctx.trace_id = new_trace_id()
    return ctx.trace_id


def header(span_id: str = "") -> str:
    return f"00-{current_trace_id()}-{span_id or new_span_id()}-01"


class _TraceHandler(urllib.request.BaseHandler):
    """Adds ``traceparent`` (and the request id) to every outgoing urllib request that has none."""

    handler_order = 100  # before the HTTP handlers send the request

    def http_request(self, req):
        if not req.has_header("Traceparent"):
            req.add_unredirected_header("Traceparent", header())
        from app.core.context import get_ctx

        rid = get_ctx().request_id
        if rid and not req.has_header("X-request-id"):
            req.add_unredirected_header("X-request-id", rid)
        return req

    https_request = http_request


_installed = False


def install() -> None:
    """Once per process: the global urllib opener (used by ``urlopen``) gets the trace handler."""
    global _installed
    if _installed:
        return
    urllib.request.install_opener(urllib.request.build_opener(_TraceHandler()))
    _installed = True
