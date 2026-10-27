"""Structured JSON logs for the web and worker processes (NFR-OBS-01)."""
from __future__ import annotations

import json
import logging


class JsonFormatter(logging.Formatter):
    """NFR-OBS-01: structured JSON logs carrying the request id and the trace id."""

    def format(self, record: logging.LogRecord) -> str:
        from app.core.context import get_ctx

        ctx = get_ctx()
        out = {"ts": self.formatTime(record), "level": record.levelname, "logger": record.name,
               "msg": record.getMessage(), "request_id": ctx.request_id, "trace_id": ctx.trace_id}
        if record.exc_info:
            out["exc"] = self.formatException(record.exc_info)[-4000:]
        return json.dumps(out, ensure_ascii=False)


def setup() -> None:
    from app.core import tracing

    tracing.install()  # outgoing HTTP calls carry the trace id
    handler = logging.StreamHandler()
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(logging.INFO)
