"""Application and business metrics in the Prometheus text format (NFR-OBS-01, NFR-OBS-02).

HTTP counters and latency buckets are kept per process (each worker is scraped separately); business
gauges are read from the database at scrape time. The endpoint /metrics answers only with the bearer token
from METRICS_TOKEN and is invisible (404) without it.
"""
from __future__ import annotations

import threading
from collections import defaultdict

BUCKETS = (0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0)
_lock = threading.Lock()
_requests: dict[tuple[str, str], int] = defaultdict(int)
_latency: dict[str, list[int]] = defaultdict(lambda: [0] * (len(BUCKETS) + 1))
_latency_sum: dict[str, float] = defaultdict(float)


def _route_group(path: str) -> str:
    """Low-cardinality label: first path segment only (ids never become labels)."""
    seg = path.strip("/").split("/", 1)[0]
    return seg if seg.isalpha() and len(seg) < 20 else "other"


def observe(method: str, path: str, status: int, seconds: float) -> None:
    group = _route_group(path)
    with _lock:
        _requests[(method, f"{status // 100}xx")] += 1
        counts = _latency[group]
        for i, b in enumerate(BUCKETS):
            if seconds <= b:
                counts[i] += 1
        counts[-1] += 1
        _latency_sum[group] += seconds


def _business(db) -> list[tuple[str, str, float]]:
    from datetime import timedelta

    from sqlalchemy import func, select

    from app.db import utcnow
    from app.modules.deals.models import Deal
    from app.modules.fleet.models import VerificationRequest
    from app.modules.notifications.models import OutboxMessage
    from app.modules.orders.models import Order
    from app.modules.platform.models import AntifraudAlert, IntegrationCall, SecurityAlert
    from app.modules.webhooks.models import WebhookDelivery

    now = utcnow()
    hour_ago = now - timedelta(hours=1)
    out = [("abdex_deals_created_last_hour", "", db.execute(select(func.count(Deal.id)).where(Deal.created_at >= hour_ago))
            .scalar_one())]
    for status, n in db.execute(select(Order.status, func.count(Order.id)).group_by(Order.status)).all():
        out.append(("abdex_orders", f'status="{status}"', n))
    out.append(("abdex_moderation_queue", "", db.execute(select(func.count(VerificationRequest.id)).where(
        VerificationRequest.status == "pending")).scalar_one()))
    queued = db.execute(select(func.count(OutboxMessage.id), func.min(OutboxMessage.created_at))
                        .where(OutboxMessage.status == "queued", OutboxMessage.next_attempt_at <= now)).one()
    out.append(("abdex_notifications_queued", "", queued[0]))
    out.append(("abdex_notification_delay_seconds", "", (now - queued[1]).total_seconds() if queued[1] else 0))
    out.append(("abdex_notifications_failed_last_hour", "", db.execute(select(func.count(OutboxMessage.id)).where(
        OutboxMessage.status == "failed", OutboxMessage.updated_at >= hour_ago)).scalar_one()))
    out.append(("abdex_webhooks_pending", "", db.execute(select(func.count(WebhookDelivery.id)).where(
        WebhookDelivery.status == "pending")).scalar_one()))
    out.append(("abdex_integration_errors_last_hour", "", db.execute(select(func.count(IntegrationCall.id)).where(
        IntegrationCall.status != "ok", IntegrationCall.created_at >= hour_ago)).scalar_one()))
    from app.modules.accounts.models import AuditLog

    out.append(("abdex_document_errors_last_hour", "", db.execute(select(func.count(AuditLog.id)).where(
        AuditLog.action.like("document.%"), AuditLog.result == "error", AuditLog.created_at >= hour_ago)).scalar_one()))
    out.append(("abdex_antifraud_open", "", db.execute(select(func.count(AntifraudAlert.id)).where(
        AntifraudAlert.status == "open")).scalar_one()))
    out.append(("abdex_security_alerts_open", "", db.execute(select(func.count(SecurityAlert.id)).where(
        SecurityAlert.status == "open")).scalar_one()))
    return out


def render(db) -> str:
    lines = ["# TYPE abdex_http_requests_total counter"]
    with _lock:
        for (method, cls), n in sorted(_requests.items()):
            lines.append(f'abdex_http_requests_total{{method="{method}",status="{cls}"}} {n}')
        lines.append("# TYPE abdex_http_request_seconds histogram")
        for group, counts in sorted(_latency.items()):
            for b, n in zip(BUCKETS, counts, strict=False):
                lines.append(f'abdex_http_request_seconds_bucket{{route="{group}",le="{b}"}} {n}')
            lines.append(f'abdex_http_request_seconds_bucket{{route="{group}",le="+Inf"}} {counts[-1]}')
            lines.append(f'abdex_http_request_seconds_count{{route="{group}"}} {counts[-1]}')
            lines.append(f'abdex_http_request_seconds_sum{{route="{group}"}} {_latency_sum[group]:.4f}')
    seen = set()
    for name, labels, value in _business(db):
        if name not in seen:
            lines.append(f"# TYPE {name} gauge")
            seen.add(name)
        lines.append(f"{name}{{{labels}}} {value}" if labels else f"{name} {value}")
    return "\n".join(lines) + "\n"
