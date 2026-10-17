"""Outgoing webhooks on deal events (FR-API-03).

* The body is signed: ``X-AbdEX-Signature: t=<unix>,v1=<hex HMAC-SHA256(secret, "<t>.<body>")>``;
  receivers check the signature and reject old timestamps (replay).
* Retries with growing pauses (1 min … 12 h), a journal entry per delivery, and the endpoint is switched off
  after many failures in a row with a notice to the company owner.
* SSRF protection (SEC-APP): only https, no credentials in the URL, standard ports, and the host must resolve
  to public addresses only; the connection goes to the vetted address (no DNS rebinding) and redirects are
  not followed.
* Payloads carry identifiers and statuses only, never personal data (NFR-LAW, SEC-DAT-02).
"""
from __future__ import annotations

import hashlib
import hmac
import http.client
import ipaddress
import json
import logging
import secrets
import socket
import ssl
import time
from datetime import timedelta
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import events
from app.core.audit import audit
from app.core.context import get_ctx
from app.core.errors import NotFound, ValidationFailed
from app.db import utcnow, uuid7
from app.modules.webhooks.models import WebhookDelivery, WebhookEndpoint

log = logging.getLogger("abdex.webhooks")

EVENTS = ("deal.created", "deal.status_changed", "deal.document_signed", "deal.checkpoint")
BACKOFF_SECONDS = (60, 300, 1800, 7200, 21600, 43200)
MAX_ATTEMPTS = len(BACKOFF_SECONDS) + 1
DISABLE_AFTER_FAILURES = 20
MAX_ENDPOINTS = 5
TIMEOUT = 5.0
ALLOWED_PORTS = (443, 8443)


class UnsafeTarget(Exception):
    pass


def sign(secret: str, body: bytes, ts: int) -> str:
    mac = hmac.new(secret.encode(), f"{ts}.".encode() + body, hashlib.sha256).hexdigest()
    return f"t={ts},v1={mac}"


def verify(secret: str, body: bytes, header: str, *, tolerance: int = 300, now: int | None = None) -> bool:
    """Reference check for receivers (also used in tests and documentation)."""
    try:
        parts = dict(p.split("=", 1) for p in header.split(","))
        ts = int(parts["t"])
    except (ValueError, KeyError):
        return False
    if abs((now or int(time.time())) - ts) > tolerance:
        return False
    return hmac.compare_digest(sign(secret, body, ts), header)


def validate_url(url: str) -> str:
    url = (url or "").strip()
    parts = urlsplit(url)
    if parts.scheme != "https" or not parts.hostname or parts.username or parts.password or len(url) > 500:
        raise ValidationFailed({"url": "error.webhook_url"})
    if (parts.port or 443) not in ALLOWED_PORTS:
        raise ValidationFailed({"url": "error.webhook_url"})
    try:
        ip = ipaddress.ip_address(parts.hostname)
    except ValueError:
        ip = None
    if ip is not None and not ip.is_global:
        raise ValidationFailed({"url": "error.webhook_url"})
    if parts.hostname.lower() in ("localhost",) or parts.hostname.lower().endswith((".local", ".internal")):
        raise ValidationFailed({"url": "error.webhook_url"})
    return url


def _resolve_public(host: str, port: int) -> str:
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    addrs = {i[4][0] for i in infos}
    if not addrs or any(not ipaddress.ip_address(a.split("%")[0]).is_global for a in addrs):
        raise UnsafeTarget(host)
    return sorted(addrs)[0]


class _PinnedHTTPS(http.client.HTTPSConnection):
    """Connects to an already vetted IP while TLS still verifies the original host name."""

    def __init__(self, host: str, ip: str, port: int):
        super().__init__(host, port, timeout=TIMEOUT, context=ssl.create_default_context())
        self._ip = ip

    def connect(self):
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def _post(url: str, body: bytes, headers: dict) -> int:
    parts = urlsplit(url)
    port = parts.port or 443
    ip = _resolve_public(parts.hostname, port)
    conn = _PinnedHTTPS(parts.hostname, ip, port)
    try:
        path = parts.path or "/"
        if parts.query:
            path += "?" + parts.query
        conn.request("POST", path, body=body, headers=headers)
        return conn.getresponse().status  # redirects are not followed
    finally:
        conn.close()


def safe_get_json(url: str, headers: dict, *, max_bytes: int = 2_000_000):
    """GET a JSON document from a customer-configured https URL with the same SSRF guards as webhooks: public
    address only, resolved once and pinned, TLS checked against the host name, no redirects, bounded size."""
    import json as _json

    validate_url(url)
    parts = urlsplit(url)
    port = parts.port or 443
    ip = _resolve_public(parts.hostname, port)
    conn = _PinnedHTTPS(parts.hostname, ip, port)
    try:
        path = (parts.path or "/") + (f"?{parts.query}" if parts.query else "")
        conn.request("GET", path, headers=headers)
        resp = conn.getresponse()
        if resp.status != 200:
            raise RuntimeError(f"status {resp.status}")
        return _json.loads(resp.read(max_bytes))
    finally:
        conn.close()


# ------------------------------------------------------------------ endpoints


def endpoints(db: Session, company_id) -> list[WebhookEndpoint]:
    return list(db.execute(select(WebhookEndpoint).where(WebhookEndpoint.company_id == company_id,
                                                         WebhookEndpoint.is_deleted.is_(False))
                           .order_by(WebhookEndpoint.created_at)).scalars())


def create_endpoint(db: Session, company_id, url: str, events_list: list[str], *,
                    sandbox: bool = False) -> tuple[WebhookEndpoint, str]:
    url = validate_url(url)
    chosen = [e for e in events_list if e in EVENTS] or list(EVENTS)
    if len(endpoints(db, company_id)) >= MAX_ENDPOINTS:
        raise ValidationFailed({"url": "error.webhook_limit"})
    secret = secrets.token_hex(32)
    ep = WebhookEndpoint(company_id=company_id, url=url, secret=secret, events=",".join(chosen), sandbox=sandbox,
                         created_by=get_ctx().user_id)
    db.add(ep)
    db.flush()
    audit(db, "webhook.created", object_type="webhook", object_id=ep.id, details={"events": ep.events})
    return ep, secret


def get_endpoint(db: Session, company_id, endpoint_id) -> WebhookEndpoint:
    ep = db.get(WebhookEndpoint, endpoint_id)
    if ep is None or ep.company_id != company_id or ep.is_deleted:
        raise NotFound()
    return ep


def delete_endpoint(db: Session, ep: WebhookEndpoint) -> None:
    ep.is_deleted = True
    ep.active = False
    audit(db, "webhook.deleted", object_type="webhook", object_id=ep.id)


def deliveries(db: Session, endpoint_id, limit: int = 50) -> list[WebhookDelivery]:
    return list(db.execute(select(WebhookDelivery).where(WebhookDelivery.endpoint_id == endpoint_id)
                           .order_by(WebhookDelivery.created_at.desc()).limit(limit)).scalars())


# ------------------------------------------------------------------ enqueue & deliver


def enqueue(db: Session, company_ids, event: str, data: dict) -> int:
    from app.core import rls

    with rls.system(db):  # deal events fan out to both participants' endpoints
        return _enqueue(db, company_ids, event, data)


def _enqueue(db: Session, company_ids, event: str, data: dict, *, sandbox: bool = False) -> int:
    """Live events go to live endpoints only; sandbox events (FR-API-05) to sandbox endpoints only."""
    event_id = str(uuid7())
    body = {"id": event_id, "type": event, "created_at": utcnow().isoformat(), "data": data}
    if sandbox:
        body["livemode"] = False
    payload = json.dumps(body, ensure_ascii=False, default=str, separators=(",", ":"))
    count = 0
    for cid in {c for c in company_ids if c}:
        for ep in db.execute(select(WebhookEndpoint).where(WebhookEndpoint.company_id == cid,
                                                           WebhookEndpoint.active.is_(True),
                                                           WebhookEndpoint.sandbox.is_(sandbox),
                                                           WebhookEndpoint.is_deleted.is_(False))).scalars():
            if event not in ep.events.split(","):
                continue
            db.add(WebhookDelivery(endpoint_id=ep.id, event=event, event_id=event_id, payload=payload,
                                   next_attempt_at=utcnow()))
            count += 1
    return count


def enqueue_sandbox(db: Session, company_id, event: str, data: dict) -> int:
    return _enqueue(db, (company_id,), event, data, sandbox=True)


def send_test(db: Session, ep: WebhookEndpoint) -> None:
    db.add(WebhookDelivery(endpoint_id=ep.id, event="ping", event_id=str(uuid7()), next_attempt_at=utcnow(),
                           payload=json.dumps({"type": "ping", "created_at": utcnow().isoformat(), "data": {}})))


def process(db: Session, limit: int = 20) -> int:
    now = utcnow()
    rows = db.execute(select(WebhookDelivery).where(WebhookDelivery.status == "pending",
                                                    WebhookDelivery.next_attempt_at <= now)
                      .order_by(WebhookDelivery.next_attempt_at).limit(limit)
                      .with_for_update(skip_locked=True)).scalars().all()  # several workers never post one twice
    for d in rows:
        ep = db.get(WebhookEndpoint, d.endpoint_id)
        if ep is None or not ep.active or ep.is_deleted:
            d.status, d.last_error = "failed", "endpoint disabled"
            continue
        body = d.payload.encode()
        ts = int(time.time())
        headers = {"Content-Type": "application/json", "User-Agent": "AbdEX-Webhooks/1",
                   "X-AbdEX-Event": d.event, "X-AbdEX-Delivery": str(d.id), "X-AbdEX-Signature": sign(ep.secret, body, ts)}
        d.attempts += 1
        try:
            code = _post(ep.url, body, headers)
            d.last_status_code = code
            ok = 200 <= code < 300
            d.last_error = "" if ok else f"HTTP {code}"
        except UnsafeTarget:
            ok, d.last_error = False, "target resolves to a non-public address"
        except (OSError, http.client.HTTPException) as exc:
            ok, d.last_error = False, type(exc).__name__
        if ok:
            d.status, d.delivered_at, d.next_attempt_at = "delivered", utcnow(), None
            ep.failures_in_row = 0
            continue
        ep.failures_in_row += 1
        if d.attempts >= MAX_ATTEMPTS:
            d.status, d.next_attempt_at = "failed", None
        else:
            d.next_attempt_at = utcnow() + timedelta(seconds=BACKOFF_SECONDS[d.attempts - 1])
        if ep.failures_in_row >= DISABLE_AFTER_FAILURES and ep.active:
            ep.active = False
            from app.modules.notifications.service import notify_company_owners

            notify_company_owners(db, ep.company_id, "webhook.disabled", {"url": urlsplit(ep.url).hostname},
                                  link="/company/webhooks", dedup=f"webhook_off:{ep.id}:{now:%Y%m%d}")
    db.commit()
    return len(rows)


# ------------------------------------------------------------------ domain events → webhooks


@events.subscribe("order.status_changed")
def _on_status(db: Session, order, frm, to, **_):
    from app.modules.deals.models import Deal

    deal = db.execute(select(Deal).where(Deal.order_id == order.id)).scalar_one_or_none()
    if deal is None:
        return
    data = {"deal_id": str(deal.id), "deal_number": deal.number, "order_id": str(order.id),
            "order_number": order.number, "from": frm, "to": to}
    enqueue(db, (deal.client_company_id, deal.carrier_company_id),
            "deal.created" if to == "assigned" and frm == "bidding" else "deal.status_changed", data)
