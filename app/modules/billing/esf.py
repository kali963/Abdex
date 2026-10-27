"""Sending ЭСФ/АВР to IS ESF (FR-BIL-07, follow-up of the XML preparation in accounting.py).

The documents are built by ``accounting.esf_xml`` from the stored accrual; this module queues them and sends them
through an adapter with statuses, retries with a growing pause and a journal:

* ``ESF_GATEWAY_URL`` — the platform's IS ESF gateway (it holds the EDS session with IS ESF and accepts our XML
  over https with a bearer token, answering ``{"status": "accepted", "registrationNumber": ...}`` or an error);
* without it, outside production, a simulator validates the XML and returns a test registration number.
Switched by the ``gov.esf`` flag; staff queue a period on /admin/finance and follow the statuses there.
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import timedelta
from xml.etree import ElementTree as ET  # noqa: S405 — parses our own generated XML only

from sqlalchemy import or_, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.secrets import secret
from app.config import settings
from app.core.audit import audit
from app.core.errors import AppError
from app.db import utcnow
from app.modules.billing.models import EsfSubmission, Invoice
from app.modules.integrations.base import Adapter, IntegrationUnavailable

MAX_ATTEMPTS = 6
BACKOFF_MINUTES = (5, 30, 120, 360, 720)


class EsfAdapter(Adapter):
    name = "esf"
    timeout = 30.0  # state systems may answer slowly under load; runs in the background worker
    retries = 0

    @property
    def provider_name(self) -> str:
        return "esf-gateway" if os.getenv("ESF_GATEWAY_URL") else "esf-sim"

    def send(self, xml: bytes, kind: str) -> dict:
        return self.call("send", lambda: self._send(xml, kind), summary=kind)

    def _send(self, xml: bytes, kind: str) -> dict:
        url = os.getenv("ESF_GATEWAY_URL", "")
        if url:
            import urllib.request

            if not url.startswith("https://"):
                raise IntegrationUnavailable("ESF_GATEWAY_URL must be https")
            req = urllib.request.Request(url, data=xml, method="POST",  # noqa: S310 — configured https gateway
                                         headers={"Content-Type": "application/xml", "X-Document-Kind": kind,
                                                  "Authorization": f"Bearer {secret('ESF_GATEWAY_TOKEN')}"})
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310 — configured https gateway
                out = json.loads(resp.read(100_000))
            ok = str(out.get("status", "")).lower() == "accepted"
            return {"ok": ok, "number": str(out.get("registrationNumber", ""))[:60],
                    "error": "" if ok else str(out.get("error", "rejected"))[:300]}
        if settings.is_production:
            raise IntegrationUnavailable("ESF_GATEWAY_URL is not configured")
        root = ET.fromstring(xml)  # noqa: S314 — our own document
        missing = [t for t in ("sellers/seller/tin", "customers/customer/tin", "productSet/product/description")
                   if not (root.findtext(t) or "").strip()]
        if missing:
            return {"ok": False, "number": "", "error": "missing: " + ", ".join(missing)}
        digest = int(hashlib.sha256(xml).hexdigest()[:10], 16) % 10**10
        return {"ok": True, "number": f"ESF-{'I' if kind == 'invoice' else 'A'}-{digest:010d}", "error": ""}


adapter = EsfAdapter()


def queue_period(db: Session, items: list[dict]) -> int:
    """Queue ЭСФ and АВР of the invoices of a period that are not sent yet."""
    from app.modules.platform.service import flag_enabled

    if not flag_enabled(db, "gov.esf"):
        raise AppError("esf_off", status_code=403)
    n = 0
    for r in items:
        inv = r["invoice"]
        if inv.status == "cancelled" or inv.amount_minor <= 0:
            continue
        for kind in ("invoice", "act"):
            try:
                with db.begin_nested():
                    db.add(EsfSubmission(invoice_id=inv.id, kind=kind))
                    db.flush()
                n += 1
            except IntegrityError:
                continue  # already queued or sent
    audit(db, "esf.queued", object_type="platform", object_id="esf", details={"count": n})
    return n


def process(db: Session, limit: int = 20) -> int:
    """Worker job: send queued documents; a temporary outage is retried with a growing pause."""
    from app.modules.billing.accounting import esf_xml

    now = utcnow()
    rows = db.execute(select(EsfSubmission).where(
        EsfSubmission.status == "pending",
        or_(EsfSubmission.next_attempt_at.is_(None), EsfSubmission.next_attempt_at <= now))
        .order_by(EsfSubmission.created_at).limit(limit).with_for_update(skip_locked=True)).scalars().all()
    for sub in rows:
        sub.attempts += 1
        inv = db.get(Invoice, sub.invoice_id)
        try:
            out = adapter.send(esf_xml(db, inv, kind=sub.kind), sub.kind)
        except IntegrationUnavailable as exc:
            sub.last_error = f"unavailable: {exc}"[:300]
            if sub.attempts >= MAX_ATTEMPTS:
                sub.status = "error"
            else:
                sub.next_attempt_at = now + timedelta(minutes=BACKOFF_MINUTES[min(sub.attempts - 1, len(BACKOFF_MINUTES) - 1)])
            continue
        sub.sent_at = utcnow()
        if out["ok"]:
            sub.status, sub.registration_number, sub.last_error = "accepted", out["number"], ""
        else:
            sub.status, sub.last_error = "error", out["error"]
        audit(db, "esf.sent", object_type="invoice", object_id=inv.id, role="system",
              result="ok" if out["ok"] else "error", details={"kind": sub.kind})
    db.commit()
    return len(rows)


def retry(db: Session, sub: EsfSubmission) -> None:
    sub.status, sub.attempts, sub.next_attempt_at, sub.last_error = "pending", 0, None, ""


def recent(db: Session, limit: int = 100) -> list[tuple[EsfSubmission, Invoice]]:
    return list(db.execute(select(EsfSubmission, Invoice).join(Invoice, Invoice.id == EsfSubmission.invoice_id)
                           .order_by(EsfSubmission.created_at.desc()).limit(limit)).all())
