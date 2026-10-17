"""Online payment of platform invoices (FR-BIL-06).

* The client is redirected to the provider's hosted checkout: card data is entered there and never passes
  through the platform (PCI DSS scope stays with the provider).
* The provider confirms the payment with a server-to-server callback to /hooks/payments, signed with
  HMAC-SHA256 over ``"<timestamp>.<body>"`` and checked for freshness (SEC-APP-12). The redirect back to the
  site is never a proof of payment.
* Callbacks are idempotent: a repeated callback for the same payment changes nothing.

``HttpProvider`` speaks a generic hosted-checkout API (create checkout → id + URL; signed callback); mapping a
concrete acquirer is a matter of this adapter only. Without PAYMENT_PROVIDER_URL a simulator is used outside
production: its "checkout page" is /dev/pay/<ref>, and its callback goes through the same signature check.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import time

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.config import settings
from app.core.audit import audit
from app.core.errors import AppError, Conflict, NotFound
from app.db import utcnow
from app.modules.billing.models import Invoice, PaymentIntent
from app.modules.integrations.base import Adapter

TOLERANCE = 300


def _secret() -> str:
    if settings.payment_webhook_secret:
        return settings.payment_webhook_secret
    if settings.is_production:
        raise RuntimeError("PAYMENT_WEBHOOK_SECRET must be set in production")
    return hashlib.sha256(f"dev-payments:{settings.secret_key}".encode()).hexdigest()


def sign(body: bytes, ts: int | None = None) -> str:
    ts = ts or int(time.time())
    return f"t={ts},v1={hmac.new(_secret().encode(), f'{ts}.'.encode() + body, hashlib.sha256).hexdigest()}"


def verify(body: bytes, header: str, *, now: int | None = None) -> bool:
    try:
        parts = dict(p.split("=", 1) for p in header.split(","))
        ts = int(parts["t"])
    except (ValueError, KeyError):
        return False
    if abs((now or int(time.time())) - ts) > TOLERANCE:
        return False
    return hmac.compare_digest(sign(body, ts), header)


class SimulatedProvider(Adapter):
    name = "payments"
    provider = "sim-checkout"

    def create_checkout(self, intent: PaymentIntent, *, return_url: str) -> dict:
        def _do():
            ref = "sim_" + secrets.token_hex(12)
            return {"ref": ref, "url": f"/dev/pay/{ref}"}

        return self.call("create_checkout", _do, summary=f"amount:{intent.amount_minor}")


class HttpProvider(Adapter):
    name = "payments"
    provider = "http-checkout"
    timeout = 10.0

    def create_checkout(self, intent: PaymentIntent, *, return_url: str) -> dict:
        import urllib.request

        def _do():
            body = json.dumps({"amount": intent.amount_minor, "currency": intent.currency, "order_id": str(intent.id),
                               "description": "AbdEX platform fee", "success_url": return_url, "fail_url": return_url,
                               "callback_url": settings.public_base_url.rstrip("/") + "/hooks/payments"}).encode()
            req = urllib.request.Request(settings.payment_provider_url.rstrip("/") + "/checkouts", data=body, method="POST",  # noqa: S310 — scheme checked in config
                                         headers={"Content-Type": "application/json",
                                                  "Authorization": f"Bearer {settings.payment_provider_key}"})
            with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310 — configured provider URL
                out = json.loads(resp.read())
            return {"ref": str(out["id"]), "url": str(out["url"])}

        return self.call("create_checkout", _do, summary=f"amount:{intent.amount_minor}")


_providers: dict[str, Adapter] = {}


def provider() -> Adapter:
    if settings.payment_provider_url:
        return _providers.setdefault("http", HttpProvider())
    if settings.is_production:
        raise RuntimeError("PAYMENT_PROVIDER_URL must be set in production")
    return _providers.setdefault("sim", SimulatedProvider())


def start(db: Session, invoice: Invoice, company_id) -> PaymentIntent:
    from app.modules.platform.service import flag_enabled

    if not flag_enabled(db, "online_payments", company_id):
        raise AppError("online_payments_off", status_code=403)
    if invoice.company_id != company_id:
        raise NotFound()
    if invoice.status != "issued" or invoice.amount_minor <= 0:
        raise Conflict("invoice_not_payable")
    p = provider()
    intent = PaymentIntent(invoice_id=invoice.id, company_id=company_id, provider=p.provider, provider_ref="pending",
                           amount_minor=invoice.amount_minor, currency=invoice.currency)
    db.add(intent)
    db.flush()
    out = p.create_checkout(intent, return_url=settings.public_base_url.rstrip("/") + f"/finance?payment={intent.id}")
    intent.provider_ref, intent.checkout_url = out["ref"][:80], out["url"][:500]
    db.flush()
    audit(db, "billing.payment_started", object_type="invoice", object_id=invoice.id,
          details={"provider": p.provider, "amount": intent.amount_minor})
    return intent


def handle_callback(db: Session, body: bytes, signature: str) -> str:
    """Provider callback. Returns a short status for the provider; raises NotFound on a bad signature."""
    from app.core import rls
    from app.modules.billing.service import register_payment

    if not verify(body, signature):
        raise NotFound()
    try:
        event = json.loads(body)
        ref, status = str(event["ref"]), str(event["status"])
        amount = int(event["amount"])
    except (ValueError, KeyError, TypeError):
        raise NotFound()
    with rls.system(db):  # the provider is not a user: it may settle any company's invoice
        intent = db.execute(select(PaymentIntent).where(PaymentIntent.provider_ref == ref).with_for_update()
                            ).scalar_one_or_none()
        if intent is None:
            raise NotFound()
        if intent.status != "created":
            return "duplicate"
        if status != "succeeded":
            intent.status = "failed"
            audit(db, "billing.payment_failed", object_type="invoice", object_id=intent.invoice_id, role="system")
            return "failed"
        if amount != intent.amount_minor or str(event.get("currency", intent.currency)) != intent.currency:
            intent.status = "failed"
            audit(db, "billing.payment_mismatch", object_type="invoice", object_id=intent.invoice_id, role="system",
                  result="error", details={"expected": intent.amount_minor, "got": amount})
            return "mismatch"
        intent.status, intent.paid_at = "paid", utcnow()
        invoice = db.get(Invoice, intent.invoice_id)
        if invoice.status != "cancelled":
            # the money arrived even if the invoice was meanwhile paid another way: it is recorded (an
            # over-payment is then visible to finance instead of disappearing)
            register_payment(db, invoice, amount, source="provider", reference=ref)
    return "ok"


def simulate(db: Session, ref: str, *, succeed: bool) -> str:
    """Development checkout page: produces the same signed callback a real provider would send."""
    if settings.payment_provider_url or settings.is_production:
        raise NotFound()
    intent = db.execute(select(PaymentIntent).where(PaymentIntent.provider_ref == ref)).scalar_one_or_none()
    if intent is None:
        raise NotFound()
    body = json.dumps({"ref": ref, "status": "succeeded" if succeed else "declined", "amount": intent.amount_minor,
                       "currency": intent.currency}).encode()
    return handle_callback(db, body, sign(body))
