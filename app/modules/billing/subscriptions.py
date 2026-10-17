"""Subscriptions and paid digital modules (FR-BIL-08, FR-PVD-07).

* A module is bound to a feature flag: while the company's subscription is active (paid period not over), the
  flag is on for that company (``platform.service.flag_enabled``). Modules and prices are platform data
  (/admin/modules), not code.
* Connecting charges the first period at once: an accrual with the module's own income type (digital modules
  or subscription — accounted separately in the PVD report), an invoice and an act.
* Auto-renewal: the worker charges the next period when the paid one ends; without auto-renewal, or for a
  company restricted for debt, the subscription expires and the module switches off.
* Switching off stops auto-renewal; the paid period is used to the end (no partial refunds).
"""
from __future__ import annotations

import json
from datetime import timedelta

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.audit import audit
from app.core.errors import AppError, Conflict, NotFound, ValidationFailed
from app.core.money import format_money, to_minor
from app.db import utcnow
from app.modules.accounts.models import Company
from app.modules.billing.models import (
    INCOME_DIGITAL_MODULES,
    INCOME_SUBSCRIPTION,
    Accrual,
    DigitalModule,
    Invoice,
    Subscription,
)
from app.modules.platform.service import get_setting, next_number

MODULE_SUBJECT = ("услуги по предоставлению доступа к цифровому модулю «{name}» платформы AbdEX "
                  "за период {start} — {end}")  # FR-PVD-03 wording, no transport services
MODULE_SUBJECT_KK = ("{start} — {end} кезеңге AbdEX платформасының «{name}» цифрлық модуліне қол жеткізуді "
                     "ұсыну қызметтері")  # FR-LOC-05
AUDIENCES = ("any", "client", "carrier")
MAX_CATCH_UP = 12  # periods charged at most in one renewal run


def modules(db: Session, *, only_active: bool = True) -> list[DigitalModule]:
    q = select(DigitalModule).order_by(DigitalModule.name)
    if only_active:
        q = q.where(DigitalModule.active.is_(True))
    return list(db.execute(q).scalars())


def catalog(db: Session, company: Company) -> list[tuple[DigitalModule, Subscription | None]]:
    subs = {s.module_id: s for s in db.execute(select(Subscription).where(Subscription.company_id == company.id)).scalars()}
    return [(m, subs.get(m.id)) for m in modules(db, only_active=False)
            if (m.active or m.id in subs) and m.audience in ("any", company.kind)]


def is_active(sub: Subscription | None, on=None) -> bool:
    on = on or utcnow().date()
    return bool(sub) and sub.status in ("active", "cancelled") and sub.period_start <= on <= sub.period_end


def flag_from_subscription(db: Session, key: str, company_id) -> bool:
    """Used by flag_enabled: an active paid subscription switches the module's flag on for the company."""
    today = utcnow().date()
    return db.execute(select(Subscription.id).join(DigitalModule, DigitalModule.id == Subscription.module_id)
                      .where(DigitalModule.flag_key == key, Subscription.company_id == company_id,
                             Subscription.status.in_(("active", "cancelled")),
                             Subscription.period_start <= today, Subscription.period_end >= today)).first() is not None


def _charge(db: Session, sub: Subscription, module: DigitalModule, company: Company) -> Invoice | None:
    """One period = one accrual (idempotent by event) + invoice + act."""
    from app.modules.documents.service import generate

    event = f"subscription:{sub.id}:{sub.period_start.isoformat()}"
    if db.execute(select(Accrual.id).where(Accrual.event == event)).first():
        return None
    kk = company.locale == "kk"
    subject = (MODULE_SUBJECT_KK if kk else MODULE_SUBJECT).format(
        name=module.name, start=sub.period_start.strftime("%d.%m.%Y"), end=sub.period_end.strftime("%d.%m.%Y"))
    invoice = Invoice(number=next_number(db, "fee_invoice", "СЧ"), company_id=company.id,
                      amount_minor=module.price_minor, currency=module.currency,
                      due_date=utcnow().date() + timedelta(days=int(get_setting(db, "billing.payment_days", 5))))
    db.add(invoice)
    db.flush()
    try:
        with db.begin_nested():
            db.add(Accrual(company_id=company.id, invoice_id=invoice.id, income_type=module.income_type,
                           amount_minor=module.price_minor, currency=module.currency, event=event,
                           calculation=json.dumps({"module": module.code, "price_minor": module.price_minor,
                                                   "period_start": sub.period_start.isoformat(),
                                                   "period_end": sub.period_end.isoformat(), "subject": subject},
                                                  ensure_ascii=False)))
            db.flush()
    except IntegrityError:
        db.delete(invoice)
        return None
    ctx = {"client_name": company.name, "client_bin": company.bin_iin, "subject": subject, "module": module.name,
           "period": f"{sub.period_start:%d.%m.%Y} — {sub.period_end:%d.%m.%Y}",
           "amount": format_money(invoice.amount_minor, invoice.currency),
           "due_date": invoice.due_date.strftime("%d.%m.%Y"), "vat_note": get_setting(db, "billing.vat_note", "Без НДС")}
    if module.price_minor == 0:
        invoice.status, invoice.paid_at = "paid", utcnow()
    invoice.document_id = generate(db, "module_invoice", ctx, company_id=company.id, number=invoice.number,
                                   locale=company.locale).id
    invoice.act_document_id = generate(db, "fee_act", ctx, company_id=company.id, locale=company.locale).id
    audit(db, "billing.accrued", object_type="subscription", object_id=sub.id,
          details={"amount": module.price_minor, "income": module.income_type})
    return invoice


def subscribe(db: Session, company: Company, module_id) -> Subscription:
    from app.modules.platform.service import has_restriction

    module = db.get(DigitalModule, module_id)
    if module is None or not module.active or module.audience not in ("any", company.kind):
        raise NotFound()
    from app.modules.platform.service import flag_enabled

    sales_flag = "subscriptions" if module.income_type == INCOME_SUBSCRIPTION else "digital_modules"
    if not flag_enabled(db, sales_flag, company.id):
        raise AppError("modules_off", status_code=403)
    if has_restriction(db, company.id, ("no_new_orders", "block")):
        raise AppError("subscription_restricted", status_code=403)
    sub = db.execute(select(Subscription).where(Subscription.company_id == company.id,
                                                Subscription.module_id == module.id).with_for_update()
                     ).scalar_one_or_none()
    today = utcnow().date()
    if sub is not None and is_active(sub, today):
        raise Conflict("subscription_active")
    if sub is None:
        sub = Subscription(company_id=company.id, module_id=module.id, started_at=utcnow(), period_start=today,
                           period_end=today + timedelta(days=module.period_days - 1))
        db.add(sub)
    else:
        sub.status, sub.auto_renew, sub.cancelled_at, sub.started_at = "active", True, None, utcnow()
        sub.period_start, sub.period_end = today, today + timedelta(days=module.period_days - 1)
        sub.periods += 1
    db.flush()
    _charge(db, sub, module, company)
    audit(db, "subscription.started", object_type="subscription", object_id=sub.id, details={"module": module.code})
    return sub


def set_auto_renew(db: Session, company: Company, sub_id, on: bool) -> Subscription:
    sub = db.get(Subscription, sub_id)
    if sub is None or sub.company_id != company.id:
        raise NotFound()
    if not is_active(sub):
        raise Conflict("subscription_not_active")
    sub.auto_renew = on
    sub.status = "active" if on else "cancelled"
    sub.cancelled_at = None if on else utcnow()
    audit(db, "subscription.resumed" if on else "subscription.cancelled", object_type="subscription",
          object_id=sub.id, details={"until": sub.period_end.isoformat()})
    return sub


def renew_due(db: Session) -> int:
    """Worker job: charge the next period of auto-renewed subscriptions, expire the rest."""
    from app.core import rls
    from app.modules.notifications.service import notify_company_owners
    from app.modules.platform.service import has_restriction

    today = utcnow().date()
    done = 0
    with rls.system(db):
        due = db.execute(select(Subscription).where(Subscription.status.in_(("active", "cancelled")),
                                                    Subscription.period_end < today)).scalars().all()
        for sub in due:
            module = db.get(DigitalModule, sub.module_id)
            company = db.get(Company, sub.company_id)
            renew = (sub.status == "active" and sub.auto_renew and module.active
                     and not has_restriction(db, company.id, ("no_new_orders", "block")))
            if not renew:
                sub.status = "expired"
                audit(db, "subscription.expired", object_type="subscription", object_id=sub.id, role="system")
                notify_company_owners(db, company.id, "subscription.expired", {"module": module.name}, link="/modules")
                done += 1
                continue
            for _ in range(MAX_CATCH_UP):
                if sub.period_end >= today:
                    break
                sub.period_start = sub.period_end + timedelta(days=1)
                sub.period_end = sub.period_start + timedelta(days=module.period_days - 1)
                sub.periods += 1
                _charge(db, sub, module, company)
            audit(db, "subscription.renewed", object_type="subscription", object_id=sub.id, role="system",
                  details={"until": sub.period_end.isoformat()})
            notify_company_owners(db, company.id, "subscription.renewed", {"module": module.name}, link="/modules")
            done += 1
    db.commit()
    return done


# ------------------------------------------------------------------ admin catalogue


def save_module(db: Session, form, module: DigitalModule | None = None) -> DigitalModule:
    errors: dict = {}
    code = str(form.get("code", "")).strip().lower()
    name = str(form.get("name", "")).strip()
    flag_key = str(form.get("flag_key", "")).strip()
    if module is None and (not code or not code.replace("_", "").replace(".", "").isalnum() or len(code) > 40):
        errors["code"] = "error.invalid_value"
    if not name:
        errors["name"] = "error.required"
    if not flag_key:
        errors["flag_key"] = "error.required"
    try:
        price = to_minor(str(form.get("price", "")).replace(" ", "").replace(",", "."))
        if price < 0:
            raise ValueError
    except (ValueError, ArithmeticError):
        errors["price"] = "error.number"
        price = 0
    try:
        period = int(form.get("period_days", 30))
        if not 1 <= period <= 366:
            raise ValueError
    except ValueError:
        errors["period_days"] = "error.number"
        period = 30
    income = str(form.get("income_type", INCOME_DIGITAL_MODULES))
    audience = str(form.get("audience", "any"))
    if income not in (INCOME_DIGITAL_MODULES, INCOME_SUBSCRIPTION):
        errors["income_type"] = "error.invalid_choice"
    if audience not in AUDIENCES:
        errors["audience"] = "error.invalid_choice"
    if module is None and code and db.execute(select(DigitalModule.id).where(DigitalModule.code == code)).first():
        errors["code"] = "error.duplicate"
    if errors:
        raise ValidationFailed(errors)
    _ensure_flag(db, flag_key)
    if module is None:
        module = DigitalModule(code=code)
        db.add(module)
    module.name, module.description, module.flag_key = name[:200], str(form.get("description", ""))[:500], flag_key[:60]
    module.price_minor, module.period_days, module.income_type, module.audience = price, period, income, audience
    module.active = bool(form.get("active", "1"))
    db.flush()
    audit(db, "module.saved", object_type="digital_module", object_id=module.id,
          details={"code": module.code, "price": price, "period": period})
    return module


def _ensure_flag(db: Session, key: str) -> None:
    from app.modules.platform.models import FeatureFlag

    if not db.execute(select(FeatureFlag.id).where(FeatureFlag.key == key)).first():
        db.add(FeatureFlag(key=key[:60], description="Платный модуль", enabled=False))
        db.flush()


def stats(db: Session) -> dict:
    from sqlalchemy import func

    rows = db.execute(select(Subscription.module_id, Subscription.status, func.count())
                      .group_by(Subscription.module_id, Subscription.status)).all()
    out: dict = {}
    for mid, status, n in rows:
        out.setdefault(mid, {})[status] = n
    return out
