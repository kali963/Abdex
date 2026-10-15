"""Antifraud rules engine, device marks and velocity checks (SEC-FRD-01..03, SEC-APP-07).

Every signal the code can raise is a rule stored in the database: an administrator switches it on or off,
chooses the action (allow / flag / review / restrict / block), the severity and, for velocity rules, the
threshold and the time window — without a release. Nothing is blocked silently: every action leaves an alert
in the queue and an audit record (FR-KYC-07).
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.context import get_ctx
from app.db import utcnow
from app.modules.platform.models import AntifraudRule, DeviceEvent

ACTIONS = ("allow", "flag", "review", "restrict", "block")

# code: (action, severity, threshold, window minutes, description)
DEFAULT_RULES: dict[str, tuple[str, str, int, int, str]] = {
    "contact_leak_attempt": ("flag", "low", 0, 0, "Контакты в тексте до акцепта"),
    "duplicate_company_bin": ("review", "high", 0, 0, "Повторная регистрация БИН"),
    "duplicate_driver_iin": ("review", "high", 0, 0, "ИИН водителя у несвязанных компаний"),
    "duplicate_iban": ("review", "high", 0, 0, "IBAN у несвязанных компаний"),
    "duplicate_vehicle_plate": ("review", "high", 0, 0, "Госномер у несвязанных компаний"),
    "executor_foreign_driver": ("review", "high", 0, 0, "Водитель другой компании в сделке"),
    "executor_foreign_vehicle": ("review", "high", 0, 0, "ТС другой компании в сделке"),
    "vehicle_parallel_deals": ("review", "high", 0, 0, "ТС в пересекающихся сделках"),
    "high_risk_deal": ("review", "high", 0, 0, "Скоринг риска сделки выше порога"),
    "registry_mismatch": ("review", "medium", 0, 0, "Расхождение с реестром"),
    "shared_device": ("review", "medium", 0, 0, "Одно устройство у аккаунтов несвязанных компаний"),
    "velocity_registrations": ("review", "medium", 5, 60, "Серия регистраций с одного IP"),
    "velocity_bids": ("flag", "medium", 40, 60, "Массовая подача предложений"),
    "velocity_orders": ("flag", "medium", 60, 60, "Аномальное число заявок"),
    "velocity_bank_changes": ("review", "high", 3, 43200, "Частая смена банковских реквизитов"),
    "velocity_cancellations": ("flag", "medium", 10, 10080, "Много отмен заявок"),
    "mass_card_views": ("flag", "medium", 200, 60, "Массовый просмотр карточек заявок"),
}

# tracked action -> (velocity rule, counted by "ip" / "company" / "user")
VELOCITY = {
    "register": ("velocity_registrations", "ip"),
    "bid": ("velocity_bids", "company"),
    "order_create": ("velocity_orders", "company"),
    "bank_change": ("velocity_bank_changes", "company"),
    "order_cancel": ("velocity_cancellations", "company"),
    "card_view": ("mass_card_views", "company"),
}
DEVICE_ACTIONS = ("register", "login")


@dataclass
class Rule:
    code: str
    enabled: bool
    action: str
    severity: str
    threshold: int
    window_minutes: int


def seed(db: Session) -> None:
    have = set(db.execute(select(AntifraudRule.code)).scalars())
    for code, (action, severity, threshold, window, desc) in DEFAULT_RULES.items():
        if code not in have:
            db.add(AntifraudRule(code=code, action=action, severity=severity, threshold=threshold,
                                 window_minutes=window, description=desc))


def rule(db: Session, code: str) -> Rule:
    r = db.execute(select(AntifraudRule).where(AntifraudRule.code == code)).scalar_one_or_none()
    if r is not None:
        return Rule(code, r.enabled, r.action, r.severity, r.threshold, r.window_minutes)
    action, severity, threshold, window, _ = DEFAULT_RULES.get(code, ("review", "medium", 0, 0, ""))
    return Rule(code, True, action, severity, threshold, window)


def track(db: Session, action: str, *, user_id=None, company_id=None) -> None:
    """Record a device/network mark and run the velocity and shared-device checks for the action."""
    from app.modules.platform.service import raise_alert

    ctx = get_ctx()
    user_id = user_id or ctx.user_id
    company_id = company_id or ctx.company_id
    db.add(DeviceEvent(action=action, device_id=(ctx.device_id or "")[:64], ip=(ctx.ip or "")[:64], user_id=user_id,
                       company_id=company_id))
    db.flush()
    if action in VELOCITY:
        code, by = VELOCITY[action]
        r = rule(db, code)
        key = {"ip": ctx.ip, "company": company_id, "user": user_id}[by]
        if r.enabled and r.threshold and key:
            col = {"ip": DeviceEvent.ip, "company": DeviceEvent.company_id, "user": DeviceEvent.user_id}[by]
            since = utcnow() - timedelta(minutes=r.window_minutes or 60)
            n = db.execute(select(func.count(DeviceEvent.id)).where(DeviceEvent.action == action, col == key,
                                                                    DeviceEvent.created_at >= since)).scalar_one()
            if n > r.threshold:
                raise_alert(db, code, company_id=company_id if by != "ip" else None,
                            details={"count": n, "window_min": r.window_minutes, "by": by,
                                     "ip": ctx.ip if by == "ip" else ""})
    if action in DEVICE_ACTIONS and ctx.device_id and user_id:
        _shared_device(db, ctx.device_id, user_id)


def _shared_device(db: Session, device_id: str, user_id) -> None:
    """Accounts of companies with no common membership seen on the same device."""
    from app.modules.accounts.models import Membership
    from app.modules.platform.service import raise_alert

    others = set(db.execute(select(DeviceEvent.user_id).where(DeviceEvent.device_id == device_id,
                                                              DeviceEvent.user_id.is_not(None),
                                                              DeviceEvent.user_id != user_id)).scalars())
    if not others:
        return
    mine = set(db.execute(select(Membership.company_id).where(Membership.user_id == user_id)).scalars())
    for other in others:
        theirs = set(db.execute(select(Membership.company_id).where(Membership.user_id == other)).scalars())
        if mine and theirs and not (mine & theirs):
            raise_alert(db, "shared_device", company_id=next(iter(mine)),
                        details={"other_companies": [str(c) for c in theirs], "device": device_id[:8] + "…"})
            return


def apply_action(db: Session, r: Rule, alert) -> None:
    """restrict / block act on the company immediately; the alert stays in the queue for a human."""
    if r.action not in ("restrict", "block") or not alert.company_id:
        return
    from app.core.audit import audit
    from app.modules.accounts.models import Company
    from app.modules.platform.models import Restriction
    from app.modules.platform.service import has_restriction

    company = db.get(Company, alert.company_id)
    if company is None:
        return
    if r.action == "block":
        kind = "block"
        company.is_blocked = True
    else:
        kind = "no_bids" if company.kind == "carrier" else "no_new_orders"
    if has_restriction(db, company.id, (kind,)):
        return
    db.add(Restriction(company_id=company.id, kind=kind, reason=f"antifraud:{r.code}",
                       until=None if kind == "block" else utcnow().date() + timedelta(days=7)))
    db.flush()
    audit(db, "antifraud.auto_restriction", object_type="company", object_id=company.id, role="system",
          details={"rule": r.code, "kind": kind, "alert": str(alert.id)})
