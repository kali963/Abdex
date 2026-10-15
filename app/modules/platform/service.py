"""Dictionaries, settings, feature flags, numbering, antifraud alerts, idempotency."""
from __future__ import annotations

import json
import zlib

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.context import get_ctx
from app.db import utcnow
from app.modules.documents.models import DocumentCounter
from app.modules.platform.models import (
    AntifraudAlert,
    DictionaryHistory,
    DictionaryItem,
    FeatureFlag,
    IdempotencyKey,
    PlatformSetting,
)

# ---------------------------------------------------------------- dictionaries (FR-ADM-01)


def dictionary(db: Session, name: str, *, active_only: bool = True) -> list[DictionaryItem]:
    q = select(DictionaryItem).where(DictionaryItem.dictionary == name)
    if active_only:
        q = q.where(DictionaryItem.is_active.is_(True))
    return list(db.execute(q.order_by(DictionaryItem.sort, DictionaryItem.name_ru)).scalars())


def dictionary_map(db: Session, name: str) -> dict[str, str]:
    loc = get_ctx().locale
    return {i.code: (i.name_kk if loc == "kk" and i.name_kk else i.name_ru) for i in dictionary(db, name, active_only=False)}


def dictionary_label(db: Session, name: str, code: str) -> str:
    return dictionary_map(db, name).get(code, code)


def dictionary_extra(db: Session, name: str) -> dict[str, dict]:
    return {i.code: json.loads(i.extra or "{}") for i in dictionary(db, name)}


def update_dictionary_item(db: Session, item: DictionaryItem, *, name_ru: str, name_kk: str, extra: str,
                           is_active: bool, sort: int) -> None:
    before = json.dumps({"name_ru": item.name_ru, "name_kk": item.name_kk, "extra": item.extra,
                         "is_active": item.is_active, "sort": item.sort}, ensure_ascii=False)
    json.loads(extra or "{}")  # validate JSON
    item.name_ru, item.name_kk, item.extra, item.is_active, item.sort = name_ru, name_kk, extra or "{}", is_active, sort
    item.updated_by = get_ctx().user_id
    after = json.dumps({"name_ru": name_ru, "name_kk": name_kk, "extra": extra, "is_active": is_active, "sort": sort},
                       ensure_ascii=False)
    db.add(DictionaryHistory(item_id=item.id, before=before, after=after, created_by=get_ctx().user_id))


# ---------------------------------------------------------------- settings (FR-ADM-06, FR-PVD-05)


def get_setting(db: Session, key: str, default=None):
    row = db.execute(select(PlatformSetting).where(PlatformSetting.key == key)).scalar_one_or_none()
    if row is None:
        return default
    try:
        return json.loads(row.value)
    except ValueError:
        return row.value


def set_setting(db: Session, key: str, value, description: str = "") -> None:
    row = db.execute(select(PlatformSetting).where(PlatformSetting.key == key)).scalar_one_or_none()
    raw = json.dumps(value, ensure_ascii=False)
    if row is None:
        db.add(PlatformSetting(key=key, value=raw, description=description))
    else:
        row.value = raw
        row.updated_by = get_ctx().user_id


def localized_setting(db: Session, key: str) -> str:
    value = get_setting(db, key, {})
    if isinstance(value, dict):
        return value.get(get_ctx().locale) or value.get("ru") or ""
    return str(value or "")


# ---------------------------------------------------------------- feature flags (FR-ADM-03)


def flag_enabled(db: Session, key: str, company_id=None) -> bool:
    flag = db.execute(select(FeatureFlag).where(FeatureFlag.key == key)).scalar_one_or_none()
    if flag is None:
        return False
    if flag.enabled:
        return True
    if company_id is not None:
        if str(company_id) in {c.strip() for c in flag.company_ids.split(",") if c.strip()}:
            return True
        if flag.percent and (zlib.crc32(f"{key}:{company_id}".encode()) % 100) < flag.percent:
            return True
    return False


# ---------------------------------------------------------------- numbering (FR-DOC-03)


def next_number(db: Session, doc_type: str, prefix: str, *, width: int = 6) -> str:
    """Collision-safe sequential numbering per type and year (row lock + unique constraint)."""
    year = utcnow().year
    for _ in range(3):
        counter = db.execute(
            select(DocumentCounter).where(DocumentCounter.doc_type == doc_type, DocumentCounter.year == year)
            .with_for_update()
        ).scalar_one_or_none()
        if counter is None:
            try:
                with db.begin_nested():
                    counter = DocumentCounter(doc_type=doc_type, year=year, last_value=0)
                    db.add(counter)
                    db.flush()
            except IntegrityError:
                continue
        counter.last_value += 1
        db.flush()
        return f"{prefix}-{year}-{counter.last_value:0{width}d}"
    raise RuntimeError("numbering contention")


# ---------------------------------------------------------------- antifraud alerts


def raise_alert(db: Session, kind: str, *, severity: str = "medium", company_id=None, deal_id=None,
                details: dict | None = None) -> AntifraudAlert | None:
    """Alerts go to the manual review queue; nothing is blocked silently (FR-KYC-07).

    The rule for `kind` (SEC-FRD-01) decides: disabled or "allow" -> nothing; "flag" -> a low-priority record;
    "review" -> the manual review queue; "restrict"/"block" -> also an immediate restriction of the company."""
    from app.modules.platform.antifraud import apply_action, rule

    r = rule(db, kind)
    if not r.enabled or r.action == "allow":
        return None
    severity = r.severity or severity
    existing = db.execute(
        select(AntifraudAlert).where(AntifraudAlert.kind == kind, AntifraudAlert.company_id == company_id,
                                     AntifraudAlert.deal_id == deal_id,
                                     AntifraudAlert.status.in_(("open", "flagged")))
    ).scalar_one_or_none()
    if existing:
        return existing
    alert = AntifraudAlert(kind=kind, severity=severity, company_id=company_id, deal_id=deal_id,
                           status="flagged" if r.action == "flag" else "open",
                           details=json.dumps(details or {}, ensure_ascii=False, default=str))
    db.add(alert)
    db.flush()
    apply_action(db, r, alert)
    return alert


# ---------------------------------------------------------------- idempotency (NFR-API-04)


def idempotent_lookup(db: Session, user_id, key: str | None, scope: str) -> str | None:
    if not key:
        return None
    row = db.execute(
        select(IdempotencyKey).where(IdempotencyKey.user_id == user_id, IdempotencyKey.key == key[:80])
    ).scalar_one_or_none()
    return row.result_ref if row else None


def idempotent_store(db: Session, user_id, key: str | None, scope: str, result_ref: str) -> None:
    if not key:
        return
    db.add(IdempotencyKey(user_id=user_id, key=key[:80], scope=scope, result_ref=result_ref))


# ---------------------------------------------------------------- restrictions (FR-RAT-04, FR-BID-08)


def has_restriction(db: Session, company_id, kinds: tuple[str, ...]) -> bool:
    from app.modules.platform.models import Restriction

    active = db.execute(select(Restriction).where(Restriction.company_id == company_id, Restriction.kind.in_(kinds),
                                                  Restriction.lifted_at.is_(None))).scalars().all()
    today = utcnow().date()
    return any(r.until is None or r.until >= today for r in active)
