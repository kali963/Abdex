"""Calculation module (M9). All coefficients come from the `calc_coefficients` dictionary,
never from code (FR-CALC-01). Results are stored with inputs and methodology version so old
deals are not "recalculated" when dictionaries change (FR-CALC-05)."""
from __future__ import annotations

import json
from decimal import Decimal

from sqlalchemy.orm import Session

from app.core.context import get_ctx
from app.core.errors import ValidationFailed
from app.core.money import round_minor
from app.modules.platform.models import CalcResult
from app.modules.platform.service import dictionary_extra, get_setting

METHODOLOGY_VERSION = "2026.1"


def _coef(db: Session) -> dict:
    """Coefficients in minor units / ratios, keyed by code."""
    out = {}
    for code, extra in dictionary_extra(db, "calc_coefficients").items():
        out[code] = Decimal(str(extra.get("value", 0)))
    return out


def _num(form: dict, key: str, errors: dict, default: float = 0) -> Decimal:
    raw = (form.get(key) or "").replace(",", ".").replace(" ", "")
    if not raw:
        return Decimal(str(default))
    try:
        v = Decimal(raw)
    except Exception:  # noqa: BLE001
        errors[key] = "error.number"
        return Decimal(0)
    if v < 0:
        errors[key] = "error.number_min"
    return v


def trip_cost(db: Session, form: dict, *, save: bool = True) -> dict:
    """FR-CALC-01: cost of a trip for the carrier."""
    errors: dict = {}
    c = _coef(db)
    distance = _num(form, "distance_km", errors)
    days = _num(form, "days", errors, 1)
    fuel_per_100 = _num(form, "fuel_per_100", errors, float(c.get("fuel_per_100_km", 32)))
    fuel_price = _num(form, "fuel_price", errors, float(c.get("diesel_price_kzt", 310)))
    tolls = _num(form, "tolls", errors)
    loading = _num(form, "loading", errors)
    parking = _num(form, "parking", errors)
    other = _num(form, "other", errors)
    price = _num(form, "price", errors)
    if distance <= 0:
        errors["distance_km"] = "error.required"
    if errors:
        raise ValidationFailed(errors)
    per_diem = c.get("driver_per_diem_kzt", Decimal(15000))
    amort = c.get("amortization_per_km_kzt", Decimal(60))
    tax_rate = c.get("tax_rate", Decimal("0.03"))
    fee = Decimal(get_setting(db, "billing.reference_fixed_fee_minor", 3_500_000)) / 100
    items = {
        "fuel": distance * fuel_per_100 / 100 * fuel_price,
        "per_diem": per_diem * days,
        "tolls": tolls,
        "loading": loading,
        "parking": parking,
        "amortization": amort * distance,
        "other": other,
    }
    total = sum(items.values())
    result = {k: round_minor(v * 100) for k, v in items.items()}
    result["total"] = round_minor(total * 100)
    if price > 0:
        taxes = price * tax_rate
        margin = price - total - taxes - fee
        result.update({"price": round_minor(price * 100), "taxes": round_minor(taxes * 100),
                       "platform_fee": round_minor(fee * 100), "margin": round_minor(margin * 100),
                       "margin_pct": float(round(margin * 100 / price, 1)),
                       "cost_per_km": round_minor(total / distance * 100)})
    if save:
        _save(db, "trip_cost", form, result)
    return result


def client_price(db: Session, form: dict, *, save: bool = True) -> dict:
    """FR-CALC-02: indicative price for the client by base rate and surcharges."""
    errors: dict = {}
    c = _coef(db)
    distance = _num(form, "distance_km", errors)
    if distance <= 0:
        errors["distance_km"] = "error.required"
    if errors:
        raise ValidationFailed(errors)
    body = form.get("body_type") or "tent"
    base = c.get(f"base_rate_{body}", c.get("base_rate_tent", Decimal(450)))
    mult = Decimal(1)
    applied = []
    for flag, code in (("urgent", "surcharge_urgent"), ("temperature", "surcharge_temperature"),
                       ("adr", "surcharge_adr"), ("oversize", "surcharge_oversize"), ("season", "surcharge_season")):
        if form.get(flag):
            mult += c.get(code, Decimal(0))
            applied.append(code)
    price = distance * base * mult
    result = {"base_rate_per_km": round_minor(base * 100), "multiplier": float(mult), "applied": applied,
              "total": round_minor(price * 100)}
    if save:
        _save(db, "client_price", form, result)
    return result


def _save(db: Session, kind: str, inputs: dict, result: dict) -> None:
    ctx = get_ctx()
    clean = {k: v for k, v in inputs.items() if k != "csrf_token"}
    db.add(CalcResult(company_id=ctx.company_id, user_id=ctx.user_id, kind=kind, methodology_version=METHODOLOGY_VERSION,
                      inputs=json.dumps(clean, ensure_ascii=False), result=json.dumps(result)))
