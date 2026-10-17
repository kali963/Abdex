"""Multi-currency with the rate fixed on the deal date (FR-LOC-04).

* Tenge is the base currency. Official rates of the National Bank of Kazakhstan are loaded daily by the worker
  (``FX_RATES_URL``, the NBRK RSS feed ``get_rates.cfm?fdate=DD.MM.YYYY``); finance staff can enter a rate by
  hand when the source is unavailable (/admin/fx) — the manual rate is marked as such.
* A deal in another currency stores the rate to tenge on its date (``deal.fx_rate``, ``deal.fx_date``); reports,
  analytics and a percent platform fee use that stored rate, so later rate changes never alter old deals.
* Without any known rate the deal still goes on: the rate stays empty and the deal is shown in its own currency;
  the fee falls back to the fixed part of the tariff (the calculation records why).
"""
from __future__ import annotations

from datetime import date, timedelta
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from xml.etree import ElementTree as ET  # noqa: S405 — parses the configured official feed only

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.config import settings
from app.core.audit import audit
from app.core.errors import ValidationFailed
from app.core.timeutil import local_today
from app.modules.integrations.base import Adapter, IntegrationUnavailable
from app.modules.platform.models import CurrencyRate

BASE = "KZT"
CURRENCIES = ("USD", "EUR", "CNY", "RUB")
SIM_RATES = {"USD": "478.50", "EUR": "521.20", "CNY": "66.40", "RUB": "5.92"}  # test values, development only


class NbrkRates(Adapter):
    name = "fx"
    provider = "nbrk"
    timeout = 10.0

    def fetch(self, on: date) -> dict[str, str]:
        return self.call("rates", lambda: self._fetch(on), cache_key=on.isoformat(), summary=on.isoformat())

    def _fetch(self, on: date) -> dict[str, str]:
        import urllib.request

        url = f"{settings.fx_rates_url}?fdate={on:%d.%m.%Y}"
        with urllib.request.urlopen(url, timeout=self.timeout) as resp:  # noqa: S310 — configured https feed
            root = ET.fromstring(resp.read())  # noqa: S314 — official feed
        out = {}
        for item in root.iter("item"):
            code = (item.findtext("title") or "").strip().upper()
            try:
                quant = Decimal((item.findtext("quant") or "1").strip() or "1")
                rate = Decimal((item.findtext("description") or "").strip()) / quant
            except (InvalidOperation, ZeroDivisionError):
                continue
            if code in CURRENCIES:
                out[code] = str(rate.quantize(Decimal("0.000001")))
        return out


class SimRates(Adapter):
    name = "fx"
    provider = "sim"

    def fetch(self, on: date) -> dict[str, str]:
        return self.call("rates", lambda: dict(SIM_RATES), cache_key=on.isoformat(), summary=on.isoformat())


_sources: dict[str, Adapter] = {}


def source() -> Adapter | None:
    if settings.fx_rates_url:
        return _sources.setdefault("nbrk", NbrkRates())
    if settings.is_production:
        return None  # no feed configured: finance staff enter rates by hand
    return _sources.setdefault("sim", SimRates())


def _store(db: Session, on: date, code: str, rate: str, src: str) -> CurrencyRate:
    row = db.execute(select(CurrencyRate).where(CurrencyRate.on_date == on, CurrencyRate.code == code)
                     ).scalar_one_or_none()
    if row is None:
        row = CurrencyRate(on_date=on, code=code, rate=rate, source=src)
        try:
            with db.begin_nested():
                db.add(row)
                db.flush()
        except IntegrityError:
            row = db.execute(select(CurrencyRate).where(CurrencyRate.on_date == on, CurrencyRate.code == code)
                             ).scalar_one()
    elif row.source != "manual" or src == "manual":
        row.rate, row.source = rate, src  # a manual rate is never overwritten by the feed
    return row


def load(db: Session, on: date | None = None) -> int:
    """Worker job / on demand: official rates for the date."""
    on = on or local_today()
    src = source()
    if src is None:
        return 0
    try:
        rates = src.fetch(on)
    except IntegrationUnavailable:
        return 0
    for code, rate in rates.items():
        _store(db, on, code, rate, src.provider)
    db.commit()
    return len(rates)


def set_manual(db: Session, on: date, code: str, rate_raw: str) -> CurrencyRate:
    code = (code or "").upper()
    if code not in CURRENCIES:
        raise ValidationFailed({"code": "error.invalid_choice"})
    try:
        rate = Decimal(str(rate_raw).replace(",", ".").replace(" ", ""))
        if rate <= 0 or rate > 1_000_000:
            raise InvalidOperation
    except InvalidOperation:
        raise ValidationFailed({"rate": "error.number"})
    row = _store(db, on, code, str(rate.quantize(Decimal("0.000001"))), "manual")
    audit(db, "fx.manual_rate", object_type="currency_rate", object_id=f"{code}:{on.isoformat()}",
          details={"rate": row.rate})
    return row


def rate_on(db: Session, code: str, on: date, *, fetch: bool = True) -> Decimal | None:
    """Rate of one unit of ``code`` in tenge on the date: the latest known rate not later than the date
    (rates are published for business days), loading the day from the source when nothing is known."""
    code = (code or BASE).upper()
    if code == BASE:
        return Decimal(1)
    row = db.execute(select(CurrencyRate).where(CurrencyRate.code == code, CurrencyRate.on_date <= on,
                                                CurrencyRate.on_date >= on - timedelta(days=10))
                     .order_by(CurrencyRate.on_date.desc())).scalars().first()
    if row is None and fetch and source() is not None:
        try:
            for c, r in source().fetch(on).items():
                _store(db, on, c, r, source().provider)
        except IntegrationUnavailable:
            return None
        return rate_on(db, code, on, fetch=False)
    return Decimal(row.rate) if row else None


def fix_for_deal(db: Session, deal) -> None:
    """Called when the deal is created: the rate on the deal date is stored in the deal."""
    on = local_today()
    rate = rate_on(db, deal.currency, on)
    deal.fx_rate, deal.fx_date = (str(rate) if rate is not None else ""), on


def to_kzt_minor(amount_minor: int, currency: str, rate: str | Decimal | None) -> int | None:
    if (currency or BASE).upper() == BASE:
        return amount_minor
    if rate in (None, ""):
        return None
    return int((Decimal(amount_minor) * Decimal(str(rate))).quantize(Decimal(1), rounding=ROUND_HALF_UP))


def deal_kzt(deal) -> int | None:
    return to_kzt_minor(deal.price_minor, deal.currency, deal.fx_rate)


def latest(db: Session, limit_days: int = 14) -> list[CurrencyRate]:
    since = local_today() - timedelta(days=limit_days)
    return list(db.execute(select(CurrencyRate).where(CurrencyRate.on_date >= since)
                           .order_by(CurrencyRate.on_date.desc(), CurrencyRate.code)).scalars())
