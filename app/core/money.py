"""Money handling (FR-CALC-04, NFR-API-08).

All amounts are stored as integers in minor units (tiyn for KZT) together with an ISO 4217
currency code. Rounding happens ONLY in this module, by one documented rule:
ROUND_HALF_UP to the nearest minor unit.
"""
from __future__ import annotations

from decimal import ROUND_HALF_UP, Decimal, InvalidOperation

CURRENCIES: dict[str, dict] = {
    "KZT": {"symbol": "₸", "minor": 100},
    "USD": {"symbol": "$", "minor": 100},
    "EUR": {"symbol": "€", "minor": 100},
    "RUB": {"symbol": "₽", "minor": 100},
    "CNY": {"symbol": "¥", "minor": 100},
}
DEFAULT_CURRENCY = "KZT"


def round_minor(value: Decimal | float | int) -> int:
    """The single rounding point of the system."""
    return int(Decimal(str(value)).quantize(Decimal("1"), rounding=ROUND_HALF_UP))


def to_minor(amount: str | int | float | Decimal, currency: str = DEFAULT_CURRENCY) -> int:
    """Parse a human amount ("35 000,50") into minor units."""
    if isinstance(amount, str):
        cleaned = amount.replace(" ", "").replace(" ", "").replace(",", ".")
        if not cleaned:
            raise ValueError("empty amount")
        try:
            dec = Decimal(cleaned)
        except InvalidOperation as exc:
            raise ValueError("invalid amount") from exc
    else:
        dec = Decimal(str(amount))
    if dec < 0:
        raise ValueError("negative amount")
    return round_minor(dec * CURRENCIES.get(currency, {"minor": 100})["minor"])


def from_minor(minor: int, currency: str = DEFAULT_CURRENCY) -> Decimal:
    return Decimal(minor) / CURRENCIES.get(currency, {"minor": 100})["minor"]


def percent_of(minor: int, basis_points: int) -> int:
    """basis_points: 1% == 100 bp."""
    return round_minor(Decimal(minor) * Decimal(basis_points) / Decimal(10000))


def format_money(minor: int | None, currency: str = DEFAULT_CURRENCY) -> str:
    if minor is None:
        return "—"
    value = from_minor(minor, currency)
    whole = int(value)
    frac = abs(value - whole)
    text = f"{whole:,}".replace(",", " ")
    if frac:
        text += "," + f"{frac:.2f}"[2:]
    return f"{text} {CURRENCIES.get(currency, {'symbol': currency})['symbol']}"
