"""Safe tabular exports (SEC-APP): a cell that starts like a formula is written as text, so a company name or a
city typed by another user can never run as a spreadsheet formula (CSV/formula injection)."""
from __future__ import annotations

_FORMULA_START = ("=", "+", "-", "@", "\t", "\r", "\n")


def cell(value):
    if isinstance(value, str) and value.startswith(_FORMULA_START):
        return "'" + value
    return value


def row(values) -> list:
    return [cell(v) for v in values]
