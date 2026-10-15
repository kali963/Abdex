"""Bulk order import from CSV / XLSX (FR-ORD-06).

All-or-nothing: every row is validated first with the same rules as the web form; if any row
has errors, nothing is created and the user gets an error report by row and column.
"""
from __future__ import annotations

import csv
import io
from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy.orm import Session

from app.core.errors import AppError, ValidationFailed
from app.modules.accounts.models import Company
from app.modules.orders import service as orders

MAX_ROWS = 500
COLUMNS = ("from_city", "from_address", "to_city", "to_address", "cargo_name", "weight_kg", "volume_m3", "places",
           "body_type", "load_date", "unload_date", "desired_rate", "payment_terms", "publish")
REQUIRED = ("from_city", "to_city", "cargo_name", "weight_kg", "load_date")
EXAMPLE = ("Алматы", "ул. Складская, 5", "Астана", "пр. Туран, 20", "Мука в мешках", "20000", "60", "20", "tent",
           "2026-12-01 09:00", "2026-12-03 18:00", "650000", "on_unload", "да")
_DATE_FORMATS = ("%Y-%m-%d %H:%M", "%Y-%m-%dT%H:%M", "%d.%m.%Y %H:%M", "%Y-%m-%d", "%d.%m.%Y")


@dataclass
class ImportResult:
    created: list = field(default_factory=list)
    errors: list[tuple[int, str, str]] = field(default_factory=list)  # (row, column, message key)


def _to_local_input(value) -> str:
    if value in (None, ""):
        return ""
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%dT%H:%M")
    text = str(value).strip()
    for fmt in _DATE_FORMATS:
        try:
            return datetime.strptime(text, fmt).strftime("%Y-%m-%dT%H:%M")
        except ValueError:
            continue
    raise ValueError(text)


def read_rows(filename: str, data: bytes) -> list[dict]:
    name = (filename or "").lower()
    if name.endswith(".xlsx"):
        from openpyxl import load_workbook

        try:
            wb = load_workbook(io.BytesIO(data), read_only=True, data_only=True)
        except Exception as exc:  # noqa: BLE001 — any parse failure is a bad file for the user
            raise AppError("import_bad_file") from exc
        rows = list(wb.active.iter_rows(values_only=True))
        if not rows:
            return []
        header = [str(h or "").strip().lower() for h in rows[0]]
        return [dict(zip(header, r, strict=False)) for r in rows[1:] if any(c not in (None, "") for c in r)]
    if name.endswith(".csv"):
        text = data.decode("utf-8-sig", errors="replace")
        try:
            dialect = csv.Sniffer().sniff(text[:2000], delimiters=";,\t")
        except csv.Error:
            dialect = csv.excel
        reader = csv.DictReader(io.StringIO(text), dialect=dialect)
        return [{(k or "").strip().lower(): v for k, v in row.items()} for row in reader if any((v or "").strip() for v in row.values())]
    raise AppError("import_bad_file")


def _row_form(row: dict) -> dict:
    get = lambda k: "" if row.get(k) is None else str(row.get(k)).strip()  # noqa: E731
    form = {"cargo_name": get("cargo_name"), "weight_kg": get("weight_kg"), "volume_m3": get("volume_m3"),
            "places": get("places"), "body_type": get("body_type") or "tent", "desired_rate": get("desired_rate"),
            "payment_terms": get("payment_terms") or "on_unload", "currency": "KZT", "vat_included": "on",
            "point_kind": ["load", "unload"], "point_city": [get("from_city"), get("to_city")],
            "point_address": [get("from_address"), get("to_address")], "point_contact_name": ["", ""],
            "point_contact_phone": ["", ""]}
    form["load_from"] = _to_local_input(row.get("load_date"))
    form["unload_to"] = _to_local_input(row.get("unload_date"))
    return form


def import_orders(db: Session, company: Company, filename: str, data: bytes) -> ImportResult:
    rows = read_rows(filename, data)
    result = ImportResult()
    if not rows:
        raise AppError("import_empty")
    if len(rows) > MAX_ROWS:
        raise AppError("import_too_many", limit=MAX_ROWS)
    missing = [c for c in REQUIRED if c not in rows[0]]
    if missing:
        raise AppError("import_missing_columns", columns=", ".join(missing))
    forms = []
    for i, row in enumerate(rows, start=2):  # row 1 is the header
        try:
            form = _row_form(row)
        except ValueError:
            result.errors.append((i, "load_date / unload_date", "error.date"))
            continue
        try:
            orders.parse_order_form(form)
        except ValidationFailed as exc:
            result.errors.extend((i, k, v) for k, v in exc.fields.items())
            continue
        publish = str(row.get("publish") or "").strip().lower() in ("да", "yes", "1", "true", "иә")
        forms.append((form, publish))
    if result.errors:
        return result  # all-or-nothing: no partial import
    from app.core import ratelimit

    ratelimit.hit("export", f"import:{company.id}")  # one bulk import counts once, not per row
    for form, publish in forms:
        order = orders.create_order(db, company, form, rate_limited=False)
        if publish:
            orders.submit(db, order)
        result.created.append(order)
    return result


def template_xlsx() -> bytes:
    from openpyxl import Workbook
    from openpyxl.styles import Font

    wb = Workbook()
    ws = wb.active
    ws.title = "orders"
    ws.append(list(COLUMNS))
    for cell in ws[1]:
        cell.font = Font(bold=True)
    ws.append(list(EXAMPLE))
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()
