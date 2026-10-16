"""Accounting export and preparation of electronic invoices / acts (FR-BIL-07).

* XLSX register of platform invoices, acts and payments for a period — for the client's accountant (own
  company only) and for the platform's finance team (all companies).
* XML of the electronic invoice (ЭСФ) and the electronic act of completed services (АВР) per invoice, built from
  the stored accrual (single rounding, FR-BIL-02) and the platform requisites setting. The structure follows
  the data set of the IS ESF documents; sending to IS ESF is a separate adapter (Ц3) — here the files are
  prepared and downloadable, so the accountant can load them into IS ESF or 1C.
"""
from __future__ import annotations

import io
import json
import zipfile
from datetime import date, datetime, time, timezone
from xml.etree import ElementTree as ET  # noqa: S405 — only builds XML, never parses untrusted input

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.money import from_minor
from app.modules.accounts.models import Company
from app.modules.billing.models import Accrual, Invoice, Payment
from app.modules.deals.models import Deal

SUBJECT = ("Услуги по предоставлению программно-технических возможностей платформы AbdEX для оформления "
           "сделки № {deal}")


def _period(d1: date, d2: date):
    return datetime.combine(d1, time.min, tzinfo=timezone.utc), datetime.combine(d2, time.max, tzinfo=timezone.utc)


def rows(db: Session, d1: date, d2: date, company_id=None) -> list[dict]:
    start, end = _period(d1, d2)
    q = select(Invoice, Company).join(Company, Company.id == Invoice.company_id).where(
        Invoice.created_at >= start, Invoice.created_at <= end).order_by(Invoice.created_at)
    if company_id is not None:
        q = q.where(Invoice.company_id == company_id)
    out = []
    for inv, company in db.execute(q).all():
        deal = db.get(Deal, inv.deal_id) if inv.deal_id else None
        paid = sum(p.amount_minor for p in db.execute(select(Payment).where(Payment.invoice_id == inv.id)).scalars())
        out.append({"invoice": inv, "company": company, "deal": deal, "paid_minor": paid})
    return out


def register_xlsx(items: list[dict], labels: dict[str, str]) -> bytes:
    from openpyxl import Workbook
    from openpyxl.styles import Font

    wb = Workbook()
    ws = wb.active
    ws.title = "invoices"
    head = [labels[k] for k in ("date", "invoice", "deal", "buyer", "bin", "amount", "currency", "status", "paid",
                                "due")]
    ws.append(head)
    for c in ws[1]:
        c.font = Font(bold=True)
    for r in items:
        inv = r["invoice"]
        ws.append([inv.created_at.strftime("%d.%m.%Y"), inv.number, r["deal"].number if r["deal"] else "",
                   r["company"].name, r["company"].bin_iin, float(from_minor(inv.amount_minor, inv.currency)),
                   inv.currency, labels.get(f"st.{inv.status}", inv.status),
                   float(from_minor(r["paid_minor"], inv.currency)), inv.due_date.strftime("%d.%m.%Y") if inv.due_date else ""])
    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


def _accrual(db: Session, inv: Invoice) -> Accrual | None:
    return db.execute(select(Accrual).where(Accrual.invoice_id == inv.id, Accrual.storno_of_id.is_(None))).scalars().first()


def _party(parent, tag: str, *, name: str, tin: str, address: str = "", iik: str = "", bank: str = "", bik: str = ""):
    p = ET.SubElement(parent, tag)
    ET.SubElement(p, "tin").text = tin
    ET.SubElement(p, "name").text = name
    ET.SubElement(p, "address").text = address
    if iik:
        ET.SubElement(p, "iik").text = iik
        ET.SubElement(p, "bank").text = bank
        ET.SubElement(p, "bik").text = bik
    return p


def esf_xml(db: Session, inv: Invoice, *, kind: str = "invoice") -> bytes:
    """kind: invoice (ЭСФ) or act (АВР). Amounts come from the accrual, never recalculated."""
    from app.modules.platform.service import get_setting

    req = get_setting(db, "platform.requisites", {}) or {}
    buyer = db.get(Company, inv.company_id)
    deal = db.get(Deal, inv.deal_id) if inv.deal_id else None
    vat_payer = bool(req.get("vat_payer"))
    amount = from_minor(inv.amount_minor, inv.currency)
    root = ET.Element("v2:invoice" if kind == "invoice" else "awp:act",
                      {"xmlns:v2": "abdex:esf:v2", "xmlns:awp": "abdex:awp:v1", "num": inv.number,
                       "date": inv.created_at.strftime("%d.%m.%Y")})
    ET.SubElement(root, "invoiceType").text = "ORDINARY_INVOICE" if kind == "invoice" else "COMPLETED_WORKS"
    ET.SubElement(root, "turnoverDate").text = inv.created_at.strftime("%d.%m.%Y")
    sellers = ET.SubElement(root, "sellers")
    _party(sellers, "seller", name=req.get("name", ""), tin=req.get("bin", ""), address=req.get("address", ""),
           iik=req.get("iik", ""), bank=req.get("bank", ""), bik=req.get("bik", ""))
    customers = ET.SubElement(root, "customers")
    _party(customers, "customer", name=buyer.name, tin=buyer.bin_iin, address=buyer.legal_address)
    products = ET.SubElement(root, "productSet", {"currencyCode": inv.currency})
    prod = ET.SubElement(products, "product")
    acc = _accrual(db, inv)
    own_subject = json.loads(acc.calculation or "{}").get("subject", "") if acc is not None and not deal else ""
    ET.SubElement(prod, "description").text = (own_subject[:1].upper() + own_subject[1:] if own_subject  # FR-BIL-08 modules
                                               else SUBJECT.format(deal=deal.number if deal else inv.number))
    ET.SubElement(prod, "unitNomenclature").text = "услуга"
    ET.SubElement(prod, "quantity").text = "1"
    ET.SubElement(prod, "unitPrice").text = f"{amount:.2f}"
    ET.SubElement(prod, "priceWithoutTax").text = f"{amount:.2f}"
    ET.SubElement(prod, "ndsRate").text = "12" if vat_payer else "БЕЗ НДС"
    ET.SubElement(prod, "priceWithTax").text = f"{amount:.2f}"
    totals = ET.SubElement(products, "totals")
    ET.SubElement(totals, "totalPriceWithTax").text = f"{amount:.2f}"
    if acc is not None:
        ET.SubElement(root, "incomeType").text = acc.income_type  # FR-PVD-01: kept for the ПВД report
    ET.indent(root)
    return b'<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="utf-8")


def esf_zip(db: Session, items: list[dict]) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for r in items:
            inv = r["invoice"]
            if inv.status == "cancelled" or inv.amount_minor <= 0:
                continue
            safe = inv.number.replace("/", "-")
            z.writestr(f"esf/{safe}.xml", esf_xml(db, inv, kind="invoice"))
            z.writestr(f"awp/{safe}.xml", esf_xml(db, inv, kind="act"))
    return buf.getvalue()
