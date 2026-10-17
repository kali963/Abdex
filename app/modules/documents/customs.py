"""Customs data for international trips (GOV-TR-06): Kazakhstan — China — CIS.

The ТЗ asks to prepare the data and the documents; the exchange with customs systems (ASTANA-1, the
preliminary information of the EAEU, the Chinese single window) is decided after study in cycle 3, so here:

* the data set is collected on the deal from both sides: the shipper gives the goods (HS code of the EAEU
  nomenclature, description, weights, places, invoice, origin, consignee abroad), the carrier gives the
  transport part (transit document — TIR carnet or transit declaration, border crossing);
* which data and documents are required depends on the destination and is the platform setting
  ``customs.rules`` (groups of countries) — no code change for a new direction;
* a checklist shows what is missing; when complete the dossier is "ready" and is exported as XML (structure of
  the preliminary information: consignor, consignee, goods items, transport, border) and as a PDF summary;
* inside the EAEU there is no customs declaration, so for RU/BY/KG/AM only the shipping documents are asked.
"""
from __future__ import annotations

import json
import re
from xml.etree import ElementTree as ET  # noqa: S405 — builds XML only

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.audit import audit
from app.core.errors import Conflict, NotFound, ValidationFailed
from app.db import utcnow
from app.modules.accounts.models import Company
from app.modules.deals.models import Deal
from app.modules.documents.models import CustomsDossier, Document
from app.modules.orders.models import Order

CLIENT_FIELDS = ("hs_code", "goods_description", "gross_kg", "net_kg", "places", "packaging", "invoice_number",
                 "invoice_date", "invoice_value", "invoice_currency", "origin_country", "consignee_name",
                 "consignee_address", "consignee_country", "consignee_tax_id")
CARRIER_FIELDS = ("transit_mode", "tir_carnet", "transit_declaration", "border_crossing", "trailer_plate")
ALL_FIELDS = CLIENT_FIELDS + CARRIER_FIELDS
TRANSIT_MODES = ("tir", "transit_declaration", "none")
CURRENCIES = ("KZT", "USD", "CNY", "RUB", "EUR")
TRANSIT_DOC = {"tir": "tir_carnet", "transit_declaration": "transit_declaration"}


def rules(db: Session) -> dict:
    from app.modules.platform.service import get_setting

    from app.bootstrap import SETTINGS

    value = get_setting(db, "customs.rules", None)
    return value if isinstance(value, dict) and "groups" in value else SETTINGS["customs.rules"][0]


def countries_of(db: Session, order: Order) -> list[str]:
    """Order countries are free text ("CN, KZ", "Китай"); normalised to ISO codes via the dictionary."""
    from app.modules.platform.service import dictionary

    names = {}
    for item in dictionary(db, "countries"):
        names[item.code.upper()] = item.code.upper()
        names[item.name_ru.casefold()] = item.code.upper()
        names[item.name_kk.casefold()] = item.code.upper()
    out = []
    for token in re.split(r"[,;/]+|\s{2,}", order.countries or ""):
        token = token.strip()
        code = names.get(token.upper()) or names.get(token.casefold())
        if not code and len(token) == 2 and token.isalpha():
            code = token.upper()
        if code and code != "KZ" and code not in out:
            out.append(code)
    return out


def requirements(db: Session, order: Order) -> dict:
    """Union of the requirements of all foreign countries on the route."""
    r = rules(db)
    groups = []
    for code in countries_of(db, order):
        for g, members in r["groups"].items():
            if code in members and g not in groups:
                groups.append(g)
    if not groups and countries_of(db, order):
        groups = ["cis"]  # an unknown foreign country: the strictest common set
    fields, docs, customs = [], [], False
    for g in groups:
        spec = r.get(g, {})
        customs = customs or bool(spec.get("customs"))
        fields += [f for f in spec.get("fields", []) if f not in fields]
        docs += [d for d in spec.get("documents", []) if d not in docs]
    return {"groups": groups, "customs": customs, "fields": fields, "documents": docs}


def get(db: Session, deal: Deal) -> CustomsDossier | None:
    return db.execute(select(CustomsDossier).where(CustomsDossier.deal_id == deal.id)).scalar_one_or_none()


def data_of(dossier: CustomsDossier | None, deal: Deal, order: Order) -> dict:
    """Saved values, prefilled from the order and the deal where the platform already knows them."""
    d = {"goods_description": order.cargo_name, "gross_kg": order.weight_kg or "", "places": order.places or "",
         "packaging": order.packaging, "border_crossing": order.border_crossing, "trailer_plate": deal.trailer_plate,
         "invoice_currency": order.currency, "origin_country": "KZ", "transit_mode": "tir" if order.needs_tir else ""}
    if dossier is not None:
        d.update({k: v for k, v in json.loads(dossier.data or "{}").items() if v not in (None, "")})
    return d


def _validate(form: dict, allowed: tuple[str, ...]) -> tuple[dict, dict]:
    errors, clean = {}, {}
    for k in allowed:
        v = str(form.get(k, "")).strip()
        if not v:
            clean[k] = ""
            continue
        if k == "hs_code":
            v = v.replace(" ", "").replace(".", "")
            if not re.fullmatch(r"\d{10}", v):
                errors[k] = "error.hs_code"
        elif k in ("gross_kg", "net_kg", "places"):
            if not v.isdigit() or int(v) <= 0:
                errors[k] = "error.number_min"
        elif k == "invoice_value":
            try:
                if float(v.replace(" ", "").replace(",", ".")) <= 0:
                    raise ValueError
                v = v.replace(" ", "").replace(",", ".")
            except ValueError:
                errors[k] = "error.number"
        elif k == "invoice_currency" and v.upper() not in CURRENCIES:
            errors[k] = "error.invalid_choice"
        elif k in ("origin_country", "consignee_country"):
            v = v.upper()
            if not re.fullmatch(r"[A-Z]{2}", v):
                errors[k] = "error.country_code"
        elif k == "transit_mode" and v not in TRANSIT_MODES:
            errors[k] = "error.invalid_choice"
        elif k == "invoice_date" and not re.fullmatch(r"\d{4}-\d{2}-\d{2}", v):
            errors[k] = "error.date"
        clean[k] = v.upper() if k == "invoice_currency" else v[:300]
    if form.get("net_kg") and form.get("gross_kg") and not errors.get("net_kg") and not errors.get("gross_kg"):
        if int(form["net_kg"]) > int(form["gross_kg"]):
            errors["net_kg"] = "error.net_over_gross"
    return clean, errors


def save(db: Session, deal: Deal, side: str, form: dict) -> CustomsDossier:
    """Each side edits its own part; the other side's values stay untouched."""
    order = db.get(Order, deal.order_id)
    if not order.is_international:
        raise NotFound()
    allowed = CLIENT_FIELDS if side == "client" else CARRIER_FIELDS
    clean, errors = _validate(form, allowed)
    if errors:
        raise ValidationFailed(errors)
    dossier = get(db, deal)
    if dossier is None:
        dossier = CustomsDossier(deal_id=deal.id)
        db.add(dossier)
    current = json.loads(dossier.data or "{}")
    current.update(clean)
    dossier.data = json.dumps(current, ensure_ascii=False)
    dossier.status = "draft"
    dossier.ready_at = None
    db.flush()
    audit(db, "customs.saved", object_type="deal", object_id=deal.id, details={"side": side, "fields": sorted(
        k for k, v in clean.items() if v)})
    return dossier


def checklist(db: Session, deal: Deal, order: Order, dossier: CustomsDossier | None) -> dict:
    req = requirements(db, order)
    data = data_of(dossier, deal, order)
    missing_fields = [f for f in req["fields"] if not str(data.get(f, "")).strip()]
    if data.get("transit_mode") == "tir" and not data.get("tir_carnet") and req["customs"]:
        missing_fields.append("tir_carnet")
    have = {d.doc_type for d in db.execute(select(Document).where(Document.deal_id == deal.id,
                                                                   Document.is_deleted.is_(False))).scalars()}
    if "cmr_form" in have:
        have.add("cmr")  # the CMR formed by the platform (section 51) counts
    docs = list(req["documents"])
    extra = TRANSIT_DOC.get(data.get("transit_mode", "")) if req["customs"] else None
    if extra and extra not in docs:
        docs.append(extra)
    missing_docs = [d for d in docs if d not in have]
    return {**req, "documents": docs, "missing_fields": missing_fields, "missing_documents": missing_docs,
            "complete": not missing_fields and not missing_docs, "data": data}


def mark_ready(db: Session, deal: Deal) -> CustomsDossier:
    order = db.get(Order, deal.order_id)
    dossier = get(db, deal)
    if dossier is None:
        raise Conflict("customs_incomplete")
    check = checklist(db, deal, order, dossier)
    if not check["complete"]:
        raise Conflict("customs_incomplete")
    dossier.status, dossier.ready_at = "ready", utcnow()
    audit(db, "customs.ready", object_type="deal", object_id=deal.id, details={"groups": check["groups"]})
    return dossier


def xml_export(db: Session, deal: Deal) -> bytes:
    """Structure of the preliminary information (consignor, consignee, goods, transport, border)."""
    order = db.get(Order, deal.order_id)
    dossier = get(db, deal)
    d = data_of(dossier, deal, order)
    client = db.get(Company, deal.client_company_id)
    carrier = db.get(Company, deal.carrier_company_id)
    root = ET.Element("customsPreliminaryInformation", {"deal": deal.number, "order": order.number,
                                                        "status": dossier.status if dossier else "draft",
                                                        "created": utcnow().strftime("%Y-%m-%dT%H:%M:%S%z")})
    cons = ET.SubElement(root, "consignor")
    ET.SubElement(cons, "name").text = client.name
    ET.SubElement(cons, "bin").text = client.bin_iin
    ET.SubElement(cons, "address").text = client.legal_address
    ET.SubElement(cons, "country").text = "KZ"
    cee = ET.SubElement(root, "consignee")
    for k, tag in (("consignee_name", "name"), ("consignee_tax_id", "taxId"), ("consignee_address", "address"),
                   ("consignee_country", "country")):
        ET.SubElement(cee, tag).text = str(d.get(k, ""))
    inv = ET.SubElement(root, "invoice", {"number": str(d.get("invoice_number", "")),
                                          "date": str(d.get("invoice_date", ""))})
    ET.SubElement(inv, "value", {"currency": str(d.get("invoice_currency", ""))}).text = str(d.get("invoice_value", ""))
    goods = ET.SubElement(root, "goods")
    item = ET.SubElement(goods, "item", {"no": "1"})
    for k, tag in (("hs_code", "hsCode"), ("goods_description", "description"), ("gross_kg", "grossWeightKg"),
                   ("net_kg", "netWeightKg"), ("places", "places"), ("packaging", "packaging"),
                   ("origin_country", "originCountry")):
        ET.SubElement(item, tag).text = str(d.get(k, ""))
    tr = ET.SubElement(root, "transport")
    ET.SubElement(tr, "carrier").text = f"{carrier.name}, {carrier.bin_iin}"
    from app.modules.fleet.models import Vehicle

    vehicle = db.get(Vehicle, deal.vehicle_id) if deal.vehicle_id else None
    ET.SubElement(tr, "vehicle").text = vehicle.plate if vehicle else ""
    ET.SubElement(tr, "trailer").text = str(d.get("trailer_plate", ""))
    ET.SubElement(tr, "transitMode").text = str(d.get("transit_mode", ""))
    ET.SubElement(tr, "tirCarnet").text = str(d.get("tir_carnet", ""))
    ET.SubElement(tr, "transitDeclaration").text = str(d.get("transit_declaration", ""))
    ET.SubElement(tr, "borderCrossing").text = str(d.get("border_crossing", ""))
    route = ET.SubElement(root, "route")
    for p in order.points:
        ET.SubElement(route, "point", {"kind": p.kind}).text = p.city
    ET.indent(root)
    return b'<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="utf-8")


def pdf_summary(db: Session, deal: Deal) -> Document:
    """A PDF of the data set attached to the deal (template ``customs_info``)."""
    from app.modules.documents.service import generate

    order = db.get(Order, deal.order_id)
    d = data_of(get(db, deal), deal, order)
    client = db.get(Company, deal.client_company_id)
    carrier = db.get(Company, deal.carrier_company_id)
    ctx = {**{k: d.get(k, "") for k in ALL_FIELDS}, "deal_number": deal.number, "order_number": order.number,
           "shipper_name": client.name, "shipper_bin": client.bin_iin, "carrier_name": carrier.name,
           "carrier_bin": carrier.bin_iin, "route": " → ".join(p.city for p in order.points)}
    return generate(db, "customs_info", ctx, deal_id=deal.id, company_id=deal.client_company_id)
