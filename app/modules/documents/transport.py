"""Electronic transport documents (section 51: GOV-TR-02..05).

* GOV-TR-02: the consignment note (ТТН) and, for international trips, the CMR are formed from the deal data
  (GOV-TR-01 fields) and can be downloaded as PDF and as the XML data set for the state system.
* GOV-TR-04: which documents a trip needs depends on its direction and is the platform setting
  ``transport_docs.rules`` — no code change for a new rule.
* GOV-TR-03: registration goes through an adapter with statuses (pending → registered / error) shown on the
  deal card; the worker retries. While the ``gov.etd`` flag is off the documents are prepared locally only.
* GOV-TR-05: without connection the trip is documented on paper; the paper number is entered later and the
  document is then sent for registration, while the deal history stays intact (all steps audited).
"""
from __future__ import annotations

import json
from xml.etree import ElementTree as ET  # noqa: S405 — builds XML only

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.audit import audit
from app.core.errors import Conflict, NotFound, ValidationFailed
from app.db import utcnow
from app.modules.accounts.models import Company
from app.modules.deals.models import Deal
from app.modules.documents.models import Document, TransportDocRegistration
from app.modules.fleet.models import Driver, Vehicle
from app.modules.integrations.base import Adapter, IntegrationUnavailable
from app.modules.orders import flow
from app.modules.orders.models import Order

TYPES = ("e_waybill", "cmr_form")
ALLOWED_STATUSES = (flow.ASSIGNED, flow.DOCS_SIGNED, flow.LOADING, flow.IN_TRANSIT)
REQUIRED_FIELDS = ("shipper_bin", "carrier_bin", "vehicle", "driver", "load_point", "unload_point", "cargo", "weight")
MAX_ATTEMPTS = 8
BACKOFF_MINUTES = (1, 5, 15, 60, 180, 360, 720)  # a short outage of the state system is waited out


class EtdAdapter(Adapter):
    """Exchange with the state transport documents system. The simulator validates the data set the way the
    system would (required fields) and returns a registration number; the real exchange replaces `_send`."""

    name = "etd"
    personal_data = True  # driver name and licence travel with the document
    retries = 0
    provider = "etd-sim"

    def register(self, data: dict) -> dict:
        from app.modules.integrations.adapters import simulator_guard

        simulator_guard("etd")
        return self.call("register", lambda: self._send(data), basis="law", summary=data.get("number", ""))

    def _send(self, data: dict) -> dict:
        missing = [k for k in REQUIRED_FIELDS if not str(data.get(k, "")).strip() or data.get(k) == "—"]
        if missing:
            return {"ok": False, "error": "missing: " + ", ".join(missing)}
        import hashlib

        digest = int(hashlib.sha256(str(data["number"]).encode()).hexdigest()[:8], 16) % 10**8
        return {"ok": True, "number": f"ЭТТН-{utcnow():%Y}-{digest:08d}"}


etd = EtdAdapter()


def rules(db: Session) -> dict:
    from app.modules.platform.service import get_setting

    value = get_setting(db, "transport_docs.rules", None)
    return value if isinstance(value, dict) else {"domestic": ["e_waybill"], "international": ["cmr_form", "e_waybill"]}


def required_types(db: Session, order: Order) -> list[str]:
    return [t for t in rules(db).get("international" if order.is_international else "domestic", []) if t in TYPES]


def data_set(db: Session, deal: Deal, order: Order, number: str = "") -> dict:
    client = db.get(Company, deal.client_company_id)
    carrier = db.get(Company, deal.carrier_company_id)
    vehicle = db.get(Vehicle, deal.vehicle_id) if deal.vehicle_id else None
    driver = db.get(Driver, deal.driver_id) if deal.driver_id else None
    first, last = order.origin, order.destination
    point = lambda p: f"{p.city}, {p.address}".strip(", ") if p else ""  # noqa: E731
    return {
        "number": number, "deal_number": deal.number, "order_number": order.number,
        "shipper_name": client.name, "shipper_bin": client.bin_iin, "shipper_address": client.legal_address,
        "shipper_country": "KZ", "consignee": f"{client.name} ({point(last)})",
        "carrier_name": carrier.name, "carrier_bin": carrier.bin_iin,
        "vehicle": vehicle.plate if vehicle else "—", "trailer": f", прицеп {deal.trailer_plate}" if deal.trailer_plate else "",
        "driver": driver.full_name if driver else "—", "driver_license": (driver.license_number if driver else "") or "—",
        "load_point": point(first), "unload_point": point(last),
        "load_date": order.load_from.strftime("%d.%m.%Y") if order.load_from else "",
        "unload_date": order.unload_to.strftime("%d.%m.%Y") if order.unload_to else "",
        "cargo": order.cargo_name, "packaging": order.packaging or "—", "places": order.places,
        "weight": order.weight_kg, "volume": order.volume_m3,
        "adr": f"класс {order.adr_class}, UN {order.un_number}" if order.adr_class else "нет",
        "border": order.border_crossing or "—", "international": order.is_international,
    }


def registrations(db: Session, deal_id) -> list[tuple[Document, TransportDocRegistration]]:
    return list(db.execute(select(Document, TransportDocRegistration)
                           .join(TransportDocRegistration, TransportDocRegistration.document_id == Document.id)
                           .where(TransportDocRegistration.deal_id == deal_id).order_by(Document.created_at)).all())


def form_documents(db: Session, deal: Deal, *, mode: str = "electronic", paper_number: str = "") -> list[Document]:
    from app.modules.documents.service import generate
    from app.modules.platform.service import flag_enabled

    order = db.get(Order, deal.order_id)
    if order.status not in ALLOWED_STATUSES:
        raise Conflict("transport_docs_not_now")
    if mode not in ("electronic", "paper"):
        raise ValidationFailed({"mode": "error.invalid_choice"})
    if mode == "paper" and not paper_number.strip():
        raise ValidationFailed({"paper_number": "error.required"})
    have = {d.doc_type for d, _ in registrations(db, deal.id)}
    created = []
    send = flag_enabled(db, "gov.etd", deal.carrier_company_id)
    for doc_type in required_types(db, order):
        if doc_type in have:
            continue
        ctx = data_set(db, deal, order)
        ctx["registration"] = "бумажный бланк № " + paper_number.strip() if mode == "paper" else "ожидает регистрации"
        doc = generate(db, doc_type, ctx, deal_id=deal.id, company_id=deal.carrier_company_id)
        ctx["number"] = doc.number
        status = "paper" if mode == "paper" else ("pending" if send else "local")
        db.add(TransportDocRegistration(document_id=doc.id, deal_id=deal.id, mode=mode,
                                        paper_number=paper_number.strip()[:40], status=status,
                                        data=json.dumps(ctx, ensure_ascii=False, default=str)))
        created.append(doc)
    db.flush()
    audit(db, "transport_docs.formed", object_type="deal", object_id=deal.id,
          details={"types": [d.doc_type for d in created], "mode": mode})
    return created


def submit_paper(db: Session, reg: TransportDocRegistration) -> None:
    """GOV-TR-05: the paper document's data are in the system now; send it for registration."""
    from app.modules.platform.service import flag_enabled

    if reg.status not in ("paper", "local", "error"):
        raise Conflict("already_decided")
    deal = db.get(Deal, reg.deal_id)
    reg.status = "pending" if flag_enabled(db, "gov.etd", deal.carrier_company_id) else "local"
    reg.attempts, reg.next_attempt_at = 0, None
    audit(db, "transport_docs.submitted", object_type="deal", object_id=reg.deal_id, details={"mode": reg.mode})


def process(db: Session, limit: int = 50) -> int:
    """Worker job (GOV-TR-03): register pending documents, keep errors visible on the deal card."""
    from app.core import rls

    from datetime import timedelta

    from sqlalchemy import or_

    now = utcnow()
    rows = db.execute(select(TransportDocRegistration).where(
        TransportDocRegistration.status == "pending",
        or_(TransportDocRegistration.next_attempt_at.is_(None), TransportDocRegistration.next_attempt_at <= now))
        .limit(limit).with_for_update(skip_locked=True)).scalars().all()
    with rls.system(db):
        for reg in rows:
            reg.attempts += 1
            try:
                out = etd.register(json.loads(reg.data or "{}"))
            except IntegrationUnavailable as exc:
                reg.last_error = f"unavailable: {exc}"[:300]
                if reg.attempts >= MAX_ATTEMPTS:
                    reg.status = "error"
                else:
                    pause = BACKOFF_MINUTES[min(reg.attempts - 1, len(BACKOFF_MINUTES) - 1)]
                    reg.next_attempt_at = now + timedelta(minutes=pause)
                continue
            if out.get("ok"):
                reg.status, reg.external_number, reg.registered_at, reg.last_error = "registered", out["number"], utcnow(), ""
            else:
                reg.status, reg.last_error = "error", str(out.get("error", ""))[:300]
            audit(db, "transport_docs.registration", object_type="deal", object_id=reg.deal_id, role="system",
                  result="ok" if reg.status == "registered" else "error", details={"status": reg.status})
    db.commit()
    return len(rows)


def xml_export(reg: TransportDocRegistration, doc: Document) -> bytes:
    data = json.loads(reg.data or "{}")
    root = ET.Element("transportDocument", {"type": doc.doc_type, "number": doc.number,
                                            "date": doc.created_at.strftime("%Y-%m-%d"), "mode": reg.mode})
    for key in ("deal_number", "order_number", "shipper_name", "shipper_bin", "shipper_address", "consignee",
                "carrier_name", "carrier_bin", "vehicle", "driver", "driver_license", "load_point", "load_date",
                "unload_point", "unload_date", "cargo", "packaging", "places", "weight", "volume", "adr", "border"):
        ET.SubElement(root, key).text = str(data.get(key, ""))
    if reg.paper_number:
        ET.SubElement(root, "paperNumber").text = reg.paper_number
    if reg.external_number:
        ET.SubElement(root, "registrationNumber").text = reg.external_number
    ET.indent(root)
    return b'<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="utf-8")


def get_registration(db: Session, deal_id, reg_id) -> tuple[Document, TransportDocRegistration]:
    reg = db.get(TransportDocRegistration, reg_id)
    if reg is None or reg.deal_id != deal_id:
        raise NotFound()
    return db.get(Document, reg.document_id), reg
