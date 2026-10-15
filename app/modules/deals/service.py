"""Deal lifecycle (M5, M11, M14): snapshot, supplements, executor change, trip, disputes, dossier."""
from __future__ import annotations

import io
import json
import zipfile
from dataclasses import dataclass

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from app.core.audit import audit
from app.core.context import get_ctx
from app.core.errors import AppError, Conflict, Forbidden, NotFound, ValidationFailed
from app.core.money import format_money, to_minor
from app.core.security import sha256_hex
from app.db import utcnow
from app.modules.accounts.models import Company, User
from app.modules.accounts.permissions import company_can, staff_can
from app.modules.bids.models import Bid
from app.modules.deals.models import (
    Checkpoint,
    Deal,
    DealSnapshot,
    Dispute,
    ExecutorChange,
    Incident,
    Rating,
    Supplement,
)
from app.modules.fleet.models import Driver, Vehicle
from app.modules.orders import flow
from app.modules.rating import service as rating
from app.modules.webhooks import service as webhooks
from app.modules.orders.models import Order, StatusHistory
from app.modules.platform.service import get_setting, next_number, raise_alert

CHECKPOINTS = ("arrived_load", "loaded", "departed", "arrived_unload", "unloaded")
# Checkpoint -> status transition it triggers (section 6)
CHECKPOINT_TRANSITIONS = {"arrived_load": flow.LOADING, "loaded": flow.IN_TRANSIT, "unloaded": flow.UNLOADED}


@dataclass
class DealAccess:
    deal: Deal
    order: Order
    side: str  # client / carrier / driver / staff
    role: str


def get_access(db: Session, deal_id, *, user: User, company_id, role: str | None,
               allow_staff: bool = False) -> DealAccess:
    """FR-ACL-01/03, SEC-AZ-02: access by membership in a side of the deal, checked every request."""
    deal = db.get(Deal, deal_id)
    if deal is None:
        raise NotFound()
    order = db.get(Order, deal.order_id)
    if allow_staff and user.staff_role and staff_can(user.staff_role, "admin.deal_content") and company_id is None:
        return DealAccess(deal, order, "staff", user.staff_role)
    if not company_can(role, "deal.view"):
        raise NotFound()
    if role == "driver":
        drv = db.get(Driver, deal.driver_id) if deal.driver_id else None
        if drv is None or drv.user_id != user.id:
            raise NotFound()
        return DealAccess(deal, order, "driver", role)
    if company_id == deal.client_company_id:
        return DealAccess(deal, order, "client", role)
    if company_id == deal.carrier_company_id:
        return DealAccess(deal, order, "carrier", role)
    raise NotFound()


def snapshot_payload(db: Session, deal: Deal, order: Order) -> dict:
    client = db.get(Company, deal.client_company_id)
    carrier = db.get(Company, deal.carrier_company_id)
    vehicle = db.get(Vehicle, deal.vehicle_id) if deal.vehicle_id else None
    driver = db.get(Driver, deal.driver_id) if deal.driver_id else None
    return {
        "deal_number": deal.number,
        "order_number": order.number,
        "order_version": order.version,
        "client": {"id": str(client.id), "name": client.name, "bin": client.bin_iin},
        "carrier": {"id": str(carrier.id), "name": carrier.name, "bin": carrier.bin_iin},
        "price_minor": deal.price_minor,
        "currency": deal.currency,
        "payment_terms": order.payment_terms,
        "payment_delay_days": order.payment_delay_days,
        "vat_included": order.vat_included,
        "cargo": {"name": order.cargo_name, "type": order.cargo_type, "weight_kg": order.weight_kg,
                  "volume_m3": order.volume_m3, "places": order.places, "adr_class": order.adr_class},
        "route": [{"kind": p.kind, "city": p.city, "address": p.address} for p in order.points],
        "dates": {"load_from": order.load_from, "load_to": order.load_to, "unload_from": order.unload_from,
                  "unload_to": order.unload_to},
        "vehicle": {"id": str(vehicle.id), "plate": vehicle.plate} if vehicle else None,
        "driver": {"id": str(driver.id), "name": driver.full_name} if driver else None,
        "trailer": deal.trailer_plate,
        "downtime_terms": order.downtime_terms,
        "accepted_at": utcnow(),
    }


def _write_snapshot(db: Session, deal: Deal, payload: dict, *, reason: str, previous: DealSnapshot | None):
    data = json.dumps(payload, ensure_ascii=False, sort_keys=True, default=str)
    snap = DealSnapshot(deal_id=deal.id, version=(previous.version + 1) if previous else 1, data=data,
                        content_hash=sha256_hex(data), previous_id=previous.id if previous else None, reason=reason,
                        created_by=get_ctx().user_id)
    db.add(snap)
    db.flush()
    deal.snapshot_version = snap.version
    return snap


def latest_snapshot(db: Session, deal_id) -> DealSnapshot | None:
    return db.execute(select(DealSnapshot).where(DealSnapshot.deal_id == deal_id)
                      .order_by(DealSnapshot.version.desc())).scalars().first()


def create_deal_from_bid(db: Session, order: Order, bid: Bid) -> Deal:
    deal = Deal(order_id=order.id, bid_id=bid.id, number=next_number(db, "deal", "SD"),
                client_company_id=order.client_company_id, carrier_company_id=bid.carrier_company_id,
                price_minor=bid.price_minor, currency=bid.currency, vehicle_id=bid.vehicle_id, driver_id=bid.driver_id,
                created_by=get_ctx().user_id)
    db.add(deal)
    db.flush()
    flow.transition(db, order, flow.ASSIGNED, actor=flow.SYSTEM, reason=f"bid {bid.id} accepted")
    _write_snapshot(db, deal, snapshot_payload(db, deal, order), reason="acceptance", previous=None)
    score_risk(db, deal, order)
    check_executor_integrity(db, deal)
    generate_contract(db, deal, order)
    from app.modules.notifications.service import notify_event

    driver_user = _driver_user(db, deal)
    notify_event(db, "bid.accepted", params={"number": order.number}, link=f"/deals/{deal.id}",
                 client_company_id=deal.client_company_id, carrier_company_id=deal.carrier_company_id,
                 driver_user_id=driver_user, include_managers=deal.needs_manual_review, dedup=f"accepted:{deal.id}")
    return deal


def _driver_user(db: Session, deal: Deal):
    if not deal.driver_id:
        return None
    drv = db.get(Driver, deal.driver_id)
    return drv.user_id if drv else None


def generate_contract(db: Session, deal: Deal, order: Order):
    from app.modules.documents.service import generate

    client = db.get(Company, deal.client_company_id)
    carrier = db.get(Company, deal.carrier_company_id)
    vehicle = db.get(Vehicle, deal.vehicle_id) if deal.vehicle_id else None
    driver = db.get(Driver, deal.driver_id) if deal.driver_id else None
    route = " → ".join(f"{p.city}, {p.address}".strip(", ") for p in order.points)
    snap = latest_snapshot(db, deal.id)
    ctx = {
        "deal_number": deal.number, "order_number": order.number,
        "client_name": client.name, "client_bin": client.bin_iin, "client_address": client.legal_address,
        "carrier_name": carrier.name, "carrier_bin": carrier.bin_iin, "carrier_address": carrier.legal_address,
        "route": route, "cargo": order.cargo_name, "weight": order.weight_kg, "volume": order.volume_m3,
        "places": order.places, "price": format_money(deal.price_minor, deal.currency),
        "payment_terms": order.payment_terms, "load_date": order.load_from.strftime("%d.%m.%Y") if order.load_from else "",
        "unload_date": order.unload_to.strftime("%d.%m.%Y") if order.unload_to else "",
        "vehicle": vehicle.plate if vehicle else "—", "driver": driver.full_name if driver else "—",
        "snapshot_hash": snap.content_hash if snap else "",
    }
    return generate(db, "contract_order", ctx, deal_id=deal.id, company_id=deal.client_company_id,
                    locale=client.locale, requires_signatures=True)


def score_risk(db: Session, deal: Deal, order: Order) -> None:
    """FR-RAT-03: risk scoring at acceptance; high risk requires manual check before the trip."""
    carrier = db.get(Company, deal.carrier_company_id)
    score = 0
    reasons = []
    if carrier.verification_level < 2:
        score += 20
        reasons.append("low_verification")
    age_days = (utcnow() - carrier.created_at).days
    if age_days < 14:
        score += 25
        reasons.append("new_account")
    if order.desired_rate_minor and deal.price_minor < order.desired_rate_minor * 0.6:
        score += 25
        reasons.append("price_anomaly")
    if order.cargo_value_minor and order.cargo_value_minor > 50_000_000_00:
        score += 15
        reasons.append("high_value_cargo")
    deal.risk_score = min(score, 100)
    threshold = int(get_setting(db, "antifraud.risk_threshold", 50))
    if deal.risk_score >= threshold:
        deal.needs_manual_review = True
        raise_alert(db, "high_risk_deal", severity="high", company_id=carrier.id, deal_id=deal.id,
                    details={"score": deal.risk_score, "reasons": reasons})


def check_executor_integrity(db: Session, deal: Deal) -> None:
    """FR-DEAL-06, SEC-FRD-05: vehicle/driver of another company or reused in overlapping trips."""
    order = db.get(Order, deal.order_id)
    if deal.vehicle_id:
        v = db.get(Vehicle, deal.vehicle_id)
        if v and v.company_id != deal.carrier_company_id:
            deal.flagged = True
            raise_alert(db, "executor_foreign_vehicle", severity="high", deal_id=deal.id,
                        company_id=deal.carrier_company_id, details={"plate": v.plate})
        # same plate in another active deal of a different carrier (double brokering signal)
        same_plate = select(Vehicle.id).where(Vehicle.plate == (v.plate if v else ""))
        clash = db.execute(
            select(Deal).join(Order, Order.id == Deal.order_id)
            .where(Deal.id != deal.id, Deal.vehicle_id.in_(same_plate),
                   Order.status.in_((flow.ASSIGNED, flow.DOCS_SIGNED, flow.LOADING, flow.IN_TRANSIT)))
        ).scalars().all()
        for other in clash:
            o = db.get(Order, other.order_id)
            overlap = (o.load_from and order.unload_to and o.load_from <= order.unload_to) if o else False
            if other.carrier_company_id != deal.carrier_company_id or overlap:
                deal.flagged = True
                raise_alert(db, "vehicle_parallel_deals", severity="high", deal_id=deal.id,
                            company_id=deal.carrier_company_id, details={"other_deal": other.number})
    if deal.driver_id:
        d = db.get(Driver, deal.driver_id)
        if d and d.company_id != deal.carrier_company_id:
            deal.flagged = True
            raise_alert(db, "executor_foreign_driver", severity="high", deal_id=deal.id,
                        company_id=deal.carrier_company_id)


def on_document_signed(db: Session, deal: Deal) -> None:
    """Contract signed by both sides -> 'docs_signed'. FR-DEAL-05 criteria are computed here."""
    from app.modules.documents.models import Document
    from app.modules.documents.service import signatures

    order = flow.lock_order(db, deal.order_id)
    contract = db.execute(select(Document).where(Document.deal_id == deal.id, Document.doc_type == "contract_order")
                          .order_by(Document.created_at.desc())).scalars().first()
    if contract is None:
        return
    signed_by = {s.company_id for s in signatures(db, contract.id)}
    if {deal.client_company_id, deal.carrier_company_id} <= signed_by:
        contract.status = "signed"
        if order.status == flow.ASSIGNED:
            if deal.needs_manual_review:
                return  # FR-RAT-03: a manager must clear the deal before the trip starts
            flow.transition(db, order, flow.DOCS_SIGNED, actor=flow.SYSTEM, reason="contract signed by both sides")
        # FR-DEAL-05: formalized via AbdEX = accepted bid on platform + snapshot + contract signed by both
        deal.formalized_via_platform = latest_snapshot(db, deal.id) is not None
        webhooks.enqueue(db, (deal.client_company_id, deal.carrier_company_id), "deal.document_signed",
                         {"deal_id": str(deal.id), "deal_number": deal.number, "document": contract.number})
    elif contract.status == "required":
        contract.status = "uploaded"


def clear_manual_review(db: Session, deal: Deal, note: str) -> None:
    deal.needs_manual_review = False
    audit(db, "deal.risk_cleared", object_type="deal", object_id=deal.id, reason=note)
    on_document_signed(db, deal)


# --------------------------------------------------------------------- supplements (FR-DEAL-02)


SUPPLEMENT_FIELDS = ("price", "unload_to", "load_from")


def propose_supplement(db: Session, acc: DealAccess, form: dict) -> Supplement:
    if acc.order.status in flow.FINAL or acc.order.status == flow.DISPUTE:
        raise Conflict("deal_closed")
    changes = {}
    if form.get("price"):
        try:
            changes["price_minor"] = to_minor(form["price"], acc.deal.currency)
        except ValueError:
            raise ValidationFailed({"price": "error.number"})
    if form.get("trailer_plate"):
        changes["trailer_plate"] = form["trailer_plate"].strip().upper()[:20]
    if not changes:
        raise ValidationFailed({"price": "error.required"})
    sup = Supplement(deal_id=acc.deal.id, initiator_company_id=get_ctx().company_id,
                     changes=json.dumps(changes), reason=(form.get("reason") or "")[:500],
                     created_by=get_ctx().user_id)
    db.add(sup)
    db.flush()
    audit(db, "deal.supplement_proposed", object_type="deal", object_id=acc.deal.id, details=changes)
    _system_message(db, acc.deal.id, "sys.supplement_proposed")
    return sup


def decide_supplement(db: Session, acc: DealAccess, sup: Supplement, accept: bool) -> None:
    if sup.deal_id != acc.deal.id or sup.status != "proposed":
        raise NotFound()
    if sup.initiator_company_id == get_ctx().company_id:
        raise Forbidden("cannot_accept_own")  # the OTHER side must accept
    sup.status = "accepted" if accept else "rejected"
    sup.decided_by = get_ctx().user_id
    sup.decided_at = utcnow()
    if accept:
        changes = json.loads(sup.changes)
        if "price_minor" in changes:
            acc.deal.price_minor = changes["price_minor"]
        if "trailer_plate" in changes:
            acc.deal.trailer_plate = changes["trailer_plate"]
        prev = latest_snapshot(db, acc.deal.id)
        payload = json.loads(prev.data) if prev else {}
        payload.update({"price_minor": acc.deal.price_minor, "trailer": acc.deal.trailer_plate,
                        "supplement_id": str(sup.id), "accepted_at": utcnow()})
        _write_snapshot(db, acc.deal, payload, reason=f"supplement {sup.id}", previous=prev)
        from app.modules.notifications.service import notify_event

        notify_event(db, "deal.terms_changed", params={"number": acc.deal.number}, link=f"/deals/{acc.deal.id}",
                     client_company_id=acc.deal.client_company_id, carrier_company_id=acc.deal.carrier_company_id,
                     driver_user_id=_driver_user(db, acc.deal), include_managers=True, dedup=f"sup:{sup.id}")
    audit(db, "deal.supplement_decided", object_type="deal", object_id=acc.deal.id, details={"accept": accept})
    _system_message(db, acc.deal.id, "sys.supplement_accepted" if accept else "sys.supplement_rejected")


# --------------------------------------------------------------------- executor change (FR-DEAL-03)


def propose_executor_change(db: Session, acc: DealAccess, vehicle_id, driver_id, reason: str) -> ExecutorChange:
    if acc.side != "carrier":
        raise Forbidden()
    if not reason.strip():
        raise ValidationFailed({"reason": "error.reason_required"})
    v = db.get(Vehicle, vehicle_id) if vehicle_id else None
    d = db.get(Driver, driver_id) if driver_id else None
    if (vehicle_id and v is None) or (driver_id and d is None):
        raise ValidationFailed({"vehicle_id": "error.invalid_choice"})
    from app.modules.fleet.schedule import ensure_free

    ensure_free(db, acc.order, vehicle_id=v.id if v else None, driver_id=d.id if d else None,
                exclude_deal_id=acc.deal.id)  # FR-PLAN-04
    ch = ExecutorChange(deal_id=acc.deal.id, old_vehicle_id=acc.deal.vehicle_id, new_vehicle_id=v.id if v else None,
                        old_driver_id=acc.deal.driver_id, new_driver_id=d.id if d else None, reason=reason[:500],
                        created_by=get_ctx().user_id)
    db.add(ch)
    db.flush()
    _system_message(db, acc.deal.id, "sys.executor_change_proposed")
    from app.modules.notifications.service import notify_event

    notify_event(db, "deal.executor_changed", params={"number": acc.deal.number}, link=f"/deals/{acc.deal.id}",
                 client_company_id=acc.deal.client_company_id, include_managers=True, dedup=f"exch:{ch.id}")
    return ch


def decide_executor_change(db: Session, acc: DealAccess, ch: ExecutorChange, accept: bool) -> None:
    if acc.side != "client" or ch.deal_id != acc.deal.id or ch.status != "proposed":
        raise NotFound()
    ch.status = "confirmed" if accept else "rejected"
    ch.decided_by = get_ctx().user_id
    ch.decided_at = utcnow()
    if accept:
        if ch.new_vehicle_id:
            acc.deal.vehicle_id = ch.new_vehicle_id
        if ch.new_driver_id:
            acc.deal.driver_id = ch.new_driver_id
        prev = latest_snapshot(db, acc.deal.id)
        _write_snapshot(db, acc.deal, snapshot_payload(db, acc.deal, acc.order), reason=f"executor change {ch.id}",
                        previous=prev)
        check_executor_integrity(db, acc.deal)
    audit(db, "deal.executor_change_decided", object_type="deal", object_id=acc.deal.id, details={"accept": accept})
    _system_message(db, acc.deal.id, "sys.executor_changed" if accept else "sys.executor_change_rejected")


# --------------------------------------------------------------------- trip (M11)


def add_checkpoint(db: Session, acc: DealAccess, kind: str, *, lat=None, lng=None, photo_file_id=None, note: str = "",
                   offline_id: str = "", happened_at=None) -> Checkpoint:
    if acc.side not in ("driver", "carrier"):
        raise Forbidden()
    if kind not in CHECKPOINTS:
        raise ValidationFailed({"kind": "error.invalid_choice"})
    offline_id = (offline_id or f"{kind}:{utcnow().timestamp()}")[:64]
    dup = db.execute(select(Checkpoint).where(Checkpoint.deal_id == acc.deal.id, Checkpoint.offline_id == offline_id)
                     ).scalar_one_or_none()
    if dup:
        return dup  # FR-TRK-07: offline sync without duplicates
    order = flow.lock_order(db, acc.deal.order_id)
    target = CHECKPOINT_TRANSITIONS.get(kind)
    if target and not flow.can(order.status, target, flow.DRIVER):
        raise AppError("checkpoint_out_of_order", status_code=409)
    # FR-TRK-03: geo is stored only with explicit consent and only during the trip
    if not acc.deal.geo_consent:
        lat = lng = None
    cp = Checkpoint(deal_id=acc.deal.id, kind=kind, happened_at=happened_at or utcnow(), lat=lat, lng=lng,
                    photo_file_id=photo_file_id, note=note[:300], offline_id=offline_id,
                    created_by=get_ctx().user_id)
    db.add(cp)
    db.flush()
    if target:
        flow.transition(db, order, target, actor=flow.DRIVER, reason=f"checkpoint {kind}")
    if kind == "unloaded":
        acc.deal.geo_consent = False  # stop geo sharing automatically after the trip
        rating.on_unloaded_late(db, acc.deal, order)
    from app.modules.notifications.service import notify_event

    webhooks.enqueue(db, (acc.deal.client_company_id, acc.deal.carrier_company_id), "deal.checkpoint",
                     {"deal_id": str(acc.deal.id), "deal_number": acc.deal.number, "kind": kind,
                      "at": cp.happened_at.isoformat()})
    notify_event(db, "trip.checkpoint", params={"number": acc.deal.number, "kind": kind},
                 link=f"/deals/{acc.deal.id}", client_company_id=acc.deal.client_company_id,
                 carrier_company_id=acc.deal.carrier_company_id, dedup=f"cp:{cp.id}")
    return cp


def checkpoints(db: Session, deal_id) -> list[Checkpoint]:
    return list(db.execute(select(Checkpoint).where(Checkpoint.deal_id == deal_id).order_by(Checkpoint.happened_at))
                .scalars())


def report_incident(db: Session, acc: DealAccess, kind: str, description: str) -> Incident:
    if not description.strip():
        raise ValidationFailed({"description": "error.required"})
    inc = Incident(deal_id=acc.deal.id, kind=kind, description=description[:2000],
                   reporter_company_id=get_ctx().company_id, created_by=get_ctx().user_id)
    db.add(inc)
    _system_message(db, acc.deal.id, "sys.incident", kind=kind)
    return inc


def try_close_by_documents(db: Session, acc: DealAccess) -> bool:
    """Unloaded -> closed_docs once a closing document is uploaded; then billing."""
    from app.modules.documents.models import Document
    from app.modules.documents.service import CLOSING_DOC_TYPES

    order = flow.lock_order(db, acc.deal.order_id)
    if order.status != flow.UNLOADED:
        return False
    has_closing = db.execute(select(Document.id).where(Document.deal_id == acc.deal.id,
                                                       Document.doc_type.in_(CLOSING_DOC_TYPES),
                                                       Document.status != "rejected")).first()
    if not has_closing:
        return False
    flow.transition(db, order, flow.CLOSED_DOCS, actor=flow.SYSTEM, reason="closing documents uploaded")
    return True


# --------------------------------------------------------------------- disputes (FR-SUP-03, FR-FLOW-05)


def open_dispute(db: Session, acc: DealAccess, subject: str, description: str) -> Dispute:
    if acc.side not in ("client", "carrier"):
        raise Forbidden()
    order = flow.lock_order(db, acc.deal.order_id)
    prev = order.status
    actor = flow.CLIENT if acc.side == "client" else flow.CARRIER
    flow.transition(db, order, flow.DISPUTE, actor=actor, reason=f"{subject}: {description}"[:500])
    d = Dispute(deal_id=acc.deal.id, opened_by_company_id=get_ctx().company_id, subject=subject,
                description=description[:4000], previous_status=prev, created_by=get_ctx().user_id)
    if acc.side == "client":
        d.client_position = description[:4000]
    else:
        d.carrier_position = description[:4000]
    db.add(d)
    db.flush()
    from app.modules.notifications.service import notify_event

    notify_event(db, "dispute.opened", params={"number": acc.deal.number}, link=f"/deals/{acc.deal.id}",
                 client_company_id=acc.deal.client_company_id, carrier_company_id=acc.deal.carrier_company_id,
                 include_managers=True, dedup=f"dispute:{d.id}")
    return d


def add_dispute_position(db: Session, acc: DealAccess, dispute: Dispute, text: str) -> None:
    if dispute.status != "open":
        raise Conflict("dispute_closed")
    if acc.side == "client":
        dispute.client_position = text[:4000]
    elif acc.side == "carrier":
        dispute.carrier_position = text[:4000]
    else:
        raise Forbidden()


FAULTS = ("none", "carrier", "client")


def resolve_dispute(db: Session, dispute: Dispute, *, outcome: str, resolution: str, manager: User,
                    fault: str = "none") -> None:
    if dispute.status != "open":
        raise Conflict("dispute_closed")
    if outcome not in (flow.CLOSED_DOCS, flow.CANCELLED):
        raise ValidationFailed({"outcome": "error.invalid_choice"})
    if fault not in FAULTS:
        raise ValidationFailed({"fault": "error.invalid_choice"})
    deal = db.get(Deal, dispute.deal_id)
    order = flow.lock_order(db, deal.order_id)
    flow.transition(db, order, outcome, actor=flow.MANAGER, reason=resolution, user_id=manager.id)
    dispute.status = "resolved"
    dispute.outcome = outcome
    dispute.resolution = resolution[:4000]
    dispute.resolved_by = manager.id
    dispute.resolved_at = utcnow()
    dispute.fault = fault
    rating.on_dispute_resolved(db, deal, outcome=outcome, fault=fault)
    audit(db, "dispute.resolved", object_type="dispute", object_id=dispute.id,
          details={"outcome": outcome, "fault": fault})


def open_dispute_for(db: Session, deal_id) -> Dispute | None:
    return db.execute(select(Dispute).where(Dispute.deal_id == deal_id).order_by(Dispute.created_at.desc())
                      ).scalars().first()


# --------------------------------------------------------------------- rating (FR-DEAL-07)


def rate(db: Session, acc: DealAccess, form: dict) -> Rating:
    if acc.side not in ("client", "carrier") or acc.order.status not in (flow.COMPLETED, flow.CLOSED_DOCS,
                                                                       flow.FEE_INVOICED):
        raise Conflict("rating_not_available")
    me = get_ctx().company_id
    other = acc.deal.carrier_company_id if acc.side == "client" else acc.deal.client_company_id

    def score(k):
        try:
            v = int(form.get(k, 5))
        except ValueError:
            v = 5
        return min(5, max(1, v))

    existing = db.execute(select(Rating).where(Rating.deal_id == acc.deal.id, Rating.from_company_id == me)
                          ).scalar_one_or_none()
    if existing:
        raise Conflict("already_rated")
    r = Rating(deal_id=acc.deal.id, from_company_id=me, to_company_id=other, score=score("score"),
               punctuality=score("punctuality"), vehicle_condition=score("vehicle_condition"),
               documents_quality=score("documents_quality"), communication=score("communication"),
               payment_discipline=score("payment_discipline"), comment=(form.get("comment") or "")[:1000],
               created_by=get_ctx().user_id)
    db.add(r)
    return r


# --------------------------------------------------------------------- lists & dossier


def deals_for_company(db: Session, company_id, *, active_only: bool = False) -> list[tuple[Deal, Order]]:
    stmt = select(Deal, Order).join(Order, Order.id == Deal.order_id).where(
        or_(Deal.client_company_id == company_id, Deal.carrier_company_id == company_id))
    if active_only:
        stmt = stmt.where(Order.status.notin_(flow.FINAL))
    return list(db.execute(stmt.order_by(Deal.created_at.desc()).limit(200)).all())


def deals_for_driver(db: Session, user_id) -> list[tuple[Deal, Order]]:
    drivers = select(Driver.id).where(Driver.user_id == user_id)
    return list(db.execute(select(Deal, Order).join(Order, Order.id == Deal.order_id)
                           .where(Deal.driver_id.in_(drivers)).order_by(Deal.created_at.desc()).limit(100)).all())


def history(db: Session, order_id) -> list[StatusHistory]:
    return list(db.execute(select(StatusHistory).where(StatusHistory.order_id == order_id)
                           .order_by(StatusHistory.created_at)).scalars())


def dossier_zip(db: Session, acc: DealAccess) -> bytes:
    """FR-FLOW-06: everything about a deal in one action — PDF summary + attachments (ZIP)."""
    from app.modules.chat.service import thread_messages
    from app.modules.documents.service import deal_documents, render_pdf
    from app.core.storage import storage
    from app.modules.documents.models import StoredFile

    lines = [f"Сделка {acc.deal.number} / заявка {acc.order.number}", ""]
    lines.append("## Снапшоты условий")
    for s in db.execute(select(DealSnapshot).where(DealSnapshot.deal_id == acc.deal.id)
                        .order_by(DealSnapshot.version)).scalars():
        lines.append(f"v{s.version} · {s.created_at:%d.%m.%Y %H:%M} UTC · {s.reason} · sha256 {s.content_hash}")
    lines += ["", "## История статусов"]
    for h in history(db, acc.order.id):
        lines.append(f"{h.created_at:%d.%m.%Y %H:%M} UTC · {h.from_status} → {h.to_status} · {h.actor_role} · "
                     f"IP {h.ip or '—'} · {h.reason}")
    lines += ["", "## Чек-поинты"]
    for c in checkpoints(db, acc.deal.id):
        lines.append(f"{c.happened_at:%d.%m.%Y %H:%M} UTC · {c.kind} · {c.lat or '—'}, {c.lng or '—'}")
    lines += ["", "## Переписка"]
    for m in thread_messages(db, deal_id=acc.deal.id, include_hidden=True):
        lines.append(f"{m.created_at:%d.%m.%Y %H:%M} UTC · {m.kind} · {m.body}")
    summary = render_pdf(f"Досье сделки {acc.deal.number}", "\n".join(lines))
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("dossier.pdf", summary)
        snaps = [json.loads(s.data) for s in db.execute(select(DealSnapshot).where(DealSnapshot.deal_id == acc.deal.id)
                                                         ).scalars()]
        z.writestr("snapshots.json", json.dumps(snaps, ensure_ascii=False, indent=2, default=str))
        inventory = []
        for doc in deal_documents(db, acc.deal.id):
            if not doc.file_id:
                continue
            f = db.get(StoredFile, doc.file_id)
            ext = {"application/pdf": "pdf", "image/jpeg": "jpg", "image/png": "png"}.get(f.content_type, "bin")
            name = f"documents/{doc.doc_type}-{doc.number}.{ext}"
            z.writestr(name, storage.get(f.storage_key))
            inventory.append(f"{name}\t{doc.status}\tsha256={f.sha256}")
        z.writestr("inventory.txt", "\n".join(inventory))
    audit(db, "deal.dossier_exported", object_type="deal", object_id=acc.deal.id)
    return buf.getvalue()


def _system_message(db: Session, deal_id, key: str, **params) -> None:
    from app.modules.chat.service import post_system

    post_system(db, deal_id=deal_id, key=key, **params)


def assigned_deals_for_vehicle(db: Session, vehicle_id) -> list:
    return list(db.execute(select(Deal).join(Order, Order.id == Deal.order_id).where(
        and_(Deal.vehicle_id == vehicle_id, Order.status.notin_(flow.FINAL)))).scalars())
