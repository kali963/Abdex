"""Telematics adapter (FR-TRK-05): GPS systems of carriers' fleets feed positions into the trip map.

Two ways in, one rule for storing:
* push — the carrier's system calls ``POST /api/v1/telematics/positions`` with an API key (scope
  ``telematics:write``): ``{"positions": [{"plate", "lat", "lng", "at", "speed"}]}``;
* pull — the platform polls the carrier's system every few minutes (``TelematicsConnection``): ``GET <url>`` with
  ``Authorization: Bearer <token>`` answering the same list. Wialon, Omnicomm and the like are mapped to this
  contract by a thin gateway or by replacing ``PullAdapter._fetch``.

A position is kept only when the vehicle is on a deal of that carrier that is loading or on the way and has the
geodata consent (FR-TRK-03); everything else is dropped on arrival. Positions older than 48 hours or from the
future are refused; the same timestamp twice is stored once.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.core.audit import audit
from app.core.errors import ValidationFailed
from app.db import utcnow
from app.modules.deals.models import Deal, TelematicsConnection, TrackPoint
from app.modules.fleet.models import Vehicle
from app.modules.integrations.base import Adapter, IntegrationUnavailable
from app.modules.orders import flow
from app.modules.orders.models import Order

MAX_BATCH = 500
WINDOW = timedelta(hours=48)
ON_THE_WAY = (flow.LOADING, flow.IN_TRANSIT)


def _parse(p: dict) -> dict | None:
    try:
        lat, lng = float(p["lat"]), float(p["lng"])
        at = datetime.fromisoformat(str(p["at"]).replace("Z", "+00:00"))
        if at.tzinfo is None or not (-90 <= lat <= 90 and -180 <= lng <= 180):
            return None
        return {"plate": str(p["plate"]).replace(" ", "").upper()[:20], "lat": lat, "lng": lng, "at": at,
                "speed": max(0, min(int(float(p.get("speed") or 0)), 300))}
    except (KeyError, TypeError, ValueError):
        return None


def ingest(db: Session, company_id, positions: list, *, source: str = "api", store: bool = True) -> dict:
    if not isinstance(positions, list) or len(positions) > MAX_BATCH:
        raise ValidationFailed({"positions": "error.invalid_value"})
    now = utcnow()
    accepted = ignored = 0
    vehicles = {v.plate: v for v in db.execute(select(Vehicle).where(Vehicle.company_id == company_id,
                                                                     Vehicle.is_deleted.is_(False))).scalars()}
    deal_cache: dict = {}
    for raw in positions:
        p = _parse(raw) if isinstance(raw, dict) else None
        v = vehicles.get(p["plate"]) if p else None
        if p is None or v is None or not (now - WINDOW <= p["at"] <= now + timedelta(minutes=5)):
            ignored += 1
            continue
        if v.id not in deal_cache:
            deal_cache[v.id] = db.execute(
                select(Deal).join(Order, Order.id == Deal.order_id)
                .where(Deal.vehicle_id == v.id, Deal.carrier_company_id == company_id,
                       Order.status.in_(ON_THE_WAY), Deal.geo_consent.is_(True))).scalars().first()
        deal = deal_cache[v.id]
        if deal is None:  # not on a trip with consent: the position is not kept (FR-TRK-03)
            ignored += 1
            continue
        if store:
            try:
                with db.begin_nested():
                    db.add(TrackPoint(deal_id=deal.id, vehicle_id=v.id, at=p["at"], lat=p["lat"], lng=p["lng"],
                                      speed_kmh=p["speed"], source=source))
                    db.flush()
            except IntegrityError:
                ignored += 1
                continue
        accepted += 1
    return {"accepted": accepted, "ignored": ignored}


def points_for(db: Session, deal_id, limit: int = 500) -> list[TrackPoint]:
    rows = list(db.execute(select(TrackPoint).where(TrackPoint.deal_id == deal_id)
                           .order_by(TrackPoint.at.desc()).limit(limit)).scalars())
    return list(reversed(rows))


# ------------------------------------------------------------------ pull


class PullAdapter(Adapter):
    name = "telematics"
    personal_data = True  # a vehicle on a trip is where its driver is: registered in the processing register
    provider = "https-json"
    timeout = 10.0
    retries = 1

    def fetch(self, conn: TelematicsConnection) -> list:
        return self.call("positions", lambda: self._fetch(conn), summary=str(conn.company_id))

    def _fetch(self, conn: TelematicsConnection) -> list:
        from app.modules.webhooks.service import safe_get_json

        # https to a public address only, pinned, no redirects (SSRF): the URL is set by a customer
        data = safe_get_json(conn.url, {"Authorization": f"Bearer {conn.token}", "Accept": "application/json"})
        return data.get("positions", data) if isinstance(data, dict) else data


pull_adapter = PullAdapter()


def save_connection(db: Session, company, url: str, token: str, active: bool) -> TelematicsConnection:
    from app.modules.webhooks.service import validate_url

    url = validate_url(url.strip())
    conn = db.execute(select(TelematicsConnection).where(TelematicsConnection.company_id == company.id)
                      ).scalar_one_or_none()
    if conn is None:
        conn = TelematicsConnection(company_id=company.id, url=url)
        db.add(conn)
    conn.url, conn.active = url, active
    if token:
        conn.token = token[:500]
    db.flush()
    audit(db, "telematics.connection_saved", object_type="company", object_id=company.id, details={"active": active})
    return conn


def pull_all(db: Session) -> int:
    """Worker job: poll every active connection."""
    from app.core import rls

    total = 0
    with rls.system(db):
        for conn in db.execute(select(TelematicsConnection).where(TelematicsConnection.active.is_(True))).scalars().all():
            try:
                res = ingest(db, conn.company_id, list(pull_adapter.fetch(conn))[:MAX_BATCH], source="pull")
                conn.last_error, total = "", total + res["accepted"]
            except (IntegrationUnavailable, ValidationFailed, ValueError, RuntimeError, OSError) as exc:
                conn.last_error = str(exc)[:300] or "error"
            conn.last_sync_at = utcnow()
    db.commit()
    return total
