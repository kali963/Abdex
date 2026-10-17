"""Repeated identity check of a driver on suspicious signs (FR-KYC-09).

Signs (thresholds in the setting ``kyc.reverify``):
* new device — the driver signs in from a device never seen for this account;
* anomalous geography — a trip checkpoint far from every point of the route;
* long break — the driver is put on a deal after a long time without trips.

A sign sets ``driver.reverify_reason``: an alert goes to the antifraud queue, the driver is asked to pass the
biometric check again (FR-KYC-08) and, until it is passed, cannot be put on a new deal or mark checkpoints
(``block_trips``). A passed check clears the flag.
"""
from __future__ import annotations

from datetime import timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.audit import audit
from app.core.errors import Conflict
from app.db import utcnow
from app.modules.fleet.models import Driver

DEFAULTS = {"new_device": True, "geo_km": 300, "break_days": 90, "block_trips": True}


def settings_(db: Session) -> dict:
    from app.modules.platform.service import get_setting

    value = get_setting(db, "kyc.reverify", None)
    return {**DEFAULTS, **(value if isinstance(value, dict) else {})}


def flag(db: Session, driver: Driver, reason: str, details: dict | None = None) -> bool:
    from app.modules.notifications.service import notify_company_owners, notify_user
    from app.modules.platform.service import raise_alert

    if driver.reverify_reason:
        return False
    driver.reverify_reason, driver.reverify_since = reason, utcnow()
    audit(db, "kyc.reverify_required", object_type="driver", object_id=driver.id, role="system",
          details={"reason": reason, **(details or {})})
    raise_alert(db, "driver_reverify", company_id=driver.company_id,
                details={"driver": str(driver.id), "reason": reason, **(details or {})})
    if driver.user_id:
        notify_user(db, driver.user_id, "kyc.reverify_required", {"reason": reason}, link="/trips/biometrics",
                    critical=True)
    if driver.company_id:
        notify_company_owners(db, driver.company_id, "kyc.reverify_driver", {"driver": driver.full_name},
                              link="/fleet")
    return True


def ensure_allowed(db: Session, driver_id) -> None:
    """Called before a driver is put on a deal or marks a checkpoint."""
    if not driver_id:
        return
    driver = db.get(Driver, driver_id)
    if driver is not None and driver.reverify_reason and settings_(db)["block_trips"]:
        raise Conflict("driver_reverify_required")


# ------------------------------------------------------------------ signs


def on_login(db: Session, user_id, device_id: str) -> None:
    """New device: the account already has device marks and none of them is this device."""
    from app.modules.platform.models import DeviceEvent

    if not device_id or not settings_(db)["new_device"]:
        return
    driver = db.execute(select(Driver).where(Driver.user_id == user_id, Driver.is_deleted.is_(False))).scalars().first()
    if driver is None:
        return
    seen = db.execute(select(func.count(DeviceEvent.id)).where(DeviceEvent.user_id == user_id,
                                                               DeviceEvent.device_id == device_id)).scalar_one()
    others = db.execute(select(func.count(DeviceEvent.id)).where(DeviceEvent.user_id == user_id,
                                                                 DeviceEvent.device_id != device_id,
                                                                 DeviceEvent.device_id != "")).scalar_one()
    if others and seen <= 1:  # the event of this very login is already recorded
        flag(db, driver, "new_device")


def on_checkpoint(db: Session, deal, order, lat, lng) -> None:
    from app.modules.integrations.adapters import CITY_COORDS, _haversine

    if lat is None or lng is None or not deal.driver_id:
        return
    limit = float(settings_(db)["geo_km"] or 0)
    points = [CITY_COORDS.get((p.city or "").strip().lower()) for p in order.points]
    points = [p for p in points if p]
    if not limit or not points:
        return
    nearest = min(_haversine((float(lat), float(lng)), p) for p in points)
    # a straight segment between consecutive points is a fair corridor for the anomaly check
    if len(points) >= 2:
        nearest = min(nearest, *(_segment_distance((float(lat), float(lng)), a, b) for a, b in zip(points, points[1:], strict=False)))
    if nearest > limit:
        flag(db, db.get(Driver, deal.driver_id), "geo_anomaly", {"km": int(nearest), "deal": deal.number})


def _segment_distance(p, a, b) -> float:
    """Approximate distance (km) from point p to segment a–b on a small-scale plane."""
    from app.modules.integrations.adapters import _haversine

    best = min(_haversine(p, a), _haversine(p, b))
    for i in range(1, 20):
        t = i / 20
        q = (a[0] + (b[0] - a[0]) * t, a[1] + (b[1] - a[1]) * t)
        best = min(best, _haversine(p, q))
    return best


def on_assignment(db: Session, driver_id) -> None:
    """Long break: the previous deal of the driver is older than the threshold."""
    from app.modules.deals.models import Deal

    if not driver_id:
        return
    days = int(settings_(db)["break_days"] or 0)
    if not days:
        return
    last = db.execute(select(func.max(Deal.created_at)).where(Deal.driver_id == driver_id)).scalar_one()
    if last is not None and last < utcnow() - timedelta(days=days):
        flag(db, db.get(Driver, driver_id), "long_break", {"days": (utcnow() - last).days})
