"""Trip map for the client (FR-TRK-04): planned route, travelled track, current position and ETA.

The map is drawn as a server-side SVG (no third-party tiles or scripts, so the strict CSP stays intact and no
location data leaves the platform). Positions come only from checkpoints sent with the driver's consent
(FR-TRK-03). City coordinates come from the routing adapter's reference table; a real geocoder replaces it
together with the adapter (INT-MAP-01).
"""
from __future__ import annotations

from datetime import datetime, timedelta

from app.db import utcnow
from app.modules.integrations.adapters import CITY_COORDS, _haversine
from app.modules.orders import flow

AVG_SPEED_KMH = 60
ROAD_FACTOR = 1.25
W, H, PAD = 640, 360, 36


def _city(name: str | None):
    return CITY_COORDS.get((name or "").strip().lower())


def _project(points: list[tuple[float, float]]):
    lats = [p[0] for p in points]
    lngs = [p[1] for p in points]
    lat_min, lat_max, lng_min, lng_max = min(lats), max(lats), min(lngs), max(lngs)
    span_lat = max(lat_max - lat_min, 0.5)
    span_lng = max(lng_max - lng_min, 0.5)
    scale = min((W - 2 * PAD) / span_lng, (H - 2 * PAD) / span_lat)
    off_x = (W - span_lng * scale) / 2
    off_y = (H - span_lat * scale) / 2

    def xy(p):
        return round(off_x + (p[1] - lng_min) * scale, 1), round(H - (off_y + (p[0] - lat_min) * scale), 1)

    return xy


def trip_map(deal, order, checkpoints) -> dict | None:
    stops = [(p.city, _city(p.city)) for p in order.points]
    planned = [c for _, c in stops if c]
    track = [(c.lat, c.lng, c) for c in checkpoints if c.lat is not None and c.lng is not None]
    if len(planned) < 2 and not track:
        return None
    all_pts = planned + [(t[0], t[1]) for t in track]
    xy = _project(all_pts)
    current = track[-1] if track else None
    destination = planned[-1] if planned else None
    eta: datetime | None = None
    remaining_km = None
    if order.status in (flow.LOADING, flow.IN_TRANSIT) and destination:
        if current:
            remaining_km = round(_haversine((current[0], current[1]), destination) * ROAD_FACTOR)
            eta = current[2].happened_at + timedelta(hours=remaining_km / AVG_SPEED_KMH)
        elif order.distance_km:
            departed = next((c.happened_at for c in checkpoints if c.kind == "departed"), None)
            if departed:
                eta = departed + timedelta(hours=order.distance_km / AVG_SPEED_KMH)
    late = bool(eta and order.unload_to and eta > order.unload_to)
    return {
        "w": W, "h": H,
        "planned": " ".join(f"{x},{y}" for x, y in map(xy, planned)),
        "track": " ".join(f"{x},{y}" for x, y in (xy((t[0], t[1])) for t in track)),
        "stops": [{"name": name, "xy": xy(c), "first": i == 0, "last": i == len(stops) - 1}
                  for i, (name, c) in enumerate(stops) if c],
        "points": [{"xy": xy((t[0], t[1])), "kind": t[2].kind, "at": t[2].happened_at} for t in track],
        "current": xy((current[0], current[1])) if current else None,
        "current_at": current[2].happened_at if current else None,
        "eta": eta, "late": late, "remaining_km": remaining_km,
        "stale": bool(current and utcnow() - current[2].happened_at > timedelta(hours=6)),
        "unknown": [name for name, c in stops if not c],
    }
