"""SEC-AZ-03: default deny — every endpoint either is explicitly public or declares an access policy."""
from __future__ import annotations

from fastapi.routing import APIRoute

from app.main import app

PUBLIC = {
    "/", "/lang/{code}", "/login", "/register", "/forgot-password", "/reset-password", "/invite/{raw}",
    "/legal/{page}", "/help", "/manifest.webmanifest", "/sw.js", "/healthz", "/dev/outbox", "/logout",
    "/hooks/telegram",  # authenticated by Telegram's secret token header, not by a session
    "/metrics",  # bearer token from METRICS_TOKEN, 404 without it
    "/hooks/payments",  # HMAC signature of the payment provider
}
POLICY_DEPS = {"get_principal", "api_caller"}


def _dep_names(dependant) -> set[str]:
    names = set()
    for d in dependant.dependencies:
        fn = d.call
        names.add(getattr(fn, "__name__", ""))
        names |= _dep_names(d)
    return names


def test_every_route_has_access_policy():
    missing = []
    for route in app.routes:
        if not isinstance(route, APIRoute) or route.path in PUBLIC:
            continue
        names = _dep_names(route.dependant)
        if not (names & POLICY_DEPS or any(n.startswith("require_") for n in names)):
            missing.append(f"{sorted(route.methods)} {route.path}")
    assert not missing, "routes without access policy: " + ", ".join(missing)


def test_state_changing_routes_have_csrf():
    for route in app.routes:
        if isinstance(route, APIRoute) and route.methods & {"POST", "PUT", "PATCH", "DELETE"} and not route.path.startswith("/hooks/"):
            assert "csrf_protect" in _dep_names(route.dependant), route.path
