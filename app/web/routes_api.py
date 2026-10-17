"""Public REST API v1 (NFR-API-01..08, FR-API-01..04).

- version in path, OpenAPI generated from code (/api/v1/openapi.json, docs at /api/docs)
- unified error format, request id in every response
- idempotency keys for creating operations
- cursor pagination with server-side page size limit
- strict schemas: unknown fields are rejected (no mass assignment)
- money = integer minor units + currency; timestamps = ISO 8601 with timezone
- auth: company API key (X-API-Key) with scopes, expiry, revocation; or the browser session
- FR-API-05: test keys (abxtest_…) work against the sandbox with test data; public docs at /developers
"""
from __future__ import annotations

import hmac
from datetime import datetime, timedelta
from typing import Literal

from fastapi import APIRouter, Depends, Header, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core import ratelimit
from app.core.audit import audit
from app.core.context import get_ctx
from app.core.errors import AppError, Forbidden, NotFound
from app.core.money import from_minor
from app.core.security import hash_token, token
from app.db import get_db, utcnow
from app.modules.accounts.models import Company
from app.modules.accounts.permissions import company_can
from app.modules.bids import service as bids
from app.modules.orders import service as orders
from app.modules.orders.models import Order
from app.modules.platform import sandbox
from app.modules.platform.models import ApiKey
from app.modules.platform.service import dictionary, idempotent_lookup, idempotent_store
from app.web.deps import Principal, csrf_protect, get_principal_optional, parse_uuid, redirect, render, require

router = APIRouter(prefix="/api/v1", tags=["v1"], dependencies=[Depends(csrf_protect)])
html = APIRouter(dependencies=[Depends(csrf_protect)])

MAX_PAGE = 100
SCOPES = ("orders:read", "orders:write", "market:read", "bids:write", "dictionaries:read", "telematics:write")


class ApiCaller(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    company: Company
    user_id: object | None = None
    scopes: tuple[str, ...]
    role: str | None = None
    sandbox: bool = False


KEY_PREFIX = {"live": "abx", "test": "abxtest"}


def api_caller(request: Request, db: Session = Depends(get_db), x_api_key: str | None = Header(default=None),
               principal: Principal | None = Depends(get_principal_optional)) -> ApiCaller:
    ip = get_ctx().ip or "local"
    if x_api_key:
        parts = x_api_key.split("_")
        if len(parts) != 3 or parts[0] not in KEY_PREFIX.values():
            raise AppError("unauthorized", status_code=401)
        sandbox = parts[0] == KEY_PREFIX["test"]
        ratelimit.hit("api_sandbox" if sandbox else "api", f"key:{parts[1]}")
        key = db.execute(select(ApiKey).where(ApiKey.prefix == parts[1])).scalar_one_or_none()
        if (key is None or not hmac.compare_digest(key.key_hash, hash_token(x_api_key)) or key.revoked_at
                or (key.expires_at and key.expires_at < utcnow()) or KEY_PREFIX.get(key.environment) != parts[0]):
            raise AppError("unauthorized", status_code=401)
        key.last_used_at = utcnow()
        company = db.get(Company, key.company_id)
        if company is None or company.is_blocked:
            raise Forbidden()
        get_ctx().company_id = company.id
        get_ctx().role = "owner" if company.kind == "client" else "fleet_owner"  # never a staff role of a cookie
        get_ctx().extra.pop("rls_bypass", None)
        from app.core import rls

        rls.apply(db)  # NFR-DB-07
        db.commit()
        return ApiCaller(company=company, scopes=tuple(key.scopes.split(",")), sandbox=sandbox,
                         role="owner" if company.kind == "client" else "fleet_owner")
    ratelimit.hit("api", f"ip:{ip}")
    if principal is None or principal.company is None or not principal.session.mfa_passed:
        raise AppError("unauthorized", status_code=401)
    if principal.session.impersonator_id:
        raise Forbidden("impersonation_forbidden")  # FR-ADM-05: support sessions work only in the journaled UI
    if principal.company.is_blocked:
        raise Forbidden("company_blocked")
    return ApiCaller(company=principal.company, user_id=principal.user.id, scopes=SCOPES, role=principal.role)


def need(caller: ApiCaller, scope: str, perm: str) -> None:
    if scope not in caller.scopes or not company_can(caller.role, perm):
        raise Forbidden()


# ------------------------------------------------------------------ schemas


class Point(BaseModel):
    model_config = ConfigDict(extra="forbid")
    kind: Literal["load", "stop", "unload"]
    city: str = Field(min_length=1, max_length=100)
    address: str = Field(default="", max_length=300)


class OrderIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    cargo_name: str = Field(min_length=1, max_length=300)
    cargo_type: str = "general"
    weight_kg: int = Field(gt=0)
    volume_m3: int = 0
    body_type: str = "tent"
    load_from: datetime
    load_to: datetime | None = None
    unload_to: datetime | None = None
    desired_rate_minor: int = Field(default=0, ge=0)
    currency: str = "KZT"
    payment_terms: Literal["prepay", "on_unload", "deferred"] = "on_unload"
    payment_delay_days: int = 0
    adr_class: str = ""
    un_number: str = ""
    points: list[Point] = Field(min_length=2, max_length=10)
    publish: bool = False


class PointOut(BaseModel):
    kind: str
    city: str
    address: str | None = None


class OrderOut(BaseModel):
    id: str
    number: str
    status: str
    version: int
    cargo_name: str
    weight_kg: int
    body_type: str
    desired_rate_minor: int
    currency: str
    load_from: datetime | None
    distance_km: int
    points: list[PointOut]
    created_at: datetime


class Page(BaseModel):
    items: list[OrderOut]
    next_cursor: str | None


class BidIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    price_minor: int = Field(gt=0)
    comment: str = Field(default="", max_length=1000)
    vehicle_id: str | None = None
    driver_id: str | None = None


class BidOut(BaseModel):
    id: str
    status: str
    price_minor: int
    currency: str
    created_at: datetime | None = None


class BidList(BaseModel):
    items: list[BidOut]


class DealOut(BaseModel):
    id: str
    number: str
    status: str
    order_id: str
    price_minor: int
    currency: str


class AdvanceIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    to: str = Field(min_length=1, max_length=20)


def _order_out(o: Order, *, hide_addresses: bool = False) -> OrderOut:
    return OrderOut(id=str(o.id), number=o.number, status=o.status, version=o.version, cargo_name=o.cargo_name,
                    weight_kg=o.weight_kg, body_type=o.body_type, desired_rate_minor=o.desired_rate_minor,
                    currency=o.currency, load_from=o.load_from, distance_km=o.distance_km, created_at=o.created_at,
                    points=[PointOut(kind=p.kind, city=p.city, address=None if hide_addresses else p.address)
                            for p in o.points])


# ------------------------------------------------------------------ endpoints


@router.get("/dictionaries/{name}")
def get_dictionary(name: str, db: Session = Depends(get_db), caller: ApiCaller = Depends(api_caller)):
    if "dictionaries:read" not in caller.scopes:
        raise Forbidden()
    return {"items": [{"code": i.code, "name_ru": i.name_ru, "name_kk": i.name_kk} for i in dictionary(db, name)]}


@router.get("/orders", response_model=Page)
def list_orders(cursor: str | None = None, limit: int = 50, status: str | None = None, db: Session = Depends(get_db),
                caller: ApiCaller = Depends(api_caller)):
    need(caller, "orders:read", "order.view")
    limit = max(1, min(limit, MAX_PAGE))
    if caller.sandbox:
        items, nxt = sandbox.list_orders(db, caller.company.id, cursor=parse_uuid(cursor) if cursor else None,
                                         limit=limit, status=status)
        return Page(items=[OrderOut(**o) for o in items], next_cursor=nxt)
    stmt = select(Order).where(Order.client_company_id == caller.company.id, Order.is_deleted.is_(False))
    if status:
        stmt = stmt.where(Order.status == status)
    if cursor:
        stmt = stmt.where(Order.id < parse_uuid(cursor))
    rows = list(db.execute(stmt.order_by(Order.id.desc()).limit(limit + 1)).scalars())
    nxt = str(rows[limit - 1].id) if len(rows) > limit else None
    return Page(items=[_order_out(o) for o in rows[:limit]], next_cursor=nxt)


@router.post("/orders", response_model=OrderOut, status_code=201)
def create_order(body: OrderIn, db: Session = Depends(get_db), caller: ApiCaller = Depends(api_caller),
                 idempotency_key: str | None = Header(default=None)):
    need(caller, "orders:write", "order.create")
    owner = caller.user_id or caller.company.id
    prev = None if caller.sandbox else idempotent_lookup(db, owner, idempotency_key, "api.order.create")
    if caller.sandbox:
        scope = "api.sandbox.order.create"
        prev = idempotent_lookup(db, owner, idempotency_key, scope)
        if prev:
            return OrderOut(**sandbox.get_order(db, caller.company.id, parse_uuid(prev)))
        o = sandbox.create_order(db, caller.company.id, body)
        idempotent_store(db, owner, idempotency_key, scope, o["id"])
        db.commit()
        return OrderOut(**o)
    if prev:
        return _order_out(db.get(Order, parse_uuid(prev)))
    from app.core.i18n import to_local_input

    form = {"cargo_name": body.cargo_name, "cargo_type": body.cargo_type, "weight_kg": str(body.weight_kg),
            "volume_m3": str(body.volume_m3), "body_type": body.body_type, "currency": body.currency,
            "payment_terms": body.payment_terms, "payment_delay_days": str(body.payment_delay_days),
            "desired_rate": str(from_minor(body.desired_rate_minor, body.currency)) if body.desired_rate_minor else "",
            "adr_class": body.adr_class, "un_number": body.un_number, "vat_included": "on",
            "load_from": to_local_input(body.load_from), "load_to": to_local_input(body.load_to),
            "unload_to": to_local_input(body.unload_to),
            "point_kind": [p.kind for p in body.points], "point_city": [p.city for p in body.points],
            "point_address": [p.address for p in body.points]}
    order = orders.create_order(db, caller.company, form)
    if body.publish:
        orders.submit(db, order)
    idempotent_store(db, owner, idempotency_key, "api.order.create", str(order.id))
    db.commit()
    return _order_out(order)


@router.get("/orders/{oid}", response_model=OrderOut)
def get_order(oid: str, db: Session = Depends(get_db), caller: ApiCaller = Depends(api_caller)):
    need(caller, "orders:read", "order.view")
    if caller.sandbox:
        return OrderOut(**sandbox.get_order(db, caller.company.id, parse_uuid(oid)))
    return _order_out(orders.get_for_client(db, parse_uuid(oid), caller.company.id))


@router.get("/orders/{oid}/bids", response_model=BidList)
def list_bids(oid: str, db: Session = Depends(get_db), caller: ApiCaller = Depends(api_caller)):
    """Bids on the client's own order (carrier names are not disclosed before acceptance)."""
    need(caller, "orders:read", "order.view")
    if caller.sandbox:
        return BidList(items=[BidOut(**b) for b in sandbox.order_bids(db, caller.company.id, parse_uuid(oid))])
    order = orders.get_for_client(db, parse_uuid(oid), caller.company.id)
    return BidList(items=[BidOut(id=str(b.id), status=b.status, price_minor=b.price_minor, currency=b.currency,
                                 created_at=b.created_at) for b in bids.order_bids(db, order.id)])


@router.post("/orders/{oid}/bids/{bid_id}/accept", response_model=DealOut, status_code=201)
def accept_bid(oid: str, bid_id: str, db: Session = Depends(get_db), caller: ApiCaller = Depends(api_caller),
               idempotency_key: str | None = Header(default=None)):
    """FR-BID-06/07 through the API: atomic, idempotent acceptance creates the deal."""
    need(caller, "orders:write", "bid.accept")
    owner = caller.user_id or caller.company.id
    scope = "api.sandbox.bid.accept" if caller.sandbox else "api.bid.accept"
    prev = idempotent_lookup(db, owner, idempotency_key, scope)
    if caller.sandbox:
        if prev:
            from app.modules.platform.models import SandboxObject

            return DealOut(**sandbox.out(db.get(SandboxObject, parse_uuid(prev))))
        d = sandbox.accept(db, caller.company.id, parse_uuid(oid), parse_uuid(bid_id))
        idempotent_store(db, owner, idempotency_key, scope, d["id"])
        db.commit()
        return DealOut(**d)
    from app.modules.deals.models import Deal

    if prev:
        deal = db.get(Deal, parse_uuid(prev))
    else:
        order = orders.get_for_client(db, parse_uuid(oid), caller.company.id)
        bid = db.get(bids.Bid, parse_uuid(bid_id))
        if bid is None or bid.order_id != order.id:
            raise NotFound()
        deal = bids.accept(db, bid.id, caller.company)
        idempotent_store(db, owner, idempotency_key, scope, str(deal.id))
        db.commit()
    order = db.get(Order, deal.order_id)
    return DealOut(id=str(deal.id), number=deal.number, status=order.status, order_id=str(order.id),
                   price_minor=deal.price_minor, currency=deal.currency)


@router.get("/market", response_model=Page)
def market(from_city: str = "", to_city: str = "", body_type: str = "", limit: int = 50, db: Session = Depends(get_db),
           caller: ApiCaller = Depends(api_caller)):
    need(caller, "market:read", "market.view")
    if caller.sandbox:
        return Page(items=[OrderOut(**o) for o in sandbox.market()], next_cursor=None)
    items = orders.marketplace(db, caller.company, {"from_city": from_city, "to_city": to_city, "body_type": body_type},
                               limit=max(1, min(limit, MAX_PAGE)))
    # FR-ACL-02 / SEC-AZ-04: exact addresses are never sent to carriers before acceptance
    return Page(items=[_order_out(o, hide_addresses=True) for o in items], next_cursor=None)


@router.post("/orders/{oid}/bids", response_model=BidOut, status_code=201)
def create_bid(oid: str, body: BidIn, db: Session = Depends(get_db), caller: ApiCaller = Depends(api_caller)):
    need(caller, "bids:write", "bid.create")
    if caller.sandbox:
        b = sandbox.place_bid(db, caller.company.id, oid, body.price_minor, body.comment)
        db.commit()
        return BidOut(**b)
    form = {"price": str(from_minor(body.price_minor)), "comment": body.comment,
            "vehicle_id": body.vehicle_id or "", "driver_id": body.driver_id or ""}
    bid = bids.place_bid(db, parse_uuid(oid), caller.company, form)
    db.commit()
    return BidOut(id=str(bid.id), status=bid.status, price_minor=bid.price_minor, currency=bid.currency,
                  created_at=bid.created_at)


# ------------------------------------------------------------------ telematics (FR-TRK-05)


class PositionIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    plate: str = Field(min_length=2, max_length=20)
    lat: float = Field(ge=-90, le=90)
    lng: float = Field(ge=-180, le=180)
    at: datetime
    speed: int = Field(default=0, ge=0, le=300)


class PositionsIn(BaseModel):
    model_config = ConfigDict(extra="forbid")
    positions: list[PositionIn] = Field(min_length=1, max_length=500)


class PositionsOut(BaseModel):
    accepted: int
    ignored: int


@router.post("/telematics/positions", response_model=PositionsOut)
def telematics_positions(body: PositionsIn, db: Session = Depends(get_db), caller: ApiCaller = Depends(api_caller)):
    """GPS positions of the carrier's vehicles. Kept only for a vehicle on a deal that is loading or on the way
    with the geodata consent; anything else is counted as ignored and not stored (FR-TRK-03)."""
    from app.modules.deals import telematics

    need(caller, "telematics:write", "fleet.manage")
    ratelimit.hit("api", f"telematics:{caller.company.id}")
    res = telematics.ingest(db, caller.company.id, [p.model_dump(mode="json") for p in body.positions],
                            store=not caller.sandbox)
    db.commit()
    return PositionsOut(**res)


# ------------------------------------------------------------------ sandbox controls (FR-API-05)


def _sandbox_only(caller: ApiCaller) -> None:
    if not caller.sandbox:
        raise NotFound()


@router.post("/sandbox/orders/{oid}/advance", response_model=DealOut, tags=["sandbox"])
def sandbox_advance(oid: str, body: AdvanceIn, db: Session = Depends(get_db), caller: ApiCaller = Depends(api_caller)):
    """Test keys only: move the test deal to a later status; a webhook event is sent for every step."""
    _sandbox_only(caller)
    need(caller, "orders:write", "order.view")
    d = sandbox.advance(db, caller.company.id, parse_uuid(oid), body.to)
    db.commit()
    return DealOut(**d)


@router.post("/sandbox/reset", tags=["sandbox"])
def sandbox_reset(db: Session = Depends(get_db), caller: ApiCaller = Depends(api_caller)):
    """Test keys only: delete all test data of the company."""
    _sandbox_only(caller)
    n = sandbox.reset(db, caller.company.id)
    db.commit()
    return {"deleted": n}


# ------------------------------------------------------------------ key management (HTML)


@html.get("/company/api-keys")
def keys_page(request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("company.manage"))):
    keys = list(db.execute(select(ApiKey).where(ApiKey.company_id == me.company.id)
                           .order_by(ApiKey.created_at.desc())).scalars())
    return render(request, "company/api_keys.html", {"keys": keys, "scopes": SCOPES,
                                                     "new_key": request.query_params.get("k")})


@html.post("/company/api-keys")
async def keys_create(request: Request, db: Session = Depends(get_db), me: Principal = Depends(require("company.manage"))):
    form = await request.form()
    scopes = [s for s in form.getlist("scopes") if s in SCOPES] or ["orders:read"]
    env = "test" if form.get("environment") == "test" else "live"
    prefix = token(6)[:8].replace("_", "x").replace("-", "y")
    secret = token(24).replace("_", "x")
    raw = f"{KEY_PREFIX[env]}_{prefix}_{secret}"
    days = int(form.get("days") or 365)
    key = ApiKey(company_id=me.company.id, name=str(form.get("name", "API"))[:100], prefix=prefix,
                 key_hash=hash_token(raw), scopes=",".join(scopes), environment=env,
                 expires_at=utcnow() + timedelta(days=max(1, min(days, 730))), created_by=me.user.id)
    db.add(key)
    audit(db, "company.api_key_created", object_type="api_key", object_id=prefix, details={"environment": env})
    db.commit()
    resp = render(request, "company/api_keys.html", {"keys": list(db.execute(select(ApiKey).where(
        ApiKey.company_id == me.company.id).order_by(ApiKey.created_at.desc())).scalars()), "scopes": SCOPES,
        "new_key": raw})
    return resp


@html.post("/company/api-keys/{kid}/revoke")
def keys_revoke(kid: str, db: Session = Depends(get_db), me: Principal = Depends(require("company.manage"))):
    key = db.get(ApiKey, parse_uuid(kid))
    if key is None or key.company_id != me.company.id:
        raise NotFound()
    key.revoked_at = utcnow()
    audit(db, "company.api_key_revoked", object_type="api_key", object_id=key.prefix)
    db.commit()
    return redirect("/company/api-keys", flash=("success", "msg.saved"))



# ------------------------------------------------------------------ public developer docs (FR-API-05, NFR-API-02)


def _schema_name(ref: dict | None) -> str:
    if not ref:
        return ""
    if "$ref" in ref:
        return ref["$ref"].rsplit("/", 1)[-1]
    if ref.get("type") == "array" and ref.get("items"):
        return _schema_name(ref["items"]) + "[]"
    return ref.get("type", "")


def _type_of(prop: dict) -> str:
    if "anyOf" in prop:
        return " | ".join(_type_of(p) for p in prop["anyOf"])
    if "$ref" in prop:
        return prop["$ref"].rsplit("/", 1)[-1]
    if prop.get("type") == "array":
        return _type_of(prop.get("items", {})) + "[]"
    t = prop.get("type", "")
    if prop.get("format"):
        t += f" ({prop['format']})"
    if prop.get("enum"):
        t += ": " + " | ".join(map(str, prop["enum"]))
    return t


def api_reference(request: Request) -> dict:
    """The method reference is built from the OpenAPI document generated from code, so it never drifts."""
    spec = request.app.openapi()
    methods = []
    for path, ops in spec.get("paths", {}).items():
        if not path.startswith("/api/v1/") or path.endswith("openapi.json"):
            continue
        for verb, op in ops.items():
            body = (op.get("requestBody") or {}).get("content", {}).get("application/json", {}).get("schema")
            ok = next((r for c, r in op.get("responses", {}).items() if c.startswith("2")), {})
            resp = (ok.get("content") or {}).get("application/json", {}).get("schema")
            params = [{"name": p["name"], "in": p["in"], "required": p.get("required", False),
                       "type": _type_of(p.get("schema", {}))}
                      for p in op.get("parameters", []) if p["name"] not in ("x-api-key",)]
            methods.append({"verb": verb.upper(), "path": path, "summary": op.get("summary", ""),
                            "doc": (op.get("description") or "").strip(), "params": params,
                            "body": _schema_name(body), "response": _schema_name(resp),
                            "sandbox_only": "sandbox" in op.get("tags", [])})
    schemas = {}
    for name, sch in spec.get("components", {}).get("schemas", {}).items():
        if name in ("HTTPValidationError", "ValidationError"):
            continue
        req = set(sch.get("required", []))
        schemas[name] = [{"name": k, "type": _type_of(v), "required": k in req}
                         for k, v in sch.get("properties", {}).items()]
    return {"methods": methods, "schemas": schemas, "version": spec.get("info", {}).get("version", "")}


@html.get("/developers")
def developers(request: Request):
    import os

    from app.modules.webhooks.service import EVENTS

    base = (os.getenv("PUBLIC_BASE_URL") or str(request.base_url)).rstrip("/")
    return render(request, "public/developers.html", {**api_reference(request), "base": base, "scopes": SCOPES,
                                                      "events": EVENTS, "max_page": MAX_PAGE,
                                                      "limits": {"live": ratelimit.LIMITS["api"],
                                                                 "test": ratelimit.LIMITS["api_sandbox"]}})
