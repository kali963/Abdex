"""Public REST API v1 (NFR-API-01..08, FR-API-01..04).

- version in path, OpenAPI generated from code (/api/v1/openapi.json, docs at /api/docs)
- unified error format, request id in every response
- idempotency keys for creating operations
- cursor pagination with server-side page size limit
- strict schemas: unknown fields are rejected (no mass assignment)
- money = integer minor units + currency; timestamps = ISO 8601 with timezone
- auth: company API key (X-API-Key) with scopes, expiry, revocation; or the browser session
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
from app.modules.platform.models import ApiKey
from app.modules.platform.service import dictionary, idempotent_lookup, idempotent_store
from app.web.deps import Principal, csrf_protect, get_principal_optional, parse_uuid, redirect, render, require

router = APIRouter(prefix="/api/v1", tags=["v1"], dependencies=[Depends(csrf_protect)])
html = APIRouter(dependencies=[Depends(csrf_protect)])

MAX_PAGE = 100
SCOPES = ("orders:read", "orders:write", "market:read", "bids:write", "dictionaries:read")


class ApiCaller(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)
    company: Company
    user_id: object | None = None
    scopes: tuple[str, ...]
    role: str | None = None


def api_caller(request: Request, db: Session = Depends(get_db), x_api_key: str | None = Header(default=None),
               principal: Principal | None = Depends(get_principal_optional)) -> ApiCaller:
    ip = get_ctx().ip or "local"
    if x_api_key:
        ratelimit.hit("api", f"key:{x_api_key[:12]}")
        parts = x_api_key.split("_")
        if len(parts) != 3 or parts[0] != "abx":
            raise AppError("unauthorized", status_code=401)
        key = db.execute(select(ApiKey).where(ApiKey.prefix == parts[1])).scalar_one_or_none()
        if (key is None or not hmac.compare_digest(key.key_hash, hash_token(x_api_key)) or key.revoked_at
                or (key.expires_at and key.expires_at < utcnow())):
            raise AppError("unauthorized", status_code=401)
        key.last_used_at = utcnow()
        company = db.get(Company, key.company_id)
        if company is None or company.is_blocked:
            raise Forbidden()
        get_ctx().company_id = company.id
        db.commit()
        return ApiCaller(company=company, scopes=tuple(key.scopes.split(",")),
                         role="owner" if company.kind == "client" else "fleet_owner")
    ratelimit.hit("api", f"ip:{ip}")
    if principal is None or principal.company is None or not principal.session.mfa_passed:
        raise AppError("unauthorized", status_code=401)
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
    prev = idempotent_lookup(db, owner, idempotency_key, "api.order.create")
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
    return _order_out(orders.get_for_client(db, parse_uuid(oid), caller.company.id))


@router.get("/market", response_model=Page)
def market(from_city: str = "", to_city: str = "", body_type: str = "", limit: int = 50, db: Session = Depends(get_db),
           caller: ApiCaller = Depends(api_caller)):
    need(caller, "market:read", "market.view")
    items = orders.marketplace(db, caller.company, {"from_city": from_city, "to_city": to_city, "body_type": body_type},
                               limit=max(1, min(limit, MAX_PAGE)))
    # FR-ACL-02 / SEC-AZ-04: exact addresses are never sent to carriers before acceptance
    return Page(items=[_order_out(o, hide_addresses=True) for o in items], next_cursor=None)


@router.post("/orders/{oid}/bids", response_model=BidOut, status_code=201)
def create_bid(oid: str, body: BidIn, db: Session = Depends(get_db), caller: ApiCaller = Depends(api_caller)):
    need(caller, "bids:write", "bid.create")
    form = {"price": str(from_minor(body.price_minor)), "comment": body.comment,
            "vehicle_id": body.vehicle_id or "", "driver_id": body.driver_id or ""}
    bid = bids.place_bid(db, parse_uuid(oid), caller.company, form)
    db.commit()
    return BidOut(id=str(bid.id), status=bid.status, price_minor=bid.price_minor, currency=bid.currency)


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
    prefix = token(6)[:8].replace("_", "x").replace("-", "y")
    secret = token(24).replace("_", "x")
    raw = f"abx_{prefix}_{secret}"
    days = int(form.get("days") or 365)
    key = ApiKey(company_id=me.company.id, name=str(form.get("name", "API"))[:100], prefix=prefix,
                 key_hash=hash_token(raw), scopes=",".join(scopes),
                 expires_at=utcnow() + timedelta(days=max(1, min(days, 730))), created_by=me.user.id)
    db.add(key)
    audit(db, "company.api_key_created", object_type="api_key", object_id=prefix)
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

