"""Orders, route points, versions and status history (M3, section 6)."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, Boolean, ForeignKey, Integer, String, Text, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db import AppendOnly, AwareDateTime, Model


class Order(Model):
    __tablename__ = "orders"

    number: Mapped[str] = mapped_column(String(30), unique=True)
    client_company_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("companies.id"), index=True)
    status: Mapped[str] = mapped_column(String(20), index=True, default="draft")
    version: Mapped[int] = mapped_column(Integer, default=1)
    is_preliminary: Mapped[bool] = mapped_column(Boolean, default=False)  # FR-PLAN-02

    # Cargo (FR-ORD-01)
    cargo_name: Mapped[str] = mapped_column(String(300), default="")
    cargo_type: Mapped[str] = mapped_column(String(30), default="general")
    weight_kg: Mapped[int] = mapped_column(Integer, default=0)
    volume_m3: Mapped[int] = mapped_column(Integer, default=0)
    places: Mapped[int] = mapped_column(Integer, default=0)
    packaging: Mapped[str] = mapped_column(String(60), default="")
    cargo_value_minor: Mapped[int] = mapped_column(BigInteger, default=0)

    # Vehicle requirements
    body_type: Mapped[str] = mapped_column(String(30), default="tent")
    min_capacity_kg: Mapped[int] = mapped_column(Integer, default=0)
    temperature_mode: Mapped[str] = mapped_column(String(30), default="")
    needs_tail_lift: Mapped[bool] = mapped_column(Boolean, default=False)
    needs_straps: Mapped[bool] = mapped_column(Boolean, default=False)
    special_conditions: Mapped[str] = mapped_column(Text, default="")

    # Dangerous goods / international (FR-ORD-02, FR-ORD-03)
    adr_class: Mapped[str] = mapped_column(String(10), default="")
    un_number: Mapped[str] = mapped_column(String(10), default="")
    is_international: Mapped[bool] = mapped_column(Boolean, default=False)
    countries: Mapped[str] = mapped_column(String(100), default="")
    border_crossing: Mapped[str] = mapped_column(String(100), default="")
    needs_cmr: Mapped[bool] = mapped_column(Boolean, default=False)
    needs_tir: Mapped[bool] = mapped_column(Boolean, default=False)

    # Prices (FR-ORD-04) — minor units + currency
    desired_rate_minor: Mapped[int] = mapped_column(BigInteger, default=0)
    currency: Mapped[str] = mapped_column(String(3), default="KZT")
    payment_terms: Mapped[str] = mapped_column(String(20), default="on_unload")  # prepay / on_unload / deferred
    payment_delay_days: Mapped[int] = mapped_column(Integer, default=0)
    vat_included: Mapped[bool] = mapped_column(Boolean, default=True)
    downtime_terms: Mapped[str] = mapped_column(String(300), default="")

    # Dates
    load_from: Mapped[datetime | None] = mapped_column(AwareDateTime)
    load_to: Mapped[datetime | None] = mapped_column(AwareDateTime)
    unload_from: Mapped[datetime | None] = mapped_column(AwareDateTime)
    unload_to: Mapped[datetime | None] = mapped_column(AwareDateTime)
    bidding_deadline: Mapped[datetime | None] = mapped_column(AwareDateTime)

    # Route calculation (FR-ORD-09)
    distance_km: Mapped[int] = mapped_column(Integer, default=0)
    duration_hours: Mapped[int] = mapped_column(Integer, default=0)
    route_source: Mapped[str] = mapped_column(String(40), default="")

    # Closed pool / targeted orders (FR-BID-05)
    visibility: Mapped[str] = mapped_column(String(20), default="public")  # public / pool

    published_at: Mapped[datetime | None] = mapped_column(AwareDateTime, index=True)
    assigned_at: Mapped[datetime | None] = mapped_column(AwareDateTime)
    moderation_note: Mapped[str] = mapped_column(String(500), default="")
    search_text: Mapped[str] = mapped_column(Text, default="")  # FR-ORD-11

    points: Mapped[list["OrderPoint"]] = relationship(
        order_by="OrderPoint.seq", cascade="all, delete-orphan", lazy="selectin"
    )

    @property
    def origin(self) -> "OrderPoint | None":
        return self.points[0] if self.points else None

    @property
    def destination(self) -> "OrderPoint | None":
        return self.points[-1] if self.points else None


class OrderPoint(Model):
    __tablename__ = "order_points"

    order_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("orders.id"), index=True)
    seq: Mapped[int] = mapped_column(Integer)
    kind: Mapped[str] = mapped_column(String(10))  # load / stop / unload
    region: Mapped[str] = mapped_column(String(100), default="")
    city: Mapped[str] = mapped_column(String(100))
    address: Mapped[str] = mapped_column(String(300), default="")  # hidden from carriers until acceptance
    contact_name: Mapped[str] = mapped_column(String(100), default="")
    contact_phone: Mapped[str] = mapped_column(String(20), default="")


class OrderVersion(AppendOnly, Model):
    """Every change of a published order creates a new version (FR-ORD-07)."""

    __tablename__ = "order_versions"
    __table_args__ = (UniqueConstraint("order_id", "version", name="uq_order_version"),)

    order_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("orders.id"), index=True)
    version: Mapped[int] = mapped_column(Integer)
    data: Mapped[str] = mapped_column(Text)
    change_note: Mapped[str] = mapped_column(String(300), default="")


class StatusHistory(AppendOnly, Model):
    """FR-FLOW-02: who, when, from, to, why, from which device and IP."""

    __tablename__ = "status_history"

    order_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("orders.id"), index=True)
    from_status: Mapped[str] = mapped_column(String(20))
    to_status: Mapped[str] = mapped_column(String(20))
    reason: Mapped[str] = mapped_column(String(500), default="")
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    actor_role: Mapped[str] = mapped_column(String(20), default="system")
    ip: Mapped[str] = mapped_column(String(64), default="")
    device: Mapped[str] = mapped_column(String(300), default="")
    is_rollback: Mapped[bool] = mapped_column(Boolean, default=False)


class OrderTemplate(Model):
    """FR-ORD-05: saved templates for repeated orders."""

    __tablename__ = "order_templates"

    company_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("companies.id"), index=True)
    name: Mapped[str] = mapped_column(String(200))
    data: Mapped[str] = mapped_column(Text)


class SavedSearch(Model):
    """FR-ORD-08: carrier filter subscriptions with notification."""

    __tablename__ = "saved_searches"

    company_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("companies.id"), index=True)
    user_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id"))
    name: Mapped[str] = mapped_column(String(100))
    filters: Mapped[str] = mapped_column(Text)
    notify: Mapped[bool] = mapped_column(Boolean, default=True)


class PoolMember(Model):
    """Client's pool of trusted carriers for closed orders (FR-BID-05, FR-RAT-05)."""

    __tablename__ = "counterparty_lists"
    __table_args__ = (UniqueConstraint("owner_company_id", "other_company_id", name="uq_counterparty"),)

    owner_company_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("companies.id"), index=True)
    other_company_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("companies.id"))
    kind: Mapped[str] = mapped_column(String(10), default="trusted")  # trusted / blocked
