"""Carrier bids and negotiation history (M4)."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, ForeignKey, Integer, String, Text, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.db import AppendOnly, AwareDateTime, Model


class Bid(Model):
    __tablename__ = "bids"
    __table_args__ = (UniqueConstraint("order_id", "carrier_company_id", name="uq_bid_per_carrier"),)

    order_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("orders.id"), index=True)
    carrier_company_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("companies.id"), index=True)
    price_minor: Mapped[int] = mapped_column(BigInteger)
    currency: Mapped[str] = mapped_column(String(3), default="KZT")
    payment_terms: Mapped[str] = mapped_column(String(20), default="on_unload")
    vehicle_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("vehicles.id"))
    driver_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("drivers.id"))
    ready_at: Mapped[datetime | None] = mapped_column(AwareDateTime)
    valid_until: Mapped[datetime | None] = mapped_column(AwareDateTime)
    comment: Mapped[str] = mapped_column(Text, default="")
    # active / countered / needs_confirmation / accepted / rejected / withdrawn / expired
    status: Mapped[str] = mapped_column(String(20), default="active", index=True)
    order_version: Mapped[int] = mapped_column(Integer, default=1)
    counter_price_minor: Mapped[int | None] = mapped_column(BigInteger)


class BidEvent(AppendOnly, Model):
    """History of every negotiation iteration (FR-BID-03)."""

    __tablename__ = "bid_events"

    bid_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("bids.id"), index=True)
    kind: Mapped[str] = mapped_column(String(30))
    price_minor: Mapped[int | None] = mapped_column(BigInteger)
    actor_user_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    actor_company_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    comment: Mapped[str] = mapped_column(String(500), default="")
