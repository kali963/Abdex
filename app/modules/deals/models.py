"""Deals, immutable term snapshots, supplements, execution and disputes (M5, M11, M14)."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import BigInteger, Boolean, Float, ForeignKey, Integer, String, Text, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.db import AppendOnly, AwareDateTime, Model


class Deal(Model):
    __tablename__ = "deals"

    # Unique order_id / bid_id make double assignment impossible at the DB level (FR-BID-07).
    order_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("orders.id"), unique=True)
    bid_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("bids.id"), unique=True)
    number: Mapped[str] = mapped_column(String(30), unique=True)
    client_company_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("companies.id"), index=True)
    carrier_company_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("companies.id"), index=True)
    price_minor: Mapped[int] = mapped_column(BigInteger)
    currency: Mapped[str] = mapped_column(String(3), default="KZT")
    vehicle_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("vehicles.id"))
    driver_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("drivers.id"))
    trailer_plate: Mapped[str] = mapped_column(String(20), default="")
    snapshot_version: Mapped[int] = mapped_column(Integer, default=1)
    risk_score: Mapped[int] = mapped_column(Integer, default=0)
    needs_manual_review: Mapped[bool] = mapped_column(Boolean, default=False)
    flagged: Mapped[bool] = mapped_column(Boolean, default=False)
    # FR-DEAL-05: computed by the system, never set by hand.
    formalized_via_platform: Mapped[bool] = mapped_column(Boolean, default=False)
    geo_consent: Mapped[bool] = mapped_column(Boolean, default=False)


class DealSnapshot(AppendOnly, Model):
    """FR-DEAL-01: immutable copy of agreed terms, stored apart from working tables."""

    __tablename__ = "deal_snapshots"
    __table_args__ = (UniqueConstraint("deal_id", "version", name="uq_snapshot_version"),)

    deal_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("deals.id"), index=True)
    version: Mapped[int] = mapped_column(Integer)
    data: Mapped[str] = mapped_column(Text)
    content_hash: Mapped[str] = mapped_column(String(64))
    previous_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    reason: Mapped[str] = mapped_column(String(300), default="acceptance")


class Supplement(Model):
    """FR-DEAL-02: change of agreed terms requires acceptance by the other side."""

    __tablename__ = "supplements"

    deal_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("deals.id"), index=True)
    initiator_company_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("companies.id"))
    changes: Mapped[str] = mapped_column(Text)
    reason: Mapped[str] = mapped_column(String(500), default="")
    status: Mapped[str] = mapped_column(String(20), default="proposed")  # proposed / accepted / rejected
    decided_by: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    decided_at: Mapped[datetime | None] = mapped_column(AwareDateTime)


class ExecutorChange(Model):
    """FR-DEAL-03: replacing driver / vehicle requires client confirmation."""

    __tablename__ = "executor_changes"

    deal_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("deals.id"), index=True)
    old_vehicle_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    new_vehicle_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    old_driver_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    new_driver_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    reason: Mapped[str] = mapped_column(String(500))
    status: Mapped[str] = mapped_column(String(20), default="proposed")
    decided_by: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    decided_at: Mapped[datetime | None] = mapped_column(AwareDateTime)


class Checkpoint(AppendOnly, Model):
    """FR-TRK-01/02/07: driver checkpoints with time and geo; offline_id deduplicates sync."""

    __tablename__ = "checkpoints"
    __table_args__ = (UniqueConstraint("deal_id", "offline_id", name="uq_checkpoint_offline"),)

    deal_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("deals.id"), index=True)
    kind: Mapped[str] = mapped_column(String(20))  # arrived_load / loaded / departed / arrived_unload / unloaded
    happened_at: Mapped[datetime] = mapped_column(AwareDateTime)
    lat: Mapped[float | None] = mapped_column(Float)
    lng: Mapped[float | None] = mapped_column(Float)
    photo_file_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("stored_files.id"))
    note: Mapped[str] = mapped_column(String(300), default="")
    offline_id: Mapped[str] = mapped_column(String(64))


class Incident(AppendOnly, Model):
    __tablename__ = "incidents"

    deal_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("deals.id"), index=True)
    kind: Mapped[str] = mapped_column(String(20))  # delay / breakdown / accident / refused / downtime
    description: Mapped[str] = mapped_column(Text)
    reporter_company_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)


class Rating(Model):
    """FR-DEAL-07: mutual rating with structured criteria."""

    __tablename__ = "ratings"
    __table_args__ = (UniqueConstraint("deal_id", "from_company_id", name="uq_rating"),)

    deal_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("deals.id"))
    from_company_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("companies.id"))
    to_company_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("companies.id"), index=True)
    score: Mapped[int] = mapped_column(Integer)
    punctuality: Mapped[int] = mapped_column(Integer, default=5)
    vehicle_condition: Mapped[int] = mapped_column(Integer, default=5)
    documents_quality: Mapped[int] = mapped_column(Integer, default=5)
    communication: Mapped[int] = mapped_column(Integer, default=5)
    payment_discipline: Mapped[int] = mapped_column(Integer, default=5)
    comment: Mapped[str] = mapped_column(String(1000), default="")


class Dispute(Model):
    """FR-SUP-03."""

    __tablename__ = "disputes"

    deal_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("deals.id"), index=True)
    opened_by_company_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("companies.id"))
    subject: Mapped[str] = mapped_column(String(40))
    description: Mapped[str] = mapped_column(Text)
    client_position: Mapped[str] = mapped_column(Text, default="")
    carrier_position: Mapped[str] = mapped_column(Text, default="")
    previous_status: Mapped[str] = mapped_column(String(20))
    status: Mapped[str] = mapped_column(String(20), default="open")
    outcome: Mapped[str] = mapped_column(String(20), default="")  # closed_docs / cancelled
    resolution: Mapped[str] = mapped_column(Text, default="")
    resolved_by: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    resolved_at: Mapped[datetime | None] = mapped_column(AwareDateTime)
    fault: Mapped[str] = mapped_column(String(10), default="")  # none / carrier / client — feeds the rating
