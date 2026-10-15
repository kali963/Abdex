"""Verification of participants, vehicles and drivers (M2)."""
from __future__ import annotations

import uuid
from datetime import date, datetime

from sqlalchemy import Boolean, Date, ForeignKey, Integer, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.db import AppendOnly, AwareDateTime, Model

LEVEL_NAMES = {0: "L0", 1: "L1", 2: "L2", 3: "L3"}


class Vehicle(Model):
    __tablename__ = "vehicles"

    company_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("companies.id"), index=True)
    plate: Mapped[str] = mapped_column(String(20), index=True)
    vin: Mapped[str] = mapped_column(String(20), default="")
    category: Mapped[str] = mapped_column(String(10), default="C")
    body_type: Mapped[str] = mapped_column(String(30), default="tent")
    capacity_kg: Mapped[int] = mapped_column(Integer, default=20000)
    volume_m3: Mapped[int] = mapped_column(Integer, default=82)
    dimensions: Mapped[str] = mapped_column(String(50), default="")
    insurance_until: Mapped[date | None] = mapped_column(Date)
    has_tachograph: Mapped[bool] = mapped_column(Boolean, default=False)
    international_permit: Mapped[bool] = mapped_column(Boolean, default=False)
    adr_allowed: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(20), default="pending")  # pending / approved / rejected


class Driver(Model):
    __tablename__ = "drivers"

    company_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("companies.id"), index=True)
    user_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("users.id"), index=True)
    full_name: Mapped[str] = mapped_column(String(200))
    iin: Mapped[str] = mapped_column(String(12), index=True)
    phone: Mapped[str] = mapped_column(String(20), default="")
    license_number: Mapped[str] = mapped_column(String(30), default="")
    license_categories: Mapped[str] = mapped_column(String(30), default="C,CE")
    license_until: Mapped[date | None] = mapped_column(Date)
    adr_permit: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(20), default="pending")


class VerificationDocument(Model):
    __tablename__ = "verification_documents"

    company_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("companies.id"), index=True)
    subject_type: Mapped[str] = mapped_column(String(20))  # company / vehicle / driver
    subject_id: Mapped[uuid.UUID] = mapped_column(Uuid)
    doc_type: Mapped[str] = mapped_column(String(40))
    file_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("stored_files.id"))
    expires_on: Mapped[date | None] = mapped_column(Date)
    status: Mapped[str] = mapped_column(String(20), default="uploaded")  # uploaded / approved / rejected
    reject_reason: Mapped[str] = mapped_column(String(300), default="")


class VerificationRequest(Model):
    """Moderation queue item (FR-KYC-04)."""

    __tablename__ = "verification_requests"

    company_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("companies.id"), index=True)
    level_requested: Mapped[int] = mapped_column(Integer, default=1)
    status: Mapped[str] = mapped_column(String(20), default="pending", index=True)  # pending / approved / rejected
    priority: Mapped[int] = mapped_column(Integer, default=2)
    assigned_to: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("users.id"))
    decided_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("users.id"))
    decided_at: Mapped[datetime | None] = mapped_column(AwareDateTime)
    reason_code: Mapped[str] = mapped_column(String(40), default="")
    comment: Mapped[str] = mapped_column(String(500), default="")
    sla_due_at: Mapped[datetime | None] = mapped_column(AwareDateTime)


class RegistryCheck(AppendOnly, Model):
    """Result of a check against an external registry (FR-KYC-06, GOV-R-02)."""

    __tablename__ = "registry_checks"

    subject_type: Mapped[str] = mapped_column(String(20))  # company / person / vehicle
    subject_key: Mapped[str] = mapped_column(String(64), index=True)
    company_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, index=True)
    source: Mapped[str] = mapped_column(String(40))
    basis: Mapped[str] = mapped_column(String(40))  # consent / user_action / scheduled
    status: Mapped[str] = mapped_column(String(20))  # match / mismatch / not_found / unavailable
    result: Mapped[str] = mapped_column(Text, default="{}")
    valid_until: Mapped[datetime | None] = mapped_column(AwareDateTime)
