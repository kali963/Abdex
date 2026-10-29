"""Verification of participants, vehicles and drivers (M2)."""
from __future__ import annotations

import uuid
from datetime import date, datetime

from sqlalchemy import Boolean, Date, ForeignKey, Integer, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column, validates

from app.db import AppendOnly, AwareDateTime, Encrypted, Model

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
    # NFR-DB-08: personal data encrypted in the application; lookups go through the blind index
    iin: Mapped[str] = mapped_column(Encrypted("drivers.iin"), default="")
    iin_index: Mapped[str] = mapped_column(String(40), default="", index=True)
    phone: Mapped[str] = mapped_column(Encrypted("drivers.phone"), default="")
    license_number: Mapped[str] = mapped_column(Encrypted("drivers.license_number"), default="")
    license_categories: Mapped[str] = mapped_column(String(30), default="C,CE")
    license_until: Mapped[date | None] = mapped_column(Date)
    adr_permit: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(20), default="pending")
    # FR-KYC-09: suspicious signs require a repeated identity check before new trips
    reverify_reason: Mapped[str] = mapped_column(String(40), default="")
    reverify_since: Mapped[datetime | None] = mapped_column(AwareDateTime)

    @validates("iin")
    def _index_iin(self, key, value):
        from app.core.crypto import blind_index

        self.iin_index = blind_index(value, "iin")
        return value


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
    recognized: Mapped[str] = mapped_column(Text, default="{}")  # M6: data read from the document for the moderator


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


class BiometricCheck(Model):
    """FR-KYC-08, SEC-DAT-10: only the result is kept; source images are deleted after a short period."""

    __tablename__ = "biometric_checks"

    driver_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("drivers.id"), index=True)
    company_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("companies.id"), index=True)
    provider: Mapped[str] = mapped_column(String(40))
    match: Mapped[bool] = mapped_column(Boolean, default=False)
    liveness: Mapped[bool] = mapped_column(Boolean, default=False)
    score: Mapped[int] = mapped_column(Integer, default=0)  # 0..100
    # pending (waits for the moderator) / passed / failed / withdrawn (consent revoked before the decision) /
    # unavailable (automatic provider down)
    status: Mapped[str] = mapped_column(String(20), default="passed", index=True)
    selfie_file_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("stored_files.id"))
    selfie2_file_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("stored_files.id"))
    document_file_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("stored_files.id"))
    reviewed_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("users.id"))
    reviewed_at: Mapped[datetime | None] = mapped_column(AwareDateTime)
    review_reason: Mapped[str] = mapped_column(String(40), default="")
    review_comment: Mapped[str] = mapped_column(String(500), default="")
    images_delete_after: Mapped[datetime | None] = mapped_column(AwareDateTime)
    images_deleted_at: Mapped[datetime | None] = mapped_column(AwareDateTime)
    valid_until: Mapped[date | None] = mapped_column(Date)
