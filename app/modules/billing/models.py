"""Platform fee billing (M13, section 4).

All financial records are immutable; corrections are storno entries (FR-BIL-10).
"""
from __future__ import annotations

import uuid
from datetime import date, datetime

from sqlalchemy import BigInteger, Boolean, Date, ForeignKey, Integer, String, Text, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.db import AppendOnly, AwareDateTime, Model

# FR-PVD-01: mandatory income type dictionary.
INCOME_FIXED_FEE = "platform_fee_fixed"
INCOME_VARIABLE_FEE = "platform_fee_variable"
INCOME_DIGITAL_MODULES = "digital_modules"
INCOME_SUBSCRIPTION = "subscription"
INCOME_OTHER = "other_non_priority"
INCOME_TYPES = (INCOME_FIXED_FEE, INCOME_VARIABLE_FEE, INCOME_DIGITAL_MODULES, INCOME_SUBSCRIPTION, INCOME_OTHER)
PRIORITY_INCOME_TYPES = (INCOME_FIXED_FEE, INCOME_VARIABLE_FEE, INCOME_DIGITAL_MODULES, INCOME_SUBSCRIPTION)


class Tariff(Model):
    """FR-PVD-06, FR-BIL-01."""

    __tablename__ = "tariffs"

    name: Mapped[str] = mapped_column(String(200))
    company_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("companies.id"), index=True)  # None = default
    model: Mapped[str] = mapped_column(String(10))  # fixed / percent / combined
    fixed_minor: Mapped[int] = mapped_column(BigInteger, default=0)
    percent_bp: Mapped[int] = mapped_column(Integer, default=0)  # basis points
    min_minor: Mapped[int] = mapped_column(BigInteger, default=0)
    max_minor: Mapped[int] = mapped_column(BigInteger, default=0)  # 0 = no max
    currency: Mapped[str] = mapped_column(String(3), default="KZT")
    deal_type: Mapped[str] = mapped_column(String(20), default="any")  # any / domestic / international
    valid_from: Mapped[date] = mapped_column(Date)
    valid_to: Mapped[date | None] = mapped_column(Date)


class Invoice(Model):
    __tablename__ = "invoices"

    number: Mapped[str] = mapped_column(String(40), unique=True)
    company_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("companies.id"), index=True)
    deal_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("deals.id"))
    amount_minor: Mapped[int] = mapped_column(BigInteger)
    currency: Mapped[str] = mapped_column(String(3), default="KZT")
    status: Mapped[str] = mapped_column(String(20), default="issued")  # issued / paid / cancelled
    document_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("documents.id"))
    act_document_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("documents.id"))
    due_date: Mapped[date | None] = mapped_column(Date)
    paid_at: Mapped[datetime | None] = mapped_column(AwareDateTime)


class Accrual(AppendOnly, Model):
    """FR-BIL-02: event, tariff and calculation are stored in the accrual itself."""

    __tablename__ = "accruals"
    deal_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("deals.id"), index=True)
    company_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("companies.id"), index=True)
    invoice_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("invoices.id"))
    income_type: Mapped[str] = mapped_column(String(30), index=True)
    amount_minor: Mapped[int] = mapped_column(BigInteger)  # negative for storno
    currency: Mapped[str] = mapped_column(String(3), default="KZT")
    event: Mapped[str] = mapped_column(String(80), unique=True)  # idempotency: one accrual per event
    tariff_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("tariffs.id"))
    calculation: Mapped[str] = mapped_column(Text, default="{}")
    storno_of_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    note: Mapped[str] = mapped_column(String(300), default="")


class Payment(AppendOnly, Model):
    __tablename__ = "payments"

    invoice_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("invoices.id"), index=True)
    company_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("companies.id"))
    amount_minor: Mapped[int] = mapped_column(BigInteger)
    currency: Mapped[str] = mapped_column(String(3), default="KZT")
    source: Mapped[str] = mapped_column(String(20), default="manual")  # manual / bank_statement / provider
    reference: Mapped[str] = mapped_column(String(100), default="")


class PromoCode(Model):
    """FR-BIL-09: discounts and grace periods limited by term and number of uses."""

    __tablename__ = "promo_codes"

    code: Mapped[str] = mapped_column(String(40), unique=True)
    kind: Mapped[str] = mapped_column(String(10))  # percent / fixed / free_days
    value: Mapped[int] = mapped_column(Integer)  # percent (1..100), minor units, or number of days
    valid_from: Mapped[date] = mapped_column(Date)
    valid_to: Mapped[date | None] = mapped_column(Date)
    max_uses: Mapped[int] = mapped_column(Integer, default=0)  # 0 = unlimited
    uses: Mapped[int] = mapped_column(Integer, default=0)
    deals_per_company: Mapped[int] = mapped_column(Integer, default=1)  # how many accruals a redemption discounts
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    description: Mapped[str] = mapped_column(String(300), default="")


class PromoRedemption(Model):
    __tablename__ = "promo_redemptions"
    __table_args__ = (UniqueConstraint("promo_id", "company_id", name="uq_promo_company"),)

    promo_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("promo_codes.id"), index=True)
    company_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("companies.id"), index=True)
    free_until: Mapped[date | None] = mapped_column(Date)
    deals_used: Mapped[int] = mapped_column(Integer, default=0)
