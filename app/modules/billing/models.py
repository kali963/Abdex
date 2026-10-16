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


class PaymentIntent(Model):
    """FR-BIL-06: an online payment of a platform invoice through the provider's hosted page.
    Card data is entered only on the provider's side and never reaches the platform."""

    __tablename__ = "payment_intents"

    invoice_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("invoices.id"), index=True)
    company_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("companies.id"), index=True)
    provider: Mapped[str] = mapped_column(String(40))
    provider_ref: Mapped[str] = mapped_column(String(80), unique=True)
    amount_minor: Mapped[int] = mapped_column(BigInteger)
    currency: Mapped[str] = mapped_column(String(3), default="KZT")
    status: Mapped[str] = mapped_column(String(10), default="created", index=True)  # created / paid / failed
    checkout_url: Mapped[str] = mapped_column(String(500), default="")
    paid_at: Mapped[datetime | None] = mapped_column(AwareDateTime)


class DigitalModule(Model):
    """FR-PVD-07, FR-BIL-08: a paid digital module or subscription. Connecting it switches on the feature flag
    ``flag_key`` for the company while the subscription is active; its income is accounted separately."""

    __tablename__ = "digital_modules"

    code: Mapped[str] = mapped_column(String(40), unique=True)
    name: Mapped[str] = mapped_column(String(200))
    description: Mapped[str] = mapped_column(String(500), default="")
    flag_key: Mapped[str] = mapped_column(String(60))
    price_minor: Mapped[int] = mapped_column(BigInteger)
    currency: Mapped[str] = mapped_column(String(3), default="KZT")
    period_days: Mapped[int] = mapped_column(Integer, default=30)
    income_type: Mapped[str] = mapped_column(String(30), default=INCOME_DIGITAL_MODULES)
    audience: Mapped[str] = mapped_column(String(10), default="any")  # any / client / carrier
    active: Mapped[bool] = mapped_column(Boolean, default=True)


class Subscription(Model):
    """One row per company and module; a period is paid by an accrual and an invoice of its own."""

    __tablename__ = "subscriptions"
    __table_args__ = (UniqueConstraint("company_id", "module_id", name="uq_subscription_company_module"),)

    company_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("companies.id"), index=True)
    module_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("digital_modules.id"), index=True)
    status: Mapped[str] = mapped_column(String(12), default="active", index=True)  # active / cancelled / expired
    auto_renew: Mapped[bool] = mapped_column(Boolean, default=True)
    started_at: Mapped[datetime] = mapped_column(AwareDateTime)
    period_start: Mapped[date] = mapped_column(Date)
    period_end: Mapped[date] = mapped_column(Date, index=True)  # last day of the paid period
    periods: Mapped[int] = mapped_column(Integer, default=1)
    cancelled_at: Mapped[datetime | None] = mapped_column(AwareDateTime)
