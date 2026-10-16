"""Platform-wide data: dictionaries, feature flags, settings, antifraud, idempotency, API keys."""
from __future__ import annotations

import uuid
from datetime import date, datetime

from sqlalchemy import Boolean, Date, ForeignKey, Integer, String, Text, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.db import AppendOnly, AwareDateTime, Model


class DictionaryItem(Model):
    """FR-ADM-01: editable dictionaries, no release needed."""

    __tablename__ = "dictionary_items"
    __table_args__ = (UniqueConstraint("dictionary", "code", name="uq_dictionary_code"),)

    dictionary: Mapped[str] = mapped_column(String(40), index=True)
    code: Mapped[str] = mapped_column(String(60))
    name_ru: Mapped[str] = mapped_column(String(300))
    name_kk: Mapped[str] = mapped_column(String(300), default="")
    extra: Mapped[str] = mapped_column(Text, default="{}")
    sort: Mapped[int] = mapped_column(Integer, default=100)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)


class DictionaryHistory(AppendOnly, Model):
    __tablename__ = "dictionary_history"

    item_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("dictionary_items.id"), index=True)
    before: Mapped[str] = mapped_column(Text)
    after: Mapped[str] = mapped_column(Text)


class FeatureFlag(Model):
    """FR-ADM-03, INT-GEN-06, FR-PVD-07."""

    __tablename__ = "feature_flags"

    key: Mapped[str] = mapped_column(String(60), unique=True)
    description: Mapped[str] = mapped_column(String(300), default="")
    enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    company_ids: Mapped[str] = mapped_column(Text, default="")  # comma-separated allow list
    percent: Mapped[int] = mapped_column(Integer, default=0)


class PlatformSetting(Model):
    """FR-ADM-06 and FR-PVD-05 texts / thresholds editable without release."""

    __tablename__ = "platform_settings"

    key: Mapped[str] = mapped_column(String(60), unique=True)
    value: Mapped[str] = mapped_column(Text)
    description: Mapped[str] = mapped_column(String(300), default="")


class AntifraudAlert(Model):
    """FR-KYC-07, FR-DEAL-06, SEC-FRD-07: alert queue for manual review."""

    __tablename__ = "antifraud_alerts"

    kind: Mapped[str] = mapped_column(String(40), index=True)
    severity: Mapped[str] = mapped_column(String(10), default="medium")
    company_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, index=True)
    deal_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, index=True)
    details: Mapped[str] = mapped_column(Text, default="{}")
    status: Mapped[str] = mapped_column(String(20), default="open", index=True)  # open / confirmed / false_positive
    decided_by: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    decision_note: Mapped[str] = mapped_column(String(500), default="")


class Restriction(Model):
    """FR-RAT-04, SEC-FRD-08: every restriction has reason, term and author; reversible."""

    __tablename__ = "restrictions"

    company_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("companies.id"), index=True)
    kind: Mapped[str] = mapped_column(String(20))  # block / limit / no_new_orders
    reason: Mapped[str] = mapped_column(String(500))
    until: Mapped[date | None] = mapped_column(Date)
    lifted_at: Mapped[datetime | None] = mapped_column(AwareDateTime)
    lifted_by: Mapped[uuid.UUID | None] = mapped_column(Uuid)


class IdempotencyKey(Model):
    """NFR-API-04: a repeated request never creates a duplicate."""

    __tablename__ = "idempotency_keys"
    __table_args__ = (UniqueConstraint("user_id", "key", name="uq_idempotency"),)

    user_id: Mapped[uuid.UUID] = mapped_column(Uuid)
    key: Mapped[str] = mapped_column(String(80))
    scope: Mapped[str] = mapped_column(String(60))
    result_ref: Mapped[str] = mapped_column(String(300), default="")


class ApiKey(Model):
    """FR-API-02: keys belong to a company, have scopes, expiry and can be revoked."""

    __tablename__ = "api_keys"

    company_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("companies.id"), index=True)
    name: Mapped[str] = mapped_column(String(100))
    prefix: Mapped[str] = mapped_column(String(12), index=True)
    key_hash: Mapped[str] = mapped_column(String(64), unique=True)
    scopes: Mapped[str] = mapped_column(String(300), default="orders:read")
    expires_at: Mapped[datetime | None] = mapped_column(AwareDateTime)
    revoked_at: Mapped[datetime | None] = mapped_column(AwareDateTime)
    last_used_at: Mapped[datetime | None] = mapped_column(AwareDateTime)


class IntegrationCall(AppendOnly, Model):
    """INT-GEN-04 / GOV-R-04: journal of every external call."""

    __tablename__ = "integration_calls"

    adapter: Mapped[str] = mapped_column(String(40), index=True)
    operation: Mapped[str] = mapped_column(String(60))
    initiator_user_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    basis: Mapped[str] = mapped_column(String(40), default="")
    request_summary: Mapped[str] = mapped_column(String(500), default="")
    status: Mapped[str] = mapped_column(String(20))
    duration_ms: Mapped[int] = mapped_column(Integer, default=0)
    error: Mapped[str] = mapped_column(String(300), default="")


class KpiSnapshot(AppendOnly, Model):
    """FR-BI-02: KPI values fixed at a reporting date."""

    __tablename__ = "kpi_snapshots"

    report_date: Mapped[date] = mapped_column(Date, index=True)
    values: Mapped[str] = mapped_column(Text)


class Ticket(Model):
    """FR-SUP-01: support tickets (messages live in chat.Message with ticket_id)."""

    __tablename__ = "tickets"

    number: Mapped[str] = mapped_column(String(30), unique=True)
    company_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("companies.id"), index=True)
    user_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id"))
    deal_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("deals.id"))
    category: Mapped[str] = mapped_column(String(40))
    priority: Mapped[str] = mapped_column(String(10), default="normal")
    subject: Mapped[str] = mapped_column(String(300))
    status: Mapped[str] = mapped_column(String(20), default="open", index=True)  # open / in_progress / resolved
    assigned_to: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("users.id"))
    sla_due_at: Mapped[datetime | None] = mapped_column(AwareDateTime)


class CalcResult(Model):
    """FR-CALC-05: result stored with inputs and methodology version."""

    __tablename__ = "calc_results"

    company_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("companies.id"), index=True)
    user_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    kind: Mapped[str] = mapped_column(String(20))  # trip_cost / client_price
    methodology_version: Mapped[str] = mapped_column(String(20))
    inputs: Mapped[str] = mapped_column(Text)
    result: Mapped[str] = mapped_column(Text)


class ApprovalRequest(Model):
    """SEC-AZ-05: a privileged operation waits for a second staff member before it is executed."""

    __tablename__ = "approval_requests"

    kind: Mapped[str] = mapped_column(String(30), index=True)  # company_block / tariff_change / status_rollback / storno
    object_id: Mapped[str] = mapped_column(String(64), default="")
    payload: Mapped[str] = mapped_column(Text, default="{}")
    summary: Mapped[str] = mapped_column(String(300), default="")
    reason: Mapped[str] = mapped_column(String(500), default="")
    status: Mapped[str] = mapped_column(String(10), default="pending", index=True)  # pending/executed/rejected/failed/expired
    requested_by: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id"))
    decided_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("users.id"))
    decided_at: Mapped[datetime | None] = mapped_column(AwareDateTime)
    decision_note: Mapped[str] = mapped_column(String(500), default="")
    expires_at: Mapped[datetime] = mapped_column(AwareDateTime)


class AntifraudRule(Model):
    """SEC-FRD-01: rules with thresholds and actions, changed by an administrator without a release."""

    __tablename__ = "antifraud_rules"

    code: Mapped[str] = mapped_column(String(40), unique=True)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    action: Mapped[str] = mapped_column(String(10), default="review")  # allow / flag / review / restrict / block
    severity: Mapped[str] = mapped_column(String(10), default="medium")
    threshold: Mapped[int] = mapped_column(Integer, default=0)   # for velocity rules: events per window
    window_minutes: Mapped[int] = mapped_column(Integer, default=60)
    description: Mapped[str] = mapped_column(String(300), default="")


class DeviceEvent(Model):
    """SEC-FRD-02/03: device and network marks at registration, login and key actions (purged by retention)."""

    __tablename__ = "device_events"

    action: Mapped[str] = mapped_column(String(30), index=True)
    device_id: Mapped[str] = mapped_column(String(64), default="", index=True)
    ip: Mapped[str] = mapped_column(String(64), default="", index=True)
    user_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, index=True)
    company_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, index=True)


class SecurityAlert(Model):
    """SEC-LOG-06: correlated security events for the security officer."""

    __tablename__ = "security_alerts"

    kind: Mapped[str] = mapped_column(String(40), index=True)
    severity: Mapped[str] = mapped_column(String(10), default="medium")
    user_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    details: Mapped[str] = mapped_column(Text, default="{}")
    dedup_key: Mapped[str] = mapped_column(String(120), unique=True)
    status: Mapped[str] = mapped_column(String(10), default="open", index=True)  # open / closed
    closed_by: Mapped[uuid.UUID | None] = mapped_column(Uuid)


class ProductEvent(Model):
    """FR-BI-07: interface funnel events without personal data (anonymous session hash only)."""

    __tablename__ = "product_events"

    name: Mapped[str] = mapped_column(String(40), index=True)
    anon_id: Mapped[str] = mapped_column(String(16), index=True)
    role: Mapped[str] = mapped_column(String(20), default="")


class ProcessingRecord(Model):
    """SEC-DAT-10/11: register of personal data processing, recipients and cross-border transfers."""

    __tablename__ = "processing_records"

    code: Mapped[str] = mapped_column(String(40), unique=True)
    purpose: Mapped[str] = mapped_column(String(300))
    data_categories: Mapped[str] = mapped_column(String(500))
    legal_basis: Mapped[str] = mapped_column(String(300))
    recipient: Mapped[str] = mapped_column(String(200), default="")      # third party or processor; "" = AbdEX only
    cross_border: Mapped[bool] = mapped_column(Boolean, default=False)
    countries: Mapped[str] = mapped_column(String(200), default="")      # ISO codes for cross-border transfers
    safeguards: Mapped[str] = mapped_column(String(500), default="")
    retention: Mapped[str] = mapped_column(String(200), default="")
    adapter: Mapped[str] = mapped_column(String(40), default="")         # integration adapter that sends the data
    active: Mapped[bool] = mapped_column(Boolean, default=True)
