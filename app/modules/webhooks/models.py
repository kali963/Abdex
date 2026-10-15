"""Webhook endpoints of a company and the delivery journal (FR-API-03)."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import Boolean, ForeignKey, Integer, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.db import AwareDateTime, Model


class WebhookEndpoint(Model):
    __tablename__ = "webhook_endpoints"

    company_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("companies.id"), index=True)
    url: Mapped[str] = mapped_column(String(500))
    secret: Mapped[str] = mapped_column(String(64))  # HMAC key shown once to the owner
    events: Mapped[str] = mapped_column(String(300), default="*")
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    failures_in_row: Mapped[int] = mapped_column(Integer, default=0)


class WebhookDelivery(Model):
    __tablename__ = "webhook_deliveries"

    endpoint_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("webhook_endpoints.id"), index=True)
    event: Mapped[str] = mapped_column(String(60))
    event_id: Mapped[str] = mapped_column(String(64), index=True)
    payload: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(String(10), default="pending", index=True)  # pending / delivered / failed
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    next_attempt_at: Mapped[datetime | None] = mapped_column(AwareDateTime, index=True)
    last_status_code: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str] = mapped_column(String(300), default="")
    delivered_at: Mapped[datetime | None] = mapped_column(AwareDateTime)
