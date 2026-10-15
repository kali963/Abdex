"""In-app notifications and an outbox with delivery journal (M8)."""
from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import ForeignKey, Integer, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.db import AwareDateTime, Model


class Notification(Model):
    __tablename__ = "notifications"

    user_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id"), index=True)
    event: Mapped[str] = mapped_column(String(40))
    params: Mapped[str] = mapped_column(Text, default="{}")
    link: Mapped[str] = mapped_column(String(300), default="")
    read_at: Mapped[datetime | None] = mapped_column(AwareDateTime)


class OutboxMessage(Model):
    """FR-NTF-01: queue with retries, dedup and per-message delivery log."""

    __tablename__ = "outbox"

    channel: Mapped[str] = mapped_column(String(10))  # telegram / email / sms / push
    user_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("users.id"))
    recipient: Mapped[str] = mapped_column(String(255), default="")
    event: Mapped[str] = mapped_column(String(40))
    body: Mapped[str] = mapped_column(Text)
    dedup_key: Mapped[str] = mapped_column(String(200), unique=True)
    status: Mapped[str] = mapped_column(String(10), default="queued", index=True)  # queued / sent / failed
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    next_attempt_at: Mapped[datetime | None] = mapped_column(AwareDateTime)
    last_error: Mapped[str] = mapped_column(String(300), default="")
    sent_at: Mapped[datetime | None] = mapped_column(AwareDateTime)


class ChannelLink(Model):
    """Telegram chat binding (FR-NTF-02) and per-user channel preferences."""

    __tablename__ = "channel_links"

    user_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id"), index=True)
    channel: Mapped[str] = mapped_column(String(10))
    address: Mapped[str] = mapped_column(String(100), default="")
    link_code: Mapped[str] = mapped_column(String(20), default="")
    disabled_events: Mapped[str] = mapped_column(Text, default="")
