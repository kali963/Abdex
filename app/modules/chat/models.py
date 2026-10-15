"""Deal chat and support threads (M7). Messages are never edited or deleted (FR-CHAT-04)."""
from __future__ import annotations

import uuid

from sqlalchemy import ForeignKey, String, Text, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.db import AppendOnly, Model


class Message(AppendOnly, Model):
    __tablename__ = "messages"

    deal_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("deals.id"), index=True)
    ticket_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("tickets.id"), index=True)
    author_user_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("users.id"))
    author_company_id: Mapped[uuid.UUID | None] = mapped_column(Uuid)
    kind: Mapped[str] = mapped_column(String(10), default="user")  # user / system / staff
    body: Mapped[str] = mapped_column(Text)
    attachment_file_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("stored_files.id"))
    flags: Mapped[str] = mapped_column(String(100), default="")  # e.g. contact_leak


class MessageHidden(AppendOnly, Model):
    """Moderator hides a message; the original stays intact for the audit trail."""

    __tablename__ = "message_hidden"

    message_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("messages.id"), unique=True)
    reason: Mapped[str] = mapped_column(String(300))


class MessageRead(Model):
    __tablename__ = "message_reads"
    __table_args__ = (UniqueConstraint("message_id", "user_id", name="uq_message_read"),)

    message_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("messages.id"), index=True)
    user_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id"))
