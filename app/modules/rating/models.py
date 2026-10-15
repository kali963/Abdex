"""Rating events: the only way a rating changes (FR-RAT-01/02)."""
from __future__ import annotations

import uuid

from sqlalchemy import ForeignKey, Integer, String, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.db import AppendOnly, Model

# Objective events recorded by the system. "correction" is the only manual kind and always has an author and reason.
KIND_COMPLETED = "deal_completed"
KIND_BREAKDOWN = "breakdown"          # deal broken after acceptance through the participant's fault (FR-BID-08)
KIND_LATE = "late_delivery"
KIND_DOC_REJECTED = "doc_rejected"
KIND_DISPUTE_LOST = "dispute_lost"
KIND_CORRECTION = "correction"
KINDS = (KIND_COMPLETED, KIND_BREAKDOWN, KIND_LATE, KIND_DOC_REJECTED, KIND_DISPUTE_LOST, KIND_CORRECTION)


class RatingEvent(AppendOnly, Model):
    __tablename__ = "rating_events"

    company_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("companies.id"), index=True)
    kind: Mapped[str] = mapped_column(String(20), index=True)
    deal_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("deals.id"))
    # Only for corrections: delta in hundredths of a rating point (−100…+100).
    delta: Mapped[int] = mapped_column(Integer, default=0)
    reason: Mapped[str] = mapped_column(String(500), default="")
