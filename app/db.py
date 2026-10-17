"""Database engine, session and base model.

NFR-DB-01: primary keys are time-ordered UUIDs (UUIDv7).
NFR-DB-02: every table carries audit columns.
NFR-DB-05: append-only tables refuse UPDATE/DELETE at the ORM level; on PostgreSQL the
migration additionally installs triggers (see alembic/versions).
"""
from __future__ import annotations

import os
import secrets
import time
import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Text, Uuid, create_engine, event
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker
from sqlalchemy.types import TypeDecorator

from app.config import settings


def uuid7() -> uuid.UUID:
    ms = int(time.time() * 1000)
    rand = secrets.randbits(74)
    value = (ms & ((1 << 48) - 1)) << 80
    value |= 0x7 << 76
    value |= ((rand >> 62) & 0xFFF) << 64
    value |= 0b10 << 62
    value |= rand & ((1 << 62) - 1)
    return uuid.UUID(int=value)


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class AwareDateTime(TypeDecorator):
    """Stores timestamps as UTC and always returns aware datetimes (FR-LOC-03)."""

    impl = DateTime(timezone=True)
    cache_ok = True

    def process_bind_param(self, value, dialect):
        if value is not None and value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        if value is not None:
            value = value.astimezone(timezone.utc)
        return value

    def process_result_value(self, value, dialect):
        if value is not None and value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value


class Encrypted(TypeDecorator):
    """Field encrypted at the application level (SEC-DAT-02, NFR-DB-08). `column` is bound as associated data."""

    impl = Text
    cache_ok = True

    def __init__(self, column: str, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.column = column

    def process_bind_param(self, value, dialect):
        from app.core.crypto import encrypt

        return encrypt(value, self.column)

    def process_result_value(self, value, dialect):
        from app.core.crypto import decrypt

        return decrypt(value, self.column)


class Model(Base):
    """Abstract base: UUIDv7 key + audit columns (NFR-DB-01, NFR-DB-02)."""

    __abstract__ = True

    id: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid7)
    created_at: Mapped[datetime] = mapped_column(AwareDateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(AwareDateTime, default=utcnow, onupdate=utcnow, nullable=False)
    created_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    updated_by: Mapped[uuid.UUID | None] = mapped_column(Uuid, nullable=True)
    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class AppendOnlyError(RuntimeError):
    pass


class AppendOnly:
    """Mixin marker: rows may be inserted but never updated or deleted."""

    __append_only__ = True


@event.listens_for(Session, "before_flush")
def _guard_append_only(session: Session, flush_context, instances) -> None:
    for obj in list(session.dirty) + list(session.deleted):
        if getattr(obj, "__append_only__", False):
            if obj in session.deleted or session.is_modified(obj, include_collections=False):
                raise AppendOnlyError(f"{type(obj).__name__} is append-only")


def _make_engine():
    url = settings.database_url
    kwargs: dict = {"future": True}
    if url.startswith("sqlite"):
        path = url.replace("sqlite:///", "", 1)
        if path and path != ":memory:":
            os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        kwargs["connect_args"] = {"check_same_thread": False}
    else:
        kwargs["pool_pre_ping"] = True
    eng = create_engine(url, **kwargs)
    if url.startswith("sqlite"):
        @event.listens_for(eng, "connect")
        def _fk_on(dbapi_conn, _):  # NFR-DB-03: enforce foreign keys on SQLite too
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA foreign_keys=ON")
            cur.close()
    return eng


engine = _make_engine()
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)

# FR-BI-06: heavy reports read from a replica when ANALYTICS_DATABASE_URL is set (a streaming replica of the main
# PostgreSQL); without it they read the main database. Row-level security applies there just the same.
_analytics_url = os.getenv("ANALYTICS_DATABASE_URL", "")
analytics_engine = create_engine(_analytics_url, future=True, pool_pre_ping=True) if _analytics_url else engine
AnalyticsSession = sessionmaker(bind=analytics_engine, autoflush=False, expire_on_commit=False)


def get_analytics_db():
    db = AnalyticsSession()
    try:
        yield db
    finally:
        db.close()


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
