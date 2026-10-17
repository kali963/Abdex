"""Files, document templates, generated documents and signatures (M6)."""
from __future__ import annotations

import uuid
from datetime import date, datetime

from sqlalchemy import Boolean, Date, ForeignKey, Integer, String, Text, UniqueConstraint, Uuid
from sqlalchemy.orm import Mapped, mapped_column

from app.db import AppendOnly, AwareDateTime, Model


class StoredFile(Model):
    """SEC-FIL-04: system-generated storage key, original name kept separately."""

    __tablename__ = "stored_files"

    owner_company_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("companies.id"), index=True)
    storage_key: Mapped[str] = mapped_column(String(100), unique=True)
    original_name: Mapped[str] = mapped_column(String(255))
    content_type: Mapped[str] = mapped_column(String(100))
    size: Mapped[int] = mapped_column(Integer)
    sha256: Mapped[str] = mapped_column(String(64))
    scan_status: Mapped[str] = mapped_column(String(20), default="pending")  # pending / clean / infected
    meta: Mapped[str] = mapped_column(Text, default="{}")  # evidence metadata kept outside the file (SEC-FIL-03)


class DocumentTemplate(Model):
    """FR-DOC-02: versioned templates with a start date."""

    __tablename__ = "document_templates"
    __table_args__ = (UniqueConstraint("doc_type", "locale", "version", name="uq_template_version"),)

    doc_type: Mapped[str] = mapped_column(String(40))
    locale: Mapped[str] = mapped_column(String(5), default="ru")
    version: Mapped[int] = mapped_column(Integer, default=1)
    title: Mapped[str] = mapped_column(String(300))
    body: Mapped[str] = mapped_column(Text)
    valid_from: Mapped[date] = mapped_column(Date)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)


class Document(Model):
    __tablename__ = "documents"
    __table_args__ = (UniqueConstraint("doc_type", "number", name="uq_document_number"),)

    deal_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("deals.id"), index=True)
    company_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("companies.id"), index=True)
    doc_type: Mapped[str] = mapped_column(String(40))
    number: Mapped[str] = mapped_column(String(40))
    title: Mapped[str] = mapped_column(String(300))
    file_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("stored_files.id"))
    template_id: Mapped[uuid.UUID | None] = mapped_column(Uuid, ForeignKey("document_templates.id"))
    # FR-DOC-05: required / uploaded / checked / signed / rejected
    status: Mapped[str] = mapped_column(String(20), default="uploaded")
    reject_reason: Mapped[str] = mapped_column(String(300), default="")
    is_generated: Mapped[bool] = mapped_column(Boolean, default=False)
    sha256: Mapped[str] = mapped_column(String(64), default="")
    requires_signatures: Mapped[bool] = mapped_column(Boolean, default=False)


class DocumentCounter(Model):
    """FR-DOC-03: per-type per-year numbering, row-locked on increment."""

    __tablename__ = "document_counters"
    __table_args__ = (UniqueConstraint("doc_type", "year", name="uq_counter"),)

    doc_type: Mapped[str] = mapped_column(String(40))
    year: Mapped[int] = mapped_column(Integer)
    last_value: Mapped[int] = mapped_column(Integer, default=0)


class Signature(AppendOnly, Model):
    """FR-DOC-06 simple e-signature (code-confirmed); GOV-DS-07 distinguishes kinds."""

    __tablename__ = "signatures"
    __table_args__ = (UniqueConstraint("document_id", "company_id", name="uq_signature_company"),)

    document_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("documents.id"), index=True)
    user_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("users.id"))
    company_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("companies.id"))
    kind: Mapped[str] = mapped_column(String(20), default="simple")  # simple / qualified
    signed_at: Mapped[datetime] = mapped_column(AwareDateTime)
    ip: Mapped[str] = mapped_column(String(64), default="")
    document_hash: Mapped[str] = mapped_column(String(64))


class QualifiedSignature(AppendOnly, Model):
    """GOV-DS-04: the signature, the hash of the signed document and the server-side verification result are
    kept together as an immutable set (the document file itself is never rewritten)."""

    __tablename__ = "qualified_signatures"

    signature_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("signatures.id"), unique=True)
    document_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("documents.id"), index=True)
    package: Mapped[str] = mapped_column(Text)  # CMS (base64) or the development signer package (JSON)
    provider: Mapped[str] = mapped_column(String(40))
    document_hash: Mapped[str] = mapped_column(String(64))
    signer_iin: Mapped[str] = mapped_column(String(12), default="")
    signer_bin: Mapped[str] = mapped_column(String(12), default="")
    signer_name: Mapped[str] = mapped_column(String(300), default="")
    cert_serial: Mapped[str] = mapped_column(String(80), default="")
    cert_issuer: Mapped[str] = mapped_column(String(300), default="")
    cert_not_after: Mapped[datetime | None] = mapped_column(AwareDateTime)
    tsp_time: Mapped[datetime] = mapped_column(AwareDateTime)
    verify_result: Mapped[str] = mapped_column(Text, default="{}")


class TransportDocRegistration(Model):
    """GOV-TR-03/05: registration of an electronic transport document in the state system, with statuses and
    errors; a paper document (no connection) is entered later without breaking the deal history."""

    __tablename__ = "transport_doc_registrations"

    document_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("documents.id"), unique=True)
    deal_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("deals.id"), index=True)
    mode: Mapped[str] = mapped_column(String(10), default="electronic")  # electronic / paper
    paper_number: Mapped[str] = mapped_column(String(40), default="")
    status: Mapped[str] = mapped_column(String(12), default="pending", index=True)  # pending/registered/error/paper
    external_number: Mapped[str] = mapped_column(String(60), default="")
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str] = mapped_column(String(300), default="")
    registered_at: Mapped[datetime | None] = mapped_column(AwareDateTime)
    data: Mapped[str] = mapped_column(Text, default="{}")  # the data set sent (GOV-TR-02), kept for audit


class CustomsDossier(Model):
    """GOV-TR-06: data set for customs procedures on an international deal (Kazakhstan — China — CIS).
    Filled by both sides; the composition and the documents required depend on the destination
    (setting ``customs.rules``); exported as XML (preliminary information) and PDF."""

    __tablename__ = "customs_dossiers"

    deal_id: Mapped[uuid.UUID] = mapped_column(Uuid, ForeignKey("deals.id"), unique=True)
    status: Mapped[str] = mapped_column(String(10), default="draft")  # draft / ready
    data: Mapped[str] = mapped_column(Text, default="{}")
    ready_at: Mapped[datetime | None] = mapped_column(AwareDateTime)
