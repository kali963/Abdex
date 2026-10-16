"""Document generation, numbering, upload registry and simple e-signature (M6).

SEC-FIL-06: templates are rendered by plain placeholder substitution ($name / ${name}) —
no expression language, so user data can never execute anything.
FR-PVD-03: platform financial documents may not describe the subject as transportation.
"""
from __future__ import annotations

import io
import re
import string
from datetime import date
from pathlib import Path

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.audit import audit
from app.core.context import get_ctx
from app.core.errors import AppError, Conflict, NotFound, ValidationFailed
from app.core.security import sha256_hex
from app.core.storage import save_generated, storage
from app.db import utcnow
from app.modules.documents.models import Document, DocumentTemplate, Signature, StoredFile

FONT_DIR = Path(__file__).resolve().parent.parent.parent / "static" / "fonts"

DOC_PREFIX = {
    "contract_order": "ДЗ",      # договор-заявка
    "e_waybill": "ТТН",          # товарно-транспортная накладная (GOV-TR-02)
    "cmr_form": "CMR",           # международная накладная
    "transport_request": "ЗП",   # заявка на перевозку
    "power_of_attorney": "ДВ",
    "work_act": "АВР",
    "fee_invoice": "СЧ",
    "fee_act": "АКТ",
    "reconciliation_act": "АС",
    "dossier": "ДС",
    "waybill": "ТТН",
}
FINANCIAL_DOC_TYPES = ("fee_invoice", "fee_act", "reconciliation_act")
FORBIDDEN_FINANCIAL_PHRASES = ("услуги перевозки", "экспедирован", "доставка груза", "транспортные услуги",
                               "тасымалдау қызмет")
CLOSING_DOC_TYPES = ("waybill", "cmr", "unload_act")
UPLOAD_DOC_TYPES = ("waybill", "cmr", "unload_act", "seal_photo", "invoice_carrier", "other")


def validate_template_body(doc_type: str, body: str) -> None:
    if doc_type in FINANCIAL_DOC_TYPES:
        lowered = body.lower()
        for phrase in FORBIDDEN_FINANCIAL_PHRASES:
            if phrase in lowered:
                raise ValidationFailed({"body": "error.forbidden_phrase"}, phrase=phrase)
    if doc_type == "contract_order" and re.search(r"AbdEX[^.\n]{0,40}(перевозчик|экспедитор)", body, re.I):
        # FR-PVD-04: the platform is never a carrier or forwarder in contracts
        raise ValidationFailed({"body": "error.platform_as_carrier"})
    try:
        string.Template(body).substitute({k: "" for k in _placeholders(body)})
    except (ValueError, KeyError):
        raise ValidationFailed({"body": "error.template_syntax"})


def _placeholders(body: str) -> set[str]:
    return {m.group("named") or m.group("braced") for m in string.Template.pattern.finditer(body)
            if m.group("named") or m.group("braced")}


def active_template(db: Session, doc_type: str, locale: str = "ru") -> DocumentTemplate:
    today = utcnow().date()
    for loc in (locale, "ru"):
        tpl = db.execute(select(DocumentTemplate).where(DocumentTemplate.doc_type == doc_type,
                                                        DocumentTemplate.locale == loc,
                                                        DocumentTemplate.is_active.is_(True),
                                                        DocumentTemplate.valid_from <= today)
                         .order_by(DocumentTemplate.version.desc())).scalars().first()
        if tpl:
            return tpl
    raise AppError("template_missing", doc_type=doc_type)


def save_template_version(db: Session, doc_type: str, locale: str, title: str, body: str, valid_from: date
                          ) -> DocumentTemplate:
    """FR-DOC-02: each save is a new version; documents keep a link to the version used."""
    validate_template_body(doc_type, body)
    last = db.execute(select(DocumentTemplate).where(DocumentTemplate.doc_type == doc_type,
                                                     DocumentTemplate.locale == locale)
                      .order_by(DocumentTemplate.version.desc())).scalars().first()
    tpl = DocumentTemplate(doc_type=doc_type, locale=locale, version=(last.version + 1) if last else 1, title=title,
                           body=body, valid_from=valid_from, created_by=get_ctx().user_id)
    db.add(tpl)
    db.flush()
    audit(db, "template.saved", object_type="document_template", object_id=tpl.id,
          details={"doc_type": doc_type, "version": tpl.version})
    return tpl


def render_pdf(title: str, body: str) -> bytes:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.styles import ParagraphStyle
    from reportlab.lib.units import mm
    from reportlab.pdfbase import pdfmetrics
    from reportlab.pdfbase.ttfonts import TTFont
    from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer
    from xml.sax.saxutils import escape

    if "DejaVu" not in pdfmetrics.getRegisteredFontNames():
        pdfmetrics.registerFont(TTFont("DejaVu", str(FONT_DIR / "DejaVuSans.ttf")))
        pdfmetrics.registerFont(TTFont("DejaVu-Bold", str(FONT_DIR / "DejaVuSans-Bold.ttf")))
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, leftMargin=20 * mm, rightMargin=15 * mm, topMargin=15 * mm,
                            bottomMargin=15 * mm, title=title, author="AbdEX")
    h = ParagraphStyle("h", fontName="DejaVu-Bold", fontSize=13, leading=17, spaceAfter=8)
    p = ParagraphStyle("p", fontName="DejaVu", fontSize=9.5, leading=13)
    story = [Paragraph(escape(title), h)]
    for line in body.split("\n"):
        if line.strip() == "":
            story.append(Spacer(1, 5))
        elif line.startswith("## "):
            story.append(Paragraph(escape(line[3:]), ParagraphStyle("h2", parent=h, fontSize=11, spaceBefore=6)))
        else:
            story.append(Paragraph(escape(line), p))
    doc.build(story)
    return buf.getvalue()


def generate(db: Session, doc_type: str, context: dict, *, deal_id=None, company_id=None, locale: str = "ru",
             requires_signatures: bool = False, number: str | None = None) -> Document:
    """FR-DOC-01: generate from the active template version."""
    from app.modules.platform.service import next_number

    tpl = active_template(db, doc_type, locale)
    number = number or next_number(db, doc_type, DOC_PREFIX.get(doc_type, "DOC"))
    ctx = {k: ("" if v is None else str(v)) for k, v in context.items()}
    ctx.setdefault("number", number)
    ctx.setdefault("date", utcnow().strftime("%d.%m.%Y"))
    body = string.Template(tpl.body).safe_substitute(ctx)
    title = string.Template(tpl.title).safe_substitute(ctx)
    if doc_type in FINANCIAL_DOC_TYPES:
        validate_template_body(doc_type, body)  # guard against substituted text too
    pdf = render_pdf(title, body)
    f = save_generated(db, data=pdf, name=f"{doc_type}-{number}.pdf", content_type="application/pdf",
                       company_id=company_id)
    doc = Document(deal_id=deal_id, company_id=company_id, doc_type=doc_type, number=number, title=title,
                   file_id=f.id, template_id=tpl.id, status="required" if requires_signatures else "checked",
                   is_generated=True, sha256=f.sha256, requires_signatures=requires_signatures)
    db.add(doc)
    db.flush()
    audit(db, "document.generated", object_type="document", object_id=doc.id, details={"type": doc_type})
    return doc


def register_upload(db: Session, *, deal_id, company_id, doc_type: str, file: StoredFile) -> Document:
    if doc_type not in UPLOAD_DOC_TYPES:
        raise ValidationFailed({"doc_type": "error.invalid_choice"})
    from app.modules.platform.service import next_number

    doc = Document(deal_id=deal_id, company_id=company_id, doc_type=doc_type,
                   number=next_number(db, "upload", "UP"), title=file.original_name, file_id=file.id,
                   status="uploaded", sha256=file.sha256, created_by=get_ctx().user_id)
    db.add(doc)
    db.flush()
    audit(db, "document.uploaded", object_type="document", object_id=doc.id, details={"type": doc_type})
    return doc


def deal_documents(db: Session, deal_id) -> list[Document]:
    return list(db.execute(select(Document).where(Document.deal_id == deal_id).order_by(Document.created_at)).scalars())


def signatures(db: Session, document_id) -> list[Signature]:
    return list(db.execute(select(Signature).where(Signature.document_id == document_id)).scalars())


def sign_simple(db: Session, doc: Document, *, user, company_id, code: str) -> Signature:
    """FR-DOC-06: confirmation by one-time code, fixing time, user, IP and document hash."""
    from app.modules.accounts.service import check_otp

    if not doc.requires_signatures:
        raise Conflict("not_signable")
    if any(s.company_id == company_id for s in signatures(db, doc.id)):
        raise Conflict("already_signed")
    if not check_otp(db, user.phone, "sign", code, context=str(doc.id)):
        raise ValidationFailed({"code": "error.code_invalid"})
    f = db.get(StoredFile, doc.file_id)
    current_hash = sha256_hex(storage.get(f.storage_key))
    if current_hash != doc.sha256:
        raise AppError("document_integrity_failed", status_code=409)
    sig = Signature(document_id=doc.id, user_id=user.id, company_id=company_id, kind="simple", signed_at=utcnow(),
                    ip=get_ctx().ip, document_hash=current_hash, created_by=user.id)
    db.add(sig)
    db.flush()
    audit(db, "document.signed", object_type="document", object_id=doc.id, details={"kind": "simple"})
    return sig


def mark_status(db: Session, doc: Document, status: str, reason: str = "") -> None:
    if status not in ("checked", "rejected"):
        raise ValidationFailed({"status": "error.invalid_choice"})
    doc.status = status
    doc.reject_reason = reason[:300]
    if status == "rejected" and doc.deal_id and doc.company_id and not doc.is_generated:
        from app.modules.deals.models import Deal
        from app.modules.rating.service import on_document_rejected

        deal = db.get(Deal, doc.deal_id)
        if deal is not None:
            on_document_rejected(db, deal, doc.company_id)  # FR-RAT-01: document quality
    audit(db, "document.status", object_type="document", object_id=doc.id, details={"status": status})


def get_file(db: Session, file_id) -> tuple[StoredFile, bytes]:
    f = db.get(StoredFile, file_id)
    if f is None or f.scan_status != "clean":
        raise NotFound()
    return f, storage.get(f.storage_key)


# ---------------------------------------------------------------- FR-DOC-09: bulk export by period

PERIOD_ZIP_MAX_DOCS = 2000
PERIOD_ZIP_MAX_BYTES = 200 * 1024 * 1024
_EXT = {"application/pdf": "pdf", "image/jpeg": "jpg", "image/png": "png"}


def period_documents(db: Session, company_id, date_from: date, date_to: date) -> list[tuple[Document, str]]:
    """Documents of the company's deals (either side) and its own platform invoices/acts in the period."""
    from datetime import datetime as _dt
    from datetime import time as _time
    from datetime import timezone as _tz

    from sqlalchemy import or_

    from app.modules.deals.models import Deal

    start = _dt.combine(date_from, _time.min, tzinfo=_tz.utc)
    end = _dt.combine(date_to, _time.max, tzinfo=_tz.utc)
    deals = select(Deal.id).where(or_(Deal.client_company_id == company_id, Deal.carrier_company_id == company_id))
    rows = db.execute(
        select(Document, Deal.number).outerjoin(Deal, Deal.id == Document.deal_id)
        .where(Document.created_at >= start, Document.created_at <= end, Document.is_deleted.is_(False),
               Document.file_id.is_not(None),
               or_(Document.deal_id.in_(deals), Document.company_id == company_id))
        .order_by(Document.created_at).limit(PERIOD_ZIP_MAX_DOCS + 1)).all()
    # Platform fee documents of another company sit on the same deal: never hand them to the counterparty.
    fee_types = ("fee_invoice", "fee_act")
    return [(d, n or "") for d, n in rows if d.doc_type not in fee_types or d.company_id == company_id]


def period_zip(db: Session, company_id, date_from: date, date_to: date, labels: dict[str, str]) -> bytes:
    import csv
    import zipfile

    if date_to < date_from or (date_to - date_from).days > 366:
        raise ValidationFailed({"date_to": "error.period"})
    docs = period_documents(db, company_id, date_from, date_to)
    if not docs:
        raise AppError("export_empty", status_code=404)
    if len(docs) > PERIOD_ZIP_MAX_DOCS:
        raise AppError("export_too_large", limit=PERIOD_ZIP_MAX_DOCS)
    buf = io.BytesIO()
    inventory = io.StringIO()
    w = csv.writer(inventory, delimiter=";")
    w.writerow(["№", labels["deal"], labels["type"], labels["number"], labels["title"], labels["status"],
                labels["date"], "SHA-256", labels["file"]])
    total = 0
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for i, (doc, deal_number) in enumerate(docs, start=1):
            f = db.get(StoredFile, doc.file_id)
            if f is None or f.scan_status != "clean":
                continue
            data = storage.get(f.storage_key)
            total += len(data)
            if total > PERIOD_ZIP_MAX_BYTES:
                raise AppError("export_too_large", limit=PERIOD_ZIP_MAX_DOCS)
            folder = deal_number or "platform"
            name = f"{folder}/{doc.doc_type}-{doc.number}.{_EXT.get(f.content_type, 'bin')}".replace("..", ".")
            z.writestr(name, data)
            w.writerow([i, deal_number, labels.get(f"doc.{doc.doc_type}", doc.doc_type), doc.number, doc.title,
                        labels.get(f"st.{doc.status}", doc.status), doc.created_at.strftime("%d.%m.%Y %H:%M"),
                        f.sha256, name])
        z.writestr("inventory.csv", "﻿" + inventory.getvalue())
    return buf.getvalue()


# ---------------------------------------------------------------- qualified signature (FR-DOC-07, GOV-DS)


def sign_qualified(db: Session, doc: Document, *, user, company, package: str):
    """Verified on the server; only a valid signature gives the document the signed status (GOV-DS-02)."""
    import json as _json

    from app.modules.documents import eds
    from app.modules.documents.models import QualifiedSignature
    from app.modules.platform.service import flag_enabled, get_setting

    if not flag_enabled(db, "qualified_signature", company.id):
        raise AppError("qualified_signature_off", status_code=403)
    if not doc.requires_signatures:
        raise Conflict("not_signable")
    if any(s.company_id == company.id for s in signatures(db, doc.id)):
        raise Conflict("already_signed")
    if not package or len(package) > 200_000:
        raise ValidationFailed({"package": "error.required"})
    f = db.get(StoredFile, doc.file_id)
    data = storage.get(f.storage_key)
    current_hash = sha256_hex(data)
    if current_hash != doc.sha256:
        raise AppError("document_integrity_failed", status_code=409)
    now = utcnow()
    revoked = set(get_setting(db, "eds.revoked_serials", []) or [])
    result = eds.verifier().verify(package, data, signed_at=now, expected_bin=company.bin_iin, revoked=revoked)
    audit(db, "document.eds_verified", object_type="document", object_id=doc.id,
          result="ok" if result.valid else "denied", details={"checks": result.checks, "provider": result.provider})
    if not result.valid:
        failed = [k for k, v in result.checks.items() if not v] or [result.error or "invalid"]
        raise AppError("eds_invalid", status_code=422, checks=", ".join(failed))
    sig = Signature(document_id=doc.id, user_id=user.id, company_id=company.id, kind="qualified",
                    signed_at=result.signed_at or now, ip=get_ctx().ip, document_hash=current_hash, created_by=user.id)
    db.add(sig)
    db.flush()
    s = result.signer
    not_after = None
    if s.get("not_after"):
        from datetime import datetime as _dt

        not_after = _dt.fromisoformat(str(s["not_after"]).replace("Z", "+00:00"))
    db.add(QualifiedSignature(signature_id=sig.id, document_id=doc.id, package=package, provider=result.provider,
                              document_hash=current_hash, signer_iin=str(s.get("iin", ""))[:12],
                              signer_bin=str(s.get("bin", ""))[:12], signer_name=str(s.get("name", ""))[:300],
                              cert_serial=str(s.get("serial", ""))[:80], cert_issuer=str(s.get("issuer", ""))[:300],
                              cert_not_after=not_after, tsp_time=result.signed_at or now,
                              verify_result=_json.dumps(result.as_dict(), ensure_ascii=False), created_by=user.id))
    db.flush()
    audit(db, "document.signed", object_type="document", object_id=doc.id, details={"kind": "qualified"})
    return sig


def reverify_qualified(db: Session, doc: Document) -> list[dict]:
    """GOV-DS-05: repeat the check at any time; validity is judged at the stored signing time."""
    from app.modules.documents import eds
    from app.modules.documents.models import QualifiedSignature
    from app.modules.platform.service import get_setting

    f = db.get(StoredFile, doc.file_id)
    data = storage.get(f.storage_key)
    revoked = set(get_setting(db, "eds.revoked_serials", []) or [])
    out = []
    for q in db.execute(select(QualifiedSignature).where(QualifiedSignature.document_id == doc.id)).scalars():
        sig = db.get(Signature, q.signature_id)
        from app.modules.accounts.models import Company

        company = db.get(Company, sig.company_id)
        res = eds.verifier().verify(q.package, data, signed_at=q.tsp_time, expected_bin=company.bin_iin, revoked=revoked)
        out.append({"company": company.name, "valid": res.valid, "checks": res.checks, "signer": q.signer_name,
                    "signed_at": q.tsp_time, "not_after": q.cert_not_after})
        audit(db, "document.eds_reverified", object_type="document", object_id=doc.id,
              result="ok" if res.valid else "denied", details={"checks": res.checks})
    return out


def qualified_signatures(db: Session, document_id) -> list:
    from app.modules.documents.models import QualifiedSignature

    return list(db.execute(select(QualifiedSignature).where(QualifiedSignature.document_id == document_id)).scalars())
