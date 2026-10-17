"""Document recognition (M6): data read from uploaded verification documents for the moderator.

* PDF with a text layer (most scans from e-government services and scanners with OCR): the text is extracted
  locally with pypdf — nothing leaves the platform.
* Images and PDFs without text: an external OCR service when ``OCR_SERVICE_URL`` is configured (https POST of
  the file, JSON ``{"text": ...}`` back); otherwise the document is left for manual reading.

From the text the platform picks out BIN/IIN (12 digits with a valid control digit), dates, vehicle plates and
VIN, and compares them with what the company declared: a BIN or plate that does not match goes to the moderator
as a signal (never an automatic rejection, FR-KYC-07). The moderator sees the recognised values next to the file.
"""
from __future__ import annotations

import io
import json
import os
import re
from datetime import date

from app.db import utcnow

from sqlalchemy.orm import Session

from app.modules.integrations.base import Adapter, IntegrationUnavailable

MAX_PAGES = 10
MAX_CHARS = 50_000
_DIGITS12 = re.compile(r"(?<!\d)(\d{12})(?!\d)")
_DATE = re.compile(r"(?<!\d)(\d{2})[./](\d{2})[./](\d{4})(?!\d)")
_PLATE = re.compile(r"(?<![A-ZА-Я0-9])(\d{3}\s?[A-Z]{2,3}\s?\d{2})(?![A-Z0-9])")
_VIN = re.compile(r"(?<![A-Z0-9])([A-HJ-NPR-Z0-9]{17})(?![A-Z0-9])")
_EXPIRY_HINT = re.compile(r"(действ\w*\s+до|срок\s+действия|дейін|valid\s+until|expir\w*)", re.I)


class RecognitionAdapter(Adapter):
    name = "recognition"
    personal_data = True  # documents carry IIN, names, addresses
    retries = 0
    timeout = 20.0

    provider = "pdf-text+ocr"

    def read(self, data: bytes, content_type: str) -> str:
        return self.call("read", lambda: self._read(data, content_type), basis="consent", summary=content_type)

    def _read(self, data: bytes, content_type: str) -> str:
        text = ""
        if content_type == "application/pdf":
            from pypdf import PdfReader

            try:
                reader = PdfReader(io.BytesIO(data))
                for page in reader.pages[:MAX_PAGES]:
                    text += (page.extract_text() or "") + "\n"
                    if len(text) > MAX_CHARS:
                        break
            except Exception:  # noqa: BLE001 — a damaged PDF is simply not readable
                text = ""
        if len(text.strip()) < 20 and os.getenv("OCR_SERVICE_URL"):
            text = _ocr_service(data, content_type)
        return text[:MAX_CHARS]


def _ocr_service(data: bytes, content_type: str) -> str:
    import urllib.request

    url = os.getenv("OCR_SERVICE_URL", "")
    if not url.startswith("https://"):
        raise IntegrationUnavailable("OCR_SERVICE_URL must be https")
    req = urllib.request.Request(url, data=data, method="POST",  # noqa: S310 — configured https service
                                 headers={"Content-Type": content_type,
                                          "Authorization": f"Bearer {os.getenv('OCR_SERVICE_TOKEN', '')}"})
    with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310 — configured https service
        return str(json.loads(resp.read(1_000_000)).get("text", ""))


adapter = RecognitionAdapter()


def _valid_bin(x: str) -> bool:
    from app.modules.accounts.service import bin_control_digit

    cd = bin_control_digit(x[:11])
    return cd is not None and cd == int(x[11])


def extract(text: str) -> dict:
    up = (text or "").upper()
    ids = sorted({m for m in _DIGITS12.findall(text or "") if _valid_bin(m)})
    dates = []
    for d, m, y in _DATE.findall(text or ""):
        try:
            dates.append(date(int(y), int(m), int(d)))
        except ValueError:
            continue
    expiry = None
    for match in _EXPIRY_HINT.finditer(text or ""):
        tail = _DATE.search((text or "")[match.end(): match.end() + 40])
        if tail:
            try:
                expiry = date(int(tail.group(3)), int(tail.group(2)), int(tail.group(1)))
            except ValueError:
                pass
    plates = sorted({p.replace(" ", "") for p in _PLATE.findall(up)})
    vins = sorted(set(_VIN.findall(up)))
    return {"ids": ids[:10], "dates": [d.isoformat() for d in sorted(set(dates))][:20],
            "expiry": expiry.isoformat() if expiry else None, "plates": plates[:10], "vins": vins[:5],
            "chars": len(text or "")}


def recognize(db: Session, doc, company) -> dict:
    """Run on upload: store what was read, compare with the declared data, raise a signal on a mismatch."""
    from app.core.storage import storage
    from app.modules.documents.models import StoredFile
    from app.modules.fleet.models import Vehicle
    from app.modules.platform.service import raise_alert

    f = db.get(StoredFile, doc.file_id)
    try:
        text = adapter.read(storage.get(f.storage_key), f.content_type)
    except IntegrationUnavailable:
        text = ""
    found = extract(text)
    found["at"] = utcnow().isoformat(timespec="seconds")
    checks = {}
    if doc.subject_type == "company" and found["ids"]:
        checks["bin"] = company.bin_iin in found["ids"]
    if doc.subject_type == "vehicle" and doc.doc_type == "tech_passport" and (found["plates"] or found["vins"]):
        v = db.get(Vehicle, doc.subject_id)
        if v is not None:
            checks["plate"] = (v.plate in found["plates"]) or (bool(v.vin) and v.vin.upper() in found["vins"])
    found["checks"] = checks
    if doc.expires_on is None and found["expiry"]:
        doc.expires_on = date.fromisoformat(found["expiry"])  # the moderator still confirms the document
        found["expiry_applied"] = True
    doc.recognized = json.dumps(found, ensure_ascii=False)
    if any(v is False for v in checks.values()):
        raise_alert(db, "doc_data_mismatch", company_id=company.id,
                    details={"doc": str(doc.id), "type": doc.doc_type, "checks": checks})
    return found
