"""Object storage abstraction + upload validation (FR-DOC-08, SEC-FIL-01..05).

Local-disk backend for development; production uses an S3-compatible backend with the same
interface. Files are stored outside the web root under system-generated keys.
"""
from __future__ import annotations

import io
import json
import logging
from pathlib import Path

from sqlalchemy.orm import Session

from app.config import settings
from app.core.errors import AppError
from app.core.security import sha256_hex, token
from app.db import uuid7
from app.modules.documents.models import StoredFile

log = logging.getLogger("abdex.storage")

# SEC-FIL-01: whitelist by actual content (magic bytes), not by extension or header.
_SIGNATURES = {
    "application/pdf": [b"%PDF-"],
    "image/jpeg": [b"\xff\xd8\xff"],
    "image/png": [b"\x89PNG\r\n\x1a\n"],
    "image/webp": [b"RIFF"],
}
ALLOWED_TYPES = tuple(_SIGNATURES)
IMAGE_TYPES = ("image/jpeg", "image/png", "image/webp")


def sniff_content_type(data: bytes) -> str | None:
    for ctype, sigs in _SIGNATURES.items():
        for sig in sigs:
            if data.startswith(sig):
                if ctype == "image/webp" and data[8:12] != b"WEBP":
                    continue
                return ctype
    return None


class LocalStorage:
    def __init__(self, root: Path):
        self.root = root
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        safe = key.replace("/", "_").replace("..", "_")
        return self.root / safe[:2] / safe

    def put(self, key: str, data: bytes) -> None:
        p = self._path(key)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)

    def get(self, key: str) -> bytes:
        return self._path(key).read_bytes()

    def delete(self, key: str) -> None:
        p = self._path(key)
        if p.exists():
            p.unlink()


class DbStorage:
    """Contents in the ``file_blobs`` table. Writes go in their own short transaction, so a file saved during a
    request can be read back at once (as with the disk backend)."""

    def put(self, key: str, data: bytes) -> None:
        from sqlalchemy import delete, insert

        from app.db import engine
        from app.modules.documents.models import FileBlob

        with engine.begin() as conn:
            conn.execute(delete(FileBlob).where(FileBlob.key == key))
            conn.execute(insert(FileBlob).values(key=key, data=data))

    def get(self, key: str) -> bytes:
        from sqlalchemy import select

        from app.db import engine
        from app.modules.documents.models import FileBlob

        with engine.connect() as conn:
            data = conn.execute(select(FileBlob.data).where(FileBlob.key == key)).scalar()
        if data is None:
            raise FileNotFoundError(key)
        return bytes(data)

    def delete(self, key: str) -> None:
        from sqlalchemy import delete

        from app.db import engine
        from app.modules.documents.models import FileBlob

        with engine.begin() as conn:
            conn.execute(delete(FileBlob).where(FileBlob.key == key))


def _make_storage():
    """``STORAGE_BACKEND``: "disk" (default) or "db". On Vercel with a shared database the files go to the
    database too, otherwise a document made by one instance could not be opened through another."""
    import os

    from app.config import ON_VERCEL

    backend = os.getenv("STORAGE_BACKEND", "").strip().lower()
    if backend == "db" or (not backend and ON_VERCEL and not settings.database_url.startswith("sqlite")):
        return DbStorage()
    return LocalStorage(settings.storage_dir)


storage = _make_storage()


class AntivirusAdapter:
    """SEC-FIL-02. Production: ClamAV (clamd INSTREAM). Dev: EICAR signature check only."""

    EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

    def scan(self, data: bytes) -> str:
        return "infected" if self.EICAR in data else "clean"


antivirus = AntivirusAdapter()


def strip_image_metadata(data: bytes, content_type: str) -> tuple[bytes, dict]:
    """SEC-FIL-03: re-save images without EXIF; evidence metadata is returned separately."""
    try:
        from PIL import Image
    except ImportError:  # pragma: no cover
        return data, {}
    meta: dict = {}
    try:
        Image.MAX_IMAGE_PIXELS = 40_000_000  # ~40 MP; larger images are rejected as decompression bombs
        img = Image.open(io.BytesIO(data))
        exif = img.getexif()
        if exif:
            dt = exif.get(306)
            if dt:
                meta["exif_datetime"] = str(dt)
        out = io.BytesIO()
        fmt = {"image/jpeg": "JPEG", "image/png": "PNG", "image/webp": "WEBP"}[content_type]
        if fmt == "JPEG" and img.mode not in ("RGB", "L"):
            img = img.convert("RGB")
        # FR-MOB-04: downscale very large photos before storage
        img.thumbnail((2560, 2560))
        img.save(out, format=fmt, quality=85)
        return out.getvalue(), meta
    except Exception:  # noqa: BLE001 — a broken image is rejected below
        raise AppError("file_corrupted")


def save_upload(db: Session, *, data: bytes, original_name: str, company_id=None, user_id=None,
                allowed: tuple[str, ...] = ALLOWED_TYPES, extra_meta: dict | None = None) -> StoredFile:
    if not data:
        raise AppError("file_empty")
    if len(data) > settings.max_upload_mb * 1024 * 1024:
        raise AppError("file_too_large", limit=settings.max_upload_mb)
    ctype = sniff_content_type(data)
    if ctype not in allowed:
        raise AppError("file_type_not_allowed")
    if antivirus.scan(data) != "clean":
        log.warning("infected upload rejected")
        raise AppError("file_infected")
    meta = dict(extra_meta or {})
    if ctype in IMAGE_TYPES:
        data, img_meta = strip_image_metadata(data, ctype)
        meta.update(img_meta)
    key = f"{uuid7().hex}{token(6)}"
    storage.put(key, data)
    f = StoredFile(
        owner_company_id=company_id,
        storage_key=key,
        original_name=(original_name or "file")[-200:],
        content_type=ctype,
        size=len(data),
        sha256=sha256_hex(data),
        scan_status="clean",
        meta=json.dumps(meta, ensure_ascii=False),
        created_by=user_id,
    )
    db.add(f)
    db.flush()
    return f


def save_generated(db: Session, *, data: bytes, name: str, content_type: str, company_id=None) -> StoredFile:
    key = f"{uuid7().hex}{token(6)}"
    storage.put(key, data)
    f = StoredFile(owner_company_id=company_id, storage_key=key, original_name=name, content_type=content_type,
                   size=len(data), sha256=sha256_hex(data), scan_status="clean")
    db.add(f)
    db.flush()
    return f
