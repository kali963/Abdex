"""Security journal archive (SEC-LOG-04): kept at least 12 months, outside the database, tamper-evident.

The audit log in the database is append-only already (ORM guard + PostgreSQL triggers) and is never purged by
the retention job. In addition every new record is copied, hourly, into an archive of daily JSON-lines files
(``AUDIT_ARCHIVE_DIR``, a separate volume that only the worker writes and the backups copy off the server).

Each line carries an HMAC-SHA256 chained to the previous line, keyed with ``AUDIT_ARCHIVE_KEY`` (a secret that
is not stored in the database): changing, deleting, reordering or inserting a record anywhere breaks the chain
from that point, and without the key the chain cannot be rebuilt. ``python -m app.cli audit-verify`` checks
the whole archive and compares it with the database.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import os
from datetime import datetime
from pathlib import Path

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from app.config import settings

GENESIS = "0" * 64
BATCH = 5000
CURSOR = "audit.archive_cursor"
MIN_KEEP_DAYS = 365  # SEC-LOG-04: not less than 12 months


def archive_dir() -> Path:
    raw = os.getenv("AUDIT_ARCHIVE_DIR", "")
    return Path(raw) if raw else settings.storage_dir.parent / "audit-archive"


def _key() -> bytes:
    from app.core.secrets import secret

    raw = secret("AUDIT_ARCHIVE_KEY")
    if raw:
        return raw.encode()
    # development / tests: derived from the application key (production: preflight asks for a separate key)
    return hmac.new(settings.secret_key.encode(), b"audit-archive", hashlib.sha256).digest()


def _record(row) -> dict:
    return {"id": str(row.id), "at": row.created_at.isoformat(), "user_id": str(row.user_id or ""),
            "company_id": str(row.company_id or ""), "role": row.role, "action": row.action,
            "object_type": row.object_type, "object_id": row.object_id, "result": row.result, "ip": row.ip,
            "device": row.device, "request_id": row.request_id, "reason": row.reason, "details": row.details}


def _line_mac(key: bytes, prev: str, rec: dict) -> str:
    body = json.dumps(rec, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
    return hmac.new(key, (prev + "\n" + body).encode(), hashlib.sha256).hexdigest()


def _file_for(at: datetime) -> Path:
    from app.core.timeutil import local_date

    d = local_date(at)
    return archive_dir() / f"{d:%Y}" / f"{d:%m}" / f"audit-{d:%Y-%m-%d}.jsonl"


def export(db: Session) -> int:
    """Worker job: append the records written since the last run to the archive. Idempotent and resumable:
    the cursor (last record and last chain value) moves only after the lines are on disk."""
    from app.modules.accounts.models import AuditLog
    from app.modules.platform.service import get_setting, set_setting

    if db.get_bind().dialect.name == "postgresql":  # one exporter at a time (several workers, a manual run)
        from sqlalchemy import text

        if not db.execute(text("SELECT pg_try_advisory_xact_lock(7302916)")).scalar():
            return 0
    cur = get_setting(db, CURSOR, None) or {}
    prev = cur.get("mac", GENESIS)
    if not _heal(prev):
        import logging

        logging.getLogger("abdex.security").error("audit archive does not match its cursor: export stopped")
        return 0
    key = _key()
    q = select(AuditLog).order_by(AuditLog.created_at, AuditLog.id).limit(BATCH)
    if cur.get("at"):
        at = datetime.fromisoformat(cur["at"])
        q = q.where(or_(AuditLog.created_at > at, and_(AuditLog.created_at == at, AuditLog.id > _uuid(cur["id"]))))
    rows = db.execute(q).scalars().all()
    if not rows:
        return 0
    by_file: dict[Path, list[str]] = {}
    for row in rows:
        rec = _record(row)
        prev = _line_mac(key, prev, rec)
        by_file.setdefault(_file_for(row.created_at), []).append(
            json.dumps({"rec": rec, "mac": prev}, ensure_ascii=False, sort_keys=True, separators=(",", ":")))
    for path, lines in by_file.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "a", encoding="utf-8") as fh:
            fh.write("\n".join(lines) + "\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(path, 0o640)
    last = rows[-1]
    set_setting(db, CURSOR, {"at": last.created_at.isoformat(), "id": str(last.id), "mac": prev,
                             "count": int(cur.get("count", 0)) + len(rows)})
    db.flush()
    return len(rows)


def _heal(mac: str) -> bool:
    """The archive must end exactly at the committed cursor. Lines written after it belong to a run that crashed
    before its commit: they are cut off (the same records are exported again). If the cursor's line is nowhere,
    the archive was changed: nothing is written and ``audit-verify`` reports it."""
    files = sorted(archive_dir().rglob("audit-*.jsonl"))
    if mac == GENESIS:
        for f in files:
            _set_aside(f, f.read_text(encoding="utf-8").splitlines())
            f.unlink()
        return True
    for i in range(len(files) - 1, -1, -1):
        lines = files[i].read_text(encoding="utf-8").splitlines()
        for k in range(len(lines) - 1, -1, -1):
            try:
                found = json.loads(lines[k]).get("mac") == mac
            except ValueError:
                found = False
            if found:
                if k != len(lines) - 1:
                    _set_aside(files[i], lines[k + 1:])
                    files[i].write_text("\n".join(lines[:k + 1]) + "\n", encoding="utf-8")
                for later in files[i + 1:]:
                    _set_aside(later, later.read_text(encoding="utf-8").splitlines())
                    later.unlink()
                return True
    return False


def _set_aside(path: Path, lines: list[str]) -> None:
    """Never destroy security records: lines beyond the cursor (a crashed run, or a database restored from an
    older backup — then they are records the database no longer has) are kept in ``orphaned/`` for review."""
    if not lines:
        return
    import time

    target = archive_dir() / "orphaned" / f"orphan-{int(time.time())}-{path.name}"
    target.parent.mkdir(parents=True, exist_ok=True)
    with open(target, "a", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    import logging

    logging.getLogger("abdex.security").warning("audit archive: %d line(s) beyond the cursor set aside in %s",
                                                len(lines), target.name)


def _uuid(value: str):
    import uuid

    return uuid.UUID(value)


def verify(db: Session | None = None) -> dict:
    """Recompute the chain over the whole archive; with ``db`` also compare with the database."""
    key = _key()
    prev, count, problems, first, last = GENESIS, 0, [], None, None
    files = sorted(archive_dir().rglob("audit-*.jsonl"))
    for path in files:
        with open(path, encoding="utf-8") as fh:
            for n, line in enumerate(fh, 1):
                if not line.strip():
                    continue
                try:
                    item = json.loads(line)
                    rec, mac = item["rec"], item["mac"]
                except (ValueError, KeyError, TypeError):
                    problems.append(f"{path.name}:{n}: unreadable line")
                    return _result(count, problems, files, first, last)
                expected = _line_mac(key, prev, rec)
                if not hmac.compare_digest(expected, mac):
                    problems.append(f"{path.name}:{n}: chain broken (record {rec.get('id')} changed, removed or "
                                    "inserted)")
                    return _result(count, problems, files, first, last)
                prev, count = mac, count + 1
                first = first or rec.get("at")
                last = rec.get("at")
    if db is not None:
        from app.modules.platform.service import get_setting

        cur = get_setting(db, CURSOR, None) or {}
        if cur.get("mac", GENESIS) != prev:
            problems.append("the archive does not end where the database cursor says (files missing or added)")
        if int(cur.get("count", 0)) != count:
            problems.append(f"records in the archive: {count}, exported according to the database: {cur.get('count', 0)}")
    return _result(count, problems, files, first, last)


def _result(count, problems, files, first, last) -> dict:
    return {"ok": not problems, "records": count, "files": len(files), "first": first, "last": last,
            "problems": problems}
