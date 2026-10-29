"""Integration adapter base (NFR-ARC-05, INT-GEN-01..07).

Every adapter gets: timeout, bounded retries with growing pause, circuit breaker, response
cache with TTL, a call journal and success/latency metrics. Adapters are switched on/off by a
feature flag and have a fallback scenario for when the external service is down.
"""
from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass
from typing import Any, Callable

from app.db import SessionLocal
from app.modules.platform.models import IntegrationCall

log = logging.getLogger("abdex.integrations")

# On SQLite a second write transaction would wait for the request's lock, so journal rows are
# buffered and flushed right after the request (and by the worker). PostgreSQL writes immediately.
_pending: list[dict] = []
_pending_lock = threading.Lock()


def _deferred() -> bool:
    from app.config import settings

    return settings.database_url.startswith("sqlite")


def flush_journal() -> int:
    with _pending_lock:
        rows = list(_pending)
        _pending.clear()
    if not rows:
        return 0
    db = SessionLocal()
    try:
        db.add_all([IntegrationCall(**r) for r in rows])
        db.commit()
    except Exception:  # noqa: BLE001
        db.rollback()
        log.exception("failed to flush integration journal")
    finally:
        db.close()
    return len(rows)


class IntegrationUnavailable(Exception):
    pass


@dataclass
class CircuitBreaker:
    failure_threshold: int = 5
    reset_after: float = 60.0
    failures: int = 0
    opened_at: float = 0.0

    @property
    def is_open(self) -> bool:
        if self.failures < self.failure_threshold:
            return False
        if time.monotonic() - self.opened_at > self.reset_after:
            return False  # half-open: allow one try
        return True

    def success(self) -> None:
        self.failures = 0

    def failure(self) -> None:
        self.failures += 1
        if self.failures >= self.failure_threshold:
            self.opened_at = time.monotonic()


QUOTA_SETTING = "integrations.daily_quota"
_quota_cache: tuple[float, dict] = (float("-inf"), {})  # monotonic time starts at boot
_quota_local: dict[str, int] = {}
_quota_lock = threading.Lock()


def _quotas() -> dict:
    """{adapter: calls per day} from the platform setting (/admin/settings), re-read once a minute."""
    global _quota_cache
    if time.monotonic() - _quota_cache[0] < 60:
        return _quota_cache[1]
    value: dict = {}
    db = SessionLocal()
    try:
        from app.modules.platform.service import get_setting

        raw = get_setting(db, QUOTA_SETTING, {}) or {}
        value = {str(k): int(v) for k, v in raw.items() if str(v).lstrip("-").isdigit()} if isinstance(raw, dict) else {}
    except Exception:  # noqa: BLE001 — a quota lookup never breaks a call
        log.warning("could not read integration quotas")
    finally:
        db.close()
    _quota_cache = (time.monotonic(), value)
    return value


def _quota_take(name: str) -> bool:
    """Counts one call against today's quota (shared through Redis between processes). No quota → always True."""
    limit = _quotas().get(name)
    if not limit or limit < 0:
        return True
    from app.core.timeutil import local_today

    key = f"abdex:q:{name}:{local_today().isoformat()}"
    from app.core import ratelimit

    r = ratelimit._client()
    if r is not None:
        try:
            pipe = r.pipeline()
            pipe.incr(key)
            pipe.expire(key, 2 * 86400)
            used = int(pipe.execute()[0])
            return used <= limit
        except Exception as exc:  # noqa: BLE001
            ratelimit._redis_failed(exc)
    with _quota_lock:
        for k in [k for k in _quota_local if not k.endswith(key[-10:])]:
            _quota_local.pop(k)  # yesterday's counters
        _quota_local[key] = _quota_local.get(key, 0) + 1
        return _quota_local[key] <= limit


class NotRegistered(IntegrationUnavailable):
    """SEC-DAT-11: the transfer of personal data to this recipient is not in the processing register."""


class Adapter:
    name = "base"
    personal_data = False  # True: works only while the processing register has an active record for it
    timeout = 5.0
    retries = 2
    cache_ttl = 300.0

    def __init__(self):
        self.breaker = CircuitBreaker()
        self._cache: dict[str, tuple[float, Any]] = {}
        self.metrics = {"ok": 0, "error": 0, "total_ms": 0}

    def call(self, operation: str, fn: Callable[[], Any], *, cache_key: str | None = None, basis: str = "",
             initiator=None, summary: str = "") -> Any:
        if cache_key and cache_key in self._cache:
            ts, value = self._cache[cache_key]
            if time.monotonic() - ts < self.cache_ttl:
                return value
        if self.personal_data:
            from app.modules.platform.processing import registered_adapters

            if self.name not in registered_adapters():
                self._journal(operation, "not_registered", 0, basis, initiator, summary)
                raise NotRegistered(self.name)
        if self.breaker.is_open:
            self._journal(operation, "circuit_open", 0, basis, initiator, summary)
            raise IntegrationUnavailable(self.name)
        if not _quota_take(self.name):
            # GOV-R-05: the daily volume agreed (and paid) with the provider is used up — the fallback scenario
            # (manual check, later retry) takes over instead of an unbounded bill or mass lookups
            self._journal(operation, "quota", 0, basis, initiator, summary)
            log.warning("integration %s: daily quota reached", self.name)
            raise IntegrationUnavailable(f"{self.name}: daily quota reached")
        delay = 0.2
        last_exc: Exception | None = None
        for attempt in range(self.retries + 1):
            started = time.monotonic()
            try:
                value = fn()
                ms = int((time.monotonic() - started) * 1000)
                self.breaker.success()
                self.metrics["ok"] += 1
                self.metrics["total_ms"] += ms
                self._journal(operation, "ok", ms, basis, initiator, summary)
                if cache_key:
                    self._cache[cache_key] = (time.monotonic(), value)
                return value
            except Exception as exc:  # noqa: BLE001
                last_exc = exc
                ms = int((time.monotonic() - started) * 1000)
                self.breaker.failure()
                self.metrics["error"] += 1
                self._journal(operation, "error", ms, basis, initiator, summary, str(exc)[:300])
                if attempt < self.retries:
                    time.sleep(delay)
                    delay *= 2
        raise IntegrationUnavailable(self.name) from last_exc

    def _journal(self, operation, status, ms, basis, initiator, summary, error=""):
        row = dict(adapter=self.name, operation=operation, initiator_user_id=initiator, basis=basis,
                   request_summary=summary[:500], status=status, duration_ms=ms, error=error)
        if _deferred():
            with _pending_lock:
                _pending.append(row)
            return
        # Own short transaction so the journal survives a business-level rollback.
        db = SessionLocal()
        try:
            db.add(IntegrationCall(**row))
            db.commit()
        except Exception:  # noqa: BLE001
            db.rollback()
            log.exception("failed to journal integration call")
        finally:
            db.close()
