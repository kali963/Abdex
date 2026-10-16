"""Sliding-window rate limiter (SEC-APP-06, FR-API-04).

In-process implementation for a single instance / development. With several instances the
same interface is backed by Redis (NFR-ARC-04); swap `_store` for a Redis-backed one.
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque

from app.core.errors import RateLimited

_lock = threading.Lock()
_store: dict[str, deque] = defaultdict(deque)

LIMITS = {
    "login": (10, 300),          # 10 attempts / 5 min per IP
    "login_account": (5, 300),   # 5 attempts / 5 min per account
    "otp_send": (5, 600),
    "otp_check": (10, 600),
    "password_reset": (5, 900),
    "register": (10, 3600),
    "bid": (60, 3600),
    "order_create": (100, 3600),
    "export": (20, 3600),
    "api": (600, 60),
    "upload": (60, 600),
    "chat": (120, 600),
    "invite": (50, 3600),
    "impersonate": (10, 3600),
    "webhook_test": (10, 600),
    "forecast": (60, 3600),       # FR-CALC-06: market statistics, no scraping
    "eds_challenge": (30, 600),   # FR-AUTH-09 challenges per IP
}


DEFAULTS = dict(LIMITS)
_overrides: dict[str, tuple[int, int]] = {}
_loaded_at = 0.0
REFRESH_SECONDS = 60
loader = None  # set at start-up: returns {"bucket": [limit, window_seconds]} from the platform setting


def configure(overrides: dict | None) -> None:
    """SEC-APP-07: thresholds come from the setting ``ratelimit.limits`` and change without a release."""
    clean = {}
    for bucket, value in (overrides or {}).items():
        try:
            lim, win = int(value[0]), int(value[1])
        except (TypeError, ValueError, IndexError, KeyError):
            continue
        if bucket in DEFAULTS and lim > 0 and win > 0:
            clean[bucket] = (lim, win)
    _overrides.clear()
    _overrides.update(clean)


def _limits(bucket: str) -> tuple[int, int]:
    global _loaded_at
    if loader is not None and time.monotonic() - _loaded_at > REFRESH_SECONDS:
        _loaded_at = time.monotonic()
        try:
            configure(loader())
        except Exception:  # noqa: BLE001 — a settings read failure keeps the previous limits
            import logging

            logging.getLogger("abdex.ratelimit").warning("rate limit settings could not be loaded")
    return _overrides.get(bucket) or DEFAULTS.get(bucket, (100, 60))


def hit(bucket: str, key: str, *, limit: int | None = None, window: int | None = None, raise_exc: bool = True) -> bool:
    lim, win = _limits(bucket)
    lim = limit or lim
    win = window or win
    now = time.monotonic()
    k = f"{bucket}:{key}"
    with _lock:
        q = _store[k]
        while q and q[0] <= now - win:
            q.popleft()
        if len(q) >= lim:
            if raise_exc:
                raise RateLimited()
            return False
        q.append(now)
    return True


def count(bucket: str, key: str) -> int:
    _, win = _limits(bucket)
    now = time.monotonic()
    with _lock:
        q = _store.get(f"{bucket}:{key}")
        if not q:
            return 0
        return sum(1 for t in q if t > now - win)


def reset_all() -> None:
    with _lock:
        _store.clear()
