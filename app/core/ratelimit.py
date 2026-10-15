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
}


def hit(bucket: str, key: str, *, limit: int | None = None, window: int | None = None, raise_exc: bool = True) -> bool:
    lim, win = LIMITS.get(bucket, (100, 60))
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
    _, win = LIMITS.get(bucket, (100, 60))
    now = time.monotonic()
    with _lock:
        q = _store.get(f"{bucket}:{key}")
        if not q:
            return 0
        return sum(1 for t in q if t > now - win)


def reset_all() -> None:
    with _lock:
        _store.clear()
