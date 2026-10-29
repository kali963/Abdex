"""Sliding-window rate limiter (SEC-APP-06, FR-API-04).

With ``REDIS_URL`` the counters live in Redis and are shared by every worker process and server (NFR-ARC-04);
that is the production setup. Without it (development, a single process) they are kept in memory. If Redis
becomes unreachable the limiter falls back to memory for a while and logs it, instead of failing requests.
"""
from __future__ import annotations

import threading
import time
from collections import defaultdict, deque

from app.core.errors import RateLimited

_lock = threading.Lock()
_store: dict[str, deque] = defaultdict(deque)

LIMITS = {
    "login": (30, 300),          # per IP; mobile operators put many users behind one address (CGNAT),
                                 # the per-account limit below is what stops password guessing
    "login_account": (5, 300),   # 5 attempts / 5 min per account
    "otp_send": (5, 600),
    "otp_check": (10, 600),
    "2fa": (8, 900),             # second-factor guesses per account (TOTP and SMS together)
    "password_reset": (5, 900),
    "register": (30, 3600),      # per IP (offices and mobile networks share addresses)
    "bid": (60, 3600),
    "order_create": (100, 3600),
    "export": (20, 3600),
    "api": (600, 60),
    "api_sandbox": (120, 60),     # FR-API-05: test keys
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
_loaded_at = float("-inf")  # load at the first use, even right after boot (monotonic time)
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


# ------------------------------------------------------------------ shared counters (Redis)

_redis = None
_redis_down_until = 0.0


def _client():
    """The Redis client, or None when not configured / recently unreachable (retried after 30 s)."""
    global _redis, _redis_down_until
    import os

    url = os.getenv("REDIS_URL", "")
    if not url or time.monotonic() < _redis_down_until:
        return None
    if _redis is None:
        import redis

        _redis = redis.Redis.from_url(url, socket_timeout=0.5, socket_connect_timeout=0.5)
    return _redis


def _redis_failed(exc: Exception) -> None:
    global _redis_down_until
    import logging

    _redis_down_until = time.monotonic() + 30
    logging.getLogger("abdex.ratelimit").warning("redis unavailable, in-memory limits for 30 s: %s",
                                                 type(exc).__name__)


def _redis_hit(r, k: str, lim: int, win: int) -> bool:
    """Sliding window in a sorted set: drop old entries, count, add this one if allowed."""
    import secrets

    now = time.time()
    rk = f"abdex:rl:{k}"
    pipe = r.pipeline()
    pipe.zremrangebyscore(rk, 0, now - win)
    pipe.zcard(rk)
    _, used = pipe.execute()
    if used >= lim:
        return False
    pipe = r.pipeline()
    pipe.zadd(rk, {f"{now}:{secrets.token_hex(4)}": now})
    pipe.expire(rk, win + 1)
    pipe.execute()
    return True


def hit(bucket: str, key: str, *, limit: int | None = None, window: int | None = None, raise_exc: bool = True) -> bool:
    lim, win = _limits(bucket)
    lim = limit or lim
    win = window or win
    k = f"{bucket}:{key}"
    r = _client()
    if r is not None:
        try:
            ok = _redis_hit(r, k, lim, win)
        except Exception as exc:  # noqa: BLE001 — any Redis failure: fall back to memory
            _redis_failed(exc)
        else:
            if not ok and raise_exc:
                raise RateLimited()
            return ok
    now = time.monotonic()
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
    r = _client()
    if r is not None:
        try:
            rk = f"abdex:rl:{bucket}:{key}"
            return int(r.zcount(rk, time.time() - win, "+inf"))
        except Exception as exc:  # noqa: BLE001
            _redis_failed(exc)
    now = time.monotonic()
    with _lock:
        q = _store.get(f"{bucket}:{key}")
        if not q:
            return 0
        return sum(1 for t in q if t > now - win)


def reset_all() -> None:
    with _lock:
        _store.clear()
    r = _client()
    if r is not None:
        try:
            for rk in r.scan_iter("abdex:rl:*"):
                r.delete(rk)
        except Exception as exc:  # noqa: BLE001
            _redis_failed(exc)
