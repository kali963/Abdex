"""Localization (FR-LOC-01, FR-LOC-03).

UI strings live in app/i18n/<locale>.json; templates never contain hard-coded text and call
`_("key")`. Timestamps are stored in UTC and rendered in the user's timezone.
"""
from __future__ import annotations

import json
from datetime import date, datetime
from functools import lru_cache
from pathlib import Path
from zoneinfo import ZoneInfo

from app.core.context import get_ctx

LOCALES = ("ru", "kk", "en")  # FR-LOC-02: English for international directions and the partner API
I18N_DIR = Path(__file__).resolve().parent.parent / "i18n"


@lru_cache(maxsize=None)
def _catalog(locale: str) -> dict[str, str]:
    path = I18N_DIR / f"{locale}.json"
    if not path.exists():
        return {}
    with path.open(encoding="utf-8") as fh:
        return json.load(fh)


def reload_catalogs() -> None:
    _catalog.cache_clear()


def translate(key: str, locale: str | None = None, **params) -> str:
    loc = locale or get_ctx().locale or "ru"
    text = _catalog(loc).get(key) or _catalog("ru").get(key) or key
    if params:
        try:
            text = text.format(**params)
        except (KeyError, IndexError, ValueError):
            pass
    return text


_ = translate


def fmt_dt(value: datetime | None, with_time: bool = True) -> str:
    if value is None:
        return "—"
    tz = ZoneInfo(get_ctx().timezone or "Asia/Almaty")
    local = value.astimezone(tz)
    return local.strftime("%d.%m.%Y %H:%M" if with_time else "%d.%m.%Y")


def fmt_date(value: date | datetime | None) -> str:
    if value is None:
        return "—"
    if isinstance(value, datetime):
        return fmt_dt(value, with_time=False)
    return value.strftime("%d.%m.%Y")


def to_local_input(value: datetime | None) -> str:
    """Value for <input type=datetime-local> in the user's timezone."""
    if value is None:
        return ""
    tz = ZoneInfo(get_ctx().timezone or "Asia/Almaty")
    return value.astimezone(tz).strftime("%Y-%m-%dT%H:%M")


def parse_local_input(raw: str | None) -> datetime | None:
    if not raw:
        return None
    tz = ZoneInfo(get_ctx().timezone or "Asia/Almaty")
    try:
        naive = datetime.fromisoformat(raw)
    except ValueError:
        return None
    if naive.tzinfo is None:
        naive = naive.replace(tzinfo=tz)
    return naive.astimezone(ZoneInfo("UTC"))
