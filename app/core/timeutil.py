"""Business days are days in Kazakhstan (Asia/Almaty), not in UTC: a fee accrued at 02:00 on 1 January belongs
to January, an order loading at 03:00 local time on the 1st belongs to that month (FR-LOC-03)."""
from __future__ import annotations

from datetime import date, datetime, time, timezone
from zoneinfo import ZoneInfo

from app.config import settings


def tz() -> ZoneInfo:
    return ZoneInfo(settings.default_timezone or "Asia/Almaty")


def local_today() -> date:
    return datetime.now(timezone.utc).astimezone(tz()).date()


def local_date(value: datetime) -> date:
    return value.astimezone(tz()).date()


def day_bounds(d1: date, d2: date) -> tuple[datetime, datetime]:
    """UTC instants of the start of d1 and the end of d2 in local time."""
    return (datetime.combine(d1, time.min, tzinfo=tz()).astimezone(timezone.utc),
            datetime.combine(d2, time.max, tzinfo=tz()).astimezone(timezone.utc))
