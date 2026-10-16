"""Concrete adapters. Every one is a stub/simulator in development (INT-GEN-07):
tests and dev never hit real external systems.

- RoutingAdapter      (INT-MAP-01, FR-ORD-09): distance & duration between cities
- RegistryAdapter     (FR-KYC-06, GOV-R-01): "company check" / "person check" abstraction
- SmsAdapter, EmailAdapter, TelegramAdapter (INT-SMS-01, INT-MAIL-01, INT-TG-01)
"""
from __future__ import annotations

import logging
import math
from datetime import timedelta

from app.db import utcnow
from app.modules.integrations.base import Adapter

log = logging.getLogger("abdex.integrations")

# Approximate coordinates for the main logistics hubs; real geocoder replaces this.
CITY_COORDS = {
    "алматы": (43.238, 76.889), "астана": (51.169, 71.449), "шымкент": (42.341, 69.590),
    "караганда": (49.806, 73.085), "актобе": (50.283, 57.167), "тараз": (42.900, 71.378),
    "павлодар": (52.287, 76.967), "усть-каменогорск": (49.948, 82.628), "семей": (50.411, 80.227),
    "атырау": (47.094, 51.924), "костанай": (53.214, 63.624), "кызылорда": (44.853, 65.509),
    "уральск": (51.204, 51.370), "петропавловск": (54.866, 69.135), "актау": (43.651, 51.197),
    "талдыкорган": (45.017, 78.373), "туркестан": (43.297, 68.252), "кокшетау": (53.283, 69.383),
    "хоргос": (44.214, 80.410), "достык": (45.250, 82.483), "ташкент": (41.311, 69.240),
    "бишкек": (42.875, 74.590), "москва": (55.756, 37.617), "урумчи": (43.825, 87.617),
    "екатеринбург": (56.838, 60.597), "омск": (54.989, 73.368), "новосибирск": (55.030, 82.920),
}


class RoutingAdapter(Adapter):
    name = "routing"

    def route(self, cities: list[str]) -> dict | None:
        key = "|".join(c.lower().strip() for c in cities)

        def _do():
            total = 0.0
            pts = [CITY_COORDS.get(c.lower().strip()) for c in cities]
            if any(p is None for p in pts) or len(pts) < 2:
                return None
            for a, b in zip(pts, pts[1:], strict=False):
                total += _haversine(a, b) * 1.25  # road factor
            km = int(round(total))
            return {"distance_km": km, "duration_hours": max(1, int(round(km / 60))), "source": "abdex-sim-v1"}

        return self.call("route", _do, cache_key=key, summary=key)


def _haversine(a, b) -> float:
    r = 6371.0
    la1, lo1, la2, lo2 = map(math.radians, (a[0], a[1], b[0], b[1]))
    h = math.sin((la2 - la1) / 2) ** 2 + math.cos(la1) * math.cos(la2) * math.sin((lo2 - lo1) / 2) ** 2
    return 2 * r * math.asin(math.sqrt(h))


class RegistryAdapter(Adapter):
    """Business logic talks to "check company" / "check person", never to a concrete service.
    Switching the source (commercial -> ГБД ЮЛ via ШЭП) = new adapter + config switch."""

    name = "registry"
    personal_data = True
    source = "commercial-sim"

    def check_company(self, bin_iin: str, *, basis: str, initiator=None) -> dict:
        def _do():
            valid = len(bin_iin) == 12 and bin_iin.isdigit()
            return {"status": "match" if valid else "not_found", "source": self.source,
                    "valid_until": (utcnow() + timedelta(days=90)).isoformat(),
                    "data": {"bin": bin_iin, "active": valid}}

        return self.call("check_company", _do, basis=basis, initiator=initiator, summary=f"bin:{bin_iin[:4]}****")

    def check_person(self, iin: str, *, basis: str, initiator=None) -> dict:
        def _do():
            valid = len(iin) == 12 and iin.isdigit()
            return {"status": "match" if valid else "not_found", "source": self.source,
                    "valid_until": (utcnow() + timedelta(days=90)).isoformat(), "data": {}}

        return self.call("check_person", _do, basis=basis, initiator=initiator, summary=f"iin:{iin[:2]}**********")


def _mask(recipient: str) -> str:
    recipient = recipient or ""
    if "@" in recipient:
        return recipient[:1] + "***@" + recipient.split("@", 1)[1]
    return recipient[:4] + "***" + recipient[-2:] if len(recipient) > 6 else "***"


class _OutboundAdapter(Adapter):
    """Dev transports write to the log and to an in-memory outbox visible at /dev/outbox."""

    personal_data = True  # recipients (phone, e-mail, chat id) are personal data: SEC-DAT-11
    sent: list[dict] = []

    def send(self, recipient: str, body: str) -> None:
        from app.config import settings

        def _do():
            if settings.is_dev:  # the demo outbox exists only outside production
                entry = {"channel": self.name, "to": recipient, "body": body, "at": utcnow().isoformat()}
                _OutboundAdapter.sent.append(entry)
                del _OutboundAdapter.sent[:-200]
            self._deliver(recipient, body)
            # SEC-LOG-05: never log the text (it may hold one-time codes or links) nor the full address
            log.info("[%s] message sent to %s", self.name, _mask(recipient))
            return True

        self.call("send", _do, summary=self.name)

    def _deliver(self, recipient: str, body: str) -> None:
        """Real transport; the base class is a no-op stub (dev / demo)."""


class SmsAdapter(_OutboundAdapter):
    name = "sms"


class EmailAdapter(_OutboundAdapter):
    name = "email"


class TelegramAdapter(_OutboundAdapter):
    name = "telegram"
    timeout = 5.0

    def _deliver(self, recipient: str, body: str) -> None:
        """Bot API sendMessage when TELEGRAM_BOT_TOKEN is configured (FR-NTF-02, INT-TG-01)."""
        import json as _json
        import urllib.request

        from app.config import settings

        if not settings.telegram_bot_token:
            return
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{settings.telegram_bot_token}/sendMessage",
            data=_json.dumps({"chat_id": recipient, "text": body, "disable_web_page_preview": True}).encode(),
            headers={"Content-Type": "application/json"}, method="POST")
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:  # noqa: S310 — fixed https host
            if resp.status != 200:
                raise RuntimeError(f"telegram status {resp.status}")


class PushAdapter(_OutboundAdapter):
    name = "push"


class BiometricsAdapter(Adapter):
    """FR-KYC-08: face match of a selfie against the document photo plus a liveness check.

    The simulator stands in for a licensed provider (INT-GEN-07): the face "matches" when both images are valid
    and differ from each other; liveness passes when the two selfie frames (the user is asked to turn the head)
    are valid and not the same picture. A real provider replaces `_compare` only.
    """

    name = "biometrics"
    personal_data = True
    retries = 0
    provider = "biometrics-sim-v1"

    def compare(self, selfie: bytes, selfie2: bytes, document: bytes, *, initiator=None) -> dict:
        return self.call("compare", lambda: self._compare(selfie, selfie2, document), basis="consent",
                         initiator=initiator, summary="face-match")

    def _compare(self, selfie: bytes, selfie2: bytes, document: bytes) -> dict:
        import hashlib
        import io

        from PIL import Image

        def ok(data: bytes) -> bool:
            try:
                with Image.open(io.BytesIO(data)) as im:
                    im.verify()
                return True
            except Exception:  # noqa: BLE001 — anything unreadable is simply not a face
                return False

        h = [hashlib.sha256(x).hexdigest() for x in (selfie, selfie2, document)]
        liveness = ok(selfie) and ok(selfie2) and h[0] != h[1]
        match = ok(selfie) and ok(document) and h[0] != h[2]
        score = (70 + int(h[0][:2], 16) % 30) if match else int(h[0][:2], 16) % 30
        return {"match": match, "liveness": liveness, "score": score, "provider": self.provider}


routing = RoutingAdapter()
registry = RegistryAdapter()
sms = SmsAdapter()
email = EmailAdapter()
telegram = TelegramAdapter()
push = PushAdapter()
biometrics = BiometricsAdapter()

CHANNELS = {"sms": sms, "email": email, "telegram": telegram, "push": push}
