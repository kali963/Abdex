"""FR-CHAT-05 / SEC-FRD-06: detect attempts to move the deal off-platform before acceptance."""
from __future__ import annotations

import re

_PATTERNS = [
    re.compile(r"(?:\+?[78][\s\-()]*)?\d{3}[\s\-()]*\d{3}[\s\-]*\d{2}[\s\-]*\d{2}"),  # phone numbers
    re.compile(r"\bKZ\d{2}[0-9A-Z ]{16,20}\b", re.I),  # IBAN
    re.compile(r"(?:t\.me/|@)[A-Za-z0-9_]{4,}"),  # telegram handles
    re.compile(r"\b(?:whats\s?app|ватсап|вотсап|телеграм|telegram|вайбер|viber)\b", re.I),
    re.compile(r"[^@\s]+@[^@\s]+\.[a-z]{2,}", re.I),  # e-mail
]


def find_contacts(text: str) -> bool:
    return any(p.search(text or "") for p in _PATTERNS)


def mask_contacts(text: str) -> tuple[str, bool]:
    leaked = False
    out = text or ""
    for p in _PATTERNS:
        out, n = p.subn("[скрыто]", out)
        leaked = leaked or n > 0
    return out, leaked
