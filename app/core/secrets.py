"""Secrets of integrations and keys (GOV-R-07, NFR-ARC-06).

A secret is read, in this order, from:
1. the file named by ``<NAME>_FILE`` (a mounted secret: Docker/Kubernetes secrets, Vault agent, …);
2. ``/run/secrets/<name in lower case>`` (Docker secrets by convention);
3. the ``<NAME>`` environment variable (development, simple setups).

Files are read when needed and not cached, so a rotated secret is picked up without a restart. Values never
reach logs; the integration journal records each use of an adapter (who, when, why) without the secret itself.
"""
from __future__ import annotations

import os
from pathlib import Path

SECRETS_DIR = Path("/run/secrets")


def secret(name: str, default: str = "") -> str:
    path = os.getenv(f"{name}_FILE", "")
    if path:
        try:
            return Path(path).read_text(encoding="utf-8").strip()
        except OSError:
            return default
    candidate = SECRETS_DIR / name.lower()
    try:
        if candidate.is_file():
            value = candidate.read_text(encoding="utf-8").strip()
            if value:  # an empty mounted file (a placeholder) falls through to the variable
                return value
    except OSError:
        pass
    return os.getenv(name, default).strip()


def has(name: str) -> bool:
    return bool(secret(name))
