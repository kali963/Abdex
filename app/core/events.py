"""Tiny in-process domain event bus.

Modules publish events (e.g. "order.status_changed") and other modules subscribe, so that
notifications / chat / billing never reach into each other's tables (NFR-ARC-01).
Handlers run synchronously inside the caller's transaction; slow work goes to the outbox.
"""
from __future__ import annotations

import logging
from collections import defaultdict
from typing import Callable

log = logging.getLogger("abdex.events")
_handlers: dict[str, list[Callable]] = defaultdict(list)


def subscribe(event: str):
    def deco(fn: Callable) -> Callable:
        _handlers[event].append(fn)
        return fn

    return deco


def emit(event: str, **payload) -> None:
    for fn in _handlers.get(event, []):
        fn(**payload)
