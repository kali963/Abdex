"""Background jobs (NFR-ARC-03, FR-FLOW-04, FR-NTF-01, FR-KYC-05, FR-BIL-05).

Run as a separate process in production:  python -m app.worker
In development the same loop runs inside the web process (RUN_BACKGROUND_WORKER=true).
Every job is idempotent, so running several workers or re-running a tick is safe.
"""
from __future__ import annotations

import asyncio
import logging
import time

from app.db import SessionLocal

log = logging.getLogger("abdex.worker")

_last_daily = 0.0
_last_hourly = 0.0


def _run(name: str, job, stats: dict) -> None:
    """Each job in its own session; one failing job never stops the others."""
    db = SessionLocal()
    try:
        stats[name] = job(db)
        db.commit()
    except Exception:  # noqa: BLE001
        db.rollback()
        log.exception("job %s failed", name)
    finally:
        db.close()


def tick() -> dict:
    global _last_daily, _last_hourly
    from app.modules.billing.service import enforce_debt_limits
    from app.modules.fleet.service import check_document_expiry
    from app.modules.integrations.base import flush_journal
    from app.modules.notifications.service import process_digests, process_outbox
    from app.modules.orders.series import generate_due
    from app.modules.orders.service import expire_bidding
    from app.modules.support.service import escalate_overdue
    from app.modules.webhooks.service import process as process_webhooks

    stats = {"journal": flush_journal()}
    from app.modules.documents.transport import process as process_etd
    from app.modules.platform.retention import run as retention
    from app.modules.platform.security import scan as security_scan

    from app.modules.billing.esf import process as process_esf

    for name, job in (("outbox", process_outbox), ("bidding", expire_bidding), ("sla", escalate_overdue),
                      ("security", security_scan), ("etd", process_etd), ("esf", process_esf),
                      ("webhooks", process_webhooks)):  # outbound HTTP last: it must not delay the timers
        _run(name, job, stats)
    if time.time() - _last_hourly > 600:
        _last_hourly = time.time()
        from app.modules.billing.subscriptions import renew_due

        from app.modules.deals.telematics import pull_all as pull_telematics

        for name, job in (("digests", process_digests), ("series", generate_due), ("subscriptions", renew_due),
                          ("telematics", pull_telematics)):
            _run(name, job, stats)
    if time.time() - _last_daily > 6 * 3600:
        _last_daily = time.time()
        from app.modules.fleet.level3 import evaluate_all as evaluate_l3
        from app.modules.bids.matching import learn as learn_matching
        from app.modules.platform.fx import load as load_fx

        for name, job in (("doc_expiry", check_document_expiry), ("debt", enforce_debt_limits), ("l3", evaluate_l3), ("fx", load_fx),
                          ("matching_ai", learn_matching),
                          ("retention", retention)):
            _run(name, job, stats)
    return stats


async def run_forever(interval: float = 20.0) -> None:
    while True:
        await asyncio.to_thread(tick)
        await asyncio.sleep(interval)


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    from app.bootstrap import init_db

    init_db()
    asyncio.run(run_forever())
