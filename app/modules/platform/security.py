"""Security event correlation and the monthly security report (SEC-LOG-06, SEC-LOG-08).

The worker scans the append-only audit journal incrementally and turns patterns into security alerts for the
security officer (auditor) and administrators:

* a series of failed logins for one account or from one address;
* a staff login from an address or device never seen for that person;
* bulk exports above a threshold;
* a spike of access-denied answers for one user;
* any change of rights (permission matrix, roles, 2FA reset, support sessions);
* staff actions outside working hours.

Thresholds are the platform setting ``security.thresholds``. Alerts are deduplicated per pattern and hour.
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from datetime import date, datetime, time, timedelta, timezone
from zoneinfo import ZoneInfo

from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db import utcnow
from app.modules.accounts.models import STAFF_ADMIN, STAFF_AUDITOR, STAFF_ROLES, AuditLog, User
from app.modules.platform.models import SecurityAlert

DEFAULT_THRESHOLDS = {"failed_logins": 5, "bulk_exports_per_hour": 5, "access_denied_per_hour": 20,
                      "work_from": 8, "work_to": 20, "timezone": "Asia/Almaty"}
RIGHTS_ACTIONS = ("acl.matrix_changed", "acl.role_added", "staff.user_reset_2fa", "staff.user_block",
                  "staff.user_unblock", "impersonation.started", "antifraud.rule_changed", "staff.setting_changed",
                  "staff.flag_changed", "auth.2fa_disabled")
EXPORT_ACTIONS = ("export.bulk", "export.documents_zip", "export.pvd_report", "deal.dossier_exported")
FAILED_ACTIONS = ("auth.login_failed", "auth.login_blocked", "auth.login_throttled")
MAX_SCAN = 20000


def thresholds(db: Session) -> dict:
    from app.modules.platform.service import get_setting

    value = get_setting(db, "security.thresholds", None)
    return {**DEFAULT_THRESHOLDS, **(value if isinstance(value, dict) else {})}


def _alert(db: Session, kind: str, dedup: str, *, severity: str = "medium", user_id=None, details=None) -> bool:
    try:
        with db.begin_nested():
            db.add(SecurityAlert(kind=kind, severity=severity, user_id=user_id, dedup_key=f"{kind}:{dedup}"[:120],
                                 details=json.dumps(details or {}, ensure_ascii=False, default=str)))
            db.flush()
    except IntegrityError:
        return False
    return True


def scan(db: Session) -> int:
    """Worker job. Reads audit entries after the last scanned one; idempotent thanks to dedup keys."""
    from app.modules.platform.service import get_setting, set_setting

    t = thresholds(db)
    last = get_setting(db, "security.last_scan", None)
    since = datetime.fromisoformat(last) if last else utcnow() - timedelta(days=1)
    rows = list(db.execute(select(AuditLog).where(AuditLog.created_at > since).order_by(AuditLog.created_at)
                           .limit(MAX_SCAN)).scalars())
    if not rows:
        return 0
    staff_ids = {u.id: u for u in db.execute(select(User).where(User.staff_role.in_(STAFF_ROLES))).scalars()}
    tz = ZoneInfo(t["timezone"])
    created = 0
    failed_by_user: Counter = Counter()
    failed_by_ip: Counter = Counter()
    exports: Counter = Counter()
    denied: Counter = Counter()
    hour = lambda e: e.created_at.strftime("%Y%m%d%H")  # noqa: E731
    for e in rows:
        if e.action in FAILED_ACTIONS:
            failed_by_user[(e.object_id, hour(e))] += 1
            failed_by_ip[(e.ip, hour(e))] += 1
        elif e.action in EXPORT_ACTIONS:
            exports[(e.user_id, hour(e))] += 1
        elif e.action == "access.denied":
            denied[(e.user_id, hour(e))] += 1
        if e.action in RIGHTS_ACTIONS:
            created += _alert(db, "rights_changed", str(e.id), severity="high" if e.action.startswith("acl") else "medium",
                              user_id=e.user_id, details={"action": e.action, "object": e.object_id, "at": e.created_at})
        if e.user_id in staff_ids and e.role in STAFF_ROLES:
            local = e.created_at.astimezone(tz)
            if local.hour < int(t["work_from"]) or local.hour >= int(t["work_to"]) or local.weekday() >= 5:
                created += _alert(db, "staff_off_hours", f"{e.user_id}:{hour(e)}", user_id=e.user_id,
                                  details={"action": e.action, "local_time": local.strftime("%d.%m %H:%M")})
        if e.action == "auth.login" and e.user_id in staff_ids:
            seen = db.execute(select(func.count(AuditLog.id)).where(
                AuditLog.action == "auth.login", AuditLog.user_id == e.user_id, AuditLog.created_at < e.created_at,
                (AuditLog.ip == e.ip) | ((AuditLog.device == e.device) & (AuditLog.device != "")))).scalar_one()
            earlier = db.execute(select(func.count(AuditLog.id)).where(
                AuditLog.action == "auth.login", AuditLog.user_id == e.user_id,
                AuditLog.created_at < e.created_at)).scalar_one()
            if earlier and not seen:
                created += _alert(db, "staff_new_location", str(e.id), severity="high", user_id=e.user_id,
                                  details={"ip": e.ip})
    for (who, h), n in failed_by_user.items():
        if who and n >= int(t["failed_logins"]):
            created += _alert(db, "failed_logins", f"user:{who}:{h}", details={"account": who, "count": n})
    for (ip, h), n in failed_by_ip.items():
        if n >= int(t["failed_logins"]) * 2:
            created += _alert(db, "failed_logins", f"ip:{ip}:{h}", severity="high", details={"ip": ip, "count": n})
    for (uid, h), n in exports.items():
        if n >= int(t["bulk_exports_per_hour"]):
            created += _alert(db, "mass_export", f"{uid}:{h}", severity="high", user_id=uid, details={"count": n})
    for (uid, h), n in denied.items():
        if n >= int(t["access_denied_per_hour"]):
            created += _alert(db, "access_denied_spike", f"{uid}:{h}", user_id=uid, details={"count": n})
    set_setting(db, "security.last_scan", rows[-1].created_at.isoformat(), "SEC-LOG-06: last scanned audit entry")
    if created:
        from app.modules.notifications.service import notify_user

        for u in staff_ids.values():
            if u.staff_role in (STAFF_AUDITOR, STAFF_ADMIN):
                notify_user(db, u.id, "security.alerts", {"count": created}, link="/admin/security",
                            channels=["web", "email"], dedup=f"secalerts:{u.id}:{utcnow():%Y%m%d%H%M}")
    db.commit()
    return created


def alerts(db: Session, status: str = "open", limit: int = 300) -> list[SecurityAlert]:
    return list(db.execute(select(SecurityAlert).where(SecurityAlert.status == status)
                           .order_by(SecurityAlert.created_at.desc()).limit(limit)).scalars())


def monthly_report(db: Session, month: date) -> dict:
    """SEC-LOG-08: incidents, anomalies, vulnerability status and access changes for a month."""
    from app.modules.platform.models import AntifraudAlert
    from app.modules.platform.service import get_setting

    start = datetime.combine(month.replace(day=1), time.min, tzinfo=timezone.utc)
    nxt = (start + timedelta(days=32)).replace(day=1)
    in_month = lambda col: (col >= start) & (col < nxt)  # noqa: E731
    sec = list(db.execute(select(SecurityAlert).where(in_month(SecurityAlert.created_at))).scalars())
    by_kind = Counter(a.kind for a in sec)
    audit_counts = dict(db.execute(select(AuditLog.action, func.count(AuditLog.id))
                                   .where(in_month(AuditLog.created_at)).group_by(AuditLog.action)).all())
    rights = list(db.execute(select(AuditLog).where(in_month(AuditLog.created_at), AuditLog.action.in_(RIGHTS_ACTIONS))
                             .order_by(AuditLog.created_at)).scalars())
    fraud = dict(db.execute(select(AntifraudAlert.status, func.count(AntifraudAlert.id))
                            .where(in_month(AntifraudAlert.created_at)).group_by(AntifraudAlert.status)).all())
    by_status: dict = defaultdict(int)
    for a in sec:
        by_status[a.status] += 1
    return {
        "month": start.date(), "alerts_total": len(sec), "alerts_by_kind": dict(by_kind),
        "alerts_open": by_status.get("open", 0), "alerts_closed": by_status.get("closed", 0),
        "logins": audit_counts.get("auth.login", 0),
        "failed_logins": sum(audit_counts.get(a, 0) for a in FAILED_ACTIONS),
        "exports": sum(audit_counts.get(a, 0) for a in EXPORT_ACTIONS),
        "access_denied": audit_counts.get("access.denied", 0),
        "impersonations": audit_counts.get("impersonation.started", 0),
        "approvals": audit_counts.get("approval.executed", 0),
        "antifraud": fraud,
        "rights_changes": [{"at": r.created_at, "action": r.action, "object": r.object_id, "user": str(r.user_id or "")}
                           for r in rights],
        "vulnerabilities": get_setting(db, "security.vuln_status", "") or "",
    }


def report_pdf(report: dict, labels: dict) -> bytes:
    from app.modules.documents.service import render_pdf

    lines = ["## " + labels["summary"],
             f"{labels['alerts']}: {report['alerts_total']} ({labels['open']}: {report['alerts_open']})"]
    lines += [f"  {labels.get('k.' + k, k)}: {v}" for k, v in sorted(report["alerts_by_kind"].items())]
    lines += [f"{labels['logins']}: {report['logins']}", f"{labels['failed']}: {report['failed_logins']}",
              f"{labels['exports']}: {report['exports']}", f"{labels['denied']}: {report['access_denied']}",
              f"{labels['impersonations']}: {report['impersonations']}", f"{labels['approvals']}: {report['approvals']}",
              f"{labels['antifraud']}: " + ", ".join(f"{k} {v}" for k, v in report["antifraud"].items()),
              "", "## " + labels["rights"]]
    lines += [f"{r['at']:%d.%m.%Y %H:%M} UTC · {r['action']} · {r['object']}" for r in report["rights_changes"]] or ["—"]
    lines += ["", "## " + labels["vulns"], report["vulnerabilities"] or "—"]
    return render_pdf(f"{labels['title']} {report['month']:%m.%Y}", "\n".join(lines))
