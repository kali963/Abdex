"""Role/permission matrix (section 5, FR-ACL-01, FR-ACL-06, SEC-AZ-03 default deny).

The matrices below are the built-in defaults. At start they are seeded into the database
(``role_definitions`` / ``role_permissions``); from then on the database is the source of truth and an
administrator edits it at /admin/permissions, including new roles, without a release (FR-ACL-06).

A permission not granted is denied for everybody. Each web/API endpoint declares the permission it needs;
tests/test_permissions.py verifies that no route is left without one.
"""
from __future__ import annotations

from app.modules.accounts.models import (
    ROLE_ACCOUNTANT,
    ROLE_DISPATCHER,
    ROLE_DRIVER,
    ROLE_FLEET_OWNER,
    ROLE_LOGIST,
    ROLE_OWNER,
    STAFF_ADMIN,
    STAFF_AUDITOR,
    STAFF_FINANCE,
    STAFF_MANAGER,
    STAFF_MODERATOR,
)

COMPANY_PERMISSIONS: dict[str, frozenset[str]] = {
    "company.manage": frozenset({ROLE_OWNER, ROLE_FLEET_OWNER}),
    "company.view": frozenset({ROLE_OWNER, ROLE_LOGIST, ROLE_ACCOUNTANT, ROLE_FLEET_OWNER, ROLE_DISPATCHER}),
    "order.create": frozenset({ROLE_OWNER, ROLE_LOGIST}),
    "order.view": frozenset({ROLE_OWNER, ROLE_LOGIST, ROLE_ACCOUNTANT}),
    "bid.accept": frozenset({ROLE_OWNER, ROLE_LOGIST}),
    "market.view": frozenset({ROLE_FLEET_OWNER, ROLE_DISPATCHER}),
    "bid.create": frozenset({ROLE_FLEET_OWNER, ROLE_DISPATCHER}),
    "fleet.manage": frozenset({ROLE_FLEET_OWNER, ROLE_DISPATCHER}),
    "deal.view": frozenset({ROLE_OWNER, ROLE_LOGIST, ROLE_ACCOUNTANT, ROLE_FLEET_OWNER, ROLE_DISPATCHER, ROLE_DRIVER}),
    "deal.manage": frozenset({ROLE_OWNER, ROLE_LOGIST, ROLE_FLEET_OWNER, ROLE_DISPATCHER}),
    "deal.sign": frozenset({ROLE_OWNER, ROLE_LOGIST, ROLE_FLEET_OWNER, ROLE_DISPATCHER}),
    "trip.execute": frozenset({ROLE_DRIVER, ROLE_FLEET_OWNER, ROLE_DISPATCHER}),
    "finance.view": frozenset({ROLE_OWNER, ROLE_ACCOUNTANT, ROLE_FLEET_OWNER}),
    "analytics.view": frozenset({ROLE_OWNER, ROLE_LOGIST, ROLE_FLEET_OWNER, ROLE_DISPATCHER}),
    "plan.view": frozenset({ROLE_OWNER, ROLE_LOGIST, ROLE_FLEET_OWNER, ROLE_DISPATCHER}),
    "calc.use": frozenset({ROLE_OWNER, ROLE_LOGIST, ROLE_ACCOUNTANT, ROLE_FLEET_OWNER, ROLE_DISPATCHER}),
    "support.use": frozenset({ROLE_OWNER, ROLE_LOGIST, ROLE_ACCOUNTANT, ROLE_FLEET_OWNER, ROLE_DISPATCHER, ROLE_DRIVER}),
    "export.bulk": frozenset({ROLE_OWNER, ROLE_ACCOUNTANT, ROLE_FLEET_OWNER}),  # FR-ACL-07
}

STAFF_PERMISSIONS: dict[str, frozenset[str]] = {
    "admin.access": frozenset({STAFF_MANAGER, STAFF_MODERATOR, STAFF_FINANCE, STAFF_ADMIN, STAFF_AUDITOR}),
    "admin.orders": frozenset({STAFF_MANAGER, STAFF_ADMIN}),
    "admin.rollback": frozenset({STAFF_MANAGER}),
    "admin.disputes": frozenset({STAFF_MANAGER}),
    "admin.moderation": frozenset({STAFF_MODERATOR, STAFF_ADMIN}),
    "admin.antifraud": frozenset({STAFF_MODERATOR, STAFF_MANAGER, STAFF_ADMIN}),
    "admin.finance": frozenset({STAFF_FINANCE, STAFF_ADMIN}),
    "admin.users": frozenset({STAFF_ADMIN, STAFF_MODERATOR}),
    "admin.dictionaries": frozenset({STAFF_ADMIN}),
    "admin.settings": frozenset({STAFF_ADMIN}),
    "admin.audit": frozenset({STAFF_AUDITOR, STAFF_ADMIN}),
    "admin.kpi": frozenset({STAFF_MANAGER, STAFF_FINANCE, STAFF_ADMIN}),
    "admin.support": frozenset({STAFF_MANAGER, STAFF_ADMIN}),
    # Auditor reads journals only, never deal content (section 5).
    "admin.deal_content": frozenset({STAFF_MANAGER, STAFF_ADMIN, STAFF_FINANCE}),
    "admin.rating": frozenset({STAFF_MANAGER, STAFF_ADMIN}),  # FR-RAT-02 corrections
    "admin.impersonate": frozenset({STAFF_MANAGER, STAFF_ADMIN}),  # FR-ADM-05
}


BUILTIN_ROLES = {  # code -> scope
    ROLE_OWNER: "client", ROLE_LOGIST: "client", ROLE_ACCOUNTANT: "client",
    ROLE_FLEET_OWNER: "carrier", ROLE_DISPATCHER: "carrier", ROLE_DRIVER: "carrier",
    STAFF_MANAGER: "staff", STAFF_MODERATOR: "staff", STAFF_FINANCE: "staff", STAFF_ADMIN: "staff",
    STAFF_AUDITOR: "staff",
}
# Grants that cannot be removed, so that nobody locks the platform or a company out of its own settings.
LOCKED = {(STAFF_ADMIN, "admin.access"), (STAFF_ADMIN, "admin.settings"), (ROLE_OWNER, "company.manage"),
          (ROLE_FLEET_OWNER, "company.manage")}
# Auditor reads journals only (section 5): these are never granted to the auditor role.
NEVER = {(STAFF_AUDITOR, p) for p in STAFF_PERMISSIONS if p not in ("admin.access", "admin.audit")}

CACHE_TTL = 30.0
_cache: dict = {"at": 0.0, "perms": None, "roles": None}


def invalidate() -> None:
    _cache["at"] = 0.0


def _load() -> dict:
    """perm -> roles, from the database; built-in defaults when the table is still empty."""
    import time

    if _cache["perms"] is not None and time.monotonic() - _cache["at"] < CACHE_TTL:
        return _cache
    perms: dict[str, set[str]] = {}
    roles: dict[str, tuple[str, str, str]] = {}
    try:
        from sqlalchemy import select

        from app.db import SessionLocal
        from app.modules.accounts.models import RoleDefinition, RolePermission

        db = SessionLocal()
        try:
            for rp in db.execute(select(RolePermission).where(RolePermission.is_deleted.is_(False))).scalars():
                perms.setdefault(rp.permission, set()).add(rp.role)
            for rd in db.execute(select(RoleDefinition).where(RoleDefinition.is_deleted.is_(False))).scalars():
                roles[rd.code] = (rd.scope, rd.name_ru, rd.name_kk)
        finally:
            db.close()
    except Exception:  # noqa: BLE001 — tables not created yet (first start, migrations pending)
        perms = {}
    if not perms:
        perms = {p: set(r) for p, r in {**COMPANY_PERMISSIONS, **STAFF_PERMISSIONS}.items()}
    _cache.update(at=time.monotonic(), perms=perms, roles=roles)
    return _cache


def company_can(role: str | None, perm: str) -> bool:
    return bool(role) and not perm.startswith("admin.") and role in _load()["perms"].get(perm, ())


def staff_can(staff_role: str | None, perm: str) -> bool:
    return bool(staff_role) and perm.startswith("admin.") and staff_role in _load()["perms"].get(perm, ())


def roles_in_scope(scope: str) -> list[str]:
    """Role codes of a scope (client / carrier / staff): built-in first, then roles added by an administrator."""
    builtin = [r for r, s in BUILTIN_ROLES.items() if s == scope]
    extra = sorted(c for c, (s, _, _) in (_load()["roles"] or {}).items() if s == scope and c not in BUILTIN_ROLES)
    return builtin + extra


def role_name(code: str, locale: str = "ru") -> str | None:
    info = (_load()["roles"] or {}).get(code)
    if not info:
        return None
    return (info[2] if locale == "kk" and info[2] else info[1]) or code


def all_permissions(scope: str) -> list[str]:
    return list(STAFF_PERMISSIONS if scope == "staff" else COMPANY_PERMISSIONS)
