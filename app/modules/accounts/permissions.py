"""Role/permission matrix (section 5, FR-ACL-01, SEC-AZ-03 default deny).

A permission not listed here is denied for everybody. Each web/API endpoint declares the
permission it needs; tests/test_permissions.py verifies that no route is left without one.
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
}


def company_can(role: str | None, perm: str) -> bool:
    return bool(role) and role in COMPANY_PERMISSIONS.get(perm, frozenset())


def staff_can(staff_role: str | None, perm: str) -> bool:
    return bool(staff_role) and staff_role in STAFF_PERMISSIONS.get(perm, frozenset())
