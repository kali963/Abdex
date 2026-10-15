"""Editable permission matrix and roles (FR-ACL-06)."""
from __future__ import annotations

import re

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from app.core.audit import audit
from app.core.context import get_ctx
from app.core.errors import ValidationFailed
from app.core.i18n import translate
from app.modules.accounts import permissions as P
from app.modules.accounts.models import RoleDefinition, RolePermission

SCOPES = ("client", "carrier", "staff")
_CODE_RE = re.compile(r"^[a-z][a-z0-9_]{2,19}$")


def seed(db: Session) -> None:
    """Built-in roles and the default matrix; never overwrites what an administrator changed."""
    existing = set(db.execute(select(RoleDefinition.code)).scalars())
    for code, scope in P.BUILTIN_ROLES.items():
        if code not in existing:
            key = f"staff.{code}" if scope == "staff" else f"role.{code}"
            db.add(RoleDefinition(code=code, scope=scope, name_ru=translate(key, "ru"), name_kk=translate(key, "kk"),
                                  builtin=True))
    # Permissions introduced by a release get their default grants once; later edits by an administrator
    # (including removing every grant) are never overwritten, because the permission is then "known".
    from app.modules.platform.service import get_setting, set_setting

    known = set(get_setting(db, "acl.known_permissions", []) or [])
    defaults = {**P.COMPANY_PERMISSIONS, **P.STAFF_PERMISSIONS}
    have = set(db.execute(select(RolePermission.role, RolePermission.permission)).all())
    for perm, roles in defaults.items():
        if perm in known:
            continue
        for role in roles:
            if (role, perm) not in have:
                db.add(RolePermission(role=role, permission=perm))
    if set(defaults) - known:
        set_setting(db, "acl.known_permissions", sorted(known | set(defaults)), "FR-ACL-06: permissions seeded")
    db.flush()
    P.invalidate()


def roles(db: Session, scope: str) -> list[RoleDefinition]:
    order = {c: i for i, c in enumerate(P.BUILTIN_ROLES)}
    rows = db.execute(select(RoleDefinition).where(RoleDefinition.scope == scope,
                                                   RoleDefinition.is_deleted.is_(False))).scalars()
    return sorted(rows, key=lambda r: (order.get(r.code, 100), r.code))


def grants(db: Session) -> set[tuple[str, str]]:
    return {(rp.role, rp.permission) for rp in db.execute(select(RolePermission)).scalars()}


def save_matrix(db: Session, scope: str, wanted: set[tuple[str, str]]) -> dict:
    if scope not in SCOPES:
        raise ValidationFailed({"scope": "error.invalid_choice"})
    role_codes = {r.code for r in roles(db, scope)}
    perms = set(P.all_permissions(scope))
    wanted = {(r, p) for r, p in wanted if r in role_codes and p in perms}
    wanted |= {(r, p) for r, p in P.LOCKED if r in role_codes and p in perms}
    wanted -= P.NEVER
    current = {(r, p) for r, p in grants(db) if r in role_codes and p in perms}
    added, removed = wanted - current, current - wanted
    for r, p in added:
        db.add(RolePermission(role=r, permission=p, created_by=get_ctx().user_id))
    for r, p in removed:
        db.execute(delete(RolePermission).where(RolePermission.role == r, RolePermission.permission == p))
    if added or removed:
        audit(db, "acl.matrix_changed", object_type="acl", object_id=scope,
              details={"added": sorted(f"{r}:{p}" for r, p in added),
                       "removed": sorted(f"{r}:{p}" for r, p in removed)})
    db.flush()
    P.invalidate()
    return {"added": len(added), "removed": len(removed)}


def add_role(db: Session, *, code: str, scope: str, name_ru: str, name_kk: str = "") -> RoleDefinition:
    code = (code or "").strip().lower()
    errors = {}
    if not _CODE_RE.match(code):
        errors["code"] = "error.role_code"
    elif db.execute(select(RoleDefinition.id).where(RoleDefinition.code == code)).first():
        errors["code"] = "error.role_exists"
    if scope not in SCOPES:
        errors["scope"] = "error.invalid_choice"
    if not name_ru.strip():
        errors["name_ru"] = "error.required"
    if errors:
        raise ValidationFailed(errors)
    rd = RoleDefinition(code=code, scope=scope, name_ru=name_ru.strip()[:100], name_kk=name_kk.strip()[:100],
                        created_by=get_ctx().user_id)
    db.add(rd)
    db.flush()
    audit(db, "acl.role_added", object_type="acl", object_id=code, details={"scope": scope})
    P.invalidate()
    return rd
