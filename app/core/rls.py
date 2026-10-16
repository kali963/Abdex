"""Row-level security in PostgreSQL — the second line after the application checks (NFR-DB-07).

Every transaction tells PostgreSQL whose request it serves:

* ``app.company_id`` — the active company of the signed-in user ('' when there is none);
* ``app.rls_bypass`` — 'on' for platform staff (their access is checked by the permission matrix and audited),
  for background jobs and for explicit system steps (``system()``), 'off' otherwise.

Policies (migration 0006) hide other companies' rows of company-owned tables from SELECT/UPDATE/DELETE even if
an application check were missing. Inserts are not limited (a deal participant's action legitimately creates
rows for the counterparty, e.g. a fee invoice), but such cross-company steps run inside ``system()``.
SQLite (development, tests) has no RLS: the functions are no-ops there.
"""
from __future__ import annotations

from contextlib import contextmanager

from sqlalchemy import event, text
from sqlalchemy.orm import Session

from app.core.context import get_ctx

# table -> visibility predicate for a company context (cur = current company id)
CUR = "nullif(current_setting('app.company_id', true), '')::uuid"
BYPASS = "current_setting('app.rls_bypass', true) = 'on'"
_DEALS = f"(SELECT d.id FROM deals d WHERE d.client_company_id = {CUR} OR d.carrier_company_id = {CUR})"  # noqa: S608 — constant policy text, no input
POLICIES: dict[str, str] = {
    "bank_accounts": f"company_id = {CUR}",
    "invoices": f"company_id = {CUR}",
    "payments": f"company_id = {CUR}",
    "promo_redemptions": f"company_id = {CUR}",
    "order_templates": f"company_id = {CUR}",
    "saved_searches": f"company_id = {CUR}",
    "shipment_plans": f"company_id = {CUR}",
    "shipment_plan_lines": f"plan_id IN (SELECT p.id FROM shipment_plans p WHERE p.company_id = {CUR})",  # noqa: S608
    "webhook_endpoints": f"company_id = {CUR}",
    "webhook_deliveries": f"endpoint_id IN (SELECT w.id FROM webhook_endpoints w WHERE w.company_id = {CUR})",  # noqa: S608
    "verification_documents": f"company_id = {CUR}",
    "documents": f"company_id = {CUR} OR deal_id IN {_DEALS}",
    "payment_intents": f"company_id = {CUR}",
    "transport_doc_registrations": f"deal_id IN {_DEALS}",
}


def _bypass(ctx) -> bool:
    from app.modules.accounts.models import STAFF_ROLES

    return bool(ctx.extra.get("rls_bypass")) or ctx.role in STAFF_ROLES or not ctx.request_id


def _apply(connection) -> None:
    if connection.dialect.name != "postgresql":
        return
    ctx = get_ctx()
    connection.execute(text("SELECT set_config('app.company_id', :cid, true), set_config('app.rls_bypass', :bp, true)"),
                       {"cid": str(ctx.company_id or ""), "bp": "on" if _bypass(ctx) else "off"})


@event.listens_for(Session, "after_begin")
def _on_begin(session: Session, transaction, connection) -> None:
    _apply(connection)


def apply(db: Session) -> None:
    """Re-apply after the principal is known (the transaction may have started before)."""
    if db.in_transaction() and db.get_bind().dialect.name == "postgresql":
        _apply(db.connection())


@contextmanager
def system(db: Session):
    """A step that legitimately touches another company's rows (fee invoice, webhook fan-out)."""
    ctx = get_ctx()
    before = ctx.extra.get("rls_bypass")
    ctx.extra["rls_bypass"] = True
    apply(db)
    try:
        yield
        db.flush()  # pending cross-company writes go out while the bypass is active
    finally:
        if before is None:
            ctx.extra.pop("rls_bypass", None)
        else:
            ctx.extra["rls_bypass"] = before
        apply(db)


def policy_sql(table: str) -> list[str]:
    pred = POLICIES[table]
    return [
        f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY",
        f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY",
        f"CREATE POLICY {table}_read ON {table} FOR SELECT USING ({BYPASS} OR {pred})",
        f"CREATE POLICY {table}_insert ON {table} FOR INSERT WITH CHECK (true)",
        f"CREATE POLICY {table}_update ON {table} FOR UPDATE USING ({BYPASS} OR {pred})",
        f"CREATE POLICY {table}_delete ON {table} FOR DELETE USING ({BYPASS} OR {pred})",
    ]


def drop_sql(table: str) -> list[str]:
    return [f"DROP POLICY IF EXISTS {table}_{p} ON {table}" for p in ("read", "insert", "update", "delete")] + [
        f"ALTER TABLE {table} NO FORCE ROW LEVEL SECURITY", f"ALTER TABLE {table} DISABLE ROW LEVEL SECURITY"]
