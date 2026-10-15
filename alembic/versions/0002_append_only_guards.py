"""Append-only guards for snapshots, accruals, audit and status history (NFR-DB-05, SEC-LOG-03).

On PostgreSQL a trigger rejects UPDATE/DELETE for every role, including the application role.
In production additionally revoke the privileges from the application role:
    REVOKE UPDATE, DELETE ON <table> FROM abdex_app;

Revision ID: 0002
Revises: 0001
"""
from alembic import op

revision = "0002"
down_revision = "0001"
branch_labels = None
depends_on = None

TABLES = ("audit_log", "status_history", "deal_snapshots", "accruals", "payments", "signatures", "order_versions",
          "bid_events", "messages", "message_hidden", "checkpoints", "incidents", "registry_checks",
          "integration_calls", "kpi_snapshots", "dictionary_history")


def upgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return  # SQLite (dev/tests): enforced at ORM level in app/db.py
    op.execute("""
        CREATE OR REPLACE FUNCTION abdex_append_only() RETURNS trigger AS $$
        BEGIN
            RAISE EXCEPTION 'table % is append-only', TG_TABLE_NAME;
        END; $$ LANGUAGE plpgsql;
    """)
    for t in TABLES:
        op.execute(f"CREATE TRIGGER {t}_append_only BEFORE UPDATE OR DELETE ON {t} "
                   f"FOR EACH ROW EXECUTE FUNCTION abdex_append_only();")


def downgrade() -> None:
    if op.get_bind().dialect.name != "postgresql":
        return
    for t in TABLES:
        op.execute(f"DROP TRIGGER IF EXISTS {t}_append_only ON {t};")
    op.execute("DROP FUNCTION IF EXISTS abdex_append_only();")
