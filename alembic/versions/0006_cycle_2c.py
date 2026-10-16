"""Cycle 2, part 3: field encryption with blind indexes, row-level security, processing register,
driver biometrics (NFR-DB-07, NFR-DB-08, SEC-DAT-02, SEC-DAT-10, SEC-DAT-11, FR-KYC-08).

Existing IIN, phone, driver licence and IBAN values are encrypted in place with the current field key
(FIELD_ENCRYPTION_KEYS_FILE / FIELD_ENCRYPTION_KEYS must be available to the migration in production).

Revision ID: 0006
Revises: 0005
"""
import sqlalchemy as sa
from alembic import op

import app.db

revision = '0006'
down_revision = '0005'
branch_labels = None
depends_on = None

ENCRYPTED = {"drivers": ("iin", "phone", "license_number"), "bank_accounts": ("iban",)}
# frozen list: later migrations add policies for their own tables
RLS_TABLES = ("bank_accounts", "invoices", "payments", "promo_redemptions", "order_templates", "saved_searches",
              "shipment_plans", "shipment_plan_lines", "webhook_endpoints", "webhook_deliveries",
              "verification_documents", "documents")
INDEX = {"drivers": ("iin", "iin_index", "iin"), "bank_accounts": ("iban", "iban_index", "iban")}


def _rewrite(encrypt: bool) -> None:
    from app.core import crypto

    conn = op.get_bind()
    for table, cols in ENCRYPTED.items():
        src, idx_col, purpose = INDEX[table]
        rows = conn.execute(sa.text(f"SELECT id, {', '.join(cols)} FROM {table}")).mappings().all()  # noqa: S608
        for row in rows:
            values = {}
            for col in cols:
                raw = row[col]
                if encrypt:
                    values[col] = crypto.encrypt(crypto.decrypt(raw, f"{table}.{col}"), f"{table}.{col}")
                else:
                    values[col] = crypto.decrypt(raw, f"{table}.{col}")
            sets = ", ".join(f"{c} = :{c}" for c in values)
            if encrypt:
                values[idx_col] = crypto.blind_index(crypto.decrypt(row[src], f"{table}.{src}"), purpose)
                sets += f", {idx_col} = :{idx_col}"
            conn.execute(sa.text(f"UPDATE {table} SET {sets} WHERE id = :id"), {**values, "id": row["id"]})  # noqa: S608


def upgrade() -> None:
    op.create_table('processing_records',
    sa.Column('code', sa.String(length=40), nullable=False),
    sa.Column('purpose', sa.String(length=300), nullable=False),
    sa.Column('data_categories', sa.String(length=500), nullable=False),
    sa.Column('legal_basis', sa.String(length=300), nullable=False),
    sa.Column('recipient', sa.String(length=200), nullable=False),
    sa.Column('cross_border', sa.Boolean(), nullable=False),
    sa.Column('countries', sa.String(length=200), nullable=False),
    sa.Column('safeguards', sa.String(length=500), nullable=False),
    sa.Column('retention', sa.String(length=200), nullable=False),
    sa.Column('adapter', sa.String(length=40), nullable=False),
    sa.Column('active', sa.Boolean(), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('updated_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('created_by', sa.Uuid(), nullable=True),
    sa.Column('updated_by', sa.Uuid(), nullable=True),
    sa.Column('is_deleted', sa.Boolean(), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('code')
    )
    op.create_table('biometric_checks',
    sa.Column('driver_id', sa.Uuid(), nullable=False),
    sa.Column('company_id', sa.Uuid(), nullable=True),
    sa.Column('provider', sa.String(length=40), nullable=False),
    sa.Column('match', sa.Boolean(), nullable=False),
    sa.Column('liveness', sa.Boolean(), nullable=False),
    sa.Column('score', sa.Integer(), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('selfie_file_id', sa.Uuid(), nullable=True),
    sa.Column('document_file_id', sa.Uuid(), nullable=True),
    sa.Column('images_delete_after', app.db.AwareDateTime(timezone=True), nullable=True),
    sa.Column('images_deleted_at', app.db.AwareDateTime(timezone=True), nullable=True),
    sa.Column('valid_until', sa.Date(), nullable=True),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('updated_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('created_by', sa.Uuid(), nullable=True),
    sa.Column('updated_by', sa.Uuid(), nullable=True),
    sa.Column('is_deleted', sa.Boolean(), nullable=False),
    sa.ForeignKeyConstraint(['company_id'], ['companies.id'], ),
    sa.ForeignKeyConstraint(['document_file_id'], ['stored_files.id'], ),
    sa.ForeignKeyConstraint(['driver_id'], ['drivers.id'], ),
    sa.ForeignKeyConstraint(['selfie_file_id'], ['stored_files.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_biometric_checks_company_id'), 'biometric_checks', ['company_id'], unique=False)
    op.create_index(op.f('ix_biometric_checks_driver_id'), 'biometric_checks', ['driver_id'], unique=False)
    with op.batch_alter_table('bank_accounts') as batch:
        batch.add_column(sa.Column('iban_index', sa.String(length=40), nullable=False, server_default=''))
        batch.alter_column('iban', existing_type=sa.String(length=34), type_=sa.Text(), existing_nullable=False)
        batch.drop_index('ix_bank_accounts_iban')
        batch.create_index('ix_bank_accounts_iban_index', ['iban_index'], unique=False)
    with op.batch_alter_table('drivers') as batch:
        batch.add_column(sa.Column('iin_index', sa.String(length=40), nullable=False, server_default=''))
        batch.alter_column('iin', existing_type=sa.String(length=12), type_=sa.Text(), existing_nullable=False)
        batch.alter_column('phone', existing_type=sa.String(length=20), type_=sa.Text(), existing_nullable=False)
        batch.alter_column('license_number', existing_type=sa.String(length=30), type_=sa.Text(),
                           existing_nullable=False)
        batch.drop_index('ix_drivers_iin')
        batch.create_index('ix_drivers_iin_index', ['iin_index'], unique=False)
    _rewrite(encrypt=True)
    if op.get_bind().dialect.name == "postgresql":
        from app.core.rls import policy_sql

        for table in RLS_TABLES:
            for stmt in policy_sql(table):
                op.execute(stmt)


def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        from app.core.rls import drop_sql

        for table in RLS_TABLES:
            for stmt in drop_sql(table):
                op.execute(stmt)
    _rewrite(encrypt=False)
    with op.batch_alter_table('drivers') as batch:
        batch.drop_index('ix_drivers_iin_index')
        batch.create_index('ix_drivers_iin', ['iin'], unique=False)
        batch.alter_column('license_number', existing_type=sa.Text(), type_=sa.String(length=30), existing_nullable=False)
        batch.alter_column('phone', existing_type=sa.Text(), type_=sa.String(length=20), existing_nullable=False)
        batch.alter_column('iin', existing_type=sa.Text(), type_=sa.String(length=12), existing_nullable=False)
        batch.drop_column('iin_index')
    with op.batch_alter_table('bank_accounts') as batch:
        batch.drop_index('ix_bank_accounts_iban_index')
        batch.create_index('ix_bank_accounts_iban', ['iban'], unique=False)
        batch.alter_column('iban', existing_type=sa.Text(), type_=sa.String(length=34), existing_nullable=False)
        batch.drop_column('iban_index')
    op.drop_index('ix_biometric_checks_driver_id', table_name='biometric_checks')
    op.drop_index('ix_biometric_checks_company_id', table_name='biometric_checks')
    op.drop_table('biometric_checks')
    op.drop_table('processing_records')
