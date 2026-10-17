"""API sandbox and customs data (FR-API-05, GOV-TR-06).

Revision ID: 0009
Revises: 0008
"""
import sqlalchemy as sa
from alembic import op

import app.db

RLS_TABLES = ("sandbox_objects", "customs_dossiers")

revision = '0009'
down_revision = '0008'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('sandbox_objects',
    sa.Column('company_id', sa.Uuid(), nullable=False),
    sa.Column('kind', sa.String(length=10), nullable=False),
    sa.Column('parent_id', sa.Uuid(), nullable=True),
    sa.Column('number', sa.String(length=30), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('data', sa.Text(), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('updated_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('created_by', sa.Uuid(), nullable=True),
    sa.Column('updated_by', sa.Uuid(), nullable=True),
    sa.Column('is_deleted', sa.Boolean(), nullable=False),
    sa.ForeignKeyConstraint(['company_id'], ['companies.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('sandbox_objects', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_sandbox_objects_company_id'), ['company_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_sandbox_objects_kind'), ['kind'], unique=False)
        batch_op.create_index(batch_op.f('ix_sandbox_objects_parent_id'), ['parent_id'], unique=False)

    op.create_table('customs_dossiers',
    sa.Column('deal_id', sa.Uuid(), nullable=False),
    sa.Column('status', sa.String(length=10), nullable=False),
    sa.Column('data', sa.Text(), nullable=False),
    sa.Column('ready_at', app.db.AwareDateTime(timezone=True), nullable=True),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('updated_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('created_by', sa.Uuid(), nullable=True),
    sa.Column('updated_by', sa.Uuid(), nullable=True),
    sa.Column('is_deleted', sa.Boolean(), nullable=False),
    sa.ForeignKeyConstraint(['deal_id'], ['deals.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('deal_id')
    )
    with op.batch_alter_table('api_keys', schema=None) as batch_op:
        batch_op.add_column(sa.Column('environment', sa.String(length=4), nullable=False, server_default='live'))

    with op.batch_alter_table('webhook_endpoints', schema=None) as batch_op:
        batch_op.add_column(sa.Column('sandbox', sa.Boolean(), nullable=False, server_default=sa.false()))

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
    with op.batch_alter_table('webhook_endpoints', schema=None) as batch_op:
        batch_op.drop_column('sandbox')

    with op.batch_alter_table('api_keys', schema=None) as batch_op:
        batch_op.drop_column('environment')

    op.drop_table('customs_dossiers')
    with op.batch_alter_table('sandbox_objects', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_sandbox_objects_parent_id'))
        batch_op.drop_index(batch_op.f('ix_sandbox_objects_kind'))
        batch_op.drop_index(batch_op.f('ix_sandbox_objects_company_id'))

    op.drop_table('sandbox_objects')
