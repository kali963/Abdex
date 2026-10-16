"""Paid digital modules and subscriptions, EDS login (FR-BIL-08, FR-PVD-07, FR-AUTH-09).

Revision ID: 0008
Revises: 0007
"""
import sqlalchemy as sa
from alembic import op

import app.db

RLS_TABLES = ("subscriptions",)


revision = '0008'
down_revision = '0007'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('digital_modules',
    sa.Column('code', sa.String(length=40), nullable=False),
    sa.Column('name', sa.String(length=200), nullable=False),
    sa.Column('description', sa.String(length=500), nullable=False),
    sa.Column('flag_key', sa.String(length=60), nullable=False),
    sa.Column('price_minor', sa.BigInteger(), nullable=False),
    sa.Column('currency', sa.String(length=3), nullable=False),
    sa.Column('period_days', sa.Integer(), nullable=False),
    sa.Column('income_type', sa.String(length=30), nullable=False),
    sa.Column('audience', sa.String(length=10), nullable=False),
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
    op.create_table('subscriptions',
    sa.Column('company_id', sa.Uuid(), nullable=False),
    sa.Column('module_id', sa.Uuid(), nullable=False),
    sa.Column('status', sa.String(length=12), nullable=False),
    sa.Column('auto_renew', sa.Boolean(), nullable=False),
    sa.Column('started_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('period_start', sa.Date(), nullable=False),
    sa.Column('period_end', sa.Date(), nullable=False),
    sa.Column('periods', sa.Integer(), nullable=False),
    sa.Column('cancelled_at', app.db.AwareDateTime(timezone=True), nullable=True),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('updated_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('created_by', sa.Uuid(), nullable=True),
    sa.Column('updated_by', sa.Uuid(), nullable=True),
    sa.Column('is_deleted', sa.Boolean(), nullable=False),
    sa.ForeignKeyConstraint(['company_id'], ['companies.id'], ),
    sa.ForeignKeyConstraint(['module_id'], ['digital_modules.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('company_id', 'module_id', name='uq_subscription_company_module')
    )
    with op.batch_alter_table('subscriptions', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_subscriptions_company_id'), ['company_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_subscriptions_module_id'), ['module_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_subscriptions_period_end'), ['period_end'], unique=False)
        batch_op.create_index(batch_op.f('ix_subscriptions_status'), ['status'], unique=False)

    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.add_column(sa.Column('iin', sa.Text(), nullable=False, server_default=''))  # Encrypted → TEXT
        batch_op.add_column(sa.Column('iin_index', sa.String(length=40), nullable=False, server_default=''))
        batch_op.add_column(sa.Column('eds_linked_at', app.db.AwareDateTime(timezone=True), nullable=True))
        batch_op.create_index(batch_op.f('ix_users_iin_index'), ['iin_index'], unique=False)

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
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_users_iin_index'))
        batch_op.drop_column('eds_linked_at')
        batch_op.drop_column('iin_index')
        batch_op.drop_column('iin')

    with op.batch_alter_table('subscriptions', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_subscriptions_status'))
        batch_op.drop_index(batch_op.f('ix_subscriptions_period_end'))
        batch_op.drop_index(batch_op.f('ix_subscriptions_module_id'))
        batch_op.drop_index(batch_op.f('ix_subscriptions_company_id'))

    op.drop_table('subscriptions')
    op.drop_table('digital_modules')
