"""Verification level L3, driver re-verification, exchange rates (section 8, FR-KYC-09, FR-LOC-04).

Revision ID: 0010
Revises: 0009
"""
import sqlalchemy as sa
from alembic import op

import app.db

revision = '0010'
down_revision = '0009'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('currency_rates',
    sa.Column('on_date', sa.Date(), nullable=False),
    sa.Column('code', sa.String(length=3), nullable=False),
    sa.Column('rate', sa.String(length=24), nullable=False),
    sa.Column('source', sa.String(length=20), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('updated_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('created_by', sa.Uuid(), nullable=True),
    sa.Column('updated_by', sa.Uuid(), nullable=True),
    sa.Column('is_deleted', sa.Boolean(), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('on_date', 'code', name='uq_currency_rate_day')
    )
    with op.batch_alter_table('currency_rates', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_currency_rates_on_date'), ['on_date'], unique=False)

    with op.batch_alter_table('companies', schema=None) as batch_op:
        batch_op.add_column(sa.Column('eds_confirmed_at', app.db.AwareDateTime(timezone=True), nullable=True))
        batch_op.add_column(sa.Column('eds_cert_serial', sa.String(length=80), nullable=False, server_default=''))

    with op.batch_alter_table('deals', schema=None) as batch_op:
        batch_op.add_column(sa.Column('fx_rate', sa.String(length=24), nullable=False, server_default='1'))
        batch_op.add_column(sa.Column('fx_date', sa.Date(), nullable=True))

    with op.batch_alter_table('drivers', schema=None) as batch_op:
        batch_op.add_column(sa.Column('reverify_reason', sa.String(length=40), nullable=False, server_default=''))
        batch_op.add_column(sa.Column('reverify_since', app.db.AwareDateTime(timezone=True), nullable=True))

    # deals in other currencies made before this revision have no recorded rate
    op.execute("UPDATE deals SET fx_rate = '' WHERE currency <> 'KZT'")


def downgrade() -> None:
    with op.batch_alter_table('drivers', schema=None) as batch_op:
        batch_op.drop_column('reverify_since')
        batch_op.drop_column('reverify_reason')

    with op.batch_alter_table('deals', schema=None) as batch_op:
        batch_op.drop_column('fx_date')
        batch_op.drop_column('fx_rate')

    with op.batch_alter_table('companies', schema=None) as batch_op:
        batch_op.drop_column('eds_cert_serial')
        batch_op.drop_column('eds_confirmed_at')

    with op.batch_alter_table('currency_rates', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_currency_rates_on_date'))

    op.drop_table('currency_rates')
