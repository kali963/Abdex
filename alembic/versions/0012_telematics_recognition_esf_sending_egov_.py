"""Telematics positions, document recognition, ESF sending, eGov mobile login
(FR-TRK-05, M6, FR-BIL-07, FR-AUTH-09).

Revision ID: 0012
Revises: 0011
"""
import sqlalchemy as sa
from alembic import op

import app.db

RLS_TABLES = ("track_points", "telematics_connections", "esf_submissions")

revision = '0012'
down_revision = '0011'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('egov_sign_sessions',
    sa.Column('token_hash', sa.String(length=64), nullable=False),
    sa.Column('auth_token_hash', sa.String(length=64), nullable=False),
    sa.Column('browser_hash', sa.String(length=64), nullable=False),
    sa.Column('challenge', sa.String(length=200), nullable=False),
    sa.Column('status', sa.String(length=10), nullable=False),
    sa.Column('user_id', sa.Uuid(), nullable=True),
    sa.Column('error', sa.String(length=100), nullable=False),
    sa.Column('expires_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('updated_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('created_by', sa.Uuid(), nullable=True),
    sa.Column('updated_by', sa.Uuid(), nullable=True),
    sa.Column('is_deleted', sa.Boolean(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('token_hash')
    )
    op.create_table('telematics_connections',
    sa.Column('company_id', sa.Uuid(), nullable=False),
    sa.Column('url', sa.String(length=500), nullable=False),
    sa.Column('token', sa.Text(), nullable=False),
    sa.Column('active', sa.Boolean(), nullable=False),
    sa.Column('last_sync_at', app.db.AwareDateTime(timezone=True), nullable=True),
    sa.Column('last_error', sa.String(length=300), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('updated_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('created_by', sa.Uuid(), nullable=True),
    sa.Column('updated_by', sa.Uuid(), nullable=True),
    sa.Column('is_deleted', sa.Boolean(), nullable=False),
    sa.ForeignKeyConstraint(['company_id'], ['companies.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('company_id')
    )
    op.create_table('track_points',
    sa.Column('deal_id', sa.Uuid(), nullable=False),
    sa.Column('vehicle_id', sa.Uuid(), nullable=True),
    sa.Column('at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('lat', sa.Float(), nullable=False),
    sa.Column('lng', sa.Float(), nullable=False),
    sa.Column('speed_kmh', sa.Integer(), nullable=False),
    sa.Column('source', sa.String(length=20), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('updated_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('created_by', sa.Uuid(), nullable=True),
    sa.Column('updated_by', sa.Uuid(), nullable=True),
    sa.Column('is_deleted', sa.Boolean(), nullable=False),
    sa.ForeignKeyConstraint(['deal_id'], ['deals.id'], ),
    sa.ForeignKeyConstraint(['vehicle_id'], ['vehicles.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('deal_id', 'at', name='uq_track_point_time')
    )
    with op.batch_alter_table('track_points', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_track_points_at'), ['at'], unique=False)
        batch_op.create_index(batch_op.f('ix_track_points_deal_id'), ['deal_id'], unique=False)

    op.create_table('esf_submissions',
    sa.Column('invoice_id', sa.Uuid(), nullable=False),
    sa.Column('kind', sa.String(length=10), nullable=False),
    sa.Column('status', sa.String(length=12), nullable=False),
    sa.Column('registration_number', sa.String(length=60), nullable=False),
    sa.Column('attempts', sa.Integer(), nullable=False),
    sa.Column('next_attempt_at', app.db.AwareDateTime(timezone=True), nullable=True),
    sa.Column('last_error', sa.String(length=300), nullable=False),
    sa.Column('sent_at', app.db.AwareDateTime(timezone=True), nullable=True),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('updated_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('created_by', sa.Uuid(), nullable=True),
    sa.Column('updated_by', sa.Uuid(), nullable=True),
    sa.Column('is_deleted', sa.Boolean(), nullable=False),
    sa.ForeignKeyConstraint(['invoice_id'], ['invoices.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('invoice_id', 'kind', name='uq_esf_invoice_kind')
    )
    with op.batch_alter_table('esf_submissions', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_esf_submissions_invoice_id'), ['invoice_id'], unique=False)
        batch_op.create_index(batch_op.f('ix_esf_submissions_status'), ['status'], unique=False)

    with op.batch_alter_table('verification_documents', schema=None) as batch_op:
        batch_op.add_column(sa.Column('recognized', sa.Text(), nullable=False, server_default='{}'))

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
    with op.batch_alter_table('verification_documents', schema=None) as batch_op:
        batch_op.drop_column('recognized')

    with op.batch_alter_table('esf_submissions', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_esf_submissions_status'))
        batch_op.drop_index(batch_op.f('ix_esf_submissions_invoice_id'))

    op.drop_table('esf_submissions')
    with op.batch_alter_table('track_points', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_track_points_deal_id'))
        batch_op.drop_index(batch_op.f('ix_track_points_at'))

    op.drop_table('track_points')
    op.drop_table('telematics_connections')
    op.drop_table('egov_sign_sessions')
