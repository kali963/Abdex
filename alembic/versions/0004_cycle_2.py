"""Cycle 2: rating events, webhooks, order series and invites, notification schedule, promo codes,
support access, permission matrix in the database (FR-RAT, FR-API-03, FR-ORD-05, FR-BID-04, FR-NTF-04,
FR-BIL-09, FR-ADM-05, FR-ACL-06).

Revision ID: 0004
Revises: 0003
"""
import sqlalchemy as sa
from alembic import op

import app.db


revision = '0004'
down_revision = '0003'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('promo_codes',
    sa.Column('code', sa.String(length=40), nullable=False),
    sa.Column('kind', sa.String(length=10), nullable=False),
    sa.Column('value', sa.Integer(), nullable=False),
    sa.Column('valid_from', sa.Date(), nullable=False),
    sa.Column('valid_to', sa.Date(), nullable=True),
    sa.Column('max_uses', sa.Integer(), nullable=False),
    sa.Column('uses', sa.Integer(), nullable=False),
    sa.Column('deals_per_company', sa.Integer(), nullable=False),
    sa.Column('active', sa.Boolean(), nullable=False),
    sa.Column('description', sa.String(length=300), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('updated_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('created_by', sa.Uuid(), nullable=True),
    sa.Column('updated_by', sa.Uuid(), nullable=True),
    sa.Column('is_deleted', sa.Boolean(), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('code')
    )
    op.create_table('role_definitions',
    sa.Column('code', sa.String(length=20), nullable=False),
    sa.Column('scope', sa.String(length=10), nullable=False),
    sa.Column('name_ru', sa.String(length=100), nullable=False),
    sa.Column('name_kk', sa.String(length=100), nullable=False),
    sa.Column('builtin', sa.Boolean(), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('updated_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('created_by', sa.Uuid(), nullable=True),
    sa.Column('updated_by', sa.Uuid(), nullable=True),
    sa.Column('is_deleted', sa.Boolean(), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('code')
    )
    op.create_table('role_permissions',
    sa.Column('role', sa.String(length=20), nullable=False),
    sa.Column('permission', sa.String(length=40), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('updated_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('created_by', sa.Uuid(), nullable=True),
    sa.Column('updated_by', sa.Uuid(), nullable=True),
    sa.Column('is_deleted', sa.Boolean(), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('role', 'permission', name='uq_role_permission')
    )
    op.create_index(op.f('ix_role_permissions_role'), 'role_permissions', ['role'], unique=False)
    op.create_table('notification_prefs',
    sa.Column('user_id', sa.Uuid(), nullable=False),
    sa.Column('quiet_enabled', sa.Boolean(), nullable=False),
    sa.Column('quiet_from', sa.String(length=5), nullable=False),
    sa.Column('quiet_to', sa.String(length=5), nullable=False),
    sa.Column('digest', sa.String(length=10), nullable=False),
    sa.Column('digest_hour', sa.Integer(), nullable=False),
    sa.Column('digest_sent_at', app.db.AwareDateTime(timezone=True), nullable=True),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('updated_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('created_by', sa.Uuid(), nullable=True),
    sa.Column('updated_by', sa.Uuid(), nullable=True),
    sa.Column('is_deleted', sa.Boolean(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('user_id')
    )
    op.create_table('promo_redemptions',
    sa.Column('promo_id', sa.Uuid(), nullable=False),
    sa.Column('company_id', sa.Uuid(), nullable=False),
    sa.Column('free_until', sa.Date(), nullable=True),
    sa.Column('deals_used', sa.Integer(), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('updated_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('created_by', sa.Uuid(), nullable=True),
    sa.Column('updated_by', sa.Uuid(), nullable=True),
    sa.Column('is_deleted', sa.Boolean(), nullable=False),
    sa.ForeignKeyConstraint(['company_id'], ['companies.id'], ),
    sa.ForeignKeyConstraint(['promo_id'], ['promo_codes.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('promo_id', 'company_id', name='uq_promo_company')
    )
    op.create_index(op.f('ix_promo_redemptions_company_id'), 'promo_redemptions', ['company_id'], unique=False)
    op.create_index(op.f('ix_promo_redemptions_promo_id'), 'promo_redemptions', ['promo_id'], unique=False)
    op.create_table('support_access_grants',
    sa.Column('user_id', sa.Uuid(), nullable=False),
    sa.Column('valid_until', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('revoked_at', app.db.AwareDateTime(timezone=True), nullable=True),
    sa.Column('ticket_number', sa.String(length=30), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('updated_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('created_by', sa.Uuid(), nullable=True),
    sa.Column('updated_by', sa.Uuid(), nullable=True),
    sa.Column('is_deleted', sa.Boolean(), nullable=False),
    sa.ForeignKeyConstraint(['user_id'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_support_access_grants_user_id'), 'support_access_grants', ['user_id'], unique=False)
    op.create_table('webhook_endpoints',
    sa.Column('company_id', sa.Uuid(), nullable=False),
    sa.Column('url', sa.String(length=500), nullable=False),
    sa.Column('secret', sa.String(length=64), nullable=False),
    sa.Column('events', sa.String(length=300), nullable=False),
    sa.Column('active', sa.Boolean(), nullable=False),
    sa.Column('failures_in_row', sa.Integer(), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('updated_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('created_by', sa.Uuid(), nullable=True),
    sa.Column('updated_by', sa.Uuid(), nullable=True),
    sa.Column('is_deleted', sa.Boolean(), nullable=False),
    sa.ForeignKeyConstraint(['company_id'], ['companies.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_webhook_endpoints_company_id'), 'webhook_endpoints', ['company_id'], unique=False)
    op.create_table('order_invites',
    sa.Column('order_id', sa.Uuid(), nullable=False),
    sa.Column('carrier_company_id', sa.Uuid(), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('updated_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('created_by', sa.Uuid(), nullable=True),
    sa.Column('updated_by', sa.Uuid(), nullable=True),
    sa.Column('is_deleted', sa.Boolean(), nullable=False),
    sa.ForeignKeyConstraint(['carrier_company_id'], ['companies.id'], ),
    sa.ForeignKeyConstraint(['order_id'], ['orders.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('order_id', 'carrier_company_id', name='uq_order_invite')
    )
    op.create_index(op.f('ix_order_invites_order_id'), 'order_invites', ['order_id'], unique=False)
    op.create_table('order_series',
    sa.Column('company_id', sa.Uuid(), nullable=False),
    sa.Column('source_order_id', sa.Uuid(), nullable=False),
    sa.Column('name', sa.String(length=200), nullable=False),
    sa.Column('weekdays', sa.String(length=20), nullable=False),
    sa.Column('start_date', sa.Date(), nullable=False),
    sa.Column('end_date', sa.Date(), nullable=True),
    sa.Column('lead_days', sa.Integer(), nullable=False),
    sa.Column('auto_submit', sa.Boolean(), nullable=False),
    sa.Column('active', sa.Boolean(), nullable=False),
    sa.Column('last_load_date', sa.Date(), nullable=True),
    sa.Column('created_count', sa.Integer(), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('updated_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('created_by', sa.Uuid(), nullable=True),
    sa.Column('updated_by', sa.Uuid(), nullable=True),
    sa.Column('is_deleted', sa.Boolean(), nullable=False),
    sa.ForeignKeyConstraint(['company_id'], ['companies.id'], ),
    sa.ForeignKeyConstraint(['source_order_id'], ['orders.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_order_series_company_id'), 'order_series', ['company_id'], unique=False)
    op.create_table('webhook_deliveries',
    sa.Column('endpoint_id', sa.Uuid(), nullable=False),
    sa.Column('event', sa.String(length=60), nullable=False),
    sa.Column('event_id', sa.String(length=64), nullable=False),
    sa.Column('payload', sa.Text(), nullable=False),
    sa.Column('status', sa.String(length=10), nullable=False),
    sa.Column('attempts', sa.Integer(), nullable=False),
    sa.Column('next_attempt_at', app.db.AwareDateTime(timezone=True), nullable=True),
    sa.Column('last_status_code', sa.Integer(), nullable=False),
    sa.Column('last_error', sa.String(length=300), nullable=False),
    sa.Column('delivered_at', app.db.AwareDateTime(timezone=True), nullable=True),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('updated_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('created_by', sa.Uuid(), nullable=True),
    sa.Column('updated_by', sa.Uuid(), nullable=True),
    sa.Column('is_deleted', sa.Boolean(), nullable=False),
    sa.ForeignKeyConstraint(['endpoint_id'], ['webhook_endpoints.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_webhook_deliveries_endpoint_id'), 'webhook_deliveries', ['endpoint_id'], unique=False)
    op.create_index(op.f('ix_webhook_deliveries_event_id'), 'webhook_deliveries', ['event_id'], unique=False)
    op.create_index(op.f('ix_webhook_deliveries_next_attempt_at'), 'webhook_deliveries', ['next_attempt_at'], unique=False)
    op.create_index(op.f('ix_webhook_deliveries_status'), 'webhook_deliveries', ['status'], unique=False)
    op.create_table('rating_events',
    sa.Column('company_id', sa.Uuid(), nullable=False),
    sa.Column('kind', sa.String(length=20), nullable=False),
    sa.Column('deal_id', sa.Uuid(), nullable=True),
    sa.Column('delta', sa.Integer(), nullable=False),
    sa.Column('reason', sa.String(length=500), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('updated_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('created_by', sa.Uuid(), nullable=True),
    sa.Column('updated_by', sa.Uuid(), nullable=True),
    sa.Column('is_deleted', sa.Boolean(), nullable=False),
    sa.ForeignKeyConstraint(['company_id'], ['companies.id'], ),
    sa.ForeignKeyConstraint(['deal_id'], ['deals.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_rating_events_company_id'), 'rating_events', ['company_id'], unique=False)
    op.create_index(op.f('ix_rating_events_kind'), 'rating_events', ['kind'], unique=False)
    with op.batch_alter_table('disputes') as batch:
        batch.add_column(sa.Column('fault', sa.String(length=10), nullable=False, server_default=''))
    with op.batch_alter_table('user_sessions') as batch:
        batch.add_column(sa.Column('impersonator_id', sa.Uuid(), nullable=True))
        batch.add_column(sa.Column('impersonation_reason', sa.String(length=300), nullable=False, server_default=''))
        batch.create_foreign_key('fk_user_sessions_impersonator', 'users', ['impersonator_id'], ['id'])
    if op.get_bind().dialect.name == 'postgresql':
        # rating events are append-only like the other journals (0002)
        op.execute("CREATE TRIGGER rating_events_append_only BEFORE UPDATE OR DELETE ON rating_events "
                   "FOR EACH ROW EXECUTE FUNCTION abdex_append_only();")


def downgrade() -> None:
    if op.get_bind().dialect.name == 'postgresql':
        op.execute("DROP TRIGGER IF EXISTS rating_events_append_only ON rating_events;")
    with op.batch_alter_table('user_sessions') as batch:
        batch.drop_constraint('fk_user_sessions_impersonator', type_='foreignkey')
        batch.drop_column('impersonation_reason')
        batch.drop_column('impersonator_id')
    with op.batch_alter_table('disputes') as batch:
        batch.drop_column('fault')
    op.drop_index(op.f('ix_rating_events_kind'), table_name='rating_events')
    op.drop_index(op.f('ix_rating_events_company_id'), table_name='rating_events')
    op.drop_table('rating_events')
    op.drop_index(op.f('ix_webhook_deliveries_status'), table_name='webhook_deliveries')
    op.drop_index(op.f('ix_webhook_deliveries_next_attempt_at'), table_name='webhook_deliveries')
    op.drop_index(op.f('ix_webhook_deliveries_event_id'), table_name='webhook_deliveries')
    op.drop_index(op.f('ix_webhook_deliveries_endpoint_id'), table_name='webhook_deliveries')
    op.drop_table('webhook_deliveries')
    op.drop_index(op.f('ix_order_series_company_id'), table_name='order_series')
    op.drop_table('order_series')
    op.drop_index(op.f('ix_order_invites_order_id'), table_name='order_invites')
    op.drop_table('order_invites')
    op.drop_index(op.f('ix_webhook_endpoints_company_id'), table_name='webhook_endpoints')
    op.drop_table('webhook_endpoints')
    op.drop_index(op.f('ix_support_access_grants_user_id'), table_name='support_access_grants')
    op.drop_table('support_access_grants')
    op.drop_index(op.f('ix_promo_redemptions_promo_id'), table_name='promo_redemptions')
    op.drop_index(op.f('ix_promo_redemptions_company_id'), table_name='promo_redemptions')
    op.drop_table('promo_redemptions')
    op.drop_table('notification_prefs')
    op.drop_index(op.f('ix_role_permissions_role'), table_name='role_permissions')
    op.drop_table('role_permissions')
    op.drop_table('role_definitions')
    op.drop_table('promo_codes')
