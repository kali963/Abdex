"""Cycle 2, part 2: second-person approvals, antifraud rules, device marks, security alerts, product events,
shipment plans (SEC-AZ-05, SEC-FRD-01..03, SEC-LOG-06, FR-BI-07, FR-PLAN-03).

Revision ID: 0005
Revises: 0004
"""
import sqlalchemy as sa
from alembic import op

import app.db

revision = '0005'
down_revision = '0004'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('antifraud_rules',
    sa.Column('code', sa.String(length=40), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('action', sa.String(length=10), nullable=False),
    sa.Column('severity', sa.String(length=10), nullable=False),
    sa.Column('threshold', sa.Integer(), nullable=False),
    sa.Column('window_minutes', sa.Integer(), nullable=False),
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
    op.create_table('device_events',
    sa.Column('action', sa.String(length=30), nullable=False),
    sa.Column('device_id', sa.String(length=64), nullable=False),
    sa.Column('ip', sa.String(length=64), nullable=False),
    sa.Column('user_id', sa.Uuid(), nullable=True),
    sa.Column('company_id', sa.Uuid(), nullable=True),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('updated_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('created_by', sa.Uuid(), nullable=True),
    sa.Column('updated_by', sa.Uuid(), nullable=True),
    sa.Column('is_deleted', sa.Boolean(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_device_events_action'), 'device_events', ['action'], unique=False)
    op.create_index(op.f('ix_device_events_company_id'), 'device_events', ['company_id'], unique=False)
    op.create_index(op.f('ix_device_events_device_id'), 'device_events', ['device_id'], unique=False)
    op.create_index(op.f('ix_device_events_ip'), 'device_events', ['ip'], unique=False)
    op.create_index(op.f('ix_device_events_user_id'), 'device_events', ['user_id'], unique=False)
    op.create_table('product_events',
    sa.Column('name', sa.String(length=40), nullable=False),
    sa.Column('anon_id', sa.String(length=16), nullable=False),
    sa.Column('role', sa.String(length=20), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('updated_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('created_by', sa.Uuid(), nullable=True),
    sa.Column('updated_by', sa.Uuid(), nullable=True),
    sa.Column('is_deleted', sa.Boolean(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_product_events_anon_id'), 'product_events', ['anon_id'], unique=False)
    op.create_index(op.f('ix_product_events_name'), 'product_events', ['name'], unique=False)
    op.create_table('security_alerts',
    sa.Column('kind', sa.String(length=40), nullable=False),
    sa.Column('severity', sa.String(length=10), nullable=False),
    sa.Column('user_id', sa.Uuid(), nullable=True),
    sa.Column('details', sa.Text(), nullable=False),
    sa.Column('dedup_key', sa.String(length=120), nullable=False),
    sa.Column('status', sa.String(length=10), nullable=False),
    sa.Column('closed_by', sa.Uuid(), nullable=True),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('updated_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('created_by', sa.Uuid(), nullable=True),
    sa.Column('updated_by', sa.Uuid(), nullable=True),
    sa.Column('is_deleted', sa.Boolean(), nullable=False),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('dedup_key')
    )
    op.create_index(op.f('ix_security_alerts_kind'), 'security_alerts', ['kind'], unique=False)
    op.create_index(op.f('ix_security_alerts_status'), 'security_alerts', ['status'], unique=False)
    op.create_table('approval_requests',
    sa.Column('kind', sa.String(length=30), nullable=False),
    sa.Column('object_id', sa.String(length=64), nullable=False),
    sa.Column('payload', sa.Text(), nullable=False),
    sa.Column('summary', sa.String(length=300), nullable=False),
    sa.Column('reason', sa.String(length=500), nullable=False),
    sa.Column('status', sa.String(length=10), nullable=False),
    sa.Column('requested_by', sa.Uuid(), nullable=False),
    sa.Column('decided_by', sa.Uuid(), nullable=True),
    sa.Column('decided_at', app.db.AwareDateTime(timezone=True), nullable=True),
    sa.Column('decision_note', sa.String(length=500), nullable=False),
    sa.Column('expires_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('updated_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('created_by', sa.Uuid(), nullable=True),
    sa.Column('updated_by', sa.Uuid(), nullable=True),
    sa.Column('is_deleted', sa.Boolean(), nullable=False),
    sa.ForeignKeyConstraint(['decided_by'], ['users.id'], ),
    sa.ForeignKeyConstraint(['requested_by'], ['users.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_approval_requests_kind'), 'approval_requests', ['kind'], unique=False)
    op.create_index(op.f('ix_approval_requests_status'), 'approval_requests', ['status'], unique=False)
    op.create_table('shipment_plans',
    sa.Column('company_id', sa.Uuid(), nullable=False),
    sa.Column('name', sa.String(length=200), nullable=False),
    sa.Column('period_from', sa.Date(), nullable=False),
    sa.Column('period_to', sa.Date(), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('updated_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('created_by', sa.Uuid(), nullable=True),
    sa.Column('updated_by', sa.Uuid(), nullable=True),
    sa.Column('is_deleted', sa.Boolean(), nullable=False),
    sa.ForeignKeyConstraint(['company_id'], ['companies.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_shipment_plans_company_id'), 'shipment_plans', ['company_id'], unique=False)
    op.create_table('shipment_plan_lines',
    sa.Column('plan_id', sa.Uuid(), nullable=False),
    sa.Column('from_city', sa.String(length=100), nullable=False),
    sa.Column('to_city', sa.String(length=100), nullable=False),
    sa.Column('trips', sa.Integer(), nullable=False),
    sa.Column('weight_kg', sa.Integer(), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('updated_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('created_by', sa.Uuid(), nullable=True),
    sa.Column('updated_by', sa.Uuid(), nullable=True),
    sa.Column('is_deleted', sa.Boolean(), nullable=False),
    sa.ForeignKeyConstraint(['plan_id'], ['shipment_plans.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_shipment_plan_lines_plan_id'), 'shipment_plan_lines', ['plan_id'], unique=False)


def downgrade() -> None:
    op.drop_index(op.f('ix_shipment_plan_lines_plan_id'), table_name='shipment_plan_lines')
    op.drop_table('shipment_plan_lines')
    op.drop_index(op.f('ix_shipment_plans_company_id'), table_name='shipment_plans')
    op.drop_table('shipment_plans')
    op.drop_index(op.f('ix_approval_requests_status'), table_name='approval_requests')
    op.drop_index(op.f('ix_approval_requests_kind'), table_name='approval_requests')
    op.drop_table('approval_requests')
    op.drop_index(op.f('ix_security_alerts_status'), table_name='security_alerts')
    op.drop_index(op.f('ix_security_alerts_kind'), table_name='security_alerts')
    op.drop_table('security_alerts')
    op.drop_index(op.f('ix_product_events_name'), table_name='product_events')
    op.drop_index(op.f('ix_product_events_anon_id'), table_name='product_events')
    op.drop_table('product_events')
    op.drop_index(op.f('ix_device_events_user_id'), table_name='device_events')
    op.drop_index(op.f('ix_device_events_ip'), table_name='device_events')
    op.drop_index(op.f('ix_device_events_device_id'), table_name='device_events')
    op.drop_index(op.f('ix_device_events_company_id'), table_name='device_events')
    op.drop_index(op.f('ix_device_events_action'), table_name='device_events')
    op.drop_table('device_events')
    op.drop_table('antifraud_rules')
