"""Integrations: qualified signatures, online payments, electronic transport documents
(FR-DOC-07, GOV-DS-04, FR-BIL-06, GOV-TR-02..05).

Revision ID: 0007
Revises: 0006
"""
import sqlalchemy as sa
from alembic import op

import app.db

RLS_TABLES = ("payment_intents", "transport_doc_registrations")

revision = '0007'
down_revision = '0006'
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table('transport_doc_registrations',
    sa.Column('document_id', sa.Uuid(), nullable=False),
    sa.Column('deal_id', sa.Uuid(), nullable=False),
    sa.Column('mode', sa.String(length=10), nullable=False),
    sa.Column('paper_number', sa.String(length=40), nullable=False),
    sa.Column('status', sa.String(length=12), nullable=False),
    sa.Column('external_number', sa.String(length=60), nullable=False),
    sa.Column('attempts', sa.Integer(), nullable=False),
    sa.Column('last_error', sa.String(length=300), nullable=False),
    sa.Column('registered_at', app.db.AwareDateTime(timezone=True), nullable=True),
    sa.Column('data', sa.Text(), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('updated_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('created_by', sa.Uuid(), nullable=True),
    sa.Column('updated_by', sa.Uuid(), nullable=True),
    sa.Column('is_deleted', sa.Boolean(), nullable=False),
    sa.ForeignKeyConstraint(['deal_id'], ['deals.id'], ),
    sa.ForeignKeyConstraint(['document_id'], ['documents.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('document_id')
    )
    op.create_index(op.f('ix_transport_doc_registrations_deal_id'), 'transport_doc_registrations', ['deal_id'], unique=False)
    op.create_index(op.f('ix_transport_doc_registrations_status'), 'transport_doc_registrations', ['status'], unique=False)
    op.create_table('payment_intents',
    sa.Column('invoice_id', sa.Uuid(), nullable=False),
    sa.Column('company_id', sa.Uuid(), nullable=False),
    sa.Column('provider', sa.String(length=40), nullable=False),
    sa.Column('provider_ref', sa.String(length=80), nullable=False),
    sa.Column('amount_minor', sa.BigInteger(), nullable=False),
    sa.Column('currency', sa.String(length=3), nullable=False),
    sa.Column('status', sa.String(length=10), nullable=False),
    sa.Column('checkout_url', sa.String(length=500), nullable=False),
    sa.Column('paid_at', app.db.AwareDateTime(timezone=True), nullable=True),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('updated_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('created_by', sa.Uuid(), nullable=True),
    sa.Column('updated_by', sa.Uuid(), nullable=True),
    sa.Column('is_deleted', sa.Boolean(), nullable=False),
    sa.ForeignKeyConstraint(['company_id'], ['companies.id'], ),
    sa.ForeignKeyConstraint(['invoice_id'], ['invoices.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('provider_ref')
    )
    op.create_index(op.f('ix_payment_intents_company_id'), 'payment_intents', ['company_id'], unique=False)
    op.create_index(op.f('ix_payment_intents_invoice_id'), 'payment_intents', ['invoice_id'], unique=False)
    op.create_index(op.f('ix_payment_intents_status'), 'payment_intents', ['status'], unique=False)
    op.create_table('qualified_signatures',
    sa.Column('signature_id', sa.Uuid(), nullable=False),
    sa.Column('document_id', sa.Uuid(), nullable=False),
    sa.Column('package', sa.Text(), nullable=False),
    sa.Column('provider', sa.String(length=40), nullable=False),
    sa.Column('document_hash', sa.String(length=64), nullable=False),
    sa.Column('signer_iin', sa.String(length=12), nullable=False),
    sa.Column('signer_bin', sa.String(length=12), nullable=False),
    sa.Column('signer_name', sa.String(length=300), nullable=False),
    sa.Column('cert_serial', sa.String(length=80), nullable=False),
    sa.Column('cert_issuer', sa.String(length=300), nullable=False),
    sa.Column('cert_not_after', app.db.AwareDateTime(timezone=True), nullable=True),
    sa.Column('tsp_time', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('verify_result', sa.Text(), nullable=False),
    sa.Column('id', sa.Uuid(), nullable=False),
    sa.Column('created_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('updated_at', app.db.AwareDateTime(timezone=True), nullable=False),
    sa.Column('created_by', sa.Uuid(), nullable=True),
    sa.Column('updated_by', sa.Uuid(), nullable=True),
    sa.Column('is_deleted', sa.Boolean(), nullable=False),
    sa.ForeignKeyConstraint(['document_id'], ['documents.id'], ),
    sa.ForeignKeyConstraint(['signature_id'], ['signatures.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('signature_id')
    )
    op.create_index(op.f('ix_qualified_signatures_document_id'), 'qualified_signatures', ['document_id'], unique=False)

    if op.get_bind().dialect.name == "postgresql":
        from app.core.rls import policy_sql

        op.execute("CREATE TRIGGER qualified_signatures_append_only BEFORE UPDATE OR DELETE ON qualified_signatures "
                   "FOR EACH ROW EXECUTE FUNCTION abdex_append_only();")
        for table in RLS_TABLES:
            for stmt in policy_sql(table):
                op.execute(stmt)

def downgrade() -> None:
    if op.get_bind().dialect.name == "postgresql":
        from app.core.rls import drop_sql

        for table in RLS_TABLES:
            for stmt in drop_sql(table):
                op.execute(stmt)
        op.execute("DROP TRIGGER IF EXISTS qualified_signatures_append_only ON qualified_signatures;")
    op.drop_index(op.f('ix_qualified_signatures_document_id'), table_name='qualified_signatures')
    op.drop_table('qualified_signatures')
    op.drop_index(op.f('ix_payment_intents_status'), table_name='payment_intents')
    op.drop_index(op.f('ix_payment_intents_invoice_id'), table_name='payment_intents')
    op.drop_index(op.f('ix_payment_intents_company_id'), table_name='payment_intents')
    op.drop_table('payment_intents')
    op.drop_index(op.f('ix_transport_doc_registrations_status'), table_name='transport_doc_registrations')
    op.drop_index(op.f('ix_transport_doc_registrations_deal_id'), table_name='transport_doc_registrations')
    op.drop_table('transport_doc_registrations')
