"""eGov mobile / eGov Business signing of deal documents (FR-DOC-07, GOV-DS-01).

Revision ID: 0013
Revises: 0012
"""
import sqlalchemy as sa
from alembic import op

revision = '0013'
down_revision = '0012'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('egov_sign_sessions', schema=None) as batch_op:
        batch_op.add_column(sa.Column('purpose', sa.String(length=10), server_default='login', nullable=False))
        batch_op.add_column(sa.Column('document_id', sa.Uuid(), nullable=True))
        batch_op.add_column(sa.Column('company_id', sa.Uuid(), nullable=True))
        batch_op.create_foreign_key('fk_egov_sign_sessions_document_id_documents', 'documents', ['document_id'], ['id'])
        batch_op.create_foreign_key('fk_egov_sign_sessions_company_id_companies', 'companies', ['company_id'], ['id'])


def downgrade() -> None:
    with op.batch_alter_table('egov_sign_sessions', schema=None) as batch_op:
        batch_op.drop_constraint('fk_egov_sign_sessions_company_id_companies', type_='foreignkey')
        batch_op.drop_constraint('fk_egov_sign_sessions_document_id_documents', type_='foreignkey')
        batch_op.drop_column('company_id')
        batch_op.drop_column('document_id')
        batch_op.drop_column('purpose')
