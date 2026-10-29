"""Biometrics reviewed by a moderator: the second selfie is kept until the decision, who decided and why.

Revision ID: 0015
Revises: 0014
"""
import sqlalchemy as sa

import app.db
from alembic import op

revision = '0015'
down_revision = '0014'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('biometric_checks') as b:
        b.add_column(sa.Column('selfie2_file_id', sa.Uuid(), nullable=True))
        b.add_column(sa.Column('reviewed_by', sa.Uuid(), nullable=True))
        b.add_column(sa.Column('reviewed_at', app.db.AwareDateTime(timezone=True), nullable=True))
        b.add_column(sa.Column('review_reason', sa.String(length=40), nullable=False, server_default=''))
        b.add_column(sa.Column('review_comment', sa.String(length=500), nullable=False, server_default=''))
        b.create_foreign_key('fk_biometric_checks_selfie2_file', 'stored_files', ['selfie2_file_id'], ['id'])
        b.create_foreign_key('fk_biometric_checks_reviewed_by', 'users', ['reviewed_by'], ['id'])
    op.create_index('ix_biometric_checks_status', 'biometric_checks', ['status'])
    # Results of the test simulator approved any picture: they are not a check of anybody — the drivers send
    # their photos again and a moderator decides.
    op.execute(sa.text(
        "UPDATE biometric_checks SET status = 'failed', match = false, liveness = false, score = 0, "
        "valid_until = NULL, review_reason = 'other', "
        "review_comment = 'Автоматическая проверка отменена: отправьте фото заново, их проверит модератор' "
        "WHERE provider = 'biometrics-sim-v1' AND status = 'passed'"))


def downgrade() -> None:
    op.drop_index('ix_biometric_checks_status', table_name='biometric_checks')
    with op.batch_alter_table('biometric_checks') as b:
        b.drop_constraint('fk_biometric_checks_reviewed_by', type_='foreignkey')
        b.drop_constraint('fk_biometric_checks_selfie2_file', type_='foreignkey')
        for col in ('review_comment', 'review_reason', 'reviewed_at', 'reviewed_by', 'selfie2_file_id'):
            b.drop_column(col)
