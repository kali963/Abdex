"""SMS as a second factor; TOTP replay protection.

Revision ID: 0003
Revises: 0002
"""
import sqlalchemy as sa
from alembic import op

revision = "0003"
down_revision = "0002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table("users") as batch:
        batch.add_column(sa.Column("totp_last_step", sa.Integer(), nullable=False, server_default="0"))
        batch.add_column(sa.Column("sms_2fa_enabled", sa.Boolean(), nullable=False, server_default=sa.false()))


def downgrade() -> None:
    with op.batch_alter_table("users") as batch:
        batch.drop_column("sms_2fa_enabled")
        batch.drop_column("totp_last_step")
