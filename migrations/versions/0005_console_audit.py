"""Add append-only console administration audit history."""

import sqlalchemy as sa
from alembic import op

revision = "0005_console_audit"
down_revision = "0004_agent_identity_sessions"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "console_audit",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("actor", sa.String(256), nullable=False),
        sa.Column("action", sa.String(80), nullable=False),
        sa.Column("target", sa.String(256), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_console_audit_actor", "console_audit", ["actor"])
    op.create_index("ix_console_audit_action", "console_audit", ["action"])
    op.create_index("ix_console_audit_target", "console_audit", ["target"])
    op.create_index("ix_console_audit_timestamp", "console_audit", ["timestamp"])


def downgrade() -> None:
    op.drop_index("ix_console_audit_timestamp", table_name="console_audit")
    op.drop_index("ix_console_audit_target", table_name="console_audit")
    op.drop_index("ix_console_audit_action", table_name="console_audit")
    op.drop_index("ix_console_audit_actor", table_name="console_audit")
    op.drop_table("console_audit")
