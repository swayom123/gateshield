"""Add expiring, single-use scoped tool approvals."""

import sqlalchemy as sa
from alembic import op

revision = "0006_scoped_tool_approvals"
down_revision = "0005_console_audit"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "tool_approvals",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("application_id", sa.String(128), nullable=False),
        sa.Column("request_id", sa.String(36), nullable=False),
        sa.Column("agent_id", sa.String(128), nullable=True),
        sa.Column("session_id", sa.String(36), nullable=True),
        sa.Column("tool_name", sa.String(128), nullable=False),
        sa.Column("scope_hash", sa.String(64), nullable=False),
        sa.Column("context_hash", sa.String(64), nullable=False),
        sa.Column("arguments_redacted", sa.JSON(), nullable=False),
        sa.Column("target_redacted", sa.JSON(), nullable=True),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("approved_by", sa.String(256), nullable=True),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("consumed_at", sa.DateTime(timezone=True), nullable=True),
    )
    for column in ("application_id", "request_id", "agent_id", "session_id", "status", "expires_at"):
        op.create_index(f"ix_tool_approvals_{column}", "tool_approvals", [column])


def downgrade() -> None:
    for column in ("expires_at", "status", "session_id", "agent_id", "request_id", "application_id"):
        op.drop_index(f"ix_tool_approvals_{column}", table_name="tool_approvals")
    op.drop_table("tool_approvals")
