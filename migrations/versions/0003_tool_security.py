"""Add application-scoped tool registry and invocation audit."""

import sqlalchemy as sa
from alembic import op

revision = "0003_tool_security"
down_revision = "0002_versioned_policies"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "tool_definitions",
        sa.Column("application_id", sa.String(128), nullable=False),
        sa.Column("name", sa.String(128), nullable=False),
        sa.Column("description", sa.String(1000), nullable=False),
        sa.Column("parameters", sa.JSON(), nullable=False),
        sa.Column("resource_type", sa.String(40), nullable=False),
        sa.Column("risk_level", sa.String(20), nullable=False),
        sa.Column("scope", sa.JSON(), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["application_id"], ["applications.id"]),
        sa.PrimaryKeyConstraint("application_id", "name"),
    )
    op.create_table(
        "tool_invocations",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("application_id", sa.String(128), nullable=False),
        sa.Column("request_id", sa.String(36), nullable=True),
        sa.Column("tool_name", sa.String(128), nullable=False),
        sa.Column("decision", sa.String(40), nullable=False),
        sa.Column("risk_level", sa.String(20), nullable=False),
        sa.Column("arguments_redacted", sa.JSON(), nullable=False),
        sa.Column("reason", sa.String(1000), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_tool_invocations_application_id", "tool_invocations", ["application_id"])
    op.create_index("ix_tool_invocations_request_id", "tool_invocations", ["request_id"])
    op.create_index("ix_tool_invocations_tool_name", "tool_invocations", ["tool_name"])
    op.create_index("ix_tool_invocations_created_at", "tool_invocations", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_tool_invocations_created_at", table_name="tool_invocations")
    op.drop_index("ix_tool_invocations_tool_name", table_name="tool_invocations")
    op.drop_index("ix_tool_invocations_request_id", table_name="tool_invocations")
    op.drop_index("ix_tool_invocations_application_id", table_name="tool_invocations")
    op.drop_table("tool_invocations")
    op.drop_table("tool_definitions")
