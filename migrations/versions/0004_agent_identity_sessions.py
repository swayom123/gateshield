"""Add agent identity, sessions, and behavioral risk signals."""

import sqlalchemy as sa
from alembic import op

revision = "0004_agent_identity_sessions"
down_revision = "0003_tool_security"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "agents",
        sa.Column("id", sa.String(128), primary_key=True),
        sa.Column("application_id", sa.String(128), nullable=False),
        sa.Column("owner", sa.String(256), nullable=False),
        sa.Column("role", sa.String(128), nullable=False),
        sa.Column("environment", sa.String(128), nullable=False),
        sa.Column("allowed_tools", sa.JSON(), nullable=False),
        sa.Column("allowed_resources", sa.JSON(), nullable=False),
        sa.Column("risk_profile", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("token_hash", sa.String(64), nullable=False, unique=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["application_id"], ["applications.id"]),
    )
    op.create_index("ix_agents_application_id", "agents", ["application_id"])
    op.create_index("ix_agents_status", "agents", ["status"])
    op.create_table(
        "agent_sessions",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("agent_id", sa.String(128), nullable=False),
        sa.Column("application_id", sa.String(128), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("request_count", sa.Integer(), nullable=False),
        sa.Column("tool_call_count", sa.Integer(), nullable=False),
        sa.Column("denied_action_count", sa.Integer(), nullable=False),
        sa.Column("policy_manipulation_count", sa.Integer(), nullable=False),
        sa.Column("failure_count", sa.Integer(), nullable=False),
        sa.Column("cumulative_risk", sa.Integer(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.ForeignKeyConstraint(["agent_id"], ["agents.id"]),
        sa.ForeignKeyConstraint(["application_id"], ["applications.id"]),
    )
    op.create_index("ix_agent_sessions_agent_id", "agent_sessions", ["agent_id"])
    op.create_index("ix_agent_sessions_application_id", "agent_sessions", ["application_id"])
    op.create_index("ix_agent_sessions_expires_at", "agent_sessions", ["expires_at"])
    op.create_index("ix_agent_sessions_status", "agent_sessions", ["status"])
    op.create_table(
        "behavior_signals",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("agent_id", sa.String(128), nullable=False),
        sa.Column("session_id", sa.String(36), nullable=False),
        sa.Column("request_id", sa.String(36), nullable=True),
        sa.Column("signal", sa.String(128), nullable=False),
        sa.Column("severity", sa.String(20), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["agent_id"], ["agents.id"]),
        sa.ForeignKeyConstraint(["session_id"], ["agent_sessions.id"]),
    )
    op.create_index("ix_behavior_signals_agent_id", "behavior_signals", ["agent_id"])
    op.create_index("ix_behavior_signals_session_id", "behavior_signals", ["session_id"])
    op.create_index("ix_behavior_signals_request_id", "behavior_signals", ["request_id"])
    op.create_index("ix_behavior_signals_signal", "behavior_signals", ["signal"])
    op.create_index("ix_behavior_signals_created_at", "behavior_signals", ["created_at"])


def downgrade() -> None:
    op.drop_index("ix_behavior_signals_created_at", table_name="behavior_signals")
    op.drop_index("ix_behavior_signals_signal", table_name="behavior_signals")
    op.drop_index("ix_behavior_signals_request_id", table_name="behavior_signals")
    op.drop_index("ix_behavior_signals_session_id", table_name="behavior_signals")
    op.drop_index("ix_behavior_signals_agent_id", table_name="behavior_signals")
    op.drop_table("behavior_signals")
    op.drop_index("ix_agent_sessions_status", table_name="agent_sessions")
    op.drop_index("ix_agent_sessions_expires_at", table_name="agent_sessions")
    op.drop_index("ix_agent_sessions_application_id", table_name="agent_sessions")
    op.drop_index("ix_agent_sessions_agent_id", table_name="agent_sessions")
    op.drop_table("agent_sessions")
    op.drop_index("ix_agents_status", table_name="agents")
    op.drop_index("ix_agents_application_id", table_name="agents")
    op.drop_table("agents")
