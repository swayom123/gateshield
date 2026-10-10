"""Initial Phase 1 storage schema."""

import sqlalchemy as sa
from alembic import op

revision = "0001_phase1_schema"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "applications",
        sa.Column("id", sa.String(128), primary_key=True),
        sa.Column("organization_id", sa.String(128), nullable=True),
        sa.Column("name", sa.String(256), nullable=False),
        sa.Column("enabled", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_applications_organization_id", "applications", ["organization_id"])
    op.create_table(
        "requests",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("trace_id", sa.String(36), nullable=False),
        sa.Column(
            "application_id", sa.String(128), sa.ForeignKey("applications.id"), nullable=False
        ),
        sa.Column("user_id", sa.String(256)),
        sa.Column("agent_id", sa.String(256)),
        sa.Column("session_id", sa.String(256)),
        sa.Column("model", sa.String(256), nullable=False),
        sa.Column("provider", sa.String(64), nullable=False),
        sa.Column("decision", sa.String(40), nullable=False),
        sa.Column("risk_level", sa.String(20), nullable=False),
        sa.Column("started_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("latency_ms", sa.Integer(), nullable=False),
        sa.Column("request_redacted", sa.JSON(), nullable=False),
        sa.Column("response_redacted", sa.JSON(), nullable=False),
    )
    op.create_index("ix_requests_trace_id", "requests", ["trace_id"])
    op.create_index("ix_requests_application_id", "requests", ["application_id"])
    op.create_table(
        "security_events",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column("request_id", sa.String(36), sa.ForeignKey("requests.id"), nullable=False),
        sa.Column("trace_id", sa.String(36), nullable=False),
        sa.Column("application_id", sa.String(128), nullable=False),
        sa.Column("event_type", sa.String(80), nullable=False),
        sa.Column("decision", sa.String(40), nullable=False),
        sa.Column("risk", sa.String(20), nullable=False),
        sa.Column("evidence", sa.JSON(), nullable=False),
        sa.Column("outcome", sa.String(80), nullable=False),
        sa.Column("timestamp", sa.DateTime(timezone=True), nullable=False),
    )
    for table, column in (
        ("security_events", "request_id"),
        ("security_events", "trace_id"),
        ("security_events", "application_id"),
        ("security_events", "event_type"),
    ):
        op.create_index(f"ix_{table}_{column}", table, [column])


def downgrade() -> None:
    op.drop_table("security_events")
    op.drop_table("requests")
    op.drop_index("ix_applications_organization_id", table_name="applications")
    op.drop_table("applications")
