"""Add versioned deterministic policy storage."""

import sqlalchemy as sa
from alembic import op

revision = "0002_versioned_policies"
down_revision = "0001_phase1_schema"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "policies",
        sa.Column("id", sa.String(128), primary_key=True),
        sa.Column("organization_id", sa.String(128), nullable=True),
        sa.Column("current_version", sa.Integer(), nullable=False),
        sa.Column("active_version", sa.Integer(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_policies_organization_id", "policies", ["organization_id"])
    op.create_table(
        "policy_versions",
        sa.Column(
            "policy_id",
            sa.String(128),
            sa.ForeignKey("policies.id", ondelete="CASCADE"),
            primary_key=True,
        ),
        sa.Column("version", sa.Integer(), primary_key=True),
        sa.Column("definition", sa.JSON(), nullable=False),
        sa.Column("author", sa.String(256), nullable=False),
        sa.Column("changes", sa.JSON(), nullable=False),
        sa.Column("status", sa.String(20), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("ix_policy_versions_status", "policy_versions", ["status"])


def downgrade() -> None:
    op.drop_index("ix_policy_versions_status", table_name="policy_versions")
    op.drop_table("policy_versions")
    op.drop_index("ix_policies_organization_id", table_name="policies")
    op.drop_table("policies")
