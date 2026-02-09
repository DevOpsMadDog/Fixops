"""Create KEV waiver table"""

import sqlalchemy as sa
from alembic import op

revision = "002_add_kev_waivers"
down_revision = "001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    """Create the kev_waivers table with audit metadata."""

    op.create_table(
        "kev_waivers",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("cve_id", sa.String(length=50), nullable=False),
        sa.Column("service_name", sa.String(length=255), nullable=True),
        sa.Column("finding_id", sa.String(length=36), nullable=True),
        sa.Column("justification", sa.Text(), nullable=False),
        sa.Column("approved_by", sa.String(length=255), nullable=False),
        sa.Column("approved_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("change_ticket", sa.String(length=255), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("is_active", sa.Boolean(), server_default=sa.true(), nullable=False),
        sa.Column("version", sa.Integer(), server_default=sa.text("1"), nullable=False),
        sa.Column("metadata", sa.JSON(), nullable=True),
        sa.Column("created_by", sa.String(length=255), nullable=True),
        sa.Column("modified_by", sa.String(length=255), nullable=True),
        sa.Column("created_from_ip", sa.String(length=45), nullable=True),
        sa.Column("modified_from_ip", sa.String(length=45), nullable=True),
        sa.Column("deleted_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("deleted_by", sa.String(length=255), nullable=True),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_index("ix_kev_waivers_cve_id", "kev_waivers", ["cve_id"])
    op.create_index("ix_kev_waivers_service_name", "kev_waivers", ["service_name"])
    op.create_index("ix_kev_waivers_finding_id", "kev_waivers", ["finding_id"])
    op.create_index("ix_kev_waivers_expires_at", "kev_waivers", ["expires_at"])
    op.create_index("ix_kev_waivers_is_active", "kev_waivers", ["is_active"])
    op.create_index("ix_kev_waivers_approved_at", "kev_waivers", ["approved_at"])


def downgrade() -> None:
    """Remove the kev_waivers table."""

    op.drop_index("ix_kev_waivers_approved_at", table_name="kev_waivers")
    op.drop_index("ix_kev_waivers_is_active", table_name="kev_waivers")
    op.drop_index("ix_kev_waivers_expires_at", table_name="kev_waivers")
    op.drop_index("ix_kev_waivers_finding_id", table_name="kev_waivers")
    op.drop_index("ix_kev_waivers_service_name", table_name="kev_waivers")
    op.drop_index("ix_kev_waivers_cve_id", table_name="kev_waivers")
    op.drop_table("kev_waivers")
