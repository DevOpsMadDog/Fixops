"""Add P0 ORM-backed tables: remediation_tasks + pipeline_runs columns

This migration extends the schema created in 001 with:

1.  ``remediation_tasks`` — remediation work items linked to findings.
    New table; not present in 001.

2.  ``pipeline_runs`` additions — adds the detailed columns that the new
    ``PipelineRun`` ORM model uses beyond what was created in 001.
    Migration 001 created pipeline_runs with minimal columns; this migration
    adds the summary counts and the steps_json / input_summary columns.

3.  ``evidence_bundles`` addition — adds ``signature_algorithm`` column.

Dual-dialect design:
- All column types use SQLite-compatible equivalents.
- PostgreSQL-specific partial indexes are emitted only when the dialect is
  detected as PostgreSQL at migration run time.
- UUIDs are stored as String(36); JSON as sa.JSON (TEXT on SQLite, JSONB on
  PostgreSQL via SQLAlchemy's dialect mapping).

Revision ID: 002
Revises: 001
Create Date: 2026-03-17
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "002"
down_revision: Union[str, None] = "001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _is_postgresql() -> bool:
    """Return True when running against PostgreSQL."""
    try:
        return op.get_bind().dialect.name == "postgresql"
    except Exception:
        return False


def upgrade() -> None:
    # ------------------------------------------------------------------
    # 1. remediation_tasks — new table
    # ------------------------------------------------------------------
    op.create_table(
        "remediation_tasks",
        sa.Column("id", sa.String(36), primary_key=True, nullable=False),
        sa.Column("org_id", sa.String(64), nullable=False),
        sa.Column(
            "finding_id",
            sa.String(36),
            sa.ForeignKey("findings.id", ondelete="SET NULL"),
            nullable=True,
        ),
        sa.Column("fix_type", sa.String(64), nullable=True),
        sa.Column(
            "status",
            sa.String(32),
            server_default=sa.text("'pending'"),
            nullable=False,
        ),
        sa.Column("details", sa.JSON, nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            server_default=sa.text("CURRENT_TIMESTAMP"),
            nullable=False,
        ),
        sa.Column("completed_at", sa.DateTime(timezone=True), nullable=True),
    )
    op.create_index("idx_remediation_tasks_org", "remediation_tasks", ["org_id"])
    op.create_index(
        "idx_remediation_tasks_finding", "remediation_tasks", ["finding_id"]
    )
    op.create_index(
        "idx_remediation_tasks_status", "remediation_tasks", ["org_id", "status"]
    )

    # ------------------------------------------------------------------
    # 2. pipeline_runs — add columns not present in 001
    #
    # Migration 001 created pipeline_runs with:
    #   run_id, org_id, status, input_summary, steps, result_summary,
    #   started_at, finished_at
    #
    # The ORM model (PipelineRun) expects these additional columns:
    #   total_duration_ms, findings_ingested, clusters_created,
    #   exposure_cases_created, critical_cases, avg_risk_score, steps_json
    #
    # NOTE: ``steps`` was created in 001 as a JSONB column.  The ORM model
    # maps to ``steps_json`` (a separate column) to avoid a rename DDL.
    # ------------------------------------------------------------------
    with op.batch_alter_table("pipeline_runs") as batch_op:
        batch_op.add_column(
            sa.Column("total_duration_ms", sa.Float, nullable=True)
        )
        batch_op.add_column(
            sa.Column(
                "findings_ingested",
                sa.Integer,
                server_default=sa.text("0"),
                nullable=False,
            )
        )
        batch_op.add_column(
            sa.Column(
                "clusters_created",
                sa.Integer,
                server_default=sa.text("0"),
                nullable=False,
            )
        )
        batch_op.add_column(
            sa.Column(
                "exposure_cases_created",
                sa.Integer,
                server_default=sa.text("0"),
                nullable=False,
            )
        )
        batch_op.add_column(
            sa.Column(
                "critical_cases",
                sa.Integer,
                server_default=sa.text("0"),
                nullable=False,
            )
        )
        batch_op.add_column(
            sa.Column(
                "avg_risk_score",
                sa.Float,
                server_default=sa.text("0.0"),
                nullable=False,
            )
        )
        # steps_json is separate from the 001 ``steps`` column so we can
        # add it without touching existing data.
        batch_op.add_column(
            sa.Column("steps_json", sa.JSON, nullable=True)
        )

    # ------------------------------------------------------------------
    # 3. evidence_bundles — add signature_algorithm column
    # ------------------------------------------------------------------
    with op.batch_alter_table("evidence_bundles") as batch_op:
        batch_op.add_column(
            sa.Column("signature_algorithm", sa.String(32), nullable=True)
        )

    # ------------------------------------------------------------------
    # 4. PostgreSQL-only partial index on remediation_tasks
    # ------------------------------------------------------------------
    if _is_postgresql():
        op.create_index(
            "idx_remediation_tasks_active",
            "remediation_tasks",
            ["org_id", "status"],
            postgresql_where=sa.text("status NOT IN ('applied', 'rejected')"),
        )


def downgrade() -> None:
    # Drop PostgreSQL partial index first (no-op on SQLite)
    if _is_postgresql():
        op.drop_index(
            "idx_remediation_tasks_active",
            table_name="remediation_tasks",
        )

    # Reverse evidence_bundles change
    with op.batch_alter_table("evidence_bundles") as batch_op:
        batch_op.drop_column("signature_algorithm")

    # Reverse pipeline_runs additions
    with op.batch_alter_table("pipeline_runs") as batch_op:
        batch_op.drop_column("steps_json")
        batch_op.drop_column("avg_risk_score")
        batch_op.drop_column("critical_cases")
        batch_op.drop_column("exposure_cases_created")
        batch_op.drop_column("clusters_created")
        batch_op.drop_column("findings_ingested")
        batch_op.drop_column("total_duration_ms")

    # Drop remediation_tasks
    op.drop_index("idx_remediation_tasks_status", table_name="remediation_tasks")
    op.drop_index("idx_remediation_tasks_finding", table_name="remediation_tasks")
    op.drop_index("idx_remediation_tasks_org", table_name="remediation_tasks")
    op.drop_table("remediation_tasks")
