"""Initial schema for ALdeci CTEM+ Platform

Creates the 6 core domain tables required for multi-tenant enterprise
PostgreSQL deployment:

- findings          — vulnerability findings (all scanners/connectors)
- exposure_cases    — correlated exposure case groups (CTEM triage)
- pipeline_runs     — brain pipeline execution history
- evidence_bundles  — cryptographically signed compliance evidence
- audit_logs        — append-only tamper-evident audit trail
- mcp_sessions      — MCP (AI agent) session tracking

Revision ID: 001
Revises:
Create Date: 2026-03-17

ADR reference: ADR-010-postgresql-migration.md
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ------------------------------------------------------------------
    # Enable the pgcrypto extension for gen_random_uuid()
    # ------------------------------------------------------------------
    op.execute("CREATE EXTENSION IF NOT EXISTS pgcrypto")

    # ------------------------------------------------------------------
    # findings — all vulnerability findings from scanners and connectors
    # ------------------------------------------------------------------
    op.create_table(
        "findings",
        sa.Column(
            "id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            primary_key=True,
            nullable=False,
        ),
        sa.Column("org_id", sa.String(64), nullable=False),
        sa.Column("title", sa.Text, nullable=False),
        sa.Column("severity", sa.String(16), nullable=True),
        sa.Column("cve_id", sa.String(32), nullable=True),
        sa.Column("cwe_id", sa.String(16), nullable=True),
        sa.Column("asset_name", sa.String(256), nullable=True),
        sa.Column("source", sa.String(64), nullable=True),
        sa.Column("risk_score", sa.Float, nullable=True),
        sa.Column("epss_score", sa.Float, nullable=True),
        sa.Column("kev", sa.Boolean, server_default=sa.text("FALSE"), nullable=False),
        sa.Column("status", sa.String(32), server_default=sa.text("'open'"), nullable=False),
        sa.Column("correlation_key", sa.String(32), nullable=True),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.text("NOW()"),
            nullable=False,
        ),
        sa.Column(
            "updated_at",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.text("NOW()"),
            nullable=False,
        ),
    )
    op.create_index("idx_findings_org", "findings", ["org_id"])
    op.create_index("idx_findings_severity", "findings", ["org_id", "severity"])
    op.create_index("idx_findings_cve", "findings", ["cve_id"])
    op.create_index(
        "idx_findings_status",
        "findings",
        ["org_id", "status"],
        postgresql_where=sa.text("status != 'closed'"),
    )

    # ------------------------------------------------------------------
    # exposure_cases — correlated group of findings representing one
    # threat exposure window (CTEM output after brain pipeline step 8)
    # ------------------------------------------------------------------
    op.create_table(
        "exposure_cases",
        sa.Column(
            "case_id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            primary_key=True,
            nullable=False,
        ),
        sa.Column("org_id", sa.String(64), nullable=False),
        sa.Column("title", sa.Text, nullable=True),
        sa.Column("priority", sa.String(16), nullable=True),
        sa.Column("risk_score", sa.Float, nullable=True),
        sa.Column(
            "finding_ids",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column("finding_count", sa.Integer, server_default=sa.text("0"), nullable=False),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.text("NOW()"),
            nullable=False,
        ),
    )
    op.create_index("idx_exposure_cases_org", "exposure_cases", ["org_id"])
    op.create_index(
        "idx_exposure_cases_priority", "exposure_cases", ["org_id", "priority"]
    )

    # ------------------------------------------------------------------
    # pipeline_runs — brain pipeline execution records (12-step CTEM)
    # ------------------------------------------------------------------
    op.create_table(
        "pipeline_runs",
        sa.Column(
            "run_id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            primary_key=True,
            nullable=False,
        ),
        sa.Column("org_id", sa.String(64), nullable=False),
        sa.Column("status", sa.String(32), server_default=sa.text("'pending'"), nullable=False),
        sa.Column(
            "input_summary",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column(
            "steps",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'[]'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "result_summary",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column("started_at", sa.TIMESTAMP(timezone=True), nullable=True),
        sa.Column("finished_at", sa.TIMESTAMP(timezone=True), nullable=True),
    )
    op.create_index("idx_pipeline_runs_org", "pipeline_runs", ["org_id"])
    op.create_index(
        "idx_pipeline_runs_status", "pipeline_runs", ["org_id", "status"]
    )

    # ------------------------------------------------------------------
    # evidence_bundles — cryptographically signed compliance evidence
    # (RSA-SHA256, stored as JSONB alongside raw payload)
    # ------------------------------------------------------------------
    op.create_table(
        "evidence_bundles",
        sa.Column(
            "bundle_id",
            postgresql.UUID(as_uuid=True),
            server_default=sa.text("gen_random_uuid()"),
            primary_key=True,
            nullable=False,
        ),
        sa.Column("org_id", sa.String(64), nullable=False),
        sa.Column("framework", sa.String(32), nullable=True),
        sa.Column("signed", sa.Boolean, server_default=sa.text("FALSE"), nullable=False),
        sa.Column(
            "signature",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column(
            "payload",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.text("NOW()"),
            nullable=False,
        ),
    )
    op.create_index("idx_evidence_bundles_org", "evidence_bundles", ["org_id"])
    op.create_index(
        "idx_evidence_bundles_framework", "evidence_bundles", ["org_id", "framework"]
    )

    # ------------------------------------------------------------------
    # audit_logs — append-only tamper-evident chain (hash-chained)
    # SOC2 CC7.2, PCI-DSS 10.x compliance requirement
    # ------------------------------------------------------------------
    op.create_table(
        "audit_logs",
        sa.Column("id", sa.BigInteger, sa.Sequence("audit_logs_id_seq"), primary_key=True),
        sa.Column("org_id", sa.String(64), nullable=False),
        sa.Column("actor", sa.String(128), nullable=True),
        sa.Column("action", sa.String(64), nullable=True),
        sa.Column("entity_type", sa.String(64), nullable=True),
        sa.Column("entity_id", sa.String(128), nullable=True),
        sa.Column(
            "payload",
            postgresql.JSONB(astext_type=sa.Text()),
            nullable=True,
        ),
        sa.Column("entry_hash", sa.String(64), nullable=True),
        sa.Column("previous_hash", sa.String(64), nullable=True),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.text("NOW()"),
            nullable=False,
        ),
    )
    op.create_index("idx_audit_org", "audit_logs", ["org_id"])
    op.create_index("idx_audit_created", "audit_logs", ["org_id", "created_at"])
    op.create_index("idx_audit_actor", "audit_logs", ["org_id", "actor"])

    # ------------------------------------------------------------------
    # mcp_sessions — MCP (Model Context Protocol) agent session tracking
    # Supports multi-agent, multi-tenant AI orchestration (V7)
    # ------------------------------------------------------------------
    op.create_table(
        "mcp_sessions",
        sa.Column("session_id", sa.String(128), primary_key=True, nullable=False),
        sa.Column("org_id", sa.String(64), nullable=False),
        sa.Column("client_id", sa.String(128), nullable=True),
        sa.Column(
            "metadata",
            postgresql.JSONB(astext_type=sa.Text()),
            server_default=sa.text("'{}'::jsonb"),
            nullable=False,
        ),
        sa.Column(
            "created_at",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.text("NOW()"),
            nullable=False,
        ),
        sa.Column(
            "last_seen",
            sa.TIMESTAMP(timezone=True),
            server_default=sa.text("NOW()"),
            nullable=False,
        ),
    )
    op.create_index("idx_mcp_sessions_org", "mcp_sessions", ["org_id"])
    op.create_index("idx_mcp_sessions_client", "mcp_sessions", ["org_id", "client_id"])


def downgrade() -> None:
    # Drop in reverse dependency order
    op.drop_table("mcp_sessions")
    op.drop_table("audit_logs")
    op.drop_table("evidence_bundles")
    op.drop_table("pipeline_runs")
    op.drop_table("exposure_cases")
    op.drop_table("findings")
