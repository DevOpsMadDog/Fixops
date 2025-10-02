"""Database-backed aggregates for decision engine metrics.

This module centralises the SQL required to build production metrics for the
decision engine so that demo mode can keep returning synthetic values while
real deployments surface live numbers from the evidence lake tables.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.security_sqlite import (
    PolicyDecisionLog,
    PolicyRule,
    SecurityFinding,
    Service,
)


def _safe_json_loads(raw: str | None) -> Dict[str, Any]:
    """Parse JSON metadata gracefully."""

    if not raw:
        return {}
    try:
        return json.loads(raw)
    except (TypeError, json.JSONDecodeError):
        return {}


@dataclass
class DecisionMetricsSnapshot:
    """Aggregated metrics derived from persisted decisions."""

    total_decisions: int
    pending_review: int
    high_confidence_rate: float
    context_enrichment_rate: float
    avg_decision_latency_us: float
    consensus_rate: float
    evidence_records: int
    audit_compliance: float
    component_status: Dict[str, str]

    def to_dict(self) -> Dict[str, Any]:
        """Convert to a serialisable dictionary for API responses."""

        return {
            "total_decisions": self.total_decisions,
            "pending_review": self.pending_review,
            "high_confidence_rate": self.high_confidence_rate,
            "context_enrichment_rate": self.context_enrichment_rate,
            "avg_decision_latency_us": self.avg_decision_latency_us,
            "consensus_rate": self.consensus_rate,
            "evidence_records": self.evidence_records,
            "audit_compliance": self.audit_compliance,
        }


class DecisionMetricsRepository:
    """Compute live production metrics from SQLite (or compatible) storage."""

    @staticmethod
    async def collect(session: AsyncSession) -> DecisionMetricsSnapshot:
        """Build the production snapshot for the decision engine."""

        decision_rows = (
            await session.execute(
                select(PolicyDecisionLog).order_by(PolicyDecisionLog.created_at.desc())
            )
        ).scalars()
        decisions = list(decision_rows)

        total_decisions = len(decisions)

        if total_decisions:
            pending_review = sum(
                1 for log in decisions if (log.decision or "").upper() == "DEFER"
            )
            high_confidence = sum(1 for log in decisions if log.confidence >= 0.85)
            avg_latency_ms = sum(log.execution_time_ms for log in decisions) / total_decisions
            consensus_hits = sum(
                1
                for log in decisions
                if _safe_json_loads(getattr(log, "metadata_", None)).get(
                    "consensus_reached", False
                )
            )
            audit_records = sum(1 for log in decisions if (log.policy_version or "").strip())
            enriched_contexts = sum(
                1
                for log in decisions
                if DecisionMetricsRepository._has_enriched_context(log)
            )
        else:
            pending_review = 0
            high_confidence = 0
            avg_latency_ms = 0.0
            consensus_hits = 0
            audit_records = 0
            enriched_contexts = 0

        findings_count = await DecisionMetricsRepository._count(session, SecurityFinding.id)
        services_count = await DecisionMetricsRepository._count(session, Service.id)
        policy_rules_count = await DecisionMetricsRepository._count(session, PolicyRule.id)

        component_status = {
            "vector_db": (
                f"production_active ({findings_count} findings indexed)"
                if findings_count
                else "warming_up (no findings indexed)"
            ),
            "llm_rag": (
                "production_active"
                if total_decisions and high_confidence
                else "inactive (no high-confidence decisions)"
            ),
            "consensus_checker": (
                f"production_active ({DecisionMetricsRepository._ratio(consensus_hits, total_decisions):.0%} consensus)"
                if total_decisions
                else "inactive"
            ),
            "golden_regression": (
                f"production_active ({total_decisions} historical cases)"
                if total_decisions
                else "insufficient_history"
            ),
            "policy_engine": (
                f"production_active ({policy_rules_count} policies)"
                if policy_rules_count
                else "no_policies_configured"
            ),
            "sbom_injection": (
                f"production_active ({services_count} services tracked)"
                if services_count
                else "inactive"
            ),
        }

        snapshot = DecisionMetricsSnapshot(
            total_decisions=total_decisions,
            pending_review=pending_review,
            high_confidence_rate=DecisionMetricsRepository._ratio(
                high_confidence, total_decisions
            ),
            context_enrichment_rate=DecisionMetricsRepository._ratio(
                enriched_contexts, total_decisions
            ),
            avg_decision_latency_us=round(avg_latency_ms * 1000, 2),
            consensus_rate=DecisionMetricsRepository._ratio(
                consensus_hits, total_decisions
            ),
            evidence_records=findings_count,
            audit_compliance=DecisionMetricsRepository._ratio(audit_records, total_decisions),
            component_status=component_status,
        )

        return snapshot

    @staticmethod
    async def _count(session: AsyncSession, column) -> int:
        """Count rows for a given column without pulling entire tables."""

        result = await session.execute(select(func.count()).select_from(column.table))
        return int(result.scalar() or 0)

    @staticmethod
    def _has_enriched_context(log: PolicyDecisionLog) -> bool:
        """Detect whether the stored context contains enrichment data."""

        context = {}
        if hasattr(log, "get_input_context"):
            context = log.get_input_context()
        else:
            context = _safe_json_loads(getattr(log, "input_context", None))

        metadata = _safe_json_loads(getattr(log, "metadata_", None))

        enrichment_sources = context.get("enrichment_sources") or context.get(
            "context_sources"
        )
        evidence_links = metadata.get("evidence_links")

        return bool(enrichment_sources or evidence_links or metadata.get("context_enriched"))

    @staticmethod
    def _ratio(part: int, whole: int) -> float:
        """Return a rounded ratio, guarding against zero division."""

        if not whole:
            return 0.0
        return round(part / whole, 4)

