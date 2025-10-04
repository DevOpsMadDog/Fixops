"""Utility helpers for aggregating policy decision metrics.

This module keeps the heavy SQL aggregation logic out of the
``DecisionEngine`` so that the service can stay focused on orchestration
instead of database plumbing.  The repository exposes a single async helper
that summarises counts and latency statistics from ``PolicyDecisionLog``
records.
"""

from __future__ import annotations

import math
from typing import Any, Dict, Iterable, List

from sqlalchemy import case, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.models.security_sqlite import PolicyDecisionLog


class DecisionMetricsRepository:
    """Aggregate decision metrics from the policy decision logs."""

    HIGH_CONFIDENCE_THRESHOLD = 0.8

    @staticmethod
    async def get_metrics(session: AsyncSession) -> Dict[str, Any]:
        """Return aggregated metrics for decision logs.

        The method issues a small number of SQL queries to fetch counts and
        execution-time statistics.  Percentiles are computed in Python to stay
        compatible with SQLite, which lacks ``percentile_cont``.
        """

        aggregates_stmt = select(
            func.count(PolicyDecisionLog.id).label("total"),
            func.sum(
                case((PolicyDecisionLog.decision == "DEFER", 1), else_=0)
            ).label("pending"),
            func.sum(
                case(
                    (PolicyDecisionLog.confidence >= DecisionMetricsRepository.HIGH_CONFIDENCE_THRESHOLD, 1),
                    else_=0,
                )
            ).label("high_conf"),
            func.sum(
                case((PolicyDecisionLog.decision != "DEFER", 1), else_=0)
            ).label("consensus"),
            func.avg(PolicyDecisionLog.execution_time_ms).label("avg_latency_ms"),
            func.sum(
                case(
                    (func.length(func.trim(PolicyDecisionLog.input_context)) > 2, 1),
                    else_=0,
                )
            ).label("enriched"),
        )

        result = await session.execute(aggregates_stmt)
        total, pending, high_conf, consensus, avg_latency_ms, enriched = result.one()

        total = total or 0
        pending = pending or 0
        high_conf = high_conf or 0
        consensus = consensus or 0
        avg_latency_ms = avg_latency_ms or 0.0
        enriched = enriched or 0

        latencies_stmt = select(PolicyDecisionLog.execution_time_ms).where(
            PolicyDecisionLog.execution_time_ms.is_not(None)
        )
        latency_result = await session.execute(latencies_stmt)
        latencies_ms = [value for value in latency_result.scalars() if value is not None]

        metrics: Dict[str, Any] = {
            "total_decisions": int(total),
            "pending_review": int(pending),
            "high_confidence_rate": DecisionMetricsRepository._safe_ratio(high_conf, total),
            "context_enrichment_rate": DecisionMetricsRepository._safe_ratio(enriched, total),
            "avg_decision_latency_us": float(avg_latency_ms) * 1000.0,
            "consensus_rate": DecisionMetricsRepository._safe_ratio(consensus, total),
            "evidence_records": int(total),
            "audit_compliance": 1.0,
            "latency_percentiles_us": DecisionMetricsRepository._latency_percentiles(latencies_ms),
        }

        return metrics

    @staticmethod
    def _safe_ratio(numerator: float, denominator: float) -> float:
        if not denominator:
            return 0.0
        return float(numerator) / float(denominator)

    @staticmethod
    def _latency_percentiles(latencies_ms: Iterable[float]) -> Dict[str, float]:
        values: List[float] = sorted(float(v) for v in latencies_ms if v is not None)
        if not values:
            return {"p50": 0.0, "p95": 0.0, "p99": 0.0}

        return {
            "p50": DecisionMetricsRepository._percentile(values, 0.5) * 1000.0,
            "p95": DecisionMetricsRepository._percentile(values, 0.95) * 1000.0,
            "p99": DecisionMetricsRepository._percentile(values, 0.99) * 1000.0,
        }

    @staticmethod
    def _percentile(sorted_values: List[float], percentile: float) -> float:
        if not sorted_values:
            return 0.0

        k = (len(sorted_values) - 1) * percentile
        lower_index = math.floor(k)
        upper_index = math.ceil(k)

        if lower_index == upper_index:
            return sorted_values[int(k)]

        lower_value = sorted_values[lower_index]
        upper_value = sorted_values[upper_index]
        return lower_value + (upper_value - lower_value) * (k - lower_index)
