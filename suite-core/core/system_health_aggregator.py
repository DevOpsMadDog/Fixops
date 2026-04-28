"""
SystemHealthAggregator — checks all 50+ ALDECI engine databases and
returns a unified health report + 0-100 system score.

Two DB path patterns exist across engines:
  1. Shared DB  — .fixops_data/<name>.db  (not org-scoped)
  2. Org-scoped — .fixops_data/{org_id}_<name>.db

The aggregator handles both transparently.
"""

from __future__ import annotations

import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Tuple

import structlog

logger = structlog.get_logger(__name__)

# Repo root — two levels up from suite-core/core/
_REPO_ROOT = Path(__file__).resolve().parents[2]
_DATA_DIR = _REPO_ROOT / ".fixops_data"
_LEGACY_DATA_DIR = _REPO_ROOT / "data"  # used by threat_hunting & ir_playbook


# ---------------------------------------------------------------------------
# Engine registry
# Each entry: (engine_name, db_path_template, primary_table)
#
# Template tokens:
#   {data_dir}   → .fixops_data/
#   {org_id}     → caller-supplied org_id
#   {legacy_dir} → data/
# ---------------------------------------------------------------------------
_SHARED_ENGINES: List[Tuple[str, str, str]] = [
    # Wave 6
    ("threat_feed",             "{data_dir}/threat_feeds.db",                  "feed_sources"),
    ("digital_forensics",       "{data_dir}/digital_forensics.db",              "forensic_cases"),
    ("posture_score",           "{data_dir}/posture_score.db",                  "posture_scores"),
    ("security_roadmap",        "{data_dir}/security_roadmap.db",               "roadmap_initiatives"),
    ("data_governance",         "{data_dir}/data_governance.db",                "data_assets"),
    ("compliance_scanner",      "{data_dir}/compliance_scanner.db",             "scan_profiles"),
    ("asset_risk",              "{data_dir}/asset_risk.db",                     "asset_profiles"),
    ("security_health",         "{data_dir}/security_health.db",                "health_checks"),
    ("incident_timeline",       "{data_dir}/incident_timeline.db",              "timelines"),
    ("security_metrics",        "{data_dir}/security_metrics.db",               "metric_definitions"),
    ("devsecops",               "{data_dir}/devsecops.db",                      "pipelines"),
    ("vuln_trend",              "{data_dir}/vuln_trend.db",                     "vuln_snapshots"),
    ("config_benchmark",        "{data_dir}/config_benchmark.db",               "benchmark_profiles"),
    ("threat_model_generator",  "{data_dir}/threat_model_generator.db",         "threat_models"),
    ("security_exception",      "{data_dir}/security_exceptions.db",            "exceptions"),
    ("attack_simulation",       "{data_dir}/attack_simulation.db",              "simulation_runs"),
    # Wave 7
    ("regulatory_tracker",      "{data_dir}/regulatory_tracker_engine.db",      "regulations"),
    ("security_scorecard",      "{data_dir}/security_scorecard_engine.db",      "scorecards"),
    ("ccm",                     "{data_dir}/ccm_engine.db",                     "controls"),
    ("awareness_score",         "{data_dir}/awareness_score_engine.db",         "employee_profiles"),
    ("ndr",                     "{data_dir}/ndr.db",                            "network_flows"),
    ("xdr",                     "{data_dir}/xdr.db",                            "xdr_signals"),
    ("edr",                     "{data_dir}/edr_engine.db",                     "endpoints"),
    ("supply_chain_intel",      "{data_dir}/supply_chain_intel.db",             "tracked_packages"),
    ("threat_hunting",          "{legacy_dir}/threat_hunting.db",               "hunts"),
    ("identity_analytics",      "{data_dir}/identity_analytics.db",             "identity_profiles"),
    ("cnapp",                   "{data_dir}/cnapp_engine.db",                   "cloud_workloads"),
    ("pentest_mgmt",            "{data_dir}/pentest_mgmt.db",                   "engagements"),
    ("threat_intel_sharing",    "{data_dir}/threat_intel_sharing.db",           "sharing_groups"),
    # Wave 8
    ("deception",               "{data_dir}/deception.db",                      "canary_tokens"),
    ("ir_playbook",             "{legacy_dir}/ir_playbook.db",                  "ir_incidents"),
    ("supply_chain_risk",       "{data_dir}/supply_chain_risk.db",              "suppliers"),
    ("scheduled_reports",       "{data_dir}/scheduled_reports.db",              "report_schedules"),
]

_ORG_SCOPED_ENGINES: List[Tuple[str, str, str]] = [
    # security_champions
    ("security_champions",  "{data_dir}/{org_id}_security_champions.db",    "champions"),
    # red_team_mgmt
    ("red_team_mgmt",       "{data_dir}/{org_id}_red_team_mgmt.db",         "engagements"),
    # data_classification
    ("data_classification", "{data_dir}/{org_id}_data_classification.db",   "data_assets"),
    # threat_actor
    ("threat_actor",        "{data_dir}/{org_id}_threat_actors.db",         "actors"),
    # application_security
    ("application_security","{data_dir}/{org_id}_application_security.db",  "applications"),
    # bug_bounty
    ("bug_bounty",          "{data_dir}/{org_id}_bug_bounty.db",            "programs"),
    # sbom
    ("sbom",                "{data_dir}/{org_id}_sbom.db",                  "sbom_assets"),
]


def _resolve_path(template: str, org_id: str) -> Path:
    """Expand template tokens into a concrete filesystem path."""
    resolved = template.format(
        data_dir=str(_DATA_DIR),
        legacy_dir=str(_LEGACY_DATA_DIR),
        org_id=org_id,
    )
    return Path(resolved)


def _check_engine(
    engine_name: str,
    db_path: Path,
    table: str,
) -> Dict[str, Any]:
    """
    Probe a single engine database.

    Returns a dict with keys:
      engine, status, db_path, record_count, latency_ms, error
    """
    result: Dict[str, Any] = {
        "engine": engine_name,
        "db_path": str(db_path),
        "status": "unavailable",
        "record_count": None,
        "latency_ms": None,
        "error": None,
    }

    t0 = time.monotonic()

    # 1. DB file existence check
    if not db_path.exists():
        result["status"] = "unavailable"
        result["error"] = "DB file not found"
        return result

    # 2. Lightweight SELECT count(*)
    try:
        conn = sqlite3.connect(str(db_path), timeout=5)
        try:
            cur = conn.execute(f"SELECT COUNT(*) FROM {table}")  # noqa: S608  # nosec B608
            row = cur.fetchone()
            count = row[0] if row else 0
        finally:
            conn.close()

        elapsed_ms = round((time.monotonic() - t0) * 1000, 2)
        result["record_count"] = count
        result["latency_ms"] = elapsed_ms
        # A DB that opens and counts is healthy; if it's empty it's still
        # accessible — report degraded only on errors.
        result["status"] = "healthy"

    except sqlite3.OperationalError as exc:
        elapsed_ms = round((time.monotonic() - t0) * 1000, 2)
        result["latency_ms"] = elapsed_ms
        # Table may not exist yet (engine never initialised) → degraded
        result["status"] = "degraded"
        result["error"] = str(exc)
    except Exception as exc:  # noqa: BLE001
        elapsed_ms = round((time.monotonic() - t0) * 1000, 2)
        result["latency_ms"] = elapsed_ms
        result["status"] = "unavailable"
        result["error"] = str(exc)

    return result


class SystemHealthAggregator:
    """
    Aggregate health checks across all 50+ ALDECI engine databases.

    Usage::

        agg = SystemHealthAggregator()
        report = agg.check_all(org_id="acme")
        score  = agg.get_system_score(org_id="acme")
    """

    # Expose for tests / external introspection
    SHARED_ENGINES = _SHARED_ENGINES
    ORG_SCOPED_ENGINES = _ORG_SCOPED_ENGINES

    # Combined registry used by check_all()
    @property
    def ENGINES(self) -> List[Tuple[str, str, str]]:
        return _SHARED_ENGINES + _ORG_SCOPED_ENGINES

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def check_all(self, org_id: str = "default") -> Dict[str, Any]:
        """
        Check every engine and return a full health report.

        Returns::

            {
              "overall_status": "healthy" | "degraded" | "unavailable",
              "system_score": 87,
              "org_id": "default",
              "checked_at": 1713300000.0,
              "summary": {"healthy": 40, "degraded": 5, "unavailable": 5},
              "engines": [ {engine dict}, ... ]
            }
        """
        engines_status: List[Dict[str, Any]] = []

        all_entries = _SHARED_ENGINES + _ORG_SCOPED_ENGINES

        for name, template, table in all_entries:
            db_path = _resolve_path(template, org_id)
            status = _check_engine(name, db_path, table)
            engines_status.append(status)
            logger.debug(
                "engine_health_check",
                engine=name,
                status=status["status"],
                latency_ms=status["latency_ms"],
            )

        summary = {
            "healthy": sum(1 for e in engines_status if e["status"] == "healthy"),
            "degraded": sum(1 for e in engines_status if e["status"] == "degraded"),
            "unavailable": sum(1 for e in engines_status if e["status"] == "unavailable"),
        }

        score = self._compute_score(summary, len(engines_status))
        overall = self._overall_status(summary, len(engines_status))

        return {
            "overall_status": overall,
            "system_score": score,
            "org_id": org_id,
            "checked_at": time.time(),
            "total_engines": len(engines_status),
            "summary": summary,
            "engines": engines_status,
        }

    def get_system_score(self, org_id: str = "default") -> Dict[str, Any]:
        """
        Lightweight score endpoint — returns 0-100 health score.

        Returns::

            {
              "score": 87,
              "grade": "B+",
              "overall_status": "healthy",
              "org_id": "default",
              "summary": {"healthy": 40, "degraded": 5, "unavailable": 5},
              "checked_at": 1713300000.0,
            }
        """
        report = self.check_all(org_id=org_id)
        score = report["system_score"]
        return {
            "score": score,
            "grade": self._score_to_grade(score),
            "overall_status": report["overall_status"],
            "org_id": org_id,
            "summary": report["summary"],
            "total_engines": report["total_engines"],
            "checked_at": report["checked_at"],
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _compute_score(summary: Dict[str, int], total: int) -> int:
        """
        Weighted score:
          healthy    → full weight  (1.0)
          degraded   → half weight  (0.5)
          unavailable→ zero weight  (0.0)
        """
        if total == 0:
            return 0
        weighted = summary["healthy"] * 1.0 + summary["degraded"] * 0.5
        return round((weighted / total) * 100)

    @staticmethod
    def _overall_status(summary: Dict[str, int], total: int) -> str:
        """
        healthy    — all (or all-but-one) engines healthy
        degraded   — some engines degraded or a few unavailable
        unavailable— majority of engines unavailable
        """
        if total == 0:
            return "unavailable"
        unavail_pct = summary["unavailable"] / total
        if unavail_pct > 0.5:
            return "unavailable"
        if summary["degraded"] > 0 or summary["unavailable"] > 0:
            return "degraded"
        return "healthy"

    @staticmethod
    def _score_to_grade(score: int) -> str:
        if score >= 95:
            return "A+"
        if score >= 90:
            return "A"
        if score >= 85:
            return "B+"
        if score >= 80:
            return "B"
        if score >= 75:
            return "C+"
        if score >= 70:
            return "C"
        if score >= 60:
            return "D"
        return "F"
