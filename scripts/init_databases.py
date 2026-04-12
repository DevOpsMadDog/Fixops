#!/usr/bin/env python3
"""Initialize all SQLite databases used by ALDECI/Fixops platform modules.

Usage:
    python scripts/init_databases.py
    python scripts/init_databases.py --data-dir /var/lib/fixops/data
    python scripts/init_databases.py --data-dir /var/lib/fixops/data --org-id acme
"""

import argparse
import sys
import os
from pathlib import Path


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Initialize all SQLite databases for the ALDECI platform."
    )
    parser.add_argument(
        "--data-dir",
        default="data",
        help="Base data directory for database files (default: data)",
    )
    parser.add_argument(
        "--org-id",
        default="default",
        help="Organization ID for tenant-scoped initialization (default: default)",
    )
    return parser.parse_args()


def _db(data_dir: str, filename: str) -> str:
    """Return absolute path for a database file within data_dir."""
    return str(Path(data_dir) / filename)


def _attempt(label: str, fn, results: list) -> None:
    """Call fn(), recording success or failure into results."""
    try:
        fn()
        results.append(("ok", label))
        print(f"  [OK]   {label}")
    except ImportError as exc:
        results.append(("skip", label))
        print(f"  [SKIP] {label} — module not available: {exc}")
    except Exception as exc:
        results.append(("error", label))
        print(f"  [ERR]  {label} — {exc}")


# ---------------------------------------------------------------------------
# Individual initializers — one per database / module
# ---------------------------------------------------------------------------

def _init_analytics_db(data_dir: str):
    from core.analytics_db import AnalyticsDB
    AnalyticsDB(db_path=_db(data_dir, "analytics.db"))


def _init_audit_db(data_dir: str):
    from core.audit_db import AuditDB
    AuditDB(db_path=_db(data_dir, "audit.db"))


def _init_auth_db(data_dir: str):
    from core.auth_db import AuthDB
    AuthDB(db_path=_db(data_dir, "auth.db"))


def _init_inventory_db(data_dir: str):
    from core.inventory_db import InventoryDB
    InventoryDB(db_path=_db(data_dir, "inventory.db"))


def _init_user_db(data_dir: str):
    from core.user_db import UserDB
    UserDB(db_path=_db(data_dir, "users.db"))


def _init_workflow_db(data_dir: str):
    from core.workflow_db import WorkflowDB
    WorkflowDB(db_path=_db(data_dir, "workflows.db"))


def _init_policy_db(data_dir: str):
    from core.policy_db import PolicyDB
    PolicyDB(db_path=_db(data_dir, "policies.db"))


def _init_report_db(data_dir: str):
    from core.report_db import ReportDB
    ReportDB(db_path=_db(data_dir, "reports.db"))


def _init_secrets_db(data_dir: str):
    from core.secrets_db import SecretsDB
    SecretsDB(db_path=_db(data_dir, "secrets.db"))


def _init_iac_db(data_dir: str):
    from core.iac_db import IaCDB
    IaCDB(db_path=_db(data_dir, "iac.db"))


def _init_integration_db(data_dir: str):
    from core.integration_db import IntegrationDB
    IntegrationDB(db_path=_db(data_dir, "integrations.db"))


def _init_mpte_db(data_dir: str):
    from core.mpte_db import MPTEDB
    MPTEDB(db_path=_db(data_dir, "mpte.db"))


def _init_fail_db(data_dir: str):
    from core.fail_db import FAILDB
    FAILDB(db_path=_db(data_dir, "fail_scores.db"))


def _init_compliance_planner(data_dir: str):
    from core.compliance_planner import CompliancePlanner
    CompliancePlanner(db_path=_db(data_dir, "compliance_planner.db"))


def _init_config_drift(data_dir: str):
    from core.config_drift import ConfigDriftDetector
    ConfigDriftDetector(db_path=_db(data_dir, "config_drift.db"))


def _init_cspm(data_dir: str):
    from core.cspm import CSPMEngine
    CSPMEngine(db_path=_db(data_dir, "cspm.db"))


def _init_dashboard_builder(data_dir: str):
    from core.dashboard_builder import DashboardBuilder
    DashboardBuilder(db_path=Path(_db(data_dir, "dashboard_builder.db")))


def _init_data_retention(data_dir: str):
    from core.data_retention import DataRetentionManager
    DataRetentionManager(db_path=_db(data_dir, "data_retention.db"))


def _init_decision_memory(data_dir: str):
    from core.decision_memory import DecisionMemoryStore
    DecisionMemoryStore(db_path=_db(data_dir, "decision_memory.db"))


def _init_evidence_collector(data_dir: str):
    from core.evidence_collector import EvidenceCollector
    EvidenceCollector(db_path=_db(data_dir, "evidence.db"))


def _init_exception_policy(data_dir: str):
    from core.exception_policy import ExceptionPolicyEngine
    ExceptionPolicyEngine(db_path=Path(_db(data_dir, "exception_policy.db")))


def _init_executive_reports(data_dir: str):
    from core.executive_reports import ExecutiveReportEngine
    ExecutiveReportEngine(db_path=_db(data_dir, "executive_reports.db"))


def _init_api_versioning(data_dir: str):
    from core.api_versioning import APIVersionManager
    APIVersionManager(db_path=_db(data_dir, "api_versioning.db"))


def _init_api_learning_store(data_dir: str):
    from core.api_learning_store import APILearningStore
    APILearningStore(db_path=Path(_db(data_dir, "api_learning.db")))


def _init_bulk_operations(data_dir: str):
    from core.bulk_operations import BulkOperationsEngine
    BulkOperationsEngine(db_path=Path(_db(data_dir, "bulk_operations.db")))


def _init_integration_health(data_dir: str):
    from core.integration_health import IntegrationHealthMonitor
    IntegrationHealthMonitor(db_path=_db(data_dir, "integration_health.db"))


def _init_api_key_manager(data_dir: str):
    from core.api_key_manager import APIKeyManager
    APIKeyManager(db_path=_db(data_dir, "api_keys.db"))


def _init_audit_logger(data_dir: str):
    from core.audit_logger import AuditLogger
    AuditLogger(db_path=_db(data_dir, "audit_logger.db"))


# ---------------------------------------------------------------------------
# Registry: (label, initializer)
# ---------------------------------------------------------------------------

_INITIALIZERS = [
    ("analytics_db         -> analytics.db",         _init_analytics_db),
    ("audit_db             -> audit.db",              _init_audit_db),
    ("auth_db              -> auth.db",               _init_auth_db),
    ("inventory_db         -> inventory.db",          _init_inventory_db),
    ("user_db              -> users.db",              _init_user_db),
    ("workflow_db          -> workflows.db",          _init_workflow_db),
    ("policy_db            -> policies.db",           _init_policy_db),
    ("report_db            -> reports.db",            _init_report_db),
    ("secrets_db           -> secrets.db",            _init_secrets_db),
    ("iac_db               -> iac.db",                _init_iac_db),
    ("integration_db       -> integrations.db",       _init_integration_db),
    ("mpte_db              -> mpte.db",               _init_mpte_db),
    ("fail_db              -> fail_scores.db",        _init_fail_db),
    ("compliance_planner   -> compliance_planner.db", _init_compliance_planner),
    ("config_drift         -> config_drift.db",       _init_config_drift),
    ("cspm                 -> cspm.db",               _init_cspm),
    ("dashboard_builder    -> dashboard_builder.db",  _init_dashboard_builder),
    ("data_retention       -> data_retention.db",     _init_data_retention),
    ("decision_memory      -> decision_memory.db",    _init_decision_memory),
    ("evidence_collector   -> evidence.db",           _init_evidence_collector),
    ("exception_policy     -> exception_policy.db",   _init_exception_policy),
    ("executive_reports    -> executive_reports.db",  _init_executive_reports),
    ("api_versioning       -> api_versioning.db",     _init_api_versioning),
    ("api_learning_store   -> api_learning.db",       _init_api_learning_store),
    ("bulk_operations      -> bulk_operations.db",    _init_bulk_operations),
    ("integration_health   -> integration_health.db", _init_integration_health),
    ("api_key_manager      -> api_keys.db",           _init_api_key_manager),
    ("audit_logger         -> audit_logger.db",       _init_audit_logger),
]


def init_all(data_dir: str, org_id: str = "default") -> dict:
    """Initialize all databases. Returns summary dict."""
    Path(data_dir).mkdir(parents=True, exist_ok=True)

    print(f"\nInitializing databases in: {Path(data_dir).resolve()}")
    print(f"Organization ID: {org_id}")
    print(f"{'─' * 60}")

    results: list[tuple[str, str]] = []
    for label, fn in _INITIALIZERS:
        _attempt(label, lambda f=fn: f(data_dir), results)

    ok    = sum(1 for s, _ in results if s == "ok")
    skip  = sum(1 for s, _ in results if s == "skip")
    error = sum(1 for s, _ in results if s == "error")

    print(f"{'─' * 60}")
    print(f"Done — {ok} initialized, {skip} skipped, {error} errors\n")

    return {"ok": ok, "skip": skip, "error": error, "results": results}


def main() -> int:
    args = parse_args()
    summary = init_all(data_dir=args.data_dir, org_id=args.org_id)
    return 1 if summary["error"] > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
