"""Audits ALDECI engines for multi-tenant data isolation.

Findings from manual audit (2026-04-14):
- redis_queue.py: No org_id scoping — keys are global (aldeci:queue:{priority}).
  All tenants share the same queue namespace.
- sso_bridge.py: sso_sessions table has no org_id column (stored in JSON blob only).
  sso_providers table has no org_id column — providers are shared across tenants.
- insider_threat_engine.py: resolve_alert() fetches/updates by alert_id only,
  no org_id guard — a tenant who knows another tenant's alert_id can resolve it.
- attack_path_engine.py: get_node() and remove_node() query by node_id only,
  no org_id filter — cross-tenant node read and delete possible.
- security_kpi_tracker.py: Fully isolated. All queries filter by org_id. No issues.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any


class TenantIsolationAuditor:
    """Audits ALDECI engines for multi-tenant data isolation."""

    # ------------------------------------------------------------------
    # SQLite schema inspection
    # ------------------------------------------------------------------

    def audit_sqlite_db(
        self,
        db_path: str,
        org_id_column: str = "org_id",
    ) -> dict:
        """Check all tables in a SQLite DB for org_id column presence.

        Returns:
            {
                "db_path": str,
                "tables": {
                    "<table_name>": {
                        "has_org_id": bool,
                        "columns": [str],
                        "row_count": int,
                    }
                },
                "missing_org_id": [str],   # table names without org_id column
                "isolation_score": float,  # 0.0-1.0 (fraction of tables with org_id)
            }
        """
        path = Path(db_path)
        if not path.exists():
            return {
                "db_path": db_path,
                "error": "database file not found",
                "tables": {},
                "missing_org_id": [],
                "isolation_score": 0.0,
            }

        conn = sqlite3.connect(db_path)
        conn.row_factory = sqlite3.Row
        try:
            table_names = [
                row[0]
                for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
                ).fetchall()
            ]

            tables: dict[str, dict] = {}
            missing: list[str] = []

            for tname in table_names:
                cols = [
                    row["name"]
                    for row in conn.execute(f"PRAGMA table_info('{tname}')").fetchall()
                ]
                has_org = org_id_column in cols
                try:
                    count = conn.execute(
                        f"SELECT COUNT(*) FROM '{tname}'"  # noqa: S608  # nosec B608
                    ).fetchone()[0]
                except Exception:
                    count = -1

                tables[tname] = {
                    "has_org_id": has_org,
                    "columns": cols,
                    "row_count": count,
                }
                if not has_org:
                    missing.append(tname)

            score = (
                (len(table_names) - len(missing)) / len(table_names)
                if table_names
                else 1.0
            )
            return {
                "db_path": db_path,
                "tables": tables,
                "missing_org_id": missing,
                "isolation_score": round(score, 3),
            }
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Cross-tenant leak probe
    # ------------------------------------------------------------------

    def check_cross_tenant_leak(
        self,
        engine_instance: Any,
        test_org_1: str,
        test_org_2: str,
    ) -> list[dict]:
        """Create data for org_1, verify org_2 cannot see it.

        Supports engines with the following duck-typed interfaces:
          - SecurityKPITracker: record_kpi / get_current_kpis
          - InsiderThreatEngine: record_user_event / get_alerts
          - AttackPathEngine: add_node / list_nodes
          - SSOBridge: create_session / validate_session

        Returns:
            List of leak findings. Empty list means no leaks detected.
            Each finding: {"engine": str, "method": str, "description": str}
        """
        leaks: list[dict] = []
        engine_name = type(engine_instance).__name__

        # --- SecurityKPITracker ---
        if hasattr(engine_instance, "record_kpi") and hasattr(
            engine_instance, "get_current_kpis"
        ):
            try:
                engine_instance.record_kpi(
                    "posture_score", 99.0, org_id=test_org_1
                )
                org2_kpis = engine_instance.get_current_kpis(org_id=test_org_2)
                if "posture_score" in org2_kpis and org2_kpis["posture_score"]["value"] == 99.0:
                    leaks.append(
                        {
                            "engine": engine_name,
                            "method": "get_current_kpis",
                            "description": (
                                f"org_id={test_org_2} can read KPI recorded for "
                                f"org_id={test_org_1}"
                            ),
                        }
                    )
            except Exception as exc:
                leaks.append(
                    {
                        "engine": engine_name,
                        "method": "record_kpi/get_current_kpis",
                        "description": f"Unexpected error during KPI probe: {exc}",
                    }
                )

        # --- InsiderThreatEngine ---
        if hasattr(engine_instance, "record_user_event") and hasattr(
            engine_instance, "get_alerts"
        ):
            try:
                engine_instance.create_alert(
                    user_id="probe_user",
                    indicator="after_hours_access",
                    evidence={"probe": True},
                    severity="low",
                    org_id=test_org_1,
                )
                org2_alerts = engine_instance.get_alerts(org_id=test_org_2)
                leaked = [
                    a
                    for a in org2_alerts
                    if a.get("org_id") == test_org_1
                ]
                if leaked:
                    leaks.append(
                        {
                            "engine": engine_name,
                            "method": "get_alerts",
                            "description": (
                                f"org_id={test_org_2} can see {len(leaked)} alert(s) "
                                f"belonging to org_id={test_org_1}"
                            ),
                        }
                    )
            except Exception as exc:
                leaks.append(
                    {
                        "engine": engine_name,
                        "method": "create_alert/get_alerts",
                        "description": f"Unexpected error during alert probe: {exc}",
                    }
                )

        # --- AttackPathEngine ---
        if hasattr(engine_instance, "add_node") and hasattr(
            engine_instance, "list_nodes"
        ):
            try:
                engine_instance.add_node(
                    node_id="probe_node_isolation",
                    node_type="server",
                    name="Probe Server",
                    org_id=test_org_1,
                )
                org2_nodes = engine_instance.list_nodes(org_id=test_org_2)
                leaked = [
                    n for n in org2_nodes if n.get("node_id") == "probe_node_isolation"
                ]
                if leaked:
                    leaks.append(
                        {
                            "engine": engine_name,
                            "method": "list_nodes",
                            "description": (
                                f"org_id={test_org_2} can see node 'probe_node_isolation' "
                                f"belonging to org_id={test_org_1}"
                            ),
                        }
                    )
            except Exception as exc:
                leaks.append(
                    {
                        "engine": engine_name,
                        "method": "add_node/list_nodes",
                        "description": f"Unexpected error during node probe: {exc}",
                    }
                )

        # --- SSOBridge ---
        if hasattr(engine_instance, "create_session") and hasattr(
            engine_instance, "validate_session"
        ):
            try:
                from suite_core.core.sso_bridge import SSOUser  # type: ignore[import]
            except ImportError:
                try:
                    import os
                    import sys
                    sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
                    from core.sso_bridge import SSOUser  # type: ignore[import]
                except ImportError:
                    SSOUser = None  # type: ignore[assignment,misc]

            if SSOUser is not None:
                try:
                    user1 = SSOUser(
                        user_id="probe_user_sso",
                        email="probe@org1.example.com",
                        roles=["viewer"],
                        org_id=test_org_1,
                        provider="oidc",
                    )
                    token = engine_instance.create_session(user1)
                    result = engine_instance.validate_session(token)
                    # The session is keyed by token (unguessable) — this should succeed
                    # for the holder of the token regardless of org.
                    # The concern is whether org_id is preserved correctly.
                    if result is not None and result.org_id != test_org_1:
                        leaks.append(
                            {
                                "engine": engine_name,
                                "method": "validate_session",
                                "description": (
                                    f"Session org_id mismatch: expected {test_org_1!r}, "
                                    f"got {result.org_id!r}"
                                ),
                            }
                        )
                except Exception as exc:
                    leaks.append(
                        {
                            "engine": engine_name,
                            "method": "create_session/validate_session",
                            "description": f"Unexpected error during SSO probe: {exc}",
                        }
                    )

        return leaks

    # ------------------------------------------------------------------
    # Full isolation report
    # ------------------------------------------------------------------

    def generate_isolation_report(self) -> dict:
        """Full report of tenant isolation status across all engines.

        Returns a structured report with findings, severity, and recommendations.
        """
        findings: list[dict] = [
            {
                "engine": "RedisQueue",
                "file": "suite-core/core/redis_queue.py",
                "severity": "critical",
                "issue": "No org_id scoping on queue keys",
                "detail": (
                    "Queue keys are aldeci:queue:{priority} — global namespace shared "
                    "across all tenants. Any tenant's task can be dequeued by another "
                    "tenant's worker. enqueue() and dequeue() have no org_id parameter."
                ),
                "recommendation": (
                    "Prefix queue keys with org_id: aldeci:queue:{org_id}:{priority}. "
                    "Add org_id parameter to enqueue(), dequeue(), depth(), peek(), "
                    "and clear() methods."
                ),
                "status": "open",
            },
            {
                "engine": "SSOBridge",
                "file": "suite-core/core/sso_bridge.py",
                "severity": "medium",
                "issue": "sso_sessions table has no org_id column; sso_providers not scoped",
                "detail": (
                    "org_id is stored only in the user_json blob, not as a queryable column. "
                    "sso_providers table has no org_id — all tenants share the same provider "
                    "list. Session token lookup is globally unique (unguessable tokens), so "
                    "direct cross-tenant token theft is not possible, but provider configs "
                    "leak across tenants."
                ),
                "recommendation": (
                    "Add org_id column to sso_sessions and sso_providers tables. "
                    "Add org_id parameter to register_provider(), get_provider_config(), "
                    "and list_providers(). Add CREATE INDEX on (org_id, token)."
                ),
                "status": "open",
            },
            {
                "engine": "InsiderThreatEngine",
                "file": "suite-core/core/insider_threat_engine.py",
                "severity": "low",
                "issue": "resolve_alert() has no org_id guard",
                "detail": (
                    "resolve_alert() updates threat_alerts by alert_id only, with no "
                    "org_id filter. A tenant who discovers another tenant's alert_id "
                    "(via log leak or enumeration) can resolve or modify that alert."
                ),
                "recommendation": (
                    "Add org_id parameter to resolve_alert() and include "
                    "WHERE id = ? AND org_id = ? in the UPDATE and SELECT."
                ),
                "status": "fixed",
            },
            {
                "engine": "AttackPathEngine",
                "file": "suite-core/core/attack_path_engine.py",
                "severity": "high",
                "issue": "get_node() and remove_node() have no org_id filter",
                "detail": (
                    "get_node() selects by node_id only — returns any tenant's node. "
                    "remove_node() deletes by node_id only — can delete another tenant's "
                    "node and all its edges. Both methods have no org_id parameter."
                ),
                "recommendation": (
                    "Add org_id parameter to get_node() and remove_node(). "
                    "Include WHERE node_id = ? AND org_id = ? in both queries."
                ),
                "status": "open",
            },
            {
                "engine": "SecurityKPITracker",
                "file": "suite-core/core/security_kpi_tracker.py",
                "severity": "none",
                "issue": "No issues found",
                "detail": (
                    "All SELECT, INSERT, and aggregate queries filter by org_id. "
                    "Composite indexes (org_id, kpi_name, recorded_at) are in place. "
                    "get_current_kpis, get_kpi_trend, get_snapshots, get_targets, "
                    "set_target, record_kpi all properly scope to org_id."
                ),
                "recommendation": "No action required.",
                "status": "pass",
            },
        ]

        critical = [f for f in findings if f["severity"] == "critical"]
        high = [f for f in findings if f["severity"] == "high"]
        medium = [f for f in findings if f["severity"] == "medium"]
        low = [f for f in findings if f["severity"] == "low"]
        passed = [f for f in findings if f["status"] == "pass"]

        return {
            "summary": {
                "total_engines_audited": len(findings),
                "passed": len(passed),
                "open_findings": len(findings) - len(passed),
                "critical": len(critical),
                "high": len(high),
                "medium": len(medium),
                "low": len(low),
            },
            "findings": findings,
            "audit_date": "2026-04-14",
            "auditor": "TenantIsolationAuditor",
        }
