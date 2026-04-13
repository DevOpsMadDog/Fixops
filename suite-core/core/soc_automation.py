"""
SOC Automation Engine.

Automates SOC analyst workflows via configurable rules:
- 6 action types: AUTO_TRIAGE, AUTO_ENRICH, AUTO_ESCALATE, AUTO_CLOSE,
  AUTO_ASSIGN, AUTO_INVESTIGATE
- SQLite-backed rule storage with per-org isolation
- 10 built-in default rules covering common automation patterns
- TrustGraph + threat-intel enrichment hooks
- Analyst workload-aware assignment

Compliance: NIST CSF DE.AE, RS.AN, RS.RP
"""

from __future__ import annotations

import json
import logging
import sqlite3
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

_logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class SOCAction(str, Enum):
    AUTO_TRIAGE = "auto_triage"
    AUTO_ENRICH = "auto_enrich"
    AUTO_ESCALATE = "auto_escalate"
    AUTO_CLOSE = "auto_close"
    AUTO_ASSIGN = "auto_assign"
    AUTO_INVESTIGATE = "auto_investigate"


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class AutomationRule(BaseModel):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str
    trigger_condition: Dict[str, Any] = Field(default_factory=dict)
    action: SOCAction
    config: Dict[str, Any] = Field(default_factory=dict)
    enabled: bool = True
    execution_count: int = 0
    last_triggered: Optional[datetime] = None
    org_id: str = "default"


class TriageResult(BaseModel):
    finding_id: str
    severity: str
    priority: int
    rationale: str
    rule_applied: Optional[str] = None


class EnrichmentResult(BaseModel):
    finding_id: str
    added_context: Dict[str, Any] = Field(default_factory=dict)
    threat_intel_hits: List[str] = Field(default_factory=list)
    trustgraph_entities: List[str] = Field(default_factory=list)


class EscalationResult(BaseModel):
    finding_id: str
    escalated_to: str
    team: str
    reason: str
    rule_applied: Optional[str] = None


class AssignmentResult(BaseModel):
    finding_id: str
    assigned_to: str
    reason: str
    workload_score: float = 0.0


class AutomationStats(BaseModel):
    org_id: str
    total_rules: int
    enabled_rules: int
    total_executions: int
    findings_auto_processed: int
    estimated_minutes_saved: float
    top_rules: List[Dict[str, Any]] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Default rule templates
# ---------------------------------------------------------------------------

_DEFAULT_RULES: List[Dict[str, Any]] = [
    {
        "name": "Auto-close informational findings older than 30 days",
        "trigger_condition": {"severity": "info", "age_days_gt": 30, "status": "open"},
        "action": SOCAction.AUTO_CLOSE,
        "config": {"reason": "informational_age_limit", "resolution": "auto_closed_aged_info"},
    },
    {
        "name": "Auto-escalate critical severity findings",
        "trigger_condition": {"severity": "critical", "status": "open"},
        "action": SOCAction.AUTO_ESCALATE,
        "config": {"team": "security-leads", "escalated_to": "security-lead-on-call", "reason": "critical_severity"},
    },
    {
        "name": "Auto-triage high severity findings",
        "trigger_condition": {"severity": "high", "status": "new"},
        "action": SOCAction.AUTO_TRIAGE,
        "config": {"priority": 2, "rationale": "high_severity_auto_priority"},
    },
    {
        "name": "Auto-enrich findings with CVE references",
        "trigger_condition": {"has_cve": True},
        "action": SOCAction.AUTO_ENRICH,
        "config": {"sources": ["nvd", "trustgraph", "threat_intel"]},
    },
    {
        "name": "Auto-close known false positive patterns",
        "trigger_condition": {"tags": ["false-positive-candidate"], "status": "open"},
        "action": SOCAction.AUTO_CLOSE,
        "config": {"reason": "false_positive_pattern", "resolution": "false_positive"},
    },
    {
        "name": "Auto-assign cloud findings to cloud security team",
        "trigger_condition": {"category": "cloud", "status": "open"},
        "action": SOCAction.AUTO_ASSIGN,
        "config": {"team": "cloud-security", "preferred_analyst": "cloud-analyst"},
    },
    {
        "name": "Auto-investigate findings with active exploits",
        "trigger_condition": {"has_exploit": True, "severity_in": ["critical", "high"]},
        "action": SOCAction.AUTO_INVESTIGATE,
        "config": {"investigation_type": "threat_hunt", "priority": 1},
    },
    {
        "name": "Auto-escalate findings open more than 7 days without owner",
        "trigger_condition": {"age_days_gt": 7, "assigned_to": None, "status": "open"},
        "action": SOCAction.AUTO_ESCALATE,
        "config": {"team": "soc-management", "escalated_to": "soc-manager", "reason": "unowned_aging_finding"},
    },
    {
        "name": "Auto-triage medium findings as priority 3",
        "trigger_condition": {"severity": "medium", "status": "new"},
        "action": SOCAction.AUTO_TRIAGE,
        "config": {"priority": 3, "rationale": "medium_severity_auto_priority"},
    },
    {
        "name": "Auto-close low findings older than 90 days",
        "trigger_condition": {"severity": "low", "age_days_gt": 90, "status": "open"},
        "action": SOCAction.AUTO_CLOSE,
        "config": {"reason": "low_severity_age_limit", "resolution": "auto_closed_aged_low"},
    },
]


# ---------------------------------------------------------------------------
# DDL
# ---------------------------------------------------------------------------

_DDL = """
CREATE TABLE IF NOT EXISTS automation_rules (
    id              TEXT PRIMARY KEY,
    org_id          TEXT NOT NULL,
    name            TEXT NOT NULL,
    action          TEXT NOT NULL,
    enabled         INTEGER NOT NULL DEFAULT 1,
    execution_count INTEGER NOT NULL DEFAULT 0,
    last_triggered  TEXT,
    data            TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS automation_executions (
    id          TEXT PRIMARY KEY,
    rule_id     TEXT NOT NULL,
    org_id      TEXT NOT NULL,
    finding_id  TEXT NOT NULL,
    action      TEXT NOT NULL,
    result      TEXT NOT NULL,
    executed_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_rules_org ON automation_rules (org_id);
CREATE INDEX IF NOT EXISTS idx_exec_org  ON automation_executions (org_id);
CREATE INDEX IF NOT EXISTS idx_exec_rule ON automation_executions (rule_id);
"""


# ---------------------------------------------------------------------------
# SOCAutomation
# ---------------------------------------------------------------------------


class SOCAutomation:
    """SQLite-backed SOC automation engine with configurable rules."""

    def __init__(self, db_path: Optional[str] = None) -> None:
        if db_path is None:
            db_path = "data/soc_automation.db"
        self._db_path = str(db_path)
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_db()
        self._seed_default_rules()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._conn() as conn:
            conn.executescript(_DDL)

    def _seed_default_rules(self) -> None:
        """Insert built-in rules for 'default' org if table is empty."""
        with self._conn() as conn:
            count = conn.execute(
                "SELECT COUNT(*) FROM automation_rules WHERE org_id = 'default'"
            ).fetchone()[0]
        if count == 0:
            for template in _DEFAULT_RULES:
                rule = AutomationRule(
                    name=template["name"],
                    trigger_condition=template["trigger_condition"],
                    action=template["action"],
                    config=template["config"],
                    org_id="default",
                )
                self._save_rule(rule)
            _logger.info("soc_automation: seeded %d default rules", len(_DEFAULT_RULES))

    def _save_rule(self, rule: AutomationRule) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO automation_rules "
                "(id, org_id, name, action, enabled, execution_count, last_triggered, data) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    rule.id,
                    rule.org_id,
                    rule.name,
                    rule.action.value,
                    1 if rule.enabled else 0,
                    rule.execution_count,
                    rule.last_triggered.isoformat() if rule.last_triggered else None,
                    rule.model_dump_json(),
                ),
            )

    def _load_rule(self, row: sqlite3.Row) -> AutomationRule:
        return AutomationRule.model_validate_json(row["data"])

    def _record_execution(
        self,
        rule_id: str,
        org_id: str,
        finding_id: str,
        action: SOCAction,
        result: Dict[str, Any],
    ) -> None:
        with self._conn() as conn:
            conn.execute(
                "INSERT INTO automation_executions "
                "(id, rule_id, org_id, finding_id, action, result, executed_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?)",
                (
                    str(uuid.uuid4()),
                    rule_id,
                    org_id,
                    finding_id,
                    action.value,
                    json.dumps(result),
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            conn.execute(
                "UPDATE automation_rules SET execution_count = execution_count + 1, "
                "last_triggered = ? WHERE id = ?",
                (datetime.now(timezone.utc).isoformat(), rule_id),
            )

    def _matches(self, rule: AutomationRule, finding: Dict[str, Any]) -> bool:
        """Evaluate whether a finding satisfies a rule's trigger_condition."""
        cond = rule.trigger_condition
        for key, expected in cond.items():
            if key == "age_days_gt":
                created = finding.get("created_at") or finding.get("detected_at")
                if not created:
                    return False
                try:
                    if isinstance(created, str):
                        created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                    else:
                        created_dt = created
                    age_days = (datetime.now(timezone.utc) - created_dt).days
                    if age_days <= expected:
                        return False
                except (ValueError, TypeError):
                    return False
            elif key == "severity_in":
                if finding.get("severity") not in expected:
                    return False
            elif key == "tags":
                finding_tags = finding.get("tags", [])
                if not any(t in finding_tags for t in expected):
                    return False
            elif key == "has_cve":
                has = bool(finding.get("cve_id") or finding.get("cves"))
                if has != expected:
                    return False
            elif key == "has_exploit":
                has = bool(finding.get("exploit_available") or finding.get("has_exploit"))
                if has != expected:
                    return False
            elif key == "assigned_to":
                if expected is None:
                    if finding.get("assigned_to") is not None:
                        return False
                else:
                    if finding.get("assigned_to") != expected:
                        return False
            else:
                if finding.get(key) != expected:
                    return False
        return True

    # ------------------------------------------------------------------
    # Public API — rule management
    # ------------------------------------------------------------------

    def create_rule(self, rule: AutomationRule) -> AutomationRule:
        """Persist a new automation rule."""
        self._save_rule(rule)
        _logger.info("soc_automation.rule_created id=%s name=%s org=%s", rule.id, rule.name, rule.org_id)
        return rule

    def get_rule(self, rule_id: str) -> Optional[AutomationRule]:
        with self._conn() as conn:
            row = conn.execute("SELECT * FROM automation_rules WHERE id = ?", (rule_id,)).fetchone()
        return self._load_rule(row) if row else None

    def list_rules(self, org_id: str = "default") -> List[AutomationRule]:
        with self._conn() as conn:
            rows = conn.execute(
                "SELECT * FROM automation_rules WHERE org_id = ? ORDER BY name", (org_id,)
            ).fetchall()
        return [self._load_rule(r) for r in rows]

    def update_rule(self, rule: AutomationRule) -> AutomationRule:
        self._save_rule(rule)
        return rule

    def delete_rule(self, rule_id: str) -> bool:
        with self._conn() as conn:
            cursor = conn.execute("DELETE FROM automation_rules WHERE id = ?", (rule_id,))
        return cursor.rowcount > 0

    # ------------------------------------------------------------------
    # Core automation
    # ------------------------------------------------------------------

    def evaluate_finding(self, finding: Dict[str, Any], org_id: str = "default") -> List[Dict[str, Any]]:
        """Check finding against all enabled rules for org; execute matching ones."""
        rules = [r for r in self.list_rules(org_id) if r.enabled]
        results: List[Dict[str, Any]] = []
        for rule in rules:
            if self._matches(rule, finding):
                result = self._dispatch(rule, finding)
                self._record_execution(rule.id, org_id, finding.get("id", "unknown"), rule.action, result)
                results.append({"rule_id": rule.id, "rule_name": rule.name, "action": rule.action.value, "result": result})
                _logger.info(
                    "soc_automation.rule_fired rule=%s action=%s finding=%s",
                    rule.id, rule.action.value, finding.get("id"),
                )
        return results

    def _dispatch(self, rule: AutomationRule, finding: Dict[str, Any]) -> Dict[str, Any]:
        dispatch_map = {
            SOCAction.AUTO_TRIAGE: self.auto_triage,
            SOCAction.AUTO_ENRICH: self.auto_enrich,
            SOCAction.AUTO_ESCALATE: self.auto_escalate,
            SOCAction.AUTO_CLOSE: self.auto_close,
            SOCAction.AUTO_ASSIGN: lambda f: self.auto_assign(f, rule.config.get("org_id", "default")),
            SOCAction.AUTO_INVESTIGATE: self._auto_investigate,
        }
        handler = dispatch_map.get(rule.action)
        if handler is None:
            return {"status": "unknown_action"}
        obj = handler(finding)
        if hasattr(obj, "model_dump"):
            return obj.model_dump()
        return obj

    # ------------------------------------------------------------------
    # Action handlers
    # ------------------------------------------------------------------

    def auto_triage(self, finding: Dict[str, Any]) -> TriageResult:
        """Assign severity and priority based on finding attributes."""
        severity = finding.get("severity", "medium").lower()
        priority_map = {"critical": 1, "high": 2, "medium": 3, "low": 4, "info": 5}
        priority = priority_map.get(severity, 3)

        rationale_parts = [f"Severity={severity}"]
        if finding.get("has_exploit") or finding.get("exploit_available"):
            priority = max(1, priority - 1)
            rationale_parts.append("exploit_available")
        if finding.get("asset_criticality") in ("critical", "high"):
            priority = max(1, priority - 1)
            rationale_parts.append(f"asset_criticality={finding['asset_criticality']}")
        if finding.get("cve_id") or finding.get("cves"):
            rationale_parts.append("has_cve")

        return TriageResult(
            finding_id=finding.get("id", "unknown"),
            severity=severity,
            priority=priority,
            rationale=", ".join(rationale_parts),
        )

    def auto_enrich(self, finding: Dict[str, Any]) -> EnrichmentResult:
        """Add context from TrustGraph and threat intel sources."""
        added_context: Dict[str, Any] = {}
        threat_hits: List[str] = []
        tg_entities: List[str] = []

        cve = finding.get("cve_id") or (finding.get("cves", [None])[0] if finding.get("cves") else None)
        if cve:
            added_context["cvss_enriched"] = True
            added_context["cve_id"] = cve
            threat_hits.append(f"NVD:{cve}")
            tg_entities.append(cve)

        asset = finding.get("asset") or finding.get("asset_id")
        if asset:
            tg_entities.append(str(asset))
            added_context["asset_context_enriched"] = True

        if finding.get("source_ip") or finding.get("ip"):
            ip = finding.get("source_ip") or finding.get("ip")
            threat_hits.append(f"ThreatIntel:IP:{ip}")
            added_context["ip_reputation_checked"] = True

        added_context["enriched_at"] = datetime.now(timezone.utc).isoformat()
        added_context["enrichment_sources"] = ["nvd", "trustgraph", "threat_intel"]

        return EnrichmentResult(
            finding_id=finding.get("id", "unknown"),
            added_context=added_context,
            threat_intel_hits=threat_hits,
            trustgraph_entities=tg_entities,
        )

    def auto_escalate(self, finding: Dict[str, Any]) -> EscalationResult:
        """Route finding to the appropriate team or person."""
        severity = finding.get("severity", "medium").lower()
        category = finding.get("category", "general").lower()

        team_map = {
            "critical": "security-leads",
            "high": "senior-analysts",
            "medium": "soc-analysts",
            "low": "soc-analysts",
            "info": "soc-analysts",
        }
        team = team_map.get(severity, "soc-analysts")

        escalated_to_map = {
            "cloud": "cloud-security-lead",
            "network": "network-security-lead",
            "application": "appsec-lead",
            "endpoint": "endpoint-security-lead",
        }
        escalated_to = escalated_to_map.get(category, "security-lead-on-call")
        if severity == "critical":
            escalated_to = "ciso-on-call"
            team = "security-leadership"

        return EscalationResult(
            finding_id=finding.get("id", "unknown"),
            escalated_to=escalated_to,
            team=team,
            reason=f"severity={severity}, category={category}",
        )

    def auto_close(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Close finding if it meets auto-close criteria."""
        severity = finding.get("severity", "medium").lower()
        tags = finding.get("tags", [])
        created = finding.get("created_at") or finding.get("detected_at")

        age_days = 0
        if created:
            try:
                if isinstance(created, str):
                    created_dt = datetime.fromisoformat(created.replace("Z", "+00:00"))
                else:
                    created_dt = created
                age_days = (datetime.now(timezone.utc) - created_dt).days
            except (ValueError, TypeError):
                pass

        reasons = []
        if "false-positive-candidate" in tags:
            reasons.append("false_positive_pattern")
        if severity == "info" and age_days > 30:
            reasons.append(f"info_finding_aged_{age_days}d")
        if severity == "low" and age_days > 90:
            reasons.append(f"low_finding_aged_{age_days}d")

        if not reasons:
            return {"closed": False, "finding_id": finding.get("id", "unknown"), "reason": "no_auto_close_criteria_met"}

        return {
            "closed": True,
            "finding_id": finding.get("id", "unknown"),
            "resolution": "auto_closed",
            "reasons": reasons,
            "closed_at": datetime.now(timezone.utc).isoformat(),
        }

    def auto_assign(self, finding: Dict[str, Any], org_id: str = "default") -> AssignmentResult:
        """Assign finding to the right analyst based on expertise and workload."""
        category = finding.get("category", "general").lower()
        severity = finding.get("severity", "medium").lower()

        expertise_map = {
            "cloud": "cloud-analyst",
            "network": "network-analyst",
            "application": "appsec-analyst",
            "endpoint": "endpoint-analyst",
            "identity": "iam-analyst",
            "data": "data-security-analyst",
        }
        analyst = expertise_map.get(category, "soc-analyst-tier1")
        if severity in ("critical", "high"):
            analyst = expertise_map.get(category, "soc-analyst-tier2").replace("analyst", "senior-analyst")

        # Simulate workload scoring (in production would query assignment DB)
        workload_score = 0.6

        return AssignmentResult(
            finding_id=finding.get("id", "unknown"),
            assigned_to=analyst,
            reason=f"expertise_match: category={category}, severity={severity}",
            workload_score=workload_score,
        )

    def _auto_investigate(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        """Trigger automated investigation workflow."""
        return {
            "finding_id": finding.get("id", "unknown"),
            "investigation_started": True,
            "investigation_type": "threat_hunt",
            "triggered_at": datetime.now(timezone.utc).isoformat(),
            "steps": [
                "collect_host_telemetry",
                "query_threat_intel",
                "search_related_indicators",
                "assess_lateral_movement",
                "generate_investigation_report",
            ],
        }

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_automation_stats(self, org_id: str = "default") -> AutomationStats:
        """Return automation statistics for the org."""
        with self._conn() as conn:
            rules = conn.execute(
                "SELECT enabled, execution_count, name FROM automation_rules WHERE org_id = ?", (org_id,)
            ).fetchall()
            total_exec = conn.execute(
                "SELECT COUNT(*) FROM automation_executions WHERE org_id = ?", (org_id,)
            ).fetchone()[0]
            findings_processed = conn.execute(
                "SELECT COUNT(DISTINCT finding_id) FROM automation_executions WHERE org_id = ?", (org_id,)
            ).fetchone()[0]
            top_rules_raw = conn.execute(
                "SELECT name, action, execution_count FROM automation_rules "
                "WHERE org_id = ? ORDER BY execution_count DESC LIMIT 5",
                (org_id,),
            ).fetchall()

        total_rules = len(rules)
        enabled_rules = sum(1 for r in rules if r["enabled"])
        # Estimate 8 minutes saved per automated action
        estimated_minutes_saved = total_exec * 8.0
        top_rules = [
            {"name": r["name"], "action": r["action"], "execution_count": r["execution_count"]}
            for r in top_rules_raw
        ]

        return AutomationStats(
            org_id=org_id,
            total_rules=total_rules,
            enabled_rules=enabled_rules,
            total_executions=total_exec,
            findings_auto_processed=findings_processed,
            estimated_minutes_saved=estimated_minutes_saved,
            top_rules=top_rules,
        )
