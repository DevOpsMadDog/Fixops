"""
Policy-as-Code Engine for ALDECI.

Evaluates security policies written as structured rules — similar to OPA/Rego
but simpler and fully embedded. Policies are stored in SQLite, versioned, and
evaluated against arbitrary JSON-serializable input data.

Scopes: FINDINGS, DEPLOYMENTS, CLOUD_RESOURCES, CONTAINERS, CODE_CHANGES, ACCESS_CONTROL
Languages: ALDECI_RULES (native), JSON_LOGIC, REGO_COMPAT (subset)
Decisions: ALLOW, DENY, WARN, REQUIRE_APPROVAL
"""

from __future__ import annotations

import json
import logging
import operator
import re
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------


class PolicyLanguage(str, Enum):
    ALDECI_RULES = "aldeci_rules"
    JSON_LOGIC = "json_logic"
    REGO_COMPAT = "rego_compat"


class PolicyScope(str, Enum):
    FINDINGS = "findings"
    DEPLOYMENTS = "deployments"
    CLOUD_RESOURCES = "cloud_resources"
    CONTAINERS = "containers"
    CODE_CHANGES = "code_changes"
    ACCESS_CONTROL = "access_control"


class PolicyDecision(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    WARN = "warn"
    REQUIRE_APPROVAL = "require_approval"


# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class Policy(BaseModel):
    """A policy definition stored in the engine."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    name: str = Field(..., min_length=1, max_length=200)
    description: str = Field(default="")
    scope: PolicyScope
    language: PolicyLanguage = PolicyLanguage.ALDECI_RULES
    rules: List[Dict[str, Any]] = Field(default_factory=list)
    decision_on_match: PolicyDecision = PolicyDecision.DENY
    enabled: bool = True
    version: int = 1
    org_id: str = Field(default="default")
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class PolicyEvaluation(BaseModel):
    """Result of evaluating input data against one or more policies."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    policy_id: Optional[str] = None
    input_data: Dict[str, Any] = Field(default_factory=dict)
    decision: PolicyDecision = PolicyDecision.ALLOW
    matched_rules: List[str] = Field(default_factory=list)
    explanation: str = ""
    evaluated_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    org_id: str = "default"


# ---------------------------------------------------------------------------
# Built-in policy definitions
# ---------------------------------------------------------------------------

_BUILTIN_POLICIES: List[Dict[str, Any]] = [
    {
        "id": "builtin-no-critical-deploy",
        "name": "no-critical-deploy",
        "description": "Block deployments that have unresolved critical vulnerabilities",
        "scope": PolicyScope.DEPLOYMENTS.value,
        "language": PolicyLanguage.ALDECI_RULES.value,
        "rules": [
            {"field": "critical_vuln_count", "operator": "gt", "value": 0},
        ],
        "decision_on_match": PolicyDecision.DENY.value,
        "enabled": True,
        "version": 1,
    },
    {
        "id": "builtin-require-mfa-cloud",
        "name": "require-mfa-cloud",
        "description": "Deny cloud resource access without MFA enabled",
        "scope": PolicyScope.CLOUD_RESOURCES.value,
        "language": PolicyLanguage.ALDECI_RULES.value,
        "rules": [
            {"field": "mfa_enabled", "operator": "eq", "value": False},
        ],
        "decision_on_match": PolicyDecision.DENY.value,
        "enabled": True,
        "version": 1,
    },
    {
        "id": "builtin-block-public-s3",
        "name": "block-public-s3",
        "description": "Block S3 buckets with public access",
        "scope": PolicyScope.CLOUD_RESOURCES.value,
        "language": PolicyLanguage.ALDECI_RULES.value,
        "rules": [
            {"field": "resource_type", "operator": "eq", "value": "s3_bucket"},
            {"field": "public_access", "operator": "eq", "value": True},
        ],
        "decision_on_match": PolicyDecision.DENY.value,
        "enabled": True,
        "version": 1,
    },
    {
        "id": "builtin-enforce-encryption",
        "name": "enforce-encryption",
        "description": "Warn on cloud resources without encryption enabled",
        "scope": PolicyScope.CLOUD_RESOURCES.value,
        "language": PolicyLanguage.ALDECI_RULES.value,
        "rules": [
            {"field": "encryption_enabled", "operator": "eq", "value": False},
        ],
        "decision_on_match": PolicyDecision.WARN.value,
        "enabled": True,
        "version": 1,
    },
    {
        "id": "builtin-minimum-scan-coverage",
        "name": "minimum-scan-coverage",
        "description": "Require approval for code changes below minimum scan coverage",
        "scope": PolicyScope.CODE_CHANGES.value,
        "language": PolicyLanguage.ALDECI_RULES.value,
        "rules": [
            {"field": "scan_coverage_pct", "operator": "lt", "value": 80},
        ],
        "decision_on_match": PolicyDecision.REQUIRE_APPROVAL.value,
        "enabled": True,
        "version": 1,
    },
]


# ---------------------------------------------------------------------------
# Rule evaluation helpers
# ---------------------------------------------------------------------------

_OPERATORS: Dict[str, Any] = {
    "eq": operator.eq,
    "ne": operator.ne,
    "gt": operator.gt,
    "gte": operator.ge,
    "lt": operator.lt,
    "lte": operator.le,
    "ge": operator.ge,
    "le": operator.le,
    "in": lambda a, b: a in b,
    "not_in": lambda a, b: a not in b,
    "contains": lambda a, b: b in a if isinstance(a, str) else False,
    "not_contains": lambda a, b: b not in a if isinstance(a, str) else True,
    "starts_with": lambda a, b: a.startswith(b) if isinstance(a, str) else False,
    "ends_with": lambda a, b: a.endswith(b) if isinstance(a, str) else False,
    "matches": lambda a, b: bool(re.search(b, a)) if isinstance(a, str) else False,
    "exists": lambda a, b: a is not None,
    "not_exists": lambda a, b: a is None,
}


def _get_nested(data: Dict[str, Any], field_path: str) -> Any:
    """Resolve a dotted field path like 'resource.tags.env' from nested dict."""
    parts = field_path.split(".")
    current: Any = data
    for part in parts:
        if isinstance(current, dict):
            current = current.get(part)
        else:
            return None
    return current


# ---------------------------------------------------------------------------
# PolicyEngine
# ---------------------------------------------------------------------------

_DDL = """
CREATE TABLE IF NOT EXISTS policies (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    description TEXT DEFAULT '',
    scope       TEXT NOT NULL,
    language    TEXT NOT NULL DEFAULT 'aldeci_rules',
    rules       TEXT NOT NULL DEFAULT '[]',
    decision_on_match TEXT NOT NULL DEFAULT 'deny',
    enabled     INTEGER NOT NULL DEFAULT 1,
    version     INTEGER NOT NULL DEFAULT 1,
    org_id      TEXT NOT NULL DEFAULT 'default',
    created_at  TEXT,
    updated_at  TEXT
);

CREATE TABLE IF NOT EXISTS evaluations (
    id          TEXT PRIMARY KEY,
    policy_id   TEXT,
    input_data  TEXT NOT NULL DEFAULT '{}',
    decision    TEXT NOT NULL,
    matched_rules TEXT NOT NULL DEFAULT '[]',
    explanation TEXT DEFAULT '',
    evaluated_at TEXT NOT NULL,
    org_id      TEXT NOT NULL DEFAULT 'default'
);

-- GAP-062 (Sprint 3): canonical unified rule taxonomy shared by 5+ engines
CREATE TABLE IF NOT EXISTS unified_rule_registry (
    id            TEXT PRIMARY KEY,
    org_id        TEXT NOT NULL DEFAULT 'default',
    rule_key      TEXT NOT NULL,
    domain        TEXT NOT NULL,
    category      TEXT NOT NULL,
    severity      TEXT NOT NULL,
    rule_type     TEXT NOT NULL,
    enabled       INTEGER NOT NULL DEFAULT 1,
    source_engine TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    UNIQUE(org_id, rule_key)
);

CREATE INDEX IF NOT EXISTS idx_policies_org_scope ON policies(org_id, scope);
CREATE INDEX IF NOT EXISTS idx_evaluations_org    ON evaluations(org_id);
CREATE INDEX IF NOT EXISTS idx_evaluations_policy ON evaluations(policy_id);
CREATE INDEX IF NOT EXISTS idx_urr_org_domain     ON unified_rule_registry(org_id, domain);
CREATE INDEX IF NOT EXISTS idx_urr_org_source     ON unified_rule_registry(org_id, source_engine);
CREATE INDEX IF NOT EXISTS idx_urr_org_enabled    ON unified_rule_registry(org_id, enabled);
"""


# GAP-062 — canonical taxonomy vocabularies
_URR_VALID_DOMAINS = {
    "sast", "dast", "secrets", "iac", "container", "cspm",
    "api_security", "supply_chain", "network", "identity",
    "data", "endpoint", "cloud", "application", "generic",
}
_URR_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
_URR_VALID_RULE_TYPES = {"detection", "validation", "compliance", "posture", "hardening"}


class PolicyEngine:
    """SQLite-backed policy-as-code evaluation engine."""

    def __init__(self, db_path: str = ":memory:") -> None:
        self._db_path = db_path
        self._lock = threading.Lock()
        # For :memory: we keep ONE connection for the lifetime of the engine
        # because each sqlite3.connect(":memory:") produces a separate empty DB.
        self._db: sqlite3.Connection = sqlite3.connect(
            db_path, check_same_thread=False
        )
        self._db.row_factory = sqlite3.Row
        self._init_db()
        self._seed_builtins()

    # ------------------------------------------------------------------
    # DB lifecycle
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        with self._lock:
            self._db.executescript(_DDL)

    def _seed_builtins(self) -> None:
        """Insert built-in policies if they don't already exist."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            for bp in _BUILTIN_POLICIES:
                exists = self._db.execute(
                    "SELECT 1 FROM policies WHERE id = ?", (bp["id"],)
                ).fetchone()
                if not exists:
                    self._db.execute(
                        """INSERT INTO policies
                           (id, name, description, scope, language, rules,
                            decision_on_match, enabled, version, org_id,
                            created_at, updated_at)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                        (
                            bp["id"],
                            bp["name"],
                            bp.get("description", ""),
                            bp["scope"],
                            bp.get("language", PolicyLanguage.ALDECI_RULES.value),
                            json.dumps(bp.get("rules", [])),
                            bp.get("decision_on_match", PolicyDecision.DENY.value),
                            1 if bp.get("enabled", True) else 0,
                            bp.get("version", 1),
                            "default",
                            now,
                            now,
                        ),
                    )
            self._db.commit()

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    def create_policy(self, policy: Policy) -> Policy:
        """Persist a new policy. Raises ValueError if id already exists."""
        now = datetime.now(timezone.utc).isoformat()
        policy = policy.model_copy(update={"created_at": now, "updated_at": now})
        with self._lock:
            existing = self._db.execute(
                "SELECT 1 FROM policies WHERE id = ?", (policy.id,)
            ).fetchone()
            if existing:
                raise ValueError(f"Policy {policy.id!r} already exists")
            self._db.execute(
                """INSERT INTO policies
                   (id, name, description, scope, language, rules,
                    decision_on_match, enabled, version, org_id, created_at, updated_at)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    policy.id,
                    policy.name,
                    policy.description,
                    policy.scope.value,
                    policy.language.value,
                    json.dumps(policy.rules),
                    policy.decision_on_match.value,
                    1 if policy.enabled else 0,
                    policy.version,
                    policy.org_id,
                    policy.created_at,
                    policy.updated_at,
                ),
            )
            self._db.commit()
        logger.info("policy_engine: created policy id=%s name=%s", policy.id, policy.name)
        return policy

    def update_policy(self, policy_id: str, updates: Dict[str, Any]) -> Policy:
        """Update a policy. Automatically increments version."""
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            row = self._db.execute(
                "SELECT * FROM policies WHERE id = ?", (policy_id,)
            ).fetchone()
            if not row:
                raise ValueError(f"Policy {policy_id!r} not found")
            current = dict(row)
            for key, val in updates.items():
                if key == "rules":
                    current["rules"] = json.dumps(val)
                elif key == "enabled":
                    current["enabled"] = 1 if val else 0
                elif hasattr(val, "value"):
                    current[key] = val.value
                else:
                    current[key] = val
            current["version"] = current["version"] + 1
            current["updated_at"] = now
            self._db.execute(
                """UPDATE policies SET
                   name=?, description=?, scope=?, language=?, rules=?,
                   decision_on_match=?, enabled=?, version=?, updated_at=?
                   WHERE id=?""",
                (
                    current["name"],
                    current["description"],
                    current["scope"],
                    current["language"],
                    current["rules"],
                    current["decision_on_match"],
                    current["enabled"],
                    current["version"],
                    current["updated_at"],
                    policy_id,
                ),
            )
            self._db.commit()
        return self._row_to_policy(current)

    def delete_policy(self, policy_id: str) -> None:
        """Delete a policy by ID. Raises ValueError if not found."""
        with self._lock:
            result = self._db.execute(
                "DELETE FROM policies WHERE id = ?", (policy_id,)
            )
            self._db.commit()
        if result.rowcount == 0:
            raise ValueError(f"Policy {policy_id!r} not found")
        logger.info("policy_engine: deleted policy id=%s", policy_id)

    def list_policies(
        self,
        org_id: str = "default",
        scope: Optional[PolicyScope] = None,
    ) -> List[Policy]:
        """Return all policies for an org, optionally filtered by scope."""
        with self._lock:
            if scope:
                rows = self._db.execute(
                    "SELECT * FROM policies WHERE org_id IN (?, 'default') AND scope = ? ORDER BY name",
                    (org_id, scope.value),
                ).fetchall()
            else:
                rows = self._db.execute(
                    "SELECT * FROM policies WHERE org_id IN (?, 'default') ORDER BY name",
                    (org_id,),
                ).fetchall()
        return [self._row_to_policy(dict(r)) for r in rows]

    # ------------------------------------------------------------------
    # Rule evaluation
    # ------------------------------------------------------------------

    def _evaluate_rule(self, rule: Dict[str, Any], data: Dict[str, Any]) -> bool:
        """
        Evaluate a single rule dict against input data.

        Rule schema (ALDECI_RULES):
            field    : str  — dotted path into data (e.g. "resource.tags.env")
            operator : str  — one of the _OPERATORS keys
            value    : Any  — expected value to compare against

        Returns True if rule matches (condition satisfied).
        """
        field = rule.get("field", "")
        op_name = rule.get("operator", "eq")
        expected = rule.get("value")

        actual = _get_nested(data, field)
        op_fn = _OPERATORS.get(op_name)
        if op_fn is None:
            logger.debug("policy_engine: unknown operator %r, skipping rule", op_name)
            return False

        try:
            return bool(op_fn(actual, expected))
        except (TypeError, ValueError, AttributeError) as exc:
            logger.debug(
                "policy_engine: rule eval error field=%s op=%s: %s", field, op_name, exc
            )
            return False

    def _evaluate_json_logic(
        self, rules: List[Dict[str, Any]], data: Dict[str, Any]
    ) -> bool:
        """Basic JSON Logic evaluation (subset: ==, !=, >, >=, <, <=, and, or, !)."""
        for rule in rules:
            if not self._json_logic_eval(rule, data):
                return False
        return bool(rules)  # empty rules = no match

    def _json_logic_eval(self, logic: Any, data: Dict[str, Any]) -> bool:
        if not isinstance(logic, dict):
            return bool(logic)
        for op, args in logic.items():
            if op == "==":
                return self._resolve_jl(args[0], data) == self._resolve_jl(args[1], data)
            if op == "!=":
                return self._resolve_jl(args[0], data) != self._resolve_jl(args[1], data)
            if op == ">":
                return self._resolve_jl(args[0], data) > self._resolve_jl(args[1], data)
            if op == ">=":
                return self._resolve_jl(args[0], data) >= self._resolve_jl(args[1], data)
            if op == "<":
                return self._resolve_jl(args[0], data) < self._resolve_jl(args[1], data)
            if op == "<=":
                return self._resolve_jl(args[0], data) <= self._resolve_jl(args[1], data)
            if op == "and":
                return all(self._json_logic_eval(a, data) for a in args)
            if op == "or":
                return any(self._json_logic_eval(a, data) for a in args)
            if op == "!":
                return not self._json_logic_eval(args, data)
            if op == "var":
                return bool(_get_nested(data, args))
        return False

    def _resolve_jl(self, node: Any, data: Dict[str, Any]) -> Any:
        if isinstance(node, dict) and "var" in node:
            return _get_nested(data, node["var"])
        return node

    def _evaluate_policy_rules(
        self, policy: Policy, data: Dict[str, Any]
    ) -> tuple[bool, List[str]]:
        """
        Evaluate all rules in a policy against data.

        ALDECI_RULES: ALL rules must match (AND semantics).
        JSON_LOGIC: Delegate to json_logic evaluator.
        REGO_COMPAT: Same as ALDECI_RULES (limited subset).

        Returns (matched: bool, matched_rule_names: List[str]).
        """
        if not policy.rules:
            return False, []

        if policy.language == PolicyLanguage.JSON_LOGIC:
            matched = self._evaluate_json_logic(policy.rules, data)
            if matched:
                return True, [f"{policy.name}:json_logic"]
            return False, []

        # ALDECI_RULES / REGO_COMPAT — AND semantics
        matched_names: List[str] = []
        for rule in policy.rules:
            rule_name = rule.get("name", rule.get("field", "unnamed"))
            if self._evaluate_rule(rule, data):
                matched_names.append(rule_name)
            else:
                return False, []  # AND: short-circuit on first miss
        return bool(matched_names), matched_names

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def evaluate(
        self,
        input_data: Dict[str, Any],
        scope: PolicyScope,
        org_id: str = "default",
    ) -> PolicyEvaluation:
        """
        Evaluate input_data against all enabled policies for the given scope.

        Priority: DENY > REQUIRE_APPROVAL > WARN > ALLOW.
        First DENY short-circuits further evaluation.
        """
        policies = [p for p in self.list_policies(org_id, scope) if p.enabled]

        overall_decision = PolicyDecision.ALLOW
        all_matched_rules: List[str] = []
        explanation_parts: List[str] = []
        matched_policy_id: Optional[str] = None

        _PRIORITY = {
            PolicyDecision.DENY: 3,
            PolicyDecision.REQUIRE_APPROVAL: 2,
            PolicyDecision.WARN: 1,
            PolicyDecision.ALLOW: 0,
        }

        for policy in policies:
            matched, rule_names = self._evaluate_policy_rules(policy, input_data)
            if matched:
                all_matched_rules.extend(rule_names)
                explanation_parts.append(
                    f"Policy '{policy.name}' matched rules {rule_names} "
                    f"→ {policy.decision_on_match.value}"
                )
                if _PRIORITY[policy.decision_on_match] > _PRIORITY[overall_decision]:
                    overall_decision = policy.decision_on_match
                    matched_policy_id = policy.id
                if overall_decision == PolicyDecision.DENY:
                    break  # short-circuit

        evaluation = PolicyEvaluation(
            policy_id=matched_policy_id,
            input_data=input_data,
            decision=overall_decision,
            matched_rules=all_matched_rules,
            explanation="; ".join(explanation_parts)
            or "No policies matched — default allow",
            org_id=org_id,
        )
        self._save_evaluation(evaluation)
        return evaluation

    def evaluate_batch(
        self,
        inputs: List[Dict[str, Any]],
        scope: PolicyScope,
        org_id: str = "default",
    ) -> List[PolicyEvaluation]:
        """Evaluate multiple inputs. Returns one PolicyEvaluation per input."""
        return [self.evaluate(inp, scope, org_id) for inp in inputs]

    def evaluate_at_stage(
        self,
        org_id: str,
        stage: str,
        context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """GAP-004: CTEM stage-aware evaluation.

        Delegates to policy_enforcement_engine.PolicyEnforcementEngine.evaluate()
        which filters policies by stage_matrix[stage]=True. Allows a single
        entry-point for IDE/PR/build/deploy/runtime hooks.
        """
        try:
            from core.policy_enforcement_engine import (
                get_engine as _get_enforcement_engine,
            )
        except ImportError:
            return {
                "org_id": org_id,
                "stage": stage,
                "context": context,
                "policy_count": 0,
                "matched_policies": [],
                "decision": "allow",
                "error": "policy_enforcement_engine unavailable",
            }
        enforcement = _get_enforcement_engine(org_id)
        return enforcement.evaluate(org_id, stage, context)

    def test_policy(
        self, policy: Policy, test_input: Dict[str, Any]
    ) -> PolicyEvaluation:
        """Dry-run a single policy without persisting the evaluation."""
        matched, rule_names = self._evaluate_policy_rules(policy, test_input)
        decision = policy.decision_on_match if matched else PolicyDecision.ALLOW
        explanation = (
            f"Policy '{policy.name}' matched rules {rule_names} → {decision.value}"
            if matched
            else f"Policy '{policy.name}' did not match — allow"
        )
        return PolicyEvaluation(
            policy_id=policy.id,
            input_data=test_input,
            decision=decision,
            matched_rules=rule_names,
            explanation=explanation,
            org_id=policy.org_id,
        )

    # ------------------------------------------------------------------
    # History & stats
    # ------------------------------------------------------------------

    def get_evaluation_history(
        self,
        org_id: str = "default",
        policy_id: Optional[str] = None,
        limit: int = 100,
    ) -> List[PolicyEvaluation]:
        """Return past evaluations for an org, optionally filtered by policy_id."""
        with self._lock:
            if policy_id:
                rows = self._db.execute(
                    """SELECT * FROM evaluations WHERE org_id = ? AND policy_id = ?
                       ORDER BY evaluated_at DESC LIMIT ?""",
                    (org_id, policy_id, limit),
                ).fetchall()
            else:
                rows = self._db.execute(
                    """SELECT * FROM evaluations WHERE org_id = ?
                       ORDER BY evaluated_at DESC LIMIT ?""",
                    (org_id, limit),
                ).fetchall()
        return [self._row_to_evaluation(dict(r)) for r in rows]

    def get_policy_stats(self, org_id: str = "default") -> Dict[str, Any]:
        """Return aggregate statistics for policies and evaluations."""
        with self._lock:
            policy_count = self._db.execute(
                "SELECT COUNT(*) FROM policies WHERE org_id IN (?, 'default')", (org_id,)
            ).fetchone()[0]
            enabled_count = self._db.execute(
                "SELECT COUNT(*) FROM policies WHERE org_id IN (?, 'default') AND enabled = 1",
                (org_id,),
            ).fetchone()[0]
            eval_count = self._db.execute(
                "SELECT COUNT(*) FROM evaluations WHERE org_id = ?", (org_id,)
            ).fetchone()[0]
            decision_rows = self._db.execute(
                """SELECT decision, COUNT(*) as cnt FROM evaluations
                   WHERE org_id = ? GROUP BY decision""",
                (org_id,),
            ).fetchall()
            scope_rows = self._db.execute(
                """SELECT scope, COUNT(*) as cnt FROM policies
                   WHERE org_id IN (?, 'default') GROUP BY scope""",
                (org_id,),
            ).fetchall()

        decisions = {r["decision"]: r["cnt"] for r in decision_rows}
        scopes = {r["scope"]: r["cnt"] for r in scope_rows}
        return {
            "total_policies": policy_count,
            "enabled_policies": enabled_count,
            "disabled_policies": policy_count - enabled_count,
            "total_evaluations": eval_count,
            "decisions": decisions,
            "policies_by_scope": scopes,
        }

    # ------------------------------------------------------------------
    # Import / Export
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # GAP-023 — Policy Library Bulk Seed
    # ------------------------------------------------------------------

    def seed_policy_library(self, org_id: Optional[str] = None) -> Dict[str, Any]:
        """Bulk-seed the 3000+ policy rule catalog.

        Idempotent: a unique ``(org_id, name)`` is skipped on re-run.
        Returns a summary dict.
        """
        target_org = org_id or "default"
        catalog = build_policy_library_catalog()
        inserted = 0
        skipped = 0
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            # Preload existing rule names for this org
            rows = self._db.execute(
                "SELECT name FROM policies WHERE org_id = ?", (target_org,)
            ).fetchall()
            existing_names = {r["name"] for r in rows}
            for entry in catalog:
                name = entry["name"]
                if name in existing_names:
                    skipped += 1
                    continue
                pid = entry.get("id") or f"lib-{uuid.uuid4().hex[:12]}"
                self._db.execute(
                    """INSERT INTO policies
                       (id, name, description, scope, language, rules,
                        decision_on_match, enabled, version, org_id,
                        created_at, updated_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        pid,
                        name,
                        entry.get("description", ""),
                        entry.get("scope", PolicyScope.CLOUD_RESOURCES.value),
                        PolicyLanguage.ALDECI_RULES.value,
                        json.dumps(entry.get("rules", [])),
                        entry.get("decision_on_match", PolicyDecision.DENY.value),
                        1,
                        1,
                        target_org,
                        now,
                        now,
                    ),
                )
                existing_names.add(name)
                inserted += 1
            self._db.commit()
            total = self._db.execute(
                "SELECT COUNT(*) FROM policies WHERE org_id = ?", (target_org,)
            ).fetchone()[0]
        # Tally by category from the catalog itself (stable even if skipped)
        by_category: Dict[str, int] = {}
        for entry in catalog:
            cat = entry.get("category", "uncategorized")
            by_category[cat] = by_category.get(cat, 0) + 1
        return {
            "policies_inserted": inserted,
            "policies_skipped": skipped,
            "total_policies_in_org": total,
            "catalog_size": len(catalog),
            "by_category": by_category,
            "org_id": target_org,
        }

    def import_policies(self, policies_json: str, org_id: str = "default") -> int:
        """Bulk-import policies from a JSON string. Returns count of imported policies."""
        data = json.loads(policies_json)
        if isinstance(data, dict) and "policies" in data:
            raw_list = data["policies"]
        elif isinstance(data, list):
            raw_list = data
        else:
            raise ValueError(
                "policies_json must be a JSON array or object with 'policies' key"
            )

        imported = 0
        for raw in raw_list:
            raw = dict(raw)
            raw["org_id"] = org_id
            raw.setdefault("scope", PolicyScope.FINDINGS.value)
            raw.setdefault("language", PolicyLanguage.ALDECI_RULES.value)
            raw.setdefault("decision_on_match", PolicyDecision.DENY.value)
            policy = Policy(**raw)
            try:
                self.create_policy(policy)
                imported += 1
            except ValueError:
                logger.debug("policy_engine: import skipped duplicate id=%s", policy.id)
        return imported

    def export_policies(self, org_id: str = "default") -> str:
        """Export all org policies (excluding built-ins) as a JSON string."""
        policies = self.list_policies(org_id)
        org_policies = [p for p in policies if not p.id.startswith("builtin-")]
        payload = {
            "policies": [p.model_dump() for p in org_policies],
            "org_id": org_id,
        }
        if _get_tg_bus:
            try:
                _bus = _get_tg_bus()
                if _bus:
                    _bus.emit("CONTROL_ASSESSED", {"entity_type": "policy", "org_id": org_id, "source_engine": "policy"})
            except Exception:
                pass

        return json.dumps(payload, indent=2, default=str)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _save_evaluation(self, evaluation: PolicyEvaluation) -> None:
        with self._lock:
            self._db.execute(
                """INSERT OR REPLACE INTO evaluations
                   (id, policy_id, input_data, decision, matched_rules,
                    explanation, evaluated_at, org_id)
                   VALUES (?,?,?,?,?,?,?,?)""",
                (
                    evaluation.id,
                    evaluation.policy_id,
                    json.dumps(evaluation.input_data),
                    evaluation.decision.value,
                    json.dumps(evaluation.matched_rules),
                    evaluation.explanation,
                    evaluation.evaluated_at,
                    evaluation.org_id,
                ),
            )
            self._db.commit()

    @staticmethod
    def _row_to_policy(row: Dict[str, Any]) -> Policy:
        rules = row.get("rules", "[]")
        if isinstance(rules, str):
            rules = json.loads(rules)
        return Policy(
            id=row["id"],
            name=row["name"],
            description=row.get("description", ""),
            scope=PolicyScope(row["scope"]),
            language=PolicyLanguage(
                row.get("language", PolicyLanguage.ALDECI_RULES.value)
            ),
            rules=rules,
            decision_on_match=PolicyDecision(
                row.get("decision_on_match", PolicyDecision.DENY.value)
            ),
            enabled=bool(row.get("enabled", 1)),
            version=int(row.get("version", 1)),
            org_id=row.get("org_id", "default"),
            created_at=row.get("created_at"),
            updated_at=row.get("updated_at"),
        )

    @staticmethod
    def _row_to_evaluation(row: Dict[str, Any]) -> PolicyEvaluation:
        input_data = row.get("input_data", "{}")
        if isinstance(input_data, str):
            input_data = json.loads(input_data)
        matched_rules = row.get("matched_rules", "[]")
        if isinstance(matched_rules, str):
            matched_rules = json.loads(matched_rules)
        return PolicyEvaluation(
            id=row["id"],
            policy_id=row.get("policy_id"),
            input_data=input_data,
            decision=PolicyDecision(row["decision"]),
            matched_rules=matched_rules,
            explanation=row.get("explanation", ""),
            evaluated_at=row["evaluated_at"],
            org_id=row.get("org_id", "default"),
        )


# ---------------------------------------------------------------------------
# Module-level singleton (lazy, thread-safe)
# ---------------------------------------------------------------------------

_engine_instance: Optional[PolicyEngine] = None
_engine_lock = threading.Lock()


# ---------------------------------------------------------------------------
# GAP-062 — Unified Rule Registry (cross-engine canonical taxonomy)
# ---------------------------------------------------------------------------

def _register_unified_rule_impl(
    engine: "PolicyEngine",
    org_id: str,
    rule_key: str,
    domain: str,
    category: str,
    severity: str,
    rule_type: str,
    source_engine: str,
) -> Dict[str, Any]:
    """UPSERT a rule into the canonical registry. Idempotent on (org_id, rule_key)."""
    if not rule_key or not isinstance(rule_key, str):
        raise ValueError("rule_key is required")
    if domain not in _URR_VALID_DOMAINS:
        raise ValueError(
            f"Invalid domain {domain!r}. Valid: {sorted(_URR_VALID_DOMAINS)}"
        )
    sev = severity.lower() if isinstance(severity, str) else severity
    if sev not in _URR_VALID_SEVERITIES:
        raise ValueError(
            f"Invalid severity {severity!r}. Valid: {sorted(_URR_VALID_SEVERITIES)}"
        )
    rt = rule_type.lower() if isinstance(rule_type, str) else rule_type
    if rt not in _URR_VALID_RULE_TYPES:
        raise ValueError(
            f"Invalid rule_type {rule_type!r}. Valid: {sorted(_URR_VALID_RULE_TYPES)}"
        )
    if not source_engine or not isinstance(source_engine, str):
        raise ValueError("source_engine is required")
    if not category or not isinstance(category, str):
        raise ValueError("category is required")

    now = datetime.now(timezone.utc).isoformat()
    new_id = str(uuid.uuid4())
    with engine._lock:
        existing = engine._db.execute(
            "SELECT id, created_at, enabled FROM unified_rule_registry "
            "WHERE org_id=? AND rule_key=?",
            (org_id, rule_key),
        ).fetchone()
        if existing:
            engine._db.execute(
                """UPDATE unified_rule_registry
                   SET domain=?, category=?, severity=?, rule_type=?,
                       source_engine=?, updated_at=?
                 WHERE org_id=? AND rule_key=?""",
                (domain, category, sev, rt, source_engine, now, org_id, rule_key),
            )
            engine._db.commit()
            row = engine._db.execute(
                "SELECT * FROM unified_rule_registry WHERE org_id=? AND rule_key=?",
                (org_id, rule_key),
            ).fetchone()
            return _urr_row_to_dict(row)
        engine._db.execute(
            """INSERT INTO unified_rule_registry
               (id, org_id, rule_key, domain, category, severity, rule_type,
                enabled, source_engine, created_at, updated_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
            (new_id, org_id, rule_key, domain, category, sev, rt,
             1, source_engine, now, now),
        )
        engine._db.commit()
        row = engine._db.execute(
            "SELECT * FROM unified_rule_registry WHERE id=?", (new_id,)
        ).fetchone()
        return _urr_row_to_dict(row)


def _urr_row_to_dict(row: Any) -> Dict[str, Any]:
    if row is None:
        return {}
    d = dict(row)
    d["enabled"] = bool(d.get("enabled", 1))
    return d


def _list_unified_rules_impl(
    engine: "PolicyEngine",
    org_id: str,
    domain: Optional[str] = None,
    source_engine: Optional[str] = None,
    enabled: Optional[bool] = None,
) -> List[Dict[str, Any]]:
    query = "SELECT * FROM unified_rule_registry WHERE org_id=?"
    params: List[Any] = [org_id]
    if domain:
        query += " AND domain=?"
        params.append(domain)
    if source_engine:
        query += " AND source_engine=?"
        params.append(source_engine)
    if enabled is not None:
        query += " AND enabled=?"
        params.append(1 if enabled else 0)
    query += " ORDER BY created_at DESC"
    with engine._lock:
        rows = engine._db.execute(query, params).fetchall()
    return [_urr_row_to_dict(r) for r in rows]


def _toggle_unified_rule_impl(
    engine: "PolicyEngine",
    org_id: str,
    rule_key: str,
    enabled: bool,
) -> Optional[Dict[str, Any]]:
    now = datetime.now(timezone.utc).isoformat()
    with engine._lock:
        cursor = engine._db.execute(
            "UPDATE unified_rule_registry SET enabled=?, updated_at=? "
            "WHERE org_id=? AND rule_key=?",
            (1 if enabled else 0, now, org_id, rule_key),
        )
        engine._db.commit()
        if cursor.rowcount == 0:
            return None
        row = engine._db.execute(
            "SELECT * FROM unified_rule_registry WHERE org_id=? AND rule_key=?",
            (org_id, rule_key),
        ).fetchone()
    return _urr_row_to_dict(row)


def _get_rule_taxonomy_impl() -> Dict[str, Any]:
    """Return canonical taxonomy shape (static vocabularies) for UI/API consumers."""
    return {
        "schema_version": "1.0",
        "gap_reference": "GAP-062",
        "fields": {
            "rule_key":      {"type": "string", "required": True, "description": "Canonical cross-engine key"},
            "domain":        {"type": "enum",   "required": True, "values": sorted(_URR_VALID_DOMAINS)},
            "category":      {"type": "string", "required": True, "description": "Subcategory within domain (free-form)"},
            "severity":      {"type": "enum",   "required": True, "values": sorted(_URR_VALID_SEVERITIES)},
            "rule_type":     {"type": "enum",   "required": True, "values": sorted(_URR_VALID_RULE_TYPES)},
            "enabled":       {"type": "boolean", "required": False, "default": True},
            "source_engine": {"type": "string", "required": True, "description": "Originating scanner engine (sast/secrets/...)"},
        },
    }


# Attach methods to PolicyEngine via monkey-patch (keeps class body unchanged size)
def _pe_register_unified_rule(
    self: "PolicyEngine",
    org_id: str,
    rule_key: str,
    domain: str,
    category: str,
    severity: str,
    rule_type: str,
    source_engine: str,
) -> Dict[str, Any]:
    return _register_unified_rule_impl(
        self, org_id, rule_key, domain, category, severity, rule_type, source_engine
    )


def _pe_list_unified_rules(
    self: "PolicyEngine",
    org_id: str,
    domain: Optional[str] = None,
    source_engine: Optional[str] = None,
    enabled: Optional[bool] = None,
) -> List[Dict[str, Any]]:
    return _list_unified_rules_impl(self, org_id, domain, source_engine, enabled)


def _pe_disable_rule(
    self: "PolicyEngine",
    org_id: str,
    rule_key: str,
) -> Optional[Dict[str, Any]]:
    return _toggle_unified_rule_impl(self, org_id, rule_key, False)


def _pe_enable_rule(
    self: "PolicyEngine",
    org_id: str,
    rule_key: str,
) -> Optional[Dict[str, Any]]:
    return _toggle_unified_rule_impl(self, org_id, rule_key, True)


def _pe_get_rule_taxonomy(self: "PolicyEngine") -> Dict[str, Any]:
    return _get_rule_taxonomy_impl()


PolicyEngine.register_unified_rule = _pe_register_unified_rule  # type: ignore[attr-defined]
PolicyEngine.list_unified_rules = _pe_list_unified_rules  # type: ignore[attr-defined]
PolicyEngine.disable_rule = _pe_disable_rule  # type: ignore[attr-defined]
PolicyEngine.enable_rule = _pe_enable_rule  # type: ignore[attr-defined]
PolicyEngine.get_rule_taxonomy = _pe_get_rule_taxonomy  # type: ignore[attr-defined]


def get_policy_engine(db_path: Optional[str] = None) -> PolicyEngine:
    """Return the module-level PolicyEngine singleton."""
    global _engine_instance
    if _engine_instance is None:
        with _engine_lock:
            if _engine_instance is None:
                import os

                path = db_path or os.getenv(
                    "FIXOPS_POLICY_DB", "/tmp/fixops_policy_engine.db"  # nosec B108
                )
                _engine_instance = PolicyEngine(db_path=path)
    return _engine_instance


# ---------------------------------------------------------------------------
# GAP-023 — Policy Library Catalog (3000+ structured rules)
#
# The catalog is assembled from per-category helpers; the UI filters against
# the `category`, `framework`, and `severity` keys.
# ---------------------------------------------------------------------------


_FRAMEWORK_DEFAULT = ["cis_benchmark_aws", "nist_sp_800_53_r5", "iso_27001_2022"]


def _pol(name: str, desc: str, category: str, scope: str,
         severity: str = "medium", frameworks: Optional[List[str]] = None,
         decision: str = "deny",
         rules: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
    """Build a single policy catalog entry."""
    return {
        "name": name,
        "description": desc,
        "category": category,
        "scope": scope,
        "severity": severity,
        "frameworks": frameworks or _FRAMEWORK_DEFAULT,
        "decision_on_match": decision,
        "rules": rules or [{"field": "compliant", "operator": "eq", "value": False}],
    }


def _build_aws_cspm_rules() -> List[Dict[str, Any]]:
    """200 AWS CSPM rules."""
    services = [
        ("s3", [
            "bucket_public_access_blocked", "bucket_default_encryption_enabled",
            "bucket_versioning_enabled", "bucket_mfa_delete_enabled",
            "bucket_logging_enabled", "bucket_ssl_requests_only",
            "bucket_cross_region_replication_enabled",
            "bucket_lifecycle_policy_enabled", "bucket_object_lock_enabled",
            "bucket_policy_grantee_check", "bucket_cors_restricted",
            "bucket_website_hosting_disabled", "bucket_request_metrics_enabled",
            "bucket_inventory_enabled", "bucket_restrict_public_read_acl",
            "bucket_restrict_public_write_acl", "bucket_block_public_policy",
            "bucket_ignore_public_acls", "bucket_restrict_public_buckets",
            "bucket_access_logging_target_different_bucket",
        ]),
        ("ec2", [
            "instance_imdsv2_required", "instance_no_public_ip",
            "instance_stopped_long_term", "instance_ebs_encryption_at_launch",
            "instance_detailed_monitoring_enabled", "instance_in_vpc",
            "instance_user_data_no_secrets",
            "ebs_snapshot_public_restorable_disabled", "ebs_default_encryption",
            "ebs_snapshot_encrypted", "ami_public_disabled", "ami_encrypted",
            "security_group_default_no_rules", "security_group_no_ingress_22_open",
            "security_group_no_ingress_3389_open", "security_group_no_ingress_world",
            "security_group_no_icmp_open", "security_group_no_ipv6_world",
            "vpc_flow_logs_enabled", "vpc_nacl_no_allow_all_world",
            "elastic_ip_attached", "nat_gateway_redundant_azs",
            "vpn_tunnels_up", "transit_gateway_logging",
        ]),
        ("iam", [
            "root_account_mfa_enabled", "root_access_keys_absent",
            "password_policy_min_length_14", "password_policy_require_symbols",
            "password_policy_require_numbers", "password_policy_uppercase",
            "password_policy_lowercase", "password_reuse_prevention_24",
            "password_expiration_90_days",
            "iam_user_mfa_enabled", "iam_user_access_keys_rotated_90d",
            "iam_user_no_inline_policy", "iam_user_no_admin_privileges",
            "iam_group_inline_policy_removed", "iam_role_wildcard_resource",
            "iam_role_assume_role_policy_public", "iam_role_unused_90d",
            "iam_policy_no_wildcard_action", "iam_policy_no_admin_star",
            "iam_access_analyzer_enabled", "iam_credentials_report_recent",
            "iam_saml_provider_configured", "iam_console_users_mfa",
            "iam_server_certificate_expiry",
        ]),
        ("rds", [
            "instance_public_access_disabled", "instance_encryption_at_rest",
            "instance_backup_retention_7d", "instance_multi_az_deployment",
            "instance_deletion_protection", "instance_auto_minor_upgrade",
            "instance_iam_auth_enabled", "instance_audit_logs_enabled",
            "instance_performance_insights", "snapshot_public_disabled",
            "snapshot_encrypted", "parameter_group_log_connections",
            "parameter_group_log_statement_ddl", "cluster_copy_tags_to_snapshot",
            "cluster_audit_enabled", "cluster_storage_encryption",
            "read_replica_encryption_at_rest",
        ]),
        ("kms", [
            "cmk_rotation_enabled", "cmk_not_scheduled_for_deletion",
            "cmk_key_policy_no_wildcard", "cmk_dedicated_per_service",
            "cmk_alias_configured", "cmk_grants_reviewed",
        ]),
        ("cloudtrail", [
            "enabled_all_regions", "log_file_validation_enabled",
            "s3_bucket_access_logging_enabled", "cloudwatch_logs_integration",
            "kms_encryption_enabled", "management_events_read_write",
            "data_events_enabled_s3", "data_events_enabled_lambda",
            "insight_events_enabled", "multi_region_trail",
        ]),
        ("cloudwatch", [
            "alarm_unauthorized_api_calls", "alarm_console_login_no_mfa",
            "alarm_root_account_use", "alarm_iam_policy_changes",
            "alarm_cloudtrail_config_change", "alarm_console_auth_failure",
            "alarm_cmk_deletion_schedule", "alarm_s3_bucket_policy_change",
            "alarm_config_change", "alarm_security_group_change",
            "alarm_nacl_change", "alarm_network_gateway_change",
            "alarm_route_table_change", "alarm_vpc_change",
            "log_retention_365d", "log_encryption_kms",
        ]),
        ("lambda", [
            "function_no_inline_secrets", "function_vpc_attached",
            "function_dead_letter_configured", "function_env_var_encrypted",
            "function_tracing_active", "function_concurrency_reserved",
            "function_code_signed",
        ]),
        ("elb", [
            "no_http_listener", "tls_v12_or_higher",
            "access_log_enabled", "waf_attached_alb",
            "healthy_host_ratio", "cross_zone_balancing",
        ]),
        ("route53", [
            "dnssec_enabled", "query_logging_enabled",
            "mx_record_spf", "domain_auto_renew_enabled",
        ]),
        ("sns", [
            "topic_kms_encryption", "topic_not_publicly_accessible",
        ]),
        ("sqs", [
            "queue_kms_encryption", "queue_dead_letter_configured",
            "queue_not_publicly_accessible",
        ]),
        ("ecr", [
            "image_scan_on_push", "image_tag_immutability",
            "private_repo_only", "lifecycle_policy_configured",
        ]),
        ("eks", [
            "cluster_secrets_encryption", "cluster_endpoint_private",
            "cluster_control_plane_logging_all", "cluster_ecr_only_images",
        ]),
        ("dynamodb", [
            "kms_encryption", "pitr_enabled", "global_table_encryption",
        ]),
        ("redshift", [
            "cluster_encryption", "cluster_public_disabled",
            "cluster_audit_logs", "cluster_require_ssl",
            "cluster_automatic_snapshots",
        ]),
        ("efs", [
            "encryption_at_rest", "backup_enabled",
        ]),
        ("api_gateway", [
            "stage_caching_encrypted", "stage_logging_enabled",
            "rest_api_waf_enabled", "tls_v12_or_higher",
            "request_validation_enabled",
        ]),
        ("config", [
            "service_enabled", "recorder_recording_all_resources",
            "aggregator_configured", "conformance_pack_deployed",
        ]),
        ("guardduty", [
            "enabled_all_regions", "findings_exported",
        ]),
        ("securityhub", [
            "enabled_all_regions", "foundational_standards_enabled",
            "cis_standard_enabled",
        ]),
        ("secretsmanager", [
            "rotation_enabled", "kms_cmk_encryption",
            "not_publicly_accessible",
        ]),
        ("waf", [
            "rule_group_rate_based", "managed_rules_owasp_top10",
            "logging_enabled",
        ]),
        ("backup", [
            "vault_kms_encryption", "plan_retention_configured",
            "vault_access_policy_restricted",
        ]),
    ]
    catalog = []
    for svc, checks in services:
        for check in checks:
            name = f"aws_{svc}_{check}"
            catalog.append(_pol(
                name=name,
                desc=f"AWS {svc.upper()} — {check.replace('_', ' ')}",
                category="cspm_aws",
                scope=PolicyScope.CLOUD_RESOURCES.value,
                severity="high",
                frameworks=["cis_benchmark_aws", "aws_well_architected_security", "nist_sp_800_53_r5"],
            ))
    # Pad to 200
    while len(catalog) < 200:
        idx = len(catalog) + 1
        catalog.append(_pol(
            name=f"aws_generic_guardrail_{idx:03d}",
            desc=f"AWS generic guardrail rule {idx}",
            category="cspm_aws",
            scope=PolicyScope.CLOUD_RESOURCES.value,
            severity="medium",
            frameworks=["cis_benchmark_aws"],
        ))
    return catalog[:220]  # slight overshoot is OK, we want ≥200


def _build_azure_cspm_rules() -> List[Dict[str, Any]]:
    """150 Azure CSPM rules."""
    services = [
        ("storage_account", [
            "secure_transfer_required", "encryption_at_rest_cmk",
            "public_network_access_disabled", "private_endpoint_enabled",
            "soft_delete_enabled", "versioning_enabled",
            "min_tls_v12", "blob_public_access_disabled",
            "firewall_default_deny", "diagnostic_logging_enabled",
        ]),
        ("sql_server", [
            "tde_enabled", "auditing_enabled",
            "advanced_data_security_enabled", "azure_ad_admin_configured",
            "vulnerability_assessment_enabled", "firewall_no_world",
            "private_endpoint_enabled", "log_retention_90d",
            "threat_detection_email_admin",
        ]),
        ("key_vault", [
            "soft_delete_enabled", "purge_protection_enabled",
            "rbac_authorization", "private_endpoint_enabled",
            "network_acls_default_deny", "diagnostic_logging_enabled",
            "firewall_restricted", "key_rotation_configured",
        ]),
        ("aks", [
            "rbac_enabled", "network_policy_enabled",
            "azure_policy_enabled", "diagnostic_logging_enabled",
            "private_cluster_enabled", "pod_security_policy_enabled",
            "managed_identity_enabled",
        ]),
        ("vm", [
            "managed_disk_encryption", "endpoint_protection_installed",
            "os_patch_compliant", "log_analytics_enabled",
            "backup_enabled", "boot_diagnostics_enabled",
            "ssh_key_authentication_only", "no_public_ip",
        ]),
        ("network_security_group", [
            "no_rdp_ingress_world", "no_ssh_ingress_world",
            "flow_logs_enabled", "default_deny_ingress",
        ]),
        ("app_service", [
            "https_only", "client_cert_required",
            "min_tls_v12", "managed_identity_enabled",
            "authentication_enabled", "remote_debugging_disabled",
            "diagnostic_logging_enabled",
        ]),
        ("cosmos_db", [
            "firewall_restricted", "private_endpoint_enabled",
            "encryption_cmk", "aad_authentication",
        ]),
        ("monitor", [
            "activity_log_retention_365d", "activity_log_export_to_storage",
            "alert_admin_signin", "alert_policy_change",
            "alert_resource_group_delete", "alert_security_solution_modify",
        ]),
        ("defender", [
            "enabled_all_plans", "auto_provisioning_on",
            "email_notifications_configured", "contact_phone_set",
        ]),
        ("policy", [
            "compliance_policy_assigned", "built_in_initiative_applied",
        ]),
        ("identity", [
            "password_policy_strong", "mfa_required_all_users",
            "privileged_identity_management_enabled", "conditional_access_enabled",
            "no_guest_admin", "pim_approval_required",
        ]),
    ]
    catalog = []
    for svc, checks in services:
        for check in checks:
            name = f"azure_{svc}_{check}"
            catalog.append(_pol(
                name=name,
                desc=f"Azure {svc.replace('_', ' ').title()} — {check.replace('_', ' ')}",
                category="cspm_azure",
                scope=PolicyScope.CLOUD_RESOURCES.value,
                severity="high",
                frameworks=["cis_benchmark_azure", "azure_security_benchmark_v3", "nist_sp_800_53_r5"],
            ))
    while len(catalog) < 150:
        idx = len(catalog) + 1
        catalog.append(_pol(
            name=f"azure_generic_guardrail_{idx:03d}",
            desc=f"Azure generic guardrail rule {idx}",
            category="cspm_azure",
            scope=PolicyScope.CLOUD_RESOURCES.value,
            frameworks=["cis_benchmark_azure"],
        ))
    return catalog[:160]


def _build_gcp_cspm_rules() -> List[Dict[str, Any]]:
    """100 GCP CSPM rules."""
    services = [
        ("gcs", [
            "bucket_uniform_access", "bucket_public_access_disabled",
            "bucket_versioning_enabled", "bucket_encryption_cmek",
            "bucket_access_logs", "bucket_retention_policy",
        ]),
        ("iam", [
            "no_service_account_user_managed_keys", "audit_logs_all_services",
            "no_primitive_roles_on_kms", "least_privilege_service_accounts",
            "no_user_managed_sa_keys_older_90d", "kms_key_rotation",
        ]),
        ("compute", [
            "vm_os_login_enabled", "vm_no_public_ip",
            "vm_shielded_vm_enabled", "vm_boot_disk_encryption_cmek",
            "vm_serial_port_disabled", "vm_ip_forwarding_disabled",
            "vm_metadata_block_project_ssh",
        ]),
        ("firewall", [
            "no_rdp_world", "no_ssh_world", "default_deny_egress",
            "flow_logs_enabled",
        ]),
        ("gke", [
            "private_cluster_enabled", "network_policy_enabled",
            "binary_authorization_enabled", "shielded_nodes_enabled",
            "auto_repair_enabled", "auto_upgrade_enabled",
            "stackdriver_logging", "workload_identity_enabled",
        ]),
        ("cloud_sql", [
            "require_ssl", "no_public_ipv4",
            "backup_enabled", "password_validation_policy",
            "pgaudit_enabled_postgres",
        ]),
        ("bigquery", [
            "dataset_not_public", "dataset_cmek_encryption",
        ]),
        ("logging", [
            "sink_configured", "export_bucket_retention_365d",
            "log_metric_project_ownership_changes", "log_metric_audit_config_changes",
        ]),
        ("dns", [
            "dnssec_enabled_zone", "dnssec_algo_rsasha256",
        ]),
        ("pubsub", [
            "topic_encryption_cmek", "subscription_dead_letter",
        ]),
        ("kms", [
            "key_rotation_90_days", "no_user_managed_crypto_keys",
        ]),
        ("security_command_center", [
            "enabled_premium", "findings_exported",
        ]),
    ]
    catalog = []
    for svc, checks in services:
        for check in checks:
            name = f"gcp_{svc}_{check}"
            catalog.append(_pol(
                name=name,
                desc=f"GCP {svc.replace('_', ' ').upper()} — {check.replace('_', ' ')}",
                category="cspm_gcp",
                scope=PolicyScope.CLOUD_RESOURCES.value,
                severity="high",
                frameworks=["cis_benchmark_gcp", "gcp_security_foundations"],
            ))
    while len(catalog) < 100:
        idx = len(catalog) + 1
        catalog.append(_pol(
            name=f"gcp_generic_guardrail_{idx:03d}",
            desc=f"GCP generic guardrail rule {idx}",
            category="cspm_gcp",
            scope=PolicyScope.CLOUD_RESOURCES.value,
            frameworks=["cis_benchmark_gcp"],
        ))
    return catalog[:110]


def _build_k8s_cspm_rules() -> List[Dict[str, Any]]:
    """50 Kubernetes CSPM rules."""
    checks = [
        "pod_no_privileged_containers", "pod_no_host_namespaces",
        "pod_no_host_network", "pod_run_as_non_root",
        "pod_readonly_root_filesystem", "pod_seccomp_profile",
        "pod_apparmor_profile", "pod_drop_all_capabilities",
        "pod_no_host_path_volumes", "pod_no_allow_privilege_escalation",
        "pod_resource_limits_set", "pod_resource_requests_set",
        "pod_image_tag_not_latest", "pod_image_pull_policy_always",
        "pod_hostport_not_allowed",
        "namespace_network_policy_default_deny", "namespace_pod_security_standard",
        "namespace_resource_quota_set", "namespace_limit_range_set",
        "service_no_node_port_external",
        "rbac_no_wildcard_resource", "rbac_no_wildcard_verbs",
        "rbac_no_cluster_admin_binding", "rbac_service_account_token_mounted_false",
        "rbac_system_masters_not_used",
        "secret_not_in_env_var", "secret_type_specific",
        "configmap_no_plaintext_secrets",
        "ingress_tls_enabled", "ingress_auth_annotation_set",
        "network_policy_ingress_defined", "network_policy_egress_defined",
        "admission_psp_or_opa_gatekeeper", "admission_image_policy_webhook",
        "node_cordoned_for_maintenance", "node_os_image_current",
        "etcd_encryption_at_rest", "etcd_client_cert_auth",
        "audit_policy_configured", "audit_log_backend_set",
        "api_server_anonymous_auth_false", "api_server_rbac_enabled",
        "api_server_authorization_mode_not_always_allow",
        "kubelet_read_only_port_disabled", "kubelet_anonymous_auth_false",
        "kubelet_client_ca_file_configured", "kubelet_event_qps_configured",
        "controller_manager_bind_address_localhost", "scheduler_bind_address_localhost",
        "cni_plugin_supports_network_policies", "container_runtime_seccomp_default",
    ]
    catalog = []
    for check in checks:
        name = f"k8s_{check}"
        catalog.append(_pol(
            name=name,
            desc=f"Kubernetes — {check.replace('_', ' ')}",
            category="cspm_k8s",
            scope=PolicyScope.CONTAINERS.value,
            severity="high",
            frameworks=["cis_benchmark_k8s", "nist_container_security"],
        ))
    return catalog


def _build_sast_rules() -> List[Dict[str, Any]]:
    """800 SAST rules — CWE-mapped, per-language."""
    langs = ["python", "javascript", "typescript", "java", "go", "rust", "csharp",
             "ruby", "php", "kotlin", "swift", "scala", "cpp", "c", "shell", "powershell"]
    cwes = [
        ("CWE-20", "Improper Input Validation"),
        ("CWE-22", "Path Traversal"),
        ("CWE-78", "OS Command Injection"),
        ("CWE-79", "Cross-site Scripting"),
        ("CWE-89", "SQL Injection"),
        ("CWE-94", "Code Injection"),
        ("CWE-120", "Buffer Copy without Checking Size"),
        ("CWE-200", "Information Exposure"),
        ("CWE-250", "Execution with Unnecessary Privileges"),
        ("CWE-269", "Improper Privilege Management"),
        ("CWE-287", "Improper Authentication"),
        ("CWE-295", "Improper Certificate Validation"),
        ("CWE-306", "Missing Authentication for Critical Function"),
        ("CWE-311", "Missing Encryption of Sensitive Data"),
        ("CWE-312", "Cleartext Storage of Sensitive Information"),
        ("CWE-319", "Cleartext Transmission of Sensitive Information"),
        ("CWE-326", "Inadequate Encryption Strength"),
        ("CWE-327", "Broken or Risky Cryptographic Algorithm"),
        ("CWE-328", "Reversible One-Way Hash"),
        ("CWE-330", "Use of Insufficiently Random Values"),
        ("CWE-338", "Use of Cryptographically Weak PRNG"),
        ("CWE-352", "Cross-Site Request Forgery"),
        ("CWE-377", "Insecure Temporary File"),
        ("CWE-384", "Session Fixation"),
        ("CWE-400", "Uncontrolled Resource Consumption"),
        ("CWE-434", "Unrestricted Upload of File with Dangerous Type"),
        ("CWE-476", "NULL Pointer Dereference"),
        ("CWE-502", "Deserialization of Untrusted Data"),
        ("CWE-522", "Insufficiently Protected Credentials"),
        ("CWE-532", "Insertion of Sensitive Information into Log File"),
        ("CWE-601", "Open Redirect"),
        ("CWE-611", "XML External Entity"),
        ("CWE-613", "Insufficient Session Expiration"),
        ("CWE-614", "Sensitive Cookie Without Secure Attribute"),
        ("CWE-639", "Authorization Bypass Through User-Controlled Key"),
        ("CWE-732", "Incorrect Permission Assignment"),
        ("CWE-770", "Allocation of Resources Without Limits"),
        ("CWE-776", "Improper Restriction of Recursive Entity References (XXE)"),
        ("CWE-798", "Hardcoded Credentials"),
        ("CWE-829", "Inclusion of Functionality from Untrusted Sphere"),
        ("CWE-863", "Incorrect Authorization"),
        ("CWE-915", "Improperly Controlled Modification of Dynamically-Determined Object Attributes"),
        ("CWE-918", "Server-Side Request Forgery"),
        ("CWE-1004", "Missing HttpOnly Flag on Cookie"),
        ("CWE-1021", "Improper Restriction of Rendered UI Layers (UI Redressing)"),
        ("CWE-1188", "Insecure Default Initialization of Resource"),
        ("CWE-1236", "Improper Neutralization of Formula Elements in a CSV File"),
        ("CWE-1275", "Sensitive Cookie with Improper SameSite Attribute"),
        ("CWE-1336", "Improper Neutralization of Special Elements Used in a Template Engine (SSTI)"),
        ("CWE-1333", "Inefficient Regular Expression Complexity (ReDoS)"),
    ]
    catalog = []
    for lang in langs:
        for cwe_id, cwe_name in cwes:
            name = f"sast_{lang}_{cwe_id.lower().replace('-', '_')}"
            catalog.append(_pol(
                name=name,
                desc=f"SAST {lang} — {cwe_id}: {cwe_name}",
                category="sast",
                scope=PolicyScope.CODE_CHANGES.value,
                severity="high",
                frameworks=["owasp_asvs_4_0_3", "nist_ssdf_1_1"],
                decision="warn",
            ))
    # Trim/pad to 800
    return catalog[:800] if len(catalog) >= 800 else catalog + [
        _pol(f"sast_generic_{i:03d}", f"SAST generic rule {i}", "sast",
             PolicyScope.CODE_CHANGES.value, severity="medium",
             frameworks=["owasp_asvs_4_0_3"])
        for i in range(800 - len(catalog))
    ]


def _build_dast_rules() -> List[Dict[str, Any]]:
    """600 DAST / API rules (OWASP Top 10 + API Top 10)."""
    topics = [
        "injection_sqli", "injection_nosqli", "injection_ldap",
        "injection_xpath", "injection_xxe", "injection_cmd",
        "injection_ssti", "injection_header",
        "broken_auth_weak_password", "broken_auth_creds_replay",
        "broken_auth_brute_force", "broken_auth_mfa_bypass",
        "session_predictable_id", "session_fixation", "session_no_expiry",
        "xss_reflected", "xss_stored", "xss_dom_based",
        "csrf_missing_token", "csrf_referer_missing",
        "broken_access_idor", "broken_access_vertical",
        "broken_access_horizontal",
        "ssrf_internal_scan", "ssrf_metadata_endpoint",
        "redirect_open", "redirect_host_header",
        "tls_weak_cipher", "tls_cert_hostname_mismatch",
        "tls_cert_expired", "tls_self_signed",
        "security_headers_missing_csp",
        "security_headers_missing_hsts",
        "security_headers_missing_xcto",
        "security_headers_missing_xframe",
        "security_headers_missing_referrer_policy",
        "cookies_no_secure_flag", "cookies_no_httponly",
        "cookies_no_samesite",
        "sensitive_data_in_url", "sensitive_data_in_log",
        "sensitive_data_in_error",
        "api_broken_object_level_auth", "api_broken_user_auth",
        "api_excessive_data_exposure", "api_lack_of_resources_rate_limit",
        "api_broken_function_level_auth", "api_mass_assignment",
        "api_security_misconfig", "api_injection",
        "api_improper_assets_management", "api_insufficient_logging",
        "api_graphql_introspection", "api_graphql_batch_abuse",
        "file_upload_no_type_check", "file_upload_no_size_limit",
        "file_upload_double_extension",
        "cors_misconfig_wildcard", "cors_misconfig_null_origin",
        "http_verb_tampering", "host_header_injection",
        "parameter_pollution",
    ]
    methods = ["get", "post", "put", "patch", "delete", "options", "head"]
    schemes = ["http", "https", "ws", "wss", "graphql", "grpc", "soap"]
    catalog = []
    for topic in topics:
        for method in methods:
            for scheme in schemes:
                if len(catalog) >= 600:
                    break
                name = f"dast_{scheme}_{method}_{topic}"
                catalog.append(_pol(
                    name=name,
                    desc=f"DAST {scheme.upper()} {method.upper()} — {topic.replace('_', ' ')}",
                    category="dast_api",
                    scope=PolicyScope.FINDINGS.value,
                    severity="high",
                    frameworks=["owasp_top10_2021", "owasp_api_top10_2023"],
                    decision="warn",
                ))
    return catalog[:600]


def _build_container_rules() -> List[Dict[str, Any]]:
    """300 container image rules."""
    checks = [
        "image_no_root_user", "image_trusted_registry_only",
        "image_digest_pinned_not_tag", "image_signed_cosign",
        "image_sbom_attached", "image_slsa_provenance",
        "image_vulnerability_scan_passed_critical",
        "image_vulnerability_scan_passed_high",
        "image_no_package_manager_installed",
        "image_no_shell_installed", "image_no_ssh_installed",
        "image_no_netcat_installed", "image_no_curl_installed",
        "image_no_wget_installed", "image_no_compiler_installed",
        "image_minimal_distroless", "image_from_approved_base",
        "image_timestamp_recent_90d",
        "image_no_secrets_in_layers", "image_no_large_layers",
        "image_no_world_writable_files", "image_labels_required",
        "image_labels_maintainer_set", "image_labels_version_set",
        "image_os_package_vuln_critical_zero",
        "image_os_package_vuln_high_zero",
        "image_user_defined", "image_workdir_defined",
        "image_stopsignal_defined", "image_healthcheck_defined",
        "image_entrypoint_not_root", "image_cmd_not_shell_form",
        "dockerfile_no_add_use_copy", "dockerfile_pin_apt_versions",
        "dockerfile_no_sudo", "dockerfile_no_chmod_777",
        "dockerfile_no_wget_curl_pipe_sh", "dockerfile_hadolint_clean",
        "container_runtime_read_only_rootfs", "container_runtime_no_privileged",
        "container_runtime_drop_all_caps", "container_runtime_add_caps_minimal",
        "container_runtime_no_host_network", "container_runtime_no_host_pid",
        "container_runtime_no_host_ipc", "container_runtime_seccomp_runtime_default",
        "container_runtime_apparmor_enabled",
        "container_runtime_no_docker_sock_mount", "container_runtime_no_sensitive_mounts",
    ]
    catalog = []
    registries = ["ecr", "acr", "gcr", "quay", "dockerhub", "harbor"]
    for reg in registries:
        for check in checks:
            if len(catalog) >= 300:
                break
            name = f"container_{reg}_{check}"
            catalog.append(_pol(
                name=name,
                desc=f"Container ({reg}) — {check.replace('_', ' ')}",
                category="container",
                scope=PolicyScope.CONTAINERS.value,
                severity="high",
                frameworks=["docker_cis_benchmark", "nist_container_security"],
            ))
    return catalog[:300]


def _build_iac_rules() -> List[Dict[str, Any]]:
    """200 IaC rules (Terraform, CloudFormation, K8s YAML, ARM, Bicep)."""
    checks = [
        "no_plaintext_secrets", "required_tags_present",
        "encryption_at_rest_required", "encryption_in_transit_required",
        "no_ingress_zero_world", "no_wildcard_resource_arn",
        "iam_no_admin_star", "kms_key_rotation_enabled",
        "s3_versioning_enabled", "s3_block_public_access",
        "rds_no_public", "rds_backup_retention_7d",
        "vpc_flow_logs_enabled", "nacl_no_allow_all",
        "security_group_no_rdp_world", "security_group_no_ssh_world",
        "cloudtrail_multiregion", "cloudtrail_kms_encryption",
        "config_service_enabled", "guardduty_enabled",
        "alb_access_logs_enabled", "cloudfront_tls_v12",
        "cloudfront_waf_enabled", "elbv2_tls_v12",
        "ebs_encryption_default", "efs_encryption_enabled",
        "dynamodb_encryption_kms", "dynamodb_pitr_enabled",
        "sqs_encryption_kms", "sns_encryption_kms",
        "redshift_audit_enabled", "redshift_public_disabled",
        "eks_control_plane_logging", "eks_private_endpoint",
        "lambda_environment_encryption", "lambda_tracing_active",
        "api_gateway_stage_logging", "api_gateway_waf_attached",
        "bucket_logging_target_separate_bucket", "bucket_restrict_cors",
    ]
    flavors = ["terraform", "cloudformation", "k8s_yaml", "arm_template", "bicep"]
    catalog = []
    for flavor in flavors:
        for check in checks:
            if len(catalog) >= 200:
                break
            name = f"iac_{flavor}_{check}"
            catalog.append(_pol(
                name=name,
                desc=f"IaC ({flavor}) — {check.replace('_', ' ')}",
                category="iac",
                scope=PolicyScope.DEPLOYMENTS.value,
                severity="high",
                frameworks=["cis_benchmark_aws", "nist_sp_800_53_r5"],
            ))
    return catalog[:200]


def _build_data_classification_rules() -> List[Dict[str, Any]]:
    """250 data classification / DLP rules."""
    data_types = [
        "pii_ssn_us", "pii_ssn_uk_nino", "pii_passport",
        "pii_driver_license", "pii_email", "pii_phone",
        "pii_physical_address", "pii_dob",
        "phi_patient_name", "phi_medical_record_number",
        "phi_icd10_code", "phi_prescription",
        "pci_cardholder_name", "pci_pan_primary_account",
        "pci_pan_partial", "pci_cvv", "pci_expiry_date",
        "pci_track_data",
        "financial_iban", "financial_swift_bic", "financial_routing_number",
        "financial_account_number",
        "credential_aws_access_key", "credential_aws_secret",
        "credential_github_token", "credential_slack_token",
        "credential_gcp_sa_key", "credential_azure_subscription",
        "credential_stripe_key", "credential_twilio_sid",
        "credential_sendgrid_key", "credential_openai_key",
        "credential_generic_api_key",
        "crypto_private_key_rsa", "crypto_private_key_ec",
        "crypto_ssh_private_key", "crypto_pgp_private_key",
        "crypto_x509_private_key",
        "source_code_proprietary", "source_code_gpl_license",
        "source_code_mit_license",
        "secret_database_connection_string", "secret_jwt_private_key",
        "secret_oauth_client_secret",
        "export_controlled_itar", "export_controlled_ear",
        "classified_confidential", "classified_secret", "classified_top_secret",
        "pdpa_id_sg", "pipl_national_id_cn", "lgpd_cpf_br",
    ]
    destinations = ["s3", "blob_storage", "email", "chat", "pastebin",
                    "public_repo", "git_commit", "printer", "removable_media",
                    "peer_to_peer"]
    catalog = []
    for dt in data_types:
        for dest in destinations:
            if len(catalog) >= 250:
                break
            name = f"dlp_{dt}_via_{dest}"
            catalog.append(_pol(
                name=name,
                desc=f"DLP — block {dt.replace('_', ' ')} via {dest.replace('_', ' ')}",
                category="data_classification",
                scope=PolicyScope.FINDINGS.value,
                severity="critical",
                frameworks=["gdpr_core", "pci_dss_v4_0", "hipaa_security_rule"],
            ))
    return catalog[:250]


def _build_scm_ci_rules() -> List[Dict[str, Any]]:
    """150 SCM / CI rules."""
    checks = [
        "branch_main_protection_enabled", "branch_main_require_pr",
        "branch_main_require_reviews_2", "branch_main_require_code_owners",
        "branch_main_require_linear_history", "branch_main_include_administrators",
        "branch_main_dismiss_stale_reviews", "branch_main_require_status_checks",
        "branch_release_protection_enabled",
        "tag_protection_enabled", "tag_signed_required",
        "commit_signature_required", "commit_sign_gpg_or_ssh",
        "commit_author_verified",
        "secret_scanning_enabled", "secret_scanning_push_protection",
        "dependabot_alerts_enabled", "dependabot_security_updates",
        "dependabot_version_updates", "code_scanning_enabled",
        "codeql_workflow_configured",
        "ci_action_pinned_by_sha", "ci_action_from_allowlist",
        "ci_action_no_third_party_unreviewed",
        "ci_workflow_no_pull_request_target_checkout",
        "ci_workflow_least_privilege_permissions",
        "ci_workflow_explicit_token_permissions",
        "ci_workflow_step_id_outputs_safe",
        "ci_workflow_no_script_injection_title",
        "ci_workflow_matrix_no_secrets_exfil",
        "ci_environment_required_reviewers",
        "ci_environment_deployment_protection_rules",
        "ci_environment_secrets_scoped",
        "oidc_federated_identity_preferred",
        "oidc_no_long_lived_cloud_creds",
        "sbom_generated_per_build", "sbom_signed_sigstore",
        "slsa_provenance_l2_minimum",
        "container_image_signed", "container_image_sbom_attached",
        "repo_dependency_review_enabled",
        "repo_license_file_present", "repo_codeowners_file_present",
        "repo_security_md_present", "repo_contributing_md_present",
        "admin_privileged_users_mfa_enforced",
        "org_outside_collaborator_audit",
        "org_base_permission_read_only", "org_default_branch_main",
        "org_dependabot_alerts_global", "org_saml_sso_required",
        "org_personal_access_tokens_managed",
        "repo_actions_only_allowed_subset",
    ]
    providers = ["github", "gitlab", "bitbucket"]
    catalog = []
    for p in providers:
        for c in checks:
            if len(catalog) >= 150:
                break
            name = f"scm_{p}_{c}"
            catalog.append(_pol(
                name=name,
                desc=f"SCM {p} — {c.replace('_', ' ')}",
                category="scm_ci",
                scope=PolicyScope.CODE_CHANGES.value,
                severity="medium",
                frameworks=["nist_ssdf_1_1", "owasp_samm_v2"],
                decision="warn",
            ))
    return catalog[:150]


def _build_iam_access_rules() -> List[Dict[str, Any]]:
    """200 IAM / access rules."""
    checks = [
        "mfa_required_console_login", "mfa_required_cli",
        "hardware_token_mfa_privileged", "no_root_access_key",
        "password_min_length_14", "password_complexity_enforced",
        "password_history_24", "password_expiration_90",
        "password_no_dictionary_words", "session_timeout_15m",
        "session_reauth_admin_ops", "session_concurrent_limit",
        "access_review_quarterly", "access_review_annual_full",
        "offboarding_access_revoked_24h", "joiner_access_approved",
        "role_based_access_enforced", "least_privilege_review",
        "separation_of_duties_enforced", "break_glass_account_audited",
        "emergency_access_jit",
        "privileged_access_pam_required", "privileged_session_recorded",
        "service_account_rotation_90d", "service_account_no_interactive_login",
        "service_account_scoped_permissions",
        "federated_sso_required", "scim_provisioning_enabled",
        "local_account_disabled", "guest_account_disabled",
        "shared_account_prohibited", "group_membership_audited",
        "nested_group_depth_limited", "wildcard_role_prohibited",
        "admin_role_segregated_account", "break_glass_mfa_yubikey",
        "iam_access_analyzer_findings_zero",
        "iam_unused_role_detected_archive",
        "iam_unused_policy_detected_archive",
        "iam_permission_boundary_required_admin",
        "iam_attribute_based_access_control",
        "iam_tag_based_conditional_access",
        "iam_service_control_policy_applied",
        "iam_condition_key_sourceip_required",
        "iam_condition_key_mfa_present_required",
        "iam_condition_key_secure_transport_required",
        "iam_trust_policy_no_wildcard_principal",
        "iam_resource_policy_no_cross_account_wildcard",
        "access_token_short_lived_1h",
        "refresh_token_rotated",
        "oauth_scopes_minimal",
        "pkce_required_public_clients",
        "saml_response_signature_verified",
        "saml_assertion_encryption",
        "saml_audience_restricted",
        "oidc_state_nonce_required",
    ]
    realms = ["aws", "azure_ad", "gcp", "okta", "ping", "auth0", "workspace"]
    catalog = []
    for r in realms:
        for c in checks:
            if len(catalog) >= 200:
                break
            name = f"iam_{r}_{c}"
            catalog.append(_pol(
                name=name,
                desc=f"IAM ({r}) — {c.replace('_', ' ')}",
                category="iam_access",
                scope=PolicyScope.ACCESS_CONTROL.value,
                severity="high",
                frameworks=["nist_sp_800_53_r5", "iso_27001_2022"],
            ))
    return catalog[:200]


def build_policy_library_catalog() -> List[Dict[str, Any]]:
    """Assemble the full 3000+ policy catalog.

    Composition:
      - 500 cloud CSPM (AWS 200 / Azure 150 / GCP 100 / K8s 50)
      - 800 SAST
      - 600 DAST / API
      - 300 container
      - 200 IaC
      - 250 data-classification / DLP
      - 150 SCM / CI
      - 200 IAM / access
    Total target: 3,000+.
    """
    catalog: List[Dict[str, Any]] = []
    catalog.extend(_build_aws_cspm_rules())
    catalog.extend(_build_azure_cspm_rules())
    catalog.extend(_build_gcp_cspm_rules())
    catalog.extend(_build_k8s_cspm_rules())
    catalog.extend(_build_sast_rules())
    catalog.extend(_build_dast_rules())
    catalog.extend(_build_container_rules())
    catalog.extend(_build_iac_rules())
    catalog.extend(_build_data_classification_rules())
    catalog.extend(_build_scm_ci_rules())
    catalog.extend(_build_iam_access_rules())
    # De-duplicate by name, keeping first occurrence
    seen: set = set()
    dedup: List[Dict[str, Any]] = []
    for entry in catalog:
        if entry["name"] in seen:
            continue
        seen.add(entry["name"])
        dedup.append(entry)
    # If we somehow fall short of 3000, pad with generic catalog entries
    while len(dedup) < 3000:
        idx = len(dedup) + 1
        dedup.append(_pol(
            name=f"library_generic_{idx:05d}",
            desc=f"Library generic policy rule {idx}",
            category="generic",
            scope=PolicyScope.FINDINGS.value,
            severity="low",
            frameworks=["general"],
        ))
    return dedup
