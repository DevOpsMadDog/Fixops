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

CREATE INDEX IF NOT EXISTS idx_policies_org_scope ON policies(org_id, scope);
CREATE INDEX IF NOT EXISTS idx_evaluations_org    ON evaluations(org_id);
CREATE INDEX IF NOT EXISTS idx_evaluations_policy ON evaluations(policy_id);
"""


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
