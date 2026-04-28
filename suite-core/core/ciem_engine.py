"""Cloud Infrastructure Entitlement Management (CIEM) Engine.

Analyzes cloud IAM configurations to detect:
1. Over-privileged roles (wildcard policies, admin access)
2. Unused permissions (permissions never exercised)
3. Toxic combinations (e.g., write + delete + no logging)
4. Privilege escalation paths (chains of roles that lead to admin)
5. Cross-account trust abuse
6. Public access policies
"""

from __future__ import annotations

import logging
import sqlite3
import uuid
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from pydantic import BaseModel, Field

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus
except ImportError:
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

# AWS actions that allow privilege escalation when combined
_ESCALATION_ACTIONS: Set[str] = {
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:AttachRolePolicy",
    "iam:AttachUserPolicy",
    "iam:AttachGroupPolicy",
    "iam:PutRolePolicy",
    "iam:PutUserPolicy",
    "iam:PutGroupPolicy",
    "iam:CreateAccessKey",
    "iam:UpdateAssumeRolePolicy",
    "iam:PassRole",
    "sts:AssumeRole",
    "iam:AddUserToGroup",
    "iam:CreateLoginProfile",
    "iam:UpdateLoginProfile",
    "lambda:UpdateFunctionCode",
    "lambda:InvokeFunction",
    "ec2:RunInstances",
}

# Sensitive actions that combined with Resource=* become high-risk
_SENSITIVE_ACTIONS: Set[str] = {
    "s3:GetObject",
    "s3:PutObject",
    "s3:DeleteObject",
    "s3:ListBucket",
    "s3:GetBucketAcl",
    "s3:PutBucketAcl",
    "secretsmanager:GetSecretValue",
    "kms:Decrypt",
    "kms:Encrypt",
    "ssm:GetParameter",
    "ssm:GetParameters",
    "dynamodb:GetItem",
    "dynamodb:PutItem",
    "dynamodb:DeleteItem",
    "rds:DescribeDBInstances",
    "ec2:DescribeInstances",
}

# Toxic combinations: if a principal has all actions in a set it is flagged
_TOXIC_COMBOS: List[Dict[str, Any]] = [
    {
        "name": "s3_write_delete_no_logging",
        "required_actions": {"s3:PutObject", "s3:DeleteObject"},
        "blocked_actions": {"s3:PutBucketLogging"},
        "explanation": "Principal can write and delete S3 objects but cannot enable logging — data exfiltration/destruction with no audit trail.",
    },
    {
        "name": "iam_create_attach",
        "required_actions": {"iam:CreatePolicyVersion", "iam:AttachRolePolicy"},
        "blocked_actions": set(),
        "explanation": "Principal can create new policy versions AND attach policies — direct privilege escalation path.",
    },
    {
        "name": "secrets_and_ec2_run",
        "required_actions": {"secretsmanager:GetSecretValue", "ec2:RunInstances"},
        "blocked_actions": set(),
        "explanation": "Principal can read secrets and launch EC2 instances — credential harvesting combined with lateral movement.",
    },
    {
        "name": "kms_decrypt_s3_read",
        "required_actions": {"kms:Decrypt", "s3:GetObject"},
        "blocked_actions": set(),
        "explanation": "Principal can decrypt KMS keys and read S3 objects — encrypted data exfiltration possible.",
    },
]

# Azure built-in admin roles
_AZURE_ADMIN_ROLES: Set[str] = {
    "8e3af657-a8ff-443c-a75c-2fe8c4bcb635",  # Owner
    "b24988ac-6180-42a0-ab88-20f7382dd24c",  # Contributor
    "18d7d88d-d35e-4fb5-a5c3-7773c20a72d9",  # User Access Administrator
}

_AZURE_ADMIN_ROLE_NAMES: Set[str] = {
    "Owner",
    "Contributor",
    "User Access Administrator",
    "Global Administrator",
}


# ---------------------------------------------------------------------------
# Enums & Models
# ---------------------------------------------------------------------------


class RiskType(str, Enum):
    wildcard_permission = "wildcard_permission"
    admin_access = "admin_access"
    privilege_escalation = "privilege_escalation"
    cross_account_trust = "cross_account_trust"
    public_resource = "public_resource"
    unused_permission = "unused_permission"
    toxic_combination = "toxic_combination"


class EntitlementRisk(BaseModel):
    """A single entitlement risk finding."""

    id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    severity: str  # critical, high, medium, low
    type: RiskType
    principal: str
    permission: str
    resource: str
    explanation: str
    remediation: str
    detected_at: str = Field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "severity": self.severity,
            "type": self.type.value,
            "principal": self.principal,
            "permission": self.permission,
            "resource": self.resource,
            "explanation": self.explanation,
            "remediation": self.remediation,
            "detected_at": self.detected_at,
        }


# ---------------------------------------------------------------------------
# CIEM Engine
# ---------------------------------------------------------------------------


class CIEMEngine:
    """
    Cloud Infrastructure Entitlement Management engine.

    Accepts IAM policy JSON (no cloud SDK required) and returns
    EntitlementRisk findings.  Results are persisted to SQLite at
    .fixops_data/ciem.db.
    """

    def __init__(self, db_path: str = ".fixops_data/ciem.db") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_tables()

    # ------------------------------------------------------------------
    # DB helpers
    # ------------------------------------------------------------------

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        return conn

    def _init_tables(self) -> None:
        conn = self._connect()
        try:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS ciem_risks (
                    id TEXT PRIMARY KEY,
                    severity TEXT NOT NULL,
                    type TEXT NOT NULL,
                    principal TEXT NOT NULL,
                    permission TEXT NOT NULL,
                    resource TEXT NOT NULL,
                    explanation TEXT NOT NULL,
                    remediation TEXT NOT NULL,
                    detected_at TEXT NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_ciem_principal
                    ON ciem_risks(principal);
                CREATE INDEX IF NOT EXISTS idx_ciem_type
                    ON ciem_risks(type);
                CREATE INDEX IF NOT EXISTS idx_ciem_severity
                    ON ciem_risks(severity);
                CREATE INDEX IF NOT EXISTS idx_ciem_detected_at
                    ON ciem_risks(detected_at);
                """
            )
            conn.commit()
        finally:
            conn.close()

    def _persist_risks(self, risks: List[EntitlementRisk]) -> None:
        if not risks:
            return
        conn = self._connect()
        try:
            conn.executemany(
                """
                INSERT OR REPLACE INTO ciem_risks
                    (id, severity, type, principal, permission, resource,
                     explanation, remediation, detected_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        r.id,
                        r.severity,
                        r.type.value,
                        r.principal,
                        r.permission,
                        r.resource,
                        r.explanation,
                        r.remediation,
                        r.detected_at,
                    )
                    for r in risks
                ],
            )
            conn.commit()
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Internal AWS helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _normalise_actions(actions: Any) -> List[str]:
        """Return a flat list of action strings from an Action field value."""
        if isinstance(actions, str):
            return [actions]
        if isinstance(actions, list):
            return actions
        return []

    @staticmethod
    def _normalise_resources(resources: Any) -> List[str]:
        """Return a flat list of resource strings from a Resource field value."""
        if isinstance(resources, str):
            return [resources]
        if isinstance(resources, list):
            return resources
        return []

    def _collect_all_actions(self, policy_json: dict) -> Set[str]:
        """Collect all Allow-effect actions from a policy."""
        actions: Set[str] = set()
        for stmt in policy_json.get("Statement", []):
            if stmt.get("Effect", "Allow") != "Allow":
                continue
            actions.update(self._normalise_actions(stmt.get("Action", [])))
        return actions

    # ------------------------------------------------------------------
    # AWS IAM analysis
    # ------------------------------------------------------------------

    def analyze_aws_iam_policy(
        self, policy_json: dict, principal: str
    ) -> List[EntitlementRisk]:
        """
        Analyse a single AWS IAM policy document and return risks.

        policy_json: parsed AWS IAM policy dict (Version + Statement list).
        principal:   the IAM entity (user/role/group ARN or name) the policy is attached to.
        """
        risks: List[EntitlementRisk] = []
        statements = policy_json.get("Statement", [])

        for stmt in statements:
            effect = stmt.get("Effect", "Allow")
            if effect != "Allow":
                continue

            raw_actions = stmt.get("Action", [])
            raw_resources = stmt.get("Resource", [])
            conditions = stmt.get("Condition", {})

            actions = self._normalise_actions(raw_actions)
            resources = self._normalise_resources(raw_resources)

            # ── Wildcard action ─────────────────────────────────────────────
            if "*" in actions:
                risks.append(
                    EntitlementRisk(
                        severity="critical",
                        type=RiskType.wildcard_permission,
                        principal=principal,
                        permission="*",
                        resource=", ".join(resources) or "*",
                        explanation=(
                            "Policy grants Action=* which allows every AWS operation, "
                            "including destructive and administrative actions."
                        ),
                        remediation=(
                            "Replace Action=* with an explicit allow-list of only the "
                            "actions this principal actually needs."
                        ),
                    )
                )

            # ── Admin access (Action=* + Resource=*) ────────────────────────
            if "*" in actions and "*" in resources:
                risks.append(
                    EntitlementRisk(
                        severity="critical",
                        type=RiskType.admin_access,
                        principal=principal,
                        permission="*",
                        resource="*",
                        explanation=(
                            "Action=* combined with Resource=* is equivalent to "
                            "AdministratorAccess — full control over the entire AWS account."
                        ),
                        remediation=(
                            "Remove this statement. Apply least-privilege policies scoped "
                            "to specific actions and resources."
                        ),
                    )
                )

            # ── sts:AssumeRole without conditions ───────────────────────────
            if "sts:AssumeRole" in actions and not conditions:
                risks.append(
                    EntitlementRisk(
                        severity="high",
                        type=RiskType.cross_account_trust,
                        principal=principal,
                        permission="sts:AssumeRole",
                        resource=", ".join(resources) or "*",
                        explanation=(
                            "sts:AssumeRole is allowed without any conditions (e.g., "
                            "aws:PrincipalOrgID, MFA, IP). Any entity with this policy "
                            "can assume the target role(s) without restriction."
                        ),
                        remediation=(
                            "Add Condition blocks to restrict sts:AssumeRole — require "
                            "MFA (aws:MultiFactorAuthPresent), limit to org "
                            "(aws:PrincipalOrgID), or restrict source IP."
                        ),
                    )
                )

            # ── Privilege-escalation actions ─────────────────────────────────
            for action in actions:
                if action in _ESCALATION_ACTIONS and action != "sts:AssumeRole":
                    risks.append(
                        EntitlementRisk(
                            severity="high",
                            type=RiskType.privilege_escalation,
                            principal=principal,
                            permission=action,
                            resource=", ".join(resources) or "*",
                            explanation=(
                                f"Action '{action}' can be used to escalate privileges "
                                "by modifying IAM policies, attaching higher-privilege "
                                "roles, or gaining access to compute execution environments."
                            ),
                            remediation=(
                                f"Remove '{action}' unless this principal is an IAM "
                                "administrator. If required, scope to specific resources "
                                "and require MFA via Condition."
                            ),
                        )
                    )

            # ── Public/sensitive resource exposure ──────────────────────────
            if "*" in resources:
                for action in actions:
                    if action in _SENSITIVE_ACTIONS:
                        risks.append(
                            EntitlementRisk(
                                severity="high",
                                type=RiskType.public_resource,
                                principal=principal,
                                permission=action,
                                resource="*",
                                explanation=(
                                    f"Sensitive action '{action}' is allowed on "
                                    "Resource=* — applies to ALL resources in the account, "
                                    "including any that become public or are shared."
                                ),
                                remediation=(
                                    f"Scope '{action}' to specific resource ARNs "
                                    "rather than wildcard."
                                ),
                            )
                        )

        # ── Toxic combinations (whole-policy check) ──────────────────────
        all_actions = self._collect_all_actions(policy_json)
        risks.extend(self._detect_toxic_combos(all_actions, principal))

        self._persist_risks(risks)
        return risks

    # ------------------------------------------------------------------
    # Azure role analysis
    # ------------------------------------------------------------------

    def analyze_azure_role_assignment(
        self, role_def: dict, principal: str
    ) -> List[EntitlementRisk]:
        """
        Analyse an Azure role definition or assignment.

        role_def should contain at least one of:
          - roleDefinitionId / id  (GUID matched against known admin roles)
          - roleName / properties.roleName  (string matched against admin role names)
          - permissions  (list of permission objects with actions/notActions)
        principal: Azure object ID, UPN, or display name.
        """
        risks: List[EntitlementRisk] = []

        # Resolve role name/id
        role_id = role_def.get("roleDefinitionId") or role_def.get("id", "")
        role_name = (
            role_def.get("roleName")
            or role_def.get("properties", {}).get("roleName", "")
            or role_def.get("name", "")
        )

        # Strip GUID suffix from fully-qualified roleDefinitionId
        if "/" in role_id:
            role_id = role_id.split("/")[-1]

        is_admin_by_id = role_id in _AZURE_ADMIN_ROLES
        is_admin_by_name = role_name in _AZURE_ADMIN_ROLE_NAMES

        if is_admin_by_id or is_admin_by_name:
            risks.append(
                EntitlementRisk(
                    severity="critical",
                    type=RiskType.admin_access,
                    principal=principal,
                    permission=role_name or role_id,
                    resource="subscription/*",
                    explanation=(
                        f"Principal is assigned the Azure built-in role '{role_name or role_id}' "
                        "which grants broad administrative access to the subscription or resource group."
                    ),
                    remediation=(
                        "Replace with a custom role granting only required actions. "
                        "Apply at the narrowest scope (resource group, not subscription)."
                    ),
                )
            )

        # Check permissions array for wildcard actions
        for perm in role_def.get("permissions", []):
            raw_actions = perm.get("actions", [])
            if "*" in raw_actions or "*/read" in raw_actions or "*/write" in raw_actions:
                risks.append(
                    EntitlementRisk(
                        severity="high",
                        type=RiskType.wildcard_permission,
                        principal=principal,
                        permission=", ".join(raw_actions),
                        resource="*",
                        explanation=(
                            "Azure role permission contains a wildcard action ('*' or '*/...') "
                            "which grants access to all resource types or all operations."
                        ),
                        remediation=(
                            "List only the explicit Microsoft.* provider actions this role "
                            "requires. Avoid wildcard actions."
                        ),
                    )
                )

            # Check for Microsoft.Authorization/* (role assignment = escalation)
            for action in raw_actions:
                if "microsoft.authorization" in action.lower() and (
                    action.endswith("/*") or "roleassignments" in action.lower()
                ):
                    risks.append(
                        EntitlementRisk(
                            severity="high",
                            type=RiskType.privilege_escalation,
                            principal=principal,
                            permission=action,
                            resource="*",
                            explanation=(
                                f"Action '{action}' allows the principal to modify role "
                                "assignments — a direct privilege escalation vector."
                            ),
                            remediation=(
                                "Remove Microsoft.Authorization/roleAssignments/* unless "
                                "this is an intentional owner/UAA role."
                            ),
                        )
                    )

        self._persist_risks(risks)
        return risks

    # ------------------------------------------------------------------
    # Privilege escalation path detection
    # ------------------------------------------------------------------

    def detect_privilege_escalation_paths(
        self, policies: List[dict]
    ) -> List[EntitlementRisk]:
        """
        Scan a list of policy dicts (each with 'principal' and 'policy' keys)
        and find chains of permissions that lead to full admin access.

        Each entry: {"principal": str, "policy": <AWS IAM policy dict>}
        """
        risks: List[EntitlementRisk] = []

        # Map principal -> set of allowed actions
        principal_actions: Dict[str, Set[str]] = {}
        for entry in policies:
            principal = entry.get("principal", "unknown")
            policy = entry.get("policy", {})
            if principal not in principal_actions:
                principal_actions[principal] = set()
            principal_actions[principal].update(self._collect_all_actions(policy))

        for principal, actions in principal_actions.items():
            escalation_held = actions & _ESCALATION_ACTIONS
            if not escalation_held:
                continue

            # Check if chain can reach admin: has iam:AttachRolePolicy + iam:CreatePolicyVersion
            # OR iam:PassRole + high-privilege compute actions
            can_attach = bool(
                {"iam:AttachRolePolicy", "iam:PutRolePolicy"} & actions
            )
            can_create_policy = bool(
                {"iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"} & actions
            )
            can_pass_role = "iam:PassRole" in actions
            has_compute = bool({"ec2:RunInstances", "lambda:InvokeFunction"} & actions)

            if can_attach and can_create_policy:
                risks.append(
                    EntitlementRisk(
                        severity="critical",
                        type=RiskType.privilege_escalation,
                        principal=principal,
                        permission=", ".join(sorted(escalation_held)),
                        resource="*",
                        explanation=(
                            "Principal holds both iam:CreatePolicyVersion (or SetDefaultPolicyVersion) "
                            "AND iam:AttachRolePolicy — a well-known privilege escalation path: "
                            "create a new policy version granting AdministratorAccess and attach it "
                            "to any role."
                        ),
                        remediation=(
                            "Remove iam:CreatePolicyVersion, iam:SetDefaultPolicyVersion, and "
                            "iam:AttachRolePolicy from this principal unless they are an intentional "
                            "IAM administrator. Add an SCP to restrict these actions."
                        ),
                    )
                )

            if can_pass_role and has_compute:
                risks.append(
                    EntitlementRisk(
                        severity="high",
                        type=RiskType.privilege_escalation,
                        principal=principal,
                        permission="iam:PassRole + compute",
                        resource="*",
                        explanation=(
                            "Principal can pass a role (iam:PassRole) to a compute service "
                            "(EC2/Lambda) and invoke it — classic PassRole escalation: attach "
                            "an admin role to a new EC2 instance or Lambda function."
                        ),
                        remediation=(
                            "Scope iam:PassRole to specific role ARNs via a Condition "
                            "(iam:PassedToService). Restrict compute launch permissions."
                        ),
                    )
                )

        self._persist_risks(risks)
        return risks

    # ------------------------------------------------------------------
    # Toxic combinations
    # ------------------------------------------------------------------

    def _detect_toxic_combos(
        self, all_actions: Set[str], principal: str
    ) -> List[EntitlementRisk]:
        risks: List[EntitlementRisk] = []
        for combo in _TOXIC_COMBOS:
            required: Set[str] = combo["required_actions"]
            blocked: Set[str] = combo["blocked_actions"]
            has_required = required.issubset(all_actions)
            missing_blocked = not blocked or not (blocked & all_actions)
            if has_required and missing_blocked:
                risks.append(
                    EntitlementRisk(
                        severity="high",
                        type=RiskType.toxic_combination,
                        principal=principal,
                        permission=", ".join(sorted(required)),
                        resource="*",
                        explanation=combo["explanation"],
                        remediation=(
                            f"Separate these permissions across different roles following "
                            f"separation-of-duties principles. Toxic combo: {combo['name']}."
                        ),
                    )
                )
        return risks

    # ------------------------------------------------------------------
    # Least-privilege suggestion
    # ------------------------------------------------------------------

    # ------------------------------------------------------------------
    # Identity-scoped least privilege (GAP-032: MERGE CIEM+AD)
    # ------------------------------------------------------------------

    def recommend_least_privilege(
        self,
        org_id: str,
        identity_id: str,
        current_permissions: Optional[List[str]] = None,
        used_permissions: Optional[List[str]] = None,
        usage_log: Optional[List[Dict[str, Any]]] = None,
        window_days: int = 90,
    ) -> Dict[str, Any]:
        """Identity-scoped least-privilege recommendation.

        Returns a dict with:
          - identity_id, org_id, analysed_at, window_days
          - current_permissions:  full set declared on the identity
          - used_permissions:     set exercised within the window
          - unused_permissions:   declared but never used (revoke)
          - right_sized_policy:   AWS IAM-style policy JSON limited to used
          - reduction_pct:        percentage of permissions removed

        Inputs accept either explicit used_permissions OR a usage_log
        of {"action": ..., "timestamp": ...} rows from which actions in
        the last `window_days` are extracted.
        """
        if not identity_id:
            raise ValueError("identity_id is required")
        if not org_id:
            raise ValueError("org_id is required")

        current = set(current_permissions or [])

        used: Set[str] = set()
        if used_permissions:
            used.update(used_permissions)

        # Derive used permissions from a usage log (if provided)
        if usage_log:
            cutoff = datetime.now(timezone.utc).timestamp() - (
                window_days * 86400
            )
            for entry in usage_log:
                action = entry.get("action") or entry.get("permission")
                ts_str = entry.get("timestamp") or entry.get("ts")
                if not action:
                    continue
                if ts_str:
                    try:
                        ts = datetime.fromisoformat(
                            str(ts_str).replace("Z", "+00:00")
                        ).timestamp()
                        if ts < cutoff:
                            continue
                    except ValueError:
                        # Unparseable timestamp — keep the action rather than drop silently
                        pass
                used.add(action)

        # Trim used to actions the identity actually holds (no grants-by-inference)
        used_scoped = {a for a in used if a in current} if current else used
        unused = sorted(current - used_scoped)

        # Right-sized policy document — one Allow statement per action
        right_sized_policy = {
            "Version": "2012-10-17",
            "Statement": (
                [
                    {
                        "Sid": "LeastPrivilegeRecommended",
                        "Effect": "Allow",
                        "Action": sorted(used_scoped),
                        "Resource": "*",
                        "_ciem_note": (
                            "Scope Resource=* to specific ARNs before deploying."
                        ),
                    }
                ]
                if used_scoped
                else []
            ),
        }

        total = len(current) if current else max(len(used_scoped), 1)
        reduction_pct = (
            round(((total - len(used_scoped)) / total) * 100, 1) if total else 0.0
        )

        result = {
            "identity_id": identity_id,
            "org_id": org_id,
            "analysed_at": datetime.now(timezone.utc).isoformat(),
            "window_days": window_days,
            "current_permissions": sorted(current),
            "used_permissions": sorted(used_scoped),
            "unused_permissions": unused,
            "right_sized_policy": right_sized_policy,
            "reduction_pct": reduction_pct,
        }

        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus and getattr(bus, "enabled", False):
                    bus.emit(
                        "IDENTITY_UPDATED",
                        {
                            "entity_type": "ciem_least_privilege",
                            "entity_id": identity_id,
                            "org_id": org_id,
                            "source_engine": "ciem_engine",
                        },
                    )
            except Exception:
                pass

        return result

    def suggest_least_privilege(
        self, policy_json: dict, used_permissions: List[str]
    ) -> dict:
        """
        Return a trimmed policy that contains only the permissions in
        used_permissions, removing unused and wildcard grants.

        policy_json:       original AWS IAM policy dict.
        used_permissions:  list of actions actually observed in CloudTrail / usage logs.
        """
        used_set = set(used_permissions)
        new_statements = []

        for stmt in policy_json.get("Statement", []):
            if stmt.get("Effect", "Allow") != "Allow":
                # Keep Deny statements as-is — removing a Deny is risky
                new_statements.append(stmt)
                continue

            actions = self._normalise_actions(stmt.get("Action", []))
            resources = self._normalise_resources(stmt.get("Resource", []))

            # Expand wildcards to only the used permissions that match
            if "*" in actions:
                trimmed = sorted(used_set)
            else:
                trimmed = sorted(a for a in actions if a in used_set)

            if not trimmed:
                # No used permissions in this statement — drop it
                continue

            new_stmt = dict(stmt)
            new_stmt["Action"] = trimmed

            # If resource is wildcard and we have specific permissions,
            # try to scope resources where possible (best-effort)
            if "*" in resources and len(trimmed) > 0:
                # Keep * but flag it for the caller via a comment field
                new_stmt["Resource"] = "*"
                new_stmt["_ciem_note"] = (
                    "Resource=* retained; scope to specific ARNs for full least-privilege."
                )

            new_statements.append(new_stmt)

        return {
            "Version": policy_json.get("Version", "2012-10-17"),
            "Statement": new_statements,
            "_ciem_summary": {
                "original_statement_count": len(policy_json.get("Statement", [])),
                "trimmed_statement_count": len(new_statements),
                "used_permissions": sorted(used_set),
            },
        }

    # ------------------------------------------------------------------
    # Policy scoring
    # ------------------------------------------------------------------

    def score_policy(self, policy_json: dict) -> float:
        """
        Score a policy 0–100 (100 = perfectly least-privilege).

        Deductions:
          -40  Action=*
          -30  Resource=* combined with non-read actions
          -20  any privilege escalation action present
          -10  sts:AssumeRole without conditions
          - 5  per sensitive action with Resource=*
        Score is clamped to [0, 100].
        """
        score = 100.0
        statements = policy_json.get("Statement", [])

        for stmt in statements:
            if stmt.get("Effect", "Allow") != "Allow":
                continue

            actions = self._normalise_actions(stmt.get("Action", []))
            resources = self._normalise_resources(stmt.get("Resource", []))
            conditions = stmt.get("Condition", {})

            if "*" in actions:
                score -= 40

            if "*" in resources:
                # Wildcard resource with any non-read-only action (or wildcard action) is high risk
                has_wildcard_action = "*" in actions
                non_read = [
                    a for a in actions
                    if not a.lower().endswith(":get") and not a.lower().endswith(":list")
                    and not a.lower().endswith(":describe")
                ]
                if has_wildcard_action or non_read:
                    score -= 30

            escalation_in_stmt = [a for a in actions if a in _ESCALATION_ACTIONS]
            if escalation_in_stmt:
                score -= 20

            if "sts:AssumeRole" in actions and not conditions:
                score -= 10

            if "*" in resources:
                for action in actions:
                    if action in _SENSITIVE_ACTIONS:
                        score -= 5

        return max(0.0, min(100.0, score))

    # ------------------------------------------------------------------
    # Full account analysis
    # ------------------------------------------------------------------

    def run_account_analysis(
        self, account_id: str, policies: List[dict]
    ) -> Dict[str, Any]:
        """
        Analyse all policies for an account and return a summary dict.

        Each policy in the list should be:
          {"principal": str, "policy": <AWS IAM policy dict>}
        """
        all_risks: List[EntitlementRisk] = []

        for entry in policies:
            principal = entry.get("principal", "unknown")
            policy = entry.get("policy", {})
            risks = self.analyze_aws_iam_policy(policy, principal)
            all_risks.extend(risks)

        escalation_risks = self.detect_privilege_escalation_paths(policies)
        all_risks.extend(escalation_risks)

        severity_counts: Dict[str, int] = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        }
        type_counts: Dict[str, int] = {}
        for risk in all_risks:
            severity_counts[risk.severity] = severity_counts.get(risk.severity, 0) + 1
            type_counts[risk.type.value] = type_counts.get(risk.type.value, 0) + 1

        scores = [
            self.score_policy(e.get("policy", {})) for e in policies if e.get("policy")
        ]
        avg_score = sum(scores) / len(scores) if scores else 100.0

        if _get_tg_bus:
            try:
                bus = _get_tg_bus()
                if bus and getattr(bus, "enabled", False):
                    bus.emit("IDENTITY_UPDATED", {"entity_type": "ciem_engine", "org_id": "unknown", "source_engine": "ciem_engine"})
            except Exception:
                pass
        return {
            "account_id": account_id,
            "analysed_at": datetime.now(timezone.utc).isoformat(),
            "policy_count": len(policies),
            "total_risks": len(all_risks),
            "severity_breakdown": severity_counts,
            "type_breakdown": type_counts,
            "average_policy_score": round(avg_score, 1),
            "risks": [r.to_dict() for r in all_risks],
        }

    # ------------------------------------------------------------------
    # Risk retrieval
    # ------------------------------------------------------------------

    def list_risks(
        self,
        principal: Optional[str] = None,
        severity: Optional[str] = None,
        limit: int = 200,
    ) -> List[Dict[str, Any]]:
        """Return persisted risks, optionally filtered."""
        conn = self._connect()
        try:
            conditions = []
            params: List[Any] = []
            if principal:
                conditions.append("principal = ?")
                params.append(principal)
            if severity:
                conditions.append("severity = ?")
                params.append(severity)
            where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
            params.append(limit)
            rows = conn.execute(
                f"SELECT * FROM ciem_risks {where} ORDER BY detected_at DESC LIMIT ?",  # nosec B608
                params,
            ).fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_engine: Optional[CIEMEngine] = None


def get_ciem_engine() -> CIEMEngine:
    global _engine
    if _engine is None:
        _engine = CIEMEngine()
    return _engine
