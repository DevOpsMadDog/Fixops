"""Tests for the CIEM (Cloud Infrastructure Entitlement Management) Engine.

Covers:
- Wildcard action detection
- Admin access detection
- Privilege escalation action detection
- sts:AssumeRole without conditions
- Sensitive action on Resource=*
- Toxic combination detection
- Privilege escalation path detection (multi-policy)
- Least-privilege suggestion
- Policy scoring (wildcard = low score)
- Azure role analysis
- Full account analysis
- Risk persistence and listing
- Edge cases (empty policy, deny statements, no risks)
"""

import os
import tempfile
import pytest

os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine(tmp_path):
    from core.ciem_engine import CIEMEngine
    return CIEMEngine(db_path=str(tmp_path / "test_ciem.db"))


WILDCARD_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "*",
            "Resource": "*",
        }
    ],
}

ADMIN_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["*"],
            "Resource": ["*"],
        }
    ],
}

ESCALATION_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "iam:CreatePolicyVersion",
                "iam:AttachRolePolicy",
            ],
            "Resource": "*",
        }
    ],
}

ASSUME_ROLE_NO_CONDITION_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Resource": "*",
        }
    ],
}

ASSUME_ROLE_WITH_CONDITION_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": "sts:AssumeRole",
            "Resource": "*",
            "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-xxxx"}},
        }
    ],
}

SENSITIVE_ACTION_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:PutObject"],
            "Resource": "*",
        }
    ],
}

SAFE_SCOPED_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["s3:GetObject"],
            "Resource": "arn:aws:s3:::my-specific-bucket/*",
        }
    ],
}

DENY_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Deny",
            "Action": "*",
            "Resource": "*",
        }
    ],
}

TOXIC_S3_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["s3:PutObject", "s3:DeleteObject"],
            "Resource": "*",
        }
    ],
}

PASS_ROLE_EC2_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": ["iam:PassRole", "ec2:RunInstances"],
            "Resource": "*",
        }
    ],
}


# ---------------------------------------------------------------------------
# Test: wildcard action detection
# ---------------------------------------------------------------------------


def test_wildcard_action_detected(engine):
    risks = engine.analyze_aws_iam_policy(WILDCARD_POLICY, "arn:aws:iam::123:role/OverkillRole")
    types = [r.type.value for r in risks]
    assert "wildcard_permission" in types


def test_wildcard_action_severity_critical(engine):
    risks = engine.analyze_aws_iam_policy(WILDCARD_POLICY, "test-principal")
    wildcard_risks = [r for r in risks if r.type.value == "wildcard_permission"]
    assert wildcard_risks
    assert wildcard_risks[0].severity == "critical"


# ---------------------------------------------------------------------------
# Test: admin access detection
# ---------------------------------------------------------------------------


def test_admin_access_detected(engine):
    risks = engine.analyze_aws_iam_policy(ADMIN_POLICY, "arn:aws:iam::123:role/AdminRole")
    types = [r.type.value for r in risks]
    assert "admin_access" in types


def test_admin_access_severity_critical(engine):
    risks = engine.analyze_aws_iam_policy(ADMIN_POLICY, "test-principal")
    admin_risks = [r for r in risks if r.type.value == "admin_access"]
    assert admin_risks
    assert admin_risks[0].severity == "critical"


def test_deny_statement_not_flagged(engine):
    """Deny statements should not trigger any risks."""
    risks = engine.analyze_aws_iam_policy(DENY_POLICY, "test-principal")
    assert risks == []


# ---------------------------------------------------------------------------
# Test: privilege escalation actions
# ---------------------------------------------------------------------------


def test_privilege_escalation_action_detected(engine):
    risks = engine.analyze_aws_iam_policy(ESCALATION_POLICY, "arn:aws:iam::123:user/DevUser")
    types = [r.type.value for r in risks]
    assert "privilege_escalation" in types


def test_privilege_escalation_actions_high_severity(engine):
    risks = engine.analyze_aws_iam_policy(ESCALATION_POLICY, "DevUser")
    esc_risks = [r for r in risks if r.type.value == "privilege_escalation"]
    assert esc_risks
    for r in esc_risks:
        assert r.severity == "high"


def test_multiple_escalation_actions_each_flagged(engine):
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "iam:CreatePolicyVersion",
                    "iam:AttachRolePolicy",
                    "iam:PutRolePolicy",
                ],
                "Resource": "*",
            }
        ],
    }
    risks = engine.analyze_aws_iam_policy(policy, "DevUser")
    esc_risks = [r for r in risks if r.type.value == "privilege_escalation"]
    # Each escalation action gets its own finding
    assert len(esc_risks) >= 2


# ---------------------------------------------------------------------------
# Test: sts:AssumeRole
# ---------------------------------------------------------------------------


def test_assume_role_no_condition_flagged(engine):
    risks = engine.analyze_aws_iam_policy(
        ASSUME_ROLE_NO_CONDITION_POLICY, "arn:aws:iam::123:role/CrossAcct"
    )
    types = [r.type.value for r in risks]
    assert "cross_account_trust" in types


def test_assume_role_with_condition_not_flagged(engine):
    risks = engine.analyze_aws_iam_policy(
        ASSUME_ROLE_WITH_CONDITION_POLICY, "arn:aws:iam::123:role/CrossAcct"
    )
    cross_risks = [r for r in risks if r.type.value == "cross_account_trust"]
    assert cross_risks == []


# ---------------------------------------------------------------------------
# Test: sensitive action on Resource=*
# ---------------------------------------------------------------------------


def test_sensitive_action_wildcard_resource_flagged(engine):
    risks = engine.analyze_aws_iam_policy(SENSITIVE_ACTION_POLICY, "test-principal")
    types = [r.type.value for r in risks]
    assert "public_resource" in types


def test_sensitive_action_scoped_resource_not_flagged(engine):
    risks = engine.analyze_aws_iam_policy(SAFE_SCOPED_POLICY, "test-principal")
    public_risks = [r for r in risks if r.type.value == "public_resource"]
    assert public_risks == []


# ---------------------------------------------------------------------------
# Test: toxic combination
# ---------------------------------------------------------------------------


def test_toxic_s3_write_delete_detected(engine):
    risks = engine.analyze_aws_iam_policy(TOXIC_S3_POLICY, "test-principal")
    types = [r.type.value for r in risks]
    assert "toxic_combination" in types


def test_toxic_combo_iam_create_attach(engine):
    risks = engine.analyze_aws_iam_policy(ESCALATION_POLICY, "DevUser")
    combo_risks = [r for r in risks if r.type.value == "toxic_combination"]
    assert combo_risks


# ---------------------------------------------------------------------------
# Test: privilege escalation path detection
# ---------------------------------------------------------------------------


def test_escalation_path_create_attach(engine):
    policies = [
        {
            "principal": "arn:aws:iam::123:user/PowerUser",
            "policy": {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "iam:CreatePolicyVersion",
                            "iam:SetDefaultPolicyVersion",
                            "iam:AttachRolePolicy",
                        ],
                        "Resource": "*",
                    }
                ],
            },
        }
    ]
    risks = engine.detect_privilege_escalation_paths(policies)
    assert risks
    assert any(r.type.value == "privilege_escalation" for r in risks)
    assert any(r.severity == "critical" for r in risks)


def test_escalation_path_pass_role_ec2(engine):
    policies = [
        {
            "principal": "arn:aws:iam::123:user/DevUser",
            "policy": PASS_ROLE_EC2_POLICY,
        }
    ]
    risks = engine.detect_privilege_escalation_paths(policies)
    assert risks
    assert any(r.type.value == "privilege_escalation" for r in risks)


def test_escalation_path_no_risk_safe_policy(engine):
    policies = [
        {
            "principal": "arn:aws:iam::123:user/ReadOnlyUser",
            "policy": SAFE_SCOPED_POLICY,
        }
    ]
    risks = engine.detect_privilege_escalation_paths(policies)
    assert risks == []


# ---------------------------------------------------------------------------
# Test: least-privilege suggestion
# ---------------------------------------------------------------------------


def test_least_privilege_reduces_wildcard(engine):
    used = ["s3:GetObject", "s3:PutObject"]
    result = engine.suggest_least_privilege(WILDCARD_POLICY, used)
    stmts = result["Statement"]
    assert stmts
    for stmt in stmts:
        if stmt.get("Effect", "Allow") == "Allow":
            actions = stmt["Action"]
            assert "*" not in actions
            assert set(actions).issubset(set(used))


def test_least_privilege_drops_unused_statements(engine):
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["ec2:RunInstances"], "Resource": "*"},
            {"Effect": "Allow", "Action": ["s3:GetObject"], "Resource": "*"},
        ],
    }
    used = ["s3:GetObject"]
    result = engine.suggest_least_privilege(policy, used)
    allow_stmts = [s for s in result["Statement"] if s.get("Effect", "Allow") == "Allow"]
    # Only s3:GetObject statement should remain
    assert len(allow_stmts) == 1
    assert "s3:GetObject" in allow_stmts[0]["Action"]


def test_least_privilege_keeps_deny_statements(engine):
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Deny", "Action": ["s3:DeleteObject"], "Resource": "*"},
            {"Effect": "Allow", "Action": ["s3:GetObject", "ec2:RunInstances"], "Resource": "*"},
        ],
    }
    used = ["s3:GetObject"]
    result = engine.suggest_least_privilege(policy, used)
    deny_stmts = [s for s in result["Statement"] if s.get("Effect") == "Deny"]
    assert len(deny_stmts) == 1


def test_least_privilege_summary_present(engine):
    used = ["s3:GetObject"]
    result = engine.suggest_least_privilege(WILDCARD_POLICY, used)
    assert "_ciem_summary" in result
    assert "used_permissions" in result["_ciem_summary"]


# ---------------------------------------------------------------------------
# Test: policy scoring
# ---------------------------------------------------------------------------


def test_wildcard_policy_low_score(engine):
    score = engine.score_policy(WILDCARD_POLICY)
    assert score <= 30, f"Expected score <= 30 for wildcard policy, got {score}"


def test_safe_scoped_policy_high_score(engine):
    score = engine.score_policy(SAFE_SCOPED_POLICY)
    assert score >= 70, f"Expected score >= 70 for safe scoped policy, got {score}"


def test_score_clamped_to_zero(engine):
    score = engine.score_policy(ADMIN_POLICY)
    assert 0.0 <= score <= 100.0


def test_empty_policy_perfect_score(engine):
    score = engine.score_policy({"Version": "2012-10-17", "Statement": []})
    assert score == 100.0


# ---------------------------------------------------------------------------
# Test: Azure role analysis
# ---------------------------------------------------------------------------


def test_azure_owner_role_flagged(engine):
    role_def = {
        "roleDefinitionId": "/subscriptions/xxx/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
        "roleName": "Owner",
    }
    risks = engine.analyze_azure_role_assignment(role_def, "user@example.com")
    assert risks
    assert any(r.type.value == "admin_access" for r in risks)


def test_azure_contributor_role_flagged(engine):
    role_def = {"roleName": "Contributor", "permissions": []}
    risks = engine.analyze_azure_role_assignment(role_def, "spn-12345")
    assert any(r.type.value == "admin_access" for r in risks)


def test_azure_wildcard_action_flagged(engine):
    role_def = {
        "roleName": "CustomRole",
        "permissions": [{"actions": ["*"], "notActions": []}],
    }
    risks = engine.analyze_azure_role_assignment(role_def, "spn-custom")
    assert any(r.type.value == "wildcard_permission" for r in risks)


def test_azure_authorization_escalation_flagged(engine):
    role_def = {
        "roleName": "CustomRole",
        "permissions": [
            {
                "actions": ["Microsoft.Authorization/roleAssignments/write"],
                "notActions": [],
            }
        ],
    }
    risks = engine.analyze_azure_role_assignment(role_def, "spn-escalate")
    assert any(r.type.value == "privilege_escalation" for r in risks)


def test_azure_safe_role_no_risks(engine):
    role_def = {
        "roleName": "Reader",
        "permissions": [
            {
                "actions": ["Microsoft.Storage/storageAccounts/read"],
                "notActions": [],
            }
        ],
    }
    risks = engine.analyze_azure_role_assignment(role_def, "spn-safe")
    assert risks == []


# ---------------------------------------------------------------------------
# Test: full account analysis
# ---------------------------------------------------------------------------


def test_account_analysis_summary_structure(engine):
    policies = [
        {"principal": "role/Admin", "policy": ADMIN_POLICY},
        {"principal": "role/Dev", "policy": SAFE_SCOPED_POLICY},
    ]
    result = engine.run_account_analysis("123456789012", policies)
    assert result["account_id"] == "123456789012"
    assert result["policy_count"] == 2
    assert "severity_breakdown" in result
    assert "average_policy_score" in result
    assert isinstance(result["risks"], list)


def test_account_analysis_counts_risks(engine):
    policies = [
        {"principal": "role/Admin", "policy": ADMIN_POLICY},
    ]
    result = engine.run_account_analysis("123456789012", policies)
    assert result["total_risks"] > 0
    assert result["severity_breakdown"]["critical"] > 0


# ---------------------------------------------------------------------------
# Test: DB persistence and listing
# ---------------------------------------------------------------------------


def test_risks_persisted_and_listable(engine):
    engine.analyze_aws_iam_policy(WILDCARD_POLICY, "persist-test-principal")
    risks = engine.list_risks(principal="persist-test-principal")
    assert risks
    assert all(r["principal"] == "persist-test-principal" for r in risks)


def test_list_risks_filter_severity(engine):
    engine.analyze_aws_iam_policy(WILDCARD_POLICY, "severity-filter-test")
    critical = engine.list_risks(severity="critical")
    assert critical
    assert all(r["severity"] == "critical" for r in critical)


def test_empty_policy_no_risks(engine):
    policy = {"Version": "2012-10-17", "Statement": []}
    risks = engine.analyze_aws_iam_policy(policy, "empty-principal")
    assert risks == []
