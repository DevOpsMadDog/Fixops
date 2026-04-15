"""Tests for IAMPolicyAnalyzerEngine."""

from __future__ import annotations

import pytest
from core.iam_policy_analyzer import IAMPolicyAnalyzerEngine


@pytest.fixture
def engine(tmp_path):
    return IAMPolicyAnalyzerEngine(db_path=str(tmp_path / "test_iam.db"))


def _make_policy(name="TestPolicy", policy_type="aws_iam", principal_type="user",
                 permissions=None, resources=None):
    return {
        "policy_name": name,
        "policy_type": policy_type,
        "principal_type": principal_type,
        "principal_id": "arn:aws:iam::123456789012:user/test",
        "permissions": permissions or ["s3:GetObject", "s3:PutObject"],
        "resources": resources or ["arn:aws:s3:::my-bucket/*"],
        "conditions": {},
        "is_managed": True,
    }


# ------------------------------------------------------------------
# Initialization
# ------------------------------------------------------------------

def test_init_creates_db(tmp_path):
    db = tmp_path / "iam.db"
    engine = IAMPolicyAnalyzerEngine(db_path=str(db))
    assert db.exists()


def test_init_twice_no_error(tmp_path):
    db = str(tmp_path / "iam.db")
    IAMPolicyAnalyzerEngine(db_path=db)
    IAMPolicyAnalyzerEngine(db_path=db)


# ------------------------------------------------------------------
# add_policy / list_policies
# ------------------------------------------------------------------

def test_add_policy_returns_policy_id(engine):
    result = engine.add_policy("org1", _make_policy())
    assert "policy_id" in result
    assert result["policy_name"] == "TestPolicy"


def test_add_policy_stores_permissions(engine):
    perms = ["ec2:DescribeInstances", "ec2:StartInstances"]
    result = engine.add_policy("org1", _make_policy(permissions=perms))
    assert result["permissions"] == perms


def test_list_policies_empty(engine):
    assert engine.list_policies("org1") == []


def test_list_policies_returns_added(engine):
    engine.add_policy("org1", _make_policy("A"))
    engine.add_policy("org1", _make_policy("B"))
    policies = engine.list_policies("org1")
    assert len(policies) == 2


def test_list_policies_filter_by_type(engine):
    engine.add_policy("org1", _make_policy("AWS", policy_type="aws_iam"))
    engine.add_policy("org1", _make_policy("Azure", policy_type="azure_rbac"))
    aws = engine.list_policies("org1", policy_type="aws_iam")
    assert len(aws) == 1
    assert aws[0]["policy_type"] == "aws_iam"


def test_list_policies_filter_by_principal_type(engine):
    engine.add_policy("org1", _make_policy("User", principal_type="user"))
    engine.add_policy("org1", _make_policy("Group", principal_type="group"))
    groups = engine.list_policies("org1", principal_type="group")
    assert len(groups) == 1
    assert groups[0]["principal_type"] == "group"


def test_add_policy_invalid_type_defaults(engine):
    data = _make_policy()
    data["policy_type"] = "invalid_cloud"
    result = engine.add_policy("org1", data)
    assert result["policy_type"] == "aws_iam"


def test_add_policy_invalid_principal_defaults(engine):
    data = _make_policy()
    data["principal_type"] = "unknown"
    result = engine.add_policy("org1", data)
    assert result["principal_type"] == "user"


# ------------------------------------------------------------------
# analyze_policy — findings
# ------------------------------------------------------------------

def test_analyze_policy_not_found_returns_empty(engine):
    result = engine.analyze_policy("org1", "nonexistent-id")
    assert result["findings"] == []
    assert result["risk_score"] == 0


def test_analyze_policy_returns_findings_and_risk_score(engine):
    policy = engine.add_policy("org1", _make_policy(permissions=["*"]))
    result = engine.analyze_policy("org1", policy["policy_id"])
    assert "findings" in result
    assert "risk_score" in result
    assert isinstance(result["risk_score"], (int, float))


def test_analyze_policy_detects_wildcard_action(engine):
    policy = engine.add_policy("org1", _make_policy(permissions=["*"]))
    result = engine.analyze_policy("org1", policy["policy_id"])
    finding_types = [f["finding_type"] for f in result["findings"]]
    assert "wildcard_action" in finding_types


def test_analyze_policy_wildcard_is_critical(engine):
    policy = engine.add_policy("org1", _make_policy(permissions=["*"]))
    result = engine.analyze_policy("org1", policy["policy_id"])
    wildcard_findings = [f for f in result["findings"] if f["finding_type"] == "wildcard_action"]
    assert wildcard_findings[0]["severity"] == "critical"


def test_analyze_policy_detects_admin_access(engine):
    policy = engine.add_policy("org1", _make_policy(permissions=["iam:*"]))
    result = engine.analyze_policy("org1", policy["policy_id"])
    finding_types = [f["finding_type"] for f in result["findings"]]
    assert "admin_access" in finding_types


def test_analyze_policy_admin_access_has_recommendation(engine):
    policy = engine.add_policy("org1", _make_policy(permissions=["iam:*"]))
    result = engine.analyze_policy("org1", policy["policy_id"])
    admin = [f for f in result["findings"] if f["finding_type"] == "admin_access"]
    assert admin[0]["recommendation"] != ""


def test_analyze_policy_detects_data_exfil_risk(engine):
    perms = ["s3:GetObject", "s3:ListBucket", "secretsmanager:GetSecretValue"]
    policy = engine.add_policy("org1", _make_policy(permissions=perms))
    result = engine.analyze_policy("org1", policy["policy_id"])
    finding_types = [f["finding_type"] for f in result["findings"]]
    assert "data_exfil_risk" in finding_types


def test_analyze_policy_detects_toxic_combination(engine):
    perms = ["iam:CreateUser", "iam:AttachUserPolicy"]
    policy = engine.add_policy("org1", _make_policy(permissions=perms))
    result = engine.analyze_policy("org1", policy["policy_id"])
    finding_types = [f["finding_type"] for f in result["findings"]]
    assert "toxic_combination" in finding_types


def test_analyze_policy_high_risk_score_for_critical(engine):
    policy = engine.add_policy("org1", _make_policy(permissions=["*", "iam:CreateUser", "iam:AttachUserPolicy"]))
    result = engine.analyze_policy("org1", policy["policy_id"])
    assert result["risk_score"] >= 30


def test_analyze_policy_low_risk_for_safe_policy(engine):
    perms = ["s3:GetObject"]
    policy = engine.add_policy("org1", _make_policy(permissions=perms))
    result = engine.analyze_policy("org1", policy["policy_id"])
    assert result["risk_score"] <= 30


def test_analyze_policy_risk_score_max_100(engine):
    perms = ["*", "iam:*", "s3:*", "iam:CreateUser", "iam:AttachUserPolicy",
             "s3:GetObject", "s3:ListBucket", "secretsmanager:GetSecretValue"]
    policy = engine.add_policy("org1", _make_policy(permissions=perms))
    result = engine.analyze_policy("org1", policy["policy_id"])
    assert result["risk_score"] <= 100


def test_analyze_policy_findings_have_required_fields(engine):
    policy = engine.add_policy("org1", _make_policy(permissions=["*"]))
    result = engine.analyze_policy("org1", policy["policy_id"])
    for f in result["findings"]:
        assert "finding_type" in f
        assert "severity" in f
        assert "description" in f
        assert "affected_permissions" in f
        assert "recommendation" in f


# ------------------------------------------------------------------
# analyze_all
# ------------------------------------------------------------------

def test_analyze_all_returns_summary(engine):
    engine.add_policy("org1", _make_policy("A", permissions=["*"]))
    engine.add_policy("org1", _make_policy("B", permissions=["s3:GetObject"]))
    result = engine.analyze_all("org1")
    assert result["policies_analyzed"] == 2
    assert "total_findings" in result
    assert "high_risk_policies" in result
    assert "avg_risk_score" in result
    assert "results" in result


def test_analyze_all_empty_org(engine):
    result = engine.analyze_all("empty_org")
    assert result["policies_analyzed"] == 0
    assert result["total_findings"] == 0


# ------------------------------------------------------------------
# Access Reviews
# ------------------------------------------------------------------

def test_record_access_review_returns_review_id(engine):
    policy = engine.add_policy("org1", _make_policy())
    review = engine.record_access_review("org1", {
        "policy_id": policy["policy_id"],
        "reviewer": "alice@example.com",
        "outcome": "approved",
        "action_taken": "No changes required",
    })
    assert "review_id" in review
    assert review["outcome"] == "approved"


def test_list_access_reviews_empty(engine):
    assert engine.list_access_reviews("org1") == []


def test_list_access_reviews_returns_records(engine):
    policy = engine.add_policy("org1", _make_policy())
    engine.record_access_review("org1", {"policy_id": policy["policy_id"], "reviewer": "bob"})
    engine.record_access_review("org1", {"policy_id": policy["policy_id"], "reviewer": "alice"})
    reviews = engine.list_access_reviews("org1")
    assert len(reviews) == 2


def test_access_review_invalid_outcome_defaults(engine):
    policy = engine.add_policy("org1", _make_policy())
    review = engine.record_access_review("org1", {
        "policy_id": policy["policy_id"],
        "reviewer": "bob",
        "outcome": "unknown_outcome",
    })
    assert review["outcome"] == "approved"


# ------------------------------------------------------------------
# Stats
# ------------------------------------------------------------------

def test_get_iam_stats_structure(engine):
    engine.add_policy("org1", _make_policy(permissions=["*"]))
    engine.analyze_policy("org1", engine.list_policies("org1")[0]["policy_id"])
    stats = engine.get_iam_stats("org1")
    assert "total_policies" in stats
    assert "by_type" in stats
    assert "admin_access_count" in stats
    assert "wildcard_count" in stats
    assert "avg_risk_score" in stats
    assert "high_risk_policies" in stats
    assert "last_review_date" in stats


def test_get_iam_stats_empty_org(engine):
    stats = engine.get_iam_stats("empty_org")
    assert stats["total_policies"] == 0
    assert stats["avg_risk_score"] == 0.0


def test_get_iam_stats_counts_wildcards(engine):
    engine.add_policy("org1", _make_policy("W", permissions=["*"]))
    policy = engine.list_policies("org1")[0]
    engine.analyze_policy("org1", policy["policy_id"])
    stats = engine.get_iam_stats("org1")
    assert stats["wildcard_count"] >= 1


# ------------------------------------------------------------------
# Org isolation
# ------------------------------------------------------------------

def test_org_isolation_policies(engine):
    engine.add_policy("org1", _make_policy("OrgA"))
    engine.add_policy("org2", _make_policy("OrgB"))
    assert len(engine.list_policies("org1")) == 1
    assert len(engine.list_policies("org2")) == 1


def test_org_isolation_reviews(engine):
    p1 = engine.add_policy("org1", _make_policy())
    p2 = engine.add_policy("org2", _make_policy())
    engine.record_access_review("org1", {"policy_id": p1["policy_id"], "reviewer": "a"})
    assert len(engine.list_access_reviews("org2")) == 0


def test_org_isolation_stats(engine):
    engine.add_policy("org1", _make_policy(permissions=["*"]))
    stats_org2 = engine.get_iam_stats("org2")
    assert stats_org2["total_policies"] == 0
