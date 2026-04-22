"""Tests for DynamicRuleDSLEngine (GAP-069) — 35 tests."""

from __future__ import annotations

import pytest

from core.dynamic_rule_dsl_engine import DynamicRuleDSLEngine


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine(tmp_path):
    return DynamicRuleDSLEngine(db_path=str(tmp_path / "dsl.db"))


@pytest.fixture
def org():
    return "org-alpha"


@pytest.fixture
def org2():
    return "org-beta"


YAML_BASIC = """
key: detect-public-s3
severity: high
schema_version: 1
when:
  service: s3
  resource.public: true
  findings.count:
    gt: 0
then:
  emit_finding: true
  tags: [s3, exposure]
  remediation: Disable public ACL
""".strip()


JSON_BASIC = """
{
  "key": "json-rule",
  "severity": "medium",
  "schema_version": 1,
  "when": {
    "service": "iam",
    "resource.count": {"gte": 5}
  },
  "then": {"emit_finding": true}
}
""".strip()


# ---------------------------------------------------------------------------
# validate_dsl — parsing
# ---------------------------------------------------------------------------


def test_validate_yaml_happy_path(engine):
    r = engine.validate_dsl(YAML_BASIC, dsl_format="yaml")
    assert r["ok"] is True
    assert r["errors"] == []
    assert r["compiled"]["key"] == "detect-public-s3"
    assert r["compiled"]["severity"] == "high"
    assert "when" in r["compiled"] and "then" in r["compiled"]


def test_validate_json_happy_path(engine):
    r = engine.validate_dsl(JSON_BASIC, dsl_format="json")
    assert r["ok"] is True
    assert r["compiled"]["key"] == "json-rule"
    assert r["compiled"]["when"]["service"] == "iam"


def test_validate_empty_text_fails(engine):
    r = engine.validate_dsl("", dsl_format="yaml")
    assert r["ok"] is False
    assert any("non-empty" in e for e in r["errors"])


def test_validate_unknown_format_fails(engine):
    r = engine.validate_dsl("key: x", dsl_format="toml")
    assert r["ok"] is False
    assert any("dsl_format" in e for e in r["errors"])


def test_validate_malformed_yaml_returns_errors(engine):
    # Invalid YAML indentation / structure
    bad = "key: test\n  severity: [\n"
    r = engine.validate_dsl(bad, dsl_format="yaml")
    assert r["ok"] is False
    assert r["errors"]


def test_validate_malformed_json_returns_errors(engine):
    r = engine.validate_dsl("{not json", dsl_format="json")
    assert r["ok"] is False
    assert any("parse error" in e.lower() for e in r["errors"])


def test_validate_top_level_not_mapping(engine):
    r = engine.validate_dsl("[1, 2, 3]", dsl_format="json")
    assert r["ok"] is False


# ---------------------------------------------------------------------------
# validate_dsl — shape
# ---------------------------------------------------------------------------


def test_validate_missing_key(engine):
    dsl = """severity: low
when: {a: 1}
then: {emit: true}"""
    r = engine.validate_dsl(dsl, dsl_format="yaml")
    assert r["ok"] is False
    assert any("key" in e for e in r["errors"])


def test_validate_invalid_severity(engine):
    dsl = """key: k
severity: catastrophic
when: {a: 1}
then: {emit: true}"""
    r = engine.validate_dsl(dsl, dsl_format="yaml")
    assert r["ok"] is False
    assert any("severity" in e for e in r["errors"])


def test_validate_missing_when(engine):
    dsl = """key: k
severity: low
then: {emit: true}"""
    r = engine.validate_dsl(dsl, dsl_format="yaml")
    assert r["ok"] is False
    assert any("when" in e for e in r["errors"])


def test_validate_missing_then(engine):
    dsl = """key: k
severity: low
when: {a: 1}"""
    r = engine.validate_dsl(dsl, dsl_format="yaml")
    assert r["ok"] is False
    assert any("then" in e for e in r["errors"])


def test_validate_unknown_operator(engine):
    dsl = """key: k
severity: low
when:
  field:
    unknown_op: 1
then: {emit: true}"""
    r = engine.validate_dsl(dsl, dsl_format="yaml")
    assert r["ok"] is False
    assert any("unknown operator" in e for e in r["errors"])


def test_validate_bad_regex_operator(engine):
    dsl = """key: k
severity: low
when:
  field:
    regex: "[unclosed"
then: {emit: true}"""
    r = engine.validate_dsl(dsl, dsl_format="yaml")
    assert r["ok"] is False
    assert any("regex" in e for e in r["errors"])


def test_validate_key_format(engine):
    dsl = """key: "has spaces"
severity: low
when: {a: 1}
then: {emit: true}"""
    r = engine.validate_dsl(dsl, dsl_format="yaml")
    assert r["ok"] is False


# ---------------------------------------------------------------------------
# publish_rule — lifecycle
# ---------------------------------------------------------------------------


def test_publish_rule_creates_v1(engine, org):
    rule = engine.publish_rule(org, "detect-public-s3", YAML_BASIC, "yaml", "alice")
    assert rule["version"] == 1
    assert rule["status"] == "published"
    assert rule["authored_by"] == "alice"
    assert rule["org_id"] == org
    assert rule["compiled_json"]["key"] == "detect-public-s3"


def test_publish_rule_invalid_dsl_raises(engine, org):
    with pytest.raises(ValueError, match="validation failed"):
        engine.publish_rule(org, "k", "not-yaml: [", "yaml", "bob")


def test_publish_rule_key_mismatch_raises(engine, org):
    # DSL key is "detect-public-s3" but caller passes "different"
    with pytest.raises(ValueError, match="does not match"):
        engine.publish_rule(org, "different", YAML_BASIC, "yaml", "bob")


def test_publish_rule_bumps_version(engine, org):
    v1 = engine.publish_rule(org, "detect-public-s3", YAML_BASIC, "yaml", "alice")
    v2 = engine.publish_rule(org, "detect-public-s3", YAML_BASIC, "yaml", "alice")
    assert v1["version"] == 1
    assert v2["version"] == 2
    assert v2["status"] == "published"


def test_publish_retires_previous_published_for_same_key(engine, org):
    engine.publish_rule(org, "detect-public-s3", YAML_BASIC, "yaml", "alice")
    engine.publish_rule(org, "detect-public-s3", YAML_BASIC, "yaml", "alice")
    # Only one row should still be status=published for that key.
    rules = engine.list_rules(org, status="published")
    matching = [r for r in rules if r["key"] == "detect-public-s3"]
    assert len(matching) == 1
    assert matching[0]["version"] == 2


def test_publish_rule_severity_override(engine, org):
    r = engine.publish_rule(org, "detect-public-s3", YAML_BASIC, "yaml", "alice", severity="critical")
    assert r["severity"] == "critical"


def test_publish_rule_invalid_severity_override(engine, org):
    with pytest.raises(ValueError, match="Invalid severity"):
        engine.publish_rule(org, "detect-public-s3", YAML_BASIC, "yaml", "x", severity="wat")


# ---------------------------------------------------------------------------
# list_rules / get_rule
# ---------------------------------------------------------------------------


def test_list_rules_empty(engine, org):
    assert engine.list_rules(org) == []


def test_list_and_get_rule_latest(engine, org):
    engine.publish_rule(org, "detect-public-s3", YAML_BASIC, "yaml", "alice")
    engine.publish_rule(org, "detect-public-s3", YAML_BASIC, "yaml", "alice")
    latest = engine.get_rule(org, "detect-public-s3")
    assert latest is not None
    assert latest["version"] == 2
    assert latest["status"] == "published"


def test_get_rule_specific_version(engine, org):
    engine.publish_rule(org, "detect-public-s3", YAML_BASIC, "yaml", "alice")
    engine.publish_rule(org, "detect-public-s3", YAML_BASIC, "yaml", "alice")
    v1 = engine.get_rule(org, "detect-public-s3", version=1)
    assert v1 is not None
    assert v1["version"] == 1
    assert v1["status"] == "retired"  # old version was demoted on republish


def test_get_rule_missing_returns_none(engine, org):
    assert engine.get_rule(org, "does-not-exist") is None


def test_list_rules_invalid_status_raises(engine, org):
    with pytest.raises(ValueError, match="status must be one of"):
        engine.list_rules(org, status="weird")


# ---------------------------------------------------------------------------
# retire_rule
# ---------------------------------------------------------------------------


def test_retire_rule_marks_status(engine, org):
    engine.publish_rule(org, "detect-public-s3", YAML_BASIC, "yaml", "alice")
    out = engine.retire_rule(org, "detect-public-s3")
    assert out["status"] == "retired"
    current = engine.get_rule(org, "detect-public-s3")
    assert current["status"] == "retired"


def test_retire_rule_unknown_key_raises(engine, org):
    with pytest.raises(KeyError):
        engine.retire_rule(org, "nope")


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------


def test_get_schema_returns_dict(engine):
    s = engine.get_schema()
    assert isinstance(s, dict)
    assert s["schema_version"] == 1
    assert "yaml" in s["formats"] and "json" in s["formats"]
    assert "gt" in s["operators"] and "in" in s["operators"]
    assert s["required_top_level"] == ["key", "severity", "when", "then"]


# ---------------------------------------------------------------------------
# evaluate_rule
# ---------------------------------------------------------------------------


def test_evaluate_rule_match(engine, org):
    engine.publish_rule(org, "detect-public-s3", YAML_BASIC, "yaml", "alice")
    doc = {
        "service": "s3",
        "resource": {"public": True},
        "findings": {"count": 3},
    }
    out = engine.evaluate_rule(org, "detect-public-s3", doc)
    assert out["match"] is True
    assert "service" in out["matched_fields"]
    assert out["severity"] == "high"
    assert out["then"]["emit_finding"] is True


def test_evaluate_rule_no_match_wrong_service(engine, org):
    engine.publish_rule(org, "detect-public-s3", YAML_BASIC, "yaml", "alice")
    doc = {"service": "ec2", "resource": {"public": True}, "findings": {"count": 5}}
    out = engine.evaluate_rule(org, "detect-public-s3", doc)
    assert out["match"] is False
    assert out["then"] == {}


def test_evaluate_rule_missing_field(engine, org):
    engine.publish_rule(org, "detect-public-s3", YAML_BASIC, "yaml", "alice")
    doc = {"service": "s3", "resource": {"public": True}}  # findings.count missing
    out = engine.evaluate_rule(org, "detect-public-s3", doc)
    assert out["match"] is False


def test_evaluate_rule_retired(engine, org):
    engine.publish_rule(org, "detect-public-s3", YAML_BASIC, "yaml", "alice")
    engine.retire_rule(org, "detect-public-s3")
    out = engine.evaluate_rule(org, "detect-public-s3", {"service": "s3"})
    assert out["match"] is False
    assert out["reason"] == "rule is retired"


def test_evaluate_rule_unknown_raises(engine, org):
    with pytest.raises(KeyError):
        engine.evaluate_rule(org, "nope", {})


def test_evaluate_rule_with_in_operator(engine, org):
    dsl = """key: region-check
severity: medium
when:
  resource.region:
    in: [us-east-1, us-west-2]
then: {emit: true}"""
    engine.publish_rule(org, "region-check", dsl, "yaml", "x")
    assert engine.evaluate_rule(org, "region-check", {"resource": {"region": "us-east-1"}})["match"]
    assert not engine.evaluate_rule(org, "region-check", {"resource": {"region": "eu-west-1"}})["match"]


def test_evaluate_rule_with_regex_operator(engine, org):
    dsl = """key: tag-check
severity: low
when:
  name:
    regex: "^prod-.*"
then: {emit: true}"""
    engine.publish_rule(org, "tag-check", dsl, "yaml", "x")
    assert engine.evaluate_rule(org, "tag-check", {"name": "prod-api"})["match"]
    assert not engine.evaluate_rule(org, "tag-check", {"name": "dev-api"})["match"]


def test_evaluate_rule_with_exists_false(engine, org):
    dsl = """key: missing-tag
severity: low
when:
  owner:
    exists: false
then: {emit: true}"""
    engine.publish_rule(org, "missing-tag", dsl, "yaml", "x")
    assert engine.evaluate_rule(org, "missing-tag", {"name": "x"})["match"]
    assert not engine.evaluate_rule(org, "missing-tag", {"owner": "alice"})["match"]


# ---------------------------------------------------------------------------
# stats + org isolation
# ---------------------------------------------------------------------------


def test_stats_returns_counts(engine, org):
    engine.publish_rule(org, "detect-public-s3", YAML_BASIC, "yaml", "alice")
    engine.publish_rule(org, "detect-public-s3", YAML_BASIC, "yaml", "alice")  # v2, v1 retired
    s = engine.stats(org)
    assert s["total_rule_records"] == 2
    assert s["unique_keys"] == 1
    assert s["by_status"].get("published") == 1
    assert s["by_status"].get("retired") == 1
    assert s["published_by_severity"].get("high") == 1


def test_org_isolation(engine, org, org2):
    engine.publish_rule(org, "detect-public-s3", YAML_BASIC, "yaml", "alice")
    # org2 should not see org's rule
    assert engine.list_rules(org2) == []
    assert engine.get_rule(org2, "detect-public-s3") is None
    with pytest.raises(KeyError):
        engine.retire_rule(org2, "detect-public-s3")
    # org still has it
    assert engine.get_rule(org, "detect-public-s3") is not None
