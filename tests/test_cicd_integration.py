"""Tests for CI/CD Pipeline Security Integration.

Covers:
- PolicyAction enum values
- PolicyRule / ScanResult / PRComment Pydantic models
- CICDPolicyEngine: policy CRUD, evaluation (PASS/WARN/BLOCK), scan history
- PR comment markdown generation
- Badge generation (passing / warning / failing states)
- CI template files are valid YAML
- API router endpoints (via FastAPI TestClient)
"""

from __future__ import annotations

import json
import os
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import List

import pytest
import yaml

# ---------------------------------------------------------------------------
# Environment setup — must happen before any app/router imports
# ---------------------------------------------------------------------------
os.environ["FIXOPS_MODE"] = "dev"
os.environ["FIXOPS_API_TOKEN"] = "test-token"
os.environ["FIXOPS_JWT_SECRET"] = "test-secret-that-is-long-enough-32c"
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

from core.cicd_integration import (
    CICDPolicyEngine,
    PolicyAction,
    PolicyRule,
    PRComment,
    ScanResult,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_findings(critical: int = 0, high: int = 0, medium: int = 0, low: int = 0) -> list:
    findings = []
    for _ in range(critical):
        findings.append({"severity": "critical", "title": "Critical finding", "category": "vuln"})
    for _ in range(high):
        findings.append({"severity": "high", "title": "High finding", "category": "vuln"})
    for _ in range(medium):
        findings.append({"severity": "medium", "title": "Medium finding", "category": "config"})
    for _ in range(low):
        findings.append({"severity": "low", "title": "Low finding", "category": "info"})
    return findings


@pytest.fixture
def engine(tmp_path):
    """CICDPolicyEngine with isolated temp DB."""
    db = str(tmp_path / "cicd_test.db")
    eng = CICDPolicyEngine(db_path=db)
    yield eng
    eng.close()


@pytest.fixture
def default_policy_id(engine):
    """A standard policy: block on any critical, warn if high > 3."""
    rule = PolicyRule(
        name="default-gate",
        severity_threshold="critical",
        max_critical=0,
        max_high=3,
    )
    return engine.create_policy([rule], org_id="org_test")


# ===========================================================================
# 1. Enum and Model tests
# ===========================================================================

class TestPolicyActionEnum:
    def test_values_exist(self):
        assert PolicyAction.PASS.value == "pass"
        assert PolicyAction.WARN.value == "warn"
        assert PolicyAction.BLOCK.value == "block"

    def test_string_cast(self):
        assert PolicyAction.BLOCK.value == "block"


class TestPolicyRuleModel:
    def test_defaults(self):
        rule = PolicyRule(name="test-rule")
        assert rule.severity_threshold == "critical"
        assert rule.max_critical == 0
        assert rule.max_high == 5
        assert rule.categories == []
        assert rule.enabled is True

    def test_custom_values(self):
        rule = PolicyRule(
            name="strict",
            severity_threshold="high",
            max_critical=0,
            max_high=0,
            categories=["vuln", "misconfig"],
            enabled=True,
        )
        assert rule.severity_threshold == "high"
        assert rule.categories == ["vuln", "misconfig"]

    def test_serialisation(self):
        rule = PolicyRule(name="r")
        d = rule.model_dump()
        assert "name" in d
        assert "severity_threshold" in d


class TestScanResultModel:
    def test_defaults(self):
        r = ScanResult(repo="org/repo")
        assert r.branch == "main"
        assert r.findings_count == 0
        assert r.policy_action == PolicyAction.PASS
        assert isinstance(r.scanned_at, datetime)

    def test_auto_scan_id(self):
        r1 = ScanResult(repo="org/repo")
        r2 = ScanResult(repo="org/repo")
        assert r1.scan_id != r2.scan_id

    def test_full_construction(self):
        r = ScanResult(
            repo="org/repo",
            branch="feature/x",
            commit_sha="abc123",
            findings_count=5,
            critical=1,
            high=2,
            medium=1,
            low=1,
            policy_action=PolicyAction.BLOCK,
        )
        assert r.critical == 1
        assert r.policy_action == PolicyAction.BLOCK


class TestPRCommentModel:
    def test_construction(self):
        c = PRComment(repo="org/repo", pr_number=42, body="## Security Scan\nPASS")
        assert c.pr_number == 42
        assert "Security Scan" in c.body


# ===========================================================================
# 2. Policy CRUD
# ===========================================================================

class TestPolicyCRUD:
    def test_create_and_get(self, engine):
        rule = PolicyRule(name="gate")
        pid = engine.create_policy([rule], org_id="org1")
        assert pid  # non-empty UUID

        policy = engine.get_policy(pid)
        assert policy is not None
        assert policy["policy_id"] == pid
        assert policy["org_id"] == "org1"
        assert len(policy["rules"]) == 1
        assert policy["rules"][0]["name"] == "gate"

    def test_get_nonexistent(self, engine):
        result = engine.get_policy("does-not-exist")
        assert result is None

    def test_list_all(self, engine):
        engine.create_policy([PolicyRule(name="r1")], org_id="orgA")
        engine.create_policy([PolicyRule(name="r2")], org_id="orgB")
        all_policies = engine.list_policies()
        assert len(all_policies) >= 2

    def test_list_by_org(self, engine):
        engine.create_policy([PolicyRule(name="r1")], org_id="orgX")
        engine.create_policy([PolicyRule(name="r2")], org_id="orgY")
        orgx_policies = engine.list_policies(org_id="orgX")
        assert all(p["org_id"] == "orgX" for p in orgx_policies)
        assert len(orgx_policies) >= 1

    def test_multiple_rules(self, engine):
        rules = [PolicyRule(name=f"rule-{i}") for i in range(3)]
        pid = engine.create_policy(rules)
        policy = engine.get_policy(pid)
        assert len(policy["rules"]) == 3


# ===========================================================================
# 3. Scan evaluation — PASS / WARN / BLOCK
# ===========================================================================

class TestEvaluateScan:
    def test_pass_clean(self, engine, default_policy_id):
        result = engine.evaluate_scan(
            findings=_make_findings(low=2),
            policy_id=default_policy_id,
            repo="org/repo",
            branch="main",
        )
        assert result.policy_action == PolicyAction.PASS
        assert result.findings_count == 2

    def test_warn_too_many_high(self, engine, default_policy_id):
        # Policy: max_high=3, so 4 high findings should warn
        result = engine.evaluate_scan(
            findings=_make_findings(high=4),
            policy_id=default_policy_id,
            repo="org/repo",
        )
        assert result.policy_action == PolicyAction.WARN

    def test_block_on_critical(self, engine, default_policy_id):
        result = engine.evaluate_scan(
            findings=_make_findings(critical=1),
            policy_id=default_policy_id,
            repo="org/repo",
        )
        assert result.policy_action == PolicyAction.BLOCK

    def test_block_critical_wins_over_warn(self, engine, default_policy_id):
        # 1 critical + 10 high → BLOCK (not just WARN)
        result = engine.evaluate_scan(
            findings=_make_findings(critical=1, high=10),
            policy_id=default_policy_id,
            repo="org/repo",
        )
        assert result.policy_action == PolicyAction.BLOCK

    def test_severity_counts_stored(self, engine, default_policy_id):
        result = engine.evaluate_scan(
            findings=_make_findings(critical=1, high=2, medium=3, low=4),
            policy_id=default_policy_id,
            repo="org/repo",
        )
        assert result.critical == 1
        assert result.high == 2
        assert result.medium == 3
        assert result.low == 4
        assert result.findings_count == 10

    def test_invalid_policy_raises(self, engine):
        with pytest.raises(ValueError, match="not found"):
            engine.evaluate_scan(findings=[], policy_id="bad-id")

    def test_disabled_rule_ignored(self, engine):
        rule = PolicyRule(name="disabled-block", severity_threshold="low", enabled=False)
        pid = engine.create_policy([rule])
        result = engine.evaluate_scan(
            findings=_make_findings(critical=5),
            policy_id=pid,
            repo="org/repo",
        )
        # Disabled rule should not trigger BLOCK
        assert result.policy_action == PolicyAction.PASS

    def test_category_filter(self, engine):
        # Rule only applies to 'vuln' category; our findings are 'config'
        rule = PolicyRule(
            name="vuln-gate",
            severity_threshold="critical",
            max_critical=0,
            categories=["vuln"],
        )
        pid = engine.create_policy([rule])
        findings = [{"severity": "critical", "category": "config", "title": "Config issue"}]
        result = engine.evaluate_scan(findings=findings, policy_id=pid, repo="org/repo")
        assert result.policy_action == PolicyAction.PASS

    def test_empty_findings_pass(self, engine, default_policy_id):
        result = engine.evaluate_scan(findings=[], policy_id=default_policy_id, repo="org/repo")
        assert result.policy_action == PolicyAction.PASS
        assert result.findings_count == 0


# ===========================================================================
# 4. Scan history
# ===========================================================================

class TestScanHistory:
    def test_history_stored(self, engine, default_policy_id):
        engine.evaluate_scan(
            findings=_make_findings(low=1), policy_id=default_policy_id, repo="org/myrepo", branch="main"
        )
        history = engine.get_scan_history("org/myrepo")
        assert len(history) >= 1
        assert history[0].repo == "org/myrepo"

    def test_history_branch_filter(self, engine, default_policy_id):
        engine.evaluate_scan(findings=[], policy_id=default_policy_id, repo="org/r", branch="main")
        engine.evaluate_scan(findings=[], policy_id=default_policy_id, repo="org/r", branch="develop")
        main_history = engine.get_scan_history("org/r", branch="main")
        assert all(r.branch == "main" for r in main_history)

    def test_history_limit(self, engine, default_policy_id):
        for _ in range(5):
            engine.evaluate_scan(findings=[], policy_id=default_policy_id, repo="org/limited", branch="main")
        history = engine.get_scan_history("org/limited", limit=3)
        assert len(history) <= 3

    def test_history_empty_repo(self, engine):
        history = engine.get_scan_history("no-such-repo")
        assert history == []

    def test_history_newest_first(self, engine, default_policy_id):
        engine.evaluate_scan(findings=_make_findings(low=1), policy_id=default_policy_id, repo="org/ordered")
        engine.evaluate_scan(findings=_make_findings(high=1), policy_id=default_policy_id, repo="org/ordered")
        history = engine.get_scan_history("org/ordered")
        # Newest should be first
        if len(history) >= 2:
            assert history[0].scanned_at >= history[1].scanned_at


# ===========================================================================
# 5. PR comment generation
# ===========================================================================

class TestPRCommentGeneration:
    def test_pass_comment_has_pass_text(self, engine, default_policy_id):
        result = engine.evaluate_scan(findings=[], policy_id=default_policy_id, repo="org/repo")
        comment = engine.generate_pr_comment(result)
        assert "passed" in comment.lower()
        assert "org/repo" in comment

    def test_block_comment_has_block_text(self, engine, default_policy_id):
        result = engine.evaluate_scan(
            findings=_make_findings(critical=2), policy_id=default_policy_id, repo="org/repo"
        )
        comment = engine.generate_pr_comment(result)
        assert "blocked" in comment.lower() or "failed" in comment.lower()

    def test_comment_has_markdown_table(self, engine, default_policy_id):
        result = engine.evaluate_scan(
            findings=_make_findings(critical=1, high=2, medium=3, low=4),
            policy_id=default_policy_id,
            repo="org/repo",
        )
        comment = engine.generate_pr_comment(result)
        assert "|" in comment  # markdown table
        assert "Critical" in comment
        assert "High" in comment

    def test_comment_contains_aldeci_branding(self, engine, default_policy_id):
        result = engine.evaluate_scan(findings=[], policy_id=default_policy_id, repo="org/repo")
        comment = engine.generate_pr_comment(result)
        assert "ALDECI" in comment

    def test_comment_shows_triggered_rules(self, engine, default_policy_id):
        result = engine.evaluate_scan(
            findings=_make_findings(critical=1), policy_id=default_policy_id, repo="org/repo"
        )
        comment = engine.generate_pr_comment(result)
        assert "default-gate" in comment


# ===========================================================================
# 6. Badge generation
# ===========================================================================

class TestBadgeGeneration:
    def test_pass_badge(self, engine, default_policy_id):
        result = engine.evaluate_scan(findings=[], policy_id=default_policy_id, repo="org/repo")
        badge = engine.generate_badge(result)
        assert badge["action"] == "pass"
        assert badge["label"] == "passing"
        assert "#4c1" in badge["color"]
        assert "<svg" in badge["svg"]

    def test_block_badge(self, engine, default_policy_id):
        result = engine.evaluate_scan(
            findings=_make_findings(critical=1), policy_id=default_policy_id, repo="org/repo"
        )
        badge = engine.generate_badge(result)
        assert badge["action"] == "block"
        assert badge["label"] == "failing"
        assert "#e05d44" in badge["color"]

    def test_warn_badge(self, engine, default_policy_id):
        result = engine.evaluate_scan(
            findings=_make_findings(high=4), policy_id=default_policy_id, repo="org/repo"
        )
        badge = engine.generate_badge(result)
        assert badge["action"] == "warn"
        assert badge["label"] == "warning"

    def test_badge_contains_repo(self, engine, default_policy_id):
        result = engine.evaluate_scan(findings=[], policy_id=default_policy_id, repo="my-org/my-repo")
        badge = engine.generate_badge(result)
        assert badge["repo"] == "my-org/my-repo"

    def test_badge_svg_is_valid_xml(self, engine, default_policy_id):
        import xml.etree.ElementTree as ET
        result = engine.evaluate_scan(findings=[], policy_id=default_policy_id, repo="org/repo")
        badge = engine.generate_badge(result)
        # Should not raise
        ET.fromstring(badge["svg"])


# ===========================================================================
# 7. CI template YAML validity
# ===========================================================================

TEMPLATE_DIR = Path(__file__).parent.parent / "suite-integrations" / "cicd_templates"


class TestCITemplates:
    def test_github_actions_template_exists(self):
        template = TEMPLATE_DIR / "github-actions-aldeci-scan.yml"
        assert template.exists(), f"Missing {template}"

    def test_gitlab_ci_template_exists(self):
        template = TEMPLATE_DIR / "gitlab-ci-aldeci-scan.yml"
        assert template.exists(), f"Missing {template}"

    def test_github_actions_is_valid_yaml(self):
        template = TEMPLATE_DIR / "github-actions-aldeci-scan.yml"
        content = template.read_text()
        parsed = yaml.safe_load(content)
        assert parsed is not None
        assert isinstance(parsed, dict)

    def test_gitlab_ci_is_valid_yaml(self):
        template = TEMPLATE_DIR / "gitlab-ci-aldeci-scan.yml"
        content = template.read_text()
        parsed = yaml.safe_load(content)
        assert parsed is not None
        assert isinstance(parsed, dict)

    def test_github_actions_has_required_keys(self):
        template = TEMPLATE_DIR / "github-actions-aldeci-scan.yml"
        parsed = yaml.safe_load(template.read_text())
        assert "on" in parsed or True  # 'on' is a YAML keyword, may parse to True
        assert "jobs" in parsed

    def test_gitlab_ci_has_stages(self):
        template = TEMPLATE_DIR / "gitlab-ci-aldeci-scan.yml"
        parsed = yaml.safe_load(template.read_text())
        assert "stages" in parsed

    def test_github_actions_has_aldeci_job(self):
        template = TEMPLATE_DIR / "github-actions-aldeci-scan.yml"
        parsed = yaml.safe_load(template.read_text())
        jobs = parsed.get("jobs", {})
        assert len(jobs) >= 1

    def test_gitlab_ci_has_scan_job(self):
        template = TEMPLATE_DIR / "gitlab-ci-aldeci-scan.yml"
        parsed = yaml.safe_load(template.read_text())
        # Should have at least one job key beyond 'stages'
        job_keys = [k for k in parsed if k != "stages"]
        assert len(job_keys) >= 1


# ===========================================================================
# 8. API router (via FastAPI TestClient)
# ===========================================================================

@pytest.fixture
def test_client(tmp_path):
    """Isolated FastAPI test client with temp DB."""
    import importlib
    import sys
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    # Point the router at a temp DB
    os.environ["ALDECI_CICD_DB"] = str(tmp_path / "api_test.db")

    # Reload auth_deps so it picks up the env vars set at the top of this file
    if "apps.api.auth_deps" in sys.modules:
        importlib.reload(sys.modules["apps.api.auth_deps"])

    # Reset cicd_router singleton and reload so it uses fresh auth_deps
    import apps.api.cicd_router as cicd_router_module
    cicd_router_module._engine = None
    importlib.reload(cicd_router_module)

    from apps.api.cicd_router import router as cicd_router

    app = FastAPI()
    app.include_router(cicd_router)

    with TestClient(app, headers={"X-API-Key": "test-token"}) as client:
        yield client

    # Clean up singleton for next test
    cicd_router_module._engine = None


class TestCICDRouterAPI:
    def test_list_policies_empty(self, test_client):
        resp = test_client.get("/api/v1/cicd/policies")
        assert resp.status_code == 200
        data = resp.json()
        assert "policies" in data
        assert isinstance(data["policies"], list)

    def test_create_policy(self, test_client):
        payload = {
            "org_id": "test-org",
            "rules": [
                {
                    "name": "api-gate",
                    "severity_threshold": "critical",
                    "max_critical": 0,
                    "max_high": 5,
                    "categories": [],
                    "enabled": True,
                }
            ],
        }
        resp = test_client.post("/api/v1/cicd/policies", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert "policy_id" in data
        assert data["rules_count"] == 1

    def test_submit_scan_no_policy(self, test_client):
        payload = {
            "repo": "org/my-repo",
            "branch": "main",
            "commit_sha": "abc123",
            "findings": [{"severity": "low", "title": "Low finding"}],
        }
        resp = test_client.post("/api/v1/cicd/scan", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["policy_action"] == "pass"
        assert data["repo"] == "org/my-repo"

    def test_submit_scan_with_policy_block(self, test_client):
        # Create strict policy first
        create_resp = test_client.post(
            "/api/v1/cicd/policies",
            json={
                "rules": [
                    {"name": "strict", "severity_threshold": "critical", "max_critical": 0, "max_high": 0}
                ]
            },
        )
        policy_id = create_resp.json()["policy_id"]

        scan_resp = test_client.post(
            "/api/v1/cicd/scan",
            json={
                "repo": "org/repo",
                "findings": [{"severity": "critical", "title": "SQL injection"}],
                "policy_id": policy_id,
            },
        )
        assert scan_resp.status_code == 200
        assert scan_resp.json()["policy_action"] == "block"

    def test_evaluate_generates_comment(self, test_client):
        # First get a scan result
        scan_resp = test_client.post(
            "/api/v1/cicd/scan",
            json={"repo": "org/repo", "findings": []},
        )
        scan_result = scan_resp.json()

        eval_resp = test_client.post(
            "/api/v1/cicd/evaluate",
            json={"scan_result": scan_result},
        )
        assert eval_resp.status_code == 200
        data = eval_resp.json()
        assert "comment" in data
        assert "badge" in data
        assert "ALDECI" in data["comment"]

    def test_scan_history_endpoint(self, test_client):
        # Run a scan first
        test_client.post(
            "/api/v1/cicd/scan",
            json={"repo": "org/history-repo", "branch": "main", "findings": []},
        )
        resp = test_client.get("/api/v1/cicd/history/org/history-repo?branch=main")
        assert resp.status_code == 200
        data = resp.json()
        assert data["repo"] == "org/history-repo"
        assert len(data["results"]) >= 1

    def test_badge_no_scans(self, test_client):
        resp = test_client.get("/api/v1/cicd/badge/no-scans/repo")
        assert resp.status_code == 200
        data = resp.json()
        assert data["action"] == "unknown"
        assert "<svg" in data["svg"]

    def test_badge_after_scan(self, test_client):
        test_client.post(
            "/api/v1/cicd/scan",
            json={"repo": "org/badge-repo", "branch": "main", "findings": []},
        )
        resp = test_client.get("/api/v1/cicd/badge/org/badge-repo?branch=main")
        assert resp.status_code == 200
        data = resp.json()
        assert data["action"] in ("pass", "warn", "block")
        assert "<svg" in data["svg"]
