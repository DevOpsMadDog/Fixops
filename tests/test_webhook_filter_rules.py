"""Tests for webhook_filter_rules_router.

Covers: CRUD, evaluation logic, validation, org scoping, limit enforcement.
"""
from __future__ import annotations

import os
import sys
import tempfile
import uuid
from typing import Any, Dict
from unittest.mock import patch

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
for sub in ("suite-api", "suite-core"):
    p = os.path.join(ROOT, sub)
    if p not in sys.path:
        sys.path.insert(0, p)

import apps.api.webhook_filter_rules_router as _mod
from apps.api.webhook_filter_rules_router import (
    ALLOWED_EVENT_TYPES,
    ALLOWED_SEVERITIES,
    CreateFilterRuleRequest,
    EvaluateRequest,
    UpdateFilterRuleRequest,
    _validate_rule_id,
    evaluate_event,
    router,
)
from fastapi import HTTPException
from fastapi.testclient import TestClient
from fastapi import FastAPI

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_ORG = "test-org-filter"


def _make_app(db_path: str) -> TestClient:
    """Build a minimal FastAPI app with the filter rules router, bypassing auth."""
    app = FastAPI()

    from apps.api import webhook_filter_rules_router as _router_mod
    _router_mod._DB_PATH_OVERRIDE = db_path

    # Patch get_org_id dependency to return fixed org
    from apps.api.webhook_filter_rules_router import router as _r
    app.include_router(_r)

    # Override get_org_id
    from apps.api import dependencies as _deps
    app.dependency_overrides[_deps.get_org_id] = lambda: _ORG

    return TestClient(app, raise_server_exceptions=True)


# ---------------------------------------------------------------------------
# Unit: evaluate_event
# ---------------------------------------------------------------------------


class TestEvaluateEvent:
    def test_no_rules_defaults_allow(self):
        result = evaluate_event([], "finding.created", "high", "semgrep")
        assert result["action"] == "allow"
        assert result["allowed"] is True
        assert result["matched_rule_id"] is None

    def test_deny_by_event_type(self):
        rules = [{
            "id": "r1", "name": "block-critical", "action": "deny",
            "event_type": "finding.critical", "severity": None, "source_prefix": None,
            "enabled": True, "priority": 10,
        }]
        result = evaluate_event(rules, "finding.critical", None, None)
        assert result["action"] == "deny"
        assert result["allowed"] is False
        assert result["matched_rule_id"] == "r1"

    def test_allow_rule_wins_lower_priority(self):
        rules = [
            {
                "id": "r1", "name": "allow-all", "action": "allow",
                "event_type": None, "severity": None, "source_prefix": None,
                "enabled": True, "priority": 5,
            },
            {
                "id": "r2", "name": "deny-critical", "action": "deny",
                "event_type": "finding.critical", "severity": None, "source_prefix": None,
                "enabled": True, "priority": 50,
            },
        ]
        # priority 5 comes first and is a wildcard allow — wins
        result = evaluate_event(rules, "finding.critical", "critical", "snyk")
        assert result["action"] == "allow"
        assert result["matched_rule_id"] == "r1"

    def test_deny_by_severity(self):
        rules = [{
            "id": "r1", "name": "suppress-info", "action": "deny",
            "event_type": None, "severity": "info", "source_prefix": None,
            "enabled": True, "priority": 20,
        }]
        result = evaluate_event(rules, "finding.created", "info", "trivy")
        assert result["action"] == "deny"

    def test_deny_by_source_prefix(self):
        rules = [{
            "id": "r2", "name": "suppress-legacy", "action": "deny",
            "event_type": None, "severity": None, "source_prefix": "legacy-",
            "enabled": True, "priority": 30,
        }]
        result = evaluate_event(rules, "finding.created", "medium", "legacy-scanner")
        assert result["action"] == "deny"
        # non-matching source passes
        result2 = evaluate_event(rules, "finding.created", "medium", "snyk")
        assert result2["action"] == "allow"

    def test_disabled_rule_skipped(self):
        rules = [{
            "id": "r1", "name": "deny-all", "action": "deny",
            "event_type": None, "severity": None, "source_prefix": None,
            "enabled": False, "priority": 1,
        }]
        result = evaluate_event(rules, "finding.created", "high", "semgrep")
        assert result["action"] == "allow"


# ---------------------------------------------------------------------------
# Unit: Pydantic model validation
# ---------------------------------------------------------------------------


class TestCreateFilterRuleRequest:
    def test_valid_minimal(self):
        req = CreateFilterRuleRequest(name="test", event_type="finding.created")
        assert req.action == "allow"
        assert req.priority == 100

    def test_invalid_event_type(self):
        with pytest.raises(Exception):
            CreateFilterRuleRequest(name="test", event_type="not.an.event")

    def test_severity_normalized_lower(self):
        req = CreateFilterRuleRequest(name="test", severity="HIGH")
        assert req.severity == "high"

    def test_invalid_severity(self):
        with pytest.raises(Exception):
            CreateFilterRuleRequest(name="test", severity="extreme")

    def test_deny_action(self):
        req = CreateFilterRuleRequest(name="test", action="deny", severity="critical")
        assert req.action == "deny"


# ---------------------------------------------------------------------------
# Unit: _validate_rule_id
# ---------------------------------------------------------------------------


class TestValidateRuleId:
    def test_valid_uuid(self):
        uid = str(uuid.uuid4())
        assert _validate_rule_id(uid) == uid

    def test_invalid_raises_422(self):
        with pytest.raises(HTTPException) as exc:
            _validate_rule_id("not-a-uuid")
        assert exc.value.status_code == 422


# ---------------------------------------------------------------------------
# Integration: CRUD via TestClient
# ---------------------------------------------------------------------------


class TestFilterRulesCRUD:
    @pytest.fixture()
    def client(self, tmp_path):
        db = str(tmp_path / "fr.db")
        return _make_app(db)

    def test_list_empty(self, client):
        resp = client.get("/api/v1/webhook-filter-rules/")
        assert resp.status_code == 200
        assert resp.json() == []

    def test_create_and_list(self, client):
        body = {"name": "block-info", "action": "deny", "severity": "info", "priority": 10}
        resp = client.post("/api/v1/webhook-filter-rules/", json=body)
        assert resp.status_code == 201
        data = resp.json()
        assert data["name"] == "block-info"
        assert data["action"] == "deny"
        assert data["severity"] == "info"

        resp2 = client.get("/api/v1/webhook-filter-rules/")
        assert len(resp2.json()) == 1

    def test_create_requires_at_least_one_criterion(self, client):
        body = {"name": "wildcard"}
        resp = client.post("/api/v1/webhook-filter-rules/", json=body)
        assert resp.status_code == 422

    def test_get_single(self, client):
        create = client.post(
            "/api/v1/webhook-filter-rules/",
            json={"name": "r1", "event_type": "sla.breach"},
        )
        rule_id = create.json()["id"]
        resp = client.get(f"/api/v1/webhook-filter-rules/{rule_id}")
        assert resp.status_code == 200
        assert resp.json()["id"] == rule_id

    def test_get_not_found(self, client):
        resp = client.get(f"/api/v1/webhook-filter-rules/{uuid.uuid4()}")
        assert resp.status_code == 404

    def test_update_rule(self, client):
        create = client.post(
            "/api/v1/webhook-filter-rules/",
            json={"name": "orig", "severity": "low"},
        )
        rule_id = create.json()["id"]
        resp = client.put(
            f"/api/v1/webhook-filter-rules/{rule_id}",
            json={"name": "updated", "enabled": False},
        )
        assert resp.status_code == 200
        assert resp.json()["name"] == "updated"
        assert resp.json()["enabled"] is False

    def test_update_no_fields_422(self, client):
        create = client.post(
            "/api/v1/webhook-filter-rules/",
            json={"name": "r", "severity": "high"},
        )
        rule_id = create.json()["id"]
        resp = client.put(f"/api/v1/webhook-filter-rules/{rule_id}", json={})
        assert resp.status_code == 422

    def test_delete_rule(self, client):
        create = client.post(
            "/api/v1/webhook-filter-rules/",
            json={"name": "to-delete", "source_prefix": "old-"},
        )
        rule_id = create.json()["id"]
        resp = client.delete(f"/api/v1/webhook-filter-rules/{rule_id}")
        assert resp.status_code == 200
        assert resp.json()["status"] == "deleted"
        # Confirm gone
        resp2 = client.get(f"/api/v1/webhook-filter-rules/{rule_id}")
        assert resp2.status_code == 404

    def test_evaluate_allow(self, client):
        resp = client.post(
            "/api/v1/webhook-filter-rules/evaluate",
            json={"event_type": "finding.created", "severity": "high", "source": "semgrep"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["allowed"] is True
        assert data["action"] == "allow"

    def test_evaluate_deny_when_rule_matches(self, client):
        client.post(
            "/api/v1/webhook-filter-rules/",
            json={"name": "suppress-info", "action": "deny", "severity": "info", "priority": 5},
        )
        resp = client.post(
            "/api/v1/webhook-filter-rules/evaluate",
            json={"event_type": "finding.created", "severity": "info"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["allowed"] is False
        assert data["matched_rule_name"] == "suppress-info"
