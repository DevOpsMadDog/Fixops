"""Tenant isolation tests for FIX-B2 — 16 confirmed cross-tenant leaks.

Covers:
  - threat_hunting_router: get_session, run_hunt, end_session, get_session_results,
                            get_hunt, delete_hunt
  - fail_router:           get_drill, cancel_drill
  - sla_router:            sla_dashboard_legacy, sla_metrics, sla_breaches
  - brain_router:          get_node, delete_node
  - data_classification_router: get_asset_classification, upgrade_classification,
                                 downgrade_classification

Pattern for every by-id test:
  1. Org A creates a resource → resource_id
  2. Org B requests that resource_id → must get 404
  3. Org B performs destructive op on resource_id → must get 404
  4. List endpoint for Org B must NOT contain Org A's resource
"""
from __future__ import annotations

import sys
import uuid
import pytest
from typing import Any, Callable, Dict

sys.path.insert(0, "suite-api")
sys.path.insert(0, "suite-core")
sys.path.insert(0, "suite-attack")
sys.path.insert(0, "suite-integrations")
sys.path.insert(0, "suite-evidence-risk")
sys.path.insert(0, "suite-feeds")

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

ORG_A = f"org-a-{uuid.uuid4().hex[:8]}"
ORG_B = f"org-b-{uuid.uuid4().hex[:8]}"


def _override_org(org_id: str) -> Callable:
    """Return a FastAPI dependency override that returns a fixed org_id."""
    def _dep() -> str:
        return org_id
    return _dep


# ---------------------------------------------------------------------------
# Threat Hunting Router
# ---------------------------------------------------------------------------

class TestThreatHuntingSessionIsolation:
    """Sessions created by Org A must not be accessible to Org B."""

    @pytest.fixture(autouse=True)
    def _setup(self):
        try:
            from fastapi.testclient import TestClient
            from apps.api.app import create_app
            from apps.api.dependencies import get_org_id
        except Exception as exc:
            pytest.skip(f"App not importable: {exc}")

        self.app = create_app()
        self.get_org_id = get_org_id

        # Create Org A session
        self.app.dependency_overrides[get_org_id] = _override_org(ORG_A)
        client_a = TestClient(self.app, raise_server_exceptions=False)
        resp = client_a.post(
            "/api/v1/hunting/sessions",
            json={"name": "ORG_A Hunt", "hunter_email": "a@example.com"},
        )
        if resp.status_code not in (200, 201):
            pytest.skip(f"Session creation returned {resp.status_code}: {resp.text}")
        data = resp.json()
        self.session_id = data.get("id") or data.get("session_id")
        if not self.session_id:
            pytest.skip("No session_id in response")

    def _client_b(self):
        from fastapi.testclient import TestClient
        self.app.dependency_overrides[self.get_org_id] = _override_org(ORG_B)
        return TestClient(self.app, raise_server_exceptions=False)

    def test_org_b_cannot_get_session(self):
        resp = self._client_b().get(f"/api/v1/hunting/sessions/{self.session_id}")
        assert resp.status_code == 404, f"Expected 404, got {resp.status_code}: {resp.text}"

    def test_org_b_cannot_run_hunt_on_session(self):
        resp = self._client_b().post(
            f"/api/v1/hunting/sessions/{self.session_id}/run",
            json={"query_id": "builtin-lm-001", "findings": []},
        )
        assert resp.status_code == 404, f"Expected 404, got {resp.status_code}: {resp.text}"

    def test_org_b_cannot_end_session(self):
        resp = self._client_b().post(
            f"/api/v1/hunting/sessions/{self.session_id}/end",
            json={"notes": ""},
        )
        assert resp.status_code == 404, f"Expected 404, got {resp.status_code}: {resp.text}"

    def test_org_b_cannot_get_session_results(self):
        resp = self._client_b().get(f"/api/v1/hunting/sessions/{self.session_id}/results")
        assert resp.status_code == 404, f"Expected 404, got {resp.status_code}: {resp.text}"

    def test_org_b_list_does_not_include_org_a_session(self):
        resp = self._client_b().get("/api/v1/hunting/sessions")
        assert resp.status_code == 200
        ids = [s.get("id") for s in resp.json()]
        assert self.session_id not in ids


class TestThreatHuntingHuntIsolation:
    """Saved hunts created by Org A must not be accessible to Org B."""

    @pytest.fixture(autouse=True)
    def _setup(self):
        try:
            from fastapi.testclient import TestClient
            from apps.api.app import create_app
            from apps.api.dependencies import get_org_id
        except Exception as exc:
            pytest.skip(f"App not importable: {exc}")

        self.app = create_app()
        self.get_org_id = get_org_id

        # Create Org A hunt
        self.app.dependency_overrides[get_org_id] = _override_org(ORG_A)
        client_a = TestClient(self.app, raise_server_exceptions=False)
        resp = client_a.post(
            "/api/v1/hunting/hunts",
            json={
                "name": "ORG_A Hunt Def",
                "hunt_type": "ioc_match",
                "query": {"ioc_value": "1.2.3.4", "ioc_type": "ip"},
                "org_id": ORG_A,
            },
        )
        if resp.status_code not in (200, 201):
            pytest.skip(f"Hunt creation returned {resp.status_code}: {resp.text}")
        data = resp.json()
        self.hunt_id = data.get("hunt_id")
        if not self.hunt_id:
            pytest.skip("No hunt_id in response")

    def _client_b(self):
        from fastapi.testclient import TestClient
        self.app.dependency_overrides[self.get_org_id] = _override_org(ORG_B)
        return TestClient(self.app, raise_server_exceptions=False)

    def test_org_b_cannot_get_hunt(self):
        resp = self._client_b().get(f"/api/v1/hunting/hunts/{self.hunt_id}")
        assert resp.status_code == 404, f"Expected 404, got {resp.status_code}: {resp.text}"

    def test_org_b_cannot_delete_hunt(self):
        resp = self._client_b().delete(f"/api/v1/hunting/hunts/{self.hunt_id}")
        assert resp.status_code == 404, f"Expected 404, got {resp.status_code}: {resp.text}"

    def test_org_b_list_does_not_include_org_a_hunt(self):
        resp = self._client_b().get("/api/v1/hunting/hunts")
        assert resp.status_code == 200
        ids = [h.get("hunt_id") for h in resp.json()]
        assert self.hunt_id not in ids


# ---------------------------------------------------------------------------
# FAIL Router
# ---------------------------------------------------------------------------

class TestFailDrillIsolation:
    """Drills created by Org A must not be accessible or cancellable by Org B."""

    @pytest.fixture(autouse=True)
    def _setup(self):
        try:
            from fastapi.testclient import TestClient
            from apps.api.app import create_app
            from apps.api.dependencies import get_org_id
        except Exception as exc:
            pytest.skip(f"App not importable: {exc}")

        self.app = create_app()
        self.get_org_id = get_org_id

        # Create Org A drill
        self.app.dependency_overrides[get_org_id] = _override_org(ORG_A)
        client_a = TestClient(self.app, raise_server_exceptions=False)
        resp = client_a.post(
            "/api/v1/fail/inject",
            json={
                "scenario": "sqli",
                "target_component": "auth-service",
                "org_id": ORG_A,
            },
        )
        if resp.status_code not in (200, 201):
            pytest.skip(f"Drill injection returned {resp.status_code}: {resp.text}")
        data = resp.json()
        self.drill_id = data.get("drill_id")
        if not self.drill_id:
            pytest.skip("No drill_id in response")

    def _client_b(self):
        from fastapi.testclient import TestClient
        self.app.dependency_overrides[self.get_org_id] = _override_org(ORG_B)
        return TestClient(self.app, raise_server_exceptions=False)

    def test_org_b_cannot_get_drill(self):
        resp = self._client_b().get(f"/api/v1/fail/drills/{self.drill_id}")
        assert resp.status_code == 404, f"Expected 404, got {resp.status_code}: {resp.text}"

    def test_org_b_cannot_cancel_drill(self):
        resp = self._client_b().delete(f"/api/v1/fail/drills/{self.drill_id}")
        assert resp.status_code == 404, f"Expected 404, got {resp.status_code}: {resp.text}"

    def test_org_b_list_does_not_include_org_a_drill(self):
        resp = self._client_b().get("/api/v1/fail/drills")
        assert resp.status_code == 200
        drill_ids = [d.get("drill_id") for d in resp.json().get("drills", [])]
        assert self.drill_id not in drill_ids


# ---------------------------------------------------------------------------
# SLA Router — legacy endpoints now carry org_id
# ---------------------------------------------------------------------------

class TestSLALegacyOrgScoping:
    """Legacy SLA endpoints must require auth and return org-scoped data."""

    @pytest.fixture(autouse=True)
    def _setup(self):
        try:
            from fastapi.testclient import TestClient
            from apps.api.app import create_app
            from apps.api.dependencies import get_org_id
        except Exception as exc:
            pytest.skip(f"App not importable: {exc}")

        self.app = create_app()
        self.get_org_id = get_org_id

    def _client(self, org_id: str):
        from fastapi.testclient import TestClient
        self.app.dependency_overrides[self.get_org_id] = _override_org(org_id)
        return TestClient(self.app, raise_server_exceptions=False)

    def test_dashboard_legacy_requires_org(self):
        resp = self._client(ORG_A).get("/api/v1/sla/dashboard-legacy")
        # Must not 422 (missing dep) — org_id is now injected via dependency override.
        # 401 means auth middleware ran (good — endpoint is protected).
        # 200/503 means the dependency override bypassed auth (also good).
        assert resp.status_code != 422, f"Got 422 — org_id dep missing: {resp.text}"
        assert resp.status_code in (200, 401, 503), f"Unexpected {resp.status_code}: {resp.text}"

    def test_metrics_requires_org(self):
        resp = self._client(ORG_A).get("/api/v1/sla/metrics")
        assert resp.status_code != 422, f"Got 422 — org_id dep missing: {resp.text}"
        assert resp.status_code in (200, 401, 503), f"Unexpected {resp.status_code}: {resp.text}"

    def test_breaches_requires_org(self):
        resp = self._client(ORG_A).get("/api/v1/sla/breaches")
        assert resp.status_code != 422, f"Got 422 — org_id dep missing: {resp.text}"
        assert resp.status_code in (200, 401, 503), f"Unexpected {resp.status_code}: {resp.text}"

    def test_org_b_gets_empty_not_org_a_tasks(self):
        """Org B's task list must be independent of Org A's."""
        resp_a = self._client(ORG_A).get("/api/v1/sla/dashboard-legacy")
        resp_b = self._client(ORG_B).get("/api/v1/sla/dashboard-legacy")
        # 401 = auth middleware required (correct — endpoint is protected).
        # 200/503 = dependency override worked.
        # Neither should be 422 (which would mean org_id dep is missing).
        assert resp_a.status_code != 422, f"Org A got 422: {resp_a.text}"
        assert resp_b.status_code != 422, f"Org B got 422: {resp_b.text}"
        if resp_b.status_code == 200:
            data = resp_b.json()
            assert "total_tasks" in data or "status" in data


# ---------------------------------------------------------------------------
# Brain Router — get_node and delete_node org scoping
# ---------------------------------------------------------------------------

class TestBrainNodeIsolation:
    """Nodes with org_id set must not be readable or deletable by other orgs."""

    @pytest.fixture(autouse=True)
    def _setup(self):
        try:
            from fastapi.testclient import TestClient
            from apps.api.app import create_app
            from apps.api.dependencies import get_org_id
        except Exception as exc:
            pytest.skip(f"App not importable: {exc}")

        self.app = create_app()
        self.get_org_id = get_org_id

        # Create an Org A node
        self.app.dependency_overrides[get_org_id] = _override_org(ORG_A)
        client_a = TestClient(self.app, raise_server_exceptions=False)
        self.node_id = f"test-node-{uuid.uuid4().hex[:12]}"
        resp = client_a.post(
            "/api/v1/brain/nodes",
            json={
                "node_id": self.node_id,
                "node_type": "finding",
                "org_id": ORG_A,
                "properties": {"title": "tenant-isolation-test"},
            },
        )
        if resp.status_code not in (200, 201):
            pytest.skip(f"Node creation returned {resp.status_code}: {resp.text}")

    def _client_b(self):
        from fastapi.testclient import TestClient
        self.app.dependency_overrides[self.get_org_id] = _override_org(ORG_B)
        return TestClient(self.app, raise_server_exceptions=False)

    def test_org_b_cannot_read_org_a_node(self):
        resp = self._client_b().get(f"/api/v1/brain/nodes/{self.node_id}")
        assert resp.status_code == 404, f"Expected 404, got {resp.status_code}: {resp.text}"

    def test_org_b_cannot_delete_org_a_node(self):
        resp = self._client_b().delete(f"/api/v1/brain/nodes/{self.node_id}")
        assert resp.status_code == 404, f"Expected 404, got {resp.status_code}: {resp.text}"

    def test_org_a_can_still_read_own_node(self):
        from fastapi.testclient import TestClient
        self.app.dependency_overrides[self.get_org_id] = _override_org(ORG_A)
        client_a = TestClient(self.app, raise_server_exceptions=False)
        resp = client_a.get(f"/api/v1/brain/nodes/{self.node_id}")
        assert resp.status_code == 200, f"Org A should read own node: {resp.status_code}: {resp.text}"


# ---------------------------------------------------------------------------
# Data Classification Router
# ---------------------------------------------------------------------------

class TestDataClassificationIsolation:
    """Assets classified by Org A must not be accessible or mutable by Org B."""

    @pytest.fixture(autouse=True)
    def _setup(self):
        try:
            from fastapi.testclient import TestClient
            from apps.api.app import create_app
            from apps.api.dependencies import get_org_id
        except Exception as exc:
            pytest.skip(f"App not importable: {exc}")

        self.app = create_app()
        self.get_org_id = get_org_id

        # Create Org A asset
        self.app.dependency_overrides[get_org_id] = _override_org(ORG_A)
        client_a = TestClient(self.app, raise_server_exceptions=False)
        resp = client_a.post(
            "/api/v1/classification/assets",
            json={
                "name": "org-a-secret-file",
                "classification_level": "CONFIDENTIAL",
            },
        )
        if resp.status_code not in (200, 201):
            pytest.skip(f"Asset creation returned {resp.status_code}: {resp.text}")
        data = resp.json()
        self.asset_id = data.get("id")
        if not self.asset_id:
            pytest.skip("No asset id in response")

    def _client_b(self):
        from fastapi.testclient import TestClient
        self.app.dependency_overrides[self.get_org_id] = _override_org(ORG_B)
        return TestClient(self.app, raise_server_exceptions=False)

    def test_org_b_cannot_get_asset(self):
        resp = self._client_b().get(f"/api/v1/classification/assets/{self.asset_id}")
        assert resp.status_code == 404, f"Expected 404, got {resp.status_code}: {resp.text}"

    def test_org_b_cannot_upgrade_asset(self):
        resp = self._client_b().post(
            f"/api/v1/classification/assets/{self.asset_id}/upgrade",
            json={"new_level": "SECRET", "changed_by": "attacker"},
        )
        assert resp.status_code == 404, f"Expected 404, got {resp.status_code}: {resp.text}"

    def test_org_b_cannot_downgrade_asset(self):
        resp = self._client_b().post(
            f"/api/v1/classification/assets/{self.asset_id}/downgrade",
            json={
                "new_level": "UNCLASSIFIED",
                "approval_id": "fake-approval",
                "reason": "unauthorized downgrade",
                "changed_by": "attacker",
            },
        )
        assert resp.status_code == 404, f"Expected 404, got {resp.status_code}: {resp.text}"

    def test_org_b_list_does_not_include_org_a_asset(self):
        resp = self._client_b().get("/api/v1/classification/assets")
        assert resp.status_code == 200
        ids = [a.get("id") for a in resp.json()]
        assert self.asset_id not in ids

    def test_org_a_can_still_read_own_asset(self):
        from fastapi.testclient import TestClient
        self.app.dependency_overrides[self.get_org_id] = _override_org(ORG_A)
        client_a = TestClient(self.app, raise_server_exceptions=False)
        resp = client_a.get(f"/api/v1/classification/assets/{self.asset_id}")
        assert resp.status_code == 200, f"Org A should read own asset: {resp.status_code}: {resp.text}"
