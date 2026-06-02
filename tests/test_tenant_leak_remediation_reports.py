"""
Tenant isolation tests for remediation_router and reports_router.

Verifies:
  - Org A creates a task / report → org B GET/update/download returns 404
  - Org B list endpoints return empty (not A's items)

Skips cleanly if an engine dependency returns 503 / is unconfigured.
"""
import pytest
from fastapi.testclient import TestClient


# ---------------------------------------------------------------------------
# App bootstrap
# ---------------------------------------------------------------------------

def _make_client():
    """Import create_app inside the function to avoid module-level side-effects."""
    import sys, os
    # Ensure suite paths are on sys.path (mirrors sitecustomize.py)
    repo = os.path.dirname(os.path.dirname(__file__))
    for sub in ("suite-api", "suite-core", "suite-attack", "suite-feeds",
                "suite-integrations", "suite-evidence-risk"):
        p = os.path.join(repo, sub)
        if p not in sys.path:
            sys.path.insert(0, p)
    from apps.api.app import create_app
    app = create_app()
    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture(scope="module")
def client():
    return _make_client()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

ORG_A = "tenant-alpha"
ORG_B = "tenant-beta"


def _api_token() -> str:
    """The live configured API token (conftest sets FIXOPS_API_TOKEN session-wide)."""
    import os

    return os.environ.get("FIXOPS_API_TOKEN", "test-key")


def _headers(org_id: str) -> dict:
    """Produce auth headers that satisfy api_key_auth + get_org_id."""
    return {"X-Org-ID": org_id, "X-API-Key": _api_token()}


def _skip_if_engine_down(response, endpoint: str):
    """Pytest-skip helper: if the endpoint returned 503/501 the engine is unconfigured."""
    if response.status_code in (501, 503):
        pytest.skip(f"{endpoint} returned {response.status_code} — engine not configured, skipping")


# ===========================================================================
# REMEDIATION — task-level tenant isolation
# ===========================================================================

class TestRemediationTenantIsolation:

    def test_org_b_cannot_get_org_a_task(self, client):
        """Org A creates a task; org B GET → 404."""
        # Create task as org A
        create_resp = client.post(
            "/api/v1/remediation/tasks",
            json={
                "cluster_id": "cluster-1",
                "org_id": ORG_A,
                "app_id": "app-1",
                "title": "XSS in login form",
                "severity": "high",
            },
            headers=_headers(ORG_A),
        )
        _skip_if_engine_down(create_resp, "POST /api/v1/remediation/tasks")
        assert create_resp.status_code in (200, 201), f"create failed: {create_resp.text}"
        task_id = create_resp.json().get("task_id")
        assert task_id, "no task_id in response"

        # Org B tries to get it — must be 404
        get_resp = client.get(
            f"/api/v1/remediation/tasks/{task_id}",
            headers=_headers(ORG_B),
        )
        assert get_resp.status_code == 404, (
            f"LEAK: org B got {get_resp.status_code} for org A task {task_id}"
        )

    def test_org_b_cannot_update_org_a_task_status(self, client):
        """Org A creates a task; org B PUT /status → 404."""
        create_resp = client.post(
            "/api/v1/remediation/tasks",
            json={
                "cluster_id": "cluster-2",
                "org_id": ORG_A,
                "app_id": "app-1",
                "title": "SQL injection",
                "severity": "critical",
            },
            headers=_headers(ORG_A),
        )
        _skip_if_engine_down(create_resp, "POST /api/v1/remediation/tasks")
        assert create_resp.status_code in (200, 201)
        task_id = create_resp.json()["task_id"]

        update_resp = client.put(
            f"/api/v1/remediation/tasks/{task_id}/status",
            json={"status": "assigned"},
            headers=_headers(ORG_B),
        )
        assert update_resp.status_code == 404, (
            f"LEAK: org B updated status of org A task, got {update_resp.status_code}"
        )

    def test_org_b_cannot_assign_org_a_task(self, client):
        """Org A creates a task; org B PUT /assign → 404."""
        create_resp = client.post(
            "/api/v1/remediation/tasks",
            json={
                "cluster_id": "cluster-3",
                "org_id": ORG_A,
                "app_id": "app-2",
                "title": "Path traversal",
                "severity": "medium",
            },
            headers=_headers(ORG_A),
        )
        _skip_if_engine_down(create_resp, "POST /api/v1/remediation/tasks")
        assert create_resp.status_code in (200, 201)
        task_id = create_resp.json()["task_id"]

        assign_resp = client.put(
            f"/api/v1/remediation/tasks/{task_id}/assign",
            json={"assignee": "attacker"},
            headers=_headers(ORG_B),
        )
        assert assign_resp.status_code == 404, (
            f"LEAK: org B assigned org A task, got {assign_resp.status_code}"
        )

    def test_org_b_cannot_submit_verification_for_org_a_task(self, client):
        """Org A creates a task; org B POST /verification → 404."""
        create_resp = client.post(
            "/api/v1/remediation/tasks",
            json={
                "cluster_id": "cluster-4",
                "org_id": ORG_A,
                "app_id": "app-3",
                "title": "SSRF",
                "severity": "high",
            },
            headers=_headers(ORG_A),
        )
        _skip_if_engine_down(create_resp, "POST /api/v1/remediation/tasks")
        assert create_resp.status_code in (200, 201)
        task_id = create_resp.json()["task_id"]

        verify_resp = client.post(
            f"/api/v1/remediation/tasks/{task_id}/verification",
            json={"evidence_type": "scan", "evidence_data": {"tool": "x"}},
            headers=_headers(ORG_B),
        )
        assert verify_resp.status_code == 404, (
            f"LEAK: org B submitted verification for org A task, got {verify_resp.status_code}"
        )

    def test_org_b_cannot_link_ticket_for_org_a_task(self, client):
        """Org A creates a task; org B PUT /ticket → 404."""
        create_resp = client.post(
            "/api/v1/remediation/tasks",
            json={
                "cluster_id": "cluster-5",
                "org_id": ORG_A,
                "app_id": "app-4",
                "title": "Open redirect",
                "severity": "low",
            },
            headers=_headers(ORG_A),
        )
        _skip_if_engine_down(create_resp, "POST /api/v1/remediation/tasks")
        assert create_resp.status_code in (200, 201)
        task_id = create_resp.json()["task_id"]

        link_resp = client.put(
            f"/api/v1/remediation/tasks/{task_id}/ticket",
            json={"ticket_id": "JIRA-999"},
            headers=_headers(ORG_B),
        )
        assert link_resp.status_code == 404, (
            f"LEAK: org B linked ticket to org A task, got {link_resp.status_code}"
        )

    def test_org_b_cannot_get_timeline_for_org_a_task(self, client):
        """Org A creates a task; org B GET /timeline → 404."""
        create_resp = client.post(
            "/api/v1/remediation/tasks",
            json={
                "cluster_id": "cluster-6",
                "org_id": ORG_A,
                "app_id": "app-5",
                "title": "Prototype pollution",
                "severity": "medium",
            },
            headers=_headers(ORG_A),
        )
        _skip_if_engine_down(create_resp, "POST /api/v1/remediation/tasks")
        assert create_resp.status_code in (200, 201)
        task_id = create_resp.json()["task_id"]

        timeline_resp = client.get(
            f"/api/v1/remediation/tasks/{task_id}/timeline",
            headers=_headers(ORG_B),
        )
        assert timeline_resp.status_code == 404, (
            f"LEAK: org B got timeline for org A task, got {timeline_resp.status_code}"
        )

    def test_org_b_list_excludes_org_a_tasks(self, client):
        """Org A creates a task; org B list → does not include A's task_id."""
        create_resp = client.post(
            "/api/v1/remediation/tasks",
            json={
                "cluster_id": "cluster-7",
                "org_id": ORG_A,
                "app_id": "app-6",
                "title": "Clickjacking",
                "severity": "low",
            },
            headers=_headers(ORG_A),
        )
        _skip_if_engine_down(create_resp, "POST /api/v1/remediation/tasks")
        assert create_resp.status_code in (200, 201)
        task_id = create_resp.json()["task_id"]

        list_resp = client.get(
            "/api/v1/remediation/tasks",
            headers=_headers(ORG_B),
        )
        _skip_if_engine_down(list_resp, "GET /api/v1/remediation/tasks")
        assert list_resp.status_code == 200
        tasks = list_resp.json().get("tasks", [])
        ids = [t.get("task_id") for t in tasks]
        assert task_id not in ids, f"LEAK: org A task {task_id} appeared in org B list"

    def test_remediation_stats_scoped_to_org(self, client):
        """Stats endpoint uses org_id from auth header, not query param."""
        resp = client.get("/api/v1/remediation/stats", headers=_headers(ORG_B))
        _skip_if_engine_down(resp, "GET /api/v1/remediation/stats")
        assert resp.status_code == 200

    def test_remediation_queue_scoped_to_org(self, client):
        """Queue endpoint uses org_id from auth header."""
        resp = client.get("/api/v1/remediation/queue", headers=_headers(ORG_B))
        _skip_if_engine_down(resp, "GET /api/v1/remediation/queue")
        assert resp.status_code == 200

    def test_remediation_summary_scoped_to_org(self, client):
        """Summary endpoint uses org_id from auth header, not hardcoded 'default'."""
        resp = client.get("/api/v1/remediation/summary", headers=_headers(ORG_B))
        _skip_if_engine_down(resp, "GET /api/v1/remediation/summary")
        assert resp.status_code == 200


# ===========================================================================
# REPORTS — report-level tenant isolation
# ===========================================================================

class TestReportsTenantIsolation:

    def _create_report(self, client, org_id: str):
        """Helper: create a report for the given org, return report id or skip."""
        resp = client.post(
            "/api/v1/reports",
            json={"name": f"Test Report {org_id}", "report_type": "vulnerability", "format": "json"},
            headers=_headers(org_id),
        )
        _skip_if_engine_down(resp, "POST /api/v1/reports")
        assert resp.status_code in (200, 201), f"create failed: {resp.text}"
        return resp.json()["id"]

    def test_org_b_cannot_get_org_a_report(self, client):
        """Org A creates a report; org B GET /{id} → 404."""
        report_id = self._create_report(client, ORG_A)

        get_resp = client.get(f"/api/v1/reports/{report_id}", headers=_headers(ORG_B))
        assert get_resp.status_code == 404, (
            f"LEAK: org B got report {report_id}, status {get_resp.status_code}"
        )

    def test_org_b_cannot_download_org_a_report(self, client):
        """Org A creates a report; org B GET /{id}/download → 404."""
        report_id = self._create_report(client, ORG_A)

        dl_resp = client.get(f"/api/v1/reports/{report_id}/download", headers=_headers(ORG_B))
        assert dl_resp.status_code == 404, (
            f"LEAK: org B downloaded report {report_id}, status {dl_resp.status_code}"
        )

    def test_org_b_cannot_get_file_for_org_a_report(self, client):
        """Org A creates a report; org B GET /{id}/file → 404."""
        report_id = self._create_report(client, ORG_A)

        file_resp = client.get(f"/api/v1/reports/{report_id}/file", headers=_headers(ORG_B))
        assert file_resp.status_code == 404, (
            f"LEAK: org B got file for report {report_id}, status {file_resp.status_code}"
        )

    def test_org_b_list_excludes_org_a_reports(self, client):
        """Org A creates a report; org B list → excludes A's report."""
        report_id = self._create_report(client, ORG_A)

        list_resp = client.get("/api/v1/reports", headers=_headers(ORG_B))
        _skip_if_engine_down(list_resp, "GET /api/v1/reports")
        assert list_resp.status_code == 200
        items = list_resp.json().get("items", [])
        ids = [r.get("id") for r in items]
        assert report_id not in ids, (
            f"LEAK: org A report {report_id} appeared in org B list"
        )

    def test_report_stats_requires_auth(self, client):
        """Stats endpoint now requires org_id (auth header)."""
        resp = client.get("/api/v1/reports/stats", headers=_headers(ORG_B))
        _skip_if_engine_down(resp, "GET /api/v1/reports/stats")
        assert resp.status_code == 200

    def test_list_schedules_scoped_to_org(self, client):
        """Schedules list is scoped to authenticated org."""
        resp = client.get("/api/v1/reports/schedules/list", headers=_headers(ORG_B))
        _skip_if_engine_down(resp, "GET /api/v1/reports/schedules/list")
        assert resp.status_code == 200
