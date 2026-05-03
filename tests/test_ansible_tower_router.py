"""Router-level HTTP tests for Ansible Tower / AWX pass-through API.

Covers /api/v1/ansible-tower/* via FastAPI TestClient with a stub httpx.Client
so no real Tower call is made.

Tests:
1.  GET  /                                         capability summary unavailable when env unset
2.  GET  /                                         capability summary ok when env set
3.  GET  /api/v2/inventories                       list inventories with pagination + search
4.  GET  /api/v2/job_templates                     list job templates
5.  POST /api/v2/job_templates/{id}/launch         launch returns {job:{...}}
6.  GET  /api/v2/jobs/{id}                         fetch job
7.  GET  /api/v2/jobs/{id}/job_events              stream job events
8.  GET  /api/v2/projects                          list projects
9.  GET  /api/v2/credentials                       list credentials
10. GET  /api/v2/inventories                       503 when env unset
11. GET  /api/v2/jobs/{id}                         upstream 404 surfaces as 404 with payload echo
12. POST launch                                    bearer auth header attached
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx
import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

# Ensure suite paths are importable regardless of cwd
for _p in ["suite-core", "suite-api"]:
    _abs = str(Path(__file__).parent.parent / _p)
    if _abs not in sys.path:
        sys.path.insert(0, _abs)

import apps.api.ansible_tower_router as _router_mod
from apps.api.ansible_tower_router import router
from core.ansible_tower_engine import (
    AnsibleTowerEngine,
    reset_ansible_tower_engine,
)


# ---------------------------------------------------------------------------
# Stub httpx.Client
# ---------------------------------------------------------------------------


class _StubResponse:
    def __init__(self, status_code: int, json_payload: Any = None, text: str = "") -> None:
        self.status_code = status_code
        self._json = json_payload
        self.text = text
        # content must be non-empty to bypass the "empty body" early-return in engine
        if json_payload is not None:
            self.content = b"{}" if not text else text.encode("utf-8")
        elif text:
            self.content = text.encode("utf-8") if isinstance(text, str) else text
        else:
            self.content = b""

    def json(self) -> Any:
        if self._json is None:
            raise ValueError("no json")
        return self._json


class StubHTTPXClient:
    """Captures requests and returns scripted responses keyed by (METHOD, suffix)."""

    def __init__(self, routes: Optional[Dict[str, _StubResponse]] = None) -> None:
        self.routes: Dict[str, _StubResponse] = routes or {}
        self.calls: List[Dict[str, Any]] = []

    def set(self, method: str, suffix: str, response: _StubResponse) -> None:
        self.routes[f"{method.upper()} {suffix}"] = response

    def request(
        self,
        method: str,
        url: str,
        json: Any = None,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> _StubResponse:
        marker = "/api/v2/"
        idx = url.find(marker)
        suffix = url[idx + len(marker):] if idx >= 0 else url
        self.calls.append(
            {
                "method": method.upper(),
                "url": url,
                "suffix": suffix,
                "json": json,
                "params": params,
                "headers": headers,
            }
        )
        key = f"{method.upper()} {suffix}"
        if key in self.routes:
            return self.routes[key]
        return _StubResponse(200, {})

    def close(self) -> None:  # pragma: no cover
        pass


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _reset_singleton():
    reset_ansible_tower_engine()
    yield
    reset_ansible_tower_engine()


def _build_app(engine: AnsibleTowerEngine) -> TestClient:
    _router_mod._get_engine = lambda: engine  # type: ignore[attr-defined]
    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=True)


@pytest.fixture
def stub() -> StubHTTPXClient:
    return StubHTTPXClient()


@pytest.fixture
def configured_engine(stub: StubHTTPXClient) -> AnsibleTowerEngine:
    return AnsibleTowerEngine(
        tower_host="https://tower.example.com",
        tower_oauth_token="awx-pat-12345",
        verify_ssl=False,
        client=stub,  # type: ignore[arg-type]
    )


@pytest.fixture
def unavailable_engine() -> AnsibleTowerEngine:
    return AnsibleTowerEngine(
        tower_host="",
        tower_oauth_token="",
        verify_ssl=False,
        client=httpx.Client(),
    )


# ---------------------------------------------------------------------------
# 1. Capability summary — unavailable
# ---------------------------------------------------------------------------


def test_capability_summary_unavailable(unavailable_engine: AnsibleTowerEngine) -> None:
    client = _build_app(unavailable_engine)
    resp = client.get("/api/v1/ansible-tower/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["service"] == "Ansible Tower/AWX"
    assert body["tower_host_present"] is False
    assert body["tower_oauth_token_present"] is False
    assert body["status"] == "unavailable"
    assert "/api/v2/inventories" in body["endpoints"]
    assert "/api/v2/job_templates" in body["endpoints"]
    assert "/api/v2/jobs" in body["endpoints"]
    assert "/api/v2/projects" in body["endpoints"]
    assert "/api/v2/credentials" in body["endpoints"]


# ---------------------------------------------------------------------------
# 2. Capability summary — ok when configured
# ---------------------------------------------------------------------------


def test_capability_summary_ok(configured_engine: AnsibleTowerEngine) -> None:
    client = _build_app(configured_engine)
    resp = client.get("/api/v1/ansible-tower/")
    assert resp.status_code == 200
    body = resp.json()
    assert body["tower_host_present"] is True
    assert body["tower_oauth_token_present"] is True
    assert body["status"] == "ok"


# ---------------------------------------------------------------------------
# 3. List inventories with pagination + search
# ---------------------------------------------------------------------------


def test_list_inventories(configured_engine: AnsibleTowerEngine, stub: StubHTTPXClient) -> None:
    stub.set(
        "GET",
        "inventories/",
        _StubResponse(
            200,
            {
                "count": 1,
                "next": None,
                "previous": None,
                "results": [
                    {
                        "id": 5,
                        "name": "prod-inv",
                        "description": "production inventory",
                        "organization": 1,
                        "kind": "",
                        "host_filter": None,
                        "variables": "",
                        "has_active_failures": False,
                        "total_hosts": 42,
                        "hosts_with_active_failures": 0,
                        "total_groups": 8,
                        "has_inventory_sources": True,
                        "total_inventory_sources": 2,
                        "inventory_sources_with_failures": 0,
                    }
                ],
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get(
        "/api/v1/ansible-tower/api/v2/inventories",
        params={"page": 2, "page_size": 50, "search": "prod"},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 1
    assert body["results"][0]["name"] == "prod-inv"
    assert body["results"][0]["total_hosts"] == 42
    sent = stub.calls[0]
    assert sent["params"]["page"] == 2
    assert sent["params"]["page_size"] == 50
    assert sent["params"]["search"] == "prod"


# ---------------------------------------------------------------------------
# 4. List job templates
# ---------------------------------------------------------------------------


def test_list_job_templates(configured_engine: AnsibleTowerEngine, stub: StubHTTPXClient) -> None:
    stub.set(
        "GET",
        "job_templates/",
        _StubResponse(
            200,
            {
                "count": 1,
                "results": [
                    {
                        "id": 11,
                        "name": "deploy-app",
                        "description": "Deploy production app",
                        "job_type": "run",
                        "inventory": 5,
                        "project": 3,
                        "playbook": "site.yml",
                        "scm_branch": "main",
                        "forks": 0,
                        "limit": "",
                        "verbosity": 0,
                        "extra_vars": "",
                        "job_tags": "",
                        "force_handlers": False,
                        "skip_tags": "",
                        "start_at_task": "",
                        "timeout": 0,
                        "use_fact_cache": False,
                        "last_job_run": "2026-04-30T12:00:00Z",
                        "last_job_failed": False,
                        "status": "successful",
                    }
                ],
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get("/api/v1/ansible-tower/api/v2/job_templates", params={"search": "deploy"})
    assert resp.status_code == 200
    body = resp.json()
    assert body["results"][0]["name"] == "deploy-app"
    assert body["results"][0]["playbook"] == "site.yml"


# ---------------------------------------------------------------------------
# 5. Launch job template
# ---------------------------------------------------------------------------


def test_launch_job_template(configured_engine: AnsibleTowerEngine, stub: StubHTTPXClient) -> None:
    stub.set(
        "POST",
        "job_templates/11/launch/",
        _StubResponse(
            201,
            {
                "id": 9001,
                "name": "deploy-app",
                "status": "pending",
                "started": None,
                "finished": None,
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.post(
        "/api/v1/ansible-tower/api/v2/job_templates/11/launch",
        json={
            "extra_vars": {"app_version": "v1.2.3"},
            "limit": "web",
            "job_tags": "deploy",
            "credentials": [42],
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["job"]["id"] == 9001
    assert body["job"]["status"] == "pending"
    sent = stub.calls[0]
    assert sent["json"]["extra_vars"] == {"app_version": "v1.2.3"}
    assert sent["json"]["limit"] == "web"
    assert sent["json"]["job_tags"] == "deploy"
    assert sent["json"]["credentials"] == [42]
    # None-valued optional fields stripped
    assert "skip_tags" not in sent["json"]
    assert "inventory" not in sent["json"]
    # Bearer auth header attached
    assert sent["headers"]["Authorization"] == "Bearer awx-pat-12345"


# ---------------------------------------------------------------------------
# 6. Get job
# ---------------------------------------------------------------------------


def test_get_job(configured_engine: AnsibleTowerEngine, stub: StubHTTPXClient) -> None:
    stub.set(
        "GET",
        "jobs/9001/",
        _StubResponse(
            200,
            {
                "id": 9001,
                "name": "deploy-app",
                "type": "job",
                "url": "/api/v2/jobs/9001/",
                "related": {},
                "summary_fields": {},
                "created": "2026-04-30T12:00:00Z",
                "modified": "2026-04-30T12:01:00Z",
                "started": "2026-04-30T12:00:05Z",
                "finished": "2026-04-30T12:00:55Z",
                "elapsed": 50.0,
                "failed": False,
                "status": "successful",
                "job_template": 11,
                "playbook": "site.yml",
                "host_status_counts": {
                    "ok": 5,
                    "changed": 2,
                    "dark": 0,
                    "failures": 0,
                    "processed": 5,
                    "skipped": 1,
                    "rescued": 0,
                    "ignored": 0,
                },
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get("/api/v1/ansible-tower/api/v2/jobs/9001")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "successful"
    assert body["host_status_counts"]["ok"] == 5
    assert body["host_status_counts"]["failures"] == 0


# ---------------------------------------------------------------------------
# 7. List job events
# ---------------------------------------------------------------------------


def test_list_job_events(configured_engine: AnsibleTowerEngine, stub: StubHTTPXClient) -> None:
    stub.set(
        "GET",
        "jobs/9001/job_events/",
        _StubResponse(
            200,
            {
                "count": 2,
                "results": [
                    {
                        "id": 1,
                        "type": "job_event",
                        "event": "playbook_on_start",
                        "event_data": {
                            "play": "deploy",
                            "task": "",
                            "host": "",
                            "res": {},
                            "changed": False,
                            "failed": False,
                        },
                        "counter": 1,
                        "parent_uuid": "",
                        "host_name": "",
                    },
                    {
                        "id": 2,
                        "type": "job_event",
                        "event": "runner_on_ok",
                        "event_data": {
                            "play": "deploy",
                            "task": "Install package",
                            "host": "web1",
                            "res": {"changed": True, "msg": "installed"},
                            "changed": True,
                            "failed": False,
                        },
                        "counter": 2,
                        "parent_uuid": "abc",
                        "host_name": "web1",
                    },
                ],
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get(
        "/api/v1/ansible-tower/api/v2/jobs/9001/job_events",
        params={"page": 1, "page_size": 50},
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 2
    assert body["results"][1]["event"] == "runner_on_ok"
    assert body["results"][1]["event_data"]["host"] == "web1"


# ---------------------------------------------------------------------------
# 8. List projects
# ---------------------------------------------------------------------------


def test_list_projects(configured_engine: AnsibleTowerEngine, stub: StubHTTPXClient) -> None:
    stub.set(
        "GET",
        "projects/",
        _StubResponse(
            200,
            {
                "count": 1,
                "results": [
                    {
                        "id": 3,
                        "name": "infra-playbooks",
                        "scm_type": "git",
                        "scm_url": "git@github.com:example/playbooks.git",
                        "scm_branch": "main",
                        "scm_clean": True,
                        "scm_delete_on_update": False,
                        "last_job_run": "2026-04-30T11:00:00Z",
                        "last_job_failed": False,
                        "status": "successful",
                    }
                ],
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get("/api/v1/ansible-tower/api/v2/projects")
    assert resp.status_code == 200
    body = resp.json()
    assert body["results"][0]["scm_type"] == "git"
    assert body["results"][0]["status"] == "successful"


# ---------------------------------------------------------------------------
# 9. List credentials
# ---------------------------------------------------------------------------


def test_list_credentials(configured_engine: AnsibleTowerEngine, stub: StubHTTPXClient) -> None:
    stub.set(
        "GET",
        "credentials/",
        _StubResponse(
            200,
            {
                "count": 2,
                "results": [
                    {"id": 1, "name": "ssh-prod", "credential_type": 1},
                    {"id": 2, "name": "vault-pass", "credential_type": 3},
                ],
            },
        ),
    )
    client = _build_app(configured_engine)
    resp = client.get("/api/v1/ansible-tower/api/v2/credentials")
    assert resp.status_code == 200
    body = resp.json()
    assert body["count"] == 2
    assert body["results"][0]["name"] == "ssh-prod"


# ---------------------------------------------------------------------------
# 10. Lookup endpoint returns 503 when env unset
# ---------------------------------------------------------------------------


def test_lookup_endpoint_503_when_unavailable(unavailable_engine: AnsibleTowerEngine) -> None:
    client = _build_app(unavailable_engine)
    resp = client.get("/api/v1/ansible-tower/api/v2/inventories")
    assert resp.status_code == 503
    body = resp.json()
    assert body["detail"]["error"] == "ansible_tower_unavailable"


# ---------------------------------------------------------------------------
# 11. Upstream 404 surfaces as 404 with payload echo
# ---------------------------------------------------------------------------


def test_upstream_404_surfaces(configured_engine: AnsibleTowerEngine, stub: StubHTTPXClient) -> None:
    stub.set(
        "GET",
        "jobs/9999/",
        _StubResponse(404, {"detail": "Not found."}),
    )
    client = _build_app(configured_engine)
    resp = client.get("/api/v1/ansible-tower/api/v2/jobs/9999")
    assert resp.status_code == 404
    body = resp.json()
    assert body["detail"]["error"] == "tower_upstream_error"
    assert body["detail"]["upstream_status"] == 404
    assert body["detail"]["payload"]["detail"] == "Not found."


# ---------------------------------------------------------------------------
# 12. Bearer auth header attached on launch
# ---------------------------------------------------------------------------


def test_bearer_auth_header_on_launch(configured_engine: AnsibleTowerEngine, stub: StubHTTPXClient) -> None:
    stub.set(
        "POST",
        "job_templates/22/launch/",
        _StubResponse(201, {"id": 9100, "status": "pending"}),
    )
    client = _build_app(configured_engine)
    resp = client.post(
        "/api/v1/ansible-tower/api/v2/job_templates/22/launch",
        json={"extra_vars": "key: value"},
    )
    assert resp.status_code == 200
    sent = stub.calls[0]
    assert sent["headers"]["Authorization"] == "Bearer awx-pat-12345"
    # YAML/JSON-string extra_vars passes through as a string
    assert sent["json"]["extra_vars"] == "key: value"
