"""Router-level tests for SCM anomaly endpoints — /api/v1/access-anomaly/scm-anomalies.

6 tests covering: POST record, GET list, GET filter by author/type, missing required fields.
"""

from __future__ import annotations

import os
import pytest
from fastapi.testclient import TestClient

from apps.api.app import create_app

_TEST_TOKEN = "scm-test-token-abc"


@pytest.fixture(scope="module")
def client(tmp_path_factory, monkeypatch_session=None):
    tmp = tmp_path_factory.mktemp("scm_router")
    db_path = str(tmp / "access_anomaly_scm_test.db")

    # Set token env before importing auth_deps resolves tokens per-request
    os.environ["FIXOPS_API_TOKEN"] = _TEST_TOKEN

    # Patch engine to use isolated tmp DB
    import apps.api.access_anomaly_router as _mod
    from core.access_anomaly_engine import AccessAnomalyEngine

    _mod._engine = AccessAnomalyEngine(db_path=db_path)

    app = create_app()
    yield TestClient(app, headers={"X-API-Key": _TEST_TOKEN})

    # Cleanup
    os.environ.pop("FIXOPS_API_TOKEN", None)
    _mod._engine = None


ORG = "org-scm-test"
AUTHOR = "dev@example.com"


class TestScmAnomalyPost:
    def test_record_scm_anomaly_returns_record(self, client):
        resp = client.post(
            "/api/v1/access-anomaly/scm-anomalies",
            json={
                "org_id": ORG,
                "author_email": AUTHOR,
                "anomaly_type": "off_hours",
                "evidence_json": {"commit_sha": "abc123", "hour": 3},
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["org_id"] == ORG
        assert data["author_email"] == AUTHOR
        assert data["anomaly_type"] == "off_hours"
        assert "id" in data
        assert data["evidence_json"]["commit_sha"] == "abc123"

    def test_record_scm_anomaly_no_evidence(self, client):
        resp = client.post(
            "/api/v1/access-anomaly/scm-anomalies",
            json={
                "org_id": ORG,
                "author_email": AUTHOR,
                "anomaly_type": "force_push",
            },
        )
        assert resp.status_code == 200
        data = resp.json()
        assert data["anomaly_type"] == "force_push"

    def test_record_scm_anomaly_missing_author_returns_422(self, client):
        resp = client.post(
            "/api/v1/access-anomaly/scm-anomalies",
            json={
                "org_id": ORG,
                "author_email": "",
                "anomaly_type": "privilege_escalation",
            },
        )
        assert resp.status_code == 422


class TestScmAnomalyGet:
    def test_list_scm_anomalies_returns_list(self, client):
        # Seed one first
        client.post(
            "/api/v1/access-anomaly/scm-anomalies",
            json={
                "org_id": ORG,
                "author_email": "other@example.com",
                "anomaly_type": "bulk_rename",
            },
        )
        resp = client.get(
            "/api/v1/access-anomaly/scm-anomalies",
            params={"org_id": ORG},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert isinstance(data, list)
        assert len(data) >= 1

    def test_list_scm_anomalies_filter_by_author(self, client):
        resp = client.get(
            "/api/v1/access-anomaly/scm-anomalies",
            params={"org_id": ORG, "author_email": AUTHOR},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert all(row["author_email"] == AUTHOR for row in data)

    def test_list_scm_anomalies_filter_by_type(self, client):
        resp = client.get(
            "/api/v1/access-anomaly/scm-anomalies",
            params={"org_id": ORG, "anomaly_type": "off_hours"},
        )
        assert resp.status_code == 200
        data = resp.json()
        assert all(row["anomaly_type"] == "off_hours" for row in data)
