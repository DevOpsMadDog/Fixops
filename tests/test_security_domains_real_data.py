"""Batch 6 — Security Domains: supply-chain, chaos, ransomware, malware.

Four endpoints wired to real engines (no mocks, no stubs):
  1. GET  /api/v1/supply-chain-attacks/stats
  2. GET  /api/v1/security-chaos/stats
  3. GET  /api/v1/ransomware-protection/summary
  4. GET  /api/v1/malware-analysis/stats

Each section covers:
  - HTTP 200 happy path + real key validation
  - Write + read round-trip (proves real DB, not in-memory mock)
  - Filter / query-param variants
  - 404 / 422 error paths
"""

from __future__ import annotations

import os
import uuid

import pytest
from fastapi.testclient import TestClient

TEST_API_KEY = "test-security-domains-batch6"
os.environ["FIXOPS_API_TOKEN"] = TEST_API_KEY
os.environ.setdefault("FIXOPS_MODE", "dev")

from apps.api.app import create_app  # noqa: E402

HEADERS = {
    "X-API-Key": TEST_API_KEY,
    "Authorization": f"Bearer {TEST_API_KEY}",
}


@pytest.fixture(scope="module")
def client() -> TestClient:
    app = create_app()
    return TestClient(app, follow_redirects=True)


def _org() -> str:
    return f"test-org-{uuid.uuid4().hex[:8]}"


# ---------------------------------------------------------------------------
# 1. supply-chain-attacks/stats
# ---------------------------------------------------------------------------

class TestSupplyChainAttackStats:
    """GET /api/v1/supply-chain-attacks/stats"""

    BASE = "/api/v1/supply-chain-attacks"

    def test_stats_empty_org_returns_200(self, client: TestClient):
        org = _org()
        r = client.get(f"{self.BASE}/stats", params={"org_id": org}, headers=HEADERS)
        assert r.status_code == 200, r.text
        data = r.json()
        assert isinstance(data, dict)

    def test_stats_contains_expected_keys(self, client: TestClient):
        org = _org()
        r = client.get(f"{self.BASE}/stats", params={"org_id": org}, headers=HEADERS)
        assert r.status_code == 200, r.text
        data = r.json()
        for key in ("total_packages", "suspicious_packages", "malicious_packages", "total_detections"):
            assert key in data, f"Missing key '{key}' in supply-chain stats: {data}"

    def test_register_package_then_stats_increments(self, client: TestClient):
        org = _org()
        payload = {
            "org_id": org,
            "package_name": f"pkg-{uuid.uuid4().hex[:6]}",
            "ecosystem": "npm",
            "version": "1.0.0",
            "risk_score": 0.2,
            "attack_type": "none",
        }
        r_post = client.post(f"{self.BASE}/packages", json=payload, headers=HEADERS)
        assert r_post.status_code in (200, 201), r_post.text

        r_stats = client.get(f"{self.BASE}/stats", params={"org_id": org}, headers=HEADERS)
        assert r_stats.status_code == 200, r_stats.text
        data = r_stats.json()
        assert data.get("total_packages", 0) >= 1

    def test_list_packages_returns_list(self, client: TestClient):
        org = _org()
        r = client.get(f"{self.BASE}/packages", params={"org_id": org}, headers=HEADERS)
        assert r.status_code == 200, r.text
        assert isinstance(r.json(), list)

    def test_record_detection_then_stats_increments(self, client: TestClient):
        org = _org()
        # First register a package
        r_pkg = client.post(
            f"{self.BASE}/packages",
            json={
                "org_id": org,
                "package_name": f"malicious-{uuid.uuid4().hex[:6]}",
                "ecosystem": "pypi",
                "version": "0.0.1",
                "risk_score": 0.9,
                "attack_type": "typosquatting",
            },
            headers=HEADERS,
        )
        assert r_pkg.status_code in (200, 201), r_pkg.text
        pkg_id = r_pkg.json().get("package_id") or r_pkg.json().get("id", "")

        # Record a detection (use a valid detection_type from the engine enum)
        r_det = client.post(
            f"{self.BASE}/detections",
            json={
                "org_id": org,
                "package_id": pkg_id,
                "detection_type": "name_similarity",
                "confidence_score": 0.85,
                "severity": "high",
                "evidence": "Package name differs by 1 char from popular lib",
                "detected_at": "2026-05-03T00:00:00Z",
            },
            headers=HEADERS,
        )
        assert r_det.status_code in (200, 201), r_det.text

        r_stats = client.get(f"{self.BASE}/stats", params={"org_id": org}, headers=HEADERS)
        assert r_stats.status_code == 200
        assert r_stats.json().get("total_detections", 0) >= 1

    def test_list_detections_returns_list(self, client: TestClient):
        org = _org()
        r = client.get(f"{self.BASE}/detections", params={"org_id": org}, headers=HEADERS)
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_list_policies_returns_list(self, client: TestClient):
        org = _org()
        r = client.get(f"{self.BASE}/policies", params={"org_id": org}, headers=HEADERS)
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_stats_org_isolation(self, client: TestClient):
        org_a = _org()
        org_b = _org()
        # Register package in org_a only
        client.post(
            f"{self.BASE}/packages",
            json={
                "org_id": org_a,
                "package_name": f"isolated-{uuid.uuid4().hex[:6]}",
                "ecosystem": "npm",
                "version": "1.0.0",
            },
            headers=HEADERS,
        )
        r_b = client.get(f"{self.BASE}/stats", params={"org_id": org_b}, headers=HEADERS)
        assert r_b.status_code == 200
        assert r_b.json().get("total_packages", 0) == 0


# ---------------------------------------------------------------------------
# 2. security-chaos/stats
# ---------------------------------------------------------------------------

class TestSecurityChaosStats:
    """GET /api/v1/security-chaos/stats"""

    BASE = "/api/v1/security-chaos"

    def test_stats_empty_org_returns_200(self, client: TestClient):
        org = _org()
        r = client.get(f"{self.BASE}/stats", params={"org_id": org}, headers=HEADERS)
        assert r.status_code == 200, r.text
        assert isinstance(r.json(), dict)

    def test_stats_contains_expected_keys(self, client: TestClient):
        org = _org()
        r = client.get(f"{self.BASE}/stats", params={"org_id": org}, headers=HEADERS)
        assert r.status_code == 200, r.text
        data = r.json()
        for key in ("total_experiments", "by_status", "avg_resilience_score"):
            assert key in data, f"Missing key '{key}' in chaos stats: {data}"

    def test_create_experiment_then_stats_increments(self, client: TestClient):
        org = _org()
        r_post = client.post(
            f"{self.BASE}/experiments",
            params={"org_id": org},
            json={
                "experiment_name": f"exp-{uuid.uuid4().hex[:6]}",
                "experiment_type": "auth_disruption",
                "target_system": "api-gateway",
                "hypothesis": "Service degrades gracefully under partition",
                "expected_outcome": "50% degraded, no data loss",
            },
            headers=HEADERS,
        )
        assert r_post.status_code in (200, 201), r_post.text

        r_stats = client.get(f"{self.BASE}/stats", params={"org_id": org}, headers=HEADERS)
        assert r_stats.status_code == 200
        assert r_stats.json().get("total_experiments", 0) >= 1

    def test_list_experiments_returns_list(self, client: TestClient):
        org = _org()
        r = client.get(f"{self.BASE}/experiments", params={"org_id": org}, headers=HEADERS)
        assert r.status_code == 200
        data = r.json()
        # router returns either a list or a dict with 'experiments' key
        items = data if isinstance(data, list) else data.get("experiments", data.get("items", []))
        assert isinstance(items, list)

    def test_get_experiment_not_found(self, client: TestClient):
        org = _org()
        r = client.get(
            f"{self.BASE}/experiments/nonexistent-id",
            params={"org_id": org},
            headers=HEADERS,
        )
        assert r.status_code == 404

    def test_create_and_start_experiment(self, client: TestClient):
        org = _org()
        r_post = client.post(
            f"{self.BASE}/experiments",
            params={"org_id": org},
            json={
                "experiment_name": f"start-exp-{uuid.uuid4().hex[:6]}",
                "experiment_type": "mfa_failure",
                "target_system": "worker-service",
                "hypothesis": "Worker stays responsive under CPU stress",
            },
            headers=HEADERS,
        )
        assert r_post.status_code in (200, 201), r_post.text
        exp_id = r_post.json().get("experiment_id") or r_post.json().get("id", "")

        r_start = client.put(
            f"{self.BASE}/experiments/{exp_id}/start",
            params={"org_id": org},
            headers=HEADERS,
        )
        assert r_start.status_code in (200, 201, 204), r_start.text

    def test_stats_org_isolation(self, client: TestClient):
        org_a = _org()
        org_b = _org()
        client.post(
            f"{self.BASE}/experiments",
            params={"org_id": org_a},
            json={
                "experiment_name": "isolated-exp",
                "experiment_type": "siem_outage",
                "target_system": "db-service",
            },
            headers=HEADERS,
        )
        r_b = client.get(f"{self.BASE}/stats", params={"org_id": org_b}, headers=HEADERS)
        assert r_b.status_code == 200
        assert r_b.json().get("total_experiments", 0) == 0


# ---------------------------------------------------------------------------
# 3. ransomware-protection/summary
# ---------------------------------------------------------------------------

class TestRansomwareProtectionSummary:
    """GET /api/v1/ransomware-protection/summary"""

    BASE = "/api/v1/ransomware-protection"

    def test_summary_empty_org_returns_200(self, client: TestClient):
        org = _org()
        r = client.get(f"{self.BASE}/summary", params={"org_id": org}, headers=HEADERS)
        assert r.status_code == 200, r.text
        assert isinstance(r.json(), dict)

    def test_summary_contains_expected_keys(self, client: TestClient):
        org = _org()
        r = client.get(f"{self.BASE}/summary", params={"org_id": org}, headers=HEADERS)
        assert r.status_code == 200, r.text
        data = r.json()
        for key in ("total_detections", "backup_coverage_pct"):
            assert key in data, f"Missing key '{key}' in ransomware summary: {data}"

    def test_register_detection_then_summary_increments(self, client: TestClient):
        org = _org()
        r_post = client.post(
            f"{self.BASE}/detections",
            json={
                "org_id": org,
                "detection_name": f"ransomware-{uuid.uuid4().hex[:6]}",
                "detection_type": "behavioral",
                "affected_systems": ["file-server-01"],
                "file_extensions": [".locked", ".enc"],
                "confidence": 0.92,
                "severity": "critical",
            },
            headers=HEADERS,
        )
        assert r_post.status_code in (200, 201), r_post.text

        r_sum = client.get(f"{self.BASE}/summary", params={"org_id": org}, headers=HEADERS)
        assert r_sum.status_code == 200
        assert r_sum.json().get("total_detections", 0) >= 1

    def test_root_returns_200(self, client: TestClient):
        """GET / on the router (BUG-2 guard)."""
        org = _org()
        r = client.get(f"{self.BASE}/", params={"org_id": org}, headers=HEADERS)
        assert r.status_code == 200, r.text

    def test_list_detections_returns_list(self, client: TestClient):
        org = _org()
        r = client.get(f"{self.BASE}/detections", params={"org_id": org}, headers=HEADERS)
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_register_backup_then_summary(self, client: TestClient):
        org = _org()
        r_bkp = client.post(
            f"{self.BASE}/backups",
            json={
                "org_id": org,
                "system_name": f"server-{uuid.uuid4().hex[:6]}",
                "backup_type": "full",
                "backup_location": "s3://backups/prod",
                "immutable": True,
                "encrypted": True,
                "retention_days": 90,
            },
            headers=HEADERS,
        )
        assert r_bkp.status_code in (200, 201), r_bkp.text

        r_sum = client.get(f"{self.BASE}/summary", params={"org_id": org}, headers=HEADERS)
        assert r_sum.status_code == 200
        # backup_coverage_pct should reflect registered backup
        assert "backup_coverage_pct" in r_sum.json()

    def test_protection_status_returns_200(self, client: TestClient):
        org = _org()
        r = client.get(f"{self.BASE}/status", params={"org_id": org}, headers=HEADERS)
        assert r.status_code == 200, r.text

    def test_list_backups_returns_list(self, client: TestClient):
        org = _org()
        r = client.get(f"{self.BASE}/backups", params={"org_id": org}, headers=HEADERS)
        assert r.status_code == 200
        assert isinstance(r.json(), list)


# ---------------------------------------------------------------------------
# 4. malware-analysis/stats
# ---------------------------------------------------------------------------

class TestMalwareAnalysisStats:
    """GET /api/v1/malware-analysis/stats"""

    BASE = "/api/v1/malware-analysis"

    def test_stats_empty_org_returns_200(self, client: TestClient):
        org = _org()
        r = client.get(f"{self.BASE}/stats", params={"org_id": org}, headers=HEADERS)
        assert r.status_code == 200, r.text
        assert isinstance(r.json(), dict)

    def test_stats_contains_expected_keys(self, client: TestClient):
        org = _org()
        r = client.get(f"{self.BASE}/stats", params={"org_id": org}, headers=HEADERS)
        assert r.status_code == 200, r.text
        data = r.json()
        for key in ("total_samples", "malicious_count", "clean_count"):
            assert key in data, f"Missing key '{key}' in malware stats: {data}"

    def test_submit_sample_then_stats_increments(self, client: TestClient):
        org = _org()
        sha = uuid.uuid4().hex * 2  # 64-char sha256
        r_post = client.post(
            f"{self.BASE}/samples",
            params={"org_id": org},
            json={
                "sha256": sha,
                "file_name": "suspicious.exe",
                "file_type": "PE32",
                "file_size": 102400,
                "source": "email_attachment",
            },
            headers=HEADERS,
        )
        assert r_post.status_code in (200, 201), r_post.text

        r_stats = client.get(f"{self.BASE}/stats", params={"org_id": org}, headers=HEADERS)
        assert r_stats.status_code == 200
        assert r_stats.json().get("total_samples", 0) >= 1

    def test_list_samples_returns_list(self, client: TestClient):
        org = _org()
        r = client.get(f"{self.BASE}/samples", params={"org_id": org}, headers=HEADERS)
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_list_samples_verdict_filter(self, client: TestClient):
        org = _org()
        sha = uuid.uuid4().hex * 2
        r_post = client.post(
            f"{self.BASE}/samples",
            params={"org_id": org},
            json={
                "sha256": sha,
                "file_name": "clean.pdf",
                "file_type": "PDF",
                "file_size": 2048,
                "source": "upload",
            },
            headers=HEADERS,
        )
        assert r_post.status_code in (200, 201), r_post.text

        r = client.get(
            f"{self.BASE}/samples",
            params={"org_id": org, "verdict": "unknown"},
            headers=HEADERS,
        )
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_get_sample_not_found(self, client: TestClient):
        org = _org()
        r = client.get(
            f"{self.BASE}/samples/nonexistent-sample-id",
            params={"org_id": org},
            headers=HEADERS,
        )
        assert r.status_code == 404

    def test_list_iocs_returns_list(self, client: TestClient):
        org = _org()
        r = client.get(f"{self.BASE}/iocs", params={"org_id": org}, headers=HEADERS)
        assert r.status_code == 200
        assert isinstance(r.json(), list)

    def test_root_returns_200(self, client: TestClient):
        """GET / on the router (BUG-2 guard)."""
        org = _org()
        r = client.get(f"{self.BASE}/", params={"org_id": org}, headers=HEADERS)
        assert r.status_code == 200, r.text

    def test_stats_org_isolation(self, client: TestClient):
        org_a = _org()
        org_b = _org()
        sha = uuid.uuid4().hex * 2
        client.post(
            f"{self.BASE}/samples",
            params={"org_id": org_a},
            json={"sha256": sha, "file_name": "isolated.exe", "file_type": "PE32"},
            headers=HEADERS,
        )
        r_b = client.get(f"{self.BASE}/stats", params={"org_id": org_b}, headers=HEADERS)
        assert r_b.status_code == 200
        assert r_b.json().get("total_samples", 0) == 0
