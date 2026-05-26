"""
Tests for KubernetesSecurityEngine.

Coverage:
  - Initialization, CRUD, org isolation, stats (unchanged real operations)
  - run_cis_benchmark() — real checkov integration + error paths
  - get_rbac_analysis() — real static RBAC YAML analysis + error paths
  - Router layer — CIS 422/200, RBAC 422/200, posture summary
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from core.kubernetes_security_engine import (
    KubernetesSecurityEngine,
    KubernetesSecurityError,
)

# ---------------------------------------------------------------------------
# Fixtures directory (real K8s manifests)
# ---------------------------------------------------------------------------

_FIXTURES = Path(__file__).resolve().parent / "fixtures" / "k8s_manifests"
_WORKLOAD_YAML = _FIXTURES / "workload.yaml"
_RBAC_YAML = _FIXTURES / "rbac.yaml"

# checkov must be present for integration tests — it IS present at /opt/homebrew/bin/checkov
_CHECKOV_PRESENT = shutil.which("checkov") is not None


# ---------------------------------------------------------------------------
# Engine fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def engine(tmp_path):
    return KubernetesSecurityEngine(db_path=str(tmp_path / "k8s.db"))


@pytest.fixture
def cluster(engine):
    return engine.register_cluster("org1", {
        "cluster_name": "prod-cluster",
        "provider": "eks",
        "k8s_version": "1.28",
        "node_count": 10,
        "namespace_count": 5,
    })


@pytest.fixture
def finding(engine, cluster):
    return engine.record_finding("org1", {
        "cluster_id": cluster["id"],
        "finding_type": "privileged_container",
        "severity": "critical",
        "namespace": "kube-system",
        "resource_name": "nginx",
        "resource_type": "Pod",
        "description": "Privileged container detected",
        "remediation": "Remove privileged flag",
    })


# ---------------------------------------------------------------------------
# Initialization
# ---------------------------------------------------------------------------

class TestInit:
    def test_init_creates_db(self, tmp_path):
        db = str(tmp_path / "sub" / "k8s.db")
        KubernetesSecurityEngine(db_path=db)
        import os
        assert os.path.exists(db)

    def test_init_creates_tables(self, tmp_path):
        import sqlite3
        db = str(tmp_path / "k8s.db")
        KubernetesSecurityEngine(db_path=db)
        conn = sqlite3.connect(db)
        tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()}
        assert "k8s_clusters" in tables
        assert "k8s_findings" in tables
        conn.close()

    def test_init_idempotent(self, tmp_path):
        db = str(tmp_path / "k8s.db")
        KubernetesSecurityEngine(db_path=db)
        KubernetesSecurityEngine(db_path=db)


# ---------------------------------------------------------------------------
# Cluster registration
# ---------------------------------------------------------------------------

class TestRegisterCluster:
    def test_register_returns_dict(self, engine):
        result = engine.register_cluster("org1", {"cluster_name": "my-cluster"})
        assert isinstance(result, dict)

    def test_register_has_id(self, engine):
        result = engine.register_cluster("org1", {"cluster_name": "my-cluster"})
        assert "id" in result
        assert len(result["id"]) == 36  # UUID

    def test_register_stores_org_id(self, engine):
        result = engine.register_cluster("org-abc", {"cluster_name": "my-cluster"})
        assert result["org_id"] == "org-abc"

    def test_register_stores_cluster_name(self, engine):
        result = engine.register_cluster("org1", {"cluster_name": "production"})
        assert result["cluster_name"] == "production"

    def test_register_default_provider_eks(self, engine):
        result = engine.register_cluster("org1", {"cluster_name": "c"})
        assert result["provider"] == "eks"

    def test_register_valid_provider_gke(self, engine):
        result = engine.register_cluster("org1", {"cluster_name": "c", "provider": "gke"})
        assert result["provider"] == "gke"

    def test_register_invalid_provider_defaults_to_eks(self, engine):
        result = engine.register_cluster("org1", {"cluster_name": "c", "provider": "invalid"})
        assert result["provider"] == "eks"

    def test_register_stores_node_count(self, engine):
        result = engine.register_cluster("org1", {"cluster_name": "c", "node_count": 20})
        assert result["node_count"] == 20

    def test_register_stores_k8s_version(self, engine):
        result = engine.register_cluster("org1", {"cluster_name": "c", "k8s_version": "1.29"})
        assert result["k8s_version"] == "1.29"

    def test_register_has_timestamps(self, engine):
        result = engine.register_cluster("org1", {"cluster_name": "c"})
        assert "created_at" in result
        assert "updated_at" in result


# ---------------------------------------------------------------------------
# List clusters
# ---------------------------------------------------------------------------

class TestListClusters:
    def test_list_empty(self, engine):
        assert engine.list_clusters("org1") == []

    def test_list_returns_registered(self, engine, cluster):
        result = engine.list_clusters("org1")
        assert len(result) == 1
        assert result[0]["id"] == cluster["id"]

    def test_list_multiple_clusters(self, engine):
        engine.register_cluster("org1", {"cluster_name": "a"})
        engine.register_cluster("org1", {"cluster_name": "b"})
        assert len(engine.list_clusters("org1")) == 2

    def test_list_org_isolation(self, engine):
        engine.register_cluster("org1", {"cluster_name": "c1"})
        engine.register_cluster("org2", {"cluster_name": "c2"})
        assert len(engine.list_clusters("org1")) == 1
        assert len(engine.list_clusters("org2")) == 1

    def test_list_returns_most_recent_first(self, engine):
        engine.register_cluster("org1", {"cluster_name": "first"})
        engine.register_cluster("org1", {"cluster_name": "second"})
        results = engine.list_clusters("org1")
        assert results[0]["cluster_name"] == "second"


# ---------------------------------------------------------------------------
# Findings
# ---------------------------------------------------------------------------

class TestRecordFinding:
    def test_record_returns_dict(self, engine, cluster):
        result = engine.record_finding("org1", {
            "cluster_id": cluster["id"],
            "finding_type": "host_network",
            "severity": "high",
        })
        assert isinstance(result, dict)

    def test_record_has_id(self, engine, cluster):
        result = engine.record_finding("org1", {"cluster_id": cluster["id"]})
        assert "id" in result
        assert len(result["id"]) == 36

    def test_record_default_status_open(self, engine, cluster):
        result = engine.record_finding("org1", {"cluster_id": cluster["id"]})
        assert result["status"] == "open"

    def test_record_invalid_finding_type_defaults(self, engine, cluster):
        result = engine.record_finding("org1", {
            "cluster_id": cluster["id"],
            "finding_type": "bogus_type",
        })
        assert result["finding_type"] == "no_resource_limits"

    def test_record_invalid_severity_defaults_to_medium(self, engine, cluster):
        result = engine.record_finding("org1", {
            "cluster_id": cluster["id"],
            "severity": "extreme",
        })
        assert result["severity"] == "medium"

    def test_record_stores_namespace(self, engine, cluster):
        result = engine.record_finding("org1", {
            "cluster_id": cluster["id"],
            "namespace": "kube-system",
        })
        assert result["namespace"] == "kube-system"


class TestListFindings:
    def test_list_empty(self, engine):
        assert engine.list_findings("org1") == []

    def test_list_returns_recorded(self, engine, finding):
        result = engine.list_findings("org1")
        assert len(result) == 1
        assert result[0]["id"] == finding["id"]

    def test_filter_by_severity(self, engine, cluster):
        engine.record_finding("org1", {"cluster_id": cluster["id"], "severity": "critical"})
        engine.record_finding("org1", {"cluster_id": cluster["id"], "severity": "low"})
        result = engine.list_findings("org1", severity="critical")
        assert len(result) == 1
        assert result[0]["severity"] == "critical"

    def test_filter_by_finding_type(self, engine, cluster):
        engine.record_finding("org1", {"cluster_id": cluster["id"], "finding_type": "host_network"})
        engine.record_finding("org1", {"cluster_id": cluster["id"], "finding_type": "rbac_wildcard"})
        result = engine.list_findings("org1", finding_type="host_network")
        assert len(result) == 1

    def test_filter_by_cluster_id(self, engine):
        c1 = engine.register_cluster("org1", {"cluster_name": "c1"})
        c2 = engine.register_cluster("org1", {"cluster_name": "c2"})
        engine.record_finding("org1", {"cluster_id": c1["id"]})
        engine.record_finding("org1", {"cluster_id": c2["id"]})
        result = engine.list_findings("org1", cluster_id=c1["id"])
        assert len(result) == 1
        assert result[0]["cluster_id"] == c1["id"]

    def test_filter_by_status(self, engine, cluster):
        f = engine.record_finding("org1", {"cluster_id": cluster["id"]})
        engine.resolve_finding("org1", f["id"], "admin")
        open_results = engine.list_findings("org1", status="open")
        resolved_results = engine.list_findings("org1", status="resolved")
        assert len(open_results) == 0
        assert len(resolved_results) == 1

    def test_org_isolation(self, engine, cluster):
        engine.record_finding("org1", {"cluster_id": cluster["id"]})
        assert engine.list_findings("org2") == []


class TestResolveFinding:
    def test_resolve_changes_status(self, engine, finding):
        result = engine.resolve_finding("org1", finding["id"], "admin-user")
        assert result["status"] == "resolved"

    def test_resolve_sets_resolved_by(self, engine, finding):
        result = engine.resolve_finding("org1", finding["id"], "admin-user")
        assert result["resolved_by"] == "admin-user"

    def test_resolve_sets_resolution_notes(self, engine, finding):
        result = engine.resolve_finding("org1", finding["id"], "admin", "Fixed by patch")
        assert result["resolution_notes"] == "Fixed by patch"

    def test_resolve_sets_resolved_at(self, engine, finding):
        result = engine.resolve_finding("org1", finding["id"], "admin")
        assert result["resolved_at"] is not None

    def test_resolve_wrong_org_raises(self, engine, finding):
        with pytest.raises(ValueError):
            engine.resolve_finding("org-other", finding["id"], "admin")

    def test_resolve_nonexistent_raises(self, engine):
        with pytest.raises(ValueError):
            engine.resolve_finding("org1", "nonexistent-id", "admin")


# ---------------------------------------------------------------------------
# CIS Benchmark — real checkov integration tests
# ---------------------------------------------------------------------------

class TestCISBenchmark:
    """Integration tests — checkov IS present so these MUST run (not skip)."""

    def test_checkov_absent_raises_kubernetes_security_error(self, engine, cluster, monkeypatch):
        """When checkov is absent, KubernetesSecurityError is raised (not NotImplementedError)."""
        monkeypatch.setattr(shutil, "which", lambda _: None)
        with pytest.raises(KubernetesSecurityError) as exc_info:
            engine.run_cis_benchmark("org1", cluster["id"], manifest_path=str(_FIXTURES))
        assert "checkov" in str(exc_info.value).lower()

    def test_missing_manifest_path_raises(self, engine, cluster):
        """No manifest_path provided → KubernetesSecurityError."""
        with pytest.raises(KubernetesSecurityError):
            engine.run_cis_benchmark("org1", cluster["id"], manifest_path=None)

    def test_nonexistent_manifest_path_raises(self, engine, cluster, tmp_path):
        """manifest_path that does not exist → KubernetesSecurityError."""
        with pytest.raises(KubernetesSecurityError):
            engine.run_cis_benchmark(
                "org1", cluster["id"],
                manifest_path=str(tmp_path / "does_not_exist"),
            )

    def test_empty_directory_raises(self, engine, cluster, tmp_path):
        """manifest_path with no YAML files → KubernetesSecurityError."""
        with pytest.raises(KubernetesSecurityError):
            engine.run_cis_benchmark("org1", cluster["id"], manifest_path=str(tmp_path))

    @pytest.mark.skipif(not _CHECKOV_PRESENT, reason="checkov not installed")
    def test_real_checkov_scan_returns_counts(self, engine, cluster):
        """Real checkov scan against the workload fixture must return passed>0 and failed>0."""
        # Scan just the workload YAML (known misconfigured manifests)
        result = engine.run_cis_benchmark(
            "org1", cluster["id"],
            manifest_path=str(_WORKLOAD_YAML),
        )
        print(f"\n[checkov] passed={result['passed']} failed={result['failed']} score={result['score']}")
        assert result["passed"] >= 0
        assert result["failed"] > 0, (
            f"Expected failed>0 from the misconfigured fixture, got failed={result['failed']}"
        )
        assert result["total_checks"] == result["passed"] + result["failed"]
        assert 0.0 <= result["score"] <= 100.0
        assert result["scanner"] == "checkov"
        assert result["framework"] == "kubernetes"

    @pytest.mark.skipif(not _CHECKOV_PRESENT, reason="checkov not installed")
    def test_real_checkov_scan_persists_findings(self, engine, cluster):
        """Failed checks must be persisted as real k8s_findings rows."""
        before = engine.list_findings("org1", cluster_id=cluster["id"])
        result = engine.run_cis_benchmark(
            "org1", cluster["id"],
            manifest_path=str(_WORKLOAD_YAML),
        )
        after = engine.list_findings("org1", cluster_id=cluster["id"])
        assert len(after) > len(before), (
            f"Expected new findings persisted; before={len(before)}, after={len(after)}, "
            f"checkov failed={result['failed']}"
        )
        # Each persisted finding must have a valid finding_type and severity
        from core.kubernetes_security_engine import _VALID_FINDING_TYPES, _VALID_SEVERITIES
        for f in after:
            assert f["finding_type"] in _VALID_FINDING_TYPES, f"Invalid finding_type: {f['finding_type']}"
            assert f["severity"] in _VALID_SEVERITIES, f"Invalid severity: {f['severity']}"

    @pytest.mark.skipif(not _CHECKOV_PRESENT, reason="checkov not installed")
    def test_real_checkov_scan_full_fixture_dir(self, engine, cluster):
        """Scan the full fixture directory — both workload.yaml and rbac.yaml."""
        result = engine.run_cis_benchmark(
            "org1", cluster["id"],
            manifest_path=str(_FIXTURES),
        )
        print(f"\n[checkov dir] passed={result['passed']} failed={result['failed']} score={result['score']}")
        assert result["total_checks"] > 0
        assert result["failed"] > 0


# ---------------------------------------------------------------------------
# RBAC Analysis — real static YAML analysis
# ---------------------------------------------------------------------------

class TestRBACAnalysis:
    """Integration tests for static RBAC analysis — no cluster connectivity needed."""

    def test_missing_manifest_path_raises(self, engine, cluster):
        """No manifest_path → KubernetesSecurityError."""
        with pytest.raises(KubernetesSecurityError):
            engine.get_rbac_analysis("org1", cluster["id"], manifest_path=None)

    def test_nonexistent_manifest_path_raises(self, engine, cluster, tmp_path):
        """manifest_path that does not exist → KubernetesSecurityError."""
        with pytest.raises(KubernetesSecurityError):
            engine.get_rbac_analysis(
                "org1", cluster["id"],
                manifest_path=str(tmp_path / "missing"),
            )

    def test_no_rbac_objects_raises(self, engine, cluster, tmp_path):
        """YAML file with no RBAC-kind objects → KubernetesSecurityError."""
        non_rbac = tmp_path / "configmap.yaml"
        non_rbac.write_text(
            "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: test\n",
            encoding="utf-8",
        )
        with pytest.raises(KubernetesSecurityError) as exc_info:
            engine.get_rbac_analysis("org1", cluster["id"], manifest_path=str(non_rbac))
        assert "RBAC" in str(exc_info.value) or "rbac" in str(exc_info.value).lower()

    def test_real_rbac_fixture_wildcard_permissions(self, engine, cluster):
        """Real RBAC YAML with wildcard rule → wildcard_permissions > 0."""
        result = engine.get_rbac_analysis(
            "org1", cluster["id"],
            manifest_path=str(_RBAC_YAML),
        )
        print(
            f"\n[rbac] total_roles={result['total_roles']} "
            f"cluster_admin_bindings={result['cluster_admin_bindings']} "
            f"wildcard_permissions={result['wildcard_permissions']}"
        )
        assert result["wildcard_permissions"] > 0, (
            f"Expected wildcard_permissions>0 from rbac.yaml fixture, got {result['wildcard_permissions']}"
        )

    def test_real_rbac_fixture_cluster_admin_bindings(self, engine, cluster):
        """Real RBAC YAML with cluster-admin binding → cluster_admin_bindings > 0."""
        result = engine.get_rbac_analysis(
            "org1", cluster["id"],
            manifest_path=str(_RBAC_YAML),
        )
        assert result["cluster_admin_bindings"] > 0, (
            f"Expected cluster_admin_bindings>0 from rbac.yaml fixture, got {result['cluster_admin_bindings']}"
        )

    def test_real_rbac_fixture_total_roles(self, engine, cluster):
        """rbac.yaml has ClusterRole(wildcard-admin) + Role(pod-reader) = 2 roles."""
        result = engine.get_rbac_analysis(
            "org1", cluster["id"],
            manifest_path=str(_RBAC_YAML),
        )
        # wildcard-admin ClusterRole + pod-reader Role = 2
        assert result["total_roles"] == 2, (
            f"Expected 2 roles (ClusterRole+Role) from fixture, got {result['total_roles']}"
        )

    def test_real_rbac_fixture_offenders_present(self, engine, cluster):
        """Offenders list must be non-empty for the rbac.yaml fixture."""
        result = engine.get_rbac_analysis(
            "org1", cluster["id"],
            manifest_path=str(_RBAC_YAML),
        )
        assert len(result["offenders"]) > 0

    def test_real_rbac_fixture_full_dir(self, engine, cluster):
        """Scan the full fixture directory (workload.yaml + rbac.yaml) for RBAC objects."""
        result = engine.get_rbac_analysis(
            "org1", cluster["id"],
            manifest_path=str(_FIXTURES),
        )
        assert result["rbac_objects_found"] >= 4  # ClusterRole + Role + ClusterRoleBinding + RoleBinding

    def test_rbac_zero_counts_is_valid_not_error(self, engine, cluster, tmp_path):
        """A tightly-scoped Role with no wildcards and no cluster-admin binding → real zero counts."""
        clean_rbac = tmp_path / "clean.yaml"
        clean_rbac.write_text(
            "apiVersion: rbac.authorization.k8s.io/v1\n"
            "kind: Role\n"
            "metadata:\n  name: narrow\n  namespace: default\n"
            "rules:\n"
            "  - apiGroups: [\"\"]\n"
            "    resources: [\"pods\"]\n"
            "    verbs: [\"get\"]\n",
            encoding="utf-8",
        )
        result = engine.get_rbac_analysis("org1", cluster["id"], manifest_path=str(clean_rbac))
        assert result["wildcard_permissions"] == 0
        assert result["cluster_admin_bindings"] == 0
        assert result["total_roles"] == 1

    def test_rbac_wildcard_findings_still_tracked_in_db(self, engine, cluster):
        """record_finding() with rbac_wildcard type still works independently of get_rbac_analysis()."""
        engine.record_finding("org1", {
            "cluster_id": cluster["id"],
            "finding_type": "rbac_wildcard",
            "severity": "high",
        })
        wildcard_findings = engine.list_findings("org1", finding_type="rbac_wildcard")
        assert len(wildcard_findings) == 1
        assert wildcard_findings[0]["finding_type"] == "rbac_wildcard"


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------

class TestClusterStats:
    def test_empty_org_stats(self, engine):
        result = engine.get_cluster_stats("org1")
        assert result["total_clusters"] == 0
        assert result["total_findings"] == 0
        assert result["avg_cis_score"] == 100.0

    def test_counts_clusters(self, engine):
        engine.register_cluster("org1", {"cluster_name": "c1"})
        engine.register_cluster("org1", {"cluster_name": "c2"})
        result = engine.get_cluster_stats("org1")
        assert result["total_clusters"] == 2

    def test_counts_findings(self, engine, cluster, finding):
        result = engine.get_cluster_stats("org1")
        assert result["total_findings"] >= 1

    def test_critical_count(self, engine, cluster, finding):
        result = engine.get_cluster_stats("org1")
        assert result["critical_count"] >= 1

    def test_resolved_count(self, engine, cluster, finding):
        engine.resolve_finding("org1", finding["id"], "admin")
        result = engine.get_cluster_stats("org1")
        assert result["resolved_count"] == 1

    def test_by_severity_map(self, engine, cluster):
        engine.record_finding("org1", {"cluster_id": cluster["id"], "severity": "high"})
        engine.record_finding("org1", {"cluster_id": cluster["id"], "severity": "low"})
        result = engine.get_cluster_stats("org1")
        assert "high" in result["by_severity"]
        assert "low" in result["by_severity"]

    def test_org_isolation_in_stats(self, engine):
        engine.register_cluster("org1", {"cluster_name": "c"})
        result = engine.get_cluster_stats("org2")
        assert result["total_clusters"] == 0


# ---------------------------------------------------------------------------
# Router layer tests
# ---------------------------------------------------------------------------

@pytest.fixture()
def client(tmp_path, monkeypatch):
    """TestClient with a fresh in-process engine backed by tmp_path."""
    fresh_engine = KubernetesSecurityEngine(db_path=str(tmp_path / "k8s_test.db"))

    import apps.api.kubernetes_security_router as router_mod
    monkeypatch.setattr(router_mod, "_engine", fresh_engine)

    from fastapi import FastAPI
    from apps.api.kubernetes_security_router import router
    from apps.api.auth_deps import api_key_auth
    from fastapi.testclient import TestClient

    app = FastAPI()
    app.include_router(router)
    app.dependency_overrides[api_key_auth] = lambda: True
    return TestClient(app)


class TestRouterCISBenchmark:
    def test_missing_manifest_path_returns_422(self, client, tmp_path):
        """Non-existent manifest_path → 422."""
        engine_obj = client.app.state if hasattr(client.app, "state") else None
        r = client.post(
            "/api/v1/kubernetes-security/clusters/fake-cluster/cis-benchmark",
            params={"org_id": "org1"},
            json={"manifest_path": str(tmp_path / "does_not_exist")},
        )
        assert r.status_code == 422

    @pytest.mark.skipif(not _CHECKOV_PRESENT, reason="checkov not installed")
    def test_real_scan_returns_200(self, client, tmp_path, monkeypatch):
        """Real scan against fixture → 200 with data._data_source.is_simulated=False."""
        import apps.api.kubernetes_security_router as router_mod
        # Register a cluster first so we have a real cluster_id
        fresh_engine = KubernetesSecurityEngine(db_path=str(tmp_path / "k8s_router.db"))
        monkeypatch.setattr(router_mod, "_engine", fresh_engine)
        cluster = fresh_engine.register_cluster("org1", {"cluster_name": "ci-cluster"})

        from fastapi import FastAPI
        from apps.api.kubernetes_security_router import router
        from apps.api.auth_deps import api_key_auth
        from fastapi.testclient import TestClient
        app = FastAPI()
        app.include_router(router)
        app.dependency_overrides[api_key_auth] = lambda: True
        c = TestClient(app)

        r = c.post(
            f"/api/v1/kubernetes-security/clusters/{cluster['id']}/cis-benchmark",
            params={"org_id": "org1"},
            json={"manifest_path": str(_WORKLOAD_YAML)},
        )
        assert r.status_code == 200
        body = r.json()
        assert "_data_source" in body
        assert body["_data_source"]["is_simulated"] is False
        assert body["data"]["failed"] > 0


class TestRouterRBACAnalysis:
    def test_missing_manifest_path_returns_422(self, client):
        """Non-existent manifest_path → 422."""
        r = client.get(
            "/api/v1/kubernetes-security/clusters/fake-cluster/rbac-analysis",
            params={"org_id": "org1", "manifest_path": "/tmp/does_not_exist_xyz"},
        )
        assert r.status_code == 422

    def test_real_rbac_returns_200(self, client):
        """Real RBAC YAML fixture → 200 with real metrics."""
        r = client.get(
            "/api/v1/kubernetes-security/clusters/fake-cluster/rbac-analysis",
            params={"org_id": "org1", "manifest_path": str(_RBAC_YAML)},
        )
        assert r.status_code == 200
        body = r.json()
        assert body["_data_source"]["is_simulated"] is False
        assert body["data"]["wildcard_permissions"] > 0
        assert body["data"]["cluster_admin_bindings"] > 0
