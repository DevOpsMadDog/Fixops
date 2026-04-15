"""
Tests for KubernetesSecurityEngine — 30+ tests covering init, CRUD, org isolation, stats.
"""
import pytest
from core.kubernetes_security_engine import KubernetesSecurityEngine


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
        eng = KubernetesSecurityEngine(db_path=db)
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
        # Second init should not raise
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
# CIS Benchmark
# ---------------------------------------------------------------------------

class TestCISBenchmark:
    def test_run_returns_dict(self, engine, cluster):
        result = engine.run_cis_benchmark("org1", cluster["id"])
        assert isinstance(result, dict)

    def test_run_has_score(self, engine, cluster):
        result = engine.run_cis_benchmark("org1", cluster["id"])
        assert "score_pct" in result
        assert 0.0 <= result["score_pct"] <= 100.0

    def test_run_has_categories(self, engine, cluster):
        result = engine.run_cis_benchmark("org1", cluster["id"])
        assert "categories" in result
        assert len(result["categories"]) == 5

    def test_run_has_passed_failed(self, engine, cluster):
        result = engine.run_cis_benchmark("org1", cluster["id"])
        assert "passed" in result
        assert "failed" in result
        assert result["passed"] + result["failed"] > 0

    def test_run_wrong_cluster_raises(self, engine):
        with pytest.raises(ValueError):
            engine.run_cis_benchmark("org1", "no-such-cluster")

    def test_run_wrong_org_raises(self, engine, cluster):
        with pytest.raises(ValueError):
            engine.run_cis_benchmark("org-other", cluster["id"])

    def test_run_benchmark_name(self, engine, cluster):
        result = engine.run_cis_benchmark("org1", cluster["id"])
        assert "CIS Kubernetes Benchmark" in result["benchmark"]


# ---------------------------------------------------------------------------
# RBAC Analysis
# ---------------------------------------------------------------------------

class TestRBACAnalysis:
    def test_returns_dict(self, engine, cluster):
        result = engine.get_rbac_analysis("org1", cluster["id"])
        assert isinstance(result, dict)

    def test_has_total_roles(self, engine, cluster):
        result = engine.get_rbac_analysis("org1", cluster["id"])
        assert "total_roles" in result
        assert result["total_roles"] > 0

    def test_has_cluster_admin_bindings(self, engine, cluster):
        result = engine.get_rbac_analysis("org1", cluster["id"])
        assert "cluster_admin_bindings" in result

    def test_wildcard_permissions_reflects_findings(self, engine, cluster):
        engine.record_finding("org1", {
            "cluster_id": cluster["id"],
            "finding_type": "rbac_wildcard",
            "severity": "high",
        })
        result = engine.get_rbac_analysis("org1", cluster["id"])
        assert result["wildcard_permissions"] == 1

    def test_wrong_org_raises(self, engine, cluster):
        with pytest.raises(ValueError):
            engine.get_rbac_analysis("org-other", cluster["id"])


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
        # fixture finding has severity=critical
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
