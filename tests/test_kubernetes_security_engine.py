"""
Tests for KubernetesSecurityEngine — 56 tests covering init, CRUD, org isolation, stats.

NotImplementedError migration:
  - run_cis_benchmark() → raises NotImplementedError (unless K8S_KUBEBENCH_URL set)
  - get_rbac_analysis()  → raises NotImplementedError (unless K8S_KUBEBENCH_URL set)
  All other methods remain production-ready.
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
# CIS Benchmark — run_cis_benchmark() raises NotImplementedError
# (requires K8S_KUBEBENCH_URL env var; unset in test environment)
# ---------------------------------------------------------------------------

class TestCISBenchmark:
    def test_run_raises_not_implemented(self, engine, cluster):
        """run_cis_benchmark() must raise NotImplementedError when kube-bench not configured."""
        with pytest.raises(NotImplementedError):
            engine.run_cis_benchmark("org1", cluster["id"])

    def test_run_error_message_mentions_kubebench(self, engine, cluster):
        """NotImplementedError message must reference kube-bench / K8S_KUBEBENCH_URL."""
        with pytest.raises(NotImplementedError) as exc_info:
            engine.run_cis_benchmark("org1", cluster["id"])
        assert "kube-bench" in str(exc_info.value).lower() or "K8S_KUBEBENCH_URL" in str(exc_info.value)

    def test_run_raises_for_unknown_cluster(self, engine):
        """run_cis_benchmark() on unknown cluster_id still raises NotImplementedError."""
        with pytest.raises(NotImplementedError):
            engine.run_cis_benchmark("org1", "no-such-cluster")

    def test_run_raises_for_wrong_org(self, engine, cluster):
        """run_cis_benchmark() with wrong org raises NotImplementedError (env check fires first)."""
        with pytest.raises(NotImplementedError):
            engine.run_cis_benchmark("org-other", cluster["id"])

    def test_run_raises_not_value_error(self, engine, cluster):
        """run_cis_benchmark() must raise NotImplementedError, not ValueError or RuntimeError."""
        try:
            engine.run_cis_benchmark("org1", cluster["id"])
            pytest.fail("Expected NotImplementedError")
        except NotImplementedError:
            pass
        except Exception as exc:
            pytest.fail(f"Expected NotImplementedError, got {type(exc).__name__}: {exc}")

    def test_run_does_not_return_score(self, engine, cluster):
        """run_cis_benchmark() must not silently return a fake score."""
        raised = False
        try:
            engine.run_cis_benchmark("org1", cluster["id"])
        except NotImplementedError:
            raised = True
        assert raised, "Expected NotImplementedError to be raised"

    def test_run_does_not_modify_db(self, engine, cluster):
        """run_cis_benchmark() raising NotImplementedError must not write findings to DB."""
        before = engine.list_findings("org1")
        try:
            engine.run_cis_benchmark("org1", cluster["id"])
        except NotImplementedError:
            pass
        after = engine.list_findings("org1")
        assert len(after) == len(before)


# ---------------------------------------------------------------------------
# RBAC Analysis — get_rbac_analysis() raises NotImplementedError
# (requires K8S_KUBEBENCH_URL env var; unset in test environment)
# ---------------------------------------------------------------------------

class TestRBACAnalysis:
    def test_raises_not_implemented(self, engine, cluster):
        """get_rbac_analysis() must raise NotImplementedError when K8s API not configured."""
        with pytest.raises(NotImplementedError):
            engine.get_rbac_analysis("org1", cluster["id"])

    def test_error_message_mentions_connector(self, engine, cluster):
        """NotImplementedError message must reference the connector config path."""
        with pytest.raises(NotImplementedError) as exc_info:
            engine.get_rbac_analysis("org1", cluster["id"])
        msg = str(exc_info.value)
        assert "K8S_KUBEBENCH_URL" in msg or "kubernetes" in msg.lower()

    def test_raises_for_wrong_org(self, engine, cluster):
        """get_rbac_analysis() with wrong org still raises NotImplementedError."""
        with pytest.raises(NotImplementedError):
            engine.get_rbac_analysis("org-other", cluster["id"])

    def test_raises_for_unknown_cluster(self, engine):
        """get_rbac_analysis() on unknown cluster_id raises NotImplementedError."""
        with pytest.raises(NotImplementedError):
            engine.get_rbac_analysis("org1", "no-such-cluster")

    def test_rbac_wildcard_findings_still_tracked_in_db(self, engine, cluster):
        """record_finding() with rbac_wildcard type is real — findings persist in DB.

        The RBAC wildcard count is derivable from list_findings() even though
        get_rbac_analysis() is not yet available. Preserve this real read path.
        """
        engine.record_finding("org1", {
            "cluster_id": cluster["id"],
            "finding_type": "rbac_wildcard",
            "severity": "high",
        })
        # get_rbac_analysis raises, but real data is still queryable via list_findings
        with pytest.raises(NotImplementedError):
            engine.get_rbac_analysis("org1", cluster["id"])
        # Confirm the finding is stored and queryable via the real read path
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
