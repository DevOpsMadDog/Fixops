"""Tests for Code-to-Cloud Traceability Engine (code_to_cloud.py).

Covers all 8 feature areas:
  1. Code Change Tracking
  2. Build Artifact Mapping
  3. Deployment Tracking
  4. Runtime Correlation / Finding Indexing
  5. Material Change Detection
  6. Blast Radius Analysis
  7. Developer Risk Profiles
  8. Timeline Reconstruction + Full Provenance Trace
"""

from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

from core.code_to_cloud import (
    ArtifactType,
    BlastRadius,
    BuildArtifact,
    ChangeCategory,
    ChangeRisk,
    CloudProvider,
    CodeChange,
    CodeToCloudEngine,
    Deployment,
    DeploymentEnvironment,
    DeveloperRiskProfile,
    FileChange,
    ProvenanceTrace,
    TimelineEvent,
    get_engine,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _fresh() -> CodeToCloudEngine:
    """Return a clean engine instance (not the singleton)."""
    return CodeToCloudEngine()


def _commit(engine: CodeToCloudEngine, sha: str = "abc123def456", **kwargs) -> CodeChange:
    defaults = dict(
        commit_sha=sha,
        author="Alice Smith",
        author_email="alice@example.com",
        message="chore: update deps",
    )
    defaults.update(kwargs)
    return engine.ingest_commit(**defaults)


# ===========================================================================
# Enum tests
# ===========================================================================

class TestEnums:
    def test_change_risk_values(self):
        expected = ["critical", "high", "medium", "low", "none"]
        for v in expected:
            assert ChangeRisk(v).value == v

    def test_change_category_values(self):
        expected = [
            "security", "infrastructure", "data", "dependency",
            "configuration", "business_logic", "test", "documentation", "unknown",
        ]
        for v in expected:
            assert ChangeCategory(v).value == v

    def test_artifact_type_values(self):
        expected = [
            "docker_image", "npm_package", "python_wheel",
            "binary", "lambda_zip", "helm_chart", "unknown",
        ]
        for v in expected:
            assert ArtifactType(v).value == v

    def test_deployment_environment_values(self):
        for v in ["production", "staging", "development", "qa", "dr", "unknown"]:
            assert DeploymentEnvironment(v).value == v

    def test_cloud_provider_values(self):
        for v in ["aws", "gcp", "azure", "on_prem", "unknown"]:
            assert CloudProvider(v).value == v


# ===========================================================================
# FileChange model
# ===========================================================================

class TestFileChange:
    def test_to_dict_fields(self):
        fc = FileChange(
            path="core/auth.py",
            change_type="modified",
            lines_added=10,
            lines_removed=2,
            functions_modified=["login", "verify"],
            is_security_relevant=True,
            category=ChangeCategory.SECURITY.value,
        )
        d = fc.to_dict()
        assert d["path"] == "core/auth.py"
        assert d["change_type"] == "modified"
        assert d["lines_added"] == 10
        assert d["lines_removed"] == 2
        assert d["functions_modified"] == ["login", "verify"]
        assert d["is_security_relevant"] is True
        assert d["category"] == "security"

    def test_default_functions_modified(self):
        fc = FileChange(path="main.py", change_type="added")
        assert fc.functions_modified == []

    def test_to_dict_has_all_keys(self):
        fc = FileChange(path="x.py", change_type="deleted")
        keys = fc.to_dict().keys()
        for k in ("path", "change_type", "lines_added", "lines_removed",
                   "functions_modified", "is_security_relevant", "category"):
            assert k in keys


# ===========================================================================
# 1. Code Change Tracking
# ===========================================================================

class TestCodeChangeTracking:
    def test_ingest_basic_commit(self):
        e = _fresh()
        c = _commit(e)
        assert c.commit_sha == "abc123def456"
        assert c.short_sha == "abc123de"
        assert c.author == "Alice Smith"
        assert c.change_id.startswith("chg-")

    def test_ingest_returns_code_change(self):
        e = _fresh()
        c = _commit(e)
        assert isinstance(c, CodeChange)

    def test_commit_with_files(self):
        e = _fresh()
        files = [
            {"path": "core/auth.py", "change_type": "modified", "lines_added": 5},
            {"path": "tests/test_auth.py", "change_type": "added", "lines_added": 30},
        ]
        c = e.ingest_commit(
            commit_sha="deadbeef1234",
            author="Bob",
            author_email="bob@example.com",
            message="fix auth",
            files=files,
        )
        assert len(c.files_changed) == 2

    def test_security_file_classified(self):
        e = _fresh()
        files = [{"path": "core/auth_handler.py", "change_type": "modified"}]
        c = _commit(e, files=files)
        auth_file = c.files_changed[0]
        assert auth_file.is_security_relevant is True
        assert auth_file.category == ChangeCategory.SECURITY.value

    def test_infra_file_classified(self):
        e = _fresh()
        files = [{"path": "k8s/deployment.yaml", "change_type": "modified"}]
        c = _commit(e, files=files)
        assert c.files_changed[0].category == ChangeCategory.INFRASTRUCTURE.value

    def test_dependency_file_classified(self):
        e = _fresh()
        files = [{"path": "requirements.txt", "change_type": "modified"}]
        c = _commit(e, files=files)
        assert c.files_changed[0].category == ChangeCategory.DEPENDENCY.value

    def test_data_migration_classified(self):
        e = _fresh()
        files = [{"path": "alembic/versions/001_add_users.py", "change_type": "added"}]
        c = _commit(e, files=files)
        assert c.files_changed[0].category == ChangeCategory.DATA.value

    def test_test_file_classified(self):
        e = _fresh()
        files = [{"path": "tests/test_main.py", "change_type": "modified"}]
        c = _commit(e, files=files)
        assert c.files_changed[0].category == ChangeCategory.TEST.value

    def test_doc_file_classified(self):
        e = _fresh()
        files = [{"path": "docs/README.md", "change_type": "modified"}]
        c = _commit(e, files=files)
        assert c.files_changed[0].category == ChangeCategory.DOCUMENTATION.value

    def test_risk_level_critical_for_password_file(self):
        e = _fresh()
        files = [{"path": "core/password_manager.py", "change_type": "modified"}]
        c = _commit(e, files=files)
        assert c.risk_level == ChangeRisk.CRITICAL.value

    def test_risk_level_high_for_auth_file(self):
        e = _fresh()
        files = [{"path": "core/authentication.py", "change_type": "modified"}]
        c = _commit(e, files=files)
        assert c.risk_level == ChangeRisk.HIGH.value

    def test_material_change_on_high_risk(self):
        e = _fresh()
        files = [{"path": "core/auth.py", "change_type": "modified"}]
        c = _commit(e, files=files)
        assert c.is_material is True

    def test_non_material_for_docs(self):
        e = _fresh()
        files = [{"path": "docs/guide.md", "change_type": "modified"}]
        c = _commit(e, files=files)
        assert c.is_material is False

    def test_material_change_with_deps_added(self):
        e = _fresh()
        files = [{"path": "requirements.txt", "change_type": "modified",
                  "deps_added": ["requests==2.32.0"]}]
        c = _commit(e, files=files)
        assert c.is_material is True
        assert "requests==2.32.0" in c.dependencies_added

    def test_to_dict_structure(self):
        e = _fresh()
        c = _commit(e)
        d = c.to_dict()
        for key in ("change_id", "commit_sha", "short_sha", "author", "author_email",
                     "message", "timestamp", "files_changed", "risk_level",
                     "categories", "is_material"):
            assert key in d

    def test_get_recent_changes(self):
        e = _fresh()
        for i in range(5):
            _commit(e, sha=f"sha{i:040d}")
        changes = e.get_recent_changes(limit=10)
        assert len(changes) == 5

    def test_get_recent_material_changes_filter(self):
        e = _fresh()
        # Material commit
        _commit(e, sha="aaa" + "0" * 37, files=[{"path": "core/auth.py", "change_type": "modified"}])
        # Non-material commit
        _commit(e, sha="bbb" + "0" * 37, files=[{"path": "docs/readme.md", "change_type": "modified"}])
        material = e.get_recent_material_changes()
        assert all(c.is_material for c in material)

    def test_pr_metadata_stored(self):
        e = _fresh()
        c = e.ingest_commit(
            commit_sha="prsha123",
            author="Dev",
            author_email="dev@example.com",
            message="feat: add thing",
            pr_number="42",
            branch="feature/thing",
            reviewed_by=["reviewer1"],
        )
        assert c.pr_number == "42"
        assert c.branch == "feature/thing"
        assert "reviewer1" in c.reviewed_by

    def test_security_message_bumps_risk(self):
        e = _fresh()
        c = e.ingest_commit(
            commit_sha="secfix123",
            author="Dev",
            author_email="dev@example.com",
            message="fix CVE-2024-1234 vulnerability in parser",
        )
        assert c.risk_level != ChangeRisk.NONE.value


# ===========================================================================
# 2. Build Artifact Mapping
# ===========================================================================

class TestBuildArtifactMapping:
    def test_register_artifact_returns_build_artifact(self):
        e = _fresh()
        art = e.register_artifact(name="myapp", version="1.0.0", commit_sha="abc123")
        assert isinstance(art, BuildArtifact)

    def test_artifact_id_prefix(self):
        e = _fresh()
        art = e.register_artifact(name="myapp", version="1.0.0", commit_sha="abc123")
        assert art.artifact_id.startswith("art-")

    def test_artifact_sha256_computed_if_not_given(self):
        e = _fresh()
        art = e.register_artifact(name="myapp", version="1.0.0", commit_sha="abc123")
        assert len(art.sha256) == 64  # SHA-256 hex

    def test_artifact_sha256_accepted_if_given(self):
        e = _fresh()
        custom_sha = "a" * 64
        art = e.register_artifact(name="myapp", version="1.0.0", commit_sha="abc123", sha256=custom_sha)
        assert art.sha256 == custom_sha

    def test_get_artifact_for_commit(self):
        e = _fresh()
        art = e.register_artifact(name="myapp", version="2.0.0", commit_sha="sha999")
        retrieved = e.get_artifact_for_commit("sha999")
        assert retrieved is not None
        assert retrieved.artifact_id == art.artifact_id

    def test_get_artifact_for_unknown_commit_returns_none(self):
        e = _fresh()
        assert e.get_artifact_for_commit("unknownsha") is None

    def test_artifact_to_dict_keys(self):
        e = _fresh()
        art = e.register_artifact(name="svc", version="0.1", commit_sha="c1")
        d = art.to_dict()
        for k in ("artifact_id", "artifact_type", "name", "version", "sha256",
                   "commit_sha", "built_at", "builder", "size_bytes"):
            assert k in d

    def test_artifact_type_stored(self):
        e = _fresh()
        art = e.register_artifact(
            name="mypkg", version="1.0", commit_sha="c1",
            artifact_type=ArtifactType.PYTHON_WHEEL.value,
        )
        assert art.artifact_type == ArtifactType.PYTHON_WHEEL.value


# ===========================================================================
# 3. Deployment Tracking
# ===========================================================================

class TestDeploymentTracking:
    def test_register_deployment_returns_deployment(self):
        e = _fresh()
        art = e.register_artifact("svc", "1.0", "c1")
        dep = e.register_deployment(artifact_id=art.artifact_id)
        assert isinstance(dep, Deployment)

    def test_deployment_id_prefix(self):
        e = _fresh()
        art = e.register_artifact("svc", "1.0", "c1")
        dep = e.register_deployment(artifact_id=art.artifact_id)
        assert dep.deployment_id.startswith("dep-")

    def test_deployment_default_status_active(self):
        e = _fresh()
        art = e.register_artifact("svc", "1.0", "c1")
        dep = e.register_deployment(artifact_id=art.artifact_id)
        assert dep.status == "active"

    def test_deployment_k8s_fields(self):
        e = _fresh()
        art = e.register_artifact("svc", "1.0", "c1")
        dep = e.register_deployment(
            artifact_id=art.artifact_id,
            k8s_namespace="production",
            k8s_deployment="svc-deploy",
            k8s_pod_count=3,
        )
        assert dep.k8s_namespace == "production"
        assert dep.k8s_deployment == "svc-deploy"
        assert dep.k8s_pod_count == 3

    def test_deployment_internet_facing_flag(self):
        e = _fresh()
        art = e.register_artifact("svc", "1.0", "c1")
        dep = e.register_deployment(artifact_id=art.artifact_id, internet_facing=True)
        assert dep.internet_facing is True

    def test_get_deployments_for_artifact(self):
        e = _fresh()
        art = e.register_artifact("svc", "1.0", "c1")
        dep1 = e.register_deployment(artifact_id=art.artifact_id, environment="staging")
        dep2 = e.register_deployment(artifact_id=art.artifact_id, environment="production")
        deps = e.get_deployments_for_artifact(art.artifact_id)
        ids = [d.deployment_id for d in deps]
        assert dep1.deployment_id in ids
        assert dep2.deployment_id in ids

    def test_get_all_deployments(self):
        e = _fresh()
        art = e.register_artifact("svc", "1.0", "c1")
        e.register_deployment(artifact_id=art.artifact_id)
        e.register_deployment(artifact_id=art.artifact_id)
        all_deps = e.get_all_deployments()
        assert len(all_deps) >= 2

    def test_deployment_to_dict_keys(self):
        e = _fresh()
        art = e.register_artifact("svc", "1.0", "c1")
        dep = e.register_deployment(artifact_id=art.artifact_id)
        d = dep.to_dict()
        for k in ("deployment_id", "artifact_id", "environment", "deployed_at",
                   "deployed_by", "status", "internet_facing"):
            assert k in d


# ===========================================================================
# 4. Runtime Correlation — Finding indexing
# ===========================================================================

class TestRuntimeCorrelation:
    def test_index_finding_no_error(self):
        e = _fresh()
        e.index_finding(finding_id="FIND-001", commit_sha="abc123")

    def test_finding_appears_in_trace(self):
        e = _fresh()
        c = _commit(e, sha="tracesha001")
        e.index_finding(finding_id="FIND-002", commit_sha=c.commit_sha)
        trace = e.trace_finding("FIND-002")
        assert trace.code_change is not None
        assert trace.code_change.commit_sha == "tracesha001"

    def test_unknown_finding_returns_empty_trace(self):
        e = _fresh()
        trace = e.trace_finding("FIND-UNKNOWN")
        assert trace.code_change is None
        assert trace.build_artifact is None
        assert trace.deployment is None

    def test_trace_links_artifact(self):
        e = _fresh()
        c = _commit(e, sha="buildsha001")
        art = e.register_artifact("svc", "1.0", c.commit_sha)
        e.index_finding(finding_id="FIND-003", commit_sha=c.commit_sha, artifact_id=art.artifact_id)
        trace = e.trace_finding("FIND-003")
        assert trace.build_artifact is not None
        assert trace.build_artifact.artifact_id == art.artifact_id

    def test_trace_links_deployment(self):
        e = _fresh()
        art = e.register_artifact("svc", "1.0", "depsha001")
        dep = e.register_deployment(artifact_id=art.artifact_id)
        e.index_finding(finding_id="FIND-004", artifact_id=art.artifact_id, deployment_id=dep.deployment_id)
        trace = e.trace_finding("FIND-004")
        assert trace.deployment is not None
        assert trace.deployment.deployment_id == dep.deployment_id


# ===========================================================================
# 5. Material Change Detection
# ===========================================================================

class TestMaterialChangeDetection:
    def test_terraform_is_infrastructure(self):
        e = _fresh()
        files = [{"path": "infra/main.tf", "change_type": "modified"}]
        c = _commit(e, files=files)
        assert c.files_changed[0].category == ChangeCategory.INFRASTRUCTURE.value

    def test_github_actions_is_infrastructure(self):
        e = _fresh()
        files = [{"path": ".github/workflows/deploy.yml", "change_type": "modified"}]
        c = _commit(e, files=files)
        assert c.files_changed[0].category == ChangeCategory.INFRASTRUCTURE.value

    def test_docker_compose_is_infrastructure(self):
        e = _fresh()
        files = [{"path": "docker-compose.yml", "change_type": "modified"}]
        c = _commit(e, files=files)
        assert c.files_changed[0].category == ChangeCategory.INFRASTRUCTURE.value

    def test_crypto_file_is_security(self):
        e = _fresh()
        files = [{"path": "core/encrypt_utils.py", "change_type": "modified"}]
        c = _commit(e, files=files)
        assert c.files_changed[0].category == ChangeCategory.SECURITY.value

    def test_schema_change_is_data(self):
        e = _fresh()
        files = [{"path": "db/schema.sql", "change_type": "modified"}]
        c = _commit(e, files=files)
        assert c.files_changed[0].category == ChangeCategory.DATA.value

    def test_package_json_is_dependency(self):
        e = _fresh()
        files = [{"path": "frontend/package.json", "change_type": "modified"}]
        c = _commit(e, files=files)
        assert c.files_changed[0].category == ChangeCategory.DEPENDENCY.value

    def test_infra_change_is_material(self):
        e = _fresh()
        files = [{"path": "k8s/ingress.yaml", "change_type": "modified"}]
        c = _commit(e, files=files)
        assert c.is_material is True


# ===========================================================================
# 6. Blast Radius Analysis
# ===========================================================================

class TestBlastRadius:
    def test_blast_radius_for_known_commit(self):
        e = _fresh()
        files = [
            {"path": "suite-api/auth_router.py", "change_type": "modified"},
            {"path": "suite-core/db/schema.sql", "change_type": "modified"},
        ]
        c = _commit(e, sha="blastsha001", files=files)
        blast = e.compute_blast_radius(c.commit_sha)
        assert isinstance(blast, BlastRadius)
        assert blast.commit_sha == "blastsha001"

    def test_blast_radius_unknown_commit(self):
        e = _fresh()
        blast = e.compute_blast_radius("unknowncommit")
        assert blast.total_blast_score == 0.0
        assert blast.risk_level == ChangeRisk.NONE.value

    def test_blast_radius_affected_services(self):
        e = _fresh()
        files = [
            {"path": "suite-api/router.py", "change_type": "modified"},
            {"path": "suite-core/engine.py", "change_type": "modified"},
        ]
        c = _commit(e, sha="blastsha002", files=files)
        blast = e.compute_blast_radius(c.commit_sha)
        assert len(blast.affected_services) >= 1

    def test_blast_radius_compliance_controls_for_auth(self):
        e = _fresh()
        files = [{"path": "core/auth_backend.py", "change_type": "modified"}]
        c = _commit(e, sha="blastsha003", files=files)
        blast = e.compute_blast_radius(c.commit_sha)
        assert any("SOC2" in ctrl or "NIST" in ctrl or "PCI" in ctrl
                   for ctrl in blast.affected_compliance_controls)

    def test_blast_radius_to_dict_keys(self):
        e = _fresh()
        c = _commit(e, sha="blastsha004")
        blast = e.compute_blast_radius(c.commit_sha)
        d = blast.to_dict()
        for k in ("commit_sha", "affected_services", "affected_apis",
                   "affected_data_flows", "affected_compliance_controls",
                   "total_blast_score", "risk_level", "analysis_timestamp"):
            assert k in d

    def test_blast_radius_api_file_detected(self):
        e = _fresh()
        files = [{"path": "apps/api/auth_router.py", "change_type": "modified"}]
        c = _commit(e, sha="blastsha005", files=files)
        blast = e.compute_blast_radius(c.commit_sha)
        assert len(blast.affected_apis) >= 1

    def test_blast_weights_attribute(self):
        e = _fresh()
        assert "service" in e.BLAST_WEIGHTS
        assert "api" in e.BLAST_WEIGHTS
        assert "data_flow" in e.BLAST_WEIGHTS
        assert "compliance_control" in e.BLAST_WEIGHTS


# ===========================================================================
# 7. Developer Risk Profile
# ===========================================================================

class TestDeveloperRiskProfile:
    def test_profile_created_on_commit(self):
        e = _fresh()
        _commit(e, sha="devsha001")
        profiles = e.get_developer_profiles()
        assert len(profiles) == 1
        assert profiles[0].display_name == "Alice"

    def test_profile_dev_id_is_anonymised(self):
        e = _fresh()
        _commit(e, sha="devsha002")
        profiles = e.get_developer_profiles()
        assert profiles[0].developer_id.startswith("dev-")
        # Must not contain the actual email
        assert "alice@example.com" not in profiles[0].developer_id

    def test_multiple_commits_increment_counter(self):
        e = _fresh()
        _commit(e, sha="devsha003")
        _commit(e, sha="devsha004")
        profiles = e.get_developer_profiles()
        assert profiles[0].total_commits == 2

    def test_security_commit_increments_security_counter(self):
        e = _fresh()
        files = [{"path": "core/auth.py", "change_type": "modified"}]
        _commit(e, sha="devsha005", files=files)
        profiles = e.get_developer_profiles()
        assert profiles[0].security_relevant_commits == 1

    def test_profile_risk_score_range(self):
        e = _fresh()
        _commit(e, sha="devsha006")
        profiles = e.get_developer_profiles()
        assert 0.0 <= profiles[0].risk_score <= 1.0

    def test_record_finding_increases_defect_rate(self):
        e = _fresh()
        _commit(e, sha="devsha007")
        e.record_finding_for_developer("alice@example.com")
        profiles = e.get_developer_profiles()
        assert profiles[0].historical_defect_rate > 0.0

    def test_profile_to_dict_keys(self):
        e = _fresh()
        _commit(e, sha="devsha008")
        d = e.get_developer_profiles()[0].to_dict()
        for k in ("developer_id", "display_name", "total_commits",
                   "security_relevant_commits", "material_changes",
                   "historical_defect_rate", "code_review_coverage",
                   "security_training_completed", "risk_score",
                   "recommended_training"):
            assert k in d

    def test_different_developers_tracked_separately(self):
        e = _fresh()
        e.ingest_commit(commit_sha="ds009", author="Alice", author_email="alice@example.com", message="x")
        e.ingest_commit(commit_sha="ds010", author="Bob", author_email="bob@example.com", message="y")
        profiles = e.get_developer_profiles()
        assert len(profiles) == 2


# ===========================================================================
# 8. Timeline Reconstruction + Full Provenance Trace
# ===========================================================================

class TestTimeline:
    def test_timeline_minimal_has_discovery_event(self):
        e = _fresh()
        e.index_finding("FIND-TL-001")
        events = e.reconstruct_timeline("FIND-TL-001")
        assert any(ev.event_type == "vuln_discovered" for ev in events)

    def test_timeline_with_commit_has_code_written(self):
        e = _fresh()
        c = _commit(e, sha="tlsha001")
        e.index_finding("FIND-TL-002", commit_sha=c.commit_sha)
        events = e.reconstruct_timeline("FIND-TL-002")
        assert any(ev.event_type == "code_written" for ev in events)

    def test_timeline_with_artifact_has_built_event(self):
        e = _fresh()
        art = e.register_artifact("svc", "1.0", "tlsha002")
        e.index_finding("FIND-TL-003", artifact_id=art.artifact_id)
        events = e.reconstruct_timeline("FIND-TL-003")
        assert any(ev.event_type == "built" for ev in events)

    def test_timeline_with_deployment_has_deployed_event(self):
        e = _fresh()
        art = e.register_artifact("svc", "1.0", "tlsha003")
        dep = e.register_deployment(artifact_id=art.artifact_id)
        e.index_finding("FIND-TL-004", deployment_id=dep.deployment_id)
        events = e.reconstruct_timeline("FIND-TL-004")
        assert any(ev.event_type == "deployed" for ev in events)

    def test_timeline_events_sorted_by_timestamp(self):
        e = _fresh()
        c = _commit(e, sha="tlsha004", timestamp="2024-01-01T00:00:00+00:00")
        art = e.register_artifact("svc", "1.0", c.commit_sha, built_at="2024-01-02T00:00:00+00:00")
        dep = e.register_deployment(artifact_id=art.artifact_id, deployed_at="2024-01-03T00:00:00+00:00")
        e.index_finding(
            "FIND-TL-005",
            commit_sha=c.commit_sha,
            artifact_id=art.artifact_id,
            deployment_id=dep.deployment_id,
        )
        events = e.reconstruct_timeline("FIND-TL-005", discovered_at="2024-01-04T00:00:00+00:00")
        timestamps = [ev.timestamp for ev in events]
        assert timestamps == sorted(timestamps)

    def test_timeline_event_to_dict_keys(self):
        e = _fresh()
        e.index_finding("FIND-TL-006")
        events = e.reconstruct_timeline("FIND-TL-006")
        d = events[0].to_dict()
        for k in ("event_id", "event_type", "timestamp", "actor", "description", "metadata"):
            assert k in d


class TestProvenanceTrace:
    def test_full_trace_returns_provenance_trace(self):
        e = _fresh()
        trace = e.trace_finding("FIND-PT-001")
        assert isinstance(trace, ProvenanceTrace)

    def test_trace_id_prefix(self):
        e = _fresh()
        trace = e.trace_finding("FIND-PT-002")
        assert trace.trace_id.startswith("trace-")

    def test_full_provenance_chain(self):
        e = _fresh()
        c = _commit(e, sha="fullchain001",
                    timestamp="2024-01-01T10:00:00+00:00",
                    files=[{"path": "core/auth.py", "change_type": "modified"}])
        art = e.register_artifact("authsvc", "2.0", c.commit_sha,
                                  built_at="2024-01-01T11:00:00+00:00")
        dep = e.register_deployment(
            artifact_id=art.artifact_id,
            environment="production",
            internet_facing=True,
            deployed_at="2024-01-01T12:00:00+00:00",
        )
        e.index_finding(
            "FIND-FULL-001",
            commit_sha=c.commit_sha,
            artifact_id=art.artifact_id,
            deployment_id=dep.deployment_id,
        )
        trace = e.trace_finding("FIND-FULL-001", discovered_at="2024-01-02T12:00:00+00:00")

        assert trace.code_change is not None
        assert trace.build_artifact is not None
        assert trace.deployment is not None
        assert trace.blast_radius is not None
        assert trace.developer_profile is not None
        assert trace.exposure_duration_hours == 24.0
        assert trace.remediation_priority != ChangeRisk.NONE.value

    def test_exposure_duration_computed(self):
        e = _fresh()
        art = e.register_artifact("svc", "1.0", "expsha001",
                                  built_at="2024-06-01T00:00:00+00:00")
        dep = e.register_deployment(artifact_id=art.artifact_id,
                                    deployed_at="2024-06-01T00:00:00+00:00")
        e.index_finding("FIND-EXP-001", artifact_id=art.artifact_id, deployment_id=dep.deployment_id)
        trace = e.trace_finding("FIND-EXP-001", discovered_at="2024-06-02T12:00:00+00:00")
        assert trace.exposure_duration_hours == 36.0

    def test_trace_to_dict_keys(self):
        e = _fresh()
        trace = e.trace_finding("FIND-PT-003")
        d = trace.to_dict()
        for k in ("trace_id", "finding_id", "code_change", "build_artifact",
                   "deployment", "timeline", "developer_profile", "blast_radius",
                   "exposure_duration_hours", "remediation_priority", "generated_at"):
            assert k in d

    def test_remediation_priority_critical_for_internet_facing(self):
        e = _fresh()
        c = _commit(e, sha="prisha001",
                    files=[{"path": "core/auth.py", "change_type": "modified"}])
        art = e.register_artifact("svc", "1.0", c.commit_sha)
        dep = e.register_deployment(artifact_id=art.artifact_id, internet_facing=True)
        e.index_finding("FIND-PRI-001", commit_sha=c.commit_sha,
                         artifact_id=art.artifact_id, deployment_id=dep.deployment_id)
        trace = e.trace_finding("FIND-PRI-001")
        assert trace.remediation_priority in (
            ChangeRisk.CRITICAL.value, ChangeRisk.HIGH.value
        )


# ===========================================================================
# Webhook ingestion
# ===========================================================================

class TestWebhookIngestion:
    def test_push_webhook_ingests_commits(self):
        e = _fresh()
        payload = {
            "event_type": "push",
            "ref": "refs/heads/main",
            "commits": [
                {
                    "id": "webhook001abc",
                    "message": "feat: add new endpoint",
                    "author": {"name": "Charlie", "email": "charlie@example.com"},
                    "modified": ["suite-api/router.py"],
                    "added": [],
                    "removed": [],
                    "timestamp": "2024-01-01T10:00:00+00:00",
                }
            ],
        }
        result = e.process_webhook(payload)
        assert result["count"] == 1
        assert len(result["processed_changes"]) == 1

    def test_push_webhook_returns_event_type(self):
        e = _fresh()
        payload = {"event_type": "push", "commits": []}
        result = e.process_webhook(payload)
        assert result["event_type"] == "push"

    def test_pull_request_webhook_ingested(self):
        e = _fresh()
        payload = {
            "event_type": "pull_request",
            "pull_request": {
                "number": 42,
                "title": "Add auth module",
                "head": {"sha": "prwebhook001", "ref": "feature/auth"},
                "user": {"login": "dana", "email": "dana@example.com"},
            },
        }
        result = e.process_webhook(payload)
        assert result["count"] == 1

    def test_webhook_empty_commits(self):
        e = _fresh()
        payload = {"event_type": "push", "commits": []}
        result = e.process_webhook(payload)
        assert result["count"] == 0


# ===========================================================================
# Singleton
# ===========================================================================

class TestSingleton:
    def test_get_engine_returns_instance(self):
        engine = get_engine()
        assert isinstance(engine, CodeToCloudEngine)

    def test_get_engine_returns_same_instance(self):
        e1 = get_engine()
        e2 = get_engine()
        assert e1 is e2
