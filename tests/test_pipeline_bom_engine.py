"""Tests for PipelineBOMEngine (PBOM) — ALDECI GAP-017.

Covers:
- Full run lifecycle (record_run -> record_step -> record_artifact ->
  record_deploy -> complete_run).
- export_pbom nested shape (run -> steps[] -> artifacts[] -> deploys[]).
- Provenance lookup by sha256 across multiple runs / orgs.
- Step ordering in export_pbom.
- Realistic CI race: artifacts/deploys may arrive after complete_run.
- Input validation (invalid step_type, artifact_type, status, outcome,
  negative duration / size_bytes, missing fields).
- Org_id isolation (org_a cannot see org_b data).
- list_deployed_artifacts filter by environment.
- stats aggregations.
- ≥35 tests.
"""

from __future__ import annotations

import json
import sys

import pytest

sys.path.insert(0, "suite-core")
sys.path.insert(0, "suite-api")

from core.pipeline_bom_engine import PipelineBOMEngine  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine(tmp_path):
    return PipelineBOMEngine(db_path=str(tmp_path / "pipeline_bom.db"))


def _start_run(engine, org_id="org1", repo_ref="acme/api", commit_sha="abc123"):
    return engine.record_run(
        org_id=org_id,
        repo_ref=repo_ref,
        run_id_external="gha-7890",
        ci_provider="github-actions",
        trigger="push",
        branch="main",
        commit_sha=commit_sha,
    )


def _full_pipeline(engine, org_id="org1"):
    """Build a realistic build+test+scan+sign+publish+deploy pipeline."""
    run_id = _start_run(engine, org_id=org_id)
    s1 = engine.record_step(run_id, 1, "build", "build", image="gcr.io/kaniko:v1",
                            command="kaniko build .",
                            config_hash="cfg-1", duration_ms=45_000, outcome="success")
    s2 = engine.record_step(run_id, 2, "unit-tests", "test",
                            image="python:3.11", command="pytest -q",
                            config_hash="cfg-2", duration_ms=12_000, outcome="success")
    s3 = engine.record_step(run_id, 3, "sast", "scan",
                            image="semgrep/semgrep:latest", command="semgrep ci",
                            config_hash="cfg-3", duration_ms=8_000, outcome="success")
    s4 = engine.record_step(run_id, 4, "sign", "sign",
                            image="cgr.dev/chainguard/cosign",
                            command="cosign sign ...",
                            config_hash="cfg-4", duration_ms=2_500, outcome="success")
    s5 = engine.record_step(run_id, 5, "push", "publish",
                            image="gcr.io/go-containerregistry/crane",
                            command="crane push ...",
                            config_hash="cfg-5", duration_ms=6_000, outcome="success")
    s6 = engine.record_step(run_id, 6, "deploy-stg", "deploy",
                            image="bitnami/kubectl:1.29",
                            command="kubectl apply ...",
                            config_hash="cfg-6", duration_ms=3_500, outcome="success")

    a_image = engine.record_artifact(
        run_id, s1, "registry.acme.io/api:1.0.0", "container-image",
        sha256="sha256:aaaa1111", size_bytes=83_000_000,
        signed_by="", signature_algo="",
    )
    a_sbom = engine.record_artifact(
        run_id, s3, "registry.acme.io/api:1.0.0.sbom.json", "sbom",
        sha256="sha256:bbbb2222", size_bytes=120_000,
    )
    a_att = engine.record_artifact(
        run_id, s4, "registry.acme.io/api:1.0.0.att", "attestation",
        sha256="sha256:cccc3333", size_bytes=4_500,
        signed_by="ci@acme.io", signature_algo="sigstore",
    )

    dep = engine.record_deploy(
        run_id, a_image, environment="staging",
        target="cluster-stg/eu-west-1", deployed_by="gha-bot",
    )
    engine.complete_run(run_id, "success")
    return {
        "run_id": run_id,
        "steps": [s1, s2, s3, s4, s5, s6],
        "artifacts": {"image": a_image, "sbom": a_sbom, "attestation": a_att},
        "deploy": dep,
    }


# ---------------------------------------------------------------------------
# Schema / init
# ---------------------------------------------------------------------------


def test_ensure_schema_idempotent(engine, tmp_path):
    engine.ensure_schema()
    engine.ensure_schema()  # no error


def test_engine_creates_parent_dirs(tmp_path):
    db = tmp_path / "nested" / "sub" / "pbom.db"
    PipelineBOMEngine(db_path=str(db))
    assert db.parent.exists()


# ---------------------------------------------------------------------------
# record_run
# ---------------------------------------------------------------------------


def test_record_run_returns_uuid(engine):
    run_id = _start_run(engine)
    assert isinstance(run_id, str)
    assert len(run_id) == 36  # uuid4


def test_record_run_persists_fields(engine):
    run_id = engine.record_run(
        org_id="org1", repo_ref="acme/api", run_id_external="ext-1",
        ci_provider="gitlab-ci", trigger="merge_request",
        branch="feature/x", commit_sha="deadbeef",
    )
    run = engine._get_run(run_id)
    assert run["org_id"] == "org1"
    assert run["repo_ref"] == "acme/api"
    assert run["run_id_external"] == "ext-1"
    assert run["ci_provider"] == "gitlab-ci"
    assert run["trigger"] == "merge_request"
    assert run["branch"] == "feature/x"
    assert run["commit_sha"] == "deadbeef"
    assert run["status"] == "running"
    assert run["finished_at"] is None


def test_record_run_missing_org_raises(engine):
    with pytest.raises(ValueError, match="org_id"):
        engine.record_run(org_id="", repo_ref="r", run_id_external="x",
                          ci_provider="github-actions")


def test_record_run_missing_repo_ref_raises(engine):
    with pytest.raises(ValueError, match="repo_ref"):
        engine.record_run(org_id="o", repo_ref="", run_id_external="x",
                          ci_provider="github-actions")


def test_record_run_missing_ci_provider_raises(engine):
    with pytest.raises(ValueError, match="ci_provider"):
        engine.record_run(org_id="o", repo_ref="r", run_id_external="x",
                          ci_provider="")


# ---------------------------------------------------------------------------
# record_step
# ---------------------------------------------------------------------------


def test_record_step_basic(engine):
    run_id = _start_run(engine)
    sid = engine.record_step(run_id, 1, "build", "build", image="img",
                             command="cmd", config_hash="h",
                             duration_ms=100, outcome="success")
    assert isinstance(sid, str)


def test_record_step_invalid_type_raises(engine):
    run_id = _start_run(engine)
    with pytest.raises(ValueError, match="step_type"):
        engine.record_step(run_id, 1, "s", "bogus")


def test_record_step_invalid_outcome_raises(engine):
    run_id = _start_run(engine)
    with pytest.raises(ValueError, match="outcome"):
        engine.record_step(run_id, 1, "s", "build", outcome="weird")


def test_record_step_negative_duration_raises(engine):
    run_id = _start_run(engine)
    with pytest.raises(ValueError, match="duration_ms"):
        engine.record_step(run_id, 1, "s", "build", duration_ms=-5)


def test_record_step_unknown_run_raises(engine):
    with pytest.raises(ValueError, match="pipeline run not found"):
        engine.record_step("not-a-real-run", 1, "s", "build")


def test_record_step_all_valid_types(engine):
    run_id = _start_run(engine)
    for i, t in enumerate(
        ["build", "test", "lint", "scan", "sign", "publish", "deploy"], start=1
    ):
        engine.record_step(run_id, i, f"step-{t}", t)


# ---------------------------------------------------------------------------
# record_artifact
# ---------------------------------------------------------------------------


def test_record_artifact_basic(engine):
    run_id = _start_run(engine)
    sid = engine.record_step(run_id, 1, "build", "build")
    aid = engine.record_artifact(run_id, sid, "registry/img:1", "container-image",
                                  sha256="sha256:deadbeef", size_bytes=100)
    assert isinstance(aid, str)


def test_record_artifact_invalid_type_raises(engine):
    run_id = _start_run(engine)
    with pytest.raises(ValueError, match="artifact_type"):
        engine.record_artifact(run_id, None, "ref", "junk", sha256="x")


def test_record_artifact_missing_ref_raises(engine):
    run_id = _start_run(engine)
    with pytest.raises(ValueError, match="artifact_ref"):
        engine.record_artifact(run_id, None, "", "container-image", sha256="x")


def test_record_artifact_missing_sha_raises(engine):
    run_id = _start_run(engine)
    with pytest.raises(ValueError, match="sha256"):
        engine.record_artifact(run_id, None, "ref", "container-image", sha256="")


def test_record_artifact_negative_size_raises(engine):
    run_id = _start_run(engine)
    with pytest.raises(ValueError, match="size_bytes"):
        engine.record_artifact(run_id, None, "ref", "container-image",
                                sha256="x", size_bytes=-1)


def test_record_artifact_unknown_run_raises(engine):
    with pytest.raises(ValueError, match="pipeline run not found"):
        engine.record_artifact("not-a-run", None, "ref", "container-image",
                                sha256="x")


def test_record_artifact_without_step_id(engine):
    run_id = _start_run(engine)
    # Aggregate SBOM not attached to a single step.
    aid = engine.record_artifact(run_id, None, "sbom.json", "sbom",
                                  sha256="sha256:ffff")
    assert aid


# ---------------------------------------------------------------------------
# record_deploy
# ---------------------------------------------------------------------------


def test_record_deploy_basic(engine):
    run_id = _start_run(engine)
    sid = engine.record_step(run_id, 1, "build", "build")
    aid = engine.record_artifact(run_id, sid, "ref", "container-image",
                                  sha256="x")
    did = engine.record_deploy(run_id, aid, environment="prod",
                                target="cluster-prod", deployed_by="gha")
    assert isinstance(did, str)


def test_record_deploy_missing_env_raises(engine):
    run_id = _start_run(engine)
    aid = engine.record_artifact(run_id, None, "ref", "container-image",
                                  sha256="x")
    with pytest.raises(ValueError, match="environment"):
        engine.record_deploy(run_id, aid, environment="")


def test_record_deploy_unknown_run_raises(engine):
    run_id = _start_run(engine)
    aid = engine.record_artifact(run_id, None, "ref", "container-image",
                                  sha256="x")
    with pytest.raises(ValueError, match="pipeline run not found"):
        engine.record_deploy("not-a-run", aid, environment="prod")


def test_record_deploy_unknown_artifact_raises(engine):
    run_id = _start_run(engine)
    with pytest.raises(ValueError, match="artifact not found"):
        engine.record_deploy(run_id, "not-an-artifact", environment="prod")


def test_record_deploy_cross_org_rejected(engine):
    # artifact belongs to org_a, deploy run belongs to org_b -> reject.
    run_a = _start_run(engine, org_id="org_a")
    aid = engine.record_artifact(run_a, None, "ref", "container-image",
                                  sha256="cross-x")
    run_b = _start_run(engine, org_id="org_b")
    with pytest.raises(ValueError, match="same org"):
        engine.record_deploy(run_b, aid, environment="prod")


def test_record_deploy_from_different_run_same_org_ok(engine):
    # Artifact produced in run_1, deployed via run_2 in same org.
    run_1 = _start_run(engine, org_id="org1")
    aid = engine.record_artifact(run_1, None, "ref", "container-image",
                                  sha256="same-org-x")
    run_2 = _start_run(engine, org_id="org1")
    did = engine.record_deploy(run_2, aid, environment="prod")
    assert did


# ---------------------------------------------------------------------------
# complete_run
# ---------------------------------------------------------------------------


def test_complete_run_sets_status_and_finished(engine):
    run_id = _start_run(engine)
    run = engine.complete_run(run_id, "success")
    assert run["status"] == "success"
    assert run["finished_at"] is not None


def test_complete_run_invalid_status_raises(engine):
    run_id = _start_run(engine)
    with pytest.raises(ValueError, match="status"):
        engine.complete_run(run_id, "nope")


def test_complete_run_unknown_raises(engine):
    with pytest.raises(ValueError, match="pipeline run not found"):
        engine.complete_run("not-a-run", "success")


def test_complete_run_all_valid_statuses(engine):
    for status in ["queued", "running", "success", "failed", "cancelled", "partial"]:
        run_id = _start_run(engine)
        run = engine.complete_run(run_id, status)
        assert run["status"] == status


# ---------------------------------------------------------------------------
# Realistic CI race: late artifacts/deploys
# ---------------------------------------------------------------------------


def test_artifact_after_complete_run_allowed(engine):
    """Signature/attestation webhooks frequently land after the run finishes."""
    run_id = _start_run(engine)
    engine.complete_run(run_id, "success")
    aid = engine.record_artifact(run_id, None, "late.att", "attestation",
                                  sha256="late-sha",
                                  signed_by="ci", signature_algo="sigstore")
    assert aid


def test_deploy_after_complete_run_allowed(engine):
    run_id = _start_run(engine)
    aid = engine.record_artifact(run_id, None, "ref", "container-image",
                                  sha256="x")
    engine.complete_run(run_id, "success")
    did = engine.record_deploy(run_id, aid, environment="prod")
    assert did


# ---------------------------------------------------------------------------
# export_pbom
# ---------------------------------------------------------------------------


def test_export_pbom_shape(engine):
    data = _full_pipeline(engine)
    pbom = engine.export_pbom(data["run_id"])
    assert pbom["schema"] == "aldeci.pbom/v1"
    assert pbom["run"]["id"] == data["run_id"]
    assert pbom["run"]["status"] == "success"
    assert isinstance(pbom["steps"], list)
    assert len(pbom["steps"]) == 6
    assert "orphan_artifacts" in pbom


def test_export_pbom_step_ordering(engine):
    run_id = _start_run(engine)
    # Insert steps out of natural order to prove ORDER BY step_order works.
    engine.record_step(run_id, 3, "c", "scan")
    engine.record_step(run_id, 1, "a", "build")
    engine.record_step(run_id, 2, "b", "test")
    pbom = engine.export_pbom(run_id)
    names = [s["step_name"] for s in pbom["steps"]]
    assert names == ["a", "b", "c"]


def test_export_pbom_nested_artifacts_and_deploys(engine):
    data = _full_pipeline(engine)
    pbom = engine.export_pbom(data["run_id"])
    # Find the build step (step 1) and verify its artifact nests the deploy.
    build_step = next(s for s in pbom["steps"] if s["step_name"] == "build")
    assert len(build_step["artifacts"]) == 1
    assert build_step["artifacts"][0]["artifact_type"] == "container-image"
    assert len(build_step["artifacts"][0]["deploys"]) == 1
    assert build_step["artifacts"][0]["deploys"][0]["environment"] == "staging"


def test_export_pbom_orphan_artifacts(engine):
    run_id = _start_run(engine)
    engine.record_artifact(run_id, None, "agg.sbom", "sbom", sha256="orphan-x")
    pbom = engine.export_pbom(run_id)
    assert len(pbom["orphan_artifacts"]) == 1
    assert pbom["orphan_artifacts"][0]["artifact_ref"] == "agg.sbom"


def test_export_pbom_unknown_run_raises(engine):
    with pytest.raises(ValueError, match="pipeline run not found"):
        engine.export_pbom("not-a-run")


def test_export_pbom_json_is_valid_json(engine):
    data = _full_pipeline(engine)
    raw = engine.export_pbom_json(data["run_id"])
    parsed = json.loads(raw)
    assert parsed["schema"] == "aldeci.pbom/v1"


# ---------------------------------------------------------------------------
# Provenance lookup
# ---------------------------------------------------------------------------


def test_find_runs_producing_artifact_basic(engine):
    data = _full_pipeline(engine, org_id="org1")
    shas = [engine.export_pbom(data["run_id"])["steps"][0]["artifacts"][0]["sha256"]]
    # image sha we set was sha256:aaaa1111
    res = engine.find_runs_producing_artifact("org1", "sha256:aaaa1111")
    assert len(res) == 1
    assert res[0]["artifact"]["sha256"] == "sha256:aaaa1111"
    assert res[0]["run"]["id"] == data["run_id"]
    # deploys should be listed
    assert len(res[0]["deploys"]) == 1
    assert res[0]["deploys"][0]["environment"] == "staging"


def test_find_runs_producing_artifact_scoped_by_org(engine):
    run_a = _start_run(engine, org_id="org_a")
    engine.record_artifact(run_a, None, "ref", "container-image",
                            sha256="isolated-sha")
    run_b = _start_run(engine, org_id="org_b")
    engine.record_artifact(run_b, None, "ref", "container-image",
                            sha256="isolated-sha")
    # Same sha reused across orgs -> each org sees only its own.
    res_a = engine.find_runs_producing_artifact("org_a", "isolated-sha")
    res_b = engine.find_runs_producing_artifact("org_b", "isolated-sha")
    assert len(res_a) == 1 and res_a[0]["run"]["id"] == run_a
    assert len(res_b) == 1 and res_b[0]["run"]["id"] == run_b


def test_find_runs_producing_artifact_not_found(engine):
    assert engine.find_runs_producing_artifact("org1", "nonexistent-sha") == []


def test_find_runs_producing_artifact_missing_sha_raises(engine):
    with pytest.raises(ValueError, match="artifact_sha256"):
        engine.find_runs_producing_artifact("org1", "")


def test_find_runs_producing_artifact_multiple_runs_same_sha(engine):
    # Two rebuilds of the same image (same sha) in the same org.
    run_1 = _start_run(engine, org_id="org1")
    engine.record_artifact(run_1, None, "r", "container-image", sha256="rebuilt-x")
    run_2 = _start_run(engine, org_id="org1")
    engine.record_artifact(run_2, None, "r", "container-image", sha256="rebuilt-x")
    res = engine.find_runs_producing_artifact("org1", "rebuilt-x")
    assert len(res) == 2


# ---------------------------------------------------------------------------
# list_deployed_artifacts
# ---------------------------------------------------------------------------


def test_list_deployed_artifacts_all(engine):
    _full_pipeline(engine, org_id="org1")
    deps = engine.list_deployed_artifacts("org1")
    assert len(deps) == 1
    assert deps[0]["environment"] == "staging"
    # join columns present:
    assert "sha256" in deps[0]
    assert "repo_ref" in deps[0]


def test_list_deployed_artifacts_filter_by_env(engine):
    data = _full_pipeline(engine, org_id="org1")
    # Add a second deploy to prod
    engine.record_deploy(data["run_id"], data["artifacts"]["image"],
                         environment="prod", target="prod-cluster",
                         deployed_by="approver")
    stg = engine.list_deployed_artifacts("org1", environment="staging")
    prod = engine.list_deployed_artifacts("org1", environment="prod")
    assert len(stg) == 1 and stg[0]["environment"] == "staging"
    assert len(prod) == 1 and prod[0]["environment"] == "prod"


def test_list_deployed_artifacts_org_isolation(engine):
    _full_pipeline(engine, org_id="org_a")
    _full_pipeline(engine, org_id="org_b")
    assert len(engine.list_deployed_artifacts("org_a")) == 1
    assert len(engine.list_deployed_artifacts("org_b")) == 1
    assert len(engine.list_deployed_artifacts("org_c")) == 0


# ---------------------------------------------------------------------------
# stats
# ---------------------------------------------------------------------------


def test_stats_empty(engine):
    s = engine.stats("org1")
    assert s["total_runs"] == 0
    assert s["success_rate_pct"] == 0.0
    assert s["sign_rate_pct"] == 0.0
    assert s["deploys_by_env"] == {}


def test_stats_full_pipeline(engine):
    _full_pipeline(engine, org_id="org1")
    s = engine.stats("org1")
    assert s["total_runs"] == 1
    assert s["completed_runs"] == 1
    assert s["success_runs"] == 1
    assert s["success_rate_pct"] == 100.0
    assert s["total_steps"] == 6
    assert s["total_artifacts"] == 3
    assert s["signed_artifacts"] == 1  # only the attestation was signed
    assert s["total_deploys"] == 1
    assert s["deploys_by_env"] == {"staging": 1}


def test_stats_mixed_outcomes(engine):
    # One success, one failure
    r1 = _start_run(engine, org_id="org1")
    engine.complete_run(r1, "success")
    r2 = _start_run(engine, org_id="org1")
    engine.complete_run(r2, "failed")
    s = engine.stats("org1")
    assert s["total_runs"] == 2
    assert s["completed_runs"] == 2
    assert s["success_runs"] == 1
    assert s["success_rate_pct"] == 50.0


def test_stats_org_isolation(engine):
    _full_pipeline(engine, org_id="org_a")
    s_a = engine.stats("org_a")
    s_b = engine.stats("org_b")
    assert s_a["total_runs"] == 1
    assert s_b["total_runs"] == 0


# ---------------------------------------------------------------------------
# General org_id isolation
# ---------------------------------------------------------------------------


def test_export_pbom_unscoped_still_requires_run(engine):
    # export_pbom is keyed by run_db_id (uuid, unguessable), but still
    # validates the run exists.
    with pytest.raises(ValueError):
        engine.export_pbom("fake")


def test_run_of_org_a_invisible_in_org_b_stats(engine):
    run_a = _start_run(engine, org_id="org_a")
    engine.record_step(run_a, 1, "s", "build")
    engine.complete_run(run_a, "success")
    assert engine.stats("org_b")["total_runs"] == 0


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------


def test_get_engine_returns_singleton(tmp_path):
    from core.pipeline_bom_engine import get_engine
    e1 = get_engine(db_path=str(tmp_path / "a.db"))
    e2 = get_engine()  # no arg -> returns already-cached instance
    assert e1 is e2
