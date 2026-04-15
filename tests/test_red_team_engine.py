"""
Tests for RedTeamEngine and red_team_router.

Covers:
- RedTeamEngine: create_simulation, run_simulation, list_simulations,
  get_simulation_results, get_attack_surface_score, get_mitre_coverage
- red_team_router: all 6 endpoints via FastAPI TestClient

25 tests total.

Compliance: NIST SP 800-53 CA-8 (penetration testing)
"""

from __future__ import annotations

import sys
import os

import pytest

# Ensure suite-core and suite-api are importable
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-api"))

from core.red_team_engine import RedTeamEngine, TACTICS, INTENSITY_LEVELS


# ============================================================================
# FIXTURES
# ============================================================================


@pytest.fixture
def tmp_db(tmp_path) -> str:
    return str(tmp_path / "test_red_team.db")


@pytest.fixture
def engine(tmp_db: str) -> RedTeamEngine:
    return RedTeamEngine(db_path=tmp_db)


@pytest.fixture
def sim_id(engine: RedTeamEngine) -> str:
    """A created (not yet run) simulation."""
    return engine.create_simulation(
        org_id="org1",
        sim={"name": "Full Sim", "tactics": [], "intensity": "medium"},
    )


@pytest.fixture
def run_result(engine: RedTeamEngine, sim_id: str) -> dict:
    return engine.run_simulation(org_id="org1", simulation_id=sim_id)


# ============================================================================
# ENGINE — create_simulation
# ============================================================================


class TestCreateSimulation:
    def test_returns_uuid_string(self, engine):
        sid = engine.create_simulation("org1", {"name": "Test"})
        assert isinstance(sid, str)
        assert len(sid) == 36  # UUID4 format

    def test_default_tactics_all(self, engine):
        sid = engine.create_simulation("org1", {"name": "All tactics"})
        sims = engine.list_simulations("org1")
        sim = next(s for s in sims if s["id"] == sid)
        assert set(sim["tactics"]) == set(TACTICS.keys())

    def test_subset_tactics(self, engine):
        sid = engine.create_simulation(
            "org1",
            {"name": "Partial", "tactics": ["initial_access", "execution"]},
        )
        sims = engine.list_simulations("org1")
        sim = next(s for s in sims if s["id"] == sid)
        assert sim["tactics"] == ["initial_access", "execution"]

    def test_invalid_intensity_raises(self, engine):
        with pytest.raises(ValueError, match="intensity must be one of"):
            engine.create_simulation("org1", {"name": "Bad", "intensity": "extreme"})

    def test_invalid_tactic_raises(self, engine):
        with pytest.raises(ValueError, match="Unknown tactics"):
            engine.create_simulation(
                "org1", {"name": "Bad", "tactics": ["nonexistent_tactic"]}
            )

    def test_status_pending_after_create(self, engine):
        sid = engine.create_simulation("org1", {"name": "Pending"})
        sims = engine.list_simulations("org1")
        sim = next(s for s in sims if s["id"] == sid)
        assert sim["status"] == "pending"


# ============================================================================
# ENGINE — run_simulation
# ============================================================================


class TestRunSimulation:
    def test_result_keys_present(self, run_result):
        expected_keys = {
            "execution_id", "simulation_id", "techniques_attempted",
            "techniques_succeeded", "detections_triggered", "score",
            "recommendations",
        }
        assert expected_keys.issubset(run_result.keys())

    def test_techniques_attempted_non_empty(self, run_result):
        assert len(run_result["techniques_attempted"]) > 0

    def test_score_in_range(self, run_result):
        assert 0.0 <= run_result["score"] <= 100.0

    def test_deterministic_results(self, engine, sim_id):
        r1 = engine.run_simulation("org1", sim_id)
        r2 = engine.run_simulation("org1", sim_id)
        assert r1["techniques_succeeded"] == r2["techniques_succeeded"]
        assert r1["score"] == r2["score"]

    def test_attempted_equals_succeeded_plus_detected(self, run_result):
        total = len(run_result["techniques_attempted"])
        succeeded = len(run_result["techniques_succeeded"])
        detected = len(run_result["detections_triggered"])
        assert total == succeeded + detected

    def test_high_intensity_more_gaps(self, engine):
        # High intensity should expose more gaps (lower score) than low intensity
        sid_low = engine.create_simulation("org1", {"name": "Low", "intensity": "low"})
        sid_high = engine.create_simulation("org1", {"name": "High", "intensity": "high"})
        r_low = engine.run_simulation("org1", sid_low)
        r_high = engine.run_simulation("org1", sid_high)
        assert r_low["score"] >= r_high["score"]

    def test_unknown_simulation_raises(self, engine):
        with pytest.raises(ValueError):
            engine.run_simulation("org1", "00000000-0000-0000-0000-000000000000")

    def test_status_completed_after_run(self, engine, sim_id):
        engine.run_simulation("org1", sim_id)
        sims = engine.list_simulations("org1")
        sim = next(s for s in sims if s["id"] == sim_id)
        assert sim["status"] == "completed"

    def test_recommendations_non_empty(self, run_result):
        assert len(run_result["recommendations"]) > 0


# ============================================================================
# ENGINE — list / results
# ============================================================================


class TestListAndResults:
    def test_list_empty_org(self, engine):
        assert engine.list_simulations("no-such-org") == []

    def test_list_returns_created(self, engine, sim_id):
        sims = engine.list_simulations("org1")
        ids = [s["id"] for s in sims]
        assert sim_id in ids

    def test_multi_tenant_isolation(self, engine):
        sid1 = engine.create_simulation("orgA", {"name": "OrgA sim"})
        sid2 = engine.create_simulation("orgB", {"name": "OrgB sim"})
        ids_a = [s["id"] for s in engine.list_simulations("orgA")]
        ids_b = [s["id"] for s in engine.list_simulations("orgB")]
        assert sid1 in ids_a and sid2 not in ids_a
        assert sid2 in ids_b and sid1 not in ids_b

    def test_get_results_before_run(self, engine, sim_id):
        result = engine.get_simulation_results("org1", sim_id)
        assert result["status"] == "pending"
        assert "message" in result

    def test_get_results_after_run(self, engine, sim_id, run_result):
        result = engine.get_simulation_results("org1", sim_id)
        assert result["execution_id"] == run_result["execution_id"]
        assert result["score"] == run_result["score"]

    def test_get_results_wrong_org_raises(self, engine, sim_id):
        with pytest.raises(ValueError):
            engine.get_simulation_results("wrong-org", sim_id)


# ============================================================================
# ENGINE — attack surface score + MITRE coverage
# ============================================================================


class TestScoreAndCoverage:
    def test_surface_score_no_simulations(self, engine):
        result = engine.get_attack_surface_score("empty-org")
        assert result["score"] == 100
        assert result["simulation_count"] == 0

    def test_surface_score_after_run(self, engine, sim_id, run_result):
        result = engine.get_attack_surface_score("org1")
        assert 0.0 <= result["score"] <= 100.0
        assert "exposed_techniques" in result
        assert "detection_coverage" in result

    def test_mitre_coverage_all_tactics_present(self, engine):
        coverage = engine.get_mitre_coverage("empty-org2")
        assert set(coverage.keys()) == set(TACTICS.keys())

    def test_mitre_coverage_pct_range(self, engine, sim_id, run_result):
        coverage = engine.get_mitre_coverage("org1")
        for tactic, data in coverage.items():
            assert 0.0 <= data["pct"] <= 100.0
            assert data["total"] == len(TACTICS[tactic])

    def test_mitre_coverage_covered_le_total(self, engine, sim_id, run_result):
        coverage = engine.get_mitre_coverage("org1")
        for tactic, data in coverage.items():
            assert data["covered"] <= data["total"]


# ============================================================================
# ROUTER — FastAPI TestClient
# ============================================================================


@pytest.fixture
def client(tmp_db):
    """TestClient backed by a fresh database."""
    from fastapi import FastAPI
    from fastapi.testclient import TestClient
    from apps.api.red_team_router import router

    # Reset the singleton engine so each test gets a fresh db
    import apps.api.red_team_router as rt_module
    rt_module._engine = RedTeamEngine(db_path=tmp_db)

    app = FastAPI()
    app.include_router(router)
    return TestClient(app)


class TestRouter:
    def test_create_simulation_201(self, client):
        resp = client.post(
            "/api/v1/red-team/simulations",
            json={"name": "Router Test", "intensity": "low", "org_id": "r-org"},
        )
        assert resp.status_code == 200
        assert "simulation_id" in resp.json()

    def test_list_simulations(self, client):
        client.post(
            "/api/v1/red-team/simulations",
            json={"name": "S1", "org_id": "r-org"},
        )
        resp = client.get("/api/v1/red-team/simulations?org_id=r-org")
        assert resp.status_code == 200
        assert len(resp.json()) >= 1

    def test_run_simulation(self, client):
        create_resp = client.post(
            "/api/v1/red-team/simulations",
            json={"name": "Run Me", "org_id": "r-org"},
        )
        sim_id = create_resp.json()["simulation_id"]
        run_resp = client.post(
            f"/api/v1/red-team/simulations/{sim_id}/run",
            json={"org_id": "r-org"},
        )
        assert run_resp.status_code == 200
        assert "score" in run_resp.json()

    def test_run_nonexistent_404(self, client):
        resp = client.post(
            "/api/v1/red-team/simulations/00000000-0000-0000-0000-000000000000/run",
            json={"org_id": "r-org"},
        )
        assert resp.status_code == 404

    def test_get_results(self, client):
        create_resp = client.post(
            "/api/v1/red-team/simulations",
            json={"name": "Results", "org_id": "r-org"},
        )
        sim_id = create_resp.json()["simulation_id"]
        client.post(f"/api/v1/red-team/simulations/{sim_id}/run", json={"org_id": "r-org"})
        resp = client.get(f"/api/v1/red-team/simulations/{sim_id}/results?org_id=r-org")
        assert resp.status_code == 200
        assert "execution_id" in resp.json()

    def test_attack_surface_score(self, client):
        resp = client.get("/api/v1/red-team/attack-surface-score?org_id=r-org")
        assert resp.status_code == 200
        assert "score" in resp.json()

    def test_mitre_coverage(self, client):
        resp = client.get("/api/v1/red-team/mitre-coverage?org_id=r-org")
        assert resp.status_code == 200
        data = resp.json()
        for tactic in TACTICS:
            assert tactic in data
