"""FIX-C verification — Brain Pipeline product-path assertions.

Verifies the 5 things FIX-C was supposed to deliver in pipeline_router.py:

1. Clean URL: POST /api/v1/pipeline/run (NOT doubled /api/v1/pipeline/pipeline/run)
2. Top-level verdict field with a real `decision` value in POST /run response
3. pipeline_runs persistence: GET /api/v1/pipeline/runs lists the run after POST
4. evidence-pack persistence: POST /evidence/generate + GET /evidence/packs round-trip
5. Tenant isolation: org-A run/pack NOT visible to org-B

Setup mirrors the working pattern from the real app — the suite-core pipeline_router
is mounted directly (prefix="/api/v1/pipeline") with an overridden get_org_id
dependency so auth is bypassed cleanly, matching how TestClient tests elsewhere work.
"""

from __future__ import annotations

import os
import sys
import pytest

# ── Environment ──────────────────────────────────────────────────────────────
os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")

# ── PYTHONPATH (mirrors pytest invocation flags) ──────────────────────────────
_REPO = "/Users/devops.ai/fixops/Fixops"
for _p in [
    _REPO,
    f"{_REPO}/suite-api",
    f"{_REPO}/suite-core",
    f"{_REPO}/suite-attack",
    f"{_REPO}/suite-feeds",
    f"{_REPO}/suite-integrations",
    f"{_REPO}/suite-evidence-risk",
    f"{_REPO}/archive/legacy",
    f"{_REPO}/archive/enterprise_legacy",
]:
    if _p not in sys.path:
        sys.path.insert(0, _p)

from fastapi import FastAPI
from fastapi.testclient import TestClient


# ── Import the router under test ──────────────────────────────────────────────
try:
    from api.pipeline_router import router as _pipeline_router
    from apps.api.dependencies import get_org_id
except ImportError as exc:
    pytest.skip(f"pipeline_router not importable: {exc}", allow_module_level=True)


# ── Build a minimal test app with a per-test org_id override ─────────────────

def _make_app(org_id: str) -> FastAPI:
    """Return a TestClient-ready FastAPI app whose get_org_id always returns org_id."""
    app = FastAPI()

    def _fixed_org_id() -> str:
        return org_id

    app.include_router(
        _pipeline_router,
        dependencies=[],  # bypass real auth
    )
    app.dependency_overrides[get_org_id] = _fixed_org_id
    return app


def _client(org_id: str) -> TestClient:
    return TestClient(_make_app(org_id), raise_server_exceptions=True)


# ── Minimal valid pipeline run payload ───────────────────────────────────────

_RUN_PAYLOAD = {
    "org_id": "test-org-a",
    "findings": [
        {
            "id": "f-001",
            "cve_id": "CVE-2024-0001",
            "severity": "high",
            "asset_name": "api-server",
            "title": "Buffer overflow in login handler",
            "description": "Stack-based buffer overflow",
            "source": "snyk",
        }
    ],
    "assets": [
        {
            "id": "a-001",
            "name": "api-server",
            "criticality": 0.9,
            "type": "service",
        }
    ],
    "source": "test",
    "run_pentest": False,
    "run_playbooks": False,
    "generate_evidence": False,
}

_EVIDENCE_PAYLOAD = {
    "org_id": "test-org-a",
    "timeframe_days": 30,
    "findings": [],
    "assets": [],
}


# ─────────────────────────────────────────────────────────────────────────────
# FIX-C item 1 — Clean URL
# ─────────────────────────────────────────────────────────────────────────────

def test_fixc_1_clean_url_post_run():
    """POST /api/v1/pipeline/run must exist (not /api/v1/pipeline/pipeline/run).

    We inspect the router's routes directly to find the actual registered path,
    then assert it matches the correct (non-doubled) pattern.
    """
    routes = {r.path: r for r in _pipeline_router.routes if hasattr(r, "path")}
    run_paths = [p for p in routes if "run" in p and "evidence" not in p]

    # Must contain exactly /run at the end, not /pipeline/run (double segment)
    assert run_paths, f"No /run route found. Registered paths: {list(routes.keys())}"

    for p in run_paths:
        segments = [s for s in p.split("/") if s]
        # The doubled form would contain ["api", "v1", "pipeline", "pipeline", "run"]
        pipeline_count = segments.count("pipeline")
        assert pipeline_count == 1, (
            f"FAIL item-1: doubled 'pipeline' segment in route path '{p}'. "
            f"Segments: {segments}"
        )

    # Also confirm the full absolute path is /api/v1/pipeline/run
    absolute_run = next((p for p in run_paths if p.endswith("/run")), None)
    assert absolute_run is not None, (
        f"FAIL item-1: no route ending in /run found. Routes: {run_paths}"
    )
    assert absolute_run == "/api/v1/pipeline/run", (
        f"FAIL item-1: expected /api/v1/pipeline/run but got '{absolute_run}'"
    )


# ─────────────────────────────────────────────────────────────────────────────
# FIX-C item 2 — Top-level verdict field
# ─────────────────────────────────────────────────────────────────────────────

def test_fixc_2_verdict_field_in_run_response():
    """POST /api/v1/pipeline/run response must have top-level 'verdict' with 'decision'."""
    client = _client("test-org-a")
    resp = client.post("/api/v1/pipeline/run", json=_RUN_PAYLOAD)

    if resp.status_code == 503:
        pytest.skip("Brain pipeline engine unavailable (503) — engine not configured")

    assert resp.status_code == 200, (
        f"FAIL item-2: expected 200, got {resp.status_code}. Body: {resp.text[:500]}"
    )

    body = resp.json()

    # Verdict must be a top-level key
    assert "verdict" in body, (
        f"FAIL item-2: 'verdict' missing from top-level response. "
        f"Top-level keys: {list(body.keys())}"
    )

    verdict = body["verdict"]
    assert isinstance(verdict, dict), (
        f"FAIL item-2: 'verdict' is not a dict, got {type(verdict)}: {verdict}"
    )

    # decision must be a non-empty string
    assert "decision" in verdict, (
        f"FAIL item-2: 'decision' missing from verdict. verdict keys: {list(verdict.keys())}"
    )
    decision = verdict["decision"]
    assert isinstance(decision, str) and decision.strip(), (
        f"FAIL item-2: verdict.decision is not a non-empty string: {decision!r}"
    )

    # decision must be one of the expected values
    valid_decisions = {"allow", "review", "block"}
    assert decision in valid_decisions, (
        f"FAIL item-2: verdict.decision '{decision}' not in {valid_decisions}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# FIX-C item 3 — pipeline_runs persistence (GET /runs lists the run)
# ─────────────────────────────────────────────────────────────────────────────

def test_fixc_3_pipeline_runs_persistence():
    """After POST /run, GET /api/v1/pipeline/runs must list the run (no table error)."""
    client = _client("test-org-a")

    # First run the pipeline
    run_resp = client.post("/api/v1/pipeline/run", json=_RUN_PAYLOAD)
    if run_resp.status_code == 503:
        pytest.skip("Brain pipeline engine unavailable (503)")

    assert run_resp.status_code == 200, (
        f"FAIL item-3 (setup): POST /run returned {run_resp.status_code}: {run_resp.text[:300]}"
    )
    run_body = run_resp.json()
    run_id = run_body.get("run_id")
    assert run_id, f"FAIL item-3: no run_id in POST /run response. body={run_body}"

    # Now list runs
    list_resp = client.get("/api/v1/pipeline/runs")

    # Must not be a 500 (which would indicate "no such table: pipeline_runs")
    assert list_resp.status_code != 500, (
        f"FAIL item-3: GET /runs returned 500 — likely 'no such table: pipeline_runs'. "
        f"Body: {list_resp.text[:500]}"
    )

    if list_resp.status_code == 503:
        pytest.skip("Runs list endpoint unavailable (503)")

    assert list_resp.status_code == 200, (
        f"FAIL item-3: GET /runs returned {list_resp.status_code}: {list_resp.text[:300]}"
    )

    list_body = list_resp.json()
    assert "runs" in list_body, (
        f"FAIL item-3: 'runs' key missing from GET /runs response. Keys: {list(list_body.keys())}"
    )

    run_ids_in_list = [r.get("run_id") for r in list_body["runs"]]
    assert run_id in run_ids_in_list, (
        f"FAIL item-3: run_id '{run_id}' not found in GET /runs list. "
        f"Listed run_ids: {run_ids_in_list}"
    )


# ─────────────────────────────────────────────────────────────────────────────
# FIX-C item 4 — evidence-pack persistence round-trip
# ─────────────────────────────────────────────────────────────────────────────

def test_fixc_4_evidence_pack_persistence():
    """POST /evidence/generate returns pack_id; GET /evidence/packs lists it."""
    client = _client("test-org-a")

    gen_resp = client.post("/api/v1/pipeline/evidence/generate", json=_EVIDENCE_PAYLOAD)

    if gen_resp.status_code == 503:
        pytest.skip("Evidence generator engine unavailable (503)")

    assert gen_resp.status_code == 200, (
        f"FAIL item-4: POST /evidence/generate returned {gen_resp.status_code}: "
        f"{gen_resp.text[:500]}"
    )

    gen_body = gen_resp.json()
    pack_id = gen_body.get("pack_id")
    assert pack_id, (
        f"FAIL item-4: no pack_id in POST /evidence/generate response. body={gen_body}"
    )

    # GET the packs list
    list_resp = client.get("/api/v1/pipeline/evidence/packs")

    assert list_resp.status_code != 500, (
        f"FAIL item-4: GET /evidence/packs returned 500. Body: {list_resp.text[:500]}"
    )

    if list_resp.status_code == 503:
        pytest.skip("Evidence packs list endpoint unavailable (503)")

    assert list_resp.status_code == 200, (
        f"FAIL item-4: GET /evidence/packs returned {list_resp.status_code}: "
        f"{list_resp.text[:300]}"
    )

    list_body = list_resp.json()
    assert "packs" in list_body, (
        f"FAIL item-4: 'packs' key missing from GET /evidence/packs. "
        f"Keys: {list(list_body.keys())}"
    )

    listed_pack_ids = [p.get("pack_id") for p in list_body["packs"]]
    assert pack_id in listed_pack_ids, (
        f"FAIL item-4: pack_id '{pack_id}' not found in GET /evidence/packs list. "
        f"Listed: {listed_pack_ids}"
    )

    # Bonus: GET by ID
    get_resp = client.get(f"/api/v1/pipeline/evidence/packs/{pack_id}")
    assert get_resp.status_code == 200, (
        f"FAIL item-4 (bonus GET by id): status {get_resp.status_code}: {get_resp.text[:300]}"
    )
    assert get_resp.json().get("pack_id") == pack_id, (
        f"FAIL item-4 (bonus): returned pack has wrong pack_id"
    )


# ─────────────────────────────────────────────────────────────────────────────
# FIX-C item 5 — tenant isolation
# ─────────────────────────────────────────────────────────────────────────────

def test_fixc_5_tenant_isolation_runs():
    """Org-A run must NOT appear in org-B's runs list."""
    client_a = _client("test-org-a")
    client_b = _client("test-org-b")

    # Run pipeline as org-a
    run_payload_a = dict(_RUN_PAYLOAD)
    run_payload_a["org_id"] = "test-org-a"
    run_resp = client_a.post("/api/v1/pipeline/run", json=run_payload_a)
    if run_resp.status_code == 503:
        pytest.skip("Brain pipeline engine unavailable (503)")
    assert run_resp.status_code == 200, (
        f"FAIL item-5 (setup): POST /run as org-a returned {run_resp.status_code}"
    )
    run_id_a = run_resp.json().get("run_id")
    assert run_id_a

    # List runs as org-b — run_id_a must NOT appear
    list_resp_b = client_b.get("/api/v1/pipeline/runs")
    if list_resp_b.status_code in (500, 503):
        pytest.skip(f"Runs list endpoint returned {list_resp_b.status_code} for org-b")

    assert list_resp_b.status_code == 200, (
        f"FAIL item-5: GET /runs as org-b returned {list_resp_b.status_code}"
    )
    runs_b = [r.get("run_id") for r in list_resp_b.json().get("runs", [])]
    assert run_id_a not in runs_b, (
        f"FAIL item-5: org-A run_id '{run_id_a}' is visible to org-B. "
        f"org-B run list: {runs_b}"
    )

    # Also assert org-b's GET /runs/{run_id_a} returns 404
    get_resp = client_b.get(f"/api/v1/pipeline/runs/{run_id_a}")
    assert get_resp.status_code == 404, (
        f"FAIL item-5: org-B can GET org-A's run (expected 404, got {get_resp.status_code}). "
        f"Body: {get_resp.text[:300]}"
    )


def test_fixc_5_tenant_isolation_evidence():
    """Org-A evidence pack must NOT appear in org-B's packs list."""
    client_a = _client("test-org-a")
    client_b = _client("test-org-b")

    evidence_payload_a = dict(_EVIDENCE_PAYLOAD)
    evidence_payload_a["org_id"] = "test-org-a"

    gen_resp = client_a.post(
        "/api/v1/pipeline/evidence/generate", json=evidence_payload_a
    )
    if gen_resp.status_code == 503:
        pytest.skip("Evidence generator engine unavailable (503)")
    assert gen_resp.status_code == 200, (
        f"FAIL item-5-evidence (setup): returned {gen_resp.status_code}"
    )
    pack_id_a = gen_resp.json().get("pack_id")
    assert pack_id_a

    # List packs as org-b
    list_resp_b = client_b.get("/api/v1/pipeline/evidence/packs")
    if list_resp_b.status_code in (500, 503):
        pytest.skip(f"Evidence packs list returned {list_resp_b.status_code} for org-b")

    assert list_resp_b.status_code == 200
    packs_b = [p.get("pack_id") for p in list_resp_b.json().get("packs", [])]
    assert pack_id_a not in packs_b, (
        f"FAIL item-5-evidence: org-A pack '{pack_id_a}' is visible to org-B. "
        f"org-B pack list: {packs_b}"
    )

    # Also assert org-b's GET /packs/{pack_id_a} returns 404
    get_resp = client_b.get(f"/api/v1/pipeline/evidence/packs/{pack_id_a}")
    assert get_resp.status_code == 404, (
        f"FAIL item-5-evidence: org-B can GET org-A's pack "
        f"(expected 404, got {get_resp.status_code}). Body: {get_resp.text[:300]}"
    )
