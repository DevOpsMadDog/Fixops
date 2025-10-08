"""Validate Postman assets that power the multi-phase bank validation flow."""

from __future__ import annotations

import json
from pathlib import Path


def _load_json(path: str) -> dict:
    file_path = Path(path)
    assert file_path.exists(), f"Missing Postman file: {file_path}"
    return json.loads(file_path.read_text(encoding="utf-8"))


def test_phase_one_health_collection_targets_core_probes() -> None:
    collection = _load_json(
        "fixops-blended-enterprise/postman/FixOps-Bank-API-Collection.json"
    )
    folders = collection.get("item", [])
    health_folder = next(
        (item for item in folders if item.get("name") == "🏥 Health & Monitoring"),
        None,
    )
    assert health_folder is not None, "Health folder missing from bank API collection"

    requests = {
        request.get("name"): request
        for request in health_folder.get("item", [])
        if isinstance(request, dict)
    }

    expected_paths = {
        "Health Check (Liveness Probe)": "/health",
        "Readiness Check (K8s Probe)": "/ready",
        "Prometheus Metrics": "/metrics",
    }

    for name, path in expected_paths.items():
        request = requests.get(name)
        assert request is not None, f"Request '{name}' missing from health folder"
        url = request.get("request", {}).get("url")
        if isinstance(url, dict):
            raw = url.get("raw")
        else:
            raw = url
        assert isinstance(raw, str), f"Request '{name}' URL not captured"
        assert raw.endswith(path), f"Request '{name}' should target {path}, got {raw!r}"


def test_phase_two_cicd_collection_covers_allow_block_defer() -> None:
    collection = _load_json(
        "fixops-blended-enterprise/postman/FixOps-CICD-Tests.postman_collection.json"
    )
    items = {
        item.get("name"): item
        for item in collection.get("item", [])
        if isinstance(item, dict)
    }

    expected_names = {
        "1. Pre-Deployment Health Check": ("GET", "/ready"),
        "2. Payment Service - Should ALLOW": ("POST", "/api/v1/cicd/decision"),
        "3. Auth Service - Should BLOCK": ("POST", "/api/v1/cicd/decision"),
        "4. API Gateway - Should DEFER": ("POST", "/api/v1/cicd/decision"),
        "KEV Hard Block Without Waiver": ("POST", "/policy/evaluate"),
        "Signed Evidence Retrieval": ("GET", "/decisions/evidence"),
        "Negative Signature Verification": ("POST", "/cicd/verify-signature"),
    }

    for name, (method, expected_path) in expected_names.items():
        item = items.get(name)
        assert item is not None, f"Scenario '{name}' missing from CI/CD collection"
        request = item.get("request", {})
        assert request.get("method") == method, f"Scenario '{name}' uses wrong method"
        url = request.get("url")
        raw = url.get("raw") if isinstance(url, dict) else url
        assert isinstance(raw, str)
        assert expected_path in raw, f"Scenario '{name}' should reference {expected_path}"


def test_phase_three_performance_collection_targets_hot_path() -> None:
    collection = _load_json(
        "fixops-blended-enterprise/postman/FixOps-Performance-Tests.postman_collection.json"
    )
    items = collection.get("item", [])
    assert {item.get("name") for item in items} == {
        "Load Test - Decision API",
        "Concurrent Decision Test",
    }

    for item in items:
        request = item.get("request", {})
        assert request.get("method") == "POST"
        url = request.get("url")
        raw = url.get("raw") if isinstance(url, dict) else url
        assert isinstance(raw, str)
        assert raw.endswith("/api/v1/decisions/make-decision")

        scripts = []
        for event in item.get("event", []) or []:
            script = event.get("script", {})
            exec_lines = script.get("exec", []) if isinstance(script, dict) else []
            scripts.extend(exec_lines)

        script_blob = "\n".join(scripts)
        if item.get("name") == "Load Test - Decision API":
            assert "Response time under bank SLA (2s)" in script_blob
            assert "Hot path latency target (299μs)" in script_blob
        else:
            assert "Concurrent request handled" in script_blob


def test_bank_api_script_references_all_collections() -> None:
    script_path = Path("fixops-blended-enterprise/test-bank-api.sh")
    script_text = script_path.read_text(encoding="utf-8")

    for filename in [
        "FixOps-Bank-API-Collection.json",
        "FixOps-CICD-Tests.postman_collection.json",
        "FixOps-Performance-Tests.postman_collection.json",
    ]:
        assert filename in script_text, f"Script missing reference to {filename}"
        assert (Path("fixops-blended-enterprise/postman") / filename).exists()

    # Ensure script calls out each validation phase
    assert "Phase 1: Health & Readiness Validation" in script_text
    assert "Phase 2: CI/CD Pipeline Integration" in script_text
    assert "Phase 3: Performance & SLA Validation" in script_text
