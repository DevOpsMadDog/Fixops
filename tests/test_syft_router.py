"""Tests for the Syft SBOM router (real engine, no mocks).

Covers:
  GET  /api/v1/syft/                  capability summary
  POST /api/v1/syft/sbom              generate SBOM (dir + file inputs)
  GET  /api/v1/syft/sbom/{sbom_id}    fetch generated SBOM
  GET  /api/v1/syft/sbom              list recent SBOMs
  validation errors (bad input_type / bad output_format / bad scope / empty target)
  multiple output formats (cyclonedx-json, spdx-json, syft-table, github-json)

Determinism note
----------------
``FIXOPS_SYFT_DISABLE_REAL=1`` is set on every fixture so the engine uses its
in-process fallback parser even when the real ``syft`` binary is installed
(e.g. ``/opt/homebrew/bin/syft`` on macOS dev machines).  Without this, the
real binary's output would shift assertions about ``package_count`` and field
shapes between machines.
"""

from __future__ import annotations

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-core"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "suite-api"))

from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture
def client(tmp_path, monkeypatch):
    """Spin up a TestClient with the Syft router mounted on a fresh tmp DB.

    Forces ``FIXOPS_SYFT_DISABLE_REAL=1`` so that even when the real Syft
    binary is on PATH (dev machines), the engine uses the deterministic
    in-process fallback parser.
    """
    db_path = tmp_path / "syft_sboms.db"
    monkeypatch.setenv("FIXOPS_SYFT_SBOM_DB", str(db_path))
    monkeypatch.setenv("FIXOPS_SYFT_DISABLE_REAL", "1")

    # Reset singleton between tests so the new env var is honoured.
    import core.syft_sbom_engine as engine_mod  # noqa: PLC0415

    engine_mod._singleton = None

    from apps.api.syft_router import router  # noqa: PLC0415

    app = FastAPI()
    app.include_router(router)
    return TestClient(app, raise_server_exceptions=True)


# ---------------------------------------------------------------------------
# 1. GET / — capability summary, status=empty when no SBOMs yet
# ---------------------------------------------------------------------------
def test_capabilities_summary_empty(client):
    resp = client.get("/api/v1/syft/")
    assert resp.status_code == 200
    body = resp.json()

    assert body["service"] == "Syft"
    assert body["status"] == "empty"
    assert body["total_sboms"] == 0

    # Required catalogues
    assert set(body["input_types"]) == {"image", "dir", "file", "registry"}
    assert "cyclonedx-json" in body["output_formats"]
    assert "spdx-json" in body["output_formats"]
    assert "github-json" in body["output_formats"]
    assert "syft-table" in body["output_formats"]
    assert set(body["scope_options"]) == {"Squashed", "AllLayers"}
    assert body["default_output_format"] == "cyclonedx-json"
    assert body["default_scope"] == "Squashed"
    # Real binary disabled by fixture → capability advertises in-process mode.
    assert body["syft_binary_available"] is False


# ---------------------------------------------------------------------------
# 2. POST /sbom — dir input scans a real requirements.txt and parses packages
# ---------------------------------------------------------------------------
def test_generate_sbom_dir_input_parses_packages(client, tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "requirements.txt").write_text(
        "fastapi==0.115.0\npydantic>=2.0.0\nrequests\n# comment\n",
        encoding="utf-8",
    )

    resp = client.post(
        "/api/v1/syft/sbom",
        json={
            "input_type": "dir",
            "target": str(proj),
            "output_format": "cyclonedx-json",
            "scope": "Squashed",
        },
    )
    assert resp.status_code == 202, resp.text
    receipt = resp.json()
    assert receipt["sbom_id"].startswith("syft-")
    assert receipt["input_type"] == "dir"
    assert receipt["target"] == str(proj)
    assert receipt["output_format"] == "cyclonedx-json"
    assert "queued_at" in receipt

    # Fetch the SBOM and assert the inventory is real.
    fetch = client.get(f"/api/v1/syft/sbom/{receipt['sbom_id']}")
    assert fetch.status_code == 200, fetch.text
    sbom = fetch.json()

    assert sbom["status"] == "completed"
    assert sbom["package_count"] >= 3  # at least fastapi, pydantic, requests
    names = {p["name"] for p in sbom["packages"]}
    assert {"fastapi", "pydantic", "requests"}.issubset(names)

    # Verify the cyclonedx-json blob is valid + consistent.
    # (sbom_blob is not exposed via API by design — but packages array is.)
    fastapi_pkg = next(p for p in sbom["packages"] if p["name"] == "fastapi")
    assert fastapi_pkg["version"] == "0.115.0"
    assert fastapi_pkg["type"] == "python"
    assert fastapi_pkg["purl"].startswith("pkg:pypi/fastapi")


# ---------------------------------------------------------------------------
# 3. POST /sbom — file input on package.json yields npm packages
# ---------------------------------------------------------------------------
def test_generate_sbom_file_input_npm(client, tmp_path):
    pkg = tmp_path / "package.json"
    pkg.write_text(
        json.dumps(
            {
                "name": "demo",
                "license": "MIT",
                "dependencies": {"express": "^4.18.0", "lodash": "4.17.21"},
                "devDependencies": {"jest": "^29.0.0"},
            }
        ),
        encoding="utf-8",
    )

    resp = client.post(
        "/api/v1/syft/sbom",
        json={"input_type": "file", "target": str(pkg)},
    )
    assert resp.status_code == 202
    sbom_id = resp.json()["sbom_id"]

    fetch = client.get(f"/api/v1/syft/sbom/{sbom_id}").json()
    assert fetch["status"] == "completed"
    names = {p["name"] for p in fetch["packages"]}
    assert {"express", "lodash", "jest"}.issubset(names)

    # License flowed through from package.json.
    express = next(p for p in fetch["packages"] if p["name"] == "express")
    assert express["license"] == "MIT"
    assert express["type"] == "npm"
    assert express["purl"].startswith("pkg:npm/express")


# ---------------------------------------------------------------------------
# 4. POST /sbom — validation errors (bad input_type, bad format, bad scope, empty target)
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("payload", "expected_substr"),
    [
        ({"input_type": "bogus", "target": "/tmp"}, "Invalid input_type"),
        (
            {"input_type": "dir", "target": "/tmp", "output_format": "xml-of-doom"},
            "Invalid output_format",
        ),
        (
            {"input_type": "dir", "target": "/tmp", "scope": "PartialLayers"},
            "Invalid scope",
        ),
    ],
)
def test_generate_sbom_validation_errors(client, payload, expected_substr):
    resp = client.post("/api/v1/syft/sbom", json=payload)
    assert resp.status_code == 400, resp.text
    assert expected_substr in resp.json()["detail"]


def test_generate_sbom_empty_target_rejected(client):
    resp = client.post("/api/v1/syft/sbom", json={"input_type": "dir", "target": ""})
    # Pydantic's min_length=1 fires before engine validation → 422.
    assert resp.status_code in (400, 422)


# ---------------------------------------------------------------------------
# 5. GET /sbom/{sbom_id} — 404 for unknown id
# ---------------------------------------------------------------------------
def test_get_sbom_not_found(client):
    resp = client.get("/api/v1/syft/sbom/syft-does-not-exist")
    assert resp.status_code == 404
    assert "not found" in resp.json()["detail"].lower()


# ---------------------------------------------------------------------------
# 6. Multiple output formats are accepted and persisted
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    "fmt",
    ["cyclonedx-json", "cyclonedx-xml", "spdx-json", "spdx-tag-value", "syft-json", "syft-table", "github-json"],
)
def test_all_output_formats_round_trip(client, tmp_path, fmt):
    proj = tmp_path / f"proj-{fmt.replace('-', '_')}"
    proj.mkdir()
    (proj / "requirements.txt").write_text("attrs==23.1.0\n", encoding="utf-8")

    resp = client.post(
        "/api/v1/syft/sbom",
        json={"input_type": "dir", "target": str(proj), "output_format": fmt},
    )
    assert resp.status_code == 202, resp.text
    sbom_id = resp.json()["sbom_id"]

    fetched = client.get(f"/api/v1/syft/sbom/{sbom_id}").json()
    assert fetched["status"] == "completed"
    assert fetched["output_format"] == fmt
    assert fetched["package_count"] == 1
    assert fetched["packages"][0]["name"] == "attrs"


# ---------------------------------------------------------------------------
# 7. After generating SBOMs the capability status flips to "ok" + total updates
# ---------------------------------------------------------------------------
def test_capabilities_status_ok_after_generation(client, tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "requirements.txt").write_text("click==8.1.7\n", encoding="utf-8")
    client.post(
        "/api/v1/syft/sbom",
        json={"input_type": "dir", "target": str(proj)},
    )

    resp = client.get("/api/v1/syft/")
    body = resp.json()
    assert body["status"] == "ok"
    assert body["total_sboms"] >= 1


# ---------------------------------------------------------------------------
# 8. GET /sbom (list) returns most recent first
# ---------------------------------------------------------------------------
def test_list_sboms_orders_recent_first(client, tmp_path):
    for i in range(3):
        proj = tmp_path / f"p{i}"
        proj.mkdir()
        (proj / "requirements.txt").write_text(f"pkg{i}==1.0.{i}\n", encoding="utf-8")
        client.post("/api/v1/syft/sbom", json={"input_type": "dir", "target": str(proj)})

    resp = client.get("/api/v1/syft/sbom?limit=10")
    assert resp.status_code == 200
    listing = resp.json()["sboms"]
    assert len(listing) >= 3
    # Most recent first → started_at is monotonically non-increasing
    timestamps = [row["started_at"] for row in listing]
    assert timestamps == sorted(timestamps, reverse=True)


# ---------------------------------------------------------------------------
# 9. registry/image inputs complete with empty inventory (no docker available)
# ---------------------------------------------------------------------------
def test_registry_input_completes_with_empty_inventory(client):
    resp = client.post(
        "/api/v1/syft/sbom",
        json={"input_type": "registry", "target": "nginx:1.25"},
    )
    assert resp.status_code == 202
    sbom_id = resp.json()["sbom_id"]
    sbom = client.get(f"/api/v1/syft/sbom/{sbom_id}").json()
    # Without a real registry/syft binary we should record a clean empty SBOM
    # rather than a fake — status=completed, package_count=0.
    assert sbom["status"] == "completed"
    assert sbom["package_count"] == 0
    assert sbom["packages"] == []
