"""SPEC-033 C1+C2 — UI↔API contract: ingest -> readback (the #1 buyer action).

Pins the response SHAPE of the core customer path so a backend field rename can't
silently break the UI (the documented churn source, docs/architecture/api-contracts.md):

  C1  POST /api/v1/scanner-ingest/upload  -> 200, integer findings_count >= 1
  C2  GET  /api/v1/security-findings/      -> findings[] with canonical fields
        cve_id, severity, title, org_id ; CVE identity is cve_id (NOT rule_id);
        readback reflects the upload; a fresh org sees 0 (tenant isolation).

Additive contract test — asserts the contract, changes no API behavior. Real app
via create_app + TestClient, real SARIF fixture. NO MOCKS.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

os.environ.setdefault("FIXOPS_API_TOKEN", "ci-test-token")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")

_SARIF = Path(__file__).resolve().parent / "fixtures" / "real_world" / "scan.sarif"
_TOKEN = os.environ.get("FIXOPS_API_TOKEN", "ci-test-token")


@pytest.fixture(scope="module")
def client():
    from fastapi.testclient import TestClient

    from apps.api.app import create_app

    return TestClient(create_app())


def _upload(client, org: str):
    if not _SARIF.exists():
        pytest.skip(f"real SARIF fixture missing: {_SARIF}")
    headers = {"X-API-Key": _TOKEN, "X-Org-ID": org}
    return client.post(
        "/api/v1/scanner-ingest/upload",
        headers=headers,
        files={"file": ("scan.sarif", _SARIF.read_bytes(), "application/json")},
        data={"scanner_type": "sarif", "app_id": "contract-app"},
    )


def _readback(client, org: str):
    headers = {"X-API-Key": _TOKEN, "X-Org-ID": org}
    resp = client.get(f"/api/v1/security-findings/?org_id={org}&limit=200", headers=headers)
    assert resp.status_code == 200, f"readback failed: {resp.status_code} {resp.text[:200]}"
    body = resp.json()
    return body.get("findings", body if isinstance(body, list) else [])


# C1 — upload contract
def test_upload_returns_integer_findings_count(client):
    """REQ-033-01: a real multi-finding SARIF returns 200 + integer findings_count >= 1."""
    resp = _upload(client, "contract-org-c1")
    assert resp.status_code == 200, f"upload not 200: {resp.status_code} {resp.text[:200]}"
    body = resp.json()
    assert "findings_count" in body, f"upload response missing findings_count: {sorted(body)[:12]}"
    assert isinstance(body["findings_count"], int) and body["findings_count"] >= 1, body


# C2 — readback contract (canonical field names)
def test_readback_exposes_canonical_fields(client):
    """REQ-033-02: readback findings carry cve_id/severity/title/org_id, reflect the
    upload, and use cve_id (NOT rule_id) for CVE identity (the observed drift)."""
    org = "contract-org-c2"
    _upload(client, org)
    findings = _readback(client, org)
    assert findings, "readback empty after a successful upload"
    f0 = findings[0]
    for field in ("cve_id", "severity", "title", "org_id"):
        assert field in f0, f"contract field '{field}' missing from readback: {sorted(f0)[:20]}"
    # CVE identity is cve_id, not rule_id — pin the drift so it can't regress.
    assert "rule_id" not in f0 or "cve_id" in f0, "readback must expose cve_id"
    # readback reflects the upload (a famous CVE title is present)
    blob = " ".join(str(f.get("title") or "") for f in findings)
    assert ("Log4" in blob or "Spring" in blob or "CVE-" in blob), (
        f"readback does not reflect the uploaded scan: {blob[:200]}"
    )


# C2 — tenant isolation
def test_fresh_org_readback_is_empty(client):
    """REQ-033-03: a fresh org that uploaded nothing sees 0 findings (no cross-tenant leak)."""
    # seed a different org so the store is globally non-empty
    _upload(client, "contract-org-seed")
    empty = _readback(client, "contract-org-NEVER-UPLOADED-zzz")
    assert len(empty) == 0, f"fresh org must see 0 findings, got {len(empty)} (tenant leak)"
