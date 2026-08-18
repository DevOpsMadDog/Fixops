"""Ingest, see it, act on it. The three steps a customer pays for.

Walking flow 02 as a real customer — upload real scanner output, list the
findings, triage one — found four defects stacked in the write path.

1. ``/api/v1/scanner-ingest/upload`` filed everything under org "default"
   regardless of the credential. The router carries no auth dependency of its
   own; it is protected by ``_verify_api_key``, a SECOND implementation of the
   auth rule whose managed-key branch never bound ``request.state.org_id``.
   Fixing ``api_key_auth`` alone had missed it.

2. ``list_findings`` UNIONs the in-memory store with engine-DB rows; every WRITE
   handler gated on ``finding_id not in _findings_store``. So an ingested
   finding could be listed and not acted on: the list handed you an id and the
   status endpoint answered "Finding <id> not found" for that same id.

3. Once resolvable, the write mutated the in-memory copy only. HTTP 200, and the
   next GET still said "open" — the same shape as the Triage button that
   reported success and changed nothing.

4. The API and the engine had grown SEPARATE status vocabularies with no
   translation: the API validated in_progress/remediated/false_positive/
   accepted_risk, the engine accepted in-progress/resolved/false-positive. Only
   "open" and "suppressed" overlapped, so four of six statuses the API accepted
   were rejected by the store meant to record them.

Each layer hid the one under it: fixing the 404 only revealed the silent write,
and fixing the write only revealed the vocabulary split.
"""

from __future__ import annotations

import io
import json
import uuid

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

TRIVY_SAMPLE = {
    "Results": [
        {
            "Target": "package-lock.json",
            "Vulnerabilities": [
                {
                    "VulnerabilityID": "CVE-2026-12590",
                    "PkgName": "body-parser",
                    "InstalledVersion": "1.20.0",
                    "Severity": "LOW",
                    "Title": "body-parser: DoS via invalid limit option",
                },
                {
                    "VulnerabilityID": "CVE-2025-99999",
                    "PkgName": "lodash",
                    "InstalledVersion": "4.17.20",
                    "Severity": "HIGH",
                    "Title": "lodash: prototype pollution",
                },
            ],
        }
    ]
}


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setenv("FIXOPS_API_TOKEN", "spine-test-token")
    monkeypatch.setenv("FIXOPS_JWT_SECRET", "spine-test-jwt-secret-long-enough-0123456789abcdef")
    monkeypatch.setenv("FIXOPS_MODE", "enterprise")

    from apps.api.app import create_app

    return TestClient(create_app(), raise_server_exceptions=False)


@pytest.fixture()
def tenant(client):
    email = f"spine-{uuid.uuid4().hex[:12]}@probe.example"
    resp = client.post(
        "/api/v1/auth/signup",
        json={"email": email, "password": "SpineProbe123", "first_name": "Sp", "last_name": "Ine"},
    )
    assert resp.status_code in (200, 201), resp.text
    body = resp.json()
    return {"key": body["api_key"], "org": body["org_id"]}


def _ingest(client, tenant):
    payload = json.dumps(TRIVY_SAMPLE).encode()
    return client.post(
        "/api/v1/scanner-ingest/upload",
        headers={"X-API-Key": tenant["key"]},
        files={"file": ("trivy.json", io.BytesIO(payload), "application/json")},
        data={"scanner_type": "trivy"},
    )


def _findings(client, tenant):
    resp = client.get("/api/v1/findings", headers={"X-API-Key": tenant["key"]})
    assert resp.status_code == 200, resp.text
    body = resp.json()
    return body.get("findings") or body.get("items") or []


def test_ingest_lands_in_the_uploaders_tenant(client, tenant) -> None:
    """Defect 1: the front door filed everything under "default"."""
    resp = _ingest(client, tenant)
    assert resp.status_code == 200, resp.text
    assert resp.json()["org_id"] == tenant["org"], "an upload landed in the wrong tenant"


def test_what_was_ingested_can_be_listed(client, tenant) -> None:
    _ingest(client, tenant)
    assert _findings(client, tenant), "nothing visible after a successful ingest"


def test_a_listed_finding_can_actually_be_triaged(client, tenant) -> None:
    """Defect 2: the list handed out ids the write path called "not found"."""
    _ingest(client, tenant)
    finding_id = _findings(client, tenant)[0]["id"]

    resp = client.put(
        f"/api/v1/findings/{finding_id}/status",
        headers={"X-API-Key": tenant["key"]},
        json={"status": "accepted_risk", "reason": "test fixture"},
    )
    assert resp.status_code != 404, "the list returned an id the write path cannot resolve"
    assert resp.status_code == 200, resp.text


def test_the_triage_decision_survives_the_request(client, tenant) -> None:
    """Defect 3: 200 over a write that never landed."""
    _ingest(client, tenant)
    finding_id = _findings(client, tenant)[0]["id"]

    client.put(
        f"/api/v1/findings/{finding_id}/status",
        headers={"X-API-Key": tenant["key"]},
        json={"status": "accepted_risk", "reason": "test fixture"},
    )

    after = {f["id"]: f.get("status") for f in _findings(client, tenant)}
    assert after.get(finding_id) != "open", "triage reported success and changed nothing"


def test_the_status_round_trip_closes(client, tenant) -> None:
    """Defect 4: PUT accepted_risk, GET accepted-risk — a client cannot filter."""
    _ingest(client, tenant)
    finding_id = _findings(client, tenant)[0]["id"]

    client.put(
        f"/api/v1/findings/{finding_id}/status",
        headers={"X-API-Key": tenant["key"]},
        json={"status": "accepted_risk"},
    )

    after = {f["id"]: f.get("status") for f in _findings(client, tenant)}
    assert after.get(finding_id) == "accepted_risk", (
        f"sent 'accepted_risk', read back {after.get(finding_id)!r} — the round trip does not close"
    )


def test_every_status_the_api_accepts_is_one_the_engine_records(client) -> None:
    """The vocabularies must not drift apart again."""
    from apps.api.findings_routes import _API_TO_ENGINE_STATUS
    from core.security_findings_engine import _VALID_STATUSES

    unmappable = [v for v in _API_TO_ENGINE_STATUS.values() if v not in _VALID_STATUSES]
    assert not unmappable, f"API statuses the engine will reject: {unmappable}"


def test_a_tenant_cannot_triage_another_tenants_finding(client, tenant) -> None:
    """These write handlers previously took no org parameter at all."""
    _ingest(client, tenant)
    finding_id = _findings(client, tenant)[0]["id"]

    other = client.post(
        "/api/v1/auth/signup",
        json={
            "email": f"spine-other-{uuid.uuid4().hex[:10]}@probe.example",
            "password": "SpineProbe123", "first_name": "Ot", "last_name": "Her",
        },
    ).json()

    resp = client.put(
        f"/api/v1/findings/{finding_id}/status",
        headers={"X-API-Key": other["api_key"]},
        json={"status": "suppressed"},
    )
    assert resp.status_code == 404, "one tenant triaged another tenant's finding"
