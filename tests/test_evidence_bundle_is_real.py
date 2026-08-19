"""The bundle an assessor is shown must exist.

Flow 04 is the commercial wedge: a customer hands an assessor a signed,
provenanced evidence bundle. Walking it as a real customer found the sharpest
NO-MOCKS violation in the product.

``POST /api/v1/evidence/bundles/generate`` built a dict in memory and returned
it. Nothing was persisted anywhere:

* ``GET /bundles`` listed zero — the bundle you just made was invisible;
* ``GET /bundles/{id}/download`` returned 404;
* the response carried invented section page counts ("Executive Summary: 3
  pages", "SOC2 Control Mapping: 15 pages"), ``finding_count: 0`` for a tenant
  holding 33 ingested findings, and a ``hash`` computed over the bundle's own id
  and timestamp — a hash of its metadata, attesting to no content at all.

In a compliance product that is the worst possible place for a stub. It renders
as a page-counted audit artifact an assessor could be shown, and none of it
exists.

Generation now goes through the same generator ``/api/v1/pipeline/evidence``
uses, is persisted, and reports measured numbers.
"""

from __future__ import annotations

import io
import json
import uuid

import pytest
from fastapi.testclient import TestClient

TRIVY = {
    "Results": [
        {
            "Target": "package-lock.json",
            "Vulnerabilities": [
                {"VulnerabilityID": "CVE-2026-1", "PkgName": "lodash",
                 "InstalledVersion": "4.17.20", "Severity": "HIGH", "Title": "prototype pollution"},
                {"VulnerabilityID": "CVE-2026-2", "PkgName": "body-parser",
                 "InstalledVersion": "1.20.0", "Severity": "LOW", "Title": "DoS via limit"},
            ],
        }
    ]
}


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.setenv("FIXOPS_API_TOKEN", "evidence-real-token")
    monkeypatch.setenv("FIXOPS_JWT_SECRET", "evidence-real-jwt-secret-long-enough-0123456789ab")
    monkeypatch.setenv("FIXOPS_MODE", "enterprise")

    from apps.api.app import create_app

    return TestClient(create_app(), raise_server_exceptions=False)


@pytest.fixture()
def tenant(client):
    email = f"ev-{uuid.uuid4().hex[:12]}@probe.example"
    body = client.post(
        "/api/v1/auth/signup",
        json={"email": email, "password": "EvidenceProbe1", "first_name": "Ev", "last_name": "Id"},
    ).json()
    client.post(
        "/api/v1/scanner-ingest/upload",
        headers={"X-API-Key": body["api_key"]},
        files={"file": ("trivy.json", io.BytesIO(json.dumps(TRIVY).encode()), "application/json")},
        data={"scanner_type": "trivy"},
    )
    return {"key": body["api_key"], "org": body["org_id"]}


def _generate(client, tenant):
    resp = client.post(
        "/api/v1/evidence/bundles/generate",
        headers={"X-API-Key": tenant["key"]},
        json={"frameworks": ["SOC2"]},
    )
    assert resp.status_code == 200, resp.text
    return resp.json()


def test_a_generated_bundle_is_listed_afterwards(client, tenant) -> None:
    """The whole defect in one assertion."""
    bundle = _generate(client, tenant)

    listing = client.get("/api/v1/evidence/bundles", headers={"X-API-Key": tenant["key"]}).json()
    ids = {b["id"] for b in listing["bundles"]}

    assert bundle["id"] in ids, "the bundle was generated and then not listed"


def test_the_bundle_reports_measured_controls_not_invented_pages(client, tenant) -> None:
    """No number in an audit artifact may be one nobody measured."""
    bundle = _generate(client, tenant)

    assert "controls_assessed" in bundle, "no control assessment in an evidence bundle"
    assert bundle["controls_assessed"] > 0, "a bundle that assessed nothing"
    assert bundle["controls_effective"] <= bundle["controls_assessed"]

    for section in bundle.get("sections", []):
        assert "page_count" not in section, (
            f"invented page count on section {section.get('name')!r} — nothing paginates a bundle"
        )


def test_the_hash_covers_content_not_the_bundles_own_label(client, tenant) -> None:
    """A hash over id+timestamp attests to nothing and matches no verifier."""
    import hashlib

    bundle = _generate(client, tenant)
    digest = bundle["hash"].removeprefix("sha256:")

    label_hash = hashlib.sha256(
        f"{bundle['id']}{bundle['created_at']}{bundle['framework']}".encode()
    ).hexdigest()

    assert digest != label_hash, "the hash is computed over the bundle's own identifiers"
    assert len(digest) == 64


def test_a_bundle_is_not_claimed_to_be_signed(client, tenant) -> None:
    """Signing is a separate, deliberate step. Claiming it is the same lie."""
    bundle = _generate(client, tenant)
    assert bundle["signature_valid"] is False
    assert bundle["signed_by"] is None


def test_one_tenants_bundle_is_not_listed_to_another(client, tenant) -> None:
    generated = _generate(client, tenant)

    other = client.post(
        "/api/v1/auth/signup",
        json={"email": f"ev-other-{uuid.uuid4().hex[:10]}@probe.example",
              "password": "EvidenceProbe1", "first_name": "Ot", "last_name": "Her"},
    ).json()

    listing = client.get("/api/v1/evidence/bundles", headers={"X-API-Key": other["api_key"]}).json()
    assert generated["id"] not in {b["id"] for b in listing["bundles"]}


def test_verifying_an_unknown_bundle_says_so_plainly(client, tenant) -> None:
    """An assessor's verification must never answer "valid" by default."""
    resp = client.post(
        "/api/v1/evidence/bundles/EVB-DOES-NOT-EXIST-9999/verify",
        headers={"X-API-Key": tenant["key"]},
    )
    body = resp.json()
    assert body["valid"] is False
    assert body["signature_valid"] is False
    assert body.get("issuer"), "an unverifiable bundle must say why"
