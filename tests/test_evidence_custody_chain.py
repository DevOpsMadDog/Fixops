"""An evidence bundle must be provably unaltered since it was produced.

An assessor's question is not "do you have a report". It is "can you show this
report has not been changed since it was generated, and who has held it".

EvidenceChainEngine already implemented that properly — cases, custody
transfers, sealing, and a content re-hash guarded against spoofed storage paths.
Nothing in the product fed it. It filled only if a human called the API by hand,
so /api/v1/evidence-chain reported zero for every customer who had generated
evidence, and the strongest thing in the product was dark.

Generation now writes the bundle to the operator-managed evidence root, records
the hash OF THE FILE BYTES, and seals it into the chain. That last detail is the
one that matters: hashing the in-memory dict instead of the file would make
re-hashing never match, and every verification would cry tamper.
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
            ],
        }
    ]
}


@pytest.fixture()
def client(monkeypatch, tmp_path):
    monkeypatch.setenv("FIXOPS_API_TOKEN", "custody-test-token")
    monkeypatch.setenv("FIXOPS_JWT_SECRET", "custody-test-jwt-secret-long-enough-0123456789abc")
    monkeypatch.setenv("FIXOPS_MODE", "enterprise")
    monkeypatch.setenv("FIXOPS_EVIDENCE_DB", str(tmp_path / "evidence_packs.db"))
    monkeypatch.setenv("FIXOPS_EVIDENCE_STORAGE_ROOT", str(tmp_path / "artifacts"))

    from apps.api.app import create_app

    return TestClient(create_app(), raise_server_exceptions=False)


@pytest.fixture()
def bundle(client):
    email = f"cust-{uuid.uuid4().hex[:12]}@probe.example"
    acct = client.post(
        "/api/v1/auth/signup",
        json={"email": email, "password": "CustodyProbe12", "first_name": "C", "last_name": "U"},
    ).json()
    key = acct["api_key"]
    client.post(
        "/api/v1/scanner-ingest/upload",
        headers={"X-API-Key": key},
        files={"file": ("trivy.json", io.BytesIO(json.dumps(TRIVY).encode()), "application/json")},
        data={"scanner_type": "trivy"},
    )
    resp = client.post(
        "/api/v1/evidence/bundles/generate",
        headers={"X-API-Key": key},
        json={"frameworks": ["SOC2"]},
    )
    assert resp.status_code == 200, resp.text
    return {"key": key, "org": acct["org_id"], **resp.json()}


def test_a_generated_bundle_enters_the_chain_of_custody(client, bundle) -> None:
    """The whole defect: the chain existed and nothing fed it."""
    assert bundle.get("custody_evidence_id"), "the bundle was never entered into the custody chain"
    assert bundle.get("custody_sealed") is True, "the bundle was recorded but not sealed"


def test_the_chain_reports_what_the_customer_generated(client, bundle) -> None:
    stats = client.get("/api/v1/evidence-chain/", headers={"X-API-Key": bundle["key"]}).json()["stats"]
    assert stats["total_evidence"] >= 1, "the chain still reports zero after a generation"
    assert stats["sealed_count"] >= 1


def test_an_untouched_bundle_verifies_by_RECOMPUTING_its_hash(client, bundle) -> None:
    """"verified" means nothing unless the bytes were actually re-hashed."""
    resp = client.get(
        f"/api/v1/evidence-chain/evidence/{bundle['custody_evidence_id']}/verify",
        headers={"X-API-Key": bundle["key"]},
    )
    body = resp.json()

    assert body["hash_recomputed"] is True, (
        "the hash was not recomputed — 'verified' here would assert something never checked"
    )
    assert body["hash_match"] is True
    assert body["content_integrity"] == "verified"


def test_editing_a_sealed_bundle_is_detected(client, bundle, tmp_path) -> None:
    """The claim that makes this worth selling."""
    artifacts = list((tmp_path / "artifacts").rglob(f"{bundle['id']}.json"))
    assert artifacts, "no artifact was persisted, so nothing could ever be verified"

    original = json.loads(artifacts[0].read_text())
    original["overall_status"] = "effective"      # a plausible, self-serving edit
    original["controls_effective"] = 999
    artifacts[0].write_text(json.dumps(original, sort_keys=True, indent=2))

    body = client.get(
        f"/api/v1/evidence-chain/evidence/{bundle['custody_evidence_id']}/verify",
        headers={"X-API-Key": bundle["key"]},
    ).json()

    assert body["hash_match"] is False, "a compliance bundle was edited and verification said fine"
    assert body["content_integrity"] == "tampered"


def test_the_recorded_hash_is_of_the_file_not_the_in_memory_object(client, bundle, tmp_path) -> None:
    """Hash the dict instead of the bytes and every verification cries tamper."""
    import hashlib

    artifacts = list((tmp_path / "artifacts").rglob(f"{bundle['id']}.json"))
    on_disk = hashlib.sha256(artifacts[0].read_bytes()).hexdigest()

    assert bundle["hash"].removeprefix("sha256:") == on_disk


def test_one_tenant_cannot_verify_another_tenants_evidence(client, bundle) -> None:
    other = client.post(
        "/api/v1/auth/signup",
        json={"email": f"cust-other-{uuid.uuid4().hex[:10]}@probe.example",
              "password": "CustodyProbe12", "first_name": "O", "last_name": "T"},
    ).json()

    resp = client.get(
        f"/api/v1/evidence-chain/evidence/{bundle['custody_evidence_id']}/verify",
        headers={"X-API-Key": other["api_key"]},
    )
    if resp.status_code == 200:
        assert resp.json().get("verified") is not True, "cross-tenant evidence verification"
    else:
        assert resp.status_code in (403, 404)
