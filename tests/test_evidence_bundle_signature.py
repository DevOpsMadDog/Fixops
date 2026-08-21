"""Integrity proves the bundle did not change. A signature proves it is ours.

Sealing (test_evidence_custody_chain) already answers "is this the same file" —
verification re-reads the artifact, re-computes its hash, and a tampered file is
detected. An assessor's next question is different: "can you prove this came
from you, and can you deny it later". That is non-repudiation, and it needs a
signature.

The signature covers the CONTENT HASH rather than the bytes, so a verifier
checks two independent things that fail for different reasons:

* the artifact still hashes to what we recorded  -> tamper;
* that recorded hash carries our signature       -> provenance.

Both are asserted here, and so is the honest case: a bundle that could not be
signed says so and reports ``signature_valid: false`` rather than claiming one
it does not have. In a compliance product a fake signature is worse than an
absent one.
"""

from __future__ import annotations

import base64
import pathlib
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
    monkeypatch.setenv("FIXOPS_API_TOKEN", "signature-test-token")
    monkeypatch.setenv("FIXOPS_JWT_SECRET", "signature-test-jwt-secret-long-enough-0123456789")
    monkeypatch.setenv("FIXOPS_MODE", "enterprise")
    monkeypatch.setenv("FIXOPS_EVIDENCE_DB", str(tmp_path / "evidence_packs.db"))
    monkeypatch.setenv("FIXOPS_EVIDENCE_STORAGE_ROOT", str(tmp_path / "artifacts"))

    from apps.api.app import create_app

    return TestClient(create_app(), raise_server_exceptions=False)


@pytest.fixture()
def bundle(client):
    email = f"sig-{uuid.uuid4().hex[:12]}@probe.example"
    acct = client.post(
        "/api/v1/auth/signup",
        json={"email": email, "password": "SignatureProbe1", "first_name": "S", "last_name": "G"},
    ).json()
    client.post(
        "/api/v1/scanner-ingest/upload",
        headers={"X-API-Key": acct["api_key"]},
        files={"file": ("trivy.json", io.BytesIO(json.dumps(TRIVY).encode()), "application/json")},
        data={"scanner_type": "trivy"},
    )
    resp = client.post(
        "/api/v1/evidence/bundles/generate",
        headers={"X-API-Key": acct["api_key"]},
        json={"frameworks": ["SOC2"]},
    )
    assert resp.status_code == 200, resp.text
    return {"key": acct["api_key"], **resp.json()}


def test_a_generated_bundle_carries_a_real_signature(bundle) -> None:
    assert bundle.get("signature_valid") is True, (
        f"unsigned: {bundle.get('signature_unavailable_reason')}"
    )
    assert bundle.get("signature"), "no signature material"
    assert bundle["signature_algorithm"] == "RSA-PKCS1v15-SHA256"
    assert bundle.get("key_fingerprint")


def test_the_signature_is_over_the_content_hash_not_a_label(bundle) -> None:
    """Signing an identifier would attest to nothing about the content."""
    from core.crypto import CryptoManager

    content_hash = bundle["hash"].removeprefix("sha256:")

    assert CryptoManager().verify(
        content_hash.encode("utf-8"), base64.b64decode(bundle["signature"])
    )


def test_the_signature_is_persisted_so_it_can_be_checked_later(bundle, tmp_path) -> None:
    """A signature held only in the response can never be verified again."""
    sidecars = list((tmp_path / "artifacts").rglob(f"{bundle['id']}.sig.json"))
    assert sidecars, "the signature was returned and then thrown away"

    record = json.loads(sidecars[0].read_text())
    assert record["content_sha256"] == bundle["hash"].removeprefix("sha256:")
    assert record["signature_b64"] == bundle["signature"]


def test_verification_confirms_an_untouched_bundle(client, bundle) -> None:
    body = client.post(
        f"/api/v1/evidence/bundles/{bundle['id']}/verify",
        headers={"X-API-Key": bundle["key"]},
    ).json()

    assert body["hash_match"] is True
    assert body["signature_valid"] is True
    assert body["valid"] is True
    assert body["issuer"].startswith("fixops:")


def test_verification_detects_an_edited_bundle(client, bundle, tmp_path) -> None:
    """The claim that makes a signature worth having."""
    artifacts = list((tmp_path / "artifacts").rglob(f"{bundle['id']}.json"))
    artifacts = [a for a in artifacts if not a.name.endswith(".sig.json")]
    assert artifacts

    payload = json.loads(artifacts[0].read_text())
    payload["overall_status"] = "effective"
    payload["controls_effective"] = 999
    artifacts[0].write_text(json.dumps(payload, sort_keys=True, indent=2))

    body = client.post(
        f"/api/v1/evidence/bundles/{bundle['id']}/verify",
        headers={"X-API-Key": bundle["key"]},
    ).json()

    assert body["hash_match"] is False
    assert body["valid"] is False
    assert "TAMPERED" in body["issuer"]


def test_a_forged_signature_does_not_verify(client, bundle, tmp_path) -> None:
    """Replacing the signature must not make a tampered bundle pass."""
    sidecars = list((tmp_path / "artifacts").rglob(f"{bundle['id']}.sig.json"))
    record = json.loads(sidecars[0].read_text())
    record["signature_b64"] = base64.b64encode(b"forged").decode("ascii")
    sidecars[0].write_text(json.dumps(record, indent=2))

    body = client.post(
        f"/api/v1/evidence/bundles/{bundle['id']}/verify",
        headers={"X-API-Key": bundle["key"]},
    ).json()

    assert body["signature_valid"] is False
    assert body["valid"] is False


def test_malformed_signature_material_answers_rather_than_crashing(client, bundle, tmp_path) -> None:
    """An assessor asking "is this authentic?" must never get a crash."""
    sidecars = list((tmp_path / "artifacts").rglob(f"{bundle['id']}.sig.json"))
    record = json.loads(sidecars[0].read_text())
    record["signature_b64"] = "!!!not-base64!!!"
    sidecars[0].write_text(json.dumps(record, indent=2))

    resp = client.post(
        f"/api/v1/evidence/bundles/{bundle['id']}/verify",
        headers={"X-API-Key": bundle["key"]},
    )
    assert resp.status_code == 200, "verification crashed instead of answering"
    assert resp.json()["signature_valid"] is False


def test_verify_answers_false_for_malformed_input_rather_than_raising() -> None:
    """CryptoManager.verify caught only InvalidSignature, so a str or a
    truncated signature raised TypeError — a 500 where the honest answer is
    "no, that does not verify"."""
    from core.crypto import CryptoManager

    manager = CryptoManager()
    signature, _ = manager.sign(b"payload")

    assert manager.verify(b"payload", signature) is True
    assert manager.verify(b"payload", b"short") is False
    assert manager.verify(b"payload", "not-bytes") is False  # type: ignore[arg-type]


def test_an_auditor_can_verify_offline_with_no_fixops(client, bundle, tmp_path) -> None:
    """The end state: a third party checks our evidence without our software.

    An assessor should not have to trust the vendor's UI to check the vendor's
    evidence. scripts/verify_evidence_bundle.py imports nothing from FixOps and
    needs no network — only the bundle, its signature record, and the published
    public key.
    """
    import subprocess
    import sys

    key = client.get("/api/v1/evidence/public-key", headers={"X-API-Key": bundle["key"]})
    assert key.status_code == 200, key.text

    pem = tmp_path / "fixops-public.pem"
    pem.write_text(key.json()["public_key_pem"])

    artifacts = [
        a for a in (tmp_path / "artifacts").rglob(f"{bundle['id']}.json")
        if not a.name.endswith(".sig.json")
    ]
    sidecars = list((tmp_path / "artifacts").rglob(f"{bundle['id']}.sig.json"))
    assert artifacts and sidecars

    script = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "verify_evidence_bundle.py"
    result = subprocess.run(
        [sys.executable, str(script), str(artifacts[0]), str(sidecars[0]), str(pem)],
        capture_output=True, text=True, timeout=120,
    )

    assert result.returncode == 0, f"offline verification failed:\n{result.stdout}\n{result.stderr}"
    assert "VERIFIED" in result.stdout


def test_the_offline_verifier_rejects_an_edited_bundle(client, bundle, tmp_path) -> None:
    """A verifier that always says yes is worse than no verifier."""
    import subprocess
    import sys

    key = client.get("/api/v1/evidence/public-key", headers={"X-API-Key": bundle["key"]}).json()
    pem = tmp_path / "fixops-public.pem"
    pem.write_text(key["public_key_pem"])

    artifacts = [
        a for a in (tmp_path / "artifacts").rglob(f"{bundle['id']}.json")
        if not a.name.endswith(".sig.json")
    ]
    payload = json.loads(artifacts[0].read_text())
    payload["controls_effective"] = 999
    artifacts[0].write_text(json.dumps(payload, sort_keys=True, indent=2))

    sidecars = list((tmp_path / "artifacts").rglob(f"{bundle['id']}.sig.json"))
    script = pathlib.Path(__file__).resolve().parents[1] / "scripts" / "verify_evidence_bundle.py"
    result = subprocess.run(
        [sys.executable, str(script), str(artifacts[0]), str(sidecars[0]), str(pem)],
        capture_output=True, text=True, timeout=120,
    )

    assert result.returncode == 1
    assert "NOT VERIFIED" in result.stderr


def test_the_public_key_endpoint_never_exposes_the_private_key(client, bundle) -> None:
    body = client.get("/api/v1/evidence/public-key", headers={"X-API-Key": bundle["key"]}).json()
    serialised = json.dumps(body)

    assert "PUBLIC KEY" in body["public_key_pem"]
    assert "PRIVATE KEY" not in serialised
