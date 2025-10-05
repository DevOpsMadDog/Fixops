import json

import base64
import csv
import gzip
import hashlib
import hmac
import json
import os
import time
import zipfile
from io import BytesIO, StringIO
from pathlib import Path

try:
    from fastapi.testclient import TestClient  # type: ignore
except Exception:  # pragma: no cover - fastapi is optional in some environments
    TestClient = None  # type: ignore

try:
    from backend.app import create_app
except Exception:  # pragma: no cover - allow environments without FastAPI
    create_app = None  # type: ignore
from backend.normalizers import InputNormalizer
from backend.pipeline import PipelineOrchestrator


def _make_hs256_token(secret: bytes, payload: dict, *, kid: str = "demo") -> str:
    header = {"alg": "HS256", "typ": "JWT", "kid": kid}
    segments = []
    for part in (header, payload):
        encoded = base64.urlsafe_b64encode(
            json.dumps(part, separators=(",", ":")).encode("utf-8")
        ).rstrip(b"=")
        segments.append(encoded.decode("ascii"))
    signing_input = ".".join(segments).encode("ascii")
    signature = hmac.new(secret, signing_input, hashlib.sha256).digest()
    signature_segment = base64.urlsafe_b64encode(signature).rstrip(b"=").decode("ascii")
    segments.append(signature_segment)
    return ".".join(segments)


def test_end_to_end_demo_pipeline():
    design_csv = """component,owner,criticality,notes\npayment-service,app-team,high,Handles card processing\nnotification-service,platform,medium,Sends emails\nai-orchestrator,ml-team,high,LangChain agent orchestrator for support bots\n"""

    sbom_document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "components": [
            {
                "type": "library",
                "name": "payment-service",
                "version": "1.0.0",
                "purl": "pkg:pypi/payment-service@1.0.0",
                "licenses": [{"license": "MIT"}],
            },
            {
                "type": "application",
                "name": "ai-orchestrator",
                "version": "0.4.0",
                "purl": "pkg:npm/langchain-agent@0.4.0",
                "licenses": [{"license": "Apache-2.0"}],
                "description": "LangChain powered support agent",
            },
        ],
    }

    cve_feed = {
        "vulnerabilities": [
            {
                "cveID": "CVE-2024-0001",
                "title": "Example vulnerability in payment-service",
                "knownExploited": True,
                "severity": "high",
            }
        ]
    }

    sarif_document = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {"driver": {"name": "DemoScanner"}},
                "results": [
                    {
                        "ruleId": "DEMO001",
                        "level": "error",
                        "message": {"text": "SQL injection risk"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {
                                        "uri": "services/payment-service/app.py"
                                    },
                                    "region": {"startLine": 42},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }

    if TestClient is not None and create_app is not None:
        os.environ["FIXOPS_API_TOKEN"] = "demo-token"
        app = create_app()
        client = TestClient(app)

        response = client.post(
            "/inputs/design",
            headers={"X-API-Key": "demo-token"},
            files={"file": ("design.csv", design_csv, "text/csv")},
        )
        assert response.status_code == 200
        design_payload = response.json()
        assert design_payload["row_count"] == 3

        response = client.post(
            "/inputs/sbom",
            headers={"X-API-Key": "demo-token"},
            files={
                "file": (
                    "sbom.json",
                    json.dumps(sbom_document),
                    "application/json",
                )
            },
        )
        assert response.status_code == 200
        sbom_payload = response.json()
        assert sbom_payload["metadata"]["component_count"] == 2

        response = client.post(
            "/inputs/cve",
            headers={"X-API-Key": "demo-token"},
            files={
                "file": (
                    "kev.json",
                    json.dumps(cve_feed),
                    "application/json",
                )
            },
        )
        assert response.status_code == 200
        cve_payload = response.json()
        assert cve_payload["record_count"] == 1

        response = client.post(
            "/inputs/sarif",
            headers={"X-API-Key": "demo-token"},
            files={
                "file": (
                    "scan.sarif",
                    json.dumps(sarif_document),
                    "application/json",
                )
            },
        )
        assert response.status_code == 200
        sarif_payload = response.json()
        assert sarif_payload["metadata"]["finding_count"] == 1

        response = client.post("/pipeline/run", headers={"X-API-Key": "demo-token"})
        assert response.status_code == 200
        pipeline_payload = response.json()
        assert pipeline_payload["status"] == "ok"
        assert pipeline_payload["design_summary"]["row_count"] == 3
        assert len(pipeline_payload["crosswalk"]) == 3
        assert pipeline_payload["crosswalk"][0]["findings"]
        assert pipeline_payload["guardrail_evaluation"]["status"] in {"pass", "warn", "fail"}
        assert pipeline_payload["context_summary"]["summary"]["components_evaluated"] >= 1
        assert pipeline_payload["onboarding"]["mode"] == "demo"
        assert pipeline_payload["compliance_status"]["frameworks"]
        policy_payload = pipeline_payload["policy_automation"]
        assert "execution" in policy_payload
        assert policy_payload["execution"]["status"] in {"completed", "partial"}
        assert all("delivery" in entry for entry in policy_payload["execution"]["results"])
        assert "bundle" in pipeline_payload["evidence_bundle"]["files"]
        assert "compressed" in pipeline_payload["evidence_bundle"]
        assert "plans" in pipeline_payload["pricing_summary"]
        ai_analysis = pipeline_payload.get("ai_agent_analysis")
        assert ai_analysis and ai_analysis["summary"]["components_with_agents"] >= 1
        exploit_signals = pipeline_payload["exploitability_insights"]
        assert exploit_signals["overview"]["signals_configured"] >= 1
        assert exploit_signals["overview"]["matched_records"] >= 1
        refresh_info = pipeline_payload.get("exploit_feed_refresh")
        if refresh_info:
            assert refresh_info["status"] in {"fresh", "refreshed", "failed"}
        probabilistic = pipeline_payload["probabilistic_forecast"]
        assert probabilistic["metrics"]["expected_high_or_critical"] >= 0
        ssdlc = pipeline_payload["ssdlc_assessment"]
        assert ssdlc["summary"]["total_stages"] >= 1
        assert any(stage["id"] == "plan" for stage in ssdlc["stages"])
        assert "iac_posture" in pipeline_payload
        assert pipeline_payload["modules"]["status"]["iac_posture"] == "executed"
        assert pipeline_payload["evidence_bundle"]["sections"]
        archive_info = pipeline_payload.get("artifact_archive")
        assert archive_info and "sbom" in archive_info
        assert archive_info["sbom"].get("normalized_path")
        analytics = pipeline_payload["analytics"]
        assert analytics["overview"]["estimated_value"] >= 0
        assert analytics["overlay"]["mode"] == "demo"
        tenant_view = pipeline_payload["tenant_lifecycle"]
        assert tenant_view["summary"]["total_tenants"] >= 1
        performance = pipeline_payload["performance_profile"]
        assert performance["summary"]["total_estimated_latency_ms"] >= 0
        overlay = pipeline_payload["overlay"]
        assert overlay["mode"] == "demo"
        assert overlay["metadata"]["profile_applied"] == "demo"
        assert "required_inputs" in overlay
        os.environ.pop("FIXOPS_API_TOKEN", None)
    else:
        normalizer = InputNormalizer()
        reader = csv.DictReader(StringIO(design_csv))
        design_dataset = {"columns": reader.fieldnames or [], "rows": list(reader)}
        sbom = normalizer.load_sbom(json.dumps(sbom_document))
        cve_norm = normalizer.load_cve_feed(json.dumps(cve_feed))
        sarif_norm = normalizer.load_sarif(json.dumps(sarif_document))

        gz_sbom = gzip.compress(json.dumps(sbom_document).encode("utf-8"))
        sbom_gz = normalizer.load_sbom(gz_sbom)
        assert sbom_gz.metadata["component_count"] == 2

        zip_buffer = BytesIO()
        with zipfile.ZipFile(zip_buffer, mode="w") as archive:
            archive.writestr("scan.sarif", json.dumps(sarif_document))
        sarif_zip = normalizer.load_sarif(zip_buffer.getvalue())
        assert sarif_zip.metadata["finding_count"] == 1

        orchestrator = PipelineOrchestrator()
        pipeline_payload = orchestrator.run(
            design_dataset=design_dataset,
            sbom=sbom,
            sarif=sarif_norm,
            cve=cve_norm,
        )

        assert pipeline_payload["status"] == "ok"
        assert pipeline_payload["design_summary"]["row_count"] == 3
        assert len(pipeline_payload["crosswalk"]) == 3
        assert isinstance(pipeline_payload["crosswalk"][0]["findings"], list)
        if "ai_agent_analysis" in pipeline_payload:
            assert pipeline_payload["ai_agent_analysis"]["summary"]["components_with_agents"] >= 1
        if "exploitability_insights" in pipeline_payload:
            assert pipeline_payload["exploitability_insights"]["overview"]["signals_configured"] >= 1
        if "probabilistic_forecast" in pipeline_payload:
            assert pipeline_payload["probabilistic_forecast"]["metrics"]["expected_high_or_critical"] >= 0


def test_api_rejects_missing_token(tmp_path):
    if TestClient is None or create_app is None:
        return

    os.environ["FIXOPS_API_TOKEN"] = "demo-token"
    try:
        app = create_app()
        client = TestClient(app)
        response = client.post(
            "/inputs/design",
            files={"file": ("design.csv", "component,owner\nsvc,team\n", "text/csv")},
        )
        assert response.status_code == 401
    finally:
        os.environ.pop("FIXOPS_API_TOKEN", None)


def test_feedback_endpoint_rejects_invalid_payload(monkeypatch, tmp_path):
    if TestClient is None or create_app is None:
        return

    overlay_payload = {
        "mode": "demo",
        "auth": {"strategy": "token", "tokens": ["demo-token"]},
        "data": {"feedback_dir": str(tmp_path / "feedback")},
        "toggles": {"capture_feedback": True},
    }
    overlay_path = tmp_path / "overlay.json"
    overlay_path.write_text(json.dumps(overlay_payload), encoding="utf-8")

    monkeypatch.setenv("FIXOPS_OVERLAY_PATH", str(overlay_path))
    monkeypatch.setenv("FIXOPS_DATA_ROOT_ALLOWLIST", str(tmp_path))
    monkeypatch.setenv("FIXOPS_API_TOKEN", "demo-token")

    try:
        app = create_app()
        client = TestClient(app)
        response = client.post(
            "/feedback",
            headers={"X-API-Key": "demo-token"},
            json={"run_id": "../escape", "decision": "accepted"},
        )
        assert response.status_code == 400
        assert "run_id" in response.json()["detail"].lower()
    finally:
        monkeypatch.delenv("FIXOPS_OVERLAY_PATH", raising=False)
        monkeypatch.delenv("FIXOPS_DATA_ROOT_ALLOWLIST", raising=False)
        monkeypatch.delenv("FIXOPS_API_TOKEN", raising=False)


def test_oidc_rbac_enforced(monkeypatch, tmp_path):
    if TestClient is None or create_app is None:
        return

    secret = b"super-secret-key"
    jwk_secret = base64.urlsafe_b64encode(secret).decode("ascii").rstrip("=")
    overlay_payload = {
        "mode": "demo",
        "auth": {"strategy": "oidc", "tenant_header": "X-FixOps-Tenant"},
        "data": {"archive_dir": str(tmp_path / "archive_default")},
        "tenancy": {
            "defaults": {
                "identity": {
                    "allowed_audiences": ["fixops-api"],
                    "roles": {
                        "upload": ["fixops:upload"],
                        "pipeline": ["fixops:pipeline"],
                    },
                },
                "identity_provider": "demo-idp",
            },
            "identity_providers": {
                "demo-idp": {
                    "issuer": "https://idp.example.com",
                    "allowed_audiences": ["fixops-api"],
                    "jwks": {
                        "keys": [
                            {
                                "kty": "oct",
                                "k": jwk_secret,
                                "kid": "demo-key",
                                "alg": "HS256",
                            }
                        ]
                    },
                }
            },
            "tenants": [
                {
                    "id": "tenant-one",
                    "name": "Tenant One",
                    "identity": {
                        "provider": "demo-idp",
                        "allowed_audiences": ["fixops-api"],
                        "roles": {
                            "upload": ["fixops:upload"],
                            "pipeline": ["fixops:pipeline"],
                        },
                    },
                }
            ],
            "directories": {
                "tenant-one": str(tmp_path / "tenants" / "tenant-one" / "archive")
            },
        },
    }

    overlay_path = tmp_path / "overlay.json"
    overlay_path.write_text(json.dumps(overlay_payload), encoding="utf-8")

    monkeypatch.setenv("FIXOPS_OVERLAY_PATH", str(overlay_path))
    monkeypatch.setenv("FIXOPS_DATA_ROOT_ALLOWLIST", str(tmp_path))

    app = create_app()
    client = TestClient(app)

    design_csv = "component,owner\nsvc,team\n"
    sbom_document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.4",
        "version": 1,
        "components": [
            {
                "type": "library",
                "name": "svc",
                "version": "1.0.0",
                "purl": "pkg:pypi/svc@1.0.0",
            }
        ],
    }
    cve_feed = {"vulnerabilities": [{"cveID": "CVE-2024-0001", "severity": "high"}]}
    sarif_document = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {"driver": {"name": "DemoScanner"}},
                "results": [
                    {
                        "ruleId": "DEMO001",
                        "message": {"text": "Issue"},
                        "level": "error",
                    }
                ],
            }
        ],
    }

    wrong_audience_token = _make_hs256_token(
        secret,
        {
            "iss": "https://idp.example.com",
            "sub": "user@example.com",
            "aud": "other-api",
            "exp": int(time.time()) + 300,
            "roles": ["fixops:upload"],
        },
        kid="demo-key",
    )

    response = client.post(
        "/inputs/design",
        headers={
            "X-FixOps-Tenant": "tenant-one",
            "Authorization": f"Bearer {wrong_audience_token}",
        },
        files={"file": ("design.csv", design_csv, "text/csv")},
    )
    assert response.status_code == 403

    response = client.post(
        "/inputs/design",
        headers={"X-FixOps-Tenant": "tenant-one"},
        files={"file": ("design.csv", design_csv, "text/csv")},
    )
    assert response.status_code == 401

    upload_token = _make_hs256_token(
        secret,
        {
            "iss": "https://idp.example.com",
            "sub": "user@example.com",
            "aud": "fixops-api",
            "exp": int(time.time()) + 300,
            "roles": ["fixops:upload"],
        },
        kid="demo-key",
    )

    headers = {
        "X-FixOps-Tenant": "tenant-one",
        "Authorization": f"Bearer {upload_token}",
    }

    response = client.post(
        "/inputs/design",
        headers=headers,
        files={"file": ("design.csv", design_csv, "text/csv")},
    )
    assert response.status_code == 200

    response = client.post(
        "/inputs/sbom",
        headers=headers,
        files={
            "file": (
                "sbom.json",
                json.dumps(sbom_document),
                "application/json",
            )
        },
    )
    assert response.status_code == 200

    response = client.post(
        "/inputs/cve",
        headers=headers,
        files={
            "file": (
                "cve.json",
                json.dumps(cve_feed),
                "application/json",
            )
        },
    )
    assert response.status_code == 200

    response = client.post(
        "/inputs/sarif",
        headers=headers,
        files={
            "file": (
                "scan.sarif",
                json.dumps(sarif_document),
                "application/json",
            )
        },
    )
    assert response.status_code == 200

    response = client.post(
        "/pipeline/run",
        headers=headers,
    )
    assert response.status_code == 403

    full_token = _make_hs256_token(
        secret,
        {
            "iss": "https://idp.example.com",
            "sub": "user@example.com",
            "aud": "fixops-api",
            "exp": int(time.time()) + 300,
            "roles": ["fixops:upload", "fixops:pipeline"],
        },
        kid="demo-key",
    )

    response = client.post(
        "/pipeline/run",
        headers={
            "X-FixOps-Tenant": "tenant-one",
            "Authorization": f"Bearer {full_token}",
        },
    )
    assert response.status_code == 200
    pipeline_payload = response.json()
    archive_info = pipeline_payload.get("artifact_archive")
    assert archive_info and "sbom" in archive_info
    sbom_path = Path(archive_info["sbom"]["normalized_path"])
    assert sbom_path.exists()
    assert "tenant-one" in sbom_path.parts
