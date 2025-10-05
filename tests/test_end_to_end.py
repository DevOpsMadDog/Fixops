import base64
import csv
import gzip
import inspect
import json
import os
import shutil
import zipfile
from io import BytesIO, StringIO
from pathlib import Path
from tempfile import SpooledTemporaryFile

try:
    from fastapi.testclient import TestClient  # type: ignore
except Exception:  # pragma: no cover - fastapi is optional in some environments
    TestClient = None  # type: ignore
else:  # pragma: no cover - degrade gracefully when using the lightweight stub
    if "files" not in inspect.signature(TestClient.post).parameters:  # type: ignore[arg-type]
        TestClient = None  # type: ignore

try:
    from backend.app import create_app
except Exception:  # pragma: no cover - allow environments without FastAPI
    create_app = None  # type: ignore
from backend.normalizers import InputNormalizer
from backend.pipeline import PipelineOrchestrator


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
        assert "run_id" in pipeline_payload
        run_id = pipeline_payload["run_id"]
        assert isinstance(run_id, str) and run_id
        assert pipeline_payload.get("analytics_persistence")
        assert "forecasts" in pipeline_payload["analytics_persistence"]
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
        assert analytics.get("persistence") == pipeline_payload["analytics_persistence"]
        assert analytics["overview"]["estimated_value"] >= 0
        assert analytics["overlay"]["mode"] == "demo"
        dashboard_response = client.get(
            "/analytics/dashboard", headers={"X-API-Key": "demo-token"}
        )
        assert dashboard_response.status_code == 200
        dashboard = dashboard_response.json()
        assert dashboard["forecasts"]["totals"]["entries"] >= 1
        run_response = client.get(
            f"/analytics/runs/{run_id}", headers={"X-API-Key": "demo-token"}
        )
        assert run_response.status_code == 200
        run_details = run_response.json()
        assert run_details["run_id"] == run_id
        assert run_details["forecasts"]
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

        spooled = SpooledTemporaryFile(max_size=1024, mode="w+b")
        spooled.write(gzip.compress(json.dumps(sbom_document).encode("utf-8")))
        spooled.seek(0)
        sbom_spooled = normalizer.load_sbom(spooled)
        assert sbom_spooled.metadata["component_count"] == 2
        spooled.close()

        sarif_zip_buffer = SpooledTemporaryFile(max_size=1024, mode="w+b")
        with zipfile.ZipFile(sarif_zip_buffer, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("scan.sarif", json.dumps(sarif_document))
        sarif_zip_buffer.seek(0)
        sarif_spooled = normalizer.load_sarif(sarif_zip_buffer)
        assert sarif_spooled.metadata["finding_count"] == 1
        sarif_zip_buffer.close()

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

    safe_root = (Path(__file__).resolve().parent / "tmp_feedback" / tmp_path.name).resolve()
    safe_root.mkdir(parents=True, exist_ok=True)

    overlay_payload = {
        "mode": "demo",
        "auth": {"strategy": "token", "tokens": ["demo-token"]},
        "data": {"feedback_dir": str(safe_root / "feedback")},
        "toggles": {"capture_feedback": True},
    }
    overlay_path = tmp_path / "overlay.json"
    overlay_path.write_text(json.dumps(overlay_payload), encoding="utf-8")

    monkeypatch.setenv("FIXOPS_OVERLAY_PATH", str(overlay_path))
    monkeypatch.setenv("FIXOPS_DATA_ROOT_ALLOWLIST", str(safe_root))
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
        shutil.rmtree(safe_root, ignore_errors=True)


def test_large_compressed_uploads_stream_to_disk(monkeypatch, tmp_path):
    if TestClient is None or create_app is None:
        normalizer = InputNormalizer()

        components = []
        sbom_document = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "components": components,
        }
        gz_sbom = b""
        for idx in range(800):
            components.append(
                {
                    "type": "library",
                    "name": f"component-{idx}",
                    "version": "1.0.0",
                    "purl": f"pkg:pypi/component-{idx}@1.0.0",
                    "licenses": [{"license": "MIT"}],
                    "description": base64.b64encode(os.urandom(4096)).decode("ascii"),
                }
            )
            gz_sbom = gzip.compress(json.dumps(sbom_document).encode("utf-8"))
            if len(gz_sbom) > 1024 * 1024:
                break
        assert len(gz_sbom) > 1024 * 1024

        sbom_spool = SpooledTemporaryFile(max_size=1024, mode="w+b")
        sbom_spool.write(gz_sbom)
        sbom_spool.seek(0)
        sbom = normalizer.load_sbom(sbom_spool)
        assert sbom.metadata["component_count"] == len(components)
        sbom_spool.close()

        cve_entries = [
            {
                "cveID": f"CVE-2024-{idx:04d}",
                "title": base64.b64encode(os.urandom(512)).decode("ascii"),
                "severity": "high",
            }
            for idx in range(300)
        ]
        cve_zip = BytesIO()
        with zipfile.ZipFile(cve_zip, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("kev.json", json.dumps({"vulnerabilities": cve_entries}))
        cve_zip.seek(0)
        cve_spool = SpooledTemporaryFile(max_size=1024, mode="w+b")
        cve_spool.write(cve_zip.getvalue())
        cve_spool.seek(0)
        cve_norm = normalizer.load_cve_feed(cve_spool)
        assert cve_norm.metadata["record_count"] == len(cve_entries)
        cve_spool.close()

        sarif_results = [
            {
                "ruleId": f"RULE-{idx}",
                "level": "warning",
                "message": {"text": base64.b64encode(os.urandom(256)).decode("ascii")},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f"src/module_{idx}.py"},
                            "region": {"startLine": idx + 1},
                        }
                    }
                ],
            }
            for idx in range(200)
        ]
        sarif_document = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "HeavyScanner"}}, "results": sarif_results}]}
        sarif_zip = BytesIO()
        with zipfile.ZipFile(sarif_zip, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("scan.sarif", json.dumps(sarif_document))
        sarif_zip.seek(0)
        sarif_spool = SpooledTemporaryFile(max_size=1024, mode="w+b")
        sarif_spool.write(sarif_zip.getvalue())
        sarif_spool.seek(0)
        sarif = normalizer.load_sarif(sarif_spool)
        assert sarif.metadata["finding_count"] == len(sarif_results)
        sarif_spool.close()
        return

    safe_root = (Path(__file__).resolve().parent / "tmp_stream" / tmp_path.name).resolve()
    safe_root.mkdir(parents=True, exist_ok=True)

    overlay_payload = {
        "mode": "demo",
        "auth": {"strategy": "token", "tokens": ["demo-token"]},
        "data": {"archive_dir": str((safe_root / "archive").resolve())},
        "limits": {
            "max_upload_bytes": {
                "default": 16 * 1024 * 1024,
                "sbom": 16 * 1024 * 1024,
                "sarif": 16 * 1024 * 1024,
                "cve": 16 * 1024 * 1024,
            }
        },
    }
    overlay_path = tmp_path / "overlay.json"
    overlay_path.write_text(json.dumps(overlay_payload), encoding="utf-8")

    monkeypatch.setenv("FIXOPS_OVERLAY_PATH", str(overlay_path))
    monkeypatch.setenv("FIXOPS_DATA_ROOT_ALLOWLIST", str(safe_root))
    monkeypatch.setenv("FIXOPS_API_TOKEN", "demo-token")

    try:
        app = create_app()
        client = TestClient(app)
        headers = {"X-API-Key": "demo-token"}

        components = []
        sbom_document = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.4",
            "version": 1,
            "components": components,
        }
        gz_sbom = b""
        for idx in range(800):
            components.append(
                {
                    "type": "library",
                    "name": f"component-{idx}",
                    "version": "1.0.0",
                    "purl": f"pkg:pypi/component-{idx}@1.0.0",
                    "licenses": [{"license": "MIT"}],
                    "description": base64.b64encode(os.urandom(4096)).decode("ascii"),
                }
            )
            gz_sbom = gzip.compress(json.dumps(sbom_document).encode("utf-8"))
            if len(gz_sbom) > 1024 * 1024:
                break
        assert len(components) >= 1
        assert len(gz_sbom) > 1024 * 1024

        response = client.post(
            "/inputs/sbom",
            headers=headers,
            files={"file": ("sbom.json.gz", gz_sbom, "application/gzip")},
        )
        assert response.status_code == 200
        assert response.json()["metadata"]["component_count"] == len(components)

        cve_entries = [
            {
                "cveID": f"CVE-2024-{idx:04d}",
                "title": base64.b64encode(os.urandom(512)).decode("ascii"),
                "severity": "high",
            }
            for idx in range(300)
        ]
        cve_zip = BytesIO()
        with zipfile.ZipFile(cve_zip, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("kev.json", json.dumps({"vulnerabilities": cve_entries}))
        cve_zip.seek(0)

        response = client.post(
            "/inputs/cve",
            headers=headers,
            files={"file": ("kev.zip", cve_zip.getvalue(), "application/zip")},
        )
        assert response.status_code == 200
        assert response.json()["record_count"] == len(cve_entries)

        sarif_results = [
            {
                "ruleId": f"RULE-{idx}",
                "level": "warning",
                "message": {"text": base64.b64encode(os.urandom(256)).decode("ascii")},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": f"src/module_{idx}.py"},
                            "region": {"startLine": idx + 1},
                        }
                    }
                ],
            }
            for idx in range(200)
        ]
        sarif_document = {"version": "2.1.0", "runs": [{"tool": {"driver": {"name": "HeavyScanner"}}, "results": sarif_results}]}
        sarif_zip = BytesIO()
        with zipfile.ZipFile(sarif_zip, mode="w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("scan.sarif", json.dumps(sarif_document))
        sarif_zip.seek(0)

        response = client.post(
            "/inputs/sarif",
            headers=headers,
            files={"file": ("scan.zip", sarif_zip.getvalue(), "application/zip")},
        )
        assert response.status_code == 200
        assert response.json()["metadata"]["finding_count"] == len(sarif_results)
    finally:
        monkeypatch.delenv("FIXOPS_OVERLAY_PATH", raising=False)
        monkeypatch.delenv("FIXOPS_DATA_ROOT_ALLOWLIST", raising=False)
        monkeypatch.delenv("FIXOPS_API_TOKEN", raising=False)
        shutil.rmtree(safe_root, ignore_errors=True)
