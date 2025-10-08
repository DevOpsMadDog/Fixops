from __future__ import annotations

from src.services.ci_adapters import GitHubCIAdapter, JenkinsCIAdapter, SonarQubeAdapter
from src.services.compliance import ComplianceEngine
from src.services.decision_engine import DecisionEngine
from src.services.evidence import EvidenceStore
from src.services import signing


def _engine() -> DecisionEngine:
    return DecisionEngine(EvidenceStore(), ComplianceEngine())


def test_github_webhook_comment(signing_env: None) -> None:
    adapter = GitHubCIAdapter(_engine())
    payload = {
        "repository": {"full_name": "DevOpsMadDog/fixops"},
        "number": 42,
        "analysis": {
            "findings": [
                {"id": "CVE-1", "severity": "critical"},
                {"id": "CVE-2", "severity": "medium"},
            ],
            "controls": [
                {"id": "AC-1", "framework": "iso_27001", "status": "pass"},
                {"id": "CM-2", "framework": "nist_ssdf", "status": "fail"},
            ],
            "frameworks": ["iso_27001", "nist_ssdf"],
        },
    }
    result = adapter.handle_webhook("pull_request", payload)
    assert result["verdict"] in {"block", "review"}
    assert "Top factors" in result["comment"]
    assert result["top_factors"], "top_factors should surface in webhook response"
    evidence = adapter._engine.evidence_store.get(result["evidence_id"])  # type: ignore[attr-defined]
    assert evidence and evidence.signature
    assert signing.verify_manifest(evidence.manifest, evidence.signature)


def test_jenkins_signed_response(signing_env: None) -> None:
    adapter = JenkinsCIAdapter(_engine())
    payload = {
        "sarif": {
            "runs": [
                {
                    "results": [
                        {"level": "error", "message": {"text": "SQLi"}},
                        {"level": "warning", "message": {"text": "XSS"}},
                    ]
                }
            ]
        },
        "controls": [{"id": "AC-1", "framework": "iso_27001", "status": "pass"}],
    }
    response = adapter.ingest(payload)
    assert response["signature"]
    assert response["kid"] == "test-kid"
    canonical = {k: v for k, v in response.items() if k not in {"signature", "kid", "algorithm"}}
    assert signing.verify_manifest(canonical, response["signature"])


def test_sonarqube_ingest_top_factors(signing_env: None) -> None:
    adapter = SonarQubeAdapter(_engine())
    payload = {
        "issues": [
            {"key": "ISS-1", "severity": "CRITICAL", "type": "BUG", "component": "svc.py"},
            {"key": "ISS-2", "severity": "MAJOR", "type": "VULNERABILITY", "component": "svc.py"},
        ],
        "controls": [{"id": "CM-1", "framework": "nist_ssdf", "status": "gap"}],
    }
    decision = adapter.ingest(payload)
    assert len(decision["top_factors"]) >= 2
    weights = [factor["weight"] for factor in decision["top_factors"]]
    assert weights == sorted(weights, reverse=True)

