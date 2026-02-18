import json
import logging

import pytest
from apps.api.normalizers import InputNormalizer


@pytest.fixture(autouse=True)
def _reset_converter(monkeypatch):
    """Ensure tests control the optional Snyk converter."""

    monkeypatch.setattr(
        "apps.api.normalizers.snyk_converter",
        None,
        raising=False,
    )


def _build_sarif_document():
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {"driver": {"name": "FallbackScanner"}},
                "results": [
                    {
                        "ruleId": "FBK001",
                        "level": "warning",
                        "message": {"text": "Example finding"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "src/app.py"},
                                    "region": {"startLine": 10},
                                }
                            }
                        ],
                    }
                ],
            }
        ],
    }


def test_load_sarif_uses_embedded_payload_when_converter_missing():
    normalizer = InputNormalizer()
    sarif_document = _build_sarif_document()

    payload = {
        "ok": True,
        "sarif": json.dumps(sarif_document),
    }

    normalized = normalizer.load_sarif(json.dumps(payload))

    assert normalized.metadata["finding_count"] == 1
    assert normalized.metadata["supported_schema"] is True


def test_load_sarif_logs_actionable_error_without_converter(caplog):
    normalizer = InputNormalizer()

    raw_payload = json.dumps({"issues": [], "ok": False})

    with caplog.at_level(logging.ERROR):
        with pytest.raises(ValueError):
            normalizer.load_sarif(raw_payload)

    assert "snyk-to-sarif" in caplog.text


def test_load_sarif_converts_snyk_payload_without_converter():
    normalizer = InputNormalizer()

    payload = {
        "ok": False,
        "snykVersion": "1.1200.0",
        "projectName": "customer-suite",
        "org": "fixops",
        "issues": {
            "vulnerabilities": [
                {
                    "id": "SNYK-JS-SQLINJECTION",
                    "title": "SQL injection in query builder",
                    "severity": "high",
                    "from": [
                        "customer-api@1.4.2",
                        "express@4.18.0",
                    ],
                    "packageManager": "npm",
                    "packageName": "customer-api",
                    "identifiers": {"CVE": ["CVE-2023-1234"]},
                    "cvssScore": 8.1,
                }
            ]
        },
    }

    normalized = normalizer.load_sarif(json.dumps(payload))

    assert normalized.metadata["finding_count"] == 1
    assert normalized.tool_names == ["Snyk"]
    finding = normalized.findings[0]
    assert finding.rule_id == "SNYK-JS-SQLINJECTION"
    assert finding.level == "error"
    assert finding.file in {"express@4.18.0", "customer-api@1.4.2"}
    assert "dependency_path" in finding.raw.get("properties", {})


def test_load_sarif_rejects_invalid_severity():
    normalizer = InputNormalizer()
    sarif_document = _build_sarif_document()
    sarif_document["runs"][0]["results"][0]["level"] = "critical"

    with pytest.raises(ValueError):
        normalizer.load_sarif(json.dumps(sarif_document))


def test_load_sarif_rejects_oversized_payload():
    normalizer = InputNormalizer(max_document_bytes=128)
    oversized = {
        "version": "2.1.0",
        "runs": [],
        "padding": "x" * 256,
    }

    with pytest.raises(ValueError):
        normalizer.load_sarif(json.dumps(oversized))
