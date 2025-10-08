import json
import logging

import pytest

from apps.api.normalizers import InputNormalizer


@pytest.fixture(autouse=True)
def _reset_converter(monkeypatch):
    """Ensure tests control the optional Snyk converter."""

    monkeypatch.setattr("backend.normalizers.snyk_converter", None)


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
