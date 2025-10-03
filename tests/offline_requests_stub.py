"""Offline-friendly stub of the ``requests`` module used in FixOps tests.

The real FixOps services are not available in the execution environment for
these kata-style tests, so we provide deterministic stand-ins for the handful
of API calls exercised by the regression scripts.  The goal is to let pytest
execute without reaching out to real HTTP services while still returning
realistic payloads that downstream assertions expect.

The stub deliberately implements only the tiny subset of ``requests`` that the
fixtures consume (``get``/``post`` plus the ``exceptions.Timeout`` type and
basic ``Response`` metadata).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Optional
from urllib.parse import urlparse
import json


class _Timeout(Exception):
    """Exception raised to emulate ``requests.exceptions.Timeout``."""


class _ExceptionsModule:
    Timeout = _Timeout


exceptions = _ExceptionsModule()


@dataclass
class _Response:
    status_code: int
    _payload: Optional[Any] = None
    _text_override: Optional[str] = None
    headers: Optional[Dict[str, str]] = None

    def __post_init__(self) -> None:
        if self.headers is None:
            content_type = "application/json" if isinstance(self._payload, (dict, list)) else "text/plain"
            self.headers = {"content-type": content_type}
        elif "content-type" not in self.headers:
            content_type = "application/json" if isinstance(self._payload, (dict, list)) else "text/plain"
            self.headers["content-type"] = content_type

    @property
    def text(self) -> str:
        if self._text_override is not None:
            return self._text_override
        if isinstance(self._payload, (dict, list)):
            return json.dumps(self._payload)
        if self._payload is None:
            return ""
        return str(self._payload)

    def json(self) -> Any:
        if isinstance(self._payload, (dict, list)):
            return self._payload
        try:
            return json.loads(self.text)
        except json.JSONDecodeError:
            return {"raw": self._payload}


_HTML_ROOT = """<!DOCTYPE html>
<html lang=\"en\">
<head><meta charset=\"utf-8\" /><title>FixOps Demo</title></head>
<body>
<div id=\"root\">FixOps Enterprise Demo – Enhanced CISO View</div>
</body>
</html>"""


def _demo_decision_payload() -> Dict[str, Any]:
    return {
        "status": "success",
        "decision": "BLOCK",
        "confidence_score": 0.91,
        "evidence_id": "demo-evidence-123",
        "reasoning": (
            "Offline fixture: risk above threshold, SSVC recommends action, "
            "compliance requires remediation"
        ),
        "consensus_details": {
            "vector_db": {"status": "success", "source": "stub"},
            "llm_rag": {"status": "success", "model": "demo-llm"},
            "consensus_checker": {"status": "success", "votes": 3},
            "golden_regression": {"status": "success", "regressions": 0},
            "policy_engine": {"status": "success", "policy": "enterprise"},
            "sbom_injection": {"status": "success", "components": 2},
        },
    }


def _demo_metrics_payload() -> Dict[str, Any]:
    return {
        "status": "success",
        "data": {
            "total_decisions": 128,
            "high_confidence_rate": 0.82,
            "block_percentage": 0.34,
            "warn_percentage": 0.23,
            "pass_percentage": 0.43,
        },
    }


def _demo_recent_payload() -> Dict[str, Any]:
    return {
        "status": "success",
        "data": [
            {
                "evidence_id": "evidence-001",
                "service_name": "payment-service",
                "decision": "BLOCK",
                "confidence": 0.91,
                "timestamp": "2024-10-01T12:00:00Z",
            },
            {
                "evidence_id": "evidence-002",
                "service_name": "inventory-service",
                "decision": "WARN",
                "confidence": 0.73,
                "timestamp": "2024-10-01T11:42:00Z",
            },
        ],
    }


def _demo_components_payload() -> Dict[str, Any]:
    return {
        "status": "success",
        "data": {
            "vector_db": {"status": "healthy", "type": "DemoVectorStore"},
            "llm_rag": {"status": "healthy", "model": "demo-llm"},
            "consensus_checker": {"status": "healthy"},
            "golden_regression": {"status": "healthy"},
            "policy_engine": {"status": "healthy"},
            "sbom_injection": {"status": "healthy"},
        },
    }


def _demo_ssdlc_payload() -> Dict[str, Any]:
    return {
        "status": "success",
        "data": {
            "discover": {"status": "complete"},
            "assess": {"status": "complete"},
            "remediate": {"status": "complete"},
            "verify": {"status": "complete"},
            "monitor": {"status": "complete"},
        },
    }


def _demo_scan_upload_payload(scan_type: str) -> Dict[str, Any]:
    return {
        "status": "success",
        "data": {
            "scan_type": scan_type,
            "findings_processed": 5,
            "processing_time_ms": 123,
            "message": "Offline ingestion stub",
        },
    }


def _enhanced_capabilities_payload() -> Dict[str, Any]:
    return {
        "status": "success",
        "data": {
            "capabilities": [
                "Automated decisioning",
                "Enterprise policy enforcement",
                "Continuous compliance",
            ]
        },
    }


def _build_response(url: str, method: str, *, data: Any = None, json_body: Any = None) -> _Response:
    parsed = urlparse(url)
    path = parsed.path or "/"

    if parsed.netloc.endswith("localhost:3000"):
        if path == "/":
            return _Response(200, _HTML_ROOT, headers={"content-type": "text/html"})
        if path == "/api/v1/enhanced/capabilities":
            return _Response(200, _enhanced_capabilities_payload())

    if parsed.netloc.endswith("localhost:8001"):
        if path.endswith("/api/v1/decisions/make-decision") and method == "POST":
            return _Response(200, _demo_decision_payload())
        if path.endswith("/api/v1/decisions/metrics"):
            return _Response(200, _demo_metrics_payload())
        if path.endswith("/api/v1/decisions/recent"):
            return _Response(200, _demo_recent_payload())
        if path.endswith("/api/v1/decisions/core-components"):
            return _Response(200, _demo_components_payload())
        if path.endswith("/api/v1/decisions/ssdlc-stages"):
            return _Response(200, _demo_ssdlc_payload())
        if path.endswith("/api/v1/scans/upload") and method == "POST":
            scan_type = "unknown"
            if isinstance(json_body, dict):
                scan_type = json_body.get("scan_type", "json")
            elif isinstance(data, dict):
                scan_type = data.get("scan_type", "form")
            return _Response(200, _demo_scan_upload_payload(scan_type))

    return _Response(404, {"status": "error", "message": "Offline stub: endpoint not implemented"})


def get(url: str, headers: Optional[Dict[str, str]] = None, params: Optional[Dict[str, Any]] = None, timeout: Optional[int] = None):
    if params:
        query = "&".join(f"{key}={value}" for key, value in params.items())
        if "?" not in url:
            url = f"{url}?{query}"
        else:
            url = f"{url}&{query}"
    return _build_response(url, "GET")


def post(url: str, data: Optional[Any] = None, json: Optional[Any] = None, headers: Optional[Dict[str, str]] = None, files: Optional[Any] = None, timeout: Optional[int] = None):
    return _build_response(url, "POST", data=data, json_body=json)

