"""
Wave 2C — verify each connector emits ``finding.created`` (or ``incident.created``)
events on the TrustGraph event bus when its import / scan method runs.

Five tests:

1. ``test_snyk_emits_on_import``
2. ``test_trivy_emits_on_scan``
3. ``test_aws_hub_emits_after_import``
4. ``test_emit_failure_swallowed`` — bus.emit raises → connector still completes
5. ``test_is_mock_flag_preserved`` — is_mock=True findings keep the flag on emit
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

# Ensure the suite paths are loaded (sitecustomize handles this on real runs,
# but be explicit for direct ``pytest tests/test_connector_event_emit.py``)
ROOT = Path(__file__).resolve().parents[1]
for sub in ("suite-core", "suite-api", "suite-attack"):
    p = str(ROOT / sub)
    if p not in sys.path:
        sys.path.insert(0, p)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _collect_emits(bus_mock: MagicMock) -> List[Dict[str, Any]]:
    """Return list of {event_type, payload} from a mocked bus."""
    out: List[Dict[str, Any]] = []
    for call in bus_mock.emit.call_args_list:
        # bus.emit(event_type, payload)
        args, kwargs = call.args, call.kwargs
        if args and len(args) >= 2:
            out.append({"event_type": args[0], "payload": args[1]})
        elif "event_type" in kwargs and "data" in kwargs:
            out.append({"event_type": kwargs["event_type"], "payload": kwargs["data"]})
    return out


# ---------------------------------------------------------------------------
# 1. Snyk — emits on import_results
# ---------------------------------------------------------------------------


def test_snyk_emits_on_import():
    """SnykClient.import_results must emit one finding.created per finding."""
    from core import snyk_integration

    bus_mock = MagicMock()
    bus_mock.emit = MagicMock(return_value=None)

    client = snyk_integration.SnykClient(api_token="", org_id="test-org-1")
    # Unconfigured → uses _MOCK_ISSUES path → real findings list assembled.

    with patch.object(snyk_integration, "_import_history", {}):
        with patch(
            "core.trustgraph_event_bus.get_event_bus", return_value=bus_mock
        ):
            findings = client.import_results(org_id="test-org-1")

    emits = _collect_emits(bus_mock)
    assert len(findings) > 0, "snyk mock path must yield findings"
    # At least one emit per finding (some payloads may carry multiple events,
    # but at minimum one event per finding from this connector).
    assert len(emits) >= len(findings), (
        f"expected >= {len(findings)} emits, got {len(emits)}"
    )
    # All emits from the snyk connector use engine="snyk"
    snyk_emits = [e for e in emits if e["payload"].get("engine") == "snyk"]
    assert len(snyk_emits) >= len(findings), (
        f"expected >= {len(findings)} snyk emits, got {len(snyk_emits)}"
    )
    for e in snyk_emits:
        assert e["event_type"] == "finding.created"
        assert e["payload"].get("org_id") == "test-org-1"


# ---------------------------------------------------------------------------
# 2. Trivy — emits on scan_and_ingest
# ---------------------------------------------------------------------------


def test_trivy_emits_on_scan():
    """TrivyScanner.scan_and_ingest must emit finding.created events."""
    from core import trivy_integration

    bus_mock = MagicMock()
    bus_mock.emit = MagicMock(return_value=None)

    scanner = trivy_integration.TrivyScanner()

    # Force scan path to return mock results — patch is_trivy_available so
    # the scanner's mock fixture data is used.
    fake_findings = [
        {
            "id": "trivy-001",
            "cve_id": "CVE-2024-9999",
            "severity": "high",
            "title": "Test Vuln",
            "is_mock": True,
        },
        {
            "id": "trivy-002",
            "cve_id": "CVE-2024-8888",
            "severity": "medium",
            "title": "Another Vuln",
            "is_mock": True,
        },
    ]

    with patch.object(scanner, "scan_image", return_value={"Results": []}), patch.object(
        scanner, "normalize_results", return_value=fake_findings
    ), patch.object(trivy_integration, "_scan_history", {}), patch(
        "core.trustgraph_event_bus.get_event_bus", return_value=bus_mock
    ):
        result = scanner.scan_and_ingest("alpine:3.18", org_id="test-org-2")

    assert result["status"] == "completed"
    emits = _collect_emits(bus_mock)
    trivy_emits = [e for e in emits if e["payload"].get("engine") == "trivy"]
    assert len(trivy_emits) == 2, f"expected 2 trivy emits, got {len(trivy_emits)}"
    assert all(e["event_type"] == "finding.created" for e in trivy_emits)
    assert {e["payload"].get("cve_id") for e in trivy_emits} == {
        "CVE-2024-9999",
        "CVE-2024-8888",
    }


# ---------------------------------------------------------------------------
# 3. AWS Security Hub — emits after import
# ---------------------------------------------------------------------------


def test_aws_hub_emits_after_import():
    """AWSSecurityHubClient.import_findings must emit finding.created events."""
    from core import aws_security_hub

    bus_mock = MagicMock()
    bus_mock.emit = MagicMock(return_value=None)

    client = aws_security_hub.AWSSecurityHubClient()

    fake_findings = [
        {
            "id": "asff-1",
            "cve_id": "CVE-2024-1111",
            "severity": "critical",
            "title": "S3 bucket public",
        },
    ]

    with patch.object(client, "get_findings", return_value=[]), patch.object(
        client, "normalize_asff", return_value=fake_findings
    ), patch.object(client, "_try_ingest_to_pipeline"), patch.object(
        aws_security_hub, "_import_history", {}
    ), patch(
        "core.trustgraph_event_bus.get_event_bus", return_value=bus_mock
    ):
        entry = client.import_findings(org_id="test-org-3")

    assert entry["status"] == "completed"
    emits = _collect_emits(bus_mock)
    hub_emits = [e for e in emits if e["payload"].get("engine") == "aws_security_hub"]
    assert len(hub_emits) == 1, f"expected 1 aws_security_hub emit, got {len(hub_emits)}"
    assert hub_emits[0]["event_type"] == "finding.created"
    assert hub_emits[0]["payload"].get("cve_id") == "CVE-2024-1111"
    assert hub_emits[0]["payload"].get("org_id") == "test-org-3"


# ---------------------------------------------------------------------------
# 4. Failure swallowed — bus.emit blowing up must not break the connector
# ---------------------------------------------------------------------------


def test_emit_failure_swallowed():
    """If bus.emit raises, the connector must still return its normal result."""
    from core import semgrep_integration

    bus_mock = MagicMock()
    bus_mock.emit = MagicMock(side_effect=RuntimeError("event bus down"))

    scanner = semgrep_integration.SemgrepScanner()

    fake_findings = [
        {"id": "sg-1", "severity": "high", "title": "XSS", "is_mock": True},
    ]

    with patch.object(scanner, "scan_directory", return_value={"results": []}), patch.object(
        scanner, "normalize_results", return_value=fake_findings
    ), patch.object(semgrep_integration, "_scan_history", {}), patch(
        "core.trustgraph_event_bus.get_event_bus", return_value=bus_mock
    ):
        # MUST NOT raise even though bus.emit is broken
        entry = scanner.scan_and_ingest("/tmp/nowhere", org_id="test-org-4")

    assert entry["status"] == "completed"
    assert entry["findings_count"] == 1
    # The mock was attempted at least once
    assert bus_mock.emit.call_count >= 1


# ---------------------------------------------------------------------------
# 5. is_mock flag preserved through the emit payload
# ---------------------------------------------------------------------------


def test_is_mock_flag_preserved():
    """Findings carrying is_mock=True must propagate that flag into the event."""
    from core import trivy_integration

    bus_mock = MagicMock()
    bus_mock.emit = MagicMock(return_value=None)

    scanner = trivy_integration.TrivyScanner()

    fake_findings = [
        {
            "id": "fake-mock-1",
            "severity": "low",
            "title": "Marked-mock finding",
            "is_mock": True,
        },
    ]

    with patch.object(scanner, "scan_image", return_value={"Results": []}), patch.object(
        scanner, "normalize_results", return_value=fake_findings
    ), patch.object(trivy_integration, "_scan_history", {}), patch(
        "core.trustgraph_event_bus.get_event_bus", return_value=bus_mock
    ):
        scanner.scan_and_ingest("alpine:latest", org_id="test-org-5")

    emits = _collect_emits(bus_mock)
    trivy_emits = [e for e in emits if e["payload"].get("engine") == "trivy"]
    assert len(trivy_emits) == 1
    assert trivy_emits[0]["payload"].get("is_mock") is True, (
        f"expected is_mock=True, got payload: {trivy_emits[0]['payload']}"
    )
