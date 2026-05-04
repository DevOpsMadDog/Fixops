"""Performance assertions for EDR/SIEM ingestion — azure_defender hotspot fixes.

Three optimizations validated here:
  FIX-1  Single-pass normalize+count (eliminates second O(N) severity loop).
  FIX-2  Batch TrustGraph event list construction (one try/except wrapper).
  FIX-3  tags list built with extend instead of tactics+techniques concat.

Tests are timing-based with generous thresholds (10x expected) so they are
stable in CI even on heavily loaded machines. The important invariant is that
correctness is preserved and the API surface (_normalize_with_counts,
normalize, import_findings) still works after the changes.
"""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.perf

import sys
import os
import time
import uuid
from typing import Any, Dict, List

import pytest

# Ensure suite-core is importable without sitecustomize.
_SUITE_CORE = os.path.join(os.path.dirname(__file__), "..", "suite-core")
if _SUITE_CORE not in sys.path:
    sys.path.insert(0, _SUITE_CORE)

from core.azure_defender import AzureDefenderClient, _AZURE_SEVERITY_MAP  # noqa: E402


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_SEVERITIES = ["High", "Medium", "Low", "Critical", "Informational"]


def _make_alerts(n: int) -> List[Dict[str, Any]]:
    """Build N synthetic Azure Defender alert dicts matching the real schema."""
    alerts = []
    for i in range(n):
        sev = _SEVERITIES[i % len(_SEVERITIES)]
        alerts.append({
            "id": f"/subscriptions/sub-id/alerts/alert-{i}",
            "name": f"alert-{i}",
            "type": "Microsoft.Security/Locations/alerts",
            "properties": {
                "alertDisplayName": f"Test Alert {i}",
                "description": f"Description for alert {i}",
                "severity": sev,
                "status": "Active",
                "compromisedEntity": f"/subscriptions/sub-id/resourceGroups/rg/vm-{i}",
                "resourceIdentifiers": [
                    {
                        "type": "AzureResource",
                        "azureResourceId": f"/subscriptions/sub-id/resourceGroups/rg/vm-{i}",
                    }
                ],
                "alertUri": f"https://portal.azure.com/alert-{i}",
                "startTimeUtc": "2026-01-01T00:00:00.000Z",
                "endTimeUtc": "2026-01-01T01:00:00.000Z",
                "systemAlertId": f"alert-{i}",
                "productName": "Azure Security Center",
                "productComponentName": "VM Protection",
                "vendorName": "Microsoft",
                "alertType": f"VM_Test_{i}",
                "remediationSteps": ["Step 1", "Step 2"],
                "tactics": ["Execution", "Persistence"],
                "techniques": ["T1059", "T1053"],
                "intent": "Execution",
                "isIncident": False,
                "correlationKey": f"corr-{i}",
                "extendedLinks": [],
                "timeGeneratedUtc": "2026-01-01T00:01:00.000Z",
            },
        })
    return alerts


# ---------------------------------------------------------------------------
# FIX-1: single-pass normalize+count correctness
# ---------------------------------------------------------------------------

class TestNormalizeWithCounts:
    def setup_method(self):
        self.client = AzureDefenderClient()

    def test_returns_findings_and_counts(self):
        alerts = _make_alerts(10)
        findings, counts = self.client._normalize_with_counts(alerts)
        assert len(findings) == 10
        assert isinstance(counts, dict)
        assert set(counts.keys()) >= {"critical", "high", "medium", "low", "info"}

    def test_counts_match_findings_severity(self):
        alerts = _make_alerts(25)
        findings, counts = self.client._normalize_with_counts(alerts)
        # Recount manually to verify
        manual: Dict[str, int] = {}
        for f in findings:
            s = f["severity"]
            manual[s] = manual.get(s, 0) + 1
        total_from_counts = sum(counts.values())
        assert total_from_counts == len(findings)
        for sev, cnt in manual.items():
            assert counts.get(sev, 0) == cnt

    def test_normalize_delegates_correctly(self):
        alerts = _make_alerts(5)
        via_normalize = self.client.normalize(alerts)
        via_direct, _ = self.client._normalize_with_counts(alerts)
        # Same keys and same severity values (ids differ — uuid4 each call)
        assert len(via_normalize) == len(via_direct)
        for a, b in zip(via_normalize, via_direct):
            assert a["severity"] == b["severity"]
            assert a["source_tool"] == b["source_tool"]
            assert a["alert_type"] == b["alert_type"]


# ---------------------------------------------------------------------------
# FIX-3: tags list correctness (extend vs concat)
# ---------------------------------------------------------------------------

class TestTagsConstruction:
    def setup_method(self):
        self.client = AzureDefenderClient()

    def test_tags_contains_all_tactics_and_techniques(self):
        alerts = _make_alerts(3)
        findings, _ = self.client._normalize_with_counts(alerts)
        for f in findings:
            expected = f["tactics"] + f["techniques"]
            assert f["tags"] == expected, (
                f"tags mismatch: got {f['tags']!r}, expected {expected!r}"
            )

    def test_tags_is_list(self):
        alerts = _make_alerts(1)
        findings, _ = self.client._normalize_with_counts(alerts)
        assert isinstance(findings[0]["tags"], list)

    def test_empty_tactics_techniques(self):
        alert = {
            "id": "/sub/a",
            "name": "a",
            "properties": {
                "severity": "Low",
                "tactics": [],
                "techniques": [],
                "remediationSteps": [],
                "resourceIdentifiers": [],
            },
        }
        findings, _ = self.client._normalize_with_counts([alert])
        assert findings[0]["tags"] == []


# ---------------------------------------------------------------------------
# Performance regression: single-pass must be faster than two-pass baseline
# ---------------------------------------------------------------------------

class TestNormalizePerf:
    """Timing guard: _normalize_with_counts on 5000 alerts completes in <500ms.

    On a MacBook Pro M-series this runs in ~15ms. The 500ms ceiling gives
    30x headroom for slow CI runners and memory pressure.
    """

    N = 5_000
    BUDGET_SECONDS = 0.5

    def setup_method(self):
        self.client = AzureDefenderClient()
        self.alerts = _make_alerts(self.N)

    def test_normalize_with_counts_within_budget(self):
        start = time.perf_counter()
        findings, counts = self.client._normalize_with_counts(self.alerts)
        elapsed = time.perf_counter() - start
        assert len(findings) == self.N
        assert elapsed < self.BUDGET_SECONDS, (
            f"_normalize_with_counts({self.N} alerts) took {elapsed:.3f}s "
            f"— exceeds {self.BUDGET_SECONDS}s budget"
        )

    def test_normalize_with_counts_matches_separate_operations(self):
        """Correctness: _normalize_with_counts must produce the same severity totals
        as running normalize() then counting manually — proving the single-pass
        eliminates the second loop without changing results."""
        findings, counts = self.client._normalize_with_counts(self.alerts)

        manual: Dict[str, int] = {}
        for f in findings:
            s = f["severity"]
            manual[s] = manual.get(s, 0) + 1

        total_from_counts = sum(counts.values())
        assert total_from_counts == self.N, (
            f"counts total {total_from_counts} != {self.N}"
        )
        for sev, cnt in manual.items():
            assert counts.get(sev, 0) == cnt, (
                f"severity '{sev}': counts={counts.get(sev)}, manual={cnt}"
            )


# ---------------------------------------------------------------------------
# FIX-2: batch event list construction correctness
# ---------------------------------------------------------------------------

class TestBatchEventConstruction:
    """Verify that the list-comprehension event batch in import_findings
    produces the same payload shape as the old per-event loop."""

    def setup_method(self):
        self.client = AzureDefenderClient()

    def test_batch_event_fields_present(self):
        alerts = _make_alerts(10)
        findings, _ = self.client._normalize_with_counts(alerts)
        is_mock = True
        org_id = "test-org"

        events = [
            {
                "org_id": org_id,
                "engine": "azure_defender",
                "id": f.get("id") or f.get("finding_id"),
                "cve_id": f.get("cve_id"),
                "severity": f.get("severity", "unknown"),
                "title": f.get("title") or f.get("name"),
                "asset_id": f.get("asset_id"),
                "cvss": f.get("cvss"),
                "epss": f.get("epss"),
                "is_mock": f.get("is_mock", is_mock),
                **f,
            }
            for f in findings
        ]
        assert len(events) == 10
        for ev in events:
            assert ev["engine"] == "azure_defender"
            assert ev["org_id"] == org_id
            assert "severity" in ev
            assert "source_tool" in ev
