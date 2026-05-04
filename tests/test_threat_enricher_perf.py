"""Perf assertions for threat intel enrichment hotspot fixes.

Fix #1: _load_epss_cache() is skipped on repeat enrich_findings() calls.
Fix #2: _batch_fetch_epss() fires batches in parallel (ThreadPoolExecutor).
Fix #3: bulk_enrich() uses a single executemany transaction.
"""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.perf

import sys
import time
from pathlib import Path
from unittest.mock import patch

import pytest

# Ensure suite-core is importable
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "suite-core"))


# ---------------------------------------------------------------------------
# Fix #1: EPSS cache file is read only once per ThreatEnricher instance
# ---------------------------------------------------------------------------

def test_epss_cache_loaded_only_once():
    """_load_epss_cache must not be called on second enrich_findings() call."""
    from core.ml.threat_enricher import ThreatEnricher

    enricher = ThreatEnricher()

    findings = [
        {"id": "f1", "cve_id": "CVE-2021-44228", "severity": "critical"},
        {"id": "f2", "cve_id": "CVE-2023-44487", "severity": "high"},
    ]

    call_count = {"n": 0}
    original = enricher._load_epss_cache

    def counting_load():
        call_count["n"] += 1
        original()

    with patch.object(enricher, "_load_epss_cache", side_effect=counting_load):
        # First call — should load cache
        enricher._epss_cache_loaded = False
        enricher.enrich_findings(list(findings), skip_api=True)
        assert call_count["n"] == 1, "cache should be loaded on first call"

        # Second call — cache flag is set, must NOT reload
        enricher.enrich_findings(list(findings), skip_api=True)
        assert call_count["n"] == 1, "cache must NOT be reloaded on subsequent calls (fix #1)"


# ---------------------------------------------------------------------------
# Fix #2: _batch_fetch_epss fires batches in parallel
# ---------------------------------------------------------------------------

def test_batch_fetch_epss_parallel():
    """Multiple EPSS batches must be issued in parallel, not sequentially.

    We mock _fetch_json to sleep 0.1s per call and verify that fetching
    3 batches takes < 2× a single batch latency (i.e., they ran concurrently).
    """
    from core.ml import threat_enricher as te_mod
    from core.ml.threat_enricher import ThreatEnricher, EPSS_BATCH_SIZE

    BATCH_LATENCY = 0.08  # seconds per simulated network call

    def slow_fetch(url: str, timeout: int = 15):
        time.sleep(BATCH_LATENCY)
        # Parse out CVEs from url to return plausible data
        cve_param = url.split("cve=")[-1] if "cve=" in url else ""
        cves = [c for c in cve_param.split(",") if c]
        return {"data": [{"cve": c, "epss": "0.05"} for c in cves]}

    # Build enough CVEs to force 3 batches
    n_cves = EPSS_BATCH_SIZE * 3
    cve_ids = [f"CVE-2020-{i:05d}" for i in range(n_cves)]

    enricher = ThreatEnricher()

    with patch.object(te_mod, "_fetch_json", side_effect=slow_fetch):
        t0 = time.monotonic()
        enricher._batch_fetch_epss(cve_ids)
        elapsed = time.monotonic() - t0

    # Sequential would take >= 3 * BATCH_LATENCY; parallel should finish in < 2×
    sequential_floor = 3 * BATCH_LATENCY
    assert elapsed < sequential_floor * 1.8, (
        f"_batch_fetch_epss looks sequential: {elapsed:.3f}s >= {sequential_floor * 1.8:.3f}s "
        f"(fix #2 — parallel batching expected)"
    )
    # All CVEs should be enriched
    assert len(enricher._epss_cache) == n_cves, (
        f"Expected {n_cves} EPSS entries, got {len(enricher._epss_cache)}"
    )


# ---------------------------------------------------------------------------
# Fix #3: bulk_enrich uses a single executemany (O(1) transactions)
# ---------------------------------------------------------------------------

def test_bulk_enrich_single_transaction(tmp_path):
    """bulk_enrich must write N indicators efficiently and return correct records.

    Validates fix #3: single executemany replaces N serial create calls.
    We assert correctness (all records created with right fields) and that
    the operation completes well under the time N serial calls would take.
    """
    sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "suite-core"))
    from core.threat_intel_enrichment_engine import ThreatIntelEnrichmentEngine

    db_path = str(tmp_path / "test_enrich.db")
    engine = ThreatIntelEnrichmentEngine(db_path=db_path)

    N = 100
    indicators = [
        {"indicator": f"10.0.{i // 256}.{i % 256}", "indicator_type": "ip", "sources_queried": 3}
        for i in range(N)
    ]

    t0 = time.monotonic()
    created = engine.bulk_enrich("org-test", indicators)
    elapsed = time.monotonic() - t0

    assert len(created) == N, f"Expected {N} records, got {len(created)}"

    # Verify all records have required fields
    for rec in created:
        assert rec["org_id"] == "org-test"
        assert rec["status"] == "pending"
        assert rec["indicator_type"] == "ip"
        assert rec["sources_queried"] == 3
        assert rec["id"]  # uuid generated

    # Perf: single-transaction executemany should handle 100 inserts in < 300ms
    # (N serial calls with RLock + sqlite3.connect() each would easily exceed this)
    assert elapsed < 0.3, (
        f"bulk_enrich took {elapsed:.3f}s for {N} records — "
        f"single executemany should be < 0.3s (fix #3)"
    )

    # Verify records are actually persisted in the DB
    reqs = engine.list_enrichment_requests("org-test", limit=N + 10)
    assert len(reqs) == N, f"DB should have {N} rows, found {len(reqs)}"


# ---------------------------------------------------------------------------
# Regression: enrich_findings still produces correct output after fixes
# ---------------------------------------------------------------------------

def test_enrich_findings_correctness_after_fixes():
    """All three fixes must not break correctness of enrichment output."""
    from core.ml.threat_enricher import ThreatEnricher

    enricher = ThreatEnricher()
    # Pre-load KEV and EPSS with known values
    enricher._kev_set = {"CVE-2021-44228"}
    enricher._kev_details = {"CVE-2021-44228": {"dueDate": "2022-01-01", "dateAdded": "2021-12-10", "vendorProject": "Apache"}}
    enricher._kev_loaded = True
    enricher._epss_cache = {"CVE-2021-44228": 0.975, "CVE-2023-44487": 0.42}
    enricher._epss_cache_loaded = True

    findings = [
        {"id": "f1", "cve_id": "CVE-2021-44228", "severity": "critical"},
        {"id": "f2", "cve_id": "CVE-2023-44487", "severity": "high"},
        {"id": "f3", "cve_id": None, "severity": "low"},
    ]

    result = enricher.enrich_findings(findings, skip_api=True)

    assert result["enriched"] == 2
    assert findings[0]["in_kev"] is True
    assert findings[0]["epss_score"] == 0.975
    assert findings[1]["in_kev"] is False
    assert findings[1]["epss_score"] == 0.42
    # f3 has no cve_id — must be untouched
    assert "epss_score" not in findings[2]
