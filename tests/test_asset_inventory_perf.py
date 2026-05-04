"""Performance assertions for AssetInventory.

Validates the three hotspot fixes:
  PERF-FIX-1 — discover_from_findings: O(1) dict lookup instead of O(N) list scan
  PERF-FIX-2 — bulk_import: single executemany+commit instead of N commits
  PERF-FIX-3 — get_asset_stats: no second list_assets() full scan
"""


import pytest

pytestmark = pytest.mark.perf
import time
import tempfile
import os
import pytest

from core.asset_inventory import AssetInventory, ManagedAsset, AssetCriticality


def _make_inventory():
    tmp = tempfile.mktemp(suffix=".db")
    return AssetInventory(db_path=tmp)


# ---------------------------------------------------------------------------
# PERF-FIX-1: discover_from_findings — O(N²) dedup eliminated
# ---------------------------------------------------------------------------

def test_discover_from_findings_large_batch_is_fast():
    """500-finding discovery must complete in under 3 seconds.

    Before the fix each finding triggered list_assets() (full table scan) +
    linear name search → O(N·M).  After fix: one list_assets() up front +
    O(1) dict lookups → O(N+M).
    """
    inv = _make_inventory()
    org_id = "perf-org-1"

    # Pre-populate 200 existing assets to give the dedup something to match against
    existing = [
        {"name": f"host-existing-{i}", "asset_type": "server", "org_id": org_id}
        for i in range(200)
    ]
    inv.bulk_import(existing, org_id)

    # 500 new findings, 100 of which collide with existing names
    findings = []
    for i in range(500):
        if i < 100:
            # collision with pre-populated asset
            findings.append({"name": f"host-existing-{i}", "hostname": f"h-{i}", "asset_type": "server"})
        else:
            findings.append({"hostname": f"new-host-{i}", "asset_type": "container"})

    start = time.monotonic()
    result = inv.discover_from_findings(findings, org_id)
    elapsed = time.monotonic() - start

    assert len(result) == 500, f"Expected 500 assets, got {len(result)}"
    assert elapsed < 3.0, f"discover_from_findings took {elapsed:.2f}s — expected < 3s"


def test_discover_from_findings_dedup_within_batch():
    """Duplicate names within a single batch must not create duplicate records."""
    inv = _make_inventory()
    org_id = "perf-org-dedup"

    findings = [
        {"name": "same-host", "hostname": "h1", "asset_type": "server"},
        {"name": "same-host", "hostname": "h1", "asset_type": "server"},  # duplicate
        {"name": "other-host", "hostname": "h2", "asset_type": "server"},
    ]
    result = inv.discover_from_findings(findings, org_id)
    # dedup_key dedups within batch; only 2 unique assets
    assert len(result) == 2


# ---------------------------------------------------------------------------
# PERF-FIX-2: bulk_import — single commit instead of N commits
# ---------------------------------------------------------------------------

def test_bulk_import_large_batch_is_fast():
    """500-asset bulk import must complete in under 3 seconds.

    Before the fix: 500 individual register_asset() calls → 500 commits.
    After fix: one executemany + one commit.
    """
    inv = _make_inventory()
    org_id = "perf-org-2"

    batch = [
        {
            "name": f"bulk-asset-{i}",
            "asset_type": "server",
            "criticality": "medium",
            "environment": "production",
        }
        for i in range(500)
    ]

    start = time.monotonic()
    count = inv.bulk_import(batch, org_id)
    elapsed = time.monotonic() - start

    assert count == 500, f"Expected 500 imported, got {count}"
    assert elapsed < 3.0, f"bulk_import took {elapsed:.2f}s — expected < 3s"


def test_bulk_import_skips_invalid_records():
    """Invalid records must be skipped; valid ones still imported."""
    inv = _make_inventory()
    org_id = "perf-org-skip"

    batch = [
        {"name": "good-1", "asset_type": "server"},
        {"name": "bad-criticality", "asset_type": "server", "criticality": "NOT_VALID"},
        {"name": "good-2", "asset_type": "container"},
    ]
    count = inv.bulk_import(batch, org_id)
    assert count == 2, f"Expected 2 valid imports, got {count}"


def test_bulk_import_compliance_autoscope():
    """bulk_import must apply the same compliance auto-scope as register_asset."""
    inv = _make_inventory()
    org_id = "perf-org-scope"

    batch = [{"name": "restricted-asset", "asset_type": "database", "data_classification": "restricted"}]
    count = inv.bulk_import(batch, org_id)
    assert count == 1

    assets = inv.list_assets(org_id)
    assert len(assets) == 1
    # restricted -> PCI + HIPAA + ITAR auto-scoped
    assert len(assets[0].compliance_scope) > 0


# ---------------------------------------------------------------------------
# PERF-FIX-3: get_asset_stats — no second list_assets() full scan
# ---------------------------------------------------------------------------

def test_get_asset_stats_correctness():
    """get_asset_stats must return correct totals after the SQL-aggregate rewrite."""
    inv = _make_inventory()
    org_id = "perf-org-3"

    inv.bulk_import([
        {"name": f"asset-{i}", "asset_type": "server", "criticality": "high",
         "metadata": {"internet_facing": True}}
        for i in range(10)
    ], org_id)
    inv.bulk_import([
        {"name": f"asset-low-{i}", "asset_type": "container", "criticality": "low"}
        for i in range(5)
    ], org_id)

    stats = inv.get_asset_stats(org_id)

    assert stats["total"] == 15
    assert stats["by_type"].get("server") == 10
    assert stats["by_type"].get("container") == 5
    # critical_exposed computed via SQL json_extract — high assets with internet_facing=True
    assert stats["critical_exposed"] == 10


def test_get_asset_stats_is_fast():
    """get_asset_stats on 1000 assets must complete in under 1 second."""
    inv = _make_inventory()
    org_id = "perf-org-stats"

    inv.bulk_import(
        [{"name": f"s-{i}", "asset_type": "server"} for i in range(1000)],
        org_id,
    )

    start = time.monotonic()
    stats = inv.get_asset_stats(org_id)
    elapsed = time.monotonic() - start

    assert stats["total"] == 1000
    assert elapsed < 1.0, f"get_asset_stats took {elapsed:.2f}s — expected < 1s"
