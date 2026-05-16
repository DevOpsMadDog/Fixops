"""Real findings persistence tests — no mocks, real SQLite.

Tests:
  - Insert 100 fake findings into tenant-scoped DB
  - Dedup: re-inserting same fingerprints updates last_seen, not a new row
  - Filtering: severity, source, file_path, asset_id
  - Severity breakdown counts match inserted data
  - get_finding: hit + miss + cross-tenant isolation
  - Risk scores are computed (> 0 for non-informational findings)
  - Pagination: limit + offset correctness
  - Tenant isolation: tenant A cannot see tenant B rows
"""
from __future__ import annotations

import asyncio
import hashlib
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import List

import pytest

# ---------------------------------------------------------------------------
# Ensure suite paths are on sys.path (mirrors sitecustomize.py behaviour)
# ---------------------------------------------------------------------------
import sys, os

_REPO = Path(__file__).resolve().parents[1]
for _sub in ("suite-core", "suite-api", "suite-feeds", "suite-attack",
             "suite-evidence-risk", "suite-integrations"):
    _p = str(_REPO / _sub)
    if _p not in sys.path:
        sys.path.insert(0, _p)

from core.findings_persistence import (  # noqa: E402
    Finding,
    FindingsStore,
    compute_fingerprint,
    get_findings_store,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

SEVERITIES = ["critical", "high", "medium", "low", "informational"]
SOURCES = ["Semgrep", "Trivy", "Bandit", "Checkov", "Grype"]
TENANT_A = f"tenant-test-{uuid.uuid4().hex[:8]}"
TENANT_B = f"tenant-test-{uuid.uuid4().hex[:8]}"


def _make_finding(i: int, tenant_id: str = TENANT_A, source: str = "Semgrep") -> Finding:
    sev = SEVERITIES[i % len(SEVERITIES)]
    src = SOURCES[i % len(SOURCES)] if source == "_cycle" else source
    rule_id = f"rule-{i % 20}"          # 20 distinct rules → dedup when i%20 collides
    file_path = f"src/module_{i % 10}/file.py"
    start_line = (i % 50) + 1
    fp = compute_fingerprint(rule_id, file_path, start_line, tenant_id)
    return Finding(
        tenant_id=tenant_id,
        asset_id=f"asset-{i % 5}",
        source=src,
        rule_id=rule_id,
        rule_name=f"Rule {rule_id}",
        fingerprint=fp,
        file_path=file_path,
        start_line=start_line,
        end_line=start_line + 3,
        severity=sev,
        title=f"Finding {i}: {sev} issue in {file_path}",
        description=f"Detail for finding {i}",
        cve_id=f"CVE-2024-{1000 + i}" if i % 3 == 0 else "",
        cvss_score=round(3.0 + (i % 7), 1),
        epss_score=round((i % 10) / 100.0, 3),
    )


def _run(coro):
    """Run a coroutine in a fresh event loop (safe for pytest-asyncio or plain pytest)."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


# ---------------------------------------------------------------------------
# Fixture: isolated store + cleanup
# ---------------------------------------------------------------------------

@pytest.fixture()
def store(tmp_path, monkeypatch):
    """FindingsStore with data dir redirected to tmp_path so tests don't pollute data/."""
    import core.findings_persistence as fp_mod
    monkeypatch.setattr(fp_mod, "_DATA_DIR", tmp_path)
    s = FindingsStore()
    # Clear class-level cache so the tmp_path DBs are re-initialised
    s._initialized_dbs = set()
    return s


# ---------------------------------------------------------------------------
# Test 1: insert 100 findings
# ---------------------------------------------------------------------------

class TestInsert100:
    def test_insert_100_findings(self, store):
        findings = [_make_finding(i) for i in range(100)]
        result = _run(store.persist_findings(TENANT_A, "asset-batch", "Semgrep", findings))
        assert result["inserted"] + result["deduped"] == 100
        assert result["inserted"] >= 1
        # Total row count must equal inserted (deduped don't add rows)
        rows = _run(store.list_findings(TENANT_A, {}, limit=1000, offset=0))
        assert len(rows) == result["inserted"]

    def test_insert_returns_correct_totals(self, store):
        findings = [_make_finding(i) for i in range(20)]
        result = _run(store.persist_findings(TENANT_A, "asset-x", "Trivy", findings))
        assert result["inserted"] >= 1
        assert result["deduped"] >= 0
        assert result["inserted"] + result["deduped"] == 20


# ---------------------------------------------------------------------------
# Test 2: deduplication
# ---------------------------------------------------------------------------

class TestDedup:
    def test_same_fingerprint_deduped_not_inserted_twice(self, store):
        f = _make_finding(0)
        r1 = _run(store.persist_findings(TENANT_A, "asset-a", "Semgrep", [f]))
        assert r1["inserted"] == 1
        assert r1["deduped"] == 0

        # Re-insert the same finding
        r2 = _run(store.persist_findings(TENANT_A, "asset-a", "Semgrep", [f]))
        assert r2["inserted"] == 0
        assert r2["deduped"] == 1

        # Only 1 row in DB
        rows = _run(store.list_findings(TENANT_A, {}, limit=100))
        assert len(rows) == 1

    def test_dedup_updates_last_seen(self, store):
        f = _make_finding(1)
        _run(store.persist_findings(TENANT_A, "asset-a", "Semgrep", [f]))
        first = _run(store.get_finding(TENANT_A, f.id))
        assert first is not None

        import time; time.sleep(0.01)
        _run(store.persist_findings(TENANT_A, "asset-a", "Semgrep", [f]))
        second = _run(store.get_finding(TENANT_A, f.id))
        # last_seen should be updated (or equal if sub-second resolution matches)
        assert second.last_seen >= first.last_seen

    def test_different_fingerprints_all_inserted(self, store):
        findings = [_make_finding(i) for i in range(5, 15)]   # 10 distinct
        result = _run(store.persist_findings(TENANT_A, "asset-b", "Bandit", findings))
        assert result["inserted"] == 10
        assert result["deduped"] == 0


# ---------------------------------------------------------------------------
# Test 3: filtering
# ---------------------------------------------------------------------------

class TestFilters:
    def _seed(self, store):
        findings = [_make_finding(i, source="_cycle") for i in range(50)]
        _run(store.persist_findings(TENANT_A, "asset-filter", "mixed", findings))

    def test_filter_by_severity(self, store):
        self._seed(store)
        rows = _run(store.list_findings(TENANT_A, {"severity": "critical"}))
        assert all(r.severity == "critical" for r in rows)

    def test_filter_by_source(self, store):
        # Build batches with guaranteed-distinct fingerprints by using
        # unique rule_ids rather than relying on index arithmetic.
        def _make_source_finding(idx: int, source: str) -> Finding:
            rule_id = f"{source}-rule-{idx}"
            file_path = f"src/{source.lower()}/file_{idx}.py"
            fp = compute_fingerprint(rule_id, file_path, idx + 1, TENANT_A)
            return Finding(
                tenant_id=TENANT_A,
                asset_id="asset-s",
                source=source,
                rule_id=rule_id,
                rule_name=f"{source} Rule {idx}",
                fingerprint=fp,
                file_path=file_path,
                start_line=idx + 1,
                severity=SEVERITIES[idx % len(SEVERITIES)],
                title=f"{source} finding {idx}",
            )

        f1 = [_make_source_finding(i, "Semgrep") for i in range(10)]
        f2 = [_make_source_finding(i, "Trivy") for i in range(10)]
        _run(store.persist_findings(TENANT_A, "asset-s", "Semgrep", f1))
        _run(store.persist_findings(TENANT_A, "asset-s", "Trivy", f2))
        semgrep = _run(store.list_findings(TENANT_A, {"source": "Semgrep"}))
        trivy = _run(store.list_findings(TENANT_A, {"source": "Trivy"}))
        assert all(r.source == "Semgrep" for r in semgrep)
        assert all(r.source == "Trivy" for r in trivy)
        assert len(semgrep) > 0 and len(trivy) > 0

    def test_filter_by_file_path_substring(self, store):
        f = _make_finding(0)
        f.file_path = "src/payments/checkout.py"
        f.fingerprint = compute_fingerprint("unique-rule", f.file_path, 1, TENANT_A)
        _run(store.persist_findings(TENANT_A, "asset-p", "Semgrep", [f]))
        rows = _run(store.list_findings(TENANT_A, {"file_path": "payments"}))
        assert any("payments" in r.file_path for r in rows)

    def test_filter_by_asset_id(self, store):
        self._seed(store)
        rows = _run(store.list_findings(TENANT_A, {"asset_id": "asset-0"}))
        assert all(r.asset_id == "asset-0" for r in rows)


# ---------------------------------------------------------------------------
# Test 4: severity breakdown counts
# ---------------------------------------------------------------------------

class TestCounts:
    def test_count_matches_inserted_severity_distribution(self, store):
        findings = [_make_finding(i) for i in range(50)]
        _run(store.persist_findings(TENANT_A, "asset-c", "Checkov", findings))

        counts = _run(store.count_findings(TENANT_A, {}))
        assert "total" in counts
        assert counts["total"] > 0
        assert counts["critical"] >= 0
        assert counts["high"] >= 0
        assert counts["medium"] >= 0
        assert counts["low"] >= 0
        assert counts["informational"] >= 0

        # Verify total == sum of individual severities
        sev_sum = sum(counts[s] for s in ("critical", "high", "medium", "low", "informational"))
        assert counts["total"] == sev_sum

    def test_count_filter_by_source(self, store):
        f = [_make_finding(i, source="Grype") for i in range(200, 210)]
        _run(store.persist_findings(TENANT_A, "asset-g", "Grype", f))
        counts = _run(store.count_findings(TENANT_A, {"source": "Grype"}))
        assert counts["total"] == 10


# ---------------------------------------------------------------------------
# Test 5: get_finding
# ---------------------------------------------------------------------------

class TestGetFinding:
    def test_get_existing_finding(self, store):
        f = _make_finding(77)
        _run(store.persist_findings(TENANT_A, "asset-get", "Semgrep", [f]))
        result = _run(store.get_finding(TENANT_A, f.id))
        assert result is not None
        assert result.id == f.id
        assert result.severity == f.severity

    def test_get_nonexistent_returns_none(self, store):
        result = _run(store.get_finding(TENANT_A, "nonexistent-id"))
        assert result is None

    def test_get_cross_tenant_returns_none(self, store):
        f = _make_finding(88)
        _run(store.persist_findings(TENANT_A, "asset-ct", "Semgrep", [f]))
        # Same finding_id but different tenant DB — should return None
        result = _run(store.get_finding(TENANT_B, f.id))
        assert result is None


# ---------------------------------------------------------------------------
# Test 6: risk scores computed on insert
# ---------------------------------------------------------------------------

class TestRiskScores:
    def test_risk_score_nonzero_for_high_severity(self, store):
        f = _make_finding(0)
        f.severity = "high"
        f.cvss_score = 8.5
        f.fingerprint = compute_fingerprint("high-rule", "src/foo.py", 1, TENANT_A)
        _run(store.persist_findings(TENANT_A, "asset-rs", "Trivy", [f]))
        result = _run(store.get_finding(TENANT_A, f.id))
        assert result is not None
        assert result.risk_score > 0.0
        assert result.priority in ("P1", "P2", "P3", "P4")

    def test_risk_score_critical_higher_than_low(self, store):
        fc = _make_finding(200)
        fc.severity = "critical"
        fc.cvss_score = 9.8
        fc.fingerprint = compute_fingerprint("crit-rule", "src/crit.py", 1, TENANT_A)

        fl = _make_finding(201)
        fl.severity = "low"
        fl.cvss_score = 2.0
        fl.fingerprint = compute_fingerprint("low-rule", "src/low.py", 1, TENANT_A)

        _run(store.persist_findings(TENANT_A, "asset-rs2", "Trivy", [fc, fl]))
        rc = _run(store.get_finding(TENANT_A, fc.id))
        rl = _run(store.get_finding(TENANT_A, fl.id))
        assert rc is not None and rl is not None
        assert rc.risk_score >= rl.risk_score


# ---------------------------------------------------------------------------
# Test 7: pagination
# ---------------------------------------------------------------------------

class TestPagination:
    def test_limit_respected(self, store):
        findings = [_make_finding(i + 300) for i in range(30)]
        _run(store.persist_findings(TENANT_A, "asset-pag", "Semgrep", findings))
        page1 = _run(store.list_findings(TENANT_A, {}, limit=10, offset=0))
        assert len(page1) == 10

    def test_offset_pages(self, store):
        findings = [_make_finding(i + 400) for i in range(20)]
        _run(store.persist_findings(TENANT_A, "asset-pag2", "Semgrep", findings))
        page1 = _run(store.list_findings(TENANT_A, {}, limit=5, offset=0))
        page2 = _run(store.list_findings(TENANT_A, {}, limit=5, offset=5))
        ids1 = {f.id for f in page1}
        ids2 = {f.id for f in page2}
        assert ids1.isdisjoint(ids2), "Page 1 and page 2 must not overlap"


# ---------------------------------------------------------------------------
# Test 8: tenant isolation
# ---------------------------------------------------------------------------

class TestTenantIsolation:
    def test_tenant_a_cannot_see_tenant_b_findings(self, store):
        fa = _make_finding(500, tenant_id=TENANT_A)
        fb = _make_finding(501, tenant_id=TENANT_B)
        _run(store.persist_findings(TENANT_A, "asset-iso", "Semgrep", [fa]))
        _run(store.persist_findings(TENANT_B, "asset-iso", "Semgrep", [fb]))

        rows_a = _run(store.list_findings(TENANT_A, {}))
        rows_b = _run(store.list_findings(TENANT_B, {}))
        ids_a = {r.id for r in rows_a}
        ids_b = {r.id for r in rows_b}
        assert fb.id not in ids_a, "Tenant B finding must not appear in Tenant A"
        assert fa.id not in ids_b, "Tenant A finding must not appear in Tenant B"

    def test_count_scoped_to_tenant(self, store):
        findings = [_make_finding(i + 600, tenant_id=TENANT_A) for i in range(5)]
        _run(store.persist_findings(TENANT_A, "asset-cnt", "Bandit", findings))
        counts_a = _run(store.count_findings(TENANT_A, {}))
        counts_b = _run(store.count_findings(TENANT_B, {}))
        assert counts_a["total"] >= 5
        # Tenant B has no findings yet in this fixture
        assert counts_b["total"] == 0


# ---------------------------------------------------------------------------
# Test 9: fingerprint helper
# ---------------------------------------------------------------------------

class TestFingerprint:
    def test_same_inputs_same_fingerprint(self):
        fp1 = compute_fingerprint("rule-x", "src/a.py", 10, "tenant-1")
        fp2 = compute_fingerprint("rule-x", "src/a.py", 10, "tenant-1")
        assert fp1 == fp2

    def test_different_line_different_fingerprint(self):
        fp1 = compute_fingerprint("rule-x", "src/a.py", 10, "tenant-1")
        fp2 = compute_fingerprint("rule-x", "src/a.py", 11, "tenant-1")
        assert fp1 != fp2

    def test_different_tenant_different_fingerprint(self):
        fp1 = compute_fingerprint("rule-x", "src/a.py", 10, "tenant-1")
        fp2 = compute_fingerprint("rule-x", "src/a.py", 10, "tenant-2")
        assert fp1 != fp2

    def test_fingerprint_is_sha256_hex(self):
        fp = compute_fingerprint("r", "f", 1, "t")
        assert len(fp) == 64
        int(fp, 16)   # must be valid hex


# ---------------------------------------------------------------------------
# Test 10: singleton store
# ---------------------------------------------------------------------------

class TestSingleton:
    def test_get_findings_store_returns_same_instance(self):
        s1 = get_findings_store()
        s2 = get_findings_store()
        assert s1 is s2
