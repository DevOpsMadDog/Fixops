"""Tests for EPSS importer and wired endpoint.

Tests:
1. Importer parses gzipped CSV fixture correctly
2. run() bulk-imports all rows + counts high-risk (epss > 0.5)
3. list_scores pagination
4. epss_min filter (>= semantics)
5. percentile_min filter (>= semantics)
6. Re-import REPLACES (does not append)
7. GET /api/v1/epss/scores/{cve_id} returns single row
"""

from __future__ import annotations

import gzip
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

# ---------------------------------------------------------------------------
# Path setup — suite-feeds / suite-core / suite-api must be importable
# ---------------------------------------------------------------------------
REPO_ROOT = Path(__file__).parent.parent
suite_feeds_path = str(REPO_ROOT / "suite-feeds")
suite_core_path = str(REPO_ROOT / "suite-core")
suite_api_path = str(REPO_ROOT / "suite-api")
for p in [suite_feeds_path, suite_core_path, suite_api_path]:
    if p not in sys.path:
        sys.path.insert(0, p)

from feeds.epss.importer import EpssImporter  # noqa: E402


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

SAMPLE_CSV = """#model_version:v2025.03.14,score_date:2025-03-14T00:00:00+0000
cve,epss,percentile
CVE-2021-44228,0.97564,0.99987
CVE-2022-30190,0.92341,0.99821
CVE-2023-23397,0.88412,0.99654
CVE-2024-12345,0.65432,0.97231
CVE-2024-23456,0.55123,0.95001
CVE-2024-34567,0.45678,0.92345
CVE-2024-45678,0.30000,0.85000
CVE-2024-56789,0.15000,0.70000
CVE-2024-67890,0.05000,0.50000
CVE-2024-78901,0.00100,0.10000
"""

SAMPLE_CSV_SMALL = """#model_version:v2025.04.01,score_date:2025-04-01T00:00:00+0000
cve,epss,percentile
CVE-2025-00001,0.42000,0.88000
CVE-2025-00002,0.06000,0.55000
"""


def _gzip(text: str) -> bytes:
    return gzip.compress(text.encode("utf-8"))


@pytest.fixture
def tmp_db(tmp_path):
    """Return a path to a fresh temporary SQLite DB."""
    return str(tmp_path / "test_epss.db")


@pytest.fixture
def importer_with_fixture(tmp_db):
    """Importer whose _fetch returns gzipped SAMPLE_CSV."""
    imp = EpssImporter(db_path=tmp_db)
    with patch.object(imp, "_fetch", return_value=_gzip(SAMPLE_CSV)):
        yield imp


# ---------------------------------------------------------------------------
# Test 1: parse sample fixture
# ---------------------------------------------------------------------------

def test_parse_sample_fixture():
    rows = EpssImporter._parse(_gzip(SAMPLE_CSV))
    assert len(rows) == 10

    # Types are coerced to float
    for r in rows:
        assert isinstance(r["cve_id"], str)
        assert isinstance(r["epss_score"], float)
        assert isinstance(r["percentile"], float)

    # Spot-check first row
    log4j = next(r for r in rows if r["cve_id"] == "CVE-2021-44228")
    assert log4j["epss_score"] == pytest.approx(0.97564)
    assert log4j["percentile"] == pytest.approx(0.99987)

    # Lowest row
    last = next(r for r in rows if r["cve_id"] == "CVE-2024-78901")
    assert last["epss_score"] == pytest.approx(0.001)
    assert last["percentile"] == pytest.approx(0.1)


# ---------------------------------------------------------------------------
# Test 2: run imports all rows + correct high_risk_count
# ---------------------------------------------------------------------------

def test_run_imports_all_rows(importer_with_fixture):
    result = importer_with_fixture.run()
    assert result["scores_imported"] == 10
    # epss > 0.5: 0.97564, 0.92341, 0.88412, 0.65432, 0.55123 = 5 rows
    assert result["high_risk_count"] == 5
    assert "source_url" in result
    assert importer_with_fixture.total_count() == 10


# ---------------------------------------------------------------------------
# Test 3: pagination
# ---------------------------------------------------------------------------

def test_list_pagination(importer_with_fixture):
    importer_with_fixture.run()

    # Page 1, size 3 → 3 rows, total = 10
    page1 = importer_with_fixture.list_scores(page=1, page_size=3)
    assert page1["total"] == 10
    assert page1["page"] == 1
    assert page1["page_size"] == 3
    assert len(page1["scores"]) == 3
    # Ordered by epss_score DESC — first must be the highest
    assert page1["scores"][0]["cve_id"] == "CVE-2021-44228"

    # Page 4, size 3 → 1 remaining
    page4 = importer_with_fixture.list_scores(page=4, page_size=3)
    assert len(page4["scores"]) == 1


# ---------------------------------------------------------------------------
# Test 4: epss_min filter (>=)
# ---------------------------------------------------------------------------

def test_filter_epss_min(importer_with_fixture):
    importer_with_fixture.run()

    # epss >= 0.5: 0.97564, 0.92341, 0.88412, 0.65432, 0.55123 = 5 rows
    result = importer_with_fixture.list_scores(epss_min=0.5, page_size=500)
    assert result["total"] == 5
    assert len(result["scores"]) == 5
    for row in result["scores"]:
        assert row["epss_score"] >= 0.5


# ---------------------------------------------------------------------------
# Test 5: percentile_min filter (>=)
# ---------------------------------------------------------------------------

def test_filter_percentile_min(importer_with_fixture):
    importer_with_fixture.run()

    # percentile >= 0.95:
    # 0.99987, 0.99821, 0.99654, 0.97231, 0.95001 = 5 rows
    result = importer_with_fixture.list_scores(
        percentile_min=0.95, page_size=500
    )
    assert result["total"] == 5
    assert len(result["scores"]) == 5
    for row in result["scores"]:
        assert row["percentile"] >= 0.95


# ---------------------------------------------------------------------------
# Test 6: re-import REPLACES (does not append)
# ---------------------------------------------------------------------------

def test_reimport_replaces_not_appends(tmp_db):
    imp = EpssImporter(db_path=tmp_db)

    with patch.object(imp, "_fetch", return_value=_gzip(SAMPLE_CSV)):
        first = imp.run()
    assert first["scores_imported"] == 10
    assert imp.total_count() == 10

    # Re-import with a 2-row variant — must REPLACE (not append → 12)
    with patch.object(imp, "_fetch", return_value=_gzip(SAMPLE_CSV_SMALL)):
        second = imp.run()
    assert second["scores_imported"] == 2
    assert imp.total_count() == 2

    # Old CVEs are gone
    assert imp.get_by_cve("CVE-2021-44228") is None
    # New CVE present
    new_row = imp.get_by_cve("CVE-2025-00001")
    assert new_row is not None
    assert new_row["epss_score"] == pytest.approx(0.42)


# ---------------------------------------------------------------------------
# Test 7: GET /api/v1/epss/scores/{cve_id} endpoint returns single row
# ---------------------------------------------------------------------------

def test_get_by_cve_endpoint(tmp_db):
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    # Pre-load DB with fixture data
    imp = EpssImporter(db_path=tmp_db)
    with patch.object(imp, "_fetch", return_value=_gzip(SAMPLE_CSV)):
        imp.run()
    assert imp.total_count() == 10

    # Build a minimal app, override auth, mount router
    from apps.api import epss_router
    from apps.api.auth_deps import api_key_auth

    app = FastAPI()
    app.include_router(epss_router.router)
    app.dependency_overrides[api_key_auth] = lambda: None

    # Patch _get_importer to return an EpssImporter bound to our tmp_db
    def _factory():
        class _Bound(EpssImporter):
            def __init__(self_inner):
                super().__init__(db_path=tmp_db)
        return _Bound

    with patch.object(epss_router, "_get_importer", _factory):
        client = TestClient(app)

        # Existing CVE
        resp = client.get("/api/v1/epss/scores/CVE-2024-12345")
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["cve_id"] == "CVE-2024-12345"
        assert body["epss_score"] == pytest.approx(0.65432)
        assert body["percentile"] == pytest.approx(0.97231)

        # Missing CVE → 404
        resp404 = client.get("/api/v1/epss/scores/CVE-9999-99999")
        assert resp404.status_code == 404
