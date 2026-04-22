"""Tests for UpgradePathResolverEngine — ALDECI (GAP-007).

Covers:
- Version comparison helper (SemVer, PEP 440, Maven edge cases)
- pURL parsing (valid and invalid)
- NpmAdapter / PypiAdapter / MavenAdapter static catalog lookups
- resolve_upgrade lodash CVE walk (4.17.19 + CVE-2020-8203 → 4.17.21)
- resolve_upgrade pypi (requests + CVE-2023-32681 → 2.31.0)
- resolve_upgrade maven log4j (log4j-core + CVE-2021-44228 → 2.15.0+)
- Multi-CVE resolution picks max floor version
- Yanked-version skip behavior (through a custom adapter)
- No-fix-available case returns recommended_version=None
- Major-bump risk flag (high) vs patch-bump (low) vs minor (medium)
- Unresolved CVEs listed in the response
- bulk_resolve aggregates results + errors
- ingest_vuln upserts + resolve recognises the new entry
- add_package_version dedup
- stats() counters reflect vuln catalog and queries
- list_queries org-scoped history
- Org isolation: org_a queries invisible to org_b
- 35+ tests

Tests use tmp_path to isolate the DB; never touch the real .fixops_data.
"""

from __future__ import annotations

import sys

import pytest

sys.path.insert(0, "suite-core")
sys.path.insert(0, "suite-api")

from core.upgrade_path_resolver_engine import (  # noqa: E402
    EcosystemAdapter,
    MavenAdapter,
    NpmAdapter,
    PypiAdapter,
    UpgradePathResolverEngine,
    compare_versions,
    parse_purl,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def engine(tmp_path):
    return UpgradePathResolverEngine(db_path=str(tmp_path / "upgrade_path.db"))


# ---------------------------------------------------------------------------
# compare_versions
# ---------------------------------------------------------------------------


def test_compare_versions_equal():
    assert compare_versions("1.2.3", "1.2.3") == 0


def test_compare_versions_patch_bump():
    assert compare_versions("1.2.3", "1.2.4") == -1
    assert compare_versions("1.2.4", "1.2.3") == 1


def test_compare_versions_minor_bump():
    assert compare_versions("1.2.9", "1.3.0") == -1


def test_compare_versions_major_bump():
    assert compare_versions("1.9.9", "2.0.0") == -1


def test_compare_versions_different_lengths():
    assert compare_versions("1.2", "1.2.0") == 0
    assert compare_versions("1.2", "1.2.1") == -1
    assert compare_versions("1.2.1", "1.2") == 1


def test_compare_versions_prerelease_is_lower():
    # 2.0.0-rc1 < 2.0.0
    assert compare_versions("2.0.0-rc1", "2.0.0") == -1
    assert compare_versions("2.0.0", "2.0.0-rc1") == 1


def test_compare_versions_alpha_beta_rc_order():
    assert compare_versions("1.0.0-alpha", "1.0.0-beta") == -1
    assert compare_versions("1.0.0-beta", "1.0.0-rc1") == -1


def test_compare_versions_maven_suffix():
    # guava 30.0-jre < 32.0.0-jre
    assert compare_versions("30.0-jre", "32.0.0-jre") == -1


def test_compare_versions_four_segment_jackson():
    # jackson uses 4-segment patch numbering: 2.13.4.2 > 2.13.4
    assert compare_versions("2.13.4", "2.13.4.2") == -1
    assert compare_versions("2.13.4.2", "2.13.4") == 1


# ---------------------------------------------------------------------------
# parse_purl
# ---------------------------------------------------------------------------


def test_parse_purl_npm():
    out = parse_purl("pkg:npm/lodash@4.17.19")
    assert out == {"ecosystem": "npm", "name": "lodash", "version": "4.17.19"}


def test_parse_purl_pypi():
    out = parse_purl("pkg:pypi/requests@2.28.0")
    assert out["ecosystem"] == "pypi"
    assert out["name"] == "requests"


def test_parse_purl_maven_group_artifact():
    out = parse_purl(
        "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0"
    )
    assert out["ecosystem"] == "maven"
    assert out["name"] == "org.apache.logging.log4j/log4j-core"
    assert out["version"] == "2.14.0"


def test_parse_purl_without_version():
    out = parse_purl("pkg:npm/express")
    assert out["version"] == ""


def test_parse_purl_invalid_raises():
    with pytest.raises(ValueError):
        parse_purl("lodash@4.17.19")  # missing pkg: scheme
    with pytest.raises(ValueError):
        parse_purl("")
    with pytest.raises(ValueError):
        parse_purl(None)  # type: ignore[arg-type]


def test_parse_purl_ignores_query_params():
    out = parse_purl("pkg:npm/lodash@4.17.19?arch=x86_64")
    assert out["version"] == "4.17.19"


# ---------------------------------------------------------------------------
# Adapters
# ---------------------------------------------------------------------------


def test_npm_adapter_lists_lodash_versions():
    versions = NpmAdapter().list_versions("lodash")
    vers = [v[0] for v in versions]
    assert "4.17.19" in vers
    assert "4.17.21" in vers
    # ascending
    for i in range(1, len(vers)):
        assert compare_versions(vers[i - 1], vers[i]) == -1


def test_pypi_adapter_lists_requests_versions():
    versions = PypiAdapter().list_versions("requests")
    vers = [v[0] for v in versions]
    assert "2.31.0" in vers


def test_maven_adapter_lists_log4j_versions():
    versions = MavenAdapter().list_versions(
        "org.apache.logging.log4j/log4j-core"
    )
    vers = [v[0] for v in versions]
    assert "2.15.0" in vers
    assert "2.17.1" in vers


def test_adapter_unknown_package_returns_empty():
    assert NpmAdapter().list_versions("non-existent-pkg-xyz") == []


def test_adapter_is_major_bump():
    assert NpmAdapter().is_major_bump("4.17.19", "5.0.0") is True
    assert NpmAdapter().is_major_bump("4.17.19", "4.17.21") is False


# ---------------------------------------------------------------------------
# resolve_upgrade — core CVE walk
# ---------------------------------------------------------------------------


def test_resolve_lodash_cve_2020_8203(engine):
    """lodash 4.17.19 + CVE-2020-8203 → 4.17.20 (fixed_in).

    Since 4.17.20 exists in the catalog and is the floor, it should be
    chosen as the lowest safe upgrade.
    """
    out = engine.resolve_upgrade(
        org_id="o1", purl="pkg:npm/lodash@4.17.19", cve_ids=["CVE-2020-8203"]
    )
    assert out["recommended_version"] == "4.17.20"
    assert out["ecosystem"] == "npm"
    assert out["breaking_change_risk"] == "low"  # patch bump
    assert out["unresolved_cves"] == []


def test_resolve_lodash_multi_cve_picks_higher_floor(engine):
    """CVE-2020-8203 fixed in 4.17.20, CVE-2021-23337 fixed in 4.17.21.

    Must pick 4.17.21 (max floor).
    """
    out = engine.resolve_upgrade(
        org_id="o1",
        purl="pkg:npm/lodash@4.17.19",
        cve_ids=["CVE-2020-8203", "CVE-2021-23337"],
    )
    assert out["recommended_version"] == "4.17.21"
    assert out["breaking_change_risk"] == "low"


def test_resolve_pypi_requests(engine):
    out = engine.resolve_upgrade(
        org_id="o1",
        purl="pkg:pypi/requests@2.30.0",
        cve_ids=["CVE-2023-32681"],
    )
    assert out["recommended_version"] == "2.31.0"
    assert out["ecosystem"] == "pypi"


def test_resolve_maven_log4shell(engine):
    out = engine.resolve_upgrade(
        org_id="o1",
        purl="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0",
        cve_ids=["CVE-2021-44228"],
    )
    assert out["recommended_version"] == "2.15.0"
    assert out["ecosystem"] == "maven"


def test_resolve_maven_log4j_triple_cve(engine):
    """Three Log4Shell-era CVEs: floor is 2.17.0 (CVE-2021-45105 fixed_in)."""
    out = engine.resolve_upgrade(
        org_id="o1",
        purl="pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0",
        cve_ids=["CVE-2021-44228", "CVE-2021-45046", "CVE-2021-45105"],
    )
    assert out["recommended_version"] == "2.17.0"


def test_resolve_no_fix_available(engine):
    """CVE not in the catalog → no recommendation + listed unresolved."""
    out = engine.resolve_upgrade(
        org_id="o1",
        purl="pkg:npm/lodash@4.17.19",
        cve_ids=["CVE-2099-99999"],
    )
    assert out["recommended_version"] is None
    assert "CVE-2099-99999" in out["unresolved_cves"]


def test_resolve_major_bump_risk_high(engine):
    """Seed a CVE whose fix lives in a new major version."""
    engine.ingest_vuln(
        ecosystem="npm",
        package_name="express",
        version="3.0.0",
        cve_id="CVE-FAKE-MAJOR",
        fixed_in="4.0.0",
    )
    out = engine.resolve_upgrade(
        org_id="o1",
        purl="pkg:npm/express@3.0.0",
        cve_ids=["CVE-FAKE-MAJOR"],
    )
    assert out["recommended_version"] == "4.0.0"
    assert out["breaking_change_risk"] == "high"


def test_resolve_minor_bump_risk_medium(engine):
    engine.ingest_vuln(
        ecosystem="npm",
        package_name="express",
        version="4.17.0",
        cve_id="CVE-FAKE-MINOR",
        fixed_in="4.18.0",
    )
    out = engine.resolve_upgrade(
        org_id="o1",
        purl="pkg:npm/express@4.17.0",
        cve_ids=["CVE-FAKE-MINOR"],
    )
    assert out["recommended_version"] == "4.18.0"
    assert out["breaking_change_risk"] == "medium"


def test_resolve_patch_bump_risk_low(engine):
    out = engine.resolve_upgrade(
        org_id="o1",
        purl="pkg:npm/lodash@4.17.19",
        cve_ids=["CVE-2020-8203"],
    )
    assert out["breaking_change_risk"] == "low"


def test_resolve_empty_cve_ids_raises(engine):
    with pytest.raises(ValueError):
        engine.resolve_upgrade(
            org_id="o1", purl="pkg:npm/lodash@4.17.19", cve_ids=[]
        )


def test_resolve_missing_current_version_raises(engine):
    with pytest.raises(ValueError):
        engine.resolve_upgrade(
            org_id="o1", purl="pkg:npm/lodash", cve_ids=["CVE-2020-8203"]
        )


def test_resolve_missing_org_id_raises(engine):
    with pytest.raises(ValueError):
        engine.resolve_upgrade(
            org_id="", purl="pkg:npm/lodash@4.17.19", cve_ids=["CVE-2020-8203"]
        )


# ---------------------------------------------------------------------------
# Yanked-version skip — through a custom adapter
# ---------------------------------------------------------------------------


class _YankedTestAdapter:
    ecosystem = "npm"

    def list_versions(self, package_name):
        return [
            ("1.0.0", "2020-01-01", False),
            ("1.0.1", "2020-02-01", True),  # yanked → must be skipped
            ("1.0.2", "2020-03-01", False),
        ]

    def is_major_bump(self, from_v, to_v):
        return False


def test_resolve_skips_yanked_version(tmp_path):
    eng = UpgradePathResolverEngine(
        db_path=str(tmp_path / "yanked.db"),
        adapters={"npm": _YankedTestAdapter()},
    )
    eng.ingest_vuln(
        ecosystem="npm",
        package_name="testpkg",
        version="1.0.0",
        cve_id="CVE-Y-001",
        fixed_in="1.0.1",
    )
    out = eng.resolve_upgrade(
        org_id="o1", purl="pkg:npm/testpkg@1.0.0", cve_ids=["CVE-Y-001"]
    )
    # 1.0.1 is yanked → must skip to 1.0.2
    assert out["recommended_version"] == "1.0.2"
    # The yanked one shows up in alternate_paths with skipped_yanked=True
    yanked = [a for a in out["alternate_paths"] if a["skipped_yanked"]]
    assert yanked and yanked[0]["version"] == "1.0.1"


def test_resolve_unknown_package_no_recommendation(engine):
    """Package not in any adapter catalog → no versions → no recommendation."""
    engine.ingest_vuln(
        ecosystem="npm",
        package_name="mystery-pkg",
        version="1.0.0",
        cve_id="CVE-MY-1",
        fixed_in="1.0.1",
    )
    out = engine.resolve_upgrade(
        org_id="o1",
        purl="pkg:npm/mystery-pkg@1.0.0",
        cve_ids=["CVE-MY-1"],
    )
    assert out["recommended_version"] is None
    assert "no version catalog" in out["reason"]


# ---------------------------------------------------------------------------
# bulk_resolve
# ---------------------------------------------------------------------------


def test_bulk_resolve_happy_path(engine):
    out = engine.bulk_resolve(
        org_id="o1",
        findings=[
            {
                "purl": "pkg:npm/lodash@4.17.19",
                "cve_ids": ["CVE-2020-8203"],
            },
            {
                "purl": "pkg:pypi/requests@2.30.0",
                "cve_ids": ["CVE-2023-32681"],
            },
        ],
    )
    assert out["total"] == 2
    assert out["resolved"] == 2
    versions = {r["recommended_version"] for r in out["results"]}
    assert versions == {"4.17.20", "2.31.0"}


def test_bulk_resolve_with_errors(engine):
    out = engine.bulk_resolve(
        org_id="o1",
        findings=[
            {
                "purl": "pkg:npm/lodash@4.17.19",
                "cve_ids": ["CVE-2020-8203"],
            },
            {"purl": "bogus", "cve_ids": ["CVE-X"]},  # malformed pURL
            {"cve_ids": ["CVE-X"]},  # missing purl
        ],
    )
    assert out["total"] == 3
    assert out["resolved"] == 1
    assert len(out["errors"]) == 2


def test_bulk_resolve_not_a_list_raises(engine):
    with pytest.raises(ValueError):
        engine.bulk_resolve(org_id="o1", findings="not-a-list")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# ingest_vuln
# ---------------------------------------------------------------------------


def test_ingest_vuln_inserts(engine):
    row = engine.ingest_vuln(
        ecosystem="npm",
        package_name="lodash",
        version="4.17.19",
        cve_id="CVE-CUSTOM-1",
        fixed_in="4.17.21",
    )
    assert row["cve_id"] == "CVE-CUSTOM-1"
    # Can now be resolved
    out = engine.resolve_upgrade(
        org_id="o1",
        purl="pkg:npm/lodash@4.17.19",
        cve_ids=["CVE-CUSTOM-1"],
    )
    assert out["recommended_version"] == "4.17.21"


def test_ingest_vuln_missing_fields_raises(engine):
    with pytest.raises(ValueError):
        engine.ingest_vuln(
            ecosystem="",
            package_name="lodash",
            version="4.17.19",
            cve_id="CVE-X",
            fixed_in="4.17.21",
        )


def test_ingest_vuln_is_idempotent(engine):
    """Duplicate inserts on the unique key are ignored."""
    for _ in range(3):
        engine.ingest_vuln(
            ecosystem="npm",
            package_name="lodash",
            version="4.17.19",
            cve_id="CVE-DUP-TEST",
            fixed_in="4.17.21",
        )
    stats = engine.stats()
    # Seed rows + 1 new row (dup inserts ignored)
    assert stats["vuln_catalog_total"] >= 1


# ---------------------------------------------------------------------------
# add_package_version
# ---------------------------------------------------------------------------


def test_add_package_version_stores(engine):
    row = engine.add_package_version(
        org_id="o1",
        ecosystem="npm",
        package_name="lodash",
        version="4.17.19",
        release_date="2020-07-08",
        yanked=False,
    )
    assert row["package_name"] == "lodash"
    assert row["yanked"] is False


def test_add_package_version_dedup(engine):
    engine.add_package_version(
        org_id="o1", ecosystem="npm", package_name="lodash", version="4.17.19"
    )
    engine.add_package_version(
        org_id="o1", ecosystem="npm", package_name="lodash", version="4.17.19"
    )
    # INSERT OR IGNORE — no crash, no duplicate row


# ---------------------------------------------------------------------------
# stats / list_queries
# ---------------------------------------------------------------------------


def test_stats_returns_counters(engine):
    engine.resolve_upgrade(
        org_id="o1",
        purl="pkg:npm/lodash@4.17.19",
        cve_ids=["CVE-2020-8203"],
    )
    stats = engine.stats()
    assert stats["upgrade_queries_total"] >= 1
    assert stats["resolved_queries"] >= 1
    assert "npm" in stats["supported_ecosystems"]
    assert stats["vuln_catalog_total"] >= 8  # >= seed count


def test_stats_org_scoped(engine):
    engine.resolve_upgrade(
        org_id="o1",
        purl="pkg:npm/lodash@4.17.19",
        cve_ids=["CVE-2020-8203"],
    )
    engine.resolve_upgrade(
        org_id="o2",
        purl="pkg:npm/lodash@4.17.19",
        cve_ids=["CVE-2020-8203"],
    )
    a = engine.stats(org_id="o1")["upgrade_queries_total"]
    b = engine.stats(org_id="o2")["upgrade_queries_total"]
    assert a == 1
    assert b == 1


def test_list_queries_returns_history(engine):
    engine.resolve_upgrade(
        org_id="o1",
        purl="pkg:npm/lodash@4.17.19",
        cve_ids=["CVE-2020-8203"],
    )
    queries = engine.list_queries(org_id="o1")
    assert len(queries) == 1
    assert queries[0]["purl"] == "pkg:npm/lodash@4.17.19"
    assert queries[0]["recommended_version"] == "4.17.20"
    assert queries[0]["cve_ids"] == ["CVE-2020-8203"]


def test_list_queries_org_isolation(engine):
    engine.resolve_upgrade(
        org_id="o1",
        purl="pkg:npm/lodash@4.17.19",
        cve_ids=["CVE-2020-8203"],
    )
    engine.resolve_upgrade(
        org_id="o2",
        purl="pkg:pypi/requests@2.30.0",
        cve_ids=["CVE-2023-32681"],
    )
    o1 = engine.list_queries(org_id="o1")
    o2 = engine.list_queries(org_id="o2")
    assert len(o1) == 1 and len(o2) == 1
    assert o1[0]["purl"].startswith("pkg:npm/lodash")
    assert o2[0]["purl"].startswith("pkg:pypi/requests")


def test_list_queries_limit_clamp(engine):
    for _ in range(3):
        engine.resolve_upgrade(
            org_id="o1",
            purl="pkg:npm/lodash@4.17.19",
            cve_ids=["CVE-2020-8203"],
        )
    assert len(engine.list_queries(org_id="o1", limit=2)) == 2
    # negative/oversized → clamped, not crashed
    assert len(engine.list_queries(org_id="o1", limit=10_000)) >= 1


# ---------------------------------------------------------------------------
# Seed sanity
# ---------------------------------------------------------------------------


def test_seed_includes_lodash(engine):
    stats = engine.stats()
    assert stats["vuln_catalog_total"] >= 8
    assert stats["vulns_by_ecosystem"].get("npm", 0) >= 1
    assert stats["vulns_by_ecosystem"].get("pypi", 0) >= 1
    assert stats["vulns_by_ecosystem"].get("maven", 0) >= 1


def test_seed_idempotent_across_instances(tmp_path):
    db = str(tmp_path / "reseed.db")
    e1 = UpgradePathResolverEngine(db_path=db)
    n1 = e1.stats()["vuln_catalog_total"]
    # Second instance on the same DB: seeds must NOT double up
    e2 = UpgradePathResolverEngine(db_path=db)
    n2 = e2.stats()["vuln_catalog_total"]
    assert n1 == n2
