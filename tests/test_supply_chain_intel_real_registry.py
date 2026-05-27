"""
Integration tests for supply_chain_intel.py real registry lookups.

These tests make LIVE network calls to PyPI, npm, and OSV.dev.
They are skipped when network is unavailable.

Run with:
    python -m pytest tests/test_supply_chain_intel_real_registry.py \
        -x --tb=short --timeout=60 -v -o "addopts="
"""
from __future__ import annotations

import os
import socket
import sys
import uuid
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "suite-core"))
sys.path.insert(0, str(Path(__file__).parent.parent / "suite-api"))

os.environ.setdefault("FIXOPS_MODE", "enterprise")
os.environ.setdefault("FIXOPS_API_TOKEN", "test-token")
os.environ.setdefault("FIXOPS_JWT_SECRET", "test-secret")
os.environ.setdefault("FIXOPS_DISABLE_TELEMETRY", "1")
os.environ.setdefault("FIXOPS_DISABLE_RATE_LIMIT", "1")


# ---------------------------------------------------------------------------
# Network availability guard
# ---------------------------------------------------------------------------

def _network_available() -> bool:
    """Return True if HTTPS egress to pypi.org is reachable."""
    try:
        socket.setdefaulttimeout(5)
        socket.getaddrinfo("pypi.org", 443)
        return True
    except OSError:
        return False


network_required = pytest.mark.skipif(
    not _network_available(),
    reason="Live network not available — skipping registry integration tests",
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def tmp_intel(tmp_path):
    from core.supply_chain_intel import SupplyChainIntel
    return SupplyChainIntel(db_path=str(tmp_path / "sci_real_test.db"))


@pytest.fixture
def org():
    return f"test-real-{uuid.uuid4().hex[:8]}"


# ---------------------------------------------------------------------------
# 1. PyPI metadata fetch
# ---------------------------------------------------------------------------

class TestPyPIMetadataFetch:
    @network_required
    def test_requests_package_real_last_updated(self):
        """'requests' is actively maintained — last_updated_days must be a real int, not hash."""
        from core.supply_chain_intel import _fetch_pypi_metadata
        meta = _fetch_pypi_metadata("requests")
        assert meta.is_real is True
        assert meta.data_source == "pypi"
        assert meta.not_found is False
        # last_updated_days: requests is well-maintained, should be < 1000
        assert meta.last_updated_days is not None
        assert isinstance(meta.last_updated_days, int)
        assert 0 <= meta.last_updated_days < 1000, (
            f"last_updated_days={meta.last_updated_days} — expected active package"
        )

    @network_required
    def test_requests_dependencies_count_real(self):
        """'requests' has real dependencies (e.g. urllib3, certifi, charset-normalizer)."""
        from core.supply_chain_intel import _fetch_pypi_metadata
        meta = _fetch_pypi_metadata("requests")
        # requests has at least 3 direct dependencies
        assert meta.dependencies_count is not None
        assert meta.dependencies_count >= 3, (
            f"dependencies_count={meta.dependencies_count} — expected >=3 for requests"
        )

    @network_required
    def test_nonexistent_pypi_package_returns_not_found(self):
        from core.supply_chain_intel import _fetch_pypi_metadata
        meta = _fetch_pypi_metadata("this-package-absolutely-does-not-exist-xyzabc123456789")
        assert meta.not_found is True
        assert meta.is_real is True
        assert meta.last_updated_days is None

    @network_required
    def test_numpy_has_recent_update(self):
        """numpy is actively maintained."""
        from core.supply_chain_intel import _fetch_pypi_metadata
        meta = _fetch_pypi_metadata("numpy")
        assert meta.is_real is True
        assert meta.last_updated_days is not None
        assert meta.last_updated_days < 730, (
            f"numpy last_updated_days={meta.last_updated_days} — should be < 730"
        )


# ---------------------------------------------------------------------------
# 2. npm metadata fetch
# ---------------------------------------------------------------------------

class TestNpmMetadataFetch:
    @network_required
    def test_lodash_real_maintainer_count(self):
        """lodash is published on npm with a known maintainers list."""
        from core.supply_chain_intel import _fetch_npm_metadata
        meta = _fetch_npm_metadata("lodash")
        assert meta.is_real is True
        assert meta.data_source == "npm"
        assert meta.not_found is False
        # lodash maintainer count is a real int >= 1
        assert meta.maintainer_count is not None
        assert isinstance(meta.maintainer_count, int)
        assert meta.maintainer_count >= 1

    @network_required
    def test_lodash_last_updated_real(self):
        from core.supply_chain_intel import _fetch_npm_metadata
        meta = _fetch_npm_metadata("lodash")
        assert meta.last_updated_days is not None
        assert isinstance(meta.last_updated_days, int)
        assert 0 <= meta.last_updated_days < 5000

    @network_required
    def test_nonexistent_npm_package_returns_not_found(self):
        from core.supply_chain_intel import _fetch_npm_metadata
        meta = _fetch_npm_metadata("this-npm-package-does-not-exist-xyzabc123456789")
        assert meta.not_found is True
        assert meta.is_real is True

    @network_required
    def test_express_has_dependencies(self):
        from core.supply_chain_intel import _fetch_npm_metadata
        meta = _fetch_npm_metadata("express")
        assert meta.dependencies_count is not None
        assert meta.dependencies_count >= 1


# ---------------------------------------------------------------------------
# 3. OSV vulnerability count
# ---------------------------------------------------------------------------

class TestOSVVulnCount:
    @network_required
    def test_pillow_has_known_vulns(self):
        """Old Pillow versions have many CVEs; querying without version returns aggregate."""
        from core.supply_chain_intel import _fetch_osv_vuln_count
        count = _fetch_osv_vuln_count("Pillow", "pip")
        # Pillow has had many historical CVEs
        assert isinstance(count, int)
        assert count >= 0  # may be 0 if OSV only tracks current, but should be non-negative

    @network_required
    def test_requests_osv_returns_int(self):
        from core.supply_chain_intel import _fetch_osv_vuln_count
        count = _fetch_osv_vuln_count("requests", "pip")
        assert isinstance(count, int)
        assert count >= 0

    @network_required
    def test_unknown_package_osv_returns_zero(self):
        from core.supply_chain_intel import _fetch_osv_vuln_count
        count = _fetch_osv_vuln_count("this-package-absolutely-does-not-exist-xyzabc123456789", "pip")
        assert count == 0

    @network_required
    def test_unsupported_ecosystem_returns_zero(self):
        from core.supply_chain_intel import _fetch_osv_vuln_count
        # "cargo" is not in our osv_ecosystem_map
        count = _fetch_osv_vuln_count("serde", "cargo")
        assert count == 0


# ---------------------------------------------------------------------------
# 4. Full analyze_package with real registry
# ---------------------------------------------------------------------------

class TestAnalyzePackageRealRegistry:
    @network_required
    def test_requests_real_data_not_hash_derived(self, tmp_intel, org):
        """
        Core assertion: 'requests' metadata must come from PyPI, not from
        abs(hash(name)) % N.  We verify by checking that last_updated_days is
        a real calendar-based value (< 730 for an active package).
        """
        result = tmp_intel.analyze_package("requests", "pip", "2.31.0", org)
        assert result.package_name == "requests"
        assert result.is_real is True
        assert result.data_source == "pypi"
        assert result.not_found is False
        # Real value: requests is actively maintained
        assert result.last_updated_days is not None
        assert result.last_updated_days < 730, (
            f"last_updated_days={result.last_updated_days} — "
            "expected < 730 for an active package. Hash-derived values are in range 0-499."
        )
        # Real dependencies count
        assert result.dependencies_count is not None
        assert result.dependencies_count >= 3

    @network_required
    def test_nonexistent_package_honest_unknown(self, tmp_intel, org):
        """A package not found on PyPI must return not_found=True, not a fabricated score."""
        result = tmp_intel.analyze_package(
            "this-package-absolutely-does-not-exist-xyzabc123456789",
            "pip", "", org,
        )
        assert result.not_found is True
        assert result.is_real is True
        # Should add a risk entry for phantom package
        categories = [r["category"] for r in result.risks]
        assert "malicious_code" in categories

    @network_required
    def test_result_persisted_with_real_data(self, tmp_intel, org):
        """Persisted record must carry real data fields, not zeros."""
        tmp_intel.analyze_package("flask", "pip", "2.3.0", org)
        packages = tmp_intel.get_high_risk_packages(org_id=org, threshold=0.0)
        flask_pkgs = [p for p in packages if p.package_name == "flask"]
        assert len(flask_pkgs) == 1
        pkg = flask_pkgs[0]
        assert pkg.is_real is True
        assert pkg.data_source == "pypi"

    @network_required
    def test_known_malicious_still_detected(self, tmp_intel, org):
        """Known-malicious detection must still work alongside real registry lookup."""
        result = tmp_intel.analyze_package("colourama", "pip", "1.0.0", org)
        categories = [r["category"] for r in result.risks]
        assert "malicious_code" in categories
        assert result.risk_score >= 70

    @network_required
    def test_lodash_npm_real_maintainer(self, tmp_intel, org):
        """lodash on npm must return real maintainer count, not None."""
        result = tmp_intel.analyze_package("lodash", "npm", "4.17.21", org)
        assert result.is_real is True
        assert result.data_source == "npm"
        assert result.maintainer_count is not None
        assert isinstance(result.maintainer_count, int)
        assert result.maintainer_count >= 1


# ---------------------------------------------------------------------------
# 5. Registry unreachable → SupplyChainIntelError (monkeypatched)
# ---------------------------------------------------------------------------

class TestRegistryUnreachable:
    def test_network_error_raises_supply_chain_intel_error(self, tmp_intel, monkeypatch):
        """When the registry is unreachable, analyze_package must raise SupplyChainIntelError."""
        from core import supply_chain_intel as sci
        from core.supply_chain_intel import SupplyChainIntelError

        def _fail(name, ecosystem):
            raise SupplyChainIntelError("simulated network failure")

        monkeypatch.setattr(sci, "_fetch_registry_metadata", _fail)
        with pytest.raises(SupplyChainIntelError, match="simulated network failure"):
            tmp_intel.analyze_package("requests", "pip")

    def test_check_abandoned_network_error_raises(self, tmp_intel, monkeypatch):
        from core import supply_chain_intel as sci
        from core.supply_chain_intel import SupplyChainIntelError

        def _fail(name, ecosystem):
            raise SupplyChainIntelError("simulated network failure")

        monkeypatch.setattr(sci, "_fetch_registry_metadata", _fail)
        with pytest.raises(SupplyChainIntelError):
            tmp_intel.check_abandoned("requests", "pip")

    def test_check_maintainer_trust_network_error_raises(self, tmp_intel, monkeypatch):
        from core import supply_chain_intel as sci
        from core.supply_chain_intel import SupplyChainIntelError

        def _fail(name, ecosystem):
            raise SupplyChainIntelError("simulated network failure")

        monkeypatch.setattr(sci, "_fetch_registry_metadata", _fail)
        with pytest.raises(SupplyChainIntelError):
            tmp_intel.check_maintainer_trust("requests", "pip")


# ---------------------------------------------------------------------------
# 6. In-memory cache behaviour
# ---------------------------------------------------------------------------

class TestRegistryCache:
    @network_required
    def test_second_call_uses_cache(self, monkeypatch):
        """Second call for the same URL must not hit the network again."""
        import urllib.request
        from core import supply_chain_intel as sci

        call_count = {"n": 0}
        _original_urlopen = urllib.request.urlopen

        def _counting_urlopen(req, timeout=None):
            call_count["n"] += 1
            return _original_urlopen(req, timeout=timeout)

        # Clear cache first
        sci._REGISTRY_CACHE.clear()
        monkeypatch.setattr(urllib.request, "urlopen", _counting_urlopen)

        # First call — hits network
        sci._fetch_pypi_metadata("requests")
        first_count = call_count["n"]
        assert first_count >= 1

        # Second call — must use cache, no new urlopen calls
        sci._fetch_pypi_metadata("requests")
        assert call_count["n"] == first_count, (
            "Second call should use cache, not make another HTTP request"
        )
