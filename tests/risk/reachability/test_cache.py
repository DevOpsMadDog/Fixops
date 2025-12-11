"""Rigorous tests for AnalysisCache functionality.

These tests verify cache storage, retrieval, TTL expiration,
and cleanup behavior with real filesystem operations.
"""

import json
from datetime import datetime, timedelta, timezone

from risk.reachability.analyzer import (
    CodePath,
    ReachabilityConfidence,
    VulnerabilityReachability,
)
from risk.reachability.cache import AnalysisCache


class TestAnalysisCacheInit:
    """Tests for AnalysisCache initialization."""

    def test_default_initialization(self):
        """Verify cache initializes with default settings."""
        cache = AnalysisCache()
        assert cache.ttl_hours == 24
        assert cache.max_size_mb == 1000
        assert cache.cache_dir.exists()

    def test_custom_cache_dir(self, tmp_path):
        """Verify cache uses custom directory."""
        custom_dir = tmp_path / "custom_cache"
        cache = AnalysisCache(cache_dir=custom_dir)
        assert cache.cache_dir == custom_dir
        assert custom_dir.exists()

    def test_custom_ttl(self, tmp_path):
        """Verify cache respects custom TTL."""
        cache = AnalysisCache(cache_dir=tmp_path, ttl_hours=48)
        assert cache.ttl_hours == 48

    def test_custom_max_size(self, tmp_path):
        """Verify cache respects custom max size."""
        cache = AnalysisCache(cache_dir=tmp_path, max_size_mb=500)
        assert cache.max_size_mb == 500


class TestCacheKey:
    """Tests for cache key generation."""

    def test_cache_key_deterministic(self, tmp_path):
        """Verify same inputs produce same cache key."""
        cache = AnalysisCache(cache_dir=tmp_path)
        key1 = cache.get_cache_key(
            "CVE-2023-12345", "lib", "1.0.0", "https://github.com/test/repo"
        )
        key2 = cache.get_cache_key(
            "CVE-2023-12345", "lib", "1.0.0", "https://github.com/test/repo"
        )
        assert key1 == key2

    def test_cache_key_different_cve(self, tmp_path):
        """Verify different CVE produces different key."""
        cache = AnalysisCache(cache_dir=tmp_path)
        key1 = cache.get_cache_key(
            "CVE-2023-12345", "lib", "1.0.0", "https://github.com/test/repo"
        )
        key2 = cache.get_cache_key(
            "CVE-2023-54321", "lib", "1.0.0", "https://github.com/test/repo"
        )
        assert key1 != key2

    def test_cache_key_different_version(self, tmp_path):
        """Verify different version produces different key."""
        cache = AnalysisCache(cache_dir=tmp_path)
        key1 = cache.get_cache_key(
            "CVE-2023-12345", "lib", "1.0.0", "https://github.com/test/repo"
        )
        key2 = cache.get_cache_key(
            "CVE-2023-12345", "lib", "2.0.0", "https://github.com/test/repo"
        )
        assert key1 != key2

    def test_cache_key_with_commit(self, tmp_path):
        """Verify commit hash affects cache key."""
        cache = AnalysisCache(cache_dir=tmp_path)
        key1 = cache.get_cache_key(
            "CVE-2023-12345", "lib", "1.0.0", "https://github.com/test/repo", "abc123"
        )
        key2 = cache.get_cache_key(
            "CVE-2023-12345", "lib", "1.0.0", "https://github.com/test/repo", "def456"
        )
        assert key1 != key2

    def test_cache_key_without_commit_uses_head(self, tmp_path):
        """Verify missing commit defaults to HEAD."""
        cache = AnalysisCache(cache_dir=tmp_path)
        key1 = cache.get_cache_key(
            "CVE-2023-12345", "lib", "1.0.0", "https://github.com/test/repo"
        )
        key2 = cache.get_cache_key(
            "CVE-2023-12345", "lib", "1.0.0", "https://github.com/test/repo", None
        )
        assert key1 == key2

    def test_cache_key_is_sha256_hex(self, tmp_path):
        """Verify cache key is valid SHA256 hex string."""
        cache = AnalysisCache(cache_dir=tmp_path)
        key = cache.get_cache_key(
            "CVE-2023-12345", "lib", "1.0.0", "https://github.com/test/repo"
        )
        assert len(key) == 64  # SHA256 produces 64 hex characters
        assert all(c in "0123456789abcdef" for c in key)


class TestCacheSetAndGet:
    """Tests for cache set and get operations."""

    def _create_test_result(self, cve_id="CVE-2023-12345"):
        """Create a test VulnerabilityReachability result."""
        return VulnerabilityReachability(
            cve_id=cve_id,
            component_name="test-lib",
            component_version="1.0.0",
            is_reachable=True,
            confidence=ReachabilityConfidence.HIGH,
            confidence_score=0.85,
            code_paths=[
                CodePath(
                    file_path="src/main.py",
                    function_name="vulnerable_func",
                    line_number=42,
                    is_invoked=True,
                    call_chain=["main", "handler", "vulnerable_func"],
                    entry_points=["main"],
                )
            ],
            call_graph_depth=3,
            data_flow_depth=2,
            analysis_method="hybrid",
            metadata={"test": True},
        )

    def test_set_and_get_result(self, tmp_path):
        """Verify result can be stored and retrieved."""
        cache = AnalysisCache(cache_dir=tmp_path)
        result = self._create_test_result()
        repo_url = "https://github.com/test/repo"

        cache.set(result, repo_url)
        retrieved = cache.get(
            result.cve_id,
            result.component_name,
            result.component_version,
            repo_url,
        )

        assert retrieved is not None
        assert retrieved.cve_id == result.cve_id
        assert retrieved.component_name == result.component_name
        assert retrieved.is_reachable == result.is_reachable

    def test_get_nonexistent_returns_none(self, tmp_path):
        """Verify get returns None for missing entry."""
        cache = AnalysisCache(cache_dir=tmp_path)
        result = cache.get(
            "CVE-2023-99999",
            "nonexistent-lib",
            "1.0.0",
            "https://github.com/test/repo",
        )
        assert result is None

    def test_set_with_commit(self, tmp_path):
        """Verify result stored with commit hash."""
        cache = AnalysisCache(cache_dir=tmp_path)
        result = self._create_test_result()
        repo_url = "https://github.com/test/repo"
        commit = "abc123def456"

        cache.set(result, repo_url, commit)
        retrieved = cache.get(
            result.cve_id,
            result.component_name,
            result.component_version,
            repo_url,
            commit,
        )

        assert retrieved is not None
        assert retrieved.cve_id == result.cve_id

    def test_different_commits_separate_cache(self, tmp_path):
        """Verify different commits have separate cache entries."""
        cache = AnalysisCache(cache_dir=tmp_path)
        result1 = self._create_test_result("CVE-2023-11111")
        result2 = self._create_test_result("CVE-2023-22222")
        repo_url = "https://github.com/test/repo"

        # Store with different commits
        cache.set(result1, repo_url, "commit1")
        cache.set(result2, repo_url, "commit2")

        # Retrieve with specific commits
        retrieved1 = cache.get(
            result1.cve_id,
            result1.component_name,
            result1.component_version,
            repo_url,
            "commit1",
        )
        retrieved2 = cache.get(
            result2.cve_id,
            result2.component_name,
            result2.component_version,
            repo_url,
            "commit2",
        )

        assert retrieved1.cve_id == "CVE-2023-11111"
        assert retrieved2.cve_id == "CVE-2023-22222"


class TestCacheTTL:
    """Tests for cache TTL (time-to-live) behavior."""

    def _create_test_result(self):
        """Create a test VulnerabilityReachability result."""
        return VulnerabilityReachability(
            cve_id="CVE-2023-12345",
            component_name="test-lib",
            component_version="1.0.0",
            is_reachable=True,
            confidence=ReachabilityConfidence.HIGH,
            confidence_score=0.85,
            code_paths=[],
            call_graph_depth=0,
            data_flow_depth=0,
            analysis_method="static",
        )

    def test_expired_entry_returns_none(self, tmp_path):
        """Verify expired cache entry returns None."""
        cache = AnalysisCache(cache_dir=tmp_path, ttl_hours=1)
        result = self._create_test_result()
        repo_url = "https://github.com/test/repo"

        # Manually create expired cache entry
        cache_key = cache.get_cache_key(
            result.cve_id,
            result.component_name,
            result.component_version,
            repo_url,
        )
        cache_file = cache.cache_dir / f"{cache_key}.json"

        # Write entry with old timestamp
        old_time = datetime.now(timezone.utc) - timedelta(hours=2)
        data = {
            "cached_at": old_time.isoformat(),
            "result": result.to_dict(),
        }
        with open(cache_file, "w") as f:
            json.dump(data, f)

        # Should return None and delete expired entry
        retrieved = cache.get(
            result.cve_id,
            result.component_name,
            result.component_version,
            repo_url,
        )
        assert retrieved is None
        assert not cache_file.exists()

    def test_valid_entry_within_ttl(self, tmp_path):
        """Verify valid cache entry within TTL is returned."""
        cache = AnalysisCache(cache_dir=tmp_path, ttl_hours=24)
        result = self._create_test_result()
        repo_url = "https://github.com/test/repo"

        cache.set(result, repo_url)
        retrieved = cache.get(
            result.cve_id,
            result.component_name,
            result.component_version,
            repo_url,
        )
        assert retrieved is not None


class TestCacheCleanup:
    """Tests for cache cleanup operations."""

    def _create_cache_entry(self, cache, cve_id, hours_ago):
        """Create a cache entry with specific age."""
        result = VulnerabilityReachability(
            cve_id=cve_id,
            component_name="test-lib",
            component_version="1.0.0",
            is_reachable=True,
            confidence=ReachabilityConfidence.HIGH,
            confidence_score=0.85,
            code_paths=[],
            call_graph_depth=0,
            data_flow_depth=0,
            analysis_method="static",
        )
        repo_url = "https://github.com/test/repo"

        cache_key = cache.get_cache_key(cve_id, "test-lib", "1.0.0", repo_url)
        cache_file = cache.cache_dir / f"{cache_key}.json"

        timestamp = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
        data = {
            "cached_at": timestamp.isoformat(),
            "result": result.to_dict(),
        }
        with open(cache_file, "w") as f:
            json.dump(data, f)

        return cache_file

    def test_clear_expired_removes_old_entries(self, tmp_path):
        """Verify clear_expired removes entries older than TTL."""
        cache = AnalysisCache(cache_dir=tmp_path, ttl_hours=24)

        # Create entries with different ages
        old_file = self._create_cache_entry(cache, "CVE-OLD", 48)
        new_file = self._create_cache_entry(cache, "CVE-NEW", 12)

        cleared = cache.clear_expired()

        assert cleared == 1
        assert not old_file.exists()
        assert new_file.exists()

    def test_clear_expired_handles_invalid_files(self, tmp_path):
        """Verify clear_expired handles corrupted cache files."""
        cache = AnalysisCache(cache_dir=tmp_path, ttl_hours=24)

        # Create invalid cache file
        invalid_file = cache.cache_dir / "invalid.json"
        with open(invalid_file, "w") as f:
            f.write("not valid json")

        cleared = cache.clear_expired()

        assert cleared == 1
        assert not invalid_file.exists()

    def test_clear_all_removes_everything(self, tmp_path):
        """Verify clear_all removes all cache entries."""
        cache = AnalysisCache(cache_dir=tmp_path)

        # Create multiple entries
        self._create_cache_entry(cache, "CVE-1", 1)
        self._create_cache_entry(cache, "CVE-2", 2)
        self._create_cache_entry(cache, "CVE-3", 3)

        cache.clear_all()

        json_files = list(cache.cache_dir.glob("*.json"))
        assert len(json_files) == 0


class TestCacheErrorHandling:
    """Tests for cache error handling."""

    def test_get_handles_corrupted_json(self, tmp_path):
        """Verify get handles corrupted JSON gracefully."""
        cache = AnalysisCache(cache_dir=tmp_path)

        # Create corrupted cache file
        cache_key = cache.get_cache_key(
            "CVE-2023-12345", "lib", "1.0.0", "https://github.com/test/repo"
        )
        cache_file = cache.cache_dir / f"{cache_key}.json"
        with open(cache_file, "w") as f:
            f.write("corrupted json content")

        result = cache.get(
            "CVE-2023-12345", "lib", "1.0.0", "https://github.com/test/repo"
        )

        assert result is None
        assert not cache_file.exists()  # Should be deleted

    def test_get_handles_missing_fields(self, tmp_path):
        """Verify get handles cache entry with missing fields."""
        cache = AnalysisCache(cache_dir=tmp_path)

        cache_key = cache.get_cache_key(
            "CVE-2023-12345", "lib", "1.0.0", "https://github.com/test/repo"
        )
        cache_file = cache.cache_dir / f"{cache_key}.json"

        # Write entry with missing required fields
        data = {"cached_at": datetime.now(timezone.utc).isoformat()}
        with open(cache_file, "w") as f:
            json.dump(data, f)

        result = cache.get(
            "CVE-2023-12345", "lib", "1.0.0", "https://github.com/test/repo"
        )

        assert result is None

    def test_set_handles_write_error(self, tmp_path):
        """Verify set handles write errors gracefully."""
        cache = AnalysisCache(cache_dir=tmp_path)
        result = VulnerabilityReachability(
            cve_id="CVE-2023-12345",
            component_name="test-lib",
            component_version="1.0.0",
            is_reachable=True,
            confidence=ReachabilityConfidence.HIGH,
            confidence_score=0.85,
            code_paths=[],
            call_graph_depth=0,
            data_flow_depth=0,
            analysis_method="static",
        )

        # Make cache dir read-only to trigger write error
        cache.cache_dir.chmod(0o444)

        try:
            # Should not raise exception
            cache.set(result, "https://github.com/test/repo")
        finally:
            # Restore permissions for cleanup
            cache.cache_dir.chmod(0o755)
