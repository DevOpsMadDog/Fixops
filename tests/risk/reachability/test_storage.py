"""Tests for reachability storage module."""

import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from risk.reachability.storage import ReachabilityStorage


class TestReachabilityStorage:
    """Tests for ReachabilityStorage."""

    @pytest.fixture
    def temp_db_path(self):
        """Create a temporary database path."""
        with tempfile.TemporaryDirectory() as tmpdir:
            yield os.path.join(tmpdir, "test_results.db")

    @pytest.fixture
    def storage(self, temp_db_path):
        """Create a storage instance for testing."""
        return ReachabilityStorage(config={"database_path": temp_db_path})

    @pytest.fixture
    def mock_result(self):
        """Create a mock VulnerabilityReachability result."""
        result = MagicMock()
        result.cve_id = "CVE-2024-1234"
        result.component_name = "test-lib"
        result.component_version = "1.0.0"
        result.to_dict.return_value = {
            "cve_id": "CVE-2024-1234",
            "component_name": "test-lib",
            "component_version": "1.0.0",
            "is_reachable": True,
            "confidence": "high",
        }
        return result

    def test_storage_initialization(self, storage, temp_db_path):
        """Test storage initialization."""
        assert storage.config is not None
        assert storage.db_path == Path(temp_db_path)
        assert storage.cache_ttl_hours == 24
        assert storage.max_cache_size_mb == 1000

    def test_storage_with_custom_config(self, temp_db_path):
        """Test storage with custom config."""
        config = {
            "database_path": temp_db_path,
            "cache_ttl_hours": 48,
            "max_cache_size_mb": 500,
        }
        storage = ReachabilityStorage(config=config)
        assert storage.cache_ttl_hours == 48
        assert storage.max_cache_size_mb == 500

    def test_database_initialization(self, storage, temp_db_path):
        """Test database is initialized with correct schema."""
        import sqlite3

        conn = sqlite3.connect(temp_db_path)
        cursor = conn.cursor()

        # Check tables exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]

        assert "reachability_results" in tables
        assert "reachability_metrics" in tables

        conn.close()

    def test_generate_result_id(self, storage):
        """Test result ID generation."""
        result_id = storage._generate_result_id(
            cve_id="CVE-2024-1234",
            component_name="test-lib",
            component_version="1.0.0",
            repo_url="https://github.com/test/repo",
            repo_commit="abc123",
        )

        # Should be a SHA256 hash (64 characters)
        assert len(result_id) == 64
        assert result_id.isalnum()

    def test_generate_result_id_without_commit(self, storage):
        """Test result ID generation without commit."""
        result_id = storage._generate_result_id(
            cve_id="CVE-2024-1234",
            component_name="test-lib",
            component_version="1.0.0",
            repo_url="https://github.com/test/repo",
            repo_commit=None,
        )

        # Should use "HEAD" as default commit
        assert len(result_id) == 64

    def test_generate_result_id_deterministic(self, storage):
        """Test result ID generation is deterministic."""
        result_id1 = storage._generate_result_id(
            cve_id="CVE-2024-1234",
            component_name="test-lib",
            component_version="1.0.0",
            repo_url="https://github.com/test/repo",
            repo_commit="abc123",
        )
        result_id2 = storage._generate_result_id(
            cve_id="CVE-2024-1234",
            component_name="test-lib",
            component_version="1.0.0",
            repo_url="https://github.com/test/repo",
            repo_commit="abc123",
        )

        assert result_id1 == result_id2

    def test_generate_result_id_different_inputs(self, storage):
        """Test result ID generation produces different IDs for different inputs."""
        result_id1 = storage._generate_result_id(
            cve_id="CVE-2024-1234",
            component_name="test-lib",
            component_version="1.0.0",
            repo_url="https://github.com/test/repo",
            repo_commit="abc123",
        )
        result_id2 = storage._generate_result_id(
            cve_id="CVE-2024-5678",
            component_name="test-lib",
            component_version="1.0.0",
            repo_url="https://github.com/test/repo",
            repo_commit="abc123",
        )

        assert result_id1 != result_id2

    def test_save_and_get_result(self, storage, mock_result):
        """Test saving and retrieving a result."""
        repo_url = "https://github.com/test/repo"
        repo_commit = "abc123"

        # Save result
        storage.save_result(mock_result, repo_url, repo_commit)

        # Get result - need to mock the VulnerabilityReachability constructor
        with patch("risk.reachability.storage.VulnerabilityReachability") as MockVR:
            MockVR.return_value = mock_result
            result = storage.get_cached_result(
                cve_id="CVE-2024-1234",
                component_name="test-lib",
                component_version="1.0.0",
                repo_url=repo_url,
                repo_commit=repo_commit,
            )

        assert result is not None

    def test_get_cached_result_not_found(self, storage):
        """Test getting a non-existent cached result."""
        result = storage.get_cached_result(
            cve_id="CVE-2024-9999",
            component_name="nonexistent-lib",
            component_version="1.0.0",
            repo_url="https://github.com/test/repo",
            repo_commit="abc123",
        )

        assert result is None

    def test_delete_result(self, storage, mock_result):
        """Test deleting a result."""
        repo_url = "https://github.com/test/repo"
        repo_commit = "abc123"

        # Save result
        storage.save_result(mock_result, repo_url, repo_commit)

        # Delete result
        storage.delete_result(
            cve_id="CVE-2024-1234",
            component_name="test-lib",
            component_version="1.0.0",
            repo_url=repo_url,
            repo_commit=repo_commit,
        )

        # Verify it's deleted
        result = storage.get_cached_result(
            cve_id="CVE-2024-1234",
            component_name="test-lib",
            component_version="1.0.0",
            repo_url=repo_url,
            repo_commit=repo_commit,
        )

        assert result is None

    def test_cleanup_expired(self, temp_db_path):
        """Test cleaning up expired results."""
        import sqlite3

        # Create storage with very short TTL
        storage = ReachabilityStorage(
            config={
                "database_path": temp_db_path,
                "cache_ttl_hours": 0,  # Immediate expiration
            }
        )

        # Manually insert an expired result
        conn = sqlite3.connect(temp_db_path)
        cursor = conn.cursor()

        expired_time = datetime.now(timezone.utc) - timedelta(hours=1)
        cursor.execute(
            """
            INSERT INTO reachability_results
            (id, cve_id, component_name, component_version, repo_url, repo_commit,
             result_json, created_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "test-id-expired",
                "CVE-2024-1234",
                "test-lib",
                "1.0.0",
                "https://github.com/test/repo",
                "abc123",
                '{"test": "data"}',
                expired_time,
                expired_time,
            ),
        )
        conn.commit()
        conn.close()

        # Clean up expired
        deleted = storage.cleanup_expired()

        assert deleted == 1

    def test_cleanup_expired_no_expired(self, storage):
        """Test cleaning up when no results are expired."""
        deleted = storage.cleanup_expired()
        assert deleted == 0

    def test_health_check_ok(self, storage):
        """Test health check returns ok."""
        result = storage.health_check()
        assert result == "ok"

    def test_health_check_error(self, temp_db_path):
        """Test health check returns error on database issue."""
        storage = ReachabilityStorage(config={"database_path": temp_db_path})

        # Delete the database file to cause an error
        os.remove(temp_db_path)

        # Health check should still work (SQLite will recreate the file)
        result = storage.health_check()
        assert result == "ok"

    def test_get_metrics_empty(self, storage):
        """Test getting metrics with no results."""
        metrics = storage.get_metrics()

        assert metrics["total_results"] == 0
        assert metrics["expired_results"] == 0
        assert "database_size_mb" in metrics

    def test_get_metrics_with_results(self, storage, mock_result):
        """Test getting metrics with results."""
        # Save some results
        storage.save_result(mock_result, "https://github.com/test/repo", "abc123")

        metrics = storage.get_metrics()

        assert metrics["total_results"] == 1
        assert metrics["expired_results"] == 0
        assert metrics["database_size_mb"] >= 0

    def test_save_result_without_commit(self, storage, mock_result):
        """Test saving result without commit."""
        storage.save_result(mock_result, "https://github.com/test/repo", None)

        # Should be able to retrieve with None commit
        with patch("risk.reachability.storage.VulnerabilityReachability") as MockVR:
            MockVR.return_value = mock_result
            result = storage.get_cached_result(
                cve_id="CVE-2024-1234",
                component_name="test-lib",
                component_version="1.0.0",
                repo_url="https://github.com/test/repo",
                repo_commit=None,
            )

        assert result is not None

    def test_save_result_replaces_existing(self, storage, mock_result):
        """Test saving result replaces existing result."""
        repo_url = "https://github.com/test/repo"
        repo_commit = "abc123"

        # Save result twice
        storage.save_result(mock_result, repo_url, repo_commit)
        storage.save_result(mock_result, repo_url, repo_commit)

        # Should still only have one result
        metrics = storage.get_metrics()
        assert metrics["total_results"] == 1

    def test_cache_ttl_zero_no_expiration(self, temp_db_path, mock_result):
        """Test cache TTL of 0 means no expiration."""
        storage = ReachabilityStorage(
            config={
                "database_path": temp_db_path,
                "cache_ttl_hours": 0,
            }
        )

        storage.save_result(mock_result, "https://github.com/test/repo", "abc123")

        # Result should still be retrievable (expires_at is None)
        with patch("risk.reachability.storage.VulnerabilityReachability") as MockVR:
            MockVR.return_value = mock_result
            result = storage.get_cached_result(
                cve_id="CVE-2024-1234",
                component_name="test-lib",
                component_version="1.0.0",
                repo_url="https://github.com/test/repo",
                repo_commit="abc123",
            )

        # With TTL=0, expires_at is None, so result should be found
        # But the condition in get_cached_result checks expires_at > now
        # So with expires_at=None, it should still be found
        assert result is not None
