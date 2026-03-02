"""
Comprehensive unit tests for suite-core/core/storage_backends.py.

Covers:
  - RetentionMode enum
  - StorageError, RetentionViolationError, ObjectNotFoundError, ConfigurationError
  - RetentionPolicy: defaults, to_dict, from_dict, from_env, retain_until_date
  - StorageMetadata: construction, to_dict
  - StorageBackend: compute_sha256 (via concrete implementation)
  - LocalFileBackend: put, get, get_metadata, exists, delete, list_objects,
    set_legal_hold, path traversal protection, retention enforcement,
    WORM simulation, metadata persistence
  - S3ObjectLockBackend: init, configuration error, bucket validation skip
  - AzureImmutableBlobBackend: init, configuration error (if present)
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone

import pytest

from core.storage_backends import (
    RetentionMode,
    StorageError,
    RetentionViolationError,
    ObjectNotFoundError,
    ConfigurationError,
    RetentionPolicy,
    StorageMetadata,
    LocalFileBackend,
    S3ObjectLockBackend,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def storage(tmp_path):
    return LocalFileBackend(tmp_path)


@pytest.fixture
def storage_with_retention(tmp_path):
    policy = RetentionPolicy(
        mode=RetentionMode.GOVERNANCE,
        retain_until_days=365,
        legal_hold=False,
    )
    return LocalFileBackend(tmp_path, default_retention=policy)


# ===========================================================================
# RetentionMode
# ===========================================================================


class TestRetentionMode:
    def test_governance_value(self):
        assert RetentionMode.GOVERNANCE.value == "governance"

    def test_compliance_value(self):
        assert RetentionMode.COMPLIANCE.value == "compliance"


# ===========================================================================
# Exceptions
# ===========================================================================


class TestExceptions:
    def test_storage_error_hierarchy(self):
        assert issubclass(RetentionViolationError, StorageError)
        assert issubclass(ObjectNotFoundError, StorageError)
        assert issubclass(ConfigurationError, StorageError)

    def test_storage_error_message(self):
        err = StorageError("Something failed")
        assert str(err) == "Something failed"


# ===========================================================================
# RetentionPolicy
# ===========================================================================


class TestRetentionPolicy:
    def test_defaults(self):
        policy = RetentionPolicy()
        assert policy.mode == RetentionMode.GOVERNANCE
        assert policy.retain_until_days == 2555
        assert policy.legal_hold is False

    def test_retain_until_date(self):
        policy = RetentionPolicy(retain_until_days=30)
        target = policy.retain_until_date()
        now = datetime.now(timezone.utc)
        assert target > now
        assert (target - now).days >= 29
        assert (target - now).days <= 31

    def test_to_dict(self):
        policy = RetentionPolicy(
            mode=RetentionMode.COMPLIANCE,
            retain_until_days=365,
            legal_hold=True,
        )
        d = policy.to_dict()
        assert d["mode"] == "compliance"
        assert d["retain_until_days"] == 365
        assert d["legal_hold"] is True
        assert "retain_until_date" in d

    def test_from_dict(self):
        data = {
            "mode": "compliance",
            "retain_until_days": 180,
            "legal_hold": True,
        }
        policy = RetentionPolicy.from_dict(data)
        assert policy.mode == RetentionMode.COMPLIANCE
        assert policy.retain_until_days == 180
        assert policy.legal_hold is True

    def test_from_dict_defaults(self):
        policy = RetentionPolicy.from_dict({})
        assert policy.mode == RetentionMode.GOVERNANCE
        assert policy.retain_until_days == 2555
        assert policy.legal_hold is False

    def test_from_env_defaults(self, monkeypatch):
        monkeypatch.delenv("FIXOPS_RETENTION_MODE", raising=False)
        monkeypatch.delenv("FIXOPS_RETENTION_DAYS", raising=False)
        monkeypatch.delenv("FIXOPS_LEGAL_HOLD", raising=False)
        policy = RetentionPolicy.from_env()
        assert policy.mode == RetentionMode.GOVERNANCE
        assert policy.retain_until_days == 2555
        assert policy.legal_hold is False

    def test_from_env_compliance(self, monkeypatch):
        monkeypatch.setenv("FIXOPS_RETENTION_MODE", "compliance")
        monkeypatch.setenv("FIXOPS_RETENTION_DAYS", "730")
        monkeypatch.setenv("FIXOPS_LEGAL_HOLD", "true")
        policy = RetentionPolicy.from_env()
        assert policy.mode == RetentionMode.COMPLIANCE
        assert policy.retain_until_days == 730
        assert policy.legal_hold is True

    def test_from_env_legal_hold_variants(self, monkeypatch):
        for val in ("true", "1", "yes"):
            monkeypatch.setenv("FIXOPS_LEGAL_HOLD", val)
            policy = RetentionPolicy.from_env()
            assert policy.legal_hold is True, f"Failed for value: {val}"


# ===========================================================================
# StorageMetadata
# ===========================================================================


class TestStorageMetadata:
    def test_construction(self):
        meta = StorageMetadata(
            object_id="obj-1",
            path="/data/test.bin",
            size_bytes=1024,
            sha256="abc123",
        )
        assert meta.object_id == "obj-1"
        assert meta.content_type == "application/octet-stream"

    def test_to_dict_without_retention(self):
        meta = StorageMetadata(
            object_id="obj-1",
            path="/data/test.bin",
            size_bytes=512,
            sha256="def456",
        )
        d = meta.to_dict()
        assert d["object_id"] == "obj-1"
        assert d["size_bytes"] == 512
        assert "retention_policy" not in d

    def test_to_dict_with_retention(self):
        policy = RetentionPolicy(mode=RetentionMode.COMPLIANCE)
        meta = StorageMetadata(
            object_id="obj-2",
            path="/data/test2.bin",
            size_bytes=256,
            sha256="ghi789",
            retention_policy=policy,
        )
        d = meta.to_dict()
        assert "retention_policy" in d
        assert d["retention_policy"]["mode"] == "compliance"

    def test_custom_metadata(self):
        meta = StorageMetadata(
            object_id="obj-3",
            path="/p",
            size_bytes=0,
            sha256="0",
            custom_metadata={"source": "scanner", "version": "1.0"},
        )
        d = meta.to_dict()
        assert d["custom_metadata"]["source"] == "scanner"


# ===========================================================================
# LocalFileBackend: basic operations
# ===========================================================================


class TestLocalFileBackendBasic:
    def test_backend_type(self, storage):
        assert storage.backend_type == "local"

    def test_put_and_get(self, storage):
        data = b"hello world"
        meta = storage.put("test/file.bin", data)
        assert meta.size_bytes == len(data)
        assert meta.sha256 == hashlib.sha256(data).hexdigest()
        retrieved = storage.get("test/file.bin")
        assert retrieved == data

    def test_put_with_file_like_object(self, storage):
        import io
        data = b"file content"
        buf = io.BytesIO(data)
        meta = storage.put("test/stream.bin", buf)
        assert meta.size_bytes == len(data)

    def test_put_with_content_type(self, storage):
        meta = storage.put(
            "test/report.json",
            b'{"key": "value"}',
            content_type="application/json",
        )
        assert meta.content_type == "application/json"

    def test_put_with_custom_metadata(self, storage):
        meta = storage.put(
            "test/custom.bin",
            b"data",
            metadata={"source": "unit-test"},
        )
        assert meta.custom_metadata["source"] == "unit-test"

    def test_exists_true(self, storage):
        storage.put("test/exists.bin", b"data")
        assert storage.exists("test/exists.bin") is True

    def test_exists_false(self, storage):
        assert storage.exists("nonexistent.bin") is False

    def test_get_nonexistent_raises(self, storage):
        with pytest.raises(ObjectNotFoundError):
            storage.get("nonexistent.bin")

    def test_get_metadata(self, storage):
        storage.put("test/meta.bin", b"data")
        meta = storage.get_metadata("test/meta.bin")
        assert meta.object_id is not None
        assert meta.sha256 == hashlib.sha256(b"data").hexdigest()

    def test_get_metadata_nonexistent_raises(self, storage):
        with pytest.raises(ObjectNotFoundError):
            storage.get_metadata("nonexistent.bin")

    def test_delete_existing(self, storage):
        storage.put("test/delete.bin", b"data")
        assert storage.delete("test/delete.bin") is True
        assert storage.exists("test/delete.bin") is False

    def test_delete_nonexistent(self, storage):
        assert storage.delete("nonexistent.bin") is False

    def test_list_objects_empty(self, storage):
        results = storage.list_objects()
        assert results == []

    def test_list_objects_with_items(self, storage):
        storage.put("a/file1.bin", b"data1")
        storage.put("a/file2.bin", b"data2")
        storage.put("b/file3.bin", b"data3")
        results = storage.list_objects()
        assert len(results) == 3

    def test_list_objects_with_prefix(self, storage):
        storage.put("a/file1.bin", b"data1")
        storage.put("a/file2.bin", b"data2")
        storage.put("b/file3.bin", b"data3")
        results = storage.list_objects(prefix="a/")
        assert len(results) == 2

    def test_list_objects_with_limit(self, storage):
        for i in range(5):
            storage.put(f"file{i}.bin", f"data{i}".encode())
        results = storage.list_objects(limit=3)
        assert len(results) <= 3

    def test_compute_sha256(self, storage):
        data = b"test data"
        expected = hashlib.sha256(data).hexdigest()
        assert storage.compute_sha256(data) == expected

    def test_overwrite_existing_file(self, storage):
        storage.put("test/overwrite.bin", b"original")
        meta = storage.put("test/overwrite.bin", b"updated")
        assert meta.size_bytes == len(b"updated")
        assert storage.get("test/overwrite.bin") == b"updated"


# ===========================================================================
# LocalFileBackend: path traversal protection
# ===========================================================================


class TestPathTraversalProtection:
    def test_double_dot_sanitized(self, storage):
        # ".." is replaced with "_" so traversal is prevented
        storage.put("../escape.txt", b"data")
        assert storage.exists("../escape.txt")

    def test_leading_slash_stripped(self, storage):
        meta = storage.put("/absolute/path.txt", b"data")
        assert meta is not None

    def test_path_stays_within_base(self, storage, tmp_path):
        """Verify resolved path is within base_path."""
        path = storage._object_path("sub/file.txt")
        assert str(path).startswith(str(tmp_path))


# ===========================================================================
# LocalFileBackend: retention and WORM
# ===========================================================================


class TestRetentionEnforcement:
    def test_default_retention_applied(self, storage_with_retention):
        meta = storage_with_retention.put("test/retained.bin", b"data")
        assert meta.retention_policy is not None
        assert meta.retention_policy.mode == RetentionMode.GOVERNANCE

    def test_explicit_retention(self, storage):
        policy = RetentionPolicy(
            mode=RetentionMode.COMPLIANCE,
            retain_until_days=30,
        )
        meta = storage.put("test/compliance.bin", b"data", retention_policy=policy)
        assert meta.retention_policy is not None
        assert meta.retention_policy.mode == RetentionMode.COMPLIANCE

    def test_delete_under_compliance_retention_raises(self, storage):
        policy = RetentionPolicy(
            mode=RetentionMode.COMPLIANCE,
            retain_until_days=365,
        )
        storage.put("test/locked.bin", b"data", retention_policy=policy)
        with pytest.raises(RetentionViolationError, match="COMPLIANCE"):
            storage.delete("test/locked.bin")

    def test_delete_under_legal_hold_raises(self, storage):
        policy = RetentionPolicy(
            mode=RetentionMode.GOVERNANCE,
            retain_until_days=365,
            legal_hold=True,
        )
        storage.put("test/held.bin", b"data", retention_policy=policy)
        with pytest.raises(RetentionViolationError, match="legal hold"):
            storage.delete("test/held.bin")

    def test_delete_governance_no_legal_hold_succeeds(self, storage):
        """Governance mode without legal hold allows deletion (soft WORM)."""
        policy = RetentionPolicy(
            mode=RetentionMode.GOVERNANCE,
            retain_until_days=365,
            legal_hold=False,
        )
        storage.put("test/gov.bin", b"data", retention_policy=policy)
        # Governance without legal hold allows deletion
        assert storage.delete("test/gov.bin") is True

    def test_set_legal_hold_enable(self, storage):
        storage.put("test/hold.bin", b"data")
        storage.set_legal_hold("test/hold.bin", True)
        meta = storage.get_metadata("test/hold.bin")
        assert meta.retention_policy is not None
        assert meta.retention_policy.legal_hold is True

    def test_set_legal_hold_disable(self, storage):
        policy = RetentionPolicy(legal_hold=True)
        storage.put("test/unhold.bin", b"data", retention_policy=policy)
        storage.set_legal_hold("test/unhold.bin", False)
        meta = storage.get_metadata("test/unhold.bin")
        assert meta.retention_policy.legal_hold is False

    def test_set_legal_hold_nonexistent_raises(self, storage):
        with pytest.raises(ObjectNotFoundError):
            storage.set_legal_hold("nonexistent.bin", True)

    def test_overwrite_under_retention_raises(self, storage):
        policy = RetentionPolicy(
            mode=RetentionMode.COMPLIANCE,
            retain_until_days=365,
        )
        storage.put("test/worm.bin", b"original", retention_policy=policy)
        with pytest.raises(RetentionViolationError):
            storage.put("test/worm.bin", b"overwrite", retention_policy=policy)


# ===========================================================================
# LocalFileBackend: metadata persistence
# ===========================================================================


class TestMetadataPersistence:
    def test_metadata_saved_and_loaded(self, storage):
        policy = RetentionPolicy(mode=RetentionMode.GOVERNANCE, retain_until_days=30)
        storage.put(
            "test/persist.bin",
            b"data",
            content_type="text/plain",
            retention_policy=policy,
            metadata={"tag": "test"},
        )
        meta = storage.get_metadata("test/persist.bin")
        assert meta.content_type == "text/plain"
        assert meta.retention_policy is not None
        assert meta.custom_metadata["tag"] == "test"

    def test_corrupted_metadata_returns_none(self, storage, tmp_path):
        storage.put("test/corrupt.bin", b"data")
        # Corrupt the metadata file
        meta_path = storage._metadata_path("test/corrupt.bin")
        meta_path.write_text("not valid json {{{")
        # Should return None (logged warning)
        result = storage._load_metadata("test/corrupt.bin")
        assert result is None


# ===========================================================================
# S3ObjectLockBackend: init and config
# ===========================================================================


class TestS3ObjectLockBackend:
    def test_missing_bucket_raises(self, monkeypatch):
        monkeypatch.delenv("FIXOPS_S3_BUCKET", raising=False)
        with pytest.raises(ConfigurationError, match="S3 bucket"):
            S3ObjectLockBackend()

    def test_init_with_bucket(self, monkeypatch):
        monkeypatch.setenv("FIXOPS_S3_BUCKET", "test-bucket")
        monkeypatch.setenv("FIXOPS_S3_SKIP_VALIDATION", "true")
        backend = S3ObjectLockBackend(bucket="my-bucket", skip_validation=True)
        assert backend.bucket == "my-bucket"
        assert backend.backend_type == "s3"

    def test_init_from_env(self, monkeypatch):
        monkeypatch.setenv("FIXOPS_S3_BUCKET", "env-bucket")
        monkeypatch.setenv("FIXOPS_S3_PREFIX", "evidence/")
        monkeypatch.setenv("AWS_REGION", "eu-west-1")
        monkeypatch.setenv("FIXOPS_S3_SKIP_VALIDATION", "true")
        backend = S3ObjectLockBackend(skip_validation=True)
        assert backend.bucket == "env-bucket"
        assert backend.prefix == "evidence/"
        assert backend.region == "eu-west-1"

    def test_skip_validation_flag(self, monkeypatch):
        monkeypatch.setenv("FIXOPS_S3_BUCKET", "test")
        backend = S3ObjectLockBackend(bucket="test", skip_validation=True)
        assert backend._skip_validation is True
        assert backend.validate_bucket_configuration() is True

    def test_skip_validation_from_env(self, monkeypatch):
        monkeypatch.setenv("FIXOPS_S3_BUCKET", "test")
        monkeypatch.setenv("FIXOPS_S3_SKIP_VALIDATION", "true")
        backend = S3ObjectLockBackend(bucket="test")
        assert backend._skip_validation is True

    def test_default_retention_from_env(self, monkeypatch):
        monkeypatch.setenv("FIXOPS_S3_BUCKET", "test")
        monkeypatch.setenv("FIXOPS_RETENTION_MODE", "compliance")
        monkeypatch.setenv("FIXOPS_RETENTION_DAYS", "730")
        monkeypatch.setenv("FIXOPS_S3_SKIP_VALIDATION", "true")
        backend = S3ObjectLockBackend(bucket="test", skip_validation=True)
        assert backend.default_retention.mode == RetentionMode.COMPLIANCE
        assert backend.default_retention.retain_until_days == 730

    def test_custom_endpoint_url(self, monkeypatch):
        monkeypatch.setenv("FIXOPS_S3_BUCKET", "test")
        backend = S3ObjectLockBackend(
            bucket="test",
            endpoint_url="http://localhost:4566",
            skip_validation=True,
        )
        assert backend.endpoint_url == "http://localhost:4566"


# ===========================================================================
# Edge cases
# ===========================================================================


class TestEdgeCases:
    def test_empty_data(self, storage):
        meta = storage.put("test/empty.bin", b"")
        assert meta.size_bytes == 0
        assert storage.get("test/empty.bin") == b""

    def test_large_key_name(self, storage):
        key = "a/" * 50 + "file.bin"
        meta = storage.put(key, b"data")
        assert meta is not None
        assert storage.exists(key)

    def test_special_characters_in_key(self, storage):
        key = "test/file with spaces.bin"
        storage.put(key, b"data")
        assert storage.exists(key)

    def test_nested_directories(self, storage):
        key = "deep/nested/path/to/file.bin"
        storage.put(key, b"data")
        assert storage.exists(key)
        assert storage.get(key) == b"data"

    def test_put_creates_parent_dirs(self, storage, tmp_path):
        key = "new/sub/dir/file.bin"
        storage.put(key, b"data")
        expected_path = storage._object_path(key)
        assert expected_path.exists()
