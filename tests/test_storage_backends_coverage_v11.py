"""Comprehensive coverage tests for core.storage_backends — v11 swarm coverage push.

Targets: RetentionMode, StorageError, RetentionViolationError, ObjectNotFoundError,
         ConfigurationError, RetentionPolicy, StorageMetadata, LocalFileBackend.
"""

import io
import os
import sys
import tempfile

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "suite-core"))

from core.storage_backends import (
    ConfigurationError,
    ObjectNotFoundError,
    RetentionMode,
    RetentionPolicy,
    RetentionViolationError,
    StorageError,
    StorageMetadata,
)


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------


class TestExceptions:
    def test_storage_error_is_exception(self):
        with pytest.raises(StorageError):
            raise StorageError("test error")

    def test_retention_violation_is_storage_error(self):
        with pytest.raises(StorageError):
            raise RetentionViolationError("cannot delete")

    def test_object_not_found_is_storage_error(self):
        with pytest.raises(StorageError):
            raise ObjectNotFoundError("key-123")

    def test_configuration_error_is_storage_error(self):
        with pytest.raises(StorageError):
            raise ConfigurationError("bad config")


# ---------------------------------------------------------------------------
# RetentionMode
# ---------------------------------------------------------------------------


class TestRetentionMode:
    def test_governance(self):
        assert RetentionMode.GOVERNANCE.value == "governance"

    def test_compliance(self):
        assert RetentionMode.COMPLIANCE.value == "compliance"


# ---------------------------------------------------------------------------
# RetentionPolicy
# ---------------------------------------------------------------------------


class TestRetentionPolicy:
    def test_defaults(self):
        policy = RetentionPolicy()
        assert policy.mode == RetentionMode.GOVERNANCE
        assert policy.retain_until_days == 2555
        assert policy.legal_hold is False

    def test_retain_until_date(self):
        policy = RetentionPolicy(retain_until_days=30)
        date = policy.retain_until_date()
        assert date is not None

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
            "retain_until_days": 90,
            "legal_hold": True,
        }
        policy = RetentionPolicy.from_dict(data)
        assert policy.mode == RetentionMode.COMPLIANCE
        assert policy.retain_until_days == 90
        assert policy.legal_hold is True

    def test_from_dict_defaults(self):
        policy = RetentionPolicy.from_dict({})
        assert policy.mode == RetentionMode.GOVERNANCE
        assert policy.retain_until_days == 2555

    def test_from_env(self):
        with pytest.MonkeyPatch.context() as mp:
            mp.setenv("FIXOPS_RETENTION_MODE", "compliance")
            mp.setenv("FIXOPS_RETENTION_DAYS", "180")
            mp.setenv("FIXOPS_LEGAL_HOLD", "true")
            policy = RetentionPolicy.from_env()
            assert policy.mode == RetentionMode.COMPLIANCE
            assert policy.retain_until_days == 180
            assert policy.legal_hold is True

    def test_from_env_defaults(self):
        with pytest.MonkeyPatch.context() as mp:
            mp.delenv("FIXOPS_RETENTION_MODE", raising=False)
            mp.delenv("FIXOPS_RETENTION_DAYS", raising=False)
            mp.delenv("FIXOPS_LEGAL_HOLD", raising=False)
            policy = RetentionPolicy.from_env()
            assert policy.mode == RetentionMode.GOVERNANCE


# ---------------------------------------------------------------------------
# StorageMetadata
# ---------------------------------------------------------------------------


class TestStorageMetadata:
    def test_basic(self):
        meta = StorageMetadata(
            object_id="obj-001",
            path="/evidence/report.json",
            size_bytes=1024,
            sha256="abc123",
        )
        assert meta.object_id == "obj-001"
        assert meta.content_type == "application/octet-stream"

    def test_to_dict(self):
        meta = StorageMetadata(
            object_id="obj-002",
            path="/evidence/scan.sarif",
            size_bytes=2048,
            sha256="def456",
            content_type="application/json",
            custom_metadata={"scanner": "trivy"},
        )
        d = meta.to_dict()
        assert d["object_id"] == "obj-002"
        assert d["sha256"] == "def456"
        assert d["custom_metadata"]["scanner"] == "trivy"
        assert "created_at" in d

    def test_to_dict_with_retention(self):
        policy = RetentionPolicy(retain_until_days=90)
        meta = StorageMetadata(
            object_id="obj-003",
            path="/evidence/bundle.zip",
            size_bytes=4096,
            sha256="ghi789",
            retention_policy=policy,
        )
        d = meta.to_dict()
        assert "retention_policy" in d
        assert d["retention_policy"]["retain_until_days"] == 90

    def test_to_dict_without_retention(self):
        meta = StorageMetadata(
            object_id="obj-004",
            path="/tmp/test.txt",
            size_bytes=100,
            sha256="xyz",
        )
        d = meta.to_dict()
        assert "retention_policy" not in d


# ---------------------------------------------------------------------------
# LocalFileBackend
# ---------------------------------------------------------------------------


class TestLocalFileBackend:
    def test_put_and_get(self):
        from core.storage_backends import LocalFileBackend
        with tempfile.TemporaryDirectory() as tmp:
            backend = LocalFileBackend(base_path=tmp)
            data = b"hello world evidence"
            meta = backend.put("evidence/test.txt", data)
            assert meta.object_id is not None
            assert meta.size_bytes == len(data)
            # Retrieve
            retrieved = backend.get("evidence/test.txt")
            assert retrieved == data

    def test_exists(self):
        from core.storage_backends import LocalFileBackend
        with tempfile.TemporaryDirectory() as tmp:
            backend = LocalFileBackend(base_path=tmp)
            assert backend.exists("nonexistent.txt") is False
            backend.put("exists.txt", b"data")
            assert backend.exists("exists.txt") is True

    def test_get_metadata(self):
        from core.storage_backends import LocalFileBackend
        with tempfile.TemporaryDirectory() as tmp:
            backend = LocalFileBackend(base_path=tmp)
            backend.put("meta-test.json", b'{"key": "value"}', content_type="application/json")
            meta = backend.get_metadata("meta-test.json")
            assert meta is not None
            assert meta.size_bytes == len(b'{"key": "value"}')

    def test_delete(self):
        from core.storage_backends import LocalFileBackend
        with tempfile.TemporaryDirectory() as tmp:
            backend = LocalFileBackend(base_path=tmp)
            backend.put("to-delete.txt", b"data")
            assert backend.exists("to-delete.txt") is True
            result = backend.delete("to-delete.txt")
            assert result is True
            assert backend.exists("to-delete.txt") is False

    def test_delete_nonexistent(self):
        from core.storage_backends import LocalFileBackend
        with tempfile.TemporaryDirectory() as tmp:
            backend = LocalFileBackend(base_path=tmp)
            result = backend.delete("nonexistent.txt")
            assert result is False

    def test_list_objects(self):
        from core.storage_backends import LocalFileBackend
        with tempfile.TemporaryDirectory() as tmp:
            backend = LocalFileBackend(base_path=tmp)
            backend.put("dir/a.txt", b"aaa")
            backend.put("dir/b.txt", b"bbb")
            backend.put("other/c.txt", b"ccc")
            objects = backend.list_objects(prefix="dir/")
            assert len(objects) >= 2

    def test_put_with_retention(self):
        from core.storage_backends import LocalFileBackend
        with tempfile.TemporaryDirectory() as tmp:
            backend = LocalFileBackend(base_path=tmp)
            policy = RetentionPolicy(retain_until_days=30)
            meta = backend.put(
                "retained.txt", b"important", retention_policy=policy
            )
            assert meta is not None

    def test_put_with_metadata(self):
        from core.storage_backends import LocalFileBackend
        with tempfile.TemporaryDirectory() as tmp:
            backend = LocalFileBackend(base_path=tmp)
            meta = backend.put(
                "custom.txt", b"data",
                metadata={"source": "trivy", "app_id": "APP-001"},
            )
            assert meta is not None

    def test_get_not_found_raises(self):
        from core.storage_backends import LocalFileBackend
        with tempfile.TemporaryDirectory() as tmp:
            backend = LocalFileBackend(base_path=tmp)
            with pytest.raises((ObjectNotFoundError, FileNotFoundError, Exception)):
                backend.get("does-not-exist.txt")

    def test_put_with_file_like(self):
        from core.storage_backends import LocalFileBackend
        with tempfile.TemporaryDirectory() as tmp:
            backend = LocalFileBackend(base_path=tmp)
            file_obj = io.BytesIO(b"file-like data")
            meta = backend.put("filelike.txt", file_obj)
            assert meta.size_bytes > 0
