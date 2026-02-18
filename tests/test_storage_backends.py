"""Unit tests for enterprise storage backends.

Tests cover:
- LocalFileBackend: Basic CRUD operations, retention policies, legal holds
- S3ObjectLockBackend: Mocked S3 operations with Object Lock
- AzureImmutableBlobBackend: Mocked Azure operations with immutability
- Storage backend factory function
"""

import io
import os
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from core.storage_backends import (
    AzureImmutableBlobBackend,
    ConfigurationError,
    LocalFileBackend,
    ObjectNotFoundError,
    RetentionMode,
    RetentionPolicy,
    RetentionViolationError,
    S3ObjectLockBackend,
    StorageBackend,
    StorageError,
    StorageMetadata,
    create_storage_backend,
)


class TestRetentionPolicy:
    """Tests for RetentionPolicy dataclass."""

    def test_default_values(self):
        policy = RetentionPolicy()
        assert policy.mode == RetentionMode.GOVERNANCE
        assert policy.retain_until_days == 2555
        assert policy.legal_hold is False

    def test_retain_until_date(self):
        policy = RetentionPolicy(retain_until_days=30)
        expected = datetime.now(timezone.utc) + timedelta(days=30)
        actual = policy.retain_until_date()
        assert abs((actual - expected).total_seconds()) < 5

    def test_to_dict(self):
        policy = RetentionPolicy(
            mode=RetentionMode.COMPLIANCE,
            retain_until_days=365,
            legal_hold=True,
        )
        result = policy.to_dict()
        assert result["mode"] == "compliance"
        assert result["retain_until_days"] == 365
        assert result["legal_hold"] is True
        assert "retain_until_date" in result

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

    def test_from_env(self):
        with patch.dict(
            os.environ,
            {
                "FIXOPS_RETENTION_MODE": "compliance",
                "FIXOPS_RETENTION_DAYS": "90",
                "FIXOPS_LEGAL_HOLD": "true",
            },
        ):
            policy = RetentionPolicy.from_env()
            assert policy.mode == RetentionMode.COMPLIANCE
            assert policy.retain_until_days == 90
            assert policy.legal_hold is True


class TestStorageMetadata:
    """Tests for StorageMetadata dataclass."""

    def test_to_dict_without_retention(self):
        meta = StorageMetadata(
            object_id="test-id",
            path="/path/to/object",
            size_bytes=1024,
            sha256="abc123",
        )
        result = meta.to_dict()
        assert result["object_id"] == "test-id"
        assert result["path"] == "/path/to/object"
        assert result["size_bytes"] == 1024
        assert result["sha256"] == "abc123"
        assert "retention_policy" not in result

    def test_to_dict_with_retention(self):
        policy = RetentionPolicy(mode=RetentionMode.COMPLIANCE)
        meta = StorageMetadata(
            object_id="test-id",
            path="/path/to/object",
            size_bytes=1024,
            sha256="abc123",
            retention_policy=policy,
        )
        result = meta.to_dict()
        assert "retention_policy" in result
        assert result["retention_policy"]["mode"] == "compliance"


class TestLocalFileBackend:
    """Tests for LocalFileBackend."""

    @pytest.fixture
    def temp_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    @pytest.fixture
    def backend(self, temp_dir):
        return LocalFileBackend(temp_dir)

    def test_backend_type(self, backend):
        assert backend.backend_type == "local"

    def test_put_and_get(self, backend):
        data = b"test content"
        meta = backend.put("test/file.txt", data)

        assert meta.size_bytes == len(data)
        assert meta.sha256 == backend.compute_sha256(data)

        retrieved = backend.get("test/file.txt")
        assert retrieved == data

    def test_put_with_metadata(self, backend):
        data = b"test content"
        custom_meta = {"author": "test", "version": "1.0"}
        meta = backend.put(
            "test/file.txt",
            data,
            content_type="text/plain",
            metadata=custom_meta,
        )

        assert meta.content_type == "text/plain"
        assert meta.custom_metadata == custom_meta

    def test_put_with_retention_policy(self, backend):
        data = b"test content"
        policy = RetentionPolicy(retain_until_days=30)
        meta = backend.put("test/file.txt", data, retention_policy=policy)

        assert meta.retention_policy is not None
        assert meta.retention_policy.retain_until_days == 30

    def test_get_nonexistent_raises(self, backend):
        with pytest.raises(ObjectNotFoundError):
            backend.get("nonexistent/file.txt")

    def test_exists(self, backend):
        assert not backend.exists("test/file.txt")
        backend.put("test/file.txt", b"content")
        assert backend.exists("test/file.txt")

    def test_delete(self, backend):
        backend.put("test/file.txt", b"content")
        assert backend.exists("test/file.txt")

        result = backend.delete("test/file.txt")
        assert result is True
        assert not backend.exists("test/file.txt")

    def test_delete_nonexistent(self, backend):
        result = backend.delete("nonexistent/file.txt")
        assert result is False

    def test_delete_with_compliance_retention_raises(self, backend):
        policy = RetentionPolicy(
            mode=RetentionMode.COMPLIANCE,
            retain_until_days=30,
        )
        backend.put("test/file.txt", b"content", retention_policy=policy)

        with pytest.raises(RetentionViolationError):
            backend.delete("test/file.txt")

    def test_delete_with_legal_hold_raises(self, backend):
        policy = RetentionPolicy(
            mode=RetentionMode.GOVERNANCE,
            retain_until_days=30,
            legal_hold=True,
        )
        backend.put("test/file.txt", b"content", retention_policy=policy)

        with pytest.raises(RetentionViolationError):
            backend.delete("test/file.txt")

    def test_list_objects(self, backend):
        backend.put("dir1/file1.txt", b"content1")
        backend.put("dir1/file2.txt", b"content2")
        backend.put("dir2/file3.txt", b"content3")

        all_objects = backend.list_objects()
        assert len(all_objects) == 3

        dir1_objects = backend.list_objects(prefix="dir1/")
        assert len(dir1_objects) == 2

    def test_list_objects_with_limit(self, backend):
        for i in range(10):
            backend.put(f"file{i}.txt", f"content{i}".encode())

        limited = backend.list_objects(limit=5)
        assert len(limited) == 5

    def test_get_metadata(self, backend):
        data = b"test content"
        backend.put("test/file.txt", data, content_type="text/plain")

        meta = backend.get_metadata("test/file.txt")
        assert meta.size_bytes == len(data)
        assert meta.content_type == "text/plain"

    def test_get_metadata_nonexistent_raises(self, backend):
        with pytest.raises(ObjectNotFoundError):
            backend.get_metadata("nonexistent/file.txt")

    def test_set_legal_hold(self, backend):
        backend.put("test/file.txt", b"content")

        backend.set_legal_hold("test/file.txt", True)
        meta = backend.get_metadata("test/file.txt")
        assert meta.retention_policy is not None
        assert meta.retention_policy.legal_hold is True

        backend.set_legal_hold("test/file.txt", False)
        meta = backend.get_metadata("test/file.txt")
        assert meta.retention_policy.legal_hold is False

    def test_set_legal_hold_nonexistent_raises(self, backend):
        with pytest.raises(ObjectNotFoundError):
            backend.set_legal_hold("nonexistent/file.txt", True)

    def test_default_retention_policy(self, temp_dir):
        default_policy = RetentionPolicy(retain_until_days=7)
        backend = LocalFileBackend(temp_dir, default_retention=default_policy)

        meta = backend.put("test/file.txt", b"content")
        assert meta.retention_policy is not None
        assert meta.retention_policy.retain_until_days == 7

    def test_path_traversal_protection(self, backend):
        meta = backend.put("../../../etc/passwd", b"malicious")
        assert ".." not in meta.path

    def test_path_traversal_via_symlink_raises(self, temp_dir):
        """Test that symlink escape attempts raise ValueError.

        Covers lines 301-302 in storage_backends.py - the path traversal
        detection that raises ValueError when resolved path escapes base_path.
        """
        # Create a symlink inside base_path that points outside
        base_path = temp_dir / "storage"
        base_path.mkdir(parents=True, exist_ok=True)

        # Create a directory outside base_path
        outside_dir = temp_dir / "outside"
        outside_dir.mkdir(parents=True, exist_ok=True)

        # Create symlink inside base_path pointing to outside_dir
        symlink_path = base_path / "escape_link"
        try:
            symlink_path.symlink_to(outside_dir)
        except OSError:
            pytest.skip("Symlink creation not supported on this platform")

        backend = LocalFileBackend(str(base_path))

        # Attempting to access a path through the symlink should raise ValueError
        with pytest.raises(ValueError) as exc_info:
            backend._object_path("escape_link/evil_file.txt")
        assert "Path traversal detected" in str(exc_info.value)
        assert "resolves outside base_path" in str(exc_info.value)

    def test_put_with_binary_io(self, backend):
        """Test put() with a file-like object (BinaryIO) instead of bytes."""
        import io

        data = b"test content from file-like object"
        file_obj = io.BytesIO(data)
        meta = backend.put("test/file_io.txt", file_obj)

        assert meta.size_bytes == len(data)
        retrieved = backend.get("test/file_io.txt")
        assert retrieved == data

    def test_put_overwrite_under_retention_raises(self, backend):
        """Test that overwriting an object under retention raises error."""
        # First, put an object with retention policy
        policy = RetentionPolicy(
            mode=RetentionMode.COMPLIANCE,
            retain_until_days=30,
        )
        backend.put("test/retained.txt", b"original content", retention_policy=policy)

        # Try to overwrite it - should raise RetentionViolationError
        with pytest.raises(RetentionViolationError):
            backend.put("test/retained.txt", b"new content")

    def test_load_metadata_with_corrupted_file(self, backend):
        """Test that corrupted metadata file returns None."""
        # First, put a valid object
        backend.put("test/file.txt", b"content")

        # Corrupt the metadata file
        metadata_path = backend._metadata_path("test/file.txt")
        metadata_path.write_text("not valid json {{{")

        # _load_metadata should return None for corrupted files
        result = backend._load_metadata("test/file.txt")
        assert result is None


class TestS3ObjectLockBackend:
    """Tests for S3ObjectLockBackend with mocked boto3."""

    @pytest.fixture
    def mock_boto3(self):
        mock_client = MagicMock()
        with patch.dict("sys.modules", {"boto3": MagicMock()}):
            import sys

            sys.modules["boto3"].client.return_value = mock_client
            yield mock_client

    @pytest.fixture
    def backend(self, mock_boto3):
        with patch.dict(os.environ, {"FIXOPS_S3_BUCKET": "test-bucket"}):
            backend = S3ObjectLockBackend(skip_validation=True)
            backend._client = mock_boto3
            return backend

    def test_backend_type(self, backend):
        assert backend.backend_type == "s3"

    def test_missing_bucket_raises(self):
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("FIXOPS_S3_BUCKET", None)
            with pytest.raises(ConfigurationError):
                S3ObjectLockBackend()

    def test_put_calls_s3(self, backend, mock_boto3):
        data = b"test content"
        backend.put("test/file.txt", data)

        mock_boto3.put_object.assert_called_once()
        call_args = mock_boto3.put_object.call_args
        assert call_args.kwargs["Bucket"] == "test-bucket"
        assert call_args.kwargs["Key"] == "test/file.txt"
        assert call_args.kwargs["Body"] == data

    def test_put_with_retention(self, backend, mock_boto3):
        policy = RetentionPolicy(
            mode=RetentionMode.COMPLIANCE,
            retain_until_days=30,
        )
        backend.put("test/file.txt", b"content", retention_policy=policy)

        call_args = mock_boto3.put_object.call_args
        assert call_args.kwargs["ObjectLockMode"] == "COMPLIANCE"
        assert "ObjectLockRetainUntilDate" in call_args.kwargs

    def test_get_calls_s3(self, backend, mock_boto3):
        mock_body = MagicMock()
        mock_body.read.return_value = b"test content"
        mock_boto3.get_object.return_value = {"Body": mock_body}

        result = backend.get("test/file.txt")

        mock_boto3.get_object.assert_called_once()
        assert result == b"test content"

    def test_exists_returns_true(self, backend, mock_boto3):
        mock_boto3.head_object.return_value = {}
        assert backend.exists("test/file.txt") is True

    def test_exists_returns_false_on_not_found(self, backend, mock_boto3):
        class NoSuchKeyError(Exception):
            pass

        mock_boto3.exceptions = MagicMock()
        mock_boto3.exceptions.NoSuchKey = NoSuchKeyError
        mock_boto3.head_object.side_effect = NoSuchKeyError("NoSuchKey")
        assert backend.exists("test/file.txt") is False

    def test_prefix_handling(self, mock_boto3):
        with patch.dict(
            os.environ,
            {
                "FIXOPS_S3_BUCKET": "test-bucket",
                "FIXOPS_S3_PREFIX": "evidence/",
            },
        ):
            backend = S3ObjectLockBackend(skip_validation=True)
            backend._client = mock_boto3
            backend.put("test/file.txt", b"content")

            call_args = mock_boto3.put_object.call_args
            assert call_args.kwargs["Key"] == "evidence/test/file.txt"


class TestAzureImmutableBlobBackend:
    """Tests for AzureImmutableBlobBackend with mocked azure-storage-blob."""

    @pytest.fixture
    def mock_azure(self):
        with patch(
            "core.storage_backends.BlobServiceClient", create=True
        ) as mock_service:
            mock_container = MagicMock()
            mock_service.from_connection_string.return_value.get_container_client.return_value = (
                mock_container
            )
            yield mock_container

    @pytest.fixture
    def backend(self, mock_azure):
        with patch.dict(
            os.environ,
            {
                "FIXOPS_AZURE_CONTAINER": "test-container",
                "AZURE_STORAGE_CONNECTION_STRING": "DefaultEndpointsProtocol=https;AccountName=test",
            },
        ):
            with patch.object(
                AzureImmutableBlobBackend, "container_client", mock_azure
            ):
                backend = AzureImmutableBlobBackend()
                backend._container_client = mock_azure
                return backend

    def test_backend_type(self, backend):
        assert backend.backend_type == "azure"

    def test_missing_container_raises(self):
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("FIXOPS_AZURE_CONTAINER", None)
            with pytest.raises(ConfigurationError):
                AzureImmutableBlobBackend()


class TestCreateStorageBackend:
    """Tests for the storage backend factory function."""

    def test_create_local_backend(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            backend = create_storage_backend("local", base_path=tmpdir)
            assert isinstance(backend, LocalFileBackend)
            assert backend.backend_type == "local"

    def test_create_local_backend_from_env(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch.dict(
                os.environ,
                {
                    "FIXOPS_STORAGE_BACKEND": "local",
                    "FIXOPS_EVIDENCE_PATH": tmpdir,
                },
            ):
                backend = create_storage_backend()
                assert isinstance(backend, LocalFileBackend)

    def test_create_s3_backend(self):
        with patch.dict(
            os.environ,
            {"FIXOPS_S3_BUCKET": "test-bucket", "FIXOPS_S3_SKIP_VALIDATION": "true"},
        ):
            with patch.dict("sys.modules", {"boto3": MagicMock()}):
                backend = create_storage_backend("s3")
                assert isinstance(backend, S3ObjectLockBackend)

    def test_create_azure_backend(self):
        with patch.dict(
            os.environ,
            {
                "FIXOPS_AZURE_CONTAINER": "test-container",
                "AZURE_STORAGE_CONNECTION_STRING": "test-connection",
            },
        ):
            backend = create_storage_backend("azure")
            assert isinstance(backend, AzureImmutableBlobBackend)

    def test_unknown_backend_raises(self):
        with pytest.raises(ConfigurationError):
            create_storage_backend("unknown")


class TestStorageBackendInterface:
    """Tests to verify StorageBackend interface compliance."""

    def test_local_backend_implements_interface(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            backend = LocalFileBackend(tmpdir)
            assert isinstance(backend, StorageBackend)
            assert hasattr(backend, "put")
            assert hasattr(backend, "get")
            assert hasattr(backend, "get_metadata")
            assert hasattr(backend, "exists")
            assert hasattr(backend, "delete")
            assert hasattr(backend, "list_objects")
            assert hasattr(backend, "set_legal_hold")
            assert hasattr(backend, "backend_type")


class TestS3ObjectLockBackendValidation:
    """Tests for S3ObjectLockBackend validation and error handling.

    These tests cover the validation logic and error paths that are
    exercised during bucket configuration checks.
    """

    @pytest.fixture
    def mock_boto3(self):
        mock_client = MagicMock()
        with patch.dict("sys.modules", {"boto3": MagicMock()}):
            import sys

            sys.modules["boto3"].client.return_value = mock_client
            yield mock_client

    def test_skip_validation_logs_warning(self, mock_boto3):
        """Test that skip_validation=True logs a warning.

        Covers lines 519-524 in storage_backends.py.
        """
        with patch.dict(os.environ, {"FIXOPS_S3_BUCKET": "test-bucket"}):
            backend = S3ObjectLockBackend(skip_validation=True)
            backend._client = mock_boto3

            # validate_bucket_configuration should return True without calling S3
            result = backend.validate_bucket_configuration()
            assert result is True
            # S3 methods should not be called
            mock_boto3.get_bucket_versioning.assert_not_called()

    def test_versioning_not_enabled_raises(self, mock_boto3):
        """Test that missing versioning raises ConfigurationError.

        Covers lines 527-537 in storage_backends.py.
        """
        mock_boto3.get_bucket_versioning.return_value = {"Status": "Suspended"}

        with patch.dict(os.environ, {"FIXOPS_S3_BUCKET": "test-bucket"}):
            backend = S3ObjectLockBackend(skip_validation=True)
            backend._skip_validation = False  # Enable validation for this test
            backend._client = mock_boto3

            with pytest.raises(ConfigurationError) as exc_info:
                backend.validate_bucket_configuration()
            assert "versioning enabled" in str(exc_info.value).lower()

    def test_versioning_check_exception_raises(self, mock_boto3):
        """Test that versioning check exception raises ConfigurationError.

        Covers lines 541-544 in storage_backends.py.
        """
        mock_boto3.get_bucket_versioning.side_effect = Exception("Access denied")

        with patch.dict(os.environ, {"FIXOPS_S3_BUCKET": "test-bucket"}):
            backend = S3ObjectLockBackend(skip_validation=True)
            backend._skip_validation = False
            backend._client = mock_boto3

            with pytest.raises(ConfigurationError) as exc_info:
                backend.validate_bucket_configuration()
            assert "Failed to check versioning" in str(exc_info.value)

    def test_object_lock_not_enabled_raises(self, mock_boto3):
        """Test that missing Object Lock raises ConfigurationError.

        Covers lines 547-560 in storage_backends.py.
        """
        mock_boto3.get_bucket_versioning.return_value = {"Status": "Enabled"}
        mock_boto3.get_object_lock_configuration.return_value = {
            "ObjectLockConfiguration": {"ObjectLockEnabled": "Disabled"}
        }
        # Set up exceptions attribute properly
        mock_boto3.exceptions = MagicMock()
        mock_boto3.exceptions.ObjectLockConfigurationNotFoundError = type(
            "NotFound", (Exception,), {}
        )

        with patch.dict(os.environ, {"FIXOPS_S3_BUCKET": "test-bucket"}):
            backend = S3ObjectLockBackend(skip_validation=True)
            backend._skip_validation = False
            backend._client = mock_boto3

            with pytest.raises(ConfigurationError) as exc_info:
                backend.validate_bucket_configuration()
            assert "Object Lock enabled" in str(exc_info.value)

    def test_object_lock_not_found_raises(self, mock_boto3):
        """Test that ObjectLockConfigurationNotFoundError raises ConfigurationError.

        Covers lines 561-567 in storage_backends.py.
        """
        mock_boto3.get_bucket_versioning.return_value = {"Status": "Enabled"}

        # Create a mock exception class
        class ObjectLockConfigurationNotFoundError(Exception):
            pass

        mock_boto3.exceptions = MagicMock()
        mock_boto3.exceptions.ObjectLockConfigurationNotFoundError = (
            ObjectLockConfigurationNotFoundError
        )
        mock_boto3.get_object_lock_configuration.side_effect = (
            ObjectLockConfigurationNotFoundError()
        )

        with patch.dict(os.environ, {"FIXOPS_S3_BUCKET": "test-bucket"}):
            backend = S3ObjectLockBackend(skip_validation=True)
            backend._skip_validation = False
            backend._client = mock_boto3

            with pytest.raises(ConfigurationError) as exc_info:
                backend.validate_bucket_configuration()
            assert "Object Lock configured" in str(exc_info.value)

    def test_object_lock_check_exception_logs_warning(self, mock_boto3):
        """Test that Object Lock check exception logs warning and continues.

        Covers lines 570-577 in storage_backends.py.
        """
        mock_boto3.get_bucket_versioning.return_value = {"Status": "Enabled"}
        mock_boto3.get_object_lock_configuration.side_effect = Exception(
            "Not supported"
        )
        mock_boto3.exceptions = MagicMock()
        mock_boto3.exceptions.ObjectLockConfigurationNotFoundError = type(
            "NotFound", (Exception,), {}
        )

        with patch.dict(os.environ, {"FIXOPS_S3_BUCKET": "test-bucket"}):
            backend = S3ObjectLockBackend(skip_validation=True)
            backend._skip_validation = False
            backend._client = mock_boto3

            # Should succeed but with object_lock_enabled = None
            result = backend.validate_bucket_configuration()
            assert result is True
            assert backend._object_lock_enabled is None

    def test_ensure_worm_compliance_skip_validation(self, mock_boto3):
        """Test ensure_worm_compliance returns early when skip_validation=True.

        Covers lines 589-590 in storage_backends.py.
        """
        with patch.dict(os.environ, {"FIXOPS_S3_BUCKET": "test-bucket"}):
            backend = S3ObjectLockBackend(skip_validation=True)
            backend._client = mock_boto3

            # Should return without calling validate_bucket_configuration
            backend.ensure_worm_compliance()
            mock_boto3.get_bucket_versioning.assert_not_called()

    def test_ensure_worm_compliance_calls_validate(self, mock_boto3):
        """Test ensure_worm_compliance calls validate when not validated.

        Covers lines 592-593 in storage_backends.py.
        """
        mock_boto3.get_bucket_versioning.return_value = {"Status": "Enabled"}
        mock_boto3.get_object_lock_configuration.return_value = {
            "ObjectLockConfiguration": {"ObjectLockEnabled": "Enabled"}
        }
        mock_boto3.exceptions = MagicMock()
        mock_boto3.exceptions.ObjectLockConfigurationNotFoundError = type(
            "NotFound", (Exception,), {}
        )

        with patch.dict(os.environ, {"FIXOPS_S3_BUCKET": "test-bucket"}):
            backend = S3ObjectLockBackend(skip_validation=True)
            backend._skip_validation = False
            backend._client = mock_boto3

            # First call should trigger validation
            backend.ensure_worm_compliance()
            mock_boto3.get_bucket_versioning.assert_called_once()

    def test_ensure_worm_compliance_object_lock_none_raises(self, mock_boto3):
        """Test ensure_worm_compliance raises when Object Lock cannot be verified.

        Covers lines 624-629 in storage_backends.py - the fail-closed check
        when _object_lock_enabled is None after validation.
        """
        mock_boto3.get_bucket_versioning.return_value = {"Status": "Enabled"}
        # Simulate exception that leaves _object_lock_enabled as None
        mock_boto3.get_object_lock_configuration.side_effect = Exception(
            "Cannot verify"
        )
        mock_boto3.exceptions = MagicMock()
        mock_boto3.exceptions.ObjectLockConfigurationNotFoundError = type(
            "NotFound", (Exception,), {}
        )

        with patch.dict(os.environ, {"FIXOPS_S3_BUCKET": "test-bucket"}):
            backend = S3ObjectLockBackend(skip_validation=True)
            backend._skip_validation = False
            backend._client = mock_boto3
            backend._versioning_enabled = True  # Set versioning as verified
            backend._object_lock_enabled = None  # Object Lock couldn't be verified

            with pytest.raises(ConfigurationError) as exc_info:
                backend.ensure_worm_compliance()
            assert "Cannot verify Object Lock configuration" in str(exc_info.value)
            assert "fail-closed" in str(exc_info.value)

    def test_ensure_worm_compliance_versioning_none_raises(self, mock_boto3):
        """Test ensure_worm_compliance raises when versioning cannot be verified.

        Covers lines 631-636 in storage_backends.py - the fail-closed check
        when _versioning_enabled is None after validation.
        """
        # Mock validate_bucket_configuration to leave _versioning_enabled as None
        # but set _object_lock_enabled to True (simulating partial verification)
        mock_boto3.exceptions = MagicMock()
        mock_boto3.exceptions.ObjectLockConfigurationNotFoundError = type(
            "NotFound", (Exception,), {}
        )

        with patch.dict(os.environ, {"FIXOPS_S3_BUCKET": "test-bucket"}):
            backend = S3ObjectLockBackend(skip_validation=True)
            backend._skip_validation = False
            backend._client = mock_boto3
            # Simulate state after validation where Object Lock was verified
            # but versioning couldn't be verified
            backend._object_lock_enabled = True
            backend._versioning_enabled = None

            # Mock validate_bucket_configuration to do nothing (already called)
            with patch.object(backend, "validate_bucket_configuration"):
                with pytest.raises(ConfigurationError) as exc_info:
                    backend.ensure_worm_compliance()
                assert "Cannot verify versioning configuration" in str(exc_info.value)
                assert "fail-closed" in str(exc_info.value)

    def test_put_with_binary_io(self, mock_boto3):
        """Test put with BinaryIO object.

        Covers line 613 in storage_backends.py.
        """
        from io import BytesIO

        with patch.dict(os.environ, {"FIXOPS_S3_BUCKET": "test-bucket"}):
            backend = S3ObjectLockBackend(skip_validation=True)
            backend._client = mock_boto3

            data = BytesIO(b"test content")
            backend.put("test/file.txt", data)

            call_args = mock_boto3.put_object.call_args
            assert call_args.kwargs["Body"] == b"test content"

    def test_put_with_legal_hold(self, mock_boto3):
        """Test put with legal hold enabled.

        Covers line 643 in storage_backends.py.
        """
        with patch.dict(os.environ, {"FIXOPS_S3_BUCKET": "test-bucket"}):
            backend = S3ObjectLockBackend(skip_validation=True)
            backend._client = mock_boto3

            policy = RetentionPolicy(legal_hold=True)
            backend.put("test/file.txt", b"content", retention_policy=policy)

            call_args = mock_boto3.put_object.call_args
            assert call_args.kwargs["ObjectLockLegalHoldStatus"] == "ON"

    def test_put_exception_raises_storage_error(self, mock_boto3):
        """Test put raises StorageError on S3 exception.

        Covers lines 651-652 in storage_backends.py.
        """
        from core.storage_backends import StorageError

        mock_boto3.put_object.side_effect = Exception("S3 error")

        with patch.dict(os.environ, {"FIXOPS_S3_BUCKET": "test-bucket"}):
            backend = S3ObjectLockBackend(skip_validation=True)
            backend._client = mock_boto3

            with pytest.raises(StorageError) as exc_info:
                backend.put("test/file.txt", b"content")
            assert "Failed to store object" in str(exc_info.value)

    def test_get_metadata(self, mock_boto3):
        """Test get_metadata returns StorageMetadata.

        Covers lines 674-712 in storage_backends.py.
        """
        mock_boto3.head_object.return_value = {
            "ContentLength": 1024,
            "ContentType": "application/json",
            "Metadata": {"custom": "value"},
            "ObjectLockMode": "GOVERNANCE",
            "ObjectLockRetainUntilDate": datetime.now(timezone.utc)
            + timedelta(days=30),
            "ObjectLockLegalHoldStatus": "OFF",
        }

        with patch.dict(os.environ, {"FIXOPS_S3_BUCKET": "test-bucket"}):
            backend = S3ObjectLockBackend(skip_validation=True)
            backend._client = mock_boto3

            metadata = backend.get_metadata("test/file.txt")

            assert metadata.size_bytes == 1024
            assert metadata.content_type == "application/json"
            assert metadata.custom_metadata == {"custom": "value"}

    def test_get_metadata_not_found_raises(self, mock_boto3):
        """Test get_metadata raises ObjectNotFoundError when not found.

        Covers lines 709-712 in storage_backends.py.
        """

        class NoSuchKeyError(Exception):
            pass

        mock_boto3.exceptions = MagicMock()
        mock_boto3.exceptions.NoSuchKey = NoSuchKeyError
        mock_boto3.head_object.side_effect = NoSuchKeyError()

        with patch.dict(os.environ, {"FIXOPS_S3_BUCKET": "test-bucket"}):
            backend = S3ObjectLockBackend(skip_validation=True)
            backend._client = mock_boto3

            with pytest.raises(ObjectNotFoundError):
                backend.get_metadata("test/file.txt")

    def test_delete_calls_s3(self, mock_boto3):
        """Test delete calls S3 API.

        Covers lines 724-743 in storage_backends.py.
        """
        # Set up exceptions for delete operation
        mock_boto3.exceptions = MagicMock()
        mock_boto3.exceptions.NoSuchKey = type("NoSuchKey", (Exception,), {})

        with patch.dict(os.environ, {"FIXOPS_S3_BUCKET": "test-bucket"}):
            backend = S3ObjectLockBackend(skip_validation=True)
            backend._client = mock_boto3

            # Mock get_metadata to return metadata without retention
            mock_metadata = MagicMock()
            mock_metadata.retention_policy = None
            with patch.object(backend, "get_metadata", return_value=mock_metadata):
                backend.delete("test/file.txt")

            mock_boto3.delete_object.assert_called_once()

    def test_list_objects_empty(self, mock_boto3):
        """Test list_objects returns empty list when no contents.

        Covers lines 745-768 in storage_backends.py.
        """
        mock_boto3.list_objects_v2.return_value = {}
        mock_boto3.exceptions = MagicMock()
        mock_boto3.exceptions.NoSuchKey = type("NoSuchKey", (Exception,), {})

        with patch.dict(os.environ, {"FIXOPS_S3_BUCKET": "test-bucket"}):
            backend = S3ObjectLockBackend(skip_validation=True)
            backend._client = mock_boto3

            result = backend.list_objects("test/")

            assert result == []

    def test_set_legal_hold(self, mock_boto3):
        """Test set_legal_hold calls S3 API.

        Covers lines 770-784 in storage_backends.py.
        """
        mock_boto3.exceptions = MagicMock()
        mock_boto3.exceptions.NoSuchKey = type("NoSuchKey", (Exception,), {})

        with patch.dict(os.environ, {"FIXOPS_S3_BUCKET": "test-bucket"}):
            backend = S3ObjectLockBackend(skip_validation=True)
            backend._client = mock_boto3

            backend.set_legal_hold("test/file.txt", True)

            mock_boto3.put_object_legal_hold.assert_called_once()


class TestAzureImmutableBlobBackendValidation:
    """Tests for AzureImmutableBlobBackend validation and error handling."""

    @pytest.fixture
    def mock_azure(self):
        with patch(
            "core.storage_backends.BlobServiceClient", create=True
        ) as mock_service:
            mock_container = MagicMock()
            mock_service.from_connection_string.return_value.get_container_client.return_value = (
                mock_container
            )
            yield mock_container

    def test_validate_container_configuration_skip(self, mock_azure):
        """Test validate_container_configuration with skip_validation=True.

        Covers lines 891-892 in storage_backends.py.
        """
        with patch.dict(
            os.environ,
            {
                "FIXOPS_AZURE_CONTAINER": "test-container",
                "AZURE_STORAGE_CONNECTION_STRING": "test-connection",
                "FIXOPS_AZURE_SKIP_VALIDATION": "true",
            },
        ):
            with patch.object(
                AzureImmutableBlobBackend, "container_client", mock_azure
            ):
                backend = AzureImmutableBlobBackend()
                result = backend.validate_container_configuration()
                assert result is True

    def test_ensure_worm_compliance_skip(self, mock_azure):
        """Test ensure_worm_compliance with skip_validation=True.

        Covers lines 938-939 in storage_backends.py.
        """
        with patch.dict(
            os.environ,
            {
                "FIXOPS_AZURE_CONTAINER": "test-container",
                "AZURE_STORAGE_CONNECTION_STRING": "test-connection",
                "FIXOPS_AZURE_SKIP_VALIDATION": "true",
            },
        ):
            with patch.object(
                AzureImmutableBlobBackend, "container_client", mock_azure
            ):
                backend = AzureImmutableBlobBackend()
                backend.ensure_worm_compliance()  # Should not raise

    def test_ensure_worm_compliance_immutability_none_raises(self, mock_azure):
        """Test ensure_worm_compliance raises when immutability cannot be verified.

        Covers lines 991-996 in storage_backends.py - the fail-closed check
        when _immutability_enabled is None after validation.
        """
        with patch.dict(
            os.environ,
            {
                "FIXOPS_AZURE_CONTAINER": "test-container",
                "AZURE_STORAGE_CONNECTION_STRING": "test-connection",
            },
        ):
            with patch.object(
                AzureImmutableBlobBackend, "container_client", mock_azure
            ):
                backend = AzureImmutableBlobBackend(skip_validation=True)
                backend._skip_validation = False
                backend._immutability_enabled = (
                    None  # Immutability couldn't be verified
                )

                # Mock validate_container_configuration to do nothing (already called)
                with patch.object(backend, "validate_container_configuration"):
                    with pytest.raises(ConfigurationError) as exc_info:
                        backend.ensure_worm_compliance()
                    assert "Cannot verify immutability configuration" in str(
                        exc_info.value
                    )
                    assert "fail-closed" in str(exc_info.value)


class TestS3ObjectLockBackendCoverageGaps:
    """Additional tests for S3ObjectLockBackend to cover missing lines."""

    @pytest.fixture
    def mock_boto3(self):
        mock_client = MagicMock()
        with patch.dict("sys.modules", {"boto3": MagicMock()}):
            import sys

            sys.modules["boto3"].client.return_value = mock_client
            mock_client.exceptions = MagicMock()
            mock_client.exceptions.NoSuchKey = type("NoSuchKey", (Exception,), {})
            yield mock_client

    def test_get_not_found_raises_object_not_found(self, mock_boto3):
        """Test get raises ObjectNotFoundError when object not found.

        Covers lines 669-670 in storage_backends.py.
        """
        mock_boto3.get_object.side_effect = mock_boto3.exceptions.NoSuchKey()

        with patch.dict(os.environ, {"FIXOPS_S3_BUCKET": "test-bucket"}):
            backend = S3ObjectLockBackend(skip_validation=True)
            backend._client = mock_boto3

            with pytest.raises(ObjectNotFoundError):
                backend.get("test/file.txt")

    def test_get_exception_raises_storage_error(self, mock_boto3):
        """Test get raises StorageError on S3 exception.

        Covers lines 671-672 in storage_backends.py.
        """
        mock_boto3.get_object.side_effect = Exception("S3 error")

        with patch.dict(os.environ, {"FIXOPS_S3_BUCKET": "test-bucket"}):
            backend = S3ObjectLockBackend(skip_validation=True)
            backend._client = mock_boto3

            with pytest.raises(StorageError) as exc_info:
                backend.get("test/file.txt")
            assert "Failed to retrieve object" in str(exc_info.value)

    def test_get_metadata_exception_raises_storage_error(self, mock_boto3):
        """Test get_metadata raises StorageError on S3 exception.

        Covers lines 711-712 in storage_backends.py.
        """
        mock_boto3.head_object.side_effect = Exception("S3 error")

        with patch.dict(os.environ, {"FIXOPS_S3_BUCKET": "test-bucket"}):
            backend = S3ObjectLockBackend(skip_validation=True)
            backend._client = mock_boto3

            with pytest.raises(StorageError) as exc_info:
                backend.get_metadata("test/file.txt")
            assert "Failed to get metadata" in str(exc_info.value)

    def test_exists_returns_false_on_exception(self, mock_boto3):
        """Test exists returns False on S3 exception.

        Covers lines 721-722 in storage_backends.py.
        """
        mock_boto3.head_object.side_effect = Exception("S3 error")

        with patch.dict(os.environ, {"FIXOPS_S3_BUCKET": "test-bucket"}):
            backend = S3ObjectLockBackend(skip_validation=True)
            backend._client = mock_boto3

            result = backend.exists("test/file.txt")
            assert result is False

    def test_delete_with_legal_hold_raises(self, mock_boto3):
        """Test delete raises RetentionViolationError when object has legal hold.

        Covers lines 729-730 in storage_backends.py.
        """
        mock_boto3.head_object.return_value = {
            "ContentLength": 1024,
            "ObjectLockMode": "GOVERNANCE",
            "ObjectLockRetainUntilDate": datetime.now(timezone.utc)
            + timedelta(days=30),
            "ObjectLockLegalHoldStatus": "ON",
        }

        with patch.dict(os.environ, {"FIXOPS_S3_BUCKET": "test-bucket"}):
            backend = S3ObjectLockBackend(skip_validation=True)
            backend._client = mock_boto3

            with pytest.raises(RetentionViolationError) as exc_info:
                backend.delete("test/file.txt")
            assert "legal hold" in str(exc_info.value)

    def test_delete_with_compliance_retention_raises(self, mock_boto3):
        """Test delete raises RetentionViolationError when object has COMPLIANCE retention.

        Covers lines 731-734 in storage_backends.py.
        """
        mock_boto3.head_object.return_value = {
            "ContentLength": 1024,
            "ObjectLockMode": "COMPLIANCE",
            "ObjectLockRetainUntilDate": datetime.now(timezone.utc)
            + timedelta(days=30),
        }

        with patch.dict(os.environ, {"FIXOPS_S3_BUCKET": "test-bucket"}):
            backend = S3ObjectLockBackend(skip_validation=True)
            backend._client = mock_boto3

            with pytest.raises(RetentionViolationError) as exc_info:
                backend.delete("test/file.txt")
            assert "COMPLIANCE retention" in str(exc_info.value)

    def test_delete_not_found_returns_false(self, mock_boto3):
        """Test delete returns False when object not found.

        Covers lines 738-739 in storage_backends.py.
        """
        mock_boto3.head_object.side_effect = mock_boto3.exceptions.NoSuchKey()

        with patch.dict(os.environ, {"FIXOPS_S3_BUCKET": "test-bucket"}):
            backend = S3ObjectLockBackend(skip_validation=True)
            backend._client = mock_boto3

            result = backend.delete("test/file.txt")
            assert result is False

    def test_delete_exception_raises_storage_error(self, mock_boto3):
        """Test delete raises StorageError on S3 exception.

        Covers lines 742-743 in storage_backends.py.
        """
        mock_boto3.head_object.return_value = {"ContentLength": 1024}
        mock_boto3.delete_object.side_effect = Exception("S3 error")

        with patch.dict(os.environ, {"FIXOPS_S3_BUCKET": "test-bucket"}):
            backend = S3ObjectLockBackend(skip_validation=True)
            backend._client = mock_boto3

            with pytest.raises(StorageError) as exc_info:
                backend.delete("test/file.txt")
            assert "Failed to delete object" in str(exc_info.value)

    def test_list_objects_with_contents(self, mock_boto3):
        """Test list_objects returns metadata for objects.

        Covers lines 757-767 in storage_backends.py.
        """
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {
                "Contents": [
                    {"Key": "prefix/file1.txt"},
                    {"Key": "prefix/file2.txt"},
                ]
            }
        ]
        mock_boto3.get_paginator.return_value = mock_paginator
        mock_boto3.head_object.return_value = {
            "ContentLength": 1024,
            "ContentType": "text/plain",
            "Metadata": {},
        }

        with patch.dict(os.environ, {"FIXOPS_S3_BUCKET": "test-bucket"}):
            backend = S3ObjectLockBackend(skip_validation=True, prefix="prefix/")
            backend._client = mock_boto3

            results = backend.list_objects("test/")
            assert len(results) == 2

    def test_list_objects_exception_raises_storage_error(self, mock_boto3):
        """Test list_objects raises StorageError on S3 exception.

        Covers lines 766-767 in storage_backends.py.
        """
        mock_boto3.get_paginator.side_effect = Exception("S3 error")

        with patch.dict(os.environ, {"FIXOPS_S3_BUCKET": "test-bucket"}):
            backend = S3ObjectLockBackend(skip_validation=True)
            backend._client = mock_boto3

            with pytest.raises(StorageError) as exc_info:
                backend.list_objects("test/")
            assert "Failed to list objects" in str(exc_info.value)

    def test_set_legal_hold_exception_raises_storage_error(self, mock_boto3):
        """Test set_legal_hold raises StorageError on S3 exception.

        Covers lines 781-784 in storage_backends.py.
        """
        mock_boto3.put_object_legal_hold.side_effect = Exception("S3 error")

        with patch.dict(os.environ, {"FIXOPS_S3_BUCKET": "test-bucket"}):
            backend = S3ObjectLockBackend(skip_validation=True)
            backend._client = mock_boto3

            with pytest.raises(StorageError) as exc_info:
                backend.set_legal_hold("test/file.txt", True)
            assert "Failed to set legal hold" in str(exc_info.value)

    def test_set_legal_hold_not_found_raises_object_not_found(self, mock_boto3):
        """Test set_legal_hold raises ObjectNotFoundError when object doesn't exist.

        Covers line 782 in storage_backends.py.
        """
        mock_boto3.exceptions.NoSuchKey = type("NoSuchKey", (Exception,), {})
        mock_boto3.put_object_legal_hold.side_effect = mock_boto3.exceptions.NoSuchKey(
            "Not found"
        )

        with patch.dict(os.environ, {"FIXOPS_S3_BUCKET": "test-bucket"}):
            backend = S3ObjectLockBackend(skip_validation=True)
            backend._client = mock_boto3

            with pytest.raises(ObjectNotFoundError) as exc_info:
                backend.set_legal_hold("test/file.txt", True)
            assert "Object not found" in str(exc_info.value)

    def test_list_objects_skips_failed_metadata(self, mock_boto3):
        """Test list_objects continues when get_metadata fails for an object.

        Covers lines 764-765 in storage_backends.py.
        """
        mock_paginator = MagicMock()
        mock_boto3.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {"Contents": [{"Key": "test/file1.txt"}, {"Key": "test/file2.txt"}]}
        ]
        mock_boto3.head_object.side_effect = Exception("Metadata error")

        with patch.dict(os.environ, {"FIXOPS_S3_BUCKET": "test-bucket"}):
            backend = S3ObjectLockBackend(skip_validation=True)
            backend._client = mock_boto3

            results = backend.list_objects("test/")
            assert len(results) == 0


class TestAzureImmutableBlobBackendCoverageGaps:
    """Additional tests for AzureImmutableBlobBackend to cover missing lines."""

    @pytest.fixture
    def mock_azure(self):
        with patch(
            "core.storage_backends.BlobServiceClient", create=True
        ) as mock_service:
            mock_container = MagicMock()
            mock_service.from_connection_string.return_value.get_container_client.return_value = (
                mock_container
            )
            yield mock_container

    def test_full_key_with_prefix(self, mock_azure):
        """Test _full_key with prefix.

        Covers lines 875-877 in storage_backends.py.
        """
        with patch.dict(
            os.environ,
            {
                "FIXOPS_AZURE_CONTAINER": "test-container",
                "AZURE_STORAGE_CONNECTION_STRING": "test-connection",
                "FIXOPS_AZURE_SKIP_VALIDATION": "true",
            },
        ):
            with patch.object(
                AzureImmutableBlobBackend, "container_client", mock_azure
            ):
                backend = AzureImmutableBlobBackend(prefix="myprefix/")
                full_key = backend._full_key("test/file.txt")
                assert full_key == "myprefix/test/file.txt"

    def test_validate_container_configuration_with_immutability(self, mock_azure):
        """Test validate_container_configuration when immutability is enabled.

        Covers lines 899-911 in storage_backends.py.
        """
        mock_properties = MagicMock()
        mock_properties.has_immutability_policy = True
        mock_azure.get_container_properties.return_value = mock_properties

        with patch.dict(
            os.environ,
            {
                "FIXOPS_AZURE_CONTAINER": "test-container",
                "AZURE_STORAGE_CONNECTION_STRING": "test-connection",
            },
        ):
            with patch.object(
                AzureImmutableBlobBackend, "container_client", mock_azure
            ):
                backend = AzureImmutableBlobBackend(skip_validation=True)
                backend._skip_validation = False
                result = backend.validate_container_configuration()
                assert result is True
                assert backend._immutability_enabled is True

    def test_validate_container_configuration_without_immutability(self, mock_azure):
        """Test validate_container_configuration when immutability is not enabled.

        Covers lines 917, 921 in storage_backends.py.
        """
        mock_properties = MagicMock()
        mock_properties.has_immutability_policy = None
        mock_properties.immutable_storage_with_versioning_enabled = None
        mock_azure.get_container_properties.return_value = mock_properties

        with patch.dict(
            os.environ,
            {
                "FIXOPS_AZURE_CONTAINER": "test-container",
                "AZURE_STORAGE_CONNECTION_STRING": "test-connection",
            },
        ):
            with patch.object(
                AzureImmutableBlobBackend, "container_client", mock_azure
            ):
                backend = AzureImmutableBlobBackend(skip_validation=True)
                backend._skip_validation = False
                result = backend.validate_container_configuration()
                assert result is True
                assert backend._immutability_enabled is None

    def test_validate_container_configuration_exception(self, mock_azure):
        """Test validate_container_configuration raises ConfigurationError on exception.

        Covers lines 923-925 in storage_backends.py.
        """
        mock_azure.get_container_properties.side_effect = Exception("Azure error")

        with patch.dict(
            os.environ,
            {
                "FIXOPS_AZURE_CONTAINER": "test-container",
                "AZURE_STORAGE_CONNECTION_STRING": "test-connection",
            },
        ):
            with patch.object(
                AzureImmutableBlobBackend, "container_client", mock_azure
            ):
                backend = AzureImmutableBlobBackend(skip_validation=True)
                backend._skip_validation = False
                with pytest.raises(ConfigurationError) as exc_info:
                    backend.validate_container_configuration()
                assert "Failed to validate container configuration" in str(
                    exc_info.value
                )

    def test_ensure_worm_compliance_calls_validate(self, mock_azure):
        """Test ensure_worm_compliance calls validate when immutability is None.

        Covers lines 941-942 in storage_backends.py.
        """
        mock_properties = MagicMock()
        mock_properties.has_immutability_policy = True
        mock_azure.get_container_properties.return_value = mock_properties

        with patch.dict(
            os.environ,
            {
                "FIXOPS_AZURE_CONTAINER": "test-container",
                "AZURE_STORAGE_CONNECTION_STRING": "test-connection",
            },
        ):
            with patch.object(
                AzureImmutableBlobBackend, "container_client", mock_azure
            ):
                backend = AzureImmutableBlobBackend(skip_validation=True)
                backend._skip_validation = False
                backend._immutability_enabled = None
                backend.ensure_worm_compliance()
                mock_azure.get_container_properties.assert_called_once()

    def test_put_with_retention(self, mock_azure):
        """Test put with retention policy.

        Covers lines 954-995 in storage_backends.py.
        """
        mock_blob_client = MagicMock()
        mock_azure.get_blob_client.return_value = mock_blob_client

        # Create a mock ImmutabilityPolicy class
        mock_immutability_policy = MagicMock()

        with patch.dict(
            os.environ,
            {
                "FIXOPS_AZURE_CONTAINER": "test-container",
                "AZURE_STORAGE_CONNECTION_STRING": "test-connection",
                "FIXOPS_AZURE_SKIP_VALIDATION": "true",
            },
        ):
            with patch.object(
                AzureImmutableBlobBackend, "container_client", mock_azure
            ):
                # Mock the azure.storage.blob module import inside put()
                mock_azure_module = MagicMock()
                mock_azure_module.ImmutabilityPolicy = mock_immutability_policy
                with patch.dict(
                    "sys.modules", {"azure.storage.blob": mock_azure_module}
                ):
                    backend = AzureImmutableBlobBackend()
                    retention = RetentionPolicy(
                        mode=RetentionMode.GOVERNANCE,
                        retain_until_days=30,
                        legal_hold=True,
                    )
                    metadata = backend.put(
                        "test/file.txt",
                        b"content",
                        retention_policy=retention,
                    )

                    assert metadata.object_id == "test/file.txt"
                    mock_blob_client.upload_blob.assert_called_once()
                    mock_blob_client.set_immutability_policy.assert_called_once()
                    mock_blob_client.set_legal_hold.assert_called_once_with(True)

    def test_put_with_binary_io(self, mock_azure):
        """Test put with BinaryIO data.

        Covers lines 956-957 in storage_backends.py.
        """
        mock_blob_client = MagicMock()
        mock_azure.get_blob_client.return_value = mock_blob_client

        with patch.dict(
            os.environ,
            {
                "FIXOPS_AZURE_CONTAINER": "test-container",
                "AZURE_STORAGE_CONNECTION_STRING": "test-connection",
                "FIXOPS_AZURE_SKIP_VALIDATION": "true",
            },
        ):
            with patch.object(
                AzureImmutableBlobBackend, "container_client", mock_azure
            ):
                # Mock the azure.storage.blob module import inside put()
                mock_azure_module = MagicMock()
                with patch.dict(
                    "sys.modules", {"azure.storage.blob": mock_azure_module}
                ):
                    backend = AzureImmutableBlobBackend()
                    data = io.BytesIO(b"content")
                    metadata = backend.put("test/file.txt", data)

                    assert metadata.object_id == "test/file.txt"
                    mock_blob_client.upload_blob.assert_called_once()

    def test_put_exception_raises_storage_error(self, mock_azure):
        """Test put raises StorageError on Azure exception.

        Covers lines 994-995 in storage_backends.py.
        """
        mock_blob_client = MagicMock()
        mock_blob_client.upload_blob.side_effect = Exception("Azure error")
        mock_azure.get_blob_client.return_value = mock_blob_client

        with patch.dict(
            os.environ,
            {
                "FIXOPS_AZURE_CONTAINER": "test-container",
                "AZURE_STORAGE_CONNECTION_STRING": "test-connection",
                "FIXOPS_AZURE_SKIP_VALIDATION": "true",
            },
        ):
            with patch.object(
                AzureImmutableBlobBackend, "container_client", mock_azure
            ):
                backend = AzureImmutableBlobBackend()
                with pytest.raises(StorageError) as exc_info:
                    backend.put("test/file.txt", b"content")
                assert "Failed to store blob" in str(exc_info.value)

    def test_get_success(self, mock_azure):
        """Test get returns blob content.

        Covers lines 1008-1011 in storage_backends.py.
        """
        mock_blob_client = MagicMock()
        mock_blob_client.download_blob.return_value.readall.return_value = b"content"
        mock_azure.get_blob_client.return_value = mock_blob_client

        with patch.dict(
            os.environ,
            {
                "FIXOPS_AZURE_CONTAINER": "test-container",
                "AZURE_STORAGE_CONNECTION_STRING": "test-connection",
                "FIXOPS_AZURE_SKIP_VALIDATION": "true",
            },
        ):
            with patch.object(
                AzureImmutableBlobBackend, "container_client", mock_azure
            ):
                backend = AzureImmutableBlobBackend()
                result = backend.get("test/file.txt")
                assert result == b"content"

    def test_get_not_found_raises_object_not_found(self, mock_azure):
        """Test get raises ObjectNotFoundError when blob not found.

        Covers lines 1013-1014 in storage_backends.py.
        """
        mock_blob_client = MagicMock()
        mock_blob_client.download_blob.side_effect = Exception("BlobNotFound")
        mock_azure.get_blob_client.return_value = mock_blob_client

        with patch.dict(
            os.environ,
            {
                "FIXOPS_AZURE_CONTAINER": "test-container",
                "AZURE_STORAGE_CONNECTION_STRING": "test-connection",
                "FIXOPS_AZURE_SKIP_VALIDATION": "true",
            },
        ):
            with patch.object(
                AzureImmutableBlobBackend, "container_client", mock_azure
            ):
                backend = AzureImmutableBlobBackend()
                with pytest.raises(ObjectNotFoundError):
                    backend.get("test/file.txt")

    def test_get_exception_raises_storage_error(self, mock_azure):
        """Test get raises StorageError on Azure exception.

        Covers lines 1015 in storage_backends.py.
        """
        mock_blob_client = MagicMock()
        mock_blob_client.download_blob.side_effect = Exception("Azure error")
        mock_azure.get_blob_client.return_value = mock_blob_client

        with patch.dict(
            os.environ,
            {
                "FIXOPS_AZURE_CONTAINER": "test-container",
                "AZURE_STORAGE_CONNECTION_STRING": "test-connection",
                "FIXOPS_AZURE_SKIP_VALIDATION": "true",
            },
        ):
            with patch.object(
                AzureImmutableBlobBackend, "container_client", mock_azure
            ):
                backend = AzureImmutableBlobBackend()
                with pytest.raises(StorageError) as exc_info:
                    backend.get("test/file.txt")
                assert "Failed to retrieve blob" in str(exc_info.value)

    def test_get_metadata_success(self, mock_azure):
        """Test get_metadata returns StorageMetadata.

        Covers lines 1018-1055 in storage_backends.py.
        """
        mock_blob_client = MagicMock()
        mock_properties = MagicMock()
        mock_properties.size = 1024
        mock_properties.content_settings.content_type = "application/json"
        mock_properties.creation_time = datetime.now(timezone.utc)
        mock_properties.metadata = {"custom": "value"}
        mock_properties.immutability_policy = MagicMock()
        mock_properties.immutability_policy.policy_mode = "Locked"
        mock_properties.immutability_policy.expiry_time = datetime.now(
            timezone.utc
        ) + timedelta(days=30)
        mock_properties.has_legal_hold = True
        mock_blob_client.get_blob_properties.return_value = mock_properties
        mock_azure.get_blob_client.return_value = mock_blob_client

        with patch.dict(
            os.environ,
            {
                "FIXOPS_AZURE_CONTAINER": "test-container",
                "AZURE_STORAGE_CONNECTION_STRING": "test-connection",
                "FIXOPS_AZURE_SKIP_VALIDATION": "true",
            },
        ):
            with patch.object(
                AzureImmutableBlobBackend, "container_client", mock_azure
            ):
                backend = AzureImmutableBlobBackend()
                metadata = backend.get_metadata("test/file.txt")

                assert metadata.size_bytes == 1024
                assert metadata.content_type == "application/json"
                assert metadata.retention_policy is not None
                assert metadata.retention_policy.mode == RetentionMode.COMPLIANCE
                assert metadata.retention_policy.legal_hold is True

    def test_get_metadata_not_found_raises(self, mock_azure):
        """Test get_metadata raises ObjectNotFoundError when blob not found.

        Covers lines 1056-1058 in storage_backends.py.
        """
        mock_blob_client = MagicMock()
        mock_blob_client.get_blob_properties.side_effect = Exception("BlobNotFound")
        mock_azure.get_blob_client.return_value = mock_blob_client

        with patch.dict(
            os.environ,
            {
                "FIXOPS_AZURE_CONTAINER": "test-container",
                "AZURE_STORAGE_CONNECTION_STRING": "test-connection",
                "FIXOPS_AZURE_SKIP_VALIDATION": "true",
            },
        ):
            with patch.object(
                AzureImmutableBlobBackend, "container_client", mock_azure
            ):
                backend = AzureImmutableBlobBackend()
                with pytest.raises(ObjectNotFoundError):
                    backend.get_metadata("test/file.txt")

    def test_get_metadata_exception_raises_storage_error(self, mock_azure):
        """Test get_metadata raises StorageError on Azure exception.

        Covers lines 1059 in storage_backends.py.
        """
        mock_blob_client = MagicMock()
        mock_blob_client.get_blob_properties.side_effect = Exception("Azure error")
        mock_azure.get_blob_client.return_value = mock_blob_client

        with patch.dict(
            os.environ,
            {
                "FIXOPS_AZURE_CONTAINER": "test-container",
                "AZURE_STORAGE_CONNECTION_STRING": "test-connection",
                "FIXOPS_AZURE_SKIP_VALIDATION": "true",
            },
        ):
            with patch.object(
                AzureImmutableBlobBackend, "container_client", mock_azure
            ):
                backend = AzureImmutableBlobBackend()
                with pytest.raises(StorageError) as exc_info:
                    backend.get_metadata("test/file.txt")
                assert "Failed to get blob metadata" in str(exc_info.value)

    def test_exists_returns_true(self, mock_azure):
        """Test exists returns True when blob exists.

        Covers lines 1062-1066 in storage_backends.py.
        """
        mock_blob_client = MagicMock()
        mock_azure.get_blob_client.return_value = mock_blob_client

        with patch.dict(
            os.environ,
            {
                "FIXOPS_AZURE_CONTAINER": "test-container",
                "AZURE_STORAGE_CONNECTION_STRING": "test-connection",
                "FIXOPS_AZURE_SKIP_VALIDATION": "true",
            },
        ):
            with patch.object(
                AzureImmutableBlobBackend, "container_client", mock_azure
            ):
                backend = AzureImmutableBlobBackend()
                result = backend.exists("test/file.txt")
                assert result is True

    def test_exists_returns_false_on_exception(self, mock_azure):
        """Test exists returns False on exception.

        Covers lines 1067-1068 in storage_backends.py.
        """
        mock_blob_client = MagicMock()
        mock_blob_client.get_blob_properties.side_effect = Exception("Azure error")
        mock_azure.get_blob_client.return_value = mock_blob_client

        with patch.dict(
            os.environ,
            {
                "FIXOPS_AZURE_CONTAINER": "test-container",
                "AZURE_STORAGE_CONNECTION_STRING": "test-connection",
                "FIXOPS_AZURE_SKIP_VALIDATION": "true",
            },
        ):
            with patch.object(
                AzureImmutableBlobBackend, "container_client", mock_azure
            ):
                backend = AzureImmutableBlobBackend()
                result = backend.exists("test/file.txt")
                assert result is False

    def test_delete_success(self, mock_azure):
        """Test delete returns True on success.

        Covers lines 1071-1084 in storage_backends.py.
        """
        mock_blob_client = MagicMock()
        mock_properties = MagicMock()
        mock_properties.size = 1024
        mock_properties.content_settings.content_type = "text/plain"
        mock_properties.creation_time = None
        mock_properties.metadata = {}
        mock_properties.immutability_policy = None
        mock_properties.has_legal_hold = False
        mock_blob_client.get_blob_properties.return_value = mock_properties
        mock_azure.get_blob_client.return_value = mock_blob_client

        with patch.dict(
            os.environ,
            {
                "FIXOPS_AZURE_CONTAINER": "test-container",
                "AZURE_STORAGE_CONNECTION_STRING": "test-connection",
                "FIXOPS_AZURE_SKIP_VALIDATION": "true",
            },
        ):
            with patch.object(
                AzureImmutableBlobBackend, "container_client", mock_azure
            ):
                backend = AzureImmutableBlobBackend()
                result = backend.delete("test/file.txt")
                assert result is True
                mock_blob_client.delete_blob.assert_called_once()

    def test_delete_with_legal_hold_raises(self, mock_azure):
        """Test delete raises RetentionViolationError when blob has legal hold.

        Covers lines 1075-1076 in storage_backends.py.
        """
        mock_blob_client = MagicMock()
        mock_properties = MagicMock()
        mock_properties.size = 1024
        mock_properties.content_settings.content_type = "text/plain"
        mock_properties.creation_time = None
        mock_properties.metadata = {}
        mock_properties.immutability_policy = MagicMock()
        mock_properties.immutability_policy.policy_mode = "Unlocked"
        mock_properties.immutability_policy.expiry_time = None
        mock_properties.has_legal_hold = True
        mock_blob_client.get_blob_properties.return_value = mock_properties
        mock_azure.get_blob_client.return_value = mock_blob_client

        with patch.dict(
            os.environ,
            {
                "FIXOPS_AZURE_CONTAINER": "test-container",
                "AZURE_STORAGE_CONNECTION_STRING": "test-connection",
                "FIXOPS_AZURE_SKIP_VALIDATION": "true",
            },
        ):
            with patch.object(
                AzureImmutableBlobBackend, "container_client", mock_azure
            ):
                backend = AzureImmutableBlobBackend()
                with pytest.raises(RetentionViolationError) as exc_info:
                    backend.delete("test/file.txt")
                assert "legal hold" in str(exc_info.value)

    def test_delete_with_compliance_retention_raises(self, mock_azure):
        """Test delete raises RetentionViolationError when blob has COMPLIANCE retention.

        Covers lines 1077-1080 in storage_backends.py.
        """
        mock_blob_client = MagicMock()
        mock_properties = MagicMock()
        mock_properties.size = 1024
        mock_properties.content_settings.content_type = "text/plain"
        mock_properties.creation_time = None
        mock_properties.metadata = {}
        mock_properties.immutability_policy = MagicMock()
        mock_properties.immutability_policy.policy_mode = "Locked"
        mock_properties.immutability_policy.expiry_time = datetime.now(
            timezone.utc
        ) + timedelta(days=30)
        mock_properties.has_legal_hold = False
        mock_blob_client.get_blob_properties.return_value = mock_properties
        mock_azure.get_blob_client.return_value = mock_blob_client

        with patch.dict(
            os.environ,
            {
                "FIXOPS_AZURE_CONTAINER": "test-container",
                "AZURE_STORAGE_CONNECTION_STRING": "test-connection",
                "FIXOPS_AZURE_SKIP_VALIDATION": "true",
            },
        ):
            with patch.object(
                AzureImmutableBlobBackend, "container_client", mock_azure
            ):
                backend = AzureImmutableBlobBackend()
                with pytest.raises(RetentionViolationError) as exc_info:
                    backend.delete("test/file.txt")
                assert "COMPLIANCE retention" in str(exc_info.value)

    def test_delete_not_found_returns_false(self, mock_azure):
        """Test delete returns False when blob not found.

        Covers lines 1085-1086 in storage_backends.py.
        """
        mock_blob_client = MagicMock()
        mock_blob_client.get_blob_properties.side_effect = Exception("BlobNotFound")
        mock_azure.get_blob_client.return_value = mock_blob_client

        with patch.dict(
            os.environ,
            {
                "FIXOPS_AZURE_CONTAINER": "test-container",
                "AZURE_STORAGE_CONNECTION_STRING": "test-connection",
                "FIXOPS_AZURE_SKIP_VALIDATION": "true",
            },
        ):
            with patch.object(
                AzureImmutableBlobBackend, "container_client", mock_azure
            ):
                backend = AzureImmutableBlobBackend()
                result = backend.delete("test/file.txt")
                assert result is False

    def test_delete_exception_raises_storage_error(self, mock_azure):
        """Test delete raises StorageError on Azure exception.

        Covers lines 1089-1090 in storage_backends.py.
        """
        mock_blob_client = MagicMock()
        mock_properties = MagicMock()
        mock_properties.size = 1024
        mock_properties.content_settings.content_type = "text/plain"
        mock_properties.creation_time = None
        mock_properties.metadata = {}
        mock_properties.immutability_policy = None
        mock_properties.has_legal_hold = False
        mock_blob_client.get_blob_properties.return_value = mock_properties
        mock_blob_client.delete_blob.side_effect = Exception("Azure error")
        mock_azure.get_blob_client.return_value = mock_blob_client

        with patch.dict(
            os.environ,
            {
                "FIXOPS_AZURE_CONTAINER": "test-container",
                "AZURE_STORAGE_CONNECTION_STRING": "test-connection",
                "FIXOPS_AZURE_SKIP_VALIDATION": "true",
            },
        ):
            with patch.object(
                AzureImmutableBlobBackend, "container_client", mock_azure
            ):
                backend = AzureImmutableBlobBackend()
                with pytest.raises(StorageError) as exc_info:
                    backend.delete("test/file.txt")
                assert "Failed to delete blob" in str(exc_info.value)

    def test_list_objects_success(self, mock_azure):
        """Test list_objects returns metadata for blobs.

        Covers lines 1095-1112 in storage_backends.py.
        """
        mock_blob1 = MagicMock()
        mock_blob1.name = "prefix/file1.txt"
        mock_blob2 = MagicMock()
        mock_blob2.name = "prefix/file2.txt"
        mock_azure.list_blobs.return_value = [mock_blob1, mock_blob2]

        mock_blob_client = MagicMock()
        mock_properties = MagicMock()
        mock_properties.size = 1024
        mock_properties.content_settings.content_type = "text/plain"
        mock_properties.creation_time = None
        mock_properties.metadata = {}
        mock_properties.immutability_policy = None
        mock_properties.has_legal_hold = False
        mock_blob_client.get_blob_properties.return_value = mock_properties
        mock_azure.get_blob_client.return_value = mock_blob_client

        with patch.dict(
            os.environ,
            {
                "FIXOPS_AZURE_CONTAINER": "test-container",
                "AZURE_STORAGE_CONNECTION_STRING": "test-connection",
                "FIXOPS_AZURE_SKIP_VALIDATION": "true",
            },
        ):
            with patch.object(
                AzureImmutableBlobBackend, "container_client", mock_azure
            ):
                backend = AzureImmutableBlobBackend(prefix="prefix/")
                results = backend.list_objects("test/")
                assert len(results) == 2

    def test_list_objects_exception_raises_storage_error(self, mock_azure):
        """Test list_objects raises StorageError on Azure exception.

        Covers lines 1110-1111 in storage_backends.py.
        """
        mock_azure.list_blobs.side_effect = Exception("Azure error")

        with patch.dict(
            os.environ,
            {
                "FIXOPS_AZURE_CONTAINER": "test-container",
                "AZURE_STORAGE_CONNECTION_STRING": "test-connection",
                "FIXOPS_AZURE_SKIP_VALIDATION": "true",
            },
        ):
            with patch.object(
                AzureImmutableBlobBackend, "container_client", mock_azure
            ):
                backend = AzureImmutableBlobBackend()
                with pytest.raises(StorageError) as exc_info:
                    backend.list_objects("test/")
                assert "Failed to list blobs" in str(exc_info.value)

    def test_list_objects_with_limit_breaks_early(self, mock_azure):
        """Test list_objects breaks when limit is reached.

        Covers line 1101 in storage_backends.py.
        """
        mock_blob1 = MagicMock()
        mock_blob1.name = "test/file1.txt"
        mock_blob2 = MagicMock()
        mock_blob2.name = "test/file2.txt"
        mock_blob3 = MagicMock()
        mock_blob3.name = "test/file3.txt"
        mock_azure.list_blobs.return_value = [mock_blob1, mock_blob2, mock_blob3]

        mock_blob_client = MagicMock()
        mock_blob_client.get_blob_properties.return_value = MagicMock(
            size=1024,
            content_settings=MagicMock(content_type="application/octet-stream"),
            creation_time=datetime.now(timezone.utc),
            metadata={},
            immutability_policy=None,
            has_legal_hold=False,
        )
        mock_azure.get_blob_client.return_value = mock_blob_client

        with patch.dict(
            os.environ,
            {
                "FIXOPS_AZURE_CONTAINER": "test-container",
                "AZURE_STORAGE_CONNECTION_STRING": "test-connection",
                "FIXOPS_AZURE_SKIP_VALIDATION": "true",
            },
        ):
            with patch.object(
                AzureImmutableBlobBackend, "container_client", mock_azure
            ):
                backend = AzureImmutableBlobBackend()
                results = backend.list_objects("test/", limit=2)
                assert len(results) == 2

    def test_list_objects_skips_failed_metadata(self, mock_azure):
        """Test list_objects continues when get_metadata fails for a blob.

        Covers lines 1108-1109 in storage_backends.py.
        """
        mock_blob1 = MagicMock()
        mock_blob1.name = "test/file1.txt"
        mock_blob2 = MagicMock()
        mock_blob2.name = "test/file2.txt"
        mock_azure.list_blobs.return_value = [mock_blob1, mock_blob2]

        mock_blob_client = MagicMock()
        mock_blob_client.get_blob_properties.side_effect = Exception("Metadata error")
        mock_azure.get_blob_client.return_value = mock_blob_client

        with patch.dict(
            os.environ,
            {
                "FIXOPS_AZURE_CONTAINER": "test-container",
                "AZURE_STORAGE_CONNECTION_STRING": "test-connection",
                "FIXOPS_AZURE_SKIP_VALIDATION": "true",
            },
        ):
            with patch.object(
                AzureImmutableBlobBackend, "container_client", mock_azure
            ):
                backend = AzureImmutableBlobBackend()
                results = backend.list_objects("test/")
                assert len(results) == 0

    def test_set_legal_hold_success(self, mock_azure):
        """Test set_legal_hold calls Azure API.

        Covers lines 1115-1121 in storage_backends.py.
        """
        mock_blob_client = MagicMock()
        mock_azure.get_blob_client.return_value = mock_blob_client

        with patch.dict(
            os.environ,
            {
                "FIXOPS_AZURE_CONTAINER": "test-container",
                "AZURE_STORAGE_CONNECTION_STRING": "test-connection",
                "FIXOPS_AZURE_SKIP_VALIDATION": "true",
            },
        ):
            with patch.object(
                AzureImmutableBlobBackend, "container_client", mock_azure
            ):
                backend = AzureImmutableBlobBackend()
                backend.set_legal_hold("test/file.txt", True)
                mock_blob_client.set_legal_hold.assert_called_once_with(True)

    def test_set_legal_hold_not_found_raises(self, mock_azure):
        """Test set_legal_hold raises ObjectNotFoundError when blob not found.

        Covers lines 1122-1124 in storage_backends.py.
        """
        mock_blob_client = MagicMock()
        mock_blob_client.set_legal_hold.side_effect = Exception("BlobNotFound")
        mock_azure.get_blob_client.return_value = mock_blob_client

        with patch.dict(
            os.environ,
            {
                "FIXOPS_AZURE_CONTAINER": "test-container",
                "AZURE_STORAGE_CONNECTION_STRING": "test-connection",
                "FIXOPS_AZURE_SKIP_VALIDATION": "true",
            },
        ):
            with patch.object(
                AzureImmutableBlobBackend, "container_client", mock_azure
            ):
                backend = AzureImmutableBlobBackend()
                with pytest.raises(ObjectNotFoundError):
                    backend.set_legal_hold("test/file.txt", True)

    def test_set_legal_hold_exception_raises_storage_error(self, mock_azure):
        """Test set_legal_hold raises StorageError on Azure exception.

        Covers lines 1125 in storage_backends.py.
        """
        mock_blob_client = MagicMock()
        mock_blob_client.set_legal_hold.side_effect = Exception("Azure error")
        mock_azure.get_blob_client.return_value = mock_blob_client

        with patch.dict(
            os.environ,
            {
                "FIXOPS_AZURE_CONTAINER": "test-container",
                "AZURE_STORAGE_CONNECTION_STRING": "test-connection",
                "FIXOPS_AZURE_SKIP_VALIDATION": "true",
            },
        ):
            with patch.object(
                AzureImmutableBlobBackend, "container_client", mock_azure
            ):
                backend = AzureImmutableBlobBackend()
                with pytest.raises(StorageError) as exc_info:
                    backend.set_legal_hold("test/file.txt", True)
                assert "Failed to set legal hold" in str(exc_info.value)


class TestS3ClientPropertyCoverage:
    """Tests for S3ObjectLockBackend.client property to cover lazy initialization.

    These tests cover lines 494-502 in storage_backends.py.
    """

    def test_client_property_creates_boto3_client(self):
        """Test that accessing client property creates boto3 client.

        Covers lines 494-500 in storage_backends.py.
        """
        mock_boto3 = MagicMock()
        mock_client = MagicMock()
        mock_boto3.client.return_value = mock_client

        with patch.dict("sys.modules", {"boto3": mock_boto3}):
            with patch.dict(os.environ, {"FIXOPS_S3_BUCKET": "test-bucket"}):
                backend = S3ObjectLockBackend(skip_validation=True)
                backend._client = None  # Reset to trigger lazy init

                # Access the client property
                client = backend.client

                # Verify boto3.client was called
                mock_boto3.client.assert_called_once()
                assert client == mock_client

    def test_client_property_with_endpoint_url(self):
        """Test that client property uses endpoint_url when provided.

        Covers lines 498-500 in storage_backends.py.
        """
        mock_boto3 = MagicMock()
        mock_client = MagicMock()
        mock_boto3.client.return_value = mock_client

        with patch.dict("sys.modules", {"boto3": mock_boto3}):
            with patch.dict(
                os.environ,
                {
                    "FIXOPS_S3_BUCKET": "test-bucket",
                    "FIXOPS_S3_ENDPOINT_URL": "http://localhost:4566",
                },
            ):
                backend = S3ObjectLockBackend(skip_validation=True)
                backend._client = None  # Reset to trigger lazy init

                # Access the client property
                _ = backend.client

                # Verify boto3.client was called with endpoint_url
                call_kwargs = mock_boto3.client.call_args.kwargs
                assert call_kwargs.get("endpoint_url") == "http://localhost:4566"

    def test_client_property_raises_on_import_error(self):
        """Test that client property raises ConfigurationError when boto3 not installed.

        Covers lines 501-504 in storage_backends.py.
        """
        # Create a backend with _client = None
        with patch.dict(os.environ, {"FIXOPS_S3_BUCKET": "test-bucket"}):
            with patch.dict("sys.modules", {"boto3": MagicMock()}):
                backend = S3ObjectLockBackend(skip_validation=True)
                backend._client = None  # Reset to trigger lazy init

        # Now patch boto3 import to raise ImportError
        def raise_import_error(*args, **kwargs):
            raise ImportError("No module named 'boto3'")

        with patch.dict("sys.modules", {"boto3": None}):
            # Remove boto3 from sys.modules to simulate it not being installed
            import sys

            original_boto3 = sys.modules.get("boto3")
            sys.modules["boto3"] = None

            try:
                # Patch the import inside the client property
                with patch("builtins.__import__", side_effect=raise_import_error):
                    with pytest.raises(ConfigurationError) as exc_info:
                        _ = backend.client
                    assert "boto3 library required" in str(exc_info.value)
            finally:
                if original_boto3 is not None:
                    sys.modules["boto3"] = original_boto3


class TestAzureContainerClientPropertyCoverage:
    """Tests for AzureImmutableBlobBackend.container_client property.

    These tests cover lines 844-872 in storage_backends.py.
    """

    def test_container_client_with_connection_string(self):
        """Test container_client property with connection string.

        Covers lines 844-851, 864-866, 872 in storage_backends.py.
        """
        mock_blob_service = MagicMock()
        mock_container = MagicMock()
        mock_blob_service.get_container_client.return_value = mock_container

        # Create mock azure module
        mock_azure_module = MagicMock()
        mock_azure_module.BlobServiceClient.from_connection_string.return_value = (
            mock_blob_service
        )

        with patch.dict(
            "sys.modules",
            {
                "azure": MagicMock(),
                "azure.storage": MagicMock(),
                "azure.storage.blob": mock_azure_module,
            },
        ):
            with patch.dict(
                os.environ,
                {
                    "FIXOPS_AZURE_CONTAINER": "test-container",
                    "AZURE_STORAGE_CONNECTION_STRING": "DefaultEndpointsProtocol=https;AccountName=test",
                    "FIXOPS_AZURE_SKIP_VALIDATION": "true",
                },
            ):
                backend = AzureImmutableBlobBackend()
                backend._container_client = None  # Reset to trigger lazy init

                # Access the container_client property
                client = backend.container_client

                # Verify BlobServiceClient.from_connection_string was called
                mock_azure_module.BlobServiceClient.from_connection_string.assert_called_once()
                assert client == mock_container

    def test_container_client_with_account_credentials(self):
        """Test container_client property with account name and key.

        Covers lines 852-866, 872 in storage_backends.py.
        """
        mock_blob_service = MagicMock()
        mock_container = MagicMock()
        mock_blob_service.get_container_client.return_value = mock_container

        # Create mock azure module
        mock_azure_module = MagicMock()
        mock_azure_module.BlobServiceClient.return_value = mock_blob_service

        with patch.dict(
            "sys.modules",
            {
                "azure": MagicMock(),
                "azure.storage": MagicMock(),
                "azure.storage.blob": mock_azure_module,
            },
        ):
            with patch.dict(
                os.environ,
                {
                    "FIXOPS_AZURE_CONTAINER": "test-container",
                    "AZURE_STORAGE_ACCOUNT_NAME": "testaccount",
                    "AZURE_STORAGE_ACCOUNT_KEY": "testkey123",
                    "FIXOPS_AZURE_SKIP_VALIDATION": "true",
                },
            ):
                # Clear connection string to force account credentials path
                os.environ.pop("AZURE_STORAGE_CONNECTION_STRING", None)

                backend = AzureImmutableBlobBackend()
                backend._container_client = None  # Reset to trigger lazy init
                backend.connection_string = None  # Force account credentials path

                # Access the container_client property
                client = backend.container_client

                # Verify BlobServiceClient was called with account URL
                mock_azure_module.BlobServiceClient.assert_called_once()
                call_kwargs = mock_azure_module.BlobServiceClient.call_args.kwargs
                assert "testaccount" in call_kwargs.get("account_url", "")
                assert client == mock_container

    def test_container_client_missing_credentials_raises(self):
        """Test container_client raises ConfigurationError when credentials missing.

        Covers lines 855-859 in storage_backends.py.
        """
        mock_azure_module = MagicMock()

        with patch.dict(
            "sys.modules",
            {
                "azure": MagicMock(),
                "azure.storage": MagicMock(),
                "azure.storage.blob": mock_azure_module,
            },
        ):
            with patch.dict(
                os.environ,
                {
                    "FIXOPS_AZURE_CONTAINER": "test-container",
                    "FIXOPS_AZURE_SKIP_VALIDATION": "true",
                },
                clear=True,
            ):
                # Ensure no credentials are set
                os.environ.pop("AZURE_STORAGE_CONNECTION_STRING", None)
                os.environ.pop("AZURE_STORAGE_ACCOUNT_NAME", None)
                os.environ.pop("AZURE_STORAGE_ACCOUNT_KEY", None)

                backend = AzureImmutableBlobBackend()
                backend._container_client = None  # Reset to trigger lazy init
                backend.connection_string = None  # Force account credentials path

                # Access the container_client property should raise
                with pytest.raises(ConfigurationError) as exc_info:
                    _ = backend.container_client
                assert "Azure credentials not configured" in str(exc_info.value)

    def test_container_client_import_error_raises(self):
        """Test container_client raises ConfigurationError when azure SDK not installed.

        Covers lines 867-871 in storage_backends.py.
        """
        with patch.dict(
            os.environ,
            {
                "FIXOPS_AZURE_CONTAINER": "test-container",
                "AZURE_STORAGE_CONNECTION_STRING": "test-connection",
                "FIXOPS_AZURE_SKIP_VALIDATION": "true",
            },
        ):
            # Create backend first
            with patch.dict(
                "sys.modules",
                {
                    "azure": MagicMock(),
                    "azure.storage": MagicMock(),
                    "azure.storage.blob": MagicMock(),
                },
            ):
                backend = AzureImmutableBlobBackend()
                backend._container_client = None  # Reset to trigger lazy init

            # Now simulate ImportError when accessing container_client
            def raise_import_error(*args, **kwargs):
                raise ImportError("No module named 'azure'")

            with patch("builtins.__import__", side_effect=raise_import_error):
                with pytest.raises(ConfigurationError) as exc_info:
                    _ = backend.container_client
                assert "azure-storage-blob library required" in str(exc_info.value)
