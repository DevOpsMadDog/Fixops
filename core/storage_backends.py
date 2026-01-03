"""Enterprise storage backends for WORM-compliant evidence persistence.

This module provides abstract storage backend interfaces and concrete implementations
for enterprise-grade evidence storage with immutability guarantees.

Supported backends:
- LocalFileBackend: Local filesystem storage (default)
- S3ObjectLockBackend: AWS S3 with Object Lock for WORM compliance
- AzureImmutableBlobBackend: Azure Blob Storage with immutability policies

Phase 3 Implementation - Enterprise Storage
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from typing import Any, BinaryIO, Dict, List, Mapping, Optional, Union

logger = logging.getLogger(__name__)


class RetentionMode(Enum):
    """Retention mode for WORM-compliant storage."""

    GOVERNANCE = "governance"
    COMPLIANCE = "compliance"


class StorageError(Exception):
    """Base exception for storage backend errors."""


class RetentionViolationError(StorageError):
    """Raised when attempting to modify or delete retained objects."""


class ObjectNotFoundError(StorageError):
    """Raised when an object is not found in storage."""


class ConfigurationError(StorageError):
    """Raised when storage backend is misconfigured."""


@dataclass
class RetentionPolicy:
    """Configuration for object retention in WORM-compliant storage."""

    mode: RetentionMode = RetentionMode.GOVERNANCE
    retain_until_days: int = 2555
    legal_hold: bool = False

    def retain_until_date(self) -> datetime:
        return datetime.now(timezone.utc) + timedelta(days=self.retain_until_days)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "mode": self.mode.value,
            "retain_until_days": self.retain_until_days,
            "retain_until_date": self.retain_until_date().isoformat(),
            "legal_hold": self.legal_hold,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "RetentionPolicy":
        mode_str = data.get("mode", "governance")
        mode = RetentionMode(mode_str) if mode_str else RetentionMode.GOVERNANCE
        return cls(
            mode=mode,
            retain_until_days=int(data.get("retain_until_days", 2555)),
            legal_hold=bool(data.get("legal_hold", False)),
        )

    @classmethod
    def from_env(cls) -> "RetentionPolicy":
        mode_str = os.getenv("FIXOPS_RETENTION_MODE", "governance").lower()
        mode = (
            RetentionMode.COMPLIANCE
            if mode_str == "compliance"
            else RetentionMode.GOVERNANCE
        )
        return cls(
            mode=mode,
            retain_until_days=int(os.getenv("FIXOPS_RETENTION_DAYS", "2555")),
            legal_hold=os.getenv("FIXOPS_LEGAL_HOLD", "").lower()
            in ("true", "1", "yes"),
        )


@dataclass
class StorageMetadata:
    """Metadata for stored objects."""

    object_id: str
    path: str
    size_bytes: int
    sha256: str
    content_type: str = "application/octet-stream"
    created_at: str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )
    retention_policy: Optional[RetentionPolicy] = None
    custom_metadata: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        result = {
            "object_id": self.object_id,
            "path": self.path,
            "size_bytes": self.size_bytes,
            "sha256": self.sha256,
            "content_type": self.content_type,
            "created_at": self.created_at,
            "custom_metadata": self.custom_metadata,
        }
        if self.retention_policy:
            result["retention_policy"] = self.retention_policy.to_dict()
        return result


class StorageBackend(ABC):
    """Abstract base class for storage backends.

    All storage backends must implement these methods to provide
    consistent behavior across different storage systems.
    """

    @abstractmethod
    def put(
        self,
        key: str,
        data: Union[bytes, BinaryIO],
        *,
        content_type: str = "application/octet-stream",
        retention_policy: Optional[RetentionPolicy] = None,
        metadata: Optional[Dict[str, str]] = None,
    ) -> StorageMetadata:
        """Store an object with optional retention policy.

        Args:
            key: Unique identifier for the object
            data: Object content as bytes or file-like object
            content_type: MIME type of the content
            retention_policy: Optional WORM retention settings
            metadata: Optional custom metadata key-value pairs

        Returns:
            StorageMetadata with details about the stored object

        Raises:
            StorageError: If storage operation fails
        """

    @abstractmethod
    def get(self, key: str) -> bytes:
        """Retrieve an object by key.

        Args:
            key: Object identifier

        Returns:
            Object content as bytes

        Raises:
            ObjectNotFoundError: If object does not exist
            StorageError: If retrieval fails
        """

    @abstractmethod
    def get_metadata(self, key: str) -> StorageMetadata:
        """Retrieve metadata for an object.

        Args:
            key: Object identifier

        Returns:
            StorageMetadata for the object

        Raises:
            ObjectNotFoundError: If object does not exist
        """

    @abstractmethod
    def exists(self, key: str) -> bool:
        """Check if an object exists.

        Args:
            key: Object identifier

        Returns:
            True if object exists, False otherwise
        """

    @abstractmethod
    def delete(self, key: str) -> bool:
        """Delete an object if retention policy allows.

        Args:
            key: Object identifier

        Returns:
            True if deleted, False if not found

        Raises:
            RetentionViolationError: If object is under retention
        """

    @abstractmethod
    def list_objects(
        self, prefix: str = "", limit: int = 1000
    ) -> List[StorageMetadata]:
        """List objects with optional prefix filter.

        Args:
            prefix: Optional prefix to filter objects
            limit: Maximum number of objects to return

        Returns:
            List of StorageMetadata for matching objects
        """

    @abstractmethod
    def set_legal_hold(self, key: str, enabled: bool) -> None:
        """Enable or disable legal hold on an object.

        Args:
            key: Object identifier
            enabled: True to enable, False to disable

        Raises:
            ObjectNotFoundError: If object does not exist
        """

    @property
    @abstractmethod
    def backend_type(self) -> str:
        """Return the backend type identifier."""

    def compute_sha256(self, data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()


class LocalFileBackend(StorageBackend):
    """Local filesystem storage backend.

    This backend stores objects on the local filesystem with metadata
    stored in companion JSON files. It simulates WORM compliance by
    tracking retention policies in metadata.

    Note: True WORM compliance requires enterprise storage backends
    like S3 Object Lock or Azure Immutable Blob Storage.
    """

    def __init__(
        self,
        base_path: Union[str, Path],
        *,
        default_retention: Optional[RetentionPolicy] = None,
    ):
        self.base_path = Path(base_path).resolve()
        self.base_path.mkdir(parents=True, exist_ok=True)
        self.default_retention = default_retention
        self._metadata_suffix = ".metadata.json"
        logger.info(f"LocalFileBackend initialized at {self.base_path}")

    @property
    def backend_type(self) -> str:
        return "local"

    def _object_path(self, key: str) -> Path:
        safe_key = key.replace("..", "_").lstrip("/")
        return self.base_path / safe_key

    def _metadata_path(self, key: str) -> Path:
        return self._object_path(key).with_suffix(
            self._object_path(key).suffix + self._metadata_suffix
        )

    def put(
        self,
        key: str,
        data: Union[bytes, BinaryIO],
        *,
        content_type: str = "application/octet-stream",
        retention_policy: Optional[RetentionPolicy] = None,
        metadata: Optional[Dict[str, str]] = None,
    ) -> StorageMetadata:
        if hasattr(data, "read"):
            content = data.read()
        else:
            content = data

        object_path = self._object_path(key)
        object_path.parent.mkdir(parents=True, exist_ok=True)

        if object_path.exists():
            existing_meta = self._load_metadata(key)
            if existing_meta and existing_meta.retention_policy:
                retain_until = datetime.fromisoformat(
                    existing_meta.retention_policy.to_dict()["retain_until_date"]
                )
                if retain_until > datetime.now(timezone.utc):
                    raise RetentionViolationError(
                        f"Object {key} is under retention until {retain_until}"
                    )

        sha256_hash = self.compute_sha256(content)
        object_path.write_bytes(content)

        effective_retention = retention_policy or self.default_retention
        storage_meta = StorageMetadata(
            object_id=str(uuid.uuid4()),
            path=str(object_path),
            size_bytes=len(content),
            sha256=sha256_hash,
            content_type=content_type,
            retention_policy=effective_retention,
            custom_metadata=metadata or {},
        )

        self._save_metadata(key, storage_meta)
        logger.info(f"Stored object {key} ({len(content)} bytes)")
        return storage_meta

    def get(self, key: str) -> bytes:
        object_path = self._object_path(key)
        if not object_path.exists():
            raise ObjectNotFoundError(f"Object not found: {key}")
        return object_path.read_bytes()

    def get_metadata(self, key: str) -> StorageMetadata:
        meta = self._load_metadata(key)
        if meta is None:
            raise ObjectNotFoundError(f"Metadata not found for: {key}")
        return meta

    def exists(self, key: str) -> bool:
        return self._object_path(key).exists()

    def delete(self, key: str) -> bool:
        object_path = self._object_path(key)
        if not object_path.exists():
            return False

        meta = self._load_metadata(key)
        if meta and meta.retention_policy:
            retain_until_str = meta.retention_policy.to_dict().get("retain_until_date")
            if retain_until_str:
                retain_until = datetime.fromisoformat(retain_until_str)
                if retain_until > datetime.now(timezone.utc):
                    if meta.retention_policy.mode == RetentionMode.COMPLIANCE:
                        raise RetentionViolationError(
                            f"Object {key} is under COMPLIANCE retention until {retain_until}"
                        )
                    elif meta.retention_policy.legal_hold:
                        raise RetentionViolationError(
                            f"Object {key} is under legal hold"
                        )

        object_path.unlink()
        metadata_path = self._metadata_path(key)
        if metadata_path.exists():
            metadata_path.unlink()
        logger.info(f"Deleted object {key}")
        return True

    def list_objects(
        self, prefix: str = "", limit: int = 1000
    ) -> List[StorageMetadata]:
        results: List[StorageMetadata] = []
        for path in self.base_path.rglob("*"):
            if path.is_file() and not path.name.endswith(self._metadata_suffix):
                relative = path.relative_to(self.base_path)
                key = str(relative)
                if key.startswith(prefix):
                    meta = self._load_metadata(key)
                    if meta:
                        results.append(meta)
                    if len(results) >= limit:
                        break
        return results

    def set_legal_hold(self, key: str, enabled: bool) -> None:
        meta = self._load_metadata(key)
        if meta is None:
            raise ObjectNotFoundError(f"Object not found: {key}")
        if meta.retention_policy is None:
            meta.retention_policy = RetentionPolicy(legal_hold=enabled)
        else:
            meta.retention_policy.legal_hold = enabled
        self._save_metadata(key, meta)
        logger.info(f"Legal hold {'enabled' if enabled else 'disabled'} for {key}")

    def _save_metadata(self, key: str, meta: StorageMetadata) -> None:
        metadata_path = self._metadata_path(key)
        metadata_path.write_text(json.dumps(meta.to_dict(), indent=2))

    def _load_metadata(self, key: str) -> Optional[StorageMetadata]:
        metadata_path = self._metadata_path(key)
        if not metadata_path.exists():
            return None
        try:
            data = json.loads(metadata_path.read_text())
            retention_data = data.get("retention_policy")
            retention = (
                RetentionPolicy.from_dict(retention_data) if retention_data else None
            )
            return StorageMetadata(
                object_id=data["object_id"],
                path=data["path"],
                size_bytes=data["size_bytes"],
                sha256=data["sha256"],
                content_type=data.get("content_type", "application/octet-stream"),
                created_at=data.get("created_at", ""),
                retention_policy=retention,
                custom_metadata=data.get("custom_metadata", {}),
            )
        except (json.JSONDecodeError, KeyError) as e:
            logger.warning(f"Failed to load metadata for {key}: {e}")
            return None


class S3ObjectLockBackend(StorageBackend):  # pragma: no cover
    """AWS S3 storage backend with Object Lock for WORM compliance.

    This backend uses S3 Object Lock to provide true WORM (Write Once Read Many)
    compliance. Objects can be protected with either Governance or Compliance
    retention modes.

    Requirements:
    - S3 bucket must have Object Lock enabled at creation time
    - Appropriate IAM permissions for Object Lock operations
    - boto3 library must be installed

    Environment variables:
    - AWS_ACCESS_KEY_ID: AWS access key
    - AWS_SECRET_ACCESS_KEY: AWS secret key
    - AWS_REGION: AWS region (default: us-east-1)
    - FIXOPS_S3_BUCKET: S3 bucket name
    - FIXOPS_S3_PREFIX: Optional key prefix
    """

    def __init__(
        self,
        bucket: Optional[str] = None,
        *,
        prefix: str = "",
        region: Optional[str] = None,
        default_retention: Optional[RetentionPolicy] = None,
    ):
        self.bucket = bucket or os.getenv("FIXOPS_S3_BUCKET")
        if not self.bucket:
            raise ConfigurationError(
                "S3 bucket not configured. Set FIXOPS_S3_BUCKET environment variable."
            )
        self.prefix = prefix or os.getenv("FIXOPS_S3_PREFIX", "")
        self.region = region or os.getenv("AWS_REGION", "us-east-1")
        self.default_retention = default_retention or RetentionPolicy.from_env()
        self._client = None
        logger.info(f"S3ObjectLockBackend initialized for bucket {self.bucket}")

    @property
    def backend_type(self) -> str:
        return "s3"

    @property
    def client(self):
        if self._client is None:
            try:
                import boto3

                self._client = boto3.client("s3", region_name=self.region)
            except ImportError:
                raise ConfigurationError(
                    "boto3 library required for S3 backend. Install with: pip install boto3"
                )
        return self._client

    def _full_key(self, key: str) -> str:
        if self.prefix:
            return f"{self.prefix.rstrip('/')}/{key}"
        return key

    def put(
        self,
        key: str,
        data: Union[bytes, BinaryIO],
        *,
        content_type: str = "application/octet-stream",
        retention_policy: Optional[RetentionPolicy] = None,
        metadata: Optional[Dict[str, str]] = None,
    ) -> StorageMetadata:
        if hasattr(data, "read"):
            content = data.read()
        else:
            content = data

        full_key = self._full_key(key)
        sha256_hash = self.compute_sha256(content)
        effective_retention = retention_policy or self.default_retention

        put_args: Dict[str, Any] = {
            "Bucket": self.bucket,
            "Key": full_key,
            "Body": content,
            "ContentType": content_type,
            "Metadata": metadata or {},
            "ChecksumSHA256": sha256_hash,
        }

        if effective_retention:
            put_args["ObjectLockMode"] = effective_retention.mode.value.upper()
            put_args[
                "ObjectLockRetainUntilDate"
            ] = effective_retention.retain_until_date()
            if effective_retention.legal_hold:
                put_args["ObjectLockLegalHoldStatus"] = "ON"

        try:
            self.client.put_object(**put_args)
            logger.info(f"Stored object {full_key} in S3 ({len(content)} bytes)")
        except Exception as e:
            raise StorageError(f"Failed to store object in S3: {e}") from e

        return StorageMetadata(
            object_id=full_key,
            path=f"s3://{self.bucket}/{full_key}",
            size_bytes=len(content),
            sha256=sha256_hash,
            content_type=content_type,
            retention_policy=effective_retention,
            custom_metadata=metadata or {},
        )

    def get(self, key: str) -> bytes:
        full_key = self._full_key(key)
        try:
            response = self.client.get_object(Bucket=self.bucket, Key=full_key)
            return response["Body"].read()
        except self.client.exceptions.NoSuchKey:
            raise ObjectNotFoundError(f"Object not found: {key}")
        except Exception as e:
            raise StorageError(f"Failed to retrieve object from S3: {e}") from e

    def get_metadata(self, key: str) -> StorageMetadata:
        full_key = self._full_key(key)
        try:
            response = self.client.head_object(Bucket=self.bucket, Key=full_key)
            retention_mode = response.get("ObjectLockMode")
            retain_until = response.get("ObjectLockRetainUntilDate")
            legal_hold = response.get("ObjectLockLegalHoldStatus") == "ON"

            retention = None
            if retention_mode or retain_until:
                mode = (
                    RetentionMode.COMPLIANCE
                    if retention_mode == "COMPLIANCE"
                    else RetentionMode.GOVERNANCE
                )
                days = 0
                if retain_until:
                    delta = retain_until - datetime.now(timezone.utc)
                    days = max(0, delta.days)
                retention = RetentionPolicy(
                    mode=mode, retain_until_days=days, legal_hold=legal_hold
                )

            return StorageMetadata(
                object_id=full_key,
                path=f"s3://{self.bucket}/{full_key}",
                size_bytes=response.get("ContentLength", 0),
                sha256=response.get("ChecksumSHA256", ""),
                content_type=response.get("ContentType", "application/octet-stream"),
                created_at=response.get(
                    "LastModified", datetime.now(timezone.utc)
                ).isoformat(),
                retention_policy=retention,
                custom_metadata=response.get("Metadata", {}),
            )
        except self.client.exceptions.NoSuchKey:
            raise ObjectNotFoundError(f"Object not found: {key}")
        except Exception as e:
            raise StorageError(f"Failed to get metadata from S3: {e}") from e

    def exists(self, key: str) -> bool:
        full_key = self._full_key(key)
        try:
            self.client.head_object(Bucket=self.bucket, Key=full_key)
            return True
        except self.client.exceptions.NoSuchKey:
            return False
        except Exception:
            return False

    def delete(self, key: str) -> bool:
        full_key = self._full_key(key)
        try:
            meta = self.get_metadata(key)
            if meta.retention_policy:
                if meta.retention_policy.legal_hold:
                    raise RetentionViolationError(f"Object {key} is under legal hold")
                if meta.retention_policy.mode == RetentionMode.COMPLIANCE:
                    raise RetentionViolationError(
                        f"Object {key} is under COMPLIANCE retention"
                    )
            self.client.delete_object(Bucket=self.bucket, Key=full_key)
            logger.info(f"Deleted object {full_key} from S3")
            return True
        except ObjectNotFoundError:
            return False
        except RetentionViolationError:
            raise
        except Exception as e:
            raise StorageError(f"Failed to delete object from S3: {e}") from e

    def list_objects(
        self, prefix: str = "", limit: int = 1000
    ) -> List[StorageMetadata]:
        full_prefix = self._full_key(prefix) if prefix else self.prefix
        results: List[StorageMetadata] = []
        try:
            paginator = self.client.get_paginator("list_objects_v2")
            for page in paginator.paginate(
                Bucket=self.bucket,
                Prefix=full_prefix,
                PaginationConfig={"MaxItems": limit},
            ):
                for obj in page.get("Contents", []):
                    key = obj["Key"]
                    if self.prefix:
                        key = key[len(self.prefix) :].lstrip("/")
                    try:
                        meta = self.get_metadata(key)
                        results.append(meta)
                    except Exception:
                        pass
        except Exception as e:
            raise StorageError(f"Failed to list objects in S3: {e}") from e
        return results

    def set_legal_hold(self, key: str, enabled: bool) -> None:
        full_key = self._full_key(key)
        try:
            self.client.put_object_legal_hold(
                Bucket=self.bucket,
                Key=full_key,
                LegalHold={"Status": "ON" if enabled else "OFF"},
            )
            logger.info(
                f"Legal hold {'enabled' if enabled else 'disabled'} for {full_key}"
            )
        except self.client.exceptions.NoSuchKey:
            raise ObjectNotFoundError(f"Object not found: {key}")
        except Exception as e:
            raise StorageError(f"Failed to set legal hold: {e}") from e


class AzureImmutableBlobBackend(StorageBackend):  # pragma: no cover
    """Azure Blob Storage backend with immutability policies.

    This backend uses Azure Blob Storage immutability policies to provide
    WORM compliance. Supports both time-based retention and legal holds.

    Requirements:
    - Azure Storage account with immutable blob storage enabled
    - azure-storage-blob library must be installed

    Environment variables:
    - AZURE_STORAGE_CONNECTION_STRING: Azure storage connection string
    - AZURE_STORAGE_ACCOUNT_NAME: Storage account name (alternative)
    - AZURE_STORAGE_ACCOUNT_KEY: Storage account key (alternative)
    - FIXOPS_AZURE_CONTAINER: Container name
    - FIXOPS_AZURE_PREFIX: Optional blob prefix
    """

    def __init__(
        self,
        container: Optional[str] = None,
        *,
        prefix: str = "",
        connection_string: Optional[str] = None,
        default_retention: Optional[RetentionPolicy] = None,
    ):
        self.container = container or os.getenv("FIXOPS_AZURE_CONTAINER")
        if not self.container:
            raise ConfigurationError(
                "Azure container not configured. Set FIXOPS_AZURE_CONTAINER environment variable."
            )
        self.prefix = prefix or os.getenv("FIXOPS_AZURE_PREFIX", "")
        self.connection_string = connection_string or os.getenv(
            "AZURE_STORAGE_CONNECTION_STRING"
        )
        self.default_retention = default_retention or RetentionPolicy.from_env()
        self._client = None
        self._container_client = None
        logger.info(
            f"AzureImmutableBlobBackend initialized for container {self.container}"
        )

    @property
    def backend_type(self) -> str:
        return "azure"

    @property
    def container_client(self):
        if self._container_client is None:
            try:
                from azure.storage.blob import BlobServiceClient

                if self.connection_string:
                    service_client = BlobServiceClient.from_connection_string(
                        self.connection_string
                    )
                else:
                    account_name = os.getenv("AZURE_STORAGE_ACCOUNT_NAME")
                    account_key = os.getenv("AZURE_STORAGE_ACCOUNT_KEY")
                    if not account_name or not account_key:
                        raise ConfigurationError(
                            "Azure credentials not configured. Set AZURE_STORAGE_CONNECTION_STRING "
                            "or AZURE_STORAGE_ACCOUNT_NAME and AZURE_STORAGE_ACCOUNT_KEY."
                        )
                    service_client = BlobServiceClient(
                        account_url=f"https://{account_name}.blob.core.windows.net",
                        credential=account_key,
                    )
                self._container_client = service_client.get_container_client(
                    self.container
                )
            except ImportError:
                raise ConfigurationError(
                    "azure-storage-blob library required for Azure backend. "
                    "Install with: pip install azure-storage-blob"
                )
        return self._container_client

    def _full_key(self, key: str) -> str:
        if self.prefix:
            return f"{self.prefix.rstrip('/')}/{key}"
        return key

    def put(
        self,
        key: str,
        data: Union[bytes, BinaryIO],
        *,
        content_type: str = "application/octet-stream",
        retention_policy: Optional[RetentionPolicy] = None,
        metadata: Optional[Dict[str, str]] = None,
    ) -> StorageMetadata:
        if hasattr(data, "read"):
            content = data.read()
        else:
            content = data

        full_key = self._full_key(key)
        sha256_hash = self.compute_sha256(content)
        effective_retention = retention_policy or self.default_retention

        try:
            from azure.storage.blob import ImmutabilityPolicy

            blob_client = self.container_client.get_blob_client(full_key)
            blob_client.upload_blob(
                content,
                content_type=content_type,
                metadata=metadata,
                overwrite=False,
            )

            if effective_retention:
                immutability_policy = ImmutabilityPolicy(
                    expiry_time=effective_retention.retain_until_date(),
                    policy_mode=(
                        "Unlocked"
                        if effective_retention.mode == RetentionMode.GOVERNANCE
                        else "Locked"
                    ),
                )
                blob_client.set_immutability_policy(immutability_policy)

                if effective_retention.legal_hold:
                    blob_client.set_legal_hold(True)

            logger.info(f"Stored blob {full_key} in Azure ({len(content)} bytes)")
        except Exception as e:
            raise StorageError(f"Failed to store blob in Azure: {e}") from e

        return StorageMetadata(
            object_id=full_key,
            path=f"azure://{self.container}/{full_key}",
            size_bytes=len(content),
            sha256=sha256_hash,
            content_type=content_type,
            retention_policy=effective_retention,
            custom_metadata=metadata or {},
        )

    def get(self, key: str) -> bytes:
        full_key = self._full_key(key)
        try:
            blob_client = self.container_client.get_blob_client(full_key)
            return blob_client.download_blob().readall()
        except Exception as e:
            if "BlobNotFound" in str(e):
                raise ObjectNotFoundError(f"Blob not found: {key}")
            raise StorageError(f"Failed to retrieve blob from Azure: {e}") from e

    def get_metadata(self, key: str) -> StorageMetadata:
        full_key = self._full_key(key)
        try:
            blob_client = self.container_client.get_blob_client(full_key)
            properties = blob_client.get_blob_properties()

            retention = None
            if properties.immutability_policy:
                mode = (
                    RetentionMode.COMPLIANCE
                    if properties.immutability_policy.policy_mode == "Locked"
                    else RetentionMode.GOVERNANCE
                )
                expiry = properties.immutability_policy.expiry_time
                days = 0
                if expiry:
                    delta = expiry - datetime.now(timezone.utc)
                    days = max(0, delta.days)
                retention = RetentionPolicy(
                    mode=mode,
                    retain_until_days=days,
                    legal_hold=properties.has_legal_hold or False,
                )

            return StorageMetadata(
                object_id=full_key,
                path=f"azure://{self.container}/{full_key}",
                size_bytes=properties.size or 0,
                sha256="",
                content_type=properties.content_settings.content_type
                or "application/octet-stream",
                created_at=(
                    properties.creation_time.isoformat()
                    if properties.creation_time
                    else ""
                ),
                retention_policy=retention,
                custom_metadata=dict(properties.metadata or {}),
            )
        except Exception as e:
            if "BlobNotFound" in str(e):
                raise ObjectNotFoundError(f"Blob not found: {key}")
            raise StorageError(f"Failed to get blob metadata from Azure: {e}") from e

    def exists(self, key: str) -> bool:
        full_key = self._full_key(key)
        try:
            blob_client = self.container_client.get_blob_client(full_key)
            blob_client.get_blob_properties()
            return True
        except Exception:
            return False

    def delete(self, key: str) -> bool:
        full_key = self._full_key(key)
        try:
            meta = self.get_metadata(key)
            if meta.retention_policy:
                if meta.retention_policy.legal_hold:
                    raise RetentionViolationError(f"Blob {key} is under legal hold")
                if meta.retention_policy.mode == RetentionMode.COMPLIANCE:
                    raise RetentionViolationError(
                        f"Blob {key} is under COMPLIANCE retention"
                    )
            blob_client = self.container_client.get_blob_client(full_key)
            blob_client.delete_blob()
            logger.info(f"Deleted blob {full_key} from Azure")
            return True
        except ObjectNotFoundError:
            return False
        except RetentionViolationError:
            raise
        except Exception as e:
            raise StorageError(f"Failed to delete blob from Azure: {e}") from e

    def list_objects(
        self, prefix: str = "", limit: int = 1000
    ) -> List[StorageMetadata]:
        full_prefix = self._full_key(prefix) if prefix else self.prefix
        results: List[StorageMetadata] = []
        try:
            blobs = self.container_client.list_blobs(name_starts_with=full_prefix)
            for blob in blobs:
                if len(results) >= limit:
                    break
                key = blob.name
                if self.prefix:
                    key = key[len(self.prefix) :].lstrip("/")
                try:
                    meta = self.get_metadata(key)
                    results.append(meta)
                except Exception:
                    pass
        except Exception as e:
            raise StorageError(f"Failed to list blobs in Azure: {e}") from e
        return results

    def set_legal_hold(self, key: str, enabled: bool) -> None:
        full_key = self._full_key(key)
        try:
            blob_client = self.container_client.get_blob_client(full_key)
            blob_client.set_legal_hold(enabled)
            logger.info(
                f"Legal hold {'enabled' if enabled else 'disabled'} for {full_key}"
            )
        except Exception as e:
            if "BlobNotFound" in str(e):
                raise ObjectNotFoundError(f"Blob not found: {key}")
            raise StorageError(f"Failed to set legal hold: {e}") from e


def create_storage_backend(
    backend_type: Optional[str] = None,
    **kwargs: Any,
) -> StorageBackend:
    """Factory function to create storage backends.

    Args:
        backend_type: Type of backend ('local', 's3', 'azure'). If None,
                     uses FIXOPS_STORAGE_BACKEND environment variable.
        **kwargs: Backend-specific configuration options

    Returns:
        Configured StorageBackend instance

    Raises:
        ConfigurationError: If backend type is unknown or misconfigured
    """
    resolved_backend_type: str = (
        backend_type or os.getenv("FIXOPS_STORAGE_BACKEND", "local") or "local"
    )
    resolved_backend_type = resolved_backend_type.lower()

    if resolved_backend_type == "local":
        base_path: str = str(
            kwargs.get("base_path")
            or os.getenv("FIXOPS_EVIDENCE_PATH", "data/evidence")
            or "data/evidence"
        )
        return LocalFileBackend(
            base_path, **{k: v for k, v in kwargs.items() if k != "base_path"}
        )
    elif resolved_backend_type == "s3":  # pragma: no cover
        return S3ObjectLockBackend(**kwargs)  # pragma: no cover
    elif resolved_backend_type == "azure":  # pragma: no cover
        return AzureImmutableBlobBackend(**kwargs)  # pragma: no cover
    else:
        raise ConfigurationError(
            f"Unknown storage backend type: {resolved_backend_type}"
        )


__all__ = [
    "AzureImmutableBlobBackend",
    "ConfigurationError",
    "LocalFileBackend",
    "ObjectNotFoundError",
    "RetentionMode",
    "RetentionPolicy",
    "RetentionViolationError",
    "S3ObjectLockBackend",
    "StorageBackend",
    "StorageError",
    "StorageMetadata",
    "create_storage_backend",
]
