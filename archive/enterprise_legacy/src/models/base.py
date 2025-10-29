"""
Base model with common fields and enterprise patterns
"""

import uuid
from datetime import datetime
from typing import Any, Dict, Optional

import structlog
from sqlalchemy import JSON, Boolean, Column, DateTime, String, text
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import Mapped, mapped_column

logger = structlog.get_logger()

Base = declarative_base()


class BaseModel(Base):
    """Base model with common enterprise fields and functionality"""

    __abstract__ = True

    # Primary key as UUID for security and scalability
    id: Mapped[str] = mapped_column(
        UUID(as_uuid=False),
        primary_key=True,
        default=lambda: str(uuid.uuid4()),
        unique=True,
        nullable=False,
    )

    # Audit fields for compliance
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("CURRENT_TIMESTAMP"),
        nullable=False,
    )

    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        server_default=text("CURRENT_TIMESTAMP"),
        onupdate=text("CURRENT_TIMESTAMP"),
        nullable=False,
    )

    # Soft delete for data retention compliance
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Version tracking for optimistic locking
    version: Mapped[int] = mapped_column(default=1, nullable=False)

    # Metadata for extensibility
    metadata_: Mapped[Optional[Dict[str, Any]]] = mapped_column(
        "metadata", JSON, nullable=True
    )

    def to_dict(self) -> Dict[str, Any]:
        """Convert model to dictionary for API responses"""
        result = {}
        for column in self.__table__.columns:
            value = getattr(self, column.name)
            if isinstance(value, datetime):
                value = value.isoformat()
            result[column.name] = value
        return result

    def update_from_dict(self, data: Dict[str, Any]) -> None:
        """Update model from dictionary with validation"""
        for key, value in data.items():
            if hasattr(self, key) and key not in ["id", "created_at", "updated_at"]:
                setattr(self, key, value)

        # Increment version for optimistic locking
        self.version += 1

    @classmethod
    def get_table_name(cls) -> str:
        """Get table name for this model"""
        return cls.__tablename__

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}(id={self.id})>"


class AuditMixin:
    """Mixin for enhanced audit logging"""

    # Track who created/modified the record
    created_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    modified_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    # IP address tracking for security
    created_from_ip: Mapped[Optional[str]] = mapped_column(
        String(45), nullable=True  # IPv6 compatible
    )

    modified_from_ip: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)


class SoftDeleteMixin:
    """Mixin for soft delete functionality"""

    deleted_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    deleted_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    def soft_delete(self, deleted_by: str) -> None:
        """Perform soft delete"""
        self.is_active = False
        self.deleted_at = datetime.utcnow()
        self.deleted_by = deleted_by

    def restore(self) -> None:
        """Restore from soft delete"""
        self.is_active = True
        self.deleted_at = None
        self.deleted_by = None


class EncryptedFieldMixin:
    """Mixin for handling encrypted sensitive fields"""

    def set_encrypted_field(self, field_name: str, value: str) -> None:
        """Set encrypted field using SecurityManager"""
        from src.core.security import SecurityManager

        encrypted_value = SecurityManager.encrypt_sensitive_data(value)
        setattr(self, field_name, encrypted_value)

    def get_encrypted_field(self, field_name: str) -> Optional[str]:
        """Get decrypted field value"""
        from src.core.security import SecurityManager

        encrypted_value = getattr(self, field_name)
        if encrypted_value:
            return SecurityManager.decrypt_sensitive_data(encrypted_value)
        return None
