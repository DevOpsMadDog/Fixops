"""Placeholder module to ensure metadata imports succeed in tests."""

from __future__ import annotations

from sqlalchemy import Column, DateTime, Integer, String

from src.models.base_sqlite import Base


class SecurityEvent(Base):
    """Tiny stub representing a security event for metadata creation."""

    __tablename__ = "security_events"

    id = Column(Integer, primary_key=True)
    service_name = Column(String(255))
    description = Column(String(1024))
    created_at = Column(DateTime)
