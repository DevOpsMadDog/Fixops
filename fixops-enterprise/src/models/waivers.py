"""KEV waiver model used by the policy API tests."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import Boolean, DateTime, String
from sqlalchemy.orm import Mapped, mapped_column

from src.models.base_sqlite import Base


class KevWaiver(Base):
    """Persisted KEV waiver."""

    __tablename__ = "kev_waivers"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    cve_id: Mapped[str] = mapped_column(String(64), index=True)
    service_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    finding_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    justification: Mapped[str] = mapped_column(String(1024))
    approved_by: Mapped[str] = mapped_column(String(255))
    approved_at: Mapped[datetime] = mapped_column(DateTime(timezone=False))
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=False), index=True)
    change_ticket: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    requested_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    created_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    modified_by: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False), default=lambda: datetime.now(timezone.utc)
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=False), default=lambda: datetime.now(timezone.utc)
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)


def get_kev_waiver_model():
    """Compat helper mirroring the original enterprise module."""

    return KevWaiver


__all__ = ["KevWaiver", "get_kev_waiver_model"]
