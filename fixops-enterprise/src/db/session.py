"""Lightweight database session facade used by demo services."""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncGenerator, Protocol


class AsyncSession(Protocol):  # pragma: no cover - structural hint
    async def execute(self, *args, **kwargs):
        ...

    async def commit(self) -> None:
        ...

    async def rollback(self) -> None:
        ...

    async def close(self) -> None:
        ...


class DatabaseManager:
    """Placeholder database manager for environments without a real SQL backend."""

    @classmethod
    async def initialize(cls) -> None:
        """Initialize database resources (no-op in demo profile)."""

    @classmethod
    async def close(cls) -> None:
        """Release database resources (no-op in demo profile)."""

    @classmethod
    @asynccontextmanager
    async def get_session_context(cls) -> AsyncGenerator[AsyncSession, None]:
        """Provide an async session context; raises unless user overrides."""

        raise RuntimeError(
            "Database access is not configured in this profile. "
            "Override DatabaseManager.get_session_context during tests or "
            "provide a real implementation in production."
        )


async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency stub mirroring the enterprise interface."""

    async with DatabaseManager.get_session_context() as session:
        yield session
