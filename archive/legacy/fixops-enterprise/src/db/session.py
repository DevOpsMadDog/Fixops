"""Enterprise-grade async database session management with SQLAlchemy.

This module provides production-ready database connectivity with:
- Async SQLAlchemy session management
- Connection pooling with configurable limits
- Health checks and connection validation
- Transaction management with automatic rollback
- Query logging and metrics
- Support for multiple database backends (PostgreSQL, SQLite)
"""

from __future__ import annotations

import asyncio
import logging
import os
import time
from contextlib import asynccontextmanager
from typing import Any, AsyncGenerator, Dict, List, Optional, Protocol, Type, TypeVar

from sqlalchemy import event, text
from sqlalchemy.ext.asyncio import AsyncEngine
from sqlalchemy.ext.asyncio import AsyncSession as SQLAlchemyAsyncSession
from sqlalchemy.ext.asyncio import async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase
from sqlalchemy.pool import NullPool, QueuePool

logger = logging.getLogger(__name__)

T = TypeVar("T", bound="Base")


class Base(DeclarativeBase):
    """Base class for all SQLAlchemy models."""

    pass


class AsyncSession(Protocol):
    """Protocol for async database sessions."""

    async def execute(self, *args: Any, **kwargs: Any) -> Any:
        """Execute a SQL statement."""
        ...

    async def commit(self) -> None:
        """Commit the current transaction."""
        ...

    async def rollback(self) -> None:
        """Rollback the current transaction."""
        ...

    async def close(self) -> None:
        """Close the session."""
        ...

    async def refresh(self, instance: Any) -> None:
        """Refresh an instance from the database."""
        ...

    def add(self, instance: Any) -> None:
        """Add an instance to the session."""
        ...

    def add_all(self, instances: List[Any]) -> None:
        """Add multiple instances to the session."""
        ...

    async def delete(self, instance: Any) -> None:
        """Delete an instance from the database."""
        ...

    async def get(self, entity: Type[T], ident: Any) -> Optional[T]:
        """Get an instance by primary key."""
        ...


class DatabaseConfig:
    """Database configuration with environment variable support."""

    def __init__(
        self,
        url: Optional[str] = None,
        pool_size: int = 5,
        max_overflow: int = 10,
        pool_timeout: float = 30.0,
        pool_recycle: int = 1800,
        echo: bool = False,
        echo_pool: bool = False,
    ):
        """Initialize database configuration.

        Args:
            url: Database URL (defaults to env var FIXOPS_DATABASE_URL)
            pool_size: Number of connections to keep in the pool
            max_overflow: Maximum overflow connections above pool_size
            pool_timeout: Seconds to wait for a connection from pool
            pool_recycle: Seconds before recycling a connection
            echo: Log all SQL statements
            echo_pool: Log pool checkouts/checkins
        """
        self.url = url or os.environ.get(
            "FIXOPS_DATABASE_URL", "sqlite+aiosqlite:///./data/fixops.db"
        )
        self.pool_size = int(os.environ.get("FIXOPS_DB_POOL_SIZE", pool_size))
        self.max_overflow = int(os.environ.get("FIXOPS_DB_MAX_OVERFLOW", max_overflow))
        self.pool_timeout = float(
            os.environ.get("FIXOPS_DB_POOL_TIMEOUT", pool_timeout)
        )
        self.pool_recycle = int(os.environ.get("FIXOPS_DB_POOL_RECYCLE", pool_recycle))
        self.echo = os.environ.get("FIXOPS_DB_ECHO", str(echo)).lower() == "true"
        self.echo_pool = (
            os.environ.get("FIXOPS_DB_ECHO_POOL", str(echo_pool)).lower() == "true"
        )

    @property
    def is_sqlite(self) -> bool:
        """Check if using SQLite backend."""
        return "sqlite" in self.url.lower()

    @property
    def is_postgres(self) -> bool:
        """Check if using PostgreSQL backend."""
        return "postgresql" in self.url.lower() or "postgres" in self.url.lower()


class DatabaseMetrics:
    """Database metrics for monitoring."""

    def __init__(self) -> None:
        self.total_queries = 0
        self.total_sessions_succeeded = 0
        self.total_rollbacks = 0
        self.total_errors = 0
        self.active_connections = 0
        self.pool_checkouts = 0
        self.pool_checkins = 0
        self.slow_queries: List[Dict[str, Any]] = []
        self.slow_query_threshold_ms = 100.0

    def record_query(self, duration_ms: float, query: str) -> None:
        """Record a query execution."""
        self.total_queries += 1
        if duration_ms > self.slow_query_threshold_ms:
            self.slow_queries.append(
                {
                    "query": query[:200],  # Truncate for safety
                    "duration_ms": duration_ms,
                    "timestamp": time.time(),
                }
            )
            # Keep only last 100 slow queries
            if len(self.slow_queries) > 100:
                self.slow_queries = self.slow_queries[-100:]

    def to_dict(self) -> Dict[str, Any]:
        """Convert metrics to dictionary."""
        return {
            "total_queries": self.total_queries,
            "total_sessions_succeeded": self.total_sessions_succeeded,
            "total_rollbacks": self.total_rollbacks,
            "total_errors": self.total_errors,
            "active_connections": self.active_connections,
            "pool_checkouts": self.pool_checkouts,
            "pool_checkins": self.pool_checkins,
            "slow_query_count": len(self.slow_queries),
        }


class DatabaseManager:
    """Production-ready async database manager with connection pooling.

    Features:
    - Async SQLAlchemy engine and session management
    - Connection pooling with health checks
    - Transaction management with automatic rollback
    - Query logging and metrics collection
    - Support for PostgreSQL and SQLite
    """

    _engine: Optional[AsyncEngine] = None
    _session_factory: Optional[async_sessionmaker[SQLAlchemyAsyncSession]] = None
    _config: Optional[DatabaseConfig] = None
    _metrics: DatabaseMetrics = DatabaseMetrics()
    _initialized: bool = False
    _lock: asyncio.Lock = asyncio.Lock()

    @classmethod
    async def initialize(
        cls,
        config: Optional[DatabaseConfig] = None,
        create_tables: bool = True,
    ) -> None:
        """Initialize database engine and session factory.

        Args:
            config: Database configuration (uses defaults if not provided)
            create_tables: Whether to create tables on initialization
        """
        async with cls._lock:
            if cls._initialized:
                logger.debug("Database already initialized")
                return

            cls._config = config or DatabaseConfig()

            # Configure engine based on database type
            engine_kwargs: Dict[str, Any] = {
                "echo": cls._config.echo,
            }

            if cls._config.is_sqlite:
                # SQLite doesn't support connection pooling well
                engine_kwargs["poolclass"] = NullPool
                # Ensure directory exists for SQLite
                if ":///" in cls._config.url:
                    db_path = cls._config.url.split(":///")[-1]
                    if db_path and db_path != ":memory:":
                        import os

                        os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
            else:
                # PostgreSQL and other databases use connection pooling
                engine_kwargs.update(
                    {
                        "poolclass": QueuePool,
                        "pool_size": cls._config.pool_size,
                        "max_overflow": cls._config.max_overflow,
                        "pool_timeout": cls._config.pool_timeout,
                        "pool_recycle": cls._config.pool_recycle,
                        "pool_pre_ping": True,  # Validate connections before use
                    }
                )

            try:
                cls._engine = create_async_engine(cls._config.url, **engine_kwargs)

                # Set up event listeners for metrics
                if not cls._config.is_sqlite:

                    @event.listens_for(cls._engine.sync_engine, "checkout")
                    def on_checkout(
                        dbapi_conn: Any, connection_record: Any, connection_proxy: Any
                    ) -> None:
                        cls._metrics.pool_checkouts += 1
                        cls._metrics.active_connections += 1

                    @event.listens_for(cls._engine.sync_engine, "checkin")
                    def on_checkin(dbapi_conn: Any, connection_record: Any) -> None:
                        cls._metrics.pool_checkins += 1
                        cls._metrics.active_connections -= 1

                cls._session_factory = async_sessionmaker(
                    cls._engine,
                    class_=SQLAlchemyAsyncSession,
                    expire_on_commit=False,
                    autoflush=False,
                )

                # Create tables if requested
                if create_tables:
                    async with cls._engine.begin() as conn:
                        await conn.run_sync(Base.metadata.create_all)

                cls._initialized = True
                logger.info(
                    f"Database initialized: {cls._config.url.split('@')[-1] if '@' in cls._config.url else cls._config.url}"
                )

            except Exception as e:
                logger.error(f"Failed to initialize database: {e}")
                cls._metrics.total_errors += 1
                raise

    @classmethod
    async def close(cls) -> None:
        """Close database engine and release all connections."""
        async with cls._lock:
            if cls._engine is not None:
                await cls._engine.dispose()
                cls._engine = None
                cls._session_factory = None
                cls._initialized = False
                logger.info("Database connections closed")

    @classmethod
    @asynccontextmanager
    async def get_session_context(cls) -> AsyncGenerator[SQLAlchemyAsyncSession, None]:
        """Provide an async session context with automatic transaction management.

        Usage:
            async with DatabaseManager.get_session_context() as session:
                result = await session.execute(select(User))
                await session.commit()

        Yields:
            SQLAlchemy async session

        Raises:
            RuntimeError: If database is not initialized
        """
        if not cls._initialized or cls._session_factory is None:
            # Auto-initialize with defaults
            await cls.initialize()

        if cls._session_factory is None:
            raise RuntimeError("Database session factory not available")

        session = cls._session_factory()
        try:
            yield session
            cls._metrics.total_sessions_succeeded += 1
        except Exception as e:
            await session.rollback()
            cls._metrics.total_rollbacks += 1
            cls._metrics.total_errors += 1
            logger.error(f"Database session error, rolled back: {e}")
            raise
        finally:
            await session.close()

    @classmethod
    async def health_check(cls) -> Dict[str, Any]:
        """Check database health and return status.

        Returns:
            Health status dictionary with connection info
        """
        if not cls._initialized or cls._engine is None:
            return {
                "healthy": False,
                "error": "Database not initialized",
            }

        try:
            async with cls._engine.connect() as conn:
                start = time.time()
                await conn.execute(text("SELECT 1"))
                latency_ms = (time.time() - start) * 1000

                return {
                    "healthy": True,
                    "latency_ms": latency_ms,
                    "database_type": "sqlite"
                    if cls._config and cls._config.is_sqlite
                    else "postgresql",
                    "metrics": cls._metrics.to_dict(),
                }
        except Exception as e:
            return {
                "healthy": False,
                "error": str(e),
            }

    @classmethod
    def get_metrics(cls) -> Dict[str, Any]:
        """Get database metrics for monitoring."""
        return cls._metrics.to_dict()

    @classmethod
    async def execute_raw(
        cls, query: str, params: Optional[Dict[str, Any]] = None
    ) -> Any:
        """Execute a raw SQL query.

        Args:
            query: SQL query string
            params: Query parameters

        Returns:
            Query result
        """
        if not cls._initialized or cls._engine is None:
            await cls.initialize()

        if cls._engine is None:
            raise RuntimeError("Database engine not available")

        start = time.time()
        try:
            async with cls._engine.connect() as conn:
                if params:
                    result = await conn.execute(text(query), params)
                else:
                    result = await conn.execute(text(query))
                await conn.commit()

                duration_ms = (time.time() - start) * 1000
                cls._metrics.record_query(duration_ms, query)

                return result
        except Exception:
            cls._metrics.total_errors += 1
            raise


async def get_db() -> AsyncGenerator[SQLAlchemyAsyncSession, None]:
    """FastAPI dependency for database sessions.

    Usage in FastAPI:
        @app.get("/users")
        async def get_users(db: AsyncSession = Depends(get_db)):
            result = await db.execute(select(User))
            return result.scalars().all()

    Yields:
        SQLAlchemy async session
    """
    async with DatabaseManager.get_session_context() as session:
        yield session


async def init_db(config: Optional[DatabaseConfig] = None) -> None:
    """Initialize database (convenience function).

    Args:
        config: Optional database configuration
    """
    await DatabaseManager.initialize(config)


async def close_db() -> None:
    """Close database connections (convenience function)."""
    await DatabaseManager.close()


__all__ = [
    "AsyncSession",
    "Base",
    "DatabaseConfig",
    "DatabaseManager",
    "DatabaseMetrics",
    "get_db",
    "init_db",
    "close_db",
]
