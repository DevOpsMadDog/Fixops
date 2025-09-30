"""
Enterprise database session management with connection pooling and performance optimization
"""

import asyncio
from typing import Optional, AsyncGenerator
import structlog
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.pool import QueuePool
from sqlalchemy import event, text
from contextlib import asynccontextmanager

from src.config.settings import get_settings

logger = structlog.get_logger()
settings = get_settings()


class DatabaseManager:
    """Enterprise database manager with connection pooling and health monitoring"""
    
    _engine = None
    _sessionmaker = None
    
    @classmethod
    async def initialize(cls):
        """Initialize database engine with enterprise configuration"""
        if cls._engine is not None:
            return
        
        # Create async engine with performance optimizations
        cls._engine = create_async_engine(
            settings.DATABASE_URL,
            # Connection pooling for high performance
            poolclass=QueuePool,
            pool_size=settings.DATABASE_POOL_SIZE,
            max_overflow=settings.DATABASE_MAX_OVERFLOW,
            pool_timeout=settings.DATABASE_POOL_TIMEOUT,
            pool_recycle=3600,  # Recycle connections every hour
            pool_pre_ping=True,  # Validate connections before use
            # Performance optimizations
            echo=settings.DEBUG,  # Only log SQL in debug mode
            echo_pool=settings.DEBUG,
            future=True,
            # Connection optimization (conditional based on database type)
            connect_args={} if "sqlite" in settings.DATABASE_URL else {
                "server_settings": {
                    "application_name": "fixops-enterprise",
                    "jit": "off",  # Disable JIT for consistent performance
                }
            }
        )
        
        # Create session factory
        cls._sessionmaker = async_sessionmaker(
            cls._engine,
            class_=AsyncSession,
            expire_on_commit=False,
            autoflush=True,
            autocommit=False
        )
        
        # Set up connection event handlers
        cls._setup_event_handlers()
        
        logger.info(
            "Database engine initialized",
            pool_size=settings.DATABASE_POOL_SIZE,
            max_overflow=settings.DATABASE_MAX_OVERFLOW
        )
    
    @classmethod
    def _setup_event_handlers(cls):
        """Setup database event handlers for monitoring and optimization"""
        
        @event.listens_for(cls._engine.sync_engine, "connect")
        def set_sqlite_pragma(dbapi_connection, connection_record):
            """Set database connection parameters for performance"""
            if "postgresql" in settings.DATABASE_URL:
                # PostgreSQL optimizations
                with dbapi_connection.cursor() as cursor:
                    # Set session-level optimizations
                    cursor.execute("SET statement_timeout = '30s'")
                    cursor.execute("SET lock_timeout = '10s'")
                    cursor.execute("SET idle_in_transaction_session_timeout = '60s'")
        
        @event.listens_for(cls._engine.sync_engine, "checkout")
        def log_connection_checkout(dbapi_connection, connection_record, connection_proxy):
            """Log connection checkout for monitoring"""
            logger.debug("Database connection checked out")
        
        @event.listens_for(cls._engine.sync_engine, "checkin")
        def log_connection_checkin(dbapi_connection, connection_record):
            """Log connection checkin for monitoring"""
            logger.debug("Database connection checked in")
    
    @classmethod
    async def get_session(cls) -> AsyncSession:
        """Get database session from pool"""
        if cls._sessionmaker is None:
            await cls.initialize()
        
        return cls._sessionmaker()
    
    @classmethod
    @asynccontextmanager
    async def get_session_context(cls) -> AsyncGenerator[AsyncSession, None]:
        """Get database session with automatic cleanup"""
        session = await cls.get_session()
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise
        finally:
            await session.close()
    
    @classmethod
    async def health_check(cls) -> bool:
        """Health check for database connectivity"""
        if cls._engine is None:
            return False
        
        try:
            async with cls.get_session_context() as session:
                result = await session.execute(text("SELECT 1"))
                return result.scalar() == 1
        except Exception as e:
            logger.error(f"Database health check failed: {str(e)}")
            return False
    
    @classmethod
    async def close(cls):
        """Close database engine and cleanup connections"""
        if cls._engine:
            await cls._engine.dispose()
            cls._engine = None
            cls._sessionmaker = None
            logger.info("Database engine closed")


# FastAPI dependency for database sessions
async def get_db() -> AsyncGenerator[AsyncSession, None]:
    """FastAPI dependency to get database session"""
    async with DatabaseManager.get_session_context() as session:
        yield session