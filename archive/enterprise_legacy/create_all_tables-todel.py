#!/usr/bin/env python3
"""
Create all database tables using SQLite-compatible models
"""

import asyncio
from sqlalchemy import create_engine
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
import structlog

# Import SQLite-compatible models
from src.models.base_sqlite import Base
from src.models.user_sqlite import User, UserSession, UserAuditLog
from src.models.security_sqlite import (
    Service,
    SecurityFinding,
    FindingCorrelation,
    SecurityIncident,
    PolicyRule,
    PolicyDecisionLog,
    VulnerabilityIntelligence,
    ComplianceEvidence,
)

logger = structlog.get_logger()


async def create_all_tables():
    """Create all database tables"""
    try:
        # Create async engine
        engine = create_async_engine("sqlite+aiosqlite:///fixops_enterprise.db")

        # Create all tables
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)

        logger.info("✅ All database tables created successfully!")

        # Verify tables exist
        async with AsyncSession(engine) as session:
            # Test a simple query
            from sqlalchemy import select, text

            result = await session.execute(
                text("SELECT name FROM sqlite_master WHERE type='table'")
            )
            tables = [row[0] for row in result.fetchall()]
            logger.info(f"📊 Created tables: {', '.join(tables)}")

        await engine.dispose()
        return True

    except Exception as e:
        logger.error(f"❌ Failed to create tables: {str(e)}")
        return False


if __name__ == "__main__":
    print("🔧 Creating all enterprise database tables...")
    success = asyncio.run(create_all_tables())
    if success:
        print("✅ Database setup complete!")
    else:
        print("❌ Database setup failed!")
        exit(1)
