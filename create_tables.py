#!/usr/bin/env python3
"""
Simple script to create database tables for FixOps Enterprise
"""

import asyncio
import sys
from pathlib import Path

# Add project to path
sys.path.insert(0, str(Path(__file__).parent / "fixops-blended-enterprise"))

from src.db.session import DatabaseManager
from src.models.base_sqlite import Base

async def create_tables():
    """Create all database tables"""
    print("🔧 Creating database tables...")
    
    try:
        # Initialize database manager
        await DatabaseManager.initialize()
        
        # Create all tables
        async with DatabaseManager._engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
        
        print("✅ Database tables created successfully!")
        
        # Test database connection
        health = await DatabaseManager.health_check()
        print(f"✅ Database health check: {'OK' if health else 'FAILED'}")
        
    except Exception as e:
        print(f"❌ Failed to create tables: {str(e)}")
        return False
    finally:
        await DatabaseManager.close()
    
    return True

if __name__ == "__main__":
    success = asyncio.run(create_tables())
    sys.exit(0 if success else 1)