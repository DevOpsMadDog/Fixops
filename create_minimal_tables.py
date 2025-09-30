#!/usr/bin/env python3
"""
Create minimal database tables for testing FixOps Enterprise
"""

import asyncio
import sys
from pathlib import Path

# Add project to path
sys.path.insert(0, str(Path(__file__).parent / "fixops-blended-enterprise"))

from src.db.session import DatabaseManager

async def create_minimal_tables():
    """Create minimal database tables for testing"""
    print("🔧 Creating minimal database tables for testing...")
    
    try:
        # Initialize database manager
        await DatabaseManager.initialize()
        
        # Create minimal tables that the CLI health check needs
        async with DatabaseManager._engine.begin() as conn:
            # Create policy_decision_logs table (needed by CLI health check)
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS policy_decision_logs (
                    id TEXT PRIMARY KEY,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1,
                    version INTEGER DEFAULT 1,
                    metadata TEXT,
                    finding_id TEXT,
                    service_id TEXT,
                    policy_rule_id TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    confidence REAL NOT NULL,
                    input_context TEXT NOT NULL,
                    decision_rationale TEXT NOT NULL,
                    execution_time_ms REAL NOT NULL,
                    policy_version TEXT
                )
            """)
            
            # Create policy_rules table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS policy_rules (
                    id TEXT PRIMARY KEY,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1,
                    version INTEGER DEFAULT 1,
                    metadata TEXT,
                    name TEXT UNIQUE NOT NULL,
                    description TEXT NOT NULL,
                    rule_type TEXT NOT NULL,
                    rule_content TEXT NOT NULL,
                    environments TEXT NOT NULL,
                    data_classifications TEXT NOT NULL,
                    scanner_types TEXT,
                    nist_ssdf_controls TEXT,
                    priority INTEGER DEFAULT 100,
                    active BOOLEAN DEFAULT 1,
                    default_decision TEXT NOT NULL,
                    escalation_threshold INTEGER
                )
            """)
            
            # Create finding_correlations table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS finding_correlations (
                    id TEXT PRIMARY KEY,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1,
                    version INTEGER DEFAULT 1,
                    metadata TEXT,
                    finding_id TEXT NOT NULL,
                    correlated_finding_id TEXT NOT NULL,
                    correlation_type TEXT NOT NULL,
                    confidence_score REAL NOT NULL,
                    correlation_reason TEXT NOT NULL
                )
            """)
            
            # Create security_findings table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS security_findings (
                    id TEXT PRIMARY KEY,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1,
                    version INTEGER DEFAULT 1,
                    metadata TEXT,
                    service_id TEXT NOT NULL,
                    scanner_type TEXT NOT NULL,
                    scanner_name TEXT NOT NULL,
                    rule_id TEXT NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    category TEXT NOT NULL,
                    status TEXT DEFAULT 'open',
                    first_seen TIMESTAMP NOT NULL,
                    last_seen TIMESTAMP NOT NULL
                )
            """)
            
            # Create services table
            await conn.execute("""
                CREATE TABLE IF NOT EXISTS services (
                    id TEXT PRIMARY KEY,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    is_active BOOLEAN DEFAULT 1,
                    version INTEGER DEFAULT 1,
                    metadata TEXT,
                    name TEXT NOT NULL,
                    description TEXT,
                    business_capability TEXT NOT NULL,
                    data_classification TEXT NOT NULL,
                    environment TEXT NOT NULL,
                    owner_team TEXT NOT NULL,
                    owner_email TEXT NOT NULL,
                    internet_facing BOOLEAN DEFAULT 0,
                    pci_scope BOOLEAN DEFAULT 0
                )
            """)
        
        print("✅ Minimal database tables created successfully!")
        
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
    success = asyncio.run(create_minimal_tables())
    sys.exit(0 if success else 1)