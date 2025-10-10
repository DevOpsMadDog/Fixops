#!/usr/bin/env python3
"""
Run database migrations for FixOps Enterprise
"""

import os
import sys
from pathlib import Path
import subprocess

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))
os.chdir(project_root)

def run_migrations():
    """Run Alembic migrations"""
    
    print("🚀 Running FixOps Enterprise Database Migrations...")
    
    try:
        # Check if alembic is available
        result = subprocess.run(["alembic", "--version"], capture_output=True, text=True)
        if result.returncode != 0:
            print("❌ Alembic not found. Please install with: pip install alembic")
            return False
        
        print(f"✅ Using Alembic {result.stdout.strip()}")
        
        # Run migrations
        print("📋 Running database migrations...")
        result = subprocess.run(
            ["alembic", "upgrade", "head"],
            capture_output=True,
            text=True,
            cwd=project_root
        )
        
        if result.returncode == 0:
            print("✅ Database migrations completed successfully!")
            print(result.stdout)
            return True
        else:
            print("❌ Migration failed!")
            print(result.stderr)
            return False
            
    except Exception as e:
        print(f"❌ Error running migrations: {str(e)}")
        return False

if __name__ == "__main__":
    success = run_migrations()
    sys.exit(0 if success else 1)