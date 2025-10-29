#!/usr/bin/env python3
"""
Quick start script for FixOps Enterprise - bypasses alembic for demo
"""

import asyncio
import os
import sys
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

# Set environment
os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///./fixops_enterprise.db"


async def create_tables():
    """Create database tables directly"""
    from datetime import datetime

    from src.core.security import PasswordManager
    from src.db.session import DatabaseManager
    from src.models.base import Base
    from src.models.user import User, UserAuditLog, UserSession

    print("📊 Creating database tables...")

    # Initialize database manager
    await DatabaseManager.initialize()

    # Create all tables
    async with DatabaseManager._engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    print("✅ Database tables created successfully")

    # Create demo admin user
    password_manager = PasswordManager()

    demo_user = User(
        email="admin@core.com",
        username="admin",
        first_name="System",
        last_name="Administrator",
        password_hash=password_manager.hash_password("FixOpsAdmin123!"),
        roles=["admin"],
        status="active",
        email_verified=True,
        mfa_enabled=False,
        failed_login_attempts=0,
        notification_email=True,
        notification_sms=False,
        notification_slack=True,
        department="IT Security",
        job_title="Security Administrator",
        terms_accepted_at=datetime.utcnow(),
        privacy_policy_accepted_at=datetime.utcnow(),
    )

    async with DatabaseManager.get_session_context() as session:
        session.add(demo_user)

    print("✅ Demo admin user created (admin@core.com / FixOpsAdmin123!)")

    await DatabaseManager.close()


async def main():
    """Main function"""
    try:
        await create_tables()

        print(
            """
🎉 FixOps Enterprise Database Ready!

👤 Demo Login Credentials:
   Email: admin@core.com
   Password: FixOpsAdmin123!
   Role: Administrator

🚀 Next steps:
   1. Start the backend: python -m uvicorn src.main:app --host 0.0.0.0 --port 8000 --reload
   2. Start the frontend: cd frontend && yarn dev
   3. Access the platform: http://localhost:3000
        """
        )

    except Exception as e:
        print(f"❌ Error setting up database: {str(e)}")
        import traceback

        traceback.print_exc()


if __name__ == "__main__":
    asyncio.run(main())
