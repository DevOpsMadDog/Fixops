#!/usr/bin/env python3
"""
FixOps Enterprise Demo Data Seeder
Creates realistic enterprise data for testing and demonstration
"""

import asyncio
import os
import sys
from datetime import datetime, timedelta
from pathlib import Path

# Add project root to path
project_root = Path(__file__).parent.parent
sys.path.insert(0, str(project_root))

from src.core.security import PasswordManager
from src.db.session import DatabaseManager
from src.models.user import User, UserRole, UserStatus
from src.utils.crypto import generate_secure_token


async def create_demo_users():
    """Create demo users for different roles"""

    password_manager = PasswordManager()

    demo_users = [
        {
            "email": "admin@core.com",
            "username": "admin",
            "first_name": "System",
            "last_name": "Administrator",
            "password": "FixOpsAdmin123!",
            "roles": ["admin"],
            "status": UserStatus.ACTIVE,
            "email_verified": True,
            "department": "IT Security",
            "job_title": "Security Administrator",
        },
        {
            "email": "analyst@core.com",
            "username": "security_analyst",
            "first_name": "Sarah",
            "last_name": "Chen",
            "password": "SecureAnalyst123!",
            "roles": ["security_analyst"],
            "status": UserStatus.ACTIVE,
            "email_verified": True,
            "department": "Security Operations",
            "job_title": "Senior Security Analyst",
        },
        {
            "email": "operator@core.com",
            "username": "ops_operator",
            "first_name": "Mike",
            "last_name": "Johnson",
            "password": "OpsSecure123!",
            "roles": ["operator"],
            "status": UserStatus.ACTIVE,
            "email_verified": True,
            "department": "DevOps",
            "job_title": "DevOps Engineer",
        },
        {
            "email": "viewer@core.com",
            "username": "security_viewer",
            "first_name": "Emily",
            "last_name": "Rodriguez",
            "password": "ViewSecure123!",
            "roles": ["viewer"],
            "status": UserStatus.ACTIVE,
            "email_verified": True,
            "department": "Compliance",
            "job_title": "Compliance Analyst",
        },
        {
            "email": "compliance@core.com",
            "username": "compliance_officer",
            "first_name": "David",
            "last_name": "Thompson",
            "password": "Compliance123!",
            "roles": ["compliance_officer"],
            "status": UserStatus.ACTIVE,
            "email_verified": True,
            "department": "Risk & Compliance",
            "job_title": "Chief Compliance Officer",
        },
    ]

    created_users = []

    async with DatabaseManager.get_session_context() as session:
        for user_data in demo_users:
            # Hash password
            password_hash = password_manager.hash_password(user_data.pop("password"))

            # Create user
            user = User(
                **user_data,
                password_hash=password_hash,
                notification_email=True,
                notification_sms=False,
                notification_slack=True,
                terms_accepted_at=datetime.utcnow(),
                privacy_policy_accepted_at=datetime.utcnow(),
            )

            session.add(user)
            created_users.append(user)

            print(f"✅ Created user: {user.email} ({', '.join(user.roles)})")

    return created_users


async def main():
    """Main seeder function"""
    print("🚀 Starting FixOps Enterprise Demo Data Seeder...")

    try:
        # Initialize database manager
        await DatabaseManager.initialize()
        print("✅ Database connection established")

        # Create demo users
        users = await create_demo_users()
        print(f"✅ Created {len(users)} demo users")

        print(
            f"""
🎉 Demo Data Seeded Successfully!

📝 Demo User Credentials:
┌─────────────────────────┬──────────────────┬─────────────────────┐
│ Email                   │ Password         │ Role                │
├─────────────────────────┼──────────────────┼─────────────────────┤
│ admin@core.com        │ FixOpsAdmin123!  │ Administrator       │
│ analyst@core.com      │ SecureAnalyst123!│ Security Analyst    │
│ operator@core.com     │ OpsSecure123!    │ Operator            │ 
│ viewer@core.com       │ ViewSecure123!   │ Viewer              │
│ compliance@core.com   │ Compliance123!   │ Compliance Officer  │
└─────────────────────────┴──────────────────┴─────────────────────┘

🔐 All users have:
• Email verification: ✅ Verified
• MFA: ⚙️ Optional (can be enabled in settings)
• Terms: ✅ Accepted

🌐 Access the platform at: http://localhost:3000
        """
        )

    except Exception as e:
        print(f"❌ Error seeding demo data: {str(e)}")
        raise
    finally:
        await DatabaseManager.close()


if __name__ == "__main__":
    asyncio.run(main())
