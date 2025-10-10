#!/usr/bin/env python3
"""
Create default admin user for FixOps Enterprise
"""

import asyncio
import bcrypt
from datetime import datetime
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession

from src.models.user_sqlite import User, UserRole, UserStatus

async def create_admin_user():
    """Create default admin user"""
    try:
        # Create async engine
        engine = create_async_engine("sqlite+aiosqlite:///fixops_enterprise.db")
        
        # Hash password
        password_hash = bcrypt.hashpw("admin123".encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        
        async with AsyncSession(engine) as session:
            # Check if admin user already exists
            existing_user = await session.get(User, "admin-user-001")
            if existing_user:
                print("✅ Admin user already exists")
                return True
            
            # Create admin user
            admin_user = User(
                id="admin-user-001",
                email="admin@core.dev",
                username="admin",
                first_name="System",
                last_name="Administrator", 
                password_hash=password_hash,
                status=UserStatus.ACTIVE.value,
                email_verified=True,
                created_at=datetime.utcnow(),
                updated_at=datetime.utcnow()
            )
            
            # Set admin roles
            admin_user.set_roles([
                UserRole.ADMIN.value,
                UserRole.SECURITY_ANALYST.value,
                UserRole.COMPLIANCE_OFFICER.value
            ])
            
            session.add(admin_user)
            await session.commit()
            
            print("✅ Admin user created successfully!")
            print("   Email: admin@core.dev")
            print("   Password: admin123")
            print(f"   Roles: {admin_user.get_roles()}")
        
        await engine.dispose()
        return True
        
    except Exception as e:
        print(f"❌ Failed to create admin user: {str(e)}")
        return False

if __name__ == "__main__":
    print("🔧 Creating default admin user...")
    success = asyncio.run(create_admin_user())
    if success:
        print("✅ Admin user setup complete!")
    else:
        print("❌ Admin user setup failed!")
        exit(1)