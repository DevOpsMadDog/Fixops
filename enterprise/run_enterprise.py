#!/usr/bin/env python3
"""
FixOps Enterprise Platform Launcher
Comprehensive startup script for the entire platform
"""

import os
import sys
import time
import asyncio
import subprocess
from pathlib import Path

# Add project to path
project_root = Path(__file__).parent
sys.path.insert(0, str(project_root))

def run_command(cmd, description):
    """Run a command and return success/failure"""
    print(f"🔧 {description}...")
    try:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True, cwd=project_root)
        if result.returncode == 0:
            print(f"✅ {description} completed successfully")
            if result.stdout.strip():
                print(f"   {result.stdout.strip()}")
            return True
        else:
            print(f"❌ {description} failed")
            if result.stderr.strip():
                print(f"   Error: {result.stderr.strip()}")
            return False
    except Exception as e:
        print(f"❌ {description} failed: {str(e)}")
        return False

def check_dependencies():
    """Check if required services are running"""
    print("🔍 Checking system dependencies...")
    
    # Check PostgreSQL
    if not run_command("pg_isready -h localhost -p 5432", "PostgreSQL connectivity check"):
        print("❌ PostgreSQL is not running. Starting...")
        if not run_command("service postgresql start", "Starting PostgreSQL"):
            return False
    
    # Check Redis
    if not run_command("redis-cli ping", "Redis connectivity check"):
        print("❌ Redis is not running. Starting...")
        if not run_command("service redis-server start", "Starting Redis"):
            return False
    
    return True

def setup_database():
    """Setup database and run migrations"""
    print("📊 Setting up database...")
    
    # Run migrations
    if not run_command("python scripts/run_migrations.py", "Database migrations"):
        return False
    
    # Seed demo data
    if not run_command("python scripts/seed_demo_data.py", "Demo data seeding"):
        print("⚠️  Demo data seeding failed, but continuing...")
    
    return True

def setup_frontend():
    """Setup frontend dependencies"""
    print("🎨 Setting up frontend...")
    
    frontend_path = project_root / "frontend"
    
    # Install dependencies if needed
    if not (frontend_path / "node_modules").exists():
        if not run_command("cd frontend && yarn install", "Frontend dependency installation"):
            return False
    
    return True

def start_services():
    """Start all services using supervisor"""
    print("🚀 Starting FixOps Enterprise Platform...")
    
    # Copy supervisor config to system location
    supervisor_config = project_root / "supervisord.conf"
    
    if supervisor_config.exists():
        # Start supervisor with our config
        cmd = f"supervisord -c {supervisor_config}"
        print(f"🔧 Starting services with: {cmd}")
        
        result = subprocess.Popen(cmd, shell=True, cwd=project_root)
        
        # Wait a bit for services to start
        time.sleep(5)
        
        # Check service status
        status_result = subprocess.run("supervisorctl status", shell=True, capture_output=True, text=True)
        if status_result.returncode == 0:
            print("📋 Service Status:")
            print(status_result.stdout)
            return True
        else:
            print("❌ Failed to get service status")
            return False
    else:
        print("❌ Supervisor configuration not found")
        return False

def main():
    """Main launcher function"""
    print("""
╔══════════════════════════════════════════════════════════════╗
║                 FixOps Enterprise Platform                  ║
║                 Agentic DevSecOps Control Plane             ║
║                                                              ║
║  🎯 299μs Hot Path Performance Target                       ║
║  🔐 Enterprise Security & Compliance                        ║
║  📊 Real-time Analytics & Monitoring                        ║
╚══════════════════════════════════════════════════════════════╝
""")
    
    try:
        # Step 1: Check dependencies
        if not check_dependencies():
            print("❌ Dependency check failed. Please fix the issues and try again.")
            return False
        
        # Step 2: Setup database
        if not setup_database():
            print("❌ Database setup failed. Please check the configuration.")
            return False
        
        # Step 3: Setup frontend
        if not setup_frontend():
            print("❌ Frontend setup failed. Please check Node.js and yarn installation.")
            return False
        
        # Step 4: Start all services
        if not start_services():
            print("❌ Failed to start services.")
            return False
        
        # Success message
        print(f"""
🎉 FixOps Enterprise Platform Started Successfully!

🌐 Access Points:
┌─────────────────────────────────────────────────────────────┐
│  Frontend (React):      http://localhost:3000              │
│  Backend API:           http://localhost:8000              │
│  API Documentation:     http://localhost:8000/docs         │
│  Health Check:          http://localhost:8000/health       │
│  Metrics:              http://localhost:8000/metrics       │
└─────────────────────────────────────────────────────────────┘

👥 Demo User Accounts:
┌─────────────────────────┬──────────────────┬─────────────────┐
│ Email                   │ Password         │ Role            │
├─────────────────────────┼──────────────────┼─────────────────┤
│ admin@core.com        │ FixOpsAdmin123!  │ Administrator   │
│ analyst@core.com      │ SecureAnalyst123!│ Security Analyst│
│ operator@core.com     │ OpsSecure123!    │ Operator        │
│ viewer@core.com       │ ViewSecure123!   │ Viewer          │
│ compliance@core.com   │ Compliance123!   │ Compliance      │
└─────────────────────────┴──────────────────┴─────────────────┘

🔧 Management Commands:
  supervisorctl status              - Check service status
  supervisorctl restart all         - Restart all services  
  supervisorctl stop all            - Stop all services
  
📊 Performance Monitoring:
  - Hot path target: 299μs
  - Real-time metrics enabled
  - Structured logging active
  
🛡️  Enterprise Security:
  - JWT + MFA authentication
  - Role-based access control
  - Audit logging enabled
  - NIST SSDF compliance ready

✨ The platform is ready for enterprise use!
        """)
        
        return True
        
    except KeyboardInterrupt:
        print("\n⚠️  Startup interrupted by user")
        return False
    except Exception as e:
        print(f"\n❌ Unexpected error during startup: {str(e)}")
        return False

if __name__ == "__main__":
    success = main()
    if not success:
        print("\n💡 Troubleshooting tips:")
        print("  1. Ensure PostgreSQL is installed and running")
        print("  2. Ensure Redis is installed and running") 
        print("  3. Check that Node.js and yarn are installed")
        print("  4. Verify all dependencies in requirements.txt are installed")
        print("  5. Check logs in /var/log/supervisor/ for detailed error information")
    
    sys.exit(0 if success else 1)