# FixOps Comprehensive Test Suite - Mac M5 Silicon Setup Guide

## Prerequisites

### 1. Install Homebrew (if not installed)
```bash
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"
```

### 2. Install Required Tools
```bash
# Python 3.11 (matches project requirements)
brew install python@3.11

# Docker Desktop for Mac (Apple Silicon native)
brew install --cask docker

# jq for JSON processing
brew install jq

# Git (usually pre-installed)
brew install git
```

### 3. Start Docker Desktop
Open Docker Desktop from Applications and ensure it's running. For M5 Silicon, Docker Desktop runs natively without Rosetta.

## Setup Steps

### Step 1: Clone the Repository
```bash
cd ~
git clone https://github.com/DevOpsMadDog/Fixops.git
cd Fixops
```

### Step 2: Create Python Virtual Environment
```bash
python3.11 -m venv .venv
source .venv/bin/activate
```

### Step 3: Install Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 4: Configure Environment
```bash
# Copy example environment file
cp .env.example .env

# Set required environment variables
export FIXOPS_API_TOKEN="demo-token"
export FIXOPS_MODE="demo"
export FIXOPS_DISABLE_TELEMETRY=1
```

### Step 5: Start the API Server
```bash
# In terminal 1 - Start the API server
uvicorn apps.api.app:app --port 8002 --host 0.0.0.0
```

### Step 6: Verify API is Running
```bash
# In terminal 2 - Test the health endpoint
curl http://localhost:8002/health
# Expected: {"status":"healthy","service":"fixops-api","version":"1.0.0"}
```

## Running the Comprehensive Tests

### Step 1: Download Test Suite
```bash
# Create test directory
mkdir -p ~/fixops_comprehensive_test
cd ~/fixops_comprehensive_test

# Download the test script (or copy from this package)
# The comprehensive_e2e_test.py file should be in this directory
```

### Step 2: Run Tests
```bash
# Set environment variables
export FIXOPS_API_URL="http://localhost:8002"
export FIXOPS_API_TOKEN="demo-token"
export FIXOPS_TEST_OUTPUT="./results"

# Run the comprehensive test suite
python3 comprehensive_e2e_test.py
```

### Step 3: View Results
```bash
# Open HTML report in browser
open results/comprehensive_report.html

# View bugs and gaps summary
cat results/bugs_and_gaps.md

# View full JSON results
cat results/test_results.json | jq .summary
```

## Test Results Interpretation

### Result Categories
- **PASS**: API returned expected response with valid data
- **BUG**: Unexpected error or incorrect behavior (needs investigation)
- **GAP**: Missing feature or incomplete implementation
- **NEEDS-SEEDING**: Empty response expected for unseeded data (not a bug)
- **NOT-APPLICABLE**: Endpoint not relevant for current scenario

### Expected Results
After running the full test suite, you should see:
- ~187 total tests
- ~148 PASS (79%)
- ~14 BUG (mostly missing required parameters - expected behavior)
- ~1 GAP
- ~24 NEEDS-SEEDING (expected for fresh system)

### Known "Bugs" That Are Actually Expected Behavior
The following 422 errors are expected because these endpoints require specific parameters:
- `/api/v1/users` - requires `password` field
- `/api/v1/policies` - requires `policy_type` field
- `/api/v1/inventory/search` - requires `q` query parameter
- `/api/v1/audit/user-activity` - requires `user_id` query parameter
- `/api/v1/remediation/tasks` - requires `org_id` query parameter
- `/api/v1/deduplication/clusters` - requires `org_id` query parameter
- `/api/v1/collaboration/activities` - requires `org_id` query parameter
- `/api/v1/collaboration/comments` - requires `entity_type` and `entity_id` parameters
- `/api/v1/ide/suggestions` - requires `file_path` and `line` parameters

## Docker Alternative

### Pull and Run Pre-built Image
```bash
# Pull the latest FixOps image
docker pull devopsaico/fixops:latest

# Run the container
docker run -it -p 8002:8000 devopsaico/fixops:latest

# In another terminal, run tests against the container
export FIXOPS_API_URL="http://localhost:8002"
python3 comprehensive_e2e_test.py
```

## Troubleshooting

### Port Already in Use
```bash
# Find and kill process using port 8002
lsof -ti:8002 | xargs kill -9
```

### Python Version Issues
```bash
# Verify Python version
python3 --version  # Should be 3.11.x

# If wrong version, use explicit path
/opt/homebrew/bin/python3.11 -m venv .venv
```

### Docker Issues on M5 Silicon
Docker Desktop for Mac runs natively on Apple Silicon. If you encounter issues:
1. Ensure Docker Desktop is updated to the latest version
2. Check that "Use Rosetta for x86/amd64 emulation" is disabled in Docker settings
3. Restart Docker Desktop

### Virtual Environment Issues
```bash
# Remove and recreate virtual environment
rm -rf .venv
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Test Data

The test suite generates realistic sample data for:
- **14 Applications** across different tech stacks (Java, Python, Node.js, Go, Rust, Kotlin, Scala, C++, TypeScript, Solidity)
- **3 Customers** with different cloud architectures (AWS, Azure, GCP)
- **SARIF** findings based on SonarQube/Checkmarx output formats
- **SBOM** in CycloneDX 1.5 format
- **CVE** feeds with real CVE IDs (Log4Shell, Spring4Shell, etc.)
- **CNAPP** findings from AWS Security Hub, Azure Defender, GCP SCC

## Support

For issues or questions:
- Repository: https://github.com/DevOpsMadDog/Fixops
- Documentation: https://docs.devin.ai
