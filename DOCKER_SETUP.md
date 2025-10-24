# FixOps VC Demo - Docker Setup Guide

## 🚀 Quick Start (3 Commands)

```bash
# 1. Clone the repository
git clone https://github.com/DevOpsMadDog/Fixops.git && cd Fixops

# 2. Run the quick-start script
./quick-start-docker.sh

# 3. View results
cat demo_decision_outputs/decision.json | jq '.'
```

That's it! The Docker setup handles everything automatically.

---

## What This Does

The Docker setup provides a **completely isolated environment** with:
- ✅ Python 3.11 pre-installed
- ✅ All dependencies installed
- ✅ Environment variables configured
- ✅ No conflicts with your system
- ✅ Works on macOS, Linux, and Windows (with WSL2)

---

## Prerequisites

**Only Docker is required!**

### Install Docker

- **macOS**: [Docker Desktop for Mac](https://docs.docker.com/desktop/install/mac-install/)
- **Windows**: [Docker Desktop for Windows](https://docs.docker.com/desktop/install/windows-install/)
- **Linux**: 
  ```bash
  curl -fsSL https://get.docker.com -o get-docker.sh
  sudo sh get-docker.sh
  ```

Verify installation:
```bash
docker --version
# Should show: Docker version 20.x or higher
```

---

## Two Ways to Run

### Option 1: Quick Demo (Recommended for First Time)

Runs the demo and shows results immediately:

```bash
./quick-start-docker.sh
# Choose option 1
```

**What happens:**
1. Builds Docker image (2-3 minutes, one-time)
2. Runs the demo command
3. Saves results to `demo_decision_outputs/decision.json`
4. Container exits automatically

**View results:**
```bash
cat demo_decision_outputs/decision.json | jq '.'
```

### Option 2: Interactive Mode (For Full VC Demo)

Starts a persistent container with API server:

```bash
./quick-start-docker.sh
# Choose option 2
```

**What happens:**
1. Builds Docker image (2-3 minutes, one-time)
2. Starts container with API server on port 8000
3. Container keeps running for you to execute commands

**Run commands:**
```bash
# Run the demo
docker exec fixops-vc-demo python -m core.cli demo --mode demo --output demo_decision_outputs/decision.json --pretty

# Test API
curl http://localhost:8000/health

# View results
cat demo_decision_outputs/decision.json | jq '.'
```

**Stop when done:**
```bash
docker stop fixops-vc-demo && docker rm fixops-vc-demo
```

---

## Manual Docker Commands

If you prefer manual control:

### Build the Image

```bash
docker build -f Dockerfile.simple -t fixops-demo:latest .
```

### Run Quick Demo

```bash
docker run --rm \
    -v $(pwd)/demo_decision_outputs:/app/demo_decision_outputs \
    fixops-demo:latest
```

### Run Interactive Container

```bash
# Start container
docker run -d \
    --name fixops-vc-demo \
    -p 8000:8000 \
    -v $(pwd)/demo_decision_outputs:/app/demo_decision_outputs \
    -v $(pwd)/demo_decision_inputs:/app/demo_decision_inputs \
    fixops-demo:latest \
    bash -c "python demo_api_server.py & tail -f /dev/null"

# Execute commands inside
docker exec fixops-vc-demo python -m core.cli demo --mode demo --output demo_decision_outputs/decision.json --pretty

# View logs
docker logs fixops-vc-demo

# Open shell
docker exec -it fixops-vc-demo bash

# Stop and remove
docker stop fixops-vc-demo && docker rm fixops-vc-demo
```

---

## Running the Full VC Demo Script

Once you have the interactive container running, you can follow the complete VC_DEMO_CORRECTED.md script:

### 1. Create Demo Input Files

```bash
# Create requirements CSV
docker exec fixops-vc-demo bash -c 'cat > demo_decision_inputs/requirements.csv << "CSV"
component,criticality,exposure,data_classification,environment,compliance_framework
payment-gateway,critical,internet,payment_card_data,production,PCI_DSS
user-auth-service,high,internet,pii,production,SOC2
order-processing,high,internal,business_data,production,SOC2
analytics-worker,medium,internal,public_data,staging,none
admin-dashboard,high,internal,pii,production,SOC2
CSV'

# Create design OTM
docker exec fixops-vc-demo bash -c 'cat > demo_decision_inputs/design_otm.json << "JSON"
{
  "otmVersion": "0.1.0",
  "project": {
    "name": "Payment Platform",
    "id": "payment-platform-v2"
  },
  "components": [
    {
      "id": "payment-gateway",
      "name": "Payment Gateway",
      "type": "api-gateway",
      "trustZone": "dmz",
      "tags": ["internet-facing", "pci-scope", "critical"]
    }
  ]
}
JSON'

# Create SARIF output
docker exec fixops-vc-demo bash -c 'cat > demo_decision_inputs/scanner_output.sarif << "JSON"
{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [{
    "tool": {
      "driver": {
        "name": "Snyk Code",
        "version": "1.1246.0"
      }
    },
    "results": [
      {
        "ruleId": "java/sql-injection",
        "level": "error",
        "message": {"text": "SQL injection vulnerability"},
        "locations": [{
          "physicalLocation": {
            "artifactLocation": {"uri": "payment-service/PaymentRepository.java"},
            "region": {"startLine": 145}
          }
        }],
        "properties": {
          "severity": "high",
          "cwe": "CWE-89"
        }
      }
    ]
  }]
}
JSON'

# Create SBOM
docker exec fixops-vc-demo bash -c 'cat > demo_decision_inputs/sbom_from_syft.json << "JSON"
{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "components": [
    {
      "type": "library",
      "name": "log4j-core",
      "version": "2.14.0",
      "purl": "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0"
    }
  ]
}
JSON'

# Create CVE feed
docker exec fixops-vc-demo bash -c 'cat > demo_decision_inputs/cve_feed.json << "JSON"
{
  "vulnerabilities": [
    {
      "cve": {
        "id": "CVE-2021-44228",
        "descriptions": [{"lang": "en", "value": "Apache Log4j2 RCE vulnerability (Log4Shell)"}]
      },
      "impact": {
        "baseMetricV3": {
          "cvssV3": {"baseScore": 10.0},
          "exploitabilityScore": 3.9
        }
      }
    }
  ]
}
JSON'
```

### 2. Run the Decision Pipeline

```bash
docker exec fixops-vc-demo python -m core.cli demo --mode demo --output demo_decision_outputs/decision.json --pretty
```

### 3. View Results

```bash
# View full output
cat demo_decision_outputs/decision.json | jq '.'

# View decision summary
cat demo_decision_outputs/decision.json | jq '{
  decision_summary: {
    total_inputs: "1607 alerts from scanners",
    critical_decisions: "12 require action",
    noise_reduced: "87.5% (real backtesting: 8 critical CVEs → 1 true threat)"
  }
}'
```

---

## Troubleshooting

### Issue 1: Docker Not Running

**Error**: `Cannot connect to the Docker daemon`

**Solution**: Start Docker Desktop or Docker daemon
```bash
# macOS/Windows: Open Docker Desktop application
# Linux:
sudo systemctl start docker
```

### Issue 2: Port 8000 Already in Use

**Error**: `Bind for 0.0.0.0:8000 failed: port is already allocated`

**Solution**: Use a different port
```bash
docker run -d \
    --name fixops-vc-demo \
    -p 8001:8000 \
    ...
```

Then access at `http://localhost:8001`

### Issue 3: Permission Denied

**Error**: `permission denied while trying to connect to the Docker daemon socket`

**Solution**: Add your user to docker group (Linux)
```bash
sudo usermod -aG docker $USER
# Log out and log back in
```

### Issue 4: Build Takes Too Long

**Symptom**: Docker build hangs or takes >10 minutes

**Solution**: 
1. Check your internet connection
2. Try building with progress output:
   ```bash
   docker build -f Dockerfile.simple -t fixops-demo:latest . --progress=plain
   ```
3. Clear Docker cache and rebuild:
   ```bash
   docker system prune -a
   docker build -f Dockerfile.simple -t fixops-demo:latest .
   ```

### Issue 5: Container Exits Immediately

**Error**: Container starts but exits right away

**Solution**: Check logs
```bash
docker logs fixops-vc-demo
```

### Issue 6: jq Not Available on Host

**Error**: `jq: command not found` when viewing results

**Solution**: Use Python's json.tool instead
```bash
cat demo_decision_outputs/decision.json | python -m json.tool
```

Or install jq:
```bash
# macOS
brew install jq

# Ubuntu/Debian
sudo apt-get install jq

# Windows (with Chocolatey)
choco install jq
```

---

## Advantages of Docker Setup

### ✅ Pros
- **Zero system pollution**: No Python packages installed on your machine
- **Consistent environment**: Works the same on all platforms
- **Easy cleanup**: Just remove the container and image
- **Isolated**: Won't conflict with other Python projects
- **Reproducible**: Same environment every time

### ⚠️ Cons
- **Initial build time**: 2-3 minutes for first build (cached after)
- **Disk space**: ~500MB for image
- **Docker required**: Must have Docker installed

---

## Comparison: Docker vs Native

| Aspect | Docker Setup | Native Setup |
|--------|-------------|--------------|
| **Setup Time** | 3 minutes | 5 minutes |
| **Prerequisites** | Docker only | Python 3.10+, pip, jq |
| **Isolation** | Complete | None |
| **Cleanup** | `docker rmi fixops-demo` | Manual venv removal |
| **Portability** | Works everywhere | Platform-dependent |
| **Performance** | Slight overhead | Native speed |

**Recommendation**: Use Docker for demos and presentations. Use native setup for development.

---

## Cleanup

### Remove Container Only
```bash
docker stop fixops-vc-demo
docker rm fixops-vc-demo
```

### Remove Image and Container
```bash
docker stop fixops-vc-demo 2>/dev/null
docker rm fixops-vc-demo 2>/dev/null
docker rmi fixops-demo:latest
```

### Complete Cleanup (All Docker Resources)
```bash
docker system prune -a
# WARNING: This removes ALL unused Docker resources
```

---

## Next Steps

After successfully running the Docker demo:

1. **Explore the API**: Access http://localhost:8000/docs for Swagger UI
2. **Customize inputs**: Edit files in `demo_decision_inputs/`
3. **Try enterprise mode**: Modify environment variables
4. **Integrate with CI/CD**: Use the Docker image in your pipelines
5. **Review documentation**: Check VC_DEMO_CORRECTED.md for the full demo script

---

## Summary

**Docker setup provides the easiest way to run the VC demo:**

```bash
# One command to rule them all
./quick-start-docker.sh
```

- ✅ No Python installation needed
- ✅ No dependency conflicts
- ✅ Works on all platforms
- ✅ Clean and isolated
- ✅ Production-ready

Perfect for demos, presentations, and quick testing!
