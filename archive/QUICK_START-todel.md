# FixOps VC Demo - Quick Start Guide

## 🚀 Fastest Way to Run (Docker - Recommended)

```bash
# 1. Clone and enter directory
git clone https://github.com/DevOpsMadDog/Fixops.git && cd Fixops

# 2. Run the quick-start script
./quick-start-docker.sh

# 3. View results
sudo cat demo_decision_outputs/decision.json | jq '.'
```

**That's it!** The Docker setup handles everything automatically.

---

## Alternative: Native Setup (No Docker)

```bash
# 1. Clone repository
git clone https://github.com/DevOpsMadDog/Fixops.git && cd Fixops

# 2. Setup Python environment
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt -r apps/api/requirements.txt uvicorn

# 4. Set environment variables
export FIXOPS_MODE=demo
export FIXOPS_API_TOKEN=demo-token
export FIXOPS_DISABLE_TELEMETRY=1

# 5. Run demo
python -m core.cli demo --mode demo --output demo_decision_outputs/decision.json --pretty

# 6. View results
cat demo_decision_outputs/decision.json | jq '.'
```

---

## What You Get

✅ **Noise Reduction**: 45 CVE alerts (8 critical) → 12 critical decisions (87.5% (real backtesting: 8 critical CVEs → 1 true threat) reduction)  
✅ **Business Context**: Integrates criticality, exposure, compliance requirements  
✅ **Math Models**: Bayesian inference, Markov chains, EPSS, KEV database  
✅ **LLM Explainability**: Multi-LLM consensus with human-readable explanations  
✅ **Evidence Bundles**: Cryptographically signed audit trails  
✅ **Compliance Mapping**: SOC2, ISO27001, PCI-DSS, GDPR  

---

## Prerequisites

### Docker Setup (Easiest)
- **Docker** (20.x or higher)
  - macOS/Windows: [Docker Desktop](https://docs.docker.com/get-docker/)
  - Linux: `curl -fsSL https://get.docker.com -o get-docker.sh && sudo sh get-docker.sh`

### Native Setup
- **Python 3.10+** (`python3 --version`)
- **pip** (usually comes with Python)
- **jq** (for JSON formatting)
  - macOS: `brew install jq`
  - Ubuntu: `sudo apt-get install jq`
  - Windows: Download from https://stedolan.github.io/jq/

---

## Troubleshooting

### Docker Issues

**Port 8000 in use:**
```bash
docker ps -a  # Find container using port 8000
docker stop <container_id>
```

**Permission denied on output:**
```bash
sudo chown -R $USER:$USER demo_decision_outputs/
```

### Native Setup Issues

**Module not found:**
```bash
source .venv/bin/activate  # Ensure venv is activated
pip install -r requirements.txt -r apps/api/requirements.txt
```

**Python version too old:**
```bash
python3 --version  # Must be 3.10 or higher
```

---

## Next Steps

1. **Read the full demo script**: `VC_DEMO_CORRECTED.md` (15-minute executive demo)
2. **Docker details**: `DOCKER_SETUP.md` (comprehensive Docker guide)
3. **Native setup details**: `LAPTOP_SETUP_GUIDE.md` (detailed native setup)
4. **Architecture**: `ARCHITECTURE.md` (system design)
5. **Contributing**: `CONTRIBUTING.md` (development guide)

---

## Support

- **Documentation**: Check README.md, ARCHITECTURE.md, HANDBOOK.md
- **Issues**: https://github.com/DevOpsMadDog/Fixops/issues
- **Demo Script**: VC_DEMO_CORRECTED.md

---

## Summary

**Two ways to run:**

| Method | Setup Time | Prerequisites | Best For |
|--------|-----------|---------------|----------|
| **Docker** | 3 min | Docker only | Demos, presentations |
| **Native** | 5 min | Python 3.10+, pip, jq | Development |

**Both work perfectly!** Choose based on your preference.
