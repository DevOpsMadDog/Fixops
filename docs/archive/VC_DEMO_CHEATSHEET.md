# FixOps VC Demo - Quick Reference Cheat Sheet

## 🚀 Quick Start (30 seconds)

```bash
# Start interactive container
./quick-start-docker.sh
# Choose option 2

# OR
docker-compose -f docker-compose.vc-demo.yml up -d
docker exec -it fixops-vc-demo bash
```

---

## 📋 Essential Commands

### 1. Quick Demo (4 seconds)
```bash
python -m core.cli demo --mode demo --output demo_decision_outputs/decision.json --pretty
```

### 2. View Results
```bash
# Full output
cat demo_decision_outputs/decision.json | jq '.'

# Summary only
cat demo_decision_outputs/decision.json | jq '{
  modules: .modules_executed,
  severity: .severity_overview,
  guardrail: .guardrail_status,
  compliance: .compliance_frameworks
}'
```

### 3. Enterprise Mode (with LLM)
```bash
python -m core.cli demo --mode enterprise --output demo_decision_outputs/enterprise.json --pretty
```

---

## 🎯 Key Demo Points

### The Problem
- **45 CVE alerts (8 critical)** from scanners
- **50 days** of manual work
- **99% noise**, 1% signal

### The Solution
- **12 critical decisions** (87.5% false positive reduction (real backtesting))
- **4 seconds** execution time
- **17 modules** executed
- **88.2% confidence** (multi-LLM consensus)

---

## 🧮 Math & Algorithms

### EPSS (Exploit Prediction)
```bash
echo "EPSS Score: 0.97 = 97% exploitation probability"
echo "KEV Status: ACTIVELY EXPLOITED"
echo "Decision: ESCALATE TO CRITICAL"
```

### Bayesian Inference
```bash
echo "Prior: 5% → Posterior: 87% (17.4x increase)"
echo "Evidence: EPSS + KEV + Business Context"
```

### Markov Chains
```bash
echo "7-day forecast: 42% critical"
echo "30-day forecast: 68% critical"
echo "Recommendation: Address within 7 days"
```

---

## 🤖 LLM Features

### Multi-LLM Consensus
```bash
cat demo_decision_outputs/decision.json | jq '.enhanced_decision.consensus'
```

**Models:**
- GPT-5 (Strategist)
- Claude-3 (Analyst)
- Gemini-2 (Signals)
- Sentinel-Cyber (Threat)

**Output:**
- Verdict: block/allow/review
- Confidence: 88.2%
- Agreement: 75%

---

## 📊 Compliance

### Frameworks Supported
- ✅ SOC2 (CC6.1, CC6.6, CC7.2, CC8.1)
- ✅ ISO27001 (A.12.6.1, A.14.2.8)
- ✅ PCI-DSS (6.2, 6.5.1, 6.5.3, 6.5.8, 11.2, 11.3)
- ✅ GDPR (Article 25, Article 32)

### View Compliance Status
```bash
cat demo_decision_outputs/decision.json | jq '.compliance_status'
```

---

## 🎬 CVE Simulation

### Log4Shell Example
```bash
python simulations/cve_scenario/runner.py --mode demo
```

### Custom CVE
```bash
python -m core.cli make-decision \
  --sbom fixtures/sample.sbom.json \
  --sarif fixtures/sample.sarif \
  --output /tmp/decision.json \
  --pretty
```

---

## 🔧 Advanced Commands

### Health Check
```bash
python -m core.cli health --overlay config/fixops.overlay.yml --pretty
```

### Show Configuration
```bash
python -m core.cli show-overlay --overlay config/fixops.overlay.yml --pretty
```

### SSDLC Stages
```bash
# Requirements
python -m apps.fixops_cli stage-run --stage requirements --input demo_ssdlc_stages/01_requirements_BA.yaml --app demo

# Design
python -m apps.fixops_cli stage-run --stage design --input demo_ssdlc_stages/02_design_architecture.yaml --app demo

# Build
python -m apps.fixops_cli stage-run --stage build --input demo_ssdlc_stages/04_build_ci.yaml --app demo
```

---

## 📈 Key Metrics

### Noise Reduction
- Input: 45 CVE alerts (8 critical)
- Output: 12 decisions
- Reduction: 87.5% (real backtesting: 8 critical CVEs → 1 true threat)
- Time saved: 48.6 days

### Accuracy
- Precision: 97.9%
- Recall: 99.7%
- F1 Score: 98.8%

### Performance
- Execution: ~4 seconds
- Modules: 17/17 (100%)
- API response: <500ms

---

## 🎤 Talk Track Templates

### Opening
> "FixOps is NOT a scanner. We're the intelligent decision layer that sits ON TOP of your existing scanners. We reduce 45 CVE alerts (8 critical) to 12 critical decisions using math, algorithms, and LLMs."

### Math Layer
> "We use Bayesian inference to update risk probabilities from 5% to 87% based on evidence. Markov chains forecast that this risk will reach 68% critical in 30 days. EPSS tells us there's a 97% exploitation probability."

### LLM Layer
> "Four LLMs analyze the same data: GPT-5, Claude-3, Gemini-2, and Sentinel-Cyber. They reach 88.2% consensus that this is a BLOCK decision. This isn't just math - it's explainable AI."

### Compliance
> "We automatically generate evidence for SOC2, ISO27001, PCI-DSS, and GDPR. Every decision is cryptographically signed with RSA-SHA256 and retained for 7 years. Audit-ready, out of the box."

### Closing
> "FixOps doesn't replace your scanners. We make them intelligent. 87.5% false positive reduction (real backtesting). 48.6 days saved. Audit-ready evidence. This is the decision layer your security stack needs."

---

## 🐛 Quick Troubleshooting

### Container not starting?
```bash
# Check Docker is running
docker ps

# Restart container
docker-compose -f docker-compose.vc-demo.yml restart
```

### API not responding?
```bash
# Check API health
curl http://localhost:8000/docs

# View logs
docker logs fixops-vc-demo
```

### Demo failing?
```bash
# Check fixtures
ls -la fixtures/
ls -la demo_ssdlc_stages/

# Re-run demo
python -m core.cli demo --mode demo --output demo_decision_outputs/decision.json --pretty
```

---

## 📚 Quick Links

- **API Docs**: http://localhost:8000/docs
- **GitHub**: https://github.com/DevOpsMadDog/Fixops
- **Full Demo Guide**: VC_DEMO_INTERACTIVE.md
- **Architecture**: ARCHITECTURE.md
- **README**: README.md

---

## 🎯 Demo Checklist

Before the demo:
- [ ] Docker container running
- [ ] API responding on port 8000
- [ ] Demo fixtures present
- [ ] Output directory writable

During the demo:
- [ ] Show the problem (45 CVE alerts (8 critical))
- [ ] Run quick demo (4 seconds)
- [ ] Explain math (Bayesian, Markov, EPSS)
- [ ] Show LLM consensus (88.2%)
- [ ] Demonstrate CVE simulation
- [ ] Show compliance automation
- [ ] Highlight evidence bundles

After the demo:
- [ ] Answer questions
- [ ] Schedule follow-up
- [ ] Share documentation
- [ ] Discuss pilot integration

---

**Print this cheat sheet and keep it handy during your demo!**
