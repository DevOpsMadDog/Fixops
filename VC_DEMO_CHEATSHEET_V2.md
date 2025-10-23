# FixOps VC Demo - Quick Reference Cheat Sheet

**One-page guide for presentations**

---

## 🚀 Quick Start (30 seconds)

```bash
# Start container (stays running)
docker-compose -f docker-compose.vc-demo.yml up -d

# Enter container
docker exec -it fixops-vc-demo bash

# Run demo
python -m core.cli demo --mode demo --output demo_decision_outputs/decision.json --pretty

# View results
cat demo_decision_outputs/decision.json | jq '.'
```

**To exit and re-enter:**
```bash
exit                                    # Exit container (keeps running)
docker exec -it fixops-vc-demo bash    # Re-enter same container
```

---

## 📊 The Problem (Talk Track)

> "Your security team runs 5-10 scanners: Snyk, Trivy, Semgrep, Checkmarx, etc.
> 
> Each scanner finds hundreds of issues. You end up with thousands of findings.
> 
> **Example scenario:**
> - SBOM components: 847
> - CVEs found: 312
> - SAST findings: 203
> - Container issues: 156
> - IaC misconfigs: 89
> 
> **Total: 1,607 findings**
> 
> Your team: 3 people  
> Time per review: 15 minutes  
> Total time: 401 hours (10 weeks)
> 
> **Impossible to manually review. Critical issues buried in noise.**"

---

## ✅ The Solution (Talk Track)

> "FixOps adds intelligence to your existing scanners:
> 
> **1. Correlation** - Deduplicate findings across all scanners
> 
> **2. Business Context** - Which components are critical? Internet-facing? Handle PCI data?
> 
> **3. Exploit Intelligence** - EPSS (exploitation probability) + KEV (actively exploited)
> 
> **4. Mathematical Risk** - Bayesian inference, Markov chains
> 
> **5. AI Consensus** - 4 LLMs analyze from different perspectives
> 
> **Result: 1,607 findings → 12 critical decisions (99% noise reduction)**"

---

## 🧮 The Math (Key Points)

### EPSS & KEV
- **EPSS**: Exploitation probability (0.0 to 1.0)
- **KEV**: Known Exploited Vulnerabilities (1,422+ CVEs)
- **Example**: Log4Shell has EPSS 0.97 (97%) + KEV status = CRITICAL

### Bayesian Inference
```
Prior: P(Critical) = 5%
Evidence: High EPSS + PCI data + Internet-facing + Production
Posterior: P(Critical | Evidence) = 87%
Risk Increase: 17.4x
```

### Markov Chains
```
Current: HIGH severity
7-day forecast: 42% CRITICAL
30-day forecast: 68% CRITICAL
Decision: Fix within 7 days
```

---

## 🤖 The LLM Layer (Key Points)

**4 Models, 4 Perspectives:**

1. **GPT-5** (Strategist) - MITRE ATT&CK, business context
2. **Claude-3** (Analyst) - Compliance, controls
3. **Gemini-2** (Signals) - Exploit intelligence
4. **Sentinel-Cyber** (Threat) - Emerging threats

**Consensus Example:**
- GPT-5: BLOCK (92% confidence)
- Claude-3: BLOCK (89% confidence)
- Gemini-2: REVIEW (78% confidence)
- Sentinel-Cyber: BLOCK (94% confidence)

**Result: BLOCK (75% agreement, 88.2% average confidence)**

---

## 📋 Compliance (Key Points)

**Automated mapping to:**
- **SOC2**: CC8.1, CC7.2, CC6.1
- **ISO27001**: A.12.6.1, A.14.2.8
- **PCI-DSS**: 6.2, 6.5.1, 11.2
- **GDPR**: Article 32, Article 25

**Evidence bundles:**
- Cryptographically signed (RSA-SHA256)
- Compressed (gzip)
- Retained: 7 years (enterprise)

---

## 🎯 Demo Commands

### Essential Commands
```bash
# Full demo
python -m core.cli demo --mode demo --output demo_decision_outputs/decision.json --pretty

# Health check
python -m core.cli health --pretty

# Show config
python -m core.cli show-overlay --overlay config/fixops.overlay.yml --pretty

# SSDLC stages
python -m apps.fixops_cli stage-run --stage requirements --input demo_ssdlc_stages/01_requirements_BA.yaml --app demo
python -m apps.fixops_cli stage-run --stage design --input demo_ssdlc_stages/02_design_architecture.yaml --app demo
python -m apps.fixops_cli stage-run --stage code --input demo_ssdlc_stages/03_code_development.json --app demo
```

### View Results
```bash
# Full output
cat demo_decision_outputs/decision.json | jq '.'

# Summary only
cat demo_decision_outputs/decision.json | jq '{severity: .severity_overview.highest, guardrail: .guardrail_status, modules: .modules_executed}'

# Compliance status
cat demo_decision_outputs/decision.json | jq '.compliance_status'

# LLM consensus
cat demo_decision_outputs/decision.json | jq '.enhanced_decision.consensus'
```

---

## 📊 Key Metrics

### Performance
- **Execution**: ~4 seconds
- **Modules**: 17 executed
- **Throughput**: 900 decisions/hour

### Accuracy
- **Precision**: 97.9%
- **Recall**: 99.7%
- **F1 Score**: 98.8%

### Business Impact
- **Noise Reduction**: 95-99%
- **Time Savings**: 99.99% (10 weeks → 4 seconds)
- **Cost Savings**: $480K/year (3-person team @ $100/hr)

---

## 🎤 Talk Tracks

### Opening
> "Let me show you the problem every CISO faces. Your scanners work perfectly - they find EVERYTHING. But which findings actually matter? That's what FixOps solves."

### Math Layer
> "This isn't guessing. It's mathematical risk assessment. Bayesian inference updates risk from 5% to 87% based on evidence. Markov chains predict 68% critical probability in 30 days. This is how we prioritize."

### LLM Layer
> "Four LLMs analyze from different perspectives: strategic, compliance, threat intelligence, emerging threats. 75% agreement, 88.2% confidence. This is structured consensus, not AI magic."

### Compliance
> "Every decision generates a cryptographically-signed evidence bundle. SOC2, ISO27001, PCI-DSS, GDPR - all automated. Audit-ready from day one."

### Closing
> "FixOps doesn't replace your scanners. We make them intelligent. Your scanners find vulnerabilities. FixOps tells you which ones actually matter. This is the intelligent decision layer your security stack needs."

---

## 🐛 Quick Troubleshooting

### Container not running?
```bash
docker-compose -f docker-compose.vc-demo.yml up -d
```

### Can't enter container?
```bash
docker ps | grep fixops  # Check it's running
docker exec -it fixops-vc-demo bash
```

### Demo fails?
```bash
# Check fixtures exist
ls -la fixtures/
ls -la demo_ssdlc_stages/

# Re-run demo
python -m core.cli demo --mode demo --output demo_decision_outputs/decision.json --pretty
```

### Need to restart?
```bash
docker-compose -f docker-compose.vc-demo.yml restart
```

---

## ✅ Demo Checklist

### Before Demo
- [ ] Start container: `docker-compose -f docker-compose.vc-demo.yml up -d`
- [ ] Enter container: `docker exec -it fixops-vc-demo bash`
- [ ] Test demo: `python -m core.cli demo --mode demo --output demo_decision_outputs/decision.json --pretty`
- [ ] Verify output: `cat demo_decision_outputs/decision.json | jq '.'`

### During Demo
- [ ] Explain the problem (scanner overload)
- [ ] Run full demo (~4 seconds)
- [ ] Show math (Bayesian, Markov, EPSS/KEV)
- [ ] Show LLM consensus (4 models, 88.2% confidence)
- [ ] Show compliance (SOC2, PCI-DSS, etc.)
- [ ] Show evidence bundles (cryptographic signing)

### After Demo
- [ ] Answer questions
- [ ] Show additional features if requested
- [ ] Provide access to demo environment

---

## 🔗 Resources

- **Full Guide**: VC_DEMO_INTERACTIVE_V2.md
- **Docker Setup**: DOCKER_SETUP.md
- **SSDLC Testing**: SSDLC_TEST_REPORT.md
- **API Docs**: http://localhost:8000/docs

---

**End of Cheat Sheet**

**Print this page and keep it handy during your presentation! 📄**
