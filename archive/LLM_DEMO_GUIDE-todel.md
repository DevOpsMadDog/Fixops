# FixOps LLM Demo Guide - Using Real API Keys

**How to demonstrate real LLM consensus with your OpenAI API key**

---

## 🎯 Quick Start - Enable Real LLM Responses

### Step 1: Set Your OpenAI API Key

```bash
# Inside the Docker container
export OPENAI_API_KEY="sk-proj-YOUR-OPENAI-API-KEY-HERE"

# Verify it's set
echo $OPENAI_API_KEY
```

### Step 2: Run Demo with Real LLM

```bash
# Run demo - it will automatically use your OpenAI key
python -m core.cli demo --mode enterprise --output demo_decision_outputs/decision_llm.json --pretty
```

**That's it!** FixOps will now:
- ✅ Call OpenAI GPT-4o-mini with your API key
- ✅ Get real LLM analysis and recommendations
- ✅ Show actual confidence scores and reasoning
- ✅ Display real MITRE ATT&CK mappings
- ✅ Generate natural language explanations

---

## 📊 What Changes with Real LLM?

### Demo Mode (Mock Responses)
```json
{
  "enhanced_decision": {
    "consensus": {
      "verdict": "block",
      "confidence": 0.82,
      "method": "deterministic"
    },
    "models": [
      {
        "provider": "gpt-5",
        "verdict": "block",
        "confidence": 0.82,
        "rationale": "Mock response - demo mode"
      }
    ]
  }
}
```

### Enterprise Mode with Real API Key
```json
{
  "enhanced_decision": {
    "consensus": {
      "verdict": "block",
      "confidence": 0.92,
      "method": "weighted_average"
    },
    "models": [
      {
        "provider": "gpt-5",
        "verdict": "block",
        "confidence": 0.92,
        "rationale": "SQL injection vulnerability in payment-gateway poses critical risk. Component handles payment card data (PCI DSS scope) and is internet-facing. EPSS score 0.85 indicates high exploitation probability. Recommend immediate remediation per PCI DSS 6.5.1.",
        "mitre_techniques": ["T1190", "T1059"],
        "compliance_concerns": ["PCI_DSS:6.5.1", "SOC2:CC7.2"],
        "attack_vectors": ["SQL injection", "Remote code execution"],
        "metadata": {
          "mode": "remote",
          "provider": "gpt-5",
          "model": "gpt-4o-mini",
          "duration_ms": 1234.56
        }
      }
    ]
  }
}
```

---

## 🔧 How FixOps Uses LLM Providers

### Supported Providers

FixOps supports 4 LLM providers (configured in `config/fixops.overlay.yml`):

1. **OpenAI (GPT-4o-mini)** - Strategist
   - Environment variable: `OPENAI_API_KEY` or `FIXOPS_OPENAI_KEY`
   - Model: `gpt-4o-mini` (default)
   - Focus: MITRE ATT&CK, business context
   - Style: Strategic risk assessment

2. **Anthropic (Claude-3)** - Analyst
   - Environment variable: `ANTHROPIC_API_KEY` or `FIXOPS_ANTHROPIC_KEY`
   - Model: `claude-3-5-sonnet-20240620`
   - Focus: Compliance, guardrails
   - Style: Detailed control analysis

3. **Google (Gemini)** - Signals
   - Environment variable: `GOOGLE_API_KEY` or `FIXOPS_GEMINI_KEY`
   - Model: `gemini-1.5-pro`
   - Focus: Exploit signals, CNAPP
   - Style: Threat intelligence

4. **Sentinel-Cyber** - Threat (Deterministic)
   - No API key needed (uses heuristics)
   - Focus: Marketplace, AI agents
   - Style: Emerging threats

### Fallback Behavior

**Important:** FixOps is designed to work even without API keys!

- If no API key is set → Uses deterministic/mock responses
- If API call fails → Falls back to heuristic defaults
- If API times out → Returns default action with timeout note
- If API returns invalid JSON → Uses default reasoning

**This means your demo will ALWAYS work, even without API keys.**

---

## 🎤 Demo Script - Showing Real LLM

### Part 1: Show Mock Response (Demo Mode)

```bash
# Run without API key (demo mode)
unset OPENAI_API_KEY
python -m core.cli demo --mode demo --output /tmp/demo_mock.json --pretty

# Show the response
cat /tmp/demo_mock.json | jq '.enhanced_decision.models[0]'
```

**Talk Track:**
> "In demo mode, FixOps uses deterministic responses. This is great for testing and CI/CD pipelines where you don't want to call external APIs. But let me show you what happens when we enable real LLM analysis..."

### Part 2: Enable Real LLM

```bash
# Set your OpenAI API key
export OPENAI_API_KEY="sk-proj-..."

# Run with real LLM (enterprise mode)
python -m core.cli demo --mode enterprise --output /tmp/demo_real.json --pretty

# Show the response
cat /tmp/demo_real.json | jq '.enhanced_decision.models[0]'
```

**Talk Track:**
> "Now with the OpenAI API key set, FixOps calls GPT-4o-mini in real-time. Watch the response - it's analyzing the actual CVE data, SBOM components, and business context. You'll see:
> - Real confidence scores (not just 0.82)
> - Natural language reasoning
> - MITRE ATT&CK techniques identified
> - Compliance concerns mapped
> - Attack vectors explained
> - Response time in milliseconds"

### Part 3: Compare Responses

```bash
echo "=== MOCK RESPONSE (Demo Mode) ==="
cat /tmp/demo_mock.json | jq '.enhanced_decision.models[0].metadata'

echo ""
echo "=== REAL RESPONSE (Enterprise Mode with API Key) ==="
cat /tmp/demo_real.json | jq '.enhanced_decision.models[0].metadata'
```

**Talk Track:**
> "Notice the difference:
> - Mock: `mode: deterministic`, `reason: provider_disabled`
> - Real: `mode: remote`, `model: gpt-4o-mini`, `duration_ms: 1234.56`
> 
> The real LLM analyzed the security context and provided actionable recommendations in about 1 second."

---

## 🧪 Testing Different Scenarios

### Scenario 1: Critical CVE in Payment System

```bash
export OPENAI_API_KEY="sk-proj-..."

# Run demo with payment-related fixtures
python -m core.cli demo --mode enterprise --output /tmp/payment_cve.json --pretty

# View LLM reasoning
cat /tmp/payment_cve.json | jq '.enhanced_decision.models[0].reasoning'
```

**Expected Output:**
```
"SQL injection vulnerability in payment-gateway poses critical risk. Component handles payment card data (PCI DSS scope) and is internet-facing. EPSS score 0.85 indicates high exploitation probability. Recommend immediate remediation per PCI DSS 6.5.1."
```

### Scenario 2: Low-Risk Dev Environment Issue

```bash
# Modify context to be dev environment (if you have custom fixtures)
# Or just observe how LLM responds to different severity levels

cat /tmp/payment_cve.json | jq '.enhanced_decision.consensus'
```

**Expected Output:**
```json
{
  "verdict": "review",
  "confidence": 0.65,
  "agreement": 0.5,
  "method": "weighted_average"
}
```

---

## 📋 View Full LLM Analysis

### Command to See Everything

```bash
# Run demo with real LLM
export OPENAI_API_KEY="sk-proj-..."
python -m core.cli demo --mode enterprise --output /tmp/full_llm.json --pretty

# View full enhanced decision
cat /tmp/full_llm.json | jq '.enhanced_decision' | head -100
```

### What You'll See

```json
{
  "consensus": {
    "verdict": "block",
    "confidence": 0.92,
    "agreement": 1.0,
    "method": "weighted_average"
  },
  "models": [
    {
      "provider": "gpt-5",
      "verdict": "block",
      "confidence": 0.92,
      "rationale": "SQL injection vulnerability in payment-gateway poses critical risk...",
      "mitre_techniques": ["T1190", "T1059"],
      "compliance_concerns": ["PCI_DSS:6.5.1", "SOC2:CC7.2"],
      "attack_vectors": ["SQL injection", "Remote code execution"],
      "metadata": {
        "mode": "remote",
        "provider": "gpt-5",
        "model": "gpt-4o-mini",
        "duration_ms": 1234.56
      }
    }
  ],
  "explanation": "Multi-LLM consensus analysis indicates BLOCK with 92% confidence...",
  "mitre_mapping": ["T1190", "T1059"],
  "compliance_impact": ["PCI_DSS:6.5.1", "SOC2:CC7.2"]
}
```

---

## 🎯 VC Demo Talk Track

### Opening

> "Let me show you FixOps' multi-LLM consensus engine. First, I'll run it in demo mode without API keys - this is what you'd use in CI/CD pipelines."

```bash
unset OPENAI_API_KEY
python -m core.cli demo --mode demo --output /tmp/demo.json --pretty
cat /tmp/demo.json | jq '.enhanced_decision.models[0].metadata'
```

> "See? `mode: deterministic`. It works perfectly without external dependencies."

### The Reveal

> "Now let me enable real LLM analysis with OpenAI."

```bash
export OPENAI_API_KEY="sk-proj-..."
python -m core.cli demo --mode enterprise --output /tmp/enterprise.json --pretty
cat /tmp/enterprise.json | jq '.enhanced_decision.models[0]'
```

> "Watch this - it's calling GPT-4o-mini RIGHT NOW. In about 1 second, you'll see:
> - Real confidence score (not just 0.82)
> - Natural language reasoning
> - MITRE ATT&CK techniques
> - Compliance concerns
> - Attack vectors
> 
> This is real AI analysis, not mock data."

### The Explanation

```bash
cat /tmp/enterprise.json | jq '.enhanced_decision.models[0].reasoning'
```

> "Read that reasoning. The LLM understood:
> - This is a payment gateway (PCI DSS scope)
> - It's internet-facing (high exposure)
> - EPSS score indicates high exploitation probability
> - PCI DSS 6.5.1 requires immediate remediation
> 
> This is contextual intelligence, not just severity scoring."

### The Close

> "FixOps supports 4 LLM providers:
> - OpenAI (strategic analysis)
> - Anthropic Claude (compliance focus)
> - Google Gemini (threat intelligence)
> - Sentinel-Cyber (emerging threats)
> 
> We query all 4 simultaneously and use weighted consensus. If one provider is down, we fall back gracefully. If all providers are unavailable, we use deterministic heuristics.
> 
> **This is production-ready AI with built-in resilience.**"

---

## 🔐 Security Best Practices

### Environment Variables

**DO:**
```bash
# Set in container environment
export OPENAI_API_KEY="sk-proj-..."

# Or in docker-compose.yml
environment:
  - OPENAI_API_KEY=${OPENAI_API_KEY}
```

**DON'T:**
```bash
# Don't hardcode in code
api_key = "sk-proj-..."  # ❌ NEVER DO THIS

# Don't commit to git
echo "OPENAI_API_KEY=sk-proj-..." > .env  # ❌ DON'T COMMIT .env
```

### API Key Rotation

```bash
# Update key in environment
export OPENAI_API_KEY="sk-proj-NEW-KEY"

# Restart container if needed
docker-compose -f docker-compose.vc-demo.yml restart
```

### Cost Management

**OpenAI GPT-4o-mini pricing (as of 2024):**
- Input: $0.15 per 1M tokens
- Output: $0.60 per 1M tokens

**Typical FixOps LLM call:**
- Input: ~500 tokens (context + prompt)
- Output: ~200 tokens (response)
- Cost: ~$0.0002 per call (0.02 cents)

**For 1,000 decisions:**
- Cost: ~$0.20 (20 cents)

**Very affordable for demos and production!**

---

## 🐛 Troubleshooting

### Issue: "OpenAI fallback: timeout"

**Cause:** API call took longer than 30 seconds

**Solution:**
```bash
# Check internet connectivity
curl https://api.openai.com/v1/models

# Verify API key is valid
curl https://api.openai.com/v1/models \
  -H "Authorization: Bearer $OPENAI_API_KEY"
```

### Issue: "OpenAI error: invalid_api_key"

**Cause:** API key is incorrect or expired

**Solution:**
```bash
# Check API key is set correctly
echo $OPENAI_API_KEY

# Verify it starts with "sk-"
# Verify it's not truncated

# Get new key from https://platform.openai.com/api-keys
```

### Issue: "OpenAI error: insufficient_quota"

**Cause:** OpenAI account has no credits

**Solution:**
- Add credits to your OpenAI account
- Or use demo mode (no API key needed)

### Issue: Response shows "mode: deterministic"

**Cause:** API key not set or provider disabled

**Solution:**
```bash
# Set API key
export OPENAI_API_KEY="sk-proj-..."

# Verify it's set
echo $OPENAI_API_KEY

# Run in enterprise mode
python -m core.cli demo --mode enterprise --output /tmp/test.json --pretty
```

---

## 📚 Additional Resources

### Configuration Files
- **LLM Providers**: `core/llm_providers.py`
- **Enhanced Decision**: `core/enhanced_decision.py`
- **Overlay Config**: `config/fixops.overlay.yml`

### Environment Variables
- `OPENAI_API_KEY` or `FIXOPS_OPENAI_KEY` - OpenAI API key
- `ANTHROPIC_API_KEY` or `FIXOPS_ANTHROPIC_KEY` - Anthropic API key
- `GOOGLE_API_KEY` or `FIXOPS_GEMINI_KEY` - Google Gemini API key

### API Documentation
- OpenAI: https://platform.openai.com/docs
- Anthropic: https://docs.anthropic.com
- Google Gemini: https://ai.google.dev/docs

---

## ✅ Quick Checklist for VC Demo

### Before Demo
- [ ] Start Docker container: `docker-compose -f docker-compose.vc-demo.yml up -d`
- [ ] Enter container: `docker exec -it fixops-vc-demo bash`
- [ ] Set OpenAI API key: `export OPENAI_API_KEY="sk-proj-..."`
- [ ] Test demo mode: `python -m core.cli demo --mode demo --output /tmp/test.json --pretty`
- [ ] Test enterprise mode: `python -m core.cli demo --mode enterprise --output /tmp/test.json --pretty`
- [ ] Verify LLM response: `cat /tmp/test.json | jq '.enhanced_decision.models[0].metadata'`

### During Demo
- [ ] Show demo mode (deterministic)
- [ ] Enable OpenAI API key
- [ ] Show enterprise mode (real LLM)
- [ ] Compare metadata (deterministic vs remote)
- [ ] Show reasoning and confidence
- [ ] Explain fallback behavior

### After Demo
- [ ] Answer questions about other LLM providers
- [ ] Explain cost ($0.0002 per decision)
- [ ] Show resilience (works without API keys)

---

**End of LLM Demo Guide**

**Your OpenAI API key is ready to use! Just export it in the container and run in enterprise mode.** 🚀
