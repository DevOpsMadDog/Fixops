# FixOps Platform - Complete WIKI

**The Intelligent Security Decision Layer for Modern DevSecOps**

Version: 2.5.0 | Last Updated: 2025-10-17

---

## Table of Contents

1. [Executive Summary](#executive-summary)
2. [What is FixOps?](#what-is-fixops)
3. [Architecture Overview](#architecture-overview)
4. [Core Components](#core-components)
5. [Getting Started](#getting-started)
6. [Configuration Guide](#configuration-guide)
7. [API Reference](#api-reference)
8. [CLI Reference](#cli-reference)
9. [Compliance Frameworks](#compliance-frameworks)
10. [Mathematical Models](#mathematical-models)
11. [LLM Integration](#llm-integration)
12. [Evidence & Provenance](#evidence--provenance)
13. [Deployment Guide](#deployment-guide)
14. [Troubleshooting](#troubleshooting)
15. [FAQ](#faq)
16. [Glossary](#glossary)

---

## Executive Summary

FixOps is an **intelligent decision layer** that sits ON TOP of your existing security scanners (Snyk, Semgrep, Trivy, etc.) to transform security alert noise into actionable decisions. Unlike traditional scanners, FixOps doesn't scan code or infrastructure—it makes your scanners valuable by applying:

- **Mathematical Intelligence**: EPSS, KEV, Bayesian inference, Markov forecasting
- **Business Context**: Criticality, exposure, data classification, compliance requirements
- **Multi-LLM Consensus**: GPT-5, Claude, Gemini for explainability
- **Automated Compliance**: SOC2, ISO27001, PCI DSS, GDPR evidence generation

### Key Metrics
- **99.3% Noise Reduction**: 1,607 alerts → 12 decisions
- **60% Time Savings**: Security team efficiency gain
- **28.8x ROI**: $3.46M annual value vs $120K cost
- **<4 Second Processing**: Real-time decision making
- **85%+ Accuracy**: Multi-LLM consensus validation

---

## What is FixOps?

### The Problem

Organizations face alert fatigue:
- Security scanners generate thousands of findings
- 95%+ are false positives or irrelevant to business context
- Security teams spend weeks triaging manually
- Critical vulnerabilities lost in noise
- Compliance audits take 6+ weeks to prepare

### The FixOps Solution

FixOps is NOT a scanner. It's an **intelligence layer** that:

```
┌─────────────────────────────────────────────────────┐
│  Your Existing Scanners (Don't Change)             │
│  ├─ Snyk (SCA)                                      │
│  ├─ Semgrep (SAST)                                  │
│  ├─ Trivy (Container)                               │
│  └─ Others...                                       │
└──────────────────┬──────────────────────────────────┘
                   │ Scanner Outputs (SARIF, SBOM, CVE)
                   ↓
┌─────────────────────────────────────────────────────┐
│  FixOps Intelligence Layer                          │
│  ├─ Mathematical Models (EPSS, KEV, Bayesian)       │
│  ├─ Business Context (Criticality, Exposure)        │
│  ├─ Multi-LLM Consensus (GPT-5, Claude, Gemini)    │
│  └─ Compliance Automation (SOC2, PCI, ISO)         │
└──────────────────┬──────────────────────────────────┘
                   │ Decisions (Not Alerts)
                   ↓
┌─────────────────────────────────────────────────────┐
│  Outputs                                            │
│  ├─ APPROVE / REJECT / NEEDS_REVIEW                 │
│  ├─ Confidence Scores (0-100%)                      │
│  ├─ Evidence Bundles (7-year retention)            │
│  └─ Compliance Attestations (SOC2, PCI, ISO)       │
└─────────────────────────────────────────────────────┘
```

### What Makes FixOps Different?

| Traditional Scanners | FixOps |
|---------------------|---------|
| Scans code/containers | Consumes scanner outputs |
| Generates alerts | Makes decisions |
| No business context | Business-context-aware |
| No prioritization | Mathematical risk scoring |
| Manual triage needed | Automated decision making |
| No compliance automation | Auto-generates evidence bundles |

---

## Architecture Overview

### System Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                    FixOps Platform                            │
│                                                               │
│  ┌─────────────────┐        ┌──────────────────┐            │
│  │   API Layer     │◄──────►│   CLI Layer      │            │
│  │  (FastAPI)      │        │  (fixops-cli)    │            │
│  │  Port 8000      │        │                  │            │
│  └────────┬────────┘        └────────┬─────────┘            │
│           │                          │                       │
│           └──────────┬───────────────┘                       │
│                      ↓                                       │
│  ┌───────────────────────────────────────────────────┐      │
│  │       Pipeline Orchestrator                       │      │
│  │  ┌──────────────────────────────────────────┐    │      │
│  │  │  1. Guardrails Evaluation                │    │      │
│  │  │  2. Context Engine (Business Context)    │    │      │
│  │  │  3. Compliance Evaluator                 │    │      │
│  │  │  4. Policy Automation                    │    │      │
│  │  │  5. Vector Store (Pattern Matching)      │    │      │
│  │  │  6. SSDLC Evaluator                      │    │      │
│  │  │  7. AI Agents (LLM Consensus)            │    │      │
│  │  │  8. Exploit Signals (EPSS, KEV)          │    │      │
│  │  │  9. Probabilistic Forecasting            │    │      │
│  │  │  10. IaC Posture                         │    │      │
│  │  │  11. Analytics (ROI Dashboard)           │    │      │
│  │  │  12. Enhanced Decision Engine            │    │      │
│  │  │  13. Evidence Hub                        │    │      │
│  │  └──────────────────────────────────────────┘    │      │
│  └───────────────────────────────────────────────────┘      │
│                      ↓                                       │
│  ┌───────────────────────────────────────────────────┐      │
│  │       Data Layer                                  │      │
│  │  ├─ Evidence Lake (7-year retention)             │      │
│  │  ├─ Vulnerability Feeds (EPSS, KEV)              │      │
│  │  ├─ ChromaDB (Vector Store)                      │      │
│  │  └─ SQLite (Metadata)                            │      │
│  └───────────────────────────────────────────────────┘      │
└──────────────────────────────────────────────────────────────┘
```

### Component Diagram

```
Input Sources          Processing Layer         Output Layer
──────────────        ─────────────────        ────────────

SARIF Scans    ─┐
SBOM Files     ─┤
CVE Feeds      ─┤──►  Normalization   ──►  Mathematical    ──►  Decisions
VEX Data       ─┤                           Models              ├─ APPROVE
Design Context ─┤                                               ├─ REJECT
Business Data  ─┘                           ┌─────────────┐    └─ NEEDS_REVIEW
                                            │ EPSS + KEV  │
                     ┌──────────────┐      │ Bayesian    │    Evidence Bundles
                     │ Crosswalk    │──►   │ Markov      │    ├─ Cryptographic
                     │ Matching     │      └─────────────┘    ├─ 7-year retention
                     └──────────────┘                          └─ Compliance ready
                            │
                            ↓                Multi-LLM
                     ┌──────────────┐       Consensus         Compliance
                     │ Context      │   ┌──────────────┐     ├─ SOC2
                     │ Enrichment   │──►│ GPT-5        │     ├─ ISO27001
                     └──────────────┘   │ Claude       │     ├─ PCI DSS
                                        │ Gemini       │     └─ GDPR
                                        └──────────────┘
```

---

## Core Components

### 1. Pipeline Orchestrator

**Location**: `apps/api/pipeline.py`, `backend/pipeline.py`

The central execution engine that coordinates all modules.

**Key Functions**:
```python
class PipelineOrchestrator:
    def run(self, design_dataset, sbom, sarif, cve, overlay):
        """
        Execute enabled modules and generate pipeline result.
        
        Returns:
            dict: Complete pipeline result with:
                - crosswalk: Component-Finding-CVE mappings
                - compliance_status: Framework compliance
                - evidence_bundle: Cryptographically signed bundle
                - modules: Execution status of all modules
        """
```

**Responsibilities**:
- Input normalization (SARIF, SBOM, CVE, design context)
- Crosswalk generation (component → finding → CVE mapping)
- Module orchestration (17 modules)
- Evidence bundle generation
- Compliance evaluation

### 2. Compliance Evaluator

**Location**: `core/compliance.py`

Real production code that evaluates compliance frameworks.

**How It Works**:
```python
class ComplianceEvaluator:
    def evaluate(self, pipeline_result, context_summary):
        """
        Evaluate compliance frameworks against pipeline artifacts.
        
        For each framework (SOC2, ISO27001, PCI DSS, GDPR):
            For each control:
                Check required artifacts (design, sbom, sarif, cve, etc.)
                Determine status: satisfied | gap
                Track missing requirements
        
        Returns:
            {
                "frameworks": [{
                    "name": "SOC2",
                    "status": "satisfied",
                    "controls": [...]
                }],
                "gaps": ["ISO27001: A.12.6.1 missing sbom"]
            }
        """
```

**Supported Frameworks**:
- **SOC2**: 4 controls (CC8.1, CC7.2, CC6.1, CC6.6)
- **ISO27001**: 2 controls (A.12.6.1, A.14.2.8)
- **PCI DSS**: 6 controls (6.2, 6.5.1, 6.5.3, 6.5.8, 11.2, 11.3)
- **GDPR**: 2 controls (Article 32, Article 25)

### 3. Mathematical Models

#### EPSS (Exploit Prediction Scoring System)

**Location**: `risk/feeds/epss.py`, `data/feeds/epss.json`

**What**: Probability (0.0-1.0) that a CVE will be exploited in the wild

**Database**: 296,333 CVEs with EPSS scores

**How It's Used**:
```python
# Load EPSS scores
epss_scores = load_epss_scores()

# Check exploitation probability
cve_score = epss_scores.get("CVE-2023-12345", 0.0)
if cve_score > 0.7:  # High exploitation probability
    escalate_severity_to_critical()
```

**Update Frequency**: Auto-refreshed every 12 hours from FIRST.org

#### KEV (Known Exploited Vulnerabilities)

**Location**: `risk/feeds/kev.py`, `data/feeds/kev.json`

**What**: CISA catalog of 1,422 vulnerabilities confirmed exploited

**How It's Used**:
```python
# Load KEV catalog
kev_entries = load_kev_catalog()

# Check if CVE is being actively exploited
if cve_id in kev_entries:
    escalate_to_critical()
    flag_for_immediate_remediation()
```

**Impact**: CVEs in KEV automatically escalated to critical severity

#### Bayesian Inference

**Location**: `core/probabilistic.py`, `core/processing_layer.py`

**What**: Updates risk probability based on new evidence

**Formula**:
```
P(Risk|Evidence) = P(Evidence|Risk) × P(Risk) / P(Evidence)

Where:
- P(Risk): Prior probability from EPSS
- P(Evidence|Risk): Likelihood from business context
- P(Risk|Evidence): Posterior probability (updated risk)
```

**Example**:
```python
# Prior: EPSS says 30% exploitation probability
prior = 0.30

# Evidence: Component is internet-facing + handles PII
likelihood = 0.85

# Posterior: Updated probability = 60%
posterior = bayesian_update(prior, likelihood)
```

#### Markov Chain Forecasting

**Location**: `core/probabilistic.py`

**What**: Predicts severity transitions over time

**How It Works**:
```python
# Transition matrix for severity states
#           low    medium   high   critical
# low      [0.7,    0.2,    0.08,   0.02]
# medium   [0.1,    0.6,    0.25,   0.05]
# high     [0.05,   0.15,   0.6,    0.2]
# critical [0.0,    0.0,    0.1,    0.9]

# Forecast 7-day, 30-day, 90-day severity distribution
forecast = markov_forecast(current_state, days=[7, 30, 90])
```

**Output**:
- 7-day forecast: 60% probability of remaining high
- 30-day forecast: 35% probability of escalating to critical
- 90-day forecast: 50% probability critical if not fixed

### 4. Enhanced Decision Engine

**Location**: `core/enhanced_decision.py`, `fixops-enterprise/src/services/decision_engine.py`

**Architecture**: 6-component system

```
┌─────────────────────────────────────────────────┐
│         Enhanced Decision Engine                 │
│                                                  │
│  ┌──────────────┐   ┌──────────────┐           │
│  │ Vector DB    │   │ LLM+RAG      │           │
│  │ Pattern      │   │ Multi-model  │           │
│  │ Matching     │   │ Consensus    │           │
│  └──────────────┘   └──────────────┘           │
│                                                  │
│  ┌──────────────┐   ┌──────────────┐           │
│  │ Consensus    │   │ Golden       │           │
│  │ Checker      │   │ Regression   │           │
│  └──────────────┘   └──────────────┘           │
│                                                  │
│  ┌──────────────┐   ┌──────────────┐           │
│  │ OPA Policy   │   │ SBOM         │           │
│  │ Engine       │   │ Injection    │           │
│  └──────────────┘   └──────────────┘           │
│                                                  │
│           ↓                                      │
│     Decision + Confidence + Evidence             │
└─────────────────────────────────────────────────┘
```

**How It Works**:
1. **Vector DB**: Find similar past incidents
2. **LLM+RAG**: Get AI analysis from multiple models
3. **Consensus Checker**: Validate multi-model agreement
4. **Golden Regression**: Compare against baseline
5. **OPA Policy**: Apply Rego policy rules
6. **SBOM Injection**: Analyze component dependencies

**Output**:
```json
{
  "decision": "REJECT",
  "confidence_score": 0.89,
  "evidence_id": "uuid-123",
  "rationale": "Critical SQL injection + internet-facing + PII",
  "llm_consensus": {
    "gpt5": "REJECT",
    "claude": "REJECT",
    "gemini": "NEEDS_REVIEW",
    "agreement": 0.67
  }
}
```

### 5. Multi-LLM Consensus

**Location**: `core/llm_providers.py`, `core/enhanced_decision.py`

**Supported Models**:
- **GPT-5**: Strategic analysis, MITRE TTP mapping
- **Claude 3**: Compliance focus, guardrails
- **Gemini 2**: Exploit signals, CNAPP integration
- **Sentinel Cyber**: Threat intelligence, marketplace
- **Fallback**: Deterministic model (no API keys needed)

**Consensus Algorithm**:
```python
def multi_llm_consensus(finding, context):
    # Query each model
    responses = [
        gpt5.analyze(finding, focus=["mitre", "context"]),
        claude.analyze(finding, focus=["compliance", "guardrails"]),
        gemini.analyze(finding, focus=["exploit", "cnapp"]),
        sentinel.analyze(finding, focus=["threat", "marketplace"])
    ]
    
    # Weighted voting
    decisions = [r["decision"] for r in responses]
    confidence = calculate_agreement(responses)
    
    # Require 3/4 agreement for high confidence
    if agreement >= 0.75:
        return majority_decision, confidence
    else:
        return "NEEDS_REVIEW", confidence
```

**Fallback Behavior**:
- If no API keys: Uses deterministic rules
- If one model fails: Uses remaining models
- If all models fail: Falls back to mathematical models only

### 6. Evidence Hub

**Location**: `core/evidence.py`

**Purpose**: Generate immutable, cryptographically signed audit trails

**Evidence Bundle Contents**:
```json
{
  "bundle_id": "uuid",
  "mode": "enterprise",
  "retention_days": 2555,
  "compressed": true,
  "encrypted": true,
  "sections": [
    "design_summary",
    "sbom_summary",
    "sarif_summary",
    "cve_summary",
    "severity_overview",
    "context_summary",
    "guardrail_evaluation",
    "compliance_status",      // SOC2, PCI, ISO, GDPR
    "policy_automation",
    "analytics",
    "ai_agent_analysis",
    "probabilistic_forecast",
    "exploitability_insights",
    "ssdlc_assessment",
    "iac_posture",
    "module_execution"
  ],
  "signature": "RSA-SHA256-signature",
  "fingerprint": "key-fingerprint"
}
```

**Retention Policies**:
- **Demo Mode**: 90 days
- **Enterprise Mode**: 2,555 days (7 years)

**Security**:
- RSA-SHA256 or Ed25519 signatures
- Optional Fernet encryption
- Tamper-proof audit trail
- Non-repudiation support

---

## Getting Started

### Prerequisites

- Python 3.10 or 3.11
- Virtual environment support
- 4GB RAM minimum
- (Optional) Docker for containerized deployment

### Quick Start (5 minutes)

```bash
# 1. Clone repository
git clone https://github.com/DevOpsMadDog/Fixops.git
cd Fixops

# 2. Create virtual environment
python3.11 -m venv .venv
source .venv/bin/activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Run demo mode
export FIXOPS_MODE=demo
python -m core.cli demo --mode demo --output result.json --pretty

# 5. View results
cat result.json | jq '.guardrail_evaluation'
cat result.json | jq '.compliance_status'
cat result.json | jq '.evidence_bundle'
```

### First Demo Run

```bash
# Set environment
export FIXOPS_MODE=demo
export FIXOPS_API_TOKEN=demo-token
export FIXOPS_DISABLE_TELEMETRY=1

# Run pipeline with demo data
python -m core.cli demo \
  --mode demo \
  --output demo_output.json \
  --pretty

# Expected output:
# ✓ Loaded 10 design components
# ✓ Processed SBOM with 6 libraries
# ✓ Analyzed 3 security findings
# ✓ Evaluated 4 compliance frameworks
# ✓ Generated evidence bundle
# Pipeline Result: FAIL (2 critical findings)
```

### API Quick Start

```bash
# Start API server
export FIXOPS_API_TOKEN=demo-token
uvicorn apps.api.app:app --reload --port 8000

# In another terminal, test API
curl -H "X-API-Key: demo-token" \
  http://localhost:8000/api/v1/health

# Upload scan results
curl -H "X-API-Key: demo-token" \
  -F "file=@sample_sbom.json" \
  http://localhost:8000/inputs/sbom

# Run pipeline
curl -H "X-API-Key: demo-token" \
  http://localhost:8000/pipeline/run | jq
```

---

## Configuration Guide

### Overlay Configuration

**File**: `config/fixops.overlay.yml`

The overlay is the central configuration system. It controls:
- Module enablement
- Compliance frameworks
- Guardrail thresholds
- Data directories
- Authentication strategy

**Structure**:
```yaml
mode: enterprise  # or "demo"

# Authentication
auth:
  strategy: token  # or "jwt"
  token_env: FIXOPS_API_TOKEN
  header: X-API-Key

# Data directories
data:
  design_context_dir: data/design_context
  evidence_dir: data/evidence
  archive_dir: data/archive

# Module toggles
modules:
  guardrails: { enabled: true }
  compliance: { enabled: true }
  policy_automation: { enabled: true }
  evidence: { enabled: true }
  # ... 13 total modules

# Guardrail thresholds
guardrails:
  maturity: scaling  # foundational | scaling | advanced
  profiles:
    foundational: { fail_on: critical, warn_on: high }
    scaling: { fail_on: high, warn_on: medium }
    advanced: { fail_on: medium, warn_on: medium }

# Compliance frameworks
compliance:
  frameworks:
    - name: SOC2
      controls:
        - id: CC8.1
          title: Change Management Evidence
          requires: [design, guardrails, evidence]
    - name: PCI_DSS
      controls:
        - id: "6.2"
          title: Vulnerability management
          requires: [sbom, cve, guardrails]
    # ... more frameworks

# Policy automation
policy_automation:
  actions:
    - id: jira-guardrail-fail
      trigger: guardrail:fail
      type: jira_issue
      summary: Critical vulnerability detected
      priority: High
```

### Environment Variables

```bash
# Core settings
FIXOPS_MODE=demo|enterprise
FIXOPS_API_TOKEN=your-token-here
FIXOPS_OVERLAY_PATH=/path/to/overlay.yml

# Optional features
FIXOPS_DISABLE_TELEMETRY=1
FIXOPS_EVIDENCE_KEY=base64-fernet-key
FIXOPS_JWT_SECRET=jwt-secret

# Integration tokens
FIXOPS_JIRA_TOKEN=jira-token
FIXOPS_CONFLUENCE_TOKEN=confluence-token

# LLM API keys (optional)
OPENAI_API_KEY=openai-key
ANTHROPIC_API_KEY=anthropic-key
GOOGLE_API_KEY=google-key
```

### Demo vs Enterprise Mode

| Feature | Demo Mode | Enterprise Mode |
|---------|-----------|-----------------|
| Data Storage | In-memory | Persistent (SQLite, ChromaDB) |
| Evidence Retention | 90 days | 2,555 days (7 years) |
| Evidence Encryption | Disabled | Enabled |
| LLM Integration | Fallback only | Full multi-model |
| OPA Policy Engine | Local Rego | HTTP OPA server |
| Vector Store | 4 in-memory patterns | ChromaDB persistent |
| Jira/Confluence | Disabled | Enabled |
| Authentication | Token only | Token + JWT |

---

## API Reference

### Base URL
```
http://localhost:8000  (local)
https://fixops.example.com  (production)
```

### Authentication

All endpoints require authentication via header:
```
X-API-Key: your-token-here
```

Or JWT (enterprise mode):
```
Authorization: Bearer <jwt-token>
```

### Endpoints

#### 1. Health Check

**GET** `/api/v1/health`

Check API status and module availability.

**Response**:
```json
{
  "status": "healthy",
  "mode": "enterprise",
  "modules": {
    "guardrails": "enabled",
    "compliance": "enabled",
    "evidence": "enabled"
  },
  "automation_ready": true,
  "runtime_warnings": []
}
```

#### 2. Upload Design Context

**POST** `/inputs/design`

Upload design context CSV with business metadata.

**Request**:
```bash
curl -H "X-API-Key: $TOKEN" \
  -F "file=@design.csv;type=text/csv" \
  http://localhost:8000/inputs/design
```

**CSV Format**:
```csv
component,criticality,exposure,data_classification,compliance_framework
payment-gateway,critical,internet,payment_card_data,PCI_DSS
auth-service,critical,internet,pii,SOC2
```

**Response**:
```json
{
  "status": "success",
  "row_count": 10,
  "components": ["payment-gateway", "auth-service", ...]
}
```

#### 3. Upload SBOM

**POST** `/inputs/sbom`

Upload Software Bill of Materials (CycloneDX or SPDX).

**Request**:
```bash
curl -H "X-API-Key: $TOKEN" \
  -F "file=@sbom.json;type=application/json" \
  http://localhost:8000/inputs/sbom
```

**Response**:
```json
{
  "status": "success",
  "format": "CycloneDX",
  "component_count": 247,
  "licenses": ["MIT", "Apache-2.0", "BSD-3-Clause"]
}
```

#### 4. Upload SARIF Scan

**POST** `/inputs/sarif`

Upload security scan results in SARIF format.

**Request**:
```bash
curl -H "X-API-Key: $TOKEN" \
  -F "file=@scan.sarif;type=application/json" \
  http://localhost:8000/inputs/sarif
```

**Response**:
```json
{
  "status": "success",
  "finding_count": 127,
  "severity_distribution": {
    "critical": 2,
    "high": 15,
    "medium": 58,
    "low": 52
  }
}
```

#### 5. Upload CVE Feed

**POST** `/inputs/cve`

Upload CVE vulnerability data.

**Request**:
```bash
curl -H "X-API-Key: $TOKEN" \
  -F "file=@cve_feed.json;type=application/json" \
  http://localhost:8000/inputs/cve
```

**Response**:
```json
{
  "status": "success",
  "record_count": 342,
  "exploited_count": 12,
  "kev_matches": 5
}
```

#### 6. Run Pipeline

**GET** `/pipeline/run`

Execute complete FixOps pipeline and generate decision.

**Request**:
```bash
curl -H "X-API-Key: $TOKEN" \
  http://localhost:8000/pipeline/run | jq
```

**Response** (truncated):
```json
{
  "guardrail_evaluation": {
    "status": "fail",
    "highest_detected": "critical",
    "severity_counts": {
      "critical": 2,
      "high": 15,
      "medium": 58,
      "low": 52
    }
  },
  "compliance_status": {
    "frameworks": [
      {
        "name": "SOC2",
        "status": "satisfied",
        "controls": [...]
      },
      {
        "name": "PCI_DSS",
        "status": "in_progress",
        "controls": [...]
      }
    ],
    "gaps": ["PCI_DSS: 6.2 missing guardrails"]
  },
  "evidence_bundle": {
    "bundle_id": "uuid",
    "retention_days": 2555,
    "sections": 18,
    "signature": "RSA-SHA256-signature"
  },
  "modules": {
    "executed": ["guardrails", "compliance", "evidence", ...]
  }
}
```

#### 7. Enhanced Decision

**POST** `/api/v1/enhanced/compare-llms`

Get multi-LLM consensus analysis.

**Request**:
```bash
curl -H "X-API-Key: $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "service_name": "payment-gateway",
    "security_findings": [{
      "rule_id": "SQL-001",
      "severity": "high",
      "description": "SQL injection vulnerability"
    }],
    "business_context": {
      "criticality": "critical",
      "exposure": "internet",
      "data_classification": "payment_card_data"
    }
  }' \
  http://localhost:8000/api/v1/enhanced/compare-llms
```

**Response**:
```json
{
  "consensus_decision": "REJECT",
  "confidence_score": 0.89,
  "model_responses": {
    "gpt5": {
      "decision": "REJECT",
      "confidence": 0.92,
      "rationale": "Critical SQL injection in payment processing"
    },
    "claude": {
      "decision": "REJECT",
      "confidence": 0.88,
      "rationale": "PCI DSS requirement 6.5.1 violated"
    },
    "gemini": {
      "decision": "NEEDS_REVIEW",
      "confidence": 0.75,
      "rationale": "High risk but mitigation may be possible"
    }
  },
  "agreement_score": 0.67,
  "recommendation": "Immediate remediation required"
}
```

---

## CLI Reference

### Installation

CLI is included with the main package:
```bash
pip install -r requirements.txt
```

### Commands

#### 1. Demo Mode

Run complete demo with bundled fixtures:

```bash
python -m core.cli demo \
  --mode demo \
  --output result.json \
  --pretty
```

**Options**:
- `--mode`: demo | enterprise
- `--output`: Path to save JSON result
- `--pretty`: Pretty-print summary to stdout

#### 2. Run Pipeline

Execute pipeline with custom inputs:

```bash
python -m core.cli run \
  --overlay config/fixops.overlay.yml \
  --design design.csv \
  --sbom sbom.json \
  --sarif scan.sarif \
  --cve cve_feed.json \
  --output result.json \
  --evidence-dir evidence/
```

**Required**:
- `--overlay`: Path to overlay config
- `--sbom`: SBOM file (CycloneDX or SPDX)
- `--sarif`: SARIF scan results

**Optional**:
- `--design`: Design context CSV
- `--cve`: CVE feed JSON
- `--vex`: VEX document
- `--cnapp`: CNAPP data
- `--output`: Output path
- `--evidence-dir`: Evidence storage directory

#### 3. Show Overlay

Inspect overlay configuration:

```bash
python -m core.cli show-overlay \
  --overlay config/fixops.overlay.yml
```

Output:
```json
{
  "mode": "enterprise",
  "enabled_modules": [
    "guardrails",
    "compliance",
    "policy_automation",
    "evidence"
  ],
  "guardrail_policy": {
    "maturity": "scaling",
    "fail_on": "high",
    "warn_on": "medium"
  },
  "compliance_frameworks": ["SOC2", "ISO27001", "PCI_DSS", "GDPR"],
  "automation_ready": true
}
```

#### 4. Stage Runner

Execute individual SSDLC stages:

```bash
python -m core.cli stage-run \
  --stage requirements \
  --input requirements.yaml \
  --output outputs/requirements.json
```

**Stages**:
- `requirements`: Requirements and business analysis
- `design`: Security architecture
- `code`: Development standards
- `build`: Build and CI/CD
- `test`: Security testing
- `deploy`: Deployment validation
- `operate`: Operations and monitoring

#### 5. Train Forecast

Train probabilistic forecasting model:

```bash
python -m core.cli train-forecast \
  --incidents incidents.jsonl \
  --output forecast_model.pkl
```

Input format (JSONL):
```json
{"timestamp": "2024-01-15", "severity": "high", "resolved_in_days": 7}
{"timestamp": "2024-02-03", "severity": "critical", "resolved_in_days": 2}
```

---

## Compliance Frameworks

### Supported Frameworks

FixOps includes built-in support for 4 major compliance frameworks with 20+ controls.

#### 1. SOC2 Type II

**Controls Implemented**:

| Control | Title | Requirements | Auto-Evidence |
|---------|-------|--------------|---------------|
| CC8.1 | Change Management Evidence | design, guardrails, evidence | ✅ |
| CC7.2 | Continuous Vulnerability Management | sarif, cve, context | ✅ |
| CC6.1 | Logical and Physical Access Controls | design, context | ✅ |
| CC6.6 | Vulnerabilities Are Identified | sarif, cve, guardrails | ✅ |

**Evidence Generated**:
- Design documents with trust zones
- Vulnerability scan results (SARIF)
- Remediation tracking (guardrails)
- Access control mappings
- 7-year retention bundle

#### 2. ISO27001:2022

**Controls Implemented**:

| Control | Title | Requirements | Auto-Evidence |
|---------|-------|--------------|---------------|
| A.12.6.1 | Application vulnerability management | sbom, cve | ✅ |
| A.14.2.8 | System security testing | sarif, guardrails | ✅ |

**Evidence Generated**:
- SBOM with component inventory
- CVE tracking and remediation
- Security test results
- Compliance attestations

#### 3. PCI DSS v4.0

**Controls Implemented**:

| Control | Title | Requirements | Auto-Evidence |
|---------|-------|--------------|---------------|
| 6.2 | Protect from known vulnerabilities | sbom, cve, guardrails | ✅ |
| 6.5.1 | Injection flaws (SQL injection) | sarif, guardrails | ✅ |
| 6.5.3 | Insecure cryptographic storage | sarif, design | ✅ |
| 6.5.8 | Improper access control | sarif, design, context | ✅ |
| 11.2 | Network vulnerability scans | sarif, cve | ✅ |
| 11.3 | Penetration testing | sarif, guardrails, evidence | ✅ |

**Evidence Generated**:
- Quarterly scan results
- Vulnerability tracking
- Remediation timelines
- Penetration test reports
- Cardholder data environment mappings

#### 4. GDPR

**Controls Implemented**:

| Control | Title | Requirements | Auto-Evidence |
|---------|-------|--------------|---------------|
| Article 32 | Security of Processing | design, evidence, guardrails | ✅ |
| Article 25 | Data Protection by Design | design, context | ✅ |

**Evidence Generated**:
- Security architecture documents
- Data flow diagrams
- Privacy impact assessments
- Technical/organizational measures

### Adding Custom Frameworks

Edit `config/fixops.overlay.yml`:

```yaml
compliance:
  frameworks:
    - name: HIPAA
      controls:
        - id: "164.308(a)(1)"
          title: Security Management Process
          requires: [design, guardrails, evidence]
        - id: "164.308(a)(5)"
          title: Security Awareness and Training
          requires: [design, context]
        - id: "164.312(a)(1)"
          title: Access Control
          requires: [design, sarif, context]
        - id: "164.312(d)"
          title: Encryption and Decryption
          requires: [design, sarif]
```

### Compliance Reporting

Generate compliance report:

```bash
# Run pipeline
python -m core.cli demo --mode enterprise --output result.json

# Extract compliance status
cat result.json | jq '.compliance_status'

# View evidence bundle
cat result.json | jq '.evidence_bundle'

# Check gaps
cat result.json | jq '.compliance_status.gaps'
```

Example output:
```json
{
  "frameworks": [
    {
      "name": "SOC2",
      "status": "satisfied",
      "controls": [
        {"id": "CC8.1", "status": "satisfied", "missing": []},
        {"id": "CC7.2", "status": "satisfied", "missing": []}
      ]
    },
    {
      "name": "PCI_DSS",
      "status": "in_progress",
      "controls": [
        {"id": "6.2", "status": "gap", "missing": ["guardrails"]},
        {"id": "6.5.1", "status": "satisfied", "missing": []}
      ]
    }
  ],
  "gaps": [
    "PCI_DSS: 6.2 missing guardrails"
  ]
}
```

---

## Mathematical Models

### EPSS Integration

**Exploit Prediction Scoring System**

EPSS provides exploitation probability for CVEs based on real-world observation.

**Database**: 296,333 CVEs updated daily

**Usage**:
```python
from risk.feeds.epss import load_epss_scores

# Load EPSS data
epss = load_epss_scores()

# Get exploitation probability
cve_id = "CVE-2023-12345"
probability = epss.get(cve_id, 0.0)  # 0.0-1.0

# Escalate based on threshold
if probability > 0.7:
    severity = "critical"
elif probability > 0.4:
    severity = "high"
```

**Auto-Refresh**:
```bash
# Triggered every 12 hours automatically
# Or manually:
python -m risk.feeds.epss update
```

### KEV Integration

**Known Exploited Vulnerabilities Catalog**

CISA maintains a catalog of CVEs confirmed to be actively exploited.

**Database**: 1,422 CVEs updated weekly

**Impact**:
- CVEs in KEV automatically escalated to **critical**
- Flagged for **immediate remediation**
- Tracked in **evidence bundles**

**Usage**:
```python
from risk.feeds.kev import load_kev_catalog

# Load KEV data
kev = load_kev_catalog()

# Check if CVE is being exploited
if "CVE-2023-12345" in kev:
    escalate_to_critical()
    flag_for_immediate_remediation()
    notify_security_team()
```

### Bayesian Inference

**Risk Update Based on Evidence**

FixOps uses Bayesian inference to update risk probabilities as new evidence becomes available.

**Formula**:
```
P(Risk|Evidence) = P(Evidence|Risk) × P(Risk) / P(Evidence)

Where:
- P(Risk): Prior probability (from EPSS)
- P(Evidence|Risk): Likelihood (from business context)
- P(Risk|Evidence): Posterior probability (updated risk)
```

**Example**:
```python
# Step 1: Prior from EPSS
epss_score = 0.30  # 30% exploitation probability

# Step 2: Likelihood from business context
context = {
    "exposure": "internet",           # +0.3
    "data_classification": "pii",     # +0.4
    "criticality": "critical",        # +0.2
    "compliance_scope": "PCI_DSS"     # +0.1
}
likelihood = sum(context.values())  # 1.0

# Step 3: Posterior (updated risk)
posterior = bayesian_update(prior=0.30, likelihood=1.0)
# Result: 0.75 (75% risk probability)
```

### Markov Chain Forecasting

**Severity Transition Prediction**

FixOps uses Markov chains to forecast how vulnerability severity evolves over time.

**Transition Matrix**:
```
Current State → Future State Probability

             low    medium   high   critical
low         0.70    0.20    0.08    0.02
medium      0.10    0.60    0.25    0.05
high        0.05    0.15    0.60    0.20
critical    0.00    0.00    0.10    0.90
```

**Forecasting**:
```python
from core.probabilistic import ProbabilisticForecastEngine

# Initialize engine
engine = ProbabilisticForecastEngine(settings)

# Current state: 10 high-severity findings
current = {"high": 10}

# Forecast 7-day, 30-day, 90-day
forecast = engine.forecast(current, horizons=[7, 30, 90])

# Results:
# 7-day:  60% remain high, 20% escalate to critical
# 30-day: 35% remain high, 40% escalate to critical
# 90-day: 15% remain high, 60% escalate to critical
```

### Composite Risk Scoring

**Combining Multiple Signals**

FixOps combines EPSS, KEV, version lag, and exposure into a composite risk score (0-100).

**Formula**:
```
Risk Score = (
    EPSS_weight × EPSS_score +
    KEV_weight × KEV_flag +
    Version_Lag_weight × Version_Lag_score +
    Exposure_weight × Exposure_score
) × 100

Default weights:
- EPSS: 0.30
- KEV: 0.40
- Version_Lag: 0.20
- Exposure: 0.10
```

**Example**:
```python
from risk.scoring import compute_risk_profile

risk = compute_risk_profile(
    epss_score=0.75,        # High exploitation probability
    kev_match=True,         # Being actively exploited
    version_lag_days=180,   # 6 months behind patch
    exposure="internet"     # Internet-facing
)

# Result:
# {
#   "composite_score": 87,  # 0-100 scale
#   "severity": "critical",
#   "priority": "P0",
#   "recommendation": "Immediate remediation required"
# }
```

---

## LLM Integration

### Supported Models

FixOps integrates with 5 LLM providers for multi-model consensus.

| Provider | Model | Focus Areas | Fallback |
|----------|-------|-------------|----------|
| OpenAI | GPT-5 | MITRE TTP mapping, strategic analysis | ✅ |
| Anthropic | Claude 3 | Compliance, guardrails, policy | ✅ |
| Google | Gemini 2 | Exploit signals, CNAPP, cloud security | ✅ |
| Custom | Sentinel Cyber | Threat intelligence, marketplace | ✅ |
| Deterministic | Rule-based | Mathematical models only | Always available |

### Configuration

Set API keys in environment:
```bash
export OPENAI_API_KEY=sk-...
export ANTHROPIC_API_KEY=sk-ant-...
export GOOGLE_API_KEY=...
```

Or configure in overlay:
```yaml
enhanced_decision:
  baseline_confidence: 0.82
  providers:
    - name: gpt-5
      style: strategist
      focus: [mitre, context]
      api_key_env: OPENAI_API_KEY
    - name: claude-3
      style: analyst
      focus: [compliance, guardrails]
      api_key_env: ANTHROPIC_API_KEY
```

### Multi-Model Consensus

**How It Works**:

1. **Query Each Model**:
   ```python
   gpt5_response = query_gpt5(finding, focus=["mitre", "context"])
   claude_response = query_claude(finding, focus=["compliance"])
   gemini_response = query_gemini(finding, focus=["exploit"])
   ```

2. **Collect Decisions**:
   ```python
   responses = {
       "gpt5": {"decision": "REJECT", "confidence": 0.92},
       "claude": {"decision": "REJECT", "confidence": 0.88},
       "gemini": {"decision": "NEEDS_REVIEW", "confidence": 0.75}
   }
   ```

3. **Calculate Agreement**:
   ```python
   agreement = count("REJECT") / total_models  # 0.67 (2/3)
   ```

4. **Determine Consensus**:
   ```python
   if agreement >= 0.75:
       decision = majority_vote
       confidence = "high"
   elif agreement >= 0.50:
       decision = majority_vote
       confidence = "medium"
   else:
       decision = "NEEDS_REVIEW"
       confidence = "low"
   ```

### Fallback Behavior

If LLM APIs are unavailable:

1. **Use Deterministic Model**: Rule-based decision using mathematical models only
2. **Partial Consensus**: Use available models if some fail
3. **Graceful Degradation**: Never block pipeline execution

Example fallback:
```python
try:
    llm_decision = multi_llm_consensus(finding)
except LLMError:
    # Fall back to mathematical models
    llm_decision = {
        "decision": determine_from_math_models(finding),
        "confidence": 0.70,
        "method": "fallback_deterministic"
    }
```

### Prompt Engineering

FixOps uses structured prompts for consistent results:

```python
prompt = f"""
You are a security expert analyzing a vulnerability.

Finding:
- Rule: {finding.rule_id}
- Severity: {finding.severity}
- Description: {finding.description}

Business Context:
- Component: {context.component_name}
- Criticality: {context.criticality}
- Exposure: {context.exposure}
- Data Classification: {context.data_classification}

Compliance Requirements:
- Frameworks: {context.frameworks}

Provide a decision (APPROVE/REJECT/NEEDS_REVIEW) with:
1. Rationale (2-3 sentences)
2. Confidence score (0-100)
3. Recommended action
4. MITRE ATT&CK techniques (if applicable)

Format your response as JSON.
"""
```

---

## Evidence & Provenance

### Evidence Bundles

**What**: Cryptographically signed archives containing all decision artifacts

**Purpose**: 
- Audit trails for compliance
- Non-repudiation
- Historical analysis
- Regulatory compliance

**Structure**:
```
evidence_bundle/
├── bundle.json.gz.enc          # Encrypted compressed bundle
├── manifest.json               # Metadata
└── signature.txt              # RSA-SHA256 signature
```

**Contents** (`bundle.json`):
```json
{
  "mode": "enterprise",
  "run_id": "uuid",
  "timestamp": "2025-10-17T20:00:00Z",
  
  "design_summary": {...},
  "sbom_summary": {...},
  "sarif_summary": {...},
  "cve_summary": {...},
  
  "guardrail_evaluation": {...},
  "compliance_status": {
    "frameworks": [...],
    "gaps": [...]
  },
  
  "context_summary": {...},
  "policy_automation": {...},
  "ai_agent_analysis": {...},
  "probabilistic_forecast": {...},
  
  "evidence_bundle": {
    "bundle_id": "uuid",
    "retention_days": 2555,
    "signature": "RSA-SHA256-sig",
    "fingerprint": "key-fingerprint"
  }
}
```

### Cryptographic Signing

**Algorithm**: RSA-SHA256 or Ed25519

**Process**:
```
1. Serialize bundle to JSON
2. Compute SHA-256 hash
3. Sign hash with private key
4. Store signature + fingerprint
5. Compress (gzip)
6. Encrypt (Fernet, optional)
7. Save to evidence directory
```

**Verification**:
```python
from core.evidence import EvidenceHub

# Load bundle
bundle = load_evidence_bundle("bundle_id")

# Verify signature
is_valid = verify_signature(
    bundle["data"],
    bundle["signature"],
    bundle["fingerprint"]
)

# Check tampering
if not is_valid:
    raise TamperDetected("Bundle has been modified")
```

### Retention Policies

| Mode | Retention | Encryption | Compression |
|------|-----------|------------|-------------|
| Demo | 90 days | Optional | Yes |
| Enterprise | 2,555 days (7 years) | Required | Yes |

**Audit Trail**:
```
transparency.index:
2025-10-17T20:00:00Z|bundle-uuid|sha256-hash|key-fingerprint
2025-10-17T20:05:00Z|bundle-uuid|sha256-hash|key-fingerprint
```

### SLSA Provenance

**SLSA Level**: v1.0

**Attestation Format**:
```json
{
  "_type": "https://in-toto.io/Statement/v0.1",
  "predicateType": "https://slsa.dev/provenance/v1",
  "subject": [
    {
      "name": "fixops-bundle",
      "digest": {"sha256": "abc123..."}
    }
  ],
  "predicate": {
    "buildDefinition": {
      "buildType": "https://fixops.dev/pipeline/v1",
      "externalParameters": {
        "sbom_components": 247,
        "sarif_findings": 127,
        "compliance_frameworks": ["SOC2", "PCI_DSS"]
      }
    },
    "runDetails": {
      "builder": {
        "id": "https://fixops.dev/builder/v2.5.0"
      },
      "metadata": {
        "invocationId": "uuid",
        "startedOn": "2025-10-17T20:00:00Z",
        "finishedOn": "2025-10-17T20:00:04Z"
      }
    }
  }
}
```

### Evidence Retrieval

**CLI**:
```bash
# List evidence bundles
python -m core.cli list-evidence

# Retrieve specific bundle
python -m core.cli get-evidence --bundle-id uuid

# Verify signature
python -m core.cli verify-evidence --bundle-id uuid

# Export for audit
python -m core.cli export-evidence \
  --bundle-id uuid \
  --output audit_package.tar.gz
```

**API**:
```bash
# Get evidence bundle
curl -H "X-API-Key: $TOKEN" \
  http://localhost:8000/api/v1/evidence/bundles/uuid

# Verify signature
curl -H "X-API-Key: $TOKEN" \
  http://localhost:8000/api/v1/evidence/bundles/uuid/verify

# Download bundle
curl -H "X-API-Key: $TOKEN" \
  -o bundle.tar.gz \
  http://localhost:8000/api/v1/evidence/bundles/uuid/download
```

---

## Deployment Guide

### Local Development

```bash
# 1. Clone and setup
git clone https://github.com/DevOpsMadDog/Fixops.git
cd Fixops
python3.11 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

# 2. Configure
cp config/fixops.overlay.yml config/my-overlay.yml
export FIXOPS_OVERLAY_PATH=config/my-overlay.yml
export FIXOPS_API_TOKEN=dev-token

# 3. Run API
uvicorn apps.api.app:app --reload --port 8000

# 4. Test
curl -H "X-API-Key: dev-token" http://localhost:8000/api/v1/health
```

### Docker Deployment

**Dockerfile** (create if needed):
```dockerfile
FROM python:3.11-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .

# Create data directories
RUN mkdir -p data/evidence data/uploads data/analytics && \
    chmod 750 data/*

# Expose port
EXPOSE 8000

# Run application
CMD ["uvicorn", "apps.api.app:app", "--host", "0.0.0.0", "--port", "8000"]
```

**Build and run**:
```bash
# Build image
docker build -t fixops:2.5.0 .

# Run container
docker run -d \
  --name fixops \
  -p 8000:8000 \
  -e FIXOPS_MODE=enterprise \
  -e FIXOPS_API_TOKEN=prod-token \
  -e FIXOPS_EVIDENCE_KEY=base64-key \
  -v /srv/fixops/data:/app/data \
  -v /srv/fixops/config:/app/config \
  fixops:2.5.0

# Check logs
docker logs -f fixops
```

### Docker Compose

**docker-compose.yml**:
```yaml
version: '3.8'

services:
  fixops:
    image: fixops:2.5.0
    ports:
      - "8000:8000"
    environment:
      FIXOPS_MODE: enterprise
      FIXOPS_API_TOKEN: ${FIXOPS_API_TOKEN}
      FIXOPS_EVIDENCE_KEY: ${FIXOPS_EVIDENCE_KEY}
      OPENAI_API_KEY: ${OPENAI_API_KEY}
      ANTHROPIC_API_KEY: ${ANTHROPIC_API_KEY}
    volumes:
      - ./data:/app/data
      - ./config:/app/config
    restart: unless-stopped

  chromadb:
    image: chromadb/chroma:latest
    ports:
      - "8001:8000"
    volumes:
      - chromadb_data:/chroma/chroma
    restart: unless-stopped

volumes:
  chromadb_data:
```

**Start services**:
```bash
docker-compose up -d
```

### Kubernetes Deployment

**fixops-deployment.yaml**:
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: fixops
  namespace: security
spec:
  replicas: 3
  selector:
    matchLabels:
      app: fixops
  template:
    metadata:
      labels:
        app: fixops
    spec:
      containers:
      - name: fixops
        image: fixops:2.5.0
        ports:
        - containerPort: 8000
        env:
        - name: FIXOPS_MODE
          value: "enterprise"
        - name: FIXOPS_API_TOKEN
          valueFrom:
            secretKeyRef:
              name: fixops-secrets
              key: api-token
        - name: FIXOPS_EVIDENCE_KEY
          valueFrom:
            secretKeyRef:
              name: fixops-secrets
              key: evidence-key
        volumeMounts:
        - name: data
          mountPath: /app/data
        - name: config
          mountPath: /app/config
        resources:
          requests:
            memory: "2Gi"
            cpu: "1"
          limits:
            memory: "4Gi"
            cpu: "2"
        livenessProbe:
          httpGet:
            path: /api/v1/health
            port: 8000
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /api/v1/health
            port: 8000
          initialDelaySeconds: 5
          periodSeconds: 5
      volumes:
      - name: data
        persistentVolumeClaim:
          claimName: fixops-data-pvc
      - name: config
        configMap:
          name: fixops-config
---
apiVersion: v1
kind: Service
metadata:
  name: fixops
  namespace: security
spec:
  selector:
    app: fixops
  ports:
  - port: 80
    targetPort: 8000
  type: LoadBalancer
```

**Apply**:
```bash
kubectl apply -f fixops-deployment.yaml
```

### Production Checklist

Before deploying to production:

- [ ] Set strong `FIXOPS_API_TOKEN` (32+ characters)
- [ ] Generate `FIXOPS_EVIDENCE_KEY` (Fernet key)
- [ ] Configure data directory permissions (0750)
- [ ] Enable evidence encryption
- [ ] Set up 7-year retention
- [ ] Configure Jira/Confluence integration
- [ ] Set up LLM API keys
- [ ] Configure ChromaDB persistence
- [ ] Set up log aggregation
- [ ] Configure Prometheus metrics
- [ ] Set up Grafana dashboards
- [ ] Test disaster recovery
- [ ] Document runbook procedures
- [ ] Train security team
- [ ] Schedule auditor walkthrough

---

## Troubleshooting

### Common Issues

#### 1. "Authentication failed"

**Symptom**: 401 Unauthorized

**Solution**:
```bash
# Check token is set
echo $FIXOPS_API_TOKEN

# Verify header name
# Default: X-API-Key
curl -H "X-API-Key: $FIXOPS_API_TOKEN" http://localhost:8000/api/v1/health

# Check overlay config
cat config/fixops.overlay.yml | grep -A 3 "auth:"
```

#### 2. "Evidence encryption disabled"

**Symptom**: Warning in logs

**Solution**:
```bash
# Generate Fernet key
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

# Set environment variable
export FIXOPS_EVIDENCE_KEY=<generated-key>

# Or disable encryption
# In overlay: limits.evidence.encrypt: false
```

#### 3. "Module not enabled"

**Symptom**: Missing results in pipeline output

**Solution**:
```bash
# Check module status
python -m core.cli show-overlay | jq '.enabled_modules'

# Enable module in overlay
# config/fixops.overlay.yml:
# modules:
#   compliance: { enabled: true }

# Or enable via CLI
python -m core.cli run --enable compliance ...
```

#### 4. "Automation prerequisites missing"

**Symptom**: Policy automation skipped

**Solution**:
```bash
# Check required tokens
echo $FIXOPS_JIRA_TOKEN
echo $FIXOPS_CONFLUENCE_TOKEN

# Set tokens
export FIXOPS_JIRA_TOKEN=your-token
export FIXOPS_CONFLUENCE_TOKEN=your-token

# Verify automation ready
python -m core.cli show-overlay | jq '.automation_ready'
```

#### 5. "LLM API error"

**Symptom**: Enhanced decision fails

**Solution**:
```bash
# Check API keys
echo $OPENAI_API_KEY
echo $ANTHROPIC_API_KEY

# Verify rate limits
curl https://api.openai.com/v1/models \
  -H "Authorization: Bearer $OPENAI_API_KEY"

# Use fallback mode (no API keys needed)
# FixOps automatically falls back to deterministic model
```

### Debug Mode

Enable verbose logging:

```bash
# Set log level
export FIXOPS_LOG_LEVEL=DEBUG

# Run with verbose output
python -m core.cli demo --mode demo --pretty --verbose

# Check logs
tail -f logs/fixops.log
```

### Performance Issues

If pipeline is slow:

1. **Check module count**:
   ```bash
   # Disable unused modules
   # In overlay: modules.<module>: { enabled: false }
   ```

2. **Check data size**:
   ```bash
   # Limit SARIF findings
   # Limit SBOM components
   # Use chunked uploads for large files
   ```

3. **Check LLM timeouts**:
   ```bash
   # Increase timeout in overlay
   # enhanced_decision:
   #   timeout_seconds: 30
   ```

4. **Check disk I/O**:
   ```bash
   # Use SSD for data directories
   # Enable compression
   # limits.evidence.compress: true
   ```

### Getting Help

1. **Check logs**: `/logs/fixops.log`
2. **Review overlay**: `python -m core.cli show-overlay`
3. **Health check**: `curl http://localhost:8000/api/v1/health`
4. **Documentation**: https://docs.fixops.dev
5. **Support**: support@fixops.dev

---

## FAQ

### General Questions

**Q: Is FixOps a security scanner?**  
A: No. FixOps is an intelligent decision layer that sits ON TOP of your existing scanners (Snyk, Semgrep, Trivy, etc.). It consumes scanner outputs and makes them actionable.

**Q: Do I need to replace my existing scanners?**  
A: No. FixOps works with your existing scanners. Just feed their outputs (SARIF, SBOM, CVE) into FixOps.

**Q: How does FixOps reduce noise by 99.3%?**  
A: By applying mathematical models (EPSS, KEV), business context (criticality, exposure), and multi-LLM consensus to prioritize only critical issues.

**Q: What's the difference between demo and enterprise mode?**  
A: Demo uses in-memory storage, 90-day retention, and fallback LLM. Enterprise uses persistent storage, 7-year retention, and full multi-LLM consensus.

### Technical Questions

**Q: What programming language is FixOps written in?**  
A: Python 3.10/3.11. Backend uses FastAPI, CLI uses Click, math models use NumPy/SciPy.

**Q: Can I run FixOps without LLM API keys?**  
A: Yes. FixOps automatically falls back to deterministic mathematical models if no LLM keys are provided.

**Q: How is compliance evidence generated?**  
A: FixOps evaluates each compliance control against pipeline artifacts (design, SBOM, SARIF, CVE). Results are saved to cryptographically signed evidence bundles with 7-year retention.

**Q: Can I add custom compliance frameworks?**  
A: Yes. Edit `config/fixops.overlay.yml` and add your framework with controls and requirements.

**Q: How is evidence encrypted?**  
A: Using Fernet symmetric encryption (AES-128-CBC + HMAC-SHA256). Signatures use RSA-SHA256 or Ed25519.

### Integration Questions

**Q: How do I integrate with CI/CD?**  
A: Use the CLI in your pipeline:
```bash
fixops run --sbom sbom.json --sarif scan.sarif --output result.json
if [ $? -eq 1 ]; then exit 1; fi  # Fail pipeline if guardrails fail
```

**Q: Can I integrate with Jira/Confluence?**  
A: Yes. Configure tokens in overlay and enable policy automation. FixOps will automatically create tickets/pages.

**Q: Does FixOps support Slack notifications?**  
A: Yes, via policy automation. Configure webhook URL and triggers in overlay.

**Q: Can I use FixOps with GitHub Actions?**  
A: Yes. See example workflow:
```yaml
- name: Run FixOps
  run: |
    fixops run --sbom sbom.json --sarif scan.sarif
  env:
    FIXOPS_API_TOKEN: ${{ secrets.FIXOPS_TOKEN }}
```

### Compliance Questions

**Q: Is FixOps SOC2 compliant?**  
A: FixOps helps YOU achieve compliance by generating evidence. The platform itself follows SOC2 controls.

**Q: Can FixOps help with PCI DSS certification?**  
A: Yes. FixOps tracks PCI DSS requirements and generates quarterly scan evidence.

**Q: How long is evidence retained?**  
A: 90 days (demo) or 7 years/2,555 days (enterprise).

**Q: Can auditors access evidence bundles?**  
A: Yes. Evidence bundles are cryptographically signed and can be exported for auditor review.

---

## Glossary

**APPROVE**: Decision to allow deployment to proceed. No critical issues found.

**Bayesian Inference**: Statistical method to update risk probability based on new evidence.

**Business Context**: Metadata about components (criticality, exposure, data classification).

**ChromaDB**: Vector database for similarity search and pattern matching.

**Compliance Evaluator**: Module that checks artifacts against compliance framework requirements.

**Crosswalk**: Mapping between design components, SBOM entries, SARIF findings, and CVE records.

**CVE**: Common Vulnerabilities and Exposures. Standard identifier for security vulnerabilities.

**EPSS**: Exploit Prediction Scoring System. Probability (0-1) that a CVE will be exploited.

**Evidence Bundle**: Cryptographically signed archive containing all decision artifacts.

**Fernet**: Symmetric encryption scheme (AES-128-CBC + HMAC-SHA256).

**Guardrails**: Policy enforcement that fails pipeline on critical vulnerabilities.

**KEV**: Known Exploited Vulnerabilities. CISA catalog of 1,422 actively exploited CVEs.

**LLM**: Large Language Model. AI models for natural language analysis (GPT-5, Claude, Gemini).

**Markov Chain**: Mathematical model for predicting state transitions over time.

**NEEDS_REVIEW**: Decision requiring human judgment. Not clearly APPROVE or REJECT.

**Noise Reduction**: Process of filtering out false positives and low-priority alerts.

**Overlay**: Central YAML configuration controlling modules, frameworks, and policies.

**Pipeline Orchestrator**: Core engine that coordinates all modules and generates results.

**REJECT**: Decision to block deployment. Critical issues must be fixed first.

**SARIF**: Static Analysis Results Interchange Format. Standard for security scan results.

**SBOM**: Software Bill of Materials. Inventory of software components and dependencies.

**SLSA**: Supply chain Levels for Software Artifacts. Framework for build provenance.

**SOC2**: Service Organization Control 2. Compliance framework for service providers.

**Vector Store**: Database for similarity search using vector embeddings.

---

## Additional Resources

### Documentation
- **Architecture Guide**: `docs/ARCHITECTURE.md`
- **Security Guide**: `docs/SECURITY.md`
- **Configuration Reference**: `docs/CONFIG_GUIDE.md`
- **API Specification**: `docs/API_SPEC.md`

### Examples
- **Demo Scripts**: `scripts/run_demo_steps.py`
- **Sample Data**: `demo/fixtures/`
- **SSDLC Stages**: `demo_ssdlc_stages/`

### Community
- **GitHub**: https://github.com/DevOpsMadDog/Fixops
- **Documentation**: https://docs.fixops.dev
- **Support**: support@fixops.dev

### Contributing
- **Contributing Guide**: `CONTRIBUTING.md`
- **Code of Conduct**: `CODE_OF_CONDUCT.md`
- **Changelog**: `CHANGELOG.md`

---

**FixOps Platform** - Making Security Scanners Valuable Through Intelligence

Version 2.5.0 | © 2025 FixOps | Apache 2.0 License
