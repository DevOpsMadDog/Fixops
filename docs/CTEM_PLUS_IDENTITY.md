# ALdeci CTEM+ Platform Identity

> **Canonical Reference**: Every agent, every document, every test collection MUST reference this identity.
> Last Updated: 2026-02-20

## ALdeci is NOT Just an Aggregator — It IS the Scanner

ALdeci's "Switzerland of AppSec" positioning means we work WITH every tool. But we are **not dependent** on any of them.
ALdeci is a **complete CTEM+ (Continuous Threat Exposure Management Plus) platform** with:

1. **8 Built-in Fallback Scanners** (works air-gapped, no external tools needed)
2. **OSS/SCA Engine** (Trivy, Grype, Sigstore, OPA integration + standalone)
3. **AI-Powered AutoFix Engine** (10 fix types, PR generation, confidence-based auto-apply)
4. **12-Step Brain Pipeline** (full CTEM lifecycle — every step implemented)
5. **19-Phase MPTE Verification** (prove exploitability, don't just detect)
6. **FAIL Engine** (chaos engineering for AppSec)
7. **Multi-LLM Consensus Decision Engine** (3+ LLMs, 85% threshold)
8. **Quantum-Secure Evidence** (FIPS 204 ML-DSA + RSA hybrid, 7-year WORM)

### The Air-Gap Story
When an enterprise deploys ALdeci in an air-gapped environment (defense, critical infrastructure, healthcare):
- **No Snyk? No Semgrep?** → ALdeci's native SAST engine (465 LOC) scans code directly
- **No Trivy available?** → ALdeci's native Container scanner (410 LOC) analyzes Dockerfiles/images
- **No ZAP running?** → ALdeci's native DAST engine (533 LOC) performs dynamic testing
- **No TruffleHog?** → ALdeci's native Secrets scanner (775 LOC) detects leaked credentials
- **No Prisma Cloud?** → ALdeci's native CSPM/IaC scanner (586 LOC) checks Terraform/CloudFormation
- **No commercial API fuzzer?** → ALdeci's native API Fuzzer tests endpoints
- **No malware scanner?** → ALdeci's native Malware Detector analyzes content
- **No LLM guardrails?** → ALdeci's native LLM Monitor detects prompt injection

**Result**: Full CTEM coverage with ZERO external dependencies.

---

## 8 Built-in Scanner Inventory

| # | Scanner | Engine File | LOC | Router File | Endpoints | Key Capabilities |
|---|---------|-------------|-----|-------------|-----------|------------------|
| 1 | **SAST** | `suite-core/core/sast_engine.py` | 465 | `suite-attack/api/sast_router.py` | 4 | Multi-language static analysis (Python, JS, Java, Go), pattern matching, taint analysis, rule engine |
| 2 | **DAST** | `suite-core/core/dast_engine.py` | 533 | `suite-attack/api/dast_router.py` | 2 | Dynamic web testing, XSS/SQLi/SSRF detection, authenticated scanning, crawl+fuzz |
| 3 | **Secrets** | `suite-core/core/secrets_scanner.py` | 775 | `suite-attack/api/secrets_router.py` | 7 | 200+ patterns, entropy analysis, git history scanning, cloud credential detection |
| 4 | **Container** | `suite-core/core/container_scanner.py` | 410 | `suite-attack/api/container_router.py` | 3 | Dockerfile analysis, image layer scanning, CVE matching, privilege escalation detection |
| 5 | **CSPM/IaC** | `suite-core/core/cspm_engine.py` | 586 | `suite-attack/api/cspm_router.py` + `suite-integrations/api/iac_router.py` | 9 | Terraform/CloudFormation/K8s YAML, CIS benchmarks, misconfig detection |
| 6 | **API Fuzzer** | (inline) | ~200 | `suite-attack/api/api_fuzzer_router.py` | 3 | Endpoint discovery, parameter fuzzing, auth bypass testing |
| 7 | **Malware** | (inline) | ~200 | `suite-attack/api/malware_router.py` | 4 | Content analysis, signature matching, heuristic detection |
| 8 | **LLM Monitor** | (inline) | ~200 | `suite-core/api/llm_monitor_router.py` | 4 | Prompt injection detection, jailbreak detection, PII leakage |

**Total**: ~3,369+ LOC across 10 engine/router files, ~36 API endpoints

---

## OSS/SCA Capabilities

| Tool | Integration | Endpoints | Capabilities |
|------|-------------|-----------|--------------|
| **Trivy** | `suite-integrations/api/oss_tools.py` | `/scan/trivy` | Container + filesystem vulnerability scanning |
| **Grype** | `suite-integrations/api/oss_tools.py` | `/scan/grype` | SBOM-based vulnerability matching |
| **Sigstore/Cosign** | `suite-integrations/api/oss_tools.py` | `/verify/sigstore` | Software supply chain verification |
| **OPA** | `suite-integrations/api/oss_tools.py` | `/policy/evaluate` | Policy-as-code evaluation |
| **SBOM Generation** | `suite-api/apps/api/inventory_router.py` | `/inventory/sbom` | CycloneDX 1.5 / SPDX 2.3 |
| **License Compliance** | `suite-api/apps/api/inventory_router.py` | `/inventory/license-compliance` | OSS license policy enforcement |
| **Validation** | `suite-core/api/validation_router.py` (492 LOC) | 4 endpoints | SARIF/SBOM/CVE/VEX/CNAPP format validation |

**Total**: 8 OSS endpoints + 6 SBOM/validation endpoints = 14 endpoints

---

## AutoFix Engine (1,260 LOC)

**Engine**: `suite-core/core/autofix_engine.py` (1,260 LOC)
**Router**: `suite-core/api/autofix_router.py` (270 LOC, 12 endpoints)
**Supporting**: `suite-core/automation/remediation.py` (318 LOC), `pr_generator.py` (464 LOC), `dependency_updater.py` (300 LOC)

### 10 Fix Types
| Type | Description | Auto-Apply Threshold |
|------|-------------|---------------------|
| `CODE_PATCH` | Source code vulnerability fix | HIGH confidence |
| `DEPENDENCY_UPDATE` | Upgrade vulnerable dependency | HIGH confidence |
| `CONFIG_HARDENING` | Security configuration fix | HIGH confidence |
| `IAC_FIX` | Infrastructure-as-Code remediation | MEDIUM confidence |
| `SECRET_ROTATION` | Rotate exposed credentials | IMMEDIATE |
| `PERMISSION_FIX` | Least-privilege correction | MEDIUM confidence |
| `INPUT_VALIDATION` | Add/fix input sanitization | MEDIUM confidence |
| `OUTPUT_ENCODING` | XSS prevention encoding | HIGH confidence |
| `WAF_RULE` | Generate WAF rule for finding | LOW confidence |
| `CONTAINER_FIX` | Dockerfile/image hardening | MEDIUM confidence |

### Confidence Levels
- **HIGH** (>85%): Auto-apply, create PR, notify
- **MEDIUM** (60-85%): Create PR for review, assign to dev
- **LOW** (<60%): Suggest only, human decision required

### 14 AutoFix Endpoints
`/autofix/generate`, `/autofix/generate/bulk`, `/autofix/apply/{id}`, `/autofix/validate/{id}`,
`/autofix/rollback/{id}`, `/autofix/fixes/{id}`, `/autofix/suggestions/{finding_id}`,
`/autofix/history`, `/autofix/stats`, `/autofix/health`, `/autofix/fix-types`,
`/autofix/confidence-levels`, `/remediation/auto-fix`, `/remediation/auto-fix/bulk`

---

## 12-Step Brain Pipeline (CTEM Lifecycle)

**Engine**: `suite-core/core/brain_pipeline.py` (864 LOC) — ALL 12 STEPS IMPLEMENTED

| Step | Name | Description | Status |
|------|------|-------------|--------|
| 1 | `connect` | Ingest from external scanners (Snyk, Semgrep, etc.) OR native scanners | ✅ REAL |
| 2 | `normalize` | Convert all formats to ALdeci Universal Finding Format (UFF) | ✅ REAL |
| 3 | `resolve_identity` | Map findings to APP_ID → Component → Feature hierarchy | ✅ REAL |
| 4 | `deduplicate` | Cross-scanner deduplication (same vuln from different tools) | ✅ REAL |
| 5 | `build_graph` | Construct knowledge graph (findings, assets, relationships) | ✅ REAL |
| 6 | `enrich_threats` | Enrich with NVD/KEV/EPSS threat intelligence feeds | ✅ REAL (deterministic) |
| 7 | `score_risk` | Multi-factor risk scoring (CVSS + EPSS + business context) | ✅ REAL |
| 8 | `apply_policy` | Evaluate against org security policies | ✅ REAL |
| 9 | `llm_consensus` | Multi-LLM vote (GPT-4 + Claude + Gemini), 85% threshold | ✅ REAL |
| 10 | `micro_pentest` | MPTE 19-phase exploit verification | ✅ REAL |
| 11 | `run_playbooks` | Execute remediation playbooks (AutoFix) | ✅ REAL |
| 12 | `generate_evidence` | Produce signed compliance evidence bundles | ✅ REAL |

### CTEM+ Enhancements (5-Year Roadmap)
1. **Step 6 Enhancement**: Wire live thread feed APIs (`/api/v1/feeds/*`) for real-time enrichment
2. **Step 7 Enhancement**: GNN (Graph Neural Network) attack-path analysis for contextual risk
3. **Step 10→11→10 Loop**: Remediation verification — after autofix, re-verify exploitability
4. **Step 12 Enhancement**: Quantum-secure ML-DSA signatures on evidence bundles
5. **Dedicated CTEM Router**: `/api/v1/ctem/*` — first-class CTEM API surface

---

## MPTE (Micro Pen-Test Engine) — 19 Phase Verification

**69 endpoints** across 5 router files. Proves exploitability, doesn't just detect.

| Phase | Description |
|-------|-------------|
| 1 | Target reconnaissance |
| 2 | Port/service enumeration |
| 3-5 | Vulnerability identification & classification |
| 6-8 | Exploit selection & customization |
| 9-12 | Controlled exploitation with safety bounds |
| 13-15 | Post-exploitation evidence collection |
| 16-17 | Lateral movement assessment |
| 18 | Cleanup & restoration |
| 19 | Evidence-grade report generation |

---

## 5-Year Future-Proofing Architecture

### Year 1 (2026): Foundation
- [x] 8 native scanners operational
- [x] 12-step Brain Pipeline complete
- [x] Multi-LLM consensus engine
- [x] AutoFix with 10 fix types
- [ ] Dedicated `/api/v1/ctem/*` router
- [ ] GNN attack-path analysis (step 7)

### Year 2 (2027): Intelligence
- [ ] Self-hosted LLM via vLLM ($0/mo vs $6K/mo vendor APIs)
- [ ] Federated learning across air-gapped deployments
- [ ] Real-time threat feed wiring (step 6)
- [ ] Remediation verification loop (step 11→10→11)
- [ ] Quantum-secure evidence signing (step 12)

### Year 3 (2028): Autonomy
- [ ] Autonomous CTEM — continuous scan-verify-fix without human intervention
- [ ] Self-healing remediation (auto-rollback on regression)
- [ ] Predictive vulnerability scoring (before CVE is published)
- [ ] GNN-powered blast radius estimation

### Year 4 (2029): Scale
- [ ] Multi-tenant SaaS with org-level isolation
- [ ] 1M+ findings/day processing
- [ ] Real-time compliance continuous monitoring
- [ ] Distributed MPTE across edge nodes

### Year 5 (2030): Dominance
- [ ] Industry-standard CTEM API (other tools build ON ALdeci)
- [ ] AppSec digital twin — simulate attacks before deployment
- [ ] Post-quantum cryptography (full PQC migration)
- [ ] AI agent marketplace (third-party agents plug into ALdeci)

---

## Competitor Comparison Matrix

| Capability | ALdeci CTEM+ | Snyk | Wiz | Semgrep | Checkmarx |
|-----------|-------------|------|-----|---------|-----------|
| Built-in SAST | ✅ | ✅ | ❌ | ✅ | ✅ |
| Built-in DAST | ✅ | ❌ | ❌ | ❌ | ✅ |
| Built-in Secrets | ✅ | ❌ | ✅ | ✅ | ❌ |
| Built-in Container | ✅ | ✅ | ✅ | ❌ | ❌ |
| Built-in CSPM/IaC | ✅ | ✅ | ✅ | ❌ | ❌ |
| Built-in API Fuzzer | ✅ | ❌ | ❌ | ❌ | ❌ |
| Built-in Malware | ✅ | ❌ | ✅ | ❌ | ❌ |
| Built-in LLM Monitor | ✅ | ❌ | ❌ | ❌ | ❌ |
| Multi-LLM Consensus | ✅ | ❌ | ❌ | ❌ | ❌ |
| MPTE Exploit Verification | ✅ | ❌ | ❌ | ❌ | ❌ |
| FAIL Engine (Chaos) | ✅ | ❌ | ❌ | ❌ | ❌ |
| AutoFix (10 types) | ✅ | ✅ (2) | ❌ | ✅ (1) | ✅ (1) |
| Air-Gapped Deployment | ✅ | ❌ | ❌ | ✅ | ✅ |
| Quantum-Secure Evidence | ✅ | ❌ | ❌ | ❌ | ❌ |
| Switzerland Orchestration | ✅ | ❌ | ❌ | ❌ | ❌ |
| 12-Step CTEM Pipeline | ✅ | ❌ | ❌ | ❌ | ❌ |
| MCP Gateway (650 tools) | ✅ | ❌ | ❌ | ❌ | ❌ |

---

## Key Files Reference

### Scanner Engines
- `suite-core/core/sast_engine.py` (465 LOC)
- `suite-core/core/dast_engine.py` (533 LOC)
- `suite-core/core/secrets_scanner.py` (775 LOC)
- `suite-core/core/container_scanner.py` (410 LOC)
- `suite-core/core/cspm_engine.py` (586 LOC)

### Scanner Routers
- `suite-attack/api/sast_router.py` (80 LOC)
- `suite-attack/api/dast_router.py` (42 LOC)
- `suite-attack/api/secrets_router.py` (280 LOC)
- `suite-attack/api/container_router.py` (65 LOC)
- `suite-attack/api/cspm_router.py` (78 LOC)
- `suite-attack/api/api_fuzzer_router.py` (56 LOC)
- `suite-attack/api/malware_router.py` (59 LOC)
- `suite-core/api/llm_monitor_router.py`

### Decision Engine
- `suite-core/core/brain_pipeline.py` (864 LOC) — 12-step CTEM
- `suite-core/core/llm_providers.py` — Multi-LLM consensus
- `suite-core/core/autofix_engine.py` (1,260 LOC) — AI-powered fixes

### OSS/SCA
- `suite-integrations/api/oss_tools.py` (206 LOC)
- `suite-core/api/validation_router.py` (492 LOC)
- `suite-api/apps/api/inventory_router.py`

### MPTE/Attack
- `suite-attack/api/micro_pentest_router.py`
- `suite-attack/api/mpte_router.py`
- `suite-attack/api/mpte_orchestrator_router.py`
- `suite-core/core/mpte_advanced.py`

### Evidence & Compliance
- `suite-core/core/crypto.py` — RSA + ML-DSA signatures
- `suite-evidence-risk/` — Evidence bundles, risk scoring

### Change Tracking
- `docs/CHANGE_IMPACT_REPORT.md` — All backend fixes, demo changes, persona impact (WHAT/WHY/HOW/WHO)
- `.claude/team-state/daily-digest-*.md` — Daily agent performance + change summary
