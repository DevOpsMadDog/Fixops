# ALdeci: Strategic Feature Roadmap for Market Leadership

> **Goal**: $50M+ acquisition valuation  
> **Date**: 2026-02-20  
> **Current State**: 184K LOC, 650 endpoints, full vulnerability management platform

---

## Executive Summary

ALdeci has a solid technical foundation with unique differentiators (Multi-LLM Consensus, Knowledge Graph Brain, MPTE Engine). To achieve acquisition-level valuation, we need to close critical gaps in developer experience, autofix capabilities, and cloud-native attack path visualization.

---

## Part 1: Current Competitive Advantages

### Already Differentiated From Competition

| Feature | ALdeci | Snyk | Wiz | Orca | Apiiro |
|---------|--------|------|-----|------|--------|
| Multi-LLM Consensus (GPT-4 + Claude + Gemini) | ✅ | ❌ | ❌ | ❌ | ❌ |
| Knowledge Graph Brain | ✅ | ❌ | Partial | Partial | ✅ |
| Unified 12-Stage Pipeline | ✅ | ❌ | ❌ | ❌ | ❌ |
| MPTE (Micro-Pentest Validation) | ✅ | ❌ | ❌ | ❌ | ❌ |
| Code-to-Cloud Tracing | Partial | ❌ | ✅ | ✅ | Partial |
| Evidence Auto-Generation | ✅ | ❌ | ❌ | ❌ | ❌ |

### What This Means
- **No one has LLM voting** - We can make smarter triage decisions
- **Knowledge Graph is rare** - Contextual understanding vs flat scanning
- **MPTE is unique** - We can prove exploitability, not just detect

---

## Part 2: Critical Gaps to Address

### Gap 1: Developer Experience (DX) — The Snyk Killer Move

**Current State:**
- CLI exists (`scripts/aldeci`)
- IDE endpoints exist (`/api/v1/ide`) but thin (5 endpoints)
- No native GitHub App integration

**Market Reality:**
- Developers hate security tools that slow them down
- Snyk wins because it's "easy" not because it's "better"
- First tool in the PR workflow wins adoption

**Build List:**

| Priority | Feature | Effort | Impact |
|----------|---------|--------|--------|
| P0 | VS Code Extension with real-time scanning | 2 weeks | HIGH |
| P0 | GitHub App that comments on PRs | 1 week | HIGH |
| P0 | `aldeci fix CVE-XXXX` one-liner | 3 days | HIGH |
| P1 | GitLab/Bitbucket native integrations | 2 weeks | MEDIUM |
| P1 | JetBrains plugin | 2 weeks | MEDIUM |
| P2 | Slack bot for security alerts | 1 week | LOW |

**Success Metric:** Time from `git push` to "security feedback" < 60 seconds

---

### Gap 2: AutoFix That Actually Works — The $100M Feature

**Current State:**
- `/api/v1/autofix` exists with 12 endpoints
- `POST /generate`, `POST /apply`, `POST /validate`
- Likely regex-based or template-based

**Market Reality:**
- Snyk charges premium for "Fix PRs"
- Most autofix is garbage that doesn't compile
- True AST-based fix generation is rare

**Build List:**

| Priority | Feature | Effort | Impact |
|----------|---------|--------|--------|
| P0 | AST-based code transformations (not regex) | 4 weeks | CRITICAL |
| P0 | Test generation for security fixes | 3 weeks | HIGH |
| P0 | Language support: Python, JS/TS, Java, Go | 6 weeks | CRITICAL |
| P1 | Rollback capability with git integration | 1 week | MEDIUM |
| P1 | Fix confidence scoring (will it break?) | 2 weeks | HIGH |
| P2 | Framework-specific fixes (Django, Spring, Express) | 4 weeks | MEDIUM |

**Technical Implementation:**
```python
# Target architecture for autofix engine
class ASTFixEngine:
    def analyze(self, code: str, vuln: CVE) -> FixPlan:
        ast = parse_to_ast(code)
        vulnerable_nodes = locate_vulnerable_pattern(ast, vuln)
        fix_transforms = generate_safe_transforms(vulnerable_nodes)
        return FixPlan(transforms=fix_transforms, confidence=0.95)
    
    def apply(self, fix_plan: FixPlan) -> FixResult:
        modified_ast = apply_transforms(fix_plan)
        new_code = render_ast(modified_ast)
        tests = generate_security_tests(fix_plan)
        return FixResult(code=new_code, tests=tests)
```

**Success Metric:** 80% of generated fixes compile without modification

---

### Gap 3: Cloud-Native Attack Path — The Wiz Killer

**Current State:**
- `/api/v1/code-to-cloud` has only 2 endpoints
- `/api/v1/attack-simulation` exists but no cloud integration
- Knowledge Graph exists but lacks cloud resource nodes

**Market Reality:**
- Wiz valued at $10B because of attack path visualization
- Enterprise CISOs need "blast radius" for budget justification
- One screenshot of attack path closes deals

**Build List:**

| Priority | Feature | Effort | Impact |
|----------|---------|--------|--------|
| P0 | AWS/GCP/Azure resource ingestion | 3 weeks | CRITICAL |
| P0 | Visual attack path graph (D3.js/Cytoscape) | 2 weeks | CRITICAL |
| P0 | Code → Container → K8s → Cloud → Internet chain | 4 weeks | CRITICAL |
| P1 | "Blast radius" calculation | 2 weeks | HIGH |
| P1 | Attack path prioritization (internet-reachable first) | 1 week | HIGH |
| P2 | MITRE ATT&CK overlay on attack paths | 2 weeks | MEDIUM |

**Target Demo Flow:**
```
1. "This CVE in your code..." (show code snippet)
2. "...is packaged in this container..." (show Dockerfile)
3. "...deployed to this K8s cluster..." (show deployment.yaml)
4. "...exposed via this LoadBalancer..." (show Service)
5. "...reachable from the internet at..." (show public IP)
6. [Click: "Fix All"] → Creates PR with all fixes
```

**Success Metric:** < 5 seconds to visualize full attack path

---

### Gap 4: Compliance Automation — Enterprise $$$

**Current State:**
- `/api/v1/compliance/*` endpoints scattered across agents
- Evidence generation exists (`/api/v1/evidence`)
- No continuous compliance monitoring

**Market Reality:**
- SOC2/FedRAMP audits cost companies $100K+ annually
- Auto-generated evidence saves weeks of work
- "We passed using only ALdeci" = customer story gold

**Build List:**

| Priority | Feature | Effort | Impact |
|----------|---------|--------|--------|
| P0 | SOC2 Type II continuous monitoring dashboard | 3 weeks | HIGH |
| P0 | Control-to-evidence auto-mapping | 2 weeks | HIGH |
| P1 | FedRAMP Moderate control coverage | 4 weeks | HIGH |
| P1 | PCI-DSS 4.0 compliance module | 3 weeks | HIGH |
| P1 | Auditor-ready evidence export (PDF bundles) | 2 weeks | MEDIUM |
| P2 | HIPAA compliance module | 3 weeks | MEDIUM |
| P2 | ISO 27001 mapping | 2 weeks | MEDIUM |

**Success Metric:** 90% of SOC2 evidence auto-generated

---

### Gap 5: AI Security Copilot — The ChatGPT Moment

**Current State:**
- `/api/v1/copilot` exists with 14 endpoints
- Sessions, messages, actions, quick analyze
- No true reasoning chain visibility

**Market Reality:**
- Every security tool claims "AI-powered"
- None show their reasoning transparently
- Natural language security queries are the future

**Build List:**

| Priority | Feature | Effort | Impact |
|----------|---------|--------|--------|
| P0 | Reasoning chain visualization ("why is this critical?") | 2 weeks | HIGH |
| P0 | Natural language queries ("show me exposed S3 buckets") | 3 weeks | HIGH |
| P0 | Context-aware fix suggestions for YOUR codebase | 2 weeks | HIGH |
| P1 | "What would an attacker do next?" simulation | 2 weeks | MEDIUM |
| P1 | Security chat history with export | 1 week | LOW |
| P2 | Voice interface for security queries | 4 weeks | LOW |

**Example Interactions:**
```
User: "Why is CVE-2024-1234 critical for us?"

ALdeci Copilot:
"This CVE is critical because:
1. ✅ Exists in your codebase (src/auth/jwt.py:42)
2. ✅ Package is in production (requirements.txt)
3. ✅ Function is called in auth flow (traced via Knowledge Graph)
4. ✅ Auth endpoint is internet-exposed (via ALB)
5. ✅ Known exploit exists (ExploitDB #51234)
6. ✅ Threat actor APT-28 actively exploiting

Recommended action: [Apply Fix Now] or [Create Ticket]"
```

**Success Metric:** 5-star rating on copilot responses from users

---

## Part 3: Acquisition Multipliers

### Valuation Formula

```
Valuation = ARR × Revenue Multiple × Strategic Premium

Where:
- Revenue Multiple = 10-20x for security SaaS
- Strategic Premium = +30-100% for unique tech
```

### Multiplier Levers

| Factor | Impact on Valuation | ALdeci Status |
|--------|---------------------|---------------|
| 1000+ enterprise customers | 10x ARR baseline | 🟡 Need |
| SOC2/FedRAMP certified | +30% premium | 🟡 Need |
| < 5min time-to-value demo | 2x conversion | 🟡 Need |
| GitHub/GitLab native integration | +50% adoption | 🟡 Need |
| Measurable risk reduction metrics | CFO buy-in | 🟡 Need |
| Unique technology (patents) | +50% strategic premium | 🟢 Have (LLM Consensus) |
| Public customer logos | Social proof | 🔴 Need |
| Enterprise security certs | Trust | 🟡 Need |

---

## Part 4: Quick Wins (Next 30 Days)

### Week 1: Distribution

| Task | Owner | Deliverable |
|------|-------|-------------|
| One-liner install | DevOps | `curl -sSL aldeci.io/install \| bash` |
| Docker quickstart | DevOps | `docker run aldeci/scan:latest` |
| GitHub Action | Platform | `uses: aldeci/scan@v1` |

### Week 2: Demo Experience

| Task | Owner | Deliverable |
|------|-------|-------------|
| 5-minute guided demo | Product | Scan → Findings → Fix flow |
| Interactive playground | Frontend | Try without signup |
| Landing page with logos | Marketing | Used by [X, Y, Z] |

### Week 3: Developer Adoption

| Task | Owner | Deliverable |
|------|-------|-------------|
| VS Code extension MVP | Frontend | Real-time inline warnings |
| CLI polish | Platform | `aldeci scan --fix` |
| Documentation site | Docs | docs.aldeci.io |

### Week 4: Enterprise Readiness

| Task | Owner | Deliverable |
|------|-------|-------------|
| SSO enhancement | Backend | Full SAML/OIDC |
| Audit log export | Backend | Compliance-ready logs |
| SLA dashboard | Frontend | MTTR/SLA tracking |

---

## Part 5: The $100M+ Play

### The Unified Security Data Plane

**Current market fragmentation:**
```
Code Security      → Snyk, Semgrep, Checkmarx
Container Security → Anchore, Trivy, Grype  
Cloud Security     → Wiz, Orca, Lacework
Runtime Security   → Falco, Sysdig
Compliance         → Drata, Vanta, Secureframe
```

**ALdeci's opportunity:**
```
Code → Container → Cloud → Runtime → Remediation → Compliance → Evidence
        └──────────── ALdeci owns the entire chain ──────────────┘
```

**Why this wins:**
1. One vendor vs. 6 vendors
2. One bill vs. 6 contracts
3. One integration vs. 6 integrations
4. Unified context vs. siloed alerts
5. True attack paths vs. disconnected findings

---

## Part 6: Recommended Focus

### If We Pick ONE Thing: Visual Attack Path + One-Click Fix

**The Demo That Closes Deals:**

```
┌─────────────────────────────────────────────────────────────────┐
│                    ATTACK PATH VISUALIZATION                     │
├─────────────────────────────────────────────────────────────────┤
│                                                                   │
│   [CVE-2024-1234]         [Container]         [K8s Pod]          │
│   Log4j in auth.java  ──▶  webapp:latest  ──▶  prod-api-pod     │
│        │                        │                   │            │
│        │                        │                   │            │
│        ▼                        ▼                   ▼            │
│   [Maven Dep]             [ECR Repo]           [Service]         │
│   log4j-core:2.14.1       123456.ecr.aws      LoadBalancer       │
│                                                     │            │
│                                                     ▼            │
│                                              [INTERNET]          │
│                                              api.company.com     │
│                                                                   │
│   Risk Score: 9.8 │ CVSS: 10.0 │ EPSS: 0.97 │ KEV: YES          │
│                                                                   │
│   [🔧 Apply Fix] [📝 Create Ticket] [👁️ View Details] [🚫 Accept Risk] │
│                                                                   │
└─────────────────────────────────────────────────────────────────┘
```

**Why This Wins:**
1. Visual = Instant understanding for non-technical executives
2. Attack path = Proves real risk (not theoretical)
3. One-click fix = Immediate value
4. Full context = Knowledge Graph advantage
5. Enterprise demo = Closes deals

---

## Part 7: Technical Implementation Plan

### Phase 1: Foundation (Weeks 1-4)

```
suite-core/
├── core/
│   ├── attack_path_engine.py      # NEW: Attack path calculation
│   ├── cloud_resource_graph.py    # NEW: AWS/GCP/Azure resources
│   ├── fix_engine_ast.py          # NEW: AST-based autofix
│   └── knowledge_graph.py         # ENHANCE: Add cloud nodes
│
suite-api/
├── apps/api/
│   ├── attack_path_router.py      # NEW: Attack path endpoints
│   └── cloud_resources_router.py  # NEW: Cloud resource endpoints
│
suite-ui/
├── aldeci/src/
│   ├── components/
│   │   └── AttackPathGraph/       # NEW: D3.js visualization
│   └── pages/
│       └── attack-paths/          # NEW: Attack path page
```

### Phase 2: Cloud Integration (Weeks 5-8)

```python
# Target: Cloud resource ingestion
class CloudResourceIngester:
    async def ingest_aws(self, credentials: AWSCredentials) -> List[CloudResource]:
        """Ingest AWS resources: EC2, S3, IAM, EKS, ALB, etc."""
        
    async def ingest_gcp(self, credentials: GCPCredentials) -> List[CloudResource]:
        """Ingest GCP resources: GCE, GCS, IAM, GKE, etc."""
        
    async def ingest_azure(self, credentials: AzureCredentials) -> List[CloudResource]:
        """Ingest Azure resources: VMs, Storage, AKS, etc."""
        
    async def build_relationships(self, resources: List[CloudResource]) -> None:
        """Build Knowledge Graph edges between resources"""
```

### Phase 3: Attack Path Engine (Weeks 9-12)

```python
# Target: Attack path calculation
class AttackPathEngine:
    def calculate_paths(
        self, 
        vulnerability: CVE, 
        graph: KnowledgeGraph
    ) -> List[AttackPath]:
        """
        Calculate all attack paths from vulnerability to crown jewels.
        Uses graph traversal with reachability analysis.
        """
        
    def calculate_blast_radius(self, path: AttackPath) -> BlastRadius:
        """
        Calculate blast radius if this path is exploited.
        Includes: affected assets, data exposure, business impact.
        """
        
    def prioritize_paths(self, paths: List[AttackPath]) -> List[AttackPath]:
        """
        Prioritize paths by:
        1. Internet reachability
        2. Crown jewel access
        3. Exploit availability
        4. EPSS score
        """
```

---

## Part 8: Success Metrics

### North Star Metrics

| Metric | Current | Target (6mo) | Target (12mo) |
|--------|---------|--------------|---------------|
| Time to first scan | ? | < 2 minutes | < 30 seconds |
| Time to first fix | ? | < 5 minutes | < 1 minute |
| Fix accuracy | ? | 70% | 90% |
| Attack paths visualized | 0 | 100% of findings | 100% |
| Enterprise customers | ? | 50 | 500 |
| ARR | ? | $2M | $10M |

### Leading Indicators

- GitHub stars (community adoption)
- Docker pulls (distribution)
- VS Code extension installs (developer adoption)
- Demo-to-trial conversion (product-market fit)
- Trial-to-paid conversion (value demonstration)

---

## Part 9: Pitch Deck Stage & Screen Mapping

> Source: `aldeci_story_pitch_10_20251225122748.pdf`

### 7 Core Capabilities (Live Demo Features)

The pitch deck defines 7 core capabilities that must be fully implemented and polished:

| Demo # | Capability | Current State | Build Priority |
|--------|------------|---------------|----------------|
| 01 | **Ingest & Normalize** | ✅ Implemented | Polish UI |
| 02 | **Correlate & Deduplicate** | ✅ Implemented | Enhance Graph |
| 03 | **Decide with Transparency** | ✅ Implemented | Reasoning UI |
| 04 | **Operationalize Remediation** | ✅ Implemented | SLA Dashboard |
| 05 | **Automate & Extend** | ⚠️ Partial | Playbook Builder |
| 06 | **Verify Exploitability** | ✅ Implemented | Visual Proof |
| 07 | **Prove & Retain** | ✅ Implemented | Evidence Gallery |

---

### Demo 01: Ingest & Normalize — Screen Requirements

**Pitch Promise:**
- Universal ingestion: SBOM, SARIF, CVE, VEX, CNAPP
- Push-model (no proprietary connectors)
- Latency < 200ms
- Metadata enrichment (KEV, EPSS)
- Identity binding (App ID, Service, Owner)

**Required Screens:**

| Screen | Status | Build Notes |
|--------|--------|-------------|
| Upload/Drop Zone | 🟡 Basic | Add drag-drop visual feedback, progress bars |
| Format Auto-Detect | 🟡 Backend | Surface detection in UI with format badges |
| Enrichment Preview | 🔴 Missing | Show EPSS/KEV/threat intel BEFORE import confirm |
| Identity Binding UI | 🔴 Missing | Map findings → apps/services/owners interactively |
| Import History Log | 🟡 Basic | Add timestamps, stats, error drill-down |

**API Gaps:**
```
Current: /inputs/sbom, /inputs/sarif, /inputs/cve, /inputs/vex
Needed:  /api/v1/ingest/preview (dry-run with enrichment)
         /api/v1/ingest/bind-identity (interactive mapping)
```

---

### Demo 02: Correlate & Deduplicate — Screen Requirements

**Pitch Promise:**
- Risk Graph modeling (Cytoscape.js)
- 5 correlation strategies: Fingerprint, Code Location, Root Cause, Pattern Analysis, Taxonomy
- -65% findings reduction
- 3x faster triage

**Required Screens:**

| Screen | Status | Build Notes |
|--------|--------|-------------|
| Interactive Risk Graph | 🟡 Basic | Enhance with zoom, filter layers, cluster expansion |
| Dedup Strategy Selector | 🔴 Missing | Let users pick/configure correlation strategies |
| Noise Reduction Dashboard | 🔴 Missing | Before/after visualization (70K → 400 story) |
| Cluster Inspector | 🟡 Basic | Expand clusters, see merged findings, split option |
| Merge/Split Controls | 🔴 Missing | Manual override for dedup decisions |

**API Gaps:**
```
Current: /api/v1/dedup/process, /api/v1/dedup/clusters
Needed:  /api/v1/dedup/preview (show what WOULD be merged)
         /api/v1/dedup/strategies (list available strategies)
         /api/v1/dedup/stats (reduction metrics for dashboard)
```

---

### Demo 03: Decide with Transparency — Screen Requirements

**Pitch Promise:**
- Multi-LLM Consensus (GPT-5 + Claude-3 + Gemini-2)
- ≥85% agreement for automation
- Tri-State verdicts: ALLOW / BLOCK / REVIEW
- Step-by-step reasoning mapped to MITRE ATT&CK

**Required Screens:**

| Screen | Status | Build Notes |
|--------|--------|-------------|
| Consensus Visualization | 🔴 Missing | Show each LLM vote + confidence % |
| Verdict Card | 🟡 Basic | Add ALLOW/BLOCK/REVIEW with color coding |
| Reasoning Chain Viewer | 🔴 Missing | Collapsible step-by-step analysis |
| MITRE ATT&CK Mapping | 🔴 Missing | Link techniques to reasoning |
| Decision Override UI | 🔴 Missing | Human override with audit trail |

**API Gaps:**
```
Current: /api/v1/decisions/make-decision
Needed:  /api/v1/decisions/{id}/reasoning (get full reasoning chain)
         /api/v1/decisions/{id}/llm-votes (individual LLM decisions)
         /api/v1/decisions/{id}/mitre-mapping (ATT&CK linkage)
         /api/v1/decisions/{id}/override (human override endpoint)
```

---

### Demo 04: Operationalize Remediation — Screen Requirements

**Pitch Promise:**
- SLA lifecycle tracking (Detection → Closure)
- Bulk operations (100s in one click)
- Regression checks (prevent re-opening)
- MTTR ↓60%, Efficiency +76%
- Jira bi-directional sync, Slack alerts

**Required Screens:**

| Screen | Status | Build Notes |
|--------|--------|-------------|
| SLA Timeline Visualization | 🔴 Missing | Visual workflow: Created → PR → Verified → Closed |
| Bulk Operations Panel | 🟡 Basic | Add "Select All", filters, progress feedback |
| MTTR Dashboard | 🔴 Missing | Before/after comparison chart |
| Jira Sync Status | 🔴 Missing | Show sync state, conflicts, last update |
| Regression Alert Panel | 🔴 Missing | List re-opened issues, prevent close until fixed |

**API Gaps:**
```
Current: /api/v1/remediation/tasks, /api/v1/bulk/*
Needed:  /api/v1/remediation/sla-timeline/{task_id}
         /api/v1/remediation/mttr-stats (aggregated metrics)
         /api/v1/remediation/regression-status
         /api/v1/integrations/jira/sync-status
```

---

### Demo 05: Automate & Extend — Screen Requirements

**Pitch Promise:**
- YAML configuration (risk models, thresholds, compliance overlays)
- GitOps ready
- 25+ automation playbooks
- API-first (243+ endpoints, 67 CLI commands)
- Marketplace for micro-apps

**Required Screens:**

| Screen | Status | Build Notes |
|--------|--------|-------------|
| YAML Config Editor | 🔴 Missing | In-browser editor with syntax highlighting |
| Playbook Library | 🔴 Missing | Browse, search, preview playbooks |
| Playbook Builder | 🔴 Missing | Visual drag-drop playbook creator |
| Marketplace | 🟡 Basic | Add ratings, downloads, verified badges |
| API Explorer | 🔴 Missing | Interactive Swagger-like documentation |

**API Gaps:**
```
Current: /api/v1/marketplace/*, /api/v1/workflows/*
Needed:  /api/v1/config/overlay (get/set YAML config)
         /api/v1/config/validate (validate config before apply)
         /api/v1/playbooks/templates (list playbook templates)
         /api/v1/playbooks/builder/save (save custom playbook)
```

---

### Demo 06: Verify Exploitability — Screen Requirements

**Pitch Promise:**
- Automated reachability analysis
- Internet Gateway → Service → Component → Vulnerable Function
- Filter 60% unreachable noise
- Micro-pentest engine (SQLi, XSS, RCE in sandbox)
- Blast radius calculation

**Required Screens:**

| Screen | Status | Build Notes |
|--------|--------|-------------|
| Reachability Path Visualization | 🔴 CRITICAL | Attack path from internet to vuln function |
| Blast Radius Calculator | 🔴 Missing | Show impact scope, lateral movement potential |
| Micro-Pentest Console | 🟡 Basic | Real-time test output, payload details |
| Proof Artifact Gallery | 🔴 Missing | pcap dumps, screenshots, logs |
| REACHABLE/UNREACHABLE Filter | 🔴 Missing | Quick toggle to show only actionable |

**API Gaps:**
```
Current: /api/v1/reachability/analyze, /api/v1/mpte/*
Needed:  /api/v1/reachability/path/{finding_id} (full path JSON)
         /api/v1/reachability/blast-radius/{finding_id}
         /api/v1/mpte/evidence/{test_id}/artifacts
         /api/v1/findings?reachable=true (filter param)
```

---

### Demo 07: Prove & Retain — Screen Requirements

**Pitch Promise:**
- Evidence-as-Code (cryptographically signed bundles)
- RSA-SHA256 + SLSA v1 attestation
- Immutable storage (7+ years, WORM compliant)
- Full JSON/SARIF export

**Required Screens:**

| Screen | Status | Build Notes |
|--------|--------|-------------|
| Evidence Bundle Gallery | 🟡 Basic | Add signing status, verification button |
| Signature Verification UI | 🔴 Missing | One-click verify with visual confirmation |
| Audit Trail Timeline | 🔴 Missing | Chain of custody visualization |
| Retention Policy Manager | 🔴 Missing | Configure retention by framework |
| Export Center | 🟡 Basic | Add format selection, preview, bulk export |

**API Gaps:**
```
Current: /api/v1/evidence/*, /api/v1/evidence/verify
Needed:  /api/v1/evidence/{id}/chain-of-custody
         /api/v1/evidence/retention-policies
         /api/v1/evidence/export/bulk
```

---

## Part 10: CTEM Loop Implementation

The pitch deck positions ALdeci as the **only complete CTEM loop**:

```
┌─────────────────────────────────────────────────────────────────────┐
│                     CONTINUOUS THREAT EXPOSURE MANAGEMENT           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                       │
│   1. DISCOVER/INGEST                    2. PRIORITIZE                │
│   ┌─────────────────┐                   ┌─────────────────┐          │
│   │ SBOM, SARIF,    │                   │ Multi-LLM       │          │
│   │ VEX, CNAPP      │────────────────▶  │ Consensus +     │          │
│   │ (Push Model)    │                   │ Business Context│          │
│   └─────────────────┘                   └────────┬────────┘          │
│                                                  │                    │
│   ▲                                              ▼                    │
│   │                                                                   │
│   │    5. MEASURE                       3. VALIDATE                  │
│   │    ┌─────────────────┐              ┌─────────────────┐          │
│   │    │ Signed Evidence │              │ Micro-Pentest   │          │
│   │    │ SLSA v1, 7yr    │◀────────────│ Reachability    │          │
│   │    │ Retention       │              │ Exploit Verify  │          │
│   │    └─────────────────┘              └────────┬────────┘          │
│   │                                              │                    │
│   │            4. REMEDIATE                      │                    │
│   │            ┌─────────────────┐               │                    │
│   └────────────│ SLA Tracking    │◀──────────────┘                   │
│                │ Bulk Actions    │                                    │
│                │ Jira/Slack      │                                    │
│                └─────────────────┘                                    │
│                                                                       │
│   ✅ ALdeci: Full Loop with Cryptographic Proof                      │
│   ⚠️ RBVM/ASPM: Stop at Prioritize                                   │
│   ❌ Scanners: Stop at Discover                                       │
│                                                                       │
└─────────────────────────────────────────────────────────────────────┘
```

### CTEM Screen Requirements

| Phase | Screen | Status | Build Priority |
|-------|--------|--------|----------------|
| 1. Discover | Unified Ingest Dashboard | 🟡 | P1 |
| 1. Discover | Asset Inventory | 🟡 | P1 |
| 2. Prioritize | Risk Prioritization Queue | 🔴 | P0 |
| 2. Prioritize | Business Context Overlay | 🔴 | P0 |
| 3. Validate | Attack Path Visualization | 🔴 | P0 (CRITICAL) |
| 3. Validate | Pentest Evidence Viewer | 🟡 | P1 |
| 4. Remediate | Remediation Workflow Board | 🔴 | P0 |
| 4. Remediate | SLA Dashboard | 🔴 | P0 |
| 5. Measure | Evidence Bundle Manager | 🟡 | P1 |
| 5. Measure | Compliance Dashboard | 🔴 | P0 |

---

## Part 11: Compliance Automation Mapping

### Frameworks to Support (from Pitch Deck)

| Framework | Status | Pitch Promise | Build Requirements |
|-----------|--------|---------------|-------------------|
| **ISO 27001:2022** | 🔴 | Auto-evidence for secure coding controls | Control → Evidence auto-mapping |
| **NIST SSDF / EO 14028** | 🔴 | Self-attestation forms, SLSA v1 provenance | Form generator, provenance tracker |
| **EU Cyber Resilience Act** | 🔴 | SBOM generation, disclosure timelines | SBOM generator, timeline tracker |
| **SOC2 Type II** | 🔴 | Change management trail, continuous monitoring | Audit trail, monitoring dashboard |
| **PCI-DSS v4.0** | 🔴 | Vuln scan reports, pentest evidence | Report generator, evidence bundler |
| **GDPR / CCPA** | 🔴 | DPIA, security by design proof | Privacy controls, design evidence |

### Compliance Control Mapping Implementation

```python
# Required: suite-core/core/compliance_mapper.py

class ComplianceControlMapper:
    """
    Maps security findings and evidence to compliance framework controls.
    Auto-generates audit-ready evidence bundles.
    """
    
    FRAMEWORK_MAPPINGS = {
        "ISO_27001": {
            "A.8.25": {  # Secure Development
                "finding_types": ["SAST", "SCA", "Container"],
                "evidence_types": ["scan_results", "remediation_proof"],
                "auto_collect": True
            },
            "A.8.9": {  # Configuration Management
                "finding_types": ["CSPM", "IaC"],
                "evidence_types": ["config_audit", "drift_detection"],
                "auto_collect": True
            },
        },
        "SOC2_TYPE_II": {
            "CC6.1": {  # Logical Access Controls
                "finding_types": ["IAM", "Secrets"],
                "evidence_types": ["access_logs", "rotation_proof"],
                "auto_collect": True
            },
            "CC7.1": {  # System Operations
                "finding_types": ["Runtime", "Monitoring"],
                "evidence_types": ["alert_logs", "response_records"],
                "auto_collect": True
            },
        },
        "PCI_DSS_V4": {
            "6.2.4": {  # Software Development
                "finding_types": ["SAST", "DAST", "SCA"],
                "evidence_types": ["scan_reports", "fix_verification"],
                "auto_collect": True
            },
            "11.3": {  # Penetration Testing
                "finding_types": ["MPTE", "Pentest"],
                "evidence_types": ["pentest_reports", "remediation_proof"],
                "auto_collect": True
            },
        },
        "NIST_SSDF": {
            "PO.1.1": {  # Security Requirements
                "finding_types": ["Design", "Threat-Model"],
                "evidence_types": ["requirements_docs", "threat_models"],
                "auto_collect": False
            },
            "PS.1.1": {  # Secure Software
                "finding_types": ["SAST", "SBOM"],
                "evidence_types": ["scan_results", "sbom_attestations"],
                "auto_collect": True
            },
        },
    }
    
    async def map_findings_to_controls(
        self, 
        findings: List[Finding],
        framework: str
    ) -> Dict[str, ControlEvidence]:
        """Maps findings to framework controls with auto-generated evidence."""
        pass
    
    async def generate_evidence_bundle(
        self,
        framework: str,
        period: DateRange
    ) -> SignedEvidenceBundle:
        """Generates signed evidence bundle for audit."""
        pass
    
    async def gap_analysis(
        self,
        framework: str
    ) -> ComplianceGapReport:
        """Identifies controls without sufficient evidence."""
        pass
```

### Compliance Dashboard Requirements

| Component | Description | Priority |
|-----------|-------------|----------|
| **Framework Selector** | Toggle between ISO/SOC2/PCI/NIST views | P0 |
| **Control Coverage Heatmap** | Visual grid of controls + evidence status | P0 |
| **Gap Alert Banner** | Show missing evidence for upcoming audit | P0 |
| **Auto-Collect Status** | Which controls have auto-generated evidence | P1 |
| **Evidence Timeline** | When evidence was last collected/verified | P1 |
| **Audit Package Generator** | One-click bundle for auditors | P0 |
| **Retention Status** | Show 7-year compliance for WORM storage | P1 |

---

## Part 12: 10 Key Differentiators — Feature Status

From the pitch deck competitive matrix:

| # | Differentiator | Pitch Promise | Current Status | Build Priority |
|---|----------------|---------------|----------------|----------------|
| 1 | **Signed Evidence** | SLSA v1 + 7yr Retention | 🟡 Basic signing | P1 - SLSA compliance |
| 2 | **Compliance Auto** | Auto-generated artifacts | 🔴 Missing | P0 - CRITICAL |
| 3 | **Explainability** | Transparent "Why" | 🔴 Missing | P0 - CRITICAL |
| 4 | **Integration** | Push-Model / Universal | ✅ Done | Polish |
| 5 | **Sovereignty** | On-Prem / Air-Gapped | ✅ Done | Documentation |
| 6 | **CTEM Loop** | P-V-R-M + Proof | 🟡 Partial | P0 - Complete loop |
| 7 | **Exploit Verify** | Micro-Pentest Engine | ✅ Done | P1 - Visual proof |
| 8 | **Time-to-Value** | ~30 Mins onboarding | 🟡 Unknown | P1 - Guided wizard |
| 9 | **Data Control** | Zero Lock-In | ✅ Done | Polish |
| 10 | **Attack Path** | Map + Crypto Proof | 🔴 Missing | P0 - CRITICAL |

### Critical Build Items (P0)

Based on pitch deck promises, these MUST be built:

1. **Attack Path Visualization** - The "Wiz killer" screenshot
2. **Compliance Auto-Generation** - SOC2/ISO/PCI evidence bundles
3. **Explainability UI** - LLM reasoning chains with MITRE mapping
4. **CTEM Loop Completion** - Visual workflow for full loop

---

## Part 13: Platform Metrics vs. Pitch Deck Claims

### Pitch Deck Claims:

| Metric | Claim | Actual | Gap |
|--------|-------|--------|-----|
| API Endpoints | 243+ | 650 | ✅ Exceeds |
| Micro-Frontends | 27 | ~15 | 🔴 Need 12 more |
| CLI Commands | 67 | ~40 | 🔴 Need 27 more |
| Router Modules | 22 | 62 | ✅ Exceeds |
| Deploy Modes | 3 (SaaS/On-Prem/Air-Gap) | 2 | 🔴 Need SaaS mode |

### MFE Screen Gap Analysis

The pitch claims 27 Micro-Frontend apps. Required screens:

| MFE # | Screen | Status |
|-------|--------|--------|
| 01 | Dashboard Overview | ✅ |
| 02 | Findings List | ✅ |
| 03 | Finding Detail | ✅ |
| 04 | Risk Graph | ✅ |
| 05 | Triage Queue | 🟡 |
| 06 | Remediation Board | 🟡 |
| 07 | SLA Dashboard | 🔴 |
| 08 | Compliance Dashboard | 🔴 |
| 09 | Evidence Gallery | 🟡 |
| 10 | Integration Settings | ✅ |
| 11 | Playbook Library | 🔴 |
| 12 | Playbook Builder | 🔴 |
| 13 | Marketplace | 🟡 |
| 14 | API Explorer | 🔴 |
| 15 | Config Editor | 🔴 |
| 16 | Attack Path Viewer | 🔴 |
| 17 | Pentest Console | 🟡 |
| 18 | Reachability Analyzer | 🔴 |
| 19 | MTTR Analytics | 🔴 |
| 20 | Noise Reduction Report | 🔴 |
| 21 | LLM Consensus Viewer | 🔴 |
| 22 | Audit Trail | 🟡 |
| 23 | User Management | ✅ |
| 24 | Team Management | ✅ |
| 25 | Reports Center | 🟡 |
| 26 | Import Wizard | 🔴 |
| 27 | Onboarding Flow | 🔴 |

**Build Needed:** 12 new screens to match pitch deck claim

---

## Part 14: Future Product — AI Data Quality (2026)

From the pitch deck's "Next Product" slide:

### Capabilities to Build:

| Capability | Description | Foundation Exists |
|------------|-------------|-------------------|
| Dataset Profiling | Track data sources, transformations, quality | 🔴 New |
| Schema & PII Checks | Validate compliance, detect PII | 🔴 New |
| Retrieval Quality | Measure RAG accuracy, context utilization | 🔴 New |
| Agent Consensus | Cross-validate multi-agent outputs | 🟡 Reuse LLM Consensus |
| Hallucination Defense | Reference-checking against ground truth | 🔴 New |
| Signed Audit Trail | Crypto-signed prompts, context, outputs | 🟡 Reuse Evidence Engine |

### Target Use Cases:
1. Regulated AI Systems (Financial, Healthcare)
2. Documentation Assistants (prevent hallucinations)
3. SDLC Copilots (validate code generation)
4. SOC Copilots (accurate threat analysis)

### Synergy with ALdeci:
- Shared Evidence Engine for signed audit trails
- Push-based ingestion architecture
- On-premise deployment capability

---

## Conclusion

ALdeci has the technical foundation to beat every AppSec tool in the market. The Multi-LLM Consensus and Knowledge Graph Brain are genuine innovations that competitors don't have.

**To reach $50M+ acquisition valuation:**

1. **Fix developer experience** - Be easier than Snyk
2. **Build real autofix** - Not garbage that breaks builds
3. **Visualize attack paths** - The "Wiz screenshot" moment
4. **Automate compliance** - Enterprise budget unlocks
5. **Ship the AI copilot** - The "ChatGPT for security" moment

**Based on Pitch Deck, Critical Gaps Are:**

| Gap | Impact | Effort |
|-----|--------|--------|
| Attack Path Visualization | CRITICAL - Demo closer | 4 weeks |
| Compliance Auto-Generation | CRITICAL - Enterprise $$$ | 6 weeks |
| LLM Explainability UI | HIGH - Trust builder | 2 weeks |
| 12 Missing MFE Screens | HIGH - Match pitch claims | 8 weeks |
| SLA + MTTR Dashboards | HIGH - Metrics story | 3 weeks |

**Focus recommendation:** Attack Path Visualization + Compliance Dashboard

These two features combined:
1. Close enterprise deals (visual proof of risk)
2. Unlock compliance budgets (auto-evidence generation)
3. Match pitch deck promises (27 MFEs, full CTEM loop)
4. Differentiate from ALL competitors

---

## Part 15: UI/UX Deep Audit — Current State vs. All Competitors

> Source: `aldeci_story_pitch_10_20260103134309.pdf` (Updated Jan 2026 deck)

### Current UI Inventory

| Metric | Count |
|--------|-------|
| Total page files (.tsx) | 57 |
| Total frontend files (.tsx + .ts) | 84 |
| Total frontend LOC | 22,434 |
| Components | 17 |
| Pages > 400 LOC (feature-complete) | 15 |
| Pages 200-400 LOC (partial) | 14 |
| Pages < 200 LOC (thin/stub) | 28 |

**Problem:** 28 out of 57 pages (49%) are thin stubs under 200 LOC. These are placeholder screens.

### Competitor UI/UX Standards (What We Must Beat)

#### NopSec (Bootstrapped, $6M ARR, CTEM)

| Feature | NopSec Has | ALdeci Status |
|---------|-----------|---------------|
| Unified vulnerability triage queue | ✅ Polished | 🟡 Basic |
| Risk-ranked findings list with filters | ✅ | 🟡 Basic |
| SLA tracking dashboard | ✅ | 🔴 Stub (89 LOC) |
| Remediation workflow board | ✅ | 🟡 (103 LOC) |
| Integration management | ✅ | ✅ (466 LOC) |
| Report generation | ✅ | 🔴 Stub (76 LOC) |
| Audit logs | ✅ | 🔴 Stub (52 LOC) |

#### Nucleus Security ($43M Series B, RBVM)

| Feature | Nucleus Has | ALdeci Status |
|---------|------------|---------------|
| Asset-centric vulnerability view | ✅ Polished | 🔴 Stub (53 LOC Inventory) |
| Deduplication dashboard | ✅ | 🟡 (453 LOC DataFabric) |
| Connector marketplace | ✅ | 🔴 Stub (66 LOC Marketplace) |
| Custom risk scoring UI | ✅ | 🟡 (272 LOC OverlayConfig) |
| Trend analytics | ✅ | 🟡 (151 LOC EvidenceAnalytics) |
| RBAC + team management | ✅ | 🔴 Stubs (55 LOC each) |

#### Apiiro (Fortune 10 Customers, ASPM)

| Feature | Apiiro Has | ALdeci Status |
|---------|-----------|---------------|
| Code-to-runtime risk graph | ✅ Signature feature | 🟡 (589 LOC KnowledgeGraph) |
| PR risk scoring inline | ✅ | 🔴 Missing |
| SDLC security posture view | ✅ | 🔴 Missing |
| Material change detection | ✅ | 🔴 Missing |
| Developer-facing security portal | ✅ | 🔴 Missing |
| Compliance control mapping | ✅ | 🟡 (400 LOC ComplianceReports) |

#### ArmorCode ($65M Raised, ASPM)

| Feature | ArmorCode Has | ALdeci Status |
|---------|--------------|---------------|
| Unified findings dashboard | ✅ Polished | ✅ (472 LOC Dashboard) |
| Correlation engine UI | ✅ | 🔴 Stub (78 LOC) |
| Policy management | ✅ | 🔴 Stub (75 LOC) |
| Workflow automation builder | ✅ | 🟡 (387 LOC PlaybookEditor) |
| Ticket sync status | ✅ | 🟡 (573 LOC Webhooks) |
| Executive dashboards | ✅ | 🔴 Missing |

#### Cycode ($81M Raised, ASPM)

| Feature | Cycode Has | ALdeci Status |
|---------|-----------|---------------|
| Pipeline security view | ✅ | 🟡 (448 LOC BrainPipeline) |
| Secrets detection dashboard | ✅ | ✅ (400 LOC SecretsDetection) |
| Code scanning results | ✅ | 🟡 (260 LOC CodeScanning) |
| IaC scanning results | ✅ | 🔴 Stub (67 LOC) |
| SBOM viewer | ✅ | 🔴 Stub (136 LOC) |
| Supply chain graph | ✅ | 🔴 Missing |

#### Vulcan (Acquired $150M, RBVM)

| Feature | Vulcan Has | ALdeci Status |
|---------|-----------|---------------|
| Risk prioritization queue | ✅ Polished | 🟡 Basic |
| Remediation orchestration | ✅ | 🟡 (435 LOC RemediationCenter) |
| Fix automation UI | ✅ | 🟡 (248 LOC AutoFixDashboard) |
| Connector health dashboard | ✅ | 🔴 Stub (89 LOC SystemHealth) |
| Campaign management | ✅ | 🔴 Missing |
| SLA breach alerts | ✅ | 🔴 Missing |

#### Snyk ($7.4B Valuation, Scanner)

| Feature | Snyk Has | ALdeci Status |
|---------|---------|---------------|
| Developer-first UX | ✅ Best-in-class | 🔴 Not developer-facing |
| Project import wizard | ✅ | 🔴 Missing |
| Fix PR generation UI | ✅ | 🟡 (248 LOC AutoFix) |
| Dependency tree browser | ✅ | 🔴 Missing |
| Container image scanner | ✅ | 🔴 Stub (134 LOC) |
| License compliance view | ✅ | 🔴 Missing |
| IDE integration feedback | ✅ | 🔴 Missing |

---

### Part 16: Persona-to-Screen Mapping (From Updated Pitch Deck)

The pitch deck defines 12 personas. Every persona needs screens that work:

| Persona | Primary Screen Needed | Current Status | Gap |
|---------|----------------------|----------------|-----|
| **VM Analyst** | Findings list + dedup view | 🟡 DataFabric exists | Filter/sort polish |
| **VA Analyst** | Validation console + false positive mgmt | 🟡 DecisionEngine | Missing FP workflow |
| **Threat & VM Engineer** | Risk scoring + KEV/EPSS enrichment | 🟡 IntelligenceHub | Missing enrichment view |
| **Security Analyst (SOC+VM)** | Alert correlation + incident linkage | 🔴 Stub CorrelationEngine | 78 LOC - needs rebuild |
| **VM Specialist** | Deep risk views + evidence gallery | 🟡 EvidenceVault | Missing drill-down |
| **VM Manager** | SLA dashboard + MTTR metrics | 🔴 Missing | CRITICAL GAP |
| **Security Engineer** | CI/CD gates + policy-as-code | 🔴 Stub Policies | 75 LOC - needs rebuild |
| **DevOps Engineer** | Integration status + pipeline view | 🟡 BrainPipeline | Missing CI/CD integration |
| **App Engineering Lead** | Prioritized fix list + context | 🔴 Missing | No developer portal |
| **Compliance / GRC Officer** | Evidence bundles + control mapping | 🟡 ComplianceReports | Missing auto-mapping |
| **CISO** | Executive risk dashboard + forecasts | 🔴 Missing | CRITICAL GAP |
| **CTO / CIO** | Risk-vs-delivery metrics | 🔴 Missing | CRITICAL GAP |

**Critical Finding:** 5 of 12 personas have no dedicated screen. The highest-value personas (VM Manager, CISO, CTO) are unserved.

---

### Part 17: 28 Stub Pages That Need Rebuilding

Pages under 200 LOC that need real implementation:

| Page | Current LOC | Priority | What Competitor Has |
|------|-------------|----------|-------------------|
| evidence/AuditLogs.tsx | 52 | P0 | NopSec: Full audit trail with export |
| code/Inventory.tsx | 53 | P0 | Nucleus: Asset-centric vuln mapping |
| settings/Users.tsx | 55 | P1 | Nucleus: Full RBAC with role editor |
| settings/Teams.tsx | 55 | P1 | Nucleus: Team ownership matrix |
| settings/Marketplace.tsx | 66 | P2 | Nucleus: Connector marketplace |
| code/IaCScanning.tsx | 67 | P1 | Cycode: IaC results with fix guidance |
| protect/Workflows.tsx | 71 | P1 | ArmorCode: Visual workflow builder |
| protect/Collaboration.tsx | 72 | P2 | ArmorCode: Thread-based comments |
| evidence/EvidenceBundles.tsx | 74 | P0 | NopSec: Evidence export center |
| ai-engine/Policies.tsx | 75 | P1 | ArmorCode: Policy management UI |
| evidence/Reports.tsx | 76 | P0 | NopSec: Report gallery with templates |
| ai-engine/Predictions.tsx | 76 | P2 | Vulcan: Risk forecasting charts |
| cloud/CorrelationEngine.tsx | 78 | P1 | ArmorCode: Correlation dashboard |
| cloud/ThreatFeeds.tsx | 80 | P1 | NopSec: Feed health monitor |
| settings/SystemHealth.tsx | 89 | P1 | Vulcan: Connector health dashboard |
| protect/Remediation.tsx | 103 | P0 | Vulcan: Full remediation workflow |
| attack/Reachability.tsx | 103 | P0 | Apiiro: Reachability analysis viewer |
| ai-engine/AlgorithmicLab.tsx | 118 | P2 | None (unique) |
| attack/AttackSimulation.tsx | 123 | P1 | None (unique) |
| cloud/RuntimeProtection.tsx | 127 | P2 | Wiz: Runtime detection |
| cloud/ContainerSecurity.tsx | 134 | P1 | Snyk: Container results view |
| code/SBOMGeneration.tsx | 136 | P1 | Cycode: SBOM viewer + export |
| evidence/SLSAProvenance.tsx | 142 | P1 | None (unique differentiator) |
| evidence/EvidenceAnalytics.tsx | 151 | P1 | NopSec: Evidence metrics |
| Copilot.tsx | 153 | P0 | None (unique - AI chat) |
| feeds/LiveFeedDashboard.tsx | 206 | P1 | NopSec: Feed monitoring |

---

### Part 18: Feature-Complete Pages (Strengths to Maintain)

Pages > 400 LOC that are competitive or ahead:

| Page | LOC | Competitive Position |
|------|-----|---------------------|
| KnowledgeGraphExplorer.tsx | 589 | ✅ **Ahead** - No competitor has interactive KG |
| Webhooks.tsx | 573 | ✅ Matches ArmorCode |
| ExposureCaseCenter.tsx | 565 | ✅ **Unique** - Case management |
| Settings.tsx | 537 | ✅ Matches all |
| Playbooks.tsx | 523 | ✅ **Ahead** - ArmorCode has similar |
| DecisionEngine.tsx | 496 | ✅ **Unique** - No competitor has LLM voting |
| LogViewer.tsx | 480 | ✅ Matches NopSec |
| Dashboard.tsx | 472 | 🟡 Needs exec-level view |
| Integrations.tsx | 466 | ✅ Matches all |
| AttackLab.tsx | 458 | ✅ **Unique** - MPTE console |
| DataFabric.tsx | 453 | ✅ **Ahead** - Dedup visualization |
| BrainPipelineDashboard.tsx | 448 | ✅ **Unique** - 12-stage pipeline |
| EvidenceVault.tsx | 444 | ✅ **Unique** - Signed evidence |
| RemediationCenter.tsx | 435 | 🟡 Needs SLA tracking |
| IntelligenceHub.tsx | 431 | ✅ **Ahead** - Threat intel aggregation |

---

### Part 19: Competitor UX Patterns We Must Adopt

#### 1. Onboarding Wizard (Snyk Pattern — Every Competitor Has This)
```
Step 1: Connect your repo (GitHub, GitLab, Bitbucket)
Step 2: First scan running... (live progress)
Step 3: Results! Here are your top 5 risks
Step 4: Fix this one now? [Apply Fix]
```
**ALdeci Status:** 🔴 MISSING — No onboarding flow exists. User lands on Dashboard with no guidance.

#### 2. Findings Table with Inline Actions (Universal Pattern)
```
┌──────────┬──────────┬───────┬──────┬──────────┬──────────────┐
│ CVE      │ Severity │ EPSS  │ KEV  │ Status   │ Actions      │
├──────────┼──────────┼───────┼──────┼──────────┼──────────────┤
│ 2024-1234│ CRITICAL │ 0.97  │ YES  │ Open     │ [Fix][Ticket]│
│ 2024-5678│ HIGH     │ 0.43  │ NO   │ In Prog  │ [View PR]    │
│ 2024-9012│ MEDIUM   │ 0.02  │ NO   │ Accepted │ [Evidence]   │
└──────────┴──────────┴───────┴──────┴──────────┴──────────────┘
```
**ALdeci Status:** 🟡 Has basic table but missing inline actions, EPSS/KEV badges, status chips

#### 3. Executive Dashboard (Every $10M+ Competitor)
```
┌────────────────────┬────────────────────┬────────────────────┐
│  Risk Posture      │  MTTR Trend        │  SLA Compliance    │
│  ████████░░ 78/100 │  📉 45d → 12d     │  ✅ 94% on time   │
├────────────────────┴────────────────────┴────────────────────┤
│  Top 5 Critical Risks                    │  Compliance Status │
│  1. Log4j in payment-svc (REACHABLE)     │  SOC2: 87% ✅     │
│  2. XSS in auth-api (EXPLOITABLE)        │  PCI:  92% ✅     │
│  3. SQLi in user-svc (BLOCKED)           │  ISO:  78% ⚠️     │
│  4. SSRF in proxy (UNDER REVIEW)         │                    │
│  5. RCE in logging (FIX DEPLOYED)        │                    │
└──────────────────────────────────────────┴────────────────────┘
```
**ALdeci Status:** 🔴 MISSING — Current Dashboard (472 LOC) is operational, not executive

#### 4. SLA Tracking Board (Vulcan / NopSec Pattern)
```
┌─────────────────────────────────────────────────────────────┐
│ SLA COMPLIANCE                                    94.2%     │
├─────────────────────────────────────────────────────────────┤
│ Critical (24h)  ██████████████░░  → 3 overdue              │
│ High (7d)       ████████████████  → 0 overdue              │
│ Medium (30d)    ████████████░░░░  → 12 overdue             │
│ Low (90d)       ████████████████  → 0 overdue              │
├─────────────────────────────────────────────────────────────┤
│ MTTR: 12.4 days │ Trend: ↓ 23% │ SLA Breaches: 3          │
└─────────────────────────────────────────────────────────────┘
```
**ALdeci Status:** 🔴 MISSING — No SLA visualization exists

#### 5. Evidence Export Center (Required for Compliance Buyers)
```
┌─────────────────────────────────────────────────────────────┐
│ EVIDENCE BUNDLES                         [+ Generate New]   │
├─────────────────────────────────────────────────────────────┤
│ 📦 SOC2-Q4-2025    │ 342 artifacts │ SLSA ✓ │ [Download]  │
│ 📦 PCI-Annual-2025 │ 189 artifacts │ SLSA ✓ │ [Download]  │
│ 📦 ISO-Audit-2025  │ 267 artifacts │ SLSA ✓ │ [Download]  │
├─────────────────────────────────────────────────────────────┤
│ Auto-collected: 78% │ Manual needed: 22% │ Next audit: 45d │
└─────────────────────────────────────────────────────────────┘
```
**ALdeci Status:** 🔴 EvidenceBundles is 74 LOC stub

---

### Part 20: Priority Build Order — UI/UX Sprint Plan

#### Sprint 1 (Week 1-2): Foundation — Match Table Stakes

Every competitor has these. We can't demo without them:

| # | Screen | Current | Target LOC | Impact |
|---|--------|---------|------------|--------|
| 1 | **Onboarding Wizard** | MISSING | 300+ | First impression = everything |
| 2 | **Findings Table (enhanced)** | In Dashboard | 400+ | Core workflow for every persona |
| 3 | **Executive Dashboard** | MISSING | 500+ | CISO/CTO persona served |
| 4 | **SLA Dashboard** | MISSING | 400+ | VM Manager persona served |

#### Sprint 2 (Week 3-4): Evidence — Close Compliance Deals

Compliance buyers account for 40-60% of enterprise spend:

| # | Screen | Current | Target LOC | Impact |
|---|--------|---------|------------|--------|
| 5 | **Evidence Export Center** | 74 LOC stub | 400+ | SOC2/PCI audit readiness |
| 6 | **Compliance Control Map** | 400 LOC partial | 500+ | Framework coverage view |
| 7 | **Audit Trail (full)** | 52 LOC stub | 350+ | Immutable log viewer |
| 8 | **Reports Gallery** | 76 LOC stub | 350+ | Report templates + export |

#### Sprint 3 (Week 5-6): Attack Path — The Demo Closer

The "screenshot that sells":

| # | Screen | Current | Target LOC | Impact |
|---|--------|---------|------------|--------|
| 9 | **Attack Path Visualization** | 395 LOC | 600+ | Enhance with blast radius |
| 10 | **Reachability Viewer** | 103 LOC stub | 400+ | Internet→Code path |
| 11 | **MPTE Evidence Gallery** | Part of AttackLab | 400+ | Proof artifacts |

#### Sprint 4 (Week 7-8): Developer Experience — Adoption Driver

Without DX, no organic growth:

| # | Screen | Current | Target LOC | Impact |
|---|--------|---------|------------|--------|
| 12 | **Inventory/Asset View** | 53 LOC stub | 400+ | Asset-centric navigation |
| 13 | **Code Scanning Results** | 260 LOC | 400+ | SAST/SCA results view |
| 14 | **IaC Scanning** | 67 LOC stub | 350+ | Terraform/CloudFormation |
| 15 | **SBOM Viewer** | 136 LOC | 350+ | Dependency tree browser |

#### Sprint 5 (Week 9-10): Intelligence — Differentiator Polish

Features only ALdeci has — make them shine:

| # | Screen | Current | Target LOC | Impact |
|---|--------|---------|------------|--------|
| 16 | **LLM Consensus Viewer** | In DecisionEngine | 400+ | Show voting transparency |
| 17 | **Copilot (full chat)** | 153 LOC | 500+ | Natural language security |
| 18 | **Nerve Center** | 306 LOC | 400+ | Real-time security pulse |

---

### Part 21: CTEM Flow Screens — Matching the Pitch Deck Demo Flow

The pitch deck shows a 5-phase CTEM loop. Here's the screen mapping:

```
PHASE 1: DISCOVER/INGEST
├── Onboarding Wizard (MISSING) → "30 min to first value"
├── Upload/Drop Zone (MISSING) → SBOM, SARIF, VEX drag-drop
├── Inventory.tsx (53 LOC STUB) → Asset inventory view
└── LiveFeedDashboard.tsx (206 LOC) → Feed ingestion monitor

PHASE 2: PRIORITIZE  
├── IntelligenceHub.tsx (431 LOC ✅) → Threat intel enrichment
├── DataFabric.tsx (453 LOC ✅) → Dedup + noise reduction
├── DecisionEngine.tsx (496 LOC ✅) → LLM consensus voting
└── Executive Dashboard (MISSING) → Risk posture for CISO

PHASE 3: VALIDATE
├── AttackPaths.tsx (395 LOC 🟡) → Attack path visualization
├── Reachability.tsx (103 LOC STUB) → Internet→code tracing
├── MicroPentest.tsx (395 LOC 🟡) → MPTE console
└── AttackSimulation.tsx (123 LOC STUB) → Scenario simulation

PHASE 4: REMEDIATE
├── RemediationCenter.tsx (435 LOC 🟡) → Task board
├── AutoFixDashboard.tsx (248 LOC 🟡) → Fix generation
├── BulkOperations.tsx (412 LOC ✅) → Mass actions
├── Remediation.tsx (103 LOC STUB) → Workflow view
└── SLA Dashboard (MISSING) → MTTR + SLA tracking

PHASE 5: MEASURE
├── EvidenceVault.tsx (444 LOC ✅) → Signed evidence
├── ComplianceReports.tsx (400 LOC 🟡) → Compliance status
├── EvidenceBundles.tsx (74 LOC STUB) → Bundle export
├── AuditLogs.tsx (52 LOC STUB) → Audit trail
└── Reports.tsx (76 LOC STUB) → Report generation
```

**Summary:** 
- Phase 1 (Discover): 🔴 Weakest — no onboarding, stubs everywhere
- Phase 2 (Prioritize): ✅ Strongest — 3 feature-complete screens  
- Phase 3 (Validate): 🟡 Partial — attack path needs work
- Phase 4 (Remediate): 🟡 Partial — missing SLA tracking
- Phase 5 (Measure): 🔴 Weak — 3 stubs, evidence export broken

---

### Part 22: Head-to-Head Competitive Feature Matrix (Updated Jan 2026)

From the pitch deck competitor page — mapped to actual build status:

| Capability | Pitch Promise | NopSec | Nucleus | Apiiro | ArmorCode | Cycode | Vulcan | Snyk | ALdeci Actual |
|------------|--------------|--------|---------|--------|-----------|--------|--------|------|---------------|
| Signed Evidence | SLSA v1 | Reports | Logs only | SLA only | Reports | Basic | Basic | None | 🟡 Basic RSA |
| Compliance Auto | Generated | Basic | Basic | Basic | ⚠️ | ⚠️ | – | – | 🔴 Stub |
| Explainability | Transparent | Score Only | Score Only | Black Box | Risk Score | Partial | Risk Score | Single Model | 🟡 In DecisionEngine |
| Integration | Universal | Connectors | Connectors | Pull-based | Scanner | Platform | Agent+API | Limited | ✅ Push-model |
| Sovereignty | Air-Gapped | SaaS Only | Ltd SaaS | SaaS Only | SaaS Only | SaaS+Priv | SaaS+VPC | SaaS Only | ✅ Full Offline |
| CTEM Loop | Full P-V-R-M | Partial (No Proof) | Partial | Partial | Partial | Limited | Partial | Missing | 🟡 Partial (UI gaps) |
| Exploit Verify | Micro-Pentest | – | – | – | – | – | – | – | ✅ MPTE Engine |
| Time-to-Value | 30 mins | Weeks | Weeks | Weeks | Days | Days | Weeks | Days | 🔴 Unknown (no onboarding) |
| Data Control | Zero Lock-In | Platform | Data Trap | SaaS Silo | Platform | Platform | Platform | Silo | ✅ Full Export |
| Attack Path | Map + Proof | Visual Only | Basic | Basic | Limited | Limited | Basic | None | 🟡 Needs proof layer |

**Key Insight:** NopSec ($6M ARR, bootstrapped) is the closest competitor. They were acquired by Vulcan for **$150M**. ALdeci has MORE features but WORSE UI polish. Fix the UI = exceed NopSec = be worth more than $150M.

---

### Part 23: The Revenue Impact of UI Quality

| Competitor | Funding | ARR | Exit | UI Quality |
|-----------|---------|-----|------|------------|
| Vulcan | $55M raised | ~$10M | **Acquired $150M** | ✅ Polished |
| NopSec | Bootstrapped | $6M | **Acquired by Vulcan** | ✅ Clean |
| Nucleus | $43M Series B | $15M est | Growing | ✅ Polished |
| ArmorCode | $65M raised | $20M est | Growing | ✅ Enterprise-grade |
| Cycode | $81M raised | $25M est | Growing | ✅ Developer-friendly |
| ALdeci | $0 | $0 | Pre-seed | 🔴 49% stub pages |

**The Pattern:** Every funded/acquired competitor has polished UI. The backend is important for differentiation, but the frontend closes deals.

**ALdeci's Position:** Strongest backend (184K LOC, 650 APIs, Multi-LLM, MPTE, KG) with weakest frontend (22K LOC, 49% stubs). This is the single biggest risk to fundraising and acquisition.

---

### Part 24: Execution Priority — The 30-Day UI Sprint

#### Week 1: Demo-Blocking Screens
Build 4 screens that make or break a demo:

1. **Onboarding Wizard** — "30 min to value" promise
2. **Executive Dashboard** — CISO persona 
3. **SLA Dashboard** — VM Manager persona
4. **Evidence Export Center** — Compliance buyer

#### Week 2: Stub Replacement (P0)
Replace the 6 worst stubs:

1. AuditLogs.tsx (52 → 350 LOC)
2. Inventory.tsx (53 → 400 LOC)
3. EvidenceBundles.tsx (74 → 400 LOC)
4. Reports.tsx (76 → 350 LOC)
5. Remediation.tsx (103 → 350 LOC)
6. Reachability.tsx (103 → 400 LOC)

#### Week 3: Feature Enhancement
Upgrade 4 partial screens:

1. AttackPaths.tsx (395 → 600 LOC, add blast radius)
2. AutoFixDashboard.tsx (248 → 400 LOC, add one-click)
3. ComplianceReports.tsx (400 → 500 LOC, add control mapping)
4. Copilot.tsx (153 → 500 LOC, full chat)

#### Week 4: Polish & Integration
1. Consistent design system across all 57 pages
2. Loading states, error states, empty states everywhere
3. Responsive design for all screens
4. Dark mode consistency

**After this sprint:**
- 0 stubs under 200 LOC
- All 12 personas have a dedicated screen
- Every pitch deck promise has a matching UI
- Demo-ready for investor presentations

---

## Part 25 — MCP Architecture Expansion: Full Protocol Agent Gateway

### 25.1 Current State Audit

The existing MCP implementation lives in `suite-integrations/api/mcp_router.py` (469 LOC):

| Component | Current State | Gap |
|-----------|--------------|-----|
| Transport | HTTP+SSE enum declared, no SSE stream handler | No real-time bidirectional channel |
| Tools | 8 static `MCPTool` objects (findings, scan, evidence, autofix, risk, connectors, notify, risk_score) | Only covers ~1.2% of 650 endpoints |
| Resources | 4 static `MCPResource` URIs (critical findings, risk score, connectors, pipeline) | No dynamic resource discovery |
| Prompts | 3 static `MCPPrompt` templates (analyze_finding, explain_cve, suggest_remediation) | No prompt chaining or context injection |
| Clients | In-memory dict `_mcp_clients` | No persistence, no auth handshake, no session resumption |
| Manifest | Returns static JSON for VS Code / Cursor config | No dynamic capability negotiation |
| SDK | Custom REST-based, not using official MCP SDK | Incompatible with MCP 2024-11-05 spec |

### 25.2 Target Architecture: MCP 2024-11-05+ Full Compliance

```
┌────────────────────────────────────────────────────────────────┐
│                    MCP Gateway Layer                           │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐     │
│  │ HTTP+SSE │  │ WebSocket│  │  STDIO   │  │ Streamable│     │
│  │ Transport│  │Transport │  │Transport │  │   HTTP    │     │
│  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘     │
│       └──────────────┴──────────────┴──────────────┘          │
│                         │                                     │
│              ┌──────────▼──────────┐                          │
│              │  Protocol Handler   │                          │
│              │  - initialize       │                          │
│              │  - tools/list       │                          │
│              │  - tools/call       │                          │
│              │  - resources/list   │                          │
│              │  - resources/read   │                          │
│              │  - prompts/list     │                          │
│              │  - prompts/get      │                          │
│              │  - sampling         │                          │
│              │  - notifications    │                          │
│              │  - roots/list       │                          │
│              └──────────┬──────────┘                          │
│                         │                                     │
│     ┌───────────────────┼───────────────────┐                 │
│     ▼                   ▼                   ▼                 │
│ ┌────────┐       ┌────────────┐      ┌───────────┐           │
│ │ Tool   │       │ Resource   │      │  Prompt   │           │
│ │Registry│       │  Registry  │      │  Registry │           │
│ │(auto-  │       │ (live data │      │ (context- │           │
│ │ gen    │       │  streams)  │      │  aware)   │           │
│ │ from   │       │            │      │           │           │
│ │ 650    │       │            │      │           │           │
│ │ endpts)│       │            │      │           │           │
│ └────────┘       └────────────┘      └───────────┘           │
└────────────────────────────────────────────────────────────────┘
```

### 25.3 Auto-Generated Tool Registry from 650 Endpoints

Instead of manually defining 8 `MCPTool` objects, auto-discover all `@router` endpoints:

```python
# suite-integrations/mcp/tool_discovery.py
from fastapi import FastAPI
from mcp.server import Server
from mcp.types import Tool

def discover_tools(app: FastAPI) -> list[Tool]:
    """Auto-generate MCP tools from all FastAPI routes."""
    tools = []
    for route in app.routes:
        if not hasattr(route, "methods"):
            continue
        schema = route.endpoint.__doc__ or route.name
        input_schema = _extract_openapi_schema(route)
        tools.append(Tool(
            name=f"fixops_{route.name}",
            description=schema,
            inputSchema=input_schema,
        ))
    return tools  # → 650 tools, zero manual maintenance
```

**Category auto-mapping** from router prefix:
| Router Prefix | MCP Category | Tool Count |
|--------------|-------------|------------|
| `/api/v1/findings` | findings | ~45 |
| `/api/v1/attack` | attack | ~30 |
| `/api/v1/evidence` | evidence | ~25 |
| `/api/v1/risk` | risk | ~40 |
| `/api/v1/integrations` | integrations | ~35 |
| `/api/v1/remediation` | remediation | ~20 |
| `/api/v1/compliance` | compliance | ~30 |
| `/api/v1/pipeline` | pipeline | ~25 |
| `/api/v1/analytics` | analytics | ~20 |
| ... (all other routers) | auto-categorized | ~380 |

### 25.4 Live Resource Streams

Replace static URIs with dynamic Server-Sent Event resource subscriptions:

```python
# Real-time resources exposed via MCP
DYNAMIC_RESOURCES = {
    "fixops://findings/live":       EventStream(findings_db, poll_interval=5),
    "fixops://risk/realtime":       EventStream(risk_scorer, poll_interval=10),
    "fixops://pipeline/{run_id}":   EventStream(pipeline_tracker, per_run=True),
    "fixops://attacks/active":      EventStream(mpte_engine, poll_interval=3),
    "fixops://compliance/{framework}": EventStream(compliance_db, on_change=True),
    "fixops://connectors/health":   EventStream(health_checker, poll_interval=30),
    "fixops://sbom/{asset_id}":     EventStream(sbom_store, on_change=True),
    "fixops://evidence/{bundle_id}": EventStream(evidence_hub, on_change=True),
}
```

### 25.5 Agent Screen Interaction via MCP

The MCP gateway becomes the AI agent's interface to ALL 57 UI screens:

```python
# MCP tools that map to UI screen actions
UI_INTERACTION_TOOLS = [
    Tool(name="navigate_to_screen", inputSchema={
        "screen": {"enum": [
            "dashboard", "findings", "attack_paths", "risk_graph",
            "compliance", "evidence", "remediation", "copilot",
            "inventory", "reports", "audit_logs", "settings",
            # ... all 57 screens
        ]},
        "filters": {"type": "object"},  # screen-specific filters
    }),
    Tool(name="read_screen_state", inputSchema={
        "screen": {"type": "string"},
        "selector": {"type": "string"},  # CSS/data selector
    }),
    Tool(name="trigger_screen_action", inputSchema={
        "screen": {"type": "string"},
        "action": {"type": "string"},  # "export", "filter", "drill_down", "create"
        "params": {"type": "object"},
    }),
    Tool(name="take_screenshot", inputSchema={
        "screen": {"type": "string"},
        "format": {"enum": ["png", "pdf"]},
    }),
]
```

**Frontend MCP bridge** (React side):
```typescript
// suite-ui/aldeci/src/lib/mcp-bridge.ts
class MCPScreenBridge {
  private ws: WebSocket;

  // Agent can read any screen's current state
  async getScreenState(screen: string): Promise<ScreenState> {
    const component = screenRegistry.get(screen);
    return {
      data: component.getCurrentData(),
      filters: component.getActiveFilters(),
      selectedItems: component.getSelection(),
      visibleColumns: component.getColumns(),
    };
  }

  // Agent can trigger any UI action
  async executeAction(screen: string, action: string, params: object): Promise<ActionResult> {
    const component = screenRegistry.get(screen);
    return component.dispatch(action, params);
  }
}
```

### 25.6 MCP Implementation Roadmap

| Phase | Work | LOC Delta | Time |
|-------|------|-----------|------|
| Phase 1 | Replace custom REST with `mcp` Python SDK, implement `initialize`, `tools/list`, `tools/call` | +800, -300 | 3 days |
| Phase 2 | Auto-tool-discovery from 650 endpoints | +400 | 2 days |
| Phase 3 | SSE transport + WebSocket transport | +600 | 2 days |
| Phase 4 | Dynamic resource streams (8 live resources) | +500 | 2 days |
| Phase 5 | Context-aware prompt registry (chain prompts with finding context) | +300 | 1 day |
| Phase 6 | Frontend MCP bridge (React WebSocket ↔ MCP) | +700 (TS) | 3 days |
| Phase 7 | Agent screen interaction (navigate, read, trigger, screenshot) | +500 | 2 days |
| **Total** | | **+3,500 LOC** | **15 days** |

**Differentiator**: No AppSec tool exposes a full MCP server. Snyk, Apiiro, ArmorCode — none of them let an AI agent programmatically navigate their UI, read screen state, trigger actions, and stream live security data. This makes ALdeci the **first AI-native security platform**.

---

## Part 26 — Single AI Agent: Multi-Role Architecture (Zero Token Cost)

### 26.1 Current State: Multi-Vendor LLM Consensus

The existing architecture in `suite-core/core/llm_providers.py` (664 LOC) uses 5 providers:

| Provider | Model | Style | API Cost |
|----------|-------|-------|----------|
| `OpenAIChatProvider` | gpt-4o-mini | consensus | ~$0.15/1M input, $0.60/1M output |
| `AnthropicMessagesProvider` | claude-3-5-sonnet | analyst | ~$3.00/1M input, $15.00/1M output |
| `GeminiProvider` | gemini-1.5-flash | consensus | ~$0.075/1M input, $0.30/1M output |
| `SentinelCyberProvider` | sentinel-cyber-7b | domain-expert | Self-hosted (GPU cost) |
| `DeterministicLLMProvider` | rule-based | fallback | $0 |

**Current flow**: Every security decision calls 3-4 providers → waits for all responses → applies 85% consensus threshold → emits final recommendation.

**Cost per decision**: ~$0.003-0.02 per finding (depending on token length). At 10,000 findings/day = $30-200/day = **$900-6,000/month in API costs alone**.

### 26.2 Target Architecture: One Model, Multiple Roles, Zero Tokens

```
┌──────────────────────────────────────────────────────────────┐
│                   ALdeci Decision Agent                      │
│                                                              │
│  ┌─────────────────────────────────────────────────────────┐ │
│  │           Self-Hosted Fine-Tuned Model                  │ │
│  │    (Llama 3.1 70B / Mistral Large / Qwen2.5-72B)      │ │
│  │           Running on: vLLM / Ollama / TGI              │ │
│  │                                                         │ │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐  │ │
│  │  │  Role:   │ │  Role:   │ │  Role:   │ │  Role:   │  │ │
│  │  │ Security │ │ Pentest  │ │Compliance│ │ Risk     │  │ │
│  │  │ Analyst  │ │ Expert   │ │ Auditor  │ │ Scorer   │  │ │
│  │  │          │ │          │ │          │ │          │  │ │
│  │  │ System   │ │ System   │ │ System   │ │ System   │  │ │
│  │  │ prompt:  │ │ prompt:  │ │ prompt:  │ │ prompt:  │  │ │
│  │  │ "You are │ │ "You are │ │ "You are │ │ "You are │  │ │
│  │  │ a senior │ │ an offen-│ │ a compli-│ │ a quanti-│  │ │
│  │  │ vuln     │ │ sive     │ │ ance     │ │ tative   │  │ │
│  │  │ analyst" │ │ security │ │ officer" │ │ risk     │  │ │
│  │  │          │ │ expert"  │ │          │ │ analyst" │  │ │
│  │  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘  │ │
│  │       │             │             │             │        │ │
│  │       └─────────────┴─────────────┴─────────────┘        │ │
│  │                         │                                │ │
│  │              ┌──────────▼──────────┐                     │ │
│  │              │   Role: Moderator   │                     │ │
│  │              │  "Synthesize the 4  │                     │ │
│  │              │   expert opinions   │                     │ │
│  │              │   into a consensus  │                     │ │
│  │              │   recommendation"   │                     │ │
│  │              └──────────┬──────────┘                     │ │
│  │                         │                                │ │
│  └─────────────────────────┼───────────────────────────────┘ │
│                            ▼                                 │
│                    Final Decision                            │
│              (same LLMResponse format)                       │
└──────────────────────────────────────────────────────────────┘
```

### 26.3 Role System Prompts (Domain-Specific Personas)

```python
# suite-core/core/agent_roles.py

AGENT_ROLES = {
    "security_analyst": {
        "system_prompt": """You are a Senior Security Analyst at a Fortune 500 company.
Your expertise: CVE analysis, CVSS scoring, vulnerability triage, MITRE ATT&CK mapping.
You evaluate findings for severity accuracy, exploitability, and real-world impact.
You are conservative — you never downgrade critical vulnerabilities without strong evidence.
Output JSON: {recommended_action, confidence, reasoning, mitre_techniques}""",
        "temperature": 0.1,
        "focus": ["severity", "exploitability", "mitre_mapping"],
    },
    
    "pentest_expert": {
        "system_prompt": """You are an Offensive Security Expert (OSCP, OSCE certified).
Your expertise: exploit development, attack path analysis, lateral movement, privilege escalation.
You think like an attacker — you evaluate whether a vulnerability is actually exploitable
in the target environment, considering network topology, WAF/IDS, and access controls.
Output JSON: {recommended_action, confidence, reasoning, attack_vectors, exploit_likelihood}""",
        "temperature": 0.2,
        "focus": ["exploit_feasibility", "attack_paths", "lateral_movement"],
    },
    
    "compliance_auditor": {
        "system_prompt": """You are a Compliance Officer specializing in SOC 2, ISO 27001, PCI-DSS, NIST 800-53.
Your expertise: control mapping, evidence requirements, audit readiness, regulatory impact.
You evaluate findings through the lens of compliance obligations and audit risk.
A vulnerability that violates a SOC 2 control is ALWAYS high priority regardless of CVSS.
Output JSON: {recommended_action, confidence, reasoning, compliance_concerns, control_ids}""",
        "temperature": 0.0,
        "focus": ["compliance_impact", "control_mapping", "audit_risk"],
    },
    
    "risk_quantifier": {
        "system_prompt": """You are a Quantitative Risk Analyst with a background in actuarial science.
Your expertise: FAIR methodology, Monte Carlo simulation, financial loss estimation, blast radius.
You translate technical vulnerabilities into business risk — dollar amounts, probability of breach,
time-to-exploit estimates, and blast radius (how many systems/users are affected).
Output JSON: {recommended_action, confidence, reasoning, risk_score, financial_impact, blast_radius}""",
        "temperature": 0.0,
        "focus": ["financial_impact", "probability", "blast_radius"],
    },
    
    "moderator": {
        "system_prompt": """You are the Decision Moderator. You receive 4 expert opinions on a security finding.
Your job: synthesize them into ONE consensus recommendation.
Rules:
1. If 3+ experts agree on action → adopt it (confidence = avg of agreeing experts)
2. If experts disagree → take the MOST CONSERVATIVE recommendation
3. Merge all MITRE techniques, compliance concerns, and attack vectors
4. Final confidence = weighted average (pentest_expert gets 1.5x weight for exploit findings)
Output JSON: {recommended_action, confidence, reasoning, mitre_techniques, compliance_concerns, attack_vectors}""",
        "temperature": 0.0,
        "focus": ["synthesis", "consensus"],
    },
}
```

### 26.4 Multi-Role Conversation Chain

```python
# suite-core/core/single_agent_engine.py

class SingleAgentDecisionEngine:
    """One model, many roles, talking to each other."""
    
    def __init__(self, model_url: str = "http://localhost:8080/v1"):
        self.model_url = model_url  # vLLM / Ollama endpoint
        self.session = requests.Session()
        self.roles = AGENT_ROLES
    
    async def decide(self, finding: dict, context: dict) -> LLMResponse:
        """Run multi-role deliberation on a single finding."""
        
        prompt = self._build_finding_prompt(finding, context)
        expert_opinions = {}
        
        # Phase 1: Parallel expert analysis (4 roles)
        for role_name in ["security_analyst", "pentest_expert", 
                          "compliance_auditor", "risk_quantifier"]:
            role = self.roles[role_name]
            response = await self._invoke_role(
                system_prompt=role["system_prompt"],
                user_prompt=prompt,
                temperature=role["temperature"],
            )
            expert_opinions[role_name] = response
        
        # Phase 2: Moderator synthesizes
        moderator_prompt = self._build_moderator_prompt(
            finding, expert_opinions
        )
        final = await self._invoke_role(
            system_prompt=self.roles["moderator"]["system_prompt"],
            user_prompt=moderator_prompt,
            temperature=0.0,
        )
        
        return self._to_llm_response(final, expert_opinions)
    
    async def _invoke_role(self, system_prompt: str, 
                           user_prompt: str, temperature: float) -> dict:
        """Call the LOCAL model with a specific role's system prompt."""
        payload = {
            "model": "fixops-security-agent",  # fine-tuned model name
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": temperature,
            "response_format": {"type": "json_object"},
        }
        # Calls LOCAL vLLM/Ollama — zero external API tokens
        resp = self.session.post(
            f"{self.model_url}/chat/completions", 
            json=payload, timeout=30
        )
        return resp.json()["choices"][0]["message"]["content"]
```

### 26.5 Fine-Tuning Pipeline for Security Domain

```
┌──────────────────────────────────────────────────────┐
│              Fine-Tuning Data Pipeline               │
│                                                      │
│  1. Historical Decisions                             │
│     └─ Export all past LLM consensus results         │
│        from brain_pipeline.py (~10K+ decisions)      │
│                                                      │
│  2. Security Knowledge Corpus                        │
│     ├─ NVD/CVE database (200K+ CVEs)                │
│     ├─ MITRE ATT&CK framework (full matrix)         │
│     ├─ EPSS scores + historical accuracy             │
│     ├─ KEV catalog (1,200+ exploited vulns)          │
│     ├─ CWE taxonomy (900+ weakness types)            │
│     └─ Compliance mappings (SOC2/ISO/PCI/NIST)      │
│                                                      │
│  3. Synthetic Training Data                          │
│     └─ Generate role-specific Q&A pairs:             │
│        - "As a pentest expert, analyze CVE-X" → Y    │
│        - "As a compliance officer, assess CVE-X" → Z │
│        - "As moderator, synthesize opinions" → Final │
│                                                      │
│  4. Fine-Tune Base Model                             │
│     ├─ Base: Llama 3.1 70B-Instruct (open-weight)   │
│     ├─ Method: QLoRA (4-bit quantized, rank 64)      │
│     ├─ Training: 3 epochs, lr=2e-4, batch=4          │
│     ├─ Hardware: 2x A100 80GB (or 4x A10G)          │
│     └─ Output: fixops-security-agent-v1              │
│                                                      │
│  5. Evaluation                                       │
│     ├─ Compare against historical 3-model consensus  │
│     ├─ Target: ≥95% agreement with consensus         │
│     ├─ Pentest accuracy: validate exploit paths      │
│     └─ Compliance accuracy: validate control maps    │
└──────────────────────────────────────────────────────┘
```

### 26.6 Cost Comparison

| Metric | Current (Multi-LLM) | Target (Single Agent) |
|--------|---------------------|----------------------|
| API calls per decision | 3-4 (OpenAI + Claude + Gemini) | 5 local calls (4 experts + moderator) |
| Cost per decision | $0.003-0.02 | $0.00 (self-hosted) |
| Monthly cost (10K findings/day) | $900-6,000 | $0 API + ~$500/mo GPU (A10G spot) |
| Latency per decision | 3-8s (network round trips) | 0.5-2s (local inference) |
| Privacy | Data sent to 3 external APIs | Data never leaves your infrastructure |
| Availability | Depends on 3 external services | 100% self-controlled uptime |
| Model updates | Vendor-controlled, may change behavior | You control model version, freeze when stable |
| **Annual savings** | **Baseline** | **$10K-66K/year saved** |

### 26.7 Backward Compatibility Layer

```python
# suite-core/core/llm_providers.py — Updated

class SingleAgentProvider(BaseLLMProvider):
    """Drop-in replacement that routes to the local multi-role engine."""
    
    def __init__(self, name: str = "fixops-agent", *, 
                 model_url: str = "http://localhost:8080/v1",
                 style: str = "consensus"):
        super().__init__(name, style=style)
        self.engine = SingleAgentDecisionEngine(model_url)
    
    def analyse(self, *, prompt, context, default_action, 
                default_confidence, default_reasoning, 
                mitigation_hints=None) -> LLMResponse:
        """Same interface as OpenAIChatProvider / AnthropicMessagesProvider."""
        # Internally runs 4 experts + moderator on local model
        return asyncio.run(self.engine.decide(context, mitigation_hints))

# Config switch:
# FIXOPS_LLM_MODE=single-agent  → uses SingleAgentProvider
# FIXOPS_LLM_MODE=multi-vendor  → uses existing OpenAI+Claude+Gemini (default)
# FIXOPS_LLM_MODE=deterministic → uses DeterministicLLMProvider (offline)
```

### 26.8 Deployment Options

| Option | GPU | Model Size | Tokens/sec | Monthly Cost |
|--------|-----|-----------|------------|-------------|
| **Ollama (dev)** | M1/M2 Mac (local) | Llama 3.1 8B (quantized) | ~30 t/s | $0 |
| **vLLM (staging)** | 1x A10G (24GB) | Llama 3.1 70B (GPTQ 4-bit) | ~80 t/s | ~$250/mo spot |
| **vLLM (prod)** | 2x A100 80GB | Llama 3.1 70B (FP16) | ~200 t/s | ~$500/mo spot |
| **TGI (enterprise)** | 4x H100 | Llama 3.1 405B | ~300 t/s | ~$2,000/mo |

### 26.9 Implementation Roadmap

| Phase | Work | Time |
|-------|------|------|
| Phase 1 | Define 5 role system prompts, create `agent_roles.py` | 2 days |
| Phase 2 | Build `SingleAgentDecisionEngine` with local vLLM calls | 3 days |
| Phase 3 | Export 10K+ historical decisions as training data | 2 days |
| Phase 4 | Fine-tune Llama 3.1 70B with QLoRA | 3 days (GPU time: 8-12 hrs) |
| Phase 5 | Evaluate against historical consensus (target ≥95% agreement) | 2 days |
| Phase 6 | Create `SingleAgentProvider` as `BaseLLMProvider` subclass | 1 day |
| Phase 7 | Add `FIXOPS_LLM_MODE` config switch, backward compat tests | 1 day |
| Phase 8 | Docker compose with vLLM sidecar container | 1 day |
| **Total** | | **15 days** |

**Differentiator**: No AppSec vendor offers a self-hosted, zero-token-cost AI decision engine. Snyk uses fixed rules. ArmorCode uses basic GPT calls (they pay OpenAI). Apiiro has proprietary ML but no multi-role deliberation. ALdeci's approach — one model assuming 4 expert roles plus a moderator — is unique in the industry and eliminates vendor lock-in.

---

## Part 27 — Quantum-Secure Cryptography (Backward Compatible)

### 27.1 Current Cryptographic Inventory

**Primary signing module**: `suite-core/core/crypto.py` (571 LOC)

| Component | Current Algorithm | Quantum Threat |
|-----------|------------------|----------------|
| `RSAKeyManager` | RSA-4096 (PKCS#1 v1.5) | **BROKEN** by Shor's algorithm |
| `RSASigner.sign()` | RSA-SHA256 with PKCS1v15 padding | **BROKEN** — signatures forgeable |
| `RSAVerifier.verify()` | RSA-SHA256 verification | **BROKEN** — cannot trust old signatures |
| Key fingerprints | SHA-256 hash of public key PEM | **SAFE** — SHA-256 is quantum-resistant (Grover's only halves security to 128-bit) |
| Key storage | PEM format, PKCS8 encoding | Format is fine, algorithm inside must change |

**Evidence signing module**: `suite-core/core/evidence.py` (437 LOC)
- Imports `rsa_sign` and `rsa_verify` from `core.crypto`
- `EvidenceHub` uses RSA-SHA256 for bundle integrity
- Fernet (AES-128-CBC) encryption for sensitive bundles — **weakened** to 64-bit by Grover's

**Evidence packager**: `suite-evidence-risk/evidence/packager.py` (335 LOC)
- SHA-256 file digests for integrity — **SAFE**
- `sign_key` parameter passes through to RSA signer — **BROKEN**
- SLSA v1 attestation format — format is fine, signing algorithm must change

### 27.2 NIST Post-Quantum Cryptography Standards (FIPS 203/204/205)

| Standard | Algorithm | Purpose | Replaces | Status |
|----------|-----------|---------|----------|--------|
| **FIPS 203** (ML-KEM) | CRYSTALS-Kyber | Key encapsulation | RSA/ECDH key exchange | Finalized Aug 2024 |
| **FIPS 204** (ML-DSA) | CRYSTALS-Dilithium | Digital signatures | RSA/ECDSA signing | Finalized Aug 2024 |
| **FIPS 205** (SLH-DSA) | SPHINCS+ | Digital signatures (stateless, hash-based) | RSA/ECDSA (conservative alternative) | Finalized Aug 2024 |
| **FIPS 206** (FN-DSA) | FALCON | Digital signatures (compact) | RSA/ECDSA | Draft, expected 2025 |

### 27.3 Target Architecture: Hybrid Classical + Post-Quantum

**Design principle**: Every signature is dual-signed (classical + PQC). If either algorithm is broken, the other still protects integrity. This is NIST's recommended migration strategy.

```
┌────────────────────────────────────────────────────────┐
│              Hybrid Crypto Engine                      │
│                                                        │
│  ┌────────────┐           ┌────────────────────┐      │
│  │ Classical  │           │  Post-Quantum      │      │
│  │ Layer      │           │  Layer              │      │
│  │            │           │                     │      │
│  │ RSA-4096   │           │  ML-DSA-65          │      │
│  │ SHA-256    │    AND    │  (Dilithium3)       │      │
│  │ PKCS1v15   │           │  FIPS 204           │      │
│  │            │           │                     │      │
│  └─────┬──────┘           └──────┬──────────────┘      │
│        │                         │                     │
│        └─────────┬───────────────┘                     │
│                  ▼                                     │
│        ┌─────────────────┐                             │
│        │ Hybrid Signature│                             │
│        │ = classical_sig │                             │
│        │ || pq_sig       │                             │
│        │ || algorithm_id │                             │
│        └─────────────────┘                             │
│                                                        │
│  Verification: BOTH must pass (AND logic)              │
│  Backward compat: old verifiers check classical only   │
└────────────────────────────────────────────────────────┘
```

### 27.4 Implementation: Hybrid Key Manager

```python
# suite-core/core/pqcrypto.py

from enum import Enum
from dataclasses import dataclass
from typing import Optional, Tuple
import oqs  # liboqs-python (Open Quantum Safe)

class SignatureAlgorithm(Enum):
    """Supported signature algorithms."""
    RSA_SHA256 = "rsa-sha256"              # Classical (current)
    ML_DSA_44 = "ml-dsa-44"               # FIPS 204 Level 2 (128-bit PQ security)
    ML_DSA_65 = "ml-dsa-65"               # FIPS 204 Level 3 (192-bit PQ security)
    ML_DSA_87 = "ml-dsa-87"               # FIPS 204 Level 5 (256-bit PQ security)
    SLH_DSA_SHA2_128S = "slh-dsa-sha2-128s"  # FIPS 205 (hash-based, conservative)
    HYBRID_RSA_ML_DSA = "hybrid-rsa-ml-dsa"  # Dual signature (recommended)

class KEMAlgorithm(Enum):
    """Supported key encapsulation mechanisms."""
    RSA_OAEP = "rsa-oaep"                 # Classical (current)
    ML_KEM_768 = "ml-kem-768"             # FIPS 203 Level 3
    ML_KEM_1024 = "ml-kem-1024"           # FIPS 203 Level 5
    HYBRID_RSA_ML_KEM = "hybrid-rsa-ml-kem"  # Dual encapsulation

@dataclass
class HybridKeyPair:
    """A hybrid key pair containing both classical and PQ keys."""
    classical_private: bytes   # RSA-4096 private key (PEM)
    classical_public: bytes    # RSA-4096 public key (PEM)
    pq_private: bytes          # ML-DSA-65 private key
    pq_public: bytes           # ML-DSA-65 public key
    algorithm: SignatureAlgorithm
    key_id: str
    fingerprint: str           # SHA-256 of concatenated public keys

@dataclass
class HybridSignature:
    """A hybrid signature containing both classical and PQ signatures."""
    classical_signature: bytes
    pq_signature: bytes
    algorithm: SignatureAlgorithm
    key_fingerprint: str
    
    def to_bytes(self) -> bytes:
        """Serialize hybrid signature for storage."""
        return json.dumps({
            "v": 2,  # signature format version
            "alg": self.algorithm.value,
            "classical": base64.b64encode(self.classical_signature).decode(),
            "pq": base64.b64encode(self.pq_signature).decode(),
            "fp": self.key_fingerprint,
        }).encode()
    
    @classmethod
    def from_bytes(cls, data: bytes) -> "HybridSignature":
        """Deserialize hybrid signature."""
        obj = json.loads(data)
        if obj.get("v", 1) == 1:
            # v1 = classical only (backward compat)
            return cls(
                classical_signature=base64.b64decode(obj["sig"]),
                pq_signature=b"",
                algorithm=SignatureAlgorithm.RSA_SHA256,
                key_fingerprint=obj["fp"],
            )
        return cls(
            classical_signature=base64.b64decode(obj["classical"]),
            pq_signature=base64.b64decode(obj["pq"]),
            algorithm=SignatureAlgorithm(obj["alg"]),
            key_fingerprint=obj["fp"],
        )

class HybridSigner:
    """Dual classical + post-quantum signer."""
    
    def __init__(self, key_pair: HybridKeyPair):
        self.key_pair = key_pair
        self._rsa_manager = RSAKeyManager()  # existing classical signer
        self._pq_signer = oqs.Signature("Dilithium3")
        self._pq_signer.secret_key = key_pair.pq_private
    
    def sign(self, data: bytes) -> HybridSignature:
        """Produce dual signature (classical AND post-quantum)."""
        # Classical RSA-SHA256 signature
        classical_sig, fingerprint = self._rsa_manager.sign(data)
        
        # Post-quantum ML-DSA-65 signature
        pq_sig = self._pq_signer.sign(data)
        
        return HybridSignature(
            classical_signature=classical_sig,
            pq_signature=pq_sig,
            algorithm=SignatureAlgorithm.HYBRID_RSA_ML_DSA,
            key_fingerprint=fingerprint,
        )

class HybridVerifier:
    """Dual verification with backward compatibility."""
    
    def __init__(self, key_pair: HybridKeyPair):
        self.key_pair = key_pair
        self._rsa_verifier = RSAVerifier()
        self._pq_verifier = oqs.Signature("Dilithium3")
        self._pq_verifier.public_key = key_pair.pq_public
    
    def verify(self, data: bytes, signature: HybridSignature) -> bool:
        """Verify hybrid signature. Both must pass for v2 sigs."""
        # Always verify classical (backward compat)
        classical_ok = self._rsa_verifier.verify(
            data, signature.classical_signature
        )
        
        if signature.algorithm == SignatureAlgorithm.RSA_SHA256:
            # v1 signature — classical only (old bundles)
            return classical_ok
        
        # v2 hybrid — both must pass
        pq_ok = self._pq_verifier.verify(
            data, signature.pq_signature
        )
        
        return classical_ok and pq_ok
```

### 27.5 Backward Compatibility Strategy

```
Timeline:
─────────────────────────────────────────────────────────────────
     Phase 1 (Now)          Phase 2 (6 months)     Phase 3 (18 months)
     RSA-only signing       Dual signing           PQ-primary
                            (hybrid)               
─────────────────────────────────────────────────────────────────
Sign:   RSA-SHA256     →    RSA + ML-DSA      →   ML-DSA only
Verify: RSA-SHA256     →    RSA OR Hybrid     →   Hybrid OR ML-DSA
Format: v1             →    v1 + v2           →   v2 + v3

Old bundles: Always verifiable (classical sig preserved)
New bundles: Dual-signed (quantum-safe from day 1)
Migration:  Re-sign old bundles with hybrid key (background job)
```

**Key compatibility rules:**
1. **v1 signatures** (existing RSA-only) → always verifiable, never rejected
2. **v2 signatures** (hybrid RSA + ML-DSA) → requires updated verifier
3. **v3 signatures** (PQ-only ML-DSA) → future phase, classical dropped
4. **Signature format** includes version field → verifier auto-selects logic
5. **Key rotation** adds PQ key alongside existing RSA key → no key revocation needed

### 27.6 Evidence Bundle Impact

```python
# Updated EvidenceHub.persist() flow:

class EvidenceHub:
    def persist(self, bundle: dict, *, sign: bool = True) -> Path:
        payload = json.dumps(bundle).encode()
        
        if sign:
            if self.pq_enabled:
                # Phase 2+: Hybrid signature
                hybrid_sig = self.hybrid_signer.sign(payload)
                metadata = {
                    "signature_version": 2,
                    "algorithm": "hybrid-rsa-ml-dsa",
                    "classical_sig": b64encode(hybrid_sig.classical_signature),
                    "pq_sig": b64encode(hybrid_sig.pq_signature),
                    "fingerprint": hybrid_sig.key_fingerprint,
                }
            else:
                # Phase 1: Classical RSA (current behavior)
                sig, fp = rsa_sign(payload)
                metadata = {
                    "signature_version": 1,
                    "algorithm": "rsa-sha256",
                    "sig": b64encode(sig),
                    "fingerprint": fp,
                }
```

### 27.7 Encryption Upgrade (ML-KEM for Key Exchange)

Current: Fernet (AES-128-CBC) — Grover's attack reduces to 64-bit security.

```python
# Upgrade path for evidence encryption:

class QuantumSafeEncryption:
    """AES-256-GCM with ML-KEM key encapsulation."""
    
    def encrypt(self, plaintext: bytes, recipient_pk: bytes) -> bytes:
        # 1. ML-KEM key encapsulation (FIPS 203)
        kem = oqs.KeyEncapsulation("Kyber1024")
        ciphertext_kem, shared_secret = kem.encap_secret(recipient_pk)
        
        # 2. Derive AES-256 key from shared secret
        aes_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,  # 256-bit key
            salt=None,
            info=b"fixops-evidence-encryption",
        ).derive(shared_secret)
        
        # 3. AES-256-GCM encryption (quantum-safe symmetric)
        nonce = os.urandom(12)
        cipher = AESGCM(aes_key)
        ciphertext = cipher.encrypt(nonce, plaintext, None)
        
        return ciphertext_kem + nonce + ciphertext
```

### 27.8 Size & Performance Impact

| Operation | RSA-4096 (Current) | ML-DSA-65 (PQ) | Hybrid |
|-----------|-------------------|----------------|--------|
| Public key size | 550 bytes | 1,952 bytes | 2,502 bytes |
| Private key size | 3,272 bytes | 4,032 bytes | 7,304 bytes |
| Signature size | 512 bytes | 3,309 bytes | 3,821 bytes |
| Sign time | ~1.2ms | ~0.3ms | ~1.5ms |
| Verify time | ~0.05ms | ~0.2ms | ~0.25ms |
| Key gen time | ~200ms | ~0.15ms | ~200ms |
| Bundle overhead | ~1KB | ~4KB | ~5KB |

**Impact**: Each evidence bundle grows by ~4KB. For a platform generating ~100 bundles/day, that's 400KB/day — negligible.

### 27.9 Dependencies

```
# requirements.txt additions:
liboqs-python>=0.10.0    # Open Quantum Safe — NIST PQC implementations
pqcrypto>=0.1.0          # Alternative: pure-Python PQC (slower, no C deps)

# System dependency (for liboqs):
# brew install liboqs      (macOS)
# apt install liboqs-dev   (Ubuntu)
# docker: use openquantumsafe/oqs-provider base image
```

### 27.10 Implementation Roadmap

| Phase | Work | Time |
|-------|------|------|
| Phase 1 | Install `liboqs-python`, create `pqcrypto.py` with `HybridKeyPair`, `HybridSigner`, `HybridVerifier` | 3 days |
| Phase 2 | Add signature version field to `EvidenceHub.persist()` and `packager.py` | 2 days |
| Phase 3 | Backward compat: verifier auto-detects v1 (RSA) vs v2 (hybrid) | 1 day |
| Phase 4 | Upgrade Fernet → AES-256-GCM + ML-KEM (FIPS 203) | 2 days |
| Phase 5 | Background job to re-sign existing evidence bundles with hybrid keys | 2 days |
| Phase 6 | Add `FIXOPS_CRYPTO_MODE` env var: `classical` / `hybrid` / `pq-only` | 1 day |
| Phase 7 | SLSA attestation update: embed PQ signature in provenance | 1 day |
| Phase 8 | Integration tests with all 3 modes, key rotation tests | 2 days |
| **Total** | | **14 days** |

### 27.11 Compliance & Marketing Value

**Regulatory drivers:**
- **NSA CNSA 2.0** (2022): All national security systems must use PQC by 2035
- **NIST SP 800-208**: Recommends hash-based signatures (SLH-DSA) for firmware
- **White House OMB M-23-02**: Federal agencies must inventory cryptographic systems by 2025
- **PCI DSS 4.0**: Requires "strong cryptography" — PQC will become the baseline
- **EU Cyber Resilience Act**: Mandates "state of the art" security

**Marketing claim**: *"ALdeci is the first AppSec platform with quantum-secure evidence signing. Every compliance bundle is dual-signed with RSA-4096 and CRYSTALS-Dilithium (NIST FIPS 204), ensuring your audit evidence remains tamper-proof even against quantum computers."*

**Competitor status:**
| Vendor | Quantum-Ready | Post-Quantum Crypto |
|--------|-------------|-------------------|
| Snyk | No | No |
| ArmorCode | No | No |
| Apiiro | No | No |
| Cycode | No | No |
| Nucleus | No | No |
| NopSec | No | No (acquired, legacy) |
| Vulcan | No | No |
| **ALdeci** | **Yes** | **Hybrid RSA + ML-DSA** |

→ **Zero competitors** have post-quantum cryptography. This is a patent-worthy differentiator.

---

## Part 28 — Combined Implementation Timeline

### 28.1 Sprint Plan: MCP + Single Agent + Quantum Crypto

| Week | Focus | Deliverables |
|------|-------|-------------|
| **Week 1** | MCP SDK migration | Replace custom REST MCP with official `mcp` Python SDK, implement initialize/tools/call |
| **Week 2** | MCP auto-discovery + transports | Auto-generate 650 tools from FastAPI routes, SSE + WebSocket |
| **Week 3** | Agent roles + engine | Create `agent_roles.py` (5 roles), `single_agent_engine.py`, local vLLM calls |
| **Week 4** | Fine-tuning data + training | Export 10K decisions, generate synthetic role data, QLoRA fine-tune |
| **Week 5** | Quantum crypto core | `pqcrypto.py` with hybrid signing, liboqs integration |
| **Week 6** | Evidence + encryption upgrade | Hybrid evidence signing, AES-256-GCM + ML-KEM, backward compat |
| **Week 7** | MCP screen bridge | React MCP bridge, agent screen interaction (navigate/read/trigger) |
| **Week 8** | Integration + testing | End-to-end tests, docker compose with vLLM sidecar, key rotation tests |

### 28.2 Total Engineering Effort

| Feature | New LOC | Modified LOC | Files | Days |
|---------|---------|-------------|-------|------|
| MCP Expansion | ~3,500 | ~300 | 8 new + 3 modified | 15 |
| Single AI Agent | ~2,000 | ~200 | 5 new + 2 modified | 15 |
| Quantum Crypto | ~1,800 | ~400 | 4 new + 4 modified | 14 |
| **Total** | **~7,300** | **~900** | **17 new + 9 modified** | **44 days** |

### 28.3 Investor Pitch: Three Moats

1. **MCP-Native**: Only AppSec platform that is a full MCP server — any AI agent (Copilot, Cursor, Claude Desktop, custom) can manage security through natural language
2. **Zero-Token AI**: Self-hosted multi-role decision engine eliminates API costs and vendor lock-in — $66K/year savings at scale, data never leaves customer infra
3. **Quantum-Secure**: First AppSec platform with NIST FIPS 203/204/205 post-quantum cryptography — future-proofs every compliance evidence bundle for 30+ years

*These three features together create an acquisition-worthy technical moat that would take any competitor 12-18 months to replicate.*

---

## Part 29: The Great AppSec Obsolescence — Why Snyk, Checkmarx, Veracode & Every $100M+ Funded Scanner Will Be Irrelevant by 2028

### 29.1 The Central Thesis

**If AI writes the code, AI will review it for security, host it securely, meet compliance, and report back. What will these heavily funded guys do?**

This is not speculation — it is the logical conclusion of five converging technology shifts happening simultaneously in 2025-2026:

1. **AI Code Generation** is already mainstream (97% of enterprise developers have used AI coding tools — GitHub 2024 Survey, 2,000 respondents across US/Brazil/India/Germany)
2. **AI Security Review** is being embedded directly into the code generation pipeline (GitHub Copilot Autofix, Snyk DeepCode AI, Amazon CodeGuru)
3. **Agentic AI** is moving from "suggest" to "autonomously act" — agents that write, test, deploy, monitor, and fix code without human intervention (McKinsey: "agentic AI is acting autonomously" — Superagency Report, Jan 2025)
4. **LLM-native security** is becoming a new attack surface AND a new defense surface simultaneously (OWASP GenAI Security Project: 600+ experts, 8,000 community members)
5. **Quantum computing** is breaking all current cryptography within a decade (NIST finalized PQC standards Aug 2024: FIPS 203/204/205)

The combined effect: **the entire AppSec industry as we know it — scan-find-report-ticket — becomes a feature, not a product.**

### 29.2 The AppSec Industry's $30B Problem

#### Current Market Structure (2024-2025)

| Company | Valuation/Revenue | What They Do | Core Dependency |
|---------|-------------------|--------------|-----------------|
| Snyk | $7.4B valuation (Sep 2024, $530M raise) | SCA, SAST, Container, IaC scanning | Humans write code → Snyk scans it |
| Checkmarx | ~$1.15B (Hellman & Friedman, 2020) | SAST, SCA, DAST | Same scan-after-write model |
| Veracode | ~$2.5B (Thoma Bravo acquisition) | SAST, DAST, SCA | Same scan-after-write model |
| Wiz | $12B valuation (2024) | Cloud security posture | Humans configure cloud → Wiz audits |
| Palo Alto Networks | $120B+ market cap | CNAPP, CSPM, WAF | Network/cloud perimeter scanning |
| SonarQube/SonarSource | $4.7B (2022) | Code quality + SAST | Code review as separate workflow |
| Fortify (OpenText) | Undisclosed | SAST, DAST | Enterprise legacy scanning |
| Black Duck (Synopsys) | Part of $35B company | SCA | Open source license scanning |

**Total addressable market (TAM)**: ~$30B for application security (Gartner 2024)

**The fundamental assumption every one of these companies is built on**: *Humans write code, and a separate tool must scan it afterward to find vulnerabilities.*

#### Why This Assumption Is Dying

The scan-after-write model was designed for a world where:
- Developers write code manually → 15-50 lines/hour
- Code review happens days later → PRs sit for 2-5 days
- Security scanning happens in CI/CD → another 10-60 minutes
- Findings go into a ticketing system → tickets age 60-180 days
- Developers context-switch to fix → 30-90 minutes per fix

**Total vulnerability lifecycle: 60-180 days from introduction to fix.**

In the AI-native development world:
- AI writes code → 150-500 lines/hour (10-30x faster)
- AI reviews its own code → milliseconds (simultaneous with generation)
- AI deploys via infrastructure-as-code → auto-configured securely
- AI monitors at runtime → real-time anomaly detection
- AI fixes autonomously → no ticket, no context switch

**Total vulnerability lifecycle: 0 days. The vulnerability never exists.**

### 29.3 The Five Convergence Forces

#### Force 1: AI Code Generation Is Already Dominant

**GitHub Survey 2024** (2,000 enterprise developers, US/Brazil/India/Germany):
- **97% of developers** have used AI coding tools at work
- **90% (US) / 81% (India)** report improved code quality
- **60-71%** say AI makes it easy to adopt new programming languages
- **98%+** of organizations have experimented with AI for test case generation
- **99-100%** of respondents anticipate AI will improve code security
- Developers use saved time for **system design (47%)** and **collaboration (47%)**

**Key insight**: AI is not replacing developers — it is absorbing the mechanical aspects of coding (writing boilerplate, writing tests, writing security checks) and freeing developers for architecture and design.

**The implication for AppSec vendors**: If AI writes 70-90% of code by 2027, and that code is generated with security guardrails built into the generation prompt, the number of vulnerabilities introduced per line of code drops by 5-10x. **Fewer vulnerabilities = less need for scanners.**

#### Force 2: AI Security Is Being Embedded Into Code Generation

This is the critical shift that destroys the scan-after-write business model:

**Before (2020-2024)**: Developer writes code → pushes to repo → CI/CD runs Snyk/Checkmarx/Veracode → findings created → developer fixes days later

**Now (2025-2026)**: Developer prompts AI → AI generates code WITH security considerations → AI simultaneously reviews for OWASP Top 10 → AI suggests fixes before commit → clean code enters repo

**Key players embedding security into generation**:
- **GitHub Copilot Autofix**: Automatically identifies and suggests fixes for vulnerabilities in pull requests — 3x faster than manual review
- **Amazon CodeWhisperer**: Scans generated code for security issues in real-time, references CWE/CVE databases
- **Cursor AI**: Context-aware code generation that reads entire codebase for security patterns
- **Google Gemini Code Assist**: Generates security-compliant code with Google Cloud security best practices
- **Snyk DeepCode AI** (ironically): Integrated into IDE to catch issues at write-time — Snyk is cannibalizing its own CI/CD scanning business

**The paradox**: Snyk launched "Evo" — an agentic AI security orchestrator — because they know their core scanning business is dying. They are racing to become the "AI security for AI code" platform. But if the AI that writes code also secures it, why do you need a separate AI to re-check the first AI's work?

#### Force 3: Agentic AI Eliminates the Human-Speed Bottleneck

**McKinsey Superagency Report (Jan 2025)**:
- $4.4 trillion in added productivity from AI use cases
- 92% of companies plan to increase AI investments over next 3 years
- Only 1% of companies consider themselves "mature" in AI deployment
- Agentic AI can "converse with a customer and plan the actions it will take afterward — processing payment, checking for fraud, completing a shipping action"

**What this means for security**: Agentic AI doesn't just write code — it:
1. **Architects** the system (threat modeling at design time)
2. **Writes** the code (with security patterns baked in)
3. **Tests** the code (generates security test cases — 98% of orgs already experimenting)
4. **Deploys** the code (configures infrastructure securely via IaC)
5. **Monitors** the runtime (detects anomalies, responds to incidents)
6. **Fixes** discovered issues (auto-generates patches and PRs)
7. **Reports** compliance status (generates evidence bundles)

**This is a single autonomous loop.** There is no point in the loop where a separate scanning tool like Snyk adds value. The agent already knows every line it wrote, every dependency it chose, every configuration it set. It has **complete context** — something external scanners fundamentally lack.

#### Force 4: LLM Security Creates NEW Attack Surfaces That Scanners Can't Address

The OWASP GenAI Security Project (600+ experts, 18 countries, 8,000 community members) identifies entirely new vulnerability categories that traditional AppSec tools were never designed to find:

**OWASP Top 10 for LLM Applications (2025 version)**:
1. **LLM01: Prompt Injection** — malicious inputs that hijack model behavior
2. **LLM02: Insecure Output Handling** — trusting model outputs without validation
3. **LLM03: Training Data Poisoning** — corrupting model training data
4. **LLM04: Model Denial of Service** — resource exhaustion attacks on models
5. **LLM05: Supply Chain Vulnerabilities** — compromised model dependencies/plugins
6. **LLM06: Sensitive Information Disclosure** — models leaking PII/secrets
7. **LLM07: Insecure Plugin Design** — unsafe tool/function calling
8. **LLM08: Excessive Agency** — models taking unintended autonomous actions
9. **LLM09: Overreliance** — trusting model outputs without verification
10. **LLM10: Model Theft** — unauthorized access to proprietary models

**None of these are detectable by Snyk, Checkmarx, or Veracode.** These tools scan for SQL injection, XSS, buffer overflows — vulnerabilities in deterministic code. LLM vulnerabilities are fundamentally different: they exist in probabilistic, non-deterministic systems where the "code" is a neural network with billions of parameters.

**The AI model collapse risk** (Gartner, Jan 2026): By 2028, 50% of organizations will need zero-trust data governance because AI models will degrade as they train on AI-generated content. This creates security risks that no current AppSec tool can even conceptualize — models becoming "confidently wrong" about security recommendations.

**ALdeci's opportunity**: Our Decision Intelligence engine already reasons about non-deterministic security decisions. We can extend this to LLM security — something Snyk is trying to bolt onto a scanner-based architecture.

#### Force 5: Quantum Computing Breaks Everything Current Scanners Protect

**NIST PQC Standards (Finalized August 13, 2024)**:
- **FIPS 203 (ML-KEM)**: Module-lattice-based key encapsulation — replaces RSA/ECDH for encryption
- **FIPS 204 (ML-DSA)**: Module-lattice-based digital signatures — replaces RSA/ECDSA for signing (previously CRYSTALS-Dilithium)
- **FIPS 205 (SLH-DSA)**: Stateless hash-based digital signatures — backup for ML-DSA

**NIST directive**: "We encourage system administrators to begin transitioning to the new standards as soon as possible, because full integration will take time."

**Timeline**: Experts predict a cryptographically relevant quantum computer within a decade (RAND Corporation, 2023). Some agencies assume adversaries are already using "harvest now, decrypt later" attacks.

**The impact on AppSec companies**:
- Every SCA/SAST tool signs its findings with RSA/ECDSA → quantum-vulnerable
- Every evidence bundle they produce uses SHA-256 + RSA → quantum-vulnerable
- Their compliance attestations will be cryptographically meaningless within 10 years
- None of them (Snyk, Checkmarx, Veracode, Wiz) have announced PQC migration plans

**ALdeci's advantage**: Part 27 of this document already specifies our quantum-secure migration to FIPS 203/204/205. We will be the **first AppSec platform with post-quantum evidence signing** — a concrete, provable differentiator.

### 29.4 The Snyk Paradox: Spending $7.4B to Become a Feature

#### Snyk's Strategic Pivot (2025-2026)

Snyk has recognized the threat. Their current platform messaging reveals their desperation:

**Old Snyk (2020-2023)**: "Developer-first security scanning"
**New Snyk (2025-2026)**: "AI Security Platform — Security at machine speed"

Their new "Evo by Snyk" is described as an "agentic security orchestrator" with:
- "AI-accelerated DevSecOps"
- "Securing AI-driven development"
- "Securing AI-native software"
- "Autonomous, runtime protection for non-deterministic AI-native applications"

**The irony**: Snyk is building an AI agent to secure code that was written by AI agents. This is a **recursive dependency** — you need a security AI to watch the coding AI, but who watches the security AI? Another security AI? The cost structure collapses.

**Snyk's real financials** (what investors should scrutinize):
- $7.4B valuation on $530M raise (Sep 2024) — implies massive revenue expectations
- Still not profitable after $1B+ total funding
- IPO repeatedly delayed (originally planned 2023, then 2024, now "maybe 2025")
- Multiple rounds of layoffs (2023, 2024)
- Core product (SCA scanning) is increasingly commoditized — GitHub Advanced Security offers it free with GitHub Enterprise
- Revenue growth is decelerating as free alternatives (GitHub GHAS, Amazon Inspector, Google Cloud Security) absorb market share

**The existential question**: If GitHub Copilot writes 70% of code AND GitHub Advanced Security scans that code for free as part of GitHub Enterprise, why would any company pay $50-200/developer/year for Snyk on top of that?

#### Gartner's Reveal: The "Leader" Label Is a Lagging Indicator

Snyk was named a "Leader in the 2025 Gartner Magic Quadrant for Application Security Testing." But Gartner Magic Quadrants are backward-looking — they measure what companies have done, not what the market will need. Being a leader in a dying category is not an advantage:
- Kodak was the leader in film photography
- Blockbuster was the leader in video rental
- Nokia was the leader in mobile phones
- Snyk is the leader in scan-after-write AppSec

### 29.5 Why Every Major AppSec Company Will Fail or Pivot

#### Company-by-Company Disruption Analysis

**1. Snyk ($7.4B valuation)**
- **What they do**: SCA, SAST, container scanning, IaC scanning
- **Why it dies**: GitHub GHAS gives comparable scanning free with Enterprise; AI-generated code has fewer vulnerabilities to find; their own "Evo" pivot admits core scanning is insufficient
- **Survival play**: Become an AI security governance platform — but this is a smaller market
- **Timeline to irrelevance**: 2-3 years for core scanning; 4-5 years for AI pivot to prove out

**2. Checkmarx (~$1.15B)**
- **What they do**: Enterprise SAST/SCA/DAST
- **Why it dies**: Slowest to adopt AI; heaviest on-premise legacy; most expensive per-developer pricing; enterprises moving to free GitHub/GitLab native scanning
- **Survival play**: Private equity may force acquisition by larger security platform
- **Timeline to irrelevance**: 1-2 years; already losing enterprise renewals

**3. Veracode (~$2.5B)**
- **What they do**: Cloud-based SAST/DAST/SCA  
- **Why it dies**: Thoma Bravo PE ownership means cost-cutting over innovation; DAST is being absorbed by AI-generated integration tests; SCA is commoditized
- **Survival play**: Acquisition by Broadcom/OpenText/other PE roll-up
- **Timeline to irrelevance**: 2-3 years

**4. SonarQube/SonarSource ($4.7B)**
- **What they do**: Code quality + SAST
- **Why it dies**: AI coding assistants already enforce code quality at generation time; linting rules are embedded in LLM training data; the "code review" step they occupy is being automated away
- **Survival play**: Become the "code quality benchmark" standard — but margins collapse
- **Timeline to irrelevance**: 3-4 years (slower decline due to open-source community)

**5. Wiz ($12B valuation)**
- **What they do**: Cloud security posture management (CSPM/CNAPP)
- **Why it dies more slowly**: Cloud misconfiguration is a different problem than code security; but AI-configured IaC reduces configuration errors by 80%+
- **Survival play**: Strongest position of any AppSec company because cloud security is more durable than code security; acquired by Google for $32B (May 2025)
- **Timeline to irrelevance**: 5-7 years

**6. Fortify (OpenText) / Black Duck (Synopsys)**
- **What they do**: Legacy enterprise SAST/SCA
- **Why it dies**: Already zombies — maintained for compliance checkbox revenue from Fortune 500 companies that move slowly
- **Survival play**: Milk existing contracts; no innovation path
- **Timeline to irrelevance**: Already irrelevant for new projects; 3-5 years for legacy contracts to wind down

### 29.6 The AI-Native Security Stack (2027-2030)

What replaces the current AppSec industry:

```
┌─────────────────────────────────────────────────────────┐
│                   AI DEVELOPMENT LOOP                    │
│                                                         │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────┐ │
│  │ AI Agent │→ │ Generates │→ │ Self-    │→ │ Auto-   │ │
│  │ receives │  │ code WITH │  │ reviews  │  │ deploys │ │
│  │ task     │  │ security  │  │ for vuln │  │ secure  │ │
│  │          │  │ patterns  │  │ + tests  │  │ infra   │ │
│  └──────────┘  └──────────┘  └──────────┘  └─────────┘ │
│       ↑                                        │        │
│       │         ┌──────────────┐               │        │
│       └─────────│ AI Monitor   │←──────────────┘        │
│                 │ detects +    │                         │
│                 │ auto-fixes   │                         │
│                 └──────────────┘                         │
│                        │                                │
│                 ┌──────────────┐                         │
│                 │ Decision     │  ← THIS IS ALDECI      │
│                 │ Intelligence │                         │
│                 │ • Risk       │                         │
│                 │ • Compliance │                         │
│                 │ • Evidence   │                         │
│                 │ • Quantum PQC│                         │
│                 └──────────────┘                         │
└─────────────────────────────────────────────────────────┘
```

In this architecture:
- **Scanning tools (Snyk, Checkmarx, Veracode)** → absorbed into the AI code generation step
- **CSPM tools (Wiz, Prisma Cloud)** → absorbed into the AI deployment step
- **DAST tools** → absorbed into AI-generated integration tests
- **GRC tools** → absorbed into AI compliance evidence generation

**What remains as a product** (and what ALdeci IS):
1. **Decision Intelligence**: When the AI finds a risk, what should be done? Patch? Accept? Mitigate? Escalate? This requires business context, risk tolerance, compliance requirements — things the coding AI doesn't know
2. **Compliance Evidence**: Regulated industries need cryptographically signed, audit-ready evidence bundles with chain of custody. An AI writing code can't self-attest its own security — that's the fox guarding the henhouse
3. **Cross-system Correlation**: Vulnerabilities don't exist in isolation. A medium-severity code vuln + a misconfigured cloud + an expired certificate = critical attack path. This requires a brain that sees across all systems
4. **Quantum-secure attestation**: All evidence must survive the quantum transition. Only platforms built with FIPS 203/204/205 from the ground up will be relevant after Q-Day

### 29.7 What ALdeci Should Build to Win This Future

#### Strategic Positioning: "Not a Scanner — A Security Brain"

ALdeci should **never** position as a scanner. Scanners are dying. ALdeci should position as:

**"The Decision Intelligence layer for AI-native security"**

This means:

**1. MCP-Native Integration with Every AI Coding Agent (Part 25)**
- Don't scan code that AI wrote — instead, BE the security expert the AI consults while writing
- Other AI agents (Copilot, Cursor, Claude, Devin) call ALdeci via MCP to ask: "Is this dependency safe? Does this pattern violate our compliance requirements? What's the risk score for this architecture decision?"
- ALdeci becomes the **security oracle** in the AI development loop

**2. Compliance Evidence Engine That Survives Quantum (Parts 27-28)**
- Every evidence bundle signed with ML-DSA (FIPS 204) + SLH-DSA (FIPS 205)
- Audit trails that will be cryptographically valid in 2055
- Self-sovereign evidence (customer owns keys, not ALdeci)
- Regulatory mapping (SOC 2, ISO 27001, HIPAA, PCI-DSS, FedRAMP) auto-generated

**3. LLM Security Governance (NEW — from this research)**
- Monitor and govern AI models used in development:
  - Detect prompt injection attempts in AI coding assistants
  - Validate AI-generated code against enterprise security policies
  - Track AI model provenance (is this model safe? was training data poisoned?)
  - Enforce "zero-trust for AI outputs" (Gartner: 50% of orgs will need this by 2028)
- This is the OWASP Top 10 for LLM Applications, operationalized as a product

**4. Attack Path Intelligence Across AI + Human Systems**
- Traditional scanners look at code. ALdeci looks at the entire attack surface:
  - AI-generated code vulnerabilities
  - AI agent permission escalation risks
  - Model theft / model poisoning indicators
  - Supply chain compromises in AI dependencies (npm packages, Python packages, model weights)
  - Human-AI handoff vulnerabilities (where the agent's autonomy boundary creates gaps)

### 29.8 The Investment Thesis: Why ALdeci Wins

**For investors (seed round pitch)**:

**Market timing**: The entire $30B AppSec TAM is being restructured. Scan-after-write (Snyk, Checkmarx, Veracode) is a dying category. Decision Intelligence for AI-native security is the emerging category.

**Why now**:
- McKinsey: 92% of companies increasing AI spend; only 1% mature — massive adoption wave coming 2025-2028
- GitHub: 97% of enterprise devs already using AI tools — the shift is happening NOW
- NIST: PQC standards finalized Aug 2024 — mandatory migration window is 5-7 years
- OWASP: LLM Top 10 published — regulatory enforcement on AI security is imminent
- Gartner: 84% of CIOs increasing GenAI funding for 2026

**Why ALdeci**:
1. **Already built**: 184K LOC, 650 endpoints, multi-LLM consensus engine, MCP server, evidence signing, CTEM pipeline — 2+ years of engineering head start
2. **Architecture is right**: Decision Intelligence (not scanning) is the surviving product category
3. **Three unique moats**: MCP-native, zero-token self-hosted AI, quantum-secure crypto — 12-18 months ahead of any competitor
4. **Capital efficient**: $0 raised to date, built 184K LOC — vs Snyk's $1B+ for a dying scanning product

**Comp analysis**:
- NopSec: Bootstrapped, ~$6M ARR → acquired for ~$150M (25x revenue)
- Vulcan Cyber: $55M raised → acquired for ~$150M
- ALdeci: $0 raised, more features than both → target $3-5M seed, path to $150M+ exit or $500M+ if AI-native thesis plays out

**Revenue model for AI-native era**:
- Per-decision pricing (not per-developer) — scales with AI agent volume, not human headcount
- Compliance-as-a-Service — continuous evidence generation for regulated industries
- MCP marketplace — charge per API call for AI agents consuming ALdeci's security intelligence

### 29.9 Timeline: The AppSec Extinction Event

| Year | Event | Impact on Incumbents | ALdeci Opportunity |
|------|-------|---------------------|-------------------|
| 2025 | AI writes 30-50% of enterprise code | Scanner finding volumes drop 20-30% | Launch MCP server for AI agent integration |
| 2026 | Agentic AI handles deployment + testing | DAST/container scanning becomes redundant | LLM security governance product launch |
| 2027 | AI writes 70-90% of new code | Snyk/Checkmarx renewal rates drop below 80% | Decision Intelligence positioned as replacement |
| 2028 | First PE-funded AppSec company shutdowns begin | Consolidation wave — 3-4 acquisitions | Acquisition target OR Series A for rapid scaling |
| 2029 | NIST PQC mandatory for federal contractors | Every pre-quantum evidence bundle is invalid | Only platform with quantum-secure attestation |
| 2030 | AI security governance is $15B+ TAM | Old AppSec TAM contracts to $10B; new AI security TAM grows to $15B+ | Full AI-native security brain, quantum-secure, MCP-native |

### 29.10 The Bottom Line

**The heavily-funded AppSec companies are optimizing for a world that no longer exists.** They are building faster scanners for code that AI is writing in seconds. They are creating prettier dashboards for vulnerabilities that AI is preventing at generation time. They are raising billions for a business model — scan-find-report-ticket — that becomes a free feature of every AI coding platform.

**Snyk's $7.4B valuation is a house of cards.** Their core SCA/SAST business is being commoditized by GitHub GHAS (free with Enterprise). Their "Evo" agentic pivot is an admission that scanning is dying. Their IPO delays signal that public markets won't support the valuation.

**The survivors will be platforms that provide**:
1. Decision Intelligence (what to DO about a risk, not just what the risk IS)
2. Compliance Evidence (cryptographically proven, quantum-secure, audit-ready)
3. AI Governance (securing the AI that writes code, not scanning the code it wrote)
4. Cross-system correlation (seeing attack paths across AI + human + cloud + code)

**ALdeci is already building all four.**

The question for investors is not "Is AppSec scanning dying?" — it obviously is. The question is "Who will own the Decision Intelligence layer in the AI-native security stack?" That's ALdeci.

---

*Document updated: 2026-02-20*  
*Sources: aldeci_story_pitch_10_20251225122748.pdf, aldeci_story_pitch_10_20260103134309.pdf, GitHub Developer Survey 2024, McKinsey Superagency Report Jan 2025, NIST PQC Standards Aug 2024, OWASP Top 10 for LLM Applications 2025, Snyk Platform/Evo documentation, Gartner AI and Zero-Trust Data Governance predictions*  
*New sections: Parts 25-28 (MCP, Single Agent, Quantum Crypto, Combined Timeline), Part 29 (AppSec Obsolescence Thesis)*  
*Next review: 2026-03-20*
