# ALdeci: Strategic Feature Roadmap for Market Leadership

> **Goal**: $50M+ acquisition valuation  
> **Date**: 2026-02-26 (cleaned)  
> **Current State**: 790K+ LOC, 616 API endpoints, 114 CLI commands, full vulnerability management platform  
> **Sections**: 16 actionable parts (10 archived to `WIP_TO_VALIDATE.md`)

---

## Executive Summary

ALdeci has a solid technical foundation with unique differentiators (Multi-LLM Consensus, Knowledge Graph Brain, MPTE Engine). To achieve acquisition-level valuation, we need to close critical gaps in developer experience, autofix capabilities, and cloud-native attack path visualization.

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

## Part 30: FAIL Engine — Fault-Aware Injection Layer for Pipeline Neglect Detection

> **Source**: Mondragon et al. 2025 — "Fault-Aware Injection for Reliability Testing of AI/ML Systems"  
> **Relevance**: Critical — fills the gap between "we found a vulnerability" and "why did no one act on it for 180 days?"  
> **Priority**: High — unique differentiator, no competitor has anything remotely similar

### 30.1 The Problem: Pipeline Neglect Kills Organizations

The biggest risk in security is not the vulnerability itself — it's the **neglect zone**: the time between detection and action. Every enterprise has findings that sit in dashboards for weeks, months, or years because:

1. **Alert fatigue** — 10,000 findings per quarter, teams triage <20%
2. **Ownership ambiguity** — "That's not my service" → ticket ping-pong
3. **Pipeline rot** — CI/CD security gates exist but are bypassed ("skip-checks" commits)
4. **Stale context** — a critical finding was opened 90 days ago; nobody remembers the context
5. **False confidence** — dashboards show green because thresholds are wrong, not because risk is low

Traditional tools report vulnerabilities. **FAIL proves that your organization would miss the next one.**

### 30.2 What FAIL Does

FAIL is an **LLM-driven fault injection engine** that deliberately introduces controlled faults into ALdeci's own pipeline to measure organizational response quality. Think chaos engineering, but for security operations.

**Core capabilities:**

| Capability | Description | Value |
|-----------|-------------|-------|
| **Synthetic Vulnerability Injection** | Injects realistic-looking CVEs into the pipeline with known severity, exploitability, and blast radius | Tests whether the team actually triages within SLA |
| **Pipeline Gate Bypass Testing** | Deliberately pushes a "vulnerable" artifact through CI/CD to verify gates catch it | Proves security gates work (or exposes that they don't) |
| **Alert Response Measurement** | Fires simulated critical alerts and measures time-to-acknowledge, time-to-assign, time-to-remediate | Quantifies mean-time-to-respond (MTTR) for audit evidence |
| **Ownership Resolution Stress Testing** | Injects findings for services with ambiguous ownership to see if routing works | Exposes "no-owner" blind spots before real incidents hit them |
| **Neglect Zone Detection** | Identifies findings that have been open >30/60/90 days with zero human interaction | Auto-escalates forgotten risks to leadership |
| **Compliance Drill Mode** | Simulates an auditor asking for evidence of vulnerability response — measures how fast the team can produce it | Proves SOC 2 / ISO 27001 readiness without waiting for real audits |
| **ML Training Data Generation** | Every FAIL run produces labeled data (stimulus → response → quality score) that feeds back into ALdeci's decision models | Self-improving security intelligence — the more you run FAIL, the smarter ALdeci gets |

### 30.3 Architecture: How FAIL Integrates with ALdeci

```
┌─────────────────────────────────────────────────────┐
│                    FAIL Engine                        │
│                                                       │
│  ┌──────────┐  ┌──────────┐  ┌──────────────────┐   │
│  │ Scenario  │  │ Injector │  │ Response         │   │
│  │ Generator │──│ Engine   │──│ Measurement      │   │
│  │ (LLM)    │  │          │  │ & Grading        │   │
│  └──────────┘  └──────────┘  └──────────────────┘   │
│       │              │               │               │
│       ▼              ▼               ▼               │
│  ┌──────────────────────────────────────────────┐   │
│  │            Event Bus Integration              │   │
│  └──────────────────────────────────────────────┘   │
│       │              │               │               │
└───────┼──────────────┼───────────────┼───────────────┘
        ▼              ▼               ▼
  ┌──────────┐  ┌──────────┐  ┌──────────────┐
  │ Brain     │  │ MPTE     │  │ Integrations │
  │ Pipeline  │  │ Engine   │  │ (Jira/Slack) │
  └──────────┘  └──────────┘  └──────────────┘
```

**Key design decisions:**
- FAIL scenarios are generated by LLM (GPT-4/Claude) using real-world CVE patterns — they look indistinguishable from real findings to responders
- Injections are tagged with `_fail_drill=true` in the database so they can be excluded from real metrics post-drill
- Response grading uses multi-LLM consensus (same engine as vulnerability triage) to evaluate quality of human response
- ML training loop: every drill generates (scenario, team_response, quality_grade) tuples that improve future decision models

### 30.4 Implementation Plan

| Component | File | LOC | Days |
|-----------|------|-----|------|
| FAIL Engine core | `suite-attack/attack/fault_injection.py` | ~600 | 4 |
| FAIL API router | `suite-api/apps/api/fail_router.py` | ~180 | 1 |
| Scenario templates | `data/fail_scenarios/` | ~200 | 1 |
| Event bus integration | Modify `core/event_bus.py` | ~50 | 0.5 |
| UI drill dashboard | `suite-ui/aldeci/src/pages/fail/` | ~400 | 2 |
| Tests | `tests/test_fault_injection.py` | ~400 | 1.5 |
| **Total** | | **~1,830** | **10 days** |

**API Endpoints (7):**

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/v1/fail/scenarios` | Generate new drill scenario |
| `POST` | `/api/v1/fail/inject` | Execute fault injection |
| `GET` | `/api/v1/fail/drills` | List all drill runs |
| `GET` | `/api/v1/fail/drills/{id}` | Get drill results + response grades |
| `POST` | `/api/v1/fail/drills/{id}/grade` | Trigger LLM-based response grading |
| `GET` | `/api/v1/fail/neglect-zones` | Get findings with zero human interaction |
| `GET` | `/api/v1/fail/metrics` | MTTR, acknowledgment rates, SLA compliance |

### 30.5 Who Benefits (Persona Mapping)

| Persona | Benefit |
|---------|---------|
| **Jake** (Pen Tester) | Validates that his pen-test findings actually get addressed — runs FAIL drills 1 week after report delivery to prove follow-through |
| **Nina** (CISO) | Board-ready metric: "Our mean-time-to-respond to critical findings is 2.3 hours, validated by 12 FAIL drills this quarter" |
| **Chen** (ML Engineer) | Every FAIL drill generates labeled training data that improves ALdeci's decision models — self-improving loop |
| **Ethan** (DevOps Lead) | Tests that CI/CD security gates actually block vulnerable builds — catches misconfigured `skip-checks` patterns |
| **David** (Compliance) | Simulates auditor questions quarterly — proves SOC 2 readiness without waiting for the real audit |
| **Eve** (Junior Analyst) | Safe practice environment — learns incident response on synthetic scenarios before handling real ones |

### 30.6 Competitor Analysis

| Vendor | Fault Injection for Security? | Pipeline Neglect Detection? | Self-Improving from Drills? |
|--------|------------------------------|---------------------------|---------------------------|
| Snyk | No | No | No |
| Wiz | No | No | No |
| ArmorCode | No | No | No |
| Apiiro | No | No | No |
| Chaos Monkey (Netflix) | Yes, but infrastructure only | No | No |
| Gremlin | Yes, but infrastructure only | No | No |
| **ALdeci FAIL** | **Yes — security-specific** | **Yes** | **Yes — ML training loop** |

→ **Zero competitors** have LLM-driven fault injection for security operations. Chaos engineering exists for infrastructure; FAIL is chaos engineering for AppSec teams.

### 30.7 ROI Justification

**Without FAIL:** Organization discovers a real breach occurred because a critical Jira ticket sat unassigned for 97 days. Post-mortem reveals broken routing rules. Cost: $4.2M average breach cost (IBM 2024).

**With FAIL:** A FAIL drill would have caught the broken routing rule on day 1. Cost: $0 (synthetic scenario, no real exposure). Drill takes 15 minutes to configure, 48 hours to measure response.

**Quantified value:**
- Average breach cost avoided per year (assuming 1 prevented due to FAIL): $4.2M
- FAIL subscription cost: included in Professional tier ($18K/yr)
- ROI: **233:1**
- Insurance premium reduction: 10-15% for organizations with documented drill programs

### 30.8 Research Foundation

The FAIL concept builds on established chaos engineering principles (Netflix Chaos Monkey, 2011; Basiri et al., "Chaos Engineering," IEEE Software 2016) and extends them with:

1. **LLM-generated realistic scenarios** — not random failures, but plausible security events customized to the organization's actual tech stack
2. **Multi-LLM response grading** — consensus-based evaluation of team response quality, not just binary pass/fail
3. **Closed-loop ML training** — drill outcomes feed directly into ALdeci's decision models, creating a self-improving system
4. **Compliance integration** — drill reports are signed evidence bundles (RSA-SHA256, optionally ML-DSA quantum-hybrid) that serve as SOC 2 / ISO 27001 audit evidence

*Reference: Mondragon et al. 2025 — "Fault-Aware Injection for Reliability Testing of AI/ML Systems"*

---

## Part 32: Zero-Gravity Data — Cost-Effective On-Prem Storage for Self-Learning AI

> **Problem**: ALdeci's self-learning moat requires on-prem data accumulation, but customers pay for every GB  
> **Goal**: Reduce training data storage by 90%+ while preserving (or improving) model quality  
> **Priority**: Critical — directly determines whether air-gapped pricing is competitive vs cloud alternatives  
> **Unique angle**: The AI that learns should also learn what to forget

### 32.1 The Problem: Data Gravity Is Killing On-Prem Economics

ALdeci's self-learning architecture (Phase ⑩) has **5 feedback loops** that accumulate data continuously:

| Data Source | Growth Rate | Raw Size After 1 Year | Value Density |
|------------|------------|----------------------|---------------|
| API traffic records | ~5,000 req/day | ~15 GB | Very low (99% normal requests) |
| Vulnerability findings | ~200/week | ~2 GB | Medium (80% duplicates of known CVE patterns) |
| Triage decisions | ~50/week | ~100 MB | **Very high** (rare human insight — never discard) |
| MPTE pentest results | ~20/week | ~500 MB | High (expensive to generate, compact) |
| False positive feedback | ~30/week | ~50 MB | **Very high** (direct model correction signal) |
| Remediation outcomes | ~40/week | ~200 MB | High (what actually worked) |
| Compliance evidence bundles | ~10/week | ~1 GB | Medium (bulk is auto-generated boilerplate) |
| Knowledge Graph nodes/edges | Continuous | ~500 MB | High (naturally deduplicates) |
| Model checkpoints (scikit-learn) | 4 models × weekly | ~200 MB | Low after N+1 version exists |
| **Total naive storage** | | **~20 GB/year** | **But only ~3 GB has real learning value** |

**The insight**: 85% of on-prem training data is redundant, stale, or low-information. Customers are paying to store noise. The self-learning AI should learn **what data to keep and what to forget** — making the data lifecycle itself intelligent.

### 32.2 The Architecture: 4-Tier Data Gravity System

Instead of storing everything forever, ALdeci implements **data gravity tiers** where data falls through increasingly compressed states, and only the most informative data survives long-term:

```
┌─────────────────────────────────────────────────────────────┐
│                    ZERO-GRAVITY DATA ENGINE                  │
│                                                             │
│  TIER 1: HOT — Live Operational Data                        │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  SQLite WAL (uncompressed)   │  Last 7 days           │  │
│  │  ALL raw traffic, findings   │  ~500 MB per APP_ID    │  │
│  │  Full query speed            │  Retention: 7 days     │  │
│  └───────────────────────────────────────────────────────┘  │
│           │ age > 7d                                        │
│           ▼                                                 │
│  TIER 2: WARM — Deduplicated + Compressed                   │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  SQLite + ZSTD (row-level)   │  7-90 day data         │  │
│  │  Near-duplicate removal      │  ~100 MB per APP_ID    │  │
│  │  Dictionary compression      │  80% size reduction    │  │
│  └───────────────────────────────────────────────────────┘  │
│           │ age > 90d                                       │
│           ▼                                                 │
│  TIER 3: COLD — Coreset (Informative Samples Only)          │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  Pruned dataset              │  90+ day data          │  │
│  │  Only top 5-10% by info      │  ~20 MB per APP_ID     │  │
│  │  Sufficient for retraining   │  95% size reduction    │  │
│  └───────────────────────────────────────────────────────┘  │
│           │ age > 365d                                      │
│           ▼                                                 │
│  TIER 4: DISTILLED — Knowledge in Model Weights             │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  Raw data deleted            │  Year+ data            │  │
│  │  Knowledge lives in trained  │  ~5 MB (model files)   │  │
│  │  model parameters only       │  99.7% reduction       │  │
│  └───────────────────────────────────────────────────────┘  │
│                                                             │
│  EXCEPTION: Human Feedback (Tier 0 — NEVER aged out)        │
│  ┌───────────────────────────────────────────────────────┐  │
│  │  Triage decisions, FP flags, override reasons         │  │
│  │  ~150 MB/year — tiny, infinitely valuable             │  │
│  │  Always available for retraining                      │  │
│  └───────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

**Net result**: 20 GB/year → ~800 MB/year per customer (96% reduction)

### 32.3 Key Techniques: The Research Behind Each Tier

#### Tier 2 — SQLite Row-Level ZSTD Compression

**Technology**: [sqlite-zstd](https://github.com/phiresky/sqlite-zstd) (1.6K⭐, LGPL-3.0, Rust extension)

This extension provides transparent dictionary-based row-level compression for SQLite. The critical insight is that security findings and API traffic records are highly repetitive — same JSON structures, same CVE identifiers, same HTTP headers. Dictionary compression exploits this repetition aggressively.

**Benchmark from sqlite-zstd authors**: Database size reduced by **80%** while maintaining query performance (sometimes improving it, since less data to read from disk).

**ALdeci implementation**:
```python
# Enable transparent compression on high-volume tables
conn.execute("""
    SELECT zstd_enable_transparent('{
        "table": "api_traffic",
        "column": "request_body",
        "compression_level": 19,
        "dict_chooser": "''method'' || ''_'' || substr(path, 1, 20)"
    }')
""")
# Group dictionaries by (METHOD, path_prefix) — findings for /api/v1/findings
# compress 95%+ because they share the same JSON schema

# Background maintenance (non-blocking):
conn.execute("SELECT zstd_incremental_maintenance(60, 0.5)")
# Spend 60 seconds compressing, allow other queries 50% of the time
```

**Expected reduction**: 15 GB → ~3 GB for traffic/findings data (80% compression with trained dictionaries)

#### Tier 3 — Data Pruning via Coreset Selection

**Research**: Sorscher et al. 2022 — "Beyond Neural Scaling Laws: Beating Power Law Scaling via Data Pruning" (Outstanding Paper Award, NeurIPS 2022)

The paper proves that with a good data pruning metric, you can **beat power-law scaling** — meaning you can reach the same model accuracy with 10-50% of the training data. This isn't just "keeping recent data." It's keeping the **most informative** data.

**ALdeci-specific pruning metrics** (ranked by cost to compute):

| Metric | Cost | Description | Use Case |
|--------|------|-------------|----------|
| **Prediction confidence** | Free (already computed) | Keep samples where model was least confident | Anomaly detector, threat classifier |
| **Human disagreement** | Free (already stored) | Keep samples where human overrode model prediction | Triage decisions, FP flags |
| **Cluster centroids** | Low (k-means on features) | Keep 1 representative per cluster of similar findings | Vulnerability deduplication |
| **Forgetting score** | Medium (track across epochs) | Keep samples that the model "forgets" between retraining cycles | Identifies edge cases |
| **EL2N (Error L2 Norm)** | Medium | Keep samples with highest prediction error early in training | General-purpose pruning |

**Self-supervised metric from the paper**: Compute embedding distances within each class, keep samples farthest from the class centroid (the "hard" examples). This requires no labels and scales linearly.

**Expected reduction**: 3 GB warm data → ~300 MB coreset (90% pruning, <2% accuracy loss based on the paper's ImageNet results)

#### Tier 4 — Online Learning (The Model IS the Memory)

**Technology**: [River](https://riverml.xyz) (5.7K⭐, BSD-3, Python) — online/incremental machine learning

River processes one sample at a time without storing historical data. The model itself becomes the persistent memory. This is fundamentally different from scikit-learn's batch approach (which requires re-reading all training data).

**Current ALdeci approach (batch, requires stored data)**:
```python
# scikit-learn: Must store ALL data, retrain from scratch
rows = conn.execute("SELECT * FROM api_traffic LIMIT 10000").fetchall()
model = IsolationForest(n_estimators=100)
model.fit(X)  # needs all 10K rows in memory
```

**Proposed River approach (online, data can be discarded)**:
```python
# River: Process one sample at a time, model updates incrementally
from river import anomaly, compose, preprocessing

model = compose.Pipeline(
    preprocessing.StandardScaler(),
    anomaly.HalfSpaceTrees(n_trees=25, height=6, window_size=250)
)

# For each new API request:
score = model.score_one(features)  # predict
model.learn_one(features)          # update model weights
# Raw data can now be DISCARDED — knowledge is IN the model
```

**Key River features for ALdeci**:
- **Concept drift detection** (ADWIN, DDM, EDDM) — automatically detects when threat patterns change
- **No batch retraining** — model is always up-to-date, no scheduled retrain jobs
- **Fixed memory** — model size stays constant regardless of how much data flows through
- **Native anomaly detection** (HalfSpaceTrees) — direct replacement for IsolationForest
- **Classification** (Hoeffding trees, adaptive random forests) — replaces GradientBoosting for threat classification
- **Regression** (incremental linear models) — replaces response time predictor

**Migration path**: Replace scikit-learn models in `api_learning_store.py` with River equivalents. The models can still be serialized to SQLite for persistence, but training data doesn't need to survive past Tier 3.

**Expected reduction**: After Year 1, no historical training data needed → model weights only (~5 MB)

### 32.4 Smart Forgetting: The Prioritized Experience Buffer

Inspired by DeepMind's Prioritized Experience Replay (Schaul et al., ICLR 2016), ALdeci implements a **fixed-size priority buffer** for training data:

```
┌────────────────────────────────────────────────────┐
│         PRIORITIZED EXPERIENCE BUFFER              │
│         (Fixed size: 10,000 samples per model)     │
│                                                    │
│  Priority Score = w₁·surprise + w₂·human_signal    │
│                 + w₃·recency + w₄·diversity        │
│                                                    │
│  ┌──────────────────────────────────────────────┐  │
│  │ On new sample arrival:                       │  │
│  │  1. Score the new sample                     │  │
│  │  2. If score > min(buffer): evict lowest     │  │
│  │  3. Insert new sample                        │  │
│  │  4. Rebalance priority heap                  │  │
│  │                                              │  │
│  │ Surprise: |predicted - actual| (model error) │  │
│  │ Human: Was there human override? (+10x)      │  │
│  │ Recency: Exponential decay over time         │  │
│  │ Diversity: Distance from nearest neighbor    │  │
│  └──────────────────────────────────────────────┘  │
│                                                    │
│  Result: Buffer always contains the 10K most       │
│  informative samples. Size never grows.            │
│  10K × ~1KB avg = ~10 MB fixed cost.               │
└────────────────────────────────────────────────────┘
```

**Why this matters for ALdeci specifically**:
- Human feedback (triage overrides, FP flags) gets **10x priority** — it's the rarest and most valuable signal
- Failed predictions get high surprise scores — the model remembers its mistakes
- Diversity scoring prevents the buffer from filling with repetitive CVE-2024-XXXX variants
- The buffer has a **hard size cap** — storage cost is predictable and fixed

### 32.5 Near-Duplicate Detection for Findings

Security findings are massively redundant. The same Log4Shell CVE appears in 100 repositories with minor variations. Storing all 100 is waste.

**Approach**: MinHash + Locality-Sensitive Hashing (LSH) for near-duplicate detection

```python
# Before storing a new finding:
# 1. Compute MinHash signature (~128 bytes) from finding text
# 2. Query LSH index: "Have I seen something 90%+ similar?"
# 3. If yes: increment count on existing finding, discard duplicate
# 4. If no: store new finding, add to LSH index

# Storage cost of the LSH index: ~50 bytes per unique finding
# vs storing full finding JSON: ~2-5 KB each
# 100 similar findings: 5,000 bytes (all stored) vs 178 bytes (1 stored + count)
# Dedup ratio for typical enterprise: 70-85%
```

**Libraries**: `datasketch` (Python, MIT, lightweight) — MinHash with LSH already implemented.

### 32.6 Complete Storage Budget: Before vs After

**Per-customer, per-year storage on-prem:**

| Component | Before (Naive) | After (Zero-Gravity) | Reduction |
|-----------|---------------|---------------------|-----------|
| API traffic | 15 GB | 150 MB (compress + prune + online learning) | 99% |
| Vulnerability findings | 2 GB | 60 MB (dedup + compress) | 97% |
| Human feedback | 150 MB | 150 MB (**never reduced**) | 0% |
| MPTE results | 500 MB | 100 MB (compress) | 80% |
| Remediation outcomes | 200 MB | 50 MB (compress + prune) | 75% |
| Evidence bundles | 1 GB | 200 MB (compress, age templates) | 80% |
| Knowledge Graph | 500 MB | 300 MB (naturally deduplicates) | 40% |
| Model checkpoints | 200 MB | 20 MB (keep latest + 1 rollback) | 90% |
| Experience buffer | 0 | 50 MB (new — fixed size) | N/A |
| **Total** | **~20 GB** | **~1.08 GB** | **94.6%** |

**At scale (100 enterprise customers)**: 2 TB → 108 GB. That's the difference between a $200/mo NAS and a $50/mo SSD.

### 32.7 The Self-Improving Data Lifecycle

The truly unique part: ALdeci's data lifecycle IS a learning system. The pruning metrics, dedup thresholds, and compression dictionaries all improve over time:

```
                    ┌──────────────┐
                    │ New Data In  │
                    └──────┬───────┘
                           │
                    ┌──────▼───────┐
                    │ Score Data   │◄─── Priority model
                    │ (informative │     (learns what's valuable)
                    │  or noise?)  │
                    └──────┬───────┘
                           │
              ┌────────────┼────────────┐
              │ High Score │            │ Low Score
              ▼            │            ▼
      ┌───────────┐        │    ┌───────────────┐
      │ Keep in   │        │    │ Compress &    │
      │ Priority  │        │    │ Age Out       │
      │ Buffer    │        │    │ (Tier 2→3→4)  │
      └─────┬─────┘        │    └───────────────┘
            │              │
            ▼              │
      ┌───────────┐        │
      │ Train     │        │
      │ Models    │────────┘
      │ (River)   │     ← Models get better at scoring
      └───────────┘       which data to keep next time
```

**The feedback loop**: As models improve, they get better at identifying which new data would actually improve them further — and which data is noise. The pruning becomes more aggressive over time, **without losing accuracy**, because the model is selecting its own curriculum.

This is related to **curriculum learning** (Bengio et al. 2009) and **self-paced learning** (Kumar et al. 2010) — the model decides what to learn from and when.

### 32.8 Implementation Plan

| Phase | Work | Days |
|-------|------|------|
| 1 | Integrate `sqlite-zstd` for transparent row-level compression on `api_traffic` and `findings` tables | 2 |
| 2 | Build priority scoring function for experience buffer (surprise + human_signal + recency + diversity) | 1.5 |
| 3 | Implement fixed-size priority buffer with min-heap eviction | 1 |
| 4 | Add MinHash/LSH near-duplicate detection for findings (`datasketch`) | 1 |
| 5 | Tier aging cron job: HOT→WARM→COLD→DISTILLED based on `created_at` | 1 |
| 6 | Migrate `anomaly_detector` to River `HalfSpaceTrees` (online learning, no batch data needed) | 1.5 |
| 7 | Migrate `threat_classifier` to River `AdaptiveRandomForestClassifier` | 1.5 |
| 8 | Coreset selection for Tier 3: implement confidence-based + centroid-based pruning | 2 |
| 9 | Data lifecycle dashboard (UI): show per-tier sizes, compression ratios, pruning stats | 2 |
| 10 | Integration tests: verify model accuracy is maintained after pruning + aging cycle | 1.5 |
| **Total** | | **15 days** |

### 32.9 New Dependencies

| Package | Size | License | Purpose |
|---------|------|---------|---------|
| `river` | ~15 MB | BSD-3 | Online/incremental ML (replaces batch scikit-learn for streaming models) |
| `datasketch` | ~200 KB | MIT | MinHash + LSH for near-duplicate detection |
| `sqlite-zstd` | ~2 MB (Rust binary) | LGPL-3.0 | Transparent row-level compression for SQLite |

Total added dependency footprint: ~17 MB. All have permissive or compatible licenses (LGPL-3.0 for sqlite-zstd is fine since it's loaded as an extension, not linked).

### 32.10 Competitive Advantage

| Capability | ALdeci | Snyk | Wiz | ArmorCode |
|-----------|--------|------|-----|-----------|
| Self-learning AI | ✅ 5 feedback loops | ❌ Cloud-only AI | ❌ No on-prem | ❌ No ML |
| On-prem deployment | ✅ Air-gapped | ❌ | ❌ | ❌ |
| Intelligent data lifecycle | ✅ 4-tier auto-aging | N/A | N/A | N/A |
| Online learning (no batch retrain) | ✅ River | ❌ | ❌ | ❌ |
| Prioritized experience buffer | ✅ Smart forgetting | ❌ | ❌ | ❌ |
| Data pruning (coreset) | ✅ NeurIPS 2022 | ❌ | ❌ | ❌ |
| **On-prem storage cost** | **~1 GB/yr** | **N/A (cloud)** | **N/A** | **N/A** |

**No competitor even needs to solve this problem** — they're all cloud-hosted. ALdeci's air-gapped deployment is what makes this research unique and defensible. The phrase for investors: *"Our AI learns on-prem with less than 1 GB per year of data. That's not a technical limitation — it's a feature. The model keeps what matters and forgets what doesn't."*

### 32.11 Impact on Pricing & Customer TCO

**Before Zero-Gravity Data:**
- Year 1: 20 GB → customer buys 50 GB allocation ($15/mo)
- Year 3: 60 GB → customer needs storage upgrade ($45/mo)
- Year 5: 100 GB → customer starts asking about data retention policies ($75/mo)

**After Zero-Gravity Data:**
- Year 1: 1.08 GB → fits on any existing server
- Year 3: 1.5 GB → negligible growth (coreset doesn't grow linearly)
- Year 5: 1.8 GB → still fits on a $5/mo SSD

**Customer conversation changes from**: "How much disk do I need for ALdeci?" → "Wait, it really only uses 1 GB?"

**Pricing enabler**: This makes the Starter tier ($8K/yr) viable on commodity hardware. Without Zero-Gravity, self-hosted Starter customers need $200+/year just for storage — 2.5% of their subscription going to data they'll never look at.

### 32.12 Research Foundation

| Paper / Tool | Year | Contribution to ALdeci |
|-------------|------|----------------------|
| Sorscher et al. "Beyond Neural Scaling Laws" | NeurIPS 2022 (Outstanding Paper) | Data pruning theory — keep 5-10% of data, match full accuracy |
| Schaul et al. "Prioritized Experience Replay" | ICLR 2016 | Priority buffer architecture — keep most "surprising" samples |
| River ML | 2023 (v0.23) | Online learning library — models update per-sample, no batch storage needed |
| sqlite-zstd (phiresky) | 2022-2025 | Row-level dictionary compression — 80% size reduction on structured data |
| Bengio et al. "Curriculum Learning" | ICML 2009 | Self-paced learning theory — model decides its own training order |
| datasketch (ekzhu) | 2015-2025 | MinHash + LSH for near-duplicate detection — O(1) similarity queries |
| Kumar et al. "Self-Paced Learning" | NeurIPS 2010 | Models improve their own data selection over time |

### 32.13 Naming & Messaging

**Internal codename**: Zero-Gravity Data (ZGD)

**Customer-facing message**: *"ALdeci's self-learning AI runs on-prem with intelligent data lifecycle management. Your security intelligence gets smarter over time while using less than 1 GB of storage per year — because our AI knows what to remember and what to forget."*

**Investor pitch**: *"Our competitors need your data in their cloud to train their models. ALdeci trains on-prem, keeps only the most informative 5% of data, and achieves equal or better accuracy. The storage cost is rounding error. This makes our air-gapped tier viable on hardware that costs $5/month."*

**Technical moat**: The combination of online learning (River) + prioritized experience buffering + NeurIPS-grade data pruning + SQLite ZSTD compression creates a self-improving data engine that no competitor needs to build (they're all cloud). If they ever go on-prem, they're 2+ years behind.

---

## Part 33: Master Priority & Vision Alignment Review

> **Purpose**: Evaluate every part in this document against ALdeci's Unified Vision (10-Phase Lifecycle, APP_ID-centric, Decision Intelligence, "Not a Scanner — a Security Brain") and establish the definitive implementation priority order.
> **Date**: 2026-02-26

### 33.1 Vision Pillars (from ALDECI_UNIFIED_VISION.md)

For reference, these are the 10 non-negotiable pillars that every feature must serve:

| # | Vision Pillar | Phase | Core Promise |
|---|--------------|-------|-------------|
| V1 | APP_ID-Centric Architecture | ① | Every finding, decision, evidence traces to App → Component → Feature |
| V2 | 10-Phase Security Lifecycle | ①-⑩ | Design → IDE → ALM → Pre-merge → Build → IaC → KG → AI → Remediation → Self-Learning |
| V3 | Decision Intelligence (not scanning) | ⑧ | "What to DO about a risk, not just what the risk IS" |
| V4 | Multi-LLM Consensus / Self-Hosted AI | ⑧ | 3+ LLMs with 85% threshold OR zero-token self-hosted model |
| V5 | MPTE (Micro-Pentest Verification) | ⑧ | Prove exploitability, not just detect vulnerability |
| V6 | Quantum-Secure Evidence | ⑨ | FIPS 204 ML-DSA + RSA hybrid, 7-year WORM retention |
| V7 | MCP-Native AI Platform | ②⑧ | First AppSec platform AI agents can programmatically use |
| V8 | Self-Learning (5 Feedback Loops) | ⑩ | Decision outcomes, MPTE results, FP rates, remediation success, policy violations |
| V9 | Air-Gapped / On-Prem Deployment | All | Full offline capability on commodity hardware |
| V10 | CTEM Full Loop with Cryptographic Proof | All | Discover → Prioritize → Validate → Remediate → Measure (with signed evidence) |

### 33.2 Full Alignment Audit — Remaining Parts (Post-Cleanup)

#### Tier A: Directly Powers Vision (Build These)

| Part | Title | Vision Pillars Served | Alignment | Priority |
|------|-------|----------------------|-----------|----------|
| **30** | **FAIL Engine** | V3 V5 V8 V10 | **PERFECT** — chaos engineering for AppSec fills the "Validate" phase gap, generates ML training data (V8), proves organizational readiness (V10), unique differentiator (V3) | **P0 — BUILD FIRST** |
| **25** | MCP Architecture Expansion | V7 V2 | **PERFECT** — auto-discovers 650 tools, SSE/WebSocket transports, makes ALdeci the security oracle for all AI agents | P0 |
| **26** | Single AI Agent (Zero Token) | V4 V9 | **PERFECT** — eliminates API costs, enables air-gapped AI decisions, 4 expert roles + moderator on self-hosted model | P0 |
| **27** | Quantum-Secure Cryptography | V6 V10 | **PERFECT** — hybrid RSA + ML-DSA signing, backward-compatible, enables "evidence valid for 30+ years" claim | P0 |
| **2** | Critical Gaps (DX, AutoFix, Attack Path, Compliance, Copilot) | V2 V3 V10 | **PERFECT** — the 5 gaps map directly to the 10-phase lifecycle holes | P0 |
| **10** | CTEM Loop Implementation | V10 | **PERFECT** — the pitch deck's central demo, 5-phase with signed proof | P0 |
| **11** | Compliance Automation Mapping | V6 V10 | **PERFECT** — SOC2/PCI/ISO/NIST auto-evidence generation is Phase ⑨ | P0 |
| **12** | 10 Key Differentiators — Status | V1-V10 | **PERFECT** — audit of what's built vs claimed, keeps us honest | P0 |

#### Tier B: Enables Vision at Scale (Build After Tier A)

| Part | Title | Vision Pillars Served | Alignment | Priority |
|------|-------|----------------------|-----------|----------|
| **32** | Zero-Gravity Data | V8 V9 | **STRONG** — makes self-learning viable on-prem, 94.6% storage reduction, but infrastructure-only (not customer-facing) | **P1 — BUILD SECOND** |
| **28** | Combined Timeline (25+26+27) | V4 V6 V7 | **STRONG** — execution plan for Tier A items 25-27, 8-week sprint | P1 |
| **6** | Recommended Focus (Attack Path + Fix) | V3 V5 V10 | **STRONG** — the demo that closes deals | P1 |
| **7** | Technical Implementation Plan | V2 V3 | **STRONG** — phases 1-3 for gaps 1-3 | P1 |
| **9** | Pitch Deck Stage & Screen Mapping | V10 | **STRONG** — maps 7 core capabilities to screens | P1 |
| **15-24** | UI/UX Deep Audit & Sprint Plans | V2 V10 | **STRONG** — 49% stub pages is the biggest barrier to demos and deals | P1 |

> **Archived to `WIP_TO_VALIDATE.md`**: Parts 1, 3, 4, 5, 8, 13, 14, 29, 31, and the original Conclusion block. These were outdated, non-actionable, or tangential to the core 10 Vision Pillars.

### 33.3 Implementation Priority Ranking: Parts 30 vs 32

Based on the alignment audit, the definitive priority order:

| Rank | Part | Build When | Days | Rationale |
|------|------|-----------|------|-----------|
| **1st** | **Part 30 — FAIL Engine** | **NOW** | 10 | Customer-visible feature. Demo-able in 5 min. Zero competitors have it. Generates ML training data for self-learning (V8). Proves organizational readiness (V10). Fills "Validate" phase gap. 233:1 ROI story for investors. Only requires existing LLM + Event Bus. |
| **2nd** | **Part 32 — Zero-Gravity Data** | After FAIL ships | 15 | Makes on-prem self-learning viable long-term (V9). 94.6% storage reduction. Enables $8K Starter tier on commodity hardware. But invisible infrastructure — no customer will see it or demo it. Three new dependencies (River, datasketch, sqlite-zstd). |

> **Part 31 (ZipLLM)** archived to `WIP_TO_VALIDATE.md` — premature until air-gapped customers exist.

**Why FAIL wins**: It serves 4 vision pillars (V3, V5, V8, V10) while ZGD serves 2 (V8, V9). FAIL is the only one that generates revenue justification, is demo-able, and feeds the self-learning loop with labeled training data.

### 33.4 Consolidated Master Build Order

Combining ALL parts into a single prioritized execution plan, aligned against the vision:

#### Sprint 1 — Demo-Ready Foundation (Weeks 1-4)

| Order | Part(s) | Work | Days | Vision Pillars |
|-------|---------|------|------|---------------|
| 1 | **30** | FAIL Engine — fault injection, response grading, neglect zones | 10 | V3 V5 V8 V10 |
| 2 | **2 (Gap 3)** | Attack Path Visualization (Wiz Killer) | 10 | V3 V5 V10 |
| | | **Sprint 1 Total** | **20 days** | |

*After Sprint 1*: Demo flow = "Inject synthetic CVE → watch team response → grade MTTR → show attack path → one-click fix." This closes enterprise deals.

#### Sprint 2 — AI Moats (Weeks 5-8)

| Order | Part(s) | Work | Days | Vision Pillars |
|-------|---------|------|------|---------------|
| 3 | **25** | MCP full protocol gateway (auto-discover 650 tools, SSE transport) | 15 | V7 V2 |
| 4 | **26** | Single Agent engine (4 roles + moderator, vLLM) | 15 | V4 V9 |
| | | **Sprint 2 Total** | **30 days** | |

*After Sprint 2*: Any AI agent (Copilot, Cursor, Claude) can use ALdeci as its security oracle. Self-hosted decisions cost $0 in API tokens.

#### Sprint 3 — Compliance & Crypto (Weeks 9-12)

| Order | Part(s) | Work | Days | Vision Pillars |
|-------|---------|------|------|---------------|
| 5 | **27** | Quantum-secure hybrid signing (RSA + ML-DSA) | 14 | V6 V10 |
| 6 | **11** | Compliance auto-mapping (SOC2/PCI/ISO/NIST) | 10 | V6 V10 |
| | | **Sprint 3 Total** | **24 days** | |

*After Sprint 3*: "First AppSec platform with quantum-secure evidence signing" — patent-worthy, zero competitors, 30-year evidence validity.

#### Sprint 4 — UI Polish (Weeks 13-16)

| Order | Part(s) | Work | Days | Vision Pillars |
|-------|---------|------|------|---------------|
| 7 | **15-24** | UI stub replacement sprint — Executive Dashboard, SLA, Evidence Export, Onboarding Wizard, 12 persona screens | 20 | V2 V10 |
| | | **Sprint 4 Total** | **20 days** | |

*After Sprint 4*: 0 stub pages under 200 LOC. All 12 personas served. Every pitch deck promise has matching UI.

#### Sprint 5 — Infrastructure Optimization (Weeks 17-20)

| Order | Part(s) | Work | Days | Vision Pillars |
|-------|---------|------|------|---------------|
| 8 | **32** | Zero-Gravity Data — sqlite-zstd, River ML migration, priority buffer, MinHash dedup | 15 | V8 V9 |
| 9 | **2 (Gap 1)** | Developer Experience — VS Code Extension, GitHub App, CLI polish | 10 | V2 V7 |
| | | **Sprint 5 Total** | **25 days** | |

*After Sprint 5*: On-prem costs cut by 94.6% for training data. Developer adoption pathway built.

### 33.5 Archived Sections (moved to `WIP_TO_VALIDATE.md`)

| Part | Reason Archived |
|------|----------------|
| Part 1 (Competitive Advantages) | Outdated stats (184K LOC → 790K+), superseded by Vision doc |
| Part 3 (Acquisition Multipliers) | Generic VC formula, not actionable |
| Part 4 (Quick Wins 30 Days) | Stale, written months ago, superseded by Sprint 1-5 plan |
| Part 5 ($100M+ Play) | High-level thesis, not a buildable feature |
| Part 8 (Success Metrics) | All current values "?", needs real data |
| Part 13 (Metrics vs Claims) | Factually outdated (650 endpoints → 616, ~40 CLI → 114) |
| Part 14 (AI Data Quality) | Separate product idea, not core ALdeci MVP |
| Conclusion (original) | Referenced outdated gaps, superseded by this Part 33 |
| Part 29 (AppSec Obsolescence) | 362-line manifesto — strategic narrative, not a feature |
| Part 31 (ZipLLM) | Premature — only relevant when customers self-host fine-tuned LLMs |

### 33.6 Vision Alignment Score

| Vision Pillar | Parts That Serve It | Coverage |
|--------------|--------------------|----|
| V1 — APP_ID-Centric | Parts 9, 10 | Good (architecture exists, needs UI) |
| V2 — 10-Phase Lifecycle | Parts 2, 7, 9, 10, 15-24, 25 | Good (gaps identified, sprints planned) |
| V3 — Decision Intelligence | Parts 2, 6, **30** | **Strong** (FAIL Engine is the core differentiator) |
| V4 — Multi-LLM / Self-Hosted | **Part 26** | Strong (Single Agent engine) |
| V5 — MPTE Verification | Parts 2, 6, **30** | Strong (FAIL + Attack Path) |
| V6 — Quantum-Secure Evidence | **Part 27**, 11 | Strong (hybrid signing + compliance) |
| V7 — MCP-Native | **Part 25** | Strong (full protocol gateway) |
| V8 — Self-Learning | **Parts 30, 32** | **Strong** (FAIL generates training data, ZGD optimizes storage) |
| V9 — Air-Gapped / On-Prem | Parts 26, **32** | Strong (ZGD + self-hosted AI) |
| V10 — CTEM Full Loop | Parts 10, 11, 12, **27, 30** | Strong (FAIL validates, quantum signs, compliance maps) |

**Overall**: All 10 vision pillars have at least 2 parts serving them. No orphan pillars. Document cleaned to 16 actionable parts.

### 33.7 The One-Slide Summary

```
┌─────────────────────────────────────────────────────────────┐
│         ALdeci Implementation Priority — 5 Sprints          │
│                                                             │
│  Sprint 1 (NOW):  FAIL Engine + Attack Path                │
│                   → "Demo that closes deals"                │
│                                                             │
│  Sprint 2:        MCP Gateway + Single AI Agent            │
│                   → "AI agents use ALdeci as security brain"│
│                                                             │
│  Sprint 3:        Quantum Crypto + Compliance Auto          │
│                   → "Evidence valid for 30+ years"          │
│                                                             │
│  Sprint 4:        UI Polish (12 persona screens)            │
│                   → "Every pitch deck promise has UI"       │
│                                                             │
│  Sprint 5:        Zero-Gravity + DX                        │
│                   → "On-prem costs cut 94%, dev adoption"   │
│                                                             │
│  Total: 20 weeks │ Features: customer-facing first,         │
│                  │ infrastructure last                      │
└─────────────────────────────────────────────────────────────┘
```

---

*Document updated: 2026-02-26 (post-cleanup)*  
*Remaining: 16 actionable parts | Archived: 10 sections to `WIP_TO_VALIDATE.md`*  
*Sources: aldeci_story_pitch_10_20251225122748.pdf, aldeci_story_pitch_10_20260103134309.pdf, GitHub Developer Survey 2024, McKinsey Superagency Report Jan 2025, NIST PQC Standards Aug 2024, OWASP Top 10 for LLM Applications 2025, Mondragon et al. 2025 (FAIL), Sorscher et al. NeurIPS 2022 (Data Pruning), Schaul et al. ICLR 2016 (Prioritized Experience Replay), River ML, sqlite-zstd*  
*Active sections: Parts 2, 6, 7, 9, 10, 11, 12, 15-24, 25, 26, 27, 28, 30, 32, 33*  
*Next review: 2026-03-20*
