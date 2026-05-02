# ALdeci CTEM+ Platform — Technical Capabilities

> **Classification**: Company Confidential — Customer-Ready
> **Version**: 3.0 | **Effective**: Q1 2026
> **Audience**: CISOs, Security Architects, Enterprise Evaluation Teams, Auditors

---

## Platform Overview

ALdeci is a **Continuous Threat Exposure Management Plus (CTEM+)** platform that delivers the complete security lifecycle: Discover → Prioritize → Validate → Remediate → Comply — with cryptographic proof at every step.

ALdeci operates in **dual mode**:

- **Orchestration Mode (Switzerland Positioning)**: Ingests, normalizes, and correlates findings from the customer's existing security tools — Snyk, Semgrep, Checkmarx, Wiz, Trivy, and 200+ others. Day-one value. No rip-and-replace.
- **Native Mode (Air-Gap Capable)**: Eight built-in security engines provide complete vulnerability coverage when external tools are unavailable, restricted, or not yet deployed.

Both modes feed into the same 12-step Brain Pipeline, producing consistent, auditable, and prioritized security outcomes.

---

## Native Security Engines

ALdeci ships with eight purpose-built scanning engines. Every engine operates with **zero external dependencies** — designed for classified environments, air-gapped networks, and on-premises deployments.

| # | Engine | Capabilities | Languages / Targets |
|---|--------|-------------|---------------------|
| 1 | **Static Application Security Testing (SAST)** | 110+ vulnerability rules, taint analysis, OWASP Top 10 full coverage, CWE mapping, confidence scoring | Python, JavaScript, TypeScript, Java, Go, Ruby, PHP, C# |
| 2 | **Dynamic Application Security Testing (DAST)** | HTTP/S traffic analysis, XSS/SQLi/SSRF detection, authenticated scanning, crawl-and-fuzz | Any web application |
| 3 | **Secrets Detection** | 200+ credential patterns, entropy analysis, git history scanning, cloud credential detection (AWS, GCP, Azure) | All file types, git repositories |
| 4 | **Container Security** | Dockerfile analysis, image layer scanning, CVE matching, privilege escalation detection, CIS benchmark validation | Docker, OCI, Kubernetes manifests |
| 5 | **CSPM / Infrastructure-as-Code** | Terraform, CloudFormation, Kubernetes YAML, CIS benchmarks, misconfiguration detection, drift analysis | AWS, Azure, GCP, Kubernetes |
| 6 | **API Fuzzer** | Endpoint discovery, parameter mutation, authentication bypass testing, rate limit validation | REST, GraphQL |
| 7 | **Malware Detection** | Content analysis, signature matching, heuristic detection, supply chain artifact verification | Binary, source, package |
| 8 | **LLM Security Monitor** | Prompt injection detection, jailbreak prevention, PII leakage detection, output guardrails | Any LLM-powered application |

### Air-Gap Guarantee

When deployed in air-gapped or classified environments:

| Scenario | ALdeci Native Engine |
|----------|---------------------|
| No Snyk or Semgrep available | SAST engine provides static analysis with 110+ rules across 8 languages |
| No ZAP or Burp available | DAST engine performs dynamic testing with crawl-and-fuzz capability |
| No TruffleHog or GitLeaks available | Secrets engine detects 200+ credential patterns with entropy analysis |
| No Trivy or Aqua available | Container engine scans Dockerfiles, image layers, and Kubernetes manifests |
| No Prisma Cloud or Checkov available | CSPM/IaC engine validates Terraform, CloudFormation, and Kubernetes configurations |
| No commercial API testing tool | API Fuzzer tests endpoints for injection, auth bypass, and parameter manipulation |
| No malware scanner available | Malware engine performs signature and heuristic analysis on artifacts |
| No LLM guardrail solution | LLM Monitor detects prompt injection and PII leakage in AI-powered applications |

**Result**: Complete CTEM coverage regardless of tool availability.

---

## AI-Powered AutoFix Engine

ALdeci generates precise, context-aware remediation for every verified finding — not generic suggestions, but deployable code patches with confidence scoring.

### Fix Types

| Fix Type | Description | Confidence Gating |
|----------|-------------|-------------------|
| **Code Patch** | Source-level vulnerability fix with unified diff | HIGH → auto-apply; MEDIUM → PR for review |
| **Dependency Update** | Version upgrade for vulnerable packages with compatibility check | HIGH → auto-apply |
| **Configuration Hardening** | Security configuration correction (TLS, headers, CORS, CSP) | HIGH → auto-apply |
| **Infrastructure-as-Code Fix** | Terraform/CloudFormation/K8s remediation | MEDIUM → PR for review |
| **Secret Rotation** | Credential rotation with vault integration | IMMEDIATE → auto-execute |
| **Permission Fix** | Least-privilege correction for IAM/RBAC | MEDIUM → PR for review |
| **Input Validation** | Sanitization and validation injection | MEDIUM → PR for review |
| **Output Encoding** | XSS prevention encoding fix | HIGH → auto-apply |
| **WAF Rule** | Targeted WAF rule generation for finding | LOW → human review required |
| **Container Fix** | Dockerfile and image hardening | MEDIUM → PR for review |

### Confidence Thresholds

| Level | Confidence | Action |
|-------|-----------|--------|
| **HIGH** | >85% | Auto-apply, create PR, notify owner, log evidence |
| **MEDIUM** | 60–85% | Create PR for human review, assign to responsible developer |
| **LOW** | <60% | Generate suggestion only, human decision required |

### AutoFix Context Enrichment

Every fix is generated with context that no competitor provides:

- **FAIL score** with FACT/ASSESS/IMPACT/LIKELIHOOD breakdown
- **EPSS exploitation probability** from FIRST.org
- **CISA KEV status** (Known Exploited Vulnerabilities)
- **Reachability analysis** from the knowledge graph
- **Blast radius estimation** (asset count, user impact)
- **Attack path context** from graph traversal
- **Multi-LLM consensus validation** of fix correctness

---

## 12-Step Brain Pipeline

Every finding — whether from native engines or external tool integrations — flows through a deterministic, auditable, 12-step pipeline:

| Step | Name | Function | Enterprise Value |
|------|------|----------|-----------------|
| 1 | **Connect** | Ingest from external scanners or native engines | Universal tool support (200+ integrations) |
| 2 | **Normalize** | Convert to ALdeci Universal Finding Format (UFF) | Single data model regardless of source |
| 3 | **Resolve Identity** | Map to Application → Component → Feature | Ownership-based routing and accountability |
| 4 | **Deduplicate** | Cross-scanner deduplication | Eliminate redundant findings from overlapping tools |
| 5 | **Build Graph** | Construct knowledge graph of relationships | Blast radius, attack paths, dependency chains |
| 6 | **Enrich** | NVD, CISA KEV, EPSS, threat intelligence feeds | Real-world exploitability and threat context |
| 7 | **Score Risk** | Multi-factor scoring (CVSS + EPSS + business context + reachability) | Prioritization that reflects actual risk, not raw severity |
| 8 | **Apply Policy** | Evaluate against organizational security policies | Automated policy enforcement with exception handling |
| 9 | **AI Consensus** | Multi-LLM deliberation (3+ models, 85% agreement threshold) | Decisions backed by consensus, not single-model bias |
| 10 | **Verify Exploitability** | MPTE 19-phase exploit verification | Proof-based exploitability, eliminates theoretical findings |
| 11 | **Remediate** | AutoFix generation with confidence gating | Automated remediation with human-in-the-loop safeguards |
| 12 | **Generate Evidence** | Cryptographically signed compliance evidence | Audit-ready, quantum-resistant, WORM-retained |

**Pipeline Output**: For every finding that enters the pipeline, the organization receives: a risk-scored, exploitability-verified, ownership-assigned, remediation-ready case with signed compliance evidence. Every step is logged, auditable, and reproducible.

---

## Micro-Pentest Engine (MPTE)

MPTE is a 19-phase deterministic exploit verification engine that proves whether a vulnerability is actually exploitable — continuously, not annually.

### 19-Phase Verification Lifecycle

| Phase Group | Phases | Description |
|-------------|--------|-------------|
| **Reconnaissance** | 1 | Target reconnaissance and fingerprinting |
| **Enumeration** | 2 | Port, service, and technology enumeration |
| **Identification** | 3–5 | Vulnerability identification, classification, and correlation |
| **Exploitation Preparation** | 6–8 | Exploit selection, customization, and safety validation |
| **Controlled Exploitation** | 9–12 | Bounded exploitation with safety controls and rollback capability |
| **Evidence Collection** | 13–15 | Post-exploitation evidence capture with chain-of-custody |
| **Lateral Assessment** | 16–17 | Lateral movement potential assessment |
| **Cleanup** | 18 | Full restoration and cleanup verification |
| **Reporting** | 19 | Evidence-grade report generation with compliance mapping |

### Operational Characteristics

| Attribute | Value |
|-----------|-------|
| **Frequency** | Continuous (365x/year vs. 1x annual manual pentest) |
| **Safety** | Bounded execution with automatic rollback on anomaly |
| **Cost** | Included in platform — no per-engagement pricing |
| **Compliance** | Evidence meets SOC 2, PCI-DSS 11.3, and NIST SP 800-115 requirements |
| **Air-gapped** | Fully operational without external connectivity |

---

## FAIL Engine (Fault & Attack Injection Layer)

Chaos engineering applied to application security. Inject realistic faults, measure organizational response, and generate labeled training data for continuous improvement.

| Capability | Description |
|-----------|-------------|
| **Fault Injection** | Simulate scanner failures, network partitions, delayed responses |
| **Attack Simulation** | Inject synthetic attack patterns to test detection and triage |
| **Response Grading** | Score organizational response time, accuracy, and escalation quality |
| **Training Data Generation** | Automatically produce labeled datasets for ML model improvement |
| **Regression Detection** | Identify degradation in detection, triage, or remediation processes |

No competitor in the ASPM, SAST, or CTEM market offers an equivalent capability.

---

## Multi-LLM Consensus Decision Engine

ALdeci uses multiple large language models to make security decisions — never relying on a single model's judgment:

| Attribute | Specification |
|-----------|---------------|
| **Model Count** | 3+ configurable (default: GPT-4, Claude, Gemini) |
| **Agreement Threshold** | 85% — below threshold triggers human escalation |
| **Self-Hosted Option** | vLLM-served model on customer infrastructure — zero data egress, zero per-token cost |
| **Decision Audit** | Full vote record: model, confidence score, reasoning, timestamp |
| **Prompt Hardening** | Injection protection, output validation, context-window management |

### Self-Hosted AI Economics

| Deployment | Monthly AI Cost | Data Residency |
|------------|----------------|----------------|
| Cloud LLM APIs | ~$6,000/month | Data leaves infrastructure |
| ALdeci Self-Hosted | $0/month (customer GPU) | Data never leaves premises |

---

## Quantum-Secure Evidence & Compliance

### Cryptographic Architecture

| Component | Algorithm | Standard |
|-----------|-----------|----------|
| **Current Signing** | RSA-SHA256 (2048-bit minimum) | FIPS 186-5 |
| **Post-Quantum Signing** | Algorithm-agile hybrid envelope (RSA-PSS shipping; ML-DSA / Dilithium activatable via `FIXOPS_PQ_BACKEND=dilithium-py`) | FIPS 204-ready |
| **Evidence Integrity** | SHA-256 hash chains | NIST SP 800-185 |
| **Retention** | Write-Once-Read-Many (WORM) | Configurable: 3, 5, 7, or 10 years |

### Compliance Framework Coverage

| Framework | Controls Mapped | Automated Evidence | Status |
|-----------|----------------|--------------------|--------|
| **SOC 2 Type II** | 22 controls | 19 automated | GA |
| **PCI-DSS 4.0** | 22 controls | 20 automated | GA |
| **NIST 800-53 Rev 5** | 30 controls | 29 automated | GA |
| **ISO 27001:2022** | 21 controls | 16 automated | GA |
| **FedRAMP Moderate** | Full mapping | In progress | Roadmap |
| **CMMC Level 2** | Full mapping | In progress | Roadmap |
| **HIPAA Security Rule** | Full mapping | In progress | Roadmap |
| **DISA STIG** | Full mapping | In progress | Roadmap |

### Evidence Bundle Contents

Every evidence bundle is a self-contained, cryptographically signed artifact containing:

1. Finding record (source, severity, enrichment, timestamps)
2. Pipeline decision trail (all 12 steps with inputs and outputs)
3. AI consensus vote record (each model's vote, confidence, reasoning)
4. Exploitability verification result (MPTE output if executed)
5. Remediation action record (AutoFix applied, PR link, verification result)
6. Policy evaluation result (policies matched, exceptions granted)
7. Cryptographic signature (hybrid envelope: RSA-PSS shipping; ML-DSA side activatable per SCIF/IL5 contract — see `docs/quantum_crypto_retire_decision_2026-05-03.md`)
8. Timestamp with trusted time source

---

## Integration Ecosystem

### Inbound (Tool Ingestion)

ALdeci normalizes findings from 200+ security tools:

| Category | Supported Tools |
|----------|----------------|
| **SAST** | Snyk Code, Semgrep, Checkmarx, SonarQube, CodeQL, Fortify, Veracode, Coverity |
| **SCA/OSS** | Snyk Open Source, Dependabot, Trivy, Grype, FOSSA, WhiteSource, Black Duck |
| **DAST** | OWASP ZAP, Burp Suite, Rapid7 InsightAppSec, Qualys WAS, HCL AppScan |
| **Container** | Trivy, Snyk Container, Prisma Cloud, Aqua, Sysdig Secure, Anchore |
| **CSPM/IaC** | Wiz, Prisma Cloud, Checkov, tfsec, KICS, Bridgecrew, CloudSploit |
| **Secrets** | GitLeaks, TruffleHog, detect-secrets, AWS Secrets Manager |
| **CNAPP** | Wiz, Orca, Lacework, AWS Security Hub, Azure Defender, CrowdStrike Falcon |

### Outbound (Workflow Integration)

| Category | Supported Targets |
|----------|-------------------|
| **Ticketing** | Jira, ServiceNow, Azure DevOps Boards |
| **Communication** | Slack, Microsoft Teams, PagerDuty |
| **Source Control** | GitHub (PR generation), GitLab (MR generation), Azure DevOps, Bitbucket |
| **CI/CD** | Jenkins, GitHub Actions, GitLab CI, Azure Pipelines, CircleCI |
| **SIEM/SOAR** | Splunk, Sentinel, Sumo Logic, Elastic (via webhook/syslog) |

### Data Formats

| Format | Support | Direction |
|--------|---------|-----------|
| SARIF | Import + Export | Bidirectional |
| CycloneDX 1.5 | Generate + Import | Bidirectional |
| SPDX 2.3 | Generate + Import | Bidirectional |
| VEX | Generate | Export |
| CSAF | Generate | Export |
| OSCAL | Planned | Export |

---

## AI-Native Platform (MCP Gateway)

ALdeci is the first application security platform built for AI agent consumption:

| Attribute | Specification |
|-----------|---------------|
| **Protocol** | Model Context Protocol (MCP) — JSON-RPC 2.0 |
| **Tools Available** | 650+ auto-discovered from platform API surface |
| **Transports** | stdio, Server-Sent Events (SSE), WebSocket |
| **Compatible Agents** | GitHub Copilot, Cursor, Claude Code, LangChain, AutoGPT, custom agents |
| **Authentication** | API key or JWT — identical to human API access |
| **Discovery** | Auto-registration of all platform endpoints as MCP tools |

Enterprise AI teams can programmatically discover, scan, triage, fix, and generate compliance evidence through the same MCP interface.

---

## Deployment Specifications

### Supported Deployment Models

| Model | Infrastructure | AI Inference | Data Residency | External Connectivity |
|-------|---------------|--------------|----------------|----------------------|
| **SaaS Multi-Tenant** | ALdeci-managed cloud | Cloud LLM APIs | ALdeci region | Required |
| **Single-Tenant Cloud** | Customer-selected region | Dedicated or self-hosted | Customer-controlled | Required (LLM optional) |
| **On-Premises** | Customer data center | Self-hosted LLM | Customer-controlled | Optional |
| **Air-Gapped** | Isolated network / SCIF | Self-hosted LLM | Customer-controlled | None |

### Resource Requirements (On-Premises / Air-Gapped)

| Component | Minimum | Recommended |
|-----------|---------|-------------|
| **CPU** | 4 cores | 8+ cores |
| **RAM** | 8 GB | 16+ GB |
| **Storage** | 20 GB (platform) | 50+ GB (with self-hosted LLM) |
| **GPU** (self-hosted AI only) | NVIDIA A10 (24 GB VRAM) | NVIDIA A100 (80 GB VRAM) |
| **Annual Storage Growth** | <1 GB/year (Zero-Gravity Data) | <1 GB/year |

### Zero-Gravity Data Architecture

| Tier | Age | Storage | Compression |
|------|-----|---------|-------------|
| **Hot** | 0–30 days | Full fidelity, instant access | None |
| **Warm** | 30–90 days | Indexed, fast query | ZSTD Level 3 |
| **Cool** | 90–365 days | Coreset selection, MinHash dedup | ZSTD Level 9 |
| **Cold** | 1–7+ years | Evidence-only, WORM retention | ZSTD Level 19 |

**Result**: 20 GB raw → <1 GB/year retained. Enables air-gapped deployment on commodity hardware.

---

## Competitive Positioning

| Capability | ALdeci CTEM+ | Snyk | Apiiro | Aikido | Wiz | Checkmarx |
|-----------|-------------|------|--------|--------|-----|-----------|
| Native scanning engines | **8** | 2 | 0 | 3 | 2 | 2 |
| Decision intelligence pipeline | **12-step** | None | Basic | Basic | None | None |
| Multi-LLM consensus | **Yes** | No | No | No | No | No |
| Exploit verification (continuous) | **MPTE** | No | No | No | No | No |
| Chaos security testing | **FAIL** | No | No | No | No | No |
| AI-native MCP gateway | **650+ tools** | No | No | No | No | No |
| Self-hosted AI (zero egress) | **Yes** | No | No | No | No | No |
| Quantum-secure evidence | **FIPS 204-ready envelope** (algorithm-agile, `dilithium-py` activatable) | No | No | No | No | No |
| Full air-gapped deployment | **Yes** | No | Partial | No | No | Partial |
| AutoFix types | **10** | 2 | 0 | 1 | 0 | 1 |
| Confidence-gated auto-merge | **Yes** | No | No | No | No | No |
| Tool-agnostic orchestration | **200+ tools** | Own ecosystem | Limited | Limited | Own ecosystem | Own ecosystem |
| Knowledge graph correlation | **Yes** | No | Yes | No | No | No |
| Application-centric data model | **Yes** | Partial | Yes | Partial | No | Partial |

---

## API Surface

| Domain | Endpoint Count | Key Prefixes |
|--------|---------------|--------------|
| **Brain Pipeline** | 24+ | `/api/v1/brain/*` |
| **MPTE Verification** | 69+ | `/api/v1/mpte/*`, `/api/v1/micro-pentest/*` |
| **AutoFix** | 14+ | `/api/v1/autofix/*`, `/api/v1/remediation/*` |
| **Native Scanners** | 36+ | `/api/v1/sast/*`, `/api/v1/dast/*`, `/api/v1/secrets/*`, `/api/v1/container/*`, `/api/v1/cspm/*` |
| **Findings & Analytics** | 30+ | `/api/v1/analytics/*`, `/api/v1/findings/*` |
| **Evidence & Compliance** | 20+ | `/api/v1/evidence/*`, `/api/v1/compliance/*` |
| **Knowledge Graph** | 15+ | `/api/v1/knowledge-graph/*` |
| **MCP Gateway** | 18+ | `/api/v1/mcp/*`, `/api/v1/mcp-server/*` |
| **Integrations** | 40+ | `/api/v1/integrations/*`, `/api/v1/scanner-ingest/*` |
| **Threat Feeds** | 31+ | `/api/v1/feeds/*` |
| **Total** | **770+** | Full REST API with OpenAPI 3.x documentation |

All endpoints authenticated via API key or JWT. Rate-limited. RBAC-scoped.

---

*This document is the canonical CTEM+ platform capability reference for ALdeci. All evaluation teams, sales engagements, and technical reviews should use this as the primary technical reference.*

*Version 3.0 — Q1 2026 — Company Confidential*
