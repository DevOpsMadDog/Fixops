# ALdeci — Strategic Vision

> **Classification**: Company Confidential
> **Version**: 3.0 | **Effective**: Q1 2026
> **Audience**: Board of Directors, Investors, Enterprise Customers, Strategic Partners

---

## Executive Summary

ALdeci is a **Continuous Threat Exposure Management (CTEM+) Decision Intelligence Platform** for application security. ALdeci sits above the security toolchain — ingesting, correlating, verifying, deciding, remediating, and proving — transforming uncoordinated scanner output into prioritized, verified, and auditable security outcomes.

> **Mission**: Deliver the decisive answer to "What should we do about this risk?" — not merely "What risks exist?"

**Core value proposition**: Enterprises operating 5–15 security tools receive 11,000+ uncontextualized findings per week. ALdeci reduces that to actionable, prioritized, exploitability-verified cases — delivering **97% noise reduction**, **sub-24-hour mean-time-to-decision**, and **cryptographically signed compliance evidence** at every step.

---

## I. Market Problem

### The $380B Application Security Gap

| Metric | Industry Benchmark | Source |
|--------|--------------------|--------|
| Findings per week (200-dev org) | 11,300+ | Ponemon 2025, Gartner |
| False positive rate | 60–70% | NTT AppSec, Rezilion |
| Analyst time on triage/context | 80% | IDC Security Operations Survey |
| Mean time to remediate (MTTR) | 14+ days | DORA / Veracode State of Software Security |
| Cost per vulnerability resolved | $4,200 | IBM Cost of a Data Breach 2025 |
| Tool coordination across stack | Effectively zero | Gartner CTEM Market Guide |

Enterprises invest in best-of-breed scanners (SAST, DAST, SCA, CSPM, container, secrets). Each operates independently. No tool answers the critical question: **"Given everything we know, what should we fix first, and can we prove we did?"**

### Why Existing Solutions Fall Short

| Approach | Limitation |
|----------|-----------|
| **Scanner vendors** (Snyk, Checkmarx, Semgrep) | Point solutions. Each vendor sees only its own findings. No cross-tool correlation or exploitability verification. |
| **ASPM platforms** (Apiiro, Aikido) | Aggregation without decision authority. No native scanning for air-gapped environments. No exploit verification. |
| **SOAR/SIEM** (Splunk, Sentinel) | Designed for infrastructure events, not application vulnerability lifecycle. |
| **Manual processes** | Spreadsheets, Jira tickets, tribal knowledge. Does not scale. |

---

## II. The ALdeci Approach

### Platform Architecture

ALdeci implements the complete CTEM lifecycle defined by Gartner, extended with AI-driven decision intelligence and cryptographic evidence:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        ALdeci CTEM+ Platform                            │
│                                                                         │
│  ┌─── DISCOVER ────────────────────────────────────────────────────┐    │
│  │  200+ Tool Integrations │ 8 Native Scanners │ SBOM Generation  │    │
│  │  Universal Finding Format │ Cross-Scanner Deduplication         │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                              ↓                                          │
│  ┌─── PRIORITIZE ─────────────────────────────────────────────────┐    │
│  │  Knowledge Graph Correlation │ Multi-Factor Risk Scoring       │    │
│  │  Business Context Enrichment │ Threat Intelligence (NVD/KEV/   │    │
│  │  EPSS) │ Attack Path Analysis │ Blast Radius Estimation        │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                              ↓                                          │
│  ┌─── VALIDATE ───────────────────────────────────────────────────┐    │
│  │  Micro-Pentest Engine (MPTE) │ 19-Phase Exploit Verification  │    │
│  │  FAIL Engine (Chaos Security Testing) │ Reachability Analysis  │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                              ↓                                          │
│  ┌─── REMEDIATE ──────────────────────────────────────────────────┐    │
│  │  AI-Powered AutoFix (10 Fix Types) │ Confidence-Gated Auto-   │    │
│  │  Merge │ PR Generation │ Dependency Updates │ IaC Remediation  │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                              ↓                                          │
│  ┌─── COMPLY ─────────────────────────────────────────────────────┐    │
│  │  Quantum-Secure Evidence Signing │ Framework Auto-Mapping      │    │
│  │  (SOC 2, PCI-DSS 4.0, NIST 800-53 R5, ISO 27001, FedRAMP,   │    │
│  │  CMMC, HIPAA, DISA STIG) │ Audit-Ready Export │ WORM Retention│    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                         │
│  ┌─── DECISION ENGINE ────────────────────────────────────────────┐    │
│  │  12-Step Brain Pipeline │ Multi-LLM Consensus (85% threshold) │    │
│  │  Policy Engine │ Self-Learning (5 Feedback Loops)              │    │
│  └─────────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────────┘
```

### 12-Step Brain Pipeline

Every finding flows through a deterministic, auditable pipeline:

| Step | Function | Outcome |
|------|----------|---------|
| 1 | **Connect** | Ingest from external tools or native scanners |
| 2 | **Normalize** | Convert to Universal Finding Format (UFF) |
| 3 | **Resolve Identity** | Map to Application → Component → Feature |
| 4 | **Deduplicate** | Cross-scanner deduplication |
| 5 | **Build Graph** | Construct relationship graph (assets, vulns, code paths) |
| 6 | **Enrich** | NVD, CISA KEV, EPSS, threat intelligence feeds |
| 7 | **Score Risk** | Multi-factor scoring (CVSS + EPSS + business context + reachability) |
| 8 | **Apply Policy** | Evaluate against organizational security policies |
| 9 | **AI Consensus** | Multi-LLM deliberation with 85% agreement threshold |
| 10 | **Verify Exploitability** | MPTE-driven exploit proof |
| 11 | **Remediate** | AutoFix generation with confidence gating |
| 12 | **Generate Evidence** | Cryptographically signed compliance evidence |

---

## III. Strategic Pillars

| # | Pillar | Enterprise Value |
|---|--------|-----------------|
| 1 | **Application-Centric Data Model** | Every finding, decision, and evidence artifact traces to Application → Component → Feature. Enables ownership-based routing and accountability. |
| 2 | **Full Security Lifecycle Coverage** | Design → IDE → Pre-merge → Build → IaC → Runtime → Graph → AI Decision → Remediation → Continuous Learning |
| 3 | **Decision Intelligence** | Moves organizations from "alert fatigue" to "decision confidence" — actionable outcomes, not raw findings |
| 4 | **Multi-LLM Consensus / Self-Hosted AI** | Three or more LLMs deliberate per decision (85% agreement threshold). Self-hosted option for zero data exfiltration. |
| 5 | **Exploit Verification (MPTE)** | 19-phase deterministic engine proves exploitability. Eliminates theoretical findings from remediation queues. |
| 6 | **Quantum-Secure Evidence** | Algorithm-agile hybrid envelope: RSA-PSS shipping today; FIPS 204 ML-DSA side activatable via `dilithium-py` per SCIF/IL5 contract requirement. 7-year WORM retention. |
| 7 | **AI-Native Platform (MCP Gateway)** | 650+ auto-discovered tool endpoints consumable by AI agents, copilots, and automation frameworks |
| 8 | **Self-Learning** | Five feedback loops: decision outcomes, MPTE results, false positive rates, remediation success, policy violations |
| 9 | **Air-Gapped / On-Premises Deployment** | Full platform functionality with zero external dependencies. Commodity hardware. Sub-1 GB/year storage. |
| 10 | **CTEM Full Loop with Cryptographic Proof** | Discover → Prioritize → Validate → Remediate → Measure — with signed evidence at every stage |

---

## IV. User Experience Architecture

ALdeci organizes capabilities by **what security teams need to accomplish**, not by underlying technology:

| Workspace | Question Answered | Primary Users |
|-----------|-------------------|---------------|
| **Mission Control** | "What needs my attention right now?" | CISO, VP Engineering, SOC Managers, DevSecOps Leads |
| **Discover** | "What risks exist across my environment?" | AppSec Engineers, Cloud Security, Platform Teams |
| **Validate** | "Is this actually exploitable?" | Red Teams, Penetration Testers, Threat Analysts |
| **Remediate** | "How do I fix this, track it, close it?" | Developers, Engineering Managers, DevSecOps |
| **Comply** | "Can I prove we are secure to auditors and regulators?" | Compliance Leads, GRC Teams, CISOs, External Auditors |

**AI Copilot** available persistently across all workspaces for natural-language queries, automated triage suggestions, and remediation guidance.

**25 enterprise personas** served across Leadership, Security Operations, Engineering, Data/AI, and External Audit roles.

---

## V. Competitive Differentiation

### Capability Matrix

| Capability | ALdeci | Snyk | Apiiro | Aikido | Wiz | Checkmarx |
|-----------|--------|------|--------|--------|-----|-----------|
| Native SAST + DAST + Secrets + Container + IaC + API + Malware + LLM scanning | 8 engines | 2 | 0 | 3 | 2 | 2 |
| Multi-LLM consensus decisions | **Yes** (3+ LLMs, 85% threshold) | No | No | No | No | No |
| Exploit verification engine | **MPTE** (19-phase, continuous) | No | No | No | No | No |
| Chaos security testing (FAIL Engine) | **Yes** | No | No | No | No | No |
| AI-native MCP Gateway | **650+ tools** | No | No | No | No | No |
| Quantum-secure evidence (FIPS 204-ready envelope) | **Yes** (algorithm-agile, `dilithium-py` activatable) | No | No | No | No | No |
| Self-hosted LLM (zero API tokens) | **Yes** | No | No | No | No | No |
| Full air-gapped deployment | **Yes** | No | Partial | No | No | Partial |
| 12-step CTEM pipeline | **Yes** | No | No | No | No | No |
| AutoFix types | **10** | 2 | 0 | 1 | 0 | 1 |
| Confidence-gated auto-merge | **Yes** | No | No | No | No | No |
| Works with existing tool investments | **Yes** (200+ integrations) | Own ecosystem | Limited | Limited | Own ecosystem | Own ecosystem |

### Nine Unique Differentiators

1. **8 Native Scanners + AutoFix** — Complete CTEM pipeline built-in. Full coverage in air-gapped deployments where external tools are unavailable.
2. **12-Step Brain Pipeline** — Deterministic, auditable decision pipeline from ingestion through signed evidence.
3. **FAIL Engine** — Chaos engineering for application security. Inject faults, measure response, generate labeled training data.
4. **MCP Gateway** — First AppSec platform designed for AI agent consumption. 650+ auto-discovered tools via Model Context Protocol.
5. **Self-Hosted AI** — Enterprise-grade LLM inference on customer infrastructure. Zero data exfiltration. Zero per-token cost.
6. **Quantum-Secure Cryptography** — Algorithm-agile hybrid envelope: RSA-PSS shipping; FIPS 204 ML-DSA side activatable via `FIXOPS_PQ_BACKEND=dilithium-py` when SCIF/IL5 contract requires it.
7. **Zero-Gravity Data** — Four-tier intelligent aging reduces on-premises storage by 95%. Sub-1 GB/year.
8. **MPTE Exploit Verification** — 19-phase deterministic engine proves exploitability. Continuous. Not annual.
9. **Switzerland Positioning** — Works with every tool in the customer's existing toolchain. Day-one value. No rip-and-replace.

---

## VI. Deployment Models

| Model | Target Customer | Data Residency | AI Inference |
|-------|----------------|----------------|--------------|
| **SaaS (Multi-Tenant)** | Mid-market, cloud-native organizations | ALdeci-managed, SOC 2 Type II certified | Cloud LLM APIs |
| **Single-Tenant Cloud** | Financial services, healthcare | Customer-selected region, HIPAA-eligible | Dedicated or self-hosted |
| **On-Premises** | Government, defense, critical infrastructure | Customer-controlled, no egress | Self-hosted LLM, zero external dependencies |
| **Air-Gapped** | Classified environments, SCIF deployments | Fully isolated, DISA STIG hardened | Self-hosted LLM, all 8 native scanners active |

**All deployment models** deliver identical functionality. No feature downgrade for air-gapped or on-premises customers.

---

## VII. Compliance Framework Coverage

| Framework | Controls Mapped | Automated Evidence | Audit-Ready |
|-----------|----------------|--------------------|-------------|
| SOC 2 Type II | 22 | 19 | Yes |
| PCI-DSS 4.0 | 22 | 20 | Yes |
| NIST 800-53 Rev 5 | 30 | 29 | Yes |
| ISO 27001:2022 | 21 | 16 | Yes |
| FedRAMP Moderate | Mapped | In progress | Planned |
| CMMC Level 2 | Mapped | In progress | Planned |
| HIPAA Security Rule | Mapped | In progress | Planned |
| DISA STIG | Mapped | In progress | Planned |

All evidence bundles are cryptographically signed via an algorithm-agile hybrid envelope (RSA-PSS shipping; PQ side activatable per `docs/quantum_crypto_retire_decision_2026-05-03.md`) and stored with configurable WORM retention (default: 7 years).

---

## VIII. Integration Ecosystem

### Tool Ingestion (Day-One Value)
ALdeci normalizes and correlates findings from the customer's existing security investments:

| Category | Supported Tools |
|----------|----------------|
| **SAST** | Snyk Code, Semgrep, Checkmarx, SonarQube, CodeQL, Fortify, Veracode |
| **SCA/OSS** | Snyk Open Source, Dependabot, Trivy, Grype, FOSSA, WhiteSource |
| **DAST** | OWASP ZAP, Burp Suite, Rapid7, Qualys WAS |
| **Container** | Trivy, Snyk Container, Prisma Cloud, Aqua, Sysdig |
| **CSPM/IaC** | Wiz, Prisma Cloud, Checkov, tfsec, KICS |
| **Secrets** | GitLeaks, TruffleHog, detect-secrets |
| **CNAPP** | Wiz, Orca, Lacework, AWS Security Hub, Azure Defender |
| **Workflow** | Jira, ServiceNow, Slack, Microsoft Teams, PagerDuty |
| **Source Control** | GitHub, GitLab, Azure DevOps, Bitbucket |
| **CI/CD** | Jenkins, GitHub Actions, GitLab CI, Azure Pipelines, CircleCI |

### Output Formats
SARIF, CycloneDX 1.5, SPDX 2.3, VEX, CSAF, OSCAL, custom JSON/CSV.

---

## IX. Enterprise Outcomes

| Metric | Before ALdeci | With ALdeci | Improvement |
|--------|---------------|-------------|-------------|
| Weekly findings requiring human review | 11,300+ | ~340 | 97% reduction |
| Mean time to decision | 14+ days | <24 hours | 14x faster |
| Annual vulnerability triage cost | $520K+ | ~$45K | $475K savings |
| Compliance evidence preparation | 6–8 weeks per audit | Continuous, automated | 90% reduction |
| Exploit verification frequency | 1x/year (manual pentest) | Continuous (365x/year) | 365x increase |
| Cross-tool finding correlation | Manual/none | Automated via knowledge graph | First-time capability |
| Post-quantum evidence validity | Not addressed | Hybrid envelope ready (FIPS 204 activatable) | Future-proof |

---

## X. Vertical-Specific Value

### Defense & Intelligence (DoD, IC, Five Eyes)
- CMMC Level 2 and DISA STIG compliance automation
- Full air-gapped deployment — zero network egress
- Self-hosted AI — classified data never leaves SCIF
- Quantum-secure evidence for long-retention requirements (ITAR, EAR)
- SBOM generation and software supply chain verification (EO 14028)

### Financial Services (Top-Tier Banks, Payment Processors)
- PCI-DSS 4.0 continuous compliance with signed evidence
- SOC 2 Type II automated evidence generation
- Multi-tenant isolation with customer-controlled encryption keys
- Real-time risk scoring with EPSS and business-context weighting
- Regulatory-ready audit export (OCC, FFIEC, MAS-TRM)

### Healthcare & Life Sciences
- HIPAA Security Rule evidence automation
- PHI-aware scanning policies with data classification
- On-premises deployment for data sovereignty
- Audit trail with immutable, signed evidence chain

### Fintech & Cloud-Native
- CI/CD-native integration (shift-left and shift-right)
- Developer-first AutoFix with confidence-gated auto-merge
- SBOM and software supply chain attestation
- Rapid deployment — production value in under one hour
- SOC 2 and SOX compliance from day one

---

## XI. Technology Architecture

### Platform Principles
- **Modular monolith** scaling to microservices — single deployment unit, clean domain boundaries
- **Event-driven** internal coordination (no external message queue dependency)
- **SQLite WAL** for local persistence, PostgreSQL for multi-tenant SaaS
- **Stateless API tier** — horizontal scaling behind standard load balancers
- **Cryptographic integrity** at every decision boundary (RSA-SHA256 shipping; ML-DSA hybrid envelope activatable)

### Security of the Platform Itself
- SAST, DAST, and secrets scanning run against ALdeci's own codebase continuously (dogfooding)
- Dependency auditing with automated upgrade validation
- RBAC with organization-scoped isolation
- API authentication via JWT + API key with configurable rate limiting
- OWASP Top 10 hardened (injection, SSRF, access control, CSRF, XSS)

### AI Architecture
- Multi-LLM consensus: GPT-4, Claude, Gemini (configurable providers)
- 85% agreement threshold for automated decisions; below threshold escalates to human
- Self-hosted option: vLLM-served models on customer GPUs — zero external API calls
- Prompt injection hardening on all LLM interfaces
- Full audit trail of every AI decision, vote, and confidence score

---

## XII. Go-to-Market

### Pricing Structure
| Tier | Monthly | Target Segment |
|------|---------|---------------|
| **Community** | Free (OSS core) | Open-source teams, <10 developers |
| **Professional** | $3,000–5,000 | Mid-market, 50–200 developers |
| **Enterprise** | $8,000–15,000 | Large organizations, 200–2,000 developers |
| **Sovereign / Air-Gapped** | $15,000–25,000 | Government, defense, critical infrastructure |

### Revenue Trajectory
| Year | Milestone | Target ARR |
|------|-----------|-----------|
| 1 | 5–10 design partners, production deployments | $150K–500K |
| 2 | 20–50 enterprise customers, vertical expansion | $2M–5M |
| 3 | 100+ customers, category leadership | $10M+ |

### Competitive Moat
1. **Multi-LLM consensus** — patent-pending approach to AI-driven security decisions
2. **Knowledge graph compounding** — platform intelligence grows with data volume
3. **Self-hosted AI** — only vendor with zero-token, zero-egress AI option
4. **Quantum cryptography** — algorithm-agile envelope ready, PQ backend activatable on contract demand (multi-year head start on the integration surface)
5. **MCP protocol** — first-mover advantage in AI-native security tooling
6. **FAIL Engine** — unique capability, no competitive equivalent
7. **Switzerland positioning** — trusted by customers who refuse vendor lock-in

---

## XIII. Roadmap

| Horizon | Timeframe | Strategic Objective |
|---------|-----------|---------------------|
| **H1 — Foundation** | Q1–Q2 2026 | Design partners in production, FAIL Engine live, MCP Gateway available, SOC 2 Type II initiated |
| **H2 — Scale** | Q3–Q4 2026 | 20+ enterprise customers, quantum-secure evidence GA, air-gapped deployment for government, self-hosted AI option |
| **H3 — Category Leadership** | 2027 | 100+ customers across defense, financial services, healthcare. MCP as industry standard for AI-AppSec interop. Category creator: "Decision Intelligence for Application Security" |
| **H4 — Autonomy** | 2028 | Autonomous CTEM — continuous scan-verify-fix without human intervention. Predictive vulnerability scoring. AI agent marketplace. |
| **H5 — Dominance** | 2029–2030 | Industry-standard CTEM API. AppSec digital twin. Full post-quantum cryptography migration. 1M+ findings/day processing. |

---

## XIV. Summary

ALdeci is not another security scanner. It is not another dashboard. It is the **decision layer** that makes every security tool in the enterprise intelligent — and proves it with cryptographic evidence.

For organizations drowning in 11,000+ weekly findings across a dozen uncoordinated tools, ALdeci delivers what no competitor can: **verified, prioritized, remediated, and provable security outcomes**.

> **One platform. Every tool. Every finding. Every decision. Signed proof.**

---

*This document is the strategic north-star for ALdeci. All implementation documents, sprint plans, and engineering specifications derive from this vision. In case of conflict, this document takes precedence.*

*Version 3.0 — Q1 2026 — Company Confidential*
