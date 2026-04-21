# ALDECI Rearchitecture: TrustGraph-Native + LLM Consensus

> **Version**: 2.5 | **Date**: 2026-04-12
> **Author**: Shiva (CEO) + Claude Opus (CTO)
> **Status**: MASTER PLAN — Beast Mode source of truth. Verified by code-review-graph + deep codebase audit + 30-persona analysis
> **Analysis Tools**: code-review-graph v2.2.2 (34,301 nodes, 216,476 edges, 1,624 files, 7 languages), TrustGraph research, 9-competitor analysis, 30-persona workflow mapping
> **Git**: `feature/autonomous-foundation` merged → `features/intermediate-stage` (default branch) — commit `62153c83`
> **v2.4 changes**: Corrected connector count from 11→18 (Wiz/PrismaCloud/Orca/Lacework/ThreatMapper discovered), documented 32 native scanner parsers, updated code-review-graph from 879→1,624 files (7 languages including TS/TSX). Beast Mode v6 execution plan added.
> **v2.3 changes**: Added Part 12 — Persona Architecture (30 personas, 6 RBAC roles, 10 architecture amendments, phase gate validation). This document is now the single source of truth for all Beast Mode execution runs.
> **v2.2 changes**: Added Part 11 — Universal Connector Framework (n8n + TrustGraph MCP + DefectDojo, 620+ tool coverage, full SDLC PULL architecture across 7 stages)
> **v2.1 changes**: Corrected frontend, OWASP DC+DT, 9 competitor deep dives, 15-stage pipeline, LLM Council input feed

---

## Executive Summary

ALDECI is being rearchitected from a **FastAPI microservice with in-memory graphs** into a **TrustGraph-native security intelligence platform** with Karpathy LLM Consensus replacing weighted voting. This v2 document is verified against the actual codebase via code-review-graph structural analysis (parsed 879 files, mapped 75,533 call edges, 3,459 import edges, 379 inheritance edges) and deep source code reading of every critical module.

**Key v2.1 corrections**:
- **Frontend is `suite-ui/aldeci/`** — the "ALDECI Intelligence Hub" v2.0 (React 18 + Vite 5 + TypeScript + Radix UI + @xyflow/react + Tailwind + Zustand), NOT the old `web/aggregate-out/` Next.js static export. Pages: Dashboard, CEODashboard, AttackLab, Copilot, DataFabric, DecisionEngine, EvidenceVault, IntelligenceHub, NerveCenter, RemediationCenter, Settings, plus 14 subdirectory page groups (ai-engine, attack, cloud, code, core, discover, evidence, feeds, mission-control, protect, settings, validate). A second newer UI exists at `suite-ui/aldeci-ui-new/` (React 19 + CTEM 5-Space UI + Playwright e2e + Allure reporting).
- **OWASP Dependency-Check replaces lib4sbom** for SBOM normalization — brings CPE matching, NVD/NPM Audit/OSS Index/RetireJS/Bundler Audit correlation, SARIF output, and `failBuildOnCVSS` gating. Combined with OWASP Dependency-Track for SBOM lifecycle management (CycloneDX ingestion/republication, 6 vuln sources, EPSS, policy engine). Custom `InputNormalizer` retained for SARIF/CVE/CNAPP/VEX/BusinessContext but SBOM path rewired through DC→DT pipeline.
- **`feature/autonomous-foundation` merged into `features/intermediate-stage` (default branch)** — 863 commits including suite-based reorganization (suite-api, suite-core, suite-feeds, suite-evidence-risk, suite-integrations, suite-ui), SAST self-scan, micro-pentest TLS, autonomous validation cycles
- **Codebase reorganized into suite layout**: `suite-api/`, `suite-core/`, `suite-feeds/`, `suite-evidence-risk/`, `suite-integrations/`, `suite-ui/` — paths in this document reflect the merged structure
- An **enterprise legacy archive** exists with 48+ classes including `KnowledgeGraphBuilder`, `CorrelationEngine`, `VectorStore`, `ReinforcementLearningController`, `MarketplaceService`, `ComplianceEngine` — significant code to resurrect
- **28+ threat intelligence feeds** already implemented (NVD, OSV, GitHub, EPSS, KEV, ExploitDB, Vulners, AlienVault OTX, AbuseIPDB, vendor-specific: Microsoft, Apple, AWS, Azure, Oracle, Cisco, VMware, Docker, Kubernetes, ecosystem: NPM, PyPI, Ruby, Rust, Go, Maven, NuGet, Debian, Ubuntu, Alpine)
- **SSVC (Stakeholder-Specific Vulnerability Categorization)** framework already built with deployer plugin
- **Existing vector store** with ChromaDB + sentence-transformers + SecurityPatternMatcher — not "no vector store"
- **Feature flag system** (LaunchDarkly + local overlay + combined provider + namespace adapter)
- **OPA (Open Policy Agent)** integration exists (demo + production engines)
- **1,536 test functions** across 140+ test files — substantial test coverage

**MindsDB verdict**: Rejected. TrustGraph + LLM Consensus is superior for security decisions — no SQL injection risk, built-in audit trails, consensus-driven explainability, and portable context versioning.

---

## Part 1: ALDECI Current State — Deep Structural Analysis

### 1.1 Codebase Metrics (code-review-graph verified)

| Metric | Count | Details |
|---|---|---|
| **Total files parsed** | 879 | 524 Python + 355 JS/other |
| **Python functions** | 3,226 | Across all modules |
| **Python classes** | 895 | Including 379 inheritance edges |
| **Python test functions** | 1,536 | Across 140+ test files |
| **Total call edges** | 75,533 | Function-to-function call relationships |
| **Import edges** | 3,459 | Module-to-module dependencies |
| **Inheritance edges** | 379 | Class hierarchy relationships |

### 1.2 Architecture Layers

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        ALDECI CURRENT ARCHITECTURE                       │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                         │
│  LAYER 1: WEB FRONTEND (suite-ui/aldeci/ — ALDECI Intelligence Hub)     │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  suite-ui/aldeci/ (v2.0 — PRIMARY)                              │   │
│  │  Pages: Dashboard, CEODashboard, AttackLab, Copilot,            │   │
│  │         DataFabric, DecisionEngine, EvidenceVault,               │   │
│  │         IntelligenceHub, NerveCenter, RemediationCenter,         │   │
│  │         Settings + 14 page groups (ai-engine, attack, cloud,     │   │
│  │         code, core, discover, evidence, feeds, mission-control,  │   │
│  │         protect, settings, validate)                             │   │
│  │  Tech: React 18 + Vite 5 + TypeScript + Radix UI +              │   │
│  │        @xyflow/react + Tailwind + Zustand + cmdk + Zod           │   │
│  │  Components: AICopilot, CommandPalette, AttackPathGraph,         │   │
│  │             MultiLLMConsensusPanel, BrainPipelineLiveFeed,       │   │
│  │             CTEMProgressRing, RiskScoreGauge, MPTEChat           │   │
│  │                                                                   │   │
│  │  suite-ui/aldeci-ui-new/ (v1.0 — CTEM 5-Space)                  │   │
│  │  Tech: React 19 + Vite 6 + Radix UI + Playwright e2e + Allure   │   │
│  │  Tests: Persona RBAC, cross-role workflows, Newman API tests     │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  LAYER 2: API GATEWAY (FastAPI — 20+ routers)                           │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  apps/api/: analytics, audit, auth, bulk, iac, ide,             │   │
│  │            integrations, inventory, pentagi, pipeline,           │   │
│  │            policies, reports, secrets, teams, users, workflows   │   │
│  │  backend/api/: risk, graph, evidence, provenance, pentagi       │   │
│  │  apps/api/routes/: enhanced (multi-LLM endpoints)               │   │
│  │  Middleware: CORS, RateLimit, RequestLogging, CorrelationId      │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  LAYER 3: DECISION ENGINE (Multi-LLM + Risk Models)                     │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  core/enhanced_decision.py — MultiLLMConsensusEngine             │   │
│  │    ├── ProviderSpec (name, weight, style, focus)                 │   │
│  │    ├── 4 providers: OpenAI, Anthropic, Gemini, Sentinel          │   │
│  │    └── Weighted voting with fallback to deterministic             │   │
│  │                                                                   │   │
│  │  core/decision_tree.py — DecisionTreeOrchestrator                │   │
│  │    ├── Step 1: compute_enrichment() → EnrichmentEvidence         │   │
│  │    ├── Step 2: compute_forecast() → ForecastResult               │   │
│  │    ├── Step 3: compute_threat_model() → ThreatModelResult        │   │
│  │    ├── Step 4: map_cve_to_controls() → ComplianceMappingResult   │   │
│  │    ├── Steps 5-6: _compute_verdict()                             │   │
│  │    └── Verdict: exploitable (p≥0.70), not_exploitable (p≤0.15)  │   │
│  │                                                                   │   │
│  │  core/models/: BayesianNetworkModel, BNLRHybridModel,            │   │
│  │                WeightedScoringModel (all extend RiskModel ABC)    │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  LAYER 4: DATA PIPELINE (Normalizers + Enrichment + Feeds)              │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  apps/api/normalizers.py (1,783 lines, 57 functions)             │   │
│  │    ├── InputNormalizer: SBOM, SARIF, CVE, CNAPP, VEX, Context    │   │
│  │    └── 14 data classes: SBOMComponent, NormalizedSBOM, etc.      │   │
│  │                                                                   │   │
│  │  risk/enrichment.py — EnrichmentEvidence                         │   │
│  │    └── CVSS extraction (v3.1/v3.0/v2), CWE, KEV, EPSS, age      │   │
│  │                                                                   │   │
│  │  risk/forecasting.py — Bayesian odds update                      │   │
│  │    └── P(exploit) = prior * likelihood_ratios (KEV, advisory, CWE)│  │
│  │                                                                   │   │
│  │  risk/threat_model.py — Attack path analysis                     │   │
│  │    └── CVSS vector parsing, reachability scoring, exposure levels │   │
│  │                                                                   │   │
│  │  risk/feeds/ — 28+ THREAT INTELLIGENCE FEEDS:                    │   │
│  │    ├── base.py: ThreatIntelligenceFeed ABC, FeedRegistry          │   │
│  │    ├── nvd.py: NVDFeed                                           │   │
│  │    ├── osv.py: OSVFeed                                           │   │
│  │    ├── github.py: GitHubSecurityAdvisoriesFeed                   │   │
│  │    ├── exploits.py: ExploitDB, Vulners, AlienVault OTX,          │   │
│  │    │   AbuseCH (URLHaus, MalwareBazaar, ThreatFox), Rapid7       │   │
│  │    ├── vendors.py: Microsoft, Apple, AWS, Azure, Oracle,          │   │
│  │    │   Cisco, VMware, Docker, Kubernetes                          │   │
│  │    ├── ecosystems.py: NPM, PyPI, Ruby, Rust, Go, Maven,          │   │
│  │    │   NuGet, Debian, Ubuntu, Alpine                              │   │
│  │    └── orchestrator.py: ThreatIntelligenceOrchestrator            │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  LAYER 5: KNOWLEDGE & GRAPH (Partial — needs TrustGraph)                │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  services/graph/graph.py (721 lines, 42 functions)               │   │
│  │    ├── ProvenanceGraph (NetworkX or _SimpleMultiDiGraph fallback) │   │
│  │    ├── GraphSources: repo, attestation, sbom, risk, releases     │   │
│  │    └── Lineage, reachability, impact, anomaly detection          │   │
│  │                                                                   │   │
│  │  core/vector_store.py (444 lines)                                │   │
│  │    ├── BaseVectorStore (abstract)                                │   │
│  │    ├── InMemoryVectorStore (SHA1-based, 32-dim, cosine)          │   │
│  │    ├── ChromaVectorStore (sentence-transformers, all-MiniLM-L6)  │   │
│  │    └── SecurityPatternMatcher (loads security_patterns.json)      │   │
│  │                                                                   │   │
│  │  apps/api/knowledge_graph.py — KnowledgeGraphService             │   │
│  │  new_apps/api/processing/knowledge_graph.py —                    │   │
│  │    KnowledgeGraphProcessor, _ExtractionResult, _FallbackBuilder  │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  LAYER 6: COMPLIANCE & POLICY                                           │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  core/compliance.py — ComplianceEvaluator                        │   │
│  │    └── Checks: design, sbom, sarif, cve, context, guardrails,    │   │
│  │        evidence, policy                                          │   │
│  │  core/ssdlc.py — SSDLCEvaluator                                 │   │
│  │    └── Stages: planning→design→dev→test→deploy→ops→maintenance   │   │
│  │  compliance/mapping.py — ControlMapping, ComplianceMappingResult │   │
│  │  core/policy.py — PolicyAutomation (_OPAClient, _AutomationDisp) │   │
│  │  ssvc/ — SSVC Framework (DecisionDeployer, ExploitationStatus,   │   │
│  │          SystemExposureLevel, UtilityLevel, HumanImpactLevel)    │   │
│  │  core/flags/ — Feature Flags (LaunchDarkly, Local, Combined,     │   │
│  │                NamespaceAdapter, FlagRegistry)                    │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  LAYER 7: INTEGRATIONS & CONNECTORS                                     │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  core/connectors.py — JiraConnector, ConfluenceConnector,        │   │
│  │                       SlackConnector (all extend _BaseConnector)  │   │
│  │  integrations/github/adapter.py — GitHubCIAdapter                │   │
│  │  integrations/jenkins/adapter.py — JenkinsCIAdapter              │   │
│  │  integrations/sonarqube/adapter.py — SonarQubeAdapter            │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  LAYER 8: INFRASTRUCTURE                                                │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  core/storage.py — ArtefactArchive                               │   │
│  │  core/tenancy.py — TenantLifecycleManager                        │   │
│  │  core/analytics_db.py, audit_db.py, auth_db.py, user_db.py,     │   │
│  │    policy_db.py, report_db.py, secrets_db.py, workflow_db.py,    │   │
│  │    inventory_db.py, integration_db.py, pentagi_db.py, iac_db.py  │   │
│  │  telemetry/ — OTEL (_SilentSpanExporter, _NoopTracer, etc.)      │   │
│  │  services/evidence/ — EvidenceStore, EvidencePackager             │   │
│  │  services/provenance/ — ProvenanceAttestation, VerificationResult │   │
│  │  core/configuration.py (51 functions) — OverlayConfig system     │   │
│  └─────────────────────────────────────────────────────────────────┘   │
│                                                                         │
│  HIDDEN LAYER: ENTERPRISE LEGACY ARCHIVE (48+ classes to resurrect)     │
│  ┌─────────────────────────────────────────────────────────────────┐   │
│  │  archive/enterprise_legacy/src/services/:                        │   │
│  │    ├── knowledge_graph.py — KnowledgeGraphBuilder, CTINexusEntity │   │
│  │    │   Extractor, SecurityEntity, SecurityRelation (48 functions) │   │
│  │    ├── decision_engine.py — DecisionEngine, DecisionContext (43fn)│   │
│  │    ├── correlation_engine.py — CorrelationEngine, CorrelationResult│  │
│  │    ├── vector_store.py — VectorStore, ChromaDBVectorStore, Factory│   │
│  │    ├── rl_controller.py — ReinforcementLearningController         │   │
│  │    ├── processing_layer.py — ProcessingLayer, SSVCProbabilistic   │   │
│  │    │   Fusion, MarkovTransitionMatrixBuilder (44 functions)        │   │
│  │    ├── advanced_llm_engine.py — AdvancedLLMEngine, MultiLLMResult│   │
│  │    ├── compliance_engine.py — ComplianceEngine                   │   │
│  │    ├── evidence_lake.py — EvidenceLake                           │   │
│  │    ├── explainability.py — ExplainabilityService                 │   │
│  │    ├── fix_engine.py — FixEngine, FixRecommendation              │   │
│  │    ├── marketplace.py — MarketplaceService, MarketplaceItem      │   │
│  │    ├── golden_regression_store.py — GoldenRegressionStore        │   │
│  │    ├── oss_integrations.py — TrivyScanner, OPAPolicyEngine,      │   │
│  │    │   SigstoreVerifier, GrypeScanner                             │   │
│  │    ├── real_opa_engine.py — OPAEngine, DemoOPA, ProductionOPA    │   │
│  │    ├── chatgpt_client.py — ChatGPTClient, ChatGPTChatSession     │   │
│  │    └── risk_scorer.py — ContextualRiskScorer                     │   │
│  │                                                                   │   │
│  │  archive/enterprise_legacy/src/core/:                            │   │
│  │    ├── security.py — SecurityManager, PasswordManager, JWTManager,│   │
│  │    │   RBACManager, MFAManager, HTTPBearer                        │   │
│  │    ├── exceptions.py — 12 exception classes + SecurityViolation   │   │
│  │    └── middleware.py — Performance, Security, RateLimit, Compress  │   │
│  │                                                                   │   │
│  │  archive/enterprise_legacy/src/models/:                          │   │
│  │    ├── security.py — SecurityFinding, PolicyRule, VulnIntelligence│   │
│  │    ├── user.py — User, UserSession, UserAuditLog                 │   │
│  │    └── base.py — AuditMixin, SoftDeleteMixin, EncryptedFieldMixin│   │
│  │                                                                   │   │
│  │  archive/enterprise_legacy/src/utils/crypto.py (71 functions):   │   │
│  │    └── KeyProvider, EnvKeyProvider, AWSKMSProvider,               │   │
│  │        AzureKeyVaultProvider, SecureTokenManager                  │   │
│  └─────────────────────────────────────────────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────┘
```

### 1.3 Complete LLM Provider Hierarchy (verified)

```
BaseLLMProvider (core/llm_providers.py)
├── OpenAIChatProvider (gpt-4o-mini, temp=0, 30s timeout, JSON mode)
│     API key: OPENAI_API_KEY or FIXOPS_OPENAI_KEY
├── AnthropicMessagesProvider (claude-3-5-sonnet, max_tokens=400)
│     API key: ANTHROPIC_API_KEY or FIXOPS_ANTHROPIC_KEY
├── GeminiProvider (gemini-1.5-pro, JSON response format)
│     API key: GOOGLE_API_KEY or FIXOPS_GEMINI_KEY
├── SentinelCyberProvider (deterministic fallback, domain heuristics)
└── DeterministicLLMProvider (always returns default_action)

LLMResponse dataclass:
  recommended_action: "block" | "allow" | "defer"
  confidence: 0.0-1.0
  reasoning: str
  mitre_techniques: [T1190, T1059, ...]
  compliance_concerns: ["PCI-DSS:6.1", ...]
  attack_vectors: [...]
  metadata: {processing_time_ms, cost_usd, mode}
```

### 1.4 Complete Risk Model Hierarchy (verified)

```
RiskModel (ABC) — core/model_registry.py
├── BayesianNetworkModel (pgmpy TabularCPD, VariableElimination)
│     Nodes: exploitation, exposure, utility, safety_impact, mission_impact → risk
│     Prior: exploitation=[0.6 none, 0.3 poc, 0.1 active]
├── BNLRHybridModel (Bayesian + sklearn LogisticRegression)
│     Features: severity, kev_listed, epss_score, cvss_score, age_days
│     Two-stage: BN inference → LR refinement
└── WeightedScoringModel
      Weights: critical=1.0, high=0.75, medium=0.5, low=0.25
      Verdict: allow (<0.6), defer (0.6-0.85), block (≥0.85)

ModelRegistry tracks: ModelType, ModelMetadata, ModelPrediction
```

### 1.5 Complete Data Flow (verified end-to-end)

```
RAW INPUT                    NORMALIZATION                    ENRICHMENT
───────────                  ─────────────                    ──────────
Source code / manifests ──→ OWASP Dependency-Check (CPE) ──→ CycloneDX SBOM
CycloneDX SBOM          ──→ OWASP Dependency-Track       ──→ Component index + vuln correlation
                              (NVD + OSS Index + GitHub     (6 vuln sources, EPSS, policy engine)
                               + Snyk + OSV + VulnDB)
SARIF 2.1.0             ──→ NormalizedSARIF              ──→ Finding index
CVE JSON                ──→ NormalizedCVEFeed            ──→ CVE correlation
CNAPP findings          ──→ NormalizedCNAPP              ──→ Cloud exposure
VEX assertions          ──→ NormalizedVEX                ──→ Exploitability
Business context        ──→ NormalizedBusinessContext     ──→ Impact assessment

OWASP DC+DT PIPELINE (replaces lib4sbom):
──────────────────────────────────────────
Source/manifests → DC CLI scan → CPE matching → CycloneDX BOM
  → DT REST API ingestion → NVD/OSS Index/GitHub/Snyk/OSV/VulnDB correlation
  → Policy engine (fail on CVSS ≥ threshold) → EPSS prioritization
  → Impact analysis (which projects affected?) → TrustGraph Core 1 ingestion
  → sbom_runtime_correlator.py: +0.30 runtime, -0.20 tree-shaken, +0.50 shadow

ENRICHMENT                         FORECASTING                      VERDICT
──────────                         ───────────                      ───────
For each CVE:                      Bayesian odds update:            _compute_verdict():
 ├── Extract CVSS (v3.1/3.0/2.0)  ├── Prior = EPSS score            ├── p_exploit = forecast.p_exploit_now
 ├── Extract CWE IDs               ├── LR: KEV-listed → +0.85        ├── if KEV: max(p, 0.85)
 ├── Check KEV catalog             ├── LR: vendor_advisory → *0.8    ├── if attack_path: max(p, 0.70)
 ├── Query EPSS score              ├── LR: age → decay function      ├── if no_path & high_p: p *= 0.7
 ├── Count ExploitDB refs          ├── LR: CWE type → severity       ├── if low_reachability: p *= 0.5
 ├── Calculate age_days            └── → ForecastResult               ├── confidence = (forecast + llm) / 2
 └── → EnrichmentEvidence              (p_exploit_now, p_30d)         └── VERDICT:
                                                                           exploitable (p ≥ 0.70)
THREAT MODEL                       COMPLIANCE MAPPING                      not_exploitable (p ≤ 0.15)
────────────                       ──────────────────                      needs_review (else)
Parse CVSS vector (AV/AC/PR/UI)   Cross-ref severity + CWE →
├── attack_path_found (bool)       compliance controls (PCI,SOC2,
├── reachability: AV=Net(+0.4),   ISO27001, NIST)
│   AC=Low(+0.3), PR=None(+0.3)  → ComplianceMappingResult
├── exposure_level (internet/      (gaps, mapped_controls)
│   partner/internal)
└── → ThreatModelResult
```

### 1.6 28+ Threat Intelligence Feeds (verified class hierarchy)

```
ThreatIntelligenceFeed (ABC) — risk/feeds/base.py
├── NVDFeed                              (risk/feeds/nvd.py)
├── OSVFeed                              (risk/feeds/osv.py)
├── GitHubSecurityAdvisoriesFeed         (risk/feeds/github.py)
├── EXPLOIT FEEDS (risk/feeds/exploits.py):
│   ├── ExploitDBFeed
│   ├── VulnersFeed
│   ├── AlienVaultOTXFeed
│   ├── AbuseCHURLHausFeed
│   ├── AbuseCHMalwareBazaarFeed
│   ├── AbuseCHThreatFoxFeed
│   └── Rapid7AttackerKBFeed
├── VENDOR FEEDS (risk/feeds/vendors.py):
│   ├── MicrosoftSecurityFeed, AppleSecurityFeed
│   ├── AWSSecurityFeed, AzureSecurityFeed
│   ├── OracleSecurityFeed, CiscoSecurityFeed
│   ├── VMwareSecurityFeed, DockerSecurityFeed
│   └── KubernetesSecurityFeed
├── ECOSYSTEM FEEDS (risk/feeds/ecosystems.py):
│   ├── NPMSecurityFeed, PyPISecurityFeed
│   ├── RubySecFeed, RustSecFeed, GoVulnDBFeed
│   ├── MavenSecurityFeed, NuGetSecurityFeed
│   └── DebianSecurityFeed, UbuntuSecurityFeed, AlpineSecDBFeed
└── ThreatIntelligenceOrchestrator       (risk/feeds/orchestrator.py)
```

### 1.7 Critical Execution Flows (code-review-graph criticality analysis)

| Flow | Criticality | Depth | Nodes | Files | Description |
|---|---|---|---|---|---|
| `main` | 0.98 | 8 | 35 | 7 | Primary CLI entry point |
| `test_run_demo_pipeline_*` | 0.97 | 7 | 33 | 7 | Demo pipeline tests (3 variants) |
| `api_client` / `client` | 0.96 | 6 | 34 | 13 | SDK client variants (16 instances) |
| `analyze` | 0.93 | 3 | 23 | 5 | Core analysis entry point |
| `run` | 0.92 | 2 | 46 | 23 | Pipeline orchestrator (broadest) |
| `_handle_ingest` | 0.90 | 7 | 37 | 4 | Data ingestion handler |
| `_handle_make_decision` | 0.90 | 7 | 38 | 4 | Decision making handler |
| `_handle_analyze` | 0.90 | 7 | 38 | 4 | Analysis handler |

### 1.8 What v1 Got WRONG About Current State

| Claim in v1 | Reality (v2 verified) |
|---|---|
| "No production frontend" | **Two React frontends**: `suite-ui/aldeci/` (Intelligence Hub v2.0, 12+ pages, Radix UI) + `suite-ui/aldeci-ui-new/` (CTEM 5-Space, React 19, Playwright e2e) |
| "No vector store" | **ChromaVectorStore + InMemoryVectorStore + SecurityPatternMatcher** exist in `core/vector_store.py` |
| "No RAG/semantic search" | **SecurityPatternMatcher** does pattern-based semantic matching; ChromaDB with `all-MiniLM-L6-v2` embeddings exists |
| "~40+ endpoints" | **137+ endpoints** verified by `test_all_137_endpoints_e2e.py` |
| "4 LLM providers" | **5 providers** (including DeterministicLLMProvider fallback) + enterprise legacy `AdvancedLLMEngine` + `ChatGPTClient` |
| "NIST/PCI/ISO only" | **Also has SSVC framework** (`ssvc/` with DecisionDeployer, ExploitationStatus, etc.) |
| "No knowledge graph" | **Two KG implementations**: `services/graph/graph.py` (ProvenanceGraph) AND `archive/enterprise_legacy/src/services/knowledge_graph.py` (KnowledgeGraphBuilder with CTINexusEntityExtractor) |
| "11 integration files" | **20+ integration points** including IDE adapter, pentagi, pipeline orchestrator, upload manager, etc. |
| Missing OSS tool integration | **Trivy, OPA, Sigstore, Grype** scanners in enterprise legacy |
| No fix/remediation engine | **FixEngine + FixRecommendation** exists in enterprise legacy |
| No explainability | **ExplainabilityService** exists in enterprise legacy |
| No RL/learning | **ReinforcementLearningController** with Experience replay exists in enterprise legacy |

### 1.9 Enterprise Legacy Assets Worth Resurrecting

These classes in `archive/enterprise_legacy/` represent significant engineering effort that should be modernized and re-integrated:

| Asset | Location | Value for TrustGraph Integration |
|---|---|---|
| `KnowledgeGraphBuilder` | services/knowledge_graph.py (48 funcs) | Entity extraction logic → TrustGraph OntologyRAG |
| `CTINexusEntityExtractor` | services/knowledge_graph.py | Threat intel entity extraction → Core 2 |
| `CorrelationEngine` | services/correlation_engine.py | Finding correlation → TrustGraph graph traversal |
| `AdvancedLLMEngine` | services/advanced_llm_engine.py | Multi-LLM orchestration → LLM Council |
| `ReinforcementLearningController` | services/rl_controller.py | Decision learning → Core 4 feedback loop |
| `ComplianceEngine` | services/compliance_engine.py | Full compliance evaluation → Core 3 |
| `FixEngine` | services/fix_engine.py | Automated remediation → AutoFix agent |
| `ExplainabilityService` | services/explainability.py | Decision explanations → PROV-O traces |
| `MarketplaceService` | services/marketplace.py | Content marketplace → Plugin ecosystem |
| `GoldenRegressionStore` | services/golden_regression_store.py | Test regression → Quality gate |
| `EvidenceLake` | services/evidence_lake.py | Evidence storage → TrustGraph evidence core |
| `SecurityManager + RBACManager` | core/security.py | Auth/authz → Multi-tenant TrustGraph |
| `TrivyScanner + GrypeScanner` | services/oss_integrations.py | Scanner integration → Feed pipeline |
| `OPAEngine` | services/real_opa_engine.py | Policy-as-code → Core 3 enforcement |
| `ContextualRiskScorer` | services/risk_scorer.py | Contextual scoring → TrustGraph context |
| `CybersecurityLLMEngine` | services/llm_explanation_engine.py | Domain-specific prompts → Council |
| `KeyProvider + AWSKMSProvider` | utils/crypto.py (71 funcs) | Key management → Evidence encryption |

### 1.10 Actual vs Previously Claimed Gap Analysis

| Capability | v1 Claim | v2 Reality | TrustGraph Upgrade |
|---|---|---|---|
| Persistent Knowledge Graph | "No" | **Partial** (NetworkX + SQLite) | Full Neo4j/FalkorDB with GraphRAG |
| RAG / Semantic Search | "No" | **Partial** (ChromaDB + MiniLM) | TrustGraph GraphRAG + OntologyRAG |
| Attack Path Analysis | "No" | **Partial** (reachability scoring) | Full graph traversal + toxic combos |
| Code-to-Runtime Tracing | "No" | **No** (genuinely missing) | Core 1 component → cloud → runtime graph |
| AI AutoFix / Remediation | "No" | **Yes** (FixEngine in archive) | Resurrect + LLM Council for fix quality |
| Noise Reduction | "Partial" | **Partial** (deterministic) | Decision Memory Core for learning |
| LLM Consensus | "Weighted voting" | **Weighted voting + fallback** | Karpathy 3-stage Council |
| Frontend | "None" | **React + Vite + Radix UI (2 apps, 12+ pages)** | Integrate TrustGraph 3D GraphViz into @xyflow/react |
| Test Coverage | "Unknown" | **1,536 tests, 140+ files** | Maintain through rearchitecture |

---

## Part 2: TrustGraph Integration — 100% Capabilities

### Why TrustGraph Is THE Layer

TrustGraph is not just a graph database — it's a **context development platform** that solves ALDECI's deepest architectural gaps:

1. **GraphRAG**: Vector similarity → graph node → relationship traversal. Finds connections humans miss. Replaces ALDECI's fragmented ChromaDB + NetworkX with unified search.
2. **OntologyRAG**: Schema-driven extraction from unstructured text using OWL ontologies. Replaces manual entity extraction in `KnowledgeGraphBuilder`.
3. **Context Cores**: Versioned, portable knowledge bundles with ontologies + embeddings + graph data + retrieval policies. Nothing in ALDECI does this today.
4. **40+ LLM providers**: Including Ollama (free models), OpenAI, Anthropic — no vendor lock-in. Extends ALDECI's 5 providers massively.
5. **MCP integration**: Agents connect to external tools/services via Model Context Protocol. Replaces custom `_BaseConnector` pattern.
6. **Apache Pulsar streaming**: Real-time data ingestion. Replaces batch-mode feed processing in `ThreatIntelligenceOrchestrator`.
7. **Multi-tenancy**: Database-level, graph-level, or namespace-level isolation. Extends ALDECI's `TenantLifecycleManager`.
8. **Apache 2.0**: Fully open source, self-hostable.

### ALDECI Knowledge Core Architecture (HuntBase Pattern)

Inspired by HuntBase SecOps, ALDECI gets **5 isolated Knowledge Cores**:

```
┌─────────────────────────────────────────────────────────────────┐
│                    ALDECI TrustGraph Layer                       │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐  ┌──────────────┐  ┌───────────────────────┐ │
│  │   CORE 1     │  │   CORE 2     │  │      CORE 3           │ │
│  │  Customer     │  │  Threat      │  │  Compliance &         │ │
│  │  Environment  │  │  Intelligence│  │  Regulatory           │ │
│  │              │  │              │  │                       │ │
│  │ Replaces:    │  │ Replaces:    │  │ Replaces:             │ │
│  │ ProvenanceGr │  │ 28 feed      │  │ ComplianceEvaluator   │ │
│  │ NetworkX     │  │ classes +    │  │ SSDLCEvaluator        │ │
│  │ SQLite store │  │ Orchestrator │  │ ComplianceMapping     │ │
│  │              │  │              │  │ OPAEngine             │ │
│  │ + Adds:      │  │ + Adds:      │  │ SSVC Framework        │ │
│  │ Code→Cloud   │  │ GraphRAG     │  │                       │ │
│  │ tracing      │  │ OntologyRAG  │  │ + Adds:               │ │
│  │ Attack paths │  │ Streaming    │  │ SOC2, HIPAA, FedRAMP  │ │
│  │ Toxic combos │  │ ingestion    │  │ CIS, OWASP            │ │
│  └──────┬───────┘  └──────┬───────┘  └──────────┬────────────┘ │
│         │                 │                      │              │
│  ┌──────┴───────┐  ┌──────┴──────────────────────┴────────────┐ │
│  │   CORE 4     │  │              CORE 5                      │ │
│  │  Decision     │  │  Competitive Intelligence               │ │
│  │  Memory       │  │                                         │ │
│  │              │  │ Replaces:                                │ │
│  │ Replaces:    │  │ Manual competitive analysis              │ │
│  │ FeedbackRec  │  │                                         │ │
│  │ GoldenRegSt  │  │ + Adds:                                 │ │
│  │ RL Controller│  │ Automated feature parity tracking        │ │
│  │              │  │ Competitor graph models                  │ │
│  │ + Adds:      │  │                                         │ │
│  │ PROV-O       │  │                                         │ │
│  │ RDF triples  │  │                                         │ │
│  │ Learning loop│  │                                         │ │
│  └──────────────┘  └─────────────────────────────────────────┘ │
│                                                                 │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │              TRUSTGRAPH INFRASTRUCTURE                      ││
│  │  Graph: Neo4j/FalkorDB  |  Vector: Qdrant  |  Stream: Pulsar││
│  │  LLM: Ollama (Qwen/Gemma/DeepSeek) + Opus CTO Review      ││
│  │  SDK: Python trustgraph  |  API: REST + WebSocket + MCP    ││
│  └─────────────────────────────────────────────────────────────┘│
└─────────────────────────────────────────────────────────────────┘
```

### Core-by-Core Integration with Existing Code

**Core 1 — Customer Environment** (replaces ProvenanceGraph + extends)
- Current: `services/graph/graph.py` → ProvenanceGraph (NetworkX, SQLite, 42 functions)
- Migration: Preserve lineage/reachability/impact query interfaces, back with TrustGraph
- Adds: Code-to-cloud tracing, toxic combination detection, real-time Pulsar ingestion
- Ingests: All 6 normalized input types (SBOM, SARIF, CVE, CNAPP, VEX, BusinessContext)

**Core 2 — Threat Intelligence** (replaces ThreatIntelligenceOrchestrator + extends)
- Current: 28 feed classes in `risk/feeds/` streaming to in-memory enrichment
- Migration: Keep feed parsers, route output to TrustGraph via Pulsar instead of in-memory
- Adds: GraphRAG for threat chain discovery, OntologyRAG for auto-extracting threat reports
- Resurrect: `CTINexusEntityExtractor` from enterprise legacy for entity extraction

**Core 3 — Compliance & Regulatory** (replaces ComplianceEvaluator + SSVC + extends)
- Current: `core/compliance.py` + `core/ssdlc.py` + `ssvc/` + `compliance/mapping.py`
- Migration: Import all control mappings into TrustGraph, keep evaluation interfaces
- Adds: SOC2, HIPAA, FedRAMP, CIS Benchmarks, OWASP Top 10 (OntologyRAG extraction)
- Resurrect: `ComplianceEngine` from enterprise legacy for full evaluation

**Core 4 — Decision Memory** (replaces FeedbackRecorder + GoldenRegressionStore + extends)
- Current: `core/feedback.py` + enterprise legacy `GoldenRegressionStore` + `RL Controller`
- Migration: Store all decisions as RDF triples with W3C PROV-O provenance
- Adds: Continuous learning loop, false positive corrections, decision pattern mining
- Resurrect: `ReinforcementLearningController` for decision optimization

**Core 5 — Competitive Intelligence** (new capability)
- Current: Nothing
- Adds: Automated competitor feature tracking, gap analysis, roadmap alignment

---

## Part 3: LLM Consensus (Karpathy Pattern) Replacing Weighted Voting

### Current Implementation Detail (verified)

ALDECI's `MultiLLMConsensusEngine` (core/enhanced_decision.py, 1,279 lines):
- `ProviderSpec` with weight (1.0 default), style ("consensus"/"analyst"/"signals"), focus areas
- Parallel invocation of 4 providers, each returns `LLMResponse`
- Aggregate: weighted voting on recommended_action, confidence averaging
- Error handling: timeout → fallback to deterministic; HTTP error → retry; parse error → default
- Tracks: `processing_time_ms`, `cost_usd` per provider

**Critical flaws**:
1. No peer review — models don't see each other's reasoning
2. Hardcoded weights — no adaptation based on accuracy
3. No disagreement escalation — just averages when they disagree
4. 3 of 4 active providers are paid APIs ($$$)
5. No provenance tracking of decision rationale

### Karpathy LLM Council — 3-Stage Replacement

```
┌────────────────────────────────────────────────────────────────┐
│                 ALDECI LLM COUNCIL ENGINE                      │
│                                                                │
│  Replaces: MultiLLMConsensusEngine (core/enhanced_decision.py) │
│  Extends: BaseLLMProvider hierarchy (core/llm_providers.py)    │
│  Resurrects: AdvancedLLMEngine (enterprise legacy)             │
├────────────────────────────────────────────────────────────────┤
│                                                                │
│  STAGE 1: INDEPENDENT ANALYSIS (4 free models)                 │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐         │
│  │ Qwen 3   │ │ Gemma 4  │ │DeepSeek  │ │ Llama 4  │         │
│  │ (router) │ │ (local)  │ │ V3 (rtr) │ │ (router) │         │
│  └────┬─────┘ └────┬─────┘ └────┬─────┘ └────┬─────┘         │
│       ▼             ▼            ▼             ▼               │
│  Same LLMResponse interface: {action, confidence, reasoning,   │
│   mitre_techniques, compliance_concerns, attack_vectors}       │
│                                                                │
│  STAGE 2: ANONYMOUS PEER REVIEW                                │
│  Each model reviews all other verdicts (anonymized as A,B,C,D) │
│  Returns: {agree/disagree, confidence_adjustment, reasoning}   │
│                                                                │
│  STAGE 3: CHAIRMAN SYNTHESIS                                   │
│  IF consensus (3/4+ agree): Qwen 3 synthesizes → Cost: $0     │
│  IF disagreement (2/2 split): ESCALATE to Opus → Cost: $0.05  │
│                                                                │
│  OUTPUT → Core 4 (Decision Memory) as RDF triples              │
│  {verdict, confidence, reasoning_chain, consensus_score,       │
│   dissenting_opinions, provenance_triple}                      │
└────────────────────────────────────────────────────────────────┘
```

### Integration Points for Council

| Current Code | Council Change | Details |
|---|---|---|
| `core/llm_providers.py` | Add `OllamaProvider` + `OpenRouterProvider` extending `BaseLLMProvider` | Same `LLMResponse` interface |
| `core/enhanced_decision.py` | Replace `MultiLLMConsensusEngine` with `LLMCouncilEngine` | 3-stage pipeline |
| `core/decision_tree.py` | Steps 5-6 call Council instead of old consensus | Keep same `DecisionTreeResult` output |
| `core/feedback.py` | Route corrections to Core 4 Decision Memory | Train Council accuracy |
| Enterprise `AdvancedLLMEngine` | Resurrect multi-provider orchestration patterns | Merge into Council |
| Enterprise `ExplainabilityService` | Integrate for decision explanation generation | PROV-O traces |

---

## Part 4: Competitive Annihilation Strategy — Deep Dive (9 Competitors)

### ALDECI's Mission (Reiterated)

**ALDECI is the world's best ASPM + CTEM + CSPM platform** — a unified, self-hosted, AI-native security intelligence platform that:
1. Replaces $50K-500K+/yr enterprise tools with a pricing TBD (target: $199-$1,499/month tiered) self-hosted stack
2. Uses TrustGraph (5 Knowledge Cores) for versioned, auditable security knowledge management
3. Employs Karpathy LLM Consensus (4 free models + Opus CTO escalation) for explainable, peer-reviewed security decisions
4. Covers the complete security lifecycle: code → build → deploy → runtime → compliance → remediation
5. Learns from every decision via Decision Memory (Core 4) + ReinforcementLearningController
6. Provides mathematical transparency via SSVC + Bayesian + Markov risk models (no black-box AI)
7. Supports 28+ threat intelligence feeds — broadest in the industry
8. Is fully open-source (Apache 2.0 TrustGraph, free LLMs, self-hosted everything)

Every architectural decision below serves this mission. Every feature stolen from competitors is adapted to fit TrustGraph-native, LLM Council-driven, self-hosted philosophy.

---

### 4.1 Competitor Deep Dive: Apiiro

**Category**: ASPM (Agentic Application Security Platform)
**Gartner**: #1 ASPM 2025-2026
**Pricing**: $100K-500K+/year enterprise

#### Apiiro's Complete Feature Set

| Feature | Details | ALDECI Answer |
|---|---|---|
| **Risk Graph™** | Proprietary graph connecting code, runtime, databases, tools. Maps APIs, microservices, dependencies, sensitive data. Contextualizes findings based on business + app architecture. | **TrustGraph Core 1** (Customer Environment) — same graph capabilities PLUS versioned snapshots, GraphRAG semantic search, OntologyRAG auto-extraction, and Apache 2.0 open source |
| **Deep Code Analysis (DCA)** | Patented semantic analysis of source code architecture. Auto-discovers APIs, microservices, dependencies, data flows. | **code-review-graph** (17,936 nodes, 103,950 edges) + TrustGraph OntologyRAG. ALDECI's `suite-core/core/sbom_runtime_correlator.py` already does code-to-runtime matching. Add: AST-level semantic analysis via Tree-sitter → TrustGraph ingestion. |
| **XBOM** | Extended SBOM: technologies, frameworks, components, contributors, risks, interconnections, changes over time. | **OWASP DC → DT pipeline** generates CycloneDX BOM, TrustGraph Core 1 adds contributor/risk/change-over-time dimensions via RDF triples. XBOM = Core 1 GraphRAG query. |
| **Material Code Change Detection** | Monitors commits/PRs for changes impacting attack surface. Supports PCI, SOC 2 compliance triggers. | **New**: Add git webhook → code-review-graph blast radius analysis → TrustGraph Core 1 delta update → LLM Council risk assessment of changed code. Leverage existing `suite-core/core/stage_runner.py` pipeline. |
| **Code-to-Runtime Context** | Connects static code analysis with runtime exposure assessment. | **Existing**: `sbom_runtime_correlator.py` (27KB) already fuzzy-matches runtime packages against SBOM inventory with risk deltas (+0.30 runtime, -0.20 tree-shaken, +0.50 shadow). Extend with eBPF runtime signals. |
| **AI Threat Modeling** | Generates threats and mitigations before code exists. | **New**: LLM Council threat modeling agent — given a design doc or PR description, Council generates STRIDE/DREAD analysis stored in Core 2. Leverage existing `risk/threat_model.py`. |
| **AutoFix Agent** | Automated remediation across Design, Develop, Deliver phases. | **Existing**: Enterprise legacy `FixEngine` (resurrect) + LLM Council consensus = multi-model AutoFix PRs vs Apiiro's single-model. |
| **Policy Builder** | Granular, multidimensional, business-specific risk policies. | **Existing**: `core/flags/` feature flag system + `ssvc/` SSVC framework + OWASP DT policy engine + TrustGraph Core 3 compliance rules. Combined: richer policy than Apiiro. |
| **Developer Guardrails** | Risk-based gates ensuring only critical risks block releases. | **New**: OWASP DC `failBuildOnCVSS` + DT policy engine + LLM Council confidence threshold gates. Wire into `suite-core/core/stage_runner.py`. |
| **API Inventory & Security** | Discover and test APIs in code. | **New**: Extract API definitions from OpenAPI/Swagger specs → TrustGraph Core 1. Use DAST agent (OpenClaw) to test discovered endpoints. Leverage `suite-api/` router definitions. |
| **Secrets Security** | Detect, validate, fix, prevent exposure. | **New**: Integrate TruffleHog or Gitleaks scanner → TrustGraph Core 1 as secret-exposure entities. |
| **Sensitive Data Detection** | Identify PII, PHI, PCI data exposure in code. | **New**: Regex + NER-based scanner via LLM Council → flag sensitive data patterns in source → store in Core 1 with compliance linkage to Core 3. |
| **Enterprise Reporting** | Dashboards, benchmarking, compliance reports. | **Existing**: `suite-ui/aldeci/` Intelligence Hub already has CEODashboard, SecurityPostureCard, RiskScoreGauge, CTEMProgressRing. Extend with TrustGraph-backed historical trending. |

#### Architecture Additions from Apiiro Analysis

```
NEW COMPONENTS TO ADD:
├── Material Change Detector
│   ├── Git webhook listener → code-review-graph delta analysis
│   ├── Blast radius calculation (which Core 1 entities affected?)
│   └── Auto-trigger LLM Council risk assessment on material changes
├── API Discovery Engine
│   ├── OpenAPI/Swagger spec parser → Core 1 API entities
│   ├── Route extraction from FastAPI/Express/Spring definitions
│   └── DAST agent (OpenClaw) auto-test discovered endpoints
├── Sensitive Data Scanner
│   ├── Regex patterns for PII/PHI/PCI
│   ├── LLM-assisted NER for custom sensitive data types
│   └── Core 1 sensitive-data-flow entities → Core 3 compliance check
└── AI Threat Modeler
    ├── PR/design doc → STRIDE/DREAD analysis via LLM Council
    ├── Threat → Core 2 threat entity linkage
    └── Mitigation recommendations → Core 4 Decision Memory
```

---

### 4.2 Competitor Deep Dive: Aikido Security

**Category**: Unified Security Platform (Code to Runtime)
**Recognition**: 50K+ orgs, 100K+ developers, SOC 2 Type II + ISO 27001
**Pricing**: Free tier → $350-1050/mo

#### Aikido's Complete Feature Set

| Feature | Details | ALDECI Answer |
|---|---|---|
| **SAST** | Static analysis scanning source code before merge. Multi-language. | **Existing**: `suite-core/core/sast/` SAST engine + Semgrep integration. Enhance: LLM Council peer-reviews SAST findings for false positive filtering. |
| **SCA** | CVE detection in open-source dependencies. Malware detection via Aikido Intel. EOL/outdated checks. License risk monitoring. | **Replaced**: OWASP DC+DT pipeline handles all SCA with 6 vuln sources. Add: LLM Council malware analysis of suspicious packages (like Aikido Intel but multi-model). |
| **DAST** | Surface monitoring, API testing, simulated attacks. | **New**: Deploy OpenClaw DAST agents via TrustGraph MCP → test all discovered APIs → findings to Core 1. Leverage existing `suite-integrations/mpte-aldeci/` attack infrastructure. |
| **Container Scanning** | OS package vulns in container images. Kubernetes runtime with container reachability. | **Existing**: Docker scanning in `suite-core/`. Enhance: OWASP DC container analyzer + DT container project tracking + Kubernetes admission webhook. |
| **IaC Scanning** | Terraform, CloudFormation, Kubernetes manifest misconfigs. | **Existing**: IaC router in `suite-api/apps/api/`. Enhance: Checkov/tfsec integration → findings to Core 1 → Core 3 compliance mapping. |
| **Secrets Detection** | API keys, passwords, certificates, encryption keys in code. | **New**: TruffleHog/Gitleaks integration → Core 1. Pre-commit hook blocking. |
| **Cloud Posture (CSPM)** | Multi-cloud misconfiguration detection. | **Existing**: CNAPP normalization in `InputNormalizer`. Enhance: AWS/Azure/GCP API scanning → Core 1 cloud-resource entities. |
| **Runtime Protection** | In-app firewall, injection blocking, API rate limiting. | **New**: eBPF-based runtime agent (Falco/Tetragon) → real-time telemetry to TrustGraph via Pulsar. Runtime protection = eBPF blocking rules + LLM Council threat assessment. |
| **AI AutoFix** | One-click PRs, bulk multi-issue patches, TL;DR summaries. | **Existing**: `FixEngine` (resurrect) + LLM Council consensus. Multi-model AutoFix > single Claude Sonnet. Bulk fix via batch Council processing. |
| **AI Pentesting (200+ agents)** | Agents dispatched on features/endpoints, each focused on specific attack vector. Validate exploitability. Auto-open fix PRs. Money-back guarantee. | **New**: OpenClaw pentest swarm — deploy multiple autonomous agents each targeting different attack surfaces. LLM Council validates findings (4-model consensus reduces hallucinations). Store pentest results in Core 4. |
| **Aikido Infinite** | Continuous AI pentesting on every release. Self-remediating. | **New**: Git push webhook → Material Change Detector → auto-dispatch pentest agents on changed endpoints → Council-validated findings → auto-fix PRs. Continuous loop. |
| **95% Noise Reduction** | AutoTriage contextualizing alerts. Custom exclusion rules. Deduplication. | **ALDECI target: 97%+** via Decision Memory (Core 4) + RL Controller learning from corrections + 4-model Council consensus (4x the false-positive detection surface). |
| **SBOM Generation** | Produces SBOMs from scanned code. | **Replaced**: OWASP DC generates CycloneDX SBOMs. Existing `suite-evidence-risk/risk/sbom/generator.py` also generates SBOMs from source analysis. |

#### Architecture Additions from Aikido Analysis

```
NEW COMPONENTS TO ADD:
├── OpenClaw Pentest Swarm
│   ├── Agent-per-attack-vector architecture (like Aikido's 200+)
│   ├── Sandboxed execution environments (Docker per agent)
│   ├── LLM Council validation of all findings (no hallucinations)
│   ├── Auto-PR generation for validated vulns
│   └── Continuous-on-release via Material Change Detector webhook
├── Runtime Protection Layer (eBPF)
│   ├── Falco/Tetragon for kernel-level syscall monitoring
│   ├── Real-time injection blocking rules
│   ├── API rate limiting enforcement
│   ├── Telemetry → Pulsar → TrustGraph Core 1
│   └── Runtime findings enrich sbom_runtime_correlator.py
├── License Risk Engine
│   ├── SPDX license detection in dependencies
│   ├── Dual-license / copyleft / restrictive license flagging
│   ├── Core 3 compliance policy linkage
│   └── DT policy engine license compliance rules
└── Malware Detection (Aikido Intel equivalent)
    ├── LLM Council analysis of suspicious package behavior
    ├── Typosquatting detection (Levenshtein distance on package names)
    ├── Behavioral analysis of package install scripts
    └── Core 2 threat intel integration
```

---

### 4.3 Competitor Deep Dive: Wiz

**Category**: CNAPP (Cloud-Native Application Protection Platform)
**Gartner/Forrester**: #1 CNAPP Leader (Forrester Wave Q1 2026, highest in 10/12 criteria)
**Pricing**: $50K-500K+/year (acquired by Google for $32B)

#### Wiz's Complete Feature Set

| Feature | Details | ALDECI Answer |
|---|---|---|
| **Security Graph** | Maps every cloud resource, identity, network path, vulnerability into unified graph. Checks: running? Internet-facing? What identity? Can reach sensitive data? | **TrustGraph Core 1** — same capability with versioned snapshots + GraphRAG semantic search. Core 1 ingests cloud resources as RDF entities with relationships. Add: identity-to-resource-to-data path analysis via GraphRAG traversal. |
| **Agentless Scanning** | No agents deployed. Scans cloud config + workload block storage. Minutes to deploy, covers 100% of assets. | **Hybrid approach**: Agentless cloud API scanning (AWS/Azure/GCP SDK calls) + optional eBPF agent for runtime. ALDECI advantages: runtime telemetry (agents see what agentless misses) + code-level analysis (Wiz only sees cloud). |
| **Multi-Cloud** | AWS, Azure, GCP, OCI, Alibaba, VMware vSphere, Kubernetes. | **New**: Extend CNAPP normalization in `InputNormalizer` with cloud-specific collectors. AWS (boto3), Azure (azure-mgmt), GCP (google-cloud). Kubernetes already covered. Store in Core 1 per-tenant. |
| **Wiz Code** | Scans repos, CI/CD pipelines, container registries, images. 1-click fix PRs. | **Existing + Enhanced**: SAST + SCA + Container scanning + OWASP DC pipeline + LLM Council AutoFix. Multi-model fix PRs > single-model 1-click. |
| **Wiz Cloud** | CSPM, CWPP, CIEM, vulnerability scanning, IaC checks. Agentless posture management. | **Covered by ALDECI modules**: CSPM (CNAPP normalization), IaC scanning, vulnerability scanning (28+ feeds + OWASP DC+DT). Add: CIEM identity entitlement analysis via cloud SDK + Core 1 identity entities. |
| **Wiz Defend** | eBPF-based runtime protection, threat detection, real-time monitoring. | **New**: eBPF runtime layer (Falco/Tetragon) → Pulsar → TrustGraph. Same eBPF approach as Wiz Defend but integrated with knowledge graph. |
| **Toxic Combination Detection** | Graph-based identification of multi-factor risk combinations (e.g., internet-facing + critical CVE + admin identity + sensitive data access). | **TrustGraph GraphRAG**: Toxic combo queries become GraphRAG traversals across Core 1. "Find all entities where: internet_facing=true AND has_critical_cve=true AND identity_is_admin=true AND accesses_sensitive_data=true." More flexible than Wiz's fixed graph patterns. |
| **DSPM (Data Security)** | Sensitive data discovery across cloud storage. | **New**: Cloud storage scanner (S3/Blob/GCS) → regex + NER for PII/PHI/PCI → Core 1 data-flow entities → Core 3 compliance (GDPR, HIPAA, PCI-DSS). |
| **AI CNAPP** | Agentic AI copilots for cloud security. AI-native detection and response. | **LLM Council** is the AI layer — 4-model consensus for cloud security decisions. More transparent than Wiz's proprietary AI. |
| **Attack Path Analysis** | Cross-environment risk assessment. Visual attack paths. | **Existing**: `suite-ui/aldeci/src/components/aldeci/AttackPathGraph.tsx` already visualizes attack paths via @xyflow/react. Back with TrustGraph GraphRAG for real graph traversal. |

#### Architecture Additions from Wiz Analysis

```
NEW COMPONENTS TO ADD:
├── Cloud Identity & Entitlement Management (CIEM)
│   ├── AWS IAM / Azure AD / GCP IAM policy analysis
│   ├── Over-privileged identity detection
│   ├── Identity-to-resource-to-data path mapping in Core 1
│   └── Least-privilege recommendations via LLM Council
├── Data Security Posture Management (DSPM)
│   ├── S3/Blob/GCS bucket scanning for sensitive data
│   ├── Database schema analysis for PII/PHI columns
│   ├── Data flow mapping: source → transform → sink
│   └── Core 1 data-entity nodes with Core 3 compliance edges
├── Toxic Combination Engine
│   ├── GraphRAG multi-hop queries across Core 1
│   ├── Predefined toxic combo patterns (OWASP Top 10 Cloud)
│   ├── Custom combo rules via policy engine
│   └── Alert: "Critical: internet-facing + admin + CVE-2024-xxx + PII access"
└── Agentless Cloud Collector
    ├── AWS: boto3 (EC2, S3, IAM, Lambda, ECS, EKS)
    ├── Azure: azure-mgmt (VMs, Storage, AD, AKS)
    ├── GCP: google-cloud (Compute, Storage, IAM, GKE)
    └── Kubernetes: kubectl API (workloads, RBAC, network policies)
```

---

### 4.4 Competitor Deep Dive: Orca Security

**Category**: CNAPP (AI-Powered Agentless Cloud Security)
**Gartner**: CNAPP Leader
**Key Tech**: Patented SideScanning

#### Orca's Complete Feature Set

| Feature | Details | ALDECI Answer |
|---|---|---|
| **SideScanning™** | Patented: reads cloud config + workload runtime block storage out-of-band. No agents, no network packets, no code execution on target. Complete risk profile in <24 hours. | **Different philosophy**: ALDECI uses code-first analysis (SAST + SCA + SBOM) + optional eBPF agent. SideScanning is cloud-only; ALDECI covers code + cloud + runtime. For cloud-only orgs needing agentless, Orca is complementary. |
| **Unified Data Model** | Single model across VMs, containers, serverless, storage, VPCs, KMS keys. Auto-discovers new assets. | **TrustGraph Core 1** — unified RDF data model for all entity types. Auto-discovery via cloud SDK collectors + SBOM + runtime correlator. More extensible than Orca's proprietary model. |
| **AI Remediation Guidance** | Natural language remediation instructions. AI-powered prioritization. | **LLM Council** — 4-model consensus remediation with peer review. More thorough than single-model guidance. Stored in Core 4 for learning. |
| **Natural Language Search** | Query cloud assets in natural language. | **TrustGraph GraphRAG** — natural language queries resolved to graph traversals. "Show me all internet-facing containers with critical CVEs running in production." |
| **Vulnerability + Malware + Misconfig + IAM + Sensitive Data** | All-in-one scanning across all asset types. | **ALDECI covers all 5**: Vulnerability (OWASP DC+DT + 28 feeds), Malware (LLM Council analysis), Misconfig (IaC + CSPM), IAM (CIEM module), Sensitive Data (DSPM module). |
| **Lateral Movement Risk** | Identifies paths attackers could use to move between assets. | **TrustGraph GraphRAG** — attack path traversal across network topology, identity relationships, and data flows stored in Core 1. More sophisticated than flat graph queries. |
| **CI/CD Integration** | Pipeline scanning and integration. | **Existing**: OWASP DC CI/CD plugins + `suite-core/core/stage_runner.py` pipeline + GitHub Actions/Jenkins integration. |

---

### 4.5 Competitor Deep Dive: CrowdStrike

**Category**: CTEM (Continuous Threat Exposure Management) + Endpoint
**Recognition**: Market leader in endpoint + exposure management
**Key Tech**: ExPRT.AI, Falcon platform, single lightweight agent

#### CrowdStrike's Complete Feature Set

| Feature | Details | ALDECI Answer |
|---|---|---|
| **ExPRT.AI** | Dynamic risk scoring using real-time threat intel + global Falcon telemetry (trillions of events). Adjusts scores based on how attackers actually operate. | **ALDECI equivalent**: `ProbabilisticForecastEngine` (Bayesian odds) + EPSS + 28 feed signals + LLM Council assessment. Not as much telemetry volume, but mathematically transparent (Bayesian) vs black-box (ExPRT.AI). Add: Core 4 Decision Memory acts as ALDECI's "telemetry" — learning from every decision. |
| **Exposure Prioritization Agent** | Combines ExPRT.AI + exploitability analysis + asset criticality + adversary intel. Validates vulnerabilities, quantifies impact, provides plain-language context. | **New**: LLM Council "Exposure Prioritization" mode — given a CVE + asset context + Core 1 relationships + Core 2 threat intel, Council produces: validated exploitability, business impact score, plain-language explanation, remediation priority. Stored in Core 4. |
| **Attack Surface Discovery** | External assets, endpoints, cloud, network, OT/IoT, shadow AI. Active + passive + third-party discovery. | **Expand**: Add external attack surface discovery — Shodan/Censys integration for internet-facing asset discovery → Core 1 external-exposure entities. Existing 28 feeds include GreyNoise and Shodan signals. |
| **AI Discovery** | Real-time visibility into AI components: LLMs, AI agents, IDE extensions, MCP servers, AI-infused packages. | **New**: AI asset inventory scanner — detect AI/ML dependencies in SBOM, identify MCP servers in code, flag LLM API keys, map AI agent deployments. Store in Core 1 as ai-component entities. ALDECI is uniquely positioned here as an AI-native platform itself. |
| **Security Config Assessment** | Windows, macOS, Linux system configuration compliance. | **Existing**: OPA policy engine integration + CIS Benchmark checks in Core 3 compliance. Extend: add OS-level config assessment via agent or SSH. |
| **Network Vulnerability Assessment** | Unmanaged network asset scanning. | **New**: Nmap/Masscan integration for network asset discovery → Core 1 network-topology entities. |
| **Falcon Fusion SOAR** | Automated playbooks, ticketing, remediation orchestration. | **New**: SOAR module — LLM Council generates remediation playbooks → `FixEngine` executes → Core 4 tracks outcomes. Integrate with external SOAR (Tines, Shuffle) via webhooks. |
| **98% critical vuln reduction** | Documented customer result. | **ALDECI target: 99%** — RL Controller + Council consensus + automated remediation loop should outperform CrowdStrike's manual-escalation model. |
| **Real-time CTEM** | Continuous: discover → prioritize → validate → remediate → measure. | **ALDECI CTEM**: 28 feeds → Pulsar streaming → TrustGraph real-time update → Council assessment → `FixEngine` auto-remediate → Core 4 measure → RL Controller optimize. Full lifecycle, streaming not batch. |

#### Architecture Additions from CrowdStrike Analysis

```
NEW COMPONENTS TO ADD:
├── External Attack Surface Management (EASM)
│   ├── Shodan/Censys API integration for internet-facing assets
│   ├── DNS enumeration (subfinder/amass)
│   ├── Certificate transparency log monitoring
│   └── Core 1 external-exposure entities with risk scoring
├── AI Asset Inventory
│   ├── Detect AI/ML packages in SBOM (tensorflow, pytorch, transformers)
│   ├── Identify MCP servers, LLM API calls in source code
│   ├── Map AI agent deployments and capabilities
│   └── Core 1 ai-component entities with supply chain risk
├── SOAR Module (Security Orchestration, Automation, Response)
│   ├── LLM Council playbook generation
│   ├── FixEngine automated execution
│   ├── External SOAR integration (Tines, Shuffle, TheHive)
│   ├── Core 4 outcome tracking + RL optimization
│   └── Escalation to human when Council confidence < threshold
└── Network Discovery
    ├── Nmap/Masscan for port/service discovery
    ├── SSL/TLS certificate analysis
    ├── Core 1 network-topology entities
    └── Attack path enrichment with actual network data
```

---

### 4.6 Competitor Deep Dive: Snyk

**Category**: Developer Security Platform (SAST + SCA + Container + IaC + DAST)
**Recognition**: Developer-first security leader
**Key Tech**: DeepCode AI engine (ML-based SAST)

#### Snyk's Complete Feature Set

| Feature | Details | ALDECI Answer |
|---|---|---|
| **Snyk Code (SAST)** | DeepCode AI engine — ML trained on millions of code commits. Semantic understanding, not pattern matching. Real-time in-IDE. | **Existing**: SAST engine in `suite-core/core/sast/`. Enhance: Add Tree-sitter AST analysis + LLM Council semantic review. Council provides multi-model code understanding vs Snyk's single ML model. |
| **Snyk Open Source (SCA)** | CVE detection in third-party dependencies. | **Replaced**: OWASP DC+DT with 6 vuln sources. More data sources than Snyk's proprietary database. |
| **Snyk Container** | Container image scanning (OS + app dependencies). Base image upgrade recommendations. Registry integration (Docker Hub, ECR, GCR, ACR). | **Existing + Enhanced**: Container scanning + OWASP DC container analyzer. Add: base image recommendation engine (query DT for lowest-vuln base images). |
| **Snyk IaC** | Terraform, CloudFormation, Kubernetes, ARM template scanning. | **Existing**: IaC scanning module. Enhance: Checkov/tfsec integration + Core 3 compliance mapping. |
| **Snyk AI Security Fabric** | Secure code, models, agents. AI-generated code scanning. | **New**: AI code auditor — LLM Council reviews AI-generated code for security issues. Detect prompt injection, model poisoning, insecure API calls. Store AI security findings in Core 1. |
| **Snyk DAST** | AI-driven dynamic application security testing. | **New**: OpenClaw DAST agents with LLM Council validation. |
| **Unified Dashboard** | Single pane across all 6 products + shared policy engine. | **Existing**: `suite-ui/aldeci/` Intelligence Hub with unified dashboard, CEODashboard, NerveCenter. Already unified by design. |
| **IDE Integration** | VS Code, IntelliJ, real-time in-editor findings. | **New**: VS Code extension → ALDECI API → real-time findings in editor. Priority: add after core TrustGraph integration. |
| **Fix PRs** | Automated pull request generation for dependency upgrades. | **Existing**: `FixEngine` + LLM Council multi-model consensus PRs. |

---

### 4.7 Competitor Deep Dive: Semgrep

**Category**: SAST + SCA + Secrets (Multimodal AI AppSec)
**Recognition**: Open-source SAST leader, 2026 multimodal AI pivot
**Pricing**: Free (CE) → paid AppSec Platform

#### Semgrep's Complete Feature Set

| Feature | Details | ALDECI Answer |
|---|---|---|
| **Multimodal AI Engine** | Combines deterministic analysis with LLM reasoning. Finds IDORs, broken authz, business logic flaws. Zero false positive goal. | **ALDECI equivalent**: Deterministic SAST + LLM Council (4 models) peer review of findings. Council catches both false positives AND false negatives (4 perspectives > 1). |
| **Cross-File Analysis** | Inter-file + intra-file data flow tracking. Taint analysis. 25% fewer FPs, 250% more TPs. | **Enhance**: Add Tree-sitter inter-file data flow analysis. Existing code-review-graph already tracks 75,533 call edges — extend with taint propagation. |
| **SCA Reachability** | Flags only dependencies that are actually called in code. 98% reduction in high/critical FPs. | **Existing**: `sbom_runtime_correlator.py` already does reachability-based risk adjustment. OWASP DC provides the dependency list; correlator determines if reachable. Strengthen: Tree-sitter call graph → actual import/call chains → prune unreachable vulns. |
| **Secrets Detection** | Semantic analysis, entropy analysis, real credential validation. | **New**: Integrate TruffleHog/Gitleaks + entropy scoring + credential validation (attempt API call with detected key to verify if live). Core 1 entity: secret-exposure with validation-status. |
| **AI Assistant** | Auto-triage suppressing repeat FPs. 97% human agreement rate. Remediation guidance in PRs/IDEs. Creates reusable "memories" from triage decisions. | **ALDECI equivalent**: Core 4 Decision Memory IS the "memory" system. RL Controller learns triage patterns. Council confidence thresholds auto-suppress known FPs. Target: 98%+ agreement rate (4 models > 1). |
| **Custom Rules** | Registry of community/Semgrep-written rules. Playground for writing/sharing. | **New**: ALDECI custom rule engine — write YAML-based detection rules, share via marketplace. Leverage existing `suite-integrations/marketplace/`. Rules stored in Core 3 as detection-policy entities. |
| **MCP Server** | Security for AI-generated code via MCP integration. | **ALDECI is MCP-native**: TrustGraph already supports MCP. Add: ALDECI MCP server exposing security queries to IDE AI assistants. |

---

### 4.8 Competitor Deep Dive: ArmorCode

**Category**: AI-Powered ASPM + Vulnerability Management
**Recognition**: ASPM leader, 40 billion findings processed
**Key Tech**: Anya agentic AI, 320+ tool integrations

#### ArmorCode's Complete Feature Set

| Feature | Details | ALDECI Answer |
|---|---|---|
| **320+ Security Tool Integrations** | Ingests findings from any scanner. Normalizes into unified taxonomy. | **ALDECI equivalent**: `InputNormalizer` (1,783 lines) handles 6 input types. OWASP DC+DT adds 6 vuln sources. 28+ feed parsers. For broader integration: add generic webhook receiver → auto-detect format → normalize → Core 1. |
| **AI Correlation** | Anya AI correlates findings across tools, deduplicates, prioritizes. | **ALDECI equivalent**: LLM Council correlation — multi-model consensus on finding severity, deduplication via Core 1 entity matching, prioritization via Bayesian + EPSS + SSVC. |
| **Risk-Based VM** | Incorporates business context + threat intel into vulnerability scoring. | **Existing**: SSVC framework + Bayesian `ProbabilisticForecastEngine` + 28 threat feeds + business context normalization. Richer than ArmorCode's single-model scoring. |
| **97% Faster Remediation** | MTTR from 240 days → 7 days via AI correlation + automated ticketing. | **ALDECI target: MTTR < 3 days** — automated: Council assessment → FixEngine PR → CI validation → auto-merge if tests pass → Core 4 tracks resolution time. RL Controller optimizes the loop. |
| **Penetration Testing Management** | Module for managing external pentests. | **Existing**: Pentest infrastructure in `suite-integrations/mpte-aldeci/` + `suite-attack/`. Manage internal + external pentests in unified view. |
| **Exceptions Management** | Workflow for risk acceptance, compensating controls, temporary waivers. | **New**: Exception workflow — developer requests exception → LLM Council evaluates risk → manager approval → Core 4 tracks with expiry → auto-reopen on expiry. |
| **No-Code Automation** | Workflow builder for routing findings to teams. | **New**: YAML-based automation rules engine. "When: critical_cve AND internet_facing → Action: create_jira(team=platform, priority=P0, auto_fix=true)". Store in Core 3 as automation-policy entities. |

---

### 4.9 Competitor Deep Dive: Cycode

**Category**: Agentic Development Security Platform (Complete ASPM)
**Recognition**: Pipeline security pioneer
**Key Tech**: CI-MON runtime protection, Risk Intelligence Graph, AI Teammates

#### Cycode's Complete Feature Set

| Feature | Details | ALDECI Answer |
|---|---|---|
| **Pipeline Security** | CI/CD environment auditing, privilege scanning, code leak detection, supply chain integrity. | **Existing**: SAST self-scan capability (`scripts/aldeci_self_scan.py`), micro-pentest TLS verification, autonomous validation cycles (all merged from `feature/autonomous-foundation`). Enhance: CI-MON equivalent — runtime memory protection during builds. |
| **CI-MON Runtime Protection** | Verifies process integrity during builds/deployments. Detects memory tampering. | **New**: Build-time integrity monitor — hash verification of all build artifacts, process integrity checks, dependency lock validation. Core 1 build-integrity entities. |
| **Risk Intelligence Graph** | Natural language querying of security data. | **TrustGraph GraphRAG** — same capability but with versioned Context Cores + OntologyRAG extraction. More powerful than Cycode's proprietary graph. |
| **AI Teammates** | Change Impact Analysis Agent, Risk Intelligence Graph Agent, Exploitability Agent, Fix & Remediation Agent. | **ALDECI equivalent**: LLM Council IS the multi-agent system. Each "agent" is a Council prompt template: Impact Analysis mode, Exploitability mode, Fix mode. But Council provides peer review that individual agents don't. |
| **ConnectorX** | 100+ third-party security tool integrations. | **New**: Generic webhook connector framework. YAML-defined connectors for common tools (Snyk, Checkmarx, SonarQube, Fortify, etc.). Input → normalize → Core 1. |
| **Source Code Leakage** | Detect proprietary code leaked to public repos. | **New**: Code fingerprinting scanner — hash critical code segments → monitor GitHub/GitLab public repos for matches → alert. Core 2 threat intel entity. |

---

### 4.10 Additional Competitors Summary

#### Phoenix Security (ASPM → CTEM)
**Key insight**: 2026 Latio Report confirms ASPM is evolving to CTEM. Phoenix's PYRUS YAML engine connects code, cloud, ownership. ALDECI already does this with TrustGraph + suite layout + SSVC.

**Steal**: PYRUS-style YAML-native configuration for security policies, ownership mapping, and automation rules. ALDECI equivalent: Core 3 compliance policies + YAML automation engine.

#### Additional Competitors Tracked (Core 5 — Competitive Intelligence)

| Competitor | Category | Key Differentiator | ALDECI Coverage |
|---|---|---|---|
| **Checkmarx** | Enterprise SAST/SCA | Mature enterprise SAST, supply chain security | SAST + OWASP DC+DT covers this |
| **SonarQube** | Code Quality + SAST | Developer-focused code quality + security rules | Complementary — integrate as scanner input |
| **Veracode** | Enterprise SAST/DAST | Binary analysis, managed service | SAST + DAST agents cover this |
| **Black Duck** | SCA/OSS governance | License compliance, open-source risk | OWASP DC+DT + license risk engine |
| **Lacework** | Cloud security + runtime | Polygraph behavioral analytics | eBPF runtime + TrustGraph behavioral patterns |
| **Prisma Cloud** | CNAPP | Palo Alto enterprise cloud security | CSPM + CWPP + CIEM modules |
| **Rapid7** | VM + SIEM | InsightVM + InsightIDR unified | 28 feeds + SIEM integration via Pulsar |
| **Tenable** | VM + OT | Nessus heritage, OT/IoT coverage | VM + network discovery + OT extension |
| **Qualys** | VM + compliance | Agent-based scanning, VMDR | OWASP DC+DT + compliance engine |

---

### 4.11 ALDECI's Complete Differentiators (No Single Competitor Has ALL)

| # | Differentiator | Competitors That Come Close | Why ALDECI Wins |
|---|---|---|---|
| 1 | **Versioned Context Cores** | None | Snapshot entire security knowledge graph at any point. No competitor offers knowledge versioning. |
| 2 | **4-Model LLM Consensus with Peer Review** | Aikido (single Claude), Semgrep (single AI) | Multi-model peer review catches what single models miss. Mathematical consensus, not black-box. |
| 3 | **Decision Memory with RL** | CrowdStrike (telemetry learning) | Explicit decision audit trail + reinforcement learning optimization. PROV-O provenance for every decision. |
| 4 | **Unified ASPM + CTEM + CSPM** | Wiz (CNAPP), CrowdStrike (CTEM), Apiiro (ASPM) | One platform covers all three. Competitors are strong in one. |
| 5 | **28+ Threat Intelligence Feeds** | CrowdStrike (telemetry), ArmorCode (320 tools) | Broadest open-source feed coverage. CrowdStrike's telemetry is proprietary. ArmorCode aggregates tools, not raw intel. |
| 6 | **SSVC + Bayesian + Markov Risk Models** | None at this depth | Most mathematically rigorous and transparent risk analysis in the industry. |
| 7 | **pricing TBD (target: $199-$1,499/month tiered) total cost** | Aikido ($350/mo min) | 10x cheaper than cheapest competitor. Free models + self-hosted. |
| 8 | **Fully open-source stack** | Semgrep (open-source CE) | Apache 2.0 TrustGraph + free LLMs + OWASP DC+DT + self-hosted everything. No vendor lock-in. |
| 9 | **OntologyRAG** | None | Auto-extract structured knowledge from ANY security document into typed RDF triples. |
| 10 | **SBOM-Runtime Correlation** | Apiiro (code-to-runtime) | `sbom_runtime_correlator.py` with quantified risk deltas. More transparent than Apiiro's black-box DCA. |
| 11 | **MCP-Native Architecture** | Cycode (ConnectorX) | TrustGraph native MCP support. ALDECI exposes security queries as MCP tools for IDE AI assistants. |
| 12 | **AI Asset Inventory** | CrowdStrike (AI Discovery) | Detect LLMs, AI agents, MCP servers, AI packages. ALDECI is uniquely positioned as AI-native. |
| 13 | **Autonomous Self-Scan** | None | ALDECI scans itself — SAST self-scan, micro-pentest TLS verification, autonomous validation cycles. |
| 14 | **OpenClaw Pentest Swarm** | Aikido (200+ agents) | Multi-agent pentesting with LLM Council validation. 4-model consensus eliminates hallucination-based false positives. |
| 15 | **Build Integrity Monitoring** | Cycode (CI-MON) | Runtime integrity verification during CI/CD builds. Detect supply chain attacks at build time. |

---

## Part 4B: TrustGraph End-to-End Pipeline Integration (15 Stages)

### The Core Principle

**TrustGraph is not a bolt-on. It IS the data layer.** Every stage reads from and writes to TrustGraph. The pipeline flows THROUGH TrustGraph, not alongside it.

### Complete 15-Stage Pipeline with TrustGraph at Every Stage

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    ALDECI TRUSTGRAPH-NATIVE PIPELINE                         │
│                    (TrustGraph involved at EVERY stage)                      │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌─── STAGE 0: INPUT NORMALIZATION ──────────────────────────────────────┐ │
│  │  IN:  Raw artifacts (SBOM, SARIF, CVE, CNAPP, VEX, BusinessContext)   │ │
│  │  DO:  OWASP DC scan → CycloneDX BOM → DT correlation                 │ │
│  │       InputNormalizer for SARIF/CVE/CNAPP/VEX/BusinessContext         │ │
│  │  TG:  ✅ WRITE → Core 1 (Customer Environment)                       │ │
│  │       Every normalized entity becomes an RDF triple in Core 1          │ │
│  │       Components, findings, CVEs, cloud assets, VEX assertions        │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│       │                                                                     │
│       ▼                                                                     │
│  ┌─── STAGE 1: CROSSWALK / ENTITY CORRELATION ──────────────────────────┐ │
│  │  IN:  Normalized entities                                             │ │
│  │  DO:  Component→Finding→CVE relationship mapping                      │ │
│  │       Tokenization, fuzzy matching, PURL resolution                   │ │
│  │  TG:  ✅ WRITE → Core 1 edges (component→cve, component→finding)     │ │
│  │       ✅ READ  ← Core 1 existing entities (dedup against known)       │ │
│  │       Graph edges replace in-memory CrosswalkRow list                  │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│       │                                                                     │
│       ▼                                                                     │
│  ┌─── STAGE 2: BUSINESS CONTEXT ENRICHMENT ──────────────────────────────┐ │
│  │  IN:  Crosswalk entities + business context data                      │ │
│  │  DO:  Map data classification, service criticality, ownership          │ │
│  │  TG:  ✅ WRITE → Core 1 (business-context edges on entities)          │ │
│  │       ✅ READ  ← Core 1 historical context (what changed?)            │ │
│  │       ✅ READ  ← Core 3 (compliance requirements for this service)    │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│       │                                                                     │
│       ▼                                                                     │
│  ┌─── STAGE 3: EXPLOIT SIGNAL EVALUATION ────────────────────────────────┐ │
│  │  IN:  CVE entities from Core 1                                        │ │
│  │  DO:  Query 28+ feeds: NVD, KEV, EPSS, ExploitDB, Mandiant, Shodan   │ │
│  │       8 feed categories with geo-weighting                            │ │
│  │  TG:  ✅ WRITE → Core 2 (Threat Intelligence) — feed data as triples │ │
│  │       ✅ READ  ← Core 2 existing intel (avoid re-fetching known)      │ │
│  │       ✅ Pulsar streaming → Core 2 real-time updates                  │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│       │                                                                     │
│       ▼                                                                     │
│  ┌─── STAGE 4: ENRICHMENT EVIDENCE ─────────────────────────────────────┐ │
│  │  IN:  CVE entities + Core 2 threat intel                              │ │
│  │  DO:  CVSS extraction, CWE mapping, KEV check, EPSS lookup,           │ │
│  │       ExploitDB count, vendor advisory detection, age calculation      │ │
│  │  TG:  ✅ READ  ← Core 1 (CVE entities) + Core 2 (threat signals)     │ │
│  │       ✅ WRITE → Core 1 enrichment-evidence edges on CVE entities     │ │
│  │       Graph query replaces dict lookup                                │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│       │                                                                     │
│       ▼                                                                     │
│  ┌─── STAGE 5: PROBABILISTIC FORECASTING ───────────────────────────────┐ │
│  │  IN:  Enrichment evidence from Core 1                                 │ │
│  │  DO:  Bayesian odds: EPSS prior × KEV LR × ExploitDB LR × age LR    │ │
│  │       Markov transition: 30-day exploitation probability              │ │
│  │  TG:  ✅ READ  ← Core 1 enrichment + Core 2 threat signals           │ │
│  │       ✅ READ  ← Core 4 historical forecasts (calibration data)       │ │
│  │       ✅ WRITE → Core 1 forecast-result edges (p_exploit, p_30d)      │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│       │                                                                     │
│       ▼                                                                     │
│  ┌─── STAGE 6: THREAT MODELING & ATTACK PATH ───────────────────────────┐ │
│  │  IN:  CVE entities + component graph + network topology               │ │
│  │  DO:  CVSS vector parsing, reachability scoring, exposure assessment  │ │
│  │  TG:  ✅ READ  ← Core 1 component graph (replaces NetworkX)          │ │
│  │       ✅ GraphRAG traversal for attack paths (multi-hop queries)      │ │
│  │       ✅ READ  ← Core 2 (MITRE ATT&CK techniques for this CVE)       │ │
│  │       ✅ WRITE → Core 1 attack-path edges + threat-model results      │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│       │                                                                     │
│       ▼                                                                     │
│  ┌─── STAGE 7: COMPLIANCE MAPPING ──────────────────────────────────────┐ │
│  │  IN:  CVE severity + CWE type + affected components                   │ │
│  │  DO:  Cross-ref against NIST CSF, PCI-DSS, SOC2, HIPAA, ISO27001,   │ │
│  │       FedRAMP, CIS Benchmarks, OWASP Top 10                          │ │
│  │  TG:  ✅ READ  ← Core 3 (Compliance & Regulatory) — framework rules  │ │
│  │       ✅ OntologyRAG extraction of framework requirements             │ │
│  │       ✅ WRITE → Core 1 compliance-gap edges on affected entities     │ │
│  │       ✅ WRITE → Core 3 new control mappings (learned)                │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│       │                                                                     │
│       ▼                                                                     │
│  ┌─── STAGE 8: VERDICT COMPUTATION ─────────────────────────────────────┐ │
│  │  IN:  All evidence from stages 4-7 (all in Core 1/2/3)               │ │
│  │  DO:  Combine: forecast × KEV boost × attack path × reachability ×   │ │
│  │       compliance gaps × vendor advisory dampening                     │ │
│  │       Threshold: ≥0.70 exploitable, ≤0.15 not_exploitable            │ │
│  │  TG:  ✅ READ  ← Core 1+2+3 (all evidence via single graph query)   │ │
│  │       ✅ READ  ← Core 4 (historical verdicts for similar CVEs)        │ │
│  │       ✅ WRITE → Core 4 (Decision Memory) — verdict as RDF triple     │ │
│  │       {cve, verdict, confidence, reasoning, timestamp, provenance}    │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│       │                                                                     │
│       ▼                                                                     │
│  ┌─── STAGE 9: DEDUPLICATION & CORRELATION ─────────────────────────────┐ │
│  │  IN:  All findings from Core 1                                        │ │
│  │  DO:  Fingerprint generation, cluster detection, duplicate grouping   │ │
│  │  TG:  ✅ READ  ← Core 1 (existing findings for dedup matching)        │ │
│  │       ✅ READ  ← Core 4 (previously suppressed = auto-suppress again) │ │
│  │       ✅ WRITE → Core 1 dedup-cluster edges + noise-reduction metrics │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│       │                                                                     │
│       ▼                                                                     │
│  ┌─── STAGE 10: SEVERITY PROMOTION ─────────────────────────────────────┐ │
│  │  IN:  CVEs with exploit signals from Core 2                           │ │
│  │  DO:  Re-evaluate severity based on real-world exploitation evidence  │ │
│  │  TG:  ✅ READ  ← Core 2 (exploit signals that justify promotion)      │ │
│  │       ✅ WRITE → Core 1 updated severity + promotion-evidence edges   │ │
│  │       ✅ WRITE → Core 4 (promotion decision with reasoning)           │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│       │                                                                     │
│       ▼                                                                     │
│  ┌─── STAGE 11: LLM COUNCIL CONSENSUS ─────────────────────────────────┐ │
│  │  IN:  *** ENRICHED TRUSTGRAPH DATA — see detailed input below ***     │ │
│  │  DO:  Karpathy 3-stage: Independent → Peer Review → Synthesis         │ │
│  │       4 free models + Opus CTO escalation on disagreement             │ │
│  │  TG:  ✅ READ  ← Core 1+2+3+4 (full context for each model)          │ │
│  │       ✅ WRITE → Core 4 (complete decision record with all opinions)  │ │
│  │       ✅ READ  ← Core 4 (similar past decisions for calibration)      │ │
│  │       See "LLM Council Input Feed" section below for details          │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│       │                                                                     │
│       ▼                                                                     │
│  ┌─── STAGE 12: KNOWLEDGE GRAPH ENRICHMENT ─────────────────────────────┐ │
│  │  IN:  All entities + verdicts + council decisions                      │ │
│  │  DO:  Build/update dependency graph, attack path enumeration,         │ │
│  │       subgraph analysis for affected components                       │ │
│  │  TG:  ✅ This IS TrustGraph — no separate graph needed               │ │
│  │       GraphRAG queries replace NetworkX traversal                     │ │
│  │       Toxic combination detection via multi-hop graph queries         │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│       │                                                                     │
│       ▼                                                                     │
│  ┌─── STAGE 13: POLICY AUTOMATION ──────────────────────────────────────┐ │
│  │  IN:  Verdicts + compliance gaps + policy rules                       │ │
│  │  DO:  OPA/Rego policy evaluation, guardrail checks,                   │ │
│  │       automated actions (Jira, webhooks, FixEngine PRs)              │ │
│  │  TG:  ✅ READ  ← Core 3 (policy rules as graph entities)             │ │
│  │       ✅ READ  ← Core 4 (past policy outcomes for optimization)       │ │
│  │       ✅ WRITE → Core 4 (policy execution records)                    │ │
│  │       ✅ RL Controller reads Core 4 → optimizes policy thresholds     │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│       │                                                                     │
│       ▼                                                                     │
│  ┌─── STAGE 14: REMEDIATION & AUTOFIX ──────────────────────────────────┐ │
│  │  IN:  Exploitable verdicts + Council recommendations                  │ │
│  │  DO:  FixEngine generates PRs, Council validates fix correctness,     │ │
│  │       CI runs tests, auto-merge if passing                            │ │
│  │  TG:  ✅ READ  ← Core 1 (affected components + dependency chain)     │ │
│  │       ✅ READ  ← Core 4 (past fixes for similar vulns)                │ │
│  │       ✅ WRITE → Core 4 (fix outcome: success/failure/regression)     │ │
│  │       ✅ RL Controller learns fix effectiveness over time              │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│       │                                                                     │
│       ▼                                                                     │
│  ┌─── STAGE 15: RESULT ASSEMBLY & REPORTING ────────────────────────────┐ │
│  │  IN:  All Core 1+2+3+4 data                                          │ │
│  │  DO:  Comprehensive result JSON, evidence bundles, compliance         │ │
│  │       reports, CEO dashboard data, trend analysis                     │ │
│  │  TG:  ✅ READ  ← All 5 Cores (full knowledge graph query)            │ │
│  │       ✅ WRITE → Core 5 (Competitive Intel: how do our metrics        │ │
│  │       compare to industry benchmarks?)                                │ │
│  │       Context Core snapshot for audit trail / rollback                │ │
│  └───────────────────────────────────────────────────────────────────────┘ │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### TrustGraph Usage Summary Per Stage

| Stage | Core 1 (Customer) | Core 2 (Threat) | Core 3 (Compliance) | Core 4 (Decisions) | Core 5 (Competitive) |
|---|---|---|---|---|---|
| 0: Normalization | **WRITE** | | | | |
| 1: Crosswalk | **READ+WRITE** | | | | |
| 2: Business Context | **WRITE** | | **READ** | | |
| 3: Exploit Signals | READ | **WRITE** | | | |
| 4: Enrichment | **READ+WRITE** | **READ** | | | |
| 5: Forecasting | **READ+WRITE** | READ | | **READ** | |
| 6: Threat Model | **READ+WRITE** | **READ** | | | |
| 7: Compliance | **WRITE** | | **READ+WRITE** | | |
| 8: Verdict | READ | READ | READ | **WRITE** | |
| 9: Deduplication | **READ+WRITE** | | | **READ** | |
| 10: Severity Promo | READ+WRITE | **READ** | | **WRITE** | |
| 11: LLM Council | **READ** | **READ** | **READ** | **READ+WRITE** | |
| 12: Graph Enrichment | **IS TrustGraph** | | | | |
| 13: Policy | READ | | **READ** | **READ+WRITE** | |
| 14: Remediation | **READ** | | | **READ+WRITE** | |
| 15: Reporting | READ | READ | READ | READ | **WRITE** |

**Total**: TrustGraph is involved in **15/15 stages** — zero stages bypass the knowledge graph.

---

## Part 4C: LLM Council Input Feed Architecture (Karpathy Consensus)

### What Feeds INTO the LLM Council?

The LLM Council (Stage 11) does NOT receive raw data. It receives **enriched, contextualized data from TrustGraph** — the accumulated knowledge from Stages 0-10. This is what makes the Council decisions so much richer than single-model approaches.

### Council Input Payload (per CVE/finding)

```
LLM_COUNCIL_INPUT = {
  # ── FROM CORE 1 (Customer Environment) ──────────────────────
  "entity": {
    "cve_id": "CVE-2024-38856",
    "affected_components": [
      {"name": "apache-ofbiz", "version": "18.12.15", "purl": "pkg:maven/..."}
    ],
    "dependency_chain": ["app → framework → ofbiz → ofbiz-base"],
    "code_locations": ["src/main/java/AccountingService.java:142"],
    "business_context": {
      "service": "billing-api",
      "data_classification": "PCI",
      "criticality": "high",
      "owner": "platform-team",
      "exposure": "internet-facing"
    },
    "runtime_status": {
      "is_running": true,
      "is_reachable": true,
      "sbom_runtime_delta": "+0.30 (confirmed runtime)"
    }
  },

  # ── FROM CORE 2 (Threat Intelligence) ──────────────────────
  "threat_intel": {
    "cvss_v3_score": 9.8,
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "cwe_ids": ["CWE-863"],
    "kev_listed": true,
    "kev_date_added": "2024-08-07",
    "epss_score": 0.94,
    "exploitdb_count": 3,
    "exploit_maturity": "weaponized",
    "threat_actors": ["APT28", "FIN7"],
    "mitre_techniques": ["T1190", "T1059"],
    "vendor_advisory": "https://ofbiz.apache.org/security.html",
    "patch_available": true,
    "patch_version": "18.12.16",
    "feed_signals": {
      "nvd": "CRITICAL",
      "kev": "ACTIVE_EXPLOITATION",
      "greynoise": "mass_scanning_detected",
      "shodan": "12,847 exposed instances",
      "mandiant": "used in recent campaign targeting financial sector"
    }
  },

  # ── FROM CORE 3 (Compliance & Regulatory) ──────────────────
  "compliance": {
    "frameworks_affected": ["PCI-DSS 4.0", "SOC2 CC6.1"],
    "control_gaps": [
      "PCI-DSS 6.3.3: Known vulnerabilities must be patched within 30 days",
      "SOC2 CC6.1: Logical access boundaries for sensitive data"
    ],
    "regulatory_deadline": "2024-09-06 (30 days from KEV listing)",
    "audit_implications": "PCI audit failure if unpatched at next assessment"
  },

  # ── FROM STAGES 4-8 (Pre-computed Evidence) ────────────────
  "pre_computed": {
    "enrichment_evidence": {
      "cvss_score": 9.8,
      "kev": true,
      "epss": 0.94,
      "exploitdb_refs": 3,
      "age_days": 45,
      "vendor_advisory": true
    },
    "forecast": {
      "p_exploit_now": 0.96,
      "p_exploit_30d": 0.98,
      "confidence": 0.92
    },
    "threat_model": {
      "attack_path_found": true,
      "reachability_score": 0.85,
      "exposure_level": "internet",
      "critical_asset_in_path": true
    },
    "compliance_mapping": {
      "gap_count": 2,
      "highest_framework": "PCI-DSS 4.0",
      "remediation_deadline": "30 days"
    },
    "deterministic_verdict": "exploitable (p=0.96, confidence=0.92)"
  },

  # ── FROM CORE 4 (Decision Memory) ─────────────────────────
  "historical_context": {
    "similar_past_decisions": [
      {
        "cve": "CVE-2023-49070",
        "component": "apache-ofbiz",
        "verdict": "exploitable",
        "outcome": "patched in 3 hours, no incident",
        "council_confidence": 0.94
      }
    ],
    "false_positive_rate_for_cwe": 0.02,
    "org_specific_patterns": "OFBiz vulns historically confirmed exploitable",
    "rl_controller_adjustment": "+0.05 (historically accurate for this CWE)"
  },

  # ── COUNCIL INSTRUCTIONS ───────────────────────────────────
  "council_prompt": {
    "task": "Assess exploitability and recommend action for this CVE",
    "output_schema": {
      "action": "allow | defer | block",
      "confidence": "0.0 - 1.0",
      "reasoning": "detailed explanation",
      "mitre_techniques": ["T-codes"],
      "compliance_concerns": ["specific gaps"],
      "attack_vectors": ["specific paths"],
      "remediation_priority": "P0 | P1 | P2 | P3",
      "remediation_recommendation": "specific fix steps",
      "estimated_fix_effort": "hours"
    }
  }
}
```

### Council 3-Stage Execution Flow

```
STAGE 1: INDEPENDENT ANALYSIS
──────────────────────────────
Each model receives the SAME enriched payload above.
Each model independently produces: {action, confidence, reasoning, ...}

┌──────────────┐  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐
│   Qwen 3.6   │  │   Gemma 4    │  │  DeepSeek V3 │  │   Llama 4    │
│   (router)   │  │   (local)    │  │   (router)   │  │   (router)   │
│              │  │              │  │              │  │              │
│ Reads:       │  │ Reads:       │  │ Reads:       │  │ Reads:       │
│ • entity     │  │ • entity     │  │ • entity     │  │ • entity     │
│ • threat_intel│  │ • threat_intel│  │ • threat_intel│  │ • threat_intel│
│ • compliance │  │ • compliance │  │ • compliance │  │ • compliance │
│ • pre_computed│  │ • pre_computed│  │ • pre_computed│  │ • pre_computed│
│ • historical │  │ • historical │  │ • historical │  │ • historical │
│              │  │              │  │              │  │              │
│ Output:      │  │ Output:      │  │ Output:      │  │ Output:      │
│ block, 0.95  │  │ block, 0.93  │  │ block, 0.91  │  │ defer, 0.72  │
└──────┬───────┘  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘
       │                 │                 │                 │
       ▼                 ▼                 ▼                 ▼

STAGE 2: ANONYMOUS PEER REVIEW
──────────────────────────────
Each model reviews ALL OTHER verdicts (anonymized as A, B, C, D).
Returns: {agree/disagree, confidence_adjustment, reasoning}

Model A (Qwen):    "Agree with B,C (block). Disagree with D (defer) —
                    KEV + EPSS 0.94 + internet-facing PCI service = clear block."
Model B (Gemma):   "Agree with A,C. D's defer is underweighted given threat actors."
Model C (DeepSeek): "Agree with A,B. D may be considering patch availability, but
                    30-day PCI deadline makes defer too risky."
Model D (Llama):   "Reconsidering → agree with A,B,C. Patch available but
                    internet-facing + active exploitation justifies immediate block."

STAGE 3: SYNTHESIS
──────────────────
Consensus reached (4/4 agree after peer review):
→ Qwen 3 (Chairman) synthesizes final verdict: $0 cost

IF 2/2 split persisted:
→ ESCALATE to Claude Opus CTO: ~$0.05 per decision
→ Opus sees: all 4 opinions + all peer reviews + enriched payload
→ Opus makes final call with full transparency

FINAL OUTPUT → Core 4 (Decision Memory):
{
  "verdict": "block",
  "consensus_score": 1.0 (4/4),
  "confidence": 0.94 (weighted average),
  "reasoning_chain": [4 independent + 4 peer reviews + synthesis],
  "dissenting_opinions": ["Llama initially deferred, reconsidered"],
  "provenance": "PROV-O triple: decision wasGeneratedBy council-session-2024-08-09",
  "remediation": "Upgrade apache-ofbiz to 18.12.16 immediately. P0 priority.",
  "estimated_fix_effort": "2 hours (dependency upgrade + regression test)"
}
```

### Why This Input Feed Design Matters

| Design Choice | Reason |
|---|---|
| **Models get enriched graph data, not raw feeds** | Reduces token count by ~85%. Models reason about structured evidence, not parse raw NVD JSON. |
| **Historical decisions included** | Models learn from org-specific patterns without fine-tuning. "OFBiz vulns historically confirmed" guides new assessments. |
| **Deterministic verdict pre-computed** | Models can agree/disagree with the math. If they disagree, that's the value — catches edge cases Bayesian models miss. |
| **Compliance deadlines explicit** | Forces models to consider regulatory urgency, not just technical severity. |
| **Runtime status from correlator** | Models know if the vulnerable component is actually running and reachable, not just theoretically present in SBOM. |
| **RL Controller adjustment** | Decision Memory feeds forward — past accuracy adjusts current confidence thresholds per CWE/component type. |

---

## Part 5: Rearchitected ALDECI Stack

### Before vs After (verified against actual codebase)

```
BEFORE (Current ALDECI):                    AFTER (TrustGraph-Native ALDECI):

React/Vite Intelligence Hub (12+ pages)   React/Vite + TrustGraph 3D via @xyflow/react
       │                                         │
FastAPI (20+ routers, 137+ endpoints)      FastAPI (same routers, TG-backed endpoints)
       │                                         │
┌──────┴──────┐                            ┌──────┴──────┐
│  Decision   │                            │  LLM Council│
│  Engine     │                            │  Engine     │
│  4 LLM +   │                            │  4 free +   │
│  weighted   │                            │  Opus esc + │
│  voting     │                            │  peer review│
└──────┬──────┘                            └──────┬──────┘
       │                                         │
┌──────┴──────┐                            ┌──────┴──────┐
│  Data       │                            │  Data       │
│  Pipeline   │                            │  Pipeline   │
│  28 feeds + │                            │  28 feeds → │
│  normalizers│                            │  Pulsar →   │
│  (batch)    │                            │  TrustGraph │
└──────┬──────┘                            └──────┬──────┘
       │                                         │
┌──────┴──────┐                            ┌──────┴──────┐
│  Graph      │                            │  TrustGraph │
│  NetworkX + │                            │  5 Knowledge│
│  SQLite +   │                            │  Cores +    │
│  ChromaDB   │                            │  Neo4j +    │
│  (in-memory)│                            │  Qdrant +   │
└─────────────┘                            │  Pulsar     │
                                           └──────┬──────┘
                                                  │
                                           ┌──────┴──────┐
                                           │  Enterprise │
                                           │  Legacy     │
                                           │  Resurrected│
                                           │  KG, RL,    │
                                           │  Fix, Expl  │
                                           └─────────────┘
```

### Technology Stack (complete)

| Layer | Current Tech | TrustGraph-Native Tech | Migration |
|---|---|---|---|
| **Frontend** | React 18 + Vite 5 + Radix UI + @xyflow/react (Intelligence Hub v2.0, 12+ pages) | Same + TrustGraph 3D GraphViz via @xyflow/react | Extend, don't replace |
| **API** | FastAPI (20+ routers, 137+ endpoints) | Same FastAPI, TG-backed queries | Keep all endpoints |
| **Decision** | MultiLLMConsensusEngine (4 paid LLMs) | LLM Council (4 free + Opus CTO) | Replace engine class |
| **Risk** | BayesianNetwork + BN-LR + WeightedScoring | Same + TrustGraph context enrichment | Extend models |
| **Graph** | NetworkX + SQLite + ChromaDB | TrustGraph + Neo4j/FalkorDB + Qdrant | Full migration |
| **Streaming** | Batch feed processing | Apache Pulsar (via TrustGraph) | New layer |
| **Compliance** | ComplianceEvaluator + SSVC + mapping | TrustGraph Core 3 + OntologyRAG | Extend coverage |
| **Feeds** | 28+ ThreatIntelligenceFeed classes | Same parsers → Pulsar → TrustGraph | Route change only |
| **Auth** | Token-based + JWT (basic) | Same + TrustGraph multi-tenant RBAC | Extend |
| **Telemetry** | OTEL (NoOp fallback) | Same + TrustGraph Prometheus/Grafana | Extend |
| **Tests** | 1,536 tests, 140+ files | Maintain + add TrustGraph integration tests | Keep all |

---

## Part 6: Master Execution Plan (Updated with Enterprise Legacy Resurrection)

### Phase 0: Foundation (Week 1) — Beast Mode + TrustGraph Setup
| # | Task | Owner | Details |
|---|---|---|---|
| 0.1 | Install Beast Mode stack | SwarmClaw | Ollama + Gemma 4, OMNI, OMC, everything-claude-code, OpenRouter |
| 0.2 | Deploy TrustGraph Docker stack | SwarmClaw | Neo4j + Qdrant + Pulsar + TrustGraph services |
| 0.3 | Create CLAUDE.md for ALDECI | Opus CTO | Using v2 codebase analysis (this document) |
| 0.4 | Run code-review-graph on Shiva's Mac | SwarmClaw | `pip install code-review-graph && code-review-graph build` for blast radius analysis |
| 0.5 | Configure SwarmClaw Kanban | Shiva | Initial task board with Phase 1 tasks |

### Phase 1: TrustGraph Integration + Enterprise Resurrection (Weeks 1-2)
| # | Task | Owner | Details |
|---|---|---|---|
| 1.1 | Create TrustGraph Python client wrapper | LLM Council | Wrap `trustgraph` SDK matching ALDECI's FastAPI patterns |
| 1.2 | Migrate `services/graph/graph.py` → TrustGraph | Agent Team | ProvenanceGraph → TrustGraph REST API, keep lineage/impact interfaces |
| 1.3 | Migrate `core/vector_store.py` → Qdrant | Agent Team | ChromaVectorStore → Qdrant via TrustGraph, keep SecurityPatternMatcher |
| 1.4 | Route 28 feed parsers to Pulsar → TrustGraph | Agent Team | Keep parsers, change output from in-memory to Pulsar streaming |
| 1.5 | Build Core 2 (Threat Intel) from feeds | Agent Team | NVD/EPSS/KEV/MITRE ATT&CK/OSV + OntologyRAG extraction |
| 1.6 | Build Core 3 (Compliance) | Agent Team | Import existing NIST/PCI/ISO/SSVC + add SOC2/HIPAA/FedRAMP/CIS/OWASP |
| 1.7 | Resurrect `KnowledgeGraphBuilder` | Agent Team | Modernize `CTINexusEntityExtractor` → TrustGraph OntologyRAG |
| 1.8 | Resurrect `CorrelationEngine` | Agent Team | Integrate finding correlation with TrustGraph graph traversal |
| 1.9 | Replace lib4sbom with OWASP Dependency-Check | Agent Team | DC CLI v12.2 for CPE matching + SARIF/CycloneDX output, `failBuildOnCVSS` gating |
| 1.10 | Deploy OWASP Dependency-Track | Agent Team | DT REST API for CycloneDX ingestion, 6 vuln sources (NVD/OSS Index/GitHub/Snyk/OSV/VulnDB), EPSS, policy engine |
| 1.11 | Wire DC→DT→TrustGraph pipeline | Agent Team | DC scan → CycloneDX BOM → DT correlation → TrustGraph Core 1 ingestion via `sbom_runtime_correlator.py` |
| 1.12 | Build Core 1 (Customer Env) ingestion | Agent Team | DC-generated SBOM + SARIF/CVE/CNAPP → TrustGraph via normalized pipeline |
| 1.13 | GraphRAG attack path discovery | Agent Team | Replace NetworkX queries with TrustGraph GraphRAG + toxic combos |

### Phase 2: LLM Consensus Engine + Learning (Weeks 2-3)
| # | Task | Owner | Details |
|---|---|---|---|
| 2.1 | Add `OllamaProvider` + `OpenRouterProvider` | Agent Team | Extend BaseLLMProvider for Qwen/Gemma/DeepSeek/Llama |
| 2.2 | Build `LLMCouncilEngine` | LLM Council | 3-stage: independent → peer review → synthesis |
| 2.3 | Replace `MultiLLMConsensusEngine` | Agent Team | Swap in Council, keep `DecisionTreeOrchestrator` 6-step flow |
| 2.4 | Build Opus CTO escalation path | Agent Team | Disagreement detection → Opus final call |
| 2.5 | Build Core 4 (Decision Memory) | Agent Team | RDF triples + W3C PROV-O provenance |
| 2.6 | Resurrect `ReinforcementLearningController` | Agent Team | Decision optimization via experience replay |
| 2.7 | Resurrect `ExplainabilityService` | Agent Team | PROV-O trace generation for every decision |
| 2.8 | Build decision feedback loop | Agent Team | False positive corrections → Council accuracy tracking |

### Phase 3: Competitive Features (Weeks 3-4)
| # | Task | Owner | Details |
|---|---|---|---|
| 3.1 | Integrate TrustGraph 3D GraphViz into suite-ui/aldeci @xyflow/react | Agent Team | Extend AttackPathGraph.tsx + Dashboard pages |
| 3.2 | Resurrect `FixEngine` → AutoFix agent | LLM Council | PR generation using Council consensus |
| 3.3 | CTEM pipeline | Agent Team | Continuous: 28 feeds → Pulsar → TrustGraph → real-time alerts |
| 3.4 | Noise reduction engine | Agent Team | Decision Memory + RL Controller → target 95%+ |
| 3.5 | AI pentest agents | Agent Team | OpenClaw agents + existing pentagi module |
| 3.6 | XBOM generation | Agent Team | Extended SBOM via GraphRAG across Core 1 |
| 3.7 | Build Core 5 (Competitive Intel) | Agent Team | Ingest competitor docs, track feature parity |
| 3.8 | Resurrect `MarketplaceService` | Agent Team | Content/plugin marketplace for ALDECI |

### Phase 4: Production Hardening (Week 4+)
| # | Task | Owner | Details |
|---|---|---|---|
| 4.1 | Multi-tenant isolation | Agent Team | TrustGraph namespace + ALDECI `TenantLifecycleManager` |
| 4.2 | Resurrect `SecurityManager` + `RBACManager` | Agent Team | Enterprise-grade auth for multi-tenant |
| 4.3 | Context Core versioning | Agent Team | Snapshot/rollback knowledge at any point |
| 4.4 | Resurrect `KeyProvider` + `AWSKMSProvider` | Agent Team | Enterprise key management for evidence encryption |
| 4.5 | Performance benchmarking | Opus CTO | Decision latency, accuracy, FP rate vs competitors |
| 4.6 | Rename Fixops → ALDECI | Agent Team | Across entire codebase, docs, configs |
| 4.7 | Maintain 1,536+ tests through migration | Agent Team | All existing tests pass + new TrustGraph tests |
| 4.8 | Documentation + API docs | Agent Team | OpenAPI spec, deployment guide |

---

## Part 7: Module-by-Module Integration Map (All 20+ Modules)

| Module | File(s) | Lines | Functions | Integration Strategy |
|---|---|---|---|---|
| `core/processing_layer.py` | 1 | 461 | 28 | Replace networkx graph with TrustGraph SDK |
| `core/enhanced_decision.py` | 1 | 1,279 | 41 | Replace with LLM Council Engine |
| `core/llm_providers.py` | 1 | 619 | 28 | Add OllamaProvider + OpenRouterProvider |
| `core/decision_tree.py` | 1 | 329 | 16 | Keep 6-step flow, swap graph queries to TrustGraph |
| `core/compliance.py` | 1 | 133 | 8 | Connect to Core 3 for framework lookups |
| `core/ssdlc.py` | 1 | ~150 | ~10 | Integrate SSVC with Core 3 |
| `core/vector_store.py` | 1 | 444 | 24 | Replace ChromaDB with Qdrant via TrustGraph |
| `core/configuration.py` | 1 | ~800 | 51 | Add TrustGraph connection config to overlay |
| `core/connectors.py` | 1 | ~300 | ~15 | Extend with TrustGraph MCP connections |
| `core/context_engine.py` | 1 | ~200 | ~12 | Replace with TrustGraph Context Core lookups |
| `core/stage_runner.py` | 1 | ~600 | 37 | Route stage outputs to TrustGraph |
| `risk/enrichment.py` | 1 | 305 | ~15 | Feed enriched data to Core 2 via Pulsar |
| `risk/forecasting.py` | 1 | ~300 | ~12 | Keep Bayesian math, add TrustGraph context |
| `risk/threat_model.py` | 1 | ~250 | ~10 | Replace reachability with GraphRAG traversal |
| `risk/feeds/orchestrator.py` | 1 | 378 | ~18 | Stream to Pulsar instead of in-memory |
| `risk/feeds/*.py` | 8 | ~2000 | ~200 | Keep parsers, change output target |
| `services/graph/graph.py` | 1 | 721 | 42 | Replace entirely with TrustGraph REST client |
| `apps/api/normalizers.py` | 1 | 1,783 | 57 | Keep SARIF/CVE/CNAPP/VEX/BusinessContext normalizers; replace lib4sbom SBOM path with OWASP DC→DT pipeline; add TrustGraph ingestion step |
| `apps/api/knowledge_graph.py` | 1 | ~200 | ~10 | Replace with TrustGraph GraphRAG queries |
| `backend/api/graph/router.py` | 1 | 99 | ~6 | Expose TrustGraph queries via existing API |
| `ssvc/` | 3 | ~300 | ~20 | Integrate SSVC with Core 3 compliance graph |
| `core/flags/` | 5 | ~400 | ~30 | Keep feature flags, add TrustGraph feature gates |

---

## Part 8: Cost Analysis

### Monthly Operating Cost (unchanged from v1)

| Component | Cost |
|---|---|
| Ollama (Gemma 4 27B local) | $0 |
| Qwen 3.6+ / DeepSeek V3 / Llama 4 (OpenRouter free) | $0 |
| Claude Opus 4.6 (CTO escalation, 5% of decisions) | ~$30-50/mo |
| TrustGraph + Neo4j + Qdrant + Pulsar (self-hosted Docker) | $0 |
| OWASP Dependency-Check + Dependency-Track (self-hosted) | $0 |
| OpenRouter API overhead | ~$5-10/mo |
| **TOTAL** | **~pricing TBD (target: $199-$1,499/month tiered)** |

### vs Competitors

| Platform | Annual Cost | What You Get |
|---|---|---|
| **ALDECI** | **~$420-720/year** | ASPM + CTEM + CSPM + LLM Council + Knowledge Graph + 28 feeds |
| Apiiro | $100K-500K+ | ASPM only |
| Aikido | $4,200-12,600 | ASPM (developer-focused) |
| Wiz | $50K-500K+ | CSPM/CNAPP (cloud only) |
| CrowdStrike | $30-92/device/year | CTEM + endpoint (per-device) |

---

## Part 9: Why NOT MindsDB (unchanged verdict)

MindsDB was evaluated and rejected for ALDECI's LLM agent layer:

1. **SQL injection risk**: Agents write SQL to production databases — unacceptable for a security platform
2. **No consensus**: Single-model decisions without peer review
3. **No context versioning**: Cannot snapshot knowledge state for audit/compliance
4. **Scaling limitations**: No horizontal scaling for self-hosted
5. **Limited free model support**: OpenRouter requires community workarounds
6. **Wrong abstraction**: Data hub (database queries) vs knowledge reasoning (security decisions)

---

## Part 10: OWASP Dependency-Check + Dependency-Track Architecture

### Why Replace lib4sbom with OWASP DC+DT

| Dimension | lib4sbom (current) | OWASP DC + DT (new) |
|---|---|---|
| **SBOM parsing** | CycloneDX/SPDX/Syft/GitHub format detection | Same + CPE-based auto-detection from source code/manifests |
| **Vulnerability correlation** | None (ALDECI does this in `enrichment.py`) | Built-in: NVD + OSS Index + GitHub + Snyk + OSV + VulnDB |
| **Policy engine** | None | `failBuildOnCVSS` threshold gating, license compliance, operational risk |
| **EPSS integration** | Custom in `enrichment.py` | Native EPSS scoring in Dependency-Track |
| **Impact analysis** | Manual per-project | Automatic cross-portfolio impact detection |
| **SBOM lifecycle** | Parse only | Full lifecycle: generate → ingest → correlate → republish CycloneDX |
| **Language support** | Python SBOM parsing only | DC analyzers for Java, .NET, Node, Python, Ruby, Go, Rust, C/C++ |
| **CI/CD integration** | None | Maven/Gradle/Ant plugins, GitHub Actions, Jenkins, Azure DevOps |
| **Multi-tenancy** | None | DT supports teams + portfolio hierarchies |
| **Output formats** | Python dicts | HTML, JSON, XML, CSV, SARIF, JUnit, CycloneDX |
| **Cost** | Free (PyPI) | Free (Apache 2.0, self-hosted Docker) |

### OWASP DC+DT Integration Architecture

```
SOURCE CODE / MANIFESTS
         │
         ▼
┌─────────────────────────────────┐
│  OWASP Dependency-Check v12.2   │  ← CLI scan or Maven/Gradle plugin
│  ├── Analyzers: CPE matching     │
│  ├── Data: NVD + NPM Audit +    │
│  │   OSS Index + RetireJS +      │
│  │   Bundler Audit               │
│  └── Output: CycloneDX BOM +    │
│       SARIF + JSON reports       │
│  Gate: failBuildOnCVSS ≥ 7.0    │
└────────────┬────────────────────┘
             │ CycloneDX BOM
             ▼
┌─────────────────────────────────┐
│  OWASP Dependency-Track (DT)    │  ← REST API + webhooks
│  ├── 6 vuln sources:            │
│  │   NVD, OSS Index, GitHub,    │
│  │   Snyk, OSV, VulnDB          │
│  ├── EPSS scoring               │
│  ├── Policy engine              │
│  ├── Portfolio impact analysis   │
│  └── CycloneDX republication    │
└────────────┬────────────────────┘
             │ Correlated findings
             ▼
┌─────────────────────────────────┐
│  ALDECI sbom_runtime_correlator │  ← Existing 27KB correlator
│  ├── Fuzzy-match runtime pkgs   │
│  ├── +0.30 confirmed runtime    │
│  ├── -0.20 tree-shaken (SBOM)   │
│  ├── +0.50 shadow dependencies  │
│  └── Risk delta calibration     │
└────────────┬────────────────────┘
             │ Calibrated components
             ▼
┌─────────────────────────────────┐
│  TrustGraph Core 1              │  ← Knowledge graph ingestion
│  (Customer Environment)         │
│  ├── RDF triples per component  │
│  ├── Dependency relationships   │
│  ├── Vuln→component mapping     │
│  └── Per-tenant isolation       │
└─────────────────────────────────┘
```

### What Changes in InputNormalizer

The `InputNormalizer` class (1,783 lines) retains its role for 5 of 6 input types. Only the SBOM path changes:

| Method | Before | After |
|---|---|---|
| `load_sbom()` | lib4sbom parser + fallback CycloneDX/Syft/GitHub | DC CLI invocation → CycloneDX output → DT REST API |
| `load_sarif()` | **No change** — Pydantic SARIF validation retained |
| `load_cve_feed()` | **No change** — cvelib validation retained |
| `load_cnapp()` | **No change** — generic cloud findings retained |
| `load_vex()` | **No change** — CycloneDX VEX parsing retained |
| `load_business_context()` | **No change** — FixOps/OTM/SSVC retained |

### Customization for ALDECI's Needs

OWASP DC is highly customizable via `dependency-check.properties`:

1. **Custom CPE suppression rules** — suppress false positives for internal packages
2. **NVD API key** — required for faster NVD feed downloads (free key from NIST)
3. **Analyzer toggles** — enable/disable per ecosystem (e.g., enable Python/Node, disable .NET)
4. **CVSS threshold** — `failBuildOnCVSS=7.0` for CI/CD gates
5. **Proxy/air-gap support** — mirror NVD data locally for air-gapped environments
6. **DT policy rules** — custom per-tenant policies via DT REST API

### Docker Deployment (adds to TrustGraph stack)

```yaml
# Add to docker-compose.yml alongside TrustGraph services
dependency-track-api:
  image: dependencytrack/apiserver:latest
  ports: ["8081:8080"]
  volumes: ["dt-data:/data"]
  environment:
    ALPINE_DATABASE_MODE: "external"

dependency-track-frontend:
  image: dependencytrack/frontend:latest
  ports: ["8082:8080"]
  depends_on: [dependency-track-api]
```

DC runs as CLI in CI/CD (no persistent container needed).

---

## Part 12: Persona Architecture — Who Uses ALDECI and How

### 12.1 Current Persona Model (from codebase audit)

ALDECI already has **25 enterprise personas** defined in `suite-ui/aldeci-ui-new/e2e/helpers/auth.ts` with full RBAC enforcement, cross-role workflow tests, and per-persona API endpoint mappings. This is more mature than most competitors' persona models, but the architecture needs to ensure every persona's workflow is fully served by the rearchitected TrustGraph-native platform.

**4 RBAC Roles**: `admin` (full access), `security_analyst` (read/write findings + policies), `developer` (read findings + SBOM), `viewer` (read-only findings + SBOM)

**Scopes** (from `lib/auth.tsx`): `admin:all`, `read:findings`, `write:findings`, `read:sbom`, `write:sbom`, `read:users`, `write:users`, `read:policies`, `write:policies`

### 12.2 The 25 Personas — Grouped by Function

#### Tier 1: Executive & Board (Decision Consumers)

| # | Name | Title | Role | Primary Workflow | Key APIs | TrustGraph Core |
|---|---|---|---|---|---|---|
| P01 | Sarah Chen | CISO | admin | Executive overview: dashboard → compliance posture → risk trends → top risks → MTTR → evidence export | analytics/dashboard, compliance-engine/soc2, analytics/mttr, evidence/status | Core 1+3+4 |
| P24 | Catherine Williams | Board Member | viewer | Board reporting: executive dashboard → compliance status → risk summary → ROI metrics | analytics/dashboard, analytics/compliance-status, analytics/roi | Core 1+3 |
| P02 | Marcus Johnson | VP Engineering | admin | Engineering ops: app inventory → remediation backlog → metrics → noise reduction → pipeline status | inventory/applications, remediation/backlog, brain/stats | Core 1+4 |

**Gap analysis**: These personas need **TrustGraph Core 4 (Decision Memory)** for "why did we decide X" questions at board meetings. Currently the executive dashboard pulls from analytics APIs — needs enrichment with LLM Council verdict summaries stored in Core 4. **Missing**: ROI calculation engine that quantifies "we saved $X by auto-closing Y false positives" — no competitor does this well either, so it's a differentiator opportunity.

**Amendment**: Add `ROIEngine` service that tracks: time-to-triage reduction (before/after ALDECI), false positive auto-closure rate, MTTR improvement, compliance evidence generation hours saved. Feeds into analytics/roi endpoint. Source data: Core 4 decision logs + remediation timestamps.

#### Tier 2: Security Operations (Daily Operators)

| # | Name | Title | Role | Primary Workflow | Key APIs | TrustGraph Core |
|---|---|---|---|---|---|---|
| P03 | Alex Rivera | SOC Analyst T1 | security_analyst | Triage: findings queue → dedup clusters → nerve center pulse → copilot → recent activity | analytics/findings, deduplication/clusters, nerve-center/pulse, copilot/ask | Core 1+2 |
| P04 | Priya Sharma | SOC Analyst T2 | security_analyst | Investigation: finding detail (graph nodes) → attack paths → MITRE mapping → MPTE verify → vuln feeds | brain/nodes, attack-sim/campaigns, mitre/heatmap, mpte/verify, feeds/nvd | Core 1+2+4 |
| P14 | Karen Taylor | IR Lead | security_analyst | Incident response: nerve center pulse → intel map → playbooks → state → cases | nerve-center/pulse, nerve-center/playbooks, cases | Core 1+2 |
| P19 | Daniel Thompson | SecOps Manager | admin | Ops management: dashboard → remediation metrics → teams → workflows → policies | analytics/dashboard, remediation/metrics, teams, workflows, policies | Core 1+4 |

**Gap analysis**: SOC T1 (Alex) spends most time in the findings queue. The 15-stage pipeline (Part 4B) outputs verdicts, but **the Copilot doesn't currently query TrustGraph**. The copilot/ask endpoint needs to be wired to TrustGraph GraphRAG so Alex can ask "show me all critical findings affecting payment services" and get graph-traversal results, not just keyword search.

**Amendment**: Wire Copilot to TrustGraph via `trustgraph_mcp_bridge.py` — copilot queries become GraphRAG queries across Core 1 (customer env) + Core 2 (threat intel). This makes the Copilot dramatically more useful than competitors' keyword search.

SOC T2 (Priya) needs attack path analysis. Currently `attack-sim/campaigns` exists but isn't connected to TrustGraph's graph topology. **Amendment**: Attack path engine should traverse TrustGraph Core 1 edges (vulnerability → affects → service → exposes → network_path → reachable_from → internet) instead of building a separate in-memory graph.

IR Lead (Karen) needs the Nerve Center to correlate incidents with known vulnerabilities. **Amendment**: Nerve Center should pull from TrustGraph Core 1+2 in real-time, showing "this PagerDuty incident correlates with CVE-2024-XXXX which we flagged 3 weeks ago" — uses the new `IncidentConnector` from Part 11.

#### Tier 3: Engineering & DevSecOps (Builders)

| # | Name | Title | Role | Primary Workflow | Key APIs | TrustGraph Core |
|---|---|---|---|---|---|---|
| P05 | James Wilson | Security Engineer | security_analyst | Scanner ops: scanner support → autofix generate → autofix stats | scanner-ingest/supported, autofix/generate, autofix/stats | Core 1 |
| P06 | Emma Davis | DevSecOps Engineer | security_analyst | Pipeline ops: policies → workflows → connector types | policies, workflows, connectors/types | Core 1+3 |
| P11 | Tom Anderson | AppSec Lead | security_analyst | App security: app inventory → remediation tasks → SLA check → triage funnel → noise reduction | inventory/applications, remediation/tasks, remediation/sla | Core 1+4 |
| P16 | Ryan Murphy | Platform Engineer | admin | Platform ops: health → metrics → system config → version → readiness | health, metrics, system/config, version, ready | N/A (infra) |
| P20 | Emily Chang | Developer (Security Champion) | developer | Dev workflow: findings → autofix suggestion → copilot → fix types → confidence levels | analytics/findings, autofix/generate, copilot/ask, autofix/fix-types | Core 1 |

**Gap analysis**: Emily (Developer) has the most constrained role (`developer` — read-only findings + SBOM). This is correct for security, but her workflow is crippled — she can see findings but can't mark them as "accepted risk" or "won't fix" or "fix in progress". She has to ask a security_analyst to do it.

**Amendment**: Add `developer:triage` scope — lets developers set finding status on findings assigned to them (not all findings). This is how Snyk and Semgrep work — developers can triage their own findings without needing analyst intervention. Update ROLE_SCOPES to:
```
developer: ["read:findings", "read:sbom", "write:own_findings_status"]
```

Emma (DevSecOps) manages connectors but the current `connectors/types` endpoint is minimal. **Amendment**: She needs the full connector management UI from Part 11 — `connector_routes.py` endpoints: registry, health, pull triggers, metrics. Add `write:connectors` scope to `security_analyst` role.

**Missing persona**: **P26 — SRE / Reliability Engineer** — cares about "which vulnerabilities affect our SLO-critical services?" Needs to correlate vulnerability data (Core 1) with service catalog data (Backstage `ServiceCatalogConnector` from Part 11) and SLO definitions. No competitor targets this persona explicitly. **Add**.

#### Tier 4: Risk & Compliance (Governance)

| # | Name | Title | Role | Primary Workflow | Key APIs | TrustGraph Core |
|---|---|---|---|---|---|---|
| P07 | Robert Kim | Compliance Officer | viewer | Compliance: frameworks → assess SOC2 → gaps → HIPAA → audit trail → evidence | compliance-engine/frameworks, compliance-engine/assess, audit/logs, evidence/status | Core 3 |
| P09 | David Park | Risk Manager | viewer | Risk: top risks → FAIL stats → risk predictions → risk velocity → coverage | fail/top-risks, fail/stats, predictions/risk-trajectory, analytics/coverage | Core 1+2 |
| P13 | Michael Brown | Audit Manager | viewer | Audit: logs → frameworks → decision trail → policy changes → user activity → chain verify | audit/logs, audit/decision-trail, audit/chain/verify | Core 3+4 |
| P18 | Olivia Martin | GRC Analyst | viewer | GRC: SOC2 → PCI-DSS → gaps → evidence → audit controls | compliance-engine/soc2, compliance-engine/pci-dss, evidence/status | Core 3 |
| P25 | Mark Roberts | External Auditor | viewer | External audit: logs → frameworks → evidence → chain verify → retention | audit/logs, evidence/status, audit/chain/verify, audit/retention | Core 3+4 |

**Gap analysis**: All 5 governance personas are `viewer` role — correct for separation of duties. But Robert (Compliance Officer) currently has the same permissions as Catherine (Board Member). In practice, a Compliance Officer needs to **trigger compliance assessments** (POST /compliance-engine/assess) and **generate evidence bundles** — these are write operations.

**Amendment**: Add `compliance_officer` role between `viewer` and `security_analyst`:
```
compliance_officer: ["read:findings", "read:sbom", "read:policies", "write:compliance", "write:evidence"]
```
This lets Robert trigger assessments and generate evidence without giving him finding triage or policy write access. Scoped write access to compliance + evidence only.

The External Auditor (Mark) workflow is solid — read-only audit logs + evidence + chain verification. TrustGraph Core 4 (Decision Memory, append-only) is perfect for this — audit trails are immutable once written to the graph.

**Missing persona**: **P27 — Privacy Officer / DPO** — with DSPM connectors (Part 11), ALDECI will discover sensitive data locations. A DPO needs to see: where is PII stored, which services process it, are data processing agreements in place, is data minimization enforced. Feeds from `DSPMConnector` into Core 1+3. No competitor except Wiz touches this, and Wiz doesn't tie it to application security. **Add**.

#### Tier 5: Specialized Security (Deep Expertise)

| # | Name | Title | Role | Primary Workflow | Key APIs | TrustGraph Core |
|---|---|---|---|---|---|---|
| P08 | Lisa Zhang | Penetration Tester | security_analyst | Pentest: MITRE techniques → MPTE verify → MPTE stats → attack campaigns → FAIL scores | mitre/techniques, mpte/verify, mpte/stats, attack-sim/campaigns, fail/scores | Core 1+2 |
| P12 | Jennifer Wu | Cloud Security Architect | security_analyst | Cloud security: KG status → brain stats → asset inventory → services → code-to-cloud | knowledge-graph/status, inventory/assets, code-to-cloud/status | Core 1 |
| P15 | Chris Lee | Security Data Scientist | security_analyst | ML/AI: ML status → models → anomaly detection → self-learning weights → stats | ml/status, ml/models, ml/predict, self-learning/weights | Core 1+4 |
| P17 | Nina Patel | Threat Intel Analyst | security_analyst | Threat intel: NVD → MITRE → EPSS → feeds status → FAIL history | feeds/nvd, mitre/techniques, feeds/epss, fail/history | Core 2 |
| P21 | Richard Adams | Security Architect | security_analyst | Architecture: KG analytics → brain most-connected → attack sim → MCP tools → predictions | knowledge-graph/analytics, brain/most-connected, mcp/tools | Core 1+2+4 |
| P22 | Amanda Scott | Supply Chain Security | security_analyst | Supply chain: inventory → provenance → graph lineage → risk | inventory/assets, provenance/status, graph/status, risk/status | Core 1 |
| P23 | Brian Hall | QA Security Tester | security_analyst | QA: scanner stats → dedup stats → remediation tasks → self-learning feedback | scanner-ingest/stats, deduplication/stats, self-learning/feedback | Core 1+4 |

**Gap analysis**: Lisa (Pen Tester) runs MPTE verification but the current MPTE engine isn't connected to TrustGraph. When she verifies a finding, the result should be stored in Core 4 (Decision Memory) so the LLM Council can factor in "we verified this is exploitable" in future verdicts.

**Amendment**: Wire MPTE verification results → TrustGraph Core 4. MPTE becomes Stage 4.5 in the pipeline — between Exploit Signals and Enrichment.

Jennifer (Cloud Security Architect) needs the code-to-cloud trace that Wiz and Apiiro tout. Currently `code-to-cloud/status` exists as an endpoint but the actual graph traversal (commit → build → image → deployment → runtime) requires TrustGraph Core 1 edges that the new connectors in Part 11 will populate: `GitHubSCMConnector` (code) → `CIPipelineConnector` (build) → `ContainerScanConnector` (image) → `K8sConnector` (deployment) → `RuntimeConnector` (runtime).

**Amendment**: The code-to-cloud trace is now architecturally complete with Part 11 connectors feeding Core 1. Mark this as a key differentiator — full provenance chain from commit SHA to running pod, all in one knowledge graph.

Amanda (Supply Chain) needs SBOM lifecycle management. The OWASP DC+DT pipeline (Part 10) handles this, but she also needs to see transitive dependency chains visualized. **Amendment**: Wire DC+DT output through TrustGraph Core 1, create `dependency → transitive_dependency → vulnerability` edges that the KnowledgeGraphExplorer UI can render.

**Missing persona**: **P28 — API Security Engineer** — with the rise of API-first architectures, someone needs to own "which APIs are exposed, which have auth, which are processing sensitive data." Uses `APISpecConnector` + `APIScanConnector` from Part 11. Competitors (Salt Security, 42Crunch) focus on this, but as a standalone product — ALDECI can provide it as part of the unified platform. **Add**.

#### Tier 6: IT Administration (Platform)

| # | Name | Title | Role | Primary Workflow | Key APIs | TrustGraph Core |
|---|---|---|---|---|---|---|
| P10 | Maria Lopez | IT Director | admin | IT admin: system health → system info → teams → users → analytics summary | system/health, system/info, teams, users | N/A |

**Gap analysis**: Maria manages users and teams but there's no **tenant management** for multi-tenant deployments. In the rearchitected platform, each customer tenant gets their own TrustGraph Core 1 (per-tenant). Maria needs endpoints to manage tenant provisioning, connector configurations per tenant, and resource quotas.

**Amendment**: Add tenant management endpoints: `POST /api/v1/tenants`, `GET /api/v1/tenants/{id}/connectors`, `PUT /api/v1/tenants/{id}/quotas`. Add `admin:tenants` scope.

### 12.3 New Personas to Add (Identified from Gap Analysis)

| # | Name | Title | Role | Justification | SDLC Stage | Competitors Covering |
|---|---|---|---|---|---|---|
| P26 | Sam O'Brien | SRE / Reliability Engineer | security_analyst | Correlates vulns with SLO-critical services; no competitor targets this | Operate | None explicitly |
| P27 | Rachel Moore | Privacy Officer / DPO | compliance_officer | DSPM data + GDPR/CCPA compliance; Wiz touches this but not tied to AppSec | Govern | Wiz (partial) |
| P28 | Kevin Nguyen | API Security Engineer | security_analyst | API inventory, auth gaps, sensitive data flow; standalone products exist but not unified | Code+Deploy | Salt, 42Crunch (standalone) |
| P29 | Diana Foster | Threat Modeler | security_analyst | Owns threat model lifecycle from design through validation; uses ThreatModelConnector | Design | IriusRisk (standalone) |
| P30 | Eric Walsh | MSSP / MDR Analyst | viewer | Managed security provider monitoring multiple tenants; needs multi-tenant view | Operate | ArmorCode (partial) |

### 12.4 Updated RBAC Model (6 Roles)

The current 4-role model (`admin`, `security_analyst`, `developer`, `viewer`) needs expansion:

| Role | Existing? | Scopes | Personas |
|---|---|---|---|
| `admin` | ✅ | `admin:all` (full access including tenant management) | P01 CISO, P02 VP Eng, P10 IT Director, P16 Platform Eng, P19 SecOps Mgr |
| `security_analyst` | ✅ | `read:findings`, `write:findings`, `read:sbom`, `write:sbom`, `read:policies`, `write:policies`, `write:connectors` | P03-P06, P08, P11-P12, P14-P15, P17, P21-P23, P26, P28-P29 |
| `compliance_officer` | **NEW** | `read:findings`, `read:sbom`, `read:policies`, `write:compliance`, `write:evidence` | P07 Compliance, P18 GRC, P27 DPO |
| `developer` | ✅ (updated) | `read:findings`, `read:sbom`, `write:own_findings_status` | P20 Dev Champion |
| `viewer` | ✅ | `read:findings`, `read:sbom` | P09 Risk Mgr, P13 Audit Mgr, P24 Board, P25 External Auditor, P30 MSSP |
| `service` | ✅ (in e2e) | Machine-to-machine scopes for CI/CD integrations and n8n connector workflows | CI/CD bots, n8n, scanner integrations |

### 12.5 Persona → Architecture Feature Cross-Reference

Every Part of this architecture document must serve at least one persona. If a feature exists that no persona uses, it's bloat. If a persona needs something no feature provides, it's a gap.

| Architecture Part | Serves Personas | Gap Found? |
|---|---|---|
| Part 1: Current State Analysis | All (context) | — |
| Part 2: TrustGraph Integration | P04, P12, P15, P17, P21, P22 (graph-dependent) | ✅ Copilot (P03, P20) not yet wired to TrustGraph |
| Part 3: LLM Consensus | P03, P04, P08, P09, P11, P19 (verdict consumers) | ✅ MPTE results (P08) not feeding into Council |
| Part 4: Competitive Annihilation | All (strategic) | — |
| Part 4B: 15-Stage Pipeline | P03-P06, P08, P11, P14, P17, P19, P23 (pipeline users) | ✅ Need Stage 4.5 (MPTE verification inject) |
| Part 4C: LLM Council Input Feed | P03, P04, P09, P15 (AI consumers) | — |
| Part 5: Rearchitected Stack | P16 (platform) | — |
| Part 6: Execution Plan | All | ✅ Add persona validation to each phase gate |
| Part 7: Module Map | P16, P06 (integration) | — |
| Part 8: Cost Analysis | P01, P02, P10, P24 (budget owners) | ✅ Add per-persona license cost (currently $0 but need to quantify ops cost) |
| Part 9: MindsDB Rejection | P15, P21 (architecture) | — |
| Part 10: OWASP DC+DT | P05, P06, P22, P23 (scanner/SBOM) | — |
| Part 11: Connector Framework | P06, P12, P14, P22, P26, P27, P28 (data consumers) | ✅ Need ConnectorManagement UI page for P06 |
| Part 12: Persona Architecture | All | This section |

### 12.6 Architecture Amendments Summary (from Persona Analysis)

These amendments are REQUIRED changes identified by walking every persona through the architecture:

1. **Wire Copilot → TrustGraph GraphRAG** (serves P03, P04, P20): Copilot queries become graph traversals, not keyword search. Makes ALDECI's copilot dramatically better than competitors.

2. **Add `compliance_officer` RBAC role** (serves P07, P18, P27): Compliance personas need scoped write access to compliance + evidence without full analyst privileges.

3. **Update `developer` scopes** (serves P20): Add `write:own_findings_status` so developers can triage their assigned findings without analyst bottleneck.

4. **Wire MPTE → TrustGraph Core 4** (serves P08): Pen test verification results stored in Decision Memory, feeding into LLM Council for future verdicts. Creates Stage 4.5 in pipeline.

5. **Add ROIEngine service** (serves P01, P02, P24): Quantifies ALDECI's value: time saved, false positives auto-closed, MTTR improvement, compliance hours saved. No competitor does this well.

6. **Attack paths traverse TrustGraph** (serves P04, P08, P12, P21): Replace in-memory attack graph with TrustGraph Core 1 topology traversal. One graph to rule them all.

7. **Code-to-cloud trace complete** (serves P12, P22): Part 11 connectors (SCM→CI/CD→Container→K8s→Runtime) populate Core 1 edges that make the full provenance chain queryable.

8. **Add ConnectorManagement UI page** (serves P06): DevSecOps engineer needs to manage connectors, view health, trigger pulls, configure schedules through the UI.

9. **Add tenant management** (serves P10, P30): Multi-tenant connector configs, resource quotas, tenant provisioning endpoints.

10. **Add 5 new personas** (P26-P30): SRE, Privacy Officer, API Security Engineer, Threat Modeler, MSSP Analyst — covering gaps no competitor fully addresses.

### 12.7 Persona Workflow Validation in Beast Mode

Every Beast Mode phase gate MUST include persona validation:

- **Phase 1 (TrustGraph Core)**: Validate P12 (Cloud Architect) can query knowledge graph, P15 (Data Scientist) can access ML endpoints, P21 (Security Architect) can see graph analytics
- **Phase 2 (Connector Framework)**: Validate P06 (DevSecOps) can manage connectors, P22 (Supply Chain) can see SBOM lifecycle, P26 (SRE) can correlate vulns with services
- **Phase 3 (LLM Council)**: Validate P03 (SOC T1) gets AI-enriched verdicts, P04 (SOC T2) sees MPTE-informed decisions, P20 (Developer) gets actionable autofix
- **Phase 4 (Full Platform)**: Run ALL 30 persona E2E workflows against live deployment. Every persona's workflow must complete with 200 status on all endpoints. This is the acceptance criteria.

The existing Playwright + Allure E2E framework in `suite-ui/aldeci-ui-new/e2e/` already supports this — extend `PERSONAS` array to 30 and add workflows for P26-P30.

---

## Part 11: Universal Connector Framework — Full SDLC PULL Architecture

### 11.1 The Problem: ALDECI Is PUSH-Only, Competitors Are PULL-First

**Current state (corrected by code-review-graph v2.2.2 re-scan)**: ALDECI has **13 PULL connectors** in `suite-core/core/security_connectors.py` (1,932 lines): Snyk, SonarQube, Dependabot, AWS Security Hub, Azure Defender, **Wiz** (CNAPP), **PrismaCloud** (CNAPP), **Orca Security** (CNAPP), **Lacework** (CNAPP), **ThreatMapper** (open-source CNAPP), **DependencyTrack** (SBOM lifecycle, 470+ lines). Plus **7 bidirectional connectors** in `suite-core/core/connectors.py` (3,620 lines): Jira, **Confluence**, Slack, ServiceNow, GitLab, Azure DevOps, GitHub. Plus 3 PUSH webhook adapters in `suite-integrations/integrations/` (GitHub, Jenkins, SonarQube) and 1 fan-out PUSH connector in `suite-core/connectors/universal_connector.py` (Jira, GitHub Issues, Slack). Additionally, **32 native scanner normalizers** exist in `suite-core/core/scanner_parsers.py` (2,395 lines): ZAP, Burp, Nessus, OpenVAS, Bandit, Checkmarx, SonarQube, Fortify, Veracode, Nikto, Nuclei, Nmap, Snyk, Prowler, Checkov, Trivy, Grype, Semgrep, Dependabot, Qualys, Tenable, Rapid7, Acunetix, AWS Inspector, GitLab SAST, SARIF (universal), CycloneDX (universal), SPDX (universal), Gitleaks, ClaudeCodeSecurity, Combobulator.

**Competitor reality**:
- **ArmorCode**: 320+ integrations, bidirectional, across ALL SDLC stages including design tools (Jira, Confluence, threat modeling)
- **Apiiro SHINE**: 60+ integrations across 18 categories — SCM, CI/CD, ticketing, SAST, DAST, SCA, secrets, runtime API, cloud, container, threat modeling, bug bounty, artifact registries, K8s, API gateways, identity, SIEM, service catalog
- **Cycode ConnectorX**: 100+ integrations, agent-based, CI-MON pipeline introspection
- **CrowdStrike**: EASM external network discovery, AI asset inventory, agentless cloud

**Gap (corrected)**: ALDECI already covers **52 tools natively** (13 PULL connectors + 7 bidirectional + 32 scanner parsers). The gap vs competitors (60-320+) is smaller than initially assessed. The main gap is PULL scheduling (connectors exist but aren't polled on cron) and SDLC stages not yet covered (design tools, CI/CD introspection, K8s, SIEM, EASM, compliance platforms).

### 11.2 Architecture: n8n + TrustGraph MCP + DefectDojo + Custom Connectors

The connector framework has 4 layers, all feeding into TrustGraph's 5 Knowledge Cores:

```
┌─────────────────────────────────────────────────────────────────────┐
│                    SDLC Stage Coverage                              │
│  Design │ Code │ Build │ Test │ Deploy │ Operate │ Govern          │
└────┬────┴───┬──┴───┬───┴──┬───┴────┬───┴────┬────┴────┬───────────┘
     │        │      │      │        │        │         │
     ▼        ▼      ▼      ▼        ▼        ▼         ▼
┌─────────────────────────────────────────────────────────────────────┐
│                 Layer 1: n8n Connector Orchestration                │
│  400+ pre-built integrations · Self-hosted · Apache 2.0            │
│  Cron/webhook triggers · Retry + error handling · Credential vault │
│  Workflows: poll → normalize → route to ALDECI ingest API          │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ HTTP POST (normalized payloads)
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│              Layer 2: ALDECI Connector Gateway                      │
│  New module: suite-core/connectors/connector_gateway.py            │
│  - Extends _BaseConnector pattern (retry, circuit breaker, rate    │
│    limit) with PULL scheduling + bidirectional sync                │
│  - ConnectorRegistry: discovers + manages all connector instances  │
│  - Ingest API: receives from n8n, custom connectors, webhooks      │
│  - Schema validation (Pydantic) per source type                    │
│  - Dedup at ingest (content hash → TrustGraph Core 4 check)       │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ Normalized findings
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│          Layer 3: DefectDojo Scanner Parser Layer                   │
│  200+ scanner format parsers (Semgrep, Trivy, Checkmarx, Nessus,  │
│  Burp, ZAP, Nuclei, Prowler, ScoutSuite, tfsec, checkov...)       │
│  Self-hosted · OWASP Flagship · Python · REST API                  │
│  Role: normalize ANY scanner output ALDECI hasn't seen before      │
│  Fallback parser: if ALDECI's InputNormalizer doesn't know a       │
│  format, route through DefectDojo's parser, get normalized JSON    │
└──────────────────────────────┬──────────────────────────────────────┘
                               │ Normalized to ALDECI schema
                               ▼
┌─────────────────────────────────────────────────────────────────────┐
│       Layer 4: TrustGraph MCP Bridge → 5 Knowledge Cores           │
│  TrustGraph's MCP integration (FastMCP Python servers):            │
│  - tg-set-mcp-tool: registers each connector as an MCP tool       │
│  - tg-invoke-mcp-tool: pulls data from registered tools on demand │
│  - Context Cores ingest: connector data → knowledge graph nodes    │
│  - OntologyRAG: maps connector data to security domain ontology   │
│  Routing: Design data → Core 1+3, Code data → Core 1+2,           │
│           Build data → Core 1, Test data → Core 1+2,               │
│           Deploy data → Core 1, Operate data → Core 1+2            │
└─────────────────────────────────────────────────────────────────────┘
```

### 11.3 SDLC Stage Connector Mapping

#### Stage 1: DESIGN (Pre-Code)

| Category | Tools | n8n Node | Custom Connector | TrustGraph Core |
|---|---|---|---|---|
| Requirements/Tickets | Jira, Linear, Asana, Monday, Azure Boards, Shortcut | ✅ n8n native | Bidirectional: pull tickets, push risk tags | Core 1 (Customer Env) |
| Architecture Docs | Confluence, Notion, Google Docs, SharePoint | ✅ n8n native | Pull design docs, extract architecture decisions | Core 1, Core 3 |
| Threat Modeling | OWASP Threat Dragon, Microsoft TMT, IriusRisk, Threagile | ❌ custom | `ThreatModelConnector`: parse .tm7/.json threat models, extract threats/mitigations | Core 1, Core 2 |
| API Design | Swagger/OpenAPI specs, Postman collections | ❌ custom | `APISpecConnector`: parse OpenAPI 3.x, extract endpoints/auth/data flows | Core 1 |
| Service Catalog | Backstage, OpsLevel, Cortex | ❌ custom | `ServiceCatalogConnector`: pull service ownership, dependencies, SLOs, tech stack | Core 1 |

**Why design stage matters**: Apiiro tracks "material changes" from design through deployment. ArmorCode connects to Jira/Confluence to correlate requirements with security findings. By pulling threat models and architecture docs into TrustGraph Core 1 BEFORE code is written, ALDECI can:
- Pre-populate the threat model for the LLM Council (Stage 7 of the 15-stage pipeline)
- Flag architectural decisions that conflict with compliance requirements (Core 3)
- Track threat-to-mitigation closure across the entire SDLC

#### Stage 2: CODE (Development)

| Category | Tools | n8n Node | Custom Connector | TrustGraph Core |
|---|---|---|---|---|
| SCM (Source Control) | GitHub, GitLab, Bitbucket, Azure Repos | ✅ n8n native | `SCMPollConnector`: poll repos, PRs, commits, branch policies, CODEOWNERS | Core 1 |
| SAST | Semgrep, SonarQube, Checkmarx, CodeQL, Snyk Code | Partial | `SASTConnector`: pull scan results via APIs, normalize to SARIF | Core 1, Core 2 |
| Secrets Detection | GitLeaks, TruffleHog, Detect-Secrets, GitHub Secret Scanning | ❌ custom | `SecretsConnector`: pull detected secrets, track rotation status | Core 1 |
| Code Review | GitHub PRs, GitLab MRs, Gerrit, Crucible | ✅ n8n native | Pull review comments, approvals, security-relevant discussions | Core 1, Core 4 |
| IDE Telemetry | VS Code, JetBrains (via extension API) | ❌ custom | Future: `IDEConnector` for real-time dev feedback (Snyk-style) | Core 1 |

**Code-stage pull enriches TrustGraph**: SCM polling lets ALDECI detect material changes (Apiiro's key feature) without waiting for webhooks. By pulling CODEOWNERS and branch protection rules into Core 1, the LLM Council can factor in "who owns this code" and "is this repo properly protected" during verdict generation.

#### Stage 3: BUILD (CI/CD Pipeline)

| Category | Tools | n8n Node | Custom Connector | TrustGraph Core |
|---|---|---|---|---|
| CI/CD Platforms | GitHub Actions, Jenkins, GitLab CI, Azure Pipelines, CircleCI, Argo | Partial | `CIPipelineConnector`: introspect pipeline configs, pull build logs, artifact metadata | Core 1 |
| SBOM Generation | Syft, CycloneDX CLI, SPDX tools | ❌ custom | Handled by OWASP DC+DT pipeline (Part 10) | Core 1 |
| Container Scanning | Trivy, Grype, Docker Scout, Snyk Container | ❌ custom | `ContainerScanConnector`: pull image scan results, layer analysis | Core 1, Core 2 |
| Artifact Registries | Docker Hub, ECR, GCR, ACR, Artifactory, Nexus | ✅ partial | `ArtifactRegistryConnector`: pull image manifests, signatures, provenance (SLSA) | Core 1 |
| Build Integrity | Sigstore/Cosign, in-toto, SLSA provenance | ❌ custom | `BuildIntegrityConnector`: verify signatures, pull attestations (Cycode CI-MON equivalent) | Core 1 |

**Build-stage introspection** is where Cycode's CI-MON shines — detecting pipeline tampering, unauthorized plugin injection, secrets in build logs. ALDECI's `CIPipelineConnector` replicates this by actively pulling pipeline configs and comparing against known-good baselines stored in TrustGraph Core 1.

#### Stage 4: TEST (Quality + Security)

| Category | Tools | n8n Node | Custom Connector | TrustGraph Core |
|---|---|---|---|---|
| DAST | OWASP ZAP, Burp Suite, Nuclei, Nikto | ❌ custom | `DASTConnector`: pull scan results, correlate with SAST findings | Core 1, Core 2 |
| SCA | Snyk, Dependabot, OWASP DC (Part 10), Mend, FOSSA | Existing PULL | Extend existing `SnykConnector` + `DependabotConnector` with scheduled polling | Core 1, Core 2 |
| Fuzzing | AFL++, libFuzzer, OSS-Fuzz, Jazzer | ❌ custom | `FuzzResultConnector`: pull crash reports, coverage data | Core 1 |
| Pentest Platforms | HackerOne, Bugcrowd, Cobalt, Synack | ❌ custom | `BugBountyConnector`: pull submissions, validate fixes (Apiiro covers this) | Core 1, Core 2 |
| API Security | 42Crunch, Salt Security, Noname | ❌ custom | `APIScanConnector`: pull API inventory, vulnerability findings | Core 1, Core 2 |

#### Stage 5: DEPLOY (Release + Infrastructure)

| Category | Tools | n8n Node | Custom Connector | TrustGraph Core |
|---|---|---|---|---|
| Cloud Posture | AWS Security Hub, Azure Defender, GCP SCC | Existing PULL | Extend `AWSSecurityHubConnector` + `AzureDefenderConnector` + add `GCPSCCConnector` | Core 1 |
| IaC Scanning | Checkov, tfsec, KICS, Bridgecrew | ❌ custom | `IaCScanConnector`: pull misconfigurations from IaC repos + cloud drift | Core 1, Core 3 |
| Kubernetes | Kubernetes API, Falco, KubeAudit, Polaris | ❌ custom | `K8sConnector`: pull pod security, RBAC, network policies, runtime events | Core 1 |
| Cloud Identity | AWS IAM, Azure AD/Entra, GCP IAM | ❌ custom | `CIEMConnector`: pull IAM policies, detect over-privileged identities (Wiz CIEM equivalent) | Core 1, Core 3 |
| Data Security | AWS Macie, Azure Purview, custom DLP | ❌ custom | `DSPMConnector`: pull data classification, sensitive data locations (Wiz DSPM equivalent) | Core 1, Core 3 |

#### Stage 6: OPERATE (Runtime + Monitoring)

| Category | Tools | n8n Node | Custom Connector | TrustGraph Core |
|---|---|---|---|---|
| SIEM/SOAR | Splunk, Sentinel, Chronicle, QRadar, Elastic SIEM | ✅ n8n native | `SIEMConnector`: pull security events, correlate with known vulns | Core 1, Core 2 |
| Runtime Protection | Falco, eBPF agents, Aqua, Sysdig | ❌ custom | `RuntimeConnector`: pull runtime alerts, syscall anomalies (Aikido Runtime equivalent) | Core 1, Core 2 |
| EASM | Shodan, Censys, SecurityTrails, ProjectDiscovery | ❌ custom | `EASMConnector`: discover external attack surface (CrowdStrike EASM equivalent) | Core 1, Core 2 |
| Incident Response | PagerDuty, OpsGenie, ServiceNow Incidents | ✅ n8n native | `IncidentConnector`: pull incidents, track MTTR, correlate with vulns | Core 1, Core 4 |
| Endpoint/Network | CrowdStrike Falcon, SentinelOne, Tenable | ❌ custom | `EndpointConnector`: pull host findings, correlate with code vulns | Core 1, Core 2 |

#### Stage 7: GOVERN (Compliance + Audit)

| Category | Tools | n8n Node | Custom Connector | TrustGraph Core |
|---|---|---|---|---|
| Compliance Frameworks | Vanta, Drata, Secureframe, Tugboat Logic | ❌ custom | `ComplianceConnector`: pull control status, evidence gaps | Core 3 |
| Policy Engines | OPA (exists), Kyverno, Sentinel | Existing | Extend existing OPA integration with scheduled policy sync | Core 3 |
| Audit/GRC | Archer, MetricStream, ServiceNow GRC | ❌ custom | `GRCConnector`: pull audit findings, risk register entries | Core 3, Core 4 |
| License Compliance | FOSSA, Snyk License, SPDX tools | ❌ custom | `LicenseConnector`: pull license risks (Aikido License Risk Engine equivalent) | Core 1, Core 3 |

### 11.4 n8n as Connector Orchestration Layer

**Why n8n** (not Airbyte, not custom polling):
- **400+ pre-built nodes**: covers Jira, GitHub, GitLab, Slack, Confluence, AWS, Azure, GCP, Splunk, PagerDuty, ServiceNow, and most SDLC tools out-of-the-box
- **Self-hosted**: runs in Docker alongside TrustGraph stack — no data leaves the customer's infrastructure
- **Apache 2.0 fair-code license**: free for self-hosted, no per-connector fees
- **Workflow automation**: cron-based polling, webhook triggers, conditional routing, error handling, retry logic — all configurable via UI or JSON
- **Credential vault**: encrypted storage for API tokens, OAuth flows — each customer's credentials isolated
- **Cost**: $0 self-hosted vs Airbyte's connector marketplace fees

**n8n deployment in ALDECI stack** (adds to existing Docker Compose):

```yaml
n8n:
  image: n8nio/n8n:latest
  ports: ["5678:5678"]
  environment:
    N8N_ENCRYPTION_KEY: "${N8N_ENCRYPTION_KEY}"
    WEBHOOK_URL: "https://${ALDECI_DOMAIN}/n8n/"
    N8N_DIAGNOSTICS_ENABLED: "false"
    N8N_SECURE_COOKIE: "true"
  volumes:
    - n8n-data:/home/node/.n8n
    - ./n8n-workflows:/home/node/workflows  # pre-built ALDECI workflow templates
  depends_on: [trustgraph, dependency-track-api]
  restart: unless-stopped
```

**Pre-built n8n workflow templates ALDECI ships**:
1. `github-repo-scanner.json` — Polls GitHub orgs, discovers repos, triggers SBOM generation via DC
2. `jira-security-sync.json` — Bidirectional: pulls tickets tagged "security", pushes ALDECI findings as comments
3. `jenkins-pipeline-auditor.json` — Polls Jenkins API, pulls pipeline configs, detects security misconfigs
4. `cloud-posture-collector.json` — Scheduled AWS Security Hub / Azure Defender / GCP SCC collection
5. `siem-event-correlator.json` — Pulls Splunk/Sentinel alerts, routes to ALDECI for vuln correlation
6. `compliance-evidence-collector.json` — Pulls evidence from Vanta/Drata, stores in TrustGraph Core 3
7. `easm-discovery.json` — Scheduled external surface discovery via Shodan/Censys APIs
8. `threat-model-ingester.json` — Watches Confluence/SharePoint for threat model docs, parses and ingests

### 11.5 TrustGraph MCP as Connector-to-Graph Bridge

TrustGraph's MCP (Model Context Protocol) integration bridges connectors to knowledge:

**How it works**:
1. Each ALDECI connector is registered as an MCP tool using `tg-set-mcp-tool`
2. TrustGraph can invoke any registered connector via `tg-invoke-mcp-tool` — enabling the graph to actively pull data when it detects missing context
3. Connector data flows through TrustGraph's OntologyRAG — automatically mapped to security domain ontology (CVE, CWE, CVSS, EPSS, ATT&CK, CAPEC, compliance controls)
4. GraphRAG creates relationship edges: `vulnerability --affects--> service --owned-by--> team --responsible-for--> compliance_control`

**MCP tool registration pattern**:

```python
# Register GitHub SCM connector as TrustGraph MCP tool
from trustgraph.clients.mcp_client import MCPClient

mcp = MCPClient(pulsar_host="pulsar://localhost:6650")
mcp.set_tool(
    name="aldeci-github-scm",
    description="Pull repositories, PRs, commits, branch policies from GitHub",
    input_schema={
        "type": "object",
        "properties": {
            "org": {"type": "string"},
            "action": {"enum": ["list_repos", "get_prs", "get_commits", "get_branch_protection"]},
            "repo": {"type": "string", "description": "optional: specific repo"},
            "since": {"type": "string", "format": "date-time"}
        },
        "required": ["org", "action"]
    },
    handler="suite-core.connectors.scm.GitHubSCMConnector"
)
```

**Current limitation**: TrustGraph MCP auth is "emerging" — not production-ready for multi-tenant credential isolation. Mitigation: n8n handles all credential management and API auth; TrustGraph MCP is used for graph-internal tool invocation only (no external API calls from MCP directly).

### 11.6 DefectDojo as Scanner Parser Complement

DefectDojo (OWASP Flagship, BSD license) provides 200+ scanner format parsers that ALDECI can leverage as a fallback normalization engine:

**Role in ALDECI**: NOT a replacement for ALDECI's pipeline — a fallback parser for formats not covered by ALDECI's **32 native scanner normalizers** in `scanner_parsers.py`.
- ALDECI's `InputNormalizer` handles known formats: SARIF, CycloneDX, SPDX, CVE-JSON, CNAPP, VEX, BusinessContext
- ALDECI's `scanner_parsers.py` already handles 32 scanner formats natively (ZAP, Burp, Nessus, Checkmarx, Fortify, Veracode, Trivy, Grype, Semgrep, etc.)
- OWASP DC+DT handles SBOM path (Part 10)
- DefectDojo handles everything else: Trivy JSON, Nuclei JSONL, Prowler CSV, Burp XML, Nessus .nessus, Qualys XML, Tenable SC, ScoutSuite JS, etc.
- When a connector delivers data in an unknown format, the gateway routes it through DefectDojo's parser API, gets normalized JSON back, then feeds it into the 15-stage pipeline

**DefectDojo deployment** (parser-only mode, no UI needed):

```yaml
defectdojo-api:
  image: defectdojo/defectdojo-django:latest
  ports: ["8083:8080"]
  environment:
    DD_DATABASE_URL: "postgresql://dd:dd@dd-postgres:5432/dd"
    DD_SECRET_KEY: "${DD_SECRET_KEY}"
    DD_DISABLE_NOTIFICATIONS: "true"  # parser-only, no alerts
  depends_on: [dd-postgres]

dd-postgres:
  image: postgres:15
  environment:
    POSTGRES_DB: dd
    POSTGRES_USER: dd
    POSTGRES_PASSWORD: dd
  volumes: ["dd-pgdata:/var/lib/postgresql/data"]
```

### 11.7 Custom Connector Framework — Extending _BaseConnector

ALDECI's existing `_BaseConnector` in `suite-core/core/connectors.py` already has retry, circuit breaker, and rate limiting. The new connector framework extends this with PULL scheduling and bidirectional sync:

```python
# New: suite-core/connectors/pull_connector.py

from abc import abstractmethod
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from core.connectors import _BaseConnector, ConnectorHealth, ConnectorOutcome

@dataclass
class PullSchedule:
    """Defines when and how a connector pulls data."""
    interval: timedelta           # How often to poll (e.g., 5m, 1h, 24h)
    initial_backfill: timedelta   # How far back to look on first pull
    incremental: bool = True      # Use last_pulled_at cursor
    last_pulled_at: Optional[datetime] = None
    priority: int = 5             # 1=critical (real-time), 10=background

class PullConnector(_BaseConnector):
    """Base class for PULL connectors that actively fetch data from external systems.
    
    Extends _BaseConnector with:
    - Scheduled polling with incremental cursors
    - Bidirectional sync (pull findings, push enrichments back)
    - TrustGraph Core routing (which Core(s) to feed)
    - n8n workflow integration (can be triggered by n8n or run standalone)
    """
    
    schedule: PullSchedule
    target_cores: List[int]  # Which TrustGraph Cores to feed [1,2,3,4,5]
    
    @abstractmethod
    async def pull(self, since: Optional[datetime] = None) -> List[Dict[str, Any]]:
        """Pull data from the external system. Returns normalized findings."""
        ...
    
    @abstractmethod
    async def push_enrichment(self, entity_id: str, enrichment: Dict[str, Any]) -> ConnectorOutcome:
        """Push ALDECI enrichments back to the source system (bidirectional)."""
        ...
    
    async def execute_pull_cycle(self) -> ConnectorOutcome:
        """Full pull cycle: fetch → normalize → dedup → route to TrustGraph Cores."""
        since = self.schedule.last_pulled_at if self.schedule.incremental else None
        if since is None and self.schedule.incremental:
            since = datetime.utcnow() - self.schedule.initial_backfill
        
        findings = await self.pull(since=since)
        self.schedule.last_pulled_at = datetime.utcnow()
        
        # Dedup against TrustGraph Core 4 (Decision Memory)
        new_findings = await self._dedup_against_graph(findings)
        
        # Route to target TrustGraph Cores
        for core_id in self.target_cores:
            await self._ingest_to_core(core_id, new_findings)
        
        return ConnectorOutcome("fetched", {
            "total": len(findings),
            "new": len(new_findings),
            "cores_updated": self.target_cores
        })
```

### 11.8 Connector → 15-Stage Pipeline Integration

Every piece of data pulled by connectors enters the existing 15-stage pipeline. The connector framework determines the entry point based on data type:

| Data Type | Entry Point in Pipeline | Example |
|---|---|---|
| Raw SBOM (CycloneDX/SPDX) | Stage 1: Normalization (via OWASP DC+DT) | Syft output from artifact registry |
| SARIF scan results | Stage 1: Normalization (via InputNormalizer) | Semgrep, CodeQL, Checkmarx output |
| Unknown scanner format | Stage 1: Normalization (via DefectDojo parser) | Trivy JSON, Nuclei JSONL, Burp XML |
| Threat model documents | Stage 7: Threat Model (direct inject) | OWASP Threat Dragon .json |
| Compliance evidence | Stage 8: Compliance (direct inject) | Vanta control status |
| Cloud posture findings | Stage 1: Normalization → full pipeline | AWS Security Hub, Azure Defender |
| Runtime alerts | Stage 4: Exploit Signals (enrichment) | Falco, eBPF runtime events |
| EASM discoveries | Stage 5: Enrichment (new attack surface) | Shodan, Censys external findings |
| SCM metadata | Stage 3: Business Context (enrichment) | CODEOWNERS, branch policies, PR authors |
| CI/CD pipeline configs | Stage 3: Business Context (enrichment) | Jenkins pipeline.yml, GitHub Actions workflows |
| Incident data | Stage 12: LLM Council (decision context) | PagerDuty incidents, MTTR history |
| License findings | Stage 8: Compliance + Stage 14: Policy | FOSSA, Snyk License scan results |

### 11.9 Competitive Connector Comparison

| Capability | ALDECI (with framework) | Apiiro SHINE | ArmorCode | Cycode ConnectorX | CrowdStrike |
|---|---|---|---|---|---|
| **Total integrations** | 52 native + 400+ (via n8n) + 170+ additional parsers (DefectDojo) + custom | 60+ native | 320+ native | 100+ native | 30+ native |
| **Design stage** | Jira, Confluence, Threat Dragon, IriusRisk, Backstage | Jira, Confluence | Jira, Azure Boards | Jira | ❌ |
| **SCM polling** | GitHub, GitLab, Bitbucket, Azure Repos | ✅ deep (material changes) | ✅ | ✅ (code fingerprinting) | ❌ |
| **CI/CD introspection** | Jenkins, GH Actions, GitLab CI, Azure Pipelines, Argo, CircleCI | ✅ | ✅ | ✅ (CI-MON) | ❌ |
| **SAST/DAST/SCA** | All tools via DefectDojo parsers + native | 8+ scanners | 50+ scanners | 10+ scanners | ❌ |
| **Cloud posture** | AWS, Azure, GCP (native + n8n) | ❌ | ✅ | ❌ | ✅ (Falcon) |
| **Kubernetes** | K8s API, Falco, KubeAudit, Polaris | ❌ | ✅ | ❌ | ✅ |
| **CIEM/DSPM** | Custom connectors (Wiz equivalents) | ❌ | ❌ | ❌ | ❌ |
| **EASM** | Shodan, Censys, SecurityTrails | ❌ | ❌ | ❌ | ✅ |
| **Runtime/eBPF** | Falco, Sysdig, custom eBPF | ❌ | ❌ | ❌ | ✅ (Falcon) |
| **SIEM integration** | Splunk, Sentinel, Chronicle, QRadar, Elastic | ❌ | Splunk, Sentinel | ❌ | ✅ (native) |
| **Service catalog** | Backstage, OpsLevel, Cortex | ❌ | ❌ | ❌ | ❌ |
| **Bug bounty** | HackerOne, Bugcrowd, Cobalt | HackerOne, Bugcrowd | ❌ | ❌ | ❌ |
| **Bidirectional sync** | ✅ (push enrichments back) | ✅ | ✅ | ✅ | ❌ |
| **Self-hosted** | ✅ (100% — n8n + DefectDojo + TrustGraph) | ❌ SaaS | ❌ SaaS | ❌ SaaS | ❌ SaaS |
| **Credential isolation** | ✅ (n8n vault, per-tenant) | ❌ vendor-managed | ❌ vendor-managed | ❌ vendor-managed | ❌ vendor-managed |
| **Cost per connector** | $0 (all open source) | $$$$ bundled | $$$$ bundled | $$$$ bundled | $$$$ bundled |

**ALDECI's unique advantage**: 52 native connectors/parsers + 400+ n8n integrations + 170+ additional DefectDojo parsers = **620+ tool coverage**, entirely self-hosted, $0 per connector, with TrustGraph providing the knowledge graph that NO competitor has at the connector layer. The 13 existing PULL connectors (including 5 CNAPP connectors for Wiz/PrismaCloud/Orca/Lacework/ThreatMapper) mean ALDECI already has deeper cloud security integration than most competitors.

### 11.10 Phased Connector Rollout

**Phase 1 (Foundation — Week 1-2 of Phase 2)**:
- Deploy n8n in Docker stack
- Build `PullConnector` base class extending `_BaseConnector`
- Build `ConnectorGateway` ingest API
- Wire 3 pre-built n8n workflows: GitHub SCM poll, Jira bidirectional, Jenkins audit
- Extend existing 5 PULL connectors with scheduled polling

**Phase 2 (Scanner Coverage — Week 3-4 of Phase 2)**:
- Deploy DefectDojo in parser-only mode
- Build DefectDojo parser routing in `ConnectorGateway`
- Add n8n workflows: cloud posture collector, SIEM correlator
- Build custom connectors: `ContainerScanConnector`, `IaCScanConnector`, `DASTConnector`

**Phase 3 (Full SDLC — Phase 3)**:
- Design stage connectors: `ThreatModelConnector`, `ServiceCatalogConnector`, `APISpecConnector`
- Runtime connectors: `RuntimeConnector` (eBPF/Falco), `EASMConnector` (Shodan/Censys)
- Governance connectors: `ComplianceConnector`, `LicenseConnector`, `GRCConnector`
- Register all connectors as TrustGraph MCP tools
- Build n8n workflow template library (ship 20+ templates)

**Phase 4 (Competitive Features — Phase 4)**:
- `CIEMConnector` (Wiz equivalent — IAM over-privilege detection)
- `DSPMConnector` (Wiz equivalent — data classification + sensitive data discovery)
- `BuildIntegrityConnector` (Cycode CI-MON equivalent — pipeline tampering detection)
- `BugBountyConnector` (Apiiro equivalent — HackerOne/Bugcrowd integration)
- `EndpointConnector` (CrowdStrike equivalent — host findings correlation)
- Marketplace-ready connector SDK: let customers build custom connectors

### 11.11 Docker Compose Additions (Full Connector Stack)

```yaml
# Added to existing ALDECI Docker Compose

# n8n — Connector Orchestration (400+ integrations)
n8n:
  image: n8nio/n8n:latest
  ports: ["5678:5678"]
  environment:
    N8N_ENCRYPTION_KEY: "${N8N_ENCRYPTION_KEY}"
    WEBHOOK_URL: "https://${ALDECI_DOMAIN}/n8n/"
    N8N_DIAGNOSTICS_ENABLED: "false"
  volumes:
    - n8n-data:/home/node/.n8n
    - ./n8n-workflows:/home/node/workflows
  depends_on: [trustgraph]
  restart: unless-stopped

# DefectDojo — Scanner Parser (200+ formats)
defectdojo-api:
  image: defectdojo/defectdojo-django:latest
  ports: ["8083:8080"]
  environment:
    DD_DATABASE_URL: "postgresql://dd:dd@dd-postgres:5432/dd"
    DD_SECRET_KEY: "${DD_SECRET_KEY}"
  depends_on: [dd-postgres]

dd-postgres:
  image: postgres:15
  environment: { POSTGRES_DB: dd, POSTGRES_USER: dd, POSTGRES_PASSWORD: dd }
  volumes: ["dd-pgdata:/var/lib/postgresql/data"]
```

**Updated ALDECI total stack**: TrustGraph (Neo4j/FalkorDB + Qdrant + Pulsar + Garage) + OWASP DC + OWASP DT + n8n + DefectDojo + ALDECI core services. All Apache 2.0 / BSD / fair-code. Total additional cost: $0 in software licenses. Hardware: +2GB RAM for n8n, +1GB RAM for DefectDojo parser-only mode.

---

## Part 13: Code-Review-Graph v2.2.2 Re-Analysis (Post-Merge)

### 13.1 Analysis Delta: v2.0 → v2.3

| Metric | v2.0 Analysis (pre-merge) | v2.3 Re-Analysis (post-merge) | Delta |
|---|---|---|---|
| Files parsed | 879 | 1,624 | +84.8% |
| Node count | 17,936 | 34,301 | +91.2% |
| Edge count | 103,950 | 216,476 | +108.2% |
| Languages | Python only | Python, JavaScript, C, TypeScript, TSX, Perl, Lua | +6 languages |
| Connectors found | 11 (documented) | 20 (13 PULL + 7 bidirectional) | +9 connectors missed |
| Scanner parsers | Unknown | 32 native normalizers (2,395 lines) | New discovery |
| Test functions | ~1,536 | 9,410 | +513% (TS/JS tests now visible) |
| Production functions | Unknown | 18,830 | Now tracked |
| Inheritance edges | 379 | 1,301 | +243% |

### 13.2 What the v2.0 Analysis Missed (and Why)

1. **CNAPP Connectors**: `security_connectors.py` is 1,932 lines — v2.0 only read the first 80 lines, missing Wiz (line 554), PrismaCloud (793), Orca (924), Lacework (1011), ThreatMapper (1122), DependencyTrack (1446). These are production-ready PULL connectors with API pagination, retry logic, and normalization — NOT stubs.

2. **Bidirectional Connectors**: `connectors.py` is 3,620 lines — v2.0 only read the first 400 lines to understand `_BaseConnector`. Missed Confluence (1055), full Slack (1374), ServiceNow (1588), GitLab (1953), Azure DevOps (2312), full GitHub (2761). All have both push AND pull methods already implemented.

3. **32 Scanner Normalizers**: `scanner_parsers.py` (2,395 lines) was never read in v2.0. Contains a complete normalizer framework with `_Base` class and 31 scanner-specific normalizers covering SAST, DAST, SCA, CSPM, IaC, secrets, and universal formats (SARIF, CycloneDX, SPDX).

4. **TypeScript/TSX Layer**: v2.0 used Python-only parsing. v2.2.2 parses TypeScript and TSX, revealing:
   - 25 enterprise personas with full RBAC (e2e/helpers/auth.ts)
   - 25 persona API workflow definitions (e2e/helpers/endpoints.ts)
   - 382 TypeScript nodes + 1,431 TSX nodes = 1,813 frontend/test nodes

5. **Test Coverage**: v2.0 found ~1,536 test functions. v2.3 found **9,410 test functions** — the JavaScript/TypeScript tests (Playwright E2E, Postman/Newman API tests) were invisible before. True test-to-production ratio: 0.50 (1 test per 2 production functions).

### 13.3 Architecture Impact

**What's now redundant in the connector framework**:
- The new `sdlc_connectors.py` `ContainerScanConnector` for Trivy/Grype overlaps with existing `TrivyScannerNormalizer` and `GrypeScannerNormalizer` in `scanner_parsers.py`. **Decision**: Keep both — `scanner_parsers.py` normalizes the output format, `sdlc_connectors.py` handles the PULL scheduling. They compose: ConnectorPULL → NormalizerPARSE → Pipeline.
- The `DASTConnector` for ZAP/Burp/Nuclei overlaps with existing `ZAPNormalizer`, `BurpNormalizer`, `NucleiNormalizer`. Same composability applies.
- `DependencyTrack` already has a full 470-line connector in `security_connectors.py` — the OWASP DT architecture in Part 10 should reference this existing connector, not create a new one.

**What's still genuinely missing** (confirmed by graph analysis):
- **Design stage connectors**: No Jira PULL (existing Jira is PUSH-only for issue creation), no Confluence PULL (existing Confluence is PUSH-only for page creation), no threat model parsing, no API spec parsing, no service catalog integration
- **CI/CD introspection**: No Jenkins pipeline config pulling, no GitHub Actions workflow parsing
- **K8s + Runtime**: No Kubernetes API connector, no Falco/eBPF integration
- **EASM**: No Shodan/Censys external discovery
- **SIEM**: No Splunk/Sentinel event correlation
- **Compliance platforms**: No Vanta/Drata integration
- **PULL scheduling**: All 13 existing connectors can fetch data but none run on a cron — they're called on-demand only
- **Bidirectional PULL activation**: The 7 bidirectional connectors in `connectors.py` have pull methods but they're not wired to the ingest pipeline

### 13.4 Corrected Connector Inventory

| Layer | Count | Source | Status |
|---|---|---|---|
| PULL connectors (security tools) | 13 | `security_connectors.py` | ✅ Built, need cron scheduling |
| Bidirectional connectors | 7 | `connectors.py` | ✅ Built, PULL side not wired |
| Scanner normalizers | 32 | `scanner_parsers.py` | ✅ Built, production-ready |
| PUSH webhook adapters | 3 | `suite-integrations/` | ✅ Built |
| Fan-out PUSH | 3 | `universal_connector.py` | ✅ Built |
| **Subtotal (existing)** | **58** | | |
| New SDLC PULL connectors | 11 | `sdlc_connectors.py` (new) | Built this session |
| PullConnector base framework | 1 | `pull_connector.py` (new) | Built this session |
| ConnectorGateway + Registry | 1 | `connector_registry.py` (new) | Built this session |
| TrustGraph MCP bridge | 1 | `trustgraph_mcp_bridge.py` (new) | Built this session |
| DefectDojo parser client | 1 | `defectdojo_parser.py` (new) | Built this session |
| n8n workflow templates | 3 | `n8n-workflows/` (new) | Built this session |
| **Subtotal (new)** | **18** | | |
| **TOTAL** | **76 native** + 400+ n8n + 170+ DefectDojo | | |

---

## Appendix A: code-review-graph Analysis Summary

**Tool**: code-review-graph v2.2.2 (Tree-sitter AST parsing + SQLite graph DB)
**Run (v2.3 re-analysis)**: 1,624 files parsed, 34,301 nodes, 216,476 edges, 7 languages (Python, JavaScript, C, TypeScript, TSX, Perl, Lua)
**Previous run (v2.0)**: 879 files parsed, 17,936 nodes, 103,950 edges (Python only)

### Key Structural Findings

| Metric | Value |
|---|---|
| Python files | 524 |
| Python functions | 3,226 |
| Python classes | 895 |
| Python tests | 1,536 |
| Call edges | 75,533 |
| Import edges | 3,459 |
| Inheritance edges | 379 |
| Highest criticality flow | `main` (0.98, depth 8, 35 nodes, 7 files) |
| Broadest flow | `run` (0.92, depth 2, 46 nodes, 23 files) |

### Most Complex Files (by function count)

| Functions | File | Role |
|---|---|---|
| 57 | `apps/api/normalizers.py` | Input normalization (14 data classes) |
| 51 | `core/configuration.py` | Overlay config system |
| 50 | `risk/feeds/ecosystems.py` | 10 ecosystem feed parsers |
| 48 | `archive/.../knowledge_graph.py` | Enterprise KG builder (resurrect) |
| 45 | `risk/feeds/vendors.py` | 9 vendor feed parsers |
| 42 | `services/graph/graph.py` | Provenance graph (replace with TG) |
| 41 | `core/enhanced_decision.py` | Multi-LLM consensus (replace with Council) |

### Class Hierarchy Depth

- **Deepest inheritance**: `RiskModel (ABC) → BayesianNetworkModel/BNLRHybridModel/WeightedScoringModel`
- **Widest inheritance**: `ThreatIntelligenceFeed (ABC)` → 28 feed subclasses
- **Most Pydantic models**: `apps/api/` routers (60+ BaseModel subclasses)
- **Enterprise patterns**: `BaseModel → AuditMixin + SoftDeleteMixin + EncryptedFieldMixin` (SQLAlchemy ORM)

---

## Appendix B: TrustGraph Technical Requirements

**Docker components** (for Shiva's Mac):
- Neo4j Community (GPL) or FalkorDB (MIT) — graph store
- Qdrant (Apache 2.0) — vector store
- Apache Pulsar (Apache 2.0) — message streaming
- TrustGraph services (Apache 2.0) — core platform
- Garage (object storage) — optional

**Python packages**: `trustgraph`, `trustgraph-cli`, `trustgraph-flow` (Python 3.11+)

**Key limitation**: TrustGraph cannot ingest raw `.py` files directly — code must be converted to text/markdown with context headers, or analyzed by code-review-graph first and the structural data fed to TrustGraph.

**Integration strategy**: Use code-review-graph for code structure analysis (AST, call graphs, blast radius) and TrustGraph for knowledge management (security data, compliance, threat intel, decisions). They are complementary, not competing.

---

## Part 14: Beast Mode v6 Execution Plan

Beast Mode v6 is the **autonomous execution plan** where Claude Code runs with `--dangerously-skip-permissions` to build ALDECI at maximum speed without manual approval gates. This plan **supersedes Part 6** (the old Master Execution Plan from v2.0). The difference: Part 6 is human-paced; Part 14 is machine-paced, designed for continuous daily runs with automated testing and commit gates.

### 14.1 Prerequisites (Run on Shiva's Mac)

Before starting Beast Mode v6, Shiva must prepare the environment:

1. **Git merge**: Push the `features/intermediate-stage` branch to origin
   ```bash
   git push origin features/intermediate-stage
   ```

2. **TrustGraph Docker stack**: Install and start
   - Neo4j 5.x (or FalkorDB)
   - Qdrant vector database
   - Apache Pulsar message broker
   - TrustGraph services container

3. **n8n Docker container**: Workflow automation engine
   - Pre-load 3 templates: GitHub, Jira, Cloud Posture

4. **DefectDojo (parser-only mode)**:
   - No full multi-tenant installation needed
   - Only the DefectDojo parser SDK for 170+ format routing
   - Integrated as microservice in docker-compose.yml

5. **Claude Code setup**:
   ```bash
   claude --dangerously-skip-permissions
   ```
   - Enables autonomous commits, test execution, and deployment
   - No manual `y/n` prompts during Phase execution

6. **CLAUDE.md at repo root**:
   - Create with complete project context (see section 14.6)
   - Claude Code reads this on startup to understand ALDECI

### 14.2 Phase 1: Foundation (Days 1-3) — TrustGraph + Knowledge Cores

**Goal**: Get TrustGraph running with 5 Knowledge Cores populated, all existing connectors wired to ingest pipeline.

| # | Task | Description |
|---|---|---|---|
| 1.1 | Deploy TrustGraph Docker stack | Start containers, initialize Neo4j schemas, verify all services healthy |
| 1.2 | Create Core 1 schema (Customer Environment) | SBOM, SARIF, CVE, CNAPP findings from customer deployments |
| 1.3 | Create Core 2 schema (Threat Intelligence) | NVD, EPSS, KEV, MITRE ATT&CK, OSV, third-party threat feeds |
| 1.4 | Create Core 3 schema (Compliance) | NIST, PCI-DSS, ISO 27001, SOC2, HIPAA, FedRAMP, CIS, OWASP frameworks |
| 1.5 | Create Core 4 schema (Decision Memory) | RDF triples with W3C PROV-O provenance for all decisions |
| 1.6 | Create Core 5 schema (Competitive Intel) | Competitive tracking, feature parity, market positioning |
| 1.7 | Wire 13 existing PULL connectors to PullConnector base | All connectors inherit cron scheduling, retry logic, error handling |
| 1.8 | Activate cron scheduling on PULL connectors | Daily 00:00, 06:00, 12:00, 18:00 UTC runs for feeds, APIs |
| 1.9 | Wire 7 bidirectional connectors' PULL side to ingest pipeline | GitHub, Jira, Linear, Asana, Azure DevOps, ServiceNow, Slack PULL paths |
| 1.10 | Wire 32 scanner normalizers to ConnectorGateway | SARIF, CVE, CNAPP, VEX, BusinessContext, SBOM (lib4sbom path) normalizers |
| 1.11 | Deploy ConnectorGateway FastAPI routes | `/connector/pull`, `/connector/push`, `/connector/status`, `/connector/logs` |
| 1.12 | Deploy ConnectorRegistry | Catalog all 20 connectors, capability discovery, MCP registration |
| 1.13 | Persona validation gate | **P06 (DevSecOps)** lists all connectors; **P16 (Platform Engineer)** checks health; both return HTTP 200 |

**Acceptance**: All 1,536+ existing tests pass. TrustGraph query latency < 500ms.

### 14.3 Phase 2: PULL Activation (Days 4-6) — Make Connectors Active

**Goal**: All 20 connectors running continuously, pushing findings into TrustGraph Cores via Pulsar streaming.

| # | Task | Description |
|---|---|---|---|
| 2.1 | Add cron-based PULL scheduling to all 13 PULL connectors | Update `PullConnector.schedule_pull()` with APScheduler or cron-rs |
| 2.2 | Test PULL on each connector (GitHub, Jira, NVD, etc.) | Verify data flows to Pulsar → TrustGraph ingestion pipeline |
| 2.3 | Activate bidirectional PULL on all 7 connectors | GitHub pull requests, Jira issues, Linear updates, Asana tasks, Azure, ServiceNow, Slack threads |
| 2.4 | Deploy n8n with 3 workflow templates | GitHub (PR → issue sync), Jira (comment → Slack alert), Cloud Posture (daily summary) |
| 2.5 | Wire TrustGraph MCP bridge | Register all 20 connectors as MCP tools; Claude can call `.connector_pull()` directly |
| 2.6 | Build ThreatModelConnector | STRIDE, PASTA, attack trees from design docs → Core 2 |
| 2.7 | Build EASMConnector | External attack surface enumeration (ASM) feeds → Core 2 |
| 2.8 | Build K8sSecurityConnector | Kubernetes audit logs, network policies, pod security standards → Core 1 |
| 2.9 | Activate all 20 connectors in production | No dry-run mode; all PULL and PUSH live |
| 2.10 | Persona validation gate | **P03 (SOC T1)** sees auto-pulled findings in dashboard; **P12 (Cloud Architect)** sees multi-cloud posture across AWS/Azure/GCP; **P22 (Supply Chain)** sees SBOM lifecycle (ingested, scanned, correlated) |

**Acceptance**: All 20 connectors reporting data. E2E test suite passes for all 30 personas.

### 14.4 Phase 3: LLM Council + AI Pipeline (Days 7-10)

**Goal**: Deploy the 3-stage LLM Council and wire the 15-stage enrichment pipeline to TrustGraph Cores.

| # | Task | Description |
|---|---|---|---|
| 3.1 | Deploy Karpathy 3-stage LLM Council | Independent → Peer Review → Synthesis stages |
| 3.2 | Wire 4 free models as council members | Qwen 2.5, Gemma 2 27B, DeepSeek-R1, Llama 3.1 70B (via Ollama or OpenRouter) |
| 3.3 | Implement Opus CTO escalation path | If 3 of 4 free models disagree, escalate to Opus for final verdict |
| 3.4 | Connect 15-stage enrichment pipeline to TrustGraph Cores | Each stage reads/writes to appropriate Core (1-5) |
| 3.5 | Wire Copilot → TrustGraph GraphRAG (Amendment #1) | Copilot queries GraphRAG for context-aware answers; answers read from Core 1-5 |
| 3.6 | Wire MPTE → Core 4 (Amendment #4) | Malicious Package Threat Engine findings stored as decision artifacts in Core 4 |
| 3.7 | Wire attack path discovery → TrustGraph graph traversal (Amendment #6) | Replace NetworkX queries with TrustGraph's native GraphRAG engine |
| 3.8 | Build ROIEngine service (Amendment #5) | Quantify impact of every decision: $ saved, risks eliminated, compliance gaps closed |
| 3.9 | Test Council consensus on 100 historical findings | Accuracy, latency, escalation rate |
| 3.10 | Persona validation gate | **P04 (SOC T2)** sees AI-enriched verdicts with confidence scores; **P08 (Pen Tester)** sees MPTE results integrated in Council consensus; **P01 (CISO)** sees ROI dashboard with business metrics |

**Acceptance**: Council verdicts reach 95%+ accuracy. ROI metrics quantifiable. No escalations on 90%+ of findings.

### 14.5 Phase 4: Full Platform (Days 11-14)

**Goal**: Complete all amendments, add 5 new personas, wire remaining connectors, and pass all E2E workflows.

| # | Task | Description |
|---|---|---|---|
| 4.1 | Add `compliance_officer` RBAC role (Amendment #2) | New role with access to Core 3, compliance reports, audit logs |
| 4.2 | Update developer scopes (Amendment #3) | Fine-grained RBAC for dev persona; can see SBOM, SARIF, but not raw findings |
| 4.3 | Build remaining 12 connectors | SIEM (Splunk, ELK), Compliance (ServiceNow, Jira), API Security (42Crunch), Runtime (Datadog, New Relic) |
| 4.4 | Deploy DefectDojo parser routing for 170+ formats | Normalize Trivy, Snyk, Checkmarx, Fortify, OWASP ZAP outputs → SARIF → Core 1 |
| 4.5 | Wire code-to-cloud trace through TrustGraph Core 1 (Amendment #7) | Git commit → Docker image → K8s deployment → runtime behavior all linkable in graph |
| 4.6 | Build ConnectorManagement UI page (Amendment #8) | Admin dashboard to enable/disable, schedule, view logs for all connectors |
| 4.7 | Add tenant management endpoints (Amendment #9) | Multi-tenancy via TrustGraph namespaces; CRUD tenant lifecycle |
| 4.8 | Add 5 new personas (P26-P30) to E2E test suite | Scenario: new hire onboarding, contractor access, compliance audit, incident response, board review |
| 4.9 | Run full 30-persona E2E workflow | All workflows must return HTTP 200 |
| 4.10 | Persona validation gate | **ALL 30 persona E2E workflows pass**. This is the final acceptance gate. |

**Acceptance**: 30/30 persona workflows pass. Zero regressions in 1,536+ existing tests. Ready for production.

### 14.6 Claude Code Configuration (CLAUDE.md)

Place this file at the repository root (`./CLAUDE.md`):

```markdown
# ALDECI (Fixops) — Beast Mode v6 Execution Context

## Project Identity
- **Name**: ALDECI (Autonomous Learning Defect Engineering for Continuous Intelligence)
- **Product**: Fixops (enterprise security and compliance platform)
- **Architecture Document**: `ALDECI_REARCHITECTURE_v2.md`
- **Personas**: 30 (CISO, DevSecOps, SOC T1/T2, Cloud Architects, Developers, Compliance Officers, etc.)

## Key Directories
- `/core` — Decision, compliance, vector store, connectors, configuration
- `/risk` — Enrichment, forecasting, threat models, feeds, SBOM/SARIF parsers
- `/services/graph` — ProvenanceGraph → TrustGraph bridge
- `/apps/api` — Normalizers (SARIF, CVE, CNAPP, VEX, BusinessContext, SBOM)
- `/backend/api` — REST routes, GraphQL endpoints
- `/ssvc` — SSVC decision framework
- `/suite-ui` — React dashboard with @xyflow/react visualization
- `/docker` — Docker Compose files for TrustGraph stack, n8n, DefectDojo

## Code Conventions
- **Language**: Python 3.11+
- **Async**: `async`/`await` throughout; `asyncio`, `aiohttp`
- **ORMs**: SQLAlchemy 2.0 with `BaseModel → AuditMixin + SoftDeleteMixin + EncryptedFieldMixin`
- **APIs**: FastAPI with Pydantic v2 models
- **Data flow**: Pulsar (message streaming) → TrustGraph (knowledge graph) → REST/GraphQL APIs
- **Graph DB**: TrustGraph SDK (Neo4j/FalkorDB backend)

## Testing Conventions
- **Unit tests**: `pytest` + `pytest-asyncio`; fixtures in `conftest.py`
- **E2E tests**: Playwright (UI) + Newman (API collections)
- **Persona E2E**: 30 workflow scripts covering all use cases
- **Coverage target**: Maintain 80%+ on `core/` modules; accept 40%+ on UI

## Git Conventions
- **Default branch**: `features/intermediate-stage`
- **Feature branches**: `feature/brief-name` off `features/intermediate-stage`
- **Commits**: Atomic, descriptive. Format: `[Module] Brief description; wires X to Y` 
- **Merge strategy**: Squash + rebase to `features/intermediate-stage`
- **Tags**: Version tags on production releases (e.g., `v2.3.0-beast-mode-v6`)

## Beast Mode Rules
- **No manual approval needed**: Run with `--dangerously-skip-permissions`
- **After each module**: Run full test suite (`pytest tests/`). Abort if failures.
- **After each phase**: Create atomic commit with phase name and persona validation results
- **If architecture changes**: Update `ALDECI_REARCHITECTURE_v2.md` immediately
- **If connector added**: Register in `ConnectorRegistry` and `TrustGraph MCP` bridge

## 30 Personas Reference
See `ALDECI_REARCHITECTURE_v2.md` Part 12 for complete persona definitions:
- P01–P05: C-suite + strategic (CISO, CRO, VP Security, VP DevOps, VP Engineering)
- P06–P15: Security operations (DevSecOps, SOC T1/T2, Threat Intel, IR Lead, etc.)
- P16–P20: Platform & cloud (Platform Engineer, Cloud Architect, CNAPP Specialist, etc.)
- P21–P25: Developer & compliance (Developer, SRE, Code Reviewer, Compliance Officer, Auditor)
- P26–P30: Extended (New hire, Contractor, Board member, Incident responder, Executive)

## Phase Checkpoints
After each phase, verify:
1. All new modules have E2E tests in persona suite
2. Existing 1,536+ tests still pass (no regressions)
3. Commit with phase name and persona gate results
4. Update architecture doc if anything changed

## To Run Beast Mode v6 Locally
```bash
# Terminal 1: Start infrastructure
docker compose -f docker-compose.yml -f docker/docker-compose.connectors.yml up -d

# Terminal 2: Start Claude Code in Beast Mode
claude --dangerously-skip-permissions
```

Then give Claude Code this first prompt:
```
Read ALDECI_REARCHITECTURE_v2.md Part 14 (Beast Mode v6 Execution Plan).
Execute Phase 1. Commit after completion. Report status.
```

## Success Metrics
- All 30 persona E2E workflows: HTTP 200 on every endpoint
- TrustGraph Knowledge Cores 1–5: Populated with real data (Cores 1 and 2 minimum)
- Connectors: All 20 active, pulling on cron schedule
- LLM Council: Producing verdicts with 95%+ accuracy
- Code quality: 1,536+ tests passing, no regressions
- Business value: ROI metrics quantifiable and positive

---
*This CLAUDE.md guides all Beast Mode v6 execution. It is the "system prompt" for autonomous AI agents working on ALDECI.*
```

### 14.7 Beast Mode v6 Commands

Shiva's startup sequence on his Mac:

**Terminal 1** — Start Docker infrastructure:
```bash
cd ~/Fixops  # adjust to your actual repo path
docker compose -f docker-compose.yml -f docker/docker-compose.connectors.yml up -d
```

Verify all services healthy:
```bash
docker compose ps
docker logs trustgraph-neo4j  # should show "Started"
```

**Terminal 2** — Start Claude Code in Beast Mode:
```bash
cd ~/Fixops  # adjust to your actual repo path
claude --dangerously-skip-permissions
```

**First prompt to Claude Code** (copy-paste):
```
Read ALDECI_REARCHITECTURE_v2.md Part 14 (Beast Mode v6 Execution Plan). 
Execute Phase 1. Commit after completion. Report status.
```

Claude will then:
1. Read Part 14
2. Start Phase 1 tasks
3. Run tests after each module
4. Commit with phase name and validation results
5. Move to Phase 2 automatically

Shiva can pause by pressing Ctrl+C; resume by re-running the claude command and providing the next phase number.

### 14.8 Success Criteria

Beast Mode v6 is **complete** when:

**Persona validation** (30/30 passing):
- All 30 persona E2E workflows return HTTP 200 on every endpoint they use
- No permission errors, no missing data, no timeouts

**Data population**:
- TrustGraph Knowledge Core 1 (Customer Env) has ≥100 SBOM/CVE findings
- TrustGraph Knowledge Core 2 (Threat Intel) has ≥1000 NVD/EPSS/ATT&CK entries
- TrustGraph Knowledge Core 3 (Compliance) has ≥500 framework entries
- TrustGraph Knowledge Core 4 (Decision Memory) has ≥50 decisions with full provenance
- TrustGraph Knowledge Core 5 (Competitive Intel) has ≥20 competitive data points

**Connectors**:
- All 13 existing PULL connectors running on cron schedules (verified via logs)
- All 7 bidirectional connectors actively PULLing (verified via last_pull_timestamp)
- All 20 connectors registered in TrustGraph MCP bridge and callable via Claude

**LLM Council**:
- 4 free models (Qwen, Gemma, DeepSeek, Llama) producing independent verdicts
- Opus CTO escalation triggered on disagreement (tested with 10 conflicting scenarios)
- Council accuracy ≥95% on validation set

**AI Pipeline**:
- Copilot answering questions via TrustGraph GraphRAG (10 sample queries)
- MPTE findings stored in Core 4 with full provenance
- Attack path discovery using TrustGraph graph traversal (not NetworkX)
- ROI metrics quantified for every decision (cost saved, risks eliminated, compliance gaps closed)

**Code quality**:
- All 1,536+ existing tests pass (zero regressions)
- No linting errors (`ruff`, `mypy`, `black`)
- All new modules have ≥80% test coverage

**Readiness**:
- ConnectorManagement UI page deployed and functional
- Tenant management endpoints working (multi-tenant isolation via TrustGraph namespaces)
- All 8 amendments wired (Copilot, Compliance Officer role, Developer scopes, MPTE, ROI, attack paths, code-to-cloud trace, UI, tenants)
- Git history clean; `features/intermediate-stage` branch ready for production merge

### 14.9 Phase 5: Enterprise Hardening (Days 15-21) — Beast Mode v7

Claude Code continues autonomously. No pause between Phase 4 and Phase 5.

**Multi-Tenant SaaS Control Plane**:
- Build `suite-core/tenancy/` module: tenant provisioning, isolation, resource quotas
- Each tenant gets: own TrustGraph Core 1 namespace, own n8n credential vault, own ConnectorRegistry
- Tenant management API: `POST /api/v1/tenants`, `GET /api/v1/tenants/{id}/usage`, `DELETE /api/v1/tenants/{id}`
- Tenant-scoped data isolation: all queries filtered by `tenant_id` — zero data leakage between tenants
- Admin super-tenant dashboard: cross-tenant metrics, resource usage, health

**Authentication & Identity**:
- SSO integration: SAML 2.0 + OIDC (Okta, Azure AD/Entra, Google Workspace)
- SCIM 2.0 provisioning: auto-sync users/groups from identity provider
- API key management: scoped keys per tenant, rotation, expiry, audit trail
- MFA enforcement: TOTP + WebAuthn/passkey support
- Session management: JWT with refresh tokens, configurable expiry, device tracking

**Production Infrastructure**:
- Replace Docker Compose with Helm charts (extend existing `docker/kubernetes/fixops-6suite/`)
- Horizontal scaling: ConnectorGateway behind load balancer, n8n queue mode with Redis workers
- Database migration: SQLite → PostgreSQL for all production stores
- TrustGraph HA: Neo4j cluster mode (3-node), Qdrant replication, Pulsar cluster
- Observability: OpenTelemetry traces on every pipeline stage, Prometheus metrics, Grafana dashboards
- Secrets management: HashiCorp Vault integration (replace env vars)

**Persona validation gate**: P10 (IT Director) can provision tenants, P30 (MSSP Analyst) can view multi-tenant dashboard, P16 (Platform Engineer) can see Grafana dashboards

### 14.10 Phase 6: Load Testing & Real Data (Days 22-28) — Beast Mode v8

**Load Testing**:
- Locust load tests: 10K findings/minute ingest, 100 concurrent API users, 50 simultaneous connector pulls
- Pipeline stress test: push 100K findings through 15-stage pipeline, measure end-to-end latency
- LLM Council throughput: measure verdict generation rate with 4 models
- TrustGraph query performance: benchmark GraphRAG queries at 1M+ nodes
- Identify and fix bottlenecks (expected: Pulsar throughput, Neo4j write locks)

**Real Data Validation (ALDECI eats its own dog food)**:
- Connect ALDECI to the Fixops GitHub org — pull all repos, PRs, commits, CODEOWNERS
- Connect ALDECI to Fixops CI/CD — pull GitHub Actions workflow results
- Run OWASP DC against Fixops dependencies — generate real SBOMs
- Run Semgrep + Bandit against Fixops codebase — generate real SAST findings
- Feed everything through the 15-stage pipeline → TrustGraph → LLM Council
- Validate: are the verdicts correct? Does the Copilot answer Shiva's questions accurately?
- Tune LLM Council weights based on real finding quality

**Edge Case Hardening**:
- Scanner format variations (malformed SARIF, partial CycloneDX, legacy Nessus XML)
- Connector failures (API rate limits, expired tokens, network timeouts — circuit breaker validation)
- Dedup accuracy: test with real duplicate findings across multiple scanners
- TrustGraph consistency: verify graph integrity after 100K+ entity insertions

**Persona validation gate**: All 30 personas tested with REAL Fixops data (not mock data)

### 14.11 Phase 7: Security & Compliance (Days 29-35) — Beast Mode v9

**ALDECI Self-Assessment** (use ALDECI's own compliance engine):
- Run SOC 2 Type II self-assessment using `compliance-engine/assess`
- Generate evidence bundles for all SOC 2 trust criteria
- Run PCI-DSS assessment (if handling card data in transit)
- HIPAA assessment (if healthcare customers targeted)
- Document all security controls in TrustGraph Core 3

**Security Hardening**:
- Pen test ALDECI itself using ALDECI's MPTE engine (recursive self-test)
- Run ALDECI's SAST scanners against ALDECI's own code (already partially done in autonomous-foundation)
- API security: rate limiting, input validation, CORS, CSP headers
- LLM Guard: prompt injection protection on Copilot and all LLM endpoints (already exists at `/api/v1/llm-guard/`)
- Secrets audit: ensure no credentials in code, config, or logs
- RBAC penetration: verify all 6 roles enforce correct scopes (extend existing e2e/persona-rbac-enforcement.spec.ts)

**Data Protection**:
- Encryption at rest: AES-256 for TrustGraph stores, PostgreSQL TDE
- Encryption in transit: TLS 1.3 everywhere, mTLS between internal services
- Data retention policies: configurable per-tenant, auto-purge
- PII detection: scan connector data for PII before ingestion, mask/redact
- Audit logging: immutable append-only logs in TrustGraph Core 4

**Persona validation gate**: P25 (External Auditor) can verify complete evidence chain, P07 (Compliance Officer) can export SOC 2 evidence bundle

### 14.12 Phase 8: Customer Onboarding & Docs (Days 36-42) — Beast Mode v10

**Installer & Deployment**:
- One-line installer script: `curl -fsSL https://install.aldeci.io | bash`
- Detects infrastructure (Docker/K8s), pulls images, initializes TrustGraph, runs health checks
- Onboarding wizard: guided setup via web UI (connect SCM, connect scanners, configure compliance frameworks)
- Pre-built n8n workflow library: 20+ templates shipped in Docker image, importable via UI

**Documentation** (Claude Code generates all of these):
- Admin Guide: installation, configuration, multi-tenant setup, backup/restore
- User Guide: per-persona quick-start guides (CISO gets different docs than SOC Analyst)
- API Reference: auto-generated from FastAPI OpenAPI spec, with examples
- Connector Catalog: every connector with setup instructions, supported versions, data flow diagrams
- Architecture Guide: simplified version of this document for customers
- Runbook: incident response for ALDECI itself (what to do when TrustGraph is down, connector fails, etc.)

**Demo Environment**:
- Pre-loaded demo tenant with synthetic but realistic data
- 500 findings across 10 repos, 3 cloud accounts, 5 scanners
- LLM Council verdicts pre-generated for instant demo experience
- All 30 personas have pre-configured demo accounts
- One-click demo launch: `docker compose -f docker-compose.demo.yml up`

**Persona validation gate**: New user (P00 — "first-time evaluator") can install ALDECI, connect GitHub, see first findings, and get an LLM Council verdict within 30 minutes

### 14.13 Phase 9: Pilot Preparation (Days 43-49) — Beast Mode v11

**First Customer Target**: Identify an enterprise design partner (existing contact, open-source user, or cold outreach). Ideal: mid-size company (500-5000 employees) with AWS + GitHub + Jira + at least 2 security scanners.

**Pilot Environment Build**:
- Dedicated pilot instance (not shared with Fixops dog-food)
- Tenant configuration: customer's GitHub org, AWS account, Jira project
- Connector activation: only the connectors the customer uses
- Compliance framework selection: customer picks (SOC 2, PCI-DSS, HIPAA, ISO 27001)
- SLA definition: response time, uptime, support channel

**Pilot Success Criteria** (agree with customer):
- ALDECI discovers ≥90% of findings their existing tools find (no regression)
- ALDECI deduplicates ≥30% of findings (noise reduction)
- LLM Council verdicts are ≥90% accurate (validated by customer's security team)
- Time-to-triage reduced by ≥50% vs current workflow
- At least 3 personas actively using the platform weekly

**Sales Engineering**:
- Competitive battle cards: ALDECI vs Apiiro, vs Wiz, vs Aikido (with live demo comparisons)
- Pricing model: per-asset or per-user, tiered (Starter/Pro/Enterprise)
- ROI calculator: customer inputs current tool spend + analyst hours, ALDECI outputs savings

**Persona validation gate**: Customer's CISO (P01 equivalent), Security Engineer (P05), and Developer (P20) complete their workflows successfully

### 14.14 Phase 10: Launch (Days 50-56) — Beast Mode v12

**Product Launch Readiness**:
- Landing page + product website
- Product Hunt / Hacker News launch post
- Open-source community edition: free tier with TrustGraph + 5 connectors + basic pipeline
- Enterprise edition: full 620+ connectors, LLM Council, multi-tenant, SSO, compliance
- GitHub repo public release (if open-sourcing community edition)

**Monitoring & Support**:
- Status page: uptime monitoring for SaaS instances
- Support ticketing: integrated with ALDECI's own Jira connector (meta!)
- Alerting: PagerDuty integration for infrastructure issues
- Customer health dashboard: usage metrics, adoption tracking per persona

**Continuous Beast Mode**:
- After launch, Beast Mode doesn't stop — it shifts to continuous improvement
- Weekly: competitor feature tracking (TrustGraph Core 5), new connector additions
- Monthly: LLM Council model updates (swap in better free models as they release)
- Quarterly: major feature releases driven by customer feedback + persona gap analysis

### 14.15 Full Timeline Summary

| Week | Phase | Beast Mode | Key Deliverable |
|---|---|---|---|
| 1-2 | Phase 1-4: Core Engine | v6 | Engine + connectors + LLM Council + 30 personas passing |
| 3 | Phase 5: Enterprise Hardening | v7 | Multi-tenant, SSO/SCIM, Helm charts, HA |
| 4 | Phase 6: Load Testing + Real Data | v8 | Fixops dog-food, 10K findings/min, bottleneck fixes |
| 5 | Phase 7: Security & Compliance | v9 | SOC 2 self-assessment, pen test, encryption, RBAC hardening |
| 6 | Phase 8: Onboarding & Docs | v10 | Installer, docs, demo environment, 30-min first-value |
| 7 | Phase 9: Pilot Prep | v11 | First customer environment, battle cards, pricing |
| 8 | Phase 10: Launch | v12 | Product launch, community edition, monitoring |

**Total: 8 weeks** (compressed from 10 — Beast Mode runs 24/7, no weekends off).

Claude Code executes Phases 1-8 autonomously. Phases 9-10 require Shiva's involvement for customer relationships and business decisions, but all code/docs/infrastructure work is still Beast Mode.

---

*This plan replaces Part 6 (v2.0 Master Execution Plan). It is designed for autonomous execution at machine speed with daily incremental delivery. Shiva runs this once; Claude Code runs it to completion. 8 weeks from first `claude --dangerously-skip-permissions` to enterprise pilot.*

---

*This document is the single source of truth for ALDECI's rearchitecture. Version 2.5 is verified against the actual codebase via code-review-graph v2.2.2 structural analysis (34,301 nodes, 216,476 edges, 1,624 files, 7 languages), deep source code reading, and 30-persona workflow validation. All Beast Mode v6-v12 execution tasks derive from this plan. No code is written without a persona that needs it. No persona exists without architecture that serves them.*
