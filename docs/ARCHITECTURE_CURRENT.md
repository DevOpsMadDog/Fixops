# ALDECI — Current Architecture Reference

> **Generated**: 2026-04-17  
> **Branch**: `features/intermediate-stage`  
> **Source of truth**: verified by inspecting actual files on disk  

All counts below are real (produced by `ls ... | wc -l` on the live codebase):

| Metric | Count |
|--------|-------|
| Backend engines (`suite-core/core/*engine*.py`) | **332** |
| API router files (`suite-api/apps/api/*router*.py`) | **559** |
| Test files (`tests/test_*.py`) | **812** |
| Frontend pages (`suite-ui/aldeci-ui-new/src/pages/*.tsx`) | **282** |
| Bidirectional connectors | **7** |
| PULL connectors | **13** |
| Scanner normalizers | **31** |

---

## 1. System Overview

ALDECI is a unified ASPM + CTEM + CSPM platform composed of six suites that communicate through a shared Python path (injected by `sitecustomize.py`) and a single FastAPI gateway.

```mermaid
graph TB
    subgraph Clients
        Browser["Browser / API Client"]
        CLI["CLI (fixops-cli)"]
        Scanners["External Scanners\n(Snyk, SonarQube, Nessus,\nDependabot, AWS Security Hub…)"]
        Connectors["Ticketing / ITSM\n(Jira, ServiceNow, GitHub,\nGitLab, Azure DevOps)"]
    end

    subgraph suite-api ["suite-api  (FastAPI Gateway — 22.6K LOC)"]
        GW["app.py\n559 routers mounted\nJWT + API-key auth\nRBAC middleware"]
        Auth["auth_deps.py\napi_key_auth\nJWT validation"]
    end

    subgraph suite-core ["suite-core  (Business Logic — 140.1K LOC)"]
        BP["brain_pipeline.py\n12-step orchestrator"]
        Engines["332 Domain Engines\n(SQLite per engine)"]
        Connectors2["connectors.py\n7 bidirectional\nsecurity_connectors.py\n13 PULL connectors"]
        Parsers["scanner_parsers.py\n31 normalizers"]
        LLM["llm_consensus.py\nMulti-LLM council"]
        TG["trustgraph/\nKnowledgeStore (SQLite)\nGraphRAG\nMCP server"]
    end

    subgraph suite-feeds ["suite-feeds  (Threat Intel — 4.4K LOC)"]
        Feeds["feeds_service.py\nthreat_intel_aggregator.py\n28+ sources"]
    end

    subgraph suite-evidence-risk ["suite-evidence-risk  (Evidence & Risk — 20.3K LOC)"]
        Evidence["Evidence bundles\nRisk scoring\nCompliance packs"]
    end

    subgraph suite-attack ["suite-attack  (Offensive — 6.7K LOC)"]
        MPTE["MPTE engine\nAttack simulation\nFAIL engine"]
    end

    subgraph suite-integrations ["suite-integrations  (Integrations — 6.8K LOC)"]
        MCP["MCP server\nn8n workflows\nWebhooks\nBackstage\nCI/CD templates"]
    end

    subgraph suite-ui ["suite-ui/aldeci-ui-new  (React 19 + Vite 6 + Tailwind v4)"]
        UI["282 pages\nLazy-loaded routes\n6 Spaces layout"]
    end

    subgraph Storage
        SQLite["SQLite (WAL mode)\n~332 domain DBs\n+ brain DB\n+ identity DB"]
        Redis["Redis\nQueue mode\n(FIXOPS_QUEUE_MODE=redis)"]
        DuckDB["DuckDB\nCross-domain analytics"]
    end

    Browser --> GW
    CLI --> GW
    Scanners --> GW
    Connectors --> GW
    GW --> Auth
    Auth --> BP
    Auth --> Engines
    BP --> Engines
    BP --> LLM
    BP --> TG
    BP --> MPTE
    Engines --> SQLite
    Feeds --> BP
    Evidence --> Engines
    MPTE --> BP
    MCP --> TG
    GW --> DuckDB
    BP --> Redis
    UI --> GW
    Parsers --> BP
    Connectors2 --> BP
```

---

## 2. Data Flow — Security Finding Through the System

The `BrainPipeline` orchestrates 12 sequential steps. Steps 9, 10, and 11 can be offloaded to Redis workers when `FIXOPS_QUEUE_MODE=redis`.

```mermaid
flowchart LR
    subgraph Ingest ["Ingest (Step 1-2)"]
        SC["Scanner Output\n(ZAP, Burp, Nessus,\nSonarQube, Snyk…)"]
        NR["scanner_parsers.py\n31 normalizers\nXML/JSON → UnifiedFinding"]
    end

    subgraph Pipeline ["BrainPipeline (Steps 3-12)"]
        S3["Step 3: Identity Resolution\nFuzzy entity matching"]
        S3b["Step 3b: FP Auto-Suppress\nFalse-positive filter"]
        S4["Step 4: Deduplicate\nCollapse → ExposureCases"]
        S5["Step 5: Build Graph\nKnowledge graph nodes"]
        S6["Step 6: Enrich Threats\nEPSS + KEV + CVSS\nNVD + abuse.ch feeds"]
        S7["Step 7: Score Risk\nGNN + attack paths\nBFS lateral movement"]
        S8["Step 8: Apply Policy\nRBAC + org rules"]
        S9["Step 9: LLM Consensus\nOpenAI + Anthropic + Gemini\n85% threshold"]
        S10["Step 10: MicroPenTest\nMPTE proves exploitability"]
        S11["Step 11: Run Playbooks\nIR automation"]
        S12["Step 12: Generate Evidence\nSOC2 Type II packs"]
    end

    subgraph Outputs ["Outputs"]
        TGStore["TrustGraph\nKnowledgeStore\n(SQLite graph)"]
        Alert["Alerts / Incidents\n(alerting_notification_engine)"]
        Ticket["Jira / ServiceNow\nbidirectional connector"]
        EvidenceOut["Evidence Bundle\n(compliance packs)"]
        SOCDash["SOC Dashboard\n(282 frontend pages)"]
    end

    SC --> NR
    NR --> S3
    S3 --> S3b
    S3b --> S4
    S4 --> S5
    S5 --> TGStore
    S5 --> S6
    S6 --> S7
    S7 --> S8
    S8 --> S9
    S9 --> S10
    S10 --> S11
    S11 --> Alert
    S11 --> Ticket
    S12 --> EvidenceOut
    S11 --> S12
    Alert --> SOCDash
    EvidenceOut --> SOCDash
```

---

## 3. Engine Categories — 332 Engines in 10 Sub-Epics

All engines live in `suite-core/core/` and follow the pattern: SQLite DB per engine, WAL mode, `threading.RLock()` for concurrency, `org_id` tenant isolation.

```mermaid
graph TD
    ALDECI["332 Domain Engines\nsuite-core/core/"]

    ALDECI --> ASPM["ASPM — Application Security\n~38 engines\n(sast, dast, sbom, secret_scanner,\napi_security, app_risk, devsecops,\nvuln_scan, vuln_lifecycle, patch_mgmt,\ncve_enrichment, sca, iac_scanner…)"]

    ALDECI --> CSPM["CSPM — Cloud Security\n~42 engines\n(cloud_compliance, cloud_drift,\ncloud_posture, cloud_native,\ncloud_identity, cloud_workload,\nksec, container_registry,\ncloud_security_findings,\ncloud_incident_response…)"]

    ALDECI --> CTEM["CTEM — Continuous Threat Exposure\n~35 engines\n(threat_indicator, threat_exposure,\ndark_web_monitoring, zero_day_intel,\nthreat_intel_platform, threat_feed_sub,\nthreat_attribution, attack_surface,\nransomware_protection, breach_detection…)"]

    ALDECI --> SOC["SOC — Security Operations\n~40 engines\n(siem_integration, alert_triage,\nincident_orchestration, soc_workflow,\nincident_triage, ai_powered_soc,\nincident_metrics, itdr,\nsecurity_automation, playbook_engine…)"]

    ALDECI --> GRC["GRC — Governance, Risk & Compliance\n~45 engines\n(compliance_automation, compliance_mapping,\ncompliance_workflow, risk_register,\nrisk_scenario, risk_treatment,\naudit_management, gdpr_compliance,\ndata_privacy, security_questionnaire…)"]

    ALDECI --> IDENTITY["Identity & Access\n~28 engines\n(identity_lifecycle, identity_risk,\naccess_governance, access_anomaly,\ndigital_identity, privileged_identity,\niam_policy_analyzer, mfa_management,\nitdr, pam, ciem, rbac…)"]

    ALDECI --> NETWORK["Network & Infrastructure\n~38 engines\n(network_monitoring, network_anomaly,\nfirewall_policy, network_segmentation,\niot_security, firmware_security,\npassive_dns, ip_reputation,\nwireless_security, bandwidth_analysis…)"]

    ALDECI --> AI["AI / ML\n~12 engines\n(ai_governance, ai_powered_soc,\nai_security_advisor, anomaly_ml,\ndigital_twin_security, graphrag,\nbehavioral_analytics, context_engine,\nllm_consensus layer…)"]

    ALDECI --> EXEC["Executive & Metrics\n~28 engines\n(executive_reporting, security_budget,\nkpi_tracking, security_okr,\nsecurity_investment, security_culture,\ncyber_insurance, security_scorecard,\nmetrics_dashboard, posture_trend…)"]

    ALDECI --> ADVANCED["Advanced Capabilities\n~26 engines\n(quantum_safe_crypto, deception_analytics,\nsecurity_chaos, autonomous_remediation,\nvuln_correlation, posture_benchmarking,\nthreat_modeling_pipeline, sbom_export,\nevidence_vault, security_registry…)"]
```

---

## 4. API Layer — Request Lifecycle

```mermaid
sequenceDiagram
    participant C as Client
    participant GW as FastAPI (app.py)<br/>suite-api
    participant Auth as auth_deps.py<br/>api_key_auth / JWT
    participant Router as Domain Router<br/>(*_router.py)
    participant Engine as Domain Engine<br/>(*_engine.py)
    participant DB as SQLite DB<br/>(WAL mode, RLock)

    C->>GW: HTTP Request<br/>(Authorization: Bearer <token>)
    GW->>Auth: Depends(api_key_auth)
    Auth-->>GW: org_id + role claims
    GW->>Router: route to matching prefix<br/>(e.g. /api/v1/threat-indicators)
    Router->>Engine: call engine method<br/>(with org_id isolation)
    Engine->>DB: SQL (INSERT/SELECT/UPDATE)<br/>WAL mode, RLock guard
    DB-->>Engine: result rows
    Engine-->>Router: domain model / dict
    Router-->>GW: JSONResponse
    GW-->>C: HTTP 200 + JSON body
```

**Auth mechanisms in use:**
- `api_key_auth` — SHA-256 hashed API keys, stored per org in auth DB
- JWT (`python-jose`) — RS256 signed, org_id + role claims
- SAML/OIDC SSO bridge — PyJWKClient RS256 validation for enterprise SSO
- All 559 routers gate endpoints via `dependencies=[Depends(api_key_auth)]`

---

## 5. TrustGraph Knowledge Graph

TrustGraph is ALDECI's versioned security knowledge layer. It lives in `suite-core/trustgraph/` and exposes an MCP server for AI agent access.

```mermaid
graph TB
    subgraph TrustGraph ["TrustGraph  (suite-core/trustgraph/)"]
        KS["KnowledgeStore\n(SQLite + FTS5 full-text)\nMulti-tenant org_id isolation"]

        subgraph Cores ["5 Knowledge Cores"]
            C1["Core 1: Assets\n(services, repos, containers,\nhosts, cloud resources)"]
            C2["Core 2: Vulnerabilities\n(CVEs, findings, exposure cases)"]
            C3["Core 3: Threats\n(IOCs, TTPs, threat actors,\nMITRE ATT&CK techniques)"]
            C4["Core 4: Compliance\n(controls, frameworks, evidence,\nmappings)"]
            C5["Core 5: Identity\n(users, roles, entitlements,\naccess paths)"]
        end

        GR["graph_rag.py\nGraphRAG Retriever\n- BFS traversal (depth 2)\n- Semantic search\n- Neighborhood context\nWired to Copilot chat"]

        MCP["mcp_server.py\nMCP protocol endpoint\nfor AI agent tool calls"]

        MA["maintenance_agent.py\nNightly graph cleanup\nstale entity pruning"]
    end

    BP["BrainPipeline\nStep 5: Build Graph"]
    Copilot["AI Copilot Chat\n(frontend /copilot)"]
    Agents["External AI Agents\n(Claude Code, OMC)"]

    BP -->|"ingest_entity()\nadd_relationship()"| KS
    KS --> C1
    KS --> C2
    KS --> C3
    KS --> C4
    KS --> C5
    KS --> GR
    GR --> Copilot
    MCP --> KS
    Agents -->|"MCP tool calls"| MCP
    MA --> KS
```

**Key capabilities:**
- Full-text search via SQLite FTS5 across all cores
- Graph traversal: `get_neighbors(entity_id, depth=2)` for blast-radius analysis
- Relationship types: `owns`, `depends_on`, `exploits`, `mitigates`, `owned_by`, `maps_to`
- All entities scoped to `org_id` — strict multi-tenant isolation

---

## 6. LLM Council — Multi-Model Consensus

Step 9 of the BrainPipeline sends every security decision to 3 providers concurrently. Results are merged via weighted majority voting.

```mermaid
flowchart TB
    Input["Security Analysis Request\n(CVE, finding, attack path context)"]

    subgraph Council ["LLM Council (llm_consensus.py)"]
        direction LR
        OA["OpenAI\nweight: 1.0"]
        AN["Anthropic\nweight: 1.0"]
        GM["Gemini\nweight: 0.8"]
    end

    subgraph Voting ["Weighted Majority Voting"]
        AggR["Aggregate responses\n(concurrent ThreadPoolExecutor)"]
        Vote["Vote tallying\nagreement_ratio = votes_for_winner / total_weight"]
        Thresh{"agreement_ratio\n≥ 0.85?"}
    end

    Escalate["Flag as DISSENT\nQueue for human review\n(SOC analyst)"]
    Consensus["CONSENSUS reached\naction + confidence returned\nto BrainPipeline"]

    Input --> OA & AN & GM
    OA & AN & GM --> AggR
    AggR --> Vote
    Vote --> Thresh
    Thresh -- No --> Escalate
    Thresh -- Yes --> Consensus

    style Escalate fill:#d32f2f,color:#fff
    style Consensus fill:#388e3c,color:#fff
```

**Provider weights** (configured in `llm_consensus.py`):
| Provider | Weight | Model |
|----------|--------|-------|
| OpenAI | 1.0 | GPT-4 via `OPENAI_API_KEY` |
| Anthropic | 1.0 | Claude via `ANTHROPIC_API_KEY` |
| Gemini | 0.8 | Gemini via `GOOGLE_API_KEY` |

Consensus threshold: **85%** agreement required. Below threshold → `dissent=True`, queued for human SOC review.

---

## 7. Frontend Architecture

```mermaid
graph TB
    subgraph Frontend ["suite-ui/aldeci-ui-new  (React 19 + Vite 6 + Tailwind v4)"]
        App["App.tsx\nReact Router v6\nAll routes lazy-loaded\nCode-split per page"]

        subgraph Spaces ["6 Navigation Spaces"]
            S1["Mission Control\n(Command, CISO, SLA,\nRisk Overview, SOC T1)"]
            S2["Discover\n(Findings, Code Scanning,\nSecrets, IaC, Cloud Posture,\nKnowledge Graph, Attack Paths)"]
            S3["Validate\n(MPTE Console, Attack Sim,\nFAIL Engine, Playbooks)"]
            S4["Remediate\n(Remediation Center, AutoFix,\nBulk Ops, Workflows)"]
            S5["Comply\n(Compliance, Evidence Vault,\nSOC2, Audit Trail, Reports)"]
            S6["Settings\n(Users, Teams, Integrations,\nMarketplace, Policies)"]
        end

        Pages["282 Domain Pages\n(suite-ui/aldeci-ui-new/src/pages/*.tsx)\nAll lazy-imported via React.lazy()"]

        Auth["RequireAuth HOC\nRequireRole HOC\nJWT token via localStorage"]

        Layout["WorkspaceLayout\nSidebar navigation\nErrorBoundary wrapper\nPageSkeleton loading state"]
    end

    API["FastAPI Backend\nlocalhost:8000\n/api/v1/*"]

    App --> Auth
    Auth --> Layout
    Layout --> S1 & S2 & S3 & S4 & S5 & S6
    S1 & S2 & S3 & S4 & S5 & S6 --> Pages
    Pages -->|"fetch() / axios"| API
```

**Technology stack:**
- React 19 with concurrent features
- Vite 6 for bundling (fast HMR in dev)
- Tailwind v4 for styling
- React Router v6 for client-side routing
- All 282 pages are lazy-loaded — zero blocking imports at startup
- `RequireAuth` + `RequireRole` HOCs enforce RBAC before rendering

---

## 8. Infrastructure & Storage

```mermaid
graph TB
    subgraph Runtime ["Runtime Services"]
        API["FastAPI\n(uvicorn, port 8000)\nsys.recursionlimit=5000\n559 routers chained"]
        UI["Vite Dev / Nginx\n(port 3000 / 80)"]
    end

    subgraph Storage ["Storage Tier"]
        SQLiteEngines["SQLite (WAL mode)\n~332 engine DBs\n1 DB per engine domain\nRLock concurrency guard\norg_id tenant isolation"]
        BrainDB["brain.db\n(fixops_brain.db)\nBrainPipeline state\nExposure cases"]
        IdentityDB["identity.db\n(fixops_identity.db)\nUsers, roles, SSO sessions"]
        TrustDB["trustgraph.db\nKnowledgeStore\nFTS5 full-text index\n5 Knowledge Cores"]
        DuckDB["DuckDB\n(in-process OLAP)\nCross-domain analytics\nSQL joins across SQLite DBs\n/api/v1/analytics endpoint"]
        RedisQ["Redis (optional)\nFIXOPS_QUEUE_MODE=redis\nHeavy pipeline steps\noffloaded to workers"]
    end

    subgraph Docker ["Docker Compose Services (docker-compose.yml)"]
        AldecAPI["aldeci-api\n(FastAPI container)"]
        AldecUI["aldeci-ui\n(React container)"]
        TGInit["aldeci-trustgraph-init\n(graph seeding)"]
        DTrack["aldeci-dtrack-api\nDependency Track 4.12.3\n(SBOM analysis)"]
        DTrackUI["aldeci-dtrack-ui\n(DTrack frontend)"]
        N8N["aldeci-n8n\nn8n:latest\nWorkflow automation\nport 5678"]
    end

    subgraph ImportMechanism ["Import Mechanism (sitecustomize.py)"]
        SC["Auto-prepends 6 suite dirs\nto sys.path at Python startup\nEnables cross-suite imports\nwithout PYTHONPATH config"]
    end

    API --> SQLiteEngines
    API --> BrainDB
    API --> IdentityDB
    API --> TrustDB
    API --> DuckDB
    API -.->|"when QUEUE_MODE=redis"| RedisQ
    AldecAPI --> API
    AldecUI --> UI
    SC -->|"path injection"| API
```

**SQLite WAL pattern (used by all 332 engines):**
```
conn.execute("PRAGMA journal_mode=WAL")
self._lock = threading.RLock()
# All writes: with self._lock: conn.execute(...)
# org_id column on every table for tenant isolation
```

**DuckDB cross-domain analytics:**
- Attaches all SQLite engine DBs at query time
- Enables SQL JOINs across e.g. `vuln_scan_engine.db` × `asset_tagging_engine.db`
- Powers `/api/v1/analytics` and `CrossDomainAnalytics.tsx` dashboard

---

## Appendix: Suite LOC Summary

| Suite | Purpose | Approx LOC |
|-------|---------|-----------|
| `suite-api` | FastAPI gateway, 559 routers, auth, middleware | 22,600 |
| `suite-core` | 332 engines, BrainPipeline, connectors, TrustGraph | 140,100 |
| `suite-attack` | MPTE, attack simulation, FAIL engine | 6,700 |
| `suite-feeds` | 28+ threat intel feed integrations | 4,400 |
| `suite-evidence-risk` | Evidence bundles, risk scoring, compliance | 20,300 |
| `suite-integrations` | MCP, n8n, webhooks, Backstage, CI/CD | 6,800 |
| `suite-ui/aldeci-ui-new` | React 19 frontend, 282 pages | ~60,000 |

---

## Appendix: Key File Locations

| Component | Path |
|-----------|------|
| FastAPI entry point | `suite-api/apps/api/app.py` |
| Brain Pipeline | `suite-core/core/brain_pipeline.py` |
| LLM Consensus | `suite-core/core/llm_consensus.py` |
| Scanner Normalizers | `suite-core/core/scanner_parsers.py` |
| Bidirectional Connectors | `suite-core/core/connectors.py` |
| PULL Connectors | `suite-core/core/security_connectors.py` |
| TrustGraph Store | `suite-core/trustgraph/knowledge_store.py` |
| GraphRAG Retriever | `suite-core/trustgraph/graph_rag.py` |
| TrustGraph MCP Server | `suite-core/trustgraph/mcp_server.py` |
| Path injection | `sitecustomize.py` |
| Auth dependencies | `suite-api/apps/api/auth_deps.py` |
| Frontend routing | `suite-ui/aldeci-ui-new/src/App.tsx` |
| Docker Compose | `docker-compose.yml` |
| Threat intel feeds | `suite-feeds/feeds_service.py` |
| DuckDB analytics engine | `suite-core/core/duckdb_analytics_engine.py` |
