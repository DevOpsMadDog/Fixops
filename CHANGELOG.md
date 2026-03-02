# Changelog

All notable changes to ALdeci (FixOps) are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased] — Sprint 2: Enterprise Demo (2026-03-01 to 2026-03-06)

### Added — Day 1 (2026-03-01)
- **CTEM+ API Reference** — 769 endpoints documented by CTEM lifecycle (Discover, Validate, Remediate, Comply) with curl examples for top 20 endpoints [V3][V5][V7][V10]
- **3-step quickstart guide** in API reference — server startup, authentication, first scan [V7]
- **Architecture documentation** — Mermaid diagrams showing 12-step Brain Pipeline, 8 native scanners, integration architecture [V3]
- **Scanner Ingest router** — 25+ third-party scanner parsers (ZAP, Burp, Nessus, Checkmarx, Snyk, SonarQube, etc.) [V7]
- **Sandbox PoC Verifier** — Docker-isolated exploit verification with self-correction [V5]
- **Knowledge Graph engine** — FalkorDB-backed graph with 835 LOC client, attack path computation [V3]
- **Quantum Crypto router** — RSA + ML-DSA hybrid signature endpoints [V6]
- **Zero-Gravity Data router** — Intelligent data compression and lifecycle management [V9]
- **Single Agent router** — Self-hosted LLM execution with Llama 3.1 70B support [V4]
- **Self-Learning router** — 5 feedback loop endpoints for continuous improvement [V8]
- **Compliance Engine router** — Framework mapping for SOC2, PCI-DSS, HIPAA, GDPR, ISO 27001 [V10]
- **MCP Protocol router** — Full Model Context Protocol implementation for AI agent integration [V7]
- **MCP Auto-Discovery router** — Auto-generates MCP tools from all FastAPI routes (replaces static definitions) [V7]
- **7 Vision engine routers** (V3, V4, V6, V7, V8, V9, V10) — all returning 200 OK [V3-V10]
- **Universal Connectors router** — Jira + GitHub + Slack fan-out for remediation actions [V1]
- **Marketplace router** — Enterprise remediation pack marketplace [V7]
- **CTEM Full Loop demo** — 4 demo scripts covering Discover→Validate→Remediate→Comply→Measure [V10][V5]
- **5 Persona walkthrough scripts** — CISO, DevSecOps, Auditor, Developer, CTO (3 min each) [V3]
- **Docker one-command demo** — 34/34 health checks pass within 30s [V9]
- **MCP Gateway demo** — 705 tools auto-discovered via JSON-RPC [V7]
- **Knowledge Graph demo data** — 5 apps, 20 vulns, 10+ attack paths, 73 nodes, 110 edges [V3]
- **Compliance evidence export** — RSA-SHA256 signed bundles with SOC2/PCI-DSS/HIPAA control mapping [V10]
- **Self-learning feedback loop** — 5 loops demo-ready, score delta: -5.0% after learning [V8]

### Added — Day 2 (2026-03-02)
- **DEMO-001 complete**: All 769 routes mounted, E2E 58/58 (100%), OpenAPI returns 200 [V3]
- **DEMO-002 complete**: Postman 411/411 assertions passing (100.0%), all 7 collections GREEN [V10]
- **11 security hardening fixes** — XXE, SSRF, shell injection, code injection, secrets leakage prevention [V10]
- **Health + Status endpoints** — Every router now has both `/health` and `/status` endpoints [V7]
- **Secrets scanner YAML patterns** — 10 new patterns for YAML/env/config unquoted values [V5]
- **Brain Pipeline hardening** — Thread-safe, async support, timeout guards, sanitized inputs [V3]
- **Scanner Ingest hardening** — File size limits, path traversal prevention, injection guards [V7]
- **Scanner Parser hardening** — Crash resilience on malformed input, output caps [V7]
- **API Reference v2.1** — Updated to 769 endpoints, added 10 new router sections (IaC, IDE, Nerve Center, Decision Records, MindsDB ML, Copilot, Business Context, Graph Analysis, Webhooks full detail, MPTE Orchestrator), security hardening appendix [V3][V7]

### Added — Day 3 (2026-03-02 PM)
- **API Reference v3.0** — 780 endpoints documented across 72 routers with 32 curl examples [V3][V5][V7][V10]
- **Reachability Analysis API** — 7 new endpoints for static call-graph reachability analysis [V3]
- **Enhanced Decision Analysis API** — 4 new endpoints for multi-LLM comparison and signal analysis [V3]
- **Expanded Deduplication Engine** — 20 endpoints documented (was 4) with cluster management, correlation, baseline comparison [V3]
- **Expanded Attack Simulation** — 13 endpoints documented (was 5) with MITRE ATT&CK heatmap, breach impact [V5]
- **Expanded Vulnerability Discovery** — 11 endpoints documented (was 5) with ML retraining, community contributions [V5]
- **Expanded Algorithmic Scoring** — 11 endpoints documented (was 3) with Monte Carlo, causal inference, GNN analysis [V3]
- **Expanded Predictions** — 10 endpoints documented (was 4) with Markov chains, Bayesian networks [V3]
- **Expanded Exposure Cases** — 10 endpoints documented (was 5) with state machine transitions [V3]
- **User Guide** — Comprehensive 15-section user guide: 5-minute quickstart, 8 scanner walkthroughs, Brain Pipeline, MPTE, AutoFix, compliance, MCP, air-gapped deployment, troubleshooting [V3][V5][V7][V10]
- **Investor Technical Brief** — Product overview, TAM/SAM/SOM analysis, competitive matrix, architecture maturity evidence, business model, roadmap milestones [V3]
- **README documentation table** — Added links to User Guide, Investor Brief, Architecture, CTEM+ Identity docs [V7]

### Changed
- **README hero section** — Updated to CTEM+ Decision Intelligence Platform positioning with 8 native scanners, 25+ parsers, 780 endpoints [V3]
- **API endpoint count** — Updated from 769 to 780 endpoints across 72 routers (discovered 4 undocumented router files) [V7]
- **Scanner parser count** — Updated from 10 to 25 normalizers (ZAP, Burp, Nessus, Qualys, Checkmarx, Fortify, Veracode, Snyk, SonarQube, Semgrep, Trivy, Grype, Dependabot, Bandit, ESLint, Anchore, Aqua, Prisma Cloud, AWS Inspector, Nuclei, GitLeaks, TruffleHog, Hadolint, Tfsec, Checkov) [V7]
- **Architecture doc** — Updated LOC counts, added security hardening details, verified 780 routes [V3]

### Fixed
- **SQL injection in scan parameters** — Input validation added on all API endpoints [V10]
- **Rate limiting on scan endpoints** — Configurable per-tier rate limits [V7]
- **Backend endpoint 404/500 errors** — Backend hardener fixed all broken routes (E2E 58/58) [V3]
- **Secrets scanner YAML gap** — Was detecting 0 findings in YAML configs, now 6+ [V5]
- **Brain Pipeline thread safety** — Added proper locking for concurrent requests [V3]

### Security
- **Input validation** — All 780 endpoints use Pydantic v2 validation
- **XXE prevention** — XML external entity parsing disabled on scanner ingest [V10]
- **SSRF protection** — URL validation on DAST/MPTE/micro-pentest target parameters [V5]
- **Shell injection prevention** — Command escaping on all subprocess calls [V10]
- **Code injection prevention** — Sandboxed execution for PoC verification [V5]
- **Secrets leakage prevention** — Response sanitization, no credentials in error messages [V10]
- **Path traversal prevention** — File path sanitization on upload endpoints [V7]
- **Scope-based authorization** — Fine-grained scopes: `admin:all`, `attack:execute`, `read:evidence`, `write:integrations`
- **Rate limiting** — Per-tier rate limits (Community: 100/min, Professional: 1K/min, Enterprise: 10K/min)
- **Evidence signing** — RSA-SHA256 cryptographic signatures on all evidence bundles [V10]

## [0.1.0] — Sprint 1: Foundation (2026-02-20 to 2026-02-28)

### Added
- Initial FastAPI gateway with 34 router mounts
- 8 native scanner engines (SAST, DAST, Secrets, Container, CSPM, API Fuzzer, Malware, LLM Monitor)
- 12-step Brain Pipeline (all steps implemented)
- MPTE micro-pentest engine (19-phase verification)
- AutoFix engine with 10 fix types
- FAIL Engine (Fault & Attack Injection Layer)
- Multi-LLM consensus engine (GPT-4 + Claude + Gemini, 85% threshold)
- Threat intelligence feeds (NVD, KEV, EPSS, OSV, ExploitDB, GitHub Advisories)
- Evidence engine with RSA-SHA256 signing
- CLI with 22 commands
- React frontend (legacy, 85 source files)
- Docker Compose deployment
- 10,141 tests collected
- 16 AI agent definitions

---

*Maintained by ALdeci Technical Writer Agent*
