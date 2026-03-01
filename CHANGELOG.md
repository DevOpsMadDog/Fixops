# Changelog

All notable changes to ALdeci (FixOps) are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased] — Sprint 2: Enterprise Demo (2026-03-01 to 2026-03-06)

### Added
- **CTEM+ API Reference** — 704 endpoints documented by CTEM lifecycle (Discover, Validate, Remediate, Comply) with curl examples for top 20 endpoints [V3][V5][V7][V10]
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

### Changed
- **README hero section** — Updated to CTEM+ Decision Intelligence Platform positioning with 8 native scanners, 25+ parsers, 704 endpoints [V3]
- **API endpoint count** — Updated from 617 to 704 endpoints across 64 routers
- **Scanner parser count** — Updated from 10 to 25 normalizers (ZAP, Burp, Nessus, Qualys, Checkmarx, Fortify, Veracode, Snyk, SonarQube, Semgrep, Trivy, Grype, Dependabot, Bandit, ESLint, Anchore, Aqua, Prisma Cloud, AWS Inspector, Nuclei, GitLeaks, TruffleHog, Hadolint, Tfsec, Checkov) [V7]

### Fixed
- **SQL injection in scan parameters** — Input validation added on all API endpoints [V10]
- **Rate limiting on scan endpoints** — Configurable per-tier rate limits [V7]
- **Backend endpoint 404/500 errors** — Backend hardener fixed broken routes [V3]

### Security
- **Input validation** — All 704 endpoints use Pydantic v2 validation
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
