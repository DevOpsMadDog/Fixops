# FixOps – Functional and Non‑Functional Requirements

## Functional
- Ingest security scans
  - File upload endpoints for SARIF, SBOM (CycloneDX/SPDX), CSV, generic JSON
  - Chunked uploads for large files with progress and resume (init → chunk → complete)
- Decision & Verification Engine
  - Produce ALLOW/BLOCK/DEFER with confidence and rationale
  - Enhanced Multi‑LLM consensus and individual analyses
  - MITRE ATT&CK mapping and disagreement analysis
- SSVC integration (methodology)
  - Map FixOps decisions to SSVC outcomes: Allow→Track, Block→Act, Defer→Attend
  - Accept VEX and account for affectedness (stub today)
  - Consider EPSS/KEV for exploit likelihood and known exploited (stubs)
- Business context enrichment
  - Service criticality, data classification, environment awareness (today via payloads)
- Marketplace (stubs)
  - Browse, recommend, contribute, purchase, stats
- APIs and CLI
  - REST endpoints under /api (prefixed /api/v1)
  - CLI usage documented for CI/CD ingestion
- Dashboards
  - Enhanced analysis page (developers, architects)
  - CISO view with program KPIs and snapshot of decisions

## Non‑Functional
- Deployment & Ops
  - Containerized services, Kubernetes‑ready
  - No app‑level auth; infra controls (ingress/WAF/IP allowlist) assumed
  - MongoDB via MONGO_URL only; no hardcoded DB
  - Persistent volume for uploads (/app/data/uploads)
- Performance
  - Hot path < 299 μs target for simple routes (best effort)
  - API response times logged with correlation IDs
- Reliability & HA
  - Replicas ≥2 for HA (optional), HPA, PDB, anti‑affinity
  - Readiness/Liveness probes on /ready and /health
- Security
  - Secrets via Kubernetes Secrets
  - NetworkPolicies for DB
  - Evidence and logs stored with timestamps; redact LLM narratives if needed
- Observability
  - /metrics Prometheus endpoint, structured logs
- Compliance alignment
  - SSVC (CISA/SEI), EPSS, KEV, CycloneDX VEX minimums (documented)
- Extensibility
  - Feature flags for EPSS/KEV/VEX/RSS sidecar
  - Marketplace designed to move from in‑memory to DB in future
