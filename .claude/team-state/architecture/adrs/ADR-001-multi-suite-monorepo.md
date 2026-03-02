# ADR-001: Multi-Suite Monorepo Architecture

- **Status**: Accepted
- **Date**: 2026-02-27 (documented 2026-03-02)
- **Author**: enterprise-architect
- **Pillar**: V1 (APP_ID-Centric), V9 (Air-Gapped)

## Context

ALdeci needs to organize 6 functional domains (API gateway, core engines, offensive security, threat feeds, evidence/risk, integrations) into a codebase structure that supports:
1. A single FastAPI application mounting all routers
2. Independent development per domain
3. Cross-suite imports without pip install
4. Docker containerization (single or multi-service)
5. Air-gapped deployment (V9) — everything ships together

Alternatives considered:
- **Polyrepo**: Each suite as a separate repository → rejected due to import complexity, deployment coordination overhead
- **Single flat structure**: All code in one directory → rejected due to namespace collisions at 130K+ LOC
- **Python packages with setup.py**: Each suite as an installable package → rejected due to air-gapped complexity

## Decision

Organize the codebase as a **modular monorepo** with 6 suite directories, each containing domain-specific code:

```
suite-api/          # FastAPI gateway (apps/api/app.py = entry point)
suite-core/         # Core engines + scanners + routers
suite-attack/       # Offensive security (MPTE, scanner routers)
suite-feeds/        # Threat intel feeds (NVD, KEV, EPSS, OSV)
suite-evidence-risk/# Evidence, risk scoring, compliance
suite-integrations/ # External integrations (MCP, webhooks, IaC, OSS)
```

Cross-suite imports are enabled by `sitecustomize.py` at repo root, which auto-prepends all suite directories to `sys.path` at Python startup:

```python
# sitecustomize.py (auto-executed by Python)
import sys, os
base = os.path.dirname(os.path.abspath(__file__))
for d in ['suite-core', 'suite-api', 'suite-attack', 'suite-feeds',
          'suite-evidence-risk', 'suite-integrations']:
    sys.path.insert(0, os.path.join(base, d))
```

### Pattern: Engine vs. Router Separation
- **Engines** live in `suite-core/core/` (business logic, no HTTP)
- **Routers** live in `suite-core/api/` or respective suite's `api/` (HTTP endpoints)
- **App wiring** in `suite-api/apps/api/app.py` (34 router mounts)

## Consequences

### Positive
- Single `git clone` + `pip install -r requirements.txt` = ready to develop
- Cross-suite imports "just work" via sitecustomize.py
- Single Docker image contains everything (air-gapped friendly)
- Clear domain boundaries (core vs. attack vs. feeds vs. integrations)
- 130K+ LOC organized into manageable ~5-25K LOC suites

### Negative
- No independent versioning per suite (all share one version)
- `sitecustomize.py` is a non-standard Python import mechanism
- Tests in flat `tests/` directory, not co-located with suites
- 34 router mounts in app.py is approaching maintainability limit
- No module-level access control (any suite can import from any other)

### Risks
- Suite interdependencies can create circular imports (mitigated by lazy imports)
- Single `app.py` is a deployment bottleneck (2,742 LOC)
- No way to deploy suites independently (monolithic deployment only)

## Verification

All 6 suite directories verified present on disk (2026-03-02):
- suite-api: ✅ (22.1K LOC)
- suite-core: ✅ (130.2K LOC)
- suite-attack: ✅ (6.3K LOC)
- suite-feeds: ✅ (4.3K LOC)
- suite-evidence-risk: ✅ (20.3K LOC)
- suite-integrations: ✅ (6.7K LOC)

All critical imports verified working via `python -c "from core.brain_pipeline import BrainPipeline"` etc.
