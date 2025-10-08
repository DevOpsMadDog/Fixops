# FixOps Architecture Reference

This document is assembled from the repository index (`index/INVENTORY.csv`) and dependency graph (`index/graph.json`) generated via `scripts/generate_index.py`. It captures the layered service layout, module coupling, and runtime modes for the FixOps Blended Enterprise platform.

## Layered Overview
- **Interfaces** – FastAPI REST application (`fixops-blended-enterprise/src/main.py`) with persona-focused React front-end (`enterprise/frontend`).
- **Services** – Decision engine, evidence processing, IaC posture evaluation, and threat intelligence adapters located under `fixops-blended-enterprise/src/services/`.
- **Core Infrastructure** – Configuration, security, database session management, logging, and middleware primitives under `fixops-blended-enterprise/src/config`, `core`, and `db` packages.
- **Data Plane** – Simulations, feed schedulers, and storage connectors bridging SBOM, SARIF, IaC, and exploit intelligence inputs.

## Module Map (Top-Level Packages)
| Package | Responsibility | Key Entrypoints |
| --- | --- | --- |
| `fixops-blended-enterprise/src/main.py` | FastAPI app factory, middleware wiring, background scheduler bootstrap | `create_app`, `build_application` |
| `fixops-blended-enterprise/src/api/v1` | REST routers grouped by capability (decisions, feeds, policy, CICD, monitoring) | `decisions.py`, `feeds.py`, `policy.py` |
| `fixops-blended-enterprise/src/services` | Business logic engines orchestrating SSDLC data, marketplace integrations, IaC posture, and intelligence feeds | `decision_engine.py`, `policy_engine.py`, `feeds_scheduler.py`, `iac_posture.py` |
| `fixops-blended-enterprise/src/core` | Cross-cutting middleware, exceptions, rate limiting, logging, security helpers | `middleware.py`, `security.py`, `exceptions.py` |
| `fixops-blended-enterprise/src/config` | Pydantic settings, feature flags, environment toggles, secrets loading | `settings.py` |
| `fixops-blended-enterprise/src/db` | SQLAlchemy async engine/session factories, migrations helpers | `session.py` |
| `simulations/ssdlc` | Deterministic SSDLC lifecycle fixtures and runner CLI | `run.py`, `<stage>/inputs/*` |

## Import Graph Highlights
Using `index/graph.json`, the following modules exhibit the highest fan-out (number of same-package imports):
- `core/demo_runner.py` → orchestrates CLI demos across analytics, evidence, and storage helpers.
- `apps/api/pipeline.py` → centralizes analytics, compliance, context, and policy modules for the simulation/demo pipeline.
- `core/feedback.py` → coordinates analytics, configuration, connectors, and storage adapters.

Highly-referenced foundational modules include:
- `core/configuration.py` (imported by >10 modules) – runtime settings and feature flags.
- `core/paths.py` – normalized data paths for fixtures and generated artifacts.
- `apps/api/normalizers.py` – reused across policy, exploit signals, and modules pipelines.

## Data & Control Flows
1. **Inbound request** arrives via FastAPI router (`api/v1/decisions.py`), passes through middleware (security headers, new rate limiting), and resolves dependencies (`config.settings`, `db.session`).
2. **Decision orchestration** occurs in `services/decision_engine.py`, which reads evidence from `services/evidence.py`, merges design context, and applies policy evaluation via `services/policy_engine.py`.
3. **Feeds and posture** data is hydrated through scheduler workers (`services/feeds_scheduler.py`) that call external adapters under `services/iac_posture.py`, `services/exploit_intel.py`, etc.
4. **Results** propagate to REST responses, telemetry exporters, and the SSDLC simulation runner for reproducible analytics artifacts.

## Hot Path Considerations
- Decision execution uses cached settings and pooled DB sessions to minimize latency.
- Evidence normalization leverages asynchronous IO wrappers to parallelize SARIF/SBOM processing.
- Rate limiting ensures fairness by bounding per-IP throughput before heavy service work occurs.

## Metrics & Observability
- Metrics endpoints expose request latency, policy decision counts, and scheduler heartbeat data.
- Grafana dashboard (`docs/decisionfactory_alignment/fixops-observability-dashboard.json`) visualizes p95 latency, throttle rates, and policy block ratios.

## Dual-Mode Operation
- **Demo Mode**: Seeds fixtures, uses in-memory caches, and enables SSDLC simulations without external secrets.
- **Enterprise Mode**: Requires configured secrets, strict CORS, persistent caches, and production-grade scheduler intervals.

## Regeneration Instructions
1. Run `python scripts/generate_index.py` to refresh `index/INVENTORY.csv` and `index/graph.json`.
2. Update this document by re-running the parsing helpers in `docs/ARCHITECTURE.md` or using the snippet below:
   ```bash
   python - <<'PY'
   import json
   from collections import Counter
   graph=json.load(open('index/graph.json'))
   prefix='core/'
   dep_counts=Counter()
   for src,deps in graph.items():
       if src.startswith(prefix):
           for dep in deps:
               if dep.startswith(prefix):
                   dep_counts[dep]+=1
   print(dep_counts.most_common(10))
   PY
   ```
3. Incorporate the updated module/fan-out insights into the sections above.
