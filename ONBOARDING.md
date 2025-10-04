# FixOps Blended Enterprise – Quick Onboarding Guide

This document helps newcomers navigate the FixOps Blended Enterprise repository and understand how the major pieces fit together.

## Repository Layout
- **Root utilities** – Provisioning scripts (`create_tables.py`, `create_minimal_tables.py`) and regression test entry points (`backend_test.py`, `frontend/test_frontend.py`).
- **`fixops-blended-enterprise/`** – Main product source. The `backend` and `frontend` symlinks at the repo root both point here, so use this directory directly when exploring code.
- **`data/` & databases** – Seed data, fixtures, and the default SQLite database (`fixops_enterprise.db`) used for local demos.

## Backend Overview (`fixops-blended-enterprise/src`)
The backend is a FastAPI application optimized for “hot path” performance and lifecycle management in `main.py` with structured logging, custom middleware, and dependency initialization during startup and shutdown.【F:fixops-blended-enterprise/src/main.py†L1-L104】

Key backend sub-packages:
- **`config/settings.py`** – Centralized Pydantic settings covering demo-vs-production behavior, feature flags for external feeds, secrets management, and LLM credentials. The `get_settings()` helper caches configuration for reuse across modules.【F:fixops-blended-enterprise/src/config/settings.py†L1-L92】【F:fixops-blended-enterprise/src/config/settings.py†L107-L112】
- **`db/session.py`** – Asynchronous SQLAlchemy session factory with pooled connections, health checks, and an app-wide `DatabaseManager` used by API routes and services.【F:fixops-blended-enterprise/src/db/session.py†L1-L103】
- **`core/`** – Cross-cutting concerns such as middleware, structured exception handling, and the `SecurityManager`, which bundles password hashing, encryption, MFA helpers, and JWT utilities for the platform.【F:fixops-blended-enterprise/src/core/security.py†L1-L118】
- **`api/v1/`** – Route modules grouped by capability (decision engine, feeds, CICD, marketplace, monitoring, etc.). `decisions.py` is the flagship endpoint module, exposing decision execution, metrics, and system component status via FastAPI routers.【F:fixops-blended-enterprise/src/api/v1/decisions.py†L1-L118】
- **`services/`** – Business logic engines. The `decision_engine.py` service orchestrates demo vs. production modes, optional LLM integrations, vector stores, and fallbacks, and provides the async API consumed by the REST layer.【F:fixops-blended-enterprise/src/services/decision_engine.py†L1-L119】 Supporting services (enhanced multi-LLM engine, policy engine, feeds scheduler, marketplace integration, etc.) live alongside it.

Other noteworthy directories include `models/` (SQLAlchemy models), `schemas/` (Pydantic request/response contracts), `utils/` (logging, crypto helpers), and `cli/` (pipeline tooling). Supervisord/uvicorn entrypoints (`server.py`, `run_enterprise.py`) load the FastAPI app from `src.main` for deployment automation.【F:fixops-blended-enterprise/server.py†L1-L13】

## Frontend Overview (`fixops-blended-enterprise/frontend`)
The frontend is a Vite-powered React 18 SPA (`package.json`) that renders multiple persona dashboards through a common layout and React Router configuration.【F:fixops-blended-enterprise/frontend/package.json†L1-L35】【F:fixops-blended-enterprise/frontend/src/App.jsx†L1-L24】

Important pieces:
- **`components/SecurityLayout.jsx`** – Global navigation, system status banner, and telemetry polling against `/api/v1/decisions` endpoints to detect demo vs. production mode and render the SOC-style chrome.【F:fixops-blended-enterprise/frontend/src/components/SecurityLayout.jsx†L1-L87】
- **`pages/CommandCenter.jsx`** – Command center dashboard that pulls decision metrics, production readiness data, and simulates scan ingestion interactions for demo mode.【F:fixops-blended-enterprise/frontend/src/pages/CommandCenter.jsx†L1-L73】
- Additional persona-specific pages (`DeveloperOps`, `ExecutiveBriefing`, `ArchitectureCenter`) and shared UI primitives live under `pages/` and `components/`.

Styling mixes custom CSS (`index.css`) with Tailwind utilities, while `contexts/` and `utils/` hold client-side state stores and helpers.

## Data & Intelligence Services
The decision engine coordinates caches, optional vector stores, and third-party integrations (Jira, Confluence, threat intel). When the platform runs in demo mode—default for local onboarding—it seeds simulated datasets for vector search, policy enforcement, and regression suites so the UI and API remain interactive without external credentials.【F:fixops-blended-enterprise/src/services/decision_engine.py†L51-L119】 Feature flags in settings toggle feeds such as EPSS or CISA KEV and control multi-LLM consensus thresholds.【F:fixops-blended-enterprise/src/config/settings.py†L24-L82】

## Getting Started Locally
1. **Backend** – Launch `uvicorn server:app --reload` from `fixops-blended-enterprise/` or use `run_enterprise.py`; the FastAPI app bootstraps database pools, Redis cache (memory fallback), security subsystems, and background feed schedulers during startup.【F:fixops-blended-enterprise/src/main.py†L34-L81】
2. **Frontend** – Run `npm install && npm run dev` in `fixops-blended-enterprise/frontend/` to start the Vite dev server with hot reloads.【F:fixops-blended-enterprise/frontend/package.json†L5-L18】 By default it targets the backend’s `/api/v1` routes.
3. **Database** – The default SQLite file (`fixops_enterprise.db`) works out of the box; the `DatabaseManager` takes care of pooling and migrations for local demos.【F:fixops-blended-enterprise/src/db/session.py†L25-L92】

## Suggested Next Steps
- **Deep dive into services** – Explore `services/` beyond the decision engine (e.g., `enhanced_decision_engine.py`, `policy_engine.py`, `processing_layer.py`) to see how intelligence layers compose across demo and production modes.
- **Review API surface** – Inspect other modules under `api/v1/` such as `cicd.py`, `feeds.py`, and `monitoring.py` to understand pipeline integrations and telemetry endpoints.【F:fixops-blended-enterprise/src/api/v1/decisions.py†L55-L118】
- **Trace frontend data flows** – Follow how `SecurityLayout` and persona dashboards fetch and visualize backend metrics to extend or customize UX states.【F:fixops-blended-enterprise/frontend/src/components/SecurityLayout.jsx†L11-L61】【F:fixops-blended-enterprise/frontend/src/pages/CommandCenter.jsx†L15-L63】
- **Consult docs** – `COMPREHENSIVE_GUIDE.md` and other deployment guides under `fixops-blended-enterprise/` outline architecture, deployment patterns, and long-term roadmap for context during feature planning.【F:fixops-blended-enterprise/COMPREHENSIVE_GUIDE.md†L1-L56】

Welcome aboard! Use this map to orient yourself, then iterate through backend services and frontend persona flows to build intuition about how FixOps delivers decision automation across the DevSecOps lifecycle.
