# Enterprise Features

## Feature 1: Deduplication & Correlation Engine

A unified engine to deduplicate and correlate findings across the SDLC (Design, Build, Deploy, Runtime).

### Description
- **Canonical Data Model**: Standardized `CanonicalFinding` and `CanonicalEvent` schemas.
- **Fingerprinting**: Robust fingerprint generation using tool, vulnerability ID, location, and context.
- **Deduplication**: Automatically groups identical findings within a configurable time window.
- **Correlation**: Connects findings across stages (e.g., a runtime vulnerability traced back to a source code commit).

### API Enhancements / New APIs
- **New API**: `POST /api/v1/findings/ingest`
  - Accepts raw findings, converts to canonical format, runs deduplication/correlation, and stores.
- **New API**: `GET /api/v1/findings/{id}/correlations`
  - Returns related findings (e.g., same root cause, same CVE, cross-stage matches).

### CLI Changes
- **New Command**: `fixops-risk correlate`
  - Triggers offline correlation analysis on local finding sets.
- **Flag**: `--format canonical`
  - added to `fixops-risk` and `scanner` to output the canonical JSON format.

### YAML Overlay Changes
- **Key**: `correlation_rules`
  - `window_seconds`: Time window for deduplication (default: 3600).
  - `strategies`: List of enabled strategies (fingerprint, location, root_cause, cross_stage).

---

## Feature 2: Integrations – Audit & Completion

Audit of existing integrations and implementation of missing critical connectors.

### Description
- **Audit**:
  - GitHub: Complete
  - Jenkins: Complete
  - SonarQube: Complete
- **New Integration**: GitLab (Stub)
  - Added to support GitLab CI/CD pipelines.

### API Enhancements / New APIs
- **New API**: `POST /api/v1/integrations/gitlab/webhook`
  - Endpoint to receive GitLab merge request and pipeline events.

### CLI Changes
- No specific CLI changes; relies on `fixops-ci` adapter pattern.

### YAML Overlay Changes
- **Key**: `integrations.gitlab`
  - `enabled`: boolean
  - `token_secret_ref`: Reference to secret holding the GitLab token.

## Status
- **Deduplication & Correlation**: Planned
- **Integrations Audit**: Completed
- **GitLab Integration**: Planned
