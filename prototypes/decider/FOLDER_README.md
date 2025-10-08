# prototypes/decider/

**Purpose:** Lightweight decision-engine prototype demonstrating how FixOps could expose risk
adjustment endpoints separately from the ingestion service.

**Key Files**
- `api.py` — FastAPI app with `/decisions` and feedback endpoints.
- `processing/` — Helper modules for knowledge graph traversal, SARIF enrichment, and explanations.
- `__init__.py` — Convenience exports for embedding in other services.

**Module API**
- `create_app()` returns a standalone FastAPI instance (no overlay awareness yet).
- Processing submodules expose pure functions for testing risk scoring logic.

**Data In/Out**
- Inputs: JSON payloads describing services, risk scores, and feedback flags.
- Outputs: JSON decisions (`approve`, `review`, `reject`) plus metadata and synthetic decision IDs.

**Gotchas**
- Feedback endpoint trusts the caller; production deployments should authenticate and persist feedback.
- The app is intentionally state-light; integrate with the overlay loader when aligning with the main
  ingestion service.
