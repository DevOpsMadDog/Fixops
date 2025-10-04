# tests/

**Purpose:** Automated regression suite covering ingestion, overlay configuration, and risk processing.

**Key Files**
- `test_end_to_end.py` — Exercises FastAPI endpoints using in-memory TestClient.
- `test_overlay_configuration.py` — Ensures overlay parsing and environment overrides work.
- `test_new_backend_*.py` — Validate decision-engine processing modules.
- `fixtures/` — Contains reusable JSON/CSV inputs for tests.

**Running Tests**
- Execute `pytest` from the repository root.
- Set `FIXOPS_OVERLAY_PATH` if you want to simulate non-default overlays during tests.

**Gotchas**
- Some tests skip FastAPI imports gracefully if dependencies are missing; ensure requirements are
  installed for full coverage.
