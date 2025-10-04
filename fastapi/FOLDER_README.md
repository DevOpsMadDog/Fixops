# fastapi/

**Purpose:** Minimal FastAPI compatibility layer bundled for environments where the real FastAPI
package is unavailable.

**Key Files**
- `__init__.py` — Simplified `FastAPI` class and exception definitions.
- `testclient.py` — Lightweight TestClient used in unit tests.

**Gotchas**
- This is not a full FastAPI implementation; only features required by tests are present.
- Replace with the official FastAPI package when running the real service.
