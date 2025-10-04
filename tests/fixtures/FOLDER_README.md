# tests/fixtures/

**Purpose:** Reusable CSV/JSON fixtures supporting ingestion and pipeline tests.

**Usage**
- Import fixtures via `pytest` helpers or open the files directly when crafting new tests.
- Keep fixtures small and deterministic to maintain fast tests.

**Gotchas**
- Update associated expectations in tests if you modify fixture contents.
