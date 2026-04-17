# PRD: Community 314 — Self-Scan Main Returns Zero on API Unreachable

## Master Goal Mapping
**Goal:** Ensure the ALDECI self-scan main() function exits with code 0 (graceful degradation) even when the API is unreachable, preventing pipeline disruption in air-gapped environments.

**Domain:** Self-Scan / Resilience
**Personas:** Platform Engineer, DevOps Operator
**Node Count:** 1 | **Status:** Tested

---

## Source Files
- `tests/test_self_scan.py`

## Graph Nodes (Labels)
- main() should return 0 (success) even when API is unreachable.

---

## Architecture Diagram

```mermaid
graph TD
    A[pytest] --> B[test_self_scan.py]
    B --> C[mock API unreachable]
    C --> D[self_scan.main()]
    D --> E{API available?}
    E -->|no| F[graceful exit 0]
    E -->|yes| G[normal scan]
```

---

## Code Proof

- `tests/test_self_scan.py:L1` — main() should return 0 even when API is unreachable — resilience test

---

## Inter-Dependencies

- `suite-core/core/`
- `tests/conftest.py`

### Community Link Dependencies
- No external community dependencies

---

## Data Flow

```
mock requests → ConnectionError → main() exception handler → sys.exit(0)
```

---

## Referenced Docs

- `suite-core/core/brain_pipeline.py`
- `tests/test_phase10_e2e.py`

---

## Acceptance Criteria

- [ ] main() returns 0 with mocked unreachable API
- [ ] Logs warning not error
- [ ] No unhandled exceptions raised

---

## Effort Estimate

**0.5 day (Trivial — isolated leaf module)**

---

## Status

**Tested** — Module exists in codebase. Integration tests present.
