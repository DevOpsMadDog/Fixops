# PRD: Community 330 — Evidence Bundle — Producer Extractor

## Master Goal Mapping
**Goal:** Extract the producer identifier from ALDECI evidence bundle payloads, enabling traceability validation that each evidence bundle is correctly attributed to its source engine.

**Domain:** Testing Harness / Evidence
**Personas:** QA Engineer, Compliance Officer
**Node Count:** 1 | **Status:** Tested

---

## Source Files
- `tests/harness/evidence_validator.py`

## Graph Nodes (Labels)
- Get producer from payload.

---

## Architecture Diagram

```mermaid
graph TD
    A[evidence_validator.py] --> B[get_producer()]
    B --> C[payload JSON parse]
    C --> D[producer field]
    D --> E[Engine identifier string]
```

---

## Code Proof

- `tests/harness/evidence_validator.py:L1` — Get producer from payload — evidence harness utility

---

## Inter-Dependencies

- `tests/harness/evidence_validator.py (329, 331, 332, 333)`

### Community Link Dependencies
- No external community dependencies

---

## Data Flow

```
payload.json → json.load() → payload["producer"] → engine name string
```

---

## Referenced Docs

- `suite-core/core/evidence_chain_engine.py`

---

## Acceptance Criteria

- [ ] Returns engine name string
- [ ] Validates against known producers list
- [ ] Handles nested producer.name format

---

## Effort Estimate

**0.5 day (Trivial — isolated leaf module)**

---

## Status

**Tested** — Module exists in codebase. Integration tests present.
