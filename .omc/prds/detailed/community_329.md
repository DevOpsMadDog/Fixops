# PRD: Community 329 — Evidence Bundle — Run ID Extractor

## Master Goal Mapping
**Goal:** Extract the unique run ID from ALDECI evidence bundle manifests, enabling test harness to correlate evidence bundles with specific pipeline runs for audit validation.

**Domain:** Testing Harness / Evidence
**Personas:** QA Engineer, Compliance Officer
**Node Count:** 1 | **Status:** Tested

---

## Source Files
- `tests/harness/evidence_validator.py`

## Graph Nodes (Labels)
- Get run ID from manifest.

---

## Architecture Diagram

```mermaid
graph TD
    A[evidence_validator.py] --> B[get_run_id()]
    B --> C[manifest JSON parse]
    C --> D[run_id field]
    D --> E[Return UUID string]
```

---

## Code Proof

- `tests/harness/evidence_validator.py:L1` — Get run ID from manifest — evidence harness utility

---

## Inter-Dependencies

- `tests/harness/evidence_validator.py (330, 331, 332, 333)`
- `suite-core/core/evidence_chain_engine.py`

### Community Link Dependencies
- No external community dependencies

---

## Data Flow

```
manifest.json → json.load() → manifest["run_id"] → UUID string
```

---

## Referenced Docs

- `suite-core/core/evidence_chain_engine.py`
- `tests/harness/evidence_validator.py`

---

## Acceptance Criteria

- [ ] Returns UUID string from manifest
- [ ] Raises KeyError on missing field
- [ ] Works with both v1 and v2 manifest formats

---

## Effort Estimate

**0.5 day (Trivial — isolated leaf module)**

---

## Status

**Tested** — Module exists in codebase. Integration tests present.
