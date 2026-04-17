# PRD: Community 333 — Evidence Bundle — Compression Status Checker

## Master Goal Mapping
**Goal:** Verify evidence bundles are compressed to reduce storage costs, checking ALDECI storage efficiency standards for high-volume evidence collection.

**Domain:** Testing Harness / Storage
**Personas:** Platform Engineer, QA Engineer
**Node Count:** 1 | **Status:** Tested

---

## Source Files
- `tests/harness/evidence_validator.py`

## Graph Nodes (Labels)
- Check if bundle is compressed.

---

## Architecture Diagram

```mermaid
graph TD
    A[evidence_validator.py] --> B[is_compressed()]
    B --> C[bundle metadata check]
    C --> D{compressed flag?}
    D -->|true| E[PASS]
    D -->|false| F[WARN — uncompressed]
```

---

## Code Proof

- `tests/harness/evidence_validator.py:L1` — Check if bundle is compressed — storage efficiency check

---

## Inter-Dependencies

- `tests/harness/evidence_validator.py (329-332)`

### Community Link Dependencies
- No external community dependencies

---

## Data Flow

```
bundle → metadata["compressed"] → bool → assertion
```

---

## Referenced Docs

- `suite-core/core/evidence_vault_engine.py`

---

## Acceptance Criteria

- [ ] Returns True when gzip/zstd compressed
- [ ] Compression reduces size >50%
- [ ] Uncompressed bundles flagged as warning

---

## Effort Estimate

**0.5 day (Trivial — isolated leaf module)**

---

## Status

**Tested** — Module exists in codebase. Integration tests present.
