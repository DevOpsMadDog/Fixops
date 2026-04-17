# PRD: Community 331 — Evidence Bundle — Retention Days Extractor

## Master Goal Mapping
**Goal:** Extract retention policy duration from evidence bundle metadata to validate compliance with data retention requirements (GDPR 7yr, PCI 1yr, SOC2 1yr).

**Domain:** Testing Harness / Compliance
**Personas:** Compliance Officer, QA Engineer
**Node Count:** 1 | **Status:** Tested

---

## Source Files
- `tests/harness/evidence_validator.py`

## Graph Nodes (Labels)
- Get retention days from metadata.

---

## Architecture Diagram

```mermaid
graph TD
    A[evidence_validator.py] --> B[get_retention_days()]
    B --> C[metadata JSON parse]
    C --> D[retention_days field]
    D --> E[int: days]
```

---

## Code Proof

- `tests/harness/evidence_validator.py:L1` — Get retention days from metadata — compliance validation utility

---

## Inter-Dependencies

- `tests/harness/evidence_validator.py (329, 330, 332, 333)`
- `suite-core/core/data_retention_engine.py`

### Community Link Dependencies
- No external community dependencies

---

## Data Flow

```
metadata.json → retention_days field → int → compare vs framework minimum
```

---

## Referenced Docs

- `suite-core/core/data_retention_engine.py`
- `GDPR Article 5(1)(e)`

---

## Acceptance Criteria

- [ ] Returns integer days value
- [ ] Validates >= framework minimum
- [ ] Fails for retention_days=0

---

## Effort Estimate

**0.5 day (Trivial — isolated leaf module)**

---

## Status

**Tested** — Module exists in codebase. Integration tests present.
