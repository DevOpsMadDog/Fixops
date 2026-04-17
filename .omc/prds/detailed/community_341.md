# PRD: Community 341 — MPTE Fail Engine — GradingDimension to Dict Serializer

## Master Goal Mapping
**Goal:** Convert GradingDimension dataclass instances to JSON-serializable dicts for MPTE API responses and report export in the attack simulation engine.

**Domain:** Attack Simulation / Serialization
**Personas:** Red Team Engineer, Platform Engineer
**Node Count:** 1 | **Status:** Implemented

---

## Source Files
- `suite-attack/attack/fail_engine.py`

## Graph Nodes (Labels)
- Convert GradingDimension to dict.

---

## Architecture Diagram

```mermaid
graph TD
    A[GradingDimension object] --> B[to_dict()]
    B --> C[dataclass asdict()]
    C --> D[JSON-safe dict]
    D --> E[API response / report]
```

---

## Code Proof

- `suite-attack/attack/fail_engine.py:L1` — Convert GradingDimension to dict — serialization utility

---

## Inter-Dependencies

- `suite-attack/attack/fail_engine.py (338-340, 342-345)`
- `suite-attack/api/attack_sim_router.py`

### Community Link Dependencies
- No external community dependencies

---

## Data Flow

```
GradingDimension → asdict() or __dict__ → {name, score, grade, weight} dict
```

---

## Referenced Docs

- `suite-attack/api/attack_sim_router.py`
- `suite-attack/attack/fail_engine.py`

---

## Acceptance Criteria

- [ ] All GradingDimension fields serialized
- [ ] No datetime objects in output
- [ ] Round-trip: dict → GradingDimension → dict identical

---

## Effort Estimate

**0.5 day (Trivial — isolated leaf module)**

---

## Status

**Implemented** — Module exists in codebase. Integration tests recommended.
