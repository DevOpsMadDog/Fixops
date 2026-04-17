# Community 663 PRD — Feature Flags / Numeric Evaluation

## Master Goal Mapping
- **ALDECI Domain**: Feature Flags / Numeric Evaluation
- **Module**: `BaseFeatureFlagProvider (ABC)`
- **Source**: `suite-core/core/flags/base.py:L121`
- **Function/Method**: `number`
- **Persona Alignment**: Security Engineer, Platform Operator
- **Strategic Goal**: Provide reliable, well-defined contract for `number` within the Feature Flags / Numeric Evaluation subsystem

## Architecture Diagram

```mermaid
graph TD
    A[Caller] --> B["number()"]
    B --> C[BaseFeatureFlagProvider (ABC)]
    C --> D[Implementation]
    D --> E[Return / Side-effect]
```

## Code Proof

**File**: `suite-core/core/flags/base.py` — **Line**: `L121`

**Signature**: `abstractmethod def number(key, default, context=None) -> float`

```python
"""Evaluate a numeric flag.
Parameters
----------
key: Flag key
default: Default value if flag not found
context: Evaluation context for targeting
Returns
-------
float
    Flag value
"""
```

## Inter-Dependencies

- `EvaluationContext`
- `StaticFlagProvider.number`

## Data Flow

key → flag store → float value or default

## Referenced Docs

- `docs/ALDECI_REARCHITECTURE_v2.md` — Architecture source of truth
- `suite-core/core/flags/base.py` — Full module implementation

## Acceptance Criteria

- [ ] Returns float on success
- [ ] Returns default float on miss
- [ ] Used for rate limits, thresholds, batch sizes

## Effort Estimate

**XS**

## Status

**Implemented**
