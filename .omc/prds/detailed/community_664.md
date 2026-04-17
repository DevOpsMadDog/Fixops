# Community 664 PRD — Feature Flags / JSON Evaluation

## Master Goal Mapping
- **ALDECI Domain**: Feature Flags / JSON Evaluation
- **Module**: `BaseFeatureFlagProvider (ABC)`
- **Source**: `suite-core/core/flags/base.py:L145`
- **Function/Method**: `json`
- **Persona Alignment**: Security Engineer, Platform Operator
- **Strategic Goal**: Provide reliable, well-defined contract for `json` within the Feature Flags / JSON Evaluation subsystem

## Architecture Diagram

```mermaid
graph TD
    A[Caller] --> B["json()"]
    B --> C[BaseFeatureFlagProvider (ABC)]
    C --> D[Implementation]
    D --> E[Return / Side-effect]
```

## Code Proof

**File**: `suite-core/core/flags/base.py` — **Line**: `L145`

**Signature**: `abstractmethod def json(key, default, context=None) -> Dict[str, Any]`

```python
"""Evaluate a JSON flag.
Parameters
----------
key: Flag key
default: Default value if flag not found
context: Evaluation context for targeting
Returns
-------
Dict[str, Any]
    Flag value
"""
```

## Inter-Dependencies

- `EvaluationContext`
- `StaticFlagProvider.json`

## Data Flow

key → flag store → Dict (complex config) or default dict

## Referenced Docs

- `docs/ALDECI_REARCHITECTURE_v2.md` — Architecture source of truth
- `suite-core/core/flags/base.py` — Full module implementation

## Acceptance Criteria

- [ ] Returns dict on success
- [ ] Returns default dict on miss
- [ ] Used for complex per-feature configuration objects

## Effort Estimate

**XS**

## Status

**Implemented**
