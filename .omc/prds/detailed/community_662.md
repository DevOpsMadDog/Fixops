# Community 662 PRD — Feature Flags / String Evaluation

## Master Goal Mapping
- **ALDECI Domain**: Feature Flags / String Evaluation
- **Module**: `BaseFeatureFlagProvider (ABC)`
- **Source**: `suite-core/core/flags/base.py:L97`
- **Function/Method**: `string`
- **Persona Alignment**: Security Engineer, Platform Operator
- **Strategic Goal**: Provide reliable, well-defined contract for `string` within the Feature Flags / String Evaluation subsystem

## Architecture Diagram

```mermaid
graph TD
    A[Caller] --> B["string()"]
    B --> C[BaseFeatureFlagProvider (ABC)]
    C --> D[Implementation]
    D --> E[Return / Side-effect]
```

## Code Proof

**File**: `suite-core/core/flags/base.py` — **Line**: `L97`

**Signature**: `abstractmethod def string(key, default, context=None) -> str`

```python
"""Evaluate a string flag.
Parameters
----------
key: Flag key
default: Default value if flag not found
context: Evaluation context for targeting
Returns
-------
str
    Flag value
"""
```

## Inter-Dependencies

- `EvaluationContext`
- `LaunchDarklyProvider.string`
- `StaticFlagProvider.string`

## Data Flow

key → flag store → string value or default

## Referenced Docs

- `docs/ALDECI_REARCHITECTURE_v2.md` — Architecture source of truth
- `suite-core/core/flags/base.py` — Full module implementation

## Acceptance Criteria

- [ ] Returns string flag value when found
- [ ] Returns default string on miss
- [ ] Context enables per-org/user overrides

## Effort Estimate

**XS**

## Status

**Implemented**
