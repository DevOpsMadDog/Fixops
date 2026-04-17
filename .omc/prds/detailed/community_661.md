# Community 661 PRD — Feature Flags / Boolean Evaluation

## Master Goal Mapping
- **ALDECI Domain**: Feature Flags / Boolean Evaluation
- **Module**: `BaseFeatureFlagProvider (ABC)`
- **Source**: `suite-core/core/flags/base.py:L73`
- **Function/Method**: `bool`
- **Persona Alignment**: Security Engineer, Platform Operator
- **Strategic Goal**: Provide reliable, well-defined contract for `bool` within the Feature Flags / Boolean Evaluation subsystem

## Architecture Diagram

```mermaid
graph TD
    A[Caller] --> B["bool()"]
    B --> C[BaseFeatureFlagProvider (ABC)]
    C --> D[Implementation]
    D --> E[Return / Side-effect]
```

## Code Proof

**File**: `suite-core/core/flags/base.py` — **Line**: `L73`

**Signature**: `abstractmethod def bool(key, default, context=None) -> bool`

```python
"""Evaluate a boolean flag.
Parameters
----------
key: Flag key (e.g., "fixops.module.guardrails.enabled")
default: Default value if flag not found
context: Evaluation context for targeting
Returns
-------
bool
    Flag value
"""
```

## Inter-Dependencies

- `EvaluationContext`
- `LaunchDarklyProvider.bool`
- `StaticFlagProvider.bool`

## Data Flow

key + default + context → flag store lookup → bool (with fallback to default)

## Referenced Docs

- `docs/ALDECI_REARCHITECTURE_v2.md` — Architecture source of truth
- `suite-core/core/flags/base.py` — Full module implementation

## Acceptance Criteria

- [ ] Returns flag value when key exists
- [ ] Returns default when key not found
- [ ] Applies targeting rules from context
- [ ] Never raises on missing key

## Effort Estimate

**XS**

## Status

**Implemented**
