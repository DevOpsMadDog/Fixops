# Community 665 PRD — Feature Flags / A/B Testing

## Master Goal Mapping
- **ALDECI Domain**: Feature Flags / A/B Testing
- **Module**: `BaseFeatureFlagProvider (ABC)`
- **Source**: `suite-core/core/flags/base.py:L169`
- **Function/Method**: `variant`
- **Persona Alignment**: Security Engineer, Platform Operator
- **Strategic Goal**: Provide reliable, well-defined contract for `variant` within the Feature Flags / A/B Testing subsystem

## Architecture Diagram

```mermaid
graph TD
    A[Caller] --> B["variant()"]
    B --> C[BaseFeatureFlagProvider (ABC)]
    C --> D[Implementation]
    D --> E[Return / Side-effect]
```

## Code Proof

**File**: `suite-core/core/flags/base.py` — **Line**: `L169`

**Signature**: `abstractmethod def variant(key, default, context=None) -> str`

```python
"""Evaluate a multi-variant flag for A/B testing.
Parameters
----------
key: Flag key
default: Default variant if flag not found
context: Evaluation context for targeting (used for consistent hashing)
"""
```

## Inter-Dependencies

- `EvaluationContext.user_key (for hashing)`
- `StaticFlagProvider.variant`

## Data Flow

key + context.user_key → consistent hash → variant string (e.g. 'control'/'treatment')

## Referenced Docs

- `docs/ALDECI_REARCHITECTURE_v2.md` — Architecture source of truth
- `suite-core/core/flags/base.py` — Full module implementation

## Acceptance Criteria

- [ ] Same user_key always returns same variant
- [ ] Returns default when flag absent
- [ ] Supports multiple variants beyond A/B

## Effort Estimate

**S**

## Status

**Implemented**
