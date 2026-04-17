# PRD — Community 582: EventStream — Singleton Reset (Test Teardown)

## Master Goal Mapping
**ALDECI Pillar:** Real-time event bus — clears the process-wide `EventStream` singleton for test isolation, ensuring each test gets a fresh event bus with no leaked subscriptions.

## Architecture Diagram
```mermaid
graph LR
    A[test teardown] --> B[reset_instance]
    B -->|_default_instance = None| C[singleton cleared]
    C --> D[next instance() creates fresh EventStream]
```

## Code Proof
**File:** `suite-core/core/event_stream.py:L160`  
**Module:** `event_stream.EventStream.reset_instance`

```python
@classmethod
def reset_instance(cls) -> None:
    """Reset the singleton (useful in tests)."""
    cls._default_instance = None
```

## Inter-Dependencies
- `EventStream.instance()` — C581, creates what reset clears
- All engine tests that publish events — need reset in teardown
- `conftest.py` fixtures — should call `reset_instance()` as cleanup

## Data Flow
Test teardown → sets class-level `_default_instance` to `None` → next `instance()` call creates fresh EventStream.

## Referenced Docs
- ALDECI Rearchitecture v2 §Event Bus Testing
- pytest fixture scope and teardown

## Acceptance Criteria
- [ ] After reset, `_default_instance` is `None`
- [ ] Subsequent `instance()` creates new object
- [ ] Multiple resets are idempotent
- [ ] Leaked subscriptions from prior test not carried over

## Effort Estimate
XS — 0.5 day (implemented; add subscription-leak test)

## Status
DONE — implemented at L160
