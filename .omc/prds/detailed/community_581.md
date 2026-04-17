# PRD — Community 581: EventStream — Process-Wide Singleton Accessor

## Master Goal Mapping
**ALDECI Pillar:** Real-time event bus — provides a process-wide default `EventStream` instance via lazy initialization, enabling decoupled publish/subscribe across all ALDECI engines without explicit dependency injection.

## Architecture Diagram
```mermaid
graph LR
    A[Any engine / router] -->|EventStream.instance()| B[shared EventStream]
    B -->|_default_instance is None| C[create EventStream]
    C --> D[_default_instance cached]
    D --> E[publish / subscribe]
```

## Code Proof
**File:** `suite-core/core/event_stream.py:L153`  
**Module:** `event_stream.EventStream.instance`

```python
@classmethod
def instance(cls) -> EventStream:
    """Return (or create) the process-wide default EventStream."""
    if cls._default_instance is None:
        cls._default_instance = cls()
    return cls._default_instance
```

## Inter-Dependencies
- `EventStream.publish()` — called by engines to emit events
- `EventStream.subscribe()` — called by SSE handlers
- C582 `reset_instance` — test teardown companion
- Alert broadcaster — feeds from EventStream events

## Data Flow
Module call → class-level `_default_instance` check → lazy create → return cached instance for publish/subscribe use.

## Referenced Docs
- ALDECI Rearchitecture v2 §Event Bus
- Observer pattern / publish-subscribe architecture

## Acceptance Criteria
- [ ] First call creates an `EventStream` instance
- [ ] Second call returns same instance (identity)
- [ ] No arguments required
- [ ] C582 reset makes next call create fresh instance

## Effort Estimate
XS — 0.5 day (implemented; add singleton identity test)

## Status
DONE — implemented at L153
