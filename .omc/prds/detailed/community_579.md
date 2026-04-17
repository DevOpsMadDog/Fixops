# PRD — Community 579: KnowledgeBrain — Singleton Accessor

## Master Goal Mapping
**ALDECI Pillar:** TrustGraph knowledge layer — thread-safe double-checked locking singleton that ensures only one `KnowledgeBrain` instance exists per process, sharing the SQLite knowledge graph connection.

## Architecture Diagram
```mermaid
graph LR
    A[Any module] -->|get_instance()| B[KnowledgeBrain singleton]
    B -->|_instance None| C[acquire _lock]
    C -->|double-check| D[create KnowledgeBrain]
    D --> E[_instance set]
    E --> F[shared DB connection]
```

## Code Proof
**File:** `suite-core/core/knowledge_brain.py:L192`  
**Module:** `knowledge_brain.KnowledgeBrain.get_instance`

```python
@classmethod
def get_instance(cls, db_path="fixops_brain.db") -> "KnowledgeBrain":
    """Get or create the singleton KnowledgeBrain instance."""
    if cls._instance is None:
        with cls._lock:
            if cls._instance is None:
                cls._instance = cls(db_path=db_path)
    return cls._instance
```

## Inter-Dependencies
- `KnowledgeBrain` — the SQLite-backed knowledge graph
- TrustGraph GraphRAG retriever — calls `get_instance()` for graph queries
- Brain pipeline — calls `get_instance()` for knowledge enrichment
- C580 `reset_instance` — test teardown companion

## Data Flow
First call → double-checked lock → instantiate with `db_path` → cache in `_instance` → all subsequent calls return same object.

## Referenced Docs
- ALDECI Rearchitecture v2 §TrustGraph Knowledge Layer
- Double-checked locking pattern (Python threading)
- `threading.Lock` docs

## Acceptance Criteria
- [ ] First call creates instance
- [ ] Second call returns same object (identity check)
- [ ] Thread-safe: concurrent calls never create two instances
- [ ] Custom `db_path` honored on first call
- [ ] `_instance` is `KnowledgeBrain` type

## Effort Estimate
S — 1 day (implemented; add concurrency stress test)

## Status
DONE — implemented at L192
