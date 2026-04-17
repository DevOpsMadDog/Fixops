# PRD — Community 605: SignatureChain — Entries Snapshot Property

## Master Goal Mapping
**ALDECI Pillar:** Post-quantum tamper-evident evidence chain — returns an immutable snapshot copy of the chain entries, preventing external mutation while allowing safe iteration and audit.

## Architecture Diagram
```mermaid
graph LR
    A[Evidence vault / auditor] -->|.entries| B[SignatureChain]
    B -->|_lock + list copy| C[List[SignatureChainEntry] snapshot]
    C --> D[Chain integrity verification]
    C --> E[Audit report export]
```

## Code Proof
**File:** `suite-core/core/crypto.py:L2092`  
**Module:** `crypto.SignatureChain.entries`

```python
@property
def entries(self) -> List[SignatureChainEntry]:
    """Return a snapshot copy of the chain entries (immutable from caller's view)."""
    with self._lock:
        return list(self._entries)
```

## Inter-Dependencies
- `SignatureChain.append()` — mutates `_entries` under same lock
- `SignatureChain.verify_chain()` — reads entries for integrity check
- `EvidenceWORMStore` — calls `entries` to export audit trail
- C606 `SignatureChain.from_dict` — reconstructs entries list

## Data Flow
Thread-safe read under lock → defensive list copy → returned to caller; mutations to returned list do not affect chain.

## Referenced Docs
- ALDECI Rearchitecture v2 §Evidence Chain
- WORM storage tamper evidence design
- Thread-safe immutable snapshot pattern

## Acceptance Criteria
- [ ] Returns list (not internal deque)
- [ ] Caller mutation doesn't affect chain
- [ ] Thread-safe under concurrent append
- [ ] Length matches number of appended entries
- [ ] Each element is `SignatureChainEntry`

## Effort Estimate
XS — 0.5 day (implemented; add snapshot isolation test)

## Status
DONE — implemented at L2092
