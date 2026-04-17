# PRD — Community 606: SignatureChain — Deserialization from Dict

## Master Goal Mapping
**ALDECI Pillar:** Post-quantum tamper-evident evidence chain — reconstructs a full `SignatureChain` from a serialized dict, enabling loading of persisted audit chains from DB or JSON export.

## Architecture Diagram
```mermaid
graph LR
    A[Serialized dict from DB] --> B[SignatureChain.from_dict]
    B -->|per entry| C[SignatureChainEntry.from_dict C590]
    C --> D[chain._entries list]
    D --> E[SignatureChain ready for verify]
```

## Code Proof
**File:** `suite-core/core/crypto.py:L2232`  
**Module:** `crypto.SignatureChain.from_dict`

```python
@classmethod
def from_dict(cls, data, signer=None, verifier=None) -> "SignatureChain":
    """Reconstruct a SignatureChain from a serialised dict."""
    chain = cls(signer=signer, verifier=verifier)
    # Deserialize each entry via SignatureChainEntry.from_dict
    for entry_data in data.get("entries", []):
        entry = SignatureChainEntry.from_dict(entry_data)
        chain._entries.append(entry)
    return chain
```

## Inter-Dependencies
- `SignatureChainEntry.from_dict()` — C590, deserializes each entry
- `EvidenceWORMStore.load_chain()` — calls this to restore chain from DB
- `SignatureChain.verify_chain()` — verifies the loaded chain
- C605 `entries` property — accesses loaded entries

## Data Flow
Serialized chain dict → per-entry deserialization via C590 → rebuilt `SignatureChain` with all historical entries → passed to verifier.

## Referenced Docs
- ALDECI Rearchitecture v2 §Evidence Chain Persistence
- Hash-linked log reconstruction
- WORM chain serialization format

## Acceptance Criteria
- [ ] Empty `entries` list → empty chain
- [ ] N entries → chain with N entries
- [ ] Each entry passes `SignatureChainEntry.from_dict` validation
- [ ] Optional signer/verifier injected correctly
- [ ] Round-trip: `from_dict(chain.to_dict())` produces equivalent chain

## Effort Estimate
M — 2 days (implemented; add round-trip serialization test)

## Status
DONE — implemented at L2232
