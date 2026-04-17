# PRD — Community 600: RSAVerifier — `key_manager` Property

## Master Goal Mapping
**ALDECI Pillar:** Post-quantum hybrid cryptography — RSAVerifier checks RSA-SHA256 signatures; exposes the underlying `RSAKeyManager` so callers can access key metadata, rotation state, and fingerprints without going through the signer/verifier interface.

## Architecture Diagram
```mermaid
graph LR
    A[RSAVerifier] -->|key_manager| B[RSAKeyManager]
    B -->|.metadata| C[KeyMetadata fingerprint/algorithm]
    B -->|.private_key / public_key| D[Raw key material]
    C & D --> E[Key rotation / audit log]
```

## Code Proof
**File:** `suite-core/core/crypto.py:L1244`  
**Module:** `crypto.RSAVerifier.key_manager`

```python
@property
def key_manager(self) -> RSAKeyManager:
    """Return the underlying :RSAKeyManager:.""""""
    return self._key_manager
```

## Inter-Dependencies
- `RSAVerifier.__init__()` — accepts optional `RSAKeyManager` parameter
- Caller — accesses `key_manager` to read metadata or rotate keys
- `HybridKeyManager` — for hybrid variants, wraps RSA+MLDSA managers
- Evidence vault / audit logger — reads fingerprint via key_manager

## Data Flow
Simple property returning the underlying `RSAKeyManager` instance injected at construction or created with defaults.

## Referenced Docs
- ALDECI Rearchitecture v2 §Post-Quantum Cryptography
- Key management lifecycle
- Separation of concerns: key mgmt vs. crypto operations

## Acceptance Criteria
- [ ] Returns `RSAKeyManager` instance (not None)
- [ ] Returns same object injected at init
- [ ] No side effects
- [ ] Enables key rotation by swapping manager

## Effort Estimate
XS — 0.5 day (implemented; add property identity test)

## Status
DONE — implemented at L1244
