# PRD — Community 598: Hybrid Key Manager — Combined SHA-256 Fingerprint

## Master Goal Mapping
**ALDECI Pillar:** Post-quantum hybrid cryptography — computes a single SHA-256 fingerprint over both RSA and ML-DSA public keys, enabling efficient hybrid key identification and verification without loading full keys.

## Architecture Diagram
```mermaid
graph LR
    A[RSAKeyManager.metadata.fingerprint] --> B[combined_fingerprint]
    A2[MLDSAKeyManager.metadata.fingerprint] --> B
    B -->|sha256(rsa_fp:mldsa_fp)| C[sha256:hexdigest]
    C --> D[HybridSignature envelope]
    D --> E[Audit log / key tracking]
```

## Code Proof
**File:** `suite-core/core/crypto.py:L1084`  
**Module:** `crypto.HybridKeyManager.combined_fingerprint`

```python
@property
def combined_fingerprint(self) -> str:
    """Return a combined SHA-256 fingerprint over both public keys."""
    with self._lock:
        if self._combined_fingerprint is None:
            rsa_fp = self.rsa.metadata.fingerprint
            mldsa_fp = self.mldsa.metadata.fingerprint
            combined = hashlib.sha256(
                f"{rsa_fp}:{mldsa_fp}".encode("utf-8")
            ).hexdigest()
            self._combined_fingerprint = f"sha256:{combined}"
    return self._combined_fingerprint
```

## Inter-Dependencies
- `RSAKeyManager.metadata` — C593, provides RSA fingerprint
- `MLDSAKeyManager.metadata` — C596, provides PQ fingerprint
- `HybridSigner.sign()` — embeds combined fingerprint in signature
- Evidence vault — uses fingerprint for key tracking

## Data Flow
RSA fingerprint + ML-DSA fingerprint → colon-joined → SHA-256 hash → `sha256:<hex>` formatted → cached in `_combined_fingerprint`.

## Referenced Docs
- ALDECI Rearchitecture v2 §Post-Quantum Cryptography
- SSH key fingerprint convention (`sha256:<base64>`)
- Hybrid key identification scheme

## Acceptance Criteria
- [ ] Starts with `sha256:`
- [ ] 64-hex-char hash after prefix
- [ ] Deterministic for same key pair
- [ ] Cached on second call (no recompute)
- [ ] Thread-safe computation

## Effort Estimate
S — 1 day (implemented; add fingerprint format and caching tests)

## Status
DONE — implemented at L1084
