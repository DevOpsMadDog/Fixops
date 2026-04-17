# PRD — Community 550: ZeroGravity Compressor — Compression Ratio Calculator

## Master Goal Mapping
**ALDECI Pillar:** ZeroGravity ML context layer — calculates byte-savings ratio (0.0–1.0) from original vs compressed sizes, used for adaptive compression decisions.

## Architecture Diagram
```mermaid
graph LR
    A[original bytes] --> B[ratio]
    A2[compressed bytes] --> B
    B -->|1 - len(comp)/len(orig)| C[float 0.0 to 1.0]
    C --> D[Adaptive compression policy]
```

## Code Proof
**File:** `suite-core/core/zero_gravity.py:L162`  
**Module:** `zero_gravity.Compressor.ratio`

```python
@staticmethod
def ratio(original: bytes, compressed: bytes) -> float:
    """Calculate compression ratio."""
    if len(original) == 0:
        return 1.0
    return 1.0 - (len(compressed) / len(original))
```

## Inter-Dependencies
- `Compressor.compress()` — C548, produces compressed bytes
- ZeroGravity adaptive window — uses ratio to decide compression strategy
- C551 `window_size` — drives adaptive decisions using ratio feedback

## Data Flow
Original and compressed byte lengths → ratio formula → float in [0, 1] where 1.0 = 100% savings.

## Referenced Docs
- ALDECI Rearchitecture v2 §Context Compression
- Compression theory: ratio = 1 - (compressed / original)

## Acceptance Criteria
- [ ] Empty original → ratio = 1.0 (no division by zero)
- [ ] Incompressible data → ratio near 0.0 or negative
- [ ] Perfectly compressible → ratio close to 1.0
- [ ] Returns float in [-inf, 1.0] range

## Effort Estimate
XS — 0.5 day (implemented; add edge-case tests)

## Status
DONE — implemented at L162
