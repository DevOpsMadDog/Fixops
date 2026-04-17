# PRD — Community 552: ZeroGravity — Weighted Probabilistic Index Sampler

## Master Goal Mapping
**ALDECI Pillar:** ZeroGravity ML inference layer — selects a random index from a probability distribution using cumulative CDF sampling, with deterministic hash fallback when `random` is unavailable.

## Architecture Diagram
```mermaid
graph LR
    A[probs: List[float]] --> B[_weighted_choice]
    B -->|random.random or hash fallback| C[r: float 0-1]
    C -->|CDF walk| D[index: int]
    D --> E[token / action sampler]
```

## Code Proof
**File:** `suite-core/core/zero_gravity.py:L1697`  
**Module:** `zero_gravity._weighted_choice`

```python
@staticmethod
def _weighted_choice(probs: List[float]) -> int:
    """Return an index sampled according to probs."""
    r = hash(str(probs)) % 10_000 / 10_000.0  # Deterministic fallback
    try:
        import random as _random; r = _random.random()
    except ImportError:
        pass
    cumulative = 0.0
    for i, p in enumerate(probs):
        cumulative += p
        if r <= cumulative:
            return i
    return len(probs) - 1
```

## Inter-Dependencies
- ZeroGravity token sampler — uses this for next-token prediction
- ZeroGravity beam search — samples candidate continuations
- C551 `window_size` — context window feeding probability estimates

## Data Flow
Probability list → uniform sample `r` → CDF scan → first bucket where cumulative ≥ r → index returned.

## Referenced Docs
- ALDECI Rearchitecture v2 §Local LLM Inference
- Inverse CDF sampling algorithm

## Acceptance Criteria
- [ ] Uniform probs → roughly equal selection over many calls
- [ ] Single prob=1.0 → always returns index 0
- [ ] Deterministic fallback returns valid index when random unavailable
- [ ] All-zero probs → returns last index (edge case)

## Effort Estimate
S — 1 day (implemented; needs statistical distribution test)

## Status
DONE — implemented at L1697
