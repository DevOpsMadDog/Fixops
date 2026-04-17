# PRD — Community 621: Breach Simulation — Time-to-Detect Calculator

## Master Goal Mapping
**ALDECI Pillar:** Breach simulation engine — computes time-to-detect (seconds) from attack step metadata: undetected attacks return 24-hour dwell time; detected attacks compute time from step count before first detection trigger.

## Architecture Diagram
```mermaid
graph LR
    A[List[AttackStep]] --> B[_compute_detection_time]
    B -->|no detection| C[86400.0s = 24h dwell]
    B -->|first_detected idx * 300s| D[MTTD in seconds]
    D -->|max 60s floor| E[detection_time float]
    E --> F[SimulationResult.mttd_seconds]
```

## Code Proof
**File:** `suite-core/core/breach_simulation.py:L626`  
**Module:** `breach_simulation.BreachSimulationEngine._compute_detection_time`

```python
@staticmethod
def _compute_detection_time(steps: List[AttackStep]) -> float:
    """Compute time-to-detect in seconds.
    Steps that triggered detection reduce the detection window.
    If nothing was detected, return a large dwell time.
    """
    detected_indices = [i for i, s in enumerate(steps) if s.detection_triggered]
    if not detected_indices: return 86400.0  # 24h — not detected
    first_detected = detected_indices[0]
    base = first_detected * 300.0  # 5 min per step
    return max(60.0, base)
```

## Inter-Dependencies
- `run_simulation()` — calls `_compute_detection_time` on step results
- `_compute_containment_time()` — C622, receives detection_time as input
- `SimulationResult` — stores both MTTD and MTTC
- `/api/v1/threat-simulation` router — returns simulation metrics

## Data Flow
Attack steps → find first detection-triggered step → multiply by 5 min → apply 60s minimum floor → return MTTD in seconds.

## Referenced Docs
- ALDECI Rearchitecture v2 §Breach Simulation
- MTTD (Mean Time To Detect) metric definition
- NIST SP 800-61 (Incident Response) timing guidelines

## Acceptance Criteria
- [ ] No detected steps → 86400.0 seconds
- [ ] Detection at step 0 → max(60, 0) = 60.0 seconds
- [ ] Detection at step 2 → max(60, 600) = 600.0 seconds
- [ ] Returns `float` (not int)
- [ ] Minimum floor of 60.0 seconds enforced

## Effort Estimate
S — 1 day (implemented; add detection time parametrized test)

## Status
DONE — implemented at L626
