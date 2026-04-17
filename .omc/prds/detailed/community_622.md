# PRD — Community 622: Breach Simulation — Time-to-Contain Calculator

## Master Goal Mapping
**ALDECI Pillar:** Breach simulation engine — computes time-to-contain (seconds) by adding 10 minutes per unblocked attack step to the detection time, modeling attacker dwell time after initial detection.

## Architecture Diagram
```mermaid
graph LR
    A[List[AttackStep]] --> B[_compute_containment_time]
    A2[detection_time float] --> B
    B -->|count unblocked * 600s| C[additional seconds]
    C -->|+ detection_time| D[containment_time float]
    D --> E[SimulationResult.mttc_seconds]
```

## Code Proof
**File:** `suite-core/core/breach_simulation.py:L645`  
**Module:** `breach_simulation.BreachSimulationEngine._compute_containment_time`

```python
@staticmethod
def _compute_containment_time(steps: List[AttackStep], detection_time: float) -> float:
    """Compute time-to-contain in seconds.
    Containment follows detection. Fewer unblocked steps = faster containment.
    """
    unblocked = sum(1 for s in steps if not s.blocked)
    additional = unblocked * 600.0  # 10 min per unblocked step
    return detection_time + additional
```

## Inter-Dependencies
- `_compute_detection_time()` — C621, produces `detection_time` input
- `run_simulation()` — calls both timing helpers sequentially
- `SimulationResult` — stores MTTC alongside MTTD
- `/api/v1/threat-simulation` router

## Data Flow
Detection time + (unblocked step count × 600s) → total containment time → stored in simulation result.

## Referenced Docs
- ALDECI Rearchitecture v2 §Breach Simulation
- MTTC (Mean Time To Contain) metric definition
- Incident containment modeling

## Acceptance Criteria
- [ ] All steps blocked → containment = detection_time
- [ ] N unblocked steps → detection_time + N×600
- [ ] Returns `float`
- [ ] Always ≥ `detection_time`

## Effort Estimate
S — 1 day (implemented; add containment time test with mixed blocked/unblocked steps)

## Status
DONE — implemented at L645
