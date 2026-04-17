# PRD: Community 529 — soc_triage_engine._evaluate_conditions

## Master Goal Mapping
**ALDECI Pillar**: SOC Operations — Alert Rule Matching  
**Persona**: SOC Analyst, Security Engineer  
**Business Value**: Evaluates a conditions dict against an incoming alert, enabling rule-based triage automation where alerts matching conditions are automatically routed to the correct tier, escalated, or suppressed without manual analyst review.

## Architecture Diagram
```mermaid
graph TD
    A[Triage rule: conditions=severity=critical,source=crowdstrike] --> B[_evaluate_conditions]
    B --> C[For each key=field, value=expected]
    C --> D{alert[field] == expected?}
    D -->|string match| E[Condition met]
    D -->|regex pattern| F[re.search pattern, alert_field]
    D -->|list| G[alert_field in list]
    E & F & G --> H{All conditions met?}
    H -->|yes| I[Rule matches → apply action]
    H -->|no| J[Rule does not match → try next rule]
    style B fill:#1a1a2e,color:#fff
```

## Code Proof
**File**: `suite-core/core/soc_triage_engine.py`  
```python
def _evaluate_conditions(self, conditions: Dict[str, Any], alert: Dict[str, Any]) -> bool:
    """Evaluate conditions dict against alert.
    Each key=field, value=expected value or regex pattern."""
    for field, expected in conditions.items():
        actual = alert.get(field)
        if isinstance(expected, list):
            if actual not in expected:
                return False
        elif isinstance(expected, str) and expected.startswith("/") and expected.endswith("/"):
            pattern = expected[1:-1]
            if not re.search(pattern, str(actual or "")):
                return False
        elif actual != expected:
            return False
    return True
```

## Inter-Dependencies
- **Upstream**: `triage_alert` calls this for each triage rule
- **Downstream**: Triage action execution (escalate, assign, suppress, notify)
- **Sibling**: `get_instance` (Community 528)

## Data Flow
```
rule.conditions = {"severity": "critical", "source": "/crowdstrike|sentinel/"}
alert = {"severity": "critical", "source": "crowdstrike", "org_id": "acme"}
  → _evaluate_conditions(conditions, alert)
    → "severity": alert["severity"]="critical" == "critical" ✓
    → "source": regex /crowdstrike|sentinel/ matches "crowdstrike" ✓
  → True → apply rule action: escalate to Tier 2
```

## Referenced Docs
- `suite-core/core/soc_triage_engine.py`

## Acceptance Criteria
- [ ] Exact string match: `{"severity": "critical"}` matches alert with severity=critical
- [ ] Regex match: `{"source": "/crowd|sentinel/"}` matches crowdstrike or sentinel
- [ ] List match: `{"env": ["prod", "staging"]}` matches prod or staging
- [ ] Empty conditions dict → True (match-all rule)
- [ ] Missing alert field → condition fails (not KeyError)

## Effort Estimate
**XS** — 0.5 days. Implementation complete; parametrized tests for each match type.

## Status
**COMPLETE** — Implementation exists. Parametrized tests for each condition type needed.
