# PRD — Community 541: ntfy.sh Severity → Emoji Tag Mapping

## Master Goal Mapping
**ALDECI Pillar:** Real-time alerting layer — attaches emoji tag lists to ntfy.sh notifications so recipients can visually triage severity at a glance.

## Architecture Diagram
```mermaid
graph LR
    A[AlertSeverity.ntfy_tags] -->|list[str]| B[WebhookNotifier]
    B -->|Tags: header comma-joined| C[ntfy.sh API]
    C -->|emoji rendered| D[Subscriber device]
```

## Code Proof
**File:** `suite-core/core/webhook_notifier.py:L132`  
**Module:** `webhook_notifier.AlertSeverity.ntfy_tags`

```python
@property
def ntfy_tags(self) -> List[str]:
    """Emoji tags for ntfy.sh notification."""
    return {
        "critical": ["rotating_light", "skull"],
        "high":     ["warning", "fire"],
        "medium":   ["large_orange_circle"],
        "low":      ["large_blue_circle"],
        "info":     ["information_source"],
    }[self.value]
```

## Inter-Dependencies
- C540 (`ntfy_priority`) — sibling property on same enum
- `WebhookNotifier.send_alert()` — joins tags and sets header

## Data Flow
Severity enum → list of ntfy.sh tag strings → comma-joined `Tags:` HTTP header → emoji shown in notification.

## Referenced Docs
- ntfy.sh supported emoji tags: https://ntfy.sh/docs/publish/#tags-emojis
- ALDECI Rearchitecture v2 §Push Notifications

## Acceptance Criteria
- [ ] Each severity level returns ≥1 tag string
- [ ] Tags are valid ntfy.sh emoji identifiers
- [ ] Unit test: assert `critical` includes `rotating_light`

## Effort Estimate
XS — 0.5 day (property implemented; add test)

## Status
DONE — implemented at L132
