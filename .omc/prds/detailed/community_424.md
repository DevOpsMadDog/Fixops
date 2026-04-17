# PRD — Community 424: Security Posture Card Dashboard Component (aldeci legacy)

## Master Goal Mapping
- **Platform Goal**: Homepage security posture widget — real-time risk score, trend direction, top threats, quick navigation
- **Persona**: CISO, SOC Manager — first thing they see on the dashboard
- **ALDECI Pillar**: Security Posture / Executive View (Legacy)

## Architecture Diagram
```mermaid
graph TD
    A[Dashboard.tsx] --> B[SecurityPostureCard.tsx]
    B --> C[useQuery: api.getPosture()]
    B --> D[useQuery: feedsApi.getSummary()]
    B --> E[PostureMetric list: label/value/target/status]
    B --> F[TrendingUp/Down indicator]
    B --> G[Top threats badge list]
    B --> H[Navigate CTA: View Details]
    C --> I[GET /api/v1/posture]
    D --> J[GET /api/v1/feeds/summary]
```

## Code Proof
- **File**: `suite-ui/aldeci/src/components/dashboard/SecurityPostureCard.tsx:1-60+`
- **Queries**: `useQuery` for posture + feedsApi summary
- **PostureMetric interface**: `{ label, value, target, status: 'good'|'warning'|'critical', description }`
- **Icons**: Shield, TrendingDown/Up, AlertTriangle, CheckCircle2, ArrowRight
- **Components**: Card, CardContent, CardHeader, CardTitle, Badge, Button, Skeleton

## Inter-Dependencies
- **Backend**: `posture_score_engine.py` (35 tests), feeds summary endpoint
- **API**: `api` and `feedsApi` from `../../lib/api`
- **Parent**: `Dashboard.tsx` — primary placement

## Data Flow
```
useQuery posture → score + trend direction →
TrendingUp(green)/TrendingDown(red) →
Metrics list with status colors →
Skeleton while loading → navigate /security-posture on CTA
```

## Acceptance Criteria
- [ ] Real-time posture score displayed
- [ ] Trend direction with colored icon
- [ ] Per-metric status color (good=green/warning=yellow/critical=red)
- [ ] Top threats from feeds summary
- [ ] Skeleton loading state
- [ ] Navigate to /security-posture on CTA click

## Effort Estimate
**M** — 1.5 days (complete, frozen)

## Status
**DONE** — Frozen legacy dashboard widget
