# ALDECI Backend Architecture Review

## Critical Findings

### 1. 26 Routers Without Authentication (CRITICAL)
rbac_router, secrets_rotation_router, session_router, graphql_router and 22 more mounted without Depends(_verify_api_key). Any request succeeds without credentials.

### 2. vendor_risk_router ImportError (CRITICAL)
Line 80 lazy import references core.vendor_risk instead of core.vendor_risk_engine.

### 3. 7 Duplicate Router Mounts (MEDIUM)
dlp, attack_surface_mgmt, security_metrics_dashboard, kpi_tracking, asset_criticality, iot_security, threat_correlation mounted twice.

### 4. 53 Orphaned Router Files (LOW)
Including brain_router (741 LOC), copilot_router (2321 LOC), mpte_router (1403 LOC).

### 5. OTel Hardcoded to Docker hostname (LOW)
collector:4318 unresolvable outside Docker. 148 log errors.

### 6. Pydantic schema field shadowing (LOW)
db_security_router.py uses reserved field name.

## Recommendations
1. Add auth to 26 routers (HIGH priority)
2. Remove 7 duplicates
3. Fix vendor_risk import
4. Set OTEL_EXPORTER_OTLP_ENDPOINT in .env
5. Audit 53 orphans
6. Decompose app.py long-term
