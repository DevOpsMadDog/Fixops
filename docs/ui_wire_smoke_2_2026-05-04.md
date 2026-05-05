# UI Wire Smoke Verify #2 — 2026-05-05

**Sampled**: 15 files modified in last 2 hours  
**Build**: green (3.11s, Vite 6)  
**CRITICAL fakes**: 0  

## Results

| Component | apiFetch/useQuery | api-path | MOCK_imports | EmptyState | Status |
|-----------|:-----------------:|:--------:|:------------:|:----------:|--------|
| CloudCompliancePanel.tsx | Y | Y | N | Y | REAL |
| ComplianceGapPanel.tsx | Y | Y | N | Y | REAL |
| EndpointCompliancePanel.tsx | Y | Y | N | Y | REAL |
| AutoWaiverRulesPanel.tsx | Y* | Y* | N | Y | REAL |
| ExceptionsListPanel.tsx | Y* | Y* | N | Y | REAL |
| ExceptionWorkflowPanel.tsx | Y* | Y* | N | Y | REAL |
| FirewallPanel.tsx | Y** | Y | N | N | REAL |
| ZeroTrustPolicyPanel.tsx | Y** | Y | N | N | REAL |
| ControlTestingPanel.tsx | Y | Y | N | Y | REAL |
| CyberModelsPanel.tsx | Y* | Y* | N | Y | REAL |
| ModelingPipelinePanel.tsx | Y* | Y* | N | Y | REAL |
| StrideModelsPanel.tsx | Y* | Y* | N | Y | REAL |
| SupplyChainIntelPanel.tsx | Y** | Y | N | Y | REAL |
| SupplyChainRiskPanel.tsx | Y** | Y | N | Y | REAL |
| SupplyChainSecurityPanel.tsx | Y** | Y | N | Y | REAL |

**Notes**:
- `Y*` = uses named api object (e.g. `autoWaiverApi`, `threatModelingApi`) exported from `src/lib/api.ts` — each wraps a real `api.get("/api/v1/...")` call. Confirmed at api.ts lines 1452–1512.
- `Y**` = uses `api.get()` or `buildApiUrl`+`fetch()` directly against `/api/v1/` endpoints. No apiFetch/useQuery import but fully wired.
- No file imports from fixtures, data/, or contains MOCK_ strings.

## Summary

- **15/15 REAL** — all sampled components wire to live `/api/v1/` endpoints
- **0 SHADOWED** — no mock imports, no hardcoded fixture arrays
- **0 CRITICAL** — no MOCK_ / fixture imports detected
- Build: **green** — `✓ built in 3.11s`
