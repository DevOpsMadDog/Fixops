# PRD — Community 434: Scanner Dashboard Page (aldeci legacy)

## Master Goal Mapping
- **Platform Goal**: Unified view of all 32 scanner normalizers — health status, scan results, trigger scans
- **Persona**: Security Engineer, DevSecOps, Vulnerability Manager
- **ALDECI Pillar**: Scanner Integration / Discovery (Legacy)
- **Backend**: `suite-core/core/scanner_parsers.py` (32 normalizers)

## Architecture Diagram
```mermaid
graph TD
    A[Route: /discover/scanner] --> B[ScannerDashboard.tsx]
    B --> C[useQuery: scanner list + health]
    B --> D[useQueryClient: invalidate on scan]
    B --> E[Scanner type cards: SAST/DAST/SCA/container/cloud]
    B --> F[AnimatePresence: scan progress]
    B --> G[Play button per scanner]
    B --> H[Results: finding count by severity]
    C --> I[GET /api/v1/scanners]
    G --> J[POST /api/v1/scanners/{id}/run]
```

## Code Proof
- **File**: `suite-ui/aldeci/src/pages/discover/ScannerDashboard.tsx:1-70+`
- **Icons**: Shield, Code, Globe, Key, Box, Cloud, Zap, Bug, Brain, RefreshCw, Play, CheckCircle2, Loader2, Activity, BarChart3, Wifi, WifiOff, Server, FileCode
- **Hooks**: useState, useCallback, useQuery, useQueryClient, motion, AnimatePresence

## Inter-Dependencies
- **Backend**: 32 scanner normalizers in `scanner_parsers.py`
- **API**: `/api/v1/scanners`
- **Related**: DataFabric (data source), VulnHeatmap (findings visualization)

## Data Flow
```
GET /api/v1/scanners → 32 scanner cards →
Play → POST scan → AnimatePresence loading →
Results: finding counts by severity →
Wifi/WifiOff for scanner connectivity status
```

## Acceptance Criteria
- [ ] All 32 scanner types displayed with correct icons
- [ ] Online/offline status (Wifi/WifiOff)
- [ ] Trigger scan per scanner
- [ ] Finding counts by severity post-scan
- [ ] Scan progress animation
- [ ] Last scan timestamp displayed

## Effort Estimate
**L** — 3 days (complete, frozen)

## Status
**DONE** — Frozen legacy scanner dashboard
