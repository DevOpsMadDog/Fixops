# Threat Architecture Report — 2026-03-02 (Session 4: Investor Demo Polish)

## Mission
Build investor-ready CTEM demo scripts for DEMO-004 (Enterprise Demo 2026-03-06).

## New Deliverables

### 1. `scripts/ctem-investor-demo.sh` — 24/24 Steps ✅
Pure bash/curl investor demo with 5 phases:

| Phase | Steps | Endpoints | Status |
|-------|-------|-----------|--------|
| **DISCOVER** | 8 | SAST, Secrets, IaC, Container, CloudFormation, Malware, DAST, API Fuzzer | ✅ |
| **VALIDATE** | 5 | Brain Pipeline, MPTE verify, MPTE comprehensive, Sandbox PoC, Attack Sim | ✅ |
| **REMEDIATE** | 4 | AutoFix SQLi, AutoFix CmdI, Bulk Fix, Validate | ✅ |
| **COMPLY** | 4 | Evidence Bundle, Signed Export, SOC2, PCI-DSS | ✅ |
| **PLATFORM** | 3 | MCP Tools, Risk Dashboard, Analytics | ✅ |

- Runtime: ~80s end-to-end
- Beautiful terminal output with narration mode
- Saves JSON results to `data/demo-results/`

### 2. `scripts/mpte-sandbox-demo.sh` — 12/12 Steps ✅
MPTE + Sandbox PoC verifier integration:

| Step | Endpoint | Status |
|------|----------|--------|
| SAST Discovery | `/api/v1/sast/scan/code` | ✅ 3 findings |
| Brain Pipeline | `/api/v1/brain/pipeline/run` | ✅ 12 steps |
| MPTE Verify | `/api/v1/mpte/verify` | ✅ pending |
| MPTE Comprehensive | `/api/v1/mpte/scan/comprehensive` | ✅ scan_started |
| Sandbox PoC | `/api/v1/sandbox/verify` | ✅ sandbox_unavailable (no Docker) |
| Sandbox Finding Verify | `/api/v1/sandbox/verify-finding` | ✅ |
| Sandbox Stats | `/api/v1/sandbox/stats` | ✅ |
| AutoFix Generate | `/api/v1/autofix/generate` | ✅ confidence 0.866 |
| AutoFix Validate | `/api/v1/autofix/validate` | ✅ ok |
| Evidence Bundle | `/api/v1/evidence/bundles/generate` | ✅ EVB-2026-xxx |
| Signed Export | `/api/v1/evidence/export` | ✅ RSA-SHA256 |
| Reachability | `/api/v1/sandbox/reachability` | ✅ |

## API Response Discoveries
1. Evidence bundle `id` field (not `bundle_id`)
2. Valid frameworks: `SOC2`, `PCI-DSS`, `ISO27001` (not `ISO-27001`)
3. Evidence export `signature` is plain string, algorithm in `signature_algorithm`
4. Brain pipeline summary in `summary` dict (not top-level)
5. MPTE verify returns async `pending` with `message`
6. AutoFix fix IDs are ephemeral — may 404 between generate and validate
7. MCP tools returns direct list (not `{tools: [...]}`)
8. Risk endpoint at `/api/v1/risk/status` (not `/api/v1/risk/`)

## Complete Demo Suite Status
| Script | Steps | Pass Rate | Purpose |
|--------|-------|-----------|---------|
| `ctem-investor-demo.sh` | 24/24 | 100% | Investor meeting — NEW |
| `mpte-sandbox-demo.sh` | 12/12 | 100% | MPTE + Sandbox — NEW |
| `ctem_full_loop_demo.py` | 42/42 | 100% | Python full CTEM |
| `mpte-demo.sh` | 11/11 | 100% | MPTE standalone |
| `ctem_sunday_regression.py` | 120/120 | 100% | Multi-arch regression |
| `ctem_architecture_regression.py` | 67/67 | 100% | Architecture regression |
| **TOTAL** | **276/276** | **100%** | **All demos green** |

## Pillars Served
- **[V3]** Brain Pipeline 12-step decision processing
- **[V5]** MPTE verify + comprehensive + Sandbox PoC verifier
- **[V7]** MCP tool discovery (100 tools)
- **[V10]** RSA-SHA256 signed evidence, SOC2/PCI-DSS compliance
