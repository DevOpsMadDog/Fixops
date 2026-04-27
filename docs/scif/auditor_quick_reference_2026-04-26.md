# Auditor Quick-Reference — ALDECI SCIF Pilot Package

**Date:** 2026-04-26
**Branch:** `features/intermediate-stage`
**Build:** `aldeci:scif-hardened` (Stage 1 commits `1159ef49`, `69efa330`)
**Audience:** SCIF ISSO / 3PAO / AO assessing ALDECI for pilot authorization
**Goal:** Find every artifact you need in ≤ 5 minutes.

---

## 1. The 30-Second Summary

ALDECI is requesting authorization for a **single-tenant, single-classification, air-gapped** pilot deployment under your existing ATO inheritance pattern. The technical posture (FIPS-strict boot, HSM-backed keys, tamper-evident audit chain, active air-gap probe, SHA-256 + GPG bundle) is shipped and tested (12/12 SCIF Stage 1 tests pass). The paperwork (SSP, POA&M, NIST 800-53 control matrix, threat model, crypto datasheet) is the package below.

**Recommendation:** Approve 30-day pilot under existing ATO; weekly POA&M review; gate at day-30 to extend.

---

## 2. The Package (5-minute index)

### 2.1 Core compliance documents

| # | What you need | Where it lives |
|--:|---|---|
| 1 | **System Security Plan (SSP)** — control implementation by family, summary stats, boundary diagram | `docs/scif/SSP_aldeci_2026-04-26.md` |
| 2 | **Plan of Action & Milestones (POA&M)** — open weaknesses + compensating controls + scheduled completion | `docs/scif/POAM_aldeci_2026-04-26.md` |
| 3 | **NIST 800-53 Rev 5 control matrix** — one row per control we touch (140+ rows) | `docs/scif/nist_800-53_control_matrix_2026-04-26.csv` |
| 4 | **Threat Model** — STRIDE per component + DREAD top-10 | `docs/scif/threat_model_aldeci_2026-04-26.md` |
| 5 | **Cryptographic Module Datasheet** — FIPS 140-3 boundary, algorithms, KAT schedule | `docs/scif/crypto_module_datasheet_2026-04-26.md` |

### 2.2 Operations documents

| # | What you need | Where it lives |
|--:|---|---|
| 6 | **SCIF Pilot Bundle README for ISSO** — install, verify, operate | `docs/scif/SCIF_PILOT_BUNDLE_README.md` |
| 7 | **STIG Hardening Checklist** — DISA STIG control mapping (23/30 met) | `docs/scif/stig_hardening_checklist_2026-04-26.md` |
| 8 | **LLM Air-Gap Setup** — vLLM/Ollama on-prem inference | `docs/scif/llm_air_gap_setup_2026-04-26.md` |
| 9 | **SCIF Readiness Scorecard** — 18-month roadmap to full FedRAMP High | `docs/scif_readiness_2026-04-26.md` |

### 2.3 Live evidence (live-system endpoints)

These run against the deployed container at `http://localhost:8000` (or the customer's bound address):

| # | What you can verify | Endpoint |
|--:|---|---|
| 10 | **FIPS boot posture** (returns `fips_mode_active`, KAT results, HSM backend) | `GET /api/v1/scif/boot` |
| 11 | **Audit chain integrity** (`verify_full()` walks every row) | `GET /api/v1/scif/audit-chain/verify` |
| 12 | **HSM key inventory** (labels only, never key material) | `GET /api/v1/scif/hsm/info` |
| 13 | **Air-gap probe** (probes 8 known internet endpoints; refuses claim if any reachable) | `GET /api/v1/airgap/verify` |
| 14 | **FIPS KAT suite on demand** (re-runs all known-answer tests) | `POST /api/v1/scif/fips/kat` |
| 15 | **General health** | `GET /api/v1/health` |

### 2.4 Build & supply-chain artifacts (in the SCIF bundle tarball `dist/aldeci-scif-<sha>-<date>.tar.gz`)

| # | What you can verify | Where |
|--:|---|---|
| 16 | **Bundle SHA-256 manifest** — every file in the bundle | `manifests/sha256.txt` |
| 17 | **Bundle GPG detached signature** | `manifests/sha256.txt.asc` |
| 18 | **CycloneDX SBOM (Python wheels)** | `sbom/wheels.cdx.json` |
| 19 | **CycloneDX SBOM (container image)** | `sbom/image.cdx.json` |
| 20 | **Reproducible Dockerfile** | `docker/Dockerfile.scif` |
| 21 | **Air-gap install script** | `bin/scif-install.sh` |
| 22 | **Fail-closed entrypoint** | `docker/scif-entrypoint.sh` |

### 2.5 Test evidence

| # | What | Where |
|--:|---|---|
| 23 | **SCIF Stage 1 test suite** (12/12 pass) — exercises FIPS boot, HSM, audit chain, air-gap | `tests/test_scif_stage1.py` |
| 24 | **FIPS encryption test** | `tests/test_fips_encryption.py` |
| 25 | **Quantum-safe crypto test** | `tests/test_quantum_safe_crypto_engine.py` |
| 26 | **Air-gap deployment test** | `tests/test_airgap_deployment.py` |
| 27 | **Beast-Mode test totals** — 716+ tests passing on this branch | `tests/test_phase*.py` |

---

## 3. Five-Minute Walkthrough Script

If you have a fresh terminal pointed at a deployed pilot, this is the auditor walkthrough:

```bash
# 1) Bundle integrity (30 sec)
cd <pilot bundle dir>
gpg --verify manifests/sha256.txt.asc manifests/sha256.txt   # GPG OK
sha256sum -c manifests/sha256.txt | grep -v ': OK$' | head    # zero non-OK lines expected

# 2) Live FIPS posture (15 sec)
curl -s http://localhost:8000/api/v1/scif/boot | jq .
#   fips_mode_active: true
#   strict_boot: true
#   forbidden_imports: []
#   kats_passed: [...]
#   hsm_backend: "pkcs11:aldeci"
#   audit_chain_attached: true

# 3) Audit chain integrity (15 sec)
curl -s http://localhost:8000/api/v1/scif/audit-chain/verify | jq .
#   ok: true, first_break_seq: null

# 4) HSM key inventory (10 sec)
curl -s http://localhost:8000/api/v1/scif/hsm/info | jq .

# 5) Air-gap proof (60 sec — actively probes 8 endpoints, all must fail)
curl -s http://localhost:8000/api/v1/airgap/verify | jq .

# 6) Outbound denial proof (10 sec)
docker exec aldeci timeout 3 curl -m 2 https://api.anthropic.com 2>&1 | tail -1
# Expected: timeout or "Could not resolve host"

# 7) Documents (read in order, ~3 min)
less docs/scif/SSP_aldeci_2026-04-26.md             # 500 lines, sectioned
less docs/scif/POAM_aldeci_2026-04-26.md            # 91 lines
less docs/scif/threat_model_aldeci_2026-04-26.md    # STRIDE + DREAD
```

---

## 4. Quick Stats for the Authorization Memo

- **NIST 800-53 Rev 5 control coverage (in-scope):** 95% at-least-partial, 81% fully implemented
- **Total control rows mapped:** 140+ in CSV matrix; all 20 control families addressed in SSP
- **STIG technical controls met in code:** 23 of 30 (77%)
- **SCIF Stage 1 tests:** 12 of 12 pass
- **CRITICAL POA&M items:** 0
- **HIGH POA&M items:** 3 (all with documented compensating controls during pilot)
- **Cryptographic posture:** FIPS-strict boot + HSM-backed keys + AES-256-GCM + RSA-PSS-3072 + ML-KEM/ML-DSA/SLH-DSA inventory
- **Air-gap:** Active probe of 8 internet endpoints + telemetry kill-switch + read-only rootfs + cap-drop=ALL

---

## 5. POA&M Top-of-Mind for the ISSO

| ID | Severity | Item | Compensating control during pilot |
|---|---|---|---|
| POA-001 | HIGH | No 3PAO relationship | Pilot under customer ATO inheritance — no FedRAMP claim |
| POA-004 | HIGH | Classification labels not enforced | Single-classification single-tenant deployment |
| POA-008 | HIGH | HSM is SoftHSM (pilot) — production needs Luna/CloudHSM | Keys are SENSITIVE+EXTRACTABLE=False; production swap is config-only |
| POA-003 | MED | Off-system audit backup runbook | Customer weekly backup of `/app/audit/chain.db` to dm-verity volume |
| POA-005 | MED | SOC integration spec | stdout → journald → existing SIEM |
| POA-007 | MED | NIST 800-137 ConMon glue | Weekly `/api/v1/scif/audit-chain/verify` + ad-hoc reports |

Full POA&M with all 15 items in `docs/scif/POAM_aldeci_2026-04-26.md`.

---

## 6. What an ATO Decision Needs

1. ✅ **Bundle integrity** — SHA-256 + GPG verified
2. ✅ **FIPS posture** — `/api/v1/scif/boot` returns `fips_mode_active=true, strict_boot=true`
3. ✅ **Audit chain integrity** — `/api/v1/scif/audit-chain/verify` returns `ok=true`
4. ✅ **Air-gap proof** — `/api/v1/airgap/verify` shows zero outbound reachability
5. ✅ **SSP** — control implementation documented family-by-family
6. ✅ **POA&M** — every gap has owner, ETA, compensating control, severity
7. ✅ **Threat model** — top-10 DREAD-scored with mitigations
8. ✅ **Crypto datasheet** — FIPS boundary + KAT schedule + key lifecycle
9. ✅ **Test evidence** — `tests/test_scif_stage1.py` 12/12 pass
10. ⚠ **3PAO assessment** — open (POA-001, target 2026-12-31)

If items 1–9 satisfy your inheritance pattern and the pilot scope is constrained per the SCIF Pilot Bundle README, item 10 can remain OPEN through pilot.

---

## 7. Contact

- **Vendor system owner:** ALDECI Engineering (signed releases via approved channel only)
- **Bug reports / RFE:** transfer via customer's approved data-transfer mechanism (no telemetry from the platform)
- **Patch cadence:** new bundles via sneakernet, each GPG-signed

---

*End auditor quick-reference. All linked artifacts are present in this branch as of 2026-04-26.*
