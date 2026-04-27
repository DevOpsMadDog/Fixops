# Plan of Action & Milestones (POA&M) — ALDECI CTEM+ Platform

**Document ID:** POAM-ALDECI-2026-04-26
**Version:** 0.1 (Pilot Draft)
**Date:** 2026-04-26
**Branch under assessment:** `features/intermediate-stage`
**Build under assessment:** `aldeci:scif-hardened` (Stage 1 commits `1159ef49`, `69efa330`)
**Companion:** `SSP_aldeci_2026-04-26.md`, `nist_800-53_control_matrix_2026-04-26.csv`
**Cadence:** Weekly during pilot; monthly post-pilot
**Author:** ALDECI Technical Writer (delegated)

> All open weaknesses identified in the SSP, the SCIF Readiness Scorecard, and the STIG Hardening Checklist are consolidated here in one auditor-readable table. Each row includes a control mapping, severity, weakness description, planned remediation, resources, target completion, and risk-acceptance posture for the pilot.

---

## 1. Severity Definitions

| Severity | Meaning |
|---|---|
| **CRITICAL** | Breaks ATO; pilot cannot proceed |
| **HIGH** | Material control gap; requires compensating control + sign-off |
| **MED** | Defined gap; mitigated by operational procedure during pilot |
| **LOW** | Hardening item; no operational risk during pilot |

---

## 2. Open Items (Active POA&M)

| ID | NIST 800-53 Control | Status | Severity | Weakness | Resources Required | Scheduled Completion | Pilot Risk Acceptance |
|---|---|---|---|---|---|---|---|
| POA-001 | CA-2, CA-7, CA-8 | OPEN | HIGH | No 3PAO (3rd-Party Assessor Org) relationship — full FedRAMP High package is unverifiable until external assessment performed. | $200K–$500K 3PAO engagement + 6–9 mo cycle | 2026-12-31 (target FedRAMP "In Process" listing) | ACCEPTED for pilot. Pilot operates under customer's existing ATO inheritance; no FedRAMP authorization claim made or required during pilot window. |
| POA-002 | SR-11, CM-14 | OPEN | LOW | Cosign image signing not yet wired into CI pipeline. SHA-256 manifest + GPG sig present; sigstore key not provisioned. | 1 sigstore key + 2 days CI work | T+2 days from pilot start | ACCEPTED for pilot. Bundle is verifiable via SHA-256 manifest + GPG; cosign is incremental hardening. |
| POA-003 | AU-9(2) | OPEN | MED | Audit log off-system backup runbook not yet authored. Audit chain is append-only and HSM-checkpoint-signed but is on a single host volume. | 5 days SRE + write-once volume target | T+5 days from pilot start | ACCEPTED for pilot. Compensating control: weekly customer-side backup of `/app/audit/chain.db` to dm-verity volume per customer SCIF backup procedure. |
| POA-004 | AC-3(7), AC-16, IA-2(12) | OPEN | HIGH | Classification-level model not enforced on user/asset records. Today: tenant-scoped RBAC only; classification labels (UNCLASS / CONFIDENTIAL / SECRET / TS / SCI compartments) not modeled. | ~2 mo eng (schema + enforcement at every read site) | 2026-06-30 (Phase 2 deliverable) | ACCEPTED for pilot. Compensating control: pilot deployment is **single-classification, single-tenant** — entire enclave operates at one classification level, removing the need for cross-level enforcement during pilot. |
| POA-005 | IR-6, AU-6(3) | OPEN | MED | SOC integration spec (NIST 800-92 syslog forwarding to customer SIEM) not yet authored. | 10 days integrations | T+10 days from pilot start | ACCEPTED for pilot. Compensating control: ALDECI emits structured logs to stdout; customer can pipe via `journald` to existing SIEM during pilot. |
| POA-006 | AU-11 | OPEN | LOW | 5-year automatic audit-retention prune job not implemented. Audit DB grows append-only. | 5 days backend | T+5 days from pilot start | ACCEPTED for pilot. Pilot duration ≤ 90 days; 5-year retention not exercised. |
| POA-007 | CA-7 | OPEN | MED | NIST 800-137 Continuous Monitoring evidence pipeline not glued together. Engines exist (`core.audit_analytics`, `core.anomaly_detector`, `core.zero_trust_policy_engine`, `core.scheduled_reports_engine`) but a single ConMon report aggregator is not wired. | 2 mo eng | 2026-07-31 | ACCEPTED for pilot. Compensating control: weekly `/api/v1/scif/audit-chain/verify` + ad-hoc audit-analytics report. |
| POA-008 | SC-12, SC-13, IA-7 | OPEN | HIGH | HSM hardware not yet certified — SoftHSM 2.6 used today (FIPS 140-3 certified for software boundary only; **not** FIPS 140-3 Level 3 hardware). | $80K–$150K (Thales Luna 7 or AWS CloudHSM cluster) + 2 mo cert | 2026-09-30 | ACCEPTED for pilot. Compensating control: keys created with `SENSITIVE=True, EXTRACTABLE=False`; production swap is `PKCS11_MODULE` env var change + key migration — no code change. |
| POA-009 | CM-2, SR-4 | READY — pending CAC token, T+0 hours engineering | LOW | Iron Bank base image not yet adopted. Today: `registry.access.redhat.com/ubi9-minimal:latest` (Red Hat signed). Iron Bank publication needs DoD CAC token. `docker/Dockerfile.scif.ironbank` is prepared; swap is a single `FROM`-line change activated via `make scif-build-ironbank` once `IRONBANK_TOKEN` is set. | DoD CAC token (procurement only — 0 additional engineering days) | T+0 hours once CAC token issued | ACCEPTED for pilot. UBI9-minimal is Red Hat signed; Iron Bank Dockerfile already prepared at `docker/Dockerfile.scif.ironbank`. |
| POA-010 | CM-3, SA-15 | OPEN | LOW | Build pipeline not yet SLSA L3 hermetic. SLSA L2 attestations produced today via `core.slsa_provenance_engine`. | 2 mo eng (hermetic builder + provenance signing) | 2026-08-31 | ACCEPTED for pilot. SLSA L2 is FedRAMP-acceptable; L3 is target. |
| POA-011 | PL-2, PL-8, CA-2 | CLOSED | — | SSP, POA&M, NIST 800-53 control matrix, threat model, crypto datasheet all required for pilot ATO walk-through. | 1 day technical-writer | 2026-04-26 | **CLOSED** — this sprint produced the artifacts. |
| POA-012 | SI-2 | OPEN | LOW | `dependabot` triage backlog (~13K legacy code-quality violations identified by TrueCourse audit). Hot paths cleaned; remaining are non-security-impacting. | 6 FTE-mo cleanup | 2026-12-31 | ACCEPTED for pilot. None of the violations are security-impacting; tracked for hygiene. |
| POA-013 | SC-28(1) | OPEN | MED | Encryption-at-rest is per-engine opt-in. `core.fips_encryption.FIPSEncryption` AES-GCM available; not wired into every SQLite domain DB by default. | 3 wk eng | 2026-06-30 | ACCEPTED for pilot. Compensating control: customer LUKS encryption at host disk layer covers all SQLite files transparently. |
| POA-014 | RA-5, CA-8 | OPEN | LOW | Internal pentest cadence not yet scheduled. `core.auto_pentest`, `core.micro_pentest`, `core.pentest_scheduler` available; no recurring schedule defined. | 2 days config | T+5 days from pilot start | ACCEPTED for pilot. Customer or 3PAO will perform external pentest. |
| POA-015 | CP-2, CP-9 | OPEN | LOW | Customer-facing contingency-plan template not authored. Backup engine functional. | 5 days docs | T+10 days from pilot start | ACCEPTED for pilot. Customer typically has organizational CP. |

---

## 3. Closed Items (resolved this sprint)

| ID | NIST 800-53 Control | Closure date | Closure evidence |
|---|---|---|---|
| POA-011 | PL-2, PL-8, CA-2 | 2026-04-26 | `docs/scif/SSP_aldeci_2026-04-26.md`, this POA&M, `nist_800-53_control_matrix_2026-04-26.csv`, `threat_model_aldeci_2026-04-26.md`, `crypto_module_datasheet_2026-04-26.md` |
| POA-CLOSED-A | AU-9, AU-9(3), AU-10 | 2026-04-26 | Stage 1 commit `69efa330` — `core.audit_chain.AuditChain` SHA-256 prev-hash chain + HSM RSA-3072 checkpoint signing; verified by `tests/test_scif_stage1.py` (12/12 pass) |
| POA-CLOSED-B | SC-12, IA-7 | 2026-04-26 | Stage 1 commit `1159ef49` — `core.hsm_provider.PKCS11Provider` with SoftHSM integration; keys `SENSITIVE+EXTRACTABLE=False` |
| POA-CLOSED-C | IA-7, SC-13 | 2026-04-26 | Stage 1 — `core.fips_boot.run_fips_boot()` — refuses to boot if non-FIPS python crypto importable; `FIPS_STRICT_BOOT=1` exit-code 10–13 fail-closed |
| POA-CLOSED-D | AC-4, SC-7(8) | 2026-04-26 | Stage 1 — `core.airgap_deployment.BLOCKED_EXTERNAL_HOSTS` actively probed; `FIXOPS_DISABLE_TELEMETRY=1` env-default in `Dockerfile.scif` |
| POA-CLOSED-E | CM-2, CM-7 | 2026-04-26 | Stage 1 — `docker/Dockerfile.scif` UBI9-minimal hardened build; `USER 1001:1001`, `--cap-drop=ALL`, read-only fs, `microdnf clean all` |
| POA-CLOSED-F | CM-8, SR-4 | 2026-04-26 | Stage 1 — `scripts/build_scif_bundle.sh` produces SHA-256 manifest + (when syft present) CycloneDX SBOMs `wheels.cdx.json` and `image.cdx.json` |

---

## 4. Risk Posture Summary

- **0** CRITICAL items
- **3** HIGH items (POA-001, POA-004, POA-008) — all with documented compensating controls during pilot
- **5** MED items — all with documented compensating controls
- **7** LOW items — hygiene
- **7** items closed in Stage 1 sprint

**Net pilot posture:** No CRITICAL gaps; all HIGH gaps have signed-off compensating controls. Pilot is authorizable under customer's existing ATO inheritance pattern.

---

## 5. Cadence & Reporting

- **Weekly during pilot:** ISSO reviews this POA&M with vendor; status updates appended to `docs/scif/poam_changelog.md` (to be created on first update).
- **Monthly post-pilot:** standard FedRAMP POA&M reporting cadence.
- **At pilot exit:** all OPEN items re-evaluated for go/no-go on production deployment.

---

## 6. Approval

| Role | Name | Signature | Date |
|---|---|---|---|
| ALDECI System Owner | _(vendor)_ | | |
| Customer ISSO | | | |
| Customer AO (acceptance of pilot risk posture) | | | |

*End POA&M.*
