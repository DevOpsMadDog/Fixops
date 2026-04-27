# ALDECI SCIF Pilot — Statement of Work (Template)

**Document version:** 2026-04-26 (v1)
**Effective date:** _________________ ("Effective Date")
**Pilot duration:** 30 days from Effective Date (extendable by mutual written agreement to 90 days)
**Authority cite:** Customer's existing ATO inheritance pattern; this pilot does NOT require fresh FedRAMP High authorization
**Companion docs (incorporated by reference):**
`docs/scif/SCIF_PILOT_BUNDLE_README.md`, `docs/scif/SSP_aldeci_2026-04-26.md`, `docs/scif/POAM_aldeci_2026-04-26.md`, `docs/scif/nist_800-53_control_matrix_2026-04-26.csv`, `docs/scif/threat_model_aldeci_2026-04-26.md`, `docs/scif/crypto_module_datasheet_2026-04-26.md`, `docs/scif/auditor_quick_reference_2026-04-26.md`, `docs/sales/scif/reference_arch_scif_2026-04-26.md`

---

## 1. Parties

| Role | Entity | Designated POC | Title |
|---|---|---|---|
| **Provider** | DevOpsAI (ALDECI) | _________________ | _________________ |
| **Customer** | _________________ | _________________ | AO / ISSM |
| **Customer Tech Lead** | _________________ | _________________ | ISSO |

---

## 2. Pilot Scope

Provider shall deliver, install, and support the **ALDECI SCIF Pilot Bundle** (artefact pattern: `dist/aldeci-scif-<git_sha>-<utc_date>.tar.gz`) in Customer's designated air-gapped environment for a 30-day evaluation pilot.

**In scope:**

1. One (1) signed, reproducible bundle delivered via Customer's approved data-transfer mechanism (sneakernet, cross-domain solution, encrypted removable media — Customer's choice)
2. Air-gap installation on one (1) Customer-designated SCIF host meeting prerequisites in `SCIF_PILOT_BUNDLE_README.md` § 2.1
3. SoftHSM-backed pilot deployment (Customer may swap to production HSM — Thales Luna, AWS CloudHSM, or YubiHSM2 — at any time during pilot; swap is configuration-only, no code change)
4. End-to-end demonstration of one (1) Customer-designated security workflow through the full Brain Pipeline (ingestion → DPO consensus → finding → remediation suggestion → tamper-evident audit-chain entry → Council learning loop)
5. ISSO walk-through of the 40-minute auditor-quick-reference checklist (`auditor_quick_reference_2026-04-26.md`)
6. Weekly POA&M update cadence (4 cycles over 30 days), each cycle ≤ 90 minutes
7. Bundle hand-off documentation: SHA-256 manifest, CycloneDX SBOM, GPG-signed manifest, cosign image signature

**Out of scope:**

1. FedRAMP High Authorization (separate 12–18 month track; see `docs/scif_readiness_2026-04-26.md`)
2. DoD IL5 / IL6 Provisional Authorization (separate Phase-5 track)
3. Multi-tenant SaaS deployment (pilot is single-tenant by design)
4. Production HSM hardware procurement (Customer may use SoftHSM for pilot; production HSM is Customer's procurement)
5. Customer's existing SOC, EDR, IdP, or NGFW integration beyond pre-built connectors
6. Pen-test, 3PAO assessment, or independent security validation (these are post-pilot Phase-4 activities)

---

## 3. Deliverables

| # | Deliverable | Format | Due |
|---:|---|---|---|
| D1 | SCIF Pilot Bundle artefact + GPG-signed manifest + SBOM | Signed `.tar.gz` via Customer's approved transfer mechanism | T+5 working days from Effective Date |
| D2 | Successful air-gap install on Customer SCIF host (smoke tests pass per § 2.3 of bundle README) | Verified by Customer ISSO | T+7 working days |
| D3 | One real workflow demonstrated end-to-end | Live walk-through, recorded if Customer permits | T+14 working days |
| D4 | Auditor quick-reference walk-through complete | ISSO-signed checklist | T+18 working days |
| D5 | Weekly POA&M update reports (×4) | Markdown delivered to Customer ISSO | Weekly during pilot |
| D6 | Pilot final report: ConMon evidence baseline + open POA&M + extension recommendation | Markdown + supporting evidence bundle | T+30 working days |

---

## 4. Success Criteria (binary; pilot succeeds iff all are true)

1. **No outbound network traffic** observed from ALDECI container during pilot (verified via Customer host-firewall logs + container egress monitor)
2. **`/api/v1/scif/audit-chain/verify` returns `ok=true`** at every weekly check
3. **`/api/v1/scif/boot` returns `fips_mode_active=true`, `hsm_backend="pkcs11:..."`, `audit_chain_attached=true`** at install time and at every weekly verification
4. **Auditor quick-reference checklist** completed by Customer ISSO with ≥85% controls demonstrated (some POA&M items intentionally open per § 6)
5. **At least one (1) real Customer workflow** processed end-to-end through the Brain Pipeline with auditable DPO consensus trail
6. **Weekly POA&M cycles** completed on schedule (4 of 4)

---

## 5. Cost (Customer Selects ONE Option)

> ☐ **Option A — Design-Partner ($0)**
> Provider delivers the pilot at no cost in exchange for:
> (a) reference rights — Customer agrees that Provider may, with Customer's prior written approval per use, name Customer as a design-partner pilot in marketing materials (logo + 1-sentence quote, no operational detail);
> (b) outcome data — Customer agrees to share aggregate pilot outcomes (success-criteria pass/fail, MTTR baseline, qualitative feedback) which Provider may publish in anonymized form;
> (c) product feedback — Customer designates one (1) ISSO to participate in monthly product feedback sessions (60 min/month) for 6 months post-pilot.

> ☐ **Option B — All-Inclusive Fixed-Fee ($25,000 USD)**
> Provider delivers the pilot for a fixed fee of $25,000 inclusive of all bundle delivery, install, support, and weekly POA&M cycles. No reference or outcome-data obligations on Customer. Invoice issued at Effective Date, NET-30 terms.

In either Option, Customer bears its own internal personnel costs (ISSO time, AO review time, any host hardware procurement).

---

## 6. IP, Data, and Confidentiality Terms

1. **No data exfiltration.** Provider warrants that the SCIF Pilot Bundle ships with `FIXOPS_DISABLE_TELEMETRY=1` as the enforced default and contains no out-bound telemetry, beacon, or phone-home logic. Provider has no visibility into Customer's environment during or after the pilot.

2. **Customer owns all DPO learning data.** All decision-pattern-optimization (DPO) corrections, council-vote records, finding annotations, and Brain Pipeline outputs generated during the pilot are the exclusive property of Customer. Provider receives no copy, derivative, or aggregate of this data.

3. **Anonymized product telemetry — opt-in only.** Provider may, with Customer's explicit written opt-in (default: NO), receive anonymized aggregate metrics (counts, latencies, control-pass-rates) for product improvement purposes. No finding content, no entity identifiers, no Customer-specific data.

4. **Provider IP retention.** ALDECI source code, bundle artefacts, container images, container signatures, build provenance, models, and documentation remain the exclusive property of Provider. Customer receives a non-exclusive, non-transferable license to operate the bundle for the duration of the pilot.

5. **Customer-generated configuration.** Any Customer-specific configuration files, policy templates, or integration scripts created during the pilot remain Customer property. Provider may not reuse Customer-specific configuration without explicit written consent.

6. **Confidentiality.** Both parties shall treat as Confidential any non-public information disclosed during the pilot, with standard 3-year survival post-pilot. Standard mutual-NDA terms apply (incorporated by reference; if Customer requires its own NDA template, Provider will execute prior to D1 delivery).

7. **Export control.** Provider warrants the bundle does NOT contain ITAR-controlled technical data. The PQC inventory module ships under EAR99 classification (commercial cryptography). Customer is responsible for any classification-level handling of operational data within its SCIF.

8. **Termination.** Either party may terminate the pilot for any reason with 5 working days written notice. On termination, Customer ceases use, Provider has no exfiltration capability, and parties return or destroy any received Confidential information per standard practice. No refund of Option B fees if terminated by Customer; pro-rated refund if terminated by Provider for non-Customer-caused reason.

---

## 7. Signature Window & Schedule

| Milestone | Date |
|---|---|
| **SOW issued to Customer** | _________________ |
| **Customer signature deadline** | _________________ (Issued + 7 working days) |
| **Effective Date** (later of: both signatures OR Customer's contracting-officer counter-sign) | _________________ |
| **D1 — Bundle delivered** | Effective + 5 working days |
| **D2 — Install verified** | Effective + 7 working days |
| **D3 — Workflow demonstrated** | Effective + 14 working days |
| **D4 — Auditor walk-through complete** | Effective + 18 working days |
| **Pilot end** | Effective + 30 working days |
| **D6 — Final report delivered** | Effective + 33 working days |

If Customer signature is not received by the deadline, Provider reserves the right to re-issue the SOW with an updated bundle artefact (new git SHA, updated POA&M).

---

## 8. Liability & Warranty

Standard mutual limitation of liability — direct damages capped at amounts paid under this SOW (Option A: $0 cap, Option B: $25,000 cap), no consequential or indirect damages, mutual hold-harmless for third-party IP claims. Provider warrants the bundle is delivered free of known critical CVEs as of bundle build date (per CycloneDX SBOM). Provider does NOT warrant the bundle achieves any specific compliance certification (FedRAMP, DoD IL5, etc.) — pilot is explicitly under Customer's existing ATO inheritance.

---

## 9. Approval Block

```
PROVIDER (DevOpsAI / ALDECI)              CUSTOMER (___________________)

By: ________________________              By: ________________________
Name: ______________________              Name: ______________________
Title: _____________________              Title: _____________________
Date: ______________________              Date: ______________________

                                          CONTRACTING OFFICER (if separate)

                                          By: ________________________
                                          Name: ______________________
                                          Title: _____________________
                                          Date: ______________________
```

---

## 10. Notes to Customer Contracting Officer

1. **No security clearance required for Provider.** Bundle is delivered, installed, and operated by Customer-cleared personnel. Provider has no access to Customer's environment.
2. **No Privacy Act / PII implications** — the platform processes security-tooling output (vulnerability findings, SBOMs, scanner reports), not personal data.
3. **No Section 508 / accessibility waiver needed** — UI is web-standard and will be evaluated post-pilot if Customer chooses to extend.
4. **No FAR Part 39 acquisition planning required** — this is a pilot under existing ATO inheritance, not a production IT acquisition.
5. **DUNS / SAM / CAGE codes** for Provider available on request.
6. **For OTA-friendly customers (DIU, AFWERX, SOFWERX, NavalX):** Provider can convert this SOW into a CSO/OTA proposal format on request — typically adds 3 working days and no scope change.

*End SOW template.*
