# Threat Model — ALDECI CTEM+ Platform (SCIF Pilot Build)

**Document ID:** TM-ALDECI-2026-04-26
**Version:** 0.1 (Pilot Draft)
**Date:** 2026-04-26
**Branch under assessment:** `features/intermediate-stage`
**Build under assessment:** `aldeci:scif-hardened` (Stage 1 commits `1159ef49`, `69efa330`)
**Methodology:** STRIDE per component + DREAD scoring on top threats
**Companion:** `SSP_aldeci_2026-04-26.md`, `POAM_aldeci_2026-04-26.md`
**Author:** ALDECI Technical Writer (delegated)

---

## 1. Scope and Methodology

This threat model covers the ALDECI **SCIF pilot deployment** — a single hardened container running on a customer-controlled, FIPS-enabled, air-gapped host. It uses:

- **STRIDE** (Spoofing / Tampering / Repudiation / Information Disclosure / Denial of Service / Elevation of Privilege) per major component
- **DREAD** (Damage / Reproducibility / Exploitability / Affected users / Discoverability — each scored 1-10) for the top 10 threats

Out of scope: external SaaS multi-tenant deployment (different threat surface — covered separately).

---

## 2. System Components in Scope

| ID | Component | Purpose | Source |
|---|---|---|---|
| C1 | **FastAPI Gateway** | Entry point; AuthN/AuthZ; routes to engines | `suite-api/apps/api/app.py` + 580 routers |
| C2 | **TrustGraph Event Bus** | Knowledge graph + event distribution to subscribers | `suite-core/trustgraph/` |
| C3 | **Brain Pipeline** | 12-step decision pipeline (ingest → analyze → decide → remediate) | `core/brain_pipeline.py` |
| C4 | **LLM Council** | Multi-AI consensus engine (Karpathy pattern) — local vLLM/Ollama in SCIF | `core/llm_council.py`, `core/llm_providers.py` |
| C5 | **IDE Backend** | IDE-gateway endpoints for developer workflows | `suite-api/.../developer_portal_router.py` |
| C6 | **MCP Gateway** | Model Context Protocol endpoint for tool orchestration | `suite-integrations/` |
| C7 | **ASPM/CSPM/CTEM Ingestion** | Scanner output normalization + threat-feed ingest | `core/scanner_parsers.py`, `suite-feeds/` |
| C8 | **Audit Chain + HSM** | Tamper-evident chain + PKCS#11 root-of-trust | `core/audit_chain.py`, `core/hsm_provider.py` |
| C9 | **RBAC + MFA** | AuthN/AuthZ enforcement | `core/rbac_engine.py`, `core/mfa_management_engine.py` |
| C10 | **Air-Gap Boundary** | Outbound denial + active probe | `core/airgap_deployment.py` |

---

## 3. Trust Boundaries

```
Internet (UNTRUSTED)  ←  [Customer SCIF Boundary, ICD-705 enforced]  →  SCIF host
                                                                       ↓
                                                             [Host firewall, FIPS kernel]
                                                                       ↓
                                                       [Container boundary: read-only, no-new-priv]
                                                                       ↓
                                                  C1 ── C9 (AuthZ trust boundary) ── C2-C7
                                                                       ↓
                                                  C8 (audit, HSM trust boundary)
```

Trust transitions:
- **TB-1**: SCIF perimeter — physical/ICD-705 (customer)
- **TB-2**: Host kernel ← container — namespace/cgroup isolation
- **TB-3**: Unauthenticated → Authenticated — `core.mfa_management_engine` + `core.rbac_engine`
- **TB-4**: Authenticated → Privileged — FIDO2 hardware-key step-up
- **TB-5**: Application → HSM — PKCS#11 PIN + token

---

## 4. STRIDE Per Component

### 4.1 C1 — FastAPI Gateway

| Threat | Type | Mitigation | Residual risk |
|---|---|---|---|
| Forged JWT | S | `core.mfa_management_engine` enforces issuer + audience; FIDO2 for privileged | LOW |
| Request body tampering | T | Pydantic v2 strict validation on every endpoint; `core.write_audit_middleware` chains every write | LOW |
| Action denial after the fact | R | `core.audit_chain.AuditChain` SHA-256 prev-hash chain; HSM-signed checkpoints every 100 rows | VERY LOW |
| Endpoint enumeration discloses internal structure | I | OpenAPI hidden behind auth in SCIF mode (`FIXOPS_HIDE_DOCS=1`); error responses sanitized via `core.error_responses` | LOW |
| Resource exhaustion via unbounded payload | D | `core.tenant_rate_limiter`; FastAPI body-size limit | LOW |
| Path-traversal to escape route handler | E | FastAPI/Starlette path-param validation; container `--read-only` rootfs | VERY LOW |

### 4.2 C2 — TrustGraph Event Bus

| Threat | Type | Mitigation | Residual risk |
|---|---|---|---|
| Subscriber spoofing | S | Subscribers identified by SCIM-provisioned service account + RBAC scope | LOW |
| Event payload tampering in transit | T | Internal-only IPC; in-process Python calls or local Unix socket | LOW |
| Event publish without attribution | R | Every publish goes through `core.write_audit_middleware` | LOW |
| Cross-tenant event leak | I | `core.tenant_isolation_auditor`; subscribers RBAC-checked at delivery | MED — known gap, see SSP §4.1 PARTIAL note |
| Event-storm DoS on subscribers | D | Per-subscriber back-pressure queue | LOW |
| Subscriber escalates via crafted event | E | Event schema strict; `core.error_handling_auditor` quarantines deserialization failures | LOW |

### 4.3 C3 — Brain Pipeline

| Threat | Type | Mitigation | Residual risk |
|---|---|---|---|
| Spoofed scanner output | S | All ingest signed by tenant API key; `core.scanner_parsers` validates schema before normalization | LOW |
| Malicious scanner XML/JSON triggers parser RCE | T | `defusedxml` for XML; `pydantic` strict for JSON; `core.error_handling_auditor` quarantines | LOW |
| Pipeline decision repudiated | R | Each step writes to audit chain with HSM checkpoint | VERY LOW |
| Pipeline exposes raw secrets in audit trail | I | `core.scanner_parsers` redacts secrets via `core.secrets_redactor` (when wired); manual review | MED |
| Pipeline backlog DoS | D | Bounded queue + `core.tenant_rate_limiter` | LOW |
| Pipeline plugin loaded with elevated permissions | E | Plugins run in-process with same UID 1001; no out-of-band escalation path | LOW |

### 4.4 C4 — LLM Council (vLLM/Ollama in SCIF)

| Threat | Type | Mitigation | Residual risk |
|---|---|---|---|
| Adversary swaps model weights | S | Model bundle SHA-256 + GPG signature verified at load (POA-009 hardens) | MED |
| Prompt-injection causes false consensus | T | Multi-model consensus dampens single-model attack; `core.llm_monitor` flags anomalies | MED |
| LLM action without attribution | R | All LLM calls audit-chained with prompt-hash + response-hash | LOW |
| Sensitive data exfiltrated via prompt | I | All inference local (vLLM/Ollama); air-gap engine blocks any outbound; prompt redaction available | LOW |
| Model server resource exhaustion | D | vLLM `--max-model-len` + memory-limit cgroup | LOW |
| Adversary trains on SCIF data | E | No telemetry; no outbound; weights are read-only | VERY LOW |

### 4.5 C5 — IDE Backend

| Threat | Type | Mitigation | Residual risk |
|---|---|---|---|
| IDE plugin token replay | S | Tokens scoped + short TTL; FIDO2 step-up for write actions | LOW |
| IDE-submitted source modified server-side without dev knowledge | T | Diff returned to IDE for explicit accept; audit-chained | LOW |
| Dev denies sending a fix request | R | Audit chain + per-dev attribution | LOW |
| IDE backend leaks other devs' code | I | RBAC-scoped per developer; tenant isolation | MED — needs classification labels (POA-004) |
| Massive IDE submission DoS | D | Rate limited per dev | LOW |
| Dev tooling escalates to admin | E | Dev-role tokens cannot reach admin endpoints; FIDO2 required for elevation | LOW |

### 4.6 C6 — MCP Gateway

| Threat | Type | Mitigation | Residual risk |
|---|---|---|---|
| Spoofed MCP client | S | Mutual TLS + RBAC | LOW |
| Tool arguments tampered | T | Pydantic schema | LOW |
| Tool action denied | R | Audit chained | LOW |
| Tool registry leaks tool list | I | RBAC-scoped tool discovery | LOW |
| Tool-call storm | D | Rate limiter | LOW |
| Tool registers itself with elevated capabilities | E | Tool registry write requires admin + FIDO2 | LOW |

### 4.7 C7 — ASPM/CSPM/CTEM Ingestion

| Threat | Type | Mitigation | Residual risk |
|---|---|---|---|
| Forged scanner identity | S | API key + tenant scope | LOW |
| Forged finding (false positive flood / false negative) | T | `core.scanner_parsers` schema validation; cross-correlation in Brain Pipeline; `core.anomaly_detector` flags volume spikes | MED |
| Scanner denies submitting | R | Audit chain | LOW |
| Findings disclose third-party secret | I | `core.secrets_redactor` (when wired); operator review during pilot | MED |
| Massive scanner ingest DoS | D | Per-tenant rate limit | LOW |
| Crafted parser input causes RCE | E | `defusedxml`; quarantine of deserialization failures; container read-only fs | LOW |

### 4.8 C8 — Audit Chain + HSM

| Threat | Type | Mitigation | Residual risk |
|---|---|---|---|
| Audit row insertion impersonating other actor | S | Each row stamps subject from authenticated context; cannot be set by caller | VERY LOW |
| Audit row mutation | T | SHA-256 prev-hash chain; `verify_full()` detects tampering at exact mutated row | VERY LOW |
| Operator deletes log file | R | HSM-signed checkpoint every 100 rows; deletion detectable across off-system backup | LOW |
| Audit log read by unauthorized user | I | Audit endpoints RBAC-scoped to Auditor role | LOW |
| Audit DB grows unbounded | D | POA-006 5-year prune; current 80% disk alert | LOW |
| HSM PIN extracted from env | E | PIN read once at boot; HSM `LOGIN_REQUIRED + USER_PIN_INITIALIZED`; pilot uses container env, prod uses Kubernetes Secret w/ KMS | MED |

### 4.9 C9 — RBAC + MFA

| Threat | Type | Mitigation | Residual risk |
|---|---|---|---|
| Phished password | S | FIDO2 mandatory for privileged accounts | LOW |
| Role membership tampered | T | Role mutation audit-chained | LOW |
| Admin claims they didn't add a role | R | Audit chain | VERY LOW |
| RBAC matrix leaked | I | Admin-scoped read | LOW |
| Massive auth attempts | D | `core.access_anomaly_engine` lockout | LOW |
| Privilege escalation via missing scope check | E | `core.rbac_engine.check_tenant_access()` is the central check; `core.tenant_isolation_auditor` re-validates | LOW |

### 4.10 C10 — Air-Gap Boundary

| Threat | Type | Mitigation | Residual risk |
|---|---|---|---|
| Outbound DNS exfiltration | S/I | Host firewall whitelist; no DNS allowed outbound; `core.airgap_deployment` actively probes 8 known endpoints | LOW |
| Telemetry SDK re-introduced via dependency update | T | `core.fips_boot` rejects non-FIPS imports; `FIXOPS_DISABLE_TELEMETRY=1` enforced; SBOM diff per release | LOW |
| Operator silently disables air-gap | R | Boot-time air-gap verification audit-chained; `/api/v1/scif/boot` returns posture | LOW |
| Crafted vulnerability data exfiltrates target list | I | All feeds offline; offline import requires GPG-signed bundle | LOW |
| Air-gap probe DoSes external endpoints | D | Probes only at boot + on-demand `/api/v1/airgap/verify` | VERY LOW |
| Operator escapes air-gap via debug shell | E | No shell on runtime user (`/sbin/nologin`); no `dnf`/`apt` in image | LOW |

---

## 5. Top 10 Threats — DREAD Scoring

DREAD scale 1-10 each; total /50; Risk = Total*2 (0-100).

| # | Threat | D | R | E | A | Disc | Total | Risk | Mitigation |
|--:|---|--:|--:|--:|--:|--:|--:|--:|---|
| 1 | Audit-chain mutation by privileged insider | 9 | 4 | 4 | 8 | 3 | 28 | 56 | HSM-signed checkpoints; off-system backup (POA-003); `verify_full()` |
| 2 | HSM PIN extraction from container env | 8 | 6 | 5 | 9 | 5 | 33 | 66 | Production: KMS-backed Secret; pilot: file-mode 0400 + restricted access |
| 3 | LLM model-weight swap (supply chain) | 8 | 3 | 5 | 7 | 4 | 27 | 54 | Model SHA-256 + GPG verified at load (POA hardens) |
| 4 | Cross-tenant event leak via TrustGraph subscriber | 7 | 5 | 4 | 7 | 4 | 27 | 54 | `tenant_isolation_auditor`; classification labels (POA-004) |
| 5 | Forged scanner finding floods Brain Pipeline | 6 | 7 | 5 | 6 | 6 | 30 | 60 | Per-tenant rate limit; cross-correlation; anomaly detection |
| 6 | Telemetry SDK re-introduced via dep update | 7 | 5 | 4 | 8 | 5 | 29 | 58 | FIPS boot rejects non-FIPS imports; SBOM diff per release |
| 7 | Privilege escalation via missing scope check on a new endpoint | 8 | 4 | 4 | 8 | 4 | 28 | 56 | `tenant_isolation_auditor` re-validates; CI test for scope coverage |
| 8 | Prompt injection causes LLM Council to converge on attacker output | 6 | 6 | 5 | 5 | 5 | 27 | 54 | Multi-model consensus; `core.llm_monitor` anomaly detect |
| 9 | Forged JWT via clock-skew or weak nonce | 8 | 3 | 3 | 9 | 3 | 26 | 52 | FIPS-grade RNG; HSM signing; FIDO2 for privileged |
| 10 | XML-bomb via SAST scanner output triggers parser DoS | 6 | 7 | 5 | 5 | 7 | 30 | 60 | `defusedxml`; quarantine on deserialization failure; rate limit |

---

## 6. Top Mitigation Roadmap

| Priority | Mitigation | Closes threats | Status |
|---|---|---|---|
| 1 | Classification-level labels on user/asset (POA-004) | #4, #7 | OPEN — Phase 2 |
| 2 | Audit-log off-system backup runbook (POA-003) | #1 | OPEN — T+5 days |
| 3 | HSM hardware certification (POA-008) | #2 | OPEN — 2026-09-30 |
| 4 | Model bundle GPG verification at load | #3 | PARTIAL — bundle has GPG; load-time check is hardening item |
| 5 | Cosign image signing in CI (POA-002) | #6 | OPEN — T+2 days |
| 6 | ConMon evidence pipeline (POA-007) | #1, #4, #6, #7 | OPEN — 2026-07-31 |

---

## 7. Assumptions and Dependencies

- The customer SCIF physical perimeter is intact (ICD-705).
- The host kernel is FIPS-validated (`fips=1`) and OS patches are current.
- The customer IdP correctly emits clearance attributes via SCIM (when AC-3(7) enforcement lands).
- The customer's existing SOC ingests ALDECI's syslog stream (POA-005 closes the spec).
- Personnel cleared per the customer's PS-3/PS-4 program — ALDECI does not adjudicate clearance.

---

## 8. Out of Scope

- Side-channel attacks on the host CPU (Spectre/Meltdown class) — host responsibility.
- Acoustic / EM emanations from the SCIF — ICD-705 (customer).
- Insider with physical HSM access — assumed mitigated by SCIF physical access controls.
- Quantum cryptanalysis pre-2030 — PQC roadmap covers; current FIPS algorithms remain RSA-3072 / ECDSA P-384.

---

## 9. References

- Microsoft STRIDE
- Howard & LeBlanc — Writing Secure Code (DREAD)
- NIST SP 800-30 Rev 1 — Risk Assessment
- NIST SP 800-154 — Data-Centric System Threat Modeling
- Companion: `docs/scif/SSP_aldeci_2026-04-26.md`, `POAM_aldeci_2026-04-26.md`, `crypto_module_datasheet_2026-04-26.md`

*End threat model.*
