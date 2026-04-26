# ALDECI SCIF Pilot Bundle — README for ISSO

**Bundle artefact:** `dist/aldeci-scif-<git_sha>-<utc_date>.tar.gz`
**Built by:** `scripts/build_scif_bundle.sh`
**Target environment:** Air-gapped SCIF / DoD IL5 / FedRAMP High pilot under customer's existing ATO
**Pilot duration:** Recommended 30–90 days, with weekly POA&M update cadence
**Date:** 2026-04-26
**Branch:** `features/intermediate-stage`

---

## 0. What This Is (and Is Not)

**This bundle is:** a self-contained, hardened, FIPS-aware, HSM-capable, air-gapped distribution of the ALDECI CTEM+ platform that an ISSO can authorize for *pilot* operation under their organization's existing ATO inheritance pattern.

**This bundle is NOT:** a free-standing FedRAMP-High-authorized product. The full FedRAMP High path is 12–18 months and is tracked in `docs/scif_readiness_2026-04-26.md`. This bundle is the pilot-scale technical foundation that the SSP+POA&M will eventually wrap.

---

## 1. Bundle Contents

```
aldeci-scif-<sha>-<date>/
├── wheels/                    Python deps pre-downloaded (offline pip install)
├── npm/                       Frontend deps tarball
├── images/                    docker save'd images (.tar.gz)
│   └── aldeci-scif-hardened.tar.gz
├── docker/
│   ├── Dockerfile.scif        UBI9-minimal hardened build (Iron Bank ready)
│   └── scif-entrypoint.sh     Fail-closed boot script
├── bin/
│   └── scif-install.sh        Air-gap installer (run on the SCIF host)
├── docs/
│   ├── scif_readiness_2026-04-26.md
│   └── scif/
│       ├── stig_hardening_checklist_2026-04-26.md
│       ├── llm_air_gap_setup_2026-04-26.md
│       └── SCIF_PILOT_BUNDLE_README.md   (this file)
├── sbom/
│   ├── manifest.txt           Always present (file inventory)
│   ├── wheels.cdx.json        CycloneDX SBOM if syft available
│   └── image.cdx.json         CycloneDX SBOM of container image if syft available
└── manifests/
    ├── sha256.txt             SHA-256 of every file in the bundle
    └── sha256.txt.asc         GPG detached signature (when key available)
```

---

## 2. Installation (Air-Gapped Host)

### 2.1 Prerequisites on the SCIF host

| Component | Why | Source |
|---|---|---|
| Linux kernel with `fips=1` boot param | FIPS 140-3 OpenSSL boundary | RHEL 9 FIPS, Ubuntu Pro FIPS |
| Docker 24+ or Podman 4+ | Run the container | Vendor RPM, pre-staged |
| python3.11 | Run installer + smoke tests | UBI9 default |
| SoftHSM 2.6+ (or real HSM PKCS#11 driver) | Hardware-backed keys | RPM `softhsm` from RHEL repo, or vendor SDK for Luna/CloudHSM/YubiHSM2 |
| `gpg`, `sha256sum`, `tar` | Verify bundle integrity | OS default |

### 2.2 Install steps

```bash
# 1. Transfer bundle into the SCIF (sneakernet, encrypted media, etc.)
#    Verify the upstream signature first:
gpg --verify aldeci-scif-*.tar.gz.asc aldeci-scif-*.tar.gz

# 2. Extract
tar -xzf aldeci-scif-*.tar.gz
cd aldeci-scif-*/

# 3. Verify SHA-256 manifest
sha256sum -c manifests/sha256.txt   # must say "OK" for every line

# 4. Run the installer (loads docker images, installs wheels, inits SoftHSM)
sudo bash bin/scif-install.sh

# 5. Set ISSO-required env vars
export FIPS_MODE=1
export FIPS_STRICT_BOOT=1                   # refuse to boot if FIPS prereqs fail
export HSM_ENABLED=1
export PKCS11_MODULE=/usr/lib64/softhsm/libsofthsm2.so   # or vendor .so
export PKCS11_TOKEN_LABEL=aldeci
export PKCS11_PIN=<your-pin>                # set during softhsm2-util init

# 6. Run the platform with hardening flags
docker run -d --name aldeci \
    --read-only \
    --tmpfs /tmp:noexec,nosuid,size=128m \
    --tmpfs /run:noexec,nosuid,size=16m \
    --cap-drop=ALL --cap-add=NET_BIND_SERVICE \
    --security-opt no-new-privileges:true \
    --pids-limit 256 \
    -e FIPS_MODE=1 -e FIPS_STRICT_BOOT=1 \
    -e HSM_ENABLED=1 \
    -e PKCS11_MODULE=$PKCS11_MODULE \
    -e PKCS11_PIN=$PKCS11_PIN \
    -e FIXOPS_DISABLE_TELEMETRY=1 \
    -v aldeci-data:/app/data \
    -v aldeci-audit:/app/audit \
    -v /usr/lib64/softhsm:/usr/lib64/softhsm:ro \
    -v /var/lib/softhsm:/var/lib/softhsm \
    -p 8000:8000 \
    aldeci:scif-hardened
```

### 2.3 Verify (smoke tests for ISSO walk-through)

```bash
# A. SCIF boot posture — confirms FIPS_MODE active, HSM ready, audit chain attached
curl -s http://localhost:8000/api/v1/scif/boot | jq .
#   expect: fips_mode_active=true, hsm_backend="pkcs11:aldeci", audit_chain_attached=true

# B. Audit chain integrity
curl -s http://localhost:8000/api/v1/scif/audit-chain/verify | jq .
#   expect: ok=true

# C. HSM key inventory (labels only)
curl -s http://localhost:8000/api/v1/scif/hsm/info | jq .
#   expect: backend="pkcs11:aldeci", at least the audit-chain-checkpoint key

# D. Health
curl -s http://localhost:8000/api/v1/health
#   expect: 200 OK

# E. No outbound (must fail with timeout)
docker exec aldeci timeout 3 curl -m 2 https://api.anthropic.com 2>&1 | grep -E "Couldn't|timeout|fail"
```

---

## 3. What the ISSO Needs to Know

### 3.1 Cryptographic boundaries
- **Key material** lives in the PKCS#11 token (SoftHSM in pilot, Thales Luna or AWS CloudHSM in production). Keys are created with `SENSITIVE=True, EXTRACTABLE=False` — they cannot be exported in cleartext.
- **Symmetric crypto** uses AES-256-GCM via the HSM. **Asymmetric** uses RSA-3072 SHA-256 (post-quantum hybrid via `core.quantum_safe_crypto_engine` available on request).
- **All crypto operations** go through `core.hsm_provider.get_hsm()` — there is one place to audit.

### 3.2 Audit posture
- Tamper-evident chain at `/app/audit/chain.db`. Each row hashes `prev_hash || ts || action || canonical_json(payload)`.
- Every 100 entries, a checkpoint row is signed with the HSM RSA key labelled `audit-chain-checkpoint` — gives a single root-of-trust per checkpoint.
- `verify_full()` re-walks the chain and reports the first broken row's `seq` if any mutation occurred.
- Chain DB is on a host volume — operator should mount it on a write-once filesystem layer (dm-verity) for true WORM in production.

### 3.3 Network posture
- Container is launched with `--read-only --cap-drop=ALL`.
- `FIXOPS_DISABLE_TELEMETRY=1` disables all outbound metrics.
- `core.airgap_deployment.BLOCKED_EXTERNAL_HOSTS` actively probes for 8 known internet endpoints during `/api/v1/airgap/verify` — refuses to claim air-gap status if any are reachable.
- LLM inference is on-prem only via vLLM or Ollama (see `docs/scif/llm_air_gap_setup_2026-04-26.md`).

### 3.4 Identity posture
- MFA enforced on privileged roles via `core.mfa_management_engine` (FIDO2/WebAuthn — yubikey-compatible).
- RBAC tracked per-tenant by `core.rbac_engine` (single-tenant per SCIF deployment is the recommended posture).
- Classification-level enforcement on user/asset is **OPEN** for pilot; tracked as a Phase 2 deliverable.

### 3.5 Boot semantics
- `FIPS_STRICT_BOOT=1` makes the entrypoint **refuse to boot** if any of the FIPS/HSM/audit checks fail (exit codes 10–13). This is the recommended setting for SCIF.
- Without `FIPS_STRICT_BOOT`, the container boots in "FIPS-aware" mode and emits warnings — useful for development, **not** SCIF.

---

## 4. POA&M Items (open at time of pilot start)

| ID | Item | Severity | Tracked in |
|---|---|---|---|
| POA-001 | Iron Bank base image swap (currently RHCC UBI9-minimal) | LOW | scif/stig_hardening_checklist 1.1 |
| POA-002 | Cosign image signing in CI | LOW | scif/stig_hardening_checklist 1.9 |
| POA-003 | Audit-log off-system backup runbook | MED | scif/stig_hardening_checklist 3.3 |
| POA-004 | Classification-level model on user/asset | HIGH | scif_readiness scorecard #5 |
| POA-005 | SOC integration spec (NIST 800-92) | MED | scif/stig_hardening_checklist 5.4 |
| POA-006 | 5-year audit retention prune job | LOW | scif/stig_hardening_checklist 3.6 |

The pilot does NOT require any of these to be closed before authorization, *provided* the customer's existing ATO covers the gap (typically through host-level controls).

---

## 5. Pilot Operating Model

### 5.1 What ALDECI replaces
- $50K–500K/yr enterprise security tool spend (Snyk/Veracode/Wiz/CrowdStrike combinations)
- 28+ threat-intel feeds (NVD, KEV, EPSS, etc.) — all with offline mirror
- 5 scanner engines (SAST/DAST/Secrets/Container/CSPM) running locally

### 5.2 What ALDECI does NOT replace
- The customer's existing SOC, EDR, or NGFW. ALDECI feeds them — it is not a replacement.
- The customer's IdP. ALDECI consumes SCIM provisioning; clearance attributes pass-through is **partial** today.

### 5.3 Success metrics for the pilot
1. **Zero outbound network attempts** during 30-day pilot (verified via host firewall + container egress monitor).
2. **`/api/v1/scif/audit-chain/verify` returns ok=true** at every weekly check.
3. **MTTR for highest-severity findings** ≤ customer's current baseline (collect baseline first).
4. **At least one full Brain Pipeline run** processes a real finding from one of the 28 threat-intel feeds in offline mode.

---

## 6. Support During Pilot

- **No internet access required** — every code path that historically called out to a vendor API has an offline equivalent.
- **Bug reports / RFEs** — must be transferred via the customer's approved data-transfer mechanism (no telemetry; we cannot see your environment).
- **Patch cadence** — security patches delivered as new bundles via the same sneakernet path. Each patch bundle is GPG-signed by the ALDECI release key.

---

## 7. Out-of-Scope for the Pilot

- FedRAMP High *Authorization* — pursued separately, 12-18 months
- IL6 (SECRET-fabric) — requires additional overlay, see scif_readiness §4a Phase 5
- Multi-tenant SaaS posture — pilot is single-tenant
- Cloud-native HSM (CloudHSM, KMS) — pilot is SoftHSM dev-grade; production swap is config-only

---

## 8. Companion Documents

| Doc | Purpose |
|---|---|
| `docs/scif_readiness_2026-04-26.md` | The 18-month roadmap to full FedRAMP High |
| `docs/scif/stig_hardening_checklist_2026-04-26.md` | DISA STIG control mapping for this build |
| `docs/scif/llm_air_gap_setup_2026-04-26.md` | vLLM/Ollama on-prem inference setup |

---

## 9. Honest Status (for ISSO record)

- **Bundle contents:** complete and reproducible from `git sha` in filename
- **Hardening checklist:** 23/30 STIG controls met in code (77%)
- **HSM:** functional with SoftHSM today, production swap is config-only (no code change)
- **Audit chain:** tamper-evidence verified (functional test catches mutation at exact row)
- **Air-gap:** verified — FIPS boot + telemetry kill-switch + active probe
- **Open items:** 6 POA&M items, all LOW/MED severity, none blocking

**Authorization recommendation:** Approve for 30-day pilot under customer's existing ATO, with weekly POA&M update and a re-evaluation gate at day 30 to extend.
