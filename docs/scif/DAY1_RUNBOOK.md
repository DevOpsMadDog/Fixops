# ALDECI SCIF Pilot — Day-1 Install Runbook

**Audience:** Customer ISSO (Information System Security Officer) running the install inside the SCIF perimeter
**Companion script:** `scripts/scif_pilot_day1_install.sh`
**Companion smoke test:** `tests/test_scif_day1_install.sh`
**Branch:** `features/intermediate-stage`
**Date:** 2026-04-26

---

## 0. What This Runbook Covers

This runbook walks the ISSO through the **fully-automated Day-1 install** of the ALDECI SCIF pilot bundle. Everything below maps 1:1 to a step inside `scripts/scif_pilot_day1_install.sh` so you can both (a) run the script unattended and (b) hand-verify each step if your accreditation policy requires manual sign-off per phase.

**TL;DR — fast path:**

```bash
# Inside the SCIF, after sneakernet of the bundle:
sudo bash scripts/scif_pilot_day1_install.sh
# Read the summary table at the end. Sign it. File it.
```

If anything fails, the script exits non-zero with a `[FIX]` line containing the exact remediation. **State is left inspectable** under `/var/lib/aldeci-scif/` so the ISSO can re-run idempotently.

---

## 1. Pre-Install Prerequisites (T-1 day)

| Item | Owner | Verify |
|---|---|---|
| Bundle tarball `aldeci-scif-<sha>-<utc>.tar.gz` transferred via approved data-transfer mechanism | Pilot lead | sha256sum matches release manifest |
| GPG signature `aldeci-scif-*.tar.gz.asc` and ALDECI release public key | ISSO | `gpg --verify` returns "Good signature" |
| Host kernel booted with `fips=1` (RHEL 9 FIPS or Ubuntu Pro FIPS) | Sysadmin | `cat /proc/sys/crypto/fips_enabled` = 1 |
| HSM PKCS#11 module installed (vendor SDK or `softhsm2`) | Sysadmin | `pkcs11-tool --list-slots` returns ≥ 1 slot |
| Air-gap confirmed (default route dropped or no NIC on WAN) | Network team | `curl -m 3 8.8.8.8` times out |
| Docker 24+ + `docker compose` plugin from vendor RPM (no internet pull) | Sysadmin | `docker compose version` succeeds |
| Pre-staged binaries: `tar`, `sha256sum`, `jq`, `curl`, `python3` | Sysadmin | each `command -v <bin>` succeeds |
| ATO inheritance package open + paragraph identifying ALDECI as a pilot subsystem | ISSO | document under change-control |

If any of the above is missing on Day-1 morning, the script will exit 10 with a clear `[FIX]` line — fix and re-run. **The script is idempotent** — re-running after a fix never double-creates state.

---

## 2. Day-1 Step-by-Step

### Step 1 — Pre-flight (script step 1/8, exit code 10 on fail)

The script verifies four things in this order:

1. **FIPS kernel** — reads `/proc/sys/crypto/fips_enabled`. Must be `1`. If 0, exit with `[FIX]`: enable FIPS-mode-setup or `pro enable fips`.
2. **HSM PKCS#11 token** — reads `/usr/lib64/softhsm/libsofthsm2.so` (or `$PKCS11_MODULE`). If missing, suggests installing vendor SDK or running with `--dev-mode`.
3. **Air-gap probe** — opens TCP to `8.8.8.8:53`, `1.1.1.1:53`, `registry-1.docker.io:443`. If *any* succeed, refuses to install.
4. **Required packages** — `docker`, `tar`, `sha256sum`, `jq`, `curl`, `python3`, plus `docker compose` plugin.

**Manual verify (if your policy requires double-check):**

```bash
cat /proc/sys/crypto/fips_enabled                          # 1
openssl version                                             # FIPS-validated build
pkcs11-tool --module $PKCS11_MODULE --list-slots            # ≥ 1 token
timeout 3 bash -c '</dev/tcp/8.8.8.8/53'; echo "rc=$?"       # rc != 0 = good
for b in docker tar sha256sum jq curl python3; do command -v $b; done
docker compose version
```

**Rollback:** No state created. Just don't proceed.

---

### Step 2 — Bundle Extraction (script step 2/8, exit code 20)

If `--skip-extract` is *not* passed, the script auto-detects `aldeci-scif-*.tar.gz` in `/opt`, `/tmp`, or the current directory and extracts to `/var/lib/aldeci-scif/bundle/`. Then it runs:

- `sha256sum -c manifests/sha256.txt` — every file must verify
- `cosign verify-blob` if `manifests/sha256.txt.cosign.sig` is present (advisory; failure logged but not fatal — note in ISSO record)
- `docker load` for every `images/*.tar.gz`

**Manual verify:**

```bash
cd /var/lib/aldeci-scif/bundle/aldeci-scif-*
sha256sum -c manifests/sha256.txt | grep -v ': OK'    # must produce no output
docker images aldeci:scif-hardened                      # image present
```

**Rollback:**
```bash
docker rmi aldeci:scif-hardened 2>/dev/null
rm -rf /var/lib/aldeci-scif/bundle
```

---

### Step 3 — HSM Token Init (script step 3/8, exit code 30)

Two paths:

- **Real HSM (Luna/CloudHSM/YubiHSM2):** the script *does not touch* the token — vendor's pre-existing keys are used. ISSO must ensure `PKCS11_PIN` is exported in the shell.
- **SoftHSM (dev/pilot fallback):** the script generates random 12-char PINs (user PIN + SO-PIN), runs `softhsm2-util --init-token --slot 0 --label aldeci`, and persists the PINs to `/var/lib/aldeci-scif/hsm.pin` (mode 0600).

**Manual verify:**
```bash
softhsm2-util --show-slots | grep -A2 "Label:.*aldeci"   # token visible
ls -l /var/lib/aldeci-scif/hsm.pin                         # mode 0600
```

**Rollback:**
```bash
# SoftHSM only — destroys the token AND any keys generated under it
softhsm2-util --delete-token --token aldeci
rm -f /var/lib/aldeci-scif/hsm.pin /var/lib/aldeci-scif/hsm.sopin
```

⚠ **DO NOT roll back** the HSM step on a real HSM in production — it would destroy keys the production environment depends on. Real-HSM rollback is a vendor-specific procedure tracked in your KMS runbook.

---

### Step 4 — Per-Tenant API Keys (script step 4/8, exit code 40)

Generates one tenant API key (formatted `ald_` + 32 url-safe random bytes) and persists to `/var/lib/aldeci-scif/tenant-api-keys.json` (mode 0600). The HSM RSA-3072 key labelled `tenant-api-key-<tenant-id>` is referenced for downstream non-repudiation signing — actual signing happens in the application after first start, when the HSM session is open.

The JSON record includes:
- `tenant_id`, `key_id`, `api_key`, `api_key_sha256`
- `created_utc`, `rotation_due_utc` (created + 90 days)
- `hsm_backend`, `hsm_signing_label`

**Manual verify:**
```bash
sudo jq . /var/lib/aldeci-scif/tenant-api-keys.json
# Confirm: tenant_id, key_id, hsm_signing_label all present; api_key starts with "ald_"
```

**Rollback:**
```bash
sudo rm -f /var/lib/aldeci-scif/tenant-api-keys.json
# Re-run Step 4 only:
sudo bash scripts/scif_pilot_day1_install.sh --skip-extract
```

⚠ **Distribute the API key out-of-band** (signed envelope, in-person, or via approved courier). **Never email.**

---

### Step 5 — Boot ALDECI Containers (script step 5/8, exit code 50)

Looks for a compose file in this order:
1. `${BUNDLE_DIR}/docker/docker-compose.scif.yml`
2. `${BUNDLE_DIR}/docker/docker-compose.enterprise.yml`
3. `./docker/docker-compose.scif.yml`
4. `./docker/docker-compose.enterprise.yml`

If none found, falls back to a direct `docker run` with the SCIF hardening flags from `docs/scif/SCIF_PILOT_BUNDLE_README.md` §2.2:

```
--read-only --tmpfs /tmp:noexec,nosuid,size=128m
--cap-drop=ALL --cap-add=NET_BIND_SERVICE
--security-opt no-new-privileges:true
--pids-limit 256
-e FIPS_MODE=1 -e FIPS_STRICT_BOOT=1
-e HSM_ENABLED=1 -e PKCS11_MODULE=... -e PKCS11_PIN=...
-e FIXOPS_DISABLE_TELEMETRY=1
```

After start, polls `http://localhost:8000/api/v1/health` for up to 90s.

**Manual verify:**
```bash
docker ps --filter name=aldeci                    # running, "healthy"
curl -sf http://localhost:8000/api/v1/health      # 200 OK
docker inspect aldeci-scif | jq '.[0].HostConfig.ReadonlyRootfs'   # true
```

**Rollback:**
```bash
docker compose -f docker/docker-compose.scif.yml down -v   # if using compose
docker rm -f aldeci-scif                                    # if direct run
docker volume rm aldeci-data aldeci-audit                  # ⚠ wipes data
```

⚠ Volume removal **destroys the audit chain** — only do this on a brand-new install. If a prior pilot is still in evidence-retention, snapshot the audit volume first (`docker run --rm -v aldeci-audit:/src -v $(pwd):/dst busybox tar -cf /dst/audit-snapshot.tar /src`).

---

### Step 6 — FIPS NIST KAT Self-Test (script step 6/8, exit code 60)

Calls `GET /api/v1/scif/boot` and asserts `fips_mode_active = true`. The endpoint is wired into `suite-api/apps/api/app.py:2096` and reads `app.state.fips_report` populated by `core.fips_boot.boot_check()` at startup. The boot check runs the OpenSSL FIPS Known-Answer Tests (NIST CAVP-validated AES, SHA, RSA, HMAC vectors) before the API accepts traffic.

In `--dev-mode` this step is skipped (FIPS_MODE=0).

**Manual verify:**
```bash
curl -s http://localhost:8000/api/v1/scif/boot | jq .
# Expect: fips_mode_requested=true, fips_mode_active=true, boot_refused=false
```

**Rollback:** if KAT fails, the script exits 60. Inspect `docker logs aldeci-scif | grep -i fips` for the failed vector. Common cause: a non-FIPS Python crypto library (`pycryptodome`, `Crypto.Cipher.ARC4`) was installed inadvertently — rebuild image without it.

---

### Step 7 — Audit Chain Integrity (script step 7/8, exit code 70)

Calls `GET /api/v1/scif/audit-chain/verify`. The endpoint is wired into `suite-api/apps/api/app.py:2101` and calls `core.audit_chain.get_audit_chain().verify_full()`, which re-walks the SQLite chain at `/app/audit/chain.db` and recomputes `hash = sha256(prev_hash || ts || action || canonical_json(payload))` for every row. Returns `ok=true` only if every row's stored hash matches its recomputed hash AND every checkpoint signature verifies against the HSM `audit-chain-checkpoint` key.

**Manual verify:**
```bash
curl -s http://localhost:8000/api/v1/scif/audit-chain/verify | jq .
# Expect: ok=true, total_entries>=1, first_broken_seq=null,
#         checkpoint_signatures_verified>=0, checkpoint_signatures_failed=0
```

**Rollback:** if the chain is broken (`ok=false`), the script exits 70 reporting `first_broken_seq`. Options:
- Restore the audit volume from off-system backup (your `aldeci-audit` snapshot mechanism — see POA-003 in `SCIF_PILOT_BUNDLE_README.md` §4)
- Initialise a fresh chain (loses all prior audit history — only acceptable on first install)
- Refuse to start and contact ALDECI support with the `chain.db` snapshot for forensic analysis

---

### Step 8 — ISSO Summary Table (script step 8/8)

The script prints a boxed summary table containing:
- pre-flight status (FIPS, HSM, air-gap, packages)
- bundle source dir + manifest verification status
- first tenant ID, onboarding URL, API key ID, **the API key itself** (only on stdout — never persisted in plaintext outside the 0600 JSON file)
- API key SHA-256 fingerprint for the audit log
- key rotation due date (D+90)
- FIPS KAT and audit chain pass/fail
- service URLs
- state directory and install log paths
- "ISSO MUST DO TODAY" + "DO NOT" lists

**Capture this output** — it's your Day-1 install record. Print, sign, file under your ATO inheritance package.

---

## 3. Failure Matrix (every exit code, every fix)

| Exit | Step | Meaning | First fix |
|---|---|---|---|
| 2  | -- | usage error / not-root | re-run with sudo, check `--help` |
| 10 | 1  | pre-flight failed (FIPS / HSM / air-gap / pkg) | follow `[FIX]` line printed above the failure |
| 20 | 2  | bundle missing or sha256 mismatch | re-acquire bundle, verify GPG sig, re-extract |
| 30 | 3  | SoftHSM init failed | check `/var/lib/softhsm` permissions; `softhsm2-util --show-slots` |
| 40 | 4  | API key gen failed (python3 stdlib unavailable) | install python3.11 from bundle wheels |
| 50 | 5  | docker compose / docker run failed | `docker logs aldeci-scif` ; check disk space, port 8000 free |
| 60 | 6  | FIPS NIST KAT failed | check container logs for "non-FIPS lib importable" |
| 70 | 7  | audit chain broken | restore from off-system backup; or wipe + reinstall |
| 80 | 8  | health probe never returned 200 | container started but app crashed — check logs |

---

## 4. Idempotency

The script is **safe to re-run**:
- Pre-flight is read-only — no side effects.
- Bundle extract checks if files already exist before extracting.
- SoftHSM init skips if the `aldeci` token already exists.
- API key gen overwrites the JSON only if missing or rotation due — pass `TENANT_ID=<new>` env to mint a second tenant.
- Container boot uses `docker compose up -d` (idempotent) or `docker rm -f aldeci-scif` before `docker run`.

---

## 5. Post-Install ISSO Checklist (Day-1 evening)

| # | Item | Done |
|---|---|------|
| 1 | Print the Step-8 summary table, sign, file in ATO package | ☐ |
| 2 | Confirm `fips_mode_active=true` and `audit-chain ok=true` via `curl` | ☐ |
| 3 | Distribute API key to pilot lead **out-of-band** (in-person or signed envelope) | ☐ |
| 4 | Set up off-system backup of `aldeci-audit` volume (cron + encrypted media) | ☐ |
| 5 | Open POA&M items in your tracker (POA-001..006 from `SCIF_PILOT_BUNDLE_README.md` §4) | ☐ |
| 6 | Lock the host firewall to deny all outbound — verify with `nft list ruleset` | ☐ |
| 7 | Schedule Day-2 review (see §6 below) for T+1 morning | ☐ |
| 8 | File install log `/var/log/aldeci-scif-day1.log` under change-control | ☐ |

---

## 6. Day-2 Readiness — TWO Things ISSO Must Do AFTER Day-1

These are the **two non-negotiable Day-2 actions** without which the pilot is technically running but not auditable:

### 6.1 Off-system backup of the audit chain
The Day-1 script creates `aldeci-audit` as a Docker volume on local disk. **A drive failure = total audit history loss.** The audit chain is the linchpin of the SCIF posture — if you cannot restore it, you cannot prove what the platform did.

**Minimum acceptable Day-2 setup:**
```bash
# /etc/cron.daily/aldeci-audit-backup
#!/bin/bash
TS=$(date -u +%Y%m%dT%H%M%SZ)
docker run --rm -v aldeci-audit:/src -v /mnt/encrypted-backup:/dst busybox \
    tar -czf /dst/aldeci-audit-${TS}.tar.gz /src
# Then sync to write-once media (LTO tape, BD-R) or off-host encrypted storage
```

Plus a quarterly **restore drill** — restore to a scratch container and run `/api/v1/scif/audit-chain/verify` against it. Document in your DR runbook.

This closes POA-003 from `SCIF_PILOT_BUNDLE_README.md` §4.

### 6.2 Tenant API key rotation policy + tenant onboarding through the actual flow
The Day-1 script generated **one** tenant API key with rotation due D+90. By Day-2 you must:

1. **Document the rotation procedure** — how the pilot lead requests a new key, who approves, who delivers, how the old key is revoked. (Write a 1-page runbook; file under change-control.)
2. **Onboard the first real tenant via the UI** — `http://localhost:8000/onboard?tenant=<id>` then create org, connector, repo enrollment. **Do NOT** use seed scripts that write directly to the DB — that bypasses the connector framework, tenant isolation, and the Brain Pipeline. (See `CLAUDE.md` "REAL CUSTOMERS, NOT SEEDED DATA".)
3. **Run one end-to-end Brain Pipeline** with a real finding from the bundled threat-intel feeds. Verify `/api/v1/scif/audit-chain/verify` still returns `ok=true` after the pipeline writes audit rows. **This is the canonical pilot-success demo** — until you've done this, the pilot is "installed" but not "validated".

---

## 7. Smoke Test (developer / lab use)

```bash
# Run the full Day-1 path in dev-mode (no FIPS, no real HSM, no egress probe)
bash tests/test_scif_day1_install.sh
# Asserts each of the 8 steps succeeds and exits 0 on green.
```

The smoke test is the regression net for the install script — every change to `scripts/scif_pilot_day1_install.sh` must keep this green.

---

## 8. References

- `scripts/scif_pilot_day1_install.sh` — the script this runbook describes
- `tests/test_scif_day1_install.sh` — smoke test (dev-mode, dry-run)
- `scripts/build_scif_bundle.sh` — build the bundle this script consumes
- `docker/Dockerfile.scif.ironbank` — Iron Bank base image (T+0 once CAC token in hand)
- `docker/scif-entrypoint.sh` — fail-closed boot script enforced inside the container
- `docs/scif/SCIF_PILOT_BUNDLE_README.md` — full ISSO bundle README (POA&M, support model, out-of-scope)
- `docs/scif/stig_hardening_checklist_2026-04-26.md` — DISA STIG control mapping
- `docs/scif/SSP_aldeci_2026-04-26.md` — System Security Plan
- `suite-api/apps/api/app.py:2089-2134` — `/api/v1/scif/*` endpoint definitions
- `suite-core/core/audit_chain.py` — tamper-evident audit chain
- `suite-core/core/fips_boot.py` — FIPS NIST KAT runner
