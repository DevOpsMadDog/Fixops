# Fixops On-Prem & HA Reference Architecture

**Audience:** platform engineers, federal compliance officers, DoD IL4/IL5 operators, FedRAMP High deployers, air-gapped / classified-side deployers.
**Status:** placeholder reference (Sprint 3 will produce the full Helm chart, published image SHA pins, and federal STIG-aligned hardening guide). This document supersedes the former `onprem_ha_reference_engine` PRD — the capability is **packaging**, not code.
**Related gaps:** GAP-003 (this doc), GAP-001 (air-gap signed bundles), GAP-042 (FIPS mode).
**Compliance targets:** FedRAMP Moderate / High, DoD IL4 / IL5, NIST SP 800-53 Rev. 5, CIS Kubernetes Benchmark v1.9, ISO/IEC 27001:2022 Annex A.

---

## 1. Deployment Modes

Fixops supports five production deployment shapes. Every mode must pass `fixops-cli preflight` before start.

### 1.1 Single-node (dev / POC)
A single Linux host or VM running `docker compose -f docker/docker-compose.prod.yml up -d`. All components (API, pipeline workers, Postgres, Redis, UI, Nginx, TrustGraph) live on one host. Suitable for evaluation up to ~5 analysts and ~50 scans/day.

**Minimum resources:** 8 vCPU, 32 GB RAM, 500 GB SSD, 1 Gbps NIC.
**SLA:** no HA. Recovery = restart container. RTO ≤ 15 min, RPO ≤ 24 h (daily backup).
**Supported OS:** Ubuntu 22.04/24.04 LTS, RHEL 9, Rocky Linux 9, Debian 12.
**TLS:** Nginx terminates TLS; certs placed at `/etc/fixops/tls/`.
**Backups:** `docker compose exec postgres pg_dumpall` nightly; evidence vault to object store or local disk.

### 1.2 HA-3node (standard enterprise)
Three-node Kubernetes cluster (1 control-plane HA, 3 worker). Postgres runs as a Patroni-managed StatefulSet with 3 replicas on PVC-backed storage (block, RWO). Redis Sentinel 3 node. NGINX ingress 2 replicas. Fixops API replicas: 3. Pipeline workers: 3. UI: 2.

**Minimum resources (per worker):** 16 vCPU, 64 GB RAM, 1 TB SSD, 10 Gbps NIC.
**SLA:** single-node API/worker failure → zero downtime. Patroni auto-promotes. Redis Sentinel quorum 2/3. Load balancer drains failing pod in ≤ 30 s.
**RTO ≤ 5 min, RPO ≤ 5 min** (Patroni sync replica + WAL archiving to S3 / MinIO).
**CNI:** Calico or Cilium (network policies are load-bearing for zero-trust).
**Ingress:** NGINX + cert-manager or Istio gateway.
**Storage class:** any CSI driver with RWO block storage (AWS EBS gp3, Azure Premium SSD, Ceph RBD, Longhorn).

### 1.3 HA-5node (large enterprise / multi-AZ)
Five-node Kubernetes cluster spanning ≥ 2 availability zones. Postgres Patroni 5 replicas (sync + 2 async). Redis Sentinel 5 node. Fixops API replicas: 5 (one per AZ minimum). Pipeline workers: 5 with autoscaling 5–20 based on queue depth. UI: 3. Evidence vault on object store with versioning + legal hold.

**Minimum resources (per worker):** 32 vCPU, 128 GB RAM, 2 TB NVMe, 25 Gbps NIC.
**SLA:** survives full AZ loss. Postgres primary auto-elects in surviving AZ. Redis Sentinel quorum 3/5.
**RTO ≤ 2 min, RPO ≤ 30 s**.
**Cross-AZ traffic:** encrypted via CNI WireGuard tunnels (Calico) or mTLS (Istio).
**Backups:** Postgres WAL archived to object store every 30 s; full base backup nightly; evidence chain WORM retained 7 y.

### 1.4 DR-pair (active / warm-standby cross-site)
Two geographically separated HA-3node clusters. Primary handles live traffic. DR cluster receives async Postgres streaming + evidence vault replication + TrustGraph event stream replay. Promotion via documented runbook.

**RTO ≤ 30 min (manual DNS cutover), RPO ≤ 5 min**.
**Network:** dedicated replication link ≥ 1 Gbps, latency ≤ 100 ms.
**Testing:** quarterly DR drill mandatory. Runbook: `docs/deployment/dr-drill-runbook.md` (Sprint 3).

### 1.5 Air-gap / classified-side (SAGE-class)
HA-3node or HA-5node cluster with **no outbound connectivity**. Updates arrive as signed offline bundles (see GAP-001). Container images pulled once on the connected side, shipped via trusted-courier media, imported to an internal registry (Harbor / Quay / Nexus mirror). Fixops operates against a bundled CVE/EPSS/KEV/license feed imported and verified via the `fixops-cli intel apply-bundle` command. No telemetry, no error-reporting call-home.

**Isolation:** cluster egress firewall default-deny. Allow-list only internal registry + NTP + internal PKI (OCSP). All DNS resolves internally.
**Signing:** Cosign keyless is disabled; signer uses a hardware key held offline. Bundles signed with FIPS 140-3 validated algorithm set (Dilithium + RSA hybrid — see GAP-042).
**Operator mode:** banner displays "AIR-GAP" on every UI page. `/metrics` endpoint exposes only internal scrape target.

---

## 2. Per-mode Requirements Matrix

| Requirement | Single | HA-3 | HA-5 | DR-pair | Air-gap |
|---|---|---|---|---|---|
| Postgres 15+ with Patroni | optional (single instance OK) | required (3 replicas) | required (5 replicas) | required (primary + DR) | required (3 or 5 replicas) |
| Redis Sentinel | optional | required (3 node) | required (5 node) | required | required |
| Shared object storage (S3 / MinIO / Ceph RGW) | optional | recommended | required | required | required (internal MinIO) |
| Kubernetes 1.28+ | no | yes | yes | yes | yes |
| Ingress controller (NGINX / Istio / Traefik) | no (Nginx reverse proxy) | yes | yes | yes | yes |
| Cert-manager + internal CA | no | recommended | required | required | required |
| Network policies (CNI) | n/a | recommended | required | required | required |
| FIPS-140 crypto (openssl-fips / BoringSSL) | optional | recommended | required | required | **required** |
| Offline bundle importer | n/a | optional | optional | optional | **required** |
| STIG-applied base OS | optional | recommended | recommended | recommended | **required** |
| Tamper-evident evidence vault (GAP-040) | enabled | enabled | enabled | enabled | enabled |
| Multi-factor auth on every operator login | optional | recommended | required | required | required |
| SIEM egress via syslog/CEF (GAP-035) | recommended | required | required | required | required |

---

## 3. Postgres HA Guidance (Patroni reference)

Fixops ships with Postgres 15 as the canonical data tier. On HA, the recommended controller is **Patroni** (Zalando), backed by etcd, Consul, or Kubernetes API as the DCS.

### 3.1 Reference topology (HA-3)
- 3 × Postgres 15 pods in a StatefulSet.
- `pg_rewind` + WAL streaming.
- One synchronous standby (`synchronous_commit = on`, `synchronous_standby_names = 'ANY 1 (*)'`).
- WAL archived every 30 s to object store via `pgBackRest` or `wal-g`.
- Read replicas served via a Patroni "replica" Kubernetes service; writes via the "master" service.
- Failover: Patroni DCS-backed leader election. Promotion target: ≤ 30 s.

### 3.2 Storage
- StorageClass: block, RWO, encrypted at rest (LUKS / CSI encryption / cloud KMS).
- PVC size: 500 GB minimum, auto-expand enabled.
- fsType: ext4 or xfs.

### 3.3 Backup strategy
- **Nightly full** via `pg_basebackup` → object store (retained 30 d).
- **WAL archive** every 30 s (retained 7 d).
- **Logical dumps** weekly via `pg_dump --format=directory --jobs=4 --compress=9` for portability.
- **Point-in-time recovery** (PITR) tested quarterly.

### 3.4 Tuning baselines
- `shared_buffers = 25% of RAM`
- `effective_cache_size = 75% of RAM`
- `max_connections = 500` (Fixops API uses connection pooling via pgBouncer in HA modes)
- `wal_level = replica`
- `max_wal_senders = 10`
- `hot_standby = on`
- `checkpoint_timeout = 15min`, `checkpoint_completion_target = 0.9`

### 3.5 Known-good operators
- CloudNativePG (CNPG) — preferred for Kubernetes-native.
- Zalando Postgres Operator — preferred if Patroni is the team standard.
- Crunchy PGO — acceptable; heavier resource profile.

---

## 4. Redis Sentinel Reference

Fixops uses Redis for cache, queue, rate-limit, and WebSocket fan-out. HA deploys Redis Sentinel for automated failover.

### 4.1 Reference topology
- 3 × Redis primary/replica pods (1 master, 2 replicas).
- 3 × Sentinel processes (co-located or standalone pods).
- Quorum: 2 / 3.
- `sentinel down-after-milliseconds 5000`, `sentinel failover-timeout 10000`.
- Password authentication mandatory (`requirepass` + `masterauth`).
- TLS enabled between client ↔ Redis and Sentinel ↔ Redis.

### 4.2 Failover behavior
- Sentinel promotes a replica within ≤ 15 s of primary failure.
- Fixops clients (pipeline worker, API) use `redis-py` `Sentinel` class → automatic primary discovery.
- Cluster mode (Redis Cluster) is **not** supported today; Sentinel is the only HA path.

### 4.3 Persistence
- AOF on, `appendfsync everysec`.
- RDB snapshot every 15 min.
- Both stored on encrypted PVC.

---

## 5. Evidence Vault Backup Plan

Fixops's evidence vault (tamper-evident, WORM, quantum-secure signed — see GAP-040, GAP-042) is the system of record for compliance. Loss of evidence is unacceptable.

### 5.1 Storage tiers
- **Hot tier:** local encrypted volume (fast reads for ongoing investigations). Retain 30 d.
- **Warm tier:** object store with versioning + object lock (S3 Object Lock / MinIO ILM / Azure Immutable Blob). Retain 1 y.
- **Cold tier:** archival (Glacier / Azure Archive / on-prem tape). Retain 7 y (FedRAMP) or 10 y (HIPAA / regulated finance).

### 5.2 Replication
- Hot → Warm: continuous, async, every committed evidence entry triggers upload.
- Warm → Cold: scheduled daily, delta-only.
- Cross-region replication for HA-5 / DR-pair: required.

### 5.3 Integrity verification
- Every evidence entry is Merkle-linked (`evidence_chain_engine`).
- Nightly cron job: `fixops-cli evidence verify --range=last-24h`. Exits non-zero on any broken link; alerts PagerDuty / Opsgenie.
- Weekly full verification: `fixops-cli evidence verify --full`. Expected runtime proportional to vault size.

### 5.4 Restore testing
- Quarterly: pick random 1% of evidence entries, restore from Warm tier, verify hash matches current Merkle root.
- Annual: full Cold-tier restore drill to an isolated cluster.

### 5.5 Disaster-recovery RPO
- Hot tier loss: recoverable from Warm tier within ≤ 5 min.
- Hot + Warm tier loss: recoverable from Cold tier within ≤ 4 h (cloud) or ≤ 24 h (tape).
- Full multi-site loss: unrecoverable — operators must accept and document RPO of 24 h; this is why cross-region replication is required at HA-5.

---

## 6. Hardening Requirements (per-mode)

All modes enforce a hardening baseline; additional requirements layer on top per the matrix in §2.

### 6.1 Base OS
- STIG-applied (CIS Level 2 or DISA STIG).
- Kernel: latest LTS. Auto-patching daily, rebooted during maintenance window.
- SELinux or AppArmor enforcing.
- SSH: keys only, no passwords, no root login, port 22 restricted to bastion.
- Time: NTP from at least two authenticated sources (or internal PTP in air-gap).

### 6.2 Container images
- Every Fixops image signed with Cosign (keyless on connected side; hardware-key on air-gap).
- Base image: distroless or UBI-minimal. No shell, no package manager at runtime.
- Non-root user (`USER 1000`).
- Read-only root filesystem. Writable volumes only for `/tmp`, `/var/log`, explicit PVC mounts.
- `seccomp=RuntimeDefault`, `capabilities: drop: ALL`, no `hostPath` mounts.

### 6.3 Network
- Ingress: TLS 1.3 only, HSTS with `max-age=63072000; includeSubDomains; preload`.
- Egress: default-deny; explicit allow-list for each pod.
- mTLS between API ↔ pipeline-worker ↔ Postgres ↔ Redis.
- No pod exposes `:0.0.0.0`; listeners bind internal service IPs.

### 6.4 Secrets
- No secrets in env vars for production. Mount via SealedSecrets or External Secrets Operator → Vault / AWS Secrets Manager / Azure Key Vault.
- Rotation: every 90 d minimum, automated.
- Never echoed in logs (grep audit: `scripts/secret_leak_check.sh`).

### 6.5 Authentication & authorization
- SSO (OIDC or SAML) required for operator UI.
- API: short-lived JWTs (exp ≤ 1 h) + refresh tokens + per-user disposable scoped tokens (GAP-039).
- RBAC: 6 roles (admin/analyst/responder/auditor/viewer/readonly) — enforced at API layer.
- Audit log: append-only (GAP-040), streamed to SIEM.

### 6.6 Monitoring
- Prometheus scraping required. Alertmanager → on-call (PagerDuty / Opsgenie).
- Structured JSON logs → Fluent Bit → SIEM (Splunk / Sentinel / Chronicle).
- Distributed tracing via OpenTelemetry; traces sampled at 10%.
- Golden signals: RED (rate, errors, duration), USE (utilization, saturation, errors).

### 6.7 Compliance artefacts
- STIG checklist: `docs/compliance/stig-checklist.xlsx` (Sprint 3).
- FedRAMP SSP boilerplate: `docs/compliance/ssp-boilerplate.docx` (Sprint 3).
- CIS Benchmark scorecard from `compliance_scanner_engine` on every cluster, refreshed hourly.
- FIPS mode attestation endpoint: `GET /api/v1/system/fips-mode` (GAP-042).

---

## 7. Preflight Checks (`fixops-cli preflight`)

Before any mode starts, the preflight CLI validates:
1. Kernel version ≥ 6.1 (Linux).
2. Docker / containerd version ≥ 24.0 / 1.7.
3. Kubernetes version ≥ 1.28 (HA modes).
4. Postgres version ≥ 15.0; connection RTT ≤ 5 ms from API pods.
5. Redis version ≥ 7.2; replication lag ≤ 100 ms.
6. TLS cert validity ≥ 30 d remaining.
7. Clock skew across nodes ≤ 100 ms.
8. Storage class supports RWO + encryption at rest.
9. `sysctl` tuning: `vm.max_map_count`, `net.core.somaxconn`, `fs.file-max` meet documented thresholds.
10. OS kernel security: SELinux/AppArmor enforcing, no unsigned kernel modules.
11. FIPS mode (if required): `openssl version -a` reports FIPS-certified provider.
12. Outbound reachability (non-air-gap only): registry, cert authority, NTP.
13. Air-gap guard (air-gap only): verify default-deny egress by attempting `curl https://anthropic.com` → expected to time out. Non-timeout = FAIL.

Exits 0 only when every check passes. Logs results to `/var/log/fixops/preflight.log` with severity tags, and to the Fixops API as a compliance event on the control cluster.

---

## 8. Helm Chart Layout

The replacement chart lives at `docker/helm/fixops/`. See `docker/helm/fixops/Chart.yaml` and `docker/helm/fixops/values.yaml` for entry points. The chart is intentionally placeholder in the current sprint — Sprint 3 will flesh out Patroni, Sentinel, and ingress templates.

Planned templates (Sprint 3):
- `templates/api-deployment.yaml` (Fixops API replicas)
- `templates/pipeline-statefulset.yaml` (pipeline workers with persistent queue)
- `templates/postgres-patroni.yaml` (Patroni StatefulSet + Services)
- `templates/redis-sentinel.yaml` (Sentinel StatefulSet + Services)
- `templates/trustgraph-statefulset.yaml` (TrustGraph core store)
- `templates/evidence-vault.yaml` (object-store integration)
- `templates/ingress.yaml` (NGINX or Istio gateway)
- `templates/networkpolicy.yaml` (default-deny + allow-lists)
- `templates/serviceaccount.yaml` + `templates/rbac.yaml`
- `templates/prometheusrule.yaml` (Fixops golden signal alerts)
- `templates/sealedsecret.yaml` (bootstrap config)

---

## 9. References

- Sonatype Lifecycle HA reference: https://help.sonatype.com/ (competitor reference cited in `raw/competitive/competitor-sonatype.md` §2)
- Patroni: https://patroni.readthedocs.io/
- Redis Sentinel: https://redis.io/docs/latest/operate/oss_and_stack/management/sentinel/
- CIS Kubernetes Benchmark v1.9
- NIST SP 800-53 Rev. 5
- FedRAMP Moderate / High Baseline
- `raw/competitive/gap-matrix.md` — GAP-001, GAP-003, GAP-042
- `docs/CTEM_PLUS_IDENTITY.md` — platform identity and guarantees

---

*This document replaces the Python engine/router that was formerly tracked as `onprem_ha_reference_engine` (GAP-003 KILL, 2026-04-22). The capability is packaging artefacts, not runtime code.*
