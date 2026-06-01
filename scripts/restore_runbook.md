# ALDECI SQLite WAL Replication — Restore Runbook

**REQ-008-03** | Last updated: 2026-06-01

This runbook documents the exact steps to recover a critical SQLite database
from a Litestream WAL replica.

---

## Prerequisites

- Litestream binary installed and on PATH: `litestream version`
- Access to the replica target (local filesystem, NAS mount, or S3-compatible)
- `FIXOPS_REPLICA_PATH` env var set to the replica base directory
  (default: `./data/replicas` relative to repo root)
- Application stopped (or at least the service owning the DB to restore)

---

## 1. Identify the DB to restore

Check current protection status:

```bash
python scripts/backup_verify.py
```

List available generations in a replica:

```bash
litestream generations \
    -config docker/litestream.yml \
    <path/to/target.db>
```

Example (findings DB):

```bash
litestream generations \
    -config docker/litestream.yml \
    ./security_findings_engine.db
```

---

## 2. Restore commands — per critical DB

Stop the application before restoring to avoid WAL conflicts:

```bash
docker compose -f docker/docker-compose.yml stop api
# or: systemctl stop aldeci-api
```

### 2a. security_findings_engine (tier-1)

```bash
# Restore to a staging path first, then move atomically
litestream restore \
    -config docker/litestream.yml \
    -o /tmp/security_findings_engine.db.restored \
    ./security_findings_engine.db

# Verify integrity before replacing live DB
sqlite3 /tmp/security_findings_engine.db.restored "PRAGMA integrity_check;"

# Atomic replace
mv ./security_findings_engine.db ./security_findings_engine.db.bak.$(date +%s)
mv /tmp/security_findings_engine.db.restored ./security_findings_engine.db
```

### 2b. fixops_brain (tier-1)

```bash
litestream restore \
    -config docker/litestream.yml \
    -o /tmp/fixops_brain.db.restored \
    ./data/fixops_brain.db

sqlite3 /tmp/fixops_brain.db.restored "PRAGMA integrity_check;"

mv ./data/fixops_brain.db ./data/fixops_brain.db.bak.$(date +%s)
mv /tmp/fixops_brain.db.restored ./data/fixops_brain.db
```

### 2c. auth (tier-1)

```bash
litestream restore \
    -config docker/litestream.yml \
    -o /tmp/auth.db.restored \
    ./data/auth.db

sqlite3 /tmp/auth.db.restored "PRAGMA integrity_check;"

mv ./data/auth.db ./data/auth.db.bak.$(date +%s)
mv /tmp/auth.db.restored ./data/auth.db
```

### 2d. api_keys (tier-1)

```bash
litestream restore \
    -config docker/litestream.yml \
    -o /tmp/api_keys.db.restored \
    ./.fixops_data/api_keys.db

sqlite3 /tmp/api_keys.db.restored "PRAGMA integrity_check;"

mv ./.fixops_data/api_keys.db ./.fixops_data/api_keys.db.bak.$(date +%s)
mv /tmp/api_keys.db.restored ./.fixops_data/api_keys.db
```

### 2e. evidence_chain (tier-1)

```bash
litestream restore \
    -config docker/litestream.yml \
    -o /tmp/evidence_chain.db.restored \
    ./data/evidence_chain.db

sqlite3 /tmp/evidence_chain.db.restored "PRAGMA integrity_check;"

mv ./data/evidence_chain.db ./data/evidence_chain.db.bak.$(date +%s)
mv /tmp/evidence_chain.db.restored ./data/evidence_chain.db
```

### 2f. evidence_vault (tier-1)

```bash
litestream restore \
    -config docker/litestream.yml \
    -o /tmp/evidence_vault.db.restored \
    ./.fixops_data/evidence_vault.db

sqlite3 /tmp/evidence_vault.db.restored "PRAGMA integrity_check;"

mv ./.fixops_data/evidence_vault.db ./.fixops_data/evidence_vault.db.bak.$(date +%s)
mv /tmp/evidence_vault.db.restored ./.fixops_data/evidence_vault.db
```

### 2g. compliance_planner + compliance_automation (tier-1)

```bash
for DB in data/compliance_planner.db data/compliance_automation.db; do
    BASENAME=$(basename $DB)
    litestream restore \
        -config docker/litestream.yml \
        -o /tmp/${BASENAME}.restored \
        ./$DB
    sqlite3 /tmp/${BASENAME}.restored "PRAGMA integrity_check;"
    mv ./$DB ./${DB}.bak.$(date +%s)
    mv /tmp/${BASENAME}.restored ./$DB
done
```

### 2h. analytics (tier-2)

```bash
litestream restore \
    -config docker/litestream.yml \
    -o /tmp/analytics.db.restored \
    ./data/analytics.db

sqlite3 /tmp/analytics.db.restored "PRAGMA integrity_check;"

mv ./data/analytics.db ./data/analytics.db.bak.$(date +%s)
mv /tmp/analytics.db.restored ./data/analytics.db
```

### 2i. audit_trail (tier-2)

```bash
litestream restore \
    -config docker/litestream.yml \
    -o /tmp/audit_trail.db.restored \
    ./data/audit_trail.db

sqlite3 /tmp/audit_trail.db.restored "PRAGMA integrity_check;"

mv ./data/audit_trail.db ./data/audit_trail.db.bak.$(date +%s)
mv /tmp/audit_trail.db.restored ./data/audit_trail.db
```

---

## 3. Point-in-time restore

To restore to a specific timestamp (e.g. before a bad migration):

```bash
litestream restore \
    -config docker/litestream.yml \
    -timestamp "2026-06-01T14:30:00Z" \
    -o /tmp/findings.restored \
    ./security_findings_engine.db
```

---

## 4. Restore from S3-compatible target (MinIO / AWS S3)

If `FIXOPS_S3_BUCKET` is set, Litestream will have written to S3 in parallel.
To restore directly from S3:

```bash
export FIXOPS_S3_BUCKET=my-aldeci-replicas
export FIXOPS_S3_ENDPOINT=https://minio.internal:9000  # or blank for AWS
export AWS_ACCESS_KEY_ID=<key>
export AWS_SECRET_ACCESS_KEY=<secret>

litestream restore \
    -config docker/litestream.yml \
    -o /tmp/findings.restored \
    ./security_findings_engine.db
```

---

## 5. Post-restore verification

After restoring and before restarting the application:

```bash
# 1. Integrity check all restored DBs
for DB in \
    security_findings_engine.db \
    data/fixops_brain.db \
    data/auth.db \
    data/evidence_chain.db; do
    echo "=== $DB ==="
    sqlite3 $DB "PRAGMA integrity_check; PRAGMA wal_checkpoint;"
done

# 2. Run backup_verify to confirm protection state
python scripts/backup_verify.py

# 3. Run smoke tests
python -m pytest tests/test_health.py -q --timeout=10

# 4. Restart application
docker compose -f docker/docker-compose.yml start api
```

---

## 6. Air-gap deployment notes

In air-gapped deployments (FIXOPS_AIRGAP_MODE=enforced):

- Use `FIXOPS_REPLICA_PATH` pointing to a NAS or local disk mount
- Do NOT configure S3 targets unless using on-prem MinIO
- Replica directory should be on separate physical storage from the DBs
- Suggested layout:
  ```
  /mnt/nas-backup/aldeci-replicas/   <- FIXOPS_REPLICA_PATH
  /opt/aldeci/data/                  <- live DBs
  ```

---

## 7. Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| `litestream restore` fails with "no generations found" | Litestream never ran or replica path wrong | Check `FIXOPS_REPLICA_PATH`, run `litestream generations` |
| `PRAGMA integrity_check` returns errors | Partial/corrupt restore | Re-run restore from an earlier generation |
| `backup_verify.py` shows UNPROTECTED after restart | Litestream not running as a sidecar | Start `litestream replicate -config docker/litestream.yml` |
| Replica dir exists but is empty | Litestream started but DB not opened yet | Wait for first WAL write, or run a write transaction against the DB |

---

## 8. Starting Litestream as a sidecar

Production deployment (add to docker-compose or systemd):

```yaml
# docker/docker-compose.yml addition
litestream:
  image: litestream/litestream:latest
  command: replicate -config /etc/litestream.yml
  volumes:
    - ./docker/litestream.yml:/etc/litestream.yml:ro
    - .:/app:rw
    - ${FIXOPS_REPLICA_PATH:-./data/replicas}:/replicas:rw
  restart: unless-stopped
  depends_on:
    - api
```

Systemd unit:

```ini
[Unit]
Description=ALDECI Litestream WAL replication
After=aldeci-api.service

[Service]
ExecStart=/usr/local/bin/litestream replicate -config /opt/aldeci/docker/litestream.yml
Restart=on-failure
Environment=FIXOPS_REPLICA_PATH=/mnt/nas-backup/aldeci-replicas

[Install]
WantedBy=multi-user.target
```

---

*See also: `docker/litestream.yml`, `suite-core/core/db_durability.py`, `scripts/backup_verify.py`*
*Spec reference: `specs/SPEC-008-ha-durability.md`*
