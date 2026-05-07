# ALDECI Backup & Restore

Infrastructure for backing up and restoring critical ALDECI state.

## What Gets Backed Up

- **data/** — Threat feeds, threat intelligence cache, analytics DBs
- **.swarm/memory.db** — Agent memory store (AgentDB with 8K+ entries)
- **.hive-mind/** — Hive-mind coordination metadata + task queue
- **.env** — Configuration (API keys, LLM endpoints, etc.)

Excludes: `__pycache__`, `*.pyc`, `.DS_Store` (safely compresses to ~50-200MB depending on threat feed size).

## Scripts

### backup.sh — Create Backup

```bash
./scripts/backup.sh [output_dir]
```

**Default behavior**: Creates `/tmp/aldeci-backup-YYYYMMDD-HHMMSS.tgz`

**With custom output dir**:
```bash
./scripts/backup.sh /mnt/backups
```

**Output**:
```
✓ Including data/
✓ Including .swarm/memory.db
✓ Including .hive-mind/
✓ Including .env
✓ Backup complete: /tmp/aldeci-backup-20260505-231200.tgz (87M)
  Timestamp: 20260505-231200
```

### restore.sh — Restore from Backup

```bash
./scripts/restore.sh <backup_file>
```

**Example**:
```bash
./scripts/restore.sh /tmp/aldeci-backup-20260505-231200.tgz
```

**Interactive prompt** (requires confirmation):
```
ALDECI Restore Started
⚠ This will restore state. Continue? (y/N)
```

**Output on success**:
```
✓ Restored data/
✓ Restored .swarm/memory.db
✓ Restored .hive-mind/
✓ Restored .env
✓ Restore complete: 4 items restored
```

## Usage Patterns

### Daily Backup (Cron)
```bash
# Daily 2 AM backup to /mnt/backups/
0 2 * * * cd /path/to/Fixops && ./scripts/backup.sh /mnt/backups/
```

### Pre-Deployment Snapshot
```bash
./scripts/backup.sh /tmp/
# Deploy...
# If rollback needed: ./scripts/restore.sh /tmp/aldeci-backup-*.tgz
```

### Container/K8s Restore
```bash
# Inside pod: copy backup in, restore, restart services
kubectl cp backup.tgz pod:/tmp/
kubectl exec pod -- /app/scripts/restore.sh /tmp/backup.tgz
kubectl rollout restart deployment/aldeci-api
```

## Safety

- **Backup is non-destructive** — reads only, creates new archive
- **Restore is interactive** — requires human confirmation (prevents accidental overwrites)
- **Excludes Python cache** — `__pycache__` and `.pyc` not backed up (regenerated on import)
- **Preserves structure** — extracts to repo root, maintains original directory layout

## Size Estimates

| Item | Typical Size |
|------|--------------|
| data/ (threat feeds) | 50-150 MB |
| .swarm/memory.db | 5-20 MB |
| .hive-mind/ | <5 MB |
| .env | <1 KB |
| **Total** | **60-175 MB** |

Full archive (with compression): ~40-100 MB
