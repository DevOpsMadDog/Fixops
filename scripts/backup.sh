#!/bin/bash
# ALDECI Backup Script
# Backs up critical state: data/, .swarm/memory.db, .hive-mind/, .env
# Usage: ./scripts/backup.sh [output_dir]
# Default: /tmp/aldeci-backup-$(date +%Y%m%d-%H%M%S).tgz

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

OUTPUT_DIR="${1:-.}"
DATE=$(date +%Y%m%d-%H%M%S)
BACKUP_FILE="${OUTPUT_DIR}/aldeci-backup-${DATE}.tgz"

# Ensure output dir exists
mkdir -p "$OUTPUT_DIR"

echo "ALDECI Backup Started"
echo "Repo root: $REPO_ROOT"
echo "Output: $BACKUP_FILE"

# Build tar include list dynamically (only backup what exists)
TAR_INCLUDE=""
[ -d "data" ] && TAR_INCLUDE="$TAR_INCLUDE data" && echo "✓ Including data/"
[ -f ".swarm/memory.db" ] && TAR_INCLUDE="$TAR_INCLUDE .swarm/memory.db" && echo "✓ Including .swarm/memory.db"
[ -d ".hive-mind" ] && TAR_INCLUDE="$TAR_INCLUDE .hive-mind" && echo "✓ Including .hive-mind/"
[ -f ".env" ] && TAR_INCLUDE="$TAR_INCLUDE .env" && echo "✓ Including .env"

if [ -z "$TAR_INCLUDE" ]; then
  echo "⚠ Warning: No backup items found. Exiting."
  exit 1
fi

# Create tar.gz archive (exclude __pycache__, .pyc, etc.)
tar --exclude='__pycache__' --exclude='*.pyc' --exclude='.DS_Store' \
    -czf "$BACKUP_FILE" $TAR_INCLUDE

SIZE=$(du -h "$BACKUP_FILE" | cut -f1)
echo "✓ Backup complete: $BACKUP_FILE ($SIZE)"
echo "  Timestamp: $DATE"
