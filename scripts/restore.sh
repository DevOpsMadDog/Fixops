#!/bin/bash
# ALDECI Restore Script
# Restores state from a backup archive created by backup.sh
# Usage: ./scripts/restore.sh <backup_file>
# Example: ./scripts/restore.sh /tmp/aldeci-backup-20260505-231200.tgz

set -euo pipefail

if [ $# -ne 1 ]; then
  echo "Usage: $0 <backup_file>"
  echo "Example: $0 /tmp/aldeci-backup-20260505-231200.tgz"
  exit 1
fi

BACKUP_FILE="$1"
REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"

if [ ! -f "$BACKUP_FILE" ]; then
  echo "❌ Backup file not found: $BACKUP_FILE"
  exit 1
fi

echo "ALDECI Restore Started"
echo "Repo root: $REPO_ROOT"
echo "Backup file: $BACKUP_FILE"
echo "Size: $(du -h "$BACKUP_FILE" | cut -f1)"

# Confirm before restore
read -p "⚠ This will restore state. Continue? (y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
  echo "Cancelled."
  exit 0
fi

cd "$REPO_ROOT"

# Extract archive
echo "Extracting..."
tar -xzf "$BACKUP_FILE"

# Verify key files restored
RESTORED_COUNT=0
[ -d "data" ] && echo "✓ Restored data/" && ((RESTORED_COUNT++))
[ -f ".swarm/memory.db" ] && echo "✓ Restored .swarm/memory.db" && ((RESTORED_COUNT++))
[ -d ".hive-mind" ] && echo "✓ Restored .hive-mind/" && ((RESTORED_COUNT++))
[ -f ".env" ] && echo "✓ Restored .env" && ((RESTORED_COUNT++))

echo "✓ Restore complete: $RESTORED_COUNT items restored"
