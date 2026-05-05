#!/bin/bash
# ============================================================================
# PostgreSQL Primary — Replication Setup
# ============================================================================
# Creates a replication user and configures pg_hba.conf for streaming
# replication from the replica container.
# This script runs during initdb (first start only).
# ============================================================================
set -euo pipefail

echo "Configuring PostgreSQL replication..."

# Create replication user
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-EOSQL
    CREATE ROLE replicator WITH REPLICATION LOGIN PASSWORD '${POSTGRES_PASSWORD}';
    GRANT pg_read_all_data TO replicator;
EOSQL

# Allow replication connections from the Docker network
cat >> "$PGDATA/pg_hba.conf" <<EOF

# Replication connections from Docker network
host    replication     replicator      172.28.0.0/16           scram-sha-256
host    all             all             172.28.0.0/16           scram-sha-256
EOF

# Create archive directory
mkdir -p /var/lib/postgresql/archive
chown postgres:postgres /var/lib/postgresql/archive

echo "Replication configuration complete."
