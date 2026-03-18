-- ALdeci PostgreSQL initialization
-- Runs once when the postgres container is first created.
-- Subsequent schema changes are handled by Alembic migrations.

-- Enable pgcrypto for gen_random_uuid() used in all primary keys
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Enable pg_stat_statements for query performance monitoring
-- (optional but recommended for production)
CREATE EXTENSION IF NOT EXISTS pg_stat_statements;

-- Set default timezone
SET timezone = 'UTC';
