"""
Alembic environment configuration for ALdeci CTEM+ Platform.

The database URL is read exclusively from the ``FIXOPS_DB_DSN`` environment
variable.  This ensures that no credentials are stored in alembic.ini or in
version control.

Usage:
    export FIXOPS_DB_DSN="postgresql://fixops:pass@localhost:5432/fixops"
    alembic upgrade head
    alembic revision --autogenerate -m "add column x to findings"
"""

from __future__ import annotations

import logging
import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

# -- Alembic Config object ---------------------------------------------------

config = context.config

# Configure Python logging from alembic.ini [loggers] section
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

logger = logging.getLogger("alembic.env")

# -- Target metadata ---------------------------------------------------------
# Import P0 ORM models so that ``alembic revision --autogenerate`` can detect
# schema drift against the database.
#
# The models live in suite-core/core/db/models.py and use the dual-dialect
# Base (SQLite + PostgreSQL compatible types).
#
# sitecustomize.py injects all suite paths so this import works without
# pip install -e.
try:
    import sys
    import os
    _repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for _suite in (
        "suite-core",
        "suite-core/core",
        "suite-api",
        "suite-attack",
        "suite-feeds",
        "suite-evidence-risk",
        "suite-integrations",
    ):
        _path = os.path.join(_repo_root, _suite)
        if _path not in sys.path:
            sys.path.insert(0, _path)

    from core.db.models import Base  # noqa: E402, F401 — P0 models
    target_metadata = Base.metadata
    logger.info("Loaded P0 ORM models for autogenerate (core.db.models.Base)")
except Exception as _e:
    logger.warning("Could not import core.db.models.Base: %s — autogenerate disabled", _e)
    target_metadata = None


# ---------------------------------------------------------------------------
# Helper — resolve the database URL
# ---------------------------------------------------------------------------

def _get_db_url() -> str:
    """
    Resolve PostgreSQL connection URL.

    Priority:
    1. FIXOPS_DB_DSN environment variable  (preferred — no credentials in files)
    2. alembic.ini [alembic] sqlalchemy.url (fallback for local dev)
    """
    dsn = os.environ.get("FIXOPS_DB_DSN", "").strip()
    if dsn:
        logger.info("Using database URL from FIXOPS_DB_DSN environment variable")
        return dsn

    ini_url = config.get_main_option("sqlalchemy.url")
    logger.warning(
        "FIXOPS_DB_DSN not set — falling back to alembic.ini sqlalchemy.url. "
        "Set FIXOPS_DB_DSN for production deployments."
    )
    return ini_url


# ---------------------------------------------------------------------------
# Offline migration (generates SQL script, no live DB connection)
# ---------------------------------------------------------------------------

def run_migrations_offline() -> None:
    """
    Run migrations in 'offline' mode.

    This outputs the SQL statements to stdout or a file without connecting
    to the database.  Useful for generating scripts to review before applying.

    Usage:
        alembic upgrade head --sql > migration.sql
    """
    url = _get_db_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        # PostgreSQL-specific: include transaction-wrapping DDL
        transaction_per_migration=True,
    )

    with context.begin_transaction():
        context.run_migrations()


# ---------------------------------------------------------------------------
# Online migration (connects to the live database)
# ---------------------------------------------------------------------------

def run_migrations_online() -> None:
    """
    Run migrations in 'online' mode against a live database connection.

    Uses NullPool to avoid leaving idle connections after migration completes —
    important when running migrations from CI/CD pipelines.
    """
    url = _get_db_url()

    # Override the URL from ini with the resolved URL
    configuration = config.get_section(config.config_ini_section, {})
    configuration["sqlalchemy.url"] = url

    connectable = engine_from_config(
        configuration,
        prefix="sqlalchemy.",
        # NullPool is preferred for short-lived migration scripts — it closes
        # connections immediately rather than pooling them.
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            # PostgreSQL: compare server defaults in autogenerate
            compare_server_default=True,
        )

        with context.begin_transaction():
            context.run_migrations()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
