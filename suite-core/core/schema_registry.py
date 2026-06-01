"""
REQ-010-04 — Schema Registry
==============================
A lightweight, reusable migration-discipline helper for ALDECI's SQLite engines.

The two core problems it solves:
  1. NULL-id / bad-enum crashes caused by schema drift — an engine's DB was
     created months ago but the Python model has since grown new columns.
  2. 1,569 inline CREATE TABLE statements scattered across engines with no
     migration tracking.

This module does NOT replace all 1,569 statements at once (out of scope for
SPEC-010).  It provides the primitives so that engines can OPT IN one at a
time:

    from core.schema_registry import register_schema, apply_pending

    register_schema(
        "findings",
        '''CREATE TABLE IF NOT EXISTS findings (
               id TEXT PRIMARY KEY,
               title TEXT NOT NULL,
               severity TEXT NOT NULL
           )'''
    )

    # Call once at engine startup — idempotent, safe to repeat.
    apply_pending(conn)   # creates table + adds any missing columns

Usage
-----
    register_schema(name, create_sql)
        Register a table's canonical DDL. Safe to call at module load time
        (no DB connection required).

    apply_pending(conn)
        Execute all registered DDL statements that haven't been applied yet,
        then call add_missing_columns() for every registered table.

    add_missing_columns(conn, table, expected_cols)
        Given a dict {col_name: col_type_sql}, introspect the live table via
        PRAGMA table_info and ALTER TABLE ADD COLUMN for any that are absent.
        Existing data is never touched.

    get_registered()
        Return a copy of the registry dict (read-only snapshot).
"""
from __future__ import annotations

import logging
import sqlite3
import threading
from typing import Dict, List, Tuple

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Internal registry — thread-safe
# ---------------------------------------------------------------------------

_lock = threading.Lock()

# name -> (create_sql, expected_columns_dict)
# expected_columns_dict: {col_name: col_type_sql}  e.g. {"tenant_id": "TEXT"}
_registry: Dict[str, Tuple[str, Dict[str, str]]] = {}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def register_schema(
    name: str,
    create_sql: str,
    expected_columns: Dict[str, str] | None = None,
) -> None:
    """
    Register a table schema with the global registry.

    Parameters
    ----------
    name : str
        Logical name for this table/schema (usually the table name).
    create_sql : str
        The ``CREATE TABLE IF NOT EXISTS ...`` DDL string.
    expected_columns : dict, optional
        Mapping of ``{column_name: sql_type}`` that the table MUST have.
        ``apply_pending()`` will ALTER TABLE ADD COLUMN for any that are
        absent.  This is the primary fix for NULL-id / bad-enum drift.
    """
    with _lock:
        _registry[name] = (create_sql, expected_columns or {})
    logger.debug("schema_registry: registered schema '%s'", name)


def apply_pending(conn: sqlite3.Connection) -> None:
    """
    Apply all registered schemas to *conn*:
      1. Execute each CREATE TABLE IF NOT EXISTS.
      2. Call add_missing_columns() for every registered table.

    Idempotent — safe to call on every engine startup.

    Parameters
    ----------
    conn : sqlite3.Connection
        An open SQLite connection.  WAL mode is recommended for engines
        that share the same DB file across threads.
    """
    with _lock:
        snapshot = dict(_registry)

    for name, (create_sql, expected_cols) in snapshot.items():
        try:
            conn.execute(create_sql)
            conn.commit()
            logger.debug("schema_registry: applied DDL for '%s'", name)
        except sqlite3.Error as exc:
            logger.warning("schema_registry: DDL for '%s' failed: %s", name, exc)
            continue

        if expected_cols:
            # Derive table name from create_sql if not trivially the registry name
            table_name = _parse_table_name(create_sql) or name
            add_missing_columns(conn, table_name, expected_cols)


def add_missing_columns(
    conn: sqlite3.Connection,
    table: str,
    expected_cols: Dict[str, str],
) -> List[str]:
    """
    Inspect *table* via PRAGMA table_info and ALTER TABLE ADD COLUMN for
    every column in *expected_cols* that does not yet exist.

    Returns a list of column names that were actually added (empty if none).

    Parameters
    ----------
    conn : sqlite3.Connection
        An open SQLite connection.
    table : str
        The table name to introspect.
    expected_cols : dict
        ``{column_name: sql_type}`` e.g. ``{"tenant_id": "TEXT DEFAULT ''"}``
    """
    try:
        pragma_rows = conn.execute(f"PRAGMA table_info({table})").fetchall()  # noqa: S608
    except sqlite3.Error as exc:
        logger.warning(
            "schema_registry.add_missing_columns: PRAGMA table_info(%s) failed: %s",
            table,
            exc,
        )
        return []

    existing = {row[1].lower() for row in pragma_rows}  # row[1] = name
    added: List[str] = []

    for col_name, col_type in expected_cols.items():
        if col_name.lower() not in existing:
            try:
                conn.execute(
                    f"ALTER TABLE {table} ADD COLUMN {col_name} {col_type}"  # noqa: S608
                )
                conn.commit()
                added.append(col_name)
                logger.info(
                    "schema_registry: added column '%s %s' to table '%s'",
                    col_name,
                    col_type,
                    table,
                )
            except sqlite3.Error as exc:
                logger.warning(
                    "schema_registry: ALTER TABLE %s ADD COLUMN %s failed: %s",
                    table,
                    col_name,
                    exc,
                )

    return added


def get_registered() -> Dict[str, Tuple[str, Dict[str, str]]]:
    """Return a read-only snapshot of the current registry."""
    with _lock:
        return dict(_registry)


def clear_registry() -> None:
    """
    Remove all registered schemas.  Intended for test isolation only —
    do NOT call in production code.
    """
    with _lock:
        _registry.clear()


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_CREATE_RE = None


def _parse_table_name(create_sql: str) -> str | None:
    """Extract the table name from a CREATE TABLE [IF NOT EXISTS] statement."""
    import re as _re
    global _CREATE_RE
    if _CREATE_RE is None:
        _CREATE_RE = _re.compile(
            r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`'\"]?(\w+)[`'\"]?",
            _re.IGNORECASE,
        )
    m = _CREATE_RE.search(create_sql)
    return m.group(1) if m else None
