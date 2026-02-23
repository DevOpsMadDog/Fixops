"""
SQLite-backed persistent dictionary.

Drop-in replacement for ``dict`` that survives process restarts.
All values are JSON-serialised.  An in-memory cache keeps read
performance identical to a plain dict.

Usage::

    from core.persistent_store import PersistentDict

    _jobs = PersistentDict("bulk_jobs")
    _jobs["abc"] = {"status": "pending"}   # auto-persisted
    _jobs["abc"]["status"] = "running"     # in-place mutation – NOT auto-persisted
    _jobs.persist("abc")                   # explicit flush after mutation
"""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, Optional, Tuple

_DEFAULT_DB = "data/state.db"


class PersistentDict:
    """Dict-like object backed by a single SQLite table."""

    def __init__(self, table: str, db_path: str = _DEFAULT_DB) -> None:
        self._table = table
        self._db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init_table()
        self._cache: Dict[str, Any] = {}
        self._load_all()

    # -- SQLite helpers -------------------------------------------------------

    def _conn(self) -> sqlite3.Connection:
        return sqlite3.connect(self._db_path)

    def _init_table(self) -> None:
        with self._conn() as conn:
            conn.execute(
                f"CREATE TABLE IF NOT EXISTS [{self._table}] "
                "(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )

    def _load_all(self) -> None:
        with self._conn() as conn:
            for key, raw in conn.execute(f"SELECT key, value FROM [{self._table}]"):
                self._cache[key] = json.loads(raw)

    def _write(self, key: str, value: Any) -> None:
        with self._conn() as conn:
            conn.execute(
                f"INSERT OR REPLACE INTO [{self._table}] (key, value) VALUES (?, ?)",
                (key, json.dumps(value, default=str)),
            )

    def _delete(self, key: str) -> None:
        with self._conn() as conn:
            conn.execute(f"DELETE FROM [{self._table}] WHERE key = ?", (key,))

    # -- dict interface -------------------------------------------------------

    def __getitem__(self, key: str) -> Any:
        return self._cache[key]

    def __setitem__(self, key: str, value: Any) -> None:
        self._cache[key] = value
        self._write(key, value)

    def __delitem__(self, key: str) -> None:
        del self._cache[key]
        self._delete(key)

    def __contains__(self, key: object) -> bool:
        return key in self._cache

    def __len__(self) -> int:
        return len(self._cache)

    def __iter__(self) -> Iterator[str]:
        return iter(self._cache)

    def __bool__(self) -> bool:
        return bool(self._cache)

    def get(self, key: str, default: Any = None) -> Any:
        return self._cache.get(key, default)

    def pop(self, key: str, *args: Any) -> Any:
        result = self._cache.pop(key, *args)
        self._delete(key)
        return result

    def setdefault(self, key: str, default: Any = None) -> Any:
        if key not in self._cache:
            self[key] = default
        return self._cache[key]

    def keys(self):  # noqa: ANN201
        return self._cache.keys()

    def values(self):  # noqa: ANN201
        return self._cache.values()

    def items(self):  # noqa: ANN201
        return self._cache.items()

    # -- mutation helper ------------------------------------------------------

    def persist(self, key: str) -> None:
        """Flush a key to disk after in-place mutation of its value."""
        if key in self._cache:
            self._write(key, self._cache[key])

    def persist_all(self) -> None:
        """Flush every cached key to disk."""
        with self._conn() as conn:
            for key, value in self._cache.items():
                conn.execute(
                    f"INSERT OR REPLACE INTO [{self._table}] (key, value) VALUES (?, ?)",
                    (key, json.dumps(value, default=str)),
                )
