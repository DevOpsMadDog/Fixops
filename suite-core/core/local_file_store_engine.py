"""Local File Store Engine — ALDECI (GAP-064).

Zero-infrastructure `.fixops/` local JSON store. Enables `npx fixops analyze`
to run against a repository without Postgres, Redis, or any running server.

Design constraints:
  - **Single-user, single-host**: no org_id, no multi-tenant logic.
  - **Atomic writes**: every payload is written to `.tmp-<uuid>` then
    `os.rename()`d into place. POSIX `rename` is atomic within the same
    filesystem, so a crash mid-write never leaves a half-file at the target.
  - **Exclusive lock**: a `.analyze.lock` file is created with
    ``os.O_WRONLY | os.O_CREAT | os.O_EXCL``. A second acquire attempt on the
    same repo fails fast (not blocks). Callers may supply a ``timeout`` in
    seconds to retry acquisition.
  - **Crash-safe**: if a previous run crashed mid-write, a stray `.tmp-*`
    file may remain. These are ignored (never committed as LATEST).

Schema on disk (all relative to ``<repo>/.fixops/``):
  - ``LATEST.json``                     – symlink-style pointer, full payload
  - ``analyses/<iso>_<uuid>.json``      – immutable per-run archives
  - ``history.json``                    – ordered list of analysis descriptors
  - ``config.json``                     – local CLI config (target, excludes…)
  - ``.analyze.lock``                   – O_EXCL mutex while a run is active

Public API:
  acquire_lock(repo_path, timeout=30) -> Dict[str, Any]
  release_lock(repo_path)             -> bool
  save_analysis(repo_path, payload)   -> Dict[str, Any]
  get_latest(repo_path)               -> Optional[Dict[str, Any]]
  list_history(repo_path, limit=50)   -> List[Dict[str, Any]]
  read_config(repo_path)              -> Dict[str, Any]
  write_config(repo_path, config)     -> Dict[str, Any]
  clear_store(repo_path)              -> int
"""
from __future__ import annotations

# ---------------------------------------------------------------------------
# TrustGraph second-brain wiring
# ---------------------------------------------------------------------------
try:  # pragma: no cover - optional dependency
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:  # noqa: BLE001
    _get_tg_bus = None  # type: ignore[assignment]


def _emit_event(event_type: str, payload: dict) -> None:
    """Emit to TrustGraph event bus. Never raises."""
    if _get_tg_bus is None:
        return
    try:
        bus = _get_tg_bus()
        if bus is None:
            return
        emit = getattr(bus, "emit", None) or getattr(bus, "publish", None)
        if emit is None:
            return
        result = emit(event_type, payload)
        try:
            import asyncio as _aio
            import inspect as _insp
            if _insp.iscoroutine(result):
                try:
                    loop = _aio.get_running_loop()
                    loop.create_task(result)
                except RuntimeError:
                    result.close()
        except Exception:  # pragma: no cover
            pass
    except Exception:  # pragma: no cover
        pass


try:  # pragma: no cover
    _emit_event("engine.loaded", {"module": __name__})
except Exception:  # noqa: BLE001
    pass


import json
import logging
import os
import shutil
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except ImportError:  # pragma: no cover - bus optional
    _get_tg_bus = None


_logger = logging.getLogger(__name__)

_STORE_DIRNAME = ".fixops"
_ANALYSES_DIRNAME = "analyses"
_LATEST_FILE = "LATEST.json"
_HISTORY_FILE = "history.json"
_CONFIG_FILE = "config.json"
_LOCK_FILE = ".analyze.lock"
_TMP_PREFIX = ".tmp-"

_DEFAULT_LOCK_TIMEOUT = 30
_DEFAULT_HISTORY_LIMIT = 50
_MAX_HISTORY_LIMIT = 1000
_LOCK_STALE_SECS = 3600  # 1 hour — a lock older than this is considered stale


def _now_iso() -> str:
    """Current UTC time as ISO-8601 string."""
    return datetime.now(timezone.utc).isoformat()


def _safe_iso_filename(ts: str) -> str:
    """Turn an ISO timestamp into a filesystem-safe filename fragment."""
    return ts.replace(":", "-").replace(".", "-").replace("+", "-")


class LocalFileStoreError(RuntimeError):
    """Base exception for the local file store."""


class LockAcquireError(LocalFileStoreError):
    """Raised when the analyze lock cannot be acquired within the timeout."""


class LockNotHeldError(LocalFileStoreError):
    """Raised when release is called without a matching acquire."""


class LocalFileStoreEngine:
    """Zero-infra `.fixops/` local JSON store for single-user CLI usage.

    The engine is a thin wrapper over POSIX primitives (``os.open(O_EXCL)``
    + ``os.rename``). It is re-entrant within a process thanks to the
    in-memory ``_lock_registry`` that tracks locks owned by this process —
    a second ``acquire_lock`` call from the same interpreter honors the
    timeout semantics and doesn't block forever on its own lock file.

    All methods accept a ``repo_path`` (str or Path). The `.fixops/` subtree
    is created on demand; callers never have to mkdir anything.
    """

    # Map of absolute lock-file path -> (owner_token, acquired_at_monotonic)
    _lock_registry: Dict[str, Dict[str, Any]] = {}
    _registry_lock = threading.Lock()

    # ------------------------------------------------------------------
    # Path helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _store_dir(repo_path: Any) -> Path:
        root = Path(repo_path).expanduser().resolve()
        return root / _STORE_DIRNAME

    def _ensure_store(self, repo_path: Any) -> Path:
        store = self._store_dir(repo_path)
        store.mkdir(parents=True, exist_ok=True)
        (store / _ANALYSES_DIRNAME).mkdir(parents=True, exist_ok=True)
        return store

    def _lock_path(self, repo_path: Any) -> Path:
        return self._store_dir(repo_path) / _LOCK_FILE

    def _latest_path(self, repo_path: Any) -> Path:
        return self._store_dir(repo_path) / _LATEST_FILE

    def _history_path(self, repo_path: Any) -> Path:
        return self._store_dir(repo_path) / _HISTORY_FILE

    def _config_path(self, repo_path: Any) -> Path:
        return self._store_dir(repo_path) / _CONFIG_FILE

    def _analyses_dir(self, repo_path: Any) -> Path:
        return self._store_dir(repo_path) / _ANALYSES_DIRNAME

    # ------------------------------------------------------------------
    # Atomic write primitive
    # ------------------------------------------------------------------

    @staticmethod
    def _atomic_write_json(target: Path, payload: Any) -> None:
        """Write ``payload`` as JSON to ``target`` atomically.

        Implementation: write to ``<target>.tmp-<uuid>`` first, fsync,
        then ``os.rename`` to the destination. POSIX guarantees rename is
        atomic within a filesystem — readers will either see the old file
        or the new file, never a truncated half-write.
        """
        target.parent.mkdir(parents=True, exist_ok=True)
        tmp_name = f"{target.name}{_TMP_PREFIX}{uuid.uuid4().hex}"
        tmp_path = target.parent / tmp_name
        serialized = json.dumps(payload, indent=2, default=str, sort_keys=False)
        # Use low-level os.open so we control fsync before rename
        fd = os.open(
            str(tmp_path),
            os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
            0o600,
        )
        try:
            os.write(fd, serialized.encode("utf-8"))
            os.fsync(fd)
        finally:
            os.close(fd)
        os.rename(str(tmp_path), str(target))

    @staticmethod
    def _read_json(target: Path) -> Optional[Dict[str, Any]]:
        """Read JSON from ``target`` — returns None if missing or corrupt."""
        if not target.exists():
            return None
        try:
            with target.open("r", encoding="utf-8") as fh:
                data = json.load(fh)
            if not isinstance(data, (dict, list)):
                return None
            return data  # type: ignore[return-value]
        except (json.JSONDecodeError, OSError) as exc:
            _logger.warning("local_file_store: corrupt file %s (%s)", target, exc)
            return None

    # ------------------------------------------------------------------
    # Lock
    # ------------------------------------------------------------------

    def acquire_lock(
        self,
        repo_path: Any,
        timeout: float = _DEFAULT_LOCK_TIMEOUT,
    ) -> Dict[str, Any]:
        """Acquire an exclusive lock on ``repo_path/.fixops/.analyze.lock``.

        Uses ``os.O_WRONLY | os.O_CREAT | os.O_EXCL`` so concurrent callers
        will see ``FileExistsError`` — which we translate to a fast retry
        loop until ``timeout`` expires.

        Returns the owner descriptor (with ``owner_token``, ``acquired_at``,
        ``lock_path``, ``pid``). Callers MUST pass the ``owner_token`` back
        to ``release_lock`` to avoid releasing someone else's lock.

        Stale locks (older than :data:`_LOCK_STALE_SECS`) are considered
        abandoned and stolen — this prevents a crashed previous run from
        holding the lock forever.
        """
        if timeout < 0:
            raise ValueError("timeout must be >= 0")
        self._ensure_store(repo_path)
        lock_path = self._lock_path(repo_path)
        deadline = time.monotonic() + float(timeout)

        # Try up to every 0.1s
        attempt = 0
        while True:
            attempt += 1
            try:
                fd = os.open(
                    str(lock_path),
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                    0o600,
                )
            except FileExistsError:
                # Check for stale lock we can steal
                if self._try_steal_stale_lock(lock_path):
                    continue
                if time.monotonic() >= deadline:
                    raise LockAcquireError(
                        f"Could not acquire {_LOCK_FILE} on "
                        f"{repo_path} within {timeout}s "
                        f"(attempt={attempt})"
                    )
                time.sleep(0.1)
                continue
            except OSError as exc:  # pragma: no cover — disk full etc.
                raise LocalFileStoreError(f"lock acquire failed: {exc}") from exc

            # We own the lock — write owner metadata
            owner_token = uuid.uuid4().hex
            acquired_at = _now_iso()
            meta = {
                "owner_token": owner_token,
                "pid": os.getpid(),
                "acquired_at": acquired_at,
                "lock_path": str(lock_path),
            }
            try:
                os.write(fd, json.dumps(meta).encode("utf-8"))
                os.fsync(fd)
            finally:
                os.close(fd)

            with self._registry_lock:
                self._lock_registry[str(lock_path)] = {
                    "owner_token": owner_token,
                    "acquired_at_mono": time.monotonic(),
                }
            return meta

    def _try_steal_stale_lock(self, lock_path: Path) -> bool:
        """If the lock on disk is older than _LOCK_STALE_SECS, remove it."""
        try:
            st = lock_path.stat()
        except FileNotFoundError:
            return True  # gone already — caller can retry immediately
        except OSError:
            return False
        age = time.time() - st.st_mtime
        if age < _LOCK_STALE_SECS:
            return False
        try:
            lock_path.unlink()
            _logger.warning(
                "local_file_store: stole stale lock %s (age=%.0fs)", lock_path, age
            )
            return True
        except FileNotFoundError:
            return True
        except OSError:
            return False

    def release_lock(
        self,
        repo_path: Any,
        owner_token: Optional[str] = None,
    ) -> bool:
        """Release the analyze lock for ``repo_path``.

        If ``owner_token`` is supplied, the lock is only released if the
        on-disk token matches — protecting against a later process clobbering
        a different owner's lock. If not supplied, the lock is force-released.

        Returns True on success. Raises :class:`LockNotHeldError` when the
        lock file doesn't exist at all.
        """
        lock_path = self._lock_path(repo_path)
        if not lock_path.exists():
            raise LockNotHeldError(f"No lock held on {lock_path}")

        if owner_token is not None:
            disk_meta = self._read_json(lock_path) or {}
            disk_token = (disk_meta or {}).get("owner_token")
            if disk_token and disk_token != owner_token:
                raise LockNotHeldError(
                    "Refusing to release lock owned by a different token"
                )

        try:
            lock_path.unlink()
        except FileNotFoundError:
            raise LockNotHeldError(f"Lock vanished under us: {lock_path}")
        except OSError as exc:
            raise LocalFileStoreError(f"lock release failed: {exc}") from exc

        with self._registry_lock:
            self._lock_registry.pop(str(lock_path), None)
        return True

    # ------------------------------------------------------------------
    # Analysis persistence
    # ------------------------------------------------------------------

    def save_analysis(
        self,
        repo_path: Any,
        payload: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Save an analysis run atomically.

        Side effects (all atomic):
          1. ``analyses/<iso>_<uuid>.json`` – immutable archive
          2. ``LATEST.json``              – pointer to newest full payload
          3. ``history.json``             – prepended descriptor (id, iso, summary)

        Returns a descriptor ``{id, iso, path, stored_at}`` without the
        full payload so callers can reference without double-copy.
        """
        if not isinstance(payload, dict):
            raise ValueError("payload must be a dict")
        self._ensure_store(repo_path)
        analysis_id = uuid.uuid4().hex
        iso = _now_iso()

        # Merge in ALDECI-managed metadata — do not let callers override id/iso
        enriched = dict(payload)
        enriched["id"] = analysis_id
        enriched["iso"] = iso
        enriched["stored_at"] = iso

        archive_name = f"{_safe_iso_filename(iso)}_{analysis_id}.json"
        archive_path = self._analyses_dir(repo_path) / archive_name
        self._atomic_write_json(archive_path, enriched)

        # LATEST points at the enriched full payload
        self._atomic_write_json(self._latest_path(repo_path), enriched)

        # History — prepended
        descriptor: Dict[str, Any] = {
            "id": analysis_id,
            "iso": iso,
            "path": str(archive_path.relative_to(self._store_dir(repo_path))),
            "summary": payload.get("summary") or {},
        }
        self._prepend_history(repo_path, descriptor)
        result = {
            "id": analysis_id,
            "iso": iso,
            "path": str(archive_path),
            "stored_at": iso,
        }
        self._emit_event(
            "fixops_local.analysis.saved",
            {
                "analysis_id": analysis_id,
                "iso": iso,
                "repo_path": str(repo_path),
                "summary_keys": list((payload.get("summary") or {}).keys()),
            },
        )
        return result

    def _prepend_history(
        self,
        repo_path: Any,
        descriptor: Dict[str, Any],
    ) -> None:
        """Read history.json, prepend descriptor, rewrite atomically."""
        history_path = self._history_path(repo_path)
        current = self._read_json(history_path)
        items: List[Dict[str, Any]]
        if isinstance(current, list):
            items = current
        elif isinstance(current, dict) and "items" in current:
            items = list(current["items"])
        else:
            items = []
        items.insert(0, descriptor)
        # Cap history at MAX so the file never grows unbounded
        if len(items) > _MAX_HISTORY_LIMIT:
            items = items[:_MAX_HISTORY_LIMIT]
        self._atomic_write_json(history_path, {"items": items, "updated_at": _now_iso()})

    def get_latest(self, repo_path: Any) -> Optional[Dict[str, Any]]:
        """Return the latest analysis payload, or None if none exists."""
        latest = self._read_json(self._latest_path(repo_path))
        if not isinstance(latest, dict):
            return None
        return latest

    def list_history(
        self,
        repo_path: Any,
        limit: int = _DEFAULT_HISTORY_LIMIT,
    ) -> List[Dict[str, Any]]:
        """Return up to ``limit`` history descriptors, newest-first."""
        if limit <= 0:
            limit = _DEFAULT_HISTORY_LIMIT
        if limit > _MAX_HISTORY_LIMIT:
            limit = _MAX_HISTORY_LIMIT
        history = self._read_json(self._history_path(repo_path))
        if isinstance(history, list):
            items = history
        elif isinstance(history, dict):
            items = history.get("items") or []
        else:
            items = []
        if not isinstance(items, list):
            return []
        return list(items[:limit])

    # ------------------------------------------------------------------
    # Config
    # ------------------------------------------------------------------

    def read_config(self, repo_path: Any) -> Dict[str, Any]:
        """Read config.json — returns empty dict if missing."""
        cfg = self._read_json(self._config_path(repo_path))
        if isinstance(cfg, dict):
            return cfg
        return {}

    def write_config(
        self,
        repo_path: Any,
        config: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Write config.json atomically. Returns the stored object.

        Writes are idempotent — writing the same config twice produces the
        same on-disk bytes (modulo ``updated_at``).
        """
        if not isinstance(config, dict):
            raise ValueError("config must be a dict")
        self._ensure_store(repo_path)
        enriched = dict(config)
        enriched["updated_at"] = _now_iso()
        self._atomic_write_json(self._config_path(repo_path), enriched)
        return enriched

    # ------------------------------------------------------------------
    # Clear
    # ------------------------------------------------------------------

    def clear_store(self, repo_path: Any) -> int:
        """Remove the entire ``.fixops/`` subtree. Returns files deleted."""
        store = self._store_dir(repo_path)
        if not store.exists():
            return 0

        # Count files before delete (one file = one deletion for reporting)
        count = 0
        for dirpath, _dirs, files in os.walk(store):
            count += len(files)
        shutil.rmtree(store, ignore_errors=False)

        # Flush in-memory lock registry for that store
        lock_path = str(self._lock_path(repo_path))
        with self._registry_lock:
            self._lock_registry.pop(lock_path, None)
        return count

    # ------------------------------------------------------------------
    # TrustGraph event emission (best-effort, non-blocking)
    # ------------------------------------------------------------------

    def _emit_event(self, event_type: str, payload: "dict[str, Any]") -> None:
        """Emit an event to the TrustGraph event bus. Never raises."""
        if _get_tg_bus is None:
            return
        try:
            bus = _get_tg_bus()
            if bus is None:
                return
            emit = getattr(bus, "emit", None) or getattr(bus, "publish", None)
            if emit is None:
                return
            result = emit(event_type, payload)
            try:
                import asyncio
                import inspect
                if inspect.iscoroutine(result):
                    try:
                        loop = asyncio.get_running_loop()
                        loop.create_task(result)
                    except RuntimeError:
                        result.close()
            except Exception:  # pragma: no cover
                pass
        except Exception:  # pragma: no cover - best-effort telemetry
            pass




# Module-level singleton (CLI convenience)
_singleton: Optional[LocalFileStoreEngine] = None
_singleton_lock = threading.Lock()


def get_engine() -> LocalFileStoreEngine:
    """Return the process-wide LocalFileStoreEngine singleton."""
    global _singleton
    if _singleton is None:
        with _singleton_lock:
            if _singleton is None:
                _singleton = LocalFileStoreEngine()
    return _singleton
