"""Local File Store API Router — ALDECI platform blob store.

Serves the UI's LocalFileStoreDashboard at prefix /api/v1/local-file-store.
Backs onto a real configurable directory (FIXOPS_LOCAL_FILE_STORE_DIR env var,
default ./data/file_store) — never fabricates files.

Endpoints:
  GET /api/v1/local-file-store/stats   — real counts + total bytes from disk
  GET /api/v1/local-file-store/list    — real file inventory (name, size, mtime, sha256, kind)
  GET /api/v1/local-file-store/config  — store configuration (path, quota, settings)

Design:
  - FIXOPS_LOCAL_FILE_STORE_DIR   — override store root (absolute or relative to cwd)
  - FIXOPS_LOCAL_FILE_STORE_QUOTA — quota in bytes (default 10 GiB)
  - If the directory doesn't exist or is empty, returns honest empty/zero results.
  - SHA-256 is computed lazily only for files <= _SHA256_MAX_BYTES to avoid
    blocking on huge scan artifacts.  Files above that threshold get sha256=null.
  - Kind is inferred from file extension (sbom, report, attestation, evidence,
    archive, json, blob).
"""
from __future__ import annotations

import hashlib
import logging
import os
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from apps.api.auth_deps import api_key_auth
from fastapi import APIRouter, Depends, HTTPException

_logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_DEFAULT_STORE_SUBDIR = "data/file_store"
_DEFAULT_QUOTA_BYTES = 10 * 1024 * 1024 * 1024  # 10 GiB
_SHA256_MAX_BYTES = 10 * 1024 * 1024  # 10 MiB — skip hash above this

# Extension → semantic kind mapping
_EXT_KIND: Dict[str, str] = {
    ".json": "json",
    ".jsonl": "json",
    ".xml": "xml",
    ".sarif": "sarif",
    ".sbom": "sbom",
    ".cdx": "sbom",
    ".spdx": "sbom",
    ".pdf": "report",
    ".html": "report",
    ".htm": "report",
    ".zip": "archive",
    ".tar": "archive",
    ".gz": "archive",
    ".tgz": "archive",
    ".bz2": "archive",
    ".xz": "archive",
    ".attest": "attestation",
    ".sig": "attestation",
    ".pem": "attestation",
    ".evidence": "evidence",
    ".evt": "evidence",
    ".log": "log",
    ".txt": "text",
    ".csv": "csv",
    ".yaml": "yaml",
    ".yml": "yaml",
}


def _store_root() -> Path:
    """Return the configured store root directory (may not exist)."""
    raw = os.environ.get("FIXOPS_LOCAL_FILE_STORE_DIR", "").strip()
    if raw:
        p = Path(raw)
        if not p.is_absolute():
            p = Path.cwd() / p
        return p.resolve()
    # Default: <repo_root>/data/file_store
    # Walk up from this file to find the repo root (contains suite-api/)
    here = Path(__file__).resolve()
    for parent in here.parents:
        if (parent / "suite-api").exists():
            return parent / _DEFAULT_STORE_SUBDIR
    return Path.cwd() / _DEFAULT_STORE_SUBDIR


def _quota_bytes() -> int:
    raw = os.environ.get("FIXOPS_LOCAL_FILE_STORE_QUOTA", "").strip()
    if raw:
        try:
            return int(raw)
        except ValueError:
            pass
    return _DEFAULT_QUOTA_BYTES


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utc_iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def _kind_from_path(p: Path) -> str:
    return _EXT_KIND.get(p.suffix.lower(), "blob")


def _sha256_of(p: Path, max_bytes: int = _SHA256_MAX_BYTES) -> Optional[str]:
    """Return hex SHA-256 of file, or None if file is too large or unreadable."""
    try:
        size = p.stat().st_size
    except OSError:
        return None
    if size > max_bytes:
        return None
    try:
        h = hashlib.sha256()
        with p.open("rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return None


def _scan_store(root: Path) -> List[Dict[str, Any]]:
    """Walk root and return one dict per file (never raises)."""
    if not root.exists() or not root.is_dir():
        return []
    entries: List[Dict[str, Any]] = []
    try:
        for dirpath_s, _dirs, filenames in os.walk(root):
            dirpath = Path(dirpath_s)
            for fname in sorted(filenames):
                fp = dirpath / fname
                try:
                    st = fp.stat()
                except OSError:
                    continue
                rel = fp.relative_to(root)
                entries.append(
                    {
                        "id": str(rel),
                        "path": str(rel),
                        "name": fp.name,
                        "size_bytes": st.st_size,
                        "sha256": _sha256_of(fp),
                        "kind": _kind_from_path(fp),
                        "created_at": _utc_iso(st.st_ctime),
                        "modified_at": _utc_iso(st.st_mtime),
                    }
                )
    except OSError as exc:
        _logger.warning("local_file_store_api: scan error: %s", exc)
    return entries


# ---------------------------------------------------------------------------
# Router
# ---------------------------------------------------------------------------

router = APIRouter(
    prefix="/api/v1/local-file-store",
    tags=["Local File Store API"],
)


@router.get("/stats", dependencies=[Depends(api_key_auth)])
def get_stats() -> Dict[str, Any]:
    """Real storage statistics — counts and bytes from disk scan."""
    root = _store_root()
    quota = _quota_bytes()

    if not root.exists() or not root.is_dir():
        return {
            "total_files": 0,
            "total_size_bytes": 0,
            "used_pct": 0.0,
            "quota_bytes": quota,
            "oldest": None,
            "latest": None,
        }

    entries = _scan_store(root)
    total_files = len(entries)
    total_bytes = sum(e["size_bytes"] for e in entries)
    used_pct = round((total_bytes / quota) * 100, 2) if quota > 0 else 0.0

    created_times = [e["created_at"] for e in entries if e.get("created_at")]
    oldest = min(created_times) if created_times else None
    latest_ts = max(created_times) if created_times else None

    return {
        "total_files": total_files,
        "total_size_bytes": total_bytes,
        "used_pct": used_pct,
        "quota_bytes": quota,
        "oldest": oldest,
        "latest": latest_ts,
    }


@router.get("/list", dependencies=[Depends(api_key_auth)])
def list_files() -> List[Dict[str, Any]]:
    """Real file inventory — name, size, mtime, sha256, kind.

    Returns an empty list if the store directory doesn't exist or is empty.
    Never returns fabricated entries.
    """
    root = _store_root()
    return _scan_store(root)


@router.get("/config", dependencies=[Depends(api_key_auth)])
def get_config() -> Dict[str, Any]:
    """Store configuration — root path, quota, and settings read from env."""
    root = _store_root()
    quota = _quota_bytes()
    return {
        "root_path": str(root),
        "max_size_bytes": quota,
        "encryption": os.environ.get("FIXOPS_LOCAL_FILE_STORE_ENCRYPTION", "none"),
        "retention_days": _safe_int(
            os.environ.get("FIXOPS_LOCAL_FILE_STORE_RETENTION_DAYS"), default=None
        ),
        "compression": os.environ.get("FIXOPS_LOCAL_FILE_STORE_COMPRESSION", "").lower()
        in ("1", "true", "yes"),
        "replicas": _safe_int(
            os.environ.get("FIXOPS_LOCAL_FILE_STORE_REPLICAS"), default=1
        ),
    }


# ---------------------------------------------------------------------------
# Misc helpers
# ---------------------------------------------------------------------------

def _safe_int(val: Optional[str], default: Any = None) -> Any:
    if val is None:
        return default
    try:
        return int(val)
    except (ValueError, TypeError):
        return default
