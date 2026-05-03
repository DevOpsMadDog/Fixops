"""
GreyNoise Threat-Intel Lookup Engine — ALDECI.

Wraps the GreyNoise REST APIs and provides a process-wide singleton plus a
SQLite-backed response cache.

Endpoint coverage
-----------------
* Community v3   (/v3/community/{ip})            — usable on the free tier
* Context  v2    (/v2/noise/context/{ip})        — paid tier only
* RIOT     v2    (/v2/riot/{ip})                  — paid tier only

Cache schema
------------
    greynoise_cache (
        cache_key      TEXT PRIMARY KEY,   -- "<query_type>:<canonical-params>"
        query_type     TEXT NOT NULL,       -- community | context | riot
        params_json    TEXT NOT NULL,       -- JSON-encoded request params
        response_json  TEXT NOT NULL,       -- JSON-encoded normalized response
        fetched_at     TEXT NOT NULL,       -- ISO-8601 timestamp
        expires_at     TEXT NOT NULL        -- ISO-8601 timestamp
    )

TTLs:  community=1h  context=6h  riot=24h.

NO MOCKS rule
-------------
* GREYNOISE_API_KEY env unset:
    - community endpoint still works against the GreyNoise public community tier
      (it is rate-limited but does not require auth).
    - context + riot endpoints raise GreyNoiseUnavailableError (router → HTTP 503).
* Capability summary surfaces ``status="unavailable"`` when the key is missing,
  ``"empty"`` when key present but cache is empty, and ``"ok"`` otherwise.
* No fabricated payloads — every cached response was actually returned by GreyNoise.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Optional

import httpx

_logger = logging.getLogger(__name__)

GREYNOISE_API_BASE = "https://api.greynoise.io"
DEFAULT_TIMEOUT_SECONDS = 8.0

# Cache TTLs (seconds)
_TTL_COMMUNITY = 1 * 3600       # 1 hour
_TTL_CONTEXT = 6 * 3600          # 6 hours
_TTL_RIOT = 24 * 3600            # 24 hours


class GreyNoiseUnavailableError(RuntimeError):
    """Raised when GreyNoise API key is missing, network failed, or the upstream
    returned an unrecoverable status."""


class GreyNoiseLookupEngine:
    """Thread-safe GreyNoise REST client with sqlite response cache."""

    def __init__(
        self,
        db_path: Optional[str] = None,
        api_key: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        # Resolve DB path
        if db_path is None:
            base = Path(os.environ.get("FIXOPS_DATA_DIR", "data")) / "security"
            base.mkdir(parents=True, exist_ok=True)
            db_path = str(base / "greynoise_cache.db")
        self._db_path = db_path
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)

        # Explicit api_key wins over env (re-read each call so tests can monkeypatch).
        self._explicit_api_key = api_key

        # HTTP client
        self._client = client or httpx.Client(timeout=timeout)
        self._owns_client = client is None
        self._timeout = timeout

        self._lock = threading.RLock()
        self._init_db()

    # --------------------------------------------------------------- db

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=30, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS greynoise_cache (
                    cache_key      TEXT PRIMARY KEY,
                    query_type     TEXT NOT NULL,
                    params_json    TEXT NOT NULL,
                    response_json  TEXT NOT NULL,
                    fetched_at     TEXT NOT NULL,
                    expires_at     TEXT NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_greynoise_cache_expires "
                "ON greynoise_cache(expires_at)"
            )
            conn.commit()

    # ----------------------------------------------------------- helpers

    def _api_key(self) -> Optional[str]:
        if self._explicit_api_key:
            return self._explicit_api_key
        v = os.environ.get("GREYNOISE_API_KEY")
        return v or None

    def api_key_present(self) -> bool:
        return bool(self._api_key())

    def cache_size(self) -> int:
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS n FROM greynoise_cache").fetchone()
            return int(row["n"]) if row else 0

    def _cache_get(self, key: str) -> Optional[Dict[str, Any]]:
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT response_json FROM greynoise_cache "
                "WHERE cache_key = ? AND expires_at > ?",
                (key, now),
            ).fetchone()
            if row is None:
                return None
            try:
                return json.loads(row["response_json"])
            except json.JSONDecodeError:
                return None

    def _cache_put(
        self,
        key: str,
        query_type: str,
        params: Dict[str, Any],
        response: Dict[str, Any],
        ttl_seconds: int,
    ) -> None:
        now = datetime.now(timezone.utc)
        expires = now + timedelta(seconds=ttl_seconds)
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO greynoise_cache (cache_key, query_type, params_json,
                    response_json, fetched_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(cache_key) DO UPDATE SET
                    response_json = excluded.response_json,
                    fetched_at = excluded.fetched_at,
                    expires_at = excluded.expires_at
                """,
                (
                    key,
                    query_type,
                    json.dumps(params, sort_keys=True),
                    json.dumps(response),
                    now.isoformat(),
                    expires.isoformat(),
                ),
            )
            conn.commit()

    def _request(
        self,
        path: str,
        require_key: bool,
    ) -> Dict[str, Any]:
        api_key = self._api_key()
        if require_key and not api_key:
            raise GreyNoiseUnavailableError(
                "GREYNOISE_API_KEY is not configured (paid endpoint requires auth)"
            )
        headers: Dict[str, str] = {"Accept": "application/json"}
        if api_key:
            headers["key"] = api_key
        url = f"{GREYNOISE_API_BASE}{path}"
        try:
            resp = self._client.get(url, headers=headers)
        except httpx.HTTPError as exc:
            raise GreyNoiseUnavailableError(
                f"GreyNoise request failed: {exc}"
            ) from exc
        if resp.status_code in (401, 403):
            raise GreyNoiseUnavailableError(
                f"GreyNoise rejected credentials (HTTP {resp.status_code})"
            )
        if resp.status_code == 404:
            # Community endpoint surfaces 404 as "unknown" — caller decides.
            try:
                return resp.json()
            except ValueError:
                raise GreyNoiseUnavailableError(
                    "GreyNoise returned 404 with non-JSON body"
                )
        if resp.status_code == 429:
            raise GreyNoiseUnavailableError(
                "GreyNoise rate-limit exceeded (HTTP 429)"
            )
        if resp.status_code >= 400:
            raise GreyNoiseUnavailableError(
                f"GreyNoise returned HTTP {resp.status_code}: {resp.text[:200]}"
            )
        try:
            return resp.json()
        except ValueError as exc:
            raise GreyNoiseUnavailableError(
                f"GreyNoise returned non-JSON response: {exc}"
            ) from exc

    # ----------------------------------------------------------- lookups

    def community(self, ip: str) -> Dict[str, Any]:
        """GreyNoise Community v3 — free tier, key optional."""
        if not ip:
            raise ValueError("ip must not be empty")
        cache_key = f"community:{ip}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached
        raw = self._request(f"/v3/community/{ip}", require_key=False)
        normalized = self._normalize_community(ip, raw)
        self._cache_put(
            cache_key, "community", {"ip": ip}, normalized, _TTL_COMMUNITY
        )
        return normalized

    def context(self, ip: str) -> Dict[str, Any]:
        """GreyNoise Context v2 — paid tier, key required."""
        if not ip:
            raise ValueError("ip must not be empty")
        cache_key = f"context:{ip}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached
        raw = self._request(f"/v2/noise/context/{ip}", require_key=True)
        normalized = self._normalize_context(ip, raw)
        self._cache_put(
            cache_key, "context", {"ip": ip}, normalized, _TTL_CONTEXT
        )
        return normalized

    def riot(self, ip: str) -> Dict[str, Any]:
        """GreyNoise RIOT v2 — paid tier, key required."""
        if not ip:
            raise ValueError("ip must not be empty")
        cache_key = f"riot:{ip}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached
        raw = self._request(f"/v2/riot/{ip}", require_key=True)
        normalized = self._normalize_riot(ip, raw)
        self._cache_put(cache_key, "riot", {"ip": ip}, normalized, _TTL_RIOT)
        return normalized

    # -------------------------------------------------------- normalize

    @staticmethod
    def _normalize_community(ip: str, raw: Dict[str, Any]) -> Dict[str, Any]:
        # Community v3 sample fields:
        #   { "ip": "...", "noise": bool, "riot": bool,
        #     "classification": "malicious|benign|unknown",
        #     "name": "...", "link": "...", "last_seen": "ISO8601",
        #     "message": "..." }
        if not isinstance(raw, dict):
            raw = {}
        return {
            "ip": raw.get("ip") or ip,
            "noise": bool(raw.get("noise", False)),
            "riot": bool(raw.get("riot", False)),
            "classification": raw.get("classification") or "unknown",
            "name": raw.get("name") or "",
            "link": raw.get("link") or "",
            "last_seen": raw.get("last_seen") or "",
            "message": raw.get("message") or "",
        }

    @staticmethod
    def _normalize_context(ip: str, raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        meta = raw.get("metadata") or {}
        raw_data = raw.get("raw_data") or {}
        return {
            "ip": raw.get("ip") or ip,
            "seen": bool(raw.get("seen", False)),
            "classification": raw.get("classification") or "unknown",
            "first_seen": raw.get("first_seen") or "",
            "last_seen": raw.get("last_seen") or "",
            "actor": raw.get("actor") or "",
            "tags": list(raw.get("tags") or []),
            "cve": list(raw.get("cve") or []),
            "asn": meta.get("asn") or raw.get("asn") or "",
            "organization": meta.get("organization") or raw.get("organization") or "",
            "raw_data": {
                "scan": list(raw_data.get("scan") or []),
                "web": raw_data.get("web") or {},
                "ja3": list(raw_data.get("ja3") or []),
            },
        }

    @staticmethod
    def _normalize_riot(ip: str, raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        return {
            "ip": raw.get("ip") or ip,
            "riot": bool(raw.get("riot", False)),
            "name": raw.get("name") or "",
            "category": raw.get("category") or "",
            "description": raw.get("description") or "",
            "explanation": raw.get("explanation") or "",
            "last_updated": raw.get("last_updated") or "",
            "reference": raw.get("reference") or "",
            "trust_level": raw.get("trust_level") or "",
        }

    # ----------------------------------------------------------- cleanup

    def close(self) -> None:
        if self._owns_client:
            try:
                self._client.close()
            except Exception:
                pass


# --------------------------------------------------------------- singleton

_singleton: Optional[GreyNoiseLookupEngine] = None
_singleton_lock = threading.Lock()


def get_greynoise_lookup_engine(
    db_path: Optional[str] = None,
    api_key: Optional[str] = None,
    client: Optional[httpx.Client] = None,
) -> GreyNoiseLookupEngine:
    """Return the process-wide GreyNoiseLookupEngine singleton."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = GreyNoiseLookupEngine(
                db_path=db_path, api_key=api_key, client=client
            )
        return _singleton


def reset_greynoise_lookup_engine() -> None:
    """Tear down the singleton — used by tests with tmp_path DBs."""
    global _singleton
    with _singleton_lock:
        if _singleton is not None:
            _singleton.close()
        _singleton = None


__all__ = [
    "GreyNoiseLookupEngine",
    "GreyNoiseUnavailableError",
    "get_greynoise_lookup_engine",
    "reset_greynoise_lookup_engine",
]
