"""
AbuseIPDB Threat-Intel Lookup Engine — ALDECI.

Wraps the AbuseIPDB v2 REST API (https://api.abuseipdb.com) and provides a
process-wide singleton plus a SQLite-backed response cache.

Endpoint coverage
-----------------
* /v2/check       (GET)  — IP reputation lookup (abuseConfidenceScore, etc.)
* /v2/blacklist   (GET)  — top-N abusive IPs (paid blacklist export)
* /v2/report      (POST) — submit an abuse report against an IP

Cache schema
------------
    abuseipdb_cache (
        cache_key      TEXT PRIMARY KEY,   -- "<query_type>:<canonical-params>"
        query_type     TEXT NOT NULL,       -- check | blacklist | report
        params_json    TEXT NOT NULL,       -- JSON-encoded request params
        response_json  TEXT NOT NULL,       -- JSON-encoded normalized response
        fetched_at     TEXT NOT NULL,       -- ISO-8601 timestamp
        expires_at     TEXT NOT NULL        -- ISO-8601 timestamp
    )

TTL: 6 hours for all query types (per task spec).

NO MOCKS rule
-------------
* ABUSEIPDB_API_KEY env unset:
    - All live endpoints raise AbuseIPDBUnavailableError (router → HTTP 503).
    - Capability summary surfaces ``status="unavailable"``.
* No fabricated payloads — every cached response was actually returned by AbuseIPDB.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

import httpx

_logger = logging.getLogger(__name__)

ABUSEIPDB_API_BASE = "https://api.abuseipdb.com"
DEFAULT_TIMEOUT_SECONDS = 8.0

# All query types share a 6-hour TTL per task spec.
_TTL_SECONDS = 6 * 3600


class AbuseIPDBUnavailableError(RuntimeError):
    """Raised when AbuseIPDB API key is missing, network failed, or upstream
    returned an unrecoverable status."""


class AbuseIPDBLookupEngine:
    """Thread-safe AbuseIPDB REST client with sqlite response cache."""

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
            db_path = str(base / "abuseipdb_cache.db")
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
                CREATE TABLE IF NOT EXISTS abuseipdb_cache (
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
                "CREATE INDEX IF NOT EXISTS idx_abuseipdb_cache_expires "
                "ON abuseipdb_cache(expires_at)"
            )
            conn.commit()

    # ----------------------------------------------------------- helpers

    def _api_key(self) -> Optional[str]:
        if self._explicit_api_key:
            return self._explicit_api_key
        v = os.environ.get("ABUSEIPDB_API_KEY")
        return v or None

    def api_key_present(self) -> bool:
        return bool(self._api_key())

    def cache_size(self) -> int:
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS n FROM abuseipdb_cache").fetchone()
            return int(row["n"]) if row else 0

    def _cache_get(self, key: str) -> Optional[Dict[str, Any]]:
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT response_json FROM abuseipdb_cache "
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
        ttl_seconds: int = _TTL_SECONDS,
    ) -> None:
        now = datetime.now(timezone.utc)
        expires = now + timedelta(seconds=ttl_seconds)
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                INSERT INTO abuseipdb_cache (cache_key, query_type, params_json,
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
        method: str,
        path: str,
        *,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        api_key = self._api_key()
        if not api_key:
            raise AbuseIPDBUnavailableError(
                "ABUSEIPDB_API_KEY is not configured"
            )
        headers: Dict[str, str] = {
            "Accept": "application/json",
            "Key": api_key,
        }
        url = f"{ABUSEIPDB_API_BASE}{path}"
        try:
            if method.upper() == "GET":
                resp = self._client.get(url, headers=headers, params=params)
            elif method.upper() == "POST":
                resp = self._client.post(url, headers=headers, data=data)
            else:
                raise AbuseIPDBUnavailableError(
                    f"unsupported HTTP method: {method}"
                )
        except httpx.HTTPError as exc:
            raise AbuseIPDBUnavailableError(
                f"AbuseIPDB request failed: {exc}"
            ) from exc
        if resp.status_code in (401, 403):
            raise AbuseIPDBUnavailableError(
                f"AbuseIPDB rejected credentials (HTTP {resp.status_code})"
            )
        if resp.status_code == 422:
            # Validation error from upstream — surface body
            try:
                body = resp.json()
            except ValueError:
                body = {"error": resp.text[:200]}
            raise ValueError(f"AbuseIPDB validation error: {body}")
        if resp.status_code == 429:
            raise AbuseIPDBUnavailableError(
                "AbuseIPDB rate-limit exceeded (HTTP 429)"
            )
        if resp.status_code >= 400:
            raise AbuseIPDBUnavailableError(
                f"AbuseIPDB returned HTTP {resp.status_code}: {resp.text[:200]}"
            )
        try:
            return resp.json()
        except ValueError as exc:
            raise AbuseIPDBUnavailableError(
                f"AbuseIPDB returned non-JSON response: {exc}"
            ) from exc

    # ----------------------------------------------------------- lookups

    def check(self, ip_address: str, max_age_in_days: int = 90) -> Dict[str, Any]:
        """AbuseIPDB v2 /check — IP reputation lookup."""
        if not ip_address:
            raise ValueError("ipAddress must not be empty")
        if max_age_in_days < 1 or max_age_in_days > 365:
            raise ValueError("maxAgeInDays must be between 1 and 365")
        cache_key = f"check:{ip_address}:{max_age_in_days}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached
        raw = self._request(
            "GET",
            "/api/v2/check",
            params={
                "ipAddress": ip_address,
                "maxAgeInDays": str(max_age_in_days),
            },
        )
        normalized = self._normalize_check(ip_address, raw)
        self._cache_put(
            cache_key,
            "check",
            {"ipAddress": ip_address, "maxAgeInDays": max_age_in_days},
            normalized,
        )
        return normalized

    def blacklist(
        self,
        confidence_minimum: int = 90,
        limit: int = 10000,
    ) -> Dict[str, Any]:
        """AbuseIPDB v2 /blacklist — top-N abusive IPs."""
        if confidence_minimum < 25 or confidence_minimum > 100:
            raise ValueError("confidenceMinimum must be between 25 and 100")
        if limit < 1 or limit > 500000:
            raise ValueError("limit must be between 1 and 500000")
        cache_key = f"blacklist:{confidence_minimum}:{limit}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached
        raw = self._request(
            "GET",
            "/api/v2/blacklist",
            params={
                "confidenceMinimum": str(confidence_minimum),
                "limit": str(limit),
            },
        )
        normalized = self._normalize_blacklist(raw)
        self._cache_put(
            cache_key,
            "blacklist",
            {"confidenceMinimum": confidence_minimum, "limit": limit},
            normalized,
        )
        return normalized

    def report(
        self,
        ip: str,
        categories: Iterable[int],
        comment: str = "",
    ) -> Dict[str, Any]:
        """AbuseIPDB v2 /report — submit an abuse report.

        Reports are NEVER cached (writes are idempotent on the server side
        but we always want a fresh confirmation)."""
        if not ip:
            raise ValueError("ip must not be empty")
        cat_list = [int(c) for c in categories if str(c).strip()]
        if not cat_list:
            raise ValueError("categories must contain at least one int code")
        cat_csv = ",".join(str(c) for c in cat_list)
        raw = self._request(
            "POST",
            "/api/v2/report",
            data={
                "ip": ip,
                "categories": cat_csv,
                "comment": comment or "",
            },
        )
        return self._normalize_report(ip, raw)

    # -------------------------------------------------------- normalize

    @staticmethod
    def _normalize_check(ip: str, raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        # AbuseIPDB wraps in {"data": {...}}
        data = raw.get("data") if isinstance(raw.get("data"), dict) else raw
        return {
            "data": {
                "ipAddress": data.get("ipAddress") or ip,
                "isPublic": bool(data.get("isPublic", False)),
                "ipVersion": int(data.get("ipVersion") or 4),
                "isWhitelisted": bool(data.get("isWhitelisted", False)),
                "abuseConfidenceScore": int(data.get("abuseConfidenceScore") or 0),
                "countryCode": data.get("countryCode") or "",
                "usageType": data.get("usageType") or "",
                "isp": data.get("isp") or "",
                "domain": data.get("domain") or "",
                "totalReports": int(data.get("totalReports") or 0),
                "numDistinctUsers": int(data.get("numDistinctUsers") or 0),
                "lastReportedAt": data.get("lastReportedAt") or "",
            }
        }

    @staticmethod
    def _normalize_blacklist(raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        meta = raw.get("meta") if isinstance(raw.get("meta"), dict) else {}
        data = raw.get("data") if isinstance(raw.get("data"), list) else []
        rows: List[Dict[str, Any]] = []
        for entry in data:
            if not isinstance(entry, dict):
                continue
            rows.append(
                {
                    "ipAddress": entry.get("ipAddress") or "",
                    "countryCode": entry.get("countryCode") or "",
                    "abuseConfidenceScore": int(
                        entry.get("abuseConfidenceScore") or 0
                    ),
                    "lastReportedAt": entry.get("lastReportedAt") or "",
                }
            )
        return {
            "meta": {
                "generatedAt": meta.get("generatedAt") or "",
            },
            "data": rows,
        }

    @staticmethod
    def _normalize_report(ip: str, raw: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(raw, dict):
            raw = {}
        data = raw.get("data") if isinstance(raw.get("data"), dict) else raw
        return {
            "data": {
                "ipAddress": data.get("ipAddress") or ip,
                "abuseConfidenceScore": int(
                    data.get("abuseConfidenceScore") or 0
                ),
            }
        }

    # ----------------------------------------------------------- cleanup

    def close(self) -> None:
        if self._owns_client:
            try:
                self._client.close()
            except Exception:
                pass


# --------------------------------------------------------------- singleton

_singleton: Optional[AbuseIPDBLookupEngine] = None
_singleton_lock = threading.Lock()


def get_abuseipdb_lookup_engine(
    db_path: Optional[str] = None,
    api_key: Optional[str] = None,
    client: Optional[httpx.Client] = None,
) -> AbuseIPDBLookupEngine:
    """Return the process-wide AbuseIPDBLookupEngine singleton."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = AbuseIPDBLookupEngine(
                db_path=db_path, api_key=api_key, client=client
            )
        return _singleton


def reset_abuseipdb_lookup_engine() -> None:
    """Tear down the singleton — used by tests with tmp_path DBs."""
    global _singleton
    with _singleton_lock:
        if _singleton is not None:
            _singleton.close()
        _singleton = None


__all__ = [
    "AbuseIPDBLookupEngine",
    "AbuseIPDBUnavailableError",
    "get_abuseipdb_lookup_engine",
    "reset_abuseipdb_lookup_engine",
]
