"""
VirusTotal v3 Threat-Intel Lookup Engine — ALDECI.

Wraps the VirusTotal v3 REST API (https://www.virustotal.com/api/v3) and
provides a process-wide singleton plus a SQLite-backed response cache.
This engine deliberately avoids returning fabricated data when
VT_API_KEY (or VIRUSTOTAL_API_KEY) is unset — callers receive
``status="unavailable"`` from the capability summary and a 503 from the
live-lookup endpoints.

Cache schema
------------
    virustotal_cache (
        cache_key   TEXT PRIMARY KEY,   -- "<query_type>:<canonical-params>"
        query_type  TEXT NOT NULL,      -- file | url | domain | ip
        params_json TEXT NOT NULL,      -- JSON-encoded request params
        response_json TEXT NOT NULL,    -- JSON-encoded successful response
        fetched_at  TEXT NOT NULL,      -- ISO-8601 timestamp
        expires_at  TEXT NOT NULL       -- ISO-8601 timestamp
    )

The default TTL is 24 hours for all four query types.

NO MOCKS rule: when VT_API_KEY (or VIRUSTOTAL_API_KEY) is missing the
engine is still constructible (so capability summaries can render), but
every live lookup raises ``VirusTotalUnavailableError`` which the router
translates to HTTP 503.
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

VIRUSTOTAL_API_BASE = "https://www.virustotal.com/api/v3"
DEFAULT_TIMEOUT_SECONDS = 8.0

# Cache TTLs (seconds) — 24h for all VT query types.
_TTL_FILE = 24 * 3600
_TTL_URL = 24 * 3600
_TTL_DOMAIN = 24 * 3600
_TTL_IP = 24 * 3600


class VirusTotalUnavailableError(RuntimeError):
    """Raised when VT API key is unset or the API returned an unrecoverable error."""


class VirusTotalLookupEngine:
    """Thread-safe VirusTotal v3 REST client with sqlite response cache."""

    def __init__(
        self,
        db_path: Optional[str] = None,
        api_key: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        if db_path is None:
            base = Path(os.environ.get("FIXOPS_DATA_DIR", "data")) / "security"
            base.mkdir(parents=True, exist_ok=True)
            db_path = str(base / "virustotal_cache.db")
        self._db_path = db_path
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)

        self._explicit_api_key = api_key

        self._client = client or httpx.Client(timeout=timeout)
        self._owns_client = client is None
        self._timeout = timeout

        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------ db

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self._db_path, timeout=30, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS virustotal_cache (
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
                "CREATE INDEX IF NOT EXISTS idx_virustotal_cache_expires "
                "ON virustotal_cache(expires_at)"
            )
            conn.commit()

    # ------------------------------------------------------------ helpers

    def _api_key(self) -> Optional[str]:
        if self._explicit_api_key:
            return self._explicit_api_key
        v = os.environ.get("VT_API_KEY") or os.environ.get("VIRUSTOTAL_API_KEY")
        return v or None

    def api_key_present(self) -> bool:
        return bool(self._api_key())

    def cache_size(self) -> int:
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS n FROM virustotal_cache").fetchone()
            return int(row["n"]) if row else 0

    def _cache_get(self, key: str) -> Optional[Dict[str, Any]]:
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT response_json FROM virustotal_cache "
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
                INSERT INTO virustotal_cache (cache_key, query_type, params_json,
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

    def _request(self, path: str) -> Dict[str, Any]:
        api_key = self._api_key()
        if not api_key:
            raise VirusTotalUnavailableError(
                "VT_API_KEY (or VIRUSTOTAL_API_KEY) is not configured"
            )
        url = f"{VIRUSTOTAL_API_BASE}{path}"
        headers = {"x-apikey": api_key, "accept": "application/json"}
        try:
            resp = self._client.get(url, headers=headers)
        except httpx.HTTPError as exc:
            raise VirusTotalUnavailableError(
                f"VirusTotal request failed: {exc}"
            ) from exc
        if resp.status_code in (401, 403):
            raise VirusTotalUnavailableError(
                f"VirusTotal rejected credentials (HTTP {resp.status_code})"
            )
        if resp.status_code == 404:
            raise VirusTotalUnavailableError(
                "VirusTotal returned 404 — resource not found"
            )
        if resp.status_code >= 400:
            raise VirusTotalUnavailableError(
                f"VirusTotal returned HTTP {resp.status_code}: {resp.text[:200]}"
            )
        try:
            return resp.json()
        except ValueError as exc:
            raise VirusTotalUnavailableError(
                f"VirusTotal returned non-JSON response: {exc}"
            ) from exc

    # ----------------------------------------------------------- lookups

    def lookup_file(self, file_hash: str) -> Dict[str, Any]:
        if not file_hash or not file_hash.strip():
            raise ValueError("file_hash must not be empty")
        h = file_hash.strip().lower()
        cache_key = f"file:{h}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return self._normalize_file(cached, h)
        raw = self._request(f"/files/{h}")
        self._cache_put(cache_key, "file", {"hash": h}, raw, _TTL_FILE)
        return self._normalize_file(raw, h)

    def lookup_url(self, url_id: str) -> Dict[str, Any]:
        if not url_id or not url_id.strip():
            raise ValueError("url_id must not be empty")
        u = url_id.strip()
        cache_key = f"url:{u}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return self._normalize_url(cached, u)
        raw = self._request(f"/urls/{u}")
        self._cache_put(cache_key, "url", {"url_id": u}, raw, _TTL_URL)
        return self._normalize_url(raw, u)

    def lookup_domain(self, domain: str) -> Dict[str, Any]:
        if not domain or not domain.strip():
            raise ValueError("domain must not be empty")
        d = domain.strip().lower()
        cache_key = f"domain:{d}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return self._normalize_domain(cached, d)
        raw = self._request(f"/domains/{d}")
        self._cache_put(cache_key, "domain", {"domain": d}, raw, _TTL_DOMAIN)
        return self._normalize_domain(raw, d)

    def lookup_ip(self, ip: str) -> Dict[str, Any]:
        if not ip or not ip.strip():
            raise ValueError("ip must not be empty")
        i = ip.strip()
        cache_key = f"ip:{i}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return self._normalize_ip(cached, i)
        raw = self._request(f"/ip_addresses/{i}")
        self._cache_put(cache_key, "ip", {"ip": i}, raw, _TTL_IP)
        return self._normalize_ip(raw, i)

    # --------------------------------------------------------- normalize

    @staticmethod
    def _data_attrs(raw: Dict[str, Any]) -> Dict[str, Any]:
        data = raw.get("data") if isinstance(raw, dict) else None
        if not isinstance(data, dict):
            return {}
        attrs = data.get("attributes")
        return attrs if isinstance(attrs, dict) else {}

    @staticmethod
    def _data_id(raw: Dict[str, Any], fallback: str) -> str:
        data = raw.get("data") if isinstance(raw, dict) else None
        if isinstance(data, dict) and data.get("id"):
            return str(data["id"])
        return fallback

    @classmethod
    def _normalize_file(cls, raw: Dict[str, Any], fallback_id: str) -> Dict[str, Any]:
        attrs = cls._data_attrs(raw)
        stats = attrs.get("last_analysis_stats") or {}
        return {
            "data": {
                "id": cls._data_id(raw, fallback_id),
                "type": "file",
                "attributes": {
                    "md5": attrs.get("md5"),
                    "sha1": attrs.get("sha1"),
                    "sha256": attrs.get("sha256"),
                    "last_analysis_stats": {
                        "malicious": int(stats.get("malicious", 0) or 0),
                        "suspicious": int(stats.get("suspicious", 0) or 0),
                        "undetected": int(stats.get("undetected", 0) or 0),
                        "harmless": int(stats.get("harmless", 0) or 0),
                    },
                    "last_analysis_results": attrs.get("last_analysis_results") or {},
                    "type_description": attrs.get("type_description"),
                    "names": list(attrs.get("names") or []),
                },
            }
        }

    @classmethod
    def _normalize_url(cls, raw: Dict[str, Any], fallback_id: str) -> Dict[str, Any]:
        attrs = cls._data_attrs(raw)
        stats = attrs.get("last_analysis_stats") or {}
        return {
            "data": {
                "id": cls._data_id(raw, fallback_id),
                "type": "url",
                "attributes": {
                    "url": attrs.get("url"),
                    "title": attrs.get("title"),
                    "last_analysis_stats": {
                        "malicious": int(stats.get("malicious", 0) or 0),
                        "suspicious": int(stats.get("suspicious", 0) or 0),
                        "undetected": int(stats.get("undetected", 0) or 0),
                        "harmless": int(stats.get("harmless", 0) or 0),
                    },
                    "last_analysis_results": attrs.get("last_analysis_results") or {},
                    "last_final_url": attrs.get("last_final_url"),
                },
            }
        }

    @classmethod
    def _normalize_domain(cls, raw: Dict[str, Any], fallback_id: str) -> Dict[str, Any]:
        attrs = cls._data_attrs(raw)
        stats = attrs.get("last_analysis_stats") or {}
        return {
            "data": {
                "id": cls._data_id(raw, fallback_id),
                "type": "domain",
                "attributes": {
                    "categories": dict(attrs.get("categories") or {}),
                    "last_analysis_stats": {
                        "malicious": int(stats.get("malicious", 0) or 0),
                        "suspicious": int(stats.get("suspicious", 0) or 0),
                        "undetected": int(stats.get("undetected", 0) or 0),
                        "harmless": int(stats.get("harmless", 0) or 0),
                    },
                    "jarm": attrs.get("jarm"),
                    "popularity_ranks": dict(attrs.get("popularity_ranks") or {}),
                    "registrar": attrs.get("registrar"),
                },
            }
        }

    @classmethod
    def _normalize_ip(cls, raw: Dict[str, Any], fallback_id: str) -> Dict[str, Any]:
        attrs = cls._data_attrs(raw)
        stats = attrs.get("last_analysis_stats") or {}
        return {
            "data": {
                "id": cls._data_id(raw, fallback_id),
                "type": "ip_address",
                "attributes": {
                    "country": attrs.get("country"),
                    "asn": attrs.get("asn"),
                    "as_owner": attrs.get("as_owner"),
                    "regional_internet_registry": attrs.get(
                        "regional_internet_registry"
                    ),
                    "network": attrs.get("network"),
                    "last_analysis_stats": {
                        "malicious": int(stats.get("malicious", 0) or 0),
                        "suspicious": int(stats.get("suspicious", 0) or 0),
                        "undetected": int(stats.get("undetected", 0) or 0),
                        "harmless": int(stats.get("harmless", 0) or 0),
                    },
                },
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

_singleton: Optional[VirusTotalLookupEngine] = None
_singleton_lock = threading.Lock()


def get_virustotal_lookup_engine(
    db_path: Optional[str] = None,
    api_key: Optional[str] = None,
    client: Optional[httpx.Client] = None,
) -> VirusTotalLookupEngine:
    """Return the process-wide VirusTotalLookupEngine singleton."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = VirusTotalLookupEngine(
                db_path=db_path, api_key=api_key, client=client
            )
        return _singleton


def reset_virustotal_lookup_engine() -> None:
    """Tear down the singleton — used by tests with tmp_path DBs."""
    global _singleton
    with _singleton_lock:
        if _singleton is not None:
            _singleton.close()
        _singleton = None


__all__ = [
    "VirusTotalLookupEngine",
    "VirusTotalUnavailableError",
    "get_virustotal_lookup_engine",
    "reset_virustotal_lookup_engine",
]
