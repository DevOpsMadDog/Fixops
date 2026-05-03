"""
Shodan Threat-Intel Lookup Engine — ALDECI.

Wraps the Shodan REST API (https://api.shodan.io) and provides a
process-wide singleton plus a SQLite-backed response cache. This engine
deliberately avoids returning fabricated data when SHODAN_API_KEY is
unset — callers receive ``status="unavailable"`` from the capability
summary and a 503 from the live-lookup endpoints.

Cache schema
------------
    shodan_cache (
        cache_key   TEXT PRIMARY KEY,   -- "<query_type>:<canonical-params>"
        query_type  TEXT NOT NULL,       -- host | search | honeyscore | count | dns
        params_json TEXT NOT NULL,       -- JSON-encoded request params
        response_json TEXT NOT NULL,     -- JSON-encoded successful response
        fetched_at  TEXT NOT NULL,       -- ISO-8601 timestamp
        expires_at  TEXT NOT NULL        -- ISO-8601 timestamp
    )

The default TTL is 6 hours; honeyscore and DNS-resolve use 24 hours
because they change rarely.

NO MOCKS rule: when SHODAN_API_KEY is missing the engine is still
constructible (so capability summaries can render), but every live
lookup raises ``ShodanUnavailableError`` which the router translates
to HTTP 503.
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx

_logger = logging.getLogger(__name__)

SHODAN_API_BASE = "https://api.shodan.io"
DEFAULT_TIMEOUT_SECONDS = 8.0

# Cache TTLs (seconds)
_TTL_HOST = 6 * 3600
_TTL_SEARCH = 6 * 3600
_TTL_COUNT = 6 * 3600
_TTL_HONEYSCORE = 24 * 3600
_TTL_DNS = 24 * 3600


class ShodanUnavailableError(RuntimeError):
    """Raised when Shodan API key is unset or the API returned an unrecoverable error."""


class ShodanLookupEngine:
    """Thread-safe Shodan REST client with sqlite response cache."""

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
            db_path = str(base / "shodan_cache.db")
        self._db_path = db_path
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)

        # API key resolution: explicit arg wins, then env (re-read each call
        # to capture monkeypatch.setenv updates in tests).
        self._explicit_api_key = api_key

        # HTTP client
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
                CREATE TABLE IF NOT EXISTS shodan_cache (
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
                "CREATE INDEX IF NOT EXISTS idx_shodan_cache_expires "
                "ON shodan_cache(expires_at)"
            )
            conn.commit()

    # ------------------------------------------------------------ helpers

    def _api_key(self) -> Optional[str]:
        if self._explicit_api_key:
            return self._explicit_api_key
        v = os.environ.get("SHODAN_API_KEY")
        return v or None

    def api_key_present(self) -> bool:
        return bool(self._api_key())

    def cache_size(self) -> int:
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS n FROM shodan_cache").fetchone()
            return int(row["n"]) if row else 0

    def _cache_get(self, key: str) -> Optional[Dict[str, Any]]:
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT response_json FROM shodan_cache "
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
                INSERT INTO shodan_cache (cache_key, query_type, params_json,
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

    def _request(self, path: str, params: Dict[str, Any]) -> Dict[str, Any]:
        api_key = self._api_key()
        if not api_key:
            raise ShodanUnavailableError("SHODAN_API_KEY is not configured")
        full_params = dict(params)
        full_params["key"] = api_key
        url = f"{SHODAN_API_BASE}{path}"
        try:
            resp = self._client.get(url, params=full_params)
        except httpx.HTTPError as exc:
            raise ShodanUnavailableError(f"Shodan request failed: {exc}") from exc
        if resp.status_code == 401 or resp.status_code == 403:
            raise ShodanUnavailableError(
                f"Shodan rejected credentials (HTTP {resp.status_code})"
            )
        if resp.status_code == 404:
            raise ShodanUnavailableError("Shodan returned 404 — resource not found")
        if resp.status_code >= 400:
            raise ShodanUnavailableError(
                f"Shodan returned HTTP {resp.status_code}: {resp.text[:200]}"
            )
        try:
            return resp.json()
        except ValueError as exc:
            raise ShodanUnavailableError(
                f"Shodan returned non-JSON response: {exc}"
            ) from exc

    # ----------------------------------------------------------- lookups

    def lookup_host(self, ip: str) -> Dict[str, Any]:
        if not ip:
            raise ValueError("ip must not be empty")
        cache_key = f"host:{ip}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return self._normalize_host(cached)
        raw = self._request(f"/shodan/host/{ip}", {})
        self._cache_put(cache_key, "host", {"ip": ip}, raw, _TTL_HOST)
        return self._normalize_host(raw)

    def search(self, query: str, page: int = 1) -> Dict[str, Any]:
        if not query:
            raise ValueError("query must not be empty")
        if page < 1:
            page = 1
        cache_key = f"search:{query}:{page}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return self._normalize_search(cached)
        raw = self._request(
            "/shodan/host/search",
            {"query": query, "page": page},
        )
        self._cache_put(
            cache_key, "search", {"query": query, "page": page}, raw, _TTL_SEARCH
        )
        return self._normalize_search(raw)

    def honeyscore(self, ip: str) -> Dict[str, Any]:
        if not ip:
            raise ValueError("ip must not be empty")
        cache_key = f"honeyscore:{ip}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached
        raw = self._request(f"/labs/honeyscore/{ip}", {})
        # Shodan returns just a float (e.g. 0.5) for honeyscore.
        try:
            score = float(raw) if not isinstance(raw, dict) else float(
                raw.get("honeyscore", 0.0)
            )
        except (TypeError, ValueError):
            score = 0.0
        score = max(0.0, min(1.0, score))
        normalized = {"ip": ip, "honeyscore": score}
        self._cache_put(cache_key, "honeyscore", {"ip": ip}, normalized, _TTL_HONEYSCORE)
        return normalized

    def count(self, query: str) -> Dict[str, Any]:
        if not query:
            raise ValueError("query must not be empty")
        cache_key = f"count:{query}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return self._normalize_count(cached)
        raw = self._request("/shodan/host/count", {"query": query})
        self._cache_put(cache_key, "count", {"query": query}, raw, _TTL_COUNT)
        return self._normalize_count(raw)

    def dns_resolve(self, hostnames: List[str]) -> Dict[str, Optional[str]]:
        if not hostnames:
            raise ValueError("hostnames must not be empty")
        clean = sorted({h.strip() for h in hostnames if h and h.strip()})
        if not clean:
            raise ValueError("hostnames must contain at least one non-empty entry")
        cache_key = f"dns:{','.join(clean)}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached
        raw = self._request("/dns/resolve", {"hostnames": ",".join(clean)})
        if not isinstance(raw, dict):
            raise ShodanUnavailableError("Shodan dns/resolve returned non-mapping")
        normalized: Dict[str, Optional[str]] = {h: raw.get(h) for h in clean}
        self._cache_put(cache_key, "dns", {"hostnames": clean}, normalized, _TTL_DNS)
        return normalized

    # --------------------------------------------------------- normalize

    @staticmethod
    def _normalize_host(raw: Dict[str, Any]) -> Dict[str, Any]:
        services: List[Dict[str, Any]] = []
        for entry in raw.get("data", []) or []:
            services.append(
                {
                    "port": entry.get("port"),
                    "protocol": entry.get("transport") or entry.get("_shodan", {}).get(
                        "module"
                    ),
                    "product": entry.get("product"),
                    "version": entry.get("version"),
                    "banner": (entry.get("data") or "")[:512],
                }
            )
        return {
            "ip": raw.get("ip_str") or raw.get("ip"),
            "country": raw.get("country_name"),
            "city": raw.get("city"),
            "isp": raw.get("isp"),
            "asn": raw.get("asn"),
            "hostnames": list(raw.get("hostnames") or []),
            "services": services,
            "vulns": list(raw.get("vulns") or []),
        }

    @staticmethod
    def _normalize_search(raw: Dict[str, Any]) -> Dict[str, Any]:
        matches: List[Dict[str, Any]] = []
        for entry in raw.get("matches", []) or []:
            location = entry.get("location") or {}
            matches.append(
                {
                    "ip_str": entry.get("ip_str"),
                    "port": entry.get("port"),
                    "hostnames": list(entry.get("hostnames") or []),
                    "location": {
                        "country_name": location.get("country_name"),
                        "city": location.get("city"),
                    },
                    "product": entry.get("product"),
                }
            )
        out: Dict[str, Any] = {
            "total": int(raw.get("total", 0) or 0),
            "matches": matches,
        }
        if raw.get("facets"):
            out["facets"] = raw["facets"]
        return out

    @staticmethod
    def _normalize_count(raw: Dict[str, Any]) -> Dict[str, Any]:
        out: Dict[str, Any] = {"total": int(raw.get("total", 0) or 0)}
        if raw.get("facets"):
            out["facets"] = raw["facets"]
        return out

    # ----------------------------------------------------------- cleanup

    def close(self) -> None:
        if self._owns_client:
            try:
                self._client.close()
            except Exception:
                pass


# --------------------------------------------------------------- singleton

_singleton: Optional[ShodanLookupEngine] = None
_singleton_lock = threading.Lock()


def get_shodan_lookup_engine(
    db_path: Optional[str] = None,
    api_key: Optional[str] = None,
    client: Optional[httpx.Client] = None,
) -> ShodanLookupEngine:
    """Return the process-wide ShodanLookupEngine singleton."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = ShodanLookupEngine(
                db_path=db_path, api_key=api_key, client=client
            )
        return _singleton


def reset_shodan_lookup_engine() -> None:
    """Tear down the singleton — used by tests with tmp_path DBs."""
    global _singleton
    with _singleton_lock:
        if _singleton is not None:
            _singleton.close()
        _singleton = None


__all__ = [
    "ShodanLookupEngine",
    "ShodanUnavailableError",
    "get_shodan_lookup_engine",
    "reset_shodan_lookup_engine",
]
