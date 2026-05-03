"""
Censys Threat-Intel Lookup Engine — ALDECI.

Wraps the Censys v2 REST API (https://search.censys.io/api/v2) and provides
a process-wide singleton plus a SQLite-backed response cache. Avoids
returning fabricated data when CENSYS_API_ID or CENSYS_API_SECRET are
unset — callers receive ``status="unavailable"`` from the capability
summary and a 503 from the live-lookup endpoints.

Cache schema
------------
    censys_cache (
        cache_key   TEXT PRIMARY KEY,   -- "<query_type>:<canonical-params>"
        query_type  TEXT NOT NULL,       -- host | cert | search
        params_json TEXT NOT NULL,       -- JSON-encoded request params
        response_json TEXT NOT NULL,     -- JSON-encoded successful response
        fetched_at  TEXT NOT NULL,       -- ISO-8601 timestamp
        expires_at  TEXT NOT NULL        -- ISO-8601 timestamp
    )

TTLs:
    host   -> 6h
    cert   -> 24h
    search -> 1h

NO MOCKS rule: when API_ID/SECRET are missing the engine is still
constructible (so capability summaries can render), but every live
lookup raises ``CensysUnavailableError`` which the router translates
to HTTP 503.
"""

from __future__ import annotations

import base64
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

CENSYS_API_BASE = "https://search.censys.io/api/v2"
DEFAULT_TIMEOUT_SECONDS = 8.0

# Cache TTLs (seconds)
_TTL_HOST = 6 * 3600
_TTL_CERT = 24 * 3600
_TTL_SEARCH = 1 * 3600


class CensysUnavailableError(RuntimeError):
    """Raised when Censys credentials are unset or the API returned an unrecoverable error."""


class CensysLookupEngine:
    """Thread-safe Censys v2 REST client with sqlite response cache."""

    def __init__(
        self,
        db_path: Optional[str] = None,
        api_id: Optional[str] = None,
        api_secret: Optional[str] = None,
        client: Optional[httpx.Client] = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        # Resolve DB path
        if db_path is None:
            base = Path(os.environ.get("FIXOPS_DATA_DIR", "data")) / "security"
            base.mkdir(parents=True, exist_ok=True)
            db_path = str(base / "censys_cache.db")
        self._db_path = db_path
        Path(self._db_path).parent.mkdir(parents=True, exist_ok=True)

        # Credentials: explicit args win, else env (re-read each call to
        # capture monkeypatch.setenv updates in tests).
        self._explicit_api_id = api_id
        self._explicit_api_secret = api_secret

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
                CREATE TABLE IF NOT EXISTS censys_cache (
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
                "CREATE INDEX IF NOT EXISTS idx_censys_cache_expires "
                "ON censys_cache(expires_at)"
            )
            conn.commit()

    # ------------------------------------------------------------ helpers

    def _api_id(self) -> Optional[str]:
        if self._explicit_api_id:
            return self._explicit_api_id
        v = os.environ.get("CENSYS_API_ID")
        return v or None

    def _api_secret(self) -> Optional[str]:
        if self._explicit_api_secret:
            return self._explicit_api_secret
        v = os.environ.get("CENSYS_API_SECRET")
        return v or None

    def api_id_present(self) -> bool:
        return bool(self._api_id())

    def api_secret_present(self) -> bool:
        return bool(self._api_secret())

    def credentials_present(self) -> bool:
        return self.api_id_present() and self.api_secret_present()

    def cache_size(self) -> int:
        with self._connect() as conn:
            row = conn.execute("SELECT COUNT(*) AS n FROM censys_cache").fetchone()
            return int(row["n"]) if row else 0

    def _cache_get(self, key: str) -> Optional[Dict[str, Any]]:
        now = datetime.now(timezone.utc).isoformat()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT response_json FROM censys_cache "
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
                INSERT INTO censys_cache (cache_key, query_type, params_json,
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
        api_id = self._api_id()
        api_secret = self._api_secret()
        if not api_id or not api_secret:
            raise CensysUnavailableError(
                "CENSYS_API_ID and CENSYS_API_SECRET must both be configured"
            )
        token = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()
        headers = {
            "Authorization": f"Basic {token}",
            "Accept": "application/json",
        }
        url = f"{CENSYS_API_BASE}{path}"
        try:
            resp = self._client.get(url, params=params or None, headers=headers)
        except httpx.HTTPError as exc:
            raise CensysUnavailableError(f"Censys request failed: {exc}") from exc
        if resp.status_code in (401, 403):
            raise CensysUnavailableError(
                f"Censys rejected credentials (HTTP {resp.status_code})"
            )
        if resp.status_code == 404:
            raise CensysUnavailableError("Censys returned 404 — resource not found")
        if resp.status_code >= 400:
            raise CensysUnavailableError(
                f"Censys returned HTTP {resp.status_code}: {resp.text[:200]}"
            )
        try:
            return resp.json()
        except ValueError as exc:
            raise CensysUnavailableError(
                f"Censys returned non-JSON response: {exc}"
            ) from exc

    # ----------------------------------------------------------- lookups

    def lookup_host(self, ip: str) -> Dict[str, Any]:
        if not ip:
            raise ValueError("ip must not be empty")
        cache_key = f"host:{ip}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return self._normalize_host(cached)
        raw = self._request(f"/hosts/{ip}", {})
        self._cache_put(cache_key, "host", {"ip": ip}, raw, _TTL_HOST)
        return self._normalize_host(raw)

    def lookup_certificate(self, fingerprint: str) -> Dict[str, Any]:
        if not fingerprint:
            raise ValueError("fingerprint must not be empty")
        cache_key = f"cert:{fingerprint}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return self._normalize_certificate(cached)
        raw = self._request(f"/certificates/{fingerprint}", {})
        self._cache_put(
            cache_key, "cert", {"fingerprint": fingerprint}, raw, _TTL_CERT
        )
        return self._normalize_certificate(raw)

    def search_hosts(self, query: str, per_page: int = 25) -> Dict[str, Any]:
        if not query:
            raise ValueError("query must not be empty")
        if per_page < 1:
            per_page = 1
        if per_page > 100:
            per_page = 100
        cache_key = f"search:{query}:{per_page}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return self._normalize_search(cached)
        raw = self._request(
            "/hosts/search",
            {"q": query, "per_page": per_page},
        )
        self._cache_put(
            cache_key,
            "search",
            {"q": query, "per_page": per_page},
            raw,
            _TTL_SEARCH,
        )
        return self._normalize_search(raw)

    # --------------------------------------------------------- normalize

    @staticmethod
    def _normalize_host(raw: Dict[str, Any]) -> Dict[str, Any]:
        # Censys v2 host responses wrap data in {code, status, result: {...}}
        result = raw.get("result") if isinstance(raw, dict) else None
        if not isinstance(result, dict):
            result = raw if isinstance(raw, dict) else {}

        services_out: List[Dict[str, Any]] = []
        for entry in result.get("services", []) or []:
            if not isinstance(entry, dict):
                continue
            software = entry.get("software")
            if not isinstance(software, list):
                software = [software] if software else []
            services_out.append(
                {
                    "port": entry.get("port"),
                    "protocol": entry.get("transport_protocol")
                    or entry.get("service_name"),
                    "software": [
                        s for s in software if s is not None
                    ],
                }
            )

        location = result.get("location") or {}
        if not isinstance(location, dict):
            location = {}
        autonomous_system = result.get("autonomous_system") or {}
        if not isinstance(autonomous_system, dict):
            autonomous_system = {}

        return {
            "ip": result.get("ip"),
            "services": services_out,
            "location": {
                "country": location.get("country"),
                "country_code": location.get("country_code"),
                "city": location.get("city"),
                "continent": location.get("continent"),
            },
            "autonomous_system": {
                "asn": autonomous_system.get("asn"),
                "name": autonomous_system.get("name"),
                "country_code": autonomous_system.get("country_code"),
            },
            "last_updated_at": result.get("last_updated_at"),
        }

    @staticmethod
    def _normalize_certificate(raw: Dict[str, Any]) -> Dict[str, Any]:
        result = raw.get("result") if isinstance(raw, dict) else None
        if not isinstance(result, dict):
            result = raw if isinstance(raw, dict) else {}

        parsed = result.get("parsed") or {}
        if not isinstance(parsed, dict):
            parsed = {}

        # subject / issuer can come as dict (CN/O/OU/...) or as a DN string.
        subject = parsed.get("subject") or parsed.get("subject_dn")
        issuer = parsed.get("issuer") or parsed.get("issuer_dn")

        validity = parsed.get("validity") or parsed.get("validity_period") or {}
        if not isinstance(validity, dict):
            validity = {}

        names = result.get("names") or parsed.get("names") or []
        if not isinstance(names, list):
            names = []

        ct_logs = result.get("ct") or result.get("ct_logs") or []
        if isinstance(ct_logs, dict):
            # Censys CT block sometimes nests {ct: {entries: [...]}}
            ct_logs = ct_logs.get("entries") or list(ct_logs.values())
        if not isinstance(ct_logs, list):
            ct_logs = []

        return {
            "fingerprint": result.get("fingerprint_sha256")
            or result.get("fingerprint")
            or parsed.get("fingerprint_sha256"),
            "parsed": {
                "subject": subject,
                "issuer": issuer,
                "validity_period": {
                    "start": validity.get("start") or validity.get("not_before"),
                    "end": validity.get("end") or validity.get("not_after"),
                    "length_seconds": validity.get("length"),
                },
                "names": list(names),
            },
            "ct_logs": ct_logs,
        }

    @staticmethod
    def _normalize_search(raw: Dict[str, Any]) -> Dict[str, Any]:
        result = raw.get("result") if isinstance(raw, dict) else None
        if not isinstance(result, dict):
            result = raw if isinstance(raw, dict) else {}

        total = result.get("total") or 0
        try:
            total = int(total)
        except (TypeError, ValueError):
            total = 0

        hits_out: List[Dict[str, Any]] = []
        for hit in result.get("hits", []) or []:
            if not isinstance(hit, dict):
                continue
            services = hit.get("services") or []
            if not isinstance(services, list):
                services = []
            services_summary: List[Dict[str, Any]] = []
            for svc in services:
                if not isinstance(svc, dict):
                    continue
                services_summary.append(
                    {
                        "port": svc.get("port"),
                        "service_name": svc.get("service_name")
                        or svc.get("transport_protocol"),
                    }
                )

            name = hit.get("name")
            if not name:
                names_list = hit.get("names")
                if isinstance(names_list, list) and names_list:
                    name = names_list[0]

            hits_out.append(
                {
                    "ip": hit.get("ip"),
                    "name": name,
                    "services_summary": services_summary,
                }
            )

        return {
            "result": {
                "total": total,
                "hits": hits_out,
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

_singleton: Optional[CensysLookupEngine] = None
_singleton_lock = threading.Lock()


def get_censys_lookup_engine(
    db_path: Optional[str] = None,
    api_id: Optional[str] = None,
    api_secret: Optional[str] = None,
    client: Optional[httpx.Client] = None,
) -> CensysLookupEngine:
    """Return the process-wide CensysLookupEngine singleton."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = CensysLookupEngine(
                db_path=db_path,
                api_id=api_id,
                api_secret=api_secret,
                client=client,
            )
        return _singleton


def reset_censys_lookup_engine() -> None:
    """Tear down the singleton — used by tests with tmp_path DBs."""
    global _singleton
    with _singleton_lock:
        if _singleton is not None:
            _singleton.close()
        _singleton = None


__all__ = [
    "CensysLookupEngine",
    "CensysUnavailableError",
    "get_censys_lookup_engine",
    "reset_censys_lookup_engine",
]
