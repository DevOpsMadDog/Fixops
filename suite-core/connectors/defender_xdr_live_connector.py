"""Microsoft Defender XDR — Live API Connector.

Extends defender_xdr_connector.py with a real Microsoft Graph Security API
polling path.

Live API flow:
1. POST https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token
   → app-only bearer token (client_credentials grant, 1-hour TTL)
2. GET  https://graph.microsoft.com/v1.0/security/alerts_v2
   → paginated Defender XDR / Sentinel alerts
3. Normalize via _normalize_alert() (from defender_xdr_connector)
4. Push to SecurityFindingsEngine.record_finding (idempotent)

Required env vars:
    DEFENDER_TENANT_ID        Azure AD tenant ID (GUID)
    DEFENDER_CLIENT_ID        App registration client ID
    DEFENDER_CLIENT_SECRET    App registration client secret

Optional:
    DEFENDER_MAX_ALERTS       Max alerts per fetch (default 500)

Credential fallback: if any of the three required vars is absent →
    graceful no-op → {status: "needs_credentials"}.

Cache: 1-hour TTL per (org_id, filter).
Idempotent: correlation_key="defender_xdr|{alertId}" deduplicates.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from connectors._emit import emit_connector_event
from connectors.defender_xdr_connector import _normalize_alert

_logger = logging.getLogger(__name__)

_GRAPH_TOKEN_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
_GRAPH_ALERTS_URL = "https://graph.microsoft.com/v1.0/security/alerts_v2"
_GRAPH_SCOPE = "https://graph.microsoft.com/.default"
_TOKEN_TTL_BUFFER = 120          # refresh 2 min before expiry
_CACHE_TTL_SECONDS = 3600        # 1-hour result cache
_DEFAULT_MAX_ALERTS = 500


# ---------------------------------------------------------------------------
# Module-level caches
# ---------------------------------------------------------------------------
_token_cache: Dict[str, Any] = {}   # key: (tenant_id, client_id)
_result_cache: Dict[str, Any] = {}  # key: (org_id, tenant_id, client_id, filter_str)
_cache_lock = threading.Lock()


def _creds_present() -> bool:
    return all(
        os.environ.get(v)
        for v in ("DEFENDER_TENANT_ID", "DEFENDER_CLIENT_ID", "DEFENDER_CLIENT_SECRET")
    )


def _get_graph_token(tenant_id: str, client_id: str, client_secret: str) -> str:
    """Obtain or reuse a cached Microsoft Graph bearer token."""
    cache_key = (tenant_id, client_id)
    with _cache_lock:
        cached = _token_cache.get(cache_key)
        if cached and time.monotonic() < cached["expires_at"]:
            return cached["token"]

    import httpx

    url = _GRAPH_TOKEN_URL.format(tenant_id=tenant_id)
    data = {
        "grant_type": "client_credentials",
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": _GRAPH_SCOPE,
    }
    resp = httpx.post(url, data=data, timeout=15)
    resp.raise_for_status()
    body = resp.json()
    token = body.get("access_token") or ""
    if not token:
        raise ValueError("Microsoft Graph OAuth2 returned no access_token")
    expires_in = int(body.get("expires_in", 3600))

    with _cache_lock:
        _token_cache[cache_key] = {
            "token": token,
            "expires_at": time.monotonic() + expires_in - _TOKEN_TTL_BUFFER,
        }
    return token


def _fetch_alerts_page(token: str, url: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Fetch one page of alerts from Microsoft Graph Security API."""
    import httpx

    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }
    resp = httpx.get(url, params=params, headers=headers, timeout=30)
    resp.raise_for_status()
    return resp.json()


def _fetch_all_alerts(
    token: str,
    max_alerts: int = _DEFAULT_MAX_ALERTS,
    filter_str: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Page through alerts_v2 and collect up to max_alerts."""
    params: Dict[str, Any] = {"$top": min(1000, max_alerts)}
    if filter_str:
        params["$filter"] = filter_str

    alerts: List[Dict[str, Any]] = []
    url: Optional[str] = _GRAPH_ALERTS_URL

    while url and len(alerts) < max_alerts:
        body = _fetch_alerts_page(token, url, params if url == _GRAPH_ALERTS_URL else None)
        page = body.get("value") or []
        alerts.extend(page)
        url = body.get("@odata.nextLink")  # None when no more pages
        params = {}  # nextLink already carries params

    return alerts[:max_alerts]


# ---------------------------------------------------------------------------
# Public connector class
# ---------------------------------------------------------------------------
class DefenderXDRLiveConnector:
    """Live Microsoft Defender XDR connector via Graph Security API.

    Args:
        findings_engine: SecurityFindingsEngine instance (optional).
        max_alerts:      Cap on alerts fetched per invocation.
    """

    SOURCE_TOOL = "defender_xdr"

    def __init__(
        self,
        findings_engine: Any = None,
        max_alerts: int = _DEFAULT_MAX_ALERTS,
    ) -> None:
        self._findings = findings_engine
        self._max_alerts = max(1, min(max_alerts, 10_000))

    def fetch_alerts(
        self,
        org_id: str,
        filter_str: Optional[str] = None,
        force_refresh: bool = False,
    ) -> Dict[str, Any]:
        """Fetch live Defender XDR alerts from Microsoft Graph Security API.

        Returns {status, mode, org_id, alert_count, findings_recorded,
                 alerts, ingested_at}.
        Returns {status: "needs_credentials"} if env vars absent.
        """
        if not isinstance(org_id, str) or not org_id.strip():
            raise ValueError("org_id is required")

        tenant_id = os.environ.get("DEFENDER_TENANT_ID", "")
        client_id = os.environ.get("DEFENDER_CLIENT_ID", "")
        client_secret = os.environ.get("DEFENDER_CLIENT_SECRET", "")

        if not (tenant_id and client_id and client_secret):
            _logger.warning(
                "DefenderXDRLiveConnector: DEFENDER_TENANT_ID / DEFENDER_CLIENT_ID / "
                "DEFENDER_CLIENT_SECRET not set — skipping live fetch for org=%s",
                org_id,
            )
            return {
                "status": "needs_credentials",
                "mode": "no-op",
                "org_id": org_id,
                "alert_count": 0,
                "findings_recorded": 0,
                "alerts": [],
                "ingested_at": datetime.now(timezone.utc).isoformat(),
                "hint": (
                    "Set DEFENDER_TENANT_ID, DEFENDER_CLIENT_ID, and "
                    "DEFENDER_CLIENT_SECRET to enable live Defender XDR integration."
                ),
            }

        cache_key = (org_id, tenant_id, client_id, filter_str or "")
        if not force_refresh:
            with _cache_lock:
                cached = _result_cache.get(cache_key)
                if cached and time.monotonic() < cached["expires_at"]:
                    _logger.debug(
                        "DefenderXDRLiveConnector: returning cached result for org=%s", org_id
                    )
                    return cached["result"]

        try:
            token = _get_graph_token(tenant_id, client_id, client_secret)
            raw_alerts = _fetch_all_alerts(token, self._max_alerts, filter_str)
        except Exception as exc:
            _logger.error("DefenderXDRLiveConnector: API error for org=%s: %s", org_id, exc)
            return {
                "status": "api_error",
                "mode": "live",
                "org_id": org_id,
                "alert_count": 0,
                "findings_recorded": 0,
                "alerts": [],
                "error": str(exc),
                "ingested_at": datetime.now(timezone.utc).isoformat(),
            }

        normalized: List[Dict[str, Any]] = []
        recorded = 0
        skipped = 0

        for raw in raw_alerts:
            try:
                norm = _normalize_alert(raw)
            except (ValueError, TypeError, KeyError) as exc:
                _logger.warning("DefenderXDRLiveConnector: normalize_alert failed: %s", exc)
                skipped += 1
                continue

            # strip carry-over keys
            alert_id = norm.pop("_alert_id", "")
            norm.pop("_incident_id", None)
            norm.pop("_mitre", None)
            norm.pop("_detection_source", None)
            norm.pop("_evidence_count", None)

            normalized.append({**norm, "alert_id": alert_id})

            if self._findings is not None:
                try:
                    self._findings.record_finding(
                        org_id=org_id,
                        title=norm["title"],
                        finding_type=norm["finding_type"],
                        source_tool=self.SOURCE_TOOL,
                        severity=norm["severity"],
                        cvss_score=norm["cvss_score"],
                        asset_id=norm["asset_id"],
                        asset_type=norm["asset_type"],
                        description=norm["description"],
                        remediation=norm["remediation"],
                        correlation_key=norm["correlation_key"],
                    )
                    recorded += 1
                except (ValueError, TypeError, AttributeError) as exc:
                    _logger.warning(
                        "DefenderXDRLiveConnector: record_finding failed for %s: %s",
                        alert_id, exc,
                    )

        emit_connector_event(
            connector="DefenderXDRLiveConnector",
            org_id=org_id,
            source_kind="edr",
            finding_count=recorded,
            extra={"mode": "live", "alert_count": len(normalized), "skipped": skipped},
        )

        result = {
            "status": "ok",
            "mode": "live",
            "org_id": org_id,
            "alert_count": len(normalized),
            "findings_recorded": recorded,
            "skipped": skipped,
            "alerts": normalized,
            "ingested_at": datetime.now(timezone.utc).isoformat(),
        }

        with _cache_lock:
            _result_cache[cache_key] = {
                "result": result,
                "expires_at": time.monotonic() + _CACHE_TTL_SECONDS,
            }

        return result


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------
_singleton_lock = threading.Lock()
_singleton: Optional[DefenderXDRLiveConnector] = None


def get_defender_xdr_live_connector() -> DefenderXDRLiveConnector:
    """Lazy singleton wired to SecurityFindingsEngine."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            findings = None
            try:
                from core.security_findings_engine import SecurityFindingsEngine
                findings = SecurityFindingsEngine()
            except (ImportError, RuntimeError, OSError) as exc:
                _logger.warning("SecurityFindingsEngine unavailable: %s", exc)
            _singleton = DefenderXDRLiveConnector(findings_engine=findings)
    return _singleton


__all__ = [
    "DefenderXDRLiveConnector",
    "get_defender_xdr_live_connector",
    "_creds_present",
]
