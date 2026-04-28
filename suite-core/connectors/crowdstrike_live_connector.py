"""CrowdStrike Falcon — Live API Connector.

Extends the existing format-parser connector (crowdstrike_falcon_connector.py)
with a real OAuth2 + REST API polling path.

Live API flow:
1. POST /oauth2/token with client_id + client_secret → bearer token (30-min TTL)
2. GET  /detects/queries/detects/v1 → list of detection IDs (paginated, up to 1000/req)
3. POST /detects/entities/summaries/GET/v1 → batch-fetch detection payloads
4. Normalize via parse_event() (already battle-tested in crowdstrike_falcon_connector)
5. Push to SecurityFindingsEngine.record_finding (idempotent via correlation_key)

Credential fallback:
- CROWDSTRIKE_CLIENT_ID + CROWDSTRIKE_CLIENT_SECRET required for live mode.
- CROWDSTRIKE_BASE_URL optional (default: https://api.crowdstrike.com).
- If credentials absent → graceful no-op: returns {status: "needs_credentials"}.

Cache: 1-hour TTL per (org_id, filter). Re-running within TTL returns cached result.
Idempotent: correlation_key="crowdstrike_falcon|{detection_id}" deduplicates.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from connectors._emit import emit_connector_event
from connectors.crowdstrike_falcon_connector import parse_event

_logger = logging.getLogger(__name__)

_DEFAULT_BASE_URL = "https://api.crowdstrike.com"
_TOKEN_TTL_SECONDS = 1740        # 29 min; Falcon tokens last 30 min
_CACHE_TTL_SECONDS = 3600        # 1 hour result cache
_MAX_IDS_PER_BATCH = 1000        # Falcon /summaries endpoint limit
_DEFAULT_FILTER = "status:'new'+status:'in_progress'"


# ---------------------------------------------------------------------------
# Module-level token + result cache (shared across connector instances)
# ---------------------------------------------------------------------------
_token_cache: Dict[str, Any] = {}   # key: (client_id, base_url)
_result_cache: Dict[str, Any] = {}  # key: (org_id, base_url, filter_expr)
_cache_lock = threading.Lock()


def _creds_present() -> bool:
    return bool(
        os.environ.get("CROWDSTRIKE_CLIENT_ID")
        and os.environ.get("CROWDSTRIKE_CLIENT_SECRET")
    )


def _get_token(base_url: str, client_id: str, client_secret: str) -> str:
    """Obtain or reuse a cached Falcon OAuth2 bearer token."""
    cache_key = (client_id, base_url)
    with _cache_lock:
        cached = _token_cache.get(cache_key)
        if cached and time.monotonic() < cached["expires_at"]:
            return cached["token"]

    import httpx  # lazy import; not available in all envs

    url = f"{base_url}/oauth2/token"
    data = {"client_id": client_id, "client_secret": client_secret}
    resp = httpx.post(url, data=data, timeout=15)
    resp.raise_for_status()
    body = resp.json()
    token = body.get("access_token") or ""
    if not token:
        raise ValueError("Falcon OAuth2 returned no access_token")
    expires_in = int(body.get("expires_in", _TOKEN_TTL_SECONDS))

    with _cache_lock:
        _token_cache[cache_key] = {
            "token": token,
            "expires_at": time.monotonic() + expires_in - 60,
        }
    return token


def _fetch_detection_ids(
    base_url: str,
    token: str,
    filter_expr: str,
    max_ids: int = 9000,
) -> List[str]:
    """Page through /detects/queries/detects/v1 and collect detection IDs."""
    import httpx

    ids: List[str] = []
    offset = 0
    limit = min(1000, max_ids)
    headers = {"Authorization": f"Bearer {token}"}

    while True:
        params: Dict[str, Any] = {
            "limit": limit,
            "offset": offset,
            "sort": "created_timestamp.desc",
        }
        if filter_expr:
            params["filter"] = filter_expr

        resp = httpx.get(
            f"{base_url}/detects/queries/detects/v1",
            params=params,
            headers=headers,
            timeout=20,
        )
        resp.raise_for_status()
        body = resp.json()
        resources: List[str] = body.get("resources") or []
        ids.extend(resources)
        meta = body.get("meta") or {}
        paging = meta.get("pagination") or {}
        total = int(paging.get("total") or 0)
        offset += len(resources)
        if not resources or offset >= total or offset >= max_ids:
            break

    return ids[:max_ids]


def _fetch_detection_summaries(
    base_url: str,
    token: str,
    detection_ids: List[str],
) -> List[Dict[str, Any]]:
    """Batch-fetch detection summaries in chunks of 1000."""
    import httpx

    headers = {"Authorization": f"Bearer {token}"}
    summaries: List[Dict[str, Any]] = []

    for i in range(0, len(detection_ids), _MAX_IDS_PER_BATCH):
        chunk = detection_ids[i : i + _MAX_IDS_PER_BATCH]
        resp = httpx.post(
            f"{base_url}/detects/entities/summaries/GET/v1",
            json={"ids": chunk},
            headers=headers,
            timeout=30,
        )
        resp.raise_for_status()
        body = resp.json()
        summaries.extend(body.get("resources") or [])

    return summaries


# ---------------------------------------------------------------------------
# Public connector class
# ---------------------------------------------------------------------------
class CrowdStrikeLiveConnector:
    """Live Falcon API connector with credential fallback and 1-hour result cache.

    Args:
        findings_engine: SecurityFindingsEngine instance (optional; if None,
                         findings are returned but not persisted).
        base_url:        Override default Falcon API base URL.
        max_detections:  Cap on how many detections to fetch per call.
    """

    def __init__(
        self,
        findings_engine: Any = None,
        base_url: Optional[str] = None,
        max_detections: int = 5000,
    ) -> None:
        self._findings = findings_engine
        self._base_url = (base_url or os.environ.get("CROWDSTRIKE_BASE_URL") or _DEFAULT_BASE_URL).rstrip("/")
        self._max_detections = max(1, min(max_detections, 50_000))

    def fetch_detections(
        self,
        org_id: str,
        filter_expr: str = _DEFAULT_FILTER,
        force_refresh: bool = False,
    ) -> Dict[str, Any]:
        """Fetch live detections from CrowdStrike Falcon REST API.

        Returns normalized ALDECI findings list. Gracefully returns
        {status: "needs_credentials"} when env vars are absent.

        Args:
            org_id:       ALDECI tenant identifier.
            filter_expr:  FQL filter string (default: new+in_progress detections).
            force_refresh: Bypass the 1-hour result cache.

        Returns:
            {status, mode, org_id, detection_count, findings_recorded,
             detections, ingested_at}
        """
        if not isinstance(org_id, str) or not org_id.strip():
            raise ValueError("org_id is required")

        client_id = os.environ.get("CROWDSTRIKE_CLIENT_ID", "")
        client_secret = os.environ.get("CROWDSTRIKE_CLIENT_SECRET", "")

        if not client_id or not client_secret:
            _logger.warning(
                "CrowdStrikeLiveConnector: CROWDSTRIKE_CLIENT_ID / "
                "CROWDSTRIKE_CLIENT_SECRET not set — skipping live fetch for org=%s",
                org_id,
            )
            return {
                "status": "needs_credentials",
                "mode": "no-op",
                "org_id": org_id,
                "detection_count": 0,
                "findings_recorded": 0,
                "detections": [],
                "ingested_at": datetime.now(timezone.utc).isoformat(),
                "hint": (
                    "Set CROWDSTRIKE_CLIENT_ID and CROWDSTRIKE_CLIENT_SECRET "
                    "environment variables to enable live Falcon integration."
                ),
            }

        cache_key = (org_id, self._base_url, filter_expr)
        if not force_refresh:
            with _cache_lock:
                cached = _result_cache.get(cache_key)
                if cached and time.monotonic() < cached["expires_at"]:
                    _logger.debug("CrowdStrikeLiveConnector: returning cached result for org=%s", org_id)
                    return cached["result"]

        try:
            token = _get_token(self._base_url, client_id, client_secret)
            detection_ids = _fetch_detection_ids(
                self._base_url, token, filter_expr, self._max_detections
            )
            raw_summaries = _fetch_detection_summaries(self._base_url, token, detection_ids)
        except Exception as exc:
            _logger.error("CrowdStrikeLiveConnector: API error for org=%s: %s", org_id, exc)
            return {
                "status": "api_error",
                "mode": "live",
                "org_id": org_id,
                "detection_count": 0,
                "findings_recorded": 0,
                "detections": [],
                "error": str(exc),
                "ingested_at": datetime.now(timezone.utc).isoformat(),
            }

        # Normalize and persist
        normalized: List[Dict[str, Any]] = []
        recorded = 0
        failed = 0

        for raw in raw_summaries:
            try:
                parsed = parse_event(raw)
            except (ValueError, TypeError) as exc:
                _logger.warning("CrowdStrikeLiveConnector: parse_event failed: %s", exc)
                failed += 1
                continue

            normalized.append(parsed)

            if self._findings is not None:
                try:
                    sev = parsed["severity"] if parsed["severity"] != "informational" else "low"
                    self._findings.record_finding(
                        org_id=org_id,
                        title=parsed["title"][:200],
                        finding_type="anomaly",
                        source_tool="crowdstrike_falcon",
                        severity=sev,
                        cvss_score=parsed["cvss_score"],
                        asset_id=parsed["asset_id"][:200],
                        asset_type=parsed["asset_type"],
                        description=(
                            parsed["description"]
                            + (f" | cmd: {parsed['cmdline']}" if parsed["cmdline"] else "")
                        )[:500],
                        remediation=(
                            "Investigate in Falcon console. Isolate via "
                            "POST /api/v1/edr/endpoints/{id}/isolate if confirmed malicious."
                        ),
                        correlation_key=f"crowdstrike_falcon|{parsed['detection_id']}",
                    )
                    recorded += 1
                except (ValueError, TypeError, AttributeError) as exc:
                    _logger.warning(
                        "CrowdStrikeLiveConnector: record_finding failed for %s: %s",
                        parsed["detection_id"], exc,
                    )

        emit_connector_event(
            connector="CrowdStrikeLiveConnector",
            org_id=org_id,
            source_kind="edr",
            finding_count=recorded,
            extra={
                "mode": "live",
                "detection_count": len(normalized),
                "failed_parse": failed,
            },
        )

        result = {
            "status": "ok",
            "mode": "live",
            "org_id": org_id,
            "detection_count": len(normalized),
            "findings_recorded": recorded,
            "failed_parse": failed,
            "detections": normalized,
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
_singleton: Optional[CrowdStrikeLiveConnector] = None


def get_crowdstrike_live_connector() -> CrowdStrikeLiveConnector:
    """Lazy singleton — wires SecurityFindingsEngine on first use."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            findings = None
            try:
                from core.security_findings_engine import SecurityFindingsEngine
                findings = SecurityFindingsEngine()
            except (ImportError, RuntimeError, OSError) as exc:
                _logger.warning("SecurityFindingsEngine unavailable: %s", exc)
            _singleton = CrowdStrikeLiveConnector(findings_engine=findings)
    return _singleton


__all__ = [
    "CrowdStrikeLiveConnector",
    "get_crowdstrike_live_connector",
    "_creds_present",
]
