"""Splunk SOAR (Phantom) — Live API Connector.

Fetches containers (incidents/events), artifacts, and playbook runs from
Splunk SOAR REST API to surface SOAR findings in ALDECI and trigger playbooks.

Live API flow:
1. GET  /rest/container          (paginated; security incidents/events)
2. GET  /rest/artifact           (IOC artifacts per container)
3. POST /rest/playbook_run       (trigger a playbook on a container)
4. Normalize containers → ALDECI common-finding shape
5. Persist via SecurityFindingsEngine.record_finding (idempotent)

Credential fallback:
- SPLUNK_SOAR_BASE_URL + SPLUNK_SOAR_TOKEN required.
- If credentials absent → graceful no-op: returns {status: "needs_credentials"}.

Cache: 1-hour TTL per org_id. Idempotent via correlation_key.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from connectors._emit import emit_connector_event

_logger = logging.getLogger(__name__)

_DEFAULT_BASE_URL = "https://soar.example.com"
_CACHE_TTL_SECONDS = 3600
_PAGE_SIZE = 100

_result_cache: Dict[str, Any] = {}
_cache_lock = threading.Lock()


def _creds_present() -> bool:
    return bool(
        os.environ.get("SPLUNK_SOAR_BASE_URL") and os.environ.get("SPLUNK_SOAR_TOKEN")
    )


def _headers() -> Dict[str, str]:
    return {
        "ph-auth-token": os.environ.get("SPLUNK_SOAR_TOKEN", ""),
        "Content-Type": "application/json",
        "Accept": "application/json",
    }


def _paginate(base_url: str, endpoint: str, params: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """Page through a Splunk SOAR list endpoint (page_size + page offset)."""
    import httpx

    items: List[Dict[str, Any]] = []
    page = 0
    base_params = dict(params or {})
    base_params["page_size"] = _PAGE_SIZE

    while True:
        base_params["page"] = page
        resp = httpx.get(
            f"{base_url}{endpoint}",
            params=base_params,
            headers=_headers(),
            timeout=30,
            verify=False,  # SOAR often uses self-signed certs
        )
        if resp.status_code in (401, 403, 404):
            break
        resp.raise_for_status()
        body = resp.json()
        batch = body.get("data") or body.get("results") or []
        items.extend(batch)
        total = int(body.get("count") or body.get("total") or 0)
        page += 1
        if not batch or len(items) >= total:
            break

    return items


_SEVERITY_MAP = {
    "high": "high",
    "medium": "medium",
    "low": "low",
    "critical": "critical",
    "1": "low",
    "2": "medium",
    "3": "high",
    "4": "critical",
}

_STATUS_MAP = {
    "1": "new",
    "2": "open",
    "3": "closed",
    "new": "new",
    "open": "open",
    "closed": "closed",
    "resolved": "closed",
}


def _normalize_container(container: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a Splunk SOAR container to ALDECI common-finding shape."""
    container_id = str(container.get("id") or "unknown")
    name = container.get("name") or f"SOAR Container {container_id}"
    description = container.get("description") or container.get("label") or ""
    raw_sev = str(container.get("severity") or container.get("severity_id") or "medium").lower()
    severity = _SEVERITY_MAP.get(raw_sev, "medium")
    raw_status = str(container.get("status") or container.get("status_id") or "open").lower()
    status = _STATUS_MAP.get(raw_status, raw_status)
    label = container.get("label") or ""
    owner = container.get("owner_name") or container.get("owner") or ""
    asset_name = container.get("asset_name") or container.get("asset") or ""
    artifact_count = int(container.get("artifact_count") or 0)
    create_time = container.get("create_time") or container.get("start_time") or ""
    due_time = container.get("due_time") or ""

    return {
        "asset_id": f"soar:container:{container_id}",
        "asset_type": "soar_incident",
        "title": name[:200],
        "description": (
            f"SOAR incident '{name}' (status: {status}, label: {label}). "
            f"{description} "
            f"Owner: {owner}. Asset: {asset_name}. "
            f"Artifacts: {artifact_count}. Created: {create_time}."
            + (f" Due: {due_time}." if due_time else "")
        )[:500],
        "severity": severity,
        "cvss_score": 0.0,
        "source_tool": "splunk_soar",
        "finding_type": "incident",
        "container_id": container_id,
        "status": status,
        "label": label,
        "artifact_count": artifact_count,
        "correlation_key": f"soar_container|{container_id}",
        "remediation": (
            f"Review container {container_id} in Splunk SOAR and execute the appropriate playbook."
        ),
    }


def trigger_playbook(
    org_id: str,
    container_id: str,
    playbook_id: str,
    base_url: Optional[str] = None,
) -> Dict[str, Any]:
    """Trigger a Splunk SOAR playbook on a container.

    Args:
        org_id:       ALDECI tenant identifier (for logging).
        container_id: SOAR container ID.
        playbook_id:  SOAR playbook ID (integer or name string).
        base_url:     Override SPLUNK_SOAR_BASE_URL.

    Returns:
        {status, playbook_run_id, container_id, triggered_at} or error dict.
    """
    token = os.environ.get("SPLUNK_SOAR_TOKEN", "")
    if not token:
        return {
            "status": "needs_credentials",
            "hint": "Set SPLUNK_SOAR_BASE_URL and SPLUNK_SOAR_TOKEN.",
        }

    effective_base = (base_url or os.environ.get("SPLUNK_SOAR_BASE_URL") or _DEFAULT_BASE_URL).rstrip("/")

    try:
        import httpx
        payload = {
            "container_id": int(container_id),
            "playbook_id": playbook_id,
            "scope": "new",
            "run": True,
        }
        resp = httpx.post(
            f"{effective_base}/rest/playbook_run",
            json=payload,
            headers=_headers(),
            timeout=20,
            verify=False,
        )
        resp.raise_for_status()
        body = resp.json()
        run_id = body.get("playbook_run_id") or body.get("id")
        _logger.info(
            "SplunkSOARConnector: triggered playbook %s on container %s for org=%s → run_id=%s",
            playbook_id, container_id, org_id, run_id,
        )
        return {
            "status": "ok",
            "playbook_run_id": run_id,
            "container_id": container_id,
            "triggered_at": datetime.now(timezone.utc).isoformat(),
        }
    except Exception as exc:
        _logger.error("trigger_playbook failed: %s", exc)
        return {
            "status": "error",
            "error": str(exc),
            "container_id": container_id,
        }


class SplunkSOARConnector:
    """Splunk SOAR / Phantom connector with credential fallback and 1-hour cache.

    Args:
        findings_engine: SecurityFindingsEngine instance (optional).
        base_url:        Override SPLUNK_SOAR_BASE_URL env var.
        max_containers:  Cap on containers to fetch per call.
        label_filter:    Only fetch containers with this label (optional).
    """

    def __init__(
        self,
        findings_engine: Any = None,
        base_url: Optional[str] = None,
        max_containers: int = 1000,
        label_filter: Optional[str] = None,
    ) -> None:
        self._findings = findings_engine
        self._base_url = (
            base_url or os.environ.get("SPLUNK_SOAR_BASE_URL") or _DEFAULT_BASE_URL
        ).rstrip("/")
        self._max_containers = max(1, min(max_containers, 50_000))
        self._label_filter = label_filter

    def sync(
        self,
        org_id: str,
        force_refresh: bool = False,
    ) -> Dict[str, Any]:
        """Sync Splunk SOAR containers for an org."""
        if not isinstance(org_id, str) or not org_id.strip():
            raise ValueError("org_id is required")

        token = os.environ.get("SPLUNK_SOAR_TOKEN", "")
        if not token:
            _logger.warning(
                "SplunkSOARConnector: SPLUNK_SOAR_TOKEN not set — skipping for org=%s", org_id
            )
            return {
                "status": "needs_credentials",
                "mode": "no-op",
                "org_id": org_id,
                "containers_synced": 0,
                "findings_recorded": 0,
                "findings": [],
                "ingested_at": datetime.now(timezone.utc).isoformat(),
                "hint": (
                    "Set SPLUNK_SOAR_BASE_URL and SPLUNK_SOAR_TOKEN environment variables "
                    "to enable live Splunk SOAR integration."
                ),
            }

        cache_key = (org_id, self._base_url, self._label_filter or "")
        if not force_refresh:
            with _cache_lock:
                cached = _result_cache.get(cache_key)
                if cached and time.monotonic() < cached["expires_at"]:
                    return cached["result"]

        try:
            params: Dict[str, Any] = {"sort": "create_time", "order": "desc"}
            if self._label_filter:
                params["_filter_label"] = f'"{self._label_filter}"'
            containers = _paginate(self._base_url, "/rest/container", params=params)
            containers = containers[: self._max_containers]
        except Exception as exc:
            _logger.error("SplunkSOARConnector: API error for org=%s: %s", org_id, exc)
            return {
                "status": "api_error",
                "mode": "live",
                "org_id": org_id,
                "containers_synced": 0,
                "findings_recorded": 0,
                "findings": [],
                "error": str(exc),
                "ingested_at": datetime.now(timezone.utc).isoformat(),
            }

        all_findings: List[Dict[str, Any]] = []
        recorded = 0

        for container in containers:
            finding = _normalize_container(container)
            all_findings.append(finding)

            if self._findings is not None:
                try:
                    self._findings.record_finding(
                        org_id=org_id,
                        title=finding["title"],
                        finding_type=finding["finding_type"],
                        source_tool=finding["source_tool"],
                        severity=finding["severity"],
                        cvss_score=finding["cvss_score"],
                        asset_id=finding["asset_id"][:200],
                        asset_type=finding["asset_type"],
                        description=finding["description"],
                        remediation=finding["remediation"],
                        correlation_key=finding["correlation_key"],
                    )
                    recorded += 1
                except Exception as exc:
                    _logger.warning("SplunkSOARConnector: record_finding failed: %s", exc)

        emit_connector_event(
            connector="SplunkSOARConnector",
            org_id=org_id,
            source_kind="incident",
            finding_count=recorded,
            extra={"mode": "live", "containers_synced": len(containers)},
        )

        result = {
            "status": "ok",
            "mode": "live",
            "org_id": org_id,
            "containers_synced": len(containers),
            "findings_recorded": recorded,
            "findings": all_findings,
            "ingested_at": datetime.now(timezone.utc).isoformat(),
        }

        with _cache_lock:
            _result_cache[cache_key] = {
                "result": result,
                "expires_at": time.monotonic() + _CACHE_TTL_SECONDS,
            }

        return result


_singleton_lock = threading.Lock()
_singleton: Optional[SplunkSOARConnector] = None


def get_splunk_soar_connector() -> SplunkSOARConnector:
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
            _singleton = SplunkSOARConnector(findings_engine=findings)
    return _singleton


__all__ = [
    "SplunkSOARConnector",
    "get_splunk_soar_connector",
    "trigger_playbook",
    "_creds_present",
    "_normalize_container",
]
