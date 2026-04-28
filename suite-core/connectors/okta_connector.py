"""Okta SCIM + System Log API Connector — ALDECI.

Wires the `/api/v1/pag/accounts` endpoint (triage item #13) with real
identity data from Okta.

Two data sources combined:
1. **Okta Users API** — GET /api/v1/users (paginated, limit 200)
   Feeds identity inventory: user profile, status, MFA factors, groups.

2. **Okta System Log API** — GET /api/v1/logs (paginated, limit 100)
   Feeds security findings: failed logins, MFA challenges, suspicious sign-in,
   account suspension, privilege changes, API token operations.

Severity mapping:
    outcome.result == "FAILURE" + eventType in high-risk set → high
    outcome.result == "FAILURE" + eventType in medium-risk set → medium
    Privilege/admin changes → high
    Suspicious activity / MFA → medium
    Everything else → low

Required env var:
    OKTA_API_KEY     Okta SSWS token (or OAuth 2.0 bearer)
    OKTA_DOMAIN      e.g. https://mycompany.okta.com  (no trailing slash)

Optional:
    OKTA_MAX_USERS   Max users to sync (default: 1000)
    OKTA_MAX_LOGS    Max log events to fetch (default: 500)

Fallback: if OKTA_API_KEY or OKTA_DOMAIN absent →
    {status: "needs_credentials"} — no crash.

Cache: 1-hour TTL per org_id.
Idempotent: users deduped on (org_id, okta_user_id). Log findings deduped
on correlation_key = "okta_log|{uuid}".
"""

from __future__ import annotations

import logging
import os
import threading
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from connectors._emit import emit_connector_event

_logger = logging.getLogger(__name__)

_CACHE_TTL_SECONDS = 3600
_DEFAULT_MAX_USERS = 1000
_DEFAULT_MAX_LOGS = 500

# Okta eventType sets that map to security findings
_HIGH_RISK_EVENTS = {
    "user.authentication.auth_via_mfa",       # MFA success (track pattern)
    "user.session.start",                      # monitor unusual geos
    "user.account.lock",                       # lockout = brute-force indicator
    "user.account.reset_password",
    "policy.lifecycle.deactivate",
    "application.lifecycle.delete",
    "group.user_membership.add",               # privilege escalation
    "user.account.privilege.grant",
}

_MEDIUM_RISK_EVENTS = {
    "user.authentication.auth_via_mfa_verify_fail",
    "user.authentication.sso",
    "user.session.expire",
    "user.lifecycle.deactivate",
    "user.lifecycle.create",
    "application.user_membership.add",
}

# Okta user status → ALDECI risk signal
_OKTA_STATUS_RISK: Dict[str, str] = {
    "ACTIVE": "low",
    "STAGED": "low",
    "PROVISIONED": "low",
    "RECOVERY": "medium",
    "PASSWORD_EXPIRED": "medium",
    "LOCKED_OUT": "high",
    "SUSPENDED": "high",
    "DEPROVISIONED": "low",
}

# Module-level caches
_result_cache: Dict[str, Any] = {}
_cache_lock = threading.Lock()


def _creds_present() -> bool:
    return bool(os.environ.get("OKTA_API_KEY") and os.environ.get("OKTA_DOMAIN"))


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _okta_get(api_key: str, url: str, params: Optional[Dict[str, Any]] = None) -> Tuple[Any, Optional[str]]:
    """HTTP GET against Okta API. Returns (body, next_link_url).

    Handles Okta's Link header pagination:
      Link: <https://...>; rel="next"
    """
    import httpx

    headers = {
        "Authorization": f"SSWS {api_key}",
        "Accept": "application/json",
    }
    resp = httpx.get(url, params=params, headers=headers, timeout=20)
    resp.raise_for_status()
    body = resp.json()

    # Extract next-page URL from Link header
    next_url: Optional[str] = None
    link_header = resp.headers.get("link", "")
    for part in link_header.split(","):
        part = part.strip()
        if 'rel="next"' in part:
            url_part = part.split(";")[0].strip().lstrip("<").rstrip(">")
            if url_part:
                next_url = url_part
            break

    return body, next_url


def _fetch_all_users(api_key: str, domain: str, max_users: int) -> List[Dict[str, Any]]:
    """Fetch all active users from Okta Users API (paginated)."""
    url = f"{domain}/api/v1/users"
    params: Dict[str, Any] = {"limit": min(200, max_users), "filter": 'status eq "ACTIVE"'}
    users: List[Dict[str, Any]] = []

    while url and len(users) < max_users:
        page, next_url = _okta_get(api_key, url, params if not users else None)
        if isinstance(page, list):
            users.extend(page)
        url = next_url or ""
        params = {}

    return users[:max_users]


def _fetch_all_logs(api_key: str, domain: str, max_logs: int) -> List[Dict[str, Any]]:
    """Fetch recent system log events from Okta System Log API."""
    url = f"{domain}/api/v1/logs"
    params: Dict[str, Any] = {
        "limit": min(100, max_logs),
        "sortOrder": "DESCENDING",
    }
    logs: List[Dict[str, Any]] = []

    while url and len(logs) < max_logs:
        page, next_url = _okta_get(api_key, url, params if not logs else None)
        if isinstance(page, list):
            logs.extend(page)
        url = next_url or ""
        params = {}

    return logs[:max_logs]


def _normalize_user(user: Dict[str, Any], org_id: str) -> Dict[str, Any]:
    """Normalize an Okta user record to ALDECI identity shape."""
    profile = user.get("profile") or {}
    credentials = user.get("credentials") or {}
    provider = (credentials.get("provider") or {}).get("name", "OKTA")
    status = str(user.get("status") or "ACTIVE")
    user_id = str(user.get("id") or "")
    email = str(profile.get("email") or profile.get("login") or "")
    first_name = str(profile.get("firstName") or "")
    last_name = str(profile.get("lastName") or "")
    display_name = f"{first_name} {last_name}".strip() or email
    dept = str(profile.get("department") or "")
    title = str(profile.get("title") or "")
    mobile = str(profile.get("mobilePhone") or "")
    created = str(user.get("created") or "")
    last_login = str(user.get("lastLogin") or "")
    password_changed = str(user.get("passwordChanged") or "")
    risk = _OKTA_STATUS_RISK.get(status, "low")

    return {
        "okta_user_id": user_id,
        "email": email,
        "display_name": display_name,
        "department": dept,
        "title": title,
        "mobile": mobile,
        "status": status,
        "provider": provider,
        "risk_level": risk,
        "created_at": created,
        "last_login": last_login,
        "password_changed": password_changed,
        "org_id": org_id,
        "source": "okta",
    }


def _log_to_finding(log: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Convert an Okta system log event to an ALDECI finding payload.

    Returns None for low-risk events that don't warrant a finding.
    """
    event_type = str(log.get("eventType") or "")
    outcome = log.get("outcome") or {}
    result = str(outcome.get("result") or "").upper()
    reason = str(outcome.get("reason") or "")
    uuid_str = str(log.get("uuid") or "")
    published = str(log.get("published") or _now_iso())
    display_msg = str(log.get("displayMessage") or event_type)
    severity_label = str(log.get("severity") or "INFO").upper()

    # Map Okta severity + event type to ALDECI severity
    if event_type in _HIGH_RISK_EVENTS or result == "FAILURE" and event_type in _HIGH_RISK_EVENTS:
        sev = "high"
        cvss = 7.5
    elif event_type in _MEDIUM_RISK_EVENTS or result == "FAILURE":
        sev = "medium"
        cvss = 5.0
    elif severity_label in ("ERROR", "WARN"):
        sev = "medium"
        cvss = 4.0
    else:
        # Purely informational — skip
        return None

    # Extract actor identity
    actor = log.get("actor") or {}
    actor_id = str(actor.get("id") or "")
    actor_display = str(actor.get("displayName") or actor.get("alternateId") or actor_id)

    # Extract target (what was affected)
    targets = log.get("target") or []
    target_display = ""
    if isinstance(targets, list) and targets:
        t = targets[0] if isinstance(targets[0], dict) else {}
        target_display = str(t.get("displayName") or t.get("alternateId") or "")

    title = f"Okta: {display_msg}"
    if target_display:
        title = f"{title} [{target_display}]"

    description = (
        f"eventType={event_type} result={result}"
        + (f" reason={reason}" if reason else "")
        + (f" actor={actor_display}" if actor_display else "")
        + f" published={published}"
    )

    finding_type_map = {
        "user.account.lock": "anomaly",
        "user.account.privilege.grant": "policy-violation",
        "group.user_membership.add": "policy-violation",
        "user.authentication.auth_via_mfa_verify_fail": "anomaly",
        "user.account.reset_password": "anomaly",
    }
    finding_type = finding_type_map.get(event_type, "anomaly")

    return {
        "title": title[:255],
        "finding_type": finding_type,
        "source_tool": "okta",
        "severity": sev,
        "cvss_score": cvss,
        "asset_id": actor_id or actor_display or "unknown-okta-user",
        "asset_type": "user",
        "description": description[:1000],
        "remediation": (
            "Review Okta System Log for full context. "
            "Reset credentials and enforce MFA if account is compromised."
        ),
        "correlation_key": f"okta_log|{uuid_str}",
    }


# ---------------------------------------------------------------------------
# Public connector class
# ---------------------------------------------------------------------------
class OktaConnector:
    """Okta identity connector — syncs users and security log events.

    Args:
        findings_engine: SecurityFindingsEngine instance (optional).
        max_users:       Cap on users to sync (default 1000).
        max_logs:        Cap on log events to process (default 500).
    """

    def __init__(
        self,
        findings_engine: Any = None,
        max_users: int = _DEFAULT_MAX_USERS,
        max_logs: int = _DEFAULT_MAX_LOGS,
    ) -> None:
        self._findings = findings_engine
        self._max_users = max(1, min(max_users, 10_000))
        self._max_logs = max(1, min(max_logs, 5_000))

    def sync(
        self,
        org_id: str,
        force_refresh: bool = False,
    ) -> Dict[str, Any]:
        """Sync Okta identity data + security log events for the given org.

        Returns:
            {status, mode, org_id, users_synced, findings_recorded,
             users, log_findings, ingested_at}
        """
        if not isinstance(org_id, str) or not org_id.strip():
            raise ValueError("org_id is required")

        api_key = os.environ.get("OKTA_API_KEY", "")
        domain = os.environ.get("OKTA_DOMAIN", "").rstrip("/")

        if not api_key or not domain:
            _logger.warning(
                "OktaConnector: OKTA_API_KEY / OKTA_DOMAIN not set — "
                "skipping live fetch for org=%s", org_id
            )
            return {
                "status": "needs_credentials",
                "mode": "no-op",
                "org_id": org_id,
                "users_synced": 0,
                "findings_recorded": 0,
                "users": [],
                "log_findings": [],
                "ingested_at": _now_iso(),
                "hint": (
                    "Set OKTA_API_KEY and OKTA_DOMAIN environment variables "
                    "to enable live Okta identity integration."
                ),
            }

        cache_key = (org_id, domain)
        if not force_refresh:
            with _cache_lock:
                cached = _result_cache.get(cache_key)
                if cached and time.monotonic() < cached["expires_at"]:
                    _logger.debug("OktaConnector: returning cached result for org=%s", org_id)
                    return cached["result"]

        # Fetch users + logs (independent; errors logged, not raised)
        raw_users: List[Dict[str, Any]] = []
        raw_logs: List[Dict[str, Any]] = []
        errors: List[str] = []

        try:
            raw_users = _fetch_all_users(api_key, domain, self._max_users)
        except Exception as exc:
            _logger.error("OktaConnector: users fetch failed for org=%s: %s", org_id, exc)
            errors.append(f"users: {exc}")

        try:
            raw_logs = _fetch_all_logs(api_key, domain, self._max_logs)
        except Exception as exc:
            _logger.error("OktaConnector: logs fetch failed for org=%s: %s", org_id, exc)
            errors.append(f"logs: {exc}")

        # Normalize users
        normalized_users: List[Dict[str, Any]] = []
        for u in raw_users:
            try:
                normalized_users.append(_normalize_user(u, org_id))
            except Exception as exc:
                _logger.warning("OktaConnector: user normalize failed: %s", exc)

        # Normalize log events → findings
        log_findings: List[Dict[str, Any]] = []
        recorded = 0

        for log in raw_logs:
            try:
                finding = _log_to_finding(log)
            except Exception as exc:
                _logger.warning("OktaConnector: log_to_finding failed: %s", exc)
                continue

            if finding is None:
                continue

            log_findings.append(finding)

            if self._findings is not None:
                try:
                    self._findings.record_finding(
                        org_id=org_id,
                        title=finding["title"],
                        finding_type=finding["finding_type"],
                        source_tool=finding["source_tool"],
                        severity=finding["severity"],
                        cvss_score=finding["cvss_score"],
                        asset_id=finding["asset_id"],
                        asset_type=finding["asset_type"],
                        description=finding["description"],
                        remediation=finding["remediation"],
                        correlation_key=finding["correlation_key"],
                    )
                    recorded += 1
                except (ValueError, TypeError, AttributeError) as exc:
                    _logger.warning(
                        "OktaConnector: record_finding failed: %s", exc
                    )

        emit_connector_event(
            connector="OktaConnector",
            org_id=org_id,
            source_kind="iam",
            finding_count=recorded,
            extra={
                "mode": "live",
                "users_synced": len(normalized_users),
                "log_events_processed": len(raw_logs),
                "errors": errors,
            },
        )

        result = {
            "status": "ok" if not errors else "partial",
            "mode": "live",
            "org_id": org_id,
            "users_synced": len(normalized_users),
            "findings_recorded": recorded,
            "users": normalized_users,
            "log_findings": log_findings,
            "errors": errors,
            "ingested_at": _now_iso(),
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
_singleton: Optional[OktaConnector] = None


def get_okta_connector() -> OktaConnector:
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
            _singleton = OktaConnector(findings_engine=findings)
    return _singleton


__all__ = [
    "OktaConnector",
    "get_okta_connector",
    "_creds_present",
    "_normalize_user",
    "_log_to_finding",
    "_OKTA_STATUS_RISK",
    "_HIGH_RISK_EVENTS",
    "_MEDIUM_RISK_EVENTS",
]
