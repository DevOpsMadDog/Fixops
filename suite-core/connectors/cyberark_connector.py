"""CyberArk Privileged Access Manager — Live API Connector (PAM).

Connects to CyberArk PAS REST API to enumerate privileged accounts,
safes, and sessions for ALDECI security findings.

Live API flow:
1. POST /PasswordVault/API/auth/CyberArk/Logon → session token
2. GET  /PasswordVault/API/Safes → list safes (paginated)
3. GET  /PasswordVault/API/Safes/{safe}/Members → safe members
4. GET  /PasswordVault/API/Accounts → privileged accounts (paginated)
5. Normalize to ALDECI common-finding shape
6. Persist via SecurityFindingsEngine.record_finding (idempotent)

Credential fallback:
- CYBERARK_BASE_URL + CYBERARK_USER + CYBERARK_PASS required for live mode.
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

_DEFAULT_BASE_URL = "https://cyberark.example.com"
_CACHE_TTL_SECONDS = 3600
_SESSION_TTL_SECONDS = 1740  # 29 min; CyberArk sessions last 30 min
_PAGE_LIMIT = 100


_token_cache: Dict[str, Any] = {}
_result_cache: Dict[str, Any] = {}
_cache_lock = threading.Lock()


def _creds_present() -> bool:
    return bool(
        os.environ.get("CYBERARK_BASE_URL")
        and os.environ.get("CYBERARK_USER")
        and os.environ.get("CYBERARK_PASS")
    )


def _get_session_token(base_url: str, username: str, password: str) -> str:
    """Obtain or reuse a cached CyberArk session token."""
    cache_key = (base_url, username)
    with _cache_lock:
        cached = _token_cache.get(cache_key)
        if cached and time.monotonic() < cached["expires_at"]:
            return cached["token"]

    import httpx

    url = f"{base_url}/PasswordVault/API/auth/CyberArk/Logon"
    resp = httpx.post(
        url,
        json={"username": username, "password": password},
        headers={"Content-Type": "application/json"},
        timeout=15,
        verify=False,  # CyberArk often uses self-signed certs on-prem
    )
    resp.raise_for_status()
    token = resp.text.strip('"')
    if not token:
        raise ValueError("CyberArk Logon returned no session token")

    with _cache_lock:
        _token_cache[cache_key] = {
            "token": token,
            "expires_at": time.monotonic() + _SESSION_TTL_SECONDS,
        }
    return token


def _paginate(base_url: str, token: str, endpoint: str, limit: int = _PAGE_LIMIT) -> List[Dict[str, Any]]:
    """Page through a CyberArk list endpoint (offset-based)."""
    import httpx

    headers = {"Authorization": token, "Content-Type": "application/json"}
    items: List[Dict[str, Any]] = []
    offset = 0

    while True:
        params = {"limit": limit, "offset": offset}
        resp = httpx.get(
            f"{base_url}{endpoint}",
            params=params,
            headers=headers,
            timeout=20,
            verify=False,
        )
        if resp.status_code == 404:
            break
        resp.raise_for_status()
        body = resp.json()
        batch = body.get("value") or body.get("Accounts") or body.get("Safes") or []
        items.extend(batch)
        total = int(body.get("count") or body.get("Total") or 0)
        offset += len(batch)
        if not batch or offset >= total:
            break

    return items


def _normalize_account(account: Dict[str, Any]) -> Dict[str, Any]:
    """Normalize a CyberArk privileged account to ALDECI finding shape."""
    account_id = str(account.get("id") or account.get("AccountID") or "unknown")
    name = account.get("name") or account.get("AccountName") or account_id
    platform = account.get("platformId") or account.get("PlatformID") or "unknown"
    safe = account.get("safeName") or account.get("Safe") or "unknown"
    username_field = account.get("userName") or account.get("UserName") or ""
    address = account.get("address") or account.get("Address") or ""
    last_modified = account.get("lastModifiedTime") or ""

    # Score severity by platform type
    severity = "low"
    if any(kw in platform.lower() for kw in ("domain", "admin", "root", "service")):
        severity = "medium"
    if any(kw in platform.lower() for kw in ("domainadmin", "localadmin")):
        severity = "high"

    return {
        "asset_id": f"cyberark:account:{account_id}",
        "asset_type": "privileged_account",
        "title": f"CyberArk privileged account: {name} ({platform})",
        "description": (
            f"Privileged account '{name}' on platform '{platform}' "
            f"in safe '{safe}'. User: {username_field}. Address: {address}. "
            f"Last modified: {last_modified}."
        ),
        "severity": severity,
        "cvss_score": 0.0,
        "source_tool": "cyberark_pam",
        "finding_type": "pam",
        "safe": safe,
        "platform": platform,
        "account_id": account_id,
        "correlation_key": f"cyberark_account|{account_id}",
        "remediation": (
            "Review privileged account necessity and permissions. "
            "Ensure just-in-time access is enforced and accounts are rotated per policy."
        ),
    }


class CyberArkConnector:
    """CyberArk PAM connector with credential fallback and 1-hour cache.

    Args:
        findings_engine: SecurityFindingsEngine instance (optional).
        base_url:        Override CYBERARK_BASE_URL env var.
        max_accounts:    Cap on accounts to fetch per call.
    """

    def __init__(
        self,
        findings_engine: Any = None,
        base_url: Optional[str] = None,
        max_accounts: int = 1000,
    ) -> None:
        self._findings = findings_engine
        self._base_url = (
            base_url or os.environ.get("CYBERARK_BASE_URL") or _DEFAULT_BASE_URL
        ).rstrip("/")
        self._max_accounts = max(1, min(max_accounts, 50_000))

    def sync(
        self,
        org_id: str,
        force_refresh: bool = False,
    ) -> Dict[str, Any]:
        """Sync CyberArk privileged accounts for an org.

        Returns normalized ALDECI findings. Gracefully returns
        {status: "needs_credentials"} when env vars are absent.
        """
        if not isinstance(org_id, str) or not org_id.strip():
            raise ValueError("org_id is required")

        username = os.environ.get("CYBERARK_USER", "")
        password = os.environ.get("CYBERARK_PASS", "")

        if not username or not password:
            _logger.warning(
                "CyberArkConnector: CYBERARK_USER/CYBERARK_PASS not set — skipping for org=%s",
                org_id,
            )
            return {
                "status": "needs_credentials",
                "mode": "no-op",
                "org_id": org_id,
                "accounts_scanned": 0,
                "findings_recorded": 0,
                "findings": [],
                "ingested_at": datetime.now(timezone.utc).isoformat(),
                "hint": (
                    "Set CYBERARK_BASE_URL, CYBERARK_USER, and CYBERARK_PASS "
                    "environment variables to enable live CyberArk integration."
                ),
            }

        cache_key = (org_id, self._base_url)
        if not force_refresh:
            with _cache_lock:
                cached = _result_cache.get(cache_key)
                if cached and time.monotonic() < cached["expires_at"]:
                    return cached["result"]

        try:
            token = _get_session_token(self._base_url, username, password)
            accounts = _paginate(self._base_url, token, "/PasswordVault/API/Accounts")
            accounts = accounts[: self._max_accounts]
        except Exception as exc:
            _logger.error("CyberArkConnector: API error for org=%s: %s", org_id, exc)
            return {
                "status": "api_error",
                "mode": "live",
                "org_id": org_id,
                "accounts_scanned": 0,
                "findings_recorded": 0,
                "findings": [],
                "error": str(exc),
                "ingested_at": datetime.now(timezone.utc).isoformat(),
            }

        all_findings: List[Dict[str, Any]] = []
        recorded = 0

        for account in accounts:
            finding = _normalize_account(account)
            all_findings.append(finding)

            if self._findings is not None:
                try:
                    self._findings.record_finding(
                        org_id=org_id,
                        title=finding["title"][:200],
                        finding_type=finding["finding_type"],
                        source_tool=finding["source_tool"],
                        severity=finding["severity"],
                        cvss_score=finding["cvss_score"],
                        asset_id=finding["asset_id"][:200],
                        asset_type=finding["asset_type"],
                        description=finding["description"][:500],
                        remediation=finding["remediation"],
                        correlation_key=finding["correlation_key"],
                    )
                    recorded += 1
                except Exception as exc:
                    _logger.warning("CyberArkConnector: record_finding failed: %s", exc)

        emit_connector_event(
            connector="CyberArkConnector",
            org_id=org_id,
            source_kind="iam",
            finding_count=recorded,
            extra={"mode": "live", "accounts_scanned": len(accounts)},
        )

        result = {
            "status": "ok",
            "mode": "live",
            "org_id": org_id,
            "accounts_scanned": len(accounts),
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
_singleton: Optional[CyberArkConnector] = None


def get_cyberark_connector() -> CyberArkConnector:
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
            _singleton = CyberArkConnector(findings_engine=findings)
    return _singleton


__all__ = [
    "CyberArkConnector",
    "get_cyberark_connector",
    "_creds_present",
    "_normalize_account",
]
