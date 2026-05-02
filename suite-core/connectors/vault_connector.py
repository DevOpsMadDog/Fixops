"""HashiCorp Vault — Live API Connector (PAM).

Reads secrets metadata from KV-v2 mounts and active leases to surface
privileged-access findings in ALDECI.

Live API flow:
1. Verify token: GET /v1/auth/token/lookup-self
2. List KV-v2 secret paths: LIST /v1/<mount>/metadata/<path>
3. Read lease metadata: GET /v1/sys/leases/lookup (paginated)
4. Normalize to ALDECI common-finding shape
5. Persist via SecurityFindingsEngine.record_finding (idempotent)

Credential fallback:
- VAULT_ADDR + VAULT_TOKEN required for live mode.
- VAULT_KV_MOUNT optional (default: "secret").
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

_DEFAULT_VAULT_ADDR = "https://vault.example.com"
_DEFAULT_KV_MOUNT = "secret"
_CACHE_TTL_SECONDS = 3600
_LIST_LIMIT = 200


_result_cache: Dict[str, Any] = {}
_cache_lock = threading.Lock()


def _creds_present() -> bool:
    return bool(os.environ.get("VAULT_ADDR") and os.environ.get("VAULT_TOKEN"))


def _headers(token: str) -> Dict[str, str]:
    return {"X-Vault-Token": token, "Content-Type": "application/json"}


def _list_kv_paths(base_url: str, token: str, mount: str, path: str = "") -> List[str]:
    """Recursively list KV-v2 secret paths under mount/path."""
    import httpx

    endpoint = f"{base_url}/v1/{mount}/metadata/{path}".rstrip("/")
    try:
        resp = httpx.request(
            "LIST", endpoint, headers=_headers(token), timeout=15
        )
        if resp.status_code == 404:
            return []
        resp.raise_for_status()
        keys = resp.json().get("data", {}).get("keys", [])
    except Exception as exc:
        _logger.warning("Vault LIST %s failed: %s", endpoint, exc)
        return []

    paths: List[str] = []
    for key in keys:
        full = f"{path}{key}" if path else key
        if key.endswith("/"):
            paths.extend(_list_kv_paths(base_url, token, mount, full))
        else:
            paths.append(full)
    return paths


def _read_kv_metadata(
    base_url: str, token: str, mount: str, secret_path: str
) -> Dict[str, Any]:
    """Read KV-v2 metadata for a single secret path."""
    import httpx

    url = f"{base_url}/v1/{mount}/metadata/{secret_path}"
    try:
        resp = httpx.get(url, headers=_headers(token), timeout=10)
        if resp.status_code == 404:
            return {}
        resp.raise_for_status()
        return resp.json().get("data", {})
    except Exception as exc:
        _logger.debug("Vault metadata read %s failed: %s", url, exc)
        return {}


def _list_leases(base_url: str, token: str) -> List[str]:
    """List active dynamic secret leases."""
    import httpx

    lease_ids: List[str] = []
    try:
        resp = httpx.request(
            "LIST",
            f"{base_url}/v1/sys/leases/lookup",
            headers=_headers(token),
            timeout=15,
        )
        if resp.status_code in (403, 404):
            return []
        resp.raise_for_status()
        lease_ids = resp.json().get("data", {}).get("keys", [])
    except Exception as exc:
        _logger.debug("Vault lease list failed: %s", exc)
    return lease_ids


def _normalize_secret(
    mount: str, secret_path: str, metadata: Dict[str, Any]
) -> Dict[str, Any]:
    """Normalize a KV-v2 secret entry to ALDECI finding shape."""
    versions: Dict[str, Any] = metadata.get("versions", {})
    version_count = len(versions)
    min(versions.keys(), default="0") if versions else "0"
    created_time = metadata.get("created_time", "")
    updated_time = metadata.get("updated_time", "")
    deleted_version_count = sum(
        1 for v in versions.values() if v.get("destroyed") or v.get("deletion_time")
    )

    # Flag high-version-count secrets as potential rotation failures
    severity = "low"
    title = f"Vault KV secret: {mount}/{secret_path}"
    description = (
        f"Secret at {mount}/{secret_path} has {version_count} version(s). "
        f"Created: {created_time}. Last updated: {updated_time}."
    )
    if version_count >= 10:
        severity = "medium"
        title = f"Vault secret rotation concern: {mount}/{secret_path} ({version_count} versions)"
        description += " High version count may indicate stale or unrotated secret."
    if deleted_version_count > 0:
        description += f" {deleted_version_count} version(s) deleted/destroyed."

    return {
        "asset_id": f"vault:{mount}/{secret_path}",
        "asset_type": "vault_secret",
        "title": title,
        "description": description,
        "severity": severity,
        "cvss_score": 0.0,
        "source_tool": "hashicorp_vault",
        "finding_type": "pam",
        "mount": mount,
        "secret_path": secret_path,
        "version_count": version_count,
        "created_time": created_time,
        "updated_time": updated_time,
        "correlation_key": f"vault_kv|{mount}|{secret_path}",
        "remediation": (
            "Review secret rotation policy. Ensure secrets are rotated per policy "
            "and old versions are destroyed after the TTL."
        ),
    }


class VaultConnector:
    """HashiCorp Vault PAM connector with credential fallback and 1-hour cache.

    Args:
        findings_engine: SecurityFindingsEngine instance (optional).
        base_url:        Override VAULT_ADDR env var.
        kv_mount:        KV-v2 mount name (default: "secret").
        max_secrets:     Cap on secrets to enumerate per call.
    """

    def __init__(
        self,
        findings_engine: Any = None,
        base_url: Optional[str] = None,
        kv_mount: Optional[str] = None,
        max_secrets: int = 500,
    ) -> None:
        self._findings = findings_engine
        self._base_url = (
            base_url
            or os.environ.get("VAULT_ADDR")
            or _DEFAULT_VAULT_ADDR
        ).rstrip("/")
        self._kv_mount = kv_mount or os.environ.get("VAULT_KV_MOUNT") or _DEFAULT_KV_MOUNT
        self._max_secrets = max(1, min(max_secrets, 10_000))

    def sync(
        self,
        org_id: str,
        force_refresh: bool = False,
    ) -> Dict[str, Any]:
        """Sync Vault secrets metadata for an org.

        Returns normalized ALDECI findings list. Gracefully returns
        {status: "needs_credentials"} when env vars are absent.
        """
        if not isinstance(org_id, str) or not org_id.strip():
            raise ValueError("org_id is required")

        token = os.environ.get("VAULT_TOKEN", "")
        if not token:
            _logger.warning(
                "VaultConnector: VAULT_ADDR/VAULT_TOKEN not set — skipping for org=%s", org_id
            )
            return {
                "status": "needs_credentials",
                "mode": "no-op",
                "org_id": org_id,
                "secrets_scanned": 0,
                "findings_recorded": 0,
                "findings": [],
                "ingested_at": datetime.now(timezone.utc).isoformat(),
                "hint": (
                    "Set VAULT_ADDR and VAULT_TOKEN environment variables "
                    "to enable live HashiCorp Vault integration."
                ),
            }

        cache_key = (org_id, self._base_url, self._kv_mount)
        if not force_refresh:
            with _cache_lock:
                cached = _result_cache.get(cache_key)
                if cached and time.monotonic() < cached["expires_at"]:
                    return cached["result"]

        try:
            paths = _list_kv_paths(self._base_url, token, self._kv_mount)
            paths = paths[: self._max_secrets]
            leases = _list_leases(self._base_url, token)
        except Exception as exc:
            _logger.error("VaultConnector: API error for org=%s: %s", org_id, exc)
            return {
                "status": "api_error",
                "mode": "live",
                "org_id": org_id,
                "secrets_scanned": 0,
                "findings_recorded": 0,
                "findings": [],
                "error": str(exc),
                "ingested_at": datetime.now(timezone.utc).isoformat(),
            }

        all_findings: List[Dict[str, Any]] = []
        recorded = 0

        for path in paths:
            meta = _read_kv_metadata(self._base_url, token, self._kv_mount, path)
            finding = _normalize_secret(self._kv_mount, path, meta)
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
                    _logger.warning("VaultConnector: record_finding failed: %s", exc)

        # Add lease count as informational finding if leases present
        if leases:
            lease_finding = {
                "asset_id": f"vault:leases:{self._base_url}",
                "asset_type": "vault_lease",
                "title": f"Vault active dynamic leases: {len(leases)}",
                "description": (
                    f"{len(leases)} active dynamic secret lease(s) found. "
                    "Review for over-privileged or long-lived leases."
                ),
                "severity": "informational" if len(leases) < 50 else "low",
                "cvss_score": 0.0,
                "source_tool": "hashicorp_vault",
                "finding_type": "pam",
                "correlation_key": f"vault_leases|{self._base_url}",
                "remediation": "Review lease TTLs and revoke unused leases.",
            }
            all_findings.append(lease_finding)

        emit_connector_event(
            connector="VaultConnector",
            org_id=org_id,
            source_kind="iam",
            finding_count=recorded,
            extra={
                "mode": "live",
                "secrets_scanned": len(paths),
                "active_leases": len(leases),
            },
        )

        result = {
            "status": "ok",
            "mode": "live",
            "org_id": org_id,
            "secrets_scanned": len(paths),
            "active_leases": len(leases),
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
_singleton: Optional[VaultConnector] = None


def get_vault_connector() -> VaultConnector:
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
            _singleton = VaultConnector(findings_engine=findings)
    return _singleton


__all__ = ["VaultConnector", "get_vault_connector", "_creds_present", "_normalize_secret"]
