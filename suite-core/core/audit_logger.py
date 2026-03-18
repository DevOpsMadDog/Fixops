"""Structured security audit logger for ALdeci/FixOps.

Provides a single ``SecurityAuditLogger`` class that records security-relevant
events to two sinks simultaneously:
  1. structlog (JSON lines on stdout/stderr, hooked into the app log pipeline)
  2. ``data/audit_security.log`` — a dedicated append-only file for SIEM ingestion

Event categories tracked:
  - login_attempt (success/failure)
  - permission_denied
  - scanner_execution
  - autofix_application
  - api_key_usage
  - admin_action

Each event carries:
  - event_type       (str) — category above
  - outcome          (str) — "success" | "failure" | "error" | "blocked"
  - user_id          (str | None)
  - client_ip        (str | None)
  - resource         (str | None) — e.g. scanner name, finding id
  - details          (dict)       — event-specific payload
  - correlation_id   (str | None) — from request context
  - timestamp        (ISO-8601 UTC)

Usage example::

    from core.audit_logger import get_audit_logger

    audit = get_audit_logger()

    # In an auth handler:
    audit.log_login_attempt(user_id="alice", client_ip="10.0.0.1", success=True)

    # After API key validation fails:
    audit.log_permission_denied(
        user_id=None, client_ip="10.0.0.1",
        resource="/api/v1/admin/config", reason="missing scope admin:all"
    )

    # After a scanner finishes:
    audit.log_scanner_execution(
        scanner="sast", app_id="app-abc",
        findings_count=12, duration_seconds=3.4,
        correlation_id=request.state.correlation_id
    )

    # After AutoFix is applied:
    audit.log_autofix_application(
        user_id="alice", finding_id="CVE-2024-1234",
        action="apply_patch", outcome="success"
    )
"""

from __future__ import annotations

import json
import logging
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

import structlog

# ---------------------------------------------------------------------------
# Module-level logger (structlog)
# ---------------------------------------------------------------------------
_structlog_logger = structlog.get_logger("security.audit")

# ---------------------------------------------------------------------------
# Dedicated file sink
# ---------------------------------------------------------------------------
_FILE_HANDLER_LOCK = threading.Lock()
_file_handler: Optional[logging.FileHandler] = None
_file_logger: Optional[logging.Logger] = None


def _get_file_logger() -> logging.Logger:
    """Return (or lazily create) the dedicated security audit file logger.

    The log file is placed at ``data/audit_security.log`` relative to the
    current working directory, which is the repo root when running via uvicorn
    or Docker.  The path can be overridden with ``FIXOPS_AUDIT_LOG_PATH``.
    """
    global _file_handler, _file_logger

    if _file_logger is not None:
        return _file_logger

    with _FILE_HANDLER_LOCK:
        if _file_logger is not None:
            return _file_logger

        log_path_str = os.getenv(
            "FIXOPS_AUDIT_LOG_PATH",
            os.path.join(os.getcwd(), "data", "audit_security.log"),
        )
        log_path = Path(log_path_str)
        log_path.parent.mkdir(parents=True, exist_ok=True)

        _file_logger = logging.getLogger("fixops.security.audit.file")
        _file_logger.setLevel(logging.INFO)
        _file_logger.propagate = False  # do NOT bubble up to root logger

        handler = logging.FileHandler(str(log_path), encoding="utf-8")
        handler.setLevel(logging.INFO)
        # One JSON object per line — easy for Splunk/Elasticsearch to ingest
        handler.setFormatter(logging.Formatter("%(message)s"))
        _file_logger.addHandler(handler)
        _file_handler = handler

    return _file_logger


# ---------------------------------------------------------------------------
# Core event writer
# ---------------------------------------------------------------------------

def _write_event(event_type: str, payload: Dict[str, Any]) -> None:
    """Write one audit event to both structlog and the dedicated file.

    Never raises — audit logging must never break request handling.
    """
    timestamp = datetime.now(timezone.utc).isoformat() + "Z"
    full_payload = {
        "event_type": event_type,
        "timestamp": timestamp,
        **payload,
    }

    # Sink 1: structlog (ends up in the application log stream as JSON)
    try:
        _structlog_logger.info(event_type, **full_payload)
    except (OSError, ValueError, RuntimeError):  # narrowed from bare Exception
        pass

    # Sink 2: dedicated security audit file (one JSON line per event)
    try:
        file_logger = _get_file_logger()
        file_logger.info(json.dumps(full_payload, default=str))
    except (OSError, ValueError, RuntimeError):  # narrowed from bare Exception
        pass


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class SecurityAuditLogger:
    """Structured security event logger.

    Instantiate once and reuse (module-level singleton via ``get_audit_logger()``).
    All methods are synchronous and thread-safe.
    """

    # ------------------------------------------------------------------
    # Authentication
    # ------------------------------------------------------------------

    def log_login_attempt(
        self,
        *,
        user_id: Optional[str] = None,
        client_ip: Optional[str] = None,
        success: bool,
        auth_method: str = "token",
        correlation_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log an authentication attempt (success or failure).

        Failed login attempts are tracked for brute-force detection.
        """
        _write_event(
            "auth.login_attempt",
            {
                "outcome": "success" if success else "failure",
                "user_id": user_id,
                "client_ip": client_ip,
                "auth_method": auth_method,
                "correlation_id": correlation_id,
                "details": details or {},
            },
        )

    # ------------------------------------------------------------------
    # Authorization
    # ------------------------------------------------------------------

    def log_permission_denied(
        self,
        *,
        user_id: Optional[str] = None,
        client_ip: Optional[str] = None,
        resource: Optional[str] = None,
        reason: Optional[str] = None,
        required_scope: Optional[str] = None,
        correlation_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log a permission denied / authorization failure event."""
        _write_event(
            "authz.permission_denied",
            {
                "outcome": "blocked",
                "user_id": user_id,
                "client_ip": client_ip,
                "resource": resource,
                "reason": reason,
                "required_scope": required_scope,
                "correlation_id": correlation_id,
                "details": details or {},
            },
        )

    # ------------------------------------------------------------------
    # Scanner execution
    # ------------------------------------------------------------------

    def log_scanner_execution(
        self,
        *,
        scanner: str,
        app_id: Optional[str] = None,
        findings_count: int = 0,
        duration_seconds: Optional[float] = None,
        outcome: str = "success",
        user_id: Optional[str] = None,
        client_ip: Optional[str] = None,
        correlation_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log a scanner execution event.

        Args:
            scanner: Scanner name (sast, dast, secrets, container, cspm, iac, malware, api_fuzzer)
            app_id: Application ID being scanned
            findings_count: Number of findings produced
            duration_seconds: Execution wall-clock time
            outcome: "success" | "error" | "timeout"
        """
        _write_event(
            "scanner.execution",
            {
                "outcome": outcome,
                "scanner": scanner,
                "app_id": app_id,
                "findings_count": findings_count,
                "duration_seconds": duration_seconds,
                "user_id": user_id,
                "client_ip": client_ip,
                "correlation_id": correlation_id,
                "details": details or {},
            },
        )

    # ------------------------------------------------------------------
    # AutoFix
    # ------------------------------------------------------------------

    def log_autofix_application(
        self,
        *,
        finding_id: Optional[str] = None,
        action: str = "apply_patch",
        outcome: str = "success",
        user_id: Optional[str] = None,
        client_ip: Optional[str] = None,
        correlation_id: Optional[str] = None,
        fix_type: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log an AutoFix application event.

        Args:
            finding_id: The vulnerability/finding that was auto-fixed
            action: "apply_patch" | "generate" | "verify" | "rollback"
            outcome: "success" | "failure" | "error" | "skipped"
            fix_type: e.g. "dependency_update", "code_patch", "config_change"
        """
        _write_event(
            "autofix.application",
            {
                "outcome": outcome,
                "finding_id": finding_id,
                "action": action,
                "fix_type": fix_type,
                "user_id": user_id,
                "client_ip": client_ip,
                "correlation_id": correlation_id,
                "details": details or {},
            },
        )

    # ------------------------------------------------------------------
    # Generic API key usage
    # ------------------------------------------------------------------

    def log_api_key_usage(
        self,
        *,
        outcome: str = "success",
        client_ip: Optional[str] = None,
        endpoint: Optional[str] = None,
        method: Optional[str] = None,
        correlation_id: Optional[str] = None,
    ) -> None:
        """Log notable API key usage events (only failures/anomalies by default)."""
        _write_event(
            "auth.api_key_usage",
            {
                "outcome": outcome,
                "client_ip": client_ip,
                "endpoint": endpoint,
                "method": method,
                "correlation_id": correlation_id,
            },
        )

    # ------------------------------------------------------------------
    # Admin actions
    # ------------------------------------------------------------------

    def log_admin_action(
        self,
        *,
        action: str,
        user_id: Optional[str] = None,
        client_ip: Optional[str] = None,
        resource: Optional[str] = None,
        outcome: str = "success",
        correlation_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Log a privileged/admin action for compliance trail.

        Examples: config changes, user management, token rotation.
        """
        _write_event(
            "admin.action",
            {
                "action": action,
                "outcome": outcome,
                "user_id": user_id,
                "client_ip": client_ip,
                "resource": resource,
                "correlation_id": correlation_id,
                "details": details or {},
            },
        )

    # ------------------------------------------------------------------
    # Generic event (escape hatch)
    # ------------------------------------------------------------------

    def log_event(
        self,
        event_type: str,
        *,
        outcome: str = "info",
        correlation_id: Optional[str] = None,
        **kwargs: Any,
    ) -> None:
        """Write an arbitrary security event to the audit log.

        Use the typed methods above when possible — this is an escape hatch
        for events that do not fit the standard categories.
        """
        _write_event(
            event_type,
            {
                "outcome": outcome,
                "correlation_id": correlation_id,
                **kwargs,
            },
        )


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_singleton: Optional[SecurityAuditLogger] = None
_singleton_lock = threading.Lock()


def get_audit_logger() -> SecurityAuditLogger:
    """Return the process-level SecurityAuditLogger singleton."""
    global _singleton
    if _singleton is None:
        with _singleton_lock:
            if _singleton is None:
                _singleton = SecurityAuditLogger()
    return _singleton


# Convenience alias
audit_logger = get_audit_logger()

__all__ = [
    "SecurityAuditLogger",
    "get_audit_logger",
    "audit_logger",
]
