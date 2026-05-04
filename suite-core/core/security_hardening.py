"""
FixOps Security Hardening Module — Defense/FedRAMP Grade

Provides:
- Request size limits (configurable, default 10MB)
- Input sanitization utilities
- SQL injection prevention helpers
- Path traversal prevention
- SSRF protection helper
- Rate limiting per-endpoint configuration class
- IP allowlist/denylist manager class
- Session management with configurable timeout
- Audit event logger that writes to the audit SQLite DB

NIST 800-53 Controls addressed by this module:
  SC-5   (DoS Protection — rate limiting)
  SC-7   (Boundary Protection — IP filtering)
  SI-10  (Information Input Validation — sanitization, SQL injection, path traversal)
  AC-7   (Unsuccessful Logon Attempts — rate limiting auth endpoints)
  AU-2   (Audit Events — SecurityAuditLogger)
  AU-3   (Audit Record Content — structured event logging)
  SC-4   (Information in Shared Resources — session isolation)
  AC-11  (Session Lock — timeout enforcement)

Usage:
    from core.security_hardening import (
        RequestSizeLimiter, InputSanitizer, SQLInjectionGuard,
        PathTraversalGuard, SSRFGuard, RateLimitConfig,
        IPFilterManager, SessionManager, SecurityAuditLogger,
    )
"""
from __future__ import annotations

# ---------------------------------------------------------------------------
# TrustGraph event-bus wiring (auto-added by hub-wiring wave)
# ---------------------------------------------------------------------------
try:  # pragma: no cover - optional dependency
    from core.trustgraph_event_bus import get_event_bus as _get_tg_bus  # type: ignore
except Exception:  # noqa: BLE001
    _get_tg_bus = None  # type: ignore[assignment]


def _emit_event(event_type: str, payload):  # type: ignore[no-untyped-def]
    """Emit an event to the TrustGraph event bus. Never raises."""
    if _get_tg_bus is None:
        return
    try:
        bus = _get_tg_bus()
        if bus is None:
            return
        emit = getattr(bus, "emit", None) or getattr(bus, "publish", None)
        if emit is None:
            return
        result = emit(event_type, payload)
        try:
            import asyncio as _aio
            import inspect as _insp
            if _insp.iscoroutine(result):
                try:
                    loop = _aio.get_running_loop()
                    loop.create_task(result)
                except RuntimeError:
                    result.close()
        except Exception:  # pragma: no cover
            pass
    except Exception:  # pragma: no cover
        pass


# Module-load heartbeat
try:  # pragma: no cover
    _emit_event("engine.loaded", {"module": __name__})
except Exception:  # noqa: BLE001
    pass

import hashlib
import html
import ipaddress
import logging
import os
import re
import sqlite3
import time
import unicodedata
import uuid
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from threading import Lock
from typing import Any, Dict, List, Optional, Set
from urllib.parse import urlparse

from fastapi import HTTPException, Request, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Environment-driven defaults
# ---------------------------------------------------------------------------
_MAX_REQUEST_SIZE_MB: int = int(os.getenv("FIXOPS_MAX_REQUEST_SIZE_MB", "10"))
_MAX_REQUEST_SIZE_BYTES: int = _MAX_REQUEST_SIZE_MB * 1024 * 1024

_RATE_LIMIT_WINDOW_SECONDS: int = int(os.getenv("FIXOPS_RATE_LIMIT_WINDOW", "60"))
_RATE_LIMIT_DEFAULT_MAX: int = int(os.getenv("FIXOPS_RATE_LIMIT_DEFAULT_MAX", "100"))

_SESSION_TIMEOUT_MINUTES: int = int(os.getenv("FIXOPS_SESSION_TIMEOUT", "60"))

_AUDIT_DB_PATH: str = os.getenv("FIXOPS_AUDIT_DB_PATH", "data/audit.db")

# Private RFC-1918 + loopback + link-local ranges (for SSRF protection)
_PRIVATE_RANGES = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

# SQL injection detection patterns
_SQL_INJECTION_PATTERNS: List[re.Pattern] = [
    re.compile(r"(\bUNION\b.*\bSELECT\b)", re.IGNORECASE),
    re.compile(r"(\bSELECT\b.*\bFROM\b)", re.IGNORECASE),
    re.compile(r"(\bINSERT\b.*\bINTO\b)", re.IGNORECASE),
    re.compile(r"(\bUPDATE\b.*\bSET\b)", re.IGNORECASE),
    re.compile(r"(\bDELETE\b.*\bFROM\b)", re.IGNORECASE),
    re.compile(r"(\bDROP\b.*\b(TABLE|DATABASE|SCHEMA)\b)", re.IGNORECASE),
    re.compile(r"(\bEXEC(UTE)?\b.*\()", re.IGNORECASE),
    re.compile(r"(--\s*$)", re.MULTILINE),
    re.compile(r"(;\s*--)", re.IGNORECASE),
    re.compile(r"('.*;.*')", re.IGNORECASE),
    re.compile(r"(\bOR\b\s+\d+\s*=\s*\d+)", re.IGNORECASE),
    re.compile(r"(\bAND\b\s+\d+\s*=\s*\d+)", re.IGNORECASE),
    re.compile(r"(xp_cmdshell)", re.IGNORECASE),
    re.compile(r"(\bINFORMATION_SCHEMA\b)", re.IGNORECASE),
    re.compile(r"(\bSYSTEM_USER\b|\bSESSION_USER\b|\bCURRENT_USER\b)", re.IGNORECASE),
]

# Path traversal detection patterns
_PATH_TRAVERSAL_PATTERNS: List[re.Pattern] = [
    re.compile(r"\.\./"),
    re.compile(r"\.\.\\"),
    re.compile(r"%2e%2e%2f", re.IGNORECASE),
    re.compile(r"%2e%2e/", re.IGNORECASE),
    re.compile(r"\.\.%2f", re.IGNORECASE),
    re.compile(r"%252e%252e%252f", re.IGNORECASE),
    re.compile(r"(?:^|/)\.\.(?:/|$)"),
]

# Dangerous HTML/script patterns
_XSS_PATTERNS: List[re.Pattern] = [
    re.compile(r"<script[^>]*>", re.IGNORECASE),
    re.compile(r"javascript\s*:", re.IGNORECASE),
    re.compile(r"on\w+\s*=", re.IGNORECASE),
    re.compile(r"<iframe[^>]*>", re.IGNORECASE),
    re.compile(r"<object[^>]*>", re.IGNORECASE),
    re.compile(r"<embed[^>]*>", re.IGNORECASE),
    re.compile(r"data:text/html", re.IGNORECASE),
    re.compile(r"vbscript\s*:", re.IGNORECASE),
]


# ===========================================================================
# 1. Request Size Limiter
# ===========================================================================


class RequestSizeLimiter(BaseHTTPMiddleware):
    """
    ASGI middleware that rejects requests exceeding the configured size limit.

    Addresses: NIST SC-5 (DoS Protection), WS STIG WS-009.

    Configuration:
        FIXOPS_MAX_REQUEST_SIZE_MB (default: 10)

    Usage:
        app.add_middleware(RequestSizeLimiter, max_size_bytes=10 * 1024 * 1024)
    """

    def __init__(
        self,
        app,
        max_size_bytes: int = _MAX_REQUEST_SIZE_BYTES,
    ) -> None:
        super().__init__(app)
        self.max_size_bytes = max_size_bytes

    async def dispatch(self, request: Request, call_next) -> Response:
        content_length = request.headers.get("content-length")
        if content_length:
            try:
                length = int(content_length)
                if length > self.max_size_bytes:
                    logger.warning(
                        "Request rejected: Content-Length %d exceeds limit %d. "
                        "IP=%s path=%s",
                        length,
                        self.max_size_bytes,
                        _get_client_ip(request),
                        request.url.path,
                    )
                    return Response(
                        content='{"detail":"Request entity too large"}',
                        status_code=413,
                        media_type="application/json",
                    )
            except ValueError:
                pass

        # Stream-check for chunked transfers without Content-Length
        body_size = 0
        body_chunks: List[bytes] = []

        async for chunk in request.stream():
            body_size += len(chunk)
            if body_size > self.max_size_bytes:
                logger.warning(
                    "Streaming request rejected: body_size %d exceeds limit %d. "
                    "IP=%s path=%s",
                    body_size,
                    self.max_size_bytes,
                    _get_client_ip(request),
                    request.url.path,
                )
                return Response(
                    content='{"detail":"Request entity too large"}',
                    status_code=413,
                    media_type="application/json",
                )
            body_chunks.append(chunk)

        # Reconstruct the request body for downstream handlers
        async def receive():
            return {"type": "http.request", "body": b"".join(body_chunks)}

        request._receive = receive
        return await call_next(request)


# ===========================================================================
# 2. Input Sanitizer
# ===========================================================================


class InputSanitizer:
    """
    Input sanitization utilities.

    Addresses: NIST SI-10 (Input Validation), STIG APSC-DV-002590.

    All methods are stateless class methods for easy use without instantiation.
    """

    @classmethod
    def sanitize_string(
        cls,
        value: str,
        max_length: int = 4096,
        allow_html: bool = False,
        strip_null_bytes: bool = True,
    ) -> str:
        """
        Sanitize a string input:
        - Strip leading/trailing whitespace
        - Remove null bytes
        - Normalize unicode (NFC)
        - Enforce max length
        - HTML-escape if html not allowed
        - Detect and reject XSS patterns
        """
        if not isinstance(value, str):
            raise ValueError(f"Expected string, got {type(value).__name__}")

        # Normalize unicode to NFC form
        value = unicodedata.normalize("NFC", value)

        # Strip null bytes (common in binary injection attacks)
        if strip_null_bytes:
            value = value.replace("\x00", "")

        # Strip leading/trailing whitespace
        value = value.strip()

        # Enforce max length
        if len(value) > max_length:
            raise ValueError(
                f"Input exceeds maximum length of {max_length} characters"
            )

        # XSS detection and rejection (reject if detected, even if allow_html)
        for pattern in _XSS_PATTERNS:
            if pattern.search(value):
                raise ValueError("Input contains potentially malicious content")

        # HTML escape if HTML not explicitly allowed
        if not allow_html:
            value = html.escape(value, quote=True)

        return value

    @classmethod
    def sanitize_identifier(cls, value: str, max_length: int = 128) -> str:
        """
        Sanitize an identifier (username, resource ID, etc.).
        Only allows alphanumeric characters, hyphens, underscores, and dots.
        """
        sanitized = cls.sanitize_string(value, max_length=max_length)
        if not re.match(r"^[a-zA-Z0-9_\-\.]+$", sanitized):
            raise ValueError(
                f"Identifier contains invalid characters: {sanitized!r}"
            )
        return sanitized

    @classmethod
    def sanitize_email(cls, value: str) -> str:
        """Sanitize and validate an email address."""
        sanitized = cls.sanitize_string(value, max_length=254)
        # RFC 5321 compliant pattern
        if not re.match(
            r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$",
            sanitized,
        ):
            raise ValueError(f"Invalid email address format: {sanitized!r}")
        return sanitized.lower()

    @classmethod
    def sanitize_url(cls, value: str) -> str:
        """Sanitize and validate a URL."""
        sanitized = cls.sanitize_string(value, max_length=2048)
        parsed = urlparse(sanitized)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(
                f"URL scheme {parsed.scheme!r} is not allowed (only http/https)"
            )
        if not parsed.netloc:
            raise ValueError("URL must contain a valid hostname")
        return sanitized

    @classmethod
    def sanitize_filename(cls, value: str) -> str:
        """
        Sanitize a filename — removes path separators, null bytes,
        and other filesystem-dangerous characters.
        """
        sanitized = cls.sanitize_string(value, max_length=255)
        # Remove path separators
        sanitized = re.sub(r"[/\\]", "_", sanitized)
        # Remove other dangerous characters
        sanitized = re.sub(r"[<>:\"|?*\x00-\x1f]", "_", sanitized)
        # Strip leading dots (hidden files)
        sanitized = sanitized.lstrip(".")
        if not sanitized:
            raise ValueError("Filename is empty after sanitization")
        return sanitized

    @classmethod
    def sanitize_dict(cls, data: Dict[str, Any], max_depth: int = 5) -> Dict[str, Any]:
        """Recursively sanitize a dictionary of string values."""
        return cls._sanitize_recursive(data, depth=0, max_depth=max_depth)

    @classmethod
    def _sanitize_recursive(cls, obj: Any, depth: int, max_depth: int) -> Any:
        if depth > max_depth:
            raise ValueError(f"Input nesting exceeds maximum depth of {max_depth}")
        if isinstance(obj, str):
            return cls.sanitize_string(obj)
        elif isinstance(obj, dict):
            return {
                cls.sanitize_string(k, max_length=256): cls._sanitize_recursive(
                    v, depth + 1, max_depth
                )
                for k, v in obj.items()
            }
        elif isinstance(obj, list):
            return [
                cls._sanitize_recursive(item, depth + 1, max_depth) for item in obj
            ]
        elif isinstance(obj, (int, float, bool)) or obj is None:
            return obj
        else:
            raise TypeError(
                f"Unsupported type in input: {type(obj).__name__}"
            )


# ===========================================================================
# 3. SQL Injection Preventer
# ===========================================================================


class SQLInjectionPreventer:
    """
    SQL injection prevention helpers.

    Addresses: NIST SI-10, STIG APSC-DV-002560, DB STIG DB-007.

    ALWAYS use parameterized queries. This class provides:
    1. Detection of SQL injection in user input (raise on detection)
    2. Safe parameterized query builder helpers
    3. Whitelist-based column/table name validator
    """

    @classmethod
    def detect_injection(cls, value: str) -> bool:
        """
        Return True if the value contains SQL injection patterns.
        Does NOT raise — use check_injection() to raise on detection.
        """
        _emit_event("finding.created", {"module": __name__, "action": "detect_injection"})
        for pattern in _SQL_INJECTION_PATTERNS:
            if pattern.search(value):
                return True
        return False

    @classmethod
    def check_injection(cls, value: str, field_name: str = "input") -> str:
        """
        Raise ValueError if SQL injection is detected.
        Returns the original value if safe.

        Usage:
            user_id = SQLInjectionPreventer.check_injection(user_id, "user_id")
        """
        if cls.detect_injection(value):
            logger.warning(
                "SQL injection attempt detected in field '%s': %r",
                field_name,
                value[:100],
            )
            raise ValueError(
                f"Field '{field_name}' contains potentially malicious SQL content"
            )
        return value

    @classmethod
    def safe_like_value(cls, value: str) -> str:
        """
        Escape a value for use in a SQL LIKE clause.
        Escapes %, _, and \\ metacharacters.

        Usage:
            cursor.execute(
                "SELECT * FROM t WHERE name LIKE ? ESCAPE '\\\\'",
                (SQLInjectionPreventer.safe_like_value(user_input) + "%",)
            )
        """
        return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")

    @classmethod
    def validate_column_name(
        cls, column: str, allowed_columns: Set[str]
    ) -> str:
        """
        Validate a column name against an explicit whitelist.
        Raises ValueError if the column is not allowed.
        This is required when column names must be interpolated (ORDER BY, etc.).

        Usage:
            sort_col = SQLInjectionPreventer.validate_column_name(
                request.query_params.get("sort", "created_at"),
                allowed_columns={"created_at", "severity", "status"}
            )
            cursor.execute(f"SELECT * FROM findings ORDER BY {sort_col}")"""
        if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", column):
            raise ValueError(
                f"Column name contains invalid characters: {column!r}"
            )
        if column not in allowed_columns:
            raise ValueError(
                f"Column name {column!r} is not in the allowed list"
            )
        return column

    @classmethod
    def validate_table_name(cls, table: str, allowed_tables: Set[str]) -> str:
        """
        Validate a table name against an explicit whitelist.
        Same protection as validate_column_name for dynamic table references.
        """
        if not re.match(r"^[a-zA-Z_][a-zA-Z0-9_]*$", table):
            raise ValueError(
                f"Table name contains invalid characters: {table!r}"
            )
        if table not in allowed_tables:
            raise ValueError(
                f"Table name {table!r} is not in the allowed list"
            )
        return table

    @classmethod
    def build_safe_params(cls, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate all string values in a dict for SQL injection before use
        as query parameters. Non-string values are passed through unchanged.

        Usage:
            params = SQLInjectionPreventer.build_safe_params(request_data)
            cursor.execute("INSERT INTO t (a, b) VALUES (:a, :b)", params)
        """
        safe: Dict[str, Any] = {}
        for key, value in data.items():
            if isinstance(value, str):
                cls.check_injection(value, field_name=key)
            safe[key] = value
        return safe


# ===========================================================================
# 4. Path Traversal Preventer
# ===========================================================================


class PathTraversalPreventer:
    """
    Path traversal prevention helpers.

    Addresses: NIST SI-10, STIG APSC-DV-002580.
    """

    @classmethod
    def detect_traversal(cls, path: str) -> bool:
        """Return True if path contains traversal sequences."""
        for pattern in _PATH_TRAVERSAL_PATTERNS:
            if pattern.search(path):
                return True
        return False

    @classmethod
    def safe_path(
        cls,
        user_provided: str,
        base_dir: Path,
        allow_extensions: Optional[List[str]] = None,
    ) -> Path:
        """
        Resolve and validate a user-provided path component against a base directory.
        Raises ValueError if the resolved path is outside the base directory.

        Args:
            user_provided: User-supplied filename or relative path
            base_dir: The allowed base directory (must be absolute)
            allow_extensions: Optional list of allowed file extensions (e.g., ['.json', '.pdf'])

        Returns:
            Resolved absolute Path that is guaranteed to be within base_dir

        Usage:
            safe = PathTraversalPreventer.safe_path(
                request.path_params["filename"],
                base_dir=Path("/var/fixops/evidence"),
                allow_extensions=[".json", ".pdf"]
            )
        """
        if cls.detect_traversal(user_provided):
            logger.warning(
                "Path traversal attempt detected: %r (base: %s)",
                user_provided,
                base_dir,
            )
            raise ValueError(
                f"Path {user_provided!r} contains traversal sequences"
            )

        # Resolve the full path
        base_dir = base_dir.resolve()
        candidate = (base_dir / user_provided).resolve()

        # Ensure resolved path is within the base directory
        try:
            candidate.relative_to(base_dir)
        except ValueError:
            logger.warning(
                "Path escape attempt: resolved path %s is outside base %s",
                candidate,
                base_dir,
            )
            raise ValueError(
                f"Path {user_provided!r} resolves outside permitted directory"
            )

        # Validate extension if an allowlist is provided
        if allow_extensions is not None:
            ext = candidate.suffix.lower()
            if ext not in [e.lower() for e in allow_extensions]:
                raise ValueError(
                    f"File extension {ext!r} is not in the allowed list: "
                    f"{allow_extensions}"
                )

        return candidate

    @classmethod
    def sanitize_filename(cls, filename: str) -> str:
        """
        Remove all path components and dangerous characters from a filename.
        Returns only the basename.
        """
        # Use Path to strip directory components
        safe = Path(filename).name
        # Remove additional dangerous characters
        safe = re.sub(r"[<>:\"|?*\x00-\x1f]", "_", safe)
        safe = safe.lstrip(".")
        if not safe:
            raise ValueError("Filename is empty after sanitization")
        return safe


# ===========================================================================
# 5. SSRF Protection
# ===========================================================================


class SSRFProtection:
    """
    Server-Side Request Forgery (SSRF) protection helper.

    Addresses: NIST SC-7 (Boundary Protection), STIG APSC-DV-002620.
    Noted gap in docs/need_hardening.md §6.

    Validates URLs before they are used in outbound HTTP requests.
    Blocks access to:
    - Private IP ranges (RFC-1918, loopback, link-local)
    - Cloud metadata services (169.254.169.254, etc.)
    - Non-HTTP(S) schemes
    """

    # Cloud metadata endpoints — always blocked
    BLOCKED_HOSTS: Set[str] = {
        "169.254.169.254",       # AWS/GCP/Azure IMDS
        "metadata.google.internal",
        "metadata.goog",
        "169.254.170.2",         # ECS task metadata
        "100.100.100.200",       # Alibaba Cloud metadata
        "fd00:ec2::254",         # AWS IPv6 IMDS
    }

    def __init__(
        self,
        allowed_schemes: Optional[List[str]] = None,
        blocked_hosts: Optional[Set[str]] = None,
        allow_private: bool = False,
    ) -> None:
        self.allowed_schemes = allowed_schemes or ["https"]
        self.blocked_hosts = (blocked_hosts or set()) | self.BLOCKED_HOSTS
        self.allow_private = allow_private

    def validate_url(self, url: str) -> str:
        """
        Validate a URL for SSRF safety.
        Raises ValueError with a safe message if the URL is not allowed.

        Usage:
            from core.security_hardening import SSRFProtection
            ssrf = SSRFProtection()

            @app.post("/agents/tasks")
            async def run_task(request: TaskRequest):
                ssrf.validate_url(request.target_url)
                async with httpx.AsyncClient() as client:
                    return await client.get(request.target_url)
        """
        _emit_event("finding.created", {"module": __name__, "action": "validate_url"})
        try:
            parsed = urlparse(url)
        except (ValueError, KeyError, RuntimeError, TypeError, AttributeError):
            raise ValueError("Invalid URL format")

        # Scheme check
        if parsed.scheme not in self.allowed_schemes:
            raise ValueError(
                f"URL scheme {parsed.scheme!r} is not allowed. "
                f"Allowed schemes: {self.allowed_schemes}"
            )

        hostname = parsed.hostname
        if not hostname:
            raise ValueError("URL must contain a valid hostname")

        # Explicit host blocklist
        if hostname.lower() in self.blocked_hosts:
            raise ValueError(
                f"URL hostname {hostname!r} is blocked (cloud metadata or restricted host)"
            )

        # IP address private range check
        if not self.allow_private:
            try:
                ip = ipaddress.ip_address(hostname)
                for private_range in _PRIVATE_RANGES:
                    if ip in private_range:
                        raise ValueError(
                            f"URL resolves to a private/loopback IP address ({ip}). "
                            "SSRF protection: private IPs are not allowed."
                        )
            except ValueError as e:
                if "private" in str(e) or "loopback" in str(e):
                    raise
                # hostname is not an IP literal — DNS resolution would be needed
                # for production, inject a DNS-aware resolver here
                pass

        logger.debug("SSRF validation passed for URL: %s", url)
        return url


# ===========================================================================
# 6. Rate Limiter
# ===========================================================================


@dataclass
class EndpointRateLimitConfig:
    """
    Per-endpoint rate limit configuration.

    Addresses: NIST SC-5 (DoS Protection), AC-7 (Logon Attempts), WS STIG WS-010.

    Attributes:
        max_requests:   Maximum requests allowed within the window
        window_seconds: Time window in seconds
        burst_multiplier: Allow this multiple of max_requests in burst (default 1.5)
        penalty_seconds: Lock duration after limit is exceeded (default 60)

    Usage:
        RATE_LIMITS = {
            "/api/v1/auth/login": EndpointRateLimitConfig(max_requests=5, window_seconds=60),
            "/api/v1/scan": EndpointRateLimitConfig(max_requests=10, window_seconds=300),
        }
    """

    max_requests: int = _RATE_LIMIT_DEFAULT_MAX
    window_seconds: int = _RATE_LIMIT_WINDOW_SECONDS
    burst_multiplier: float = 1.5
    penalty_seconds: int = 60
    key_by: str = "ip"  # "ip" | "user" | "api_key"


class RateLimiter:
    """
    In-process rate limiter using a sliding window algorithm.

    For production HA deployments, replace the in-memory store with Redis
    using the same interface.

    Thread-safe via Lock.

    Usage:
        limiter = RateLimiter(configs={
            "/api/v1/auth/login": EndpointRateLimitConfig(max_requests=5, window_seconds=60),
        })

        # In FastAPI middleware or dependency:
        limiter.check(request, endpoint_path)
    """

    def __init__(
        self,
        configs: Optional[Dict[str, EndpointRateLimitConfig]] = None,
        default_config: Optional[EndpointRateLimitConfig] = None,
    ) -> None:
        self.configs = configs or {}
        self.default_config = default_config or EndpointRateLimitConfig()
        # {key: [(timestamp, count)]} sliding window
        self._buckets: Dict[str, List[float]] = defaultdict(list)
        self._penalties: Dict[str, float] = {}  # key -> penalty expiry timestamp
        self._lock = Lock()

    def get_config(self, path: str) -> EndpointRateLimitConfig:
        """Get rate limit config for a path, falling back to default."""
        # Exact match first
        if path in self.configs:
            return self.configs[path]
        # Prefix match
        for pattern, config in self.configs.items():
            if path.startswith(pattern):
                return config
        return self.default_config

    def _make_key(self, request: Request, config: EndpointRateLimitConfig) -> str:
        """Build the rate limit key from the request."""
        if config.key_by == "ip":
            return f"ip:{_get_client_ip(request)}"
        elif config.key_by == "user":
            user_id = getattr(request.state, "user_id", None)
            return f"user:{user_id or _get_client_ip(request)}"
        elif config.key_by == "api_key":
            api_key = request.headers.get("x-api-key", "")
            key_hash = hashlib.sha256(api_key.encode()).hexdigest()[:16]
            return f"key:{key_hash}"
        return f"ip:{_get_client_ip(request)}"

    def check(self, request: Request, path: Optional[str] = None) -> None:
        """
        Check the rate limit for the given request.
        Raises HTTP 429 if the limit is exceeded.

        Args:
            request: FastAPI/Starlette Request object
            path: Override path for config lookup (uses request.url.path if None)
        """
        path = path or request.url.path
        config = self.get_config(path)
        key = f"{path}:{self._make_key(request, config)}"
        now = time.monotonic()

        with self._lock:
            # Check penalty period
            if key in self._penalties:
                if now < self._penalties[key]:
                    remaining = int(self._penalties[key] - now)
                    logger.warning(
                        "Rate limit penalty active. key=%s remaining=%ds",
                        key,
                        remaining,
                    )
                    raise HTTPException(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        detail=f"Too many requests. Retry after {remaining} seconds.",
                        headers={"Retry-After": str(remaining)},
                    )
                else:
                    del self._penalties[key]

            # Clean expired entries outside the window
            window_start = now - config.window_seconds
            self._buckets[key] = [
                ts for ts in self._buckets[key] if ts > window_start
            ]

            count = len(self._buckets[key])
            burst_limit = int(config.max_requests * config.burst_multiplier)

            if count >= burst_limit:
                # Apply penalty
                self._penalties[key] = now + config.penalty_seconds
                logger.warning(
                    "Rate limit burst exceeded — penalty applied. "
                    "key=%s count=%d limit=%d penalty=%ds",
                    key,
                    count,
                    burst_limit,
                    config.penalty_seconds,
                )
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Too many requests. Retry after {config.penalty_seconds} seconds.",
                    headers={"Retry-After": str(config.penalty_seconds)},
                )
            elif count >= config.max_requests:
                logger.info(
                    "Rate limit exceeded. key=%s count=%d limit=%d",
                    key,
                    count,
                    config.max_requests,
                )
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail="Too many requests. Please slow down.",
                    headers={"Retry-After": str(config.window_seconds)},
                )

            # Record the request
            self._buckets[key].append(now)

    def remaining(self, request: Request, path: Optional[str] = None) -> int:
        """Return the number of remaining requests in the current window."""
        path = path or request.url.path
        config = self.get_config(path)
        key = f"{path}:{self._make_key(request, config)}"
        now = time.monotonic()
        window_start = now - config.window_seconds
        with self._lock:
            count = sum(1 for ts in self._buckets.get(key, []) if ts > window_start)
        return max(0, config.max_requests - count)


# ===========================================================================
# 7. IP Access Manager
# ===========================================================================


class IPAccessManager:
    """
    IP allowlist/denylist manager.

    Addresses: NIST SC-7 (Boundary Protection), AC-3 (Access Enforcement).

    Supports:
    - Individual IPs (IPv4 and IPv6)
    - CIDR ranges
    - Allowlist-only mode (deny all not in allowlist)
    - Denylist mode (allow all except explicitly denied)

    Usage:
        ip_manager = IPAccessManager(
            allowlist=["10.0.0.0/8", "192.168.1.100"],
            denylist=["192.168.1.50"]
        )
        ip_manager.check(request)   # raises 403 if denied
    """

    def __init__(
        self,
        allowlist: Optional[List[str]] = None,
        denylist: Optional[List[str]] = None,
        mode: str = "denylist",  # "allowlist" | "denylist"
    ) -> None:
        """
        Args:
            allowlist: IPs/CIDRs that are always permitted
            denylist: IPs/CIDRs that are always blocked
            mode: "allowlist" — only listed IPs allowed (default deny)
                  "denylist" — only listed IPs blocked (default allow)
        """
        self.mode = mode
        self._allowlist: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = (
            self._parse_list(allowlist or [])
        )
        self._denylist: List[ipaddress.IPv4Network | ipaddress.IPv6Network] = (
            self._parse_list(denylist or [])
        )
        self._lock = Lock()
        logger.info(
            "IPAccessManager initialized. mode=%s allowlist=%d denylist=%d",
            mode,
            len(self._allowlist),
            len(self._denylist),
        )

    @staticmethod
    def _parse_list(entries: List[str]) -> List[ipaddress.IPv4Network | ipaddress.IPv6Network]:
        """Parse a list of IP/CIDR strings into network objects."""
        networks = []
        for entry in entries:
            try:
                # Try as a network
                networks.append(ipaddress.ip_network(entry, strict=False))
            except ValueError:
                try:
                    # Try as a single host
                    networks.append(
                        ipaddress.ip_network(
                            str(ipaddress.ip_address(entry)), strict=False
                        )
                    )
                except ValueError:
                    logger.error("Invalid IP/CIDR in access list: %r", entry)
        return networks

    def _ip_in_list(
        self,
        ip_addr: ipaddress.IPv4Address | ipaddress.IPv6Address,
        network_list: List[ipaddress.IPv4Network | ipaddress.IPv6Network],
    ) -> bool:
        """Return True if ip_addr is in any of the network_list entries."""
        return any(ip_addr in net for net in network_list)

    def is_allowed(self, ip_str: str) -> bool:
        """
        Return True if the IP address is allowed.

        In allowlist mode: allowed only if in allowlist and not in denylist.
        In denylist mode: allowed unless in denylist (allowlist grants override).
        """
        try:
            ip = ipaddress.ip_address(ip_str)
        except ValueError:
            logger.warning("Cannot parse IP address: %r — denying", ip_str)
            return False

        with self._lock:
            in_denylist = self._ip_in_list(ip, self._denylist)
            in_allowlist = self._ip_in_list(ip, self._allowlist)

        if in_denylist:
            logger.info("IP %s denied (in denylist)", ip_str)
            return False

        if self.mode == "allowlist":
            if not in_allowlist:
                logger.info("IP %s denied (not in allowlist, allowlist mode)", ip_str)
                return False

        return True

    def check(self, request: Request) -> None:
        """
        Check if the request IP is allowed.
        Raises HTTP 403 if access is denied.
        """
        ip_str = _get_client_ip(request)
        if not self.is_allowed(ip_str):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Access denied from this IP address",
            )

    def add_to_denylist(self, ip_or_cidr: str) -> None:
        """Dynamically add an IP/CIDR to the denylist (thread-safe)."""
        parsed = self._parse_list([ip_or_cidr])
        with self._lock:
            self._denylist.extend(parsed)
        logger.info("Added to denylist: %s", ip_or_cidr)

    def remove_from_denylist(self, ip_or_cidr: str) -> None:
        """Remove an IP/CIDR from the denylist (thread-safe)."""
        try:
            net = ipaddress.ip_network(ip_or_cidr, strict=False)
        except ValueError:
            return
        with self._lock:
            self._denylist = [n for n in self._denylist if n != net]
        logger.info("Removed from denylist: %s", ip_or_cidr)

    def add_to_allowlist(self, ip_or_cidr: str) -> None:
        """Dynamically add an IP/CIDR to the allowlist (thread-safe)."""
        parsed = self._parse_list([ip_or_cidr])
        with self._lock:
            self._allowlist.extend(parsed)
        logger.info("Added to allowlist: %s", ip_or_cidr)


# ===========================================================================
# 8. Session Manager
# ===========================================================================


@dataclass
class SessionData:
    """Session data stored server-side."""

    session_id: str
    user_id: str
    created_at: datetime
    last_active: datetime
    ip_address: str
    user_agent: str
    metadata: Dict[str, Any] = field(default_factory=dict)


class SessionManager:
    """
    Server-side session management with configurable timeout.

    Addresses: NIST AC-11 (Session Lock), AC-12 (Session Termination),
              SC-10 (Network Disconnect), SC-23 (Session Authenticity).

    Sessions are stored in-memory with optional SQLite persistence.
    For HA deployments, replace with Redis-backed storage.

    Configuration:
        FIXOPS_SESSION_TIMEOUT (minutes, default 60)

    Usage:
        session_mgr = SessionManager()

        # Create session
        session_id = session_mgr.create(user_id, request)

        # Validate and refresh
        session = session_mgr.get(session_id, request)  # raises on invalid/expired

        # Terminate
        session_mgr.delete(session_id)
    """

    def __init__(
        self,
        timeout_minutes: int = _SESSION_TIMEOUT_MINUTES,
        max_sessions_per_user: int = int(os.getenv("FIXOPS_MAX_SESSIONS_PER_USER", "5")),
        db_path: Optional[str] = None,
    ) -> None:
        self.timeout_minutes = timeout_minutes
        self.max_sessions_per_user = max_sessions_per_user
        self._sessions: Dict[str, SessionData] = {}
        self._lock = Lock()
        self._db_path = db_path
        if db_path:
            self._init_db(db_path)

    def _init_db(self, db_path: str) -> None:
        """Initialize SQLite session persistence."""
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        conn = sqlite3.connect(db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                user_id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                last_active TEXT NOT NULL,
                ip_address TEXT,
                user_agent TEXT,
                metadata TEXT
            )
        """)
        conn.commit()
        conn.close()

    def create(self, user_id: str, request: Request) -> str:
        """
        Create a new session. Enforces max_sessions_per_user.
        Returns the new session ID.
        """
        now = datetime.now(timezone.utc)
        session_id = secrets_token()

        with self._lock:
            # Enforce max sessions
            user_sessions = [
                sid for sid, s in self._sessions.items()
                if s.user_id == user_id and self._is_active(s)
            ]
            if len(user_sessions) >= self.max_sessions_per_user:
                # Evict the oldest session
                oldest = min(
                    user_sessions,
                    key=lambda sid: self._sessions[sid].last_active,
                )
                logger.info(
                    "Max sessions reached for user %s — evicting session %s",
                    user_id,
                    oldest[:8] + "...",
                )
                del self._sessions[oldest]

            session = SessionData(
                session_id=session_id,
                user_id=user_id,
                created_at=now,
                last_active=now,
                ip_address=_get_client_ip(request),
                user_agent=request.headers.get("user-agent", ""),
            )
            self._sessions[session_id] = session

        logger.info(
            "Session created for user %s from IP %s",
            user_id,
            _get_client_ip(request),
        )
        return session_id

    def get(
        self,
        session_id: str,
        request: Optional[Request] = None,
        refresh: bool = True,
    ) -> SessionData:
        """
        Retrieve and optionally refresh a session.
        Raises HTTPException 401 if session is invalid or expired.

        Args:
            session_id: The session identifier
            request: If provided, validate IP consistency
            refresh: If True, update last_active timestamp
        """
        with self._lock:
            session = self._sessions.get(session_id)
            if not session:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Session not found or expired",
                )

            if not self._is_active(session):
                del self._sessions[session_id]
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="Session expired",
                )

            # Optional IP binding check (strict mode)
            if request and os.getenv("FIXOPS_SESSION_BIND_IP", "false").lower() == "true":
                if _get_client_ip(request) != session.ip_address:
                    logger.warning(
                        "Session IP mismatch for user %s: expected %s got %s",
                        session.user_id,
                        session.ip_address,
                        _get_client_ip(request),
                    )
                    del self._sessions[session_id]
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Session invalid",
                    )

            if refresh:
                session.last_active = datetime.now(timezone.utc)

            return session

    def delete(self, session_id: str) -> None:
        """Terminate a session (logout)."""
        with self._lock:
            if session_id in self._sessions:
                user_id = self._sessions[session_id].user_id
                del self._sessions[session_id]
                logger.info(
                    "Session terminated for user %s", user_id
                )

    def delete_all(self, user_id: str) -> int:
        """Terminate all sessions for a user. Returns count deleted."""
        with self._lock:
            to_delete = [
                sid for sid, s in self._sessions.items() if s.user_id == user_id
            ]
            for sid in to_delete:
                del self._sessions[sid]
        logger.info("Terminated %d sessions for user %s", len(to_delete), user_id)
        return len(to_delete)

    def cleanup_expired(self) -> int:
        """Remove all expired sessions. Returns count removed."""
        with self._lock:
            expired = [
                sid for sid, s in self._sessions.items()
                if not self._is_active(s)
            ]
            for sid in expired:
                del self._sessions[sid]
        if expired:
            logger.info("Cleaned up %d expired sessions", len(expired))
        return len(expired)

    def _is_active(self, session: SessionData) -> bool:
        """Return True if the session has not exceeded the timeout."""
        expiry = session.last_active + timedelta(minutes=self.timeout_minutes)
        return datetime.now(timezone.utc) < expiry


# ===========================================================================
# 9. Security Audit Logger
# ===========================================================================


class SecurityAuditLogger:
    """
    Structured audit event logger that writes to the audit SQLite database.

    Addresses: NIST AU-2, AU-3, AU-8, AU-9, AU-12, STIG APSC-DV-003250.

    Every security-relevant event should be logged here:
    - Authentication (login, logout, failure)
    - Authorization (access granted, denied)
    - Data access (read, create, update, delete)
    - Security events (injection attempt, rate limit, IP block)
    - Admin actions (config change, user management)

    Usage:
        audit = SecurityAuditLogger()
        audit.log_auth("login_success", user_id="uid123", ip="1.2.3.4", request=request)
        audit.log_security_event("sql_injection_attempt", details={...}, request=request)
    """

    # Event type constants
    EVENT_AUTH = "AUTH"
    EVENT_ACCESS = "ACCESS"
    EVENT_CHANGE = "CHANGE"
    EVENT_ADMIN = "ADMIN"
    EVENT_SECURITY = "SECURITY"
    EVENT_DATA = "DATA"
    EVENT_SYSTEM = "SYSTEM"

    # Severity constants
    SEV_INFO = "INFO"
    SEV_LOW = "LOW"
    SEV_MEDIUM = "MEDIUM"
    SEV_HIGH = "HIGH"
    SEV_CRITICAL = "CRITICAL"

    def __init__(self, db_path: str = _AUDIT_DB_PATH) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = Lock()
        self._init_db()

    def _init_db(self) -> None:
        """Initialize audit log table."""
        conn = self._get_conn()
        try:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS security_audit_log (
                    id TEXT PRIMARY KEY,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    action TEXT NOT NULL,
                    user_id TEXT,
                    org_id TEXT,
                    resource_type TEXT,
                    resource_id TEXT,
                    ip_address TEXT,
                    user_agent TEXT,
                    method TEXT,
                    path TEXT,
                    status_code INTEGER,
                    details TEXT,
                    outcome TEXT NOT NULL DEFAULT 'success',
                    timestamp TEXT NOT NULL,
                    correlation_id TEXT
                )
            """)
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_sal_timestamp ON security_audit_log(timestamp)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_sal_event_type ON security_audit_log(event_type)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_sal_user_id ON security_audit_log(user_id)"
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS idx_sal_ip ON security_audit_log(ip_address)"
            )
            conn.commit()
        finally:
            conn.close()

    def _get_conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        return conn

    def _log(
        self,
        event_type: str,
        severity: str,
        action: str,
        outcome: str = "success",
        user_id: Optional[str] = None,
        org_id: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        method: Optional[str] = None,
        path: Optional[str] = None,
        status_code: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
        request: Optional[Request] = None,
        correlation_id: Optional[str] = None,
    ) -> str:
        """Write a single audit record to the DB. Returns the event ID."""
        event_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()

        # Auto-extract from request if provided
        if request:
            ip_address = ip_address or _get_client_ip(request)
            user_agent = user_agent or request.headers.get("user-agent", "")
            method = method or request.method
            path = path or str(request.url.path)
            user_id = user_id or getattr(request.state, "user_id", user_id)
            org_id = org_id or getattr(request.state, "org_id", org_id)
            correlation_id = correlation_id or request.headers.get(
                "x-correlation-id", event_id
            )

        details_json = None
        if details:
            import json
            details_json = json.dumps(details, default=str)

        try:
            with self._lock:
                conn = self._get_conn()
                try:
                    conn.execute(
                        """
                        INSERT INTO security_audit_log (
                            id, event_type, severity, action, user_id, org_id,
                            resource_type, resource_id, ip_address, user_agent,
                            method, path, status_code, details, outcome,
                            timestamp, correlation_id
                        ) VALUES (
                            ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
                        )
                        """,
                        (
                            event_id, event_type, severity, action, user_id, org_id,
                            resource_type, resource_id, ip_address, user_agent,
                            method, path, status_code, details_json, outcome,
                            timestamp, correlation_id,
                        ),
                    )
                    conn.commit()
                finally:
                    conn.close()
        except (ValueError, KeyError, RuntimeError, TypeError, AttributeError) as exc:
            # Audit failures must not crash the application —
            # log to stderr and continue
            logger.error(
                "AUDIT WRITE FAILURE (event_id=%s action=%s): %s",
                event_id,
                action,
                exc,
            )

        return event_id

    def log_auth(
        self,
        action: str,
        outcome: str = "success",
        severity: Optional[str] = None,
        **kwargs,
    ) -> str:
        """Log an authentication event."""
        if severity is None:
            severity = self.SEV_HIGH if outcome == "failure" else self.SEV_INFO
        return self._log(
            event_type=self.EVENT_AUTH,
            severity=severity,
            action=action,
            outcome=outcome,
            **kwargs,
        )

    def log_access(
        self,
        action: str,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        outcome: str = "success",
        **kwargs,
    ) -> str:
        """Log an access control event (authorization decision)."""
        severity = self.SEV_MEDIUM if outcome == "denied" else self.SEV_INFO
        return self._log(
            event_type=self.EVENT_ACCESS,
            severity=severity,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            outcome=outcome,
            **kwargs,
        )

    def log_change(
        self,
        action: str,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> str:
        """Log a data change event (create, update, delete)."""
        return self._log(
            event_type=self.EVENT_CHANGE,
            severity=self.SEV_MEDIUM,
            action=action,
            resource_type=resource_type,
            resource_id=resource_id,
            details=details,
            **kwargs,
        )

    def log_admin(
        self,
        action: str,
        details: Optional[Dict[str, Any]] = None,
        **kwargs,
    ) -> str:
        """Log an administrative action."""
        return self._log(
            event_type=self.EVENT_ADMIN,
            severity=self.SEV_HIGH,
            action=action,
            details=details,
            **kwargs,
        )

    def log_security_event(
        self,
        action: str,
        severity: str = SEV_HIGH,
        details: Optional[Dict[str, Any]] = None,
        outcome: str = "blocked",
        **kwargs,
    ) -> str:
        """
        Log a security event (injection attempt, rate limit, IP block, etc.).
        These events should always be reviewed.
        """
        return self._log(
            event_type=self.EVENT_SECURITY,
            severity=severity,
            action=action,
            outcome=outcome,
            details=details,
            **kwargs,
        )

    def log_system(
        self,
        action: str,
        details: Optional[Dict[str, Any]] = None,
        severity: str = SEV_INFO,
        **kwargs,
    ) -> str:
        """Log a system-level event (startup, config load, key rotation)."""
        return self._log(
            event_type=self.EVENT_SYSTEM,
            severity=severity,
            action=action,
            details=details,
            **kwargs,
        )

    def query_events(
        self,
        event_type: Optional[str] = None,
        user_id: Optional[str] = None,
        ip_address: Optional[str] = None,
        severity: Optional[str] = None,
        since: Optional[datetime] = None,
        limit: int = 1000,
    ) -> List[Dict[str, Any]]:
        """Query audit events with optional filters."""
        conditions = []
        params = []

        if event_type:
            conditions.append("event_type = ?")
            params.append(event_type)
        if user_id:
            conditions.append("user_id = ?")
            params.append(user_id)
        if ip_address:
            conditions.append("ip_address = ?")
            params.append(ip_address)
        if severity:
            conditions.append("severity = ?")
            params.append(severity)
        if since:
            conditions.append("timestamp >= ?")
            params.append(since.isoformat())

        where = "WHERE " + " AND ".join(conditions) if conditions else ""
        query = f"SELECT * FROM security_audit_log {where} ORDER BY timestamp DESC LIMIT ?"  # nosec B608 — WHERE from hardcoded columns with ? params
        params.append(limit)

        conn = self._get_conn()
        try:
            rows = conn.execute(query, params).fetchall()
            return [dict(row) for row in rows]
        finally:
            conn.close()


# ===========================================================================
# Utility Functions
# ===========================================================================


def _get_client_ip(request: Request) -> str:
    """
    Extract the real client IP address from a request.
    Respects X-Forwarded-For and X-Real-IP headers (set by trusted reverse proxy).

    For production: configure the list of trusted proxy IPs in FIXOPS_TRUSTED_PROXIES.
    """
    trusted_proxies_str = os.getenv("FIXOPS_TRUSTED_PROXIES", "127.0.0.1,::1")
    trusted_proxies = {ip.strip() for ip in trusted_proxies_str.split(",")}

    client_ip = (
        request.client.host if request.client else "unknown"
    )

    # Only trust forwarded headers if the request comes from a trusted proxy
    if client_ip in trusted_proxies:
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            # X-Forwarded-For can be a comma-separated list; take the first entry
            client_ip = forwarded_for.split(",")[0].strip()
        else:
            real_ip = request.headers.get("x-real-ip")
            if real_ip:
                client_ip = real_ip.strip()

    return client_ip


def secrets_token(nbytes: int = 32) -> str:
    """Generate a cryptographically secure random token using secrets module."""
    import secrets
    return secrets.token_urlsafe(nbytes)


# ===========================================================================
# Convenience: Pre-configured global instances (override with env vars)
# ===========================================================================

#: Global rate limiter instance — configure with DEFAULT_RATE_LIMITS before use
DEFAULT_RATE_LIMITS: Dict[str, EndpointRateLimitConfig] = {
    "/api/v1/auth/login": EndpointRateLimitConfig(
        max_requests=5, window_seconds=60, penalty_seconds=300, key_by="ip"
    ),
    "/api/v1/auth/token": EndpointRateLimitConfig(
        max_requests=10, window_seconds=60, penalty_seconds=120, key_by="ip"
    ),
    "/api/v1/scan": EndpointRateLimitConfig(
        max_requests=10, window_seconds=300, key_by="user"
    ),
    "/api/v1/evidence": EndpointRateLimitConfig(
        max_requests=50, window_seconds=60, key_by="user"
    ),
}

global_rate_limiter = RateLimiter(configs=DEFAULT_RATE_LIMITS)
global_session_manager = SessionManager()
global_audit_logger = SecurityAuditLogger()
global_ssrf_protection = SSRFProtection()
global_ip_manager = IPAccessManager(
    allowlist=[
        ip.strip()
        for ip in os.getenv("FIXOPS_ALLOWED_IPS", "").split(",")
        if ip.strip()
    ] or None,
    denylist=[
        ip.strip()
        for ip in os.getenv("FIXOPS_BLOCKED_IPS", "").split(",")
        if ip.strip()
    ],
    mode=os.getenv("FIXOPS_IP_ACCESS_MODE", "denylist"),
)
