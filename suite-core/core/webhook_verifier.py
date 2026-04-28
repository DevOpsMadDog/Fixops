"""Webhook Signature Verification — verify incoming webhooks from all sources.

Provides:
- WebhookProvider enum: GITHUB, GITLAB, JIRA, SERVICENOW, SLACK, PAGERDUTY, STRIPE, CUSTOM
- VerificationResult Pydantic model: valid, provider, timestamp, ip_address, error
- WebhookVerifier class with per-provider HMAC/token verification, auto-detection,
  audit logging, and per-org pass/fail stats backed by SQLite.

Usage:
    from core.webhook_verifier import WebhookVerifier, WebhookProvider

    verifier = WebhookVerifier()
    result = verifier.verify(headers=dict(request.headers), payload=await request.body())
    if not result.valid:
        raise HTTPException(401, result.error)
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Mapping, Optional

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_DB_PATH = os.path.normpath(
    os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        "..",
        "..",
        "data",
        "webhook_verifier.db",
    )
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS webhook_verification_log (
    id            TEXT PRIMARY KEY,
    org_id        TEXT NOT NULL DEFAULT 'default',
    provider      TEXT NOT NULL,
    valid         INTEGER NOT NULL,
    ip_address    TEXT,
    error         TEXT,
    verified_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_wvl_org      ON webhook_verification_log (org_id, verified_at DESC);
CREATE INDEX IF NOT EXISTS idx_wvl_provider ON webhook_verification_log (org_id, provider, verified_at DESC);
"""

# Slack requires requests not older than 5 minutes to prevent replay attacks.
_SLACK_MAX_AGE_SECONDS = 300


# ---------------------------------------------------------------------------
# Enums & Models
# ---------------------------------------------------------------------------


class WebhookProvider(str, Enum):
    """Supported webhook source providers."""

    GITHUB = "github"
    GITLAB = "gitlab"
    JIRA = "jira"
    SERVICENOW = "servicenow"
    SLACK = "slack"
    PAGERDUTY = "pagerduty"
    STRIPE = "stripe"
    CUSTOM = "custom"


class VerificationResult(BaseModel):
    """Result of a webhook signature verification attempt."""

    valid: bool
    provider: WebhookProvider
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    ip_address: Optional[str] = None
    error: Optional[str] = None

    model_config = {"use_enum_values": True}


# ---------------------------------------------------------------------------
# SQLite helpers
# ---------------------------------------------------------------------------


def _get_db(db_path: str = _DB_PATH) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(_SCHEMA)
    return conn


# ---------------------------------------------------------------------------
# WebhookVerifier
# ---------------------------------------------------------------------------


class WebhookVerifier:
    """Verify incoming webhook signatures from multiple providers.

    Thread-safe. Maintains an audit log and per-org pass/fail statistics in
    SQLite. All verify_* methods return a VerificationResult with valid=False
    and a descriptive error rather than raising exceptions, so callers can
    decide how to handle failures.
    """

    def __init__(self, db_path: str = _DB_PATH) -> None:
        self._db_path = db_path
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Per-provider verification methods
    # ------------------------------------------------------------------

    def verify_github(
        self,
        payload: bytes,
        signature: str,
        secret: str,
        ip_address: Optional[str] = None,
    ) -> VerificationResult:
        """Verify GitHub webhook using HMAC-SHA256.

        GitHub sends the signature in the ``X-Hub-Signature-256`` header as
        ``sha256=<hex_digest>``.
        """
        provider = WebhookProvider.GITHUB
        try:
            if not signature:
                return self._failure(provider, "Missing signature header", ip_address)
            if not secret:
                return self._failure(provider, "No secret configured", ip_address)

            # Strip prefix if present
            sig_value = signature.removeprefix("sha256=")
            expected = hmac.new(
                secret.encode("utf-8"), payload, hashlib.sha256
            ).hexdigest()

            if not hmac.compare_digest(sig_value, expected):
                return self._failure(provider, "Signature mismatch", ip_address)

            return self._success(provider, ip_address)
        except Exception as exc:  # noqa: BLE001
            logger.warning("verify_github error: %s", exc)
            return self._failure(provider, f"Verification error: {exc}", ip_address)

    def verify_gitlab(
        self,
        payload: bytes,  # noqa: ARG002  — kept for API symmetry
        token: str,
        secret: str,
        ip_address: Optional[str] = None,
    ) -> VerificationResult:
        """Verify GitLab webhook using X-Gitlab-Token comparison.

        GitLab sends a plain-text token in the ``X-Gitlab-Token`` header.
        The comparison uses ``hmac.compare_digest`` to avoid timing attacks.
        """
        provider = WebhookProvider.GITLAB
        try:
            if not token:
                return self._failure(provider, "Missing X-Gitlab-Token header", ip_address)
            if not secret:
                return self._failure(provider, "No secret configured", ip_address)

            if not hmac.compare_digest(token.encode("utf-8"), secret.encode("utf-8")):
                return self._failure(provider, "Token mismatch", ip_address)

            return self._success(provider, ip_address)
        except Exception as exc:  # noqa: BLE001
            logger.warning("verify_gitlab error: %s", exc)
            return self._failure(provider, f"Verification error: {exc}", ip_address)

    def verify_jira(
        self,
        payload: bytes,
        signature: str,
        secret: str,
        ip_address: Optional[str] = None,
    ) -> VerificationResult:
        """Verify Atlassian/Jira webhook using HMAC-SHA256.

        Atlassian sends the signature in the ``X-Hub-Signature`` header as
        ``sha256=<hex_digest>`` (same scheme as GitHub).
        """
        provider = WebhookProvider.JIRA
        try:
            if not signature:
                return self._failure(provider, "Missing signature header", ip_address)
            if not secret:
                return self._failure(provider, "No secret configured", ip_address)

            sig_value = signature.removeprefix("sha256=")
            expected = hmac.new(
                secret.encode("utf-8"), payload, hashlib.sha256
            ).hexdigest()

            if not hmac.compare_digest(sig_value, expected):
                return self._failure(provider, "Signature mismatch", ip_address)

            return self._success(provider, ip_address)
        except Exception as exc:  # noqa: BLE001
            logger.warning("verify_jira error: %s", exc)
            return self._failure(provider, f"Verification error: {exc}", ip_address)

    def verify_slack(
        self,
        payload: bytes,
        signature: str,
        timestamp: str,
        secret: str,
        ip_address: Optional[str] = None,
    ) -> VerificationResult:
        """Verify Slack webhook using Slack's v0 signing scheme.

        Slack sends ``X-Slack-Signature`` (``v0=<hex>``) and
        ``X-Slack-Request-Timestamp`` headers. The signed base string is
        ``v0:<timestamp>:<raw_body>``. Requests older than 5 minutes are
        rejected to prevent replay attacks.
        """
        provider = WebhookProvider.SLACK
        try:
            if not signature or not timestamp:
                return self._failure(
                    provider, "Missing Slack signature or timestamp headers", ip_address
                )
            if not secret:
                return self._failure(provider, "No signing secret configured", ip_address)

            # Replay-attack guard
            try:
                req_time = int(timestamp)
            except ValueError:
                return self._failure(provider, "Invalid timestamp format", ip_address)

            now = int(datetime.now(timezone.utc).timestamp())
            if abs(now - req_time) > _SLACK_MAX_AGE_SECONDS:
                return self._failure(
                    provider,
                    f"Request timestamp too old ({abs(now - req_time)}s)",
                    ip_address,
                )

            base = f"v0:{timestamp}:{payload.decode('utf-8', errors='replace')}"
            expected = "v0=" + hmac.new(
                secret.encode("utf-8"), base.encode("utf-8"), hashlib.sha256
            ).hexdigest()

            if not hmac.compare_digest(signature, expected):
                return self._failure(provider, "Signature mismatch", ip_address)

            return self._success(provider, ip_address)
        except Exception as exc:  # noqa: BLE001
            logger.warning("verify_slack error: %s", exc)
            return self._failure(provider, f"Verification error: {exc}", ip_address)

    def verify_pagerduty(
        self,
        payload: bytes,
        signature: str,
        secret: str,
        ip_address: Optional[str] = None,
    ) -> VerificationResult:
        """Verify PagerDuty v2 webhook using HMAC-SHA256.

        PagerDuty sends ``X-PagerDuty-Signature`` as a comma-separated list
        of ``v1=<hex>`` tokens. Verification passes if ANY token matches.
        """
        provider = WebhookProvider.PAGERDUTY
        try:
            if not signature:
                return self._failure(provider, "Missing signature header", ip_address)
            if not secret:
                return self._failure(provider, "No secret configured", ip_address)

            expected = "v1=" + hmac.new(
                secret.encode("utf-8"), payload, hashlib.sha256
            ).hexdigest()

            # Header may contain multiple comma-separated signatures
            tokens = [t.strip() for t in signature.split(",")]
            if not any(hmac.compare_digest(t, expected) for t in tokens):
                return self._failure(provider, "Signature mismatch", ip_address)

            return self._success(provider, ip_address)
        except Exception as exc:  # noqa: BLE001
            logger.warning("verify_pagerduty error: %s", exc)
            return self._failure(provider, f"Verification error: {exc}", ip_address)

    def verify_stripe(
        self,
        payload: bytes,
        signature: str,
        secret: str,
        ip_address: Optional[str] = None,
    ) -> VerificationResult:
        """Verify Stripe webhook using Stripe's v1 signing scheme.

        Stripe sends ``Stripe-Signature`` as a comma-separated list of
        ``t=<unix_ts>`` and ``v1=<hex>`` components. The signed payload is
        ``<timestamp>.<raw_body>``. Requests older than 5 minutes are rejected.
        """
        provider = WebhookProvider.STRIPE
        try:
            if not signature or not secret:
                return self._failure(provider, "Missing signature or secret", ip_address)

            parts: Dict[str, str] = {}
            for item in signature.split(","):
                item = item.strip()
                if "=" in item:
                    k, v = item.split("=", 1)
                    parts[k] = v

            timestamp_str = parts.get("t", "")
            v1_sig = parts.get("v1", "")

            if not timestamp_str or not v1_sig:
                return self._failure(
                    provider, "Missing t= or v1= in Stripe-Signature", ip_address
                )

            try:
                req_time = int(timestamp_str)
            except ValueError:
                return self._failure(provider, "Invalid timestamp in Stripe-Signature", ip_address)

            now = int(datetime.now(timezone.utc).timestamp())
            if abs(now - req_time) > _SLACK_MAX_AGE_SECONDS:
                return self._failure(
                    provider,
                    f"Stripe request timestamp too old ({abs(now - req_time)}s)",
                    ip_address,
                )

            signed_payload = f"{timestamp_str}.{payload.decode('utf-8', errors='replace')}"
            expected = hmac.new(
                secret.encode("utf-8"),
                signed_payload.encode("utf-8"),
                hashlib.sha256,
            ).hexdigest()

            if not hmac.compare_digest(v1_sig, expected):
                return self._failure(provider, "Signature mismatch", ip_address)

            return self._success(provider, ip_address)
        except Exception as exc:  # noqa: BLE001
            logger.warning("verify_stripe error: %s", exc)
            return self._failure(provider, f"Verification error: {exc}", ip_address)

    def verify_custom(
        self,
        payload: bytes,
        signature: str,
        secret: str,
        algorithm: str = "sha256",
        ip_address: Optional[str] = None,
    ) -> VerificationResult:
        """Verify a custom webhook using a configurable HMAC algorithm.

        Supported algorithms: sha256, sha1, sha512, md5.
        The signature is compared as a plain hex digest (no prefix stripping).
        """
        provider = WebhookProvider.CUSTOM
        try:
            if not signature:
                return self._failure(provider, "Missing signature", ip_address)
            if not secret:
                return self._failure(provider, "No secret configured", ip_address)

            algo_map = {
                "sha256": hashlib.sha256,
                "sha1": hashlib.sha1,
                "sha512": hashlib.sha512,
                "md5": hashlib.md5,
            }
            hash_fn = algo_map.get(algorithm.lower())
            if hash_fn is None:
                return self._failure(
                    provider,
                    f"Unsupported algorithm '{algorithm}'. Use: {sorted(algo_map)}",
                    ip_address,
                )

            expected = hmac.new(secret.encode("utf-8"), payload, hash_fn).hexdigest()
            # Strip common prefix variants for convenience
            sig_clean = signature
            for prefix in ("sha256=", "sha1=", "sha512=", "md5=", "v0=", "v1="):
                if sig_clean.startswith(prefix):
                    sig_clean = sig_clean[len(prefix):]
                    break

            if not hmac.compare_digest(sig_clean, expected):
                return self._failure(provider, "Signature mismatch", ip_address)

            return self._success(provider, ip_address)
        except Exception as exc:  # noqa: BLE001
            logger.warning("verify_custom error: %s", exc)
            return self._failure(provider, f"Verification error: {exc}", ip_address)

    # ------------------------------------------------------------------
    # Auto-detection
    # ------------------------------------------------------------------

    def auto_detect_provider(self, headers: Mapping[str, str]) -> Optional[WebhookProvider]:
        """Detect the webhook source from request headers.

        Returns the detected WebhookProvider or None if unrecognised.
        Detection is based on well-known header keys sent by each provider.
        """
        # Normalise header names to lowercase for case-insensitive matching
        lower: Dict[str, str] = {k.lower(): v for k, v in headers.items()}

        if "x-hub-signature-256" in lower or lower.get("x-github-event"):
            return WebhookProvider.GITHUB
        if "x-gitlab-token" in lower or lower.get("x-gitlab-event"):
            return WebhookProvider.GITLAB
        if "x-hub-signature" in lower and "atlassian" in lower.get("user-agent", "").lower():
            return WebhookProvider.JIRA
        # Jira fallback: X-Atlassian-Webhook-Identifier
        if "x-atlassian-webhook-identifier" in lower:
            return WebhookProvider.JIRA
        if "x-slack-signature" in lower or "x-slack-request-timestamp" in lower:
            return WebhookProvider.SLACK
        if "x-pagerduty-signature" in lower:
            return WebhookProvider.PAGERDUTY
        if "stripe-signature" in lower:
            return WebhookProvider.STRIPE
        if "x-servicenow-signature" in lower or "x-sn-signature" in lower:
            return WebhookProvider.SERVICENOW

        return None

    def verify(
        self,
        headers: Mapping[str, str],
        payload: bytes,
        secrets: Optional[Dict[str, str]] = None,
        ip_address: Optional[str] = None,
    ) -> VerificationResult:
        """Auto-detect provider from headers and verify the signature.

        ``secrets`` is a mapping from provider name (lowercase) to the shared
        secret configured for that provider.  Example::

            secrets = {
                "github": "my-github-secret",
                "slack": "my-slack-signing-secret",
            }

        If no secret is found for the detected provider, verification fails.
        If the provider cannot be detected, returns CUSTOM provider failure.
        """
        lower = {k.lower(): v for k, v in headers.items()}
        secrets = secrets or {}

        provider = self.auto_detect_provider(headers)
        if provider is None:
            result = VerificationResult(
                valid=False,
                provider=WebhookProvider.CUSTOM,
                ip_address=ip_address,
                error="Unable to detect webhook provider from headers",
            )
            self.log_verification(result)
            return result

        secret = secrets.get(provider.value, "")

        if provider == WebhookProvider.GITHUB:
            sig = lower.get("x-hub-signature-256", "")
            result = self.verify_github(payload, sig, secret, ip_address)

        elif provider == WebhookProvider.GITLAB:
            token = lower.get("x-gitlab-token", "")
            result = self.verify_gitlab(payload, token, secret, ip_address)

        elif provider == WebhookProvider.JIRA:
            sig = lower.get("x-hub-signature", "")
            result = self.verify_jira(payload, sig, secret, ip_address)

        elif provider == WebhookProvider.SLACK:
            sig = lower.get("x-slack-signature", "")
            ts = lower.get("x-slack-request-timestamp", "")
            result = self.verify_slack(payload, sig, ts, secret, ip_address)

        elif provider == WebhookProvider.PAGERDUTY:
            sig = lower.get("x-pagerduty-signature", "")
            result = self.verify_pagerduty(payload, sig, secret, ip_address)

        elif provider == WebhookProvider.STRIPE:
            sig = lower.get("stripe-signature", "")
            result = self.verify_stripe(payload, sig, secret, ip_address)

        elif provider == WebhookProvider.SERVICENOW:
            sig = lower.get("x-servicenow-signature", lower.get("x-sn-signature", ""))
            result = self.verify_custom(payload, sig, secret, "sha256", ip_address)
            # Override provider label
            result = VerificationResult(
                valid=result.valid,
                provider=WebhookProvider.SERVICENOW,
                timestamp=result.timestamp,
                ip_address=result.ip_address,
                error=result.error,
            )

        else:
            result = VerificationResult(
                valid=False,
                provider=provider,
                ip_address=ip_address,
                error=f"No verification handler for provider {provider}",
            )

        self.log_verification(result)
        return result

    # ------------------------------------------------------------------
    # Audit & stats
    # ------------------------------------------------------------------

    def log_verification(
        self,
        result: VerificationResult,
        org_id: str = "default",
    ) -> None:
        """Persist a verification result to the audit log."""
        entry_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()
        provider_val = result.provider if isinstance(result.provider, str) else result.provider.value
        try:
            with self._lock:
                conn = _get_db(self._db_path)
                try:
                    conn.execute(
                        """INSERT INTO webhook_verification_log
                           (id, org_id, provider, valid, ip_address, error, verified_at)
                           VALUES (?, ?, ?, ?, ?, ?, ?)""",
                        (
                            entry_id,
                            org_id,
                            provider_val,
                            1 if result.valid else 0,
                            result.ip_address,
                            result.error,
                            now,
                        ),
                    )
                    conn.commit()
                finally:
                    conn.close()
        except sqlite3.Error as exc:
            logger.error("log_verification failed: %s", exc)

        logger.info(
            "webhook_verify provider=%s valid=%s ip=%s error=%s",
            provider_val,
            result.valid,
            result.ip_address,
            result.error,
        )

    def get_verification_stats(self, org_id: str = "default") -> Dict[str, Any]:
        """Return pass/fail rates per provider for an organisation.

        Returns:
            {
                "org_id": str,
                "total": int,
                "by_provider": {
                    "<provider>": {"total": int, "passed": int, "failed": int, "pass_rate": float}
                }
            }
        """
        try:
            with self._lock:
                conn = _get_db(self._db_path)
                try:
                    rows = conn.execute(
                        """SELECT provider,
                                  COUNT(*) as total,
                                  SUM(valid) as passed
                           FROM webhook_verification_log
                           WHERE org_id = ?
                           GROUP BY provider""",
                        (org_id,),
                    ).fetchall()
                finally:
                    conn.close()
        except sqlite3.Error as exc:
            raise RuntimeError(f"Failed to get verification stats for org {org_id}: {exc}") from exc

        by_provider: Dict[str, Any] = {}
        grand_total = 0
        for row in rows:
            total = row["total"] or 0
            passed = row["passed"] or 0
            failed = total - passed
            grand_total += total
            by_provider[row["provider"]] = {
                "total": total,
                "passed": passed,
                "failed": failed,
                "pass_rate": round(passed / total, 4) if total > 0 else 0.0,
            }

        return {
            "org_id": org_id,
            "total": grand_total,
            "by_provider": by_provider,
        }

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _success(
        provider: WebhookProvider, ip_address: Optional[str]
    ) -> VerificationResult:
        return VerificationResult(valid=True, provider=provider, ip_address=ip_address)

    @staticmethod
    def _failure(
        provider: WebhookProvider, error: str, ip_address: Optional[str]
    ) -> VerificationResult:
        return VerificationResult(
            valid=False, provider=provider, ip_address=ip_address, error=error
        )


__all__ = [
    "WebhookProvider",
    "VerificationResult",
    "WebhookVerifier",
]
