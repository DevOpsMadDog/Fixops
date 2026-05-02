"""AWS Cost Explorer — Live API Connector (FinOps + security cost lens).

Connects to AWS Cost Explorer (`ce` service) to enumerate per-service spend
snapshots so ALDECI can surface cloud-cost anomalies and abandoned-resource
risk for the cloud-cost-security engine.

Live API flow:
1. boto3.client("ce", ...) using AWS_ACCESS_KEY_ID/SECRET (or instance role)
2. ce.get_cost_and_usage(TimePeriod=last 24h, Granularity=DAILY,
                         GroupBy=[SERVICE, REGION])
3. Project each (service, region) row into ALDECI ``cost_snapshot`` shape:
       {account_id, provider="aws", service_name, region, cost_usd,
        previous_cost_usd, change_pct, snapshot_date}
4. Caller (CloudCostSecurityEngine.list_snapshots_with_cost_explorer_fallback)
   may persist the snapshots via record_snapshot() — but the connector itself
   never writes to disk; it returns inert dicts.

Credential fallback:
- AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY required (or
  AWS_PROFILE / IAM instance role / EKS pod identity).
- AWS_DEFAULT_REGION optional (defaults to us-east-1, the only region
  Cost Explorer responds in).
- If creds OR boto3 OR Cost Explorer access is missing → graceful no-op:
  returns {status: "needs_credentials"}.

Cache: 1-hour TTL per (org_id, account_id). Idempotent — never duplicates.
"""

from __future__ import annotations

import logging
import os
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

from connectors._emit import emit_connector_event

_logger = logging.getLogger(__name__)

_CACHE_TTL_SECONDS = 3600  # 1 hour

_result_cache: Dict[Any, Any] = {}
_cache_lock = threading.Lock()


def _creds_present() -> bool:
    """Check whether AWS credentials are present in the environment.

    Accepts the standard pair (AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY) or a
    named profile (AWS_PROFILE). Does NOT validate the credentials.
    """
    if os.environ.get("AWS_ACCESS_KEY_ID") and os.environ.get("AWS_SECRET_ACCESS_KEY"):
        return True
    if os.environ.get("AWS_PROFILE"):
        return True
    # AWS_ROLE_ARN (EKS pod identity) is also acceptable when present alongside
    # AWS_WEB_IDENTITY_TOKEN_FILE.
    if os.environ.get("AWS_ROLE_ARN") and os.environ.get("AWS_WEB_IDENTITY_TOKEN_FILE"):
        return True
    return False


def _today_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d")


def _yesterday_iso() -> str:
    return (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")


def _two_days_ago_iso() -> str:
    return (datetime.now(timezone.utc) - timedelta(days=2)).strftime("%Y-%m-%d")


def _normalize_snapshot(row: Dict[str, Any], account_id: str) -> Dict[str, Any]:
    """Normalize a Cost Explorer GroupBy row to ALDECI cost_snapshot shape."""
    keys = row.get("Keys") or []
    service = keys[0] if len(keys) >= 1 else "unknown"
    region = keys[1] if len(keys) >= 2 else ""
    metrics = (row.get("Metrics") or {}).get("UnblendedCost", {})
    amount = float(metrics.get("Amount") or 0.0)
    return {
        "account_id": account_id,
        "provider": "aws",
        "service_name": service,
        "region": region,
        "cost_usd": amount,
        "previous_cost_usd": 0.0,
        "change_pct": 0.0,
        "snapshot_date": _yesterday_iso(),
        "last_used": None,
        "has_public_ip": False,
        "is_idle": False,
    }


class AWSCostExplorerConnector:
    """AWS Cost Explorer connector with credential fallback and 1-hour cache.

    Args:
        account_id:    Override caller's AWS account id surface.
        region:        Cost Explorer region (default: us-east-1).
        max_results:   Cap on snapshots to fetch per call.
    """

    def __init__(
        self,
        account_id: Optional[str] = None,
        region: Optional[str] = None,
        max_results: int = 1000,
    ) -> None:
        self._account_id = (
            account_id or os.environ.get("AWS_ACCOUNT_ID") or "default-account"
        )
        self._region = region or os.environ.get("AWS_DEFAULT_REGION") or "us-east-1"
        self._max_results = max(1, min(max_results, 50_000))

    def fetch_snapshots(
        self,
        org_id: str,
        force_refresh: bool = False,
    ) -> Dict[str, Any]:
        """Fetch yesterday's per-service cost snapshots for the configured account.

        Returns a status envelope:
          - {status: "ok", snapshots: [...], snapshots_count, ...}
          - {status: "needs_credentials", ...}
          - {status: "api_error", error, ...}
        Gracefully degrades when boto3 or AWS access is missing.
        """
        if not isinstance(org_id, str) or not org_id.strip():
            raise ValueError("org_id is required")

        if not _creds_present():
            _logger.warning(
                "AWSCostExplorerConnector: AWS_ACCESS_KEY_ID/SECRET or AWS_PROFILE "
                "not set — skipping for org=%s",
                org_id,
            )
            return {
                "status": "needs_credentials",
                "mode": "no-op",
                "org_id": org_id,
                "account_id": self._account_id,
                "snapshots_count": 0,
                "snapshots": [],
                "ingested_at": datetime.now(timezone.utc).isoformat(),
                "hint": (
                    "Set AWS_ACCESS_KEY_ID + AWS_SECRET_ACCESS_KEY (or "
                    "AWS_PROFILE / IAM instance role / EKS pod identity) to "
                    "enable AWS Cost Explorer ingestion. Optional: "
                    "AWS_ACCOUNT_ID, AWS_DEFAULT_REGION."
                ),
            }

        cache_key = (org_id, self._account_id)
        if not force_refresh:
            with _cache_lock:
                cached = _result_cache.get(cache_key)
                if cached and time.monotonic() < cached["expires_at"]:
                    return cached["result"]

        try:
            import boto3  # type: ignore
        except ImportError as exc:
            _logger.warning(
                "AWSCostExplorerConnector: boto3 not installed — skipping "
                "for org=%s",
                org_id,
            )
            return {
                "status": "needs_credentials",
                "mode": "no-op",
                "org_id": org_id,
                "account_id": self._account_id,
                "snapshots_count": 0,
                "snapshots": [],
                "ingested_at": datetime.now(timezone.utc).isoformat(),
                "hint": (
                    "boto3 is not installed. `pip install boto3` to enable "
                    "AWS Cost Explorer ingestion."
                ),
                "reason": f"boto3_import_failed: {exc}",
            }

        try:
            client = boto3.client("ce", region_name=self._region)
            resp = client.get_cost_and_usage(
                TimePeriod={"Start": _two_days_ago_iso(), "End": _today_iso()},
                Granularity="DAILY",
                Metrics=["UnblendedCost"],
                GroupBy=[
                    {"Type": "DIMENSION", "Key": "SERVICE"},
                    {"Type": "DIMENSION", "Key": "REGION"},
                ],
            )
        except Exception as exc:  # noqa: BLE001
            _logger.error(
                "AWSCostExplorerConnector: API error for org=%s: %s",
                org_id,
                exc,
            )
            return {
                "status": "api_error",
                "mode": "live",
                "org_id": org_id,
                "account_id": self._account_id,
                "snapshots_count": 0,
                "snapshots": [],
                "error": str(exc)[:500],
                "ingested_at": datetime.now(timezone.utc).isoformat(),
            }

        # results_by_time is a list of buckets (one per day in TimePeriod).
        # We collect all rows, dedupe by (service, region, day), keep the
        # most recent value as "current" and the prior as "previous".
        rows_by_day: Dict[str, List[Dict[str, Any]]] = {}
        for bucket in resp.get("ResultsByTime") or []:
            day = (bucket.get("TimePeriod") or {}).get("Start", "")
            rows_by_day.setdefault(day, []).extend(bucket.get("Groups") or [])

        days = sorted(rows_by_day.keys())
        latest = rows_by_day.get(days[-1], []) if days else []
        prior = rows_by_day.get(days[-2], []) if len(days) >= 2 else []
        prior_index: Dict[tuple, float] = {}
        for r in prior:
            keys = r.get("Keys") or []
            if len(keys) >= 2:
                amt = float(((r.get("Metrics") or {}).get("UnblendedCost") or {})
                            .get("Amount") or 0.0)
                prior_index[(keys[0], keys[1])] = amt

        snapshots: List[Dict[str, Any]] = []
        for r in latest[: self._max_results]:
            snap = _normalize_snapshot(r, self._account_id)
            prev = prior_index.get((snap["service_name"], snap["region"]), 0.0)
            snap["previous_cost_usd"] = prev
            if prev > 0:
                snap["change_pct"] = round(
                    ((snap["cost_usd"] - prev) / prev) * 100.0,
                    2,
                )
            else:
                snap["change_pct"] = 0.0
            snapshots.append(snap)

        emit_connector_event(
            connector="AWSCostExplorerConnector",
            org_id=org_id,
            source_kind="cspm",
            finding_count=len(snapshots),
            extra={"mode": "live", "account_id": self._account_id,
                   "region": self._region},
        )

        result = {
            "status": "ok",
            "mode": "live",
            "org_id": org_id,
            "account_id": self._account_id,
            "snapshots_count": len(snapshots),
            "snapshots": snapshots,
            "ingested_at": datetime.now(timezone.utc).isoformat(),
        }

        with _cache_lock:
            _result_cache[cache_key] = {
                "result": result,
                "expires_at": time.monotonic() + _CACHE_TTL_SECONDS,
            }

        return result


_singleton_lock = threading.Lock()
_singleton: Optional[AWSCostExplorerConnector] = None


def get_aws_cost_explorer_connector() -> AWSCostExplorerConnector:
    """Lazy singleton."""
    global _singleton
    with _singleton_lock:
        if _singleton is None:
            _singleton = AWSCostExplorerConnector()
    return _singleton


__all__ = [
    "AWSCostExplorerConnector",
    "get_aws_cost_explorer_connector",
    "_creds_present",
    "_normalize_snapshot",
]
