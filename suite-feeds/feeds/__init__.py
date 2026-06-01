"""suite-feeds/feeds package.

SPEC-005 §4 — shared air-gap egress guard for all feed importers.

Every importer's network entry-point must call ``feeds_egress_allowed()``
(or the convenience raiser ``assert_feeds_egress_allowed()``) before making
any outbound HTTP request.  Default (non-enforced) behaviour is unchanged.
"""

from __future__ import annotations

import os


def feeds_egress_allowed() -> bool:
    """Return False when outbound feed fetches must be blocked.

    Conditions that block egress (either is sufficient):
      - FIXOPS_AIRGAP_MODE=enforced  (SCIF / hard air-gap)
      - FIXOPS_FEEDS_OFFLINE=1       (explicit offline override)

    The authoritative helper ``core.airgap_config.is_airgap_enforced`` is
    called first; if it is unavailable (isolated import context) the env-var
    is checked directly so the guard never silently fails.
    """
    # Fast path: explicit feeds-offline flag
    if os.environ.get("FIXOPS_FEEDS_OFFLINE", "").strip() == "1":
        return False

    # Delegate to the single SPEC-005 authoritative helper
    try:
        from core.airgap_config import is_airgap_enforced  # type: ignore[import]
        if is_airgap_enforced():
            return False
    except Exception:  # noqa: BLE001
        # Fallback: honour env var directly
        if os.environ.get("FIXOPS_AIRGAP_MODE", "").strip().lower() == "enforced":
            return False

    return True


def assert_feeds_egress_allowed(feed_name: str = "feed") -> None:
    """Raise ``RuntimeError`` with a clean offline message when egress is blocked.

    Usage in an importer's network entry-point::

        from feeds import assert_feeds_egress_allowed
        assert_feeds_egress_allowed("nvd_cve")
        # ... proceed with httpx / urllib call
    """
    if not feeds_egress_allowed():
        raise RuntimeError(
            f"{feed_name}: offline — FIXOPS_AIRGAP_MODE=enforced or "
            "FIXOPS_FEEDS_OFFLINE=1. Use the offline bundle import path instead."
        )
