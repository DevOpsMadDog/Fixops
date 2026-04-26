"""Connector → TrustGraph emit helper.

Single shared helper used by every connector to broadcast successful
ingest/sync/scan/pull events into the TrustGraph event bus AND the legacy
in-process event bus.  Both bus calls are wrapped in ``try/except`` so a
broken bus can never break a connector — emission is purely additive.

Canonical contract (payload keys):
    connector       str  — connector class / module name
    org_id          str  — tenant the data belongs to
    finding_count   int  — how many findings/results were produced
    source_kind     str  — "sca", "sast", "dast", "cspm", "siem", "edr",
                            "iam", "container", "threat_intel", "sdlc", ...
    correlation_id  str  — caller-supplied or auto-generated UUID
    extra           dict — connector-specific metadata (scan_id, provider…)

Usage::

    from connectors._emit import emit_connector_event

    emit_connector_event(
        connector="SnykOSSConnector",
        org_id=org_id,
        source_kind="sca",
        finding_count=len(findings),
        extra={"tenant": tenant, "scan_id": scan_id},
    )
"""
from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, Optional

_logger = logging.getLogger(__name__)

# Map source_kind → TrustGraph event_type constant string
# (constants live in core.trustgraph_event_bus; we use string literals
# to avoid a hard import at module load time).
_KIND_TO_TG_EVENT = {
    "sca": "finding.created",
    "sast": "finding.created",
    "dast": "finding.created",
    "cspm": "finding.created",
    "container": "finding.created",
    "secrets": "finding.created",
    "iac": "finding.created",
    "siem": "alert.created",
    "edr": "threat.detected",
    "iam": "identity.updated",
    "threat_intel": "actor.identified",
    "sdlc": "asset.discovered",
    "asset": "asset.discovered",
    "vuln_intel": "cve.discovered",
    "scan": "scan.completed",
    "incident": "incident.created",
    "evidence": "evidence.collected",
    "policy": "policy.updated",
    "sync": "scan.completed",  # bidirectional sync ≈ scan completion
}

# Map source_kind → legacy core.event_bus.EventType name
_KIND_TO_LEGACY_EVENT = {
    "sca": "FINDING_CREATED",
    "sast": "FINDING_CREATED",
    "dast": "FINDING_CREATED",
    "cspm": "FINDING_CREATED",
    "container": "FINDING_CREATED",
    "secrets": "SECRET_FOUND",
    "iac": "FINDING_CREATED",
    "siem": "THREAT_DETECTED",
    "edr": "THREAT_DETECTED",
    "iam": "ASSET_DISCOVERED",
    "threat_intel": "FEED_UPDATED",
    "sdlc": "ASSET_DISCOVERED",
    "asset": "ASSET_DISCOVERED",
    "vuln_intel": "CVE_DISCOVERED",
    "scan": "SCAN_COMPLETED",
    "incident": "THREAT_DETECTED",
    "evidence": "EVIDENCE_COLLECTED",
    "policy": "POLICY_VIOLATED",
    "sync": "WORKFLOW_TRIGGERED",
}


def _build_payload(
    connector: str,
    org_id: str,
    source_kind: str,
    finding_count: int,
    correlation_id: Optional[str],
    extra: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    payload: Dict[str, Any] = {
        "connector": connector,
        "org_id": org_id,
        "source_kind": source_kind,
        "finding_count": int(finding_count or 0),
        "correlation_id": correlation_id or str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "engine": connector,            # required by FindingInput contract
        "scanner": connector,
    }
    if extra:
        for k, v in extra.items():
            if k not in payload:
                payload[k] = v
    return payload


def _emit_trustgraph(event_type: str, payload: Dict[str, Any]) -> None:
    """Emit to the TrustGraph event bus (fire-and-forget, async-safe)."""
    try:
        from core.trustgraph_event_bus import get_event_bus  # type: ignore
    except Exception as exc:  # pragma: no cover
        _logger.debug("trustgraph_event_bus import skipped: %s", exc)
        return

    try:
        bus = get_event_bus()
    except Exception as exc:  # pragma: no cover
        _logger.debug("trustgraph_event_bus get_event_bus failed: %s", exc)
        return

    try:
        import asyncio

        coro = bus.emit(event_type, payload)
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(coro)
        except RuntimeError:
            # No running loop — run synchronously in a fresh loop
            new_loop = asyncio.new_event_loop()
            try:
                new_loop.run_until_complete(coro)
            finally:
                new_loop.close()
    except Exception as exc:
        _logger.debug("trustgraph_event_bus emit failed: %s", exc)


def _emit_legacy_bus(legacy_event_name: str, source: str, payload: Dict[str, Any]) -> None:
    """Emit to the legacy core.event_bus (cross-suite signalling)."""
    try:
        from core.event_bus import Event, EventType, get_event_bus  # type: ignore
    except Exception as exc:  # pragma: no cover
        _logger.debug("legacy event_bus import skipped: %s", exc)
        return

    try:
        event_type = getattr(EventType, legacy_event_name, EventType.WORKFLOW_TRIGGERED)
    except Exception:
        return

    try:
        bus = get_event_bus()
        event = Event(
            event_type=event_type,
            source=source,
            org_id=payload.get("org_id"),
            data=dict(payload),
        )
        import asyncio
        try:
            loop = asyncio.get_running_loop()
            loop.create_task(bus.emit(event))
        except RuntimeError:
            new_loop = asyncio.new_event_loop()
            try:
                new_loop.run_until_complete(bus.emit(event))
            finally:
                new_loop.close()
    except Exception as exc:
        _logger.debug("legacy event_bus emit failed: %s", exc)


def emit_connector_event(
    connector: str,
    org_id: str,
    source_kind: str,
    finding_count: int = 0,
    correlation_id: Optional[str] = None,
    extra: Optional[Dict[str, Any]] = None,
) -> None:
    """Emit a connector success event to TrustGraph + legacy bus.

    Never raises — failures are swallowed and logged at DEBUG.  Safe to
    call from any context (sync or async, with or without a running loop).
    """
    try:
        payload = _build_payload(
            connector=connector,
            org_id=org_id or "default",
            source_kind=source_kind,
            finding_count=finding_count,
            correlation_id=correlation_id,
            extra=extra,
        )
        tg_event = _KIND_TO_TG_EVENT.get(source_kind, "scan.completed")
        legacy_event = _KIND_TO_LEGACY_EVENT.get(source_kind, "WORKFLOW_TRIGGERED")
        _emit_trustgraph(tg_event, payload)
        _emit_legacy_bus(legacy_event, connector, payload)
    except Exception as exc:  # pragma: no cover — defence in depth
        _logger.debug("emit_connector_event failed (swallowed): %s", exc)


__all__ = ["emit_connector_event"]
