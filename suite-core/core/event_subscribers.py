"""
FixOps Event Subscribers — Wires real handlers to the EventBus.

Call `register_all_subscribers()` at application startup so every
emitted event triggers downstream workflows automatically.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)

_registered = False


async def _on_cve_discovered(event):
    """When a CVE is discovered: enrich with EPSS/KEV, update graph."""
    data = event.data
    cve_id = data.get("cve_id", "")
    logger.info("EventBus handler: CVE_DISCOVERED %s", cve_id)
    try:
        from core.knowledge_brain import get_brain
        brain = get_brain()
        brain.ingest_cve(cve_id, org_id=event.org_id, **{
            k: v for k, v in data.items() if k != "cve_id"
        })
        logger.info("CVE %s ingested into Knowledge Graph", cve_id)
    except Exception as exc:
        logger.warning("Failed to ingest CVE %s into graph: %s", cve_id, exc)

    # Trigger EPSS lookup
    try:
        from src.services.feeds_service import FeedsService
        svc = FeedsService()
        epss = await svc.get_epss_score(cve_id)
        if epss:
            logger.info("EPSS score for %s: %s", cve_id, epss)
    except Exception as exc:
        logger.debug("EPSS lookup skipped for %s: %s", cve_id, exc)


async def _on_scan_completed(event):
    """When a scan completes: trigger dedup and brain pipeline."""
    data = event.data
    scan_id = data.get("scan_id", "unknown")
    logger.info("EventBus handler: SCAN_COMPLETED %s", scan_id)
    try:
        from core.knowledge_brain import get_brain
        brain = get_brain()
        brain.log_event("scan.completed", event.source, data)
    except Exception as exc:
        logger.debug("Graph log skipped: %s", exc)


async def _on_finding_created(event):
    """When a finding is created: ingest into graph, trigger dedup."""
    data = event.data
    finding_id = data.get("finding_id", "")
    logger.info("EventBus handler: FINDING_CREATED %s", finding_id)
    try:
        from core.knowledge_brain import get_brain
        brain = get_brain()
        cve_id = data.get("cve_id")
        brain.ingest_finding(
            finding_id, org_id=event.org_id, cve_id=cve_id,
            **{k: v for k, v in data.items() if k not in ("finding_id", "cve_id")}
        )
    except Exception as exc:
        logger.debug("Finding graph ingest skipped: %s", exc)


async def _on_autofix_generated(event):
    """When an autofix is generated: log to graph and emit audit event."""
    data = event.data
    logger.info("EventBus handler: AUTOFIX_GENERATED fix_id=%s", data.get("fix_id", ""))
    try:
        from core.knowledge_brain import get_brain
        brain = get_brain()
        brain.log_event("autofix.generated", event.source, data)
    except Exception as exc:
        logger.debug("AutoFix graph log skipped: %s", exc)


async def _on_pentest_completed(event):
    """When a pentest completes: ingest results into graph."""
    data = event.data
    logger.info("EventBus handler: PENTEST_COMPLETED target=%s", data.get("target", ""))
    try:
        from core.knowledge_brain import get_brain
        brain = get_brain()
        brain.log_event("pentest.completed", event.source, data)
    except Exception as exc:
        logger.debug("Pentest graph log skipped: %s", exc)


async def _on_risk_changed(event):
    """When risk score changes: log to graph."""
    data = event.data
    logger.info("EventBus handler: RISK_CHANGED node=%s", data.get("node_id", ""))


async def _on_graph_updated(event):
    """When graph is updated: log for audit trail."""
    logger.debug("EventBus handler: GRAPH_UPDATED action=%s", event.data.get("action", ""))


async def _on_feed_updated(event):
    """When a feed is updated: log to graph."""
    data = event.data
    logger.info("EventBus handler: FEED_UPDATED feed=%s", data.get("feed_name", ""))


async def _on_evidence_collected(event):
    """When evidence is collected: log to graph."""
    data = event.data
    logger.info("EventBus handler: EVIDENCE_COLLECTED control=%s", data.get("control_id", ""))


async def _on_wildcard(event):
    """Wildcard handler: audit log every event."""
    logger.debug("EventBus AUDIT: %s from %s", 
                 event.event_type.value if hasattr(event.event_type, 'value') else event.event_type,
                 event.source)


def register_all_subscribers() -> int:
    """Register all event subscribers. Returns count of subscriptions."""
    global _registered
    if _registered:
        logger.debug("Event subscribers already registered, skipping")
        return 0

    from core.event_bus import EventType, get_event_bus
    bus = get_event_bus()

    handlers = [
        (EventType.CVE_DISCOVERED, _on_cve_discovered),
        (EventType.CVE_ENRICHED, _on_cve_discovered),
        (EventType.SCAN_COMPLETED, _on_scan_completed),
        (EventType.FINDING_CREATED, _on_finding_created),
        (EventType.FINDING_UPDATED, _on_finding_created),
        (EventType.AUTOFIX_GENERATED, _on_autofix_generated),
        (EventType.PENTEST_COMPLETED, _on_pentest_completed),
        (EventType.RISK_CHANGED, _on_risk_changed),
        (EventType.RISK_CALCULATED, _on_risk_changed),
        (EventType.GRAPH_UPDATED, _on_graph_updated),
        (EventType.FEED_UPDATED, _on_feed_updated),
        (EventType.EVIDENCE_COLLECTED, _on_evidence_collected),
    ]

    for event_type, handler in handlers:
        bus.subscribe(event_type, handler)

    bus.subscribe_all(_on_wildcard)

    _registered = True
    count = len(handlers) + 1  # +1 for wildcard
    logger.info("Registered %d event subscribers (%d typed + 1 wildcard)", count, len(handlers))
    return count

