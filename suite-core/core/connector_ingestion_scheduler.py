"""Connector Ingestion Scheduler - pulls from ALL configured connectors
and feeds findings into BrainPipeline automatically.

Configuration (env vars):
    ALDECI_SCHEDULER_ENABLED=1          (default: 1)
    ALDECI_SCHEDULER_INTERVAL_S=300     (default: 300)
    ALDECI_SCHEDULER_BATCH_SIZE=500     (default: 500)
    ALDECI_SCHEDULER_ORG_IDS=acme,beta  (comma-sep, default: default)

Architecture
------------
* One daemon thread per org_id (lightweight; sleeps ``interval_s``).
* Every tick the scheduler asks each ``_collect_*`` helper to return a list of
  normalised finding dicts. Helpers MUST never raise: they swallow any error,
  log a warning, and return ``[]``.
* Aggregated findings (chunked by ``batch_size``) are handed to
  ``BrainPipeline.run`` for full 12-step processing.
"""
from __future__ import annotations

import logging
import os
import threading
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Severity helpers (module-level so tests can import without the class)
# ---------------------------------------------------------------------------

def _wazuh_level_to_severity(level: Any) -> str:
    """Map a Wazuh rule.level (0-15) to ALDECI severity buckets."""
    try:
        lvl = int(level)
    except (TypeError, ValueError):
        return "low"
    if lvl >= 12:
        return "critical"
    if lvl >= 8:
        return "high"
    if lvl >= 4:
        return "medium"
    return "low"


def _thehive_severity_to_str(severity: Any) -> str:
    """Map a TheHive case severity (1=low..4=critical) to ALDECI string."""
    mapping = {1: "low", 2: "medium", 3: "high", 4: "critical"}
    try:
        return mapping.get(int(severity), "medium")
    except (TypeError, ValueError):
        return "medium"


# ---------------------------------------------------------------------------
# Scheduler
# ---------------------------------------------------------------------------

class ConnectorIngestionScheduler:
    """Periodically pull findings from every configured connector and feed
    them into the BrainPipeline.

    The scheduler is fail-safe by design: every collector is wrapped in
    try/except, the daemon thread loop never crashes, and stop() is
    idempotent. Multiple schedulers can run concurrently (one per org_id).
    """

    def __init__(
        self,
        org_id: str,
        interval_s: int = 300,
        batch_size: int = 500,
    ) -> None:
        self.org_id = org_id
        self.interval_s = max(int(interval_s), 5)  # clamp to >= 5s for safety
        self.batch_size = max(int(batch_size), 1)
        self._stop = threading.Event()
        self._thread = threading.Thread(
            target=self._run_loop,
            daemon=True,
            name=f"ingestion-{org_id}",
        )
        self._pipeline = None  # lazy-init to avoid heavy import at module load

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Start the daemon thread (idempotent)."""
        if not self._thread.is_alive():
            try:
                self._thread.start()
                logger.info(
                    "ConnectorIngestionScheduler started org=%s interval=%ss",
                    self.org_id, self.interval_s,
                )
            except RuntimeError:
                # Thread already started; recreate so a future start works
                logger.warning(
                    "Scheduler thread for org=%s already started", self.org_id,
                )

    def stop(self) -> None:
        """Signal the loop to exit at the next tick (non-blocking)."""
        self._stop.set()
        logger.info("ConnectorIngestionScheduler stop requested org=%s", self.org_id)

    # ------------------------------------------------------------------
    # Pipeline accessor (lazy)
    # ------------------------------------------------------------------

    def _get_pipeline(self):
        """Lazy-import BrainPipeline so module import stays cheap and safe
        for unit tests that mock it out."""
        if self._pipeline is None:
            try:
                from core.brain_pipeline import BrainPipeline
                self._pipeline = BrainPipeline()
            except Exception as exc:  # noqa: BLE001 - defensive
                logger.warning("BrainPipeline import failed: %s", exc)
                self._pipeline = None
        return self._pipeline

    # ------------------------------------------------------------------
    # Aggregator
    # ------------------------------------------------------------------

    def collect_all_findings(self) -> List[Dict[str, Any]]:
        """Pull from all configured connectors. NEVER raises.

        Each collector is independent. If one fails (network down, missing
        credentials, malformed response, etc.) the remaining collectors
        still execute. Returns an aggregated list of normalised finding
        dicts (may be empty).
        """
        findings: List[Dict[str, Any]] = []
        collectors = (
            self._collect_trivy,
            self._collect_semgrep,
            self._collect_snyk,
            self._collect_github_security,
            self._collect_aws_hub,
            self._collect_azure_defender,
            self._collect_gcp_scc,
            self._collect_wazuh,
            self._collect_thehive,
            self._collect_feed_fusion,
        )
        for collector in collectors:
            try:
                result = collector()
                if result:
                    findings.extend(result)
            except Exception as exc:  # noqa: BLE001 - aggregate, never crash
                name = getattr(collector, "__name__", str(collector))
                logger.warning("%s failed: %s", name, exc)
        logger.info(
            "collect_all_findings org=%s total=%d", self.org_id, len(findings),
        )
        return findings

    # ------------------------------------------------------------------
    # Asset helpers
    # ------------------------------------------------------------------

    def _list_assets(self, asset_type: Optional[str] = None) -> List[Any]:
        """Best-effort fetch of ManagedAsset rows for this org.

        Returns [] on any error so callers stay simple.
        """
        try:
            from core.asset_inventory import AssetInventory
            inv = AssetInventory()
            return inv.list_assets(self.org_id, asset_type=asset_type) or []
        except Exception as exc:  # noqa: BLE001
            logger.debug("asset inventory unavailable: %s", exc)
            return []

    # ------------------------------------------------------------------
    # Collectors - one per source (10 total)
    # ------------------------------------------------------------------

    def _collect_trivy(self) -> List[Dict[str, Any]]:
        try:
            from core.trivy_integration import TrivyScanner
            scanner = TrivyScanner()
            if not scanner.is_trivy_available():
                return []
            findings: List[Dict[str, Any]] = []
            for asset in self._list_assets(asset_type="container"):
                image = (
                    getattr(asset, "hostname", None)
                    or (getattr(asset, "metadata", {}) or {}).get("image")
                    or getattr(asset, "name", None)
                )
                if not image:
                    continue
                try:
                    raw = scanner.scan_image(image)
                    findings.extend(scanner.normalize_results(raw) or [])
                except Exception as exc:  # noqa: BLE001
                    logger.debug("trivy scan_image(%s) failed: %s", image, exc)
            return findings
        except Exception as exc:  # noqa: BLE001
            logger.debug("trivy collector skipped: %s", exc)
            return []

    def _collect_semgrep(self) -> List[Dict[str, Any]]:
        try:
            from core.semgrep_integration import SemgrepScanner
            scanner = SemgrepScanner()
            is_available = getattr(scanner, "is_semgrep_available", None)
            if callable(is_available) and not is_available():
                return []
            findings: List[Dict[str, Any]] = []
            for asset in self._list_assets(asset_type="repository"):
                meta = getattr(asset, "metadata", {}) or {}
                path = (
                    meta.get("local_path")
                    or meta.get("path")
                    or meta.get("clone_path")
                )
                if not path or not os.path.isdir(path):
                    continue
                try:
                    raw = scanner.scan_directory(path)
                    findings.extend(scanner.normalize_results(raw) or [])
                except Exception as exc:  # noqa: BLE001
                    logger.debug("semgrep scan_directory(%s) failed: %s", path, exc)
            return findings
        except Exception as exc:  # noqa: BLE001
            logger.debug("semgrep collector skipped: %s", exc)
            return []

    def _collect_snyk(self) -> List[Dict[str, Any]]:
        try:
            from core.snyk_integration import SnykClient
            client = SnykClient()
            if not client.is_configured():
                return []
            return client.import_results(self.org_id) or []
        except Exception as exc:  # noqa: BLE001
            logger.debug("snyk collector skipped: %s", exc)
            return []

    def _collect_github_security(self) -> List[Dict[str, Any]]:
        try:
            from core.github_security import GitHubSecurityClient
            client = GitHubSecurityClient()
            if not client.is_configured():
                return []
            result = client.import_all(self.org_id) or {}
            return list(result.get("findings") or [])
        except Exception as exc:  # noqa: BLE001
            logger.debug("github_security collector skipped: %s", exc)
            return []

    def _collect_aws_hub(self) -> List[Dict[str, Any]]:
        try:
            from core.aws_security_hub import AWSSecurityHubClient
            client = AWSSecurityHubClient()
            if not client.is_configured():
                return []
            result = client.import_findings(self.org_id) or {}
            return list(result.get("findings") or [])
        except Exception as exc:  # noqa: BLE001
            logger.debug("aws_security_hub collector skipped: %s", exc)
            return []

    def _collect_azure_defender(self) -> List[Dict[str, Any]]:
        try:
            from core.azure_defender import AzureDefenderClient
            client = AzureDefenderClient()
            if not client.is_configured():
                return []
            result = client.import_findings(self.org_id) or {}
            return list(result.get("findings") or [])
        except Exception as exc:  # noqa: BLE001
            logger.debug("azure_defender collector skipped: %s", exc)
            return []

    def _collect_gcp_scc(self) -> List[Dict[str, Any]]:
        try:
            from core.gcp_scc import GCPSecurityClient
            client = GCPSecurityClient()
            if not client.is_configured():
                return []
            result = client.import_findings(self.org_id) or {}
            return list(result.get("findings") or [])
        except Exception as exc:  # noqa: BLE001
            logger.debug("gcp_scc collector skipped: %s", exc)
            return []

    def _collect_wazuh(self) -> List[Dict[str, Any]]:
        try:
            from core.enterprise_sim_services import WazuhSIEMConnector
            conn = WazuhSIEMConnector()
            outcome = conn.get_alerts(limit=500)
            if not getattr(outcome, "success", False):
                return []
            alerts = (outcome.details or {}).get("alerts") or []
            findings: List[Dict[str, Any]] = []
            for alert in alerts:
                rule = alert.get("rule", {}) if isinstance(alert, dict) else {}
                level = rule.get("level") if isinstance(rule, dict) else None
                findings.append({
                    "id": str(alert.get("id") or alert.get("_id") or ""),
                    "source": "wazuh",
                    "title": (rule.get("description") if isinstance(rule, dict)
                              else None) or "Wazuh alert",
                    "severity": _wazuh_level_to_severity(level),
                    "asset_type": "host",
                    "raw": alert,
                    "org_id": self.org_id,
                })
            return findings
        except Exception as exc:  # noqa: BLE001
            logger.debug("wazuh collector skipped: %s", exc)
            return []

    def _collect_thehive(self) -> List[Dict[str, Any]]:
        try:
            from core.enterprise_sim_services import TheHiveConnector
            conn = TheHiveConnector()
            outcome = conn.list_cases(limit=100)
            if not getattr(outcome, "success", False):
                return []
            cases = (outcome.details or {}).get("cases") or []
            findings: List[Dict[str, Any]] = []
            for case in cases:
                if not isinstance(case, dict):
                    continue
                findings.append({
                    "id": str(case.get("_id") or case.get("id") or ""),
                    "source": "thehive",
                    "title": case.get("title") or "TheHive case",
                    "description": case.get("description", ""),
                    "severity": _thehive_severity_to_str(case.get("severity")),
                    "asset_type": "incident",
                    "raw": case,
                    "org_id": self.org_id,
                })
            return findings
        except Exception as exc:  # noqa: BLE001
            logger.debug("thehive collector skipped: %s", exc)
            return []

    def _collect_feed_fusion(self) -> List[Dict[str, Any]]:
        try:
            from core.vuln_intel_fusion_engine import VulnIntelFusionEngine
            engine = VulnIntelFusionEngine()
            queue = engine.get_priority_queue(self.org_id, limit=200) or []
            findings: List[Dict[str, Any]] = []
            for vuln in queue:
                sev = (vuln.get("consensus_severity") or
                       vuln.get("severity") or "medium")
                if str(sev).lower() not in ("critical", "high"):
                    continue
                findings.append({
                    "id": vuln.get("cve_id") or vuln.get("id") or "",
                    "source": "feed_fusion",
                    "title": vuln.get("title")
                             or vuln.get("cve_id")
                             or "Fused vulnerability",
                    "severity": str(sev).lower(),
                    "asset_type": "cve",
                    "raw": vuln,
                    "org_id": self.org_id,
                })
            return findings
        except Exception as exc:  # noqa: BLE001
            logger.debug("feed_fusion collector skipped: %s", exc)
            return []

    # ------------------------------------------------------------------
    # Loop body
    # ------------------------------------------------------------------

    def _run_loop(self) -> None:  # pragma: no cover - exercised via stop event
        """Daemon loop body. Sleeps between ticks; exits cleanly on stop()."""
        logger.info(
            "ingestion loop running org=%s interval=%ss",
            self.org_id, self.interval_s,
        )
        while not self._stop.is_set():
            try:
                self._tick_once()
            except Exception as exc:  # noqa: BLE001 - never let the loop die
                logger.exception("ingestion tick failed: %s", exc)
            # interruptible sleep
            if self._stop.wait(self.interval_s):
                break
        logger.info("ingestion loop exited org=%s", self.org_id)

    def _tick_once(self) -> None:
        """One iteration: collect + run pipeline if findings present."""
        findings = self.collect_all_findings()
        if not findings:
            logger.debug("no findings this tick org=%s", self.org_id)
            return
        pipeline = self._get_pipeline()
        if pipeline is None:
            logger.warning(
                "pipeline unavailable; dropping %d findings org=%s",
                len(findings), self.org_id,
            )
            return
        # Chunk by batch_size to avoid overloading the pipeline
        try:
            from core.brain_pipeline import PipelineInput
        except Exception as exc:  # noqa: BLE001
            logger.warning("PipelineInput import failed: %s", exc)
            return
        for i in range(0, len(findings), self.batch_size):
            batch = findings[i : i + self.batch_size]
            try:
                pipeline.run(PipelineInput(
                    org_id=self.org_id,
                    findings=batch,
                    source="connector_scheduler",
                    metadata={"scheduler": True, "batch_index": i},
                ))
            except Exception as exc:  # noqa: BLE001
                logger.exception("pipeline.run failed batch=%d: %s", i, exc)


# ---------------------------------------------------------------------------
# FastAPI integration helpers
# ---------------------------------------------------------------------------

_SCHEDULERS: List[ConnectorIngestionScheduler] = []


def start_schedulers_from_env() -> List[ConnectorIngestionScheduler]:
    """Read ALDECI_SCHEDULER_* env vars and start one scheduler per org_id.

    Idempotent: subsequent calls are a no-op while schedulers are running.
    Returns the list of active schedulers (possibly empty).
    """
    global _SCHEDULERS
    if _SCHEDULERS:
        return _SCHEDULERS
    if os.getenv("ALDECI_SCHEDULER_ENABLED", "1") != "1":
        logger.info("ConnectorIngestionScheduler disabled via env")
        return []
    try:
        interval = int(os.getenv("ALDECI_SCHEDULER_INTERVAL_S", "300"))
    except ValueError:
        interval = 300
    try:
        batch = int(os.getenv("ALDECI_SCHEDULER_BATCH_SIZE", "500"))
    except ValueError:
        batch = 500
    org_ids = [
        o.strip() for o in os.getenv("ALDECI_SCHEDULER_ORG_IDS", "default").split(",")
        if o.strip()
    ] or ["default"]
    started: List[ConnectorIngestionScheduler] = []
    for org_id in org_ids:
        try:
            sched = ConnectorIngestionScheduler(
                org_id=org_id, interval_s=interval, batch_size=batch,
            )
            sched.start()
            started.append(sched)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Failed to start scheduler org=%s: %s", org_id, exc)
    _SCHEDULERS = started
    return started


def stop_all_schedulers() -> None:
    """Stop every scheduler started by ``start_schedulers_from_env``."""
    global _SCHEDULERS
    for sched in _SCHEDULERS:
        try:
            sched.stop()
        except Exception as exc:  # noqa: BLE001
            logger.debug("scheduler stop error: %s", exc)
    _SCHEDULERS = []
