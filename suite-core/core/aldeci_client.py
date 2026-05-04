"""ALDECI Python Client SDK.

A lightweight, zero-dependency HTTP client for the ALDECI security platform API.
Uses only the Python standard library (``urllib``) so it works in any environment
without extra packages.

Usage example::

    from core.aldeci_client import ALDECIClient, ALDECIError

    client = ALDECIClient(
        base_url="http://localhost:8000",
        api_key=os.getenv("ALDECI_API_KEY", ""),  # never hardcode keys — use env var
    )

    # Health check
    status = client.health()

    # ASPM
    sbom = client.sbom_export_cyclonedx(project_name="my-service", org_id="acme")

    # SOC
    alerts = client.alert_queue(org_id="acme")
    incidents = client.incidents(org_id="acme")

    # Compliance
    posture = client.posture_score(org_id="acme")
    results = client.compliance_scan_results(org_id="acme")

    # Intelligence
    hits = client.graph_query(template="threat_context", org_id="acme")
    answer = client.copilot_chat("What are my top 5 open incidents?")

    # Risk
    overview = client.risk_org_score(org_id="acme")

Environment variables (override constructor params)::

    ALDECI_BASE_URL  — Base URL for the ALDECI API server
    ALDECI_API_KEY   — API key (``X-API-Key`` header value)
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ALDECIError(Exception):
    """Raised when the ALDECI API returns a 4xx or 5xx response.

    Attributes:
        status_code: HTTP status code returned by the server.
        detail: Error detail string from the response body (if JSON).
    """

    def __init__(self, status_code: int, detail: str) -> None:
        self.status_code = status_code
        self.detail = detail
        super().__init__(f"HTTP {status_code}: {detail}")


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------


class ALDECIClient:
    """ALDECI Security Platform Python SDK.

    All methods return parsed JSON (``dict`` or ``list``).  On HTTP errors they
    raise :class:`ALDECIError` with the status code and detail message.

    Args:
        base_url: Root URL of the ALDECI API server, e.g. ``http://localhost:8000``.
            Falls back to the ``ALDECI_BASE_URL`` environment variable.
        api_key: API key sent as ``X-API-Key`` header.
            Falls back to the ``ALDECI_API_KEY`` environment variable.
        timeout: Per-request socket timeout in seconds (default: 30).

    Example::

        client = ALDECIClient(base_url="http://localhost:8000", api_key="my-key")
        print(client.health())
    """

    def __init__(
        self,
        base_url: str = "",
        api_key: str = "",
        timeout: int = 30,
    ) -> None:
        self.base_url = (
            (base_url or os.getenv("ALDECI_BASE_URL", "http://localhost:8000"))
            .rstrip("/")
        )
        self._api_key = api_key or os.getenv("ALDECI_API_KEY", "")
        self._timeout = timeout

    # ------------------------------------------------------------------
    # Internal HTTP helpers
    # ------------------------------------------------------------------

    def _headers(self) -> Dict[str, str]:
        h: Dict[str, str] = {"Content-Type": "application/json", "Accept": "application/json"}
        if self._api_key:
            h["X-API-Key"] = self._api_key
        return h

    def _request(
        self,
        method: str,
        path: str,
        params: Optional[Dict[str, Any]] = None,
        body: Optional[Any] = None,
    ) -> Any:
        """Execute an HTTP request and return the parsed JSON response.

        Args:
            method: HTTP verb (``GET``, ``POST``, ``PATCH``, ``DELETE``).
            path: API path starting with ``/``.
            params: Query string parameters (will be URL-encoded).
            body: Request body — serialised to JSON.

        Returns:
            Parsed JSON response (dict, list, or primitive).

        Raises:
            ALDECIError: On 4xx/5xx responses.
        """
        url = self.base_url + path
        if params:
            filtered = {k: v for k, v in params.items() if v is not None}
            if filtered:
                url = url + "?" + urllib.parse.urlencode(filtered)

        data: Optional[bytes] = None
        if body is not None:
            data = json.dumps(body).encode("utf-8")

        req = urllib.request.Request(url, data=data, method=method, headers=self._headers())

        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                raw = resp.read()
                return json.loads(raw) if raw else {}
        except urllib.error.HTTPError as exc:
            raw = exc.read()
            try:
                payload = json.loads(raw)
                detail = payload.get("detail", str(payload))
            except Exception:
                detail = raw.decode("utf-8", errors="replace") or exc.reason or str(exc)
            raise ALDECIError(exc.code, detail) from exc

    def _get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Any:
        return self._request("GET", path, params=params)

    def _post(self, path: str, body: Any = None, params: Optional[Dict[str, Any]] = None) -> Any:
        return self._request("POST", path, params=params, body=body)

    def _patch(self, path: str, body: Any = None) -> Any:
        return self._request("PATCH", path, body=body)

    def _delete(self, path: str) -> Any:
        return self._request("DELETE", path)

    # ==================================================================
    # Health & Platform
    # ==================================================================

    def health(self) -> Dict[str, Any]:
        """Return basic API health status.

        Returns:
            ``{"status": "ok", ...}``

        Example::

            client.health()  # {"status": "ok"}
        """
        return self._get("/api/v1/health")

    def platform_health(self) -> Dict[str, Any]:
        """Return aggregate platform health (all sub-services).

        Returns:
            Dict with per-service status entries.

        Example::

            client.platform_health()
        """
        return self._get("/api/v1/platform/health")

    def deployment_health(self) -> Dict[str, Any]:
        """Return deployment-level health check across all ALDECI services.

        Returns:
            Dict with API, UI, TrustGraph service statuses.

        Example::

            client.deployment_health()
        """
        return self._get("/api/v1/deployment/health")

    # ==================================================================
    # ASPM — SBOM Export
    # ==================================================================

    def sbom_export_cyclonedx(
        self,
        project_name: str,
        org_id: str = "default",
        version: str = "1.0.0",
    ) -> Dict[str, Any]:
        """Generate a CycloneDX 1.4 SBOM for a project.

        Args:
            project_name: Name of the project to export.
            org_id: Organisation identifier.
            version: SBOM version string.

        Returns:
            CycloneDX 1.4 SBOM document as a dict.

        Example::

            sbom = client.sbom_export_cyclonedx("backend-api", org_id="acme")
        """
        return self._post(
            "/api/v1/sbom-export/generate/cyclonedx",
            body={"org_id": org_id, "project_name": project_name, "version": version},
        )

    def sbom_export_spdx(
        self,
        project_name: str,
        org_id: str = "default",
        version: str = "1.0.0",
    ) -> Dict[str, Any]:
        """Generate an SPDX 2.3 SBOM for a project.

        Args:
            project_name: Name of the project to export.
            org_id: Organisation identifier.
            version: SBOM version string.

        Returns:
            SPDX 2.3 SBOM document as a dict.

        Example::

            sbom = client.sbom_export_spdx("frontend", org_id="acme")
        """
        return self._post(
            "/api/v1/sbom-export/generate/spdx",
            body={"org_id": org_id, "project_name": project_name, "version": version},
        )

    def sbom_projects(self, org_id: str = "default") -> List[Dict[str, Any]]:
        """List SBOM projects for an organisation.

        Args:
            org_id: Organisation identifier.

        Returns:
            List of project summary dicts.

        Example::

            projects = client.sbom_projects(org_id="acme")
        """
        return self._get("/api/v1/sbom-export/projects", params={"org_id": org_id})

    # ==================================================================
    # ASPM — Supply Chain
    # ==================================================================

    def supply_chain_risks(self, org_id: str = "default") -> List[Dict[str, Any]]:
        """List supply chain risk entries for an organisation.

        Args:
            org_id: Organisation identifier.

        Returns:
            List of supply chain risk dicts.

        Example::

            risks = client.supply_chain_risks(org_id="acme")
        """
        return self._get("/api/v1/supply-chain/risks", params={"org_id": org_id})

    def supply_chain_summary(self, org_id: str = "default") -> Dict[str, Any]:
        """Return supply chain risk summary statistics.

        Args:
            org_id: Organisation identifier.

        Returns:
            Summary stats dict with counts by severity.

        Example::

            summary = client.supply_chain_summary(org_id="acme")
        """
        return self._get("/api/v1/supply-chain/summary", params={"org_id": org_id})

    # ==================================================================
    # SOC — Alert Triage
    # ==================================================================

    def alert_queue(self, org_id: str = "default") -> List[Dict[str, Any]]:
        """Return the prioritised alert triage queue.

        Alerts are ordered by priority (p1 first).

        Args:
            org_id: Organisation identifier.

        Returns:
            List of alert dicts ordered by priority.

        Example::

            queue = client.alert_queue(org_id="acme")
        """
        return self._get("/api/v1/alert-triage/queue", params={"org_id": org_id})

    def alerts(self, org_id: str = "default", status: Optional[str] = None) -> List[Dict[str, Any]]:
        """List alerts, optionally filtered by status.

        Args:
            org_id: Organisation identifier.
            status: Filter by alert status (e.g. ``"open"``, ``"triaged"``).

        Returns:
            List of alert dicts.

        Example::

            open_alerts = client.alerts(org_id="acme", status="open")
        """
        return self._get("/api/v1/alert-triage/alerts", params={"org_id": org_id, "status": status})

    def alert_stats(self, org_id: str = "default") -> Dict[str, Any]:
        """Return alert triage statistics (counts by priority/status).

        Args:
            org_id: Organisation identifier.

        Returns:
            Stats dict with counts, MTTR, queue depth, etc.

        Example::

            stats = client.alert_stats(org_id="acme")
        """
        return self._get("/api/v1/alert-triage/stats", params={"org_id": org_id})

    # ==================================================================
    # SOC — Incident Orchestration
    # ==================================================================

    def incidents(
        self,
        org_id: str = "default",
        status: Optional[str] = None,
        severity: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List incidents for an organisation.

        Args:
            org_id: Organisation identifier.
            status: Filter by lifecycle status (``open``, ``contained``, ``resolved``, etc.).
            severity: Filter by severity (``critical``, ``high``, ``medium``, ``low``).

        Returns:
            List of incident dicts.

        Example::

            critical = client.incidents(org_id="acme", severity="critical")
        """
        return self._get(
            "/api/v1/incident-orchestration/incidents",
            params={"org_id": org_id, "status": status, "severity": severity},
        )

    def incident_metrics(self, org_id: str = "default") -> Dict[str, Any]:
        """Return incident MTTR / MTTC metrics.

        Args:
            org_id: Organisation identifier.

        Returns:
            Metrics dict with MTTR, MTTC, counts by severity.

        Example::

            metrics = client.incident_metrics(org_id="acme")
        """
        return self._get("/api/v1/incident-orchestration/metrics", params={"org_id": org_id})

    def create_incident(
        self,
        title: str,
        severity: str,
        org_id: str = "default",
        description: str = "",
    ) -> Dict[str, Any]:
        """Create a new incident.

        Args:
            title: Short incident title.
            severity: ``critical`` | ``high`` | ``medium`` | ``low``.
            org_id: Organisation identifier.
            description: Optional longer description.

        Returns:
            Created incident dict with ``incident_id``.

        Example::

            inc = client.create_incident("Ransomware detected", "critical", org_id="acme")
        """
        return self._post(
            "/api/v1/incident-orchestration/incidents",
            body={
                "org_id": org_id,
                "title": title,
                "severity": severity,
                "description": description,
            },
        )

    # ==================================================================
    # Compliance
    # ==================================================================

    def compliance_scan_results(self, org_id: str = "default") -> List[Dict[str, Any]]:
        """Return compliance scanner results.

        Args:
            org_id: Organisation identifier.

        Returns:
            List of compliance check result dicts.

        Example::

            results = client.compliance_scan_results(org_id="acme")
        """
        return self._get("/api/v1/compliance-scanner/results", params={"org_id": org_id})

    def compliance_stats(self, org_id: str = "default") -> Dict[str, Any]:
        """Return compliance pass/fail statistics.

        Args:
            org_id: Organisation identifier.

        Returns:
            Stats dict with pass_count, fail_count, pass_rate.

        Example::

            stats = client.compliance_stats(org_id="acme")
        """
        return self._get("/api/v1/compliance-scanner/stats", params={"org_id": org_id})

    def evidence_collect_all(self, org_id: str = "default") -> Dict[str, Any]:
        """Trigger auto-collection of compliance evidence.

        Args:
            org_id: Organisation identifier.

        Returns:
            Dict with collection job status and collected evidence count.

        Example::

            result = client.evidence_collect_all(org_id="acme")
        """
        return self._post("/api/v1/auto-evidence/collect-all", body={"org_id": org_id})

    def compliance_status(self, org_id: str = "default") -> Dict[str, Any]:
        """Return overall compliance posture status across all frameworks.

        Args:
            org_id: Organisation identifier.

        Returns:
            Dict with per-framework compliance scores.

        Example::

            status = client.compliance_status(org_id="acme")
        """
        return self._get("/api/v1/compliance-scanner/stats", params={"org_id": org_id})

    # ==================================================================
    # Intelligence — GraphRAG
    # ==================================================================

    def graph_query(
        self,
        template: str,
        org_id: str = "default",
        max_hops: int = 2,
        limit: int = 20,
    ) -> Dict[str, Any]:
        """Query the TrustGraph knowledge graph using a retrieval template.

        Args:
            template: Named query template (e.g. ``"threat_context"``, ``"attack_paths"``).
            org_id: Organisation identifier (scopes results).
            max_hops: BFS traversal depth (default: 2).
            limit: Maximum number of results to return.

        Returns:
            Dict with ``nodes``, ``edges``, and ``context`` fields.

        Example::

            result = client.graph_query("threat_context", org_id="acme", max_hops=3)
        """
        return self._post(
            "/api/v1/graphrag/retrieve",
            body={
                "template": template,
                "org_id": org_id,
                "max_hops": max_hops,
                "limit": limit,
            },
        )

    def graph_semantic_search(
        self,
        query: str,
        org_id: str = "default",
        limit: int = 10,
    ) -> Dict[str, Any]:
        """Run a semantic similarity search over the knowledge graph.

        Args:
            query: Natural language query string.
            org_id: Organisation identifier.
            limit: Maximum number of results.

        Returns:
            Dict with ranked ``results`` list.

        Example::

            hits = client.graph_semantic_search("privilege escalation techniques")
        """
        return self._post(
            "/api/v1/graphrag/semantic-search",
            body={"query": query, "org_id": org_id, "limit": limit},
        )

    def graph_health(self) -> Dict[str, Any]:
        """Return GraphRAG / TrustGraph health status.

        Returns:
            Dict with per-core health scores and overall status.

        Example::

            client.graph_health()
        """
        return self._get("/api/v1/graphrag/health")

    def copilot_chat(self, question: str, org_id: str = "default") -> Dict[str, Any]:
        """Ask the ALDECI security copilot a natural-language question.

        Uses GraphRAG context enrichment (RAG) under the hood.

        Args:
            question: Natural language question to ask.
            org_id: Organisation identifier for context scoping.

        Returns:
            Dict with ``answer``, ``sources``, and ``confidence`` fields.

        Example::

            reply = client.copilot_chat("What are my top open vulnerabilities?")
        """
        return self._post(
            "/api/v1/copilot/chat",
            body={"message": question, "org_id": org_id},
        )

    def copilot_agents(self) -> List[Dict[str, Any]]:
        """List available copilot agent personas.

        Returns:
            List of agent dicts with ``name``, ``description``, and ``capabilities``.

        Example::

            agents = client.copilot_agents()
        """
        return self._get("/api/v1/copilot/agents")

    # ==================================================================
    # Risk
    # ==================================================================

    def risk_org_score(self, org_id: str = "default") -> Dict[str, Any]:
        """Return the composite organisational risk score (A-F grade).

        Args:
            org_id: Organisation identifier.

        Returns:
            Dict with ``score``, ``grade``, and per-domain breakdown.

        Example::

            score = client.risk_org_score(org_id="acme")
        """
        return self._get("/api/v1/risk-aggregator/org-score", params={"org_id": org_id})

    def risk_overview(self, org_id: str = "default") -> Dict[str, Any]:
        """Return risk aggregation overview including top risks and heatmap.

        Args:
            org_id: Organisation identifier.

        Returns:
            Dict with ``top_risks``, ``heatmap``, ``org_score``, and ``stats``.

        Example::

            overview = client.risk_overview(org_id="acme")
        """
        top = self._get("/api/v1/risk-aggregator/top-risks", params={"org_id": org_id})
        stats = self._get("/api/v1/risk-aggregator/stats", params={"org_id": org_id})
        org_score = self.risk_org_score(org_id=org_id)
        return {"top_risks": top, "stats": stats, "org_score": org_score}

    def risk_heatmap(self, org_id: str = "default") -> Dict[str, Any]:
        """Return risk heatmap data (entity-level risk scores).

        Args:
            org_id: Organisation identifier.

        Returns:
            Dict with heatmap cells by likelihood x impact.

        Example::

            heatmap = client.risk_heatmap(org_id="acme")
        """
        return self._get("/api/v1/risk-aggregator/heatmap", params={"org_id": org_id})

    def risk_scores(self, org_id: str = "default") -> List[Dict[str, Any]]:
        """List all entity risk scores for an organisation.

        Args:
            org_id: Organisation identifier.

        Returns:
            List of entity risk score dicts.

        Example::

            scores = client.risk_scores(org_id="acme")
        """
        return self._get("/api/v1/risk-aggregator/scores", params={"org_id": org_id})

    # ==================================================================
    # Security Posture
    # ==================================================================

    def posture_score(self, org_id: str = "default") -> Dict[str, Any]:
        """Return the current security posture score.

        Args:
            org_id: Organisation identifier.

        Returns:
            Dict with ``score``, ``grade``, and component breakdown.

        Example::

            posture = client.posture_score(org_id="acme")
        """
        return self._get("/api/v1/posture-score/current", params={"org_id": org_id})

    def posture_history(self, org_id: str = "default", limit: int = 30) -> List[Dict[str, Any]]:
        """Return posture score history (time series).

        Args:
            org_id: Organisation identifier.
            limit: Number of historical data points to return.

        Returns:
            List of ``{score, timestamp}`` dicts ordered by recency.

        Example::

            history = client.posture_history(org_id="acme", limit=90)
        """
        return self._get("/api/v1/posture-score/history", params={"org_id": org_id, "limit": limit})

    # ==================================================================
    # Vulnerability Intelligence
    # ==================================================================

    def vulnerabilities(
        self,
        org_id: str = "default",
        severity: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """List vulnerabilities with optional severity filter.

        Args:
            org_id: Organisation identifier.
            severity: Filter by severity (``critical``, ``high``, ``medium``, ``low``).
            limit: Maximum number of results.

        Returns:
            List of vulnerability dicts with CVSS, EPSS, KEV flag.

        Example::

            crits = client.vulnerabilities(org_id="acme", severity="critical")
        """
        return self._get(
            "/api/v1/vuln-intel/cves",
            params={"org_id": org_id, "severity": severity, "limit": limit},
        )

    def vulnerability_stats(self, org_id: str = "default") -> Dict[str, Any]:
        """Return vulnerability count statistics by severity.

        Args:
            org_id: Organisation identifier.

        Returns:
            Dict with counts by severity and KEV/EPSS breakdown.

        Example::

            stats = client.vulnerability_stats(org_id="acme")
        """
        return self._get("/api/v1/vuln-intel/stats", params={"org_id": org_id})

    # ==================================================================
    # Threat Intelligence
    # ==================================================================

    def threat_indicators(
        self,
        org_id: str = "default",
        ioc_type: Optional[str] = None,
        active_only: bool = True,
    ) -> List[Dict[str, Any]]:
        """List threat indicators (IOCs).

        Args:
            org_id: Organisation identifier.
            ioc_type: Filter by IOC type (``ip``, ``domain``, ``hash``, ``url``, etc.).
            active_only: If True, only return active indicators.

        Returns:
            List of indicator dicts with confidence and sighting count.

        Example::

            ips = client.threat_indicators(org_id="acme", ioc_type="ip")
        """
        return self._get(
            "/api/v1/threat-indicators/indicators",
            params={"org_id": org_id, "ioc_type": ioc_type, "active_only": active_only},
        )

    def threat_intel_stats(self, org_id: str = "default") -> Dict[str, Any]:
        """Return threat intelligence platform statistics.

        Args:
            org_id: Organisation identifier.

        Returns:
            Dict with IOC counts, TLP distribution, and feed health.

        Example::

            stats = client.threat_intel_stats(org_id="acme")
        """
        return self._get("/api/v1/tip/stats", params={"org_id": org_id})

    # ==================================================================
    # Attack Surface
    # ==================================================================

    def attack_surface_summary(self, org_id: str = "default") -> Dict[str, Any]:
        """Return attack surface management summary.

        Args:
            org_id: Organisation identifier.

        Returns:
            Dict with exposure score, asset counts, and severity distribution.

        Example::

            summary = client.attack_surface_summary(org_id="acme")
        """
        return self._get("/api/v1/asm/stats", params={"org_id": org_id})

    def attack_surface_exposures(self, org_id: str = "default") -> List[Dict[str, Any]]:
        """List open attack surface exposures.

        Args:
            org_id: Organisation identifier.

        Returns:
            List of exposure dicts ordered by severity.

        Example::

            exposures = client.attack_surface_exposures(org_id="acme")
        """
        return self._get("/api/v1/asm/exposures", params={"org_id": org_id})

    # ==================================================================
    # Assets
    # ==================================================================

    def assets(
        self,
        org_id: str = "default",
        asset_type: Optional[str] = None,
        limit: int = 100,
    ) -> List[Dict[str, Any]]:
        """List assets in the inventory.

        Args:
            org_id: Organisation identifier.
            asset_type: Filter by asset type (``server``, ``endpoint``, ``cloud``, etc.).
            limit: Maximum number of results.

        Returns:
            List of asset dicts.

        Example::

            servers = client.assets(org_id="acme", asset_type="server")
        """
        return self._get(
            "/api/v1/assets",
            params={"org_id": org_id, "asset_type": asset_type, "limit": limit},
        )

    # ==================================================================
    # KPIs
    # ==================================================================

    def kpi_summary(self, org_id: str = "default") -> Dict[str, Any]:
        """Return security KPI summary (MTTD, MTTR, scorecard).

        Args:
            org_id: Organisation identifier.

        Returns:
            Dict with current KPI values and trend direction.

        Example::

            kpis = client.kpi_summary(org_id="acme")
        """
        return self._get("/api/v1/kpi/scorecard", params={"org_id": org_id})

    # ==================================================================
    # Connectors
    # ==================================================================

    def connectors_health(self) -> Dict[str, Any]:
        """Return connector framework health status.

        Returns:
            Dict with per-connector status entries.

        Example::

            client.connectors_health()
        """
        return self._get("/api/v1/connectors/health")

    def list_connectors(self, org_id: str = "default") -> List[Dict[str, Any]]:
        """List registered connectors.

        Args:
            org_id: Organisation identifier.

        Returns:
            List of connector dicts with name, type, and status.

        Example::

            connectors = client.list_connectors(org_id="acme")
        """
        return self._get("/api/v1/connectors", params={"org_id": org_id})
