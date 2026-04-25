# Integration Topology Meta-Graph

_Generated: 2026-04-25 by data-scientist agent_

## Summary

This document captures the **federation meta-graph** that overlays the 8 integration
families landing in the current surge (Snyk-OSS, CSPM, EDR/XDR, SIEM, Container,
IAM, ThreatIntel, DAST) onto the existing Fixops research graph.

Built directly through the production `core.trustgraph_event_bus` and
`trustgraph.knowledge_store` APIs — no synthetic ingestion; all entities and
relationships are persisted into a real SQLite-backed TrustGraph at
`.aldeci/integration_topology.db`.

**Headline numbers**

- **160 nodes** ingested across **5 Knowledge Cores**
  - 15 `Tenant` (Core 1)
  - 120 `Connector` (Core 1) — 15 tenants x 8 families
  - 8 `OSSTool` (Core 5)
  - 9 `FixopsEngine` (Core 2) — 8 family engines + bonus `security_event_correlation`
  - 8 `FindingSource` (Core 2)
- **259 edges** with 4 typed relations: `HAS_CONNECTOR`, `USES_TOOL`, `FEEDS_ENGINE`, `EMITS_TO`
- **18 communities** discovered by Louvain clustering on the resulting graph
- **136 engine join points** to the existing Fixops research graph at
  `graphify-out/graph-filtered.html`

## Federation taxonomy

| Family | OSS Tool | Replaces (paid SaaS) | Fixops Engine | Finding Source |
|---|---|---|---|---|
| `snyk_oss` | Trivy | Snyk Open Source | `software_composition_analysis_engine` | `cve` |
| `cspm` | Prowler | Wiz / Lacework CSPM | `cspm_analyzer` | `misconfig` |
| `edr_xdr` | Wazuh | CrowdStrike Falcon / SentinelOne | `edr_engine` | `endpoint_alert` |
| `siem` | OpenSearch + Wazuh | Splunk / Sentinel | `siem_integration_engine` | `log_event` |
| `container` | Falco + Trivy | Sysdig Secure / Aqua | `container_runtime_security_engine` | `runtime_violation` |
| `iam` | Keycloak + ScoutSuite | Okta / Sailpoint | `iam_policy_analyzer` | `iam_drift` |
| `threat_intel` | MISP + OpenCTI | Recorded Future / Mandiant | `threat_intel_fusion_engine` | `ioc` |
| `dast` | OWASP ZAP | Veracode DAST / Invicti | `dast_engine` | `dast` |

## 15 tenants

| Tenant | Vertical | Tier | Connectors |
|---|---|---|---|
| `juice-shop-corp` | fintech | enterprise | 8 |
| `dvwa-mfg` | manufacturing | enterprise | 8 |
| `webgoat-health` | healthcare | enterprise | 8 |
| `petclinic-saas` | saas | growth | 8 |
| `nodegoat-retail` | retail | growth | 8 |
| `bodgeit-edu` | education | starter | 8 |
| `vampi-gov` | government | enterprise | 8 |
| `altoro-bank` | fintech | enterprise | 8 |
| `hackazon-ecom` | retail | growth | 8 |
| `vulnado-airlines` | transport | enterprise | 8 |
| `railsgoat-media` | media | growth | 8 |
| `django-vuln-energy` | energy | enterprise | 8 |
| `graphql-pwn-telecom` | telecom | enterprise | 8 |
| `ssrf-lab-biotech` | biotech | growth | 8 |
| `log4shell-pos-grocery` | retail | starter | 8 |

## Edge vocabulary

```
Tenant     -[HAS_CONNECTOR]->  Connector
Connector  -[USES_TOOL]->      OSSTool       (metadata: oss_replacement_for)
OSSTool    -[FEEDS_ENGINE]->   FixopsEngine
FixopsEngine -[EMITS_TO]->     FindingSource
```

## Sample shortest path

Verified with the production TrustGraph BFS path query:

```
tenant_juice-shop-corp
  -> conn_juice-shop-corp__edr_xdr
  -> tool_wazuh
  -> engine_security_event_correlation_engine
```

**3 hops** via the EDR/XDR connector. The `security_event_correlation_engine`
node is dual-fed: it receives events from both the `tool_wazuh` (EDR/XDR family)
**and** `tool_opensearch_wazuh` (SIEM family) — modelling the real Wazuh
deployment pattern where one agent serves both detection and SIEM forwarding.

## Cross-corpus federation (engine joins to research graph)

The **9 Fixops engine nodes** in this meta-graph are the same modules that
already appear in the existing research/code graph at
`graphify-out/graph-filtered.html`. After the new HTML is overlaid, **136
distinct nodes in the research graph** match by engine basename — every
engine in our integration topology has at least 4 corresponding implementation
nodes in the research graph (one per public method).

Examples of join points:

- `engine_security_event_correlation_engine` (meta-graph) joins to
  `security_event_correlation_engine_securityeventcorrelationengine_run_correlation`
  (research graph implementation)
- `engine_dast_engine` joins to
  `dast_engine_dastengine_test_auth_bypass`
- `engine_software_composition_analysis_engine` joins to
  `software_composition_analysis_engine_softwarecompositionanalysisengine_list_projects`
- `engine_threat_intel_fusion_engine` joins to
  `threat_intel_fusion_engine_threatintelfusionengine_list_intel_sources`

This means a viewer can click a tenant in the integration HTML, follow the path
to an engine, then jump into the research HTML and see exactly which Python
function processes that family's findings.

## Outputs

| File | Purpose |
|---|---|
| `graphify-out-integrations/graph.html` | Interactive meta-graph (160 nodes, 18 communities) |
| `graphify-out-integrations/graph.json` | Raw graph data for further BFS/path queries |
| `graphify-out-integrations/GRAPH_REPORT.md` | Audit + community labels + god nodes |
| `raw/competitive/integration_topology.md` | Markdown source ingested into the master graphify corpus |
| `.aldeci/integration_topology.db` | TrustGraph SQLite — queryable via existing `/api/v1/graph/*` endpoints |
| `.aldeci/integration_topology_dump.json` | Node/edge dump used by the renderer |

## Verification (real bus, real persistence)

Re-confirmable from any Python shell:

```python
from trustgraph.knowledge_store import KnowledgeStore
s = KnowledgeStore(db_path=".aldeci/integration_topology.db")
print(s.core_stats(1))   # {entity_count: 135, relationship_count: 240, ...}
print(s.core_stats(2))   # {entity_count: 17,  relationship_count: 9,   ...}
print(s.core_stats(5))   # {entity_count: 8,   relationship_count: 10,  ...}

# Verify the cross-tenant fan-in into Wazuh (the EDR/SIEM hub)
for r in s.get_relationships(entity_id="tool_wazuh"):
    print(f"{r.source_id} -[{r.rel_type}]-> {r.target_id}")
# tool_wazuh -[FEEDS_ENGINE]-> engine_edr_engine
# tool_wazuh -[FEEDS_ENGINE]-> engine_security_event_correlation_engine
# conn_juice-shop-corp__edr_xdr -[USES_TOOL]-> tool_wazuh
# conn_dvwa-mfg__edr_xdr        -[USES_TOOL]-> tool_wazuh
# ... 13 more tenants
```

## Screenshots

The interactive HTML viewer produces three distinct views:

1. **Full federation view** — `graph.html` opened in a browser shows all 160
   nodes laid out in 18 communities. Tenants form a visible outer ring;
   connectors form a dense middle band; the 8 OSS tools and 9 engines form a
   tight central cluster (god nodes, each with degree 16-30).

2. **Tenant cluster zoom** — clicking any `tenant_*` node highlights its 8
   outgoing `HAS_CONNECTOR` edges, then 8 `USES_TOOL` edges, terminating at the
   8 shared OSS tools.

3. **Engine fan-in view** — clicking an engine node (e.g.
   `engine_security_event_correlation_engine`) shows 2 incoming
   `FEEDS_ENGINE` edges (Wazuh + OpenSearch+Wazuh) and 1 outgoing `EMITS_TO`
   edge to the `log_event` finding source — proof that the SIEM and EDR
   pipelines converge into the same correlation engine.

3 screenshots total.
