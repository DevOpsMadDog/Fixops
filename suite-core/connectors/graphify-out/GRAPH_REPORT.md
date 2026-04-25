# Graph Report - suite-core/connectors  (2026-04-26)

## Corpus Check
- 21 files · ~57,461 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 1221 nodes · 3054 edges · 50 communities detected
- Extraction: 59% EXTRACTED · 41% INFERRED · 0% AMBIGUOUS · INFERRED: 1239 edges (avg confidence: 0.58)
- Token cost: 0 input · 0 output

## Community Hubs (Navigation)
- [[_COMMUNITY_Community 0|Community 0]]
- [[_COMMUNITY_Community 1|Community 1]]
- [[_COMMUNITY_Community 2|Community 2]]
- [[_COMMUNITY_Community 3|Community 3]]
- [[_COMMUNITY_Community 4|Community 4]]
- [[_COMMUNITY_Community 5|Community 5]]
- [[_COMMUNITY_Community 6|Community 6]]
- [[_COMMUNITY_Community 7|Community 7]]
- [[_COMMUNITY_Community 8|Community 8]]
- [[_COMMUNITY_Community 9|Community 9]]
- [[_COMMUNITY_Community 10|Community 10]]
- [[_COMMUNITY_Community 11|Community 11]]
- [[_COMMUNITY_Community 12|Community 12]]
- [[_COMMUNITY_Community 13|Community 13]]
- [[_COMMUNITY_Community 14|Community 14]]
- [[_COMMUNITY_Community 15|Community 15]]
- [[_COMMUNITY_Community 16|Community 16]]
- [[_COMMUNITY_Community 17|Community 17]]
- [[_COMMUNITY_Community 18|Community 18]]
- [[_COMMUNITY_Community 19|Community 19]]
- [[_COMMUNITY_Community 20|Community 20]]
- [[_COMMUNITY_Community 21|Community 21]]
- [[_COMMUNITY_Community 22|Community 22]]
- [[_COMMUNITY_Community 23|Community 23]]
- [[_COMMUNITY_Community 24|Community 24]]
- [[_COMMUNITY_Community 25|Community 25]]
- [[_COMMUNITY_Community 26|Community 26]]
- [[_COMMUNITY_Community 27|Community 27]]
- [[_COMMUNITY_Community 28|Community 28]]
- [[_COMMUNITY_Community 29|Community 29]]
- [[_COMMUNITY_Community 30|Community 30]]
- [[_COMMUNITY_Community 31|Community 31]]
- [[_COMMUNITY_Community 32|Community 32]]
- [[_COMMUNITY_Community 33|Community 33]]
- [[_COMMUNITY_Community 34|Community 34]]
- [[_COMMUNITY_Community 35|Community 35]]
- [[_COMMUNITY_Community 36|Community 36]]
- [[_COMMUNITY_Community 37|Community 37]]
- [[_COMMUNITY_Community 38|Community 38]]
- [[_COMMUNITY_Community 39|Community 39]]
- [[_COMMUNITY_Community 40|Community 40]]
- [[_COMMUNITY_Community 41|Community 41]]
- [[_COMMUNITY_Community 42|Community 42]]
- [[_COMMUNITY_Community 43|Community 43]]
- [[_COMMUNITY_Community 44|Community 44]]
- [[_COMMUNITY_Community 45|Community 45]]
- [[_COMMUNITY_Community 46|Community 46]]
- [[_COMMUNITY_Community 47|Community 47]]
- [[_COMMUNITY_Community 48|Community 48]]
- [[_COMMUNITY_Community 49|Community 49]]

## God Nodes (most connected - your core abstractions)
1. `ConnectorMetadata` - 194 edges
2. `SDLCStage` - 182 edges
3. `PullConnector` - 152 edges
4. `BidirectionalConnector` - 148 edges
5. `PullSchedule` - 123 edges
6. `ConnectorRegistry` - 71 edges
7. `CoreRouter` - 40 edges
8. `KnowledgeCoreManager` - 38 edges
9. `DefectDojoParserClient` - 37 edges
10. `ConnectorGateway` - 35 edges

## Surprising Connections (you probably didn't know these)
- `JenkinsPipelineConnector` --uses--> `BidirectionalConnector`  [INFERRED]
  suite-core/connectors/sdlc_connectors.py → suite-core/connectors/pull_connector.py
- `JenkinsPipelineConnector` --uses--> `ConnectorMetadata`  [INFERRED]
  suite-core/connectors/sdlc_connectors.py → suite-core/connectors/pull_connector.py
- `JenkinsPipelineConnector` --uses--> `PullConnector`  [INFERRED]
  suite-core/connectors/sdlc_connectors.py → suite-core/connectors/pull_connector.py
- `JenkinsPipelineConnector` --uses--> `PullSchedule`  [INFERRED]
  suite-core/connectors/sdlc_connectors.py → suite-core/connectors/pull_connector.py
- `JenkinsPipelineConnector` --uses--> `SDLCStage`  [INFERRED]
  suite-core/connectors/sdlc_connectors.py → suite-core/connectors/pull_connector.py

## Communities

### Community 0 - "Community 0"
Cohesion: 0.03
Nodes (165): _BaseConnector, BidirectionalConnector, BidirectionalConnectorAdapter, ConnectorScheduler, ALDECI Connector Bridge — adapter layer for existing connectors.  Bridges 13 sec, Background scheduler for executing connector pull cycles.      Features:     - A, Initialize scheduler.          Args:             registry: ConnectorRegistry ins, Start the scheduler background task.          This runs indefinitely, checking d (+157 more)

### Community 1 - "Community 1"
Cohesion: 0.02
Nodes (132): BaseModel, Advisory, APIEndpoint, Artifact, Assessment, ATTACKTactic, ATTACKTechnique, Branch (+124 more)

### Community 2 - "Community 2"
Cohesion: 0.03
Nodes (70): ABC, ConflictResolution, Conflict resolution strategy., register_all_existing_connectors(), Enum, str, Core1RelationshipType, Core2RelationshipType (+62 more)

### Community 3 - "Community 3"
Cohesion: 0.03
Nodes (71): AzureDevOpsSyncStrategy, BaseSyncStrategy, BidirectionalSyncEngine, ConfluenceSyncStrategy, from_dict(), GitHubSyncStrategy, GitLabSyncStrategy, JiraSyncStrategy (+63 more)

### Community 4 - "Community 4"
Cohesion: 0.05
Nodes (48): ConnectorGateway, ConnectorRegistry, _content_hash(), DefectDojoParserClient, DefectDojo Parser Client for ALDECI Connector Framework  Routes unknown scanner, Initialize DefectDojo Parser Client.          Args:             base_url: Defect, Async context manager entry., Async context manager exit. (+40 more)

### Community 5 - "Community 5"
Cohesion: 0.06
Nodes (59): JenkinsPipelineConnector, BaseSIEMAdapter, _build_cef_event(), _build_datadog_event(), _build_elk_event(), _build_k8s_audit(), _build_sentinel_event(), _build_splunk_hec_event() (+51 more)

### Community 6 - "Community 6"
Cohesion: 0.06
Nodes (37): Get pull-specific metrics extending base metrics.          Returns a dict with:, CoreQueue, CoreRoutingResult, CoreRoutingRules, CoreValidator, determine_cores(), extract_keywords(), _infer_entity_type() (+29 more)

### Community 7 - "Community 7"
Cohesion: 0.06
Nodes (35): adapt_auth0_event(), adapt_entra_event(), adapt_okta_event(), _admin_to_finding_payload(), _gen_admin_event(), _gen_login_event(), IAMSSoConfig, IAMSSoConnector (+27 more)

### Community 8 - "Community 8"
Cohesion: 0.06
Nodes (23): N8nAPIClient, N8nConnector, n8n webhook connector — bidirectional bridge for workflow automation., Remove a webhook registration. Returns True if removed, False if not found., List registered webhooks, optionally filtered by event_type., Fire all webhooks registered for event_type with payload.          Returns list, Return list of past webhook trigger events from SQLite., Return {total_webhooks, total_events, success_rate, events_by_type} (+15 more)

### Community 9 - "Community 9"
Cohesion: 0.1
Nodes (33): _cvss_from_severity(), DastPentestConnector, DastPentestRunResult, _docker_pull(), _ensure_image(), _mirror_to_bug_bounty(), _normalize_severity(), _now_iso() (+25 more)

### Community 10 - "Community 10"
Cohesion: 0.1
Nodes (32): ContainerSecurityConnector, _docker_build(), _ensure_dockerfile(), _find_dockerfile(), get_container_security_connector(), _get_findings_engine(), get_scan_history(), _mirror_to_findings() (+24 more)

### Community 11 - "Community 11"
Cohesion: 0.1
Nodes (20): _classify_value(), _misp_type_to_internal(), _now_iso(), _otx_type_to_internal(), Threat Intelligence Connector — ALDECI  Real OSS replacements for commercial Thr, Aggregate result of a sync_all() run., Real OSS Threat Intelligence connector with tenant cross-correlation.      Each, Idempotently register an intel source; return its id. (+12 more)

### Community 12 - "Community 12"
Cohesion: 0.14
Nodes (17): _build_normalizer(), CSPMConnector, CSPMScanResult, _finding_to_dict(), ALDECI CSPM Family Connector — Wiz/Lacework/Orca/Prisma OSS replacement.  Replac, Outcome of a single CSPM tool execution., Replace Wiz/Lacework/Orca/Prisma with Prowler + Checkov + CloudSploit + Agentles, Run every enabled CSPM tool for one tenant; mirror findings.          Returns a (+9 more)

### Community 13 - "Community 13"
Cohesion: 0.11
Nodes (18): EDRConnector, _falco_to_edr_event(), get_edr_connector(), _osquery_to_edr_event(), ALDECI EDR/XDR Connector — replaces CrowdStrike/SentinelOne/Defender XDR with OS, Convert a Falco JSON event into the EDREngine ingest_process_event schema., Convert an osquery snapshot record to EDR ingest format., Convert a Wazuh alert into EDR ingest format. (+10 more)

### Community 14 - "Community 14"
Cohesion: 0.15
Nodes (15): _ensure_tool(), get_default_connector(), _iter_osv_vulns(), _iter_trivy_vulns(), _normalize_severity(), _osv_severity_from_list(), Snyk-family OSS connector — replaces stubbed Snyk with real OSS scanners.  This, Run a subprocess and return (rc, stdout, stderr) — bounded. (+7 more)

### Community 15 - "Community 15"
Cohesion: 0.09
Nodes (12): TrustGraph MCP Bridge for ALDECI Connector Framework  Bridges ALDECI's connector, Ingest normalized findings into a specific Knowledge Core.          Routes entit, Create graph edges (relationships) between entities.          Examples:, Query across Knowledge Cores using GraphRAG.          Executes a natural languag, Invoke a registered connector via MCP.          TrustGraph pulls on-demand execu, Bridges ALDECI connectors to TrustGraph's MCP integration.      Routes connector, List all registered MCP tools.          Returns:             List of tool metada, Register a Knowledge Core client for ingestion and querying.          Args: (+4 more)

### Community 16 - "Community 16"
Cohesion: 0.14
Nodes (6): pull(), push_enrichment(), ALDECI Pull Connector Framework — bidirectional data integration.  Enterprise-gr, Normalize a raw finding to standard ALDECI format.          Default implementati, Execute a complete pull cycle: fetch, normalize, track.          This orchestrat, Batch push enrichments.          Push multiple enrichments in one operation. Eac

### Community 17 - "Community 17"
Cohesion: 0.3
Nodes (1): PullConnectorAdapter

### Community 18 - "Community 18"
Cohesion: 0.5
Nodes (2): Validate metadata consistency.          Returns:             True if valid, Fals, Initialize a PullConnector.          Args:             settings: Configuration m

### Community 19 - "Community 19"
Cohesion: 1.0
Nodes (1): ALDECI Universal Connector Framework =====================================  Trus

### Community 20 - "Community 20"
Cohesion: 1.0
Nodes (1): Get connector metadata.

### Community 21 - "Community 21"
Cohesion: 1.0
Nodes (1): Check if connector is fully configured.          Must be overridden by subclasse

### Community 22 - "Community 22"
Cohesion: 1.0
Nodes (1): Pull data from the source.          This is the main data retrieval method. Subc

### Community 23 - "Community 23"
Cohesion: 1.0
Nodes (1): Push enrichment data back to the source.          Bidirectional feedback: after

### Community 24 - "Community 24"
Cohesion: 1.0
Nodes (1): Sync status of a previously pushed item.          After pushing an enrichment (e

### Community 25 - "Community 25"
Cohesion: 1.0
Nodes (1): Best-effort: forward a critical/high finding into the bug-bounty         simulat

### Community 26 - "Community 26"
Cohesion: 1.0
Nodes (1): Deserialize from dict.

### Community 27 - "Community 27"
Cohesion: 1.0
Nodes (1): Pull new/updated items from external tool.          Args:             since: Opt

### Community 28 - "Community 28"
Cohesion: 1.0
Nodes (1): Push ALDECI findings/updates to external tool.          Args:             items:

### Community 29 - "Community 29"
Cohesion: 1.0
Nodes (1): Fetch a single item by ID from external tool.          Args:             item_id

### Community 30 - "Community 30"
Cohesion: 1.0
Nodes (1): Return the indicator type (ip/domain/hash/url) for a raw string.

### Community 31 - "Community 31"
Cohesion: 1.0
Nodes (1): SSRF guard — reject non-http(s) URLs and obviously private hosts.

### Community 32 - "Community 32"
Cohesion: 1.0
Nodes (1): Map MISP attribute type to our internal indicator_type.

### Community 33 - "Community 33"
Cohesion: 1.0
Nodes (1): Map OTX indicator type names to our internal taxonomy.

### Community 34 - "Community 34"
Cohesion: 1.0
Nodes (1): Get schema for a Knowledge Core.          Args:             core_id: Core ID (1-

### Community 35 - "Community 35"
Cohesion: 1.0
Nodes (1): Validate entity data against core schema.          Args:             core_id: Co

### Community 36 - "Community 36"
Cohesion: 1.0
Nodes (1): Validate that a relationship is allowed between entity types.          Args:

### Community 37 - "Community 37"
Cohesion: 1.0
Nodes (1): Get list of entity types for a core.          Args:             core_id: Core ID

### Community 38 - "Community 38"
Cohesion: 1.0
Nodes (1): Get list of relationship types for a core.          Args:             core_id: C

### Community 39 - "Community 39"
Cohesion: 1.0
Nodes (1): Route a normalized finding to appropriate Knowledge Cores.          A finding ty

### Community 40 - "Community 40"
Cohesion: 1.0
Nodes (1): Get all core schemas.

### Community 41 - "Community 41"
Cohesion: 1.0
Nodes (1): List all cores with metadata.          Returns:             List of dicts with c

### Community 42 - "Community 42"
Cohesion: 1.0
Nodes (1): Return True if this connector has valid credentials.

### Community 43 - "Community 43"
Cohesion: 1.0
Nodes (1): Create a ticket/issue/notification from a security finding.

### Community 44 - "Community 44"
Cohesion: 1.0
Nodes (1): Update an existing ticket.

### Community 45 - "Community 45"
Cohesion: 1.0
Nodes (1): Close/resolve a ticket.

### Community 46 - "Community 46"
Cohesion: 1.0
Nodes (1): Retrieve ticket details.

### Community 47 - "Community 47"
Cohesion: 1.0
Nodes (1): Test connectivity and authentication.

### Community 48 - "Community 48"
Cohesion: 1.0
Nodes (1): Execute create_ticket with error isolation.

### Community 49 - "Community 49"
Cohesion: 1.0
Nodes (1): Execute test_connection with error isolation.

## Knowledge Gaps
- **360 isolated node(s):** `Pull security events from SIEM platforms.      Supports:     - Splunk (REST API)`, `IAM / SSO Real Connector — ALDECI.  Replaces stub IAM/SSO integrations (Okta, Au`, `Result of a single sync invocation.`, `Thin admin REST client. urllib only — zero new deps.      Token cache is in-memo`, `Cheap unauthenticated reachability probe.          Tries (in order): /health ->` (+355 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **Thin community `Community 19`** (2 nodes): `ALDECI Universal Connector Framework =====================================  Trus`, `__init__.py`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 20`** (1 nodes): `Get connector metadata.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 21`** (1 nodes): `Check if connector is fully configured.          Must be overridden by subclasse`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 22`** (1 nodes): `Pull data from the source.          This is the main data retrieval method. Subc`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 23`** (1 nodes): `Push enrichment data back to the source.          Bidirectional feedback: after`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 24`** (1 nodes): `Sync status of a previously pushed item.          After pushing an enrichment (e`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 25`** (1 nodes): `Best-effort: forward a critical/high finding into the bug-bounty         simulat`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 26`** (1 nodes): `Deserialize from dict.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 27`** (1 nodes): `Pull new/updated items from external tool.          Args:             since: Opt`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 28`** (1 nodes): `Push ALDECI findings/updates to external tool.          Args:             items:`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 29`** (1 nodes): `Fetch a single item by ID from external tool.          Args:             item_id`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 30`** (1 nodes): `Return the indicator type (ip/domain/hash/url) for a raw string.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 31`** (1 nodes): `SSRF guard — reject non-http(s) URLs and obviously private hosts.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 32`** (1 nodes): `Map MISP attribute type to our internal indicator_type.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 33`** (1 nodes): `Map OTX indicator type names to our internal taxonomy.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 34`** (1 nodes): `Get schema for a Knowledge Core.          Args:             core_id: Core ID (1-`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 35`** (1 nodes): `Validate entity data against core schema.          Args:             core_id: Co`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 36`** (1 nodes): `Validate that a relationship is allowed between entity types.          Args:`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 37`** (1 nodes): `Get list of entity types for a core.          Args:             core_id: Core ID`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 38`** (1 nodes): `Get list of relationship types for a core.          Args:             core_id: C`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 39`** (1 nodes): `Route a normalized finding to appropriate Knowledge Cores.          A finding ty`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 40`** (1 nodes): `Get all core schemas.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 41`** (1 nodes): `List all cores with metadata.          Returns:             List of dicts with c`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 42`** (1 nodes): `Return True if this connector has valid credentials.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 43`** (1 nodes): `Create a ticket/issue/notification from a security finding.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 44`** (1 nodes): `Update an existing ticket.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 45`** (1 nodes): `Close/resolve a ticket.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 46`** (1 nodes): `Retrieve ticket details.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 47`** (1 nodes): `Test connectivity and authentication.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 48`** (1 nodes): `Execute create_ticket with error isolation.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.
- **Thin community `Community 49`** (1 nodes): `Execute test_connection with error isolation.`
  Too small to be a meaningful cluster - may be noise or needs more connections extracted.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `ConnectorRegistry` connect `Community 4` to `Community 0`, `Community 17`, `Community 5`?**
  _High betweenness centrality (0.079) - this node is a cross-community bridge._
- **Why does `SDLCStage` connect `Community 0` to `Community 2`, `Community 4`, `Community 5`, `Community 6`, `Community 16`, `Community 17`?**
  _High betweenness centrality (0.075) - this node is a cross-community bridge._
- **Why does `ConnectorMetadata` connect `Community 0` to `Community 2`, `Community 4`, `Community 5`, `Community 6`, `Community 16`, `Community 17`, `Community 18`?**
  _High betweenness centrality (0.054) - this node is a cross-community bridge._
- **Are the 191 inferred relationships involving `ConnectorMetadata` (e.g. with `GitHubSCMConnector` and `JiraBidirectionalConnector`) actually correct?**
  _`ConnectorMetadata` has 191 INFERRED edges - model-reasoned connections that need verification._
- **Are the 179 inferred relationships involving `SDLCStage` (e.g. with `GitHubSCMConnector` and `JiraBidirectionalConnector`) actually correct?**
  _`SDLCStage` has 179 INFERRED edges - model-reasoned connections that need verification._
- **Are the 144 inferred relationships involving `PullConnector` (e.g. with `GitHubSCMConnector` and `JiraBidirectionalConnector`) actually correct?**
  _`PullConnector` has 144 INFERRED edges - model-reasoned connections that need verification._
- **Are the 144 inferred relationships involving `BidirectionalConnector` (e.g. with `GitHubSCMConnector` and `JiraBidirectionalConnector`) actually correct?**
  _`BidirectionalConnector` has 144 INFERRED edges - model-reasoned connections that need verification._