# Community 8 — Cache, Feeds & Auth Layer

**Graphify community:** 8 | **Nodes:** 1000 | **Status:** Seventh-largest community

## Role in ALDECI

Community 8 is the operational support layer: caching, threat intelligence ingestion, authentication persistence, and observability. `CacheService` (degree 168) provides the Redis-backed response cache shared by all API routers. `FeedsService` (degree 149) manages the 28+ threat intelligence feed subscriptions (NVD, EPSS, OSV, Shodan, VirusTotal, etc.). `DatabaseManager` (degree 137) is the top-level connection-pool manager referenced by higher-level engines. `ChatGPTClient` (degree 129) bridges to OpenAI-compatible endpoints. `AuthDB` (degree 75) persists API keys, tokens, and RBAC assignments. `FixOpsMetrics` (degree 99) and `ProcessingLayer` (degree 97) instrument the processing pipeline for Prometheus scraping. `EvidenceLake` (degree 62) and `GoldenRegressionStore` (degree 53) support the evidence chain and regression testing framework.

ALDECI feature powered: 28+ threat intel feeds, Redis caching, Prometheus metrics, authentication database, evidence lake, ChatGPT/OpenAI bridge.

## Architecture Diagram

```mermaid
graph TD
    subgraph C8["Community 8 — Cache, Feeds & Auth Layer (1000 nodes)"]
        ER["error() — structured log\ndegree 295"]
        SET[".set() — cache write\ndegree 295"]
        CS["CacheService\ndegree 168"]
        FS["FeedsService\ndegree 149"]
        DM["DatabaseManager\ndegree 137"]
        CC["ChatGPTClient\ndegree 129"]
        FM["FixOpsMetrics\ndegree 99"]
        PL["ProcessingLayer\ndegree 97"]
        AU["AuthDB\ndegree 75"]
        BM["BaseModel\ndegree 66"]
        SD["SoftDeleteMixin\ndegree 64"]
        EL["EvidenceLake\ndegree 62"]
        AM["AuditMixin\ndegree 62"]
        EXR["ExplanationRequest\ndegree 55"]
        GR["GoldenRegressionStore\ndegree 53"]
    end

    CS --> SET
    CS --> ER
    FS --> DM
    DM --> ER
    PL --> FM
    PL --> CS
    PL --> FS
    AU --> DM
    EL --> DM
    CC --> EXR
    GR --> EL
    SD --> BM
    AM --> BM
    AM --> ER
```

## Cross-Community Edges

| Neighbour Community | Edge Count | Nature of coupling |
|---------------------|------------|--------------------|
| Community 2 (Scanner/Parser) | 476 | Feed data enriches scanner context; cache accelerates repeat scans |
| Community 0 (Infrastructure) | 292 | Cache invalidation hooks into _EngineDB; AuthDB shares AuditLogger |
| Community 7 (Brain Pipeline) | 125 | Feed signals injected at pipeline ingestion step |
| Community 5 (LLM/PenTest) | 125 | Threat intel context enriches LLM prompts |
| Community 3 (Playbook/Policy) | 145 | Feed severity triggers playbook escalation |
| Community 4 (Enum/Models) | 96 | Feed category enums sourced from C4 |
| Community 19 | 88 | Extended analytics pipeline integrations |
