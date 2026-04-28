"""
ALDECI Universal Connector Framework
=====================================

TrustGraph-native connector framework for the 15-stage CTEM pipeline.

Modules:
    pull_connector      - PullConnector base class, BidirectionalConnector, PullSchedule
    connector_registry  - ConnectorRegistry singleton, ConnectorGateway, IngestPayload
    sdlc_connectors     - 11 concrete SDLC PULL connectors
    connector_bridge    - Adapters wrapping existing sync connectors for async PULL
    normalizer_bridge   - NormalizerRegistry, FormatDetector, DefectDojo fallback
    trustgraph_schemas  - 5 Knowledge Core Pydantic schemas, KnowledgeCoreManager
    trustgraph_mcp_bridge - TrustGraph MCP tool registration + GraphRAG queries
    defectdojo_parser   - DefectDojo API client for 200+ scanner format fallback

Imports are lazy to avoid pulling in the full core dependency chain at module
load time.  Use explicit imports:

    from connectors.pull_connector import PullConnector, SDLCStage
    from connectors.connector_registry import ConnectorRegistry
"""

__all__ = [
    "pull_connector",
    "connector_registry",
    "sdlc_connectors",
    "connector_bridge",
    "normalizer_bridge",
    "trustgraph_schemas",
    "trustgraph_mcp_bridge",
    "defectdojo_parser",
]
