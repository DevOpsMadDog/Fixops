# Community 4 — Enum Registry & Domain Models

**Graphify community:** 4 | **Nodes:** 830 | **Status:** Eighth-largest community

## Role in ALDECI

Community 4 is the shared type-system layer. The `Enum` god-node (degree 840) anchors every security-domain enumeration — finding severity, risk level, connector type, integration status, network zone, supply-chain tier, and more. `SoftDeleteMixin` and `AuditMixin` are the two ORM mixins attached to every persistent model, enforcing soft-delete semantics and automatic audit timestamps. The file cluster (`integration_hub.py`, `vendor_risk.py`, `network_security.py`, `data_security.py`, `supply_chain_security.py`, `pentest_manager.py`, `threat_hunter.py`) each contribute their domain-specific enum sets. `SecurityManager` (degree 19) is the unified RBAC policy enforcer that references these enums.

ALDECI feature powered: type-safe domain model for all 30 personas, RBAC enforcement, integration hub type registry, soft-delete audit trail on all models.

## Architecture Diagram

```mermaid
graph TD
    subgraph C4["Community 4 — Enum Registry & Domain Models (830 nodes)"]
        EN["Enum — type root\ndegree 840"]
        BM["BaseModel — Pydantic\ndegree 56"]
        SD["SoftDeleteMixin\ndegree 54"]
        AM["AuditMixin\ndegree 52"]
        IH["integration_hub.py\ndegree 47"]
        VR["vendor_risk.py\ndegree 35"]
        NS["network_security.py\ndegree 23"]
        DS["data_security.py\ndegree 23"]
        SC["supply_chain_security.py\ndegree 23"]
        PM["pentest_manager.py\ndegree 23"]
        GC["._get_conn()\ndegree 22"]
        CN["._conn()\ndegree 20"]
        SM["SecurityManager\ndegree 19"]
        TH["threat_hunter.py\ndegree 19"]
    end

    EN --> IH
    EN --> VR
    EN --> NS
    EN --> DS
    EN --> SC
    EN --> PM
    EN --> TH
    BM --> SD
    BM --> AM
    SM --> EN
    GC --> CN
    IH --> SM
```

## Cross-Community Edges

| Neighbour Community | Edge Count | Nature of coupling |
|---------------------|------------|--------------------|
| Community 0 (Infrastructure) | 379 | Enum types resolved against DB schema; SoftDeleteMixin writes via _EngineDB |
| Community 2 (Scanner/Parser) | 311 | Finding types, severity enums consumed by scanner normaliser |
| Community 3 (Playbook/Policy) | 223 | PlaybookStatus / StepType inherit from Enum base here |
| Community 1 (API Routing) | 188 | Request/response schemas reference these enums |
| Community 7 (Brain Pipeline) | 62 | Entity/edge taxonomy enums (EntityType, EdgeType) sourced here |
| Community 8 (Cache/Feeds) | 96 | Feed category and severity enums |
