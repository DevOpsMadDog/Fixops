# Community 1 — API Routing & Schema Layer

**Graphify community:** 1 | **Nodes:** 1585 | **Status:** Third-largest community

## Role in ALDECI

Community 1 is the FastAPI surface layer. The dominant hub is `BaseModel` (Pydantic v2), which anchors every request/response schema in the system. Around it cluster the 590+ `*_router.py` files that mount to FastAPI's `create_app()`. Key routers include `copilot_router.py`, `connector_routes.py`, `trustgraph_routes.py`, `llm_router.py`, and `insider_threat_router.py`. This community represents the API contract — the set of endpoints 30 personas interact with.

ALDECI feature powered: 6300+ mounted API routes, RBAC enforcement, connector management, TrustGraph API, copilot AI assistant surface.

## Architecture Diagram

```mermaid
graph TD
    subgraph C1["Community 1 — API Routing & Schema Layer (1585 nodes)"]
        BM["BaseModel — Pydantic v2 root\ndegree 3149"]
        CP["copilot_router.py\ndegree 53"]
        CR["connector_routes.py\ndegree 24"]
        TR["trustgraph_routes.py\ndegree 22"]
        K8R["k8s_security.py\ndegree 21"]
        VS["vendor_scorecard_router.py\ndegree 18"]
        FR["findings_routes.py\ndegree 18"]
        TM["trustgraph_migrator_router.py\ndegree 17"]
        IT["insider_threat_router.py\ndegree 12"]
        TM2["trustgraph_maintenance_router.py\ndegree 11"]
        ASQ["ask_security_question()\ndegree 8"]
        EAS["_execute_action_sync()\ndegree 8"]
        LR["llm_router.py\ndegree 8"]
        CT["call_tool()\ndegree 8"]
    end

    BM --> CP
    BM --> CR
    BM --> TR
    BM --> VS
    BM --> FR
    BM --> IT
    BM --> LR
    CP --> ASQ
    CP --> CT
    CR --> EAS
    TR --> TM
    TR --> TM2
    LR --> ASQ
    K8R --> FR
```

## Cross-Community Edges

| Neighbour Community | Edge Count | Nature of coupling |
|---------------------|------------|--------------------|
| Community 3 (Playbook/Policy) | 959 | Policy/playbook schemas are Pydantic BaseModels routed via C1 |
| Community 6 (Router Utilities) | 217 | Shared helper functions (.to_dict, _generate_id, _now) |
| Community 4 (Enum/Models) | 188 | Enum types referenced in request/response schemas |
| Community 9 | 71 | Supplementary schema definitions |
| Community 20 | 69 | Extended router mounts |
| Community 17 | 61 | Additional API surface modules |
| Community 0 (Infrastructure) | 87 | Auth DB queries for API key validation |
