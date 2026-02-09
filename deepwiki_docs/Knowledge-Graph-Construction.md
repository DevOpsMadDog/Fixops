# Knowledge Graph Construction

> **Relevant source files**
> * [.github/workflows/ci.yml](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/.github/workflows/ci.yml)
> * [.github/workflows/fixops-ci.yml](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/.github/workflows/fixops-ci.yml)
> * [.github/workflows/qa.yml](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/.github/workflows/qa.yml)
> * [apps/api/bulk_router.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/bulk_router.py)
> * [apps/api/collaboration_router.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/collaboration_router.py)
> * [apps/api/deduplication_router.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/deduplication_router.py)
> * [apps/api/integrations_router.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/integrations_router.py)
> * [apps/api/normalizers.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/normalizers.py)
> * [apps/api/pipeline.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py)
> * [apps/api/remediation_router.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/remediation_router.py)
> * [apps/api/webhooks_router.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/webhooks_router.py)
> * [core/adapters.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/adapters.py)
> * [core/connectors.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/connectors.py)
> * [core/paths.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/paths.py)
> * [core/policy.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/policy.py)
> * [core/processing_layer.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/processing_layer.py)
> * [core/services/collaboration.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/services/collaboration.py)
> * [core/services/deduplication.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/services/deduplication.py)
> * [core/services/identity.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/services/identity.py)
> * [core/services/remediation.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/services/remediation.py)
> * [core/storage.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/storage.py)
> * [fixops-enterprise/src/services/feeds_service.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/fixops-enterprise/src/services/feeds_service.py)
> * [fixops-enterprise/src/services/vex_ingestion.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/fixops-enterprise/src/services/vex_ingestion.py)
> * [tests/test_file_size_limits.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_file_size_limits.py)
> * [tests/test_pipeline_integration.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_pipeline_integration.py)
> * [tests/test_round2_fresh_apps.py](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/tests/test_round2_fresh_apps.py)

The Knowledge Graph Construction system builds a unified graph representation of security findings, software components, vulnerabilities, and infrastructure assets. This graph enables relationship-based analysis, centrality scoring, and connectivity metrics that support risk assessment and decision-making.

For Bayesian and Markov modeling that uses the knowledge graph, see [5.1](/DevOpsMadDog/Fixops/5.1-bayesian-and-markov-models). For the broader processing layer integration, see [5.3](/DevOpsMadDog/Fixops/5.3-processing-layer-internals).

## Purpose and Scope

The knowledge graph system:

* Constructs a directed graph from SBOM components, SARIF findings, CVE records, and CNAPP assets
* Models relationships between components, vulnerabilities, dependencies, and infrastructure
* Computes graph-based metrics (density, centrality, connected components) for risk assessment
* Provides both NetworkX-based rich metrics and simplified fallback analytics
* Integrates with the pipeline orchestrator to enrich security analysis with graph-based insights

## Architecture Overview

```

```

**Sources:** [core/processing_layer.py L75-L105](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/processing_layer.py#L75-L105)

 [core/processing_layer.py L222-L326](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/processing_layer.py#L222-L326)

 [apps/api/pipeline.py L887-L894](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L887-L894)

## Graph Data Model

The knowledge graph uses a directed graph structure with four node types and multiple edge types representing security relationships.

```

```

**Sources:** [core/processing_layer.py L234-L307](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/processing_layer.py#L234-L307)

### Node Attributes

**Component Nodes:**

* `type`: "component"
* `name`: Component name extracted from SBOM
* `version`: Component version if available
* `purl`: Package URL (used as node ID when available)

**Vulnerability Nodes:**

* `type`: "vulnerability"
* `cve_id`: CVE identifier (node ID)
* `severity`: Vulnerability severity level
* `exploited`: Boolean indicating KEV listing

**Finding Nodes:**

* `type`: "finding"
* `rule_id`: SARIF rule identifier
* `level`: Finding severity level
* `file`: File path where finding was detected

**Asset Nodes:**

* `type`: "asset"
* `asset_id`: Unique asset identifier (node ID)
* `traits`: List of exposure characteristics (internet_exposed, partner_connected, etc.)

**Sources:** [core/processing_layer.py L234-L261](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/processing_layer.py#L234-L261)

 [core/processing_layer.py L267-L291](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/processing_layer.py#L267-L291)

## Graph Construction Process

The graph construction follows a sequential process that builds nodes first, then establishes relationships through edges.

```

```

**Sources:** [core/processing_layer.py L222-L326](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/processing_layer.py#L222-L326)

### Component Node Addition

Components are added from the SBOM with their package URL (purl) or name as the node identifier:

```

```

**Sources:** [core/processing_layer.py L234-L242](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/processing_layer.py#L234-L242)

### Vulnerability Node Addition

CVE records are added as vulnerability nodes with severity and exploitation status:

```

```

**Sources:** [core/processing_layer.py L243-L253](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/processing_layer.py#L243-L253)

### Finding Node Addition and Linkage

SARIF findings are added as nodes and linked to components via `has_finding` edges:

```

```

**Sources:** [core/processing_layer.py L254-L266](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/processing_layer.py#L254-L266)

### CNAPP Asset Integration

Assets from CNAPP findings are added with exposure traits and linked to components they host:

```

```

**Sources:** [core/processing_layer.py L267-L291](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/processing_layer.py#L267-L291)

## Graph Metrics Computation

When NetworkX is available, the system computes rich graph metrics for risk assessment. These metrics quantify the structure and connectivity of the security graph.

### Core Metrics

| Metric | Computation | Purpose |
| --- | --- | --- |
| **Density** | `nx.density(graph)` | Measures interconnectedness of vulnerabilities and components |
| **Node Count** | `graph.number_of_nodes()` | Total entities in the security graph |
| **Edge Count** | `graph.number_of_edges()` | Total relationships between entities |
| **Average Degree** | Mean of all node degrees | Average connectivity per entity |
| **Max Degree** | Maximum node degree | Identifies highly connected components |
| **Connected Components** | `nx.number_weakly_connected_components()` | Counts isolated security clusters |

**Sources:** [core/processing_layer.py L292-L307](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/processing_layer.py#L292-L307)

### Centrality Measures

Centrality metrics identify critical components in the security graph:

```

```

**Degree Centrality** identifies components with the most direct relationships (vulnerabilities, findings, or dependencies). High-centrality components represent critical attack surfaces or widely-used dependencies.

**Sources:** [core/processing_layer.py L298-L301](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/processing_layer.py#L298-L301)

### Degree Distribution

The degree distribution histogram provides insight into the graph topology:

```

```

**Sources:** [core/processing_layer.py L303-L307](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/processing_layer.py#L303-L307)

## NetworkX Integration

The system uses NetworkX as the primary graph analytics library when available, with graceful fallback to simplified metrics.

```

```

**Sources:** [core/processing_layer.py L57-L71](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/processing_layer.py#L57-L71)

 [core/processing_layer.py L222-L326](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/processing_layer.py#L222-L326)

### NetworkX Availability Check

The `ProcessingLayer` checks for NetworkX availability during initialization:

```

```

**Sources:** [core/processing_layer.py L60-L70](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/processing_layer.py#L60-L70)

### Fallback Behavior

When NetworkX is unavailable, the system provides simplified metrics based on node counts:

```

```

**Sources:** [core/processing_layer.py L308-L326](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/processing_layer.py#L308-L326)

## Pipeline Integration

The knowledge graph integrates with the pipeline orchestrator to enrich security analysis with graph-based risk metrics.

```

```

**Sources:** [apps/api/pipeline.py L887-L894](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L887-L894)

 [core/processing_layer.py L75-L105](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/processing_layer.py#L75-L105)

### Invocation from Pipeline

The `PipelineOrchestrator` invokes the processing layer to construct the knowledge graph:

```

```

**Sources:** [apps/api/pipeline.py L887-L894](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L887-L894)

### Graph Snapshot Structure

The knowledge graph snapshot returned in `ProcessingLayerResult` contains:

```

```

**Sources:** [core/processing_layer.py L292-L307](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/processing_layer.py#L292-L307)

 [core/processing_layer.py L38-L54](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/processing_layer.py#L38-L54)

## Graph-Based Risk Enhancement

The knowledge graph metrics feed into risk calculation to provide connectivity-aware risk scoring:

```

```

High-density graphs with central vulnerable components receive risk amplification, as vulnerabilities in highly connected components pose greater systemic risk through cascading dependencies.

**Sources:** [apps/api/pipeline.py L288-L449](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L288-L449)

 [core/processing_layer.py L292-L307](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/processing_layer.py#L292-L307)

## Library Dependencies

The knowledge graph system has the following dependency chain:

| Library | Purpose | Required | Fallback Behavior |
| --- | --- | --- | --- |
| `networkx` | Graph construction and analytics | Optional | Use simplified node counting |
| `uuid` | Generate unique finding node IDs | Required | N/A |
| Python `typing` | Type hints | Required | N/A |

**Sources:** [core/processing_layer.py L10-L14](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/processing_layer.py#L10-L14)

 [core/processing_layer.py L60-L70](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/processing_layer.py#L60-L70)

## Usage Example

The knowledge graph is automatically constructed during pipeline execution:

```

```

The graph metrics are included in the pipeline output under the `processing` section, providing visibility into the security graph structure for further analysis or reporting.

**Sources:** [apps/api/pipeline.py L887-L894](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/apps/api/pipeline.py#L887-L894)

 [core/processing_layer.py L75-L105](https://github.com/DevOpsMadDog/Fixops/blob/ce6eb1e9/core/processing_layer.py#L75-L105)