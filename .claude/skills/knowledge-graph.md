# Skill: Knowledge Graph — Security Graph Extension & Attack Path Analysis

> How to build, query, and extend ALdeci's security knowledge graph for decision intelligence.

## Architecture

ALdeci's knowledge graph is the foundation of V3 (Decision Intelligence):

```
Findings → Brain Pipeline Step 5 (BUILD GRAPH) → Knowledge Graph → Attack Paths → Risk Score
```

Key files:
- `suite-core/core/brain_pipeline.py` — Step 5: graph construction
- `suite-core/core/knowledge_brain.py` — Graph storage and query (858 LOC)
- `suite-core/core/attack_graph_gnn.py` — GNN-based attack path analysis (744 LOC)
- `suite-core/api/knowledge_graph_router.py` — API endpoints

## Graph Data Model

### Nodes (Entity Types)
```
APPLICATION      — top-level: {app_id, name, owner, criticality}
COMPONENT        — part of an app: {component_id, app_id, type, language}
FINDING          — vulnerability: {finding_id, cve, severity, cvss, scanner}
ASSET            — infrastructure: {asset_id, type, ip, cloud_provider}
IDENTITY         — user/service: {identity_id, type, privileges}
DEPENDENCY       — library: {name, version, ecosystem}
ATTACK_TECHNIQUE — MITRE ATT&CK: {technique_id, tactic, name}
COMPLIANCE_CTRL  — framework control: {framework, control_id, status}
```

### Edges (Relationship Types)
```
HAS_COMPONENT       — APPLICATION → COMPONENT
HAS_FINDING         — COMPONENT → FINDING
AFFECTS             — FINDING → ASSET
EXPLOITS            — FINDING → ATTACK_TECHNIQUE
DEPENDS_ON          — COMPONENT → DEPENDENCY
HAS_VULNERABILITY   — DEPENDENCY → FINDING
ACCESSED_BY         — ASSET → IDENTITY
MAPS_TO             — FINDING → COMPLIANCE_CTRL
ATTACK_PATH         — FINDING → FINDING (chained exploitability)
DUPLICATE_OF        — FINDING → FINDING (deduplication link)
```

## Adding New Node Types

```python
# In knowledge_brain.py:

class NodeType(str, Enum):
    APPLICATION = "application"
    COMPONENT = "component"
    FINDING = "finding"
    ASSET = "asset"
    # Add new type:
    CLOUD_RESOURCE = "cloud_resource"


def add_cloud_resource(self, resource: dict) -> str:
    """Add a cloud resource node to the graph.
    
    Args:
        resource: Dict with keys: resource_id, provider, service, region, arn
    Returns:
        node_id for the created node
    """
    node_id = f"cloud:{resource['provider']}:{resource['resource_id']}"
    self.graph.add_node(
        node_id,
        node_type=NodeType.CLOUD_RESOURCE,
        provider=resource["provider"],
        service=resource["service"],
        region=resource.get("region", "unknown"),
        arn=resource.get("arn", ""),
        metadata=resource,
    )
    return node_id
```

## Adding New Edge Types

```python
def link_finding_to_cloud_resource(self, finding_id: str, resource_id: str, access_type: str = "direct"):
    """Link a finding to the cloud resource it affects.
    
    Args:
        finding_id: The finding node ID
        resource_id: The cloud resource node ID
        access_type: How the finding affects the resource (direct, transitive, lateral)
    """
    self.graph.add_edge(
        finding_id,
        resource_id,
        edge_type="AFFECTS_CLOUD",
        access_type=access_type,
        discovered_at=datetime.utcnow().isoformat(),
    )
```

## Attack Path Analysis

The GNN (Graph Neural Network) in `attack_graph_gnn.py` finds multi-step attack chains:

```
Internet → Public API (CVE-2024-1234, CVSS 7.5)
         → Service Account (over-privileged)
         → Database (CVE-2024-5678, CVSS 9.8)
         → PII Data (10M records)
```

### Querying Attack Paths

```python
from core.attack_graph_gnn import AttackGraphAnalyzer

analyzer = AttackGraphAnalyzer(knowledge_graph)

# Find all paths from external to critical assets:
paths = analyzer.find_attack_paths(
    source_type=NodeType.FINDING,
    target_type=NodeType.ASSET,
    max_depth=5,
    min_severity="high",
)

# Each path has:
# - nodes: list of node IDs in the path
# - total_risk: cumulative risk score
# - exploitability: probability of successful traversal
# - mitigations: recommended fixes at each hop
```

### Extending Attack Path Logic

```python
# Add a new traversal rule:
class AttackGraphAnalyzer:
    def _can_traverse(self, source_node, target_node, edge) -> bool:
        """Determine if an attacker can traverse this edge."""
        edge_type = edge.get("edge_type")
        
        # Existing rules:
        if edge_type == "ATTACK_PATH":
            return edge.get("verified", False)  # Only verified exploits
        
        # NEW RULE: Lateral movement via shared credentials
        if edge_type == "SHARES_CREDENTIAL":
            return source_node.get("compromised", False)
        
        return False
```

## Enrichment Sources

The graph is enriched from multiple sources during Brain Pipeline Step 6 (ENRICH):

| Source | File | Data Added |
|--------|------|------------|
| NVD | `suite-feeds/feeds/nvd_feed.py` | CVE details, CVSS vectors |
| KEV | `suite-feeds/feeds/kev_feed.py` | Known exploited status |
| EPSS | `suite-feeds/feeds/epss_feed.py` | Exploitation probability |
| OSV | `suite-feeds/feeds/osv_feed.py` | Open-source vuln details |
| ExploitDB | `suite-feeds/feeds/exploitdb_feed.py` | Exploit availability |
| MITRE ATT&CK | (via enrichment) | Tactic/technique mapping |

### Adding a New Enrichment Source

```python
# In brain_pipeline.py, Step 6:
async def _enrich(self, findings: list) -> list:
    """Enrich findings with external data."""
    for finding in findings:
        # Existing enrichments:
        finding = await self._enrich_nvd(finding)
        finding = await self._enrich_epss(finding)
        
        # NEW enrichment:
        finding = await self._enrich_custom_source(finding)
    
    return findings

async def _enrich_custom_source(self, finding: dict) -> dict:
    """Enrich from custom threat intel source."""
    cve = finding.get("cve")
    if not cve:
        return finding
    
    intel = await custom_feed.lookup(cve)
    if intel:
        finding["custom_intel"] = intel
        # Update graph node with new data:
        self.knowledge_graph.update_node(
            finding["node_id"],
            custom_threat_level=intel.get("threat_level"),
            custom_last_seen=intel.get("last_seen"),
        )
    return finding
```

## API Endpoints

Key endpoints in `knowledge_graph_router.py`:

```
GET  /api/v1/knowledge-graph/stats          — Graph statistics
GET  /api/v1/knowledge-graph/nodes          — List/search nodes
GET  /api/v1/knowledge-graph/node/{id}      — Get single node
GET  /api/v1/knowledge-graph/edges          — List/search edges
GET  /api/v1/knowledge-graph/attack-paths   — Find attack paths
POST /api/v1/knowledge-graph/query          — Custom graph query
GET  /api/v1/knowledge-graph/subgraph/{id}  — Get subgraph around a node
```

## Wiring Graph to UI

The knowledge graph data feeds into:
- **Mission Control** → Risk heatmap, top attack paths
- **Discover** → Knowledge Graph visualization (interactive)
- **Validate** → Attack path explorer for MPTE targeting
- **Remediate** → Fix prioritization based on graph centrality

Frontend component: `suite-ui/aldeci/src/pages/discover/KnowledgeGraph.tsx`

## Testing the Graph

```python
"""Tests for knowledge graph operations."""
import pytest
from core.knowledge_brain import KnowledgeBrain

class TestKnowledgeGraph:
    def setup_method(self):
        self.kg = KnowledgeBrain()
    
    def test_add_finding_creates_node(self):
        node_id = self.kg.add_finding({"finding_id": "f1", "cve": "CVE-2024-1234", "severity": "critical"})
        assert node_id is not None
        node = self.kg.get_node(node_id)
        assert node["severity"] == "critical"
    
    def test_attack_path_finds_chain(self):
        # Build a simple chain: finding1 → asset1 → finding2 → critical_asset
        self.kg.add_finding({"finding_id": "f1", "severity": "high"})
        self.kg.add_asset({"asset_id": "a1", "type": "server"})
        self.kg.add_finding({"finding_id": "f2", "severity": "critical"})
        self.kg.add_asset({"asset_id": "critical", "type": "database", "criticality": "high"})
        
        self.kg.link("f1", "a1", "AFFECTS")
        self.kg.link("a1", "f2", "EXPOSES")
        self.kg.link("f2", "critical", "AFFECTS")
        
        paths = self.kg.find_paths("f1", "critical", max_depth=4)
        assert len(paths) >= 1
    
    def test_deduplication_links_findings(self):
        id1 = self.kg.add_finding({"finding_id": "f1", "cve": "CVE-2024-1234", "scanner": "snyk"})
        id2 = self.kg.add_finding({"finding_id": "f2", "cve": "CVE-2024-1234", "scanner": "trivy"})
        
        duplicates = self.kg.find_duplicates(id1)
        assert id2 in duplicates
```

## Validation

```bash
# Verify graph module imports:
python -c "from core.knowledge_brain import KnowledgeBrain; print('OK')"

# Verify attack graph imports:
python -c "from core.attack_graph_gnn import AttackGraphAnalyzer; print('OK')"

# Run graph tests:
python -m pytest tests/ -k "knowledge_graph or attack_graph" -v --timeout=10
```
