"""
Knowledge Graph Construction
Purpose: Link components, vulnerabilities, and context
Uses CTINexus for entity extraction and graph visualization
"""

from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Set

import structlog
from core.services.enterprise.chatgpt_client import (
    ChatGPTClient,
    get_primary_llm_api_key,
)

try:  # pragma: no cover - optional dependency
    import networkx as nx

    NETWORKX_AVAILABLE = True
except ImportError:  # pragma: no cover - executed in minimal envs
    nx = None  # type: ignore
    NETWORKX_AVAILABLE = False

logger = structlog.get_logger()


class NoPathError(Exception):
    """Fallback exception mirroring networkx.NetworkXNoPath."""


if NETWORKX_AVAILABLE:  # pragma: no cover - simple aliasing
    NoPathError = nx.NetworkXNoPath  # type: ignore  # noqa: F811


@dataclass
class SecurityEntity:
    """Security entity for knowledge graph"""

    entity_id: str
    entity_type: str  # "vulnerability", "component", "service", "threat_actor", "technique"
    name: str
    properties: Dict[str, Any]
    confidence: float


@dataclass
class SecurityRelation:
    """Relationship between security entities"""

    source_id: str
    target_id: str
    relation_type: str  # "exploits", "depends_on", "mitigates", "uses", "affects"
    properties: Dict[str, Any]
    confidence: float


class CTINexusEntityExtractor:
    """
    REAL CTINexus-inspired entity extraction using LLM-based in-context learning
    Based on CTINexus framework for automatic cybersecurity entity and relation extraction
    Uses optimized prompt-based LLM inference with demonstration selection
    """

    def __init__(self):
        self.llm_client: Optional[ChatGPTClient] = None
        self._initialize_llm_client()
        self.cybersecurity_ontology = self._load_cybersecurity_ontology()
        self.demonstration_examples = self._load_demonstration_examples()

    def _initialize_llm_client(self):
        """Initialize LLM client for CTINexus-style entity extraction"""
        api_key = get_primary_llm_api_key()
        if not api_key:
            logger.warning(
                "ChatGPT API key not configured – CTINexus will use heuristic fallback"
            )
            return

        try:
            self.llm_client = ChatGPTClient(
                api_key=api_key,
                model="gpt-4o-mini",
                temperature=0.1,
                max_tokens=1500,
            )
            logger.info("✅ CTINexus LLM client initialized with ChatGPT")
        except Exception as e:
            logger.error(f"CTINexus ChatGPT initialization failed: {e}")
            self.llm_client = None

    def _load_cybersecurity_ontology(self) -> Dict[str, List[str]]:
        """Load cybersecurity ontology for CTINexus entity extraction"""
        return {
            "vulnerability": ["CVE", "CWE", "vulnerability", "exploit", "bug", "flaw"],
            "threat_actor": ["APT", "threat actor", "attacker", "hacker", "group"],
            "malware": [
                "malware",
                "trojan",
                "ransomware",
                "virus",
                "backdoor",
                "rootkit",
            ],
            "technique": ["MITRE", "technique", "tactic", "procedure", "TTP"],
            "indicator": ["IOC", "hash", "IP address", "domain", "URL", "file path"],
            "asset": [
                "system",
                "server",
                "application",
                "database",
                "network",
                "endpoint",
            ],
            "control": ["patch", "update", "fix", "mitigation", "control", "defense"],
        }

    def _load_demonstration_examples(self) -> List[Dict[str, str]]:
        """Load demonstration examples for in-context learning as per CTINexus"""
        return [
            {
                "input": "CVE-2024-1234 affects Apache Struts allowing remote code execution on web servers.",
                "output": "Entities: [CVE-2024-1234|vulnerability], [Apache Struts|asset], [remote code execution|technique], [web servers|asset]. Relations: [CVE-2024-1234|affects|Apache Struts], [CVE-2024-1234|enables|remote code execution], [remote code execution|targets|web servers]",
            },
            {
                "input": "Threat actor APT29 uses PowerShell to deploy Cobalt Strike beacon for persistence.",
                "output": "Entities: [APT29|threat_actor], [PowerShell|technique], [Cobalt Strike|malware], [persistence|technique]. Relations: [APT29|uses|PowerShell], [PowerShell|deploys|Cobalt Strike], [Cobalt Strike|achieves|persistence]",
            },
            {
                "input": "SQL injection vulnerability in login form allows data exfiltration from customer database.",
                "output": "Entities: [SQL injection|vulnerability], [login form|asset], [data exfiltration|technique], [customer database|asset]. Relations: [SQL injection|located_in|login form], [SQL injection|enables|data exfiltration], [data exfiltration|targets|customer database]",
            },
        ]

    async def extract_entities(self, scan_data: Dict[str, Any]) -> List[SecurityEntity]:
        """Extract security entities using REAL CTINexus LLM-based approach"""
        entities = []

        try:
            if self.llm_client:
                # Use real CTINexus-style LLM extraction
                entities = await self._ctinexus_llm_extraction(scan_data)
            else:
                # Fallback to pattern-based extraction
                entities = await self._fallback_pattern_extraction(scan_data)

            logger.info(f"CTINexus extracted {len(entities)} entities from scan data")
            return entities

        except Exception as e:
            logger.error(f"CTINexus entity extraction failed: {e}")
            return []

    async def _ctinexus_llm_extraction(
        self, scan_data: Dict[str, Any]
    ) -> List[SecurityEntity]:
        """Real CTINexus LLM-based entity and relation extraction"""
        entities = []

        try:
            # Prepare CTI text from scan data
            cti_text = self._prepare_cti_text(scan_data)

            # Create CTINexus prompt with demonstration examples
            prompt = self._create_ctinexus_prompt(cti_text)

            # Call LLM for entity extraction
            response = await self.llm_client.generate_text(
                prompt=prompt,
                system_message="You are a cybersecurity expert extracting entities and relations from cyber threat intelligence reports. Follow the demonstration format exactly.",
            )

            entities = self._parse_ctinexus_response(response.get("content", ""))

            return entities

        except Exception as e:
            logger.error(f"CTINexus LLM extraction failed: {e}")
            return []

    def _prepare_cti_text(self, scan_data: Dict[str, Any]) -> str:
        """Prepare cyber threat intelligence text from scan data for CTINexus"""
        cti_segments = []

        # Extract text from SARIF
        if "sarif" in scan_data:
            sarif_data = scan_data["sarif"]
            for run in sarif_data.get("runs", []):
                for result in run.get("results", []):
                    message = result.get("message", {}).get("text", "")
                    rule_id = result.get("ruleId", "")
                    location = self._extract_file_location(result) or "unknown"

                    cti_segments.append(
                        f"{rule_id} vulnerability found in {location}: {message}"
                    )

        # Extract from security findings
        if "security_findings" in scan_data:
            for finding in scan_data["security_findings"]:
                title = finding.get("title", "")
                description = finding.get("description", "")
                severity = finding.get("severity", "")
                cve = finding.get("cve", "")

                cti_segments.append(f"{severity} {cve} {title}: {description}")

        return ". ".join(cti_segments)

    def _create_ctinexus_prompt(self, cti_text: str) -> str:
        """Create CTINexus-style prompt with in-context learning demonstrations"""

        # Build demonstration examples
        demonstrations = "\n\n".join(
            [
                f"Input: {ex['input']}\nOutput: {ex['output']}"
                for ex in self.demonstration_examples
            ]
        )

        prompt = f"""You are performing cybersecurity entity and relation extraction using the CTINexus framework. Extract entities and their relationships from cyber threat intelligence reports.

Entity Types: {', '.join(self.cybersecurity_ontology.keys())}

Demonstration Examples:
{demonstrations}

Now extract entities and relations from the following cyber threat intelligence:

Input: {cti_text}
Output: """

        return prompt

    def _parse_ctinexus_response(self, response: str) -> List[SecurityEntity]:
        """Parse CTINexus LLM response into SecurityEntity objects"""
        entities = []

        try:
            # Parse entities from response format: [entity_name|entity_type]
            if "Entities:" in response:
                entities_part = (
                    response.split("Entities:")[1].split("Relations:")[0]
                    if "Relations:" in response
                    else response.split("Entities:")[1]
                )

                # Extract entity mentions using regex
                import re

                entity_pattern = r"\[(.*?)\|(.*?)\]"
                matches = re.findall(entity_pattern, entities_part)

                for name, entity_type in matches:
                    entity = SecurityEntity(
                        entity_id=f"ctinexus_{entity_type}_{hash(name) % 10000}",
                        entity_type=entity_type.strip(),
                        name=name.strip(),
                        properties={
                            "extraction_method": "ctinexus_llm",
                            "source": "llm_analysis",
                        },
                        confidence=0.9,  # High confidence for LLM extraction
                    )
                    entities.append(entity)

        except Exception as e:
            logger.error(f"CTINexus response parsing failed: {e}")

        return entities

    async def _fallback_pattern_extraction(
        self, scan_data: Dict[str, Any]
    ) -> List[SecurityEntity]:
        """Fallback pattern-based extraction when LLM unavailable"""
        entities = []

        # Extract from SARIF findings
        if "sarif" in scan_data:
            sarif_entities = await self._extract_from_sarif(scan_data["sarif"])
            entities.extend(sarif_entities)

        # Extract from SBOM
        if "sbom" in scan_data:
            sbom_entities = await self._extract_from_sbom(scan_data["sbom"])
            entities.extend(sbom_entities)

        # Extract from security findings
        if "security_findings" in scan_data:
            finding_entities = await self._extract_from_findings(
                scan_data["security_findings"]
            )
            entities.extend(finding_entities)

        return entities

    async def _extract_from_sarif(
        self, sarif_data: Dict[str, Any]
    ) -> List[SecurityEntity]:
        """Extract entities from SARIF data"""
        entities = []

        for run in sarif_data.get("runs", []):
            for result in run.get("results", []):
                # Extract vulnerability entity
                rule_id = result.get("ruleId", "unknown")
                entity = SecurityEntity(
                    entity_id=f"vuln_{rule_id}_{hash(str(result)) % 10000}",
                    entity_type="vulnerability",
                    name=rule_id,
                    properties={
                        "severity": result.get("level", "note"),
                        "message": result.get("message", {}).get("text", ""),
                        "file_location": self._extract_file_location(result),
                        "cwe_id": self._extract_cwe(result),
                        "owasp_category": self._extract_owasp(result),
                    },
                    confidence=0.9,
                )
                entities.append(entity)

                # Extract component entity from file location
                file_location = self._extract_file_location(result)
                if file_location:
                    component_entity = SecurityEntity(
                        entity_id=f"component_{hash(file_location) % 10000}",
                        entity_type="component",
                        name=file_location.split("/")[-1],
                        properties={"path": file_location, "type": "source_file"},
                        confidence=0.8,
                    )
                    entities.append(component_entity)

        return entities

    async def _extract_from_sbom(
        self, sbom_data: Dict[str, Any]
    ) -> List[SecurityEntity]:
        """Extract entities from SBOM data"""
        entities = []

        # Extract components from SBOM
        components = sbom_data.get("components", [])
        for component in components:
            entity = SecurityEntity(
                entity_id=f"sbom_component_{hash(component.get('name', '') + component.get('version', '')) % 10000}",
                entity_type="component",
                name=f"{component.get('name', 'unknown')}@{component.get('version', 'unknown')}",
                properties={
                    "name": component.get("name", "unknown"),
                    "version": component.get("version", "unknown"),
                    "type": component.get("type", "library"),
                    "supplier": component.get("supplier", {}).get("name", "unknown"),
                    "licenses": component.get("licenses", []),
                    "purl": component.get("purl", ""),
                },
                confidence=0.95,
            )
            entities.append(entity)

        return entities

    async def _extract_from_findings(
        self, findings: List[Dict[str, Any]]
    ) -> List[SecurityEntity]:
        """Extract entities from security findings"""
        entities = []

        for finding in findings:
            # Extract vulnerability entity
            vuln_entity = SecurityEntity(
                entity_id=f"finding_{finding.get('id', hash(str(finding)) % 10000)}",
                entity_type="vulnerability",
                name=finding.get("title", "Unknown Vulnerability"),
                properties={
                    "severity": finding.get("severity", "MEDIUM"),
                    "description": finding.get("description", ""),
                    "cve_id": finding.get("cve", ""),
                    "cvss_score": finding.get("cvss_score", 0),
                    "epss_score": finding.get("epss_score", 0),
                    "kev_flag": finding.get("kev_flag", False),
                },
                confidence=0.85,
            )
            entities.append(vuln_entity)

            # Extract affected component if available
            if finding.get("component"):
                component_entity = SecurityEntity(
                    entity_id=f"component_{hash(finding['component']) % 10000}",
                    entity_type="component",
                    name=finding["component"],
                    properties={
                        "name": finding["component"],
                        "affected_by": vuln_entity.entity_id,
                    },
                    confidence=0.8,
                )
                entities.append(component_entity)

        return entities

    def _extract_file_location(self, sarif_result: Dict[str, Any]) -> Optional[str]:
        """Extract file location from SARIF result"""
        locations = sarif_result.get("locations", [])
        if locations:
            physical_location = locations[0].get("physicalLocation", {})
            artifact_location = physical_location.get("artifactLocation", {})
            return artifact_location.get("uri")
        return None

    def _extract_cwe(self, sarif_result: Dict[str, Any]) -> Optional[str]:
        """Extract CWE ID from SARIF result"""
        tags = sarif_result.get("tags", [])
        for tag in tags:
            if tag.startswith("CWE-"):
                return tag

        properties = sarif_result.get("properties", {})
        return properties.get("cwe_id")

    def _extract_owasp(self, sarif_result: Dict[str, Any]) -> Optional[str]:
        """Extract OWASP category from SARIF result"""
        tags = sarif_result.get("tags", [])
        for tag in tags:
            if "A0" in tag and "2021" in tag:
                return tag

        properties = sarif_result.get("properties", {})
        return properties.get("owasp_category")


class KnowledgeGraphBuilder:
    """
    Knowledge Graph Construction and Management
    Builds and maintains relationships between security entities
    """

    def __init__(self):
        self.graph = nx.DiGraph() if NETWORKX_AVAILABLE else None
        self.entity_extractor = CTINexusEntityExtractor()
        self.entities = {}
        self.relations = []
        self._node_store: Dict[str, Dict[str, Any]] = {}
        self._edge_store: Dict[str, Dict[str, Dict[str, Any]]] = defaultdict(dict)
        self._reverse_edges: Dict[str, Dict[str, Dict[str, Any]]] = defaultdict(dict)

    # ------------------------------------------------------------------
    # Internal helpers to support both NetworkX and fallback operation
    # ------------------------------------------------------------------
    def _add_node(self, entity: SecurityEntity) -> None:
        attrs = {
            "type": entity.entity_type,
            "name": entity.name,
            "confidence": entity.confidence,
            **entity.properties,
        }
        self._node_store[entity.entity_id] = attrs
        self._edge_store.setdefault(entity.entity_id, {})
        self._reverse_edges.setdefault(entity.entity_id, {})

        if self.graph is not None:
            self.graph.add_node(entity.entity_id, **attrs)

    def _add_edge(self, relation: SecurityRelation) -> None:
        edge_attrs = {
            "relation_type": relation.relation_type,
            "confidence": relation.confidence,
            **relation.properties,
        }
        self._edge_store[relation.source_id][relation.target_id] = edge_attrs
        self._reverse_edges[relation.target_id][relation.source_id] = edge_attrs
        if self.graph is not None:
            self.graph.add_edge(
                relation.source_id,
                relation.target_id,
                **edge_attrs,
            )

    def _number_of_nodes(self) -> int:
        if self.graph is not None:
            return self.graph.number_of_nodes()
        return len(self._node_store)

    def _number_of_edges(self) -> int:
        if self.graph is not None:
            return self.graph.number_of_edges()
        return sum(len(targets) for targets in self._edge_store.values())

    def _iter_nodes(self, data: bool = False) -> Iterable:
        if self.graph is not None:
            return self.graph.nodes(data=data)
        if data:
            return list(self._node_store.items())
        return list(self._node_store.keys())

    def _degree(self, node_id: str) -> int:
        if self.graph is not None:
            return self.graph.degree(node_id)
        out_degree = len(self._edge_store.get(node_id, {}))
        in_degree = len(self._reverse_edges.get(node_id, {}))
        return out_degree + in_degree

    def _node_data(self, node_id: str) -> Dict[str, Any]:
        if self.graph is not None:
            return dict(self.graph.nodes[node_id])
        return self._node_store.get(node_id, {})

    def _neighbors(self, node_id: str) -> Set[str]:
        neighbours = set(self._edge_store.get(node_id, {}).keys())
        neighbours.update(self._reverse_edges.get(node_id, {}).keys())
        return neighbours

    def _has_path(self, source: str, target: str) -> bool:
        if self.graph is not None:
            return nx.has_path(self.graph, source, target)
        return target in self._shortest_path(source, target, return_path=False)

    def _shortest_path(self, source: str, target: str, return_path: bool = True):
        if self.graph is not None:
            try:
                path = nx.shortest_path(self.graph, source, target)
            except NoPathError:
                if return_path:
                    raise
                return []
            return path if return_path else set(path)

        # Simple BFS for fallback operation
        visited = {source: None}
        queue: deque[str] = deque([source])
        while queue:
            current = queue.popleft()
            if current == target:
                break
            for neighbour in self._edge_store.get(current, {}):
                if neighbour not in visited:
                    visited[neighbour] = current
                    queue.append(neighbour)
        if target not in visited:
            if return_path:
                raise NoPathError()
            return []

        path: List[str] = []
        node = target
        while node is not None:
            path.append(node)
            node = visited[node]
        path.reverse()
        return path if return_path else set(path)

    def _weakly_connected_components(self) -> List[Set[str]]:
        if self.graph is not None:
            return list(nx.weakly_connected_components(self.graph))

        visited: Set[str] = set()
        components: List[Set[str]] = []

        for node in self._node_store:
            if node in visited:
                continue
            component = set()
            queue: deque[str] = deque([node])
            visited.add(node)
            while queue:
                current = queue.popleft()
                component.add(current)
                for neighbour in self._neighbors(current):
                    if neighbour not in visited:
                        visited.add(neighbour)
                        queue.append(neighbour)
            components.append(component)
        return components

    def _connected_components(self) -> List[Set[str]]:
        if self.graph is not None:
            undirected = self.graph.to_undirected()
            return list(nx.connected_components(undirected))
        return self._weakly_connected_components()

    def _density(self) -> float:
        nodes = self._number_of_nodes()
        if nodes <= 1:
            return 0.0
        edges = self._number_of_edges()
        return edges / (nodes * (nodes - 1))

    def _average_clustering(self) -> float:
        if self.graph is not None:
            return nx.average_clustering(self.graph.to_undirected())

        # Fallback heuristic: ratio of triangles to possible triangles is 0 in simple mode
        return 0.0

    def _degree_centrality(self) -> Dict[str, float]:
        if self.graph is not None:
            return nx.degree_centrality(self.graph)
        nodes = self._number_of_nodes()
        if nodes <= 1:
            return {node: 0.0 for node in self._node_store}
        scale = 1 / (nodes - 1)
        return {node: self._degree(node) * scale for node in self._node_store}

    def _betweenness_centrality(self) -> Dict[str, float]:
        if self.graph is not None:
            return nx.betweenness_centrality(self.graph)
        # Fallback: return zeros to keep structure predictable
        return {node: 0.0 for node in self._node_store}

    async def build_graph(
        self, scan_data: Dict[str, Any], context_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """Build knowledge graph from scan data and context"""
        try:
            # Step 1: Extract entities
            logger.info("🔍 Extracting entities from scan data...")
            entities = await self.entity_extractor.extract_entities(scan_data)

            # Step 2: Add entities to graph
            for entity in entities:
                self._add_node(entity)
                self.entities[entity.entity_id] = entity

            # Step 3: Infer relationships
            logger.info("🔗 Inferring relationships between entities...")
            relations = await self._infer_relationships(entities)

            # Step 4: Add relationships to graph
            for relation in relations:
                self._add_edge(relation)
                self.relations.append(relation)

            # Step 5: Analyze graph structure
            analysis = await self._analyze_graph()

            return {
                "status": "success",
                "entities_count": len(entities),
                "relations_count": len(relations),
                "graph_metrics": analysis,
                "critical_paths": await self._find_critical_paths(),
                "risk_clusters": await self._identify_risk_clusters(),
                "recommendations": await self._generate_recommendations(),
            }

        except Exception as e:
            logger.error(f"Knowledge graph construction failed: {e}")
            return {"status": "error", "error": str(e)}

    async def _infer_relationships(
        self, entities: List[SecurityEntity]
    ) -> List[SecurityRelation]:
        """Infer relationships between entities"""
        relations = []

        # Create entity lookup by type
        entities_by_type = {}
        for entity in entities:
            if entity.entity_type not in entities_by_type:
                entities_by_type[entity.entity_type] = []
            entities_by_type[entity.entity_type] = entity

        # Infer vulnerability -> component relationships
        vulnerabilities = [e for e in entities if e.entity_type == "vulnerability"]
        components = [e for e in entities if e.entity_type == "component"]

        for vuln in vulnerabilities:
            for component in components:
                # Check if vulnerability affects component
                if self._entities_related(vuln, component):
                    relation = SecurityRelation(
                        source_id=vuln.entity_id,
                        target_id=component.entity_id,
                        relation_type="affects",
                        properties={
                            "severity": vuln.properties.get("severity", "MEDIUM"),
                            "inference_method": "file_location_match",
                        },
                        confidence=0.7,
                    )
                    relations.append(relation)

        # Infer component -> service relationships
        services = [e for e in entities if e.entity_type == "service"]
        for component in components:
            for service in services:
                if self._component_belongs_to_service(component, service):
                    relation = SecurityRelation(
                        source_id=component.entity_id,
                        target_id=service.entity_id,
                        relation_type="belongs_to",
                        properties={"inference_method": "path_analysis"},
                        confidence=0.6,
                    )
                    relations.append(relation)

        return relations

    def _entities_related(
        self, entity1: SecurityEntity, entity2: SecurityEntity
    ) -> bool:
        """Check if two entities are related"""
        # Simple heuristic: same file path or component name matching
        if (
            entity1.entity_type == "vulnerability"
            and entity2.entity_type == "component"
        ):
            vuln_file = entity1.properties.get("file_location", "")
            component_path = entity2.properties.get("path", "")

            if vuln_file and component_path:
                return vuln_file == component_path

        return False

    def _component_belongs_to_service(
        self, component: SecurityEntity, service: SecurityEntity
    ) -> bool:
        """Check if component belongs to service"""
        component_path = component.properties.get("path", "")
        service_name = service.name

        # Simple heuristic: path contains service name
        return service_name.lower() in component_path.lower()

    async def _analyze_graph(self) -> Dict[str, Any]:
        """Analyze graph structure and metrics"""
        try:
            node_count = self._number_of_nodes()
            metrics = {
                "nodes": node_count,
                "edges": self._number_of_edges(),
                "density": self._density(),
                "connected_components": len(self._weakly_connected_components()),
                "avg_clustering": self._average_clustering(),
                "centrality_scores": {},
            }

            # Calculate centrality scores for key nodes
            if node_count > 0:
                degree_centrality = self._degree_centrality()
                betweenness_centrality = self._betweenness_centrality()

                # Get top 5 most central nodes
                top_degree = sorted(
                    degree_centrality.items(), key=lambda x: x[1], reverse=True
                )[:5]
                top_betweenness = sorted(
                    betweenness_centrality.items(), key=lambda x: x[1], reverse=True
                )[:5]

                metrics["centrality_scores"] = {
                    "top_degree_centrality": top_degree,
                    "top_betweenness_centrality": top_betweenness,
                }

            return metrics

        except Exception as e:
            logger.error(f"Graph analysis failed: {e}")
            return {"error": str(e)}

    async def _find_critical_paths(self) -> List[Dict[str, Any]]:
        """Find critical attack paths in the graph"""
        critical_paths = []

        try:
            # Find paths from vulnerabilities to high-value components/services
            vulnerabilities = [
                node
                for node, data in self._iter_nodes(data=True)
                if data.get("type") == "vulnerability"
            ]
            services = [
                node
                for node, data in self._iter_nodes(data=True)
                if data.get("type") == "service"
            ]

            for vuln in vulnerabilities:
                for service in services:
                    try:
                        if self._has_path(vuln, service):
                            path = self._shortest_path(vuln, service)
                            if len(path) > 1:
                                critical_paths.append(
                                    {
                                        "source": vuln,
                                        "target": service,
                                        "path": path,
                                        "length": len(path) - 1,
                                        "risk_score": self._calculate_path_risk(path),
                                    }
                                )
                    except NoPathError:
                        continue

            # Sort by risk score
            critical_paths.sort(key=lambda x: x["risk_score"], reverse=True)
            return critical_paths[:10]  # Top 10 critical paths

        except Exception as e:
            logger.error(f"Critical path analysis failed: {e}")
            return []

    def _calculate_path_risk(self, path: List[str]) -> float:
        """Calculate risk score for a path"""
        total_risk = 0

        for node_id in path:
            node_data = self._node_data(node_id)

            # Base risk from node type
            type_risk = {"vulnerability": 0.8, "component": 0.4, "service": 0.6}.get(
                node_data.get("type"), 0.2
            )

            # Adjust for severity/properties
            if node_data.get("type") == "vulnerability":
                severity = node_data.get("severity", "MEDIUM")
                severity_multiplier = {
                    "CRITICAL": 1.5,
                    "HIGH": 1.2,
                    "MEDIUM": 1.0,
                    "LOW": 0.7,
                }.get(severity, 1.0)
                type_risk *= severity_multiplier

            total_risk += type_risk

        return total_risk / len(path) if path else 0

    async def _identify_risk_clusters(self) -> List[Dict[str, Any]]:
        """Identify clusters of related risks"""
        clusters = []

        try:
            components = self._connected_components()

            for i, component in enumerate(components):
                if len(component) > 1:
                    cluster_nodes = list(component)
                    cluster_info = {
                        "cluster_id": f"cluster_{i}",
                        "nodes": cluster_nodes,
                        "size": len(cluster_nodes),
                        "risk_level": self._calculate_cluster_risk(cluster_nodes),
                        "types": list(
                            {
                                self._node_data(node).get("type")
                                for node in cluster_nodes
                            }
                        ),
                    }
                    clusters.append(cluster_info)

            clusters.sort(key=lambda x: x["risk_level"], reverse=True)

            return clusters

        except Exception as e:
            logger.error(f"Risk cluster identification failed: {e}")
            return []

    def _calculate_cluster_risk(self, nodes: List[str]) -> float:
        """Calculate risk level for a cluster"""
        total_risk = 0

        for node in nodes:
            node_data = self._node_data(node)
            node_type = node_data.get("type", "unknown")

            # Risk scoring by type
            type_risks = {
                "vulnerability": 0.8,
                "component": 0.4,
                "service": 0.7,
                "technique": 0.9,
            }

            risk = type_risks.get(node_type, 0.3)

            # Adjust for properties
            if node_type == "vulnerability":
                severity = node_data.get("severity", "MEDIUM")
                if severity == "CRITICAL":
                    risk *= 1.5
                elif severity == "HIGH":
                    risk *= 1.2

            total_risk += risk

        return total_risk / len(nodes) if nodes else 0

    async def _generate_recommendations(self) -> List[Dict[str, str]]:
        """Generate security recommendations based on graph analysis"""
        recommendations = []

        # Find highly connected vulnerability nodes
        vulnerability_nodes = [
            node
            for node, data in self._iter_nodes(data=True)
            if data.get("type") == "vulnerability"
        ]

        for vuln_node in vulnerability_nodes:
            degree = self._degree(vuln_node)
            if degree > 2:  # Highly connected vulnerability
                vuln_data = self._node_data(vuln_node)
                recommendations.append(
                    {
                        "type": "high_priority_fix",
                        "title": "Critical vulnerability affects multiple components",
                        "description": f"Vulnerability {vuln_data.get('name')} affects {degree} components. Priority fix recommended.",
                        "affected_entity": vuln_node,
                        "priority": "high",
                    }
                )

        # Find isolated components (potential blind spots)
        component_nodes = [
            node
            for node, data in self._iter_nodes(data=True)
            if data.get("type") == "component"
        ]

        for comp_node in component_nodes:
            if self._degree(comp_node) == 0:  # Isolated component
                comp_data = self._node_data(comp_node)
                recommendations.append(
                    {
                        "type": "security_gap",
                        "title": "Unmonitored component detected",
                        "description": f"Component {comp_data.get('name')} has no security relationships. Consider additional scanning.",
                        "affected_entity": comp_node,
                        "priority": "medium",
                    }
                )

        return recommendations


# Global knowledge graph instance
knowledge_graph = KnowledgeGraphBuilder()
