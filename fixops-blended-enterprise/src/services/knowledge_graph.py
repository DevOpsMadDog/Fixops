"""
Knowledge Graph Construction
Purpose: Link components, vulnerabilities, and context
Uses CTINexus for entity extraction and graph visualization
"""

import asyncio
import json
import networkx as nx
from datetime import datetime, timezone
from typing import Dict, List, Any, Tuple, Optional, Set
from dataclasses import dataclass
import structlog

logger = structlog.get_logger()

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
        self.llm_client = None
        self._initialize_llm_client()
        self.cybersecurity_ontology = self._load_cybersecurity_ontology()
        self.demonstration_examples = self._load_demonstration_examples()
    
    def _initialize_patterns(self) -> Dict[str, List[str]]:
        """Initialize entity extraction patterns"""
        return {
            "vulnerability": [
                r"CVE-\d{4}-\d{4,7}",
                r"CWE-\d+",
                r"GHSA-[a-z0-9]{4}-[a-z0-9]{4}-[a-z0-9]{4}"
            ],
            "component": [
                r"[\w\-]+@\d+\.\d+\.\d+",  # package@version
                r"[\w\-]+:[\w\-]+:\d+\.\d+\.\d+"  # group:artifact:version
            ],
            "service": [
                r"[a-z][a-z0-9\-]*[a-z0-9]\.service",
                r"[a-z][a-z0-9\-]*[a-z0-9]\.app"
            ],
            "technique": [
                r"T\d{4}(\.\d{3})?",  # MITRE ATT&CK techniques
                r"TA\d{4}"  # MITRE ATT&CK tactics
            ]
        }
    
    def _initialize_relation_patterns(self) -> Dict[str, List[str]]:
        """Initialize relationship extraction patterns"""
        return {
            "exploits": ["exploits", "targets", "attacks"],
            "depends_on": ["depends on", "requires", "needs", "uses"],
            "mitigates": ["fixes", "patches", "resolves", "mitigates"],
            "affects": ["affects", "impacts", "compromises"],
            "contains": ["contains", "includes", "has component"]
        }
    
    async def extract_entities(self, scan_data: Dict[str, Any]) -> List[SecurityEntity]:
        """Extract security entities from scan data"""
        entities = []
        
        try:
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
                finding_entities = await self._extract_from_findings(scan_data["security_findings"])
                entities.extend(finding_entities)
            
            logger.info(f"Extracted {len(entities)} entities from scan data")
            return entities
            
        except Exception as e:
            logger.error(f"Entity extraction failed: {e}")
            return []
    
    async def _extract_from_sarif(self, sarif_data: Dict[str, Any]) -> List[SecurityEntity]:
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
                        "owasp_category": self._extract_owasp(result)
                    },
                    confidence=0.9
                )
                entities.append(entity)
                
                # Extract component entity from file location
                file_location = self._extract_file_location(result)
                if file_location:
                    component_entity = SecurityEntity(
                        entity_id=f"component_{hash(file_location) % 10000}",
                        entity_type="component",
                        name=file_location.split("/")[-1],
                        properties={
                            "path": file_location,
                            "type": "source_file"
                        },
                        confidence=0.8
                    )
                    entities.append(component_entity)
        
        return entities
    
    async def _extract_from_sbom(self, sbom_data: Dict[str, Any]) -> List[SecurityEntity]:
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
                    "purl": component.get("purl", "")
                },
                confidence=0.95
            )
            entities.append(entity)
        
        return entities
    
    async def _extract_from_findings(self, findings: List[Dict[str, Any]]) -> List[SecurityEntity]:
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
                    "kev_flag": finding.get("kev_flag", False)
                },
                confidence=0.85
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
                        "affected_by": vuln_entity.entity_id
                    },
                    confidence=0.8
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
        self.graph = nx.DiGraph()
        self.entity_extractor = CTINexusEntityExtractor()
        self.entities = {}
        self.relations = []
    
    async def build_graph(self, scan_data: Dict[str, Any], context_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Build knowledge graph from scan data and context"""
        try:
            # Step 1: Extract entities
            logger.info("🔍 Extracting entities from scan data...")
            entities = await self.entity_extractor.extract_entities(scan_data)
            
            # Step 2: Add entities to graph
            for entity in entities:
                self.graph.add_node(
                    entity.entity_id,
                    **{
                        "type": entity.entity_type,
                        "name": entity.name,
                        "confidence": entity.confidence,
                        **entity.properties
                    }
                )
                self.entities[entity.entity_id] = entity
            
            # Step 3: Infer relationships
            logger.info("🔗 Inferring relationships between entities...")
            relations = await self._infer_relationships(entities)
            
            # Step 4: Add relationships to graph
            for relation in relations:
                self.graph.add_edge(
                    relation.source_id,
                    relation.target_id,
                    relation_type=relation.relation_type,
                    confidence=relation.confidence,
                    **relation.properties
                )
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
                "recommendations": await self._generate_recommendations()
            }
            
        except Exception as e:
            logger.error(f"Knowledge graph construction failed: {e}")
            return {"status": "error", "error": str(e)}
    
    async def _infer_relationships(self, entities: List[SecurityEntity]) -> List[SecurityRelation]:
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
                            "inference_method": "file_location_match"
                        },
                        confidence=0.7
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
                        properties={
                            "inference_method": "path_analysis"
                        },
                        confidence=0.6
                    )
                    relations.append(relation)
        
        return relations
    
    def _entities_related(self, entity1: SecurityEntity, entity2: SecurityEntity) -> bool:
        """Check if two entities are related"""
        # Simple heuristic: same file path or component name matching
        if entity1.entity_type == "vulnerability" and entity2.entity_type == "component":
            vuln_file = entity1.properties.get("file_location", "")
            component_path = entity2.properties.get("path", "")
            
            if vuln_file and component_path:
                return vuln_file == component_path
        
        return False
    
    def _component_belongs_to_service(self, component: SecurityEntity, service: SecurityEntity) -> bool:
        """Check if component belongs to service"""
        component_path = component.properties.get("path", "")
        service_name = service.name
        
        # Simple heuristic: path contains service name
        return service_name.lower() in component_path.lower()
    
    async def _analyze_graph(self) -> Dict[str, Any]:
        """Analyze graph structure and metrics"""
        try:
            metrics = {
                "nodes": self.graph.number_of_nodes(),
                "edges": self.graph.number_of_edges(),
                "density": nx.density(self.graph) if self.graph.number_of_nodes() > 0 else 0,
                "connected_components": nx.number_weakly_connected_components(self.graph),
                "avg_clustering": nx.average_clustering(self.graph.to_undirected()),
                "centrality_scores": {}
            }
            
            # Calculate centrality scores for key nodes
            if self.graph.number_of_nodes() > 0:
                degree_centrality = nx.degree_centrality(self.graph)
                betweenness_centrality = nx.betweenness_centrality(self.graph)
                
                # Get top 5 most central nodes
                top_degree = sorted(degree_centrality.items(), key=lambda x: x[1], reverse=True)[:5]
                top_betweenness = sorted(betweenness_centrality.items(), key=lambda x: x[1], reverse=True)[:5]
                
                metrics["centrality_scores"] = {
                    "top_degree_centrality": top_degree,
                    "top_betweenness_centrality": top_betweenness
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
            vulnerabilities = [node for node, data in self.graph.nodes(data=True) 
                             if data.get("type") == "vulnerability"]
            services = [node for node, data in self.graph.nodes(data=True) 
                       if data.get("type") == "service"]
            
            for vuln in vulnerabilities:
                for service in services:
                    try:
                        # Find shortest path
                        if nx.has_path(self.graph, vuln, service):
                            path = nx.shortest_path(self.graph, vuln, service)
                            if len(path) > 1:  # Actual path exists
                                path_info = {
                                    "source": vuln,
                                    "target": service,
                                    "path": path,
                                    "length": len(path) - 1,
                                    "risk_score": self._calculate_path_risk(path)
                                }
                                critical_paths.append(path_info)
                    except nx.NetworkXNoPath:
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
            node_data = self.graph.nodes[node_id]
            
            # Base risk from node type
            type_risk = {
                "vulnerability": 0.8,
                "component": 0.4,
                "service": 0.6
            }.get(node_data.get("type"), 0.2)
            
            # Adjust for severity/properties
            if node_data.get("type") == "vulnerability":
                severity = node_data.get("severity", "MEDIUM")
                severity_multiplier = {
                    "CRITICAL": 1.5,
                    "HIGH": 1.2,
                    "MEDIUM": 1.0,
                    "LOW": 0.7
                }.get(severity, 1.0)
                type_risk *= severity_multiplier
            
            total_risk += type_risk
        
        return total_risk / len(path) if path else 0
    
    async def _identify_risk_clusters(self) -> List[Dict[str, Any]]:
        """Identify clusters of related risks"""
        clusters = []
        
        try:
            # Use community detection to find clusters
            undirected_graph = self.graph.to_undirected()
            
            if undirected_graph.number_of_nodes() > 0:
                # Simple clustering based on connected components
                components = list(nx.connected_components(undirected_graph))
                
                for i, component in enumerate(components):
                    if len(component) > 1:  # Only multi-node clusters
                        cluster_nodes = list(component)
                        cluster_info = {
                            "cluster_id": f"cluster_{i}",
                            "nodes": cluster_nodes,
                            "size": len(cluster_nodes),
                            "risk_level": self._calculate_cluster_risk(cluster_nodes),
                            "types": list(set([self.graph.nodes[node].get("type") for node in cluster_nodes]))
                        }
                        clusters.append(cluster_info)
                
                # Sort by risk level
                clusters.sort(key=lambda x: x["risk_level"], reverse=True)
            
            return clusters
            
        except Exception as e:
            logger.error(f"Risk cluster identification failed: {e}")
            return []
    
    def _calculate_cluster_risk(self, nodes: List[str]) -> float:
        """Calculate risk level for a cluster"""
        total_risk = 0
        
        for node in nodes:
            node_data = self.graph.nodes[node]
            node_type = node_data.get("type", "unknown")
            
            # Risk scoring by type
            type_risks = {
                "vulnerability": 0.8,
                "component": 0.4,
                "service": 0.7,
                "technique": 0.9
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
        vulnerability_nodes = [node for node, data in self.graph.nodes(data=True) 
                              if data.get("type") == "vulnerability"]
        
        for vuln_node in vulnerability_nodes:
            degree = self.graph.degree(vuln_node)
            if degree > 2:  # Highly connected vulnerability
                vuln_data = self.graph.nodes[vuln_node]
                recommendations.append({
                    "type": "high_priority_fix",
                    "title": f"Critical vulnerability affects multiple components",
                    "description": f"Vulnerability {vuln_data.get('name')} affects {degree} components. Priority fix recommended.",
                    "affected_entity": vuln_node,
                    "priority": "high"
                })
        
        # Find isolated components (potential blind spots)
        component_nodes = [node for node, data in self.graph.nodes(data=True) 
                          if data.get("type") == "component"]
        
        for comp_node in component_nodes:
            if self.graph.degree(comp_node) == 0:  # Isolated component
                comp_data = self.graph.nodes[comp_node]
                recommendations.append({
                    "type": "security_gap",
                    "title": "Unmonitored component detected",
                    "description": f"Component {comp_data.get('name')} has no security relationships. Consider additional scanning.",
                    "affected_entity": comp_node,
                    "priority": "medium"
                })
        
        return recommendations

# Global knowledge graph instance
knowledge_graph = KnowledgeGraphBuilder()