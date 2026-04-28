"""
TrustGraph Indexer — Populate 5 Knowledge Cores with existing codebase data.

Indexes data from:
- 28 threat intelligence feeds → Core 2 (Threat Intelligence)
- 20 connector metadata → Core 1 (Customer Environment)
- 7 compliance frameworks → Core 3 (Compliance & Regulatory)
- 32 scanner normalizers → Core 1 (Customer Environment)
- Decision memory → Core 4 (Decision Memory)

Usage:
    from core.trustgraph_indexer import TrustGraphIndexer
    indexer = TrustGraphIndexer()
    stats = indexer.index_all()
    print(f"Indexed {stats['total']} entities across 5 cores")

Personas served: P01 CISO, P05 Security Engineer, P07 Compliance Officer,
P09 Risk Manager, P17 Threat Intel Analyst
"""

from __future__ import annotations

import logging
import uuid
from typing import Any, Dict

logger = logging.getLogger(__name__)


class TrustGraphIndexer:
    """Populates TrustGraph Knowledge Cores with data from the existing codebase."""

    def __init__(self, org_id: str = "default") -> None:
        """Initialize indexer.

        Args:
            org_id: Organization ID for multi-tenancy
        """
        self.org_id = org_id
        self._store = None

    def _get_store(self):
        """Lazy-load KnowledgeStore."""
        if self._store is None:
            from trustgraph import get_knowledge_store
            self._store = get_knowledge_store()
        return self._store

    def _make_entity(self, entity_id: str, core_id: int, entity_type: str,
                     name: str, properties: Dict[str, Any] = None):
        """Helper to create a KnowledgeEntity."""
        from trustgraph.knowledge_store import KnowledgeEntity
        return KnowledgeEntity(
            entity_id=entity_id,
            core_id=core_id,
            entity_type=entity_type,
            name=name,
            properties=properties or {},
            org_id=self.org_id,
        )

    def _make_rel(self, source_id: str, target_id: str, rel_type: str,
                  confidence: float = 0.95):
        """Helper to create a KnowledgeRelationship."""
        from trustgraph.knowledge_store import KnowledgeRelationship
        return KnowledgeRelationship(
            rel_id=f"rel_{uuid.uuid4().hex[:12]}",
            source_id=source_id,
            target_id=target_id,
            rel_type=rel_type,
            confidence=confidence,
        )

    # =========================================================================
    # Core 1: Customer Environment Core
    # =========================================================================

    def index_connectors(self) -> int:
        """Index connector metadata into Core 1 (Customer Environment).

        Sources:
        - 7 bidirectional connectors (Jira, Confluence, Slack, etc.)
        - 10+ security tool connectors (Snyk, SonarQube, etc.)
        - 32 scanner normalizers
        """
        store = self._get_store()
        count = 0

        # Bidirectional connectors
        bidirectional = [
            ("jira", "Jira", "Project Management & Issue Tracking"),
            ("confluence", "Confluence", "Knowledge Base & Documentation"),
            ("slack", "Slack", "Team Communication & Alerting"),
            ("servicenow", "ServiceNow", "ITSM & Incident Management"),
            ("gitlab", "GitLab", "Source Code Management & CI/CD"),
            ("azure_devops", "Azure DevOps", "DevOps Pipeline & Boards"),
            ("github", "GitHub", "Source Code & PR Management"),
        ]

        for conn_id, name, desc in bidirectional:
            entity = self._make_entity(
                entity_id=f"connector_{conn_id}",
                core_id=1,
                entity_type="Service",
                name=f"Connector: {name}",
                properties={
                    "type": "bidirectional",
                    "description": desc,
                    "sdlc_stages": ["plan", "code", "build", "test", "deploy", "operate"],
                    "capabilities": ["pull", "push", "sync"],
                },
            )
            store.ingest(entity)
            count += 1

        # Security tool connectors
        security_connectors = [
            ("snyk", "Snyk", "SCA & Container Security"),
            ("sonarqube", "SonarQube", "SAST & Code Quality"),
            ("dependabot", "Dependabot", "Dependency Updates"),
            ("aws_security_hub", "AWS Security Hub", "Cloud Security Posture"),
            ("azure_defender", "Azure Defender", "Cloud Workload Protection"),
            ("wiz", "Wiz", "Cloud-Native Application Protection"),
            ("prisma_cloud", "Prisma Cloud", "CNAPP"),
            ("orca", "Orca Security", "Agentless Cloud Security"),
            ("lacework", "Lacework", "Cloud Security Data Analytics"),
            ("threatmapper", "ThreatMapper", "Open Source Cloud Security"),
            ("dependency_track", "OWASP Dependency-Track", "SBOM Lifecycle"),
        ]

        for conn_id, name, desc in security_connectors:
            entity = self._make_entity(
                entity_id=f"connector_{conn_id}",
                core_id=1,
                entity_type="Service",
                name=f"Security Connector: {name}",
                properties={
                    "type": "pull",
                    "description": desc,
                    "sdlc_stages": ["test", "deploy", "operate"],
                    "capabilities": ["pull", "normalize"],
                },
            )
            store.ingest(entity)
            count += 1

        # Scanner normalizers
        try:
            from core.scanner_parsers import get_supported_scanners
            scanners = get_supported_scanners()
            for category, scanner_list in scanners.items():
                if category in ("note", "total_new"):
                    continue
                if isinstance(scanner_list, list):
                    for scanner_name in scanner_list:
                        entity = self._make_entity(
                            entity_id=f"scanner_{scanner_name}",
                            core_id=1,
                            entity_type="Service",
                            name=f"Scanner: {scanner_name}",
                            properties={
                                "type": "scanner",
                                "category": category,
                                "has_normalizer": True,
                            },
                        )
                        store.ingest(entity)

                        # Relate scanner to its category
                        rel = self._make_rel(
                            source_id=f"scanner_{scanner_name}",
                            target_id=f"category_{category}",
                            rel_type="belongs_to",
                        )
                        store.add_relationship(rel)
                        count += 1
        except ImportError:
            logger.warning("scanner_parsers not available for indexing")

        logger.info("Indexed %d connector/scanner entities into Core 1", count)
        return count

    # =========================================================================
    # Core 2: Threat Intelligence Core
    # =========================================================================

    def index_threat_feeds(self) -> int:
        """Index threat intelligence feed metadata into Core 2.

        Sources: 28+ threat feeds (NVD, OSV, EPSS, KEV, ExploitDB, etc.)
        """
        store = self._get_store()
        count = 0

        feeds = [
            # Government/official
            ("nvd", "NVD", "NIST National Vulnerability Database", "government"),
            ("osv", "OSV", "Open Source Vulnerability Database", "government"),
            ("kev", "CISA KEV", "Known Exploited Vulnerabilities Catalog", "government"),
            ("epss", "EPSS", "Exploit Prediction Scoring System", "government"),
            ("github_advisories", "GitHub Security Advisories", "GitHub vulnerability advisories", "platform"),
            # Exploit databases
            ("exploitdb", "ExploitDB", "Exploit Database (Offensive Security)", "exploit"),
            ("vulners", "Vulners", "Vulnerability intelligence aggregator", "exploit"),
            ("alienvault_otx", "AlienVault OTX", "Open Threat Exchange", "exploit"),
            ("abuseipdb", "AbuseIPDB", "IP address abuse reports", "exploit"),
            ("abusech_urlhaus", "URLhaus", "Malicious URL tracking", "exploit"),
            ("abusech_malwarebazaar", "MalwareBazaar", "Malware sample tracking", "exploit"),
            ("abusech_threatfox", "ThreatFox", "IOC sharing platform", "exploit"),
            ("rapid7", "Rapid7", "Vulnerability intelligence", "exploit"),
            # Vendor advisories
            ("microsoft", "Microsoft Security", "Microsoft security advisories", "vendor"),
            ("apple", "Apple Security", "Apple security updates", "vendor"),
            ("aws", "AWS Security Bulletins", "AWS security bulletins", "vendor"),
            ("azure", "Azure Security", "Azure security advisories", "vendor"),
            ("oracle", "Oracle Security", "Oracle Critical Patch Updates", "vendor"),
            ("cisco", "Cisco Security", "Cisco security advisories", "vendor"),
            ("vmware", "VMware Security", "VMware security advisories", "vendor"),
            ("docker", "Docker Security", "Docker security advisories", "vendor"),
            ("kubernetes", "Kubernetes Security", "Kubernetes CVEs", "vendor"),
            # Ecosystem feeds
            ("npm", "NPM Audit", "Node.js package vulnerabilities", "ecosystem"),
            ("pypi", "PyPI Advisory", "Python package vulnerabilities", "ecosystem"),
            ("rubygems", "RubyGems Advisory", "Ruby gem vulnerabilities", "ecosystem"),
            ("rust_advisory", "Rust Advisory DB", "Rust crate vulnerabilities", "ecosystem"),
            ("go_vuln", "Go Vulnerability DB", "Go module vulnerabilities", "ecosystem"),
            ("maven", "Maven Security", "Java/Maven vulnerabilities", "ecosystem"),
        ]

        for feed_id, name, desc, category in feeds:
            entity = self._make_entity(
                entity_id=f"feed_{feed_id}",
                core_id=2,
                entity_type="Threat",
                name=f"Feed: {name}",
                properties={
                    "description": desc,
                    "category": category,
                    "active": True,
                    "update_frequency": "hourly" if category == "government" else "daily",
                },
            )
            store.ingest(entity)

            # Create category entity and relationship
            cat_entity = self._make_entity(
                entity_id=f"feed_category_{category}",
                core_id=2,
                entity_type="Campaign",
                name=f"Feed Category: {category.title()}",
                properties={"type": "category"},
            )
            store.ingest(cat_entity)

            rel = self._make_rel(
                source_id=f"feed_{feed_id}",
                target_id=f"feed_category_{category}",
                rel_type="belongs_to",
            )
            store.add_relationship(rel)
            count += 1

        # Index common vulnerability types as TTP entities
        ttps = [
            ("T1190", "Exploit Public-Facing Application", "Initial Access"),
            ("T1059", "Command and Scripting Interpreter", "Execution"),
            ("T1078", "Valid Accounts", "Defense Evasion"),
            ("T1021", "Remote Services", "Lateral Movement"),
            ("T1048", "Exfiltration Over Alternative Protocol", "Exfiltration"),
            ("T1110", "Brute Force", "Credential Access"),
            ("T1071", "Application Layer Protocol", "Command and Control"),
            ("T1566", "Phishing", "Initial Access"),
            ("T1027", "Obfuscated Files or Information", "Defense Evasion"),
            ("T1486", "Data Encrypted for Impact", "Impact"),
        ]

        for ttp_id, name, tactic in ttps:
            entity = self._make_entity(
                entity_id=f"ttp_{ttp_id}",
                core_id=2,
                entity_type="TTP",
                name=f"MITRE ATT&CK: {ttp_id} - {name}",
                properties={
                    "mitre_id": ttp_id,
                    "tactic": tactic,
                    "description": name,
                },
            )
            store.ingest(entity)
            count += 1

        logger.info("Indexed %d threat intel entities into Core 2", count)
        return count

    # =========================================================================
    # Core 3: Compliance & Regulatory Core
    # =========================================================================

    def index_compliance_frameworks(self) -> int:
        """Index compliance framework data into Core 3.

        Sources: 7 compliance framework templates from playbook engine
        """
        store = self._get_store()
        count = 0

        frameworks = [
            ("soc2", "SOC 2 Type II", [
                ("CC1", "Control Environment"),
                ("CC2", "Communication and Information"),
                ("CC3", "Risk Assessment"),
                ("CC5", "Control Activities"),
                ("CC6", "Logical and Physical Access"),
                ("CC7", "System Operations"),
                ("CC8", "Change Management"),
                ("CC9", "Risk Mitigation"),
            ]),
            ("hipaa", "HIPAA", [
                ("164.312a", "Access Control"),
                ("164.312b", "Audit Controls"),
                ("164.312c", "Integrity"),
                ("164.312d", "Authentication"),
                ("164.312e", "Transmission Security"),
            ]),
            ("pci_dss", "PCI DSS v4.0", [
                ("1", "Install and Maintain Network Security Controls"),
                ("2", "Apply Secure Configurations"),
                ("3", "Protect Stored Account Data"),
                ("4", "Protect Cardholder Data with Strong Cryptography"),
                ("5", "Protect All Systems from Malware"),
                ("6", "Develop and Maintain Secure Systems"),
            ]),
            ("iso27001", "ISO 27001:2022", [
                ("A.5", "Organizational Controls"),
                ("A.6", "People Controls"),
                ("A.7", "Physical Controls"),
                ("A.8", "Technological Controls"),
            ]),
            ("nist_csf", "NIST CSF 2.0", [
                ("GV", "Govern"),
                ("ID", "Identify"),
                ("PR", "Protect"),
                ("DE", "Detect"),
                ("RS", "Respond"),
                ("RC", "Recover"),
            ]),
            ("gdpr", "GDPR", [
                ("Art5", "Principles of Processing"),
                ("Art25", "Data Protection by Design"),
                ("Art32", "Security of Processing"),
                ("Art33", "Breach Notification"),
                ("Art35", "Data Protection Impact Assessment"),
            ]),
            ("fedramp", "FedRAMP", [
                ("AC", "Access Control"),
                ("AU", "Audit and Accountability"),
                ("CM", "Configuration Management"),
                ("IA", "Identification and Authentication"),
                ("SC", "System and Communications Protection"),
                ("SI", "System and Information Integrity"),
            ]),
        ]

        for fw_id, fw_name, controls in frameworks:
            # Framework entity
            fw_entity = self._make_entity(
                entity_id=f"framework_{fw_id}",
                core_id=3,
                entity_type="Framework",
                name=fw_name,
                properties={
                    "framework_id": fw_id,
                    "control_count": len(controls),
                    "status": "active",
                },
            )
            store.ingest(fw_entity)
            count += 1

            # Control entities
            for ctrl_id, ctrl_name in controls:
                ctrl_entity = self._make_entity(
                    entity_id=f"control_{fw_id}_{ctrl_id}",
                    core_id=3,
                    entity_type="Control",
                    name=f"{fw_name} — {ctrl_id}: {ctrl_name}",
                    properties={
                        "framework": fw_id,
                        "control_id": ctrl_id,
                        "control_name": ctrl_name,
                    },
                )
                store.ingest(ctrl_entity)
                count += 1

                # Relate control to framework
                rel = self._make_rel(
                    source_id=f"control_{fw_id}_{ctrl_id}",
                    target_id=f"framework_{fw_id}",
                    rel_type="part_of",
                )
                store.add_relationship(rel)

        logger.info("Indexed %d compliance entities into Core 3", count)
        return count

    # =========================================================================
    # Core 4: Decision Memory Core
    # =========================================================================

    def index_decision_patterns(self) -> int:
        """Index decision patterns into Core 4 (Decision Memory).

        Seeds the decision memory with common security decision patterns
        so the LLM Council has historical context for first-run decisions.
        """
        store = self._get_store()
        count = 0

        patterns = [
            ("pattern_critical_rce", "Critical RCE — Immediate Block", "block",
             {"trigger": "CVSS >= 9.0 + RCE", "confidence": 0.95}),
            ("pattern_kev_active", "KEV Active Exploit — Escalate", "remediate_critical",
             {"trigger": "In CISA KEV + EPSS > 0.8", "confidence": 0.92}),
            ("pattern_low_epss", "Low EPSS Score — Accept Risk", "accept_risk",
             {"trigger": "EPSS < 0.1 + no KEV", "confidence": 0.85}),
            ("pattern_supply_chain", "Supply Chain Vulnerability", "remediate_high",
             {"trigger": "Dependency vuln + transitive", "confidence": 0.88}),
            ("pattern_false_positive", "Common False Positive", "false_positive",
             {"trigger": "Known FP pattern + no exploit", "confidence": 0.90}),
            ("pattern_config_drift", "Configuration Drift", "investigate",
             {"trigger": "CSPM finding + policy violation", "confidence": 0.80}),
            ("pattern_secret_leak", "Secret in Source Code", "remediate_critical",
             {"trigger": "Gitleaks/secret scanner finding", "confidence": 0.95}),
            ("pattern_container_vuln", "Container Image Vulnerability", "remediate_high",
             {"trigger": "Trivy/Grype critical in base image", "confidence": 0.87}),
        ]

        for pattern_id, name, action, properties in patterns:
            entity = self._make_entity(
                entity_id=pattern_id,
                core_id=4,
                entity_type="Decision",
                name=name,
                properties={
                    "action": action,
                    "pattern_type": "seed",
                    **properties,
                },
            )
            store.ingest(entity)
            count += 1

        logger.info("Indexed %d decision pattern entities into Core 4", count)
        return count

    # =========================================================================
    # Core 5: Competitive Intelligence Core
    # =========================================================================

    def index_competitive_intel(self) -> int:
        """Index competitor data into Core 5 (Competitive Intelligence).

        Sources: 9 competitors identified in ALDECI_REARCHITECTURE_v2.md
        """
        store = self._get_store()
        count = 0

        competitors = [
            ("aikido", "Aikido Security", "ASPM", ["SCA", "SAST", "DAST", "Cloud", "Secrets"]),
            ("snyk", "Snyk", "Developer Security", ["SCA", "SAST", "Container", "IaC"]),
            ("wiz", "Wiz", "CNAPP", ["CSPM", "CWPP", "CIEM", "DSPM"]),
            ("orca", "Orca Security", "CNAPP", ["CSPM", "CWPP", "DSPM", "SCA"]),
            ("semgrep", "Semgrep/r2c", "Code Analysis", ["SAST", "SCA", "Secrets"]),
            ("armorcode", "ArmorCode", "ASPM", ["Correlation", "Risk", "Compliance"]),
            ("apiiro", "Apiiro", "ASPM", ["Risk", "Code Analysis", "SBOM"]),
            ("phoenix", "Phoenix Security", "ASPM", ["Risk", "Compliance", "Prioritization"]),
            ("defectdojo", "DefectDojo", "Vuln Management", ["Aggregation", "Dedup", "Metrics"]),
        ]

        for comp_id, name, category, capabilities in competitors:
            entity = self._make_entity(
                entity_id=f"competitor_{comp_id}",
                core_id=5,
                entity_type="Competitor",
                name=name,
                properties={
                    "category": category,
                    "capabilities": capabilities,
                    "threat_level": "high" if category in ("ASPM", "CNAPP") else "medium",
                },
            )
            store.ingest(entity)
            count += 1

            # Create capability entities and relationships
            for cap in capabilities:
                cap_id = f"capability_{cap.lower().replace(' ', '_')}"
                cap_entity = self._make_entity(
                    entity_id=cap_id,
                    core_id=5,
                    entity_type="Capability",
                    name=f"Capability: {cap}",
                    properties={"type": "security_capability"},
                )
                store.ingest(cap_entity)

                rel = self._make_rel(
                    source_id=f"competitor_{comp_id}",
                    target_id=cap_id,
                    rel_type="has_capability",
                )
                store.add_relationship(rel)

        # Index ALDECI's own capabilities for comparison
        aldeci_caps = [
            "ASPM", "CTEM", "CSPM", "SAST", "DAST", "SCA", "Secrets",
            "Container", "IaC", "SBOM", "Threat Intel", "Risk Scoring",
            "LLM Council", "Decision Memory", "Micro Pentest", "TrustGraph",
            "30 Personas", "15-Stage Pipeline", "Air-Gapped Mode",
        ]
        aldeci_entity = self._make_entity(
            entity_id="competitor_aldeci",
            core_id=5,
            entity_type="Product",
            name="ALDECI (Fixops)",
            properties={
                "category": "ASPM + CTEM + CSPM",
                "capabilities": aldeci_caps,
                "status": "building",
                "differentiators": [
                    "TrustGraph-native knowledge cores",
                    "Karpathy 3-stage LLM Council",
                    "30 persona-driven RBAC",
                    "Decision memory with analyst feedback",
                    "CISA CTEM 15-stage pipeline",
                ],
            },
        )
        store.ingest(aldeci_entity)
        count += 1

        logger.info("Indexed %d competitive intel entities into Core 5", count)
        return count

    # =========================================================================
    # Cross-Core Relationships
    # =========================================================================

    def index_cross_core_relationships(self) -> int:
        """Create relationships between entities across different cores.

        Links connectors → feeds, feeds → compliance, etc.
        """
        store = self._get_store()
        count = 0

        # Connectors feed into threat intel
        connector_feed_links = [
            ("connector_snyk", "feed_nvd", "consumes"),
            ("connector_snyk", "feed_osv", "consumes"),
            ("connector_sonarqube", "feed_nvd", "consumes"),
            ("connector_dependabot", "feed_github_advisories", "consumes"),
            ("connector_aws_security_hub", "feed_aws", "consumes"),
            ("connector_azure_defender", "feed_azure", "consumes"),
        ]

        for src, tgt, rel_type in connector_feed_links:
            rel = self._make_rel(source_id=src, target_id=tgt, rel_type=rel_type)
            store.add_relationship(rel)
            count += 1

        # Compliance frameworks apply to security findings
        framework_ttp_links = [
            ("framework_soc2", "ttp_T1078", "mitigates"),
            ("framework_pci_dss", "ttp_T1048", "mitigates"),
            ("framework_hipaa", "ttp_T1486", "mitigates"),
            ("framework_nist_csf", "ttp_T1190", "mitigates"),
            ("framework_gdpr", "ttp_T1048", "mitigates"),
        ]

        for src, tgt, rel_type in framework_ttp_links:
            rel = self._make_rel(source_id=src, target_id=tgt, rel_type=rel_type)
            store.add_relationship(rel)
            count += 1

        logger.info("Created %d cross-core relationships", count)
        return count

    # =========================================================================
    # Main Entry Point
    # =========================================================================

    def index_all(self) -> Dict[str, Any]:
        """Run all indexers and return statistics.

        Returns:
            Dict with counts per core and total
        """
        logger.info("Starting TrustGraph indexing for org=%s", self.org_id)

        results = {
            "core_1_connectors": self.index_connectors(),
            "core_2_threat_intel": self.index_threat_feeds(),
            "core_3_compliance": self.index_compliance_frameworks(),
            "core_4_decisions": self.index_decision_patterns(),
            "core_5_competitive": self.index_competitive_intel(),
        }
        results["cross_core_relationships"] = self.index_cross_core_relationships()
        results["total"] = sum(results.values())

        # Get core stats
        store = self._get_store()
        results["core_stats"] = {}
        for core_id in range(1, 6):
            results["core_stats"][core_id] = store.core_stats(core_id)

        logger.info(
            "TrustGraph indexing complete: %d total entities across 5 cores",
            results["total"],
        )
        return results


def run_indexer(org_id: str = "default") -> Dict[str, Any]:
    """Convenience function to run the full indexer.

    Args:
        org_id: Organization ID

    Returns:
        Indexing statistics
    """
    indexer = TrustGraphIndexer(org_id=org_id)
    return indexer.index_all()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    stats = run_indexer()
    print("\nTrustGraph Indexing Complete:")
    print(f"  Core 1 (Customer Environment): {stats['core_1_connectors']} entities")
    print(f"  Core 2 (Threat Intelligence):  {stats['core_2_threat_intel']} entities")
    print(f"  Core 3 (Compliance):           {stats['core_3_compliance']} entities")
    print(f"  Core 4 (Decision Memory):      {stats['core_4_decisions']} entities")
    print(f"  Core 5 (Competitive Intel):    {stats['core_5_competitive']} entities")
    print(f"  Cross-core relationships:      {stats['cross_core_relationships']}")
    print(f"  TOTAL: {stats['total']} entities + relationships")
