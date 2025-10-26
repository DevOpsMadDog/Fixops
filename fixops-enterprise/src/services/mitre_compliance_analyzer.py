"""
MITRE ATT&CK and Compliance Analysis Module
Provides enhanced security intelligence for decision engine

Feature Flags:
- ENABLE_MITRE_MAPPING (default: False)
- ENABLE_COMPLIANCE_ANALYSIS (default: False)
"""

from dataclasses import dataclass
from typing import Any, Dict, List

import structlog

logger = structlog.get_logger()


@dataclass
class MITRETechnique:
    """MITRE ATT&CK technique details"""

    id: str
    name: str
    tactic: str
    description: str
    business_impact: str
    common_vulnerabilities: List[str]


@dataclass
class ComplianceFramework:
    """Compliance framework details"""

    id: str
    name: str
    requirements: List[str]
    critical_areas: List[str]
    penalty_range: str


class MITREComplianceAnalyzer:
    """
    Enhanced security intelligence analyzer with MITRE ATT&CK mapping
    and compliance framework analysis

    Feature Flags:
    - mitre_enabled: Enable MITRE ATT&CK mapping
    - compliance_enabled: Enable compliance analysis
    """

    def __init__(self, mitre_enabled: bool = False, compliance_enabled: bool = False):
        """
        Initialize MITRE and compliance analyzer

        Args:
            mitre_enabled: Enable MITRE ATT&CK mapping
            compliance_enabled: Enable compliance analysis
        """
        self.mitre_enabled = mitre_enabled
        self.compliance_enabled = compliance_enabled

        self.mitre_techniques = {
            "T1190": MITRETechnique(
                id="T1190",
                name="Exploit Public-Facing Application",
                tactic="initial_access",
                description="Adversaries may attempt to take advantage of a weakness in an Internet-facing computer or program",
                business_impact="high",
                common_vulnerabilities=[
                    "sql_injection",
                    "xss",
                    "rce",
                    "path_traversal",
                ],
            ),
            "T1133": MITRETechnique(
                id="T1133",
                name="External Remote Services",
                tactic="initial_access",
                description="Adversaries may leverage external-facing remote services to initially access and/or persist within a network",
                business_impact="high",
                common_vulnerabilities=[
                    "vpn_vulnerabilities",
                    "rdp_exposure",
                    "ssh_weaknesses",
                ],
            ),
            "T1566": MITRETechnique(
                id="T1566",
                name="Phishing",
                tactic="initial_access",
                description="Adversaries may send phishing messages to gain access to victim systems",
                business_impact="high",
                common_vulnerabilities=[
                    "social_engineering",
                    "malicious_attachments",
                    "credential_harvesting",
                ],
            ),
            "T1189": MITRETechnique(
                id="T1189",
                name="Drive-by Compromise",
                tactic="initial_access",
                description="Adversaries may gain access to a system through a user visiting a website over the normal course of browsing",
                business_impact="medium",
                common_vulnerabilities=[
                    "browser_vulnerabilities",
                    "malicious_scripts",
                    "exploit_kits",
                ],
            ),
            "T1059": MITRETechnique(
                id="T1059",
                name="Command and Scripting Interpreter",
                tactic="execution",
                description="Adversaries may abuse command and script interpreters to execute commands, scripts, or binaries",
                business_impact="high",
                common_vulnerabilities=[
                    "command_injection",
                    "script_injection",
                    "shell_access",
                ],
            ),
            "T1203": MITRETechnique(
                id="T1203",
                name="Exploitation for Client Execution",
                tactic="execution",
                description="Adversaries may exploit software vulnerabilities in client applications to execute code",
                business_impact="high",
                common_vulnerabilities=[
                    "browser_exploits",
                    "office_exploits",
                    "pdf_exploits",
                ],
            ),
            "T1204": MITRETechnique(
                id="T1204",
                name="User Execution",
                tactic="execution",
                description="An adversary may rely upon specific actions by a user in order to gain execution",
                business_impact="medium",
                common_vulnerabilities=[
                    "malicious_files",
                    "social_engineering",
                    "user_interaction",
                ],
            ),
            "T1053": MITRETechnique(
                id="T1053",
                name="Scheduled Task/Job",
                tactic="persistence",
                description="Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code",
                business_impact="high",
                common_vulnerabilities=[
                    "cron_abuse",
                    "scheduled_task_hijacking",
                    "at_command_abuse",
                ],
            ),
            "T1078": MITRETechnique(
                id="T1078",
                name="Valid Accounts",
                tactic="persistence",
                description="Adversaries may obtain and abuse credentials of existing accounts",
                business_impact="critical",
                common_vulnerabilities=[
                    "auth_bypass",
                    "weak_passwords",
                    "credential_stuffing",
                ],
            ),
            "T1098": MITRETechnique(
                id="T1098",
                name="Account Manipulation",
                tactic="persistence",
                description="Adversaries may manipulate accounts to maintain access to victim systems",
                business_impact="high",
                common_vulnerabilities=[
                    "privilege_escalation",
                    "account_creation",
                    "permission_modification",
                ],
            ),
            "T1505": MITRETechnique(
                id="T1505",
                name="Server Software Component",
                tactic="persistence",
                description="Adversaries may abuse legitimate extensible development features of servers to establish persistent access",
                business_impact="critical",
                common_vulnerabilities=["web_shell", "backdoor", "malicious_plugin"],
            ),
            "T1068": MITRETechnique(
                id="T1068",
                name="Exploitation for Privilege Escalation",
                tactic="privilege_escalation",
                description="Adversaries may exploit software vulnerabilities in an attempt to elevate privileges",
                business_impact="critical",
                common_vulnerabilities=[
                    "kernel_exploits",
                    "privilege_escalation",
                    "local_exploits",
                ],
            ),
            "T1055": MITRETechnique(
                id="T1055",
                name="Process Injection",
                tactic="privilege_escalation",
                description="Adversaries may inject code into processes to evade process-based defenses",
                business_impact="high",
                common_vulnerabilities=[
                    "buffer_overflow",
                    "code_injection",
                    "dll_hijacking",
                ],
            ),
            "T1548": MITRETechnique(
                id="T1548",
                name="Abuse Elevation Control Mechanism",
                tactic="privilege_escalation",
                description="Adversaries may circumvent mechanisms designed to control elevate privileges to gain higher-level permissions",
                business_impact="high",
                common_vulnerabilities=[
                    "sudo_abuse",
                    "uac_bypass",
                    "setuid_exploitation",
                ],
            ),
            "T1027": MITRETechnique(
                id="T1027",
                name="Obfuscated Files or Information",
                tactic="defense_evasion",
                description="Adversaries may attempt to make an executable or file difficult to discover or analyze",
                business_impact="medium",
                common_vulnerabilities=["code_obfuscation", "encryption", "encoding"],
            ),
            "T1070": MITRETechnique(
                id="T1070",
                name="Indicator Removal",
                tactic="defense_evasion",
                description="Adversaries may delete or alter generated artifacts on a host system",
                business_impact="medium",
                common_vulnerabilities=[
                    "log_deletion",
                    "file_deletion",
                    "timestamp_manipulation",
                ],
            ),
            "T1562": MITRETechnique(
                id="T1562",
                name="Impair Defenses",
                tactic="defense_evasion",
                description="Adversaries may maliciously modify components of a victim environment to hinder or disable defensive mechanisms",
                business_impact="high",
                common_vulnerabilities=[
                    "antivirus_disable",
                    "firewall_disable",
                    "logging_disable",
                ],
            ),
            "T1003": MITRETechnique(
                id="T1003",
                name="OS Credential Dumping",
                tactic="credential_access",
                description="Adversaries may attempt to dump credentials to obtain account login information",
                business_impact="critical",
                common_vulnerabilities=[
                    "memory_disclosure",
                    "privilege_escalation",
                    "weak_encryption",
                ],
            ),
            "T1110": MITRETechnique(
                id="T1110",
                name="Brute Force",
                tactic="credential_access",
                description="Adversaries may use brute force techniques to gain access to accounts",
                business_impact="high",
                common_vulnerabilities=[
                    "weak_passwords",
                    "no_rate_limiting",
                    "default_credentials",
                ],
            ),
            "T1555": MITRETechnique(
                id="T1555",
                name="Credentials from Password Stores",
                tactic="credential_access",
                description="Adversaries may search for common password storage locations to obtain user credentials",
                business_impact="high",
                common_vulnerabilities=[
                    "password_manager_vulnerabilities",
                    "keychain_access",
                    "credential_storage",
                ],
            ),
            "T1056": MITRETechnique(
                id="T1056",
                name="Input Capture",
                tactic="credential_access",
                description="Adversaries may use methods of capturing user input to obtain credentials",
                business_impact="high",
                common_vulnerabilities=[
                    "keylogging",
                    "form_grabbing",
                    "credential_api_hooking",
                ],
            ),
            "T1083": MITRETechnique(
                id="T1083",
                name="File and Directory Discovery",
                tactic="discovery",
                description="Adversaries may enumerate files and directories or may search in specific locations",
                business_impact="low",
                common_vulnerabilities=[
                    "information_disclosure",
                    "directory_traversal",
                    "path_enumeration",
                ],
            ),
            "T1087": MITRETechnique(
                id="T1087",
                name="Account Discovery",
                tactic="discovery",
                description="Adversaries may attempt to get a listing of valid accounts",
                business_impact="medium",
                common_vulnerabilities=[
                    "user_enumeration",
                    "ldap_enumeration",
                    "api_enumeration",
                ],
            ),
            "T1046": MITRETechnique(
                id="T1046",
                name="Network Service Discovery",
                tactic="discovery",
                description="Adversaries may attempt to get a listing of services running on remote hosts",
                business_impact="medium",
                common_vulnerabilities=[
                    "port_scanning",
                    "service_enumeration",
                    "network_discovery",
                ],
            ),
            "T1021": MITRETechnique(
                id="T1021",
                name="Remote Services",
                tactic="lateral_movement",
                description="Adversaries may use valid accounts to log into a service specifically designed to accept remote connections",
                business_impact="high",
                common_vulnerabilities=["rdp_abuse", "ssh_abuse", "smb_abuse"],
            ),
            "T1210": MITRETechnique(
                id="T1210",
                name="Exploitation of Remote Services",
                tactic="lateral_movement",
                description="Adversaries may exploit remote services to gain unauthorized access to internal systems",
                business_impact="critical",
                common_vulnerabilities=[
                    "remote_code_execution",
                    "service_vulnerabilities",
                    "protocol_exploits",
                ],
            ),
            "T1005": MITRETechnique(
                id="T1005",
                name="Data from Local System",
                tactic="collection",
                description="Adversaries may search local system sources to find files of interest",
                business_impact="high",
                common_vulnerabilities=[
                    "sensitive_data_exposure",
                    "file_access",
                    "data_leakage",
                ],
            ),
            "T1213": MITRETechnique(
                id="T1213",
                name="Data from Information Repositories",
                tactic="collection",
                description="Adversaries may leverage information repositories to mine valuable information",
                business_impact="high",
                common_vulnerabilities=[
                    "database_access",
                    "api_abuse",
                    "repository_access",
                ],
            ),
            "T1071": MITRETechnique(
                id="T1071",
                name="Application Layer Protocol",
                tactic="command_and_control",
                description="Adversaries may communicate using application layer protocols to avoid detection",
                business_impact="medium",
                common_vulnerabilities=["http_c2", "dns_tunneling", "protocol_abuse"],
            ),
            "T1573": MITRETechnique(
                id="T1573",
                name="Encrypted Channel",
                tactic="command_and_control",
                description="Adversaries may employ a known encryption algorithm to conceal command and control traffic",
                business_impact="medium",
                common_vulnerabilities=[
                    "encrypted_communications",
                    "ssl_abuse",
                    "custom_encryption",
                ],
            ),
            "T1041": MITRETechnique(
                id="T1041",
                name="Exfiltration Over C2 Channel",
                tactic="exfiltration",
                description="Adversaries may steal data by exfiltrating it over an existing command and control channel",
                business_impact="critical",
                common_vulnerabilities=[
                    "data_exfiltration",
                    "c2_channel",
                    "data_theft",
                ],
            ),
            "T1567": MITRETechnique(
                id="T1567",
                name="Exfiltration Over Web Service",
                tactic="exfiltration",
                description="Adversaries may use an existing, legitimate external Web service to exfiltrate data",
                business_impact="high",
                common_vulnerabilities=[
                    "cloud_storage_abuse",
                    "web_service_abuse",
                    "data_upload",
                ],
            ),
            "T1486": MITRETechnique(
                id="T1486",
                name="Data Encrypted for Impact",
                tactic="impact",
                description="Adversaries may encrypt data on target systems to interrupt availability",
                business_impact="critical",
                common_vulnerabilities=["ransomware", "encryption", "data_destruction"],
            ),
            "T1498": MITRETechnique(
                id="T1498",
                name="Network Denial of Service",
                tactic="impact",
                description="Adversaries may perform Network Denial of Service attacks to degrade or block availability",
                business_impact="high",
                common_vulnerabilities=["ddos", "dos", "network_flooding"],
            ),
            "T1565": MITRETechnique(
                id="T1565",
                name="Data Manipulation",
                tactic="impact",
                description="Adversaries may insert, delete, or manipulate data to influence external outcomes",
                business_impact="critical",
                common_vulnerabilities=[
                    "data_tampering",
                    "integrity_violation",
                    "data_corruption",
                ],
            ),
        }

        self.compliance_frameworks = {
            "pci_dss": ComplianceFramework(
                id="pci_dss",
                name="Payment Card Industry Data Security Standard",
                requirements=[
                    "1",
                    "2",
                    "3",
                    "4",
                    "5",
                    "6",
                    "7",
                    "8",
                    "9",
                    "10",
                    "11",
                    "12",
                ],
                critical_areas=[
                    "network_security",
                    "data_protection",
                    "vulnerability_management",
                ],
                penalty_range="$5K-$100K per month",
            ),
            "sox": ComplianceFramework(
                id="sox",
                name="Sarbanes-Oxley Act",
                requirements=["302", "404", "906"],
                critical_areas=[
                    "financial_controls",
                    "audit_trails",
                    "change_management",
                ],
                penalty_range="$10M+ fines, criminal charges",
            ),
            "hipaa": ComplianceFramework(
                id="hipaa",
                name="Health Insurance Portability and Accountability Act",
                requirements=["administrative", "physical", "technical"],
                critical_areas=["phi_protection", "access_controls", "encryption"],
                penalty_range="$100-$50K per violation",
            ),
            "nist_ssdf": ComplianceFramework(
                id="nist_ssdf",
                name="NIST Secure Software Development Framework",
                requirements=["PO", "PS", "PW", "RV"],
                critical_areas=[
                    "secure_design",
                    "secure_implementation",
                    "verification",
                ],
                penalty_range="Varies by sector",
            ),
        }

        if self.mitre_enabled:
            logger.info("MITRE ATT&CK mapping enabled")
        else:
            logger.info(
                "MITRE ATT&CK mapping disabled (set ENABLE_MITRE_MAPPING=true to enable)"
            )

        if self.compliance_enabled:
            logger.info("Compliance analysis enabled")
        else:
            logger.info(
                "Compliance analysis disabled (set ENABLE_COMPLIANCE_ANALYSIS=true to enable)"
            )

    def analyze_mitre(self, security_findings: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Perform MITRE ATT&CK analysis on security findings

        Args:
            security_findings: List of security findings

        Returns:
            MITRE analysis results
        """
        if not self.mitre_enabled:
            return {"enabled": False, "message": "MITRE mapping disabled"}

        # Map findings to MITRE techniques
        technique_mappings = []

        for finding in security_findings:
            finding_title = finding.get("title", "").lower()
            finding_type = finding.get("category", "").lower()
            severity = finding.get("severity", "medium")

            # Enhanced mapping logic
            mapped_techniques = []

            if "injection" in finding_title or finding_type == "injection":
                mapped_techniques.append("T1190")  # Exploit Public-Facing Application

            if "auth" in finding_title or finding_type == "authentication":
                mapped_techniques.append("T1078")  # Valid Accounts

            if "credential" in finding_title or "password" in finding_title:
                mapped_techniques.append("T1003")  # OS Credential Dumping

            if severity == "critical" and any(
                vuln in finding_title for vuln in ["buffer", "overflow", "injection"]
            ):
                mapped_techniques.append("T1055")  # Process Injection

            if mapped_techniques:
                technique_mappings.append(
                    {
                        "finding": finding.get("title", "Unknown"),
                        "severity": severity,
                        "mitre_techniques": mapped_techniques,
                        "technique_details": [
                            {
                                "id": tech_id,
                                "name": self.mitre_techniques[tech_id].name,
                                "tactic": self.mitre_techniques[tech_id].tactic,
                                "business_impact": self.mitre_techniques[
                                    tech_id
                                ].business_impact,
                            }
                            for tech_id in mapped_techniques
                        ],
                    }
                )

        # Calculate attack chain severity
        unique_techniques = set()
        for mapping in technique_mappings:
            unique_techniques.update(mapping["mitre_techniques"])

        attack_chain_severity = "low"
        if len(unique_techniques) >= 3:
            attack_chain_severity = "critical"
        elif len(unique_techniques) >= 2:
            attack_chain_severity = "high"
        elif len(unique_techniques) >= 1:
            attack_chain_severity = "medium"

        risk_amplification = self._calculate_risk_amplification(list(unique_techniques))

        return {
            "enabled": True,
            "techniques_identified": list(unique_techniques),
            "technique_mappings": technique_mappings,
            "attack_chain_severity": attack_chain_severity,
            "attack_path_analysis": {
                "initial_access_vectors": len(
                    [t for t in unique_techniques if t in ["T1190", "T1078"]]
                ),
                "privilege_escalation_potential": len(
                    [t for t in unique_techniques if t in ["T1055", "T1003"]]
                ),
                "persistence_mechanisms": 0,  # Would be enhanced with more techniques
                "data_exfiltration_risk": (
                    "high" if "T1190" in unique_techniques else "medium"
                ),
            },
            "business_risk_amplification": risk_amplification,
        }

    def analyze_compliance(
        self,
        security_findings: List[Dict[str, Any]],
        compliance_requirements: List[str],
    ) -> Dict[str, Any]:
        """
        Perform compliance analysis on security findings

        Args:
            security_findings: List of security findings
            compliance_requirements: List of compliance framework IDs

        Returns:
            Compliance analysis results
        """
        if not self.compliance_enabled:
            return {"enabled": False, "message": "Compliance analysis disabled"}

        compliance_status = {}

        for framework_id in compliance_requirements:
            if framework_id in self.compliance_frameworks:
                framework = self.compliance_frameworks[framework_id]

                # Analyze findings against framework
                violations = []
                for finding in security_findings:
                    if finding.get("severity") == "critical":
                        violations.append(
                            {
                                "finding": finding.get("title", "Unknown"),
                                "framework_impact": framework.critical_areas,
                                "potential_penalty": framework.penalty_range,
                            }
                        )

                compliance_status[framework_id] = {
                    "framework_name": framework.name,
                    "status": "non_compliant" if violations else "compliant",
                    "violations": violations,
                    "critical_areas_affected": framework.critical_areas,
                    "potential_penalties": (
                        framework.penalty_range if violations else "None"
                    ),
                }

        overall_compliant = all(
            status["status"] == "compliant" for status in compliance_status.values()
        )

        return {
            "enabled": True,
            "frameworks_analyzed": compliance_requirements,
            "compliance_status": compliance_status,
            "overall_compliance": "compliant" if overall_compliant else "non_compliant",
            "compliance_score": (
                len(
                    [
                        s
                        for s in compliance_status.values()
                        if s["status"] == "compliant"
                    ]
                )
                / len(compliance_status)
                if compliance_status
                else 1.0
            ),
        }

    def _calculate_risk_amplification(self, techniques: List[str]) -> Dict[str, Any]:
        """
        Calculate business risk amplification based on MITRE techniques

        Args:
            techniques: List of MITRE technique IDs

        Returns:
            Risk amplification details
        """
        amplification_factor = 1.0
        risk_categories = []

        for technique_id in techniques:
            if technique_id in self.mitre_techniques:
                technique = self.mitre_techniques[technique_id]
                if technique.business_impact == "critical":
                    amplification_factor *= 2.0
                    risk_categories.append("critical_system_compromise")
                elif technique.business_impact == "high":
                    amplification_factor *= 1.5
                    risk_categories.append("significant_system_impact")

        return {
            "amplification_factor": min(amplification_factor, 5.0),  # Cap at 5x
            "risk_categories": list(set(risk_categories)),
            "explanation": f"Risk amplified {amplification_factor:.1f}x due to {len(techniques)} MITRE techniques",
        }

    def get_stats(self) -> Dict[str, Any]:
        """Get analyzer statistics"""
        return {
            "mitre_enabled": self.mitre_enabled,
            "compliance_enabled": self.compliance_enabled,
            "mitre_techniques_count": len(self.mitre_techniques),
            "compliance_frameworks_count": len(self.compliance_frameworks),
            "supported_frameworks": list(self.compliance_frameworks.keys()),
        }


_analyzer = None


def get_mitre_compliance_analyzer(
    mitre_enabled: bool = False, compliance_enabled: bool = False
) -> MITREComplianceAnalyzer:
    """
    Get or create global MITRE compliance analyzer instance

    Args:
        mitre_enabled: Enable MITRE ATT&CK mapping
        compliance_enabled: Enable compliance analysis

    Returns:
        MITREComplianceAnalyzer instance
    """
    global _analyzer
    if _analyzer is None:
        _analyzer = MITREComplianceAnalyzer(
            mitre_enabled=mitre_enabled, compliance_enabled=compliance_enabled
        )
    return _analyzer
