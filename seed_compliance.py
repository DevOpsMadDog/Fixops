"""
Seed compliance framework data into the ALdeci FixOps platform.

This script populates the compliance_frameworks and compliance_controls tables
in data/audit.db so that GET /api/v1/audit/compliance/frameworks returns real data.

Frameworks seeded:
  - SOC2 (22 controls)
  - PCI_DSS_4.0 (22 controls)
  - ISO_27001_2022 (20 controls)
  - NIST_800_53_R5 (28 controls)
  - NIST_CSF_2.0 (6 functions / controls)
  - OWASP_ASVS_4.0 (14 chapters / controls)

Run from the Fixops root directory:
    python3 seed_compliance.py

Auth header for API verification: X-API-Key: $FIXOPS_API_TOKEN
"""

from __future__ import annotations

import json
import os
import sqlite3
import sys
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

DB_PATH = Path(__file__).parent / "data" / "audit.db"
NOW = datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Framework + Control Definitions (sourced from compliance_engine.py)
# ---------------------------------------------------------------------------

FRAMEWORKS: List[Dict[str, Any]] = [
    {
        "id": str(uuid.uuid5(uuid.NAMESPACE_DNS, "fixops.soc2")),
        "name": "SOC2",
        "version": "Type II",
        "description": (
            "SOC 2 Type II — Trust Services Criteria covering Security, Availability, "
            "Processing Integrity, Confidentiality, and Privacy (AICPA TSC 2017)."
        ),
        "metadata": {
            "issuer": "AICPA",
            "year": 2017,
            "categories": ["CC1", "CC2", "CC3", "CC4", "CC5", "CC6", "CC7", "CC8", "CC9"],
        },
    },
    {
        "id": str(uuid.uuid5(uuid.NAMESPACE_DNS, "fixops.pci_dss_4.0")),
        "name": "PCI_DSS_4.0",
        "version": "4.0",
        "description": (
            "Payment Card Industry Data Security Standard v4.0 — 12 requirements "
            "for protecting cardholder data across storage, processing, and transmission."
        ),
        "metadata": {
            "issuer": "PCI Security Standards Council",
            "year": 2022,
            "requirements": 12,
        },
    },
    {
        "id": str(uuid.uuid5(uuid.NAMESPACE_DNS, "fixops.iso_27001_2022")),
        "name": "ISO_27001_2022",
        "version": "2022",
        "description": (
            "ISO/IEC 27001:2022 — International standard for information security "
            "management systems (ISMS) with 93 controls across 4 themes."
        ),
        "metadata": {
            "issuer": "ISO/IEC",
            "year": 2022,
            "themes": ["Organizational", "People", "Physical", "Technological"],
            "total_controls": 93,
        },
    },
    {
        "id": str(uuid.uuid5(uuid.NAMESPACE_DNS, "fixops.nist_800_53_r5")),
        "name": "NIST_800_53_R5",
        "version": "Rev 5",
        "description": (
            "NIST Special Publication 800-53 Rev 5 — Security and privacy controls "
            "for federal information systems across 20 control families."
        ),
        "metadata": {
            "issuer": "NIST",
            "year": 2020,
            "control_families": 20,
        },
    },
    {
        "id": str(uuid.uuid5(uuid.NAMESPACE_DNS, "fixops.nist_csf_2.0")),
        "name": "NIST_CSF_2.0",
        "version": "2.0",
        "description": (
            "NIST Cybersecurity Framework 2.0 — Six functions (Govern, Identify, "
            "Protect, Detect, Respond, Recover) for managing cybersecurity risk."
        ),
        "metadata": {
            "issuer": "NIST",
            "year": 2024,
            "functions": ["GV", "ID", "PR", "DE", "RS", "RC"],
        },
    },
    {
        "id": str(uuid.uuid5(uuid.NAMESPACE_DNS, "fixops.owasp_asvs_4.0")),
        "name": "OWASP_ASVS_4.0",
        "version": "4.0",
        "description": (
            "OWASP Application Security Verification Standard 4.0 — 14 chapters "
            "of security requirements for web application design and development."
        ),
        "metadata": {
            "issuer": "OWASP",
            "year": 2019,
            "chapters": 14,
            "levels": ["L1", "L2", "L3"],
        },
    },
]

# Framework name → ID lookup (built from FRAMEWORKS list)
FW_ID = {fw["name"]: fw["id"] for fw in FRAMEWORKS}


# ---------------------------------------------------------------------------
# Controls per framework
# ---------------------------------------------------------------------------

SOC2_CONTROLS: List[Dict[str, Any]] = [
    {"control_id": "CC1.1", "name": "COSO Principle 1 — Integrity & Ethics",          "category": "CC1", "requirements": ["Demonstrate commitment to integrity and ethical values"],                         "metadata": {"automated": False, "evidence": ["policy_check", "training_record"]}},
    {"control_id": "CC1.2", "name": "Board Independence & Oversight",                   "category": "CC1", "requirements": ["Board exercises oversight of the development and performance of internal control"],  "metadata": {"automated": False, "evidence": ["policy_check"]}},
    {"control_id": "CC2.1", "name": "Information Quality Objectives",                   "category": "CC2", "requirements": ["Obtain, generate, and use quality information to support control functions"],        "metadata": {"automated": False, "evidence": ["policy_check"]}},
    {"control_id": "CC3.1", "name": "Risk Assessment Process",                          "category": "CC3", "requirements": ["Specify objectives with clarity to enable risk identification and assessment"],       "metadata": {"automated": True,  "evidence": ["risk_assessment"]}},
    {"control_id": "CC3.2", "name": "Fraud Risk Assessment",                            "category": "CC3", "requirements": ["Assess risks of fraud, including fraudulent reporting and misappropriation"],        "metadata": {"automated": True,  "evidence": ["risk_assessment"]}},
    {"control_id": "CC3.4", "name": "Technology Change Risk",                           "category": "CC3", "requirements": ["Assess changes to technology that impact information processing objectives"],         "metadata": {"automated": True,  "evidence": ["change_record", "risk_assessment"], "cwes": ["CWE-1104"]}},
    {"control_id": "CC4.1", "name": "Ongoing Monitoring",                               "category": "CC4", "requirements": ["Select, develop, and perform ongoing and separate evaluations"],                      "metadata": {"automated": True,  "evidence": ["scan_result", "config_audit"]}},
    {"control_id": "CC4.2", "name": "Deficiency Communication",                         "category": "CC4", "requirements": ["Evaluate and communicate deficiencies in a timely manner"],                          "metadata": {"automated": True,  "evidence": ["incident_response"]}},
    {"control_id": "CC5.1", "name": "Control Activities for Risk Mitigation",           "category": "CC5", "requirements": ["Select and develop control activities to mitigate risks"],                           "metadata": {"automated": True,  "evidence": ["policy_check"]}},
    {"control_id": "CC5.2", "name": "Technology General Controls",                      "category": "CC5", "requirements": ["Select and develop general control activities over technology"],                       "metadata": {"automated": True,  "evidence": ["config_audit", "scan_result"], "cwes": ["CWE-693"]}},
    {"control_id": "CC6.1", "name": "Logical Access Security",                          "category": "CC6", "requirements": ["Implement logical access security measures to protect against unauthorized access"],    "metadata": {"automated": True,  "evidence": ["access_review", "config_audit"], "cwes": ["CWE-287", "CWE-306", "CWE-862"]}},
    {"control_id": "CC6.2", "name": "User Provisioning",                                "category": "CC6", "requirements": ["Register and authorize new users, and maintain user access credentials"],              "metadata": {"automated": True,  "evidence": ["access_review"], "cwes": ["CWE-269", "CWE-732"]}},
    {"control_id": "CC6.3", "name": "Access Termination",                               "category": "CC6", "requirements": ["Remove access credentials when access is no longer required"],                        "metadata": {"automated": True,  "evidence": ["access_review"], "cwes": ["CWE-269"]}},
    {"control_id": "CC6.6", "name": "System Boundary Protection",                       "category": "CC6", "requirements": ["Implement controls to prevent or detect and act on unauthorized access"],              "metadata": {"automated": True,  "evidence": ["config_audit", "scan_result"], "cwes": ["CWE-284", "CWE-918"]}},
    {"control_id": "CC6.7", "name": "Data Transmission Restriction",                    "category": "CC6", "requirements": ["Restrict transmission of data to authorized parties"],                                "metadata": {"automated": True,  "evidence": ["config_audit"], "cwes": ["CWE-319", "CWE-311"]}},
    {"control_id": "CC6.8", "name": "Unauthorized Software Prevention",                 "category": "CC6", "requirements": ["Prevent or detect unauthorized or malicious software"],                               "metadata": {"automated": True,  "evidence": ["scan_result"], "cwes": ["CWE-829", "CWE-506"]}},
    {"control_id": "CC7.1", "name": "Configuration Change Detection",                   "category": "CC7", "requirements": ["Detect and respond to changes in the configuration of infrastructure components"],    "metadata": {"automated": True,  "evidence": ["config_audit", "change_record"], "cwes": ["CWE-1104"]}},
    {"control_id": "CC7.2", "name": "Anomaly Monitoring",                               "category": "CC7", "requirements": ["Monitor system components for anomalies that indicate malicious acts"],               "metadata": {"automated": True,  "evidence": ["scan_result"]}},
    {"control_id": "CC7.3", "name": "Security Event Evaluation",                        "category": "CC7", "requirements": ["Evaluate security events to determine whether they could or have resulted in failure"], "metadata": {"automated": True,  "evidence": ["incident_response"]}},
    {"control_id": "CC7.4", "name": "Incident Response",                                "category": "CC7", "requirements": ["Respond to identified security incidents by executing a defined incident-response"],   "metadata": {"automated": True,  "evidence": ["incident_response"]}},
    {"control_id": "CC8.1", "name": "Change Management",                                "category": "CC8", "requirements": ["Authorize, design, develop, acquire, implement, operate, approve changes"],            "metadata": {"automated": True,  "evidence": ["change_record", "code_review"], "cwes": ["CWE-1104"]}},
    {"control_id": "CC9.1", "name": "Risk Mitigation Activities",                       "category": "CC9", "requirements": ["Identify, select, and develop risk mitigation activities"],                           "metadata": {"automated": True,  "evidence": ["risk_assessment"]}},
]

PCI_DSS_CONTROLS: List[Dict[str, Any]] = [
    {"control_id": "1.1",  "name": "Install & Maintain Network Security Controls",     "category": "Req1",  "requirements": ["Install and maintain network security controls", "Justify all services, protocols, and ports allowed"], "metadata": {"automated": True,  "cwes": ["CWE-284"]}},
    {"control_id": "2.1",  "name": "Secure System Configurations",                     "category": "Req2",  "requirements": ["Configuration standards for all system components", "Default passwords changed before deployment"],        "metadata": {"automated": True,  "cwes": ["CWE-1188", "CWE-16"]}},
    {"control_id": "2.2",  "name": "System Hardening Standards",                       "category": "Req2",  "requirements": ["Implement system hardening standards", "Enable only necessary services and functions"],               "metadata": {"automated": True,  "cwes": ["CWE-16", "CWE-1188"]}},
    {"control_id": "3.1",  "name": "Account Data Retention Policy",                    "category": "Req3",  "requirements": ["Establish data retention and disposal policies", "Limit cardholder data storage to minimum necessary"],  "metadata": {"automated": True,  "cwes": ["CWE-312", "CWE-311"]}},
    {"control_id": "3.5",  "name": "Primary Account Number Protection",                "category": "Req3",  "requirements": ["PAN must be secured with strong cryptography if stored", "Mask PAN when displayed"],                    "metadata": {"automated": True,  "cwes": ["CWE-312", "CWE-327"]}},
    {"control_id": "4.1",  "name": "Strong Cryptography for Transmission",             "category": "Req4",  "requirements": ["Use strong cryptography for transmission over open networks", "Never send unprotected PANs"],             "metadata": {"automated": True,  "cwes": ["CWE-319", "CWE-327"]}},
    {"control_id": "5.1",  "name": "Anti-Malware Protection",                          "category": "Req5",  "requirements": ["Deploy anti-malware on all applicable systems", "Ensure anti-malware software is active and current"],   "metadata": {"automated": True,  "cwes": ["CWE-506"]}},
    {"control_id": "5.2",  "name": "Malware Prevention Mechanisms",                    "category": "Req5",  "requirements": ["Anti-malware mechanisms are kept current", "Phishing protection enabled"],                            "metadata": {"automated": True,  "cwes": ["CWE-506", "CWE-829"]}},
    {"control_id": "6.1",  "name": "Vulnerability Identification",                     "category": "Req6",  "requirements": ["Identify security vulnerabilities in all software", "Protect software from known vulnerabilities"],       "metadata": {"automated": True}},
    {"control_id": "6.2",  "name": "Bespoke & Custom Software Security",               "category": "Req6",  "requirements": ["Manage bespoke and custom software securely", "Prevent common software attacks (SQLi, XSS, etc.)"],     "metadata": {"automated": True,  "cwes": ["CWE-89", "CWE-79", "CWE-78", "CWE-502"]}},
    {"control_id": "6.3",  "name": "Security Vulnerabilities Addressed",               "category": "Req6",  "requirements": ["Remediate security vulnerabilities", "Assign risk ranking to vulnerabilities"],                        "metadata": {"automated": True}},
    {"control_id": "6.4",  "name": "Web Application Firewall",                         "category": "Req6",  "requirements": ["Deploy a web application firewall for public-facing web applications", "Review WAF rules regularly"],    "metadata": {"automated": True,  "cwes": ["CWE-79", "CWE-89"]}},
    {"control_id": "6.5",  "name": "Change Management for Code",                       "category": "Req6",  "requirements": ["Protect all components from misuse via change management processes"],                                  "metadata": {"automated": True,  "cwes": ["CWE-1104"]}},
    {"control_id": "7.1",  "name": "Restrict Access by Business Need",                 "category": "Req7",  "requirements": ["Limit access to system components to only those with business need to know"],                          "metadata": {"automated": True,  "cwes": ["CWE-269", "CWE-862"]}},
    {"control_id": "8.1",  "name": "User Identification & Authentication",             "category": "Req8",  "requirements": ["Define and implement policies for user identification and authentication"],                             "metadata": {"automated": True,  "cwes": ["CWE-287", "CWE-798"]}},
    {"control_id": "8.3",  "name": "MFA Implementation",                               "category": "Req8",  "requirements": ["Implement MFA for all non-console access to the CDE", "MFA for remote access"],                        "metadata": {"automated": True,  "cwes": ["CWE-287", "CWE-306"]}},
    {"control_id": "10.1", "name": "Audit Logging",                                    "category": "Req10", "requirements": ["Log all individual access to system components", "Protect audit logs from destruction"],               "metadata": {"automated": True,  "cwes": ["CWE-778"]}},
    {"control_id": "10.2", "name": "Audit Log Content",                                "category": "Req10", "requirements": ["Capture all required information in audit logs", "Retain audit logs for at least 12 months"],          "metadata": {"automated": True,  "cwes": ["CWE-778", "CWE-117"]}},
    {"control_id": "11.1", "name": "Wireless Access Point Testing",                    "category": "Req11", "requirements": ["Test for the presence of unauthorized wireless access points quarterly"],                              "metadata": {"automated": False}},
    {"control_id": "11.3", "name": "Vulnerability Scanning",                           "category": "Req11", "requirements": ["Run internal and external vulnerability scans at least quarterly"],                                    "metadata": {"automated": True}},
    {"control_id": "11.4", "name": "Penetration Testing",                              "category": "Req11", "requirements": ["Perform penetration testing at least annually", "Remediate exploitable vulnerabilities"],              "metadata": {"automated": True}},
    {"control_id": "12.1", "name": "Information Security Policy",                      "category": "Req12", "requirements": ["Establish, publish, maintain, and disseminate a security policy"],                                    "metadata": {"automated": False}},
]

ISO_27001_CONTROLS: List[Dict[str, Any]] = [
    {"control_id": "A.5.1",  "name": "Policies for Information Security",           "category": "Organizational", "requirements": ["Define, approve, and publish information security policies"],                                          "metadata": {"automated": False}},
    {"control_id": "A.5.2",  "name": "Information Security Roles",                  "category": "Organizational", "requirements": ["Define and assign information security responsibilities"],                                             "metadata": {"automated": False}},
    {"control_id": "A.6.1",  "name": "Screening",                                   "category": "People",         "requirements": ["Carry out background verification checks on candidates before employment"],                            "metadata": {"automated": False}},
    {"control_id": "A.6.3",  "name": "Information Security Awareness & Training",   "category": "People",         "requirements": ["Provide security awareness education and training to all personnel"],                                  "metadata": {"automated": False}},
    {"control_id": "A.7.1",  "name": "Physical Security Perimeters",                "category": "Physical",       "requirements": ["Define and use physical security perimeters to protect sensitive areas"],                             "metadata": {"automated": False}},
    {"control_id": "A.8.1",  "name": "User Endpoint Devices",                       "category": "Technological",  "requirements": ["Protect information stored on, processed by, or accessible via user endpoint devices"],              "metadata": {"automated": True}},
    {"control_id": "A.8.2",  "name": "Privileged Access Rights",                    "category": "Technological",  "requirements": ["Restrict and manage the allocation and use of privileged access rights"],                             "metadata": {"automated": True,  "cwes": ["CWE-269", "CWE-250"]}},
    {"control_id": "A.8.3",  "name": "Information Access Restriction",              "category": "Technological",  "requirements": ["Restrict access to information and application systems in accordance with policies"],                  "metadata": {"automated": True,  "cwes": ["CWE-862", "CWE-863"]}},
    {"control_id": "A.8.5",  "name": "Secure Authentication",                       "category": "Technological",  "requirements": ["Implement secure authentication technologies and procedures"],                                         "metadata": {"automated": True,  "cwes": ["CWE-287", "CWE-521"]}},
    {"control_id": "A.8.7",  "name": "Protection Against Malware",                  "category": "Technological",  "requirements": ["Implement controls for protection against malware, supported by user awareness training"],            "metadata": {"automated": True,  "cwes": ["CWE-506"]}},
    {"control_id": "A.8.8",  "name": "Management of Technical Vulnerabilities",     "category": "Technological",  "requirements": ["Obtain timely information about vulnerabilities; evaluate exposure; take appropriate measures"],       "metadata": {"automated": True}},
    {"control_id": "A.8.9",  "name": "Configuration Management",                    "category": "Technological",  "requirements": ["Establish, document, implement, monitor, and review configurations"],                                 "metadata": {"automated": True,  "cwes": ["CWE-16", "CWE-1188"]}},
    {"control_id": "A.8.12", "name": "Data Leakage Prevention",                     "category": "Technological",  "requirements": ["Apply data leakage prevention measures to systems and networks"],                                    "metadata": {"automated": True,  "cwes": ["CWE-200", "CWE-209"]}},
    {"control_id": "A.8.15", "name": "Logging",                                     "category": "Technological",  "requirements": ["Produce, store, protect, and analyse logs that record activities, exceptions, and events"],           "metadata": {"automated": True,  "cwes": ["CWE-778"]}},
    {"control_id": "A.8.16", "name": "Monitoring Activities",                       "category": "Technological",  "requirements": ["Monitor networks, systems, and applications and analyse for anomalous behaviour"],                    "metadata": {"automated": True}},
    {"control_id": "A.8.20", "name": "Networks Security",                           "category": "Technological",  "requirements": ["Secure, manage, and control the network to protect information in systems"],                         "metadata": {"automated": True,  "cwes": ["CWE-284"]}},
    {"control_id": "A.8.24", "name": "Use of Cryptography",                         "category": "Technological",  "requirements": ["Define and implement rules for effective use of cryptography, including key management"],             "metadata": {"automated": True,  "cwes": ["CWE-327", "CWE-326"]}},
    {"control_id": "A.8.25", "name": "Secure Development Life Cycle",               "category": "Technological",  "requirements": ["Establish and apply rules for the secure development of software and systems"],                       "metadata": {"automated": True}},
    {"control_id": "A.8.26", "name": "Application Security Requirements",           "category": "Technological",  "requirements": ["Identify, specify, and approve information security requirements for application development"],        "metadata": {"automated": True,  "cwes": ["CWE-89", "CWE-79"]}},
    {"control_id": "A.8.28", "name": "Secure Coding",                               "category": "Technological",  "requirements": ["Apply secure coding principles to software development"],                                            "metadata": {"automated": True,  "cwes": ["CWE-89", "CWE-79", "CWE-78", "CWE-502", "CWE-22"]}},
    {"control_id": "A.8.29", "name": "Security Testing in Development",             "category": "Technological",  "requirements": ["Implement security testing processes throughout the development lifecycle"],                           "metadata": {"automated": True}},
]

NIST_800_53_CONTROLS: List[Dict[str, Any]] = [
    {"control_id": "AC-2",  "name": "Account Management",                           "category": "AC", "requirements": ["Identify and select account types; establish conditions for group and role membership"],   "metadata": {"automated": True,  "cwes": ["CWE-269", "CWE-732"]}},
    {"control_id": "AC-3",  "name": "Access Enforcement",                           "category": "AC", "requirements": ["Enforce approved authorizations for logical access to information and system resources"],   "metadata": {"automated": True,  "cwes": ["CWE-862", "CWE-863"]}},
    {"control_id": "AC-6",  "name": "Least Privilege",                              "category": "AC", "requirements": ["Employ the principle of least privilege, allowing only authorized accesses"],               "metadata": {"automated": True,  "cwes": ["CWE-269", "CWE-250"]}},
    {"control_id": "AC-7",  "name": "Unsuccessful Login Attempts",                  "category": "AC", "requirements": ["Enforce a limit of consecutive invalid login attempts; lock account when exceeded"],       "metadata": {"automated": True,  "cwes": ["CWE-307"]}},
    {"control_id": "AT-1",  "name": "Security Awareness Training",                  "category": "AT", "requirements": ["Develop, document, and disseminate security awareness and training policies"],               "metadata": {"automated": False}},
    {"control_id": "AU-2",  "name": "Event Logging",                                "category": "AU", "requirements": ["Identify the types of events that the system is capable of logging"],                       "metadata": {"automated": True,  "cwes": ["CWE-778"]}},
    {"control_id": "AU-3",  "name": "Content of Audit Records",                     "category": "AU", "requirements": ["Produce audit records containing sufficient information to establish what type of event"],  "metadata": {"automated": True,  "cwes": ["CWE-778", "CWE-117"]}},
    {"control_id": "AU-6",  "name": "Audit Record Review & Analysis",               "category": "AU", "requirements": ["Review and analyse system audit records for indications of inappropriate or unusual activity"], "metadata": {"automated": True}},
    {"control_id": "CA-2",  "name": "Control Assessments",                          "category": "CA", "requirements": ["Select an appropriate assessor; assess controls at defined frequency"],                      "metadata": {"automated": True}},
    {"control_id": "CA-7",  "name": "Continuous Monitoring",                        "category": "CA", "requirements": ["Develop a continuous monitoring strategy; monitor controls at defined frequency"],          "metadata": {"automated": True}},
    {"control_id": "CM-2",  "name": "Baseline Configuration",                       "category": "CM", "requirements": ["Develop, document, and maintain a current baseline configuration of the system"],           "metadata": {"automated": True,  "cwes": ["CWE-16", "CWE-1188"]}},
    {"control_id": "CM-6",  "name": "Configuration Settings",                       "category": "CM", "requirements": ["Establish and document configuration settings for technology products within the system"],   "metadata": {"automated": True,  "cwes": ["CWE-16"]}},
    {"control_id": "CM-7",  "name": "Least Functionality",                          "category": "CM", "requirements": ["Configure the system to provide only essential capabilities"],                              "metadata": {"automated": True,  "cwes": ["CWE-1188"]}},
    {"control_id": "IA-2",  "name": "Identification & Authentication",              "category": "IA", "requirements": ["Uniquely identify and authenticate organizational users"],                                  "metadata": {"automated": True,  "cwes": ["CWE-287", "CWE-306"]}},
    {"control_id": "IA-5",  "name": "Authenticator Management",                     "category": "IA", "requirements": ["Manage information system authenticators by verifying identity of individuals"],            "metadata": {"automated": True,  "cwes": ["CWE-798", "CWE-521"]}},
    {"control_id": "IR-4",  "name": "Incident Handling",                            "category": "IR", "requirements": ["Implement an incident handling capability including preparation, detection, and recovery"],  "metadata": {"automated": True}},
    {"control_id": "IR-5",  "name": "Incident Monitoring",                          "category": "IR", "requirements": ["Track and document information system security incidents"],                                  "metadata": {"automated": True}},
    {"control_id": "RA-3",  "name": "Risk Assessment",                              "category": "RA", "requirements": ["Conduct a risk assessment; document results; review at defined frequency"],                 "metadata": {"automated": True}},
    {"control_id": "RA-5",  "name": "Vulnerability Monitoring & Scanning",          "category": "RA", "requirements": ["Monitor and scan for vulnerabilities in the information system and applications"],           "metadata": {"automated": True}},
    {"control_id": "SA-11", "name": "Developer Testing & Evaluation",               "category": "SA", "requirements": ["Require developer to perform security testing and evaluation"],                              "metadata": {"automated": True,  "cwes": ["CWE-89", "CWE-79", "CWE-78"]}},
    {"control_id": "SA-15", "name": "Development Process & Standards",              "category": "SA", "requirements": ["Require developer to follow a documented development process"],                              "metadata": {"automated": True}},
    {"control_id": "SC-7",  "name": "Boundary Protection",                          "category": "SC", "requirements": ["Monitor and control communications at the external boundary of the system"],                "metadata": {"automated": True,  "cwes": ["CWE-284", "CWE-918"]}},
    {"control_id": "SC-8",  "name": "Transmission Confidentiality",                 "category": "SC", "requirements": ["Implement cryptographic mechanisms to prevent unauthorized disclosure of information"],     "metadata": {"automated": True,  "cwes": ["CWE-319"]}},
    {"control_id": "SC-12", "name": "Cryptographic Key Management",                 "category": "SC", "requirements": ["Establish and manage cryptographic keys when cryptography is employed"],                   "metadata": {"automated": True,  "cwes": ["CWE-320", "CWE-327"]}},
    {"control_id": "SC-13", "name": "Cryptographic Protection",                     "category": "SC", "requirements": ["Implement cryptographic uses and types of cryptography required"],                         "metadata": {"automated": True,  "cwes": ["CWE-327", "CWE-326"]}},
    {"control_id": "SC-28", "name": "Protection of Information at Rest",            "category": "SC", "requirements": ["Implement cryptographic mechanisms to prevent unauthorized disclosure of CUI at rest"],     "metadata": {"automated": True,  "cwes": ["CWE-312", "CWE-311"]}},
    {"control_id": "SI-2",  "name": "Flaw Remediation",                             "category": "SI", "requirements": ["Identify, report, and correct information system flaws; install security-relevant patches"],  "metadata": {"automated": True}},
    {"control_id": "SI-3",  "name": "Malicious Code Protection",                    "category": "SI", "requirements": ["Employ malicious code protection mechanisms at system entry and exit points"],              "metadata": {"automated": True,  "cwes": ["CWE-506"]}},
    {"control_id": "SI-4",  "name": "System Monitoring",                            "category": "SI", "requirements": ["Monitor the information system to detect attacks and indicators of potential attacks"],      "metadata": {"automated": True}},
    {"control_id": "SI-10", "name": "Information Input Validation",                 "category": "SI", "requirements": ["Check the validity of information inputs to the system"],                                   "metadata": {"automated": True,  "cwes": ["CWE-89", "CWE-79", "CWE-78", "CWE-22"]}},
]

NIST_CSF_CONTROLS: List[Dict[str, Any]] = [
    {"control_id": "GV",  "name": "GOVERN — Organizational Context",    "category": "Govern",   "requirements": ["Establish cybersecurity risk management strategy, policies, and oversight"], "metadata": {"function": "GV", "note": "New in CSF 2.0 — covers risk governance, supply chain risk, and policy"}},
    {"control_id": "ID",  "name": "IDENTIFY — Asset Management",        "category": "Identify", "requirements": ["Understand the cybersecurity risks to systems, people, assets, and data"],   "metadata": {"function": "ID", "subcategories": ["ID.AM", "ID.BE", "ID.GV", "ID.RA", "ID.RM", "ID.SC"]}},
    {"control_id": "PR",  "name": "PROTECT — Access Control",           "category": "Protect",  "requirements": ["Safeguards to manage cybersecurity risk and support delivery of services"],   "metadata": {"function": "PR", "subcategories": ["PR.AA", "PR.AT", "PR.DS", "PR.IR", "PR.PS"]}},
    {"control_id": "DE",  "name": "DETECT — Anomalies and Events",      "category": "Detect",   "requirements": ["Enable timely discovery of cybersecurity events"],                           "metadata": {"function": "DE", "subcategories": ["DE.AE", "DE.CM"]}},
    {"control_id": "RS",  "name": "RESPOND — Response Planning",        "category": "Respond",  "requirements": ["Take action regarding a detected cybersecurity incident"],                   "metadata": {"function": "RS", "subcategories": ["RS.CO", "RS.AN", "RS.MI", "RS.IM"]}},
    {"control_id": "RC",  "name": "RECOVER — Recovery Planning",        "category": "Recover",  "requirements": ["Restore capabilities impaired by a cybersecurity incident"],                 "metadata": {"function": "RC", "subcategories": ["RC.RP", "RC.IM"]}},
]

OWASP_ASVS_CONTROLS: List[Dict[str, Any]] = [
    {"control_id": "V1",  "name": "Architecture, Design and Threat Modeling",  "category": "Architecture", "requirements": ["Security architecture documented", "Threat modelling for sensitive flows"], "metadata": {"chapter": 1}},
    {"control_id": "V2",  "name": "Authentication",                            "category": "Authentication", "requirements": ["Secure password storage", "MFA support", "Brute force protection"],       "metadata": {"chapter": 2, "cwes": ["CWE-287", "CWE-307", "CWE-521"]}},
    {"control_id": "V3",  "name": "Session Management",                        "category": "Session",       "requirements": ["Secure session token generation", "Session timeout", "CSRF protection"],   "metadata": {"chapter": 3, "cwes": ["CWE-384", "CWE-613"]}},
    {"control_id": "V4",  "name": "Access Control",                            "category": "AccessControl", "requirements": ["Principle of least privilege", "Deny by default", "RBAC enforcement"],     "metadata": {"chapter": 4, "cwes": ["CWE-269", "CWE-862"]}},
    {"control_id": "V5",  "name": "Validation, Sanitization and Encoding",    "category": "InputHandling", "requirements": ["Input validation", "Output encoding", "Prevention of injection attacks"],   "metadata": {"chapter": 5, "cwes": ["CWE-89", "CWE-79", "CWE-78", "CWE-22"]}},
    {"control_id": "V6",  "name": "Stored Cryptography",                       "category": "Cryptography",  "requirements": ["Approved algorithms only", "Key management practices", "No weak hashes"], "metadata": {"chapter": 6, "cwes": ["CWE-327", "CWE-326", "CWE-916"]}},
    {"control_id": "V7",  "name": "Error Handling and Logging",                "category": "Logging",       "requirements": ["Log security events", "No sensitive data in logs", "Error messages safe"], "metadata": {"chapter": 7, "cwes": ["CWE-778", "CWE-209"]}},
    {"control_id": "V8",  "name": "Data Protection",                           "category": "DataProtection","requirements": ["Sensitive data classified", "Data minimisation", "Encryption at rest"],     "metadata": {"chapter": 8, "cwes": ["CWE-312", "CWE-311"]}},
    {"control_id": "V9",  "name": "Communication",                             "category": "Communication", "requirements": ["TLS required", "Certificate validation", "No weak TLS versions"],          "metadata": {"chapter": 9, "cwes": ["CWE-319", "CWE-295"]}},
    {"control_id": "V10", "name": "Malicious Code",                            "category": "CodeIntegrity", "requirements": ["Source integrity verified", "Dependency scanning", "No backdoors"],        "metadata": {"chapter": 10, "cwes": ["CWE-506", "CWE-829"]}},
    {"control_id": "V11", "name": "Business Logic",                            "category": "BusinessLogic", "requirements": ["Business logic flows protected", "Rate limiting enforced"],                 "metadata": {"chapter": 11}},
    {"control_id": "V12", "name": "Files and Resources",                       "category": "FileHandling",  "requirements": ["File upload validation", "Path traversal prevention"],                     "metadata": {"chapter": 12, "cwes": ["CWE-22", "CWE-434"]}},
    {"control_id": "V13", "name": "API and Web Service",                       "category": "API",           "requirements": ["RESTful API authentication", "Input validation for all API parameters"],  "metadata": {"chapter": 13, "cwes": ["CWE-287", "CWE-918"]}},
    {"control_id": "V14", "name": "Configuration",                             "category": "Configuration", "requirements": ["Minimal attack surface", "Hardened defaults", "Dependency patching"],     "metadata": {"chapter": 14, "cwes": ["CWE-16", "CWE-1188"]}},
]

# Map framework name → list of control dicts
FRAMEWORK_CONTROLS: Dict[str, List[Dict[str, Any]]] = {
    "SOC2":          SOC2_CONTROLS,
    "PCI_DSS_4.0":   PCI_DSS_CONTROLS,
    "ISO_27001_2022": ISO_27001_CONTROLS,
    "NIST_800_53_R5": NIST_800_53_CONTROLS,
    "NIST_CSF_2.0":  NIST_CSF_CONTROLS,
    "OWASP_ASVS_4.0": OWASP_ASVS_CONTROLS,
}


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def get_connection(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(str(db_path))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def ensure_tables(conn: sqlite3.Connection) -> None:
    """Create tables if they do not already exist (idempotent)."""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS compliance_frameworks (
            id TEXT PRIMARY KEY,
            name TEXT UNIQUE NOT NULL,
            version TEXT NOT NULL,
            description TEXT NOT NULL,
            controls TEXT,
            metadata TEXT,
            created_at TEXT NOT NULL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS compliance_controls (
            id TEXT PRIMARY KEY,
            framework_id TEXT NOT NULL,
            control_id TEXT NOT NULL,
            name TEXT NOT NULL,
            description TEXT NOT NULL,
            category TEXT NOT NULL,
            requirements TEXT,
            metadata TEXT,
            FOREIGN KEY (framework_id) REFERENCES compliance_frameworks(id)
        );

        CREATE INDEX IF NOT EXISTS idx_compliance_controls_framework
            ON compliance_controls(framework_id);
    """)
    conn.commit()


def seed_framework(conn: sqlite3.Connection, fw: Dict[str, Any]) -> str:
    """Insert or update a framework record; return its DB id."""
    existing = conn.execute(
        "SELECT id FROM compliance_frameworks WHERE name=?", (fw["name"],)
    ).fetchone()

    if existing:
        fw_db_id = existing["id"]
        conn.execute(
            """UPDATE compliance_frameworks
               SET version=?, description=?, metadata=?, updated_at=?
               WHERE id=?""",
            (fw["version"], fw["description"], json.dumps(fw.get("metadata", {})),
             NOW, fw_db_id),
        )
        print(f"  [UPDATE] Framework '{fw['name']}' (id={fw_db_id})")
    else:
        fw_db_id = fw["id"]
        conn.execute(
            "INSERT INTO compliance_frameworks VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                fw_db_id,
                fw["name"],
                fw["version"],
                fw["description"],
                json.dumps([]),          # controls list (kept empty; detailed in separate table)
                json.dumps(fw.get("metadata", {})),
                NOW,
                NOW,
            ),
        )
        print(f"  [INSERT] Framework '{fw['name']}' (id={fw_db_id})")

    conn.commit()
    return fw_db_id


def seed_controls(conn: sqlite3.Connection, fw_db_id: str, fw_name: str,
                  controls: List[Dict[str, Any]]) -> int:
    """Insert controls for a framework, skipping any already present."""
    inserted = 0
    for ctrl in controls:
        existing = conn.execute(
            "SELECT id FROM compliance_controls WHERE framework_id=? AND control_id=?",
            (fw_db_id, ctrl["control_id"]),
        ).fetchone()
        if existing:
            continue

        ctrl_db_id = str(uuid.uuid4())
        conn.execute(
            "INSERT INTO compliance_controls VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                ctrl_db_id,
                fw_db_id,
                ctrl["control_id"],
                ctrl["name"],
                ctrl.get("description", ctrl["name"]),   # description = name if missing
                ctrl["category"],
                json.dumps(ctrl.get("requirements", [])),
                json.dumps(ctrl.get("metadata", {})),
            ),
        )
        inserted += 1

    conn.commit()
    return inserted


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    print(f"\nFixOps Compliance Framework Seeder")
    print(f"Database : {DB_PATH}")
    print(f"Timestamp: {NOW}")
    print("-" * 60)

    if not DB_PATH.exists():
        print(f"ERROR: Database not found at {DB_PATH}")
        print("Ensure the API server has been started at least once to create the DB.")
        sys.exit(1)

    conn = get_connection(DB_PATH)
    ensure_tables(conn)

    total_frameworks = 0
    total_controls = 0

    for fw in FRAMEWORKS:
        fw_name = fw["name"]
        controls = FRAMEWORK_CONTROLS.get(fw_name, [])
        print(f"\nSeeding: {fw_name} ({len(controls)} controls)")

        fw_db_id = seed_framework(conn, fw)
        n = seed_controls(conn, fw_db_id, fw_name, controls)
        total_frameworks += 1
        total_controls += n
        print(f"  Controls inserted: {n}")

    conn.close()

    print("\n" + "=" * 60)
    print(f"Seeding complete.")
    print(f"  Frameworks processed : {total_frameworks}")
    print(f"  Controls inserted    : {total_controls}")
    print()
    print("Verify with:")
    print("  curl -s http://localhost:8000/api/v1/audit/compliance/frameworks \\")
    api_key_display = os.environ.get("FIXOPS_API_TOKEN", "<FIXOPS_API_TOKEN not set>")
    print(f"       -H 'X-API-Key: {api_key_display}' | python3 -m json.tool")
    print()


if __name__ == "__main__":
    main()
