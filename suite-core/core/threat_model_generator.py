"""Threat Model Auto-Generator — ALDECI.

Manages threat models, STRIDE threats, mitigations, and model reviews.
Auto-generates threats per system_type using STRIDE methodology.

Multi-tenant via org_id. SQLite WAL + threading.RLock for concurrency safety.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_logger = logging.getLogger(__name__)

_DEFAULT_DB = str(
    Path(__file__).resolve().parents[2] / ".fixops_data" / "threat_model_generator.db"
)

# ---------------------------------------------------------------------------
# Auto-generation threat templates per system_type
# ---------------------------------------------------------------------------

_SYSTEM_THREATS: Dict[str, List[Dict[str, Any]]] = {
    "web_app": [
        {
            "stride_category": "Tampering",
            "title": "SQL Injection",
            "description": "Attacker injects malicious SQL via input fields to manipulate the database.",
            "attack_vector": "User-supplied input fields, URL parameters",
            "likelihood": "high",
            "impact": "high",
            "risk_rating": "critical",
            "mitigations": ["parameterized_queries", "input_validation", "waf"],
        },
        {
            "stride_category": "Tampering",
            "title": "Cross-Site Scripting (XSS)",
            "description": "Attacker injects malicious scripts into web pages viewed by other users.",
            "attack_vector": "User-generated content, URL parameters, HTTP headers",
            "likelihood": "high",
            "impact": "medium",
            "risk_rating": "high",
            "mitigations": ["output_encoding", "content_security_policy", "input_validation"],
        },
        {
            "stride_category": "Tampering",
            "title": "Cross-Site Request Forgery (CSRF)",
            "description": "Attacker tricks authenticated user into submitting malicious requests.",
            "attack_vector": "Malicious web page, phishing email",
            "likelihood": "medium",
            "impact": "medium",
            "risk_rating": "high",
            "mitigations": ["csrf_tokens", "samesite_cookies", "referer_validation"],
        },
        {
            "stride_category": "Spoofing",
            "title": "Session Hijacking",
            "description": "Attacker steals session token to impersonate a legitimate user.",
            "attack_vector": "Network sniffing, XSS, session fixation",
            "likelihood": "medium",
            "impact": "high",
            "risk_rating": "high",
            "mitigations": ["https_enforcement", "secure_httponly_cookies", "session_rotation"],
        },
        {
            "stride_category": "Information_Disclosure",
            "title": "Sensitive Data Exposure",
            "description": "Application exposes sensitive data in error messages or insecure storage.",
            "attack_vector": "Error messages, browser cache, insecure transmission",
            "likelihood": "medium",
            "impact": "high",
            "risk_rating": "high",
            "mitigations": ["encryption_at_rest", "tls_enforcement", "error_handling"],
        },
        {
            "stride_category": "Denial_of_Service",
            "title": "Application-Layer DDoS",
            "description": "Attacker floods application endpoints causing service degradation.",
            "attack_vector": "Botnet HTTP flood, slowloris, resource exhaustion",
            "likelihood": "medium",
            "impact": "high",
            "risk_rating": "high",
            "mitigations": ["rate_limiting", "waf", "cdn_ddos_protection"],
        },
        {
            "stride_category": "Elevation_of_Privilege",
            "title": "Broken Access Control",
            "description": "Attacker accesses resources or functions beyond their authorization.",
            "attack_vector": "IDOR, path traversal, privilege escalation via parameter manipulation",
            "likelihood": "high",
            "impact": "high",
            "risk_rating": "critical",
            "mitigations": ["rbac_enforcement", "server_side_authorization", "access_control_audit"],
        },
        {
            "stride_category": "Repudiation",
            "title": "Insufficient Audit Logging",
            "description": "Lack of logging allows attackers to deny malicious actions.",
            "attack_vector": "Any unauthenticated or authenticated action without logging",
            "likelihood": "medium",
            "impact": "medium",
            "risk_rating": "medium",
            "mitigations": ["centralized_logging", "tamper_proof_audit_trail", "log_monitoring"],
        },
    ],
    "api": [
        {
            "stride_category": "Spoofing",
            "title": "API Authentication Bypass",
            "description": "Attacker bypasses API authentication to access protected endpoints.",
            "attack_vector": "Weak tokens, JWT algorithm confusion, missing auth checks",
            "likelihood": "high",
            "impact": "high",
            "risk_rating": "critical",
            "mitigations": ["strong_jwt_validation", "oauth2", "mutual_tls"],
        },
        {
            "stride_category": "Denial_of_Service",
            "title": "API Rate Limit Abuse",
            "description": "Attacker exhausts API resources through excessive requests.",
            "attack_vector": "Scripted bulk requests, credential stuffing",
            "likelihood": "high",
            "impact": "medium",
            "risk_rating": "high",
            "mitigations": ["rate_limiting", "throttling", "api_gateway"],
        },
        {
            "stride_category": "Information_Disclosure",
            "title": "Excessive Data Exposure",
            "description": "API returns more data than needed, exposing sensitive fields.",
            "attack_vector": "Direct API enumeration, mass assignment exploitation",
            "likelihood": "high",
            "impact": "medium",
            "risk_rating": "high",
            "mitigations": ["field_filtering", "response_schema_validation", "data_minimization"],
        },
        {
            "stride_category": "Tampering",
            "title": "Broken Object Level Authorization",
            "description": "Attacker manipulates object IDs to access other users' resources.",
            "attack_vector": "IDOR via modified request parameters",
            "likelihood": "high",
            "impact": "high",
            "risk_rating": "critical",
            "mitigations": ["object_level_auth_checks", "indirect_references", "rbac"],
        },
        {
            "stride_category": "Elevation_of_Privilege",
            "title": "Function-Level Authorization Bypass",
            "description": "Attacker calls admin functions by guessing or enumerating endpoints.",
            "attack_vector": "HTTP verb tampering, hidden admin endpoints",
            "likelihood": "medium",
            "impact": "high",
            "risk_rating": "high",
            "mitigations": ["role_based_endpoint_protection", "api_gateway_policy", "security_testing"],
        },
        {
            "stride_category": "Tampering",
            "title": "Mass Assignment Vulnerability",
            "description": "Attacker modifies object properties not intended to be user-editable.",
            "attack_vector": "Extra fields in API request body",
            "likelihood": "medium",
            "impact": "high",
            "risk_rating": "high",
            "mitigations": ["allowlist_properties", "explicit_field_mapping", "input_validation"],
        },
        {
            "stride_category": "Information_Disclosure",
            "title": "Improper Error Handling",
            "description": "Verbose error messages reveal implementation details to attackers.",
            "attack_vector": "Malformed requests, boundary conditions",
            "likelihood": "medium",
            "impact": "medium",
            "risk_rating": "medium",
            "mitigations": ["generic_error_responses", "error_logging", "exception_handling"],
        },
        {
            "stride_category": "Repudiation",
            "title": "Missing API Audit Trail",
            "description": "API calls are not logged, preventing incident investigation.",
            "attack_vector": "Any API endpoint without logging",
            "likelihood": "low",
            "impact": "medium",
            "risk_rating": "medium",
            "mitigations": ["api_access_logging", "siem_integration", "log_retention_policy"],
        },
    ],
    "microservice": [
        {
            "stride_category": "Spoofing",
            "title": "Service Identity Spoofing",
            "description": "Malicious service impersonates a legitimate microservice in the mesh.",
            "attack_vector": "Lack of mutual TLS, weak service identity",
            "likelihood": "medium",
            "impact": "high",
            "risk_rating": "high",
            "mitigations": ["mutual_tls", "service_mesh_identity", "certificate_pinning"],
        },
        {
            "stride_category": "Tampering",
            "title": "Inter-Service Message Tampering",
            "description": "Attacker modifies messages in transit between microservices.",
            "attack_vector": "Man-in-the-middle on internal network",
            "likelihood": "medium",
            "impact": "high",
            "risk_rating": "high",
            "mitigations": ["tls_between_services", "message_signing", "integrity_checks"],
        },
        {
            "stride_category": "Denial_of_Service",
            "title": "Cascading Service Failure",
            "description": "Failure in one service cascades, causing system-wide outage.",
            "attack_vector": "Resource exhaustion, slow upstream responses",
            "likelihood": "medium",
            "impact": "high",
            "risk_rating": "high",
            "mitigations": ["circuit_breakers", "bulkheads", "timeout_policies"],
        },
        {
            "stride_category": "Information_Disclosure",
            "title": "Secrets in Service Config",
            "description": "Hardcoded credentials or secrets exposed in service configuration.",
            "attack_vector": "Config file access, environment variable leakage",
            "likelihood": "medium",
            "impact": "high",
            "risk_rating": "high",
            "mitigations": ["secrets_manager", "vault_integration", "no_hardcoded_secrets"],
        },
        {
            "stride_category": "Elevation_of_Privilege",
            "title": "Container Escape",
            "description": "Attacker breaks out of container to access host or other containers.",
            "attack_vector": "Privileged container, kernel exploits, volume mounts",
            "likelihood": "low",
            "impact": "critical",
            "risk_rating": "high",
            "mitigations": ["non_root_containers", "seccomp_profiles", "read_only_filesystem"],
        },
        {
            "stride_category": "Repudiation",
            "title": "Distributed Tracing Gaps",
            "description": "Missing correlation IDs make incident reconstruction impossible.",
            "attack_vector": "Any service call without propagated trace context",
            "likelihood": "medium",
            "impact": "medium",
            "risk_rating": "medium",
            "mitigations": ["distributed_tracing", "correlation_ids", "centralized_logging"],
        },
        {
            "stride_category": "Tampering",
            "title": "Supply Chain Compromise",
            "description": "Malicious code injected via third-party dependencies or base images.",
            "attack_vector": "Compromised npm/pip packages, poisoned container images",
            "likelihood": "medium",
            "impact": "high",
            "risk_rating": "high",
            "mitigations": ["dependency_scanning", "image_signing", "sbom_generation"],
        },
        {
            "stride_category": "Information_Disclosure",
            "title": "Internal API Exposure",
            "description": "Internal service APIs accidentally exposed to external network.",
            "attack_vector": "Misconfigured ingress, service mesh policy gaps",
            "likelihood": "medium",
            "impact": "high",
            "risk_rating": "high",
            "mitigations": ["network_segmentation", "api_gateway", "zero_trust_network"],
        },
    ],
    "mobile": [
        {
            "stride_category": "Information_Disclosure",
            "title": "Insecure Local Data Storage",
            "description": "Sensitive data stored unencrypted on device storage.",
            "attack_vector": "Physical device access, backup extraction, rooted device",
            "likelihood": "high",
            "impact": "high",
            "risk_rating": "high",
            "mitigations": ["encrypted_local_storage", "keychain_keystore", "data_minimization"],
        },
        {
            "stride_category": "Information_Disclosure",
            "title": "Insecure Data Transmission",
            "description": "App transmits data over unencrypted or improperly validated TLS.",
            "attack_vector": "MITM attack, rogue WiFi, certificate pinning bypass",
            "likelihood": "medium",
            "impact": "high",
            "risk_rating": "high",
            "mitigations": ["certificate_pinning", "tls_1_3", "network_security_config"],
        },
        {
            "stride_category": "Spoofing",
            "title": "Weak Authentication",
            "description": "App uses weak or bypassable authentication mechanisms.",
            "attack_vector": "Brute force, biometric bypass, token theft",
            "likelihood": "medium",
            "impact": "high",
            "risk_rating": "high",
            "mitigations": ["mfa", "biometric_auth", "token_binding"],
        },
        {
            "stride_category": "Elevation_of_Privilege",
            "title": "Excessive App Permissions",
            "description": "App requests more permissions than needed, expanding attack surface.",
            "attack_vector": "Permission abuse, malicious SDK",
            "likelihood": "medium",
            "impact": "medium",
            "risk_rating": "medium",
            "mitigations": ["least_privilege_permissions", "permission_audit", "runtime_permission_requests"],
        },
        {
            "stride_category": "Tampering",
            "title": "Binary Reverse Engineering",
            "description": "Attacker reverse-engineers app binary to extract secrets or bypass controls.",
            "attack_vector": "APK/IPA decompilation, dynamic instrumentation",
            "likelihood": "medium",
            "impact": "high",
            "risk_rating": "high",
            "mitigations": ["code_obfuscation", "root_jailbreak_detection", "anti_tampering"],
        },
        {
            "stride_category": "Tampering",
            "title": "Client-Side Business Logic Bypass",
            "description": "Attacker modifies app behavior by tampering with client-side logic.",
            "attack_vector": "Hooking frameworks (Frida), modified APK",
            "likelihood": "medium",
            "impact": "high",
            "risk_rating": "high",
            "mitigations": ["server_side_validation", "integrity_checks", "runtime_protection"],
        },
        {
            "stride_category": "Information_Disclosure",
            "title": "Log and Debug Information Leakage",
            "description": "Sensitive data written to device logs accessible by other apps.",
            "attack_vector": "Android logcat, iOS console, crash reports",
            "likelihood": "medium",
            "impact": "medium",
            "risk_rating": "medium",
            "mitigations": ["disable_debug_logging_prod", "log_scrubbing", "crashlytics_data_policy"],
        },
        {
            "stride_category": "Spoofing",
            "title": "Deeplink Hijacking",
            "description": "Malicious app intercepts deeplinks to steal tokens or data.",
            "attack_vector": "Implicit intent interception, custom scheme hijacking",
            "likelihood": "medium",
            "impact": "medium",
            "risk_rating": "medium",
            "mitigations": ["explicit_intents", "app_links_verification", "pkce_oauth"],
        },
    ],
    "iot": [
        {
            "stride_category": "Spoofing",
            "title": "Device Identity Spoofing",
            "description": "Attacker impersonates a legitimate IoT device to inject false data.",
            "attack_vector": "Stolen device credentials, cloned certificates",
            "likelihood": "medium",
            "impact": "high",
            "risk_rating": "high",
            "mitigations": ["device_certificates", "hardware_security_module", "device_attestation"],
        },
        {
            "stride_category": "Tampering",
            "title": "Firmware Tampering",
            "description": "Attacker modifies device firmware to insert backdoors or malware.",
            "attack_vector": "Insecure update mechanism, physical access",
            "likelihood": "medium",
            "impact": "high",
            "risk_rating": "high",
            "mitigations": ["signed_firmware_updates", "secure_boot", "code_signing"],
        },
        {
            "stride_category": "Information_Disclosure",
            "title": "Unencrypted Device Communication",
            "description": "IoT device transmits sensitive data without encryption.",
            "attack_vector": "Passive network sniffing, MITM",
            "likelihood": "high",
            "impact": "high",
            "risk_rating": "high",
            "mitigations": ["tls_mqtt", "dtls", "end_to_end_encryption"],
        },
        {
            "stride_category": "Denial_of_Service",
            "title": "Resource Exhaustion Attack",
            "description": "Attacker overwhelms constrained IoT device causing failure.",
            "attack_vector": "Flood of connections/requests to constrained device",
            "likelihood": "medium",
            "impact": "high",
            "risk_rating": "high",
            "mitigations": ["rate_limiting", "connection_limits", "watchdog_timers"],
        },
        {
            "stride_category": "Elevation_of_Privilege",
            "title": "Insecure Default Credentials",
            "description": "Device ships with default credentials that users never change.",
            "attack_vector": "Credential scanning, Shodan enumeration",
            "likelihood": "high",
            "impact": "high",
            "risk_rating": "critical",
            "mitigations": ["forced_credential_change", "unique_device_credentials", "no_default_passwords"],
        },
        {
            "stride_category": "Tampering",
            "title": "Physical Tampering",
            "description": "Attacker gains physical access to device to extract data or modify behavior.",
            "attack_vector": "JTAG access, UART console, memory extraction",
            "likelihood": "medium",
            "impact": "high",
            "risk_rating": "high",
            "mitigations": ["physical_tamper_detection", "encrypted_storage", "disable_debug_ports"],
        },
        {
            "stride_category": "Information_Disclosure",
            "title": "Privacy Data Harvesting",
            "description": "IoT device collects more personal data than disclosed or necessary.",
            "attack_vector": "Compromised cloud backend, rogue firmware update",
            "likelihood": "medium",
            "impact": "high",
            "risk_rating": "high",
            "mitigations": ["data_minimization", "privacy_by_design", "user_consent_controls"],
        },
        {
            "stride_category": "Repudiation",
            "title": "Missing Device Audit Logs",
            "description": "No logging of device actions makes forensic analysis impossible.",
            "attack_vector": "Any device action without logging",
            "likelihood": "medium",
            "impact": "medium",
            "risk_rating": "medium",
            "mitigations": ["device_event_logging", "cloud_log_aggregation", "tamper_evident_logs"],
        },
    ],
    "data_pipeline": [
        {
            "stride_category": "Tampering",
            "title": "Data Injection at Ingestion",
            "description": "Attacker injects malicious or corrupted data into the pipeline.",
            "attack_vector": "Compromised data source, schema exploitation",
            "likelihood": "medium",
            "impact": "high",
            "risk_rating": "high",
            "mitigations": ["input_validation", "schema_enforcement", "data_signing"],
        },
        {
            "stride_category": "Information_Disclosure",
            "title": "Data Exfiltration via Pipeline",
            "description": "Sensitive data leaked through misconfigured pipeline outputs.",
            "attack_vector": "Overly permissive output connectors, logging of sensitive fields",
            "likelihood": "medium",
            "impact": "high",
            "risk_rating": "high",
            "mitigations": ["data_masking", "dlp_controls", "output_access_controls"],
        },
        {
            "stride_category": "Denial_of_Service",
            "title": "Pipeline Poisoning",
            "description": "Attacker floods pipeline with malformed data causing backlog and outage.",
            "attack_vector": "High-volume malformed message injection",
            "likelihood": "medium",
            "impact": "high",
            "risk_rating": "high",
            "mitigations": ["dead_letter_queues", "rate_limiting", "schema_validation"],
        },
        {
            "stride_category": "Elevation_of_Privilege",
            "title": "Overprivileged Pipeline Service Account",
            "description": "Pipeline runs with excessive permissions, enabling lateral movement.",
            "attack_vector": "Compromised pipeline credential, permission abuse",
            "likelihood": "medium",
            "impact": "high",
            "risk_rating": "high",
            "mitigations": ["least_privilege_service_accounts", "iam_audit", "workload_identity"],
        },
        {
            "stride_category": "Repudiation",
            "title": "No Data Lineage Tracking",
            "description": "Inability to trace data origin and transformations enables data quality disputes.",
            "attack_vector": "Any untracked data transformation",
            "likelihood": "medium",
            "impact": "medium",
            "risk_rating": "medium",
            "mitigations": ["data_lineage_tools", "transformation_audit_log", "provenance_metadata"],
        },
        {
            "stride_category": "Spoofing",
            "title": "Source Impersonation",
            "description": "Attacker impersonates a trusted data source to inject malicious data.",
            "attack_vector": "Spoofed source IP/identity, stolen API keys",
            "likelihood": "medium",
            "impact": "high",
            "risk_rating": "high",
            "mitigations": ["source_authentication", "message_signing", "allowlist_sources"],
        },
        {
            "stride_category": "Tampering",
            "title": "In-Transit Data Modification",
            "description": "Data modified in transit between pipeline stages.",
            "attack_vector": "MITM on internal network, compromised message broker",
            "likelihood": "low",
            "impact": "high",
            "risk_rating": "medium",
            "mitigations": ["tls_between_stages", "message_integrity_checks", "encrypted_queues"],
        },
        {
            "stride_category": "Information_Disclosure",
            "title": "Unencrypted Data at Rest",
            "description": "Intermediate pipeline storage contains unencrypted sensitive data.",
            "attack_vector": "Direct storage access, backup theft",
            "likelihood": "medium",
            "impact": "high",
            "risk_rating": "high",
            "mitigations": ["encryption_at_rest", "key_management", "storage_access_controls"],
        },
    ],
    "cloud_infra": [
        {
            "stride_category": "Elevation_of_Privilege",
            "title": "IAM Privilege Escalation",
            "description": "Attacker exploits overly permissive IAM policies to gain elevated access.",
            "attack_vector": "Misconfigured IAM roles, privilege escalation chains",
            "likelihood": "high",
            "impact": "high",
            "risk_rating": "critical",
            "mitigations": ["least_privilege_iam", "iam_access_analyzer", "privilege_escalation_detection"],
        },
        {
            "stride_category": "Information_Disclosure",
            "title": "Public S3 Bucket / Blob Misconfiguration",
            "description": "Cloud storage buckets unintentionally exposed to the public internet.",
            "attack_vector": "Misconfigured bucket ACL or policy",
            "likelihood": "high",
            "impact": "high",
            "risk_rating": "critical",
            "mitigations": ["block_public_access", "bucket_policy_audit", "cspm_scanning"],
        },
        {
            "stride_category": "Elevation_of_Privilege",
            "title": "Instance Metadata Service Abuse",
            "description": "Attacker exploits SSRF to access cloud IMDS and steal instance credentials.",
            "attack_vector": "SSRF vulnerability, IMDSv1 exploitation",
            "likelihood": "medium",
            "impact": "high",
            "risk_rating": "high",
            "mitigations": ["imdsv2_enforcement", "ssrf_protection", "network_policy"],
        },
        {
            "stride_category": "Tampering",
            "title": "Infrastructure as Code Misconfiguration",
            "description": "Insecure IaC templates deployed creating persistent vulnerabilities.",
            "attack_vector": "Unreviewed Terraform/CloudFormation templates",
            "likelihood": "high",
            "impact": "high",
            "risk_rating": "high",
            "mitigations": ["iac_scanning", "policy_as_code", "pre_commit_security_checks"],
        },
        {
            "stride_category": "Denial_of_Service",
            "title": "Cloud Resource Exhaustion",
            "description": "Attacker causes runaway resource consumption leading to billing shock and outage.",
            "attack_vector": "Crypto mining, resource quota abuse after account compromise",
            "likelihood": "medium",
            "impact": "high",
            "risk_rating": "high",
            "mitigations": ["budget_alerts", "resource_quotas", "anomaly_detection"],
        },
        {
            "stride_category": "Spoofing",
            "title": "Credential Leakage via Code Repository",
            "description": "Cloud credentials accidentally committed to source control.",
            "attack_vector": "Git history, CI/CD environment variable leakage",
            "likelihood": "high",
            "impact": "high",
            "risk_rating": "critical",
            "mitigations": ["secrets_scanning", "git_history_scanning", "vault_secrets_management"],
        },
        {
            "stride_category": "Repudiation",
            "title": "Insufficient Cloud Audit Logging",
            "description": "CloudTrail/audit logs not enabled or incomplete, preventing forensic analysis.",
            "attack_vector": "Any cloud API call without logging",
            "likelihood": "medium",
            "impact": "high",
            "risk_rating": "high",
            "mitigations": ["cloudtrail_all_regions", "log_integrity_validation", "siem_integration"],
        },
        {
            "stride_category": "Information_Disclosure",
            "title": "Unencrypted Data in Cloud Storage",
            "description": "Sensitive data stored in cloud without server-side or client-side encryption.",
            "attack_vector": "Storage service access, insider threat",
            "likelihood": "medium",
            "impact": "high",
            "risk_rating": "high",
            "mitigations": ["sse_kms", "client_side_encryption", "key_rotation_policy"],
        },
        {
            "stride_category": "Elevation_of_Privilege",
            "title": "Overprivileged Service Roles",
            "description": "Cloud services assigned AdministratorAccess instead of scoped permissions.",
            "attack_vector": "Compromised service, supply chain attack",
            "likelihood": "high",
            "impact": "high",
            "risk_rating": "critical",
            "mitigations": ["scoped_service_roles", "permission_boundaries", "regular_iam_review"],
        },
    ],
}

# Fallback for unknown system types
_DEFAULT_THREATS = _SYSTEM_THREATS["web_app"]


class ThreatModelGenerator:
    """SQLite WAL-backed threat model generator.

    Thread-safe via RLock. Multi-tenant via org_id.
    """

    def __init__(self, db_path: str = _DEFAULT_DB) -> None:
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_db()

    # ------------------------------------------------------------------
    # Schema
    # ------------------------------------------------------------------

    def _init_db(self) -> None:
        Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
        with self._conn() as conn:
            conn.execute("PRAGMA journal_mode=WAL")
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS threat_models (
                    model_id            TEXT PRIMARY KEY,
                    org_id              TEXT NOT NULL,
                    name                TEXT NOT NULL,
                    description         TEXT NOT NULL DEFAULT '',
                    system_type         TEXT NOT NULL DEFAULT 'web_app',
                    methodology         TEXT NOT NULL DEFAULT 'STRIDE',
                    status              TEXT NOT NULL DEFAULT 'draft',
                    data_classification TEXT NOT NULL DEFAULT 'internal',
                    trust_boundaries    TEXT NOT NULL DEFAULT '[]',
                    components          TEXT NOT NULL DEFAULT '[]',
                    created_at          DATETIME NOT NULL,
                    updated_at          DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_tm_org
                    ON threat_models (org_id);

                CREATE TABLE IF NOT EXISTS threats (
                    threat_id       TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    model_id        TEXT NOT NULL REFERENCES threat_models(model_id),
                    stride_category TEXT NOT NULL DEFAULT 'Spoofing',
                    title           TEXT NOT NULL,
                    description     TEXT NOT NULL DEFAULT '',
                    attack_vector   TEXT NOT NULL DEFAULT '',
                    likelihood      TEXT NOT NULL DEFAULT 'medium',
                    impact          TEXT NOT NULL DEFAULT 'medium',
                    risk_rating     TEXT NOT NULL DEFAULT 'medium',
                    mitigations     TEXT NOT NULL DEFAULT '[]',
                    status          TEXT NOT NULL DEFAULT 'open',
                    created_at      DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_threats_org_model
                    ON threats (org_id, model_id);

                CREATE TABLE IF NOT EXISTS mitigations (
                    mitigation_id   TEXT PRIMARY KEY,
                    org_id          TEXT NOT NULL,
                    threat_id       TEXT NOT NULL REFERENCES threats(threat_id),
                    title           TEXT NOT NULL,
                    mitigation_type TEXT NOT NULL DEFAULT 'preventive',
                    status          TEXT NOT NULL DEFAULT 'planned',
                    effort          TEXT NOT NULL DEFAULT 'medium',
                    owner           TEXT NOT NULL DEFAULT '',
                    due_date        TEXT NOT NULL DEFAULT '',
                    created_at      DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_mitigations_org_threat
                    ON mitigations (org_id, threat_id);

                CREATE TABLE IF NOT EXISTS model_reviews (
                    review_id   TEXT PRIMARY KEY,
                    org_id      TEXT NOT NULL,
                    model_id    TEXT NOT NULL REFERENCES threat_models(model_id),
                    reviewer    TEXT NOT NULL,
                    verdict     TEXT NOT NULL DEFAULT 'needs_revision',
                    comments    TEXT NOT NULL DEFAULT '',
                    reviewed_at DATETIME NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_reviews_org_model
                    ON model_reviews (org_id, model_id);
                """
            )

    def _conn(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _row(row: sqlite3.Row) -> Dict[str, Any]:
        return dict(row)

    @staticmethod
    def _deserialize(record: Dict[str, Any], json_fields: List[str]) -> Dict[str, Any]:
        for field in json_fields:
            if field in record and isinstance(record[field], str):
                try:
                    record[field] = json.loads(record[field])
                except (json.JSONDecodeError, TypeError):
                    record[field] = []
        return record

    # ------------------------------------------------------------------
    # Threat Models
    # ------------------------------------------------------------------

    def create_model(self, org_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new threat model. Returns the created record."""
        model_id = str(uuid.uuid4())
        now = self._now()
        trust_boundaries = json.dumps(data.get("trust_boundaries", []))
        components = json.dumps(data.get("components", []))

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO threat_models
                        (model_id, org_id, name, description, system_type, methodology,
                         status, data_classification, trust_boundaries, components,
                         created_at, updated_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        model_id, org_id,
                        data.get("name", "Untitled Model"),
                        data.get("description", ""),
                        data.get("system_type", "web_app"),
                        data.get("methodology", "STRIDE"),
                        data.get("status", "draft"),
                        data.get("data_classification", "internal"),
                        trust_boundaries,
                        components,
                        now, now,
                    ),
                )
        return self._deserialize(
            {
                "model_id": model_id,
                "org_id": org_id,
                "name": data.get("name", "Untitled Model"),
                "description": data.get("description", ""),
                "system_type": data.get("system_type", "web_app"),
                "methodology": data.get("methodology", "STRIDE"),
                "status": data.get("status", "draft"),
                "data_classification": data.get("data_classification", "internal"),
                "trust_boundaries": data.get("trust_boundaries", []),
                "components": data.get("components", []),
                "created_at": now,
                "updated_at": now,
            },
            ["trust_boundaries", "components"],
        )

    def list_models(
        self,
        org_id: str,
        status: Optional[str] = None,
        methodology: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List threat models for an org with optional filters."""
        query = "SELECT * FROM threat_models WHERE org_id=?"
        params: list = [org_id]
        if status:
            query += " AND status=?"
            params.append(status)
        if methodology:
            query += " AND methodology=?"
            params.append(methodology)
        query += " ORDER BY created_at DESC"

        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(query, params).fetchall()

        return [
            self._deserialize(self._row(r), ["trust_boundaries", "components"])
            for r in rows
        ]

    def get_model(self, org_id: str, model_id: str) -> Optional[Dict[str, Any]]:
        """Get a single threat model with threat count."""
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT * FROM threat_models WHERE org_id=? AND model_id=?",
                    (org_id, model_id),
                ).fetchone()
                if not row:
                    return None
                record = self._deserialize(self._row(row), ["trust_boundaries", "components"])
                count = conn.execute(
                    "SELECT COUNT(*) FROM threats WHERE org_id=? AND model_id=?",
                    (org_id, model_id),
                ).fetchone()[0]
        record["threats_count"] = count
        return record

    def auto_generate_threats(self, org_id: str, model_id: str) -> List[Dict[str, Any]]:
        """Auto-generate 8-12 STRIDE threats based on system_type."""
        with self._lock:
            with self._conn() as conn:
                row = conn.execute(
                    "SELECT system_type FROM threat_models WHERE org_id=? AND model_id=?",
                    (org_id, model_id),
                ).fetchone()

        if not row:
            raise ValueError(f"Threat model {model_id} not found for org {org_id}")

        system_type = row[0]
        templates = _SYSTEM_THREATS.get(system_type, _DEFAULT_THREATS)

        now = self._now()
        created: List[Dict[str, Any]] = []

        with self._lock:
            with self._conn() as conn:
                for tmpl in templates:
                    threat_id = str(uuid.uuid4())
                    conn.execute(
                        """
                        INSERT INTO threats
                            (threat_id, org_id, model_id, stride_category, title,
                             description, attack_vector, likelihood, impact,
                             risk_rating, mitigations, status, created_at)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                        """,
                        (
                            threat_id, org_id, model_id,
                            tmpl["stride_category"],
                            tmpl["title"],
                            tmpl["description"],
                            tmpl["attack_vector"],
                            tmpl["likelihood"],
                            tmpl["impact"],
                            tmpl["risk_rating"],
                            json.dumps(tmpl["mitigations"]),
                            "open",
                            now,
                        ),
                    )
                    created.append(
                        self._deserialize(
                            {
                                "threat_id": threat_id,
                                "org_id": org_id,
                                "model_id": model_id,
                                **tmpl,
                                "status": "open",
                                "created_at": now,
                            },
                            ["mitigations"],
                        )
                    )
        return created

    def add_threat(self, org_id: str, model_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add a manual threat to a model."""
        threat_id = str(uuid.uuid4())
        now = self._now()
        mitigations = json.dumps(data.get("mitigations", []))

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO threats
                        (threat_id, org_id, model_id, stride_category, title,
                         description, attack_vector, likelihood, impact,
                         risk_rating, mitigations, status, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        threat_id, org_id, model_id,
                        data.get("stride_category", "Spoofing"),
                        data.get("title", "Untitled Threat"),
                        data.get("description", ""),
                        data.get("attack_vector", ""),
                        data.get("likelihood", "medium"),
                        data.get("impact", "medium"),
                        data.get("risk_rating", "medium"),
                        mitigations,
                        data.get("status", "open"),
                        now,
                    ),
                )
        return self._deserialize(
            {
                "threat_id": threat_id,
                "org_id": org_id,
                "model_id": model_id,
                "stride_category": data.get("stride_category", "Spoofing"),
                "title": data.get("title", "Untitled Threat"),
                "description": data.get("description", ""),
                "attack_vector": data.get("attack_vector", ""),
                "likelihood": data.get("likelihood", "medium"),
                "impact": data.get("impact", "medium"),
                "risk_rating": data.get("risk_rating", "medium"),
                "mitigations": data.get("mitigations", []),
                "status": data.get("status", "open"),
                "created_at": now,
            },
            ["mitigations"],
        )

    def list_threats(
        self,
        org_id: str,
        model_id: str,
        stride_category: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List threats for a model with optional STRIDE category filter."""
        query = "SELECT * FROM threats WHERE org_id=? AND model_id=?"
        params: list = [org_id, model_id]
        if stride_category:
            query += " AND stride_category=?"
            params.append(stride_category)
        query += " ORDER BY created_at DESC"

        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(query, params).fetchall()

        return [self._deserialize(self._row(r), ["mitigations"]) for r in rows]

    def update_threat_status(self, org_id: str, threat_id: str, status: str) -> bool:
        """Update threat status. Returns True on success."""
        with self._lock:
            with self._conn() as conn:
                cur = conn.execute(
                    "UPDATE threats SET status=? WHERE org_id=? AND threat_id=?",
                    (status, org_id, threat_id),
                )
        return cur.rowcount > 0

    # ------------------------------------------------------------------
    # Mitigations
    # ------------------------------------------------------------------

    def add_mitigation(self, org_id: str, threat_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add a mitigation to a threat."""
        mitigation_id = str(uuid.uuid4())
        now = self._now()

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO mitigations
                        (mitigation_id, org_id, threat_id, title, mitigation_type,
                         status, effort, owner, due_date, created_at)
                    VALUES (?,?,?,?,?,?,?,?,?,?)
                    """,
                    (
                        mitigation_id, org_id, threat_id,
                        data.get("title", "Untitled Mitigation"),
                        data.get("mitigation_type", "preventive"),
                        data.get("status", "planned"),
                        data.get("effort", "medium"),
                        data.get("owner", ""),
                        data.get("due_date", ""),
                        now,
                    ),
                )
        return {
            "mitigation_id": mitigation_id,
            "org_id": org_id,
            "threat_id": threat_id,
            "title": data.get("title", "Untitled Mitigation"),
            "mitigation_type": data.get("mitigation_type", "preventive"),
            "status": data.get("status", "planned"),
            "effort": data.get("effort", "medium"),
            "owner": data.get("owner", ""),
            "due_date": data.get("due_date", ""),
            "created_at": now,
        }

    def list_mitigations(self, org_id: str, threat_id: str) -> List[Dict[str, Any]]:
        """List mitigations for a threat."""
        with self._lock:
            with self._conn() as conn:
                rows = conn.execute(
                    "SELECT * FROM mitigations WHERE org_id=? AND threat_id=? ORDER BY created_at DESC",
                    (org_id, threat_id),
                ).fetchall()
        return [self._row(r) for r in rows]

    # ------------------------------------------------------------------
    # Model Reviews
    # ------------------------------------------------------------------

    def add_review(self, org_id: str, model_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Add a review to a threat model. Updates model status if verdict=approved."""
        review_id = str(uuid.uuid4())
        now = self._now()
        verdict = data.get("verdict", "needs_revision")

        with self._lock:
            with self._conn() as conn:
                conn.execute(
                    """
                    INSERT INTO model_reviews
                        (review_id, org_id, model_id, reviewer, verdict, comments, reviewed_at)
                    VALUES (?,?,?,?,?,?,?)
                    """,
                    (
                        review_id, org_id, model_id,
                        data.get("reviewer", ""),
                        verdict,
                        data.get("comments", ""),
                        now,
                    ),
                )
                # Auto-update model status based on verdict
                if verdict == "approved":
                    conn.execute(
                        "UPDATE threat_models SET status='approved', updated_at=? WHERE org_id=? AND model_id=?",
                        (now, org_id, model_id),
                    )
                elif verdict == "rejected":
                    conn.execute(
                        "UPDATE threat_models SET status='draft', updated_at=? WHERE org_id=? AND model_id=?",
                        (now, org_id, model_id),
                    )

        return {
            "review_id": review_id,
            "org_id": org_id,
            "model_id": model_id,
            "reviewer": data.get("reviewer", ""),
            "verdict": verdict,
            "comments": data.get("comments", ""),
            "reviewed_at": now,
        }

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def get_model_stats(self, org_id: str) -> Dict[str, Any]:
        """Aggregate stats for the org."""
        with self._lock:
            with self._conn() as conn:
                total_models = conn.execute(
                    "SELECT COUNT(*) FROM threat_models WHERE org_id=?", (org_id,)
                ).fetchone()[0]

                approved_models = conn.execute(
                    "SELECT COUNT(*) FROM threat_models WHERE org_id=? AND status='approved'",
                    (org_id,),
                ).fetchone()[0]

                total_threats = conn.execute(
                    "SELECT COUNT(*) FROM threats WHERE org_id=?", (org_id,)
                ).fetchone()[0]

                open_threats = conn.execute(
                    "SELECT COUNT(*) FROM threats WHERE org_id=? AND status='open'",
                    (org_id,),
                ).fetchone()[0]

                critical_risks = conn.execute(
                    "SELECT COUNT(*) FROM threats WHERE org_id=? AND risk_rating='critical'",
                    (org_id,),
                ).fetchone()[0]

                mitigations_count = conn.execute(
                    "SELECT COUNT(*) FROM mitigations WHERE org_id=?", (org_id,)
                ).fetchone()[0]

                stride_rows = conn.execute(
                    """
                    SELECT stride_category, COUNT(*) as cnt
                    FROM threats WHERE org_id=?
                    GROUP BY stride_category
                    """,
                    (org_id,),
                ).fetchall()

        by_stride = {r[0]: r[1] for r in stride_rows}
        return {
            "total_models": total_models,
            "approved_models": approved_models,
            "total_threats": total_threats,
            "open_threats": open_threats,
            "by_stride": by_stride,
            "critical_risks": critical_risks,
            "mitigations_count": mitigations_count,
        }
