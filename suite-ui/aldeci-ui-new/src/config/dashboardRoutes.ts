/**
 * dashboardRoutes.ts — GenericDashboard route configuration
 *
 * Each entry maps a URL path to GenericDashboard props.
 * Generated 2026-04-27 — replaces 69 homogeneous *Dashboard.tsx pages
 * (all ≤115 LOC, same useEffect+apiFetch+stats+table pattern).
 *
 * Pages marked with:
 *   // REPLACED by GenericDashboard config in dashboardRoutes.ts 2026-04-27
 * at their top line — kept for git history, no longer imported in App.tsx.
 */

import type { GenericDashboardProps } from "@/components/GenericDashboard";

export interface DashboardRouteEntry {
  path: string;
  props: GenericDashboardProps;
}

export const DASHBOARD_ROUTES: DashboardRouteEntry[] = [
  // ── SBOM ────────────────────────────────────────────────────────────────
  {
    path: "/sbom-dashboard",
    props: {
      title: "SBOM",
      description: "Software Bill of Materials lifecycle management",
      apiPath: "/api/v1/sbom/components",
      itemsKey: "components",
      statsPath: "/api/v1/sbom/stats",
      kpis: [
        { key: "total_assets", label: "Total Assets", colorClass: "text-blue-400" },
        { key: "total_components", label: "Components", colorClass: "text-cyan-400" },
        { key: "vulnerable_components", label: "Vulnerable", colorClass: "text-red-400" },
        { key: "license_risks", label: "License Risks", colorClass: "text-amber-400" },
      ],
    },
  },
  // ── Quantum Crypto ───────────────────────────────────────────────────────
  {
    path: "/quantum-crypto",
    props: {
      title: "Quantum Cryptography",
      description: "Post-quantum readiness, key migration, and cryptographic asset management",
      apiPath: "/api/v1/quantum-crypto/assets",
      itemsKey: "assets",
      statsPath: "/api/v1/quantum-crypto/stats",
    },
  },
  // ── Privacy Impact ───────────────────────────────────────────────────────
  {
    path: "/privacy-impact",
    props: {
      title: "Privacy Impact",
      description: "Privacy impact assessments and data subject risk",
      apiPath: "/api/v1/privacy-impact/assessments",
      itemsKey: "assessments",
      statsPath: "/api/v1/privacy-impact/stats",
    },
  },
  // ── Upgrade Path ─────────────────────────────────────────────────────────
  {
    path: "/upgrade-path",
    props: {
      title: "Upgrade Path",
      description: "Recommended dependency upgrade paths and migration guidance",
      apiPath: "/api/v1/upgrade-path/recent",
      itemsKey: "upgrades",
      statsPath: "/api/v1/upgrade-path/stats",
    },
  },
  // ── Posture Scoring ──────────────────────────────────────────────────────
  {
    path: "/posture-scoring",
    props: {
      title: "Posture Scoring",
      description: "Security posture score history, control coverage, and trend analysis",
      apiPath: "/api/v1/posture-scoring/controls",
      itemsKey: "controls",
      statsPath: "/api/v1/posture-scoring/stats",
    },
  },
  // ── Threat Indicators ────────────────────────────────────────────────────
  {
    path: "/threat-indicators",
    props: {
      title: "Threat Indicators",
      description: "IOC feed — IPs, domains, hashes correlated against assets",
      apiPath: "/api/v1/threat-indicators/indicators",
      itemsKey: "indicators",
      statsPath: "/api/v1/threat-indicators/stats",
    },
  },
  // ── Zero Trust Policies ──────────────────────────────────────────────────
  {
    path: "/zero-trust-policies",
    props: {
      title: "Zero Trust Policies",
      description: "Policy definitions, access events, and enforcement status",
      apiPath: "/api/v1/zero-trust-policy/policies",
      itemsKey: "policies",
      statsPath: "/api/v1/zero-trust-policy/stats",
    },
  },
  // ── Patch Management ─────────────────────────────────────────────────────
  {
    path: "/patch-management",
    props: {
      title: "Patch Management",
      description: "Patch status, SLA compliance, and deployment tracking",
      apiPath: "/api/v1/patch-management/patches",
      itemsKey: "patches",
      statsPath: "/api/v1/patch-management/stats",
    },
  },
  // ── PAG (Privileged Access Governance) ──────────────────────────────────
  {
    path: "/pag",
    props: {
      title: "Privileged Access Governance",
      description: "Privileged account inventory, session audits, and access reviews",
      apiPath: "/api/v1/pag/accounts",
      itemsKey: "accounts",
      statsPath: "/api/v1/pag/stats",
    },
  },
  // ── Training Effectiveness ───────────────────────────────────────────────
  {
    path: "/training-effectiveness",
    props: {
      title: "Training Effectiveness",
      description: "Security training completion, quiz scores, and phishing simulation results",
      apiPath: "/api/v1/training-effectiveness/programs",
      itemsKey: "programs",
      statsPath: "/api/v1/training-effectiveness/stats",
    },
  },
  // ── SIEM Output ──────────────────────────────────────────────────────────
  {
    path: "/siem-output",
    props: {
      title: "SIEM Output",
      description: "SIEM forwarding targets, event throughput, and alert pipeline health",
      apiPath: "/api/v1/siem-output/events",
      itemsKey: "events",
      statsPath: "/api/v1/siem-output/stats",
    },
  },
  // ── SCA ──────────────────────────────────────────────────────────────────
  {
    path: "/sca",
    props: {
      title: "Software Composition Analysis",
      description: "Open-source dependency scanning and license compliance",
      apiPath: "/api/v1/sca/vulns",
      itemsKey: "vulns",
      statsPath: "/api/v1/sca/stats",
      kpis: [
        { key: "projects", label: "Projects", colorClass: "text-blue-400" },
        { key: "scans", label: "Scans", colorClass: "text-cyan-400" },
        { key: "vulnerable_dependencies", label: "Vulnerable Deps", colorClass: "text-red-400" },
        { key: "license_violations", label: "License Violations", colorClass: "text-amber-400" },
      ],
    },
  },
  // ── ServiceNow ───────────────────────────────────────────────────────────
  {
    path: "/servicenow",
    props: {
      title: "ServiceNow",
      description: "Incident sync, CMDB enrichment, and change management integration",
      apiPath: "/api/v1/servicenow/incidents",
      itemsKey: "incidents",
      statsPath: "/api/v1/servicenow/stats",
    },
  },
  // ── System Health ────────────────────────────────────────────────────────
  {
    path: "/system-health-dashboard",
    props: {
      title: "System Health",
      description: "Platform component health, latency, and error rates",
      apiPath: "/api/v1/system/health",
      itemsKey: "components",
      statsPath: "/api/v1/platform/health",
    },
  },
  // ── Compliance Workflows ─────────────────────────────────────────────────
  {
    path: "/compliance-workflows",
    props: {
      title: "Compliance Workflows",
      description: "Workflow definitions, task status, and overdue compliance actions",
      apiPath: "/api/v1/compliance-workflows/workflows",
      itemsKey: "workflows",
      statsPath: "/api/v1/compliance-workflows/stats",
    },
  },
  // ── Access Request Management ────────────────────────────────────────────
  {
    path: "/access-requests",
    props: {
      title: "Access Request Management",
      description: "Pending, approved, and denied access requests with audit trail",
      apiPath: "/api/v1/access-requests/requests",
      itemsKey: "requests",
      statsPath: "/api/v1/access-requests/stats",
    },
  },
  // ── AI Powered SOC ───────────────────────────────────────────────────────
  {
    path: "/ai-soc-dashboard",
    props: {
      title: "AI-Powered SOC",
      description: "AI-driven detection, triage, and analyst augmentation",
      apiPath: "/api/v1/ai-soc/detections",
      itemsKey: "detections",
      statsPath: "/api/v1/ai-soc/stats",
    },
  },
  // ── AI Security Advisor ──────────────────────────────────────────────────
  {
    path: "/ai-advisor-dashboard",
    props: {
      title: "AI Security Advisor",
      description: "Proactive security advisories and contextual recommendations",
      apiPath: "/api/v1/ai-advisor/advisories",
      itemsKey: "advisories",
      statsPath: "/api/v1/ai-advisor/stats",
    },
  },
  // ── API Threat Protection ────────────────────────────────────────────────
  {
    path: "/api-threat-protection",
    props: {
      title: "API Threat Protection",
      description: "Runtime API threat detection, rate limiting, and abuse patterns",
      apiPath: "/api/v1/api-threat-protection/threats",
      itemsKey: "threats",
      statsPath: "/api/v1/api-threat-protection/stats",
    },
  },
  // ── Asset Tags ───────────────────────────────────────────────────────────
  {
    path: "/asset-tags",
    props: {
      title: "Asset Tags",
      description: "Asset tagging policies, coverage, and classification health",
      apiPath: "/api/v1/asset-tags/tags",
      itemsKey: "tags",
      statsPath: "/api/v1/asset-tags/stats",
    },
  },
  // ── Awareness Campaigns ──────────────────────────────────────────────────
  {
    path: "/awareness-campaigns",
    props: {
      title: "Awareness Campaigns",
      description: "Phishing simulation, e-learning campaigns, and completion rates",
      apiPath: "/api/v1/awareness-campaigns/campaigns",
      itemsKey: "campaigns",
      statsPath: "/api/v1/awareness-campaigns/stats",
    },
  },
  // ── Awareness Metrics ────────────────────────────────────────────────────
  {
    path: "/awareness-metrics",
    props: {
      title: "Awareness Metrics",
      description: "Security awareness program KPIs and behavioral risk trends",
      apiPath: "/api/v1/awareness-metrics/metrics",
      itemsKey: "metrics",
      statsPath: "/api/v1/awareness-metrics/stats",
    },
  },
  // ── Awareness Program ────────────────────────────────────────────────────
  {
    path: "/awareness-program",
    props: {
      title: "Awareness Program",
      description: "Full security awareness program overview and enrollment",
      apiPath: "/api/v1/awareness-program/programs",
      itemsKey: "programs",
      statsPath: "/api/v1/awareness-program/stats",
    },
  },
  // ── Behavioral Analytics ─────────────────────────────────────────────────
  {
    path: "/behavioral-analytics",
    props: {
      title: "Behavioral Analytics",
      description: "User and entity behavior analytics — anomaly detection and risk scoring",
      apiPath: "/api/v1/behavioral-analytics/anomalies",
      itemsKey: "anomalies",
      statsPath: "/api/v1/behavioral-analytics/stats",
    },
  },
  // ── Capacity Planning ────────────────────────────────────────────────────
  {
    path: "/capacity-planning",
    props: {
      title: "Capacity Planning",
      description: "Infrastructure capacity forecasts and resource utilization",
      apiPath: "/api/v1/capacity-planning/plans",
      itemsKey: "plans",
      statsPath: "/api/v1/capacity-planning/stats",
    },
  },
  // ── Certificates ─────────────────────────────────────────────────────────
  {
    path: "/certificates",
    props: {
      title: "Certificate Management",
      description: "TLS certificate inventory, expiry tracking, and CA hierarchy",
      apiPath: "/api/v1/certificates/certificates",
      itemsKey: "certificates",
      statsPath: "/api/v1/certificates/stats",
    },
  },
  // ── Change Management ────────────────────────────────────────────────────
  {
    path: "/change-management",
    props: {
      title: "Change Management",
      description: "Change requests, approval workflows, and risk assessments",
      apiPath: "/api/v1/change-management/changes",
      itemsKey: "changes",
      statsPath: "/api/v1/change-management/stats",
    },
  },
  // ── CISO Report ──────────────────────────────────────────────────────────
  {
    path: "/ciso-report",
    props: {
      title: "CISO Report",
      description: "Executive-ready security posture summary for board reporting",
      apiPath: "/api/v1/ciso-report/sections",
      itemsKey: "sections",
      statsPath: "/api/v1/ciso-report/stats",
    },
  },
  // ── Cloud Access Security ────────────────────────────────────────────────
  {
    path: "/cloud-access-security",
    props: {
      title: "Cloud Access Security",
      description: "SaaS app discovery, DLP policies, and shadow IT detection",
      apiPath: "/api/v1/cloud-access-security/apps",
      itemsKey: "apps",
      statsPath: "/api/v1/cloud-access-security/stats",
    },
  },
  // ── Cloud Accounts ───────────────────────────────────────────────────────
  {
    path: "/cloud-accounts",
    props: {
      title: "Cloud Accounts",
      description: "Multi-cloud account inventory, hygiene scores, and access reviews",
      apiPath: "/api/v1/cloud-accounts/accounts",
      itemsKey: "accounts",
      statsPath: "/api/v1/cloud-accounts/stats",
    },
  },
  // ── Cloud Compliance ─────────────────────────────────────────────────────
  {
    path: "/cloud-compliance",
    props: {
      title: "Cloud Compliance",
      description: "CIS benchmark control coverage across cloud accounts",
      apiPath: "/api/v1/cloud-compliance/controls",
      itemsKey: "controls",
      statsPath: "/api/v1/cloud-compliance/stats",
    },
  },
  // ── Cloud Cost Optimization ──────────────────────────────────────────────
  {
    path: "/cost-optimization",
    props: {
      title: "Cloud Cost Optimization",
      description: "Security-aware resource rightsizing and cost reduction opportunities",
      apiPath: "/api/v1/cost-optimization/tools",
      itemsKey: "tools",
      statsPath: "/api/v1/cost-optimization/stats",
    },
  },
  // ── Cloud Identity ───────────────────────────────────────────────────────
  {
    path: "/cloud-identity",
    props: {
      title: "Cloud Identity",
      description: "IAM identities, over-privileged accounts, and federated SSO health",
      apiPath: "/api/v1/cloud-identity/identities",
      itemsKey: "identities",
      statsPath: "/api/v1/cloud-identity/stats",
    },
  },
  // ── Cloud Resource Inventory ─────────────────────────────────────────────
  {
    path: "/cloud-inventory",
    props: {
      title: "Cloud Resource Inventory",
      description: "Complete multi-cloud asset catalogue with security metadata",
      apiPath: "/api/v1/cloud-inventory/resources",
      itemsKey: "resources",
      statsPath: "/api/v1/cloud-inventory/stats",
    },
  },
  // ── Cloud Security Analytics ─────────────────────────────────────────────
  {
    path: "/cloud-security-analytics",
    props: {
      title: "Cloud Security Analytics",
      description: "Cloud telemetry aggregation, anomaly detection, and trend analysis",
      apiPath: "/api/v1/cloud-analytics/events",
      itemsKey: "events",
      statsPath: "/api/v1/cloud-analytics/stats",
    },
  },
  // ── Cloud Security Findings ──────────────────────────────────────────────
  {
    path: "/cloud-findings",
    props: {
      title: "Cloud Security Findings",
      description: "Misconfigurations, exposure risks, and cloud-native threat detections",
      apiPath: "/api/v1/cloud-findings/findings",
      itemsKey: "findings",
      statsPath: "/api/v1/cloud-findings/stats",
    },
  },
  // ── Compliance ───────────────────────────────────────────────────────────
  {
    path: "/compliance-frameworks",
    props: {
      title: "Compliance Frameworks",
      description: "Framework coverage, control pass rates, and remediation backlogs",
      apiPath: "/api/v1/compliance/frameworks",
      itemsKey: "frameworks",
      statsPath: "/api/v1/compliance/stats",
    },
  },
  // ── Container Posture ────────────────────────────────────────────────────
  {
    path: "/container-posture",
    props: {
      title: "Container Posture",
      description: "Cluster security posture, pod policies, and runtime threats",
      apiPath: "/api/v1/container-posture/clusters",
      itemsKey: "clusters",
      statsPath: "/api/v1/container-posture/stats",
    },
  },
  // ── Container Registry ───────────────────────────────────────────────────
  {
    path: "/container-registry",
    props: {
      title: "Container Registry",
      description: "Image vulnerability scanning, base image drift, and signing status",
      apiPath: "/api/v1/container-registry-security/images",
      itemsKey: "images",
      statsPath: "/api/v1/container-registry-security/stats",
    },
  },
  // ── Crypto Keys ──────────────────────────────────────────────────────────
  {
    path: "/crypto-keys",
    props: {
      title: "Crypto Key Management",
      description: "Key inventory, rotation schedules, and HSM integration status",
      apiPath: "/api/v1/crypto-keys/keys",
      itemsKey: "keys",
      statsPath: "/api/v1/crypto-keys/stats",
    },
  },
  // ── Cyber Threat Intel ───────────────────────────────────────────────────
  {
    path: "/cyber-threat-intel",
    props: {
      title: "Cyber Threat Intelligence",
      description: "Threat reports, actor profiles, and intelligence feed health",
      apiPath: "/api/v1/cyber-threat-intel/reports",
      itemsKey: "reports",
      statsPath: "/api/v1/cyber-threat-intel/stats",
    },
  },
  // ── Cyber Threat Modeling ────────────────────────────────────────────────
  {
    path: "/cyber-threat-modeling",
    props: {
      title: "Cyber Threat Modeling",
      description: "Threat model library, STRIDE analysis, and DFD-based risk scoring",
      apiPath: "/api/v1/cyber-threat-models/models",
      itemsKey: "models",
      statsPath: "/api/v1/cyber-threat-models/stats",
    },
  },
  // ── DAST ─────────────────────────────────────────────────────────────────
  {
    path: "/dast",
    props: {
      title: "DAST",
      description: "Dynamic application security testing — live scan results",
      apiPath: "/api/v1/dast/scans",
      itemsKey: "scans",
      statsPath: "/api/v1/dast/stats",
    },
  },
  // ── Data Discovery ───────────────────────────────────────────────────────
  {
    path: "/data-discovery",
    props: {
      title: "Data Discovery",
      description: "Sensitive data store discovery, classification, and exposure risk",
      apiPath: "/api/v1/data-discovery/datastores",
      itemsKey: "datastores",
      statsPath: "/api/v1/data-discovery/stats",
    },
  },
  // ── Data Pipeline ────────────────────────────────────────────────────────
  {
    path: "/data-pipeline",
    props: {
      title: "Data Pipeline",
      description: "Security data pipeline sources, transform health, and ingestion rates",
      apiPath: "/api/v1/data-pipeline/sources",
      itemsKey: "sources",
      statsPath: "/api/v1/data-pipeline/stats",
    },
  },
  // ── Digital Identity ─────────────────────────────────────────────────────
  {
    path: "/digital-identity",
    props: {
      title: "Digital Identity",
      description: "Identity lifecycle, credential hygiene, and access risk scoring",
      apiPath: "/api/v1/digital-identity/identities",
      itemsKey: "identities",
      statsPath: "/api/v1/digital-identity/stats",
    },
  },
  // ── Digital Twin ─────────────────────────────────────────────────────────
  {
    path: "/digital-twin",
    props: {
      title: "Digital Twin",
      description: "Asset twin registry, drift detection, and compliance simulation",
      apiPath: "/api/v1/digital-twin/twins",
      itemsKey: "twins",
      statsPath: "/api/v1/digital-twin/stats",
    },
  },
  // ── DLP ──────────────────────────────────────────────────────────────────
  {
    path: "/dlp",
    props: {
      title: "Data Loss Prevention",
      description: "DLP policies, incident queue, and sensitive data egress monitoring",
      apiPath: "/api/v1/dlp/policies",
      itemsKey: "policies",
      statsPath: "/api/v1/dlp/stats",
    },
  },
  // ── Endpoint Hunting ─────────────────────────────────────────────────────
  {
    path: "/endpoint-hunting",
    props: {
      title: "Endpoint Hunting",
      description: "Proactive endpoint threat hunts, hypotheses, and findings",
      apiPath: "/api/v1/endpoint-hunting/hunts",
      itemsKey: "hunts",
      statsPath: "/api/v1/endpoint-hunting/stats",
    },
  },
  // ── Event Timeline ───────────────────────────────────────────────────────
  {
    path: "/event-timeline",
    props: {
      title: "Event Timeline",
      description: "Chronological security event correlation and investigation pivot",
      apiPath: "/api/v1/event-timeline/timelines",
      itemsKey: "timelines",
      statsPath: "/api/v1/event-timeline/stats",
    },
  },
  // ── Exception Workflow ───────────────────────────────────────────────────
  {
    path: "/exception-workflow",
    props: {
      title: "Exception Workflow",
      description: "Security exception requests, approvals, and expiry tracking",
      apiPath: "/api/v1/exception-workflow/exceptions",
      itemsKey: "exceptions",
      statsPath: "/api/v1/exception-workflow/stats",
    },
  },
  // ── Gap Analysis ─────────────────────────────────────────────────────────
  {
    path: "/gap-analysis",
    props: {
      title: "Gap Analysis",
      description: "Control gap identification against target security frameworks",
      apiPath: "/api/v1/gap-analysis/analyses",
      itemsKey: "analyses",
      statsPath: "/api/v1/gap-analysis/stats",
    },
  },
  // ── Identity Risk ────────────────────────────────────────────────────────
  {
    path: "/identity-risk",
    props: {
      title: "Identity Risk",
      description: "Identity-based risk scoring, anomalous access, and MFA gaps",
      apiPath: "/api/v1/identity-risk/identities",
      itemsKey: "identities",
      statsPath: "/api/v1/identity-risk/stats",
    },
  },
  // ── Incident Comms ───────────────────────────────────────────────────────
  {
    path: "/incident-comms",
    props: {
      title: "Incident Communications",
      description: "Stakeholder communication logs, status page updates, and notification history",
      apiPath: "/api/v1/incident-comms/communications",
      itemsKey: "communications",
      statsPath: "/api/v1/incident-comms/stats",
    },
  },
  // ── Incident Costs ───────────────────────────────────────────────────────
  {
    path: "/incident-costs",
    props: {
      title: "Incident Costs",
      description: "Financial impact tracking for security incidents and breaches",
      apiPath: "/api/v1/incident-costs/costs",
      itemsKey: "costs",
      statsPath: "/api/v1/incident-costs/stats",
    },
  },
  // ── Incident KB ──────────────────────────────────────────────────────────
  {
    path: "/incident-kb",
    props: {
      title: "Incident Knowledge Base",
      description: "Playbook articles, runbooks, and post-mortem documentation",
      apiPath: "/api/v1/incident-kb/articles",
      itemsKey: "articles",
      statsPath: "/api/v1/incident-kb/stats",
    },
  },
  // ── Incident Lessons ─────────────────────────────────────────────────────
  {
    path: "/incident-lessons",
    props: {
      title: "Incident Lessons Learned",
      description: "Post-incident review outcomes and remediation action tracking",
      apiPath: "/api/v1/incident-lessons/lessons",
      itemsKey: "lessons",
      statsPath: "/api/v1/incident-lessons/stats",
    },
  },
  // ── IP Reputation ────────────────────────────────────────────────────────
  {
    path: "/ip-reputation",
    props: {
      title: "IP Reputation",
      description: "Blocklist management, reputation feeds, and asset exposure to bad IPs",
      apiPath: "/api/v1/ip-reputation/blocklist",
      itemsKey: "blocklist",
      statsPath: "/api/v1/ip-reputation/stats",
    },
  },
  // ── IR Playbook ──────────────────────────────────────────────────────────
  {
    path: "/ir-playbook",
    props: {
      title: "IR Playbooks",
      description: "Incident response playbook library and execution history",
      apiPath: "/api/v1/ir/playbooks",
      itemsKey: "playbooks",
      statsPath: "/api/v1/ir/stats",
    },
  },
  // ── Alert Enrichment ─────────────────────────────────────────────────────
  {
    path: "/alert-enrichment",
    props: {
      title: "Alert Enrichment",
      description: "Contextual enrichment pipeline for SIEM and EDR alerts",
      apiPath: "/api/v1/alert-enrichment/alerts",
      itemsKey: "alerts",
      statsPath: "/api/v1/alert-enrichment/stats",
    },
  },
  // ── Application Risk ─────────────────────────────────────────────────────
  {
    path: "/application-risk",
    props: {
      title: "Application Risk",
      description: "Application risk scores, exposure surface, and security debt",
      apiPath: "/api/v1/app-risk/applications",
      itemsKey: "applications",
      statsPath: "/api/v1/app-risk/stats",
    },
  },
  // ── Attack Chain ─────────────────────────────────────────────────────────
  {
    path: "/attack-chains",
    props: {
      title: "Attack Chains",
      description: "Multi-stage attack path chains and lateral movement risk",
      apiPath: "/api/v1/attack-chains/chains",
      itemsKey: "chains",
      statsPath: "/api/v1/attack-chains/stats",
    },
  },
  // ── Attack Surface ───────────────────────────────────────────────────────
  {
    path: "/attack-surface-dashboard",
    props: {
      title: "Attack Surface",
      description: "External exposure inventory, reachability, and attack surface reduction",
      apiPath: "/api/v1/attack-surface/exposures",
      itemsKey: "exposures",
      statsPath: "/api/v1/attack-surface/stats",
    },
  },
  // ── Cloud Posture ────────────────────────────────────────────────────────
  {
    path: "/cloud-posture-dashboard",
    props: {
      title: "Cloud Posture",
      description: "CSPM findings, misconfigurations, and cloud security benchmark scores",
      apiPath: "/api/v1/cloud-posture/findings",
      itemsKey: "findings",
      statsPath: "/api/v1/cloud-posture/stats",
    },
  },
  // ── Evidence Vault ───────────────────────────────────────────────────────
  {
    path: "/evidence-vault-dashboard",
    props: {
      title: "Evidence Vault",
      description: "Immutable evidence store with cryptographic integrity verification",
      apiPath: "/api/v1/evidence-vault/items",
      itemsKey: "items",
      statsPath: "/api/v1/evidence-vault/stats",
    },
  },
  // ── Ransomware Protection ────────────────────────────────────────────────
  {
    path: "/ransomware-protection",
    props: {
      title: "Ransomware Protection",
      description: "Ransomware pattern detection, backup health, and recovery readiness",
      apiPath: "/api/v1/ransomware-protection/patterns",
      itemsKey: "patterns",
      statsPath: "/api/v1/ransomware-protection/stats",
    },
  },
  // ── Access Anomaly ───────────────────────────────────────────────────────
  {
    path: "/access-anomaly",
    props: {
      title: "Access Anomaly",
      description: "Unusual access patterns, time-of-day anomalies, and impossible travel",
      apiPath: "/api/v1/access-anomaly/anomalies",
      itemsKey: "anomalies",
      statsPath: "/api/v1/access-anomaly/stats",
    },
  },
  // ── Actor Tracking ───────────────────────────────────────────────────────
  {
    path: "/actor-tracking",
    props: {
      title: "Threat Actor Tracking",
      description: "Known threat actor profiles, TTPs, and campaign attribution",
      apiPath: "/api/v1/actor-tracking/actors",
      itemsKey: "actors",
      statsPath: "/api/v1/actor-tracking/stats",
    },
  },
  // ── API Inventory ────────────────────────────────────────────────────────
  {
    path: "/api-inventory",
    props: {
      title: "API Inventory",
      description: "Discovered API endpoints, authentication coverage, and risk ratings",
      apiPath: "/api/v1/api-inventory/apis",
      itemsKey: "apis",
      statsPath: "/api/v1/api-inventory/stats",
    },
  },
];

/**
 * Quick lookup: route path → GenericDashboard props
 */
export const DASHBOARD_ROUTE_MAP: Record<string, GenericDashboardProps> =
  Object.fromEntries(DASHBOARD_ROUTES.map((r) => [r.path, r.props]));
