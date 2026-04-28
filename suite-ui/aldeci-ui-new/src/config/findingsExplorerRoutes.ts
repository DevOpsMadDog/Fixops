/**
 * findingsExplorerRoutes.ts — FindingsExplorerView route configuration
 *
 * Each entry maps a URL path to FindingsExplorerView props.
 * Generated 2026-04-27 — Pattern-2 mechanical collapse (UX Phase 3 Wave 4)
 * Replaces ~40 pages (116-200 LOC) with severity filter + findings table shape.
 *
 * Pages marked with:
 *   // REPLACED by FindingsExplorerView config 2026-04-27
 * at their top line — kept for git history, no longer imported in App.tsx.
 */

import type { FindingsExplorerViewProps } from "@/components/FindingsExplorerView";

export interface FindingsExplorerRouteEntry {
  path: string;
  props: FindingsExplorerViewProps;
}

export const FINDINGS_EXPLORER_ROUTES: FindingsExplorerRouteEntry[] = [
  // ── Security Findings ─────────────────────────────────────────────────────
  {
    path: "/security-findings",
    props: {
      title: "Security Findings",
      description: "Aggregated findings from all scanners with lifecycle tracking",
      apiPath: "/api/v1/security-findings/findings",
      itemsKey: "findings",
      statsPath: "/api/v1/security-findings/summary",
      severityKey: "severity",
      columns: [
        { key: "title",       label: "Title",     className: "max-w-[260px]" },
        { key: "severity",    label: "Severity",  isSeverity: true },
        { key: "cvss",        label: "CVSS" },
        { key: "status",      label: "Status",    isStatus: true },
        { key: "asset",       label: "Asset" },
        { key: "detected_at", label: "Detected" },
      ],
      kpis: [
        { key: "critical", label: "Critical", colorClass: "text-red-400" },
        { key: "high",     label: "High",     colorClass: "text-orange-400" },
        { key: "medium",   label: "Medium",   colorClass: "text-amber-400" },
        { key: "low",      label: "Low",      colorClass: "text-blue-400" },
      ],
    },
  },

  // ── Issue Queue ───────────────────────────────────────────────────────────
  {
    path: "/issue-queue",
    props: {
      title: "Issue Queue",
      description: "New findings inbox — open findings awaiting triage",
      apiPath: "/api/v1/findings",
      itemsKey: "findings",
      statsPath: "/api/v1/findings/stats",
      severityKey: "severity",
      columns: [
        { key: "title",      label: "Title",    className: "max-w-[260px]" },
        { key: "severity",   label: "Severity", isSeverity: true },
        { key: "status",     label: "Status",   isStatus: true },
        { key: "asset",      label: "Asset" },
        { key: "scanner",    label: "Scanner" },
        { key: "created_at", label: "Created" },
      ],
    },
  },

  // ── Snapshot Findings ─────────────────────────────────────────────────────
  {
    path: "/snapshot-findings",
    props: {
      title: "Snapshot Findings",
      description: "CSPM snapshot scan findings across cloud resources",
      apiPath: "/api/v1/cspm/findings",
      itemsKey: "findings",
      statsPath: "/api/v1/cspm/stats",
      severityKey: "severity",
      columns: [
        { key: "resource",   label: "Resource",  className: "max-w-[220px]" },
        { key: "severity",   label: "Severity",  isSeverity: true },
        { key: "rule",       label: "Rule" },
        { key: "status",     label: "Status",    isStatus: true },
        { key: "region",     label: "Region" },
        { key: "detected_at",label: "Detected" },
      ],
    },
  },

  // ── Toxic Combination Issues ──────────────────────────────────────────────
  {
    path: "/issues/toxic",
    props: {
      title: "Toxic Combination Issues",
      description: "Multi-finding combinations (e.g. public bucket + writable IAM + sensitive data)",
      apiPath: "/api/v1/issues/toxic",
      itemsKey: "issues",
      statsPath: "/api/v1/issues/stats",
      severityKey: "severity",
      columns: [
        { key: "title",          label: "Combination",   className: "max-w-[260px]" },
        { key: "severity",       label: "Severity",      isSeverity: true },
        { key: "finding_count",  label: "Findings" },
        { key: "assets_affected",label: "Assets" },
        { key: "status",         label: "Status",        isStatus: true },
        { key: "detected_at",    label: "Detected" },
      ],
    },
  },

  // ── SOC Triage ────────────────────────────────────────────────────────────
  {
    path: "/soc-triage",
    props: {
      title: "SOC Triage",
      description: "Alert triage queue with AI-assisted verdict recommendations",
      apiPath: "/api/v1/soc-triage/alerts",
      itemsKey: "alerts",
      statsPath: "/api/v1/soc-triage/stats",
      severityKey: "severity",
      columns: [
        { key: "title",       label: "Alert",     className: "max-w-[240px]" },
        { key: "severity",    label: "Severity",  isSeverity: true },
        { key: "source",      label: "Source" },
        { key: "status",      label: "Status",    isStatus: true },
        { key: "assigned_to", label: "Assignee" },
        { key: "created_at",  label: "Created" },
      ],
    },
  },

  // ── Drift Tracking ────────────────────────────────────────────────────────
  {
    path: "/drift-tracking",
    props: {
      title: "Drift Tracking",
      description: "Security baseline drift — findings that deviate from approved posture",
      apiPath: "/api/v1/findings/drift",
      itemsKey: "findings",
      statsPath: "/api/v1/findings/drift/stats",
      severityKey: "severity",
      columns: [
        { key: "asset",        label: "Asset",     className: "max-w-[220px]" },
        { key: "severity",     label: "Severity",  isSeverity: true },
        { key: "drift_type",   label: "Drift Type" },
        { key: "baseline",     label: "Baseline" },
        { key: "current",      label: "Current" },
        { key: "detected_at",  label: "Detected" },
      ],
    },
  },

  // ── Stale Baseline ────────────────────────────────────────────────────────
  {
    path: "/stale-baseline",
    props: {
      title: "Stale Baseline",
      description: "Assets with outdated security baselines requiring re-evaluation",
      apiPath: "/api/v1/findings/drift",
      itemsKey: "findings",
      statsPath: "/api/v1/findings/drift/stats",
      severityKey: "severity",
      columns: [
        { key: "asset",       label: "Asset",      className: "max-w-[220px]" },
        { key: "severity",    label: "Severity",   isSeverity: true },
        { key: "baseline_age",label: "Baseline Age" },
        { key: "last_scanned",label: "Last Scanned" },
        { key: "status",      label: "Status",     isStatus: true },
        { key: "detected_at", label: "Detected" },
      ],
    },
  },

  // ── Secret Scanner ────────────────────────────────────────────────────────
  {
    path: "/secret-scanner",
    props: {
      title: "Secret Scanner",
      description: "Detected secrets, API keys, and credentials in source code and configs",
      apiPath: "/api/v1/secret-scanner/findings",
      itemsKey: "findings",
      statsPath: "/api/v1/secret-scanner/stats",
      severityKey: "severity",
      columns: [
        { key: "secret_type", label: "Type",       className: "max-w-[160px]" },
        { key: "severity",    label: "Severity",   isSeverity: true },
        { key: "file_path",   label: "File" },
        { key: "repository",  label: "Repository" },
        { key: "status",      label: "Status",     isStatus: true },
        { key: "detected_at", label: "Detected" },
      ],
    },
  },

  // ── Vulnerability Age ─────────────────────────────────────────────────────
  {
    path: "/vuln-age",
    props: {
      title: "Vulnerability Age",
      description: "Age distribution of open vulnerabilities and SLA compliance tracking",
      apiPath: "/api/v1/vuln-age/distribution",
      itemsKey: "vulnerabilities",
      statsPath: "/api/v1/vuln-age/stats",
      severityKey: "severity",
      columns: [
        { key: "cve_id",       label: "CVE",       className: "font-mono" },
        { key: "severity",     label: "Severity",  isSeverity: true },
        { key: "age_days",     label: "Age (days)" },
        { key: "sla_status",   label: "SLA",       isStatus: true },
        { key: "asset",        label: "Asset" },
        { key: "detected_at",  label: "Detected" },
      ],
      kpis: [
        { key: "overdue",          label: "Overdue",       colorClass: "text-red-400" },
        { key: "at_risk",          label: "At Risk",       colorClass: "text-orange-400" },
        { key: "avg_age_days",     label: "Avg Age",       colorClass: "text-amber-400" },
        { key: "total_open",       label: "Total Open",    colorClass: "text-indigo-400" },
      ],
    },
  },

  // ── Security Dependency Risk ──────────────────────────────────────────────
  {
    path: "/dependency-risk",
    props: {
      title: "Dependency Risk",
      description: "Vulnerable and license-risk dependencies across all repositories",
      apiPath: "/api/v1/dependency-risk/summary",
      itemsKey: "dependencies",
      statsPath: "/api/v1/dependency-risk/stats",
      severityKey: "severity",
      columns: [
        { key: "package",     label: "Package",   className: "max-w-[200px] font-mono" },
        { key: "severity",    label: "Severity",  isSeverity: true },
        { key: "cve_id",      label: "CVE" },
        { key: "version",     label: "Version" },
        { key: "repository",  label: "Repo" },
        { key: "detected_at", label: "Detected" },
      ],
    },
  },

  // ── Security Baseline ─────────────────────────────────────────────────────
  {
    path: "/security-baselines",
    props: {
      title: "Security Baselines",
      description: "Baseline compliance status across all monitored assets",
      apiPath: "/api/v1/security-baselines/baselines",
      itemsKey: "baselines",
      statsPath: "/api/v1/security-baselines/stats",
      severityKey: "severity",
      columns: [
        { key: "baseline_name", label: "Baseline",   className: "max-w-[220px]" },
        { key: "severity",      label: "Severity",   isSeverity: true },
        { key: "compliance_pct",label: "Compliance %" },
        { key: "asset_count",   label: "Assets" },
        { key: "status",        label: "Status",     isStatus: true },
        { key: "updated_at",    label: "Updated" },
      ],
    },
  },

  // ── Stage Policy Matrix ───────────────────────────────────────────────────
  {
    path: "/stage-policy-matrix",
    props: {
      title: "Stage Policy Matrix",
      description: "Policy enforcement per pipeline stage with violation tracking",
      apiPath: "/api/v1/policies",
      itemsKey: "policies",
      statsPath: "/api/v1/policies/stats",
      severityKey: "severity",
      columns: [
        { key: "policy_name", label: "Policy",    className: "max-w-[220px]" },
        { key: "severity",    label: "Severity",  isSeverity: true },
        { key: "stage",       label: "Stage" },
        { key: "action",      label: "Action" },
        { key: "violations",  label: "Violations" },
        { key: "updated_at",  label: "Updated" },
      ],
    },
  },

  // ── Choke Points ─────────────────────────────────────────────────────────
  {
    path: "/choke-points",
    props: {
      title: "Choke Points",
      description: "High-impact attack path choke points requiring immediate attention",
      apiPath: "/api/v1/attack-paths/choke-points",
      itemsKey: "choke_points",
      statsPath: "/api/v1/attack-paths/stats",
      severityKey: "severity",
      columns: [
        { key: "asset",            label: "Asset",         className: "max-w-[220px]" },
        { key: "severity",         label: "Severity",      isSeverity: true },
        { key: "attack_paths",     label: "Attack Paths" },
        { key: "exploitability",   label: "Exploitability" },
        { key: "status",           label: "Status",        isStatus: true },
        { key: "detected_at",      label: "Detected" },
      ],
    },
  },

  // ── Threat Landscape ──────────────────────────────────────────────────────
  {
    path: "/threat-landscape",
    props: {
      title: "Threat Landscape",
      description: "Active threat actors, emerging threats, and attack campaign tracking",
      apiPath: "/api/v1/threat-landscape/actors",
      itemsKey: "actors",
      statsPath: "/api/v1/threat-landscape/stats",
      severityKey: "severity",
      filterOptions: ["critical", "high", "medium", "low"],
      columns: [
        { key: "actor_name",    label: "Threat Actor",  className: "max-w-[220px]" },
        { key: "severity",      label: "Severity",      isSeverity: true },
        { key: "origin",        label: "Origin" },
        { key: "targeting",     label: "Targeting" },
        { key: "status",        label: "Status",        isStatus: true },
        { key: "last_seen",     label: "Last Seen" },
      ],
    },
  },

  // ── Privilege Escalation ──────────────────────────────────────────────────
  {
    path: "/privilege-escalation",
    props: {
      title: "Privilege Escalation",
      description: "Detected privilege escalation attempts and anomalous role changes",
      apiPath: "/api/v1/privilege-escalation/events",
      itemsKey: "events",
      statsPath: "/api/v1/privilege-escalation/stats",
      severityKey: "severity",
      columns: [
        { key: "user",          label: "User",          className: "max-w-[180px]" },
        { key: "severity",      label: "Severity",      isSeverity: true },
        { key: "from_role",     label: "From Role" },
        { key: "to_role",       label: "To Role" },
        { key: "method",        label: "Method" },
        { key: "timestamp",     label: "Time" },
      ],
      kpis: [
        { key: "total_events",      label: "Total Events",    colorClass: "text-indigo-400" },
        { key: "anomalies_detected",label: "Anomalies",       colorClass: "text-red-400" },
        { key: "blocked_attempts",  label: "Blocked",         colorClass: "text-emerald-400" },
        { key: "alert_rate",        label: "Alert Rate",      colorClass: "text-amber-400" },
      ],
    },
  },

  // ── Threat Deception ─────────────────────────────────────────────────────
  {
    path: "/threat-deception",
    props: {
      title: "Threat Deception",
      description: "Decoy asset interactions and attacker engagement tracking",
      apiPath: "/api/v1/threat-deception/decoys",
      itemsKey: "decoys",
      statsPath: "/api/v1/threat-deception/stats",
      severityKey: "severity",
      columns: [
        { key: "decoy_name",    label: "Decoy",         className: "max-w-[200px]" },
        { key: "severity",      label: "Severity",      isSeverity: true },
        { key: "decoy_type",    label: "Type" },
        { key: "interactions",  label: "Interactions" },
        { key: "status",        label: "Status",        isStatus: true },
        { key: "last_triggered",label: "Last Triggered" },
      ],
    },
  },

  // ── Network Forensics ─────────────────────────────────────────────────────
  {
    path: "/network-forensics",
    props: {
      title: "Network Forensics",
      description: "Network capture analysis and forensic artifact correlation",
      apiPath: "/api/v1/network-forensics/captures",
      itemsKey: "captures",
      statsPath: "/api/v1/network-forensics/stats",
      severityKey: "severity",
      columns: [
        { key: "capture_id",  label: "Capture",    className: "font-mono max-w-[160px]" },
        { key: "severity",    label: "Severity",   isSeverity: true },
        { key: "source_ip",   label: "Source IP" },
        { key: "protocol",    label: "Protocol" },
        { key: "artifact_count",label: "Artifacts" },
        { key: "captured_at", label: "Captured" },
      ],
    },
  },

  // ── Malware Analysis ──────────────────────────────────────────────────────
  {
    path: "/malware-analysis",
    props: {
      title: "Malware Analysis",
      description: "Malware sample analysis results and threat classification",
      apiPath: "/api/v1/malware-analysis/samples",
      itemsKey: "samples",
      statsPath: "/api/v1/malware-analysis/stats",
      severityKey: "severity",
      columns: [
        { key: "sample_name",   label: "Sample",      className: "max-w-[200px] font-mono" },
        { key: "severity",      label: "Severity",    isSeverity: true },
        { key: "malware_family",label: "Family" },
        { key: "confidence",    label: "Confidence" },
        { key: "status",        label: "Status",      isStatus: true },
        { key: "analyzed_at",   label: "Analyzed" },
      ],
    },
  },

  // ── Material Changes ──────────────────────────────────────────────────────
  {
    path: "/material-changes",
    props: {
      title: "Material Changes",
      description: "Security-relevant code and infrastructure changes requiring review",
      apiPath: "/api/v1/changes/material",
      itemsKey: "changes",
      statsPath: "/api/v1/changes/stats",
      severityKey: "severity",
      columns: [
        { key: "change_title", label: "Change",      className: "max-w-[240px]" },
        { key: "severity",     label: "Severity",    isSeverity: true },
        { key: "change_type",  label: "Type" },
        { key: "author",       label: "Author" },
        { key: "status",       label: "Status",      isStatus: true },
        { key: "changed_at",   label: "Changed" },
      ],
    },
  },

  // ── User Access Review ────────────────────────────────────────────────────
  {
    path: "/access-reviews",
    props: {
      title: "User Access Reviews",
      description: "Periodic access reviews and entitlement certification campaigns",
      apiPath: "/api/v1/access-reviews/reviews",
      itemsKey: "reviews",
      statsPath: "/api/v1/access-reviews/stats",
      severityKey: "severity",
      columns: [
        { key: "user",        label: "User",       className: "max-w-[180px]" },
        { key: "severity",    label: "Severity",   isSeverity: true },
        { key: "access_type", label: "Access Type" },
        { key: "resource",    label: "Resource" },
        { key: "status",      label: "Status",     isStatus: true },
        { key: "reviewed_at", label: "Reviewed" },
      ],
    },
  },

  // ── Agentless Scan Status ─────────────────────────────────────────────────
  {
    path: "/agentless-scan",
    props: {
      title: "Agentless Scan Status",
      description: "Agentless CSPM scan results and cloud asset coverage",
      apiPath: "/api/v1/cspm/agentless/status",
      itemsKey: "scans",
      statsPath: "/api/v1/cspm/agentless/stats",
      severityKey: "severity",
      columns: [
        { key: "account_id",  label: "Account",    className: "font-mono" },
        { key: "severity",    label: "Severity",   isSeverity: true },
        { key: "resource_type",label: "Resource Type" },
        { key: "findings",    label: "Findings" },
        { key: "status",      label: "Status",     isStatus: true },
        { key: "scanned_at",  label: "Scanned" },
      ],
    },
  },

  // ── Security Health Scorecard ─────────────────────────────────────────────
  {
    path: "/health-scorecard",
    props: {
      title: "Security Health Scorecard",
      description: "Domain-level security health scores and improvement tracking",
      apiPath: "/api/v1/health-scorecard/domains",
      itemsKey: "domains",
      statsPath: "/api/v1/health-scorecard/stats",
      severityKey: "severity",
      columns: [
        { key: "domain",      label: "Domain",    className: "max-w-[200px]" },
        { key: "severity",    label: "Severity",  isSeverity: true },
        { key: "score",       label: "Score" },
        { key: "trend",       label: "Trend" },
        { key: "findings",    label: "Findings" },
        { key: "updated_at",  label: "Updated" },
      ],
    },
  },

  // ── Security Investment ───────────────────────────────────────────────────
  {
    path: "/security-investment",
    props: {
      title: "Security Investment",
      description: "Security tool investment tracking and ROI analysis",
      apiPath: "/api/v1/security-investment/investments",
      itemsKey: "investments",
      statsPath: "/api/v1/security-investment/stats",
      severityKey: null,
      filterOptions: [],
      columns: [
        { key: "tool_name",   label: "Tool",      className: "max-w-[200px]" },
        { key: "category",    label: "Category" },
        { key: "annual_cost", label: "Annual Cost" },
        { key: "roi_pct",     label: "ROI %" },
        { key: "status",      label: "Status",    isStatus: true },
        { key: "renewed_at",  label: "Renewal" },
      ],
    },
  },

  // ── Security OKRs ─────────────────────────────────────────────────────────
  {
    path: "/security-okrs",
    props: {
      title: "Security OKRs",
      description: "Objectives and key results for security posture improvement",
      apiPath: "/api/v1/security-okrs/objectives",
      itemsKey: "objectives",
      statsPath: "/api/v1/security-okrs/stats",
      severityKey: null,
      filterOptions: [],
      columns: [
        { key: "objective",   label: "Objective", className: "max-w-[280px]" },
        { key: "owner",       label: "Owner" },
        { key: "progress_pct",label: "Progress %" },
        { key: "due_date",    label: "Due Date" },
        { key: "status",      label: "Status",    isStatus: true },
        { key: "updated_at",  label: "Updated" },
      ],
    },
  },

  // ── Security Registry ─────────────────────────────────────────────────────
  {
    path: "/security-registry",
    props: {
      title: "Security Registry",
      description: "Central registry of security artifacts, policies, and controls",
      apiPath: "/api/v1/security-registry/artifacts",
      itemsKey: "artifacts",
      statsPath: "/api/v1/security-registry/stats",
      severityKey: "severity",
      columns: [
        { key: "artifact_name",label: "Artifact",   className: "max-w-[220px]" },
        { key: "severity",     label: "Severity",   isSeverity: true },
        { key: "artifact_type",label: "Type" },
        { key: "owner",        label: "Owner" },
        { key: "status",       label: "Status",     isStatus: true },
        { key: "created_at",   label: "Created" },
      ],
    },
  },

  // ── Compliance Mapping ────────────────────────────────────────────────────
  {
    path: "/compliance-mapping",
    props: {
      title: "Compliance Mapping",
      description: "Control-to-finding mapping across compliance frameworks",
      apiPath: "/api/v1/compliance-mapping/controls",
      itemsKey: "controls",
      statsPath: "/api/v1/compliance-mapping/stats",
      severityKey: "severity",
      columns: [
        { key: "control_id",    label: "Control",    className: "font-mono max-w-[120px]" },
        { key: "severity",      label: "Severity",   isSeverity: true },
        { key: "framework",     label: "Framework" },
        { key: "findings_count",label: "Findings" },
        { key: "status",        label: "Status",     isStatus: true },
        { key: "updated_at",    label: "Updated" },
      ],
    },
  },

  // ── Deep Code Analysis ────────────────────────────────────────────────────
  {
    path: "/deep-code-analysis",
    props: {
      title: "Deep Code Analysis",
      description: "Semantic code analysis findings across all repositories",
      apiPath: "/api/v1/dca/analyses",
      itemsKey: "analyses",
      statsPath: "/api/v1/dca/stats",
      severityKey: "severity",
      columns: [
        { key: "repository",  label: "Repository", className: "max-w-[200px]" },
        { key: "severity",    label: "Severity",   isSeverity: true },
        { key: "finding_type",label: "Type" },
        { key: "file_path",   label: "File" },
        { key: "status",      label: "Status",     isStatus: true },
        { key: "analyzed_at", label: "Analyzed" },
      ],
    },
  },

  // ── Waivers Explorer ──────────────────────────────────────────────────────
  {
    path: "/waivers",
    props: {
      title: "Waivers Explorer",
      description: "Active auto-waiver rules with match counts and justifications",
      apiPath: "/api/v1/auto-waiver/rules",
      itemsKey: "rules",
      statsPath: "/api/v1/auto-waiver/stats",
      severityKey: "severity",
      columns: [
        { key: "rule_name",   label: "Rule",       className: "max-w-[220px]" },
        { key: "severity",    label: "Severity",   isSeverity: true },
        { key: "match_count", label: "Matches" },
        { key: "reason",      label: "Reason" },
        { key: "expires_at",  label: "Expires" },
        { key: "created_at",  label: "Created" },
      ],
    },
  },

  // ── Microsegmentation Policy ──────────────────────────────────────────────
  {
    path: "/microsegmentation",
    props: {
      title: "Microsegmentation Policies",
      description: "Network microsegmentation policy status and violation tracking",
      apiPath: "/api/v1/microsegmentation/segments",
      itemsKey: "segments",
      statsPath: "/api/v1/microsegmentation/stats",
      severityKey: "severity",
      columns: [
        { key: "segment_name", label: "Segment",    className: "max-w-[200px]" },
        { key: "severity",     label: "Severity",   isSeverity: true },
        { key: "policy_count", label: "Policies" },
        { key: "violations",   label: "Violations" },
        { key: "status",       label: "Status",     isStatus: true },
        { key: "updated_at",   label: "Updated" },
      ],
    },
  },

  // ── Threat Modeling ───────────────────────────────────────────────────────
  {
    path: "/threat-modeling",
    props: {
      title: "Threat Modeling",
      description: "Cyber threat models and unmitigated threat tracking",
      apiPath: "/api/v1/cyber-threat-models/unmitigated",
      itemsKey: "threats",
      statsPath: "/api/v1/cyber-threat-models/stats",
      severityKey: "severity",
      columns: [
        { key: "threat_name",  label: "Threat",     className: "max-w-[240px]" },
        { key: "severity",     label: "Severity",   isSeverity: true },
        { key: "category",     label: "Category" },
        { key: "mitigations",  label: "Mitigations" },
        { key: "status",       label: "Status",     isStatus: true },
        { key: "identified_at",label: "Identified" },
      ],
    },
  },

  // ── PII Field Inventory ───────────────────────────────────────────────────
  {
    path: "/pii-inventory",
    props: {
      title: "PII Field Inventory",
      description: "Personal data fields detected across data stores and APIs",
      apiPath: "/api/v1/findings",
      itemsKey: "findings",
      statsPath: "/api/v1/findings/stats",
      severityKey: "severity",
      filterOptions: ["critical", "high", "medium", "low"],
      columns: [
        { key: "field_name",   label: "Field",      className: "font-mono max-w-[180px]" },
        { key: "severity",     label: "Severity",   isSeverity: true },
        { key: "pii_type",     label: "PII Type" },
        { key: "data_store",   label: "Data Store" },
        { key: "status",       label: "Status",     isStatus: true },
        { key: "detected_at",  label: "Detected" },
      ],
    },
  },

  // ── Service Account Audit ─────────────────────────────────────────────────
  {
    path: "/service-account-audit",
    props: {
      title: "Service Account Audit",
      description: "Overprivileged and stale service accounts across all environments",
      apiPath: "/api/v1/service-account-auditor/accounts",
      itemsKey: "accounts",
      statsPath: "/api/v1/service-account-auditor/stats",
      severityKey: "severity",
      columns: [
        { key: "account_name",  label: "Account",     className: "max-w-[200px] font-mono" },
        { key: "severity",      label: "Severity",    isSeverity: true },
        { key: "environment",   label: "Environment" },
        { key: "last_used",     label: "Last Used" },
        { key: "permissions",   label: "Permissions" },
        { key: "status",        label: "Status",      isStatus: true },
      ],
    },
  },

  // ── Security Posture Maturity ─────────────────────────────────────────────
  {
    path: "/posture-maturity",
    props: {
      title: "Security Posture Maturity",
      description: "CTEM maturity model assessment across security domains",
      apiPath: "/api/v1/posture-maturity/overview",
      itemsKey: "domains",
      statsPath: "/api/v1/posture-maturity/stats",
      severityKey: "severity",
      columns: [
        { key: "domain",       label: "Domain",    className: "max-w-[200px]" },
        { key: "severity",     label: "Severity",  isSeverity: true },
        { key: "maturity_level",label: "Maturity" },
        { key: "score",        label: "Score" },
        { key: "gap_count",    label: "Gaps" },
        { key: "updated_at",   label: "Updated" },
      ],
    },
  },

  // ── Threat Modeling Pipeline ──────────────────────────────────────────────
  {
    path: "/threat-modeling-pipeline",
    props: {
      title: "Threat Modeling Pipeline",
      description: "Automated threat model generation pipeline status and results",
      apiPath: "/api/v1/threat-modeling-pipeline/models",
      itemsKey: "models",
      statsPath: "/api/v1/threat-modeling-pipeline/stats",
      severityKey: "severity",
      columns: [
        { key: "model_name",   label: "Model",      className: "max-w-[220px]" },
        { key: "severity",     label: "Severity",   isSeverity: true },
        { key: "threat_count", label: "Threats" },
        { key: "mitigations",  label: "Mitigations" },
        { key: "status",       label: "Status",     isStatus: true },
        { key: "generated_at", label: "Generated" },
      ],
    },
  },

  // ── Factor Weights ────────────────────────────────────────────────────────
  {
    path: "/factor-weights",
    props: {
      title: "Factor Weights",
      description: "Risk scoring factor weights and formula configuration",
      apiPath: "/api/v1/scoring/formula",
      itemsKey: "factors",
      statsPath: "/api/v1/scoring/stats",
      severityKey: null,
      filterOptions: [],
      columns: [
        { key: "factor_name", label: "Factor",     className: "max-w-[220px]" },
        { key: "weight",      label: "Weight" },
        { key: "category",    label: "Category" },
        { key: "impact",      label: "Impact" },
        { key: "status",      label: "Status",     isStatus: true },
        { key: "updated_at",  label: "Updated" },
      ],
    },
  },

  // ── Metrics Aggregator ────────────────────────────────────────────────────
  {
    path: "/metrics-aggregator",
    props: {
      title: "Metrics Aggregator",
      description: "Aggregated security metrics across all domains and time windows",
      apiPath: "/api/v1/metrics-aggregator/all",
      itemsKey: "metrics",
      statsPath: "/api/v1/metrics-aggregator/stats",
      severityKey: null,
      filterOptions: [],
      columns: [
        { key: "metric_name",  label: "Metric",    className: "max-w-[220px]" },
        { key: "value",        label: "Value" },
        { key: "category",     label: "Category" },
        { key: "trend",        label: "Trend" },
        { key: "window",       label: "Window" },
        { key: "updated_at",   label: "Updated" },
      ],
    },
  },

  // ── Posture History ───────────────────────────────────────────────────────
  {
    path: "/posture-history",
    props: {
      title: "Posture History",
      description: "Historical security posture scores and improvement trends by domain",
      apiPath: "/api/v1/posture-history/domains",
      itemsKey: "domains",
      statsPath: "/api/v1/posture-history/stats",
      severityKey: null,
      filterOptions: [],
      columns: [
        { key: "domain",       label: "Domain",    className: "max-w-[200px]" },
        { key: "score",        label: "Score" },
        { key: "prev_score",   label: "Prev Score" },
        { key: "delta",        label: "Delta" },
        { key: "period",       label: "Period" },
        { key: "recorded_at",  label: "Recorded" },
      ],
    },
  },

  // ── BU Dollar Risk Heatmap ────────────────────────────────────────────────
  {
    path: "/risk-heatmap",
    props: {
      title: "Risk Heatmap",
      description: "Business unit financial risk exposure heatmap",
      apiPath: "/api/v1/risk/heatmap",
      itemsKey: "heatmap",
      statsPath: "/api/v1/risk/stats",
      severityKey: "severity",
      columns: [
        { key: "business_unit", label: "Business Unit", className: "max-w-[200px]" },
        { key: "severity",      label: "Severity",      isSeverity: true },
        { key: "risk_score",    label: "Risk Score" },
        { key: "dollar_exposure",label: "Exposure $" },
        { key: "finding_count", label: "Findings" },
        { key: "updated_at",    label: "Updated" },
      ],
    },
  },

  // ── Air Gap Bundle Dashboard ──────────────────────────────────────────────
  {
    path: "/air-gap-bundles",
    props: {
      title: "Air Gap Bundles",
      description: "Offline update bundles for air-gapped deployments",
      apiPath: "/api/v1/air-gap/bundle/list",
      itemsKey: "bundles",
      statsPath: "/api/v1/air-gap/stats",
      severityKey: null,
      filterOptions: [],
      columns: [
        { key: "bundle_id",   label: "Bundle ID",  className: "font-mono max-w-[180px]" },
        { key: "bundle_type", label: "Type" },
        { key: "version",     label: "Version" },
        { key: "size_mb",     label: "Size MB" },
        { key: "status",      label: "Status",     isStatus: true },
        { key: "created_at",  label: "Created" },
      ],
    },
  },

  // ── Violation Lifecycle ───────────────────────────────────────────────────
  {
    path: "/violation-lifecycle",
    props: {
      title: "Violation Lifecycle",
      description: "Finding lifecycle — open → triage → fix → verify state tracking",
      apiPath: "/api/v1/findings/lifecycle/summary",
      itemsKey: "states",
      statsPath: "/api/v1/findings/lifecycle/stats",
      severityKey: null,
      filterOptions: [],
      columns: [
        { key: "state",        label: "State",     isStatus: true },
        { key: "count",        label: "Count" },
        { key: "avg_age_hrs",  label: "Avg Age (hrs)" },
        { key: "sla_breaches", label: "SLA Breaches" },
        { key: "updated_at",   label: "Updated" },
      ],
    },
  },

  // ── Security Benchmark ────────────────────────────────────────────────────
  {
    path: "/security-benchmarks",
    props: {
      title: "Security Benchmarks",
      description: "CIS, NIST, and custom benchmark compliance scores",
      apiPath: "/api/v1/security-benchmarks/results",
      itemsKey: "results",
      statsPath: "/api/v1/security-benchmarks/stats",
      severityKey: "severity",
      columns: [
        { key: "benchmark",    label: "Benchmark",  className: "max-w-[200px]" },
        { key: "severity",     label: "Severity",   isSeverity: true },
        { key: "passed",       label: "Passed" },
        { key: "failed",       label: "Failed" },
        { key: "score_pct",    label: "Score %" },
        { key: "assessed_at",  label: "Assessed" },
      ],
    },
  },
];
