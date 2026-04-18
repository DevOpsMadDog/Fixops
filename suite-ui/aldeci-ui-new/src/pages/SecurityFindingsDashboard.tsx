/**
 * Security Findings Dashboard
 *
 * Unified security findings management across all source tools.
 *   1. Summary stats (total/open/resolved, by severity bars, top-5 assets)
 *   2. Filter bar (by severity/status/source_tool)
 *   3. Findings table (title, finding_type, source_tool, severity, cvss_score bar, asset_id, status, occurrence_count)
 *   4. Finding detail panel (description, remediation, evidence list, suppression info)
 *   5. Asset findings view
 *
 * Route: /security-findings
 * API: GET /api/v1/security-findings
 */

import { useState, useEffect } from "react";
const _API_BASE = "/api/v1/security-findings";
const _getHeaders = () => ({ "X-API-Key": localStorage.getItem("apiKey") || "" });

import { Bug, Shield, AlertTriangle, CheckCircle2, Filter, BarChart2, FileText } from "lucide-react";

// ── Types ──────────────────────────────────────────────────────

interface Finding {
  id: string;
  title: string;
  finding_type: "vulnerability" | "misconfiguration" | "secret" | "compliance" | "threat" | "anomaly";
  source_tool: string;
  severity: "critical" | "high" | "medium" | "low" | "informational";
  cvss_score: number;
  asset_id: string;
  status: "open" | "in_review" | "resolved" | "suppressed" | "accepted_risk";
  occurrence_count: number;
  description: string;
  remediation: string;
  evidence: string[];
  suppressed_by?: string;
  suppressed_reason?: string;
  first_seen: string;
  last_seen: string;
}

// ── Mock data ──────────────────────────────────────────────────

const FINDINGS: Finding[] = [
  {
    id: "f01", title: "Log4Shell RCE (CVE-2021-44228)", finding_type: "vulnerability", source_tool: "Trivy",
    severity: "critical", cvss_score: 10.0, asset_id: "SRV-APP-001", status: "open", occurrence_count: 3,
    description: "Apache Log4j 2 JNDI lookup feature allows remote code execution via a specially crafted log message.",
    remediation: "Upgrade Log4j to 2.17.1+. Apply JVM flags -Dlog4j2.formatMsgNoLookups=true as interim.",
    evidence: ["trivy-scan-2026-04-16.json", "log4j-class-found.txt"],
    first_seen: "2026-01-10", last_seen: "2026-04-16",
  },
  {
    id: "f02", title: "S3 Bucket Publicly Accessible", finding_type: "misconfiguration", source_tool: "CSPM Engine",
    severity: "critical", cvss_score: 9.1, asset_id: "AWS-S3-BACKUP", status: "in_review", occurrence_count: 1,
    description: "S3 bucket 'company-backup-prod' has public read ACL enabled, exposing data to the internet.",
    remediation: "Set bucket ACL to private. Enable S3 Block Public Access at account level.",
    evidence: ["cspm-scan-2026-04-15.json"],
    first_seen: "2026-04-15", last_seen: "2026-04-16",
  },
  {
    id: "f03", title: "Hardcoded AWS Key in Source Code", finding_type: "secret", source_tool: "Secret Scanner",
    severity: "high", cvss_score: 8.5, asset_id: "REPO-backend", status: "resolved", occurrence_count: 2,
    description: "AWS access key AKIA... found hardcoded in config/settings.py at line 142.",
    remediation: "Rotate key immediately. Use environment variables or AWS Secrets Manager.",
    evidence: ["secret-scan-report.json", "git-blame-output.txt"],
    first_seen: "2026-03-20", last_seen: "2026-04-01",
  },
  {
    id: "f04", title: "MFA Not Enforced for Admin Users", finding_type: "compliance", source_tool: "IAM Analyzer",
    severity: "high", cvss_score: 7.8, asset_id: "IAM-PROD", status: "open", occurrence_count: 5,
    description: "4 admin IAM users do not have MFA enabled, violating CIS AWS Benchmark 1.2.",
    remediation: "Enforce MFA via IAM password policy. Use SCP to block console access without MFA.",
    evidence: ["iam-audit-2026-04-14.json"],
    first_seen: "2026-02-01", last_seen: "2026-04-16",
  },
  {
    id: "f05", title: "SQL Injection in /api/search Endpoint", finding_type: "vulnerability", source_tool: "DAST Engine",
    severity: "high", cvss_score: 8.1, asset_id: "APP-API-001", status: "in_review", occurrence_count: 1,
    description: "Unsanitized input in the 'q' parameter of GET /api/search allows UNION-based SQL injection.",
    remediation: "Use parameterized queries. Apply WAF rule for SQLi detection.",
    evidence: ["dast-report-2026-04-12.html", "sqlmap-output.txt"],
    first_seen: "2026-04-12", last_seen: "2026-04-12",
  },
  {
    id: "f06", title: "Unpatched OpenSSL (CVE-2022-0778)", finding_type: "vulnerability", source_tool: "Nessus",
    severity: "high", cvss_score: 7.5, asset_id: "SRV-DB-002", status: "open", occurrence_count: 4,
    description: "OpenSSL infinite loop vulnerability in BN_mod_sqrt() causing denial of service.",
    remediation: "Upgrade OpenSSL to 1.1.1n or 3.0.2+.",
    evidence: ["nessus-scan-weekly.csv"],
    first_seen: "2026-03-01", last_seen: "2026-04-16",
  },
  {
    id: "f07", title: "Default SSH Password on IoT Device", finding_type: "misconfiguration", source_tool: "Shodan Monitor",
    severity: "critical", cvss_score: 9.8, asset_id: "IOT-SENS-003", status: "accepted_risk", occurrence_count: 1,
    description: "Device IOT-SENS-003 still using vendor default password 'admin/admin' on SSH port 22.",
    remediation: "Change default credentials. Disable SSH if not needed. Place behind jump host.",
    evidence: ["shodan-alert-2026-04-10.json"],
    suppressed_by: "it-admin", suppressed_reason: "Legacy device — cannot update until Q3 refresh",
    first_seen: "2026-04-10", last_seen: "2026-04-16",
  },
  {
    id: "f08", title: "Anomalous Data Transfer Volume", finding_type: "anomaly", source_tool: "UBA Engine",
    severity: "medium", cvss_score: 5.4, asset_id: "WS-D101", status: "open", occurrence_count: 1,
    description: "User john.doe transferred 14GB of data to external USB device in 2 hours, 8x baseline.",
    remediation: "Investigate with HR. Block USB storage if policy violation confirmed.",
    evidence: ["uba-alert-2026-04-16.json"],
    first_seen: "2026-04-16", last_seen: "2026-04-16",
  },
  {
    id: "f09", title: "TLS 1.0 Enabled on Load Balancer", finding_type: "misconfiguration", source_tool: "SSL Labs",
    severity: "medium", cvss_score: 5.9, asset_id: "LB-PROD-01", status: "resolved", occurrence_count: 1,
    description: "Load balancer still accepts TLS 1.0 connections, which is deprecated and vulnerable to BEAST.",
    remediation: "Configure minimum TLS 1.2. Prefer TLS 1.3.",
    evidence: ["ssl-scan-report.html"],
    first_seen: "2026-03-15", last_seen: "2026-04-05",
  },
  {
    id: "f10", title: "Missing HTTP Security Headers", finding_type: "compliance", source_tool: "DAST Engine",
    severity: "low", cvss_score: 3.1, asset_id: "APP-WEB-001", status: "open", occurrence_count: 8,
    description: "Content-Security-Policy, X-Frame-Options, and Referrer-Policy headers missing from all responses.",
    remediation: "Add security headers via nginx config or middleware.",
    evidence: ["header-scan-2026-04-14.json"],
    first_seen: "2026-01-20", last_seen: "2026-04-16",
  },
  {
    id: "f11", title: "Cryptominer Detected on EC2", finding_type: "threat", source_tool: "GuardDuty",
    severity: "critical", cvss_score: 9.0, asset_id: "AWS-EC2-4521", status: "in_review", occurrence_count: 1,
    description: "EC2 instance communicating with known cryptomining pool stratum+tcp://pool.minexmr.com:4444.",
    remediation: "Isolate instance immediately. Forensic investigation required. Rebuild from known-good AMI.",
    evidence: ["guardduty-finding-2026-04-16.json"],
    first_seen: "2026-04-16", last_seen: "2026-04-16",
  },
];

// ── Helpers ────────────────────────────────────────────────────

const severityColor: Record<Finding["severity"], string> = {
  critical: "bg-red-600 text-white",
  high: "bg-orange-600 text-white",
  medium: "bg-yellow-600 text-black",
  low: "bg-blue-600 text-white",
  informational: "bg-gray-600 text-white",
};

const severityText: Record<Finding["severity"], string> = {
  critical: "text-red-400",
  high: "text-orange-400",
  medium: "text-yellow-400",
  low: "text-blue-400",
  informational: "text-gray-400",
};

const statusColor: Record<Finding["status"], string> = {
  open: "bg-red-900 text-red-300",
  in_review: "bg-yellow-900 text-yellow-300",
  resolved: "bg-green-900 text-green-300",
  suppressed: "bg-gray-700 text-gray-400",
  accepted_risk: "bg-purple-900 text-purple-300",
};

const findingTypeColor: Record<Finding["finding_type"], string> = {
  vulnerability: "bg-red-900 text-red-300",
  misconfiguration: "bg-orange-900 text-orange-300",
  secret: "bg-yellow-900 text-yellow-300",
  compliance: "bg-blue-900 text-blue-300",
  threat: "bg-purple-900 text-purple-300",
  anomaly: "bg-teal-900 text-teal-300",
};

const ALL_SEVERITIES = ["all","critical","high","medium","low","informational"] as const;
const ALL_STATUSES = ["all","open","in_review","resolved","suppressed","accepted_risk"] as const;
const ALL_TOOLS = ["all", ...Array.from(new Set(FINDINGS.map(f => f.source_tool)))];

// ── Component ──────────────────────────────────────────────────

export default function SecurityFindingsDashboard() {
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);
  const [filterSeverity, setFilterSeverity] = useState("all");
  useEffect(() => {
    fetch(_API_BASE, { headers: _getHeaders() })
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(() => { /* live data available */ })
      .catch(() => { setError('Failed to load data'); });
  }, []);
  const [filterStatus, setFilterStatus] = useState("all");
  const [filterTool, setFilterTool] = useState("all");

  const filtered = FINDINGS.filter(f =>
    (filterSeverity === "all" || f.severity === filterSeverity) &&
    (filterStatus === "all" || f.status === filterStatus) &&
    (filterTool === "all" || f.source_tool === filterTool)
  );

  const open = FINDINGS.filter(f => f.status === "open").length;
  const resolved = FINDINGS.filter(f => f.status === "resolved").length;
  const bySeverity = {
    critical: FINDINGS.filter(f => f.severity === "critical").length,
    high: FINDINGS.filter(f => f.severity === "high").length,
    medium: FINDINGS.filter(f => f.severity === "medium").length,
    low: FINDINGS.filter(f => f.severity === "low").length,
  };

  // Top 5 assets by finding count
  const assetCounts: Record<string, number> = {};
  FINDINGS.forEach(f => { assetCounts[f.asset_id] = (assetCounts[f.asset_id] || 0) + 1; });
  const top5Assets = Object.entries(assetCounts).sort((a, b) => b[1] - a[1]).slice(0, 5);

  return (
    <div className="min-h-screen bg-[#0f172a] text-white p-6 space-y-6">
      {error && (
        <div className="bg-red-900/20 border border-red-500/30 rounded-lg p-4 flex items-center justify-between">
          <p className="text-red-400 text-sm">{error}</p>
          <button
            onClick={() => { setError(null); window.location.reload(); }}
            className="px-3 py-1 bg-red-600 hover:bg-red-700 text-white text-xs rounded transition-colors"
          >
            Retry
          </button>
        </div>
      )}
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Bug className="w-6 h-6 text-red-400" />
            Security Findings
          </h1>
          <p className="text-gray-400 text-sm mt-1">Unified findings across all security tools and scanners</p>
        </div>
      </div>

      {/* Summary stats */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: "Total Findings", value: FINDINGS.length, icon: <Bug className="w-5 h-5 text-gray-400" />, sub: "across all tools" },
          { label: "Open", value: open, icon: <AlertTriangle className="w-5 h-5 text-red-400" />, sub: "require action" },
          { label: "In Review", value: FINDINGS.filter(f => f.status === "in_review").length, icon: <Shield className="w-5 h-5 text-yellow-400" />, sub: "being investigated" },
          { label: "Resolved", value: resolved, icon: <CheckCircle2 className="w-5 h-5 text-green-400" />, sub: "remediated" },
        ].map(k => (
          <div key={k.label} className="bg-gray-800 rounded-lg p-5">
            <div className="flex items-center justify-between mb-2">
              <span className="text-gray-400 text-xs uppercase tracking-wide">{k.label}</span>
              {k.icon}
            </div>
            <div className="text-3xl font-bold">{k.value}</div>
            <div className="text-gray-500 text-xs mt-1">{k.sub}</div>
          </div>
        ))}
      </div>

      <div className="grid lg:grid-cols-3 gap-6">
        {/* Severity bars */}
        <div className="bg-gray-800 rounded-lg p-5">
          <div className="font-semibold mb-4 flex items-center gap-2">
            <BarChart2 className="w-4 h-4 text-red-400" /> By Severity
          </div>
          {(["critical","high","medium","low"] as const).map(sev => {
            const pct = Math.round((bySeverity[sev] / FINDINGS.length) * 100);
            return (
              <div key={sev} className="mb-3">
                <div className="flex justify-between text-xs mb-1">
                  <span className={`capitalize ${severityText[sev]}`}>{sev}</span>
                  <span className="text-gray-400">{bySeverity[sev]}</span>
                </div>
                <div className="w-full bg-gray-700 rounded-full h-2">
                  <div
                    className={`h-2 rounded-full ${sev === "critical" ? "bg-red-500" : sev === "high" ? "bg-orange-500" : sev === "medium" ? "bg-yellow-500" : "bg-blue-500"}`}
                    style={{ width: `${pct}%` }}
                  />
                </div>
              </div>
            );
          })}
        </div>

        {/* Top 5 assets */}
        <div className="bg-gray-800 rounded-lg p-5">
          <div className="font-semibold mb-4 flex items-center gap-2">
            <Shield className="w-4 h-4 text-orange-400" /> Top Assets by Findings
          </div>
          <div className="space-y-3">
            {top5Assets.map(([asset, count], idx) => (
              <div key={asset} className="flex items-center gap-3">
                <span className="text-gray-500 text-xs w-4">{idx + 1}</span>
                <div className="flex-1 min-w-0">
                  <div className="text-xs font-mono truncate text-teal-300">{asset}</div>
                  <div className="w-full bg-gray-700 rounded-full h-1 mt-1">
                    <div
                      className="h-1 bg-orange-500 rounded-full"
                      style={{ width: `${(count / top5Assets[0][1]) * 100}%` }}
                    />
                  </div>
                </div>
                <span className="text-xs font-bold text-orange-400">{count}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Finding detail */}
        <div className="bg-gray-800 rounded-lg p-5">
          <div className="font-semibold mb-4 flex items-center gap-2">
            <FileText className="w-4 h-4 text-blue-400" />
            {selectedFinding ? "Finding Detail" : "Select a finding"}
          </div>
          {selectedFinding ? (
            <div className="space-y-3 text-sm">
              <div>
                <div className="text-xs text-gray-400 mb-1">Title</div>
                <div className="font-medium leading-snug">{selectedFinding.title}</div>
              </div>
              <div className="flex gap-2">
                <span className={`px-2 py-0.5 rounded text-xs ${findingTypeColor[selectedFinding.finding_type]}`}>
                  {selectedFinding.finding_type}
                </span>
                <span className={`px-2 py-0.5 rounded text-xs ${statusColor[selectedFinding.status]}`}>
                  {selectedFinding.status.replace(/_/g," ")}
                </span>
              </div>
              <div>
                <div className="text-xs text-gray-400 mb-1">Description</div>
                <p className="text-gray-300 text-xs leading-relaxed">{selectedFinding.description}</p>
              </div>
              <div>
                <div className="text-xs text-gray-400 mb-1">Remediation</div>
                <p className="text-green-300 text-xs leading-relaxed">{selectedFinding.remediation}</p>
              </div>
              <div>
                <div className="text-xs text-gray-400 mb-1">Evidence</div>
                <div className="space-y-1">
                  {selectedFinding.evidence.map(e => (
                    <div key={e} className="text-xs font-mono text-blue-400 truncate">{e}</div>
                  ))}
                </div>
              </div>
              {selectedFinding.suppressed_by && (
                <div className="bg-purple-900/30 border border-purple-700 rounded p-2">
                  <div className="text-xs text-purple-300">Suppressed by {selectedFinding.suppressed_by}</div>
                  <div className="text-xs text-gray-400 mt-0.5">{selectedFinding.suppressed_reason}</div>
                </div>
              )}
              <div className="flex justify-between text-xs text-gray-500">
                <span>First: {selectedFinding.first_seen}</span>
                <span>Last: {selectedFinding.last_seen}</span>
              </div>
            </div>
          ) : (
            <p className="text-gray-500 text-sm">Click on a finding row to view details.</p>
          )}
        </div>
      </div>

      {/* Filter bar */}
      <div className="bg-gray-800 rounded-lg p-4 flex flex-wrap gap-4 items-center">
        <div className="flex items-center gap-2 text-gray-400">
          <Filter className="w-4 h-4" />
          <span className="text-sm font-medium">Filters:</span>
        </div>
        <div className="flex items-center gap-2">
          <label className="text-xs text-gray-400">Severity</label>
          <select
            value={filterSeverity}
            onChange={e => setFilterSeverity(e.target.value)}
            className="bg-gray-700 border border-gray-600 rounded px-2 py-1 text-xs text-white focus:outline-none focus:border-blue-500"
          >
            {ALL_SEVERITIES.map(s => <option key={s} value={s}>{s}</option>)}
          </select>
        </div>
        <div className="flex items-center gap-2">
          <label className="text-xs text-gray-400">Status</label>
          <select
            value={filterStatus}
            onChange={e => setFilterStatus(e.target.value)}
            className="bg-gray-700 border border-gray-600 rounded px-2 py-1 text-xs text-white focus:outline-none focus:border-blue-500"
          >
            {ALL_STATUSES.map(s => <option key={s} value={s}>{s.replace(/_/g," ")}</option>)}
          </select>
        </div>
        <div className="flex items-center gap-2">
          <label className="text-xs text-gray-400">Source Tool</label>
          <select
            value={filterTool}
            onChange={e => setFilterTool(e.target.value)}
            className="bg-gray-700 border border-gray-600 rounded px-2 py-1 text-xs text-white focus:outline-none focus:border-blue-500"
          >
            {ALL_TOOLS.map(t => <option key={t} value={t}>{t}</option>)}
          </select>
        </div>
        <span className="text-xs text-gray-400 ml-auto">{filtered.length} of {FINDINGS.length} findings</span>
      </div>

      {/* Findings table */}
      <div className="bg-gray-800 rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-gray-700/50">
              <tr>
                {["Title","Type","Source","Severity","CVSS","Asset","Status","Count"].map(h => (
                  <th key={h} className="px-4 py-3 text-left text-gray-400 font-medium">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.map(f => (
                <tr
                  key={f.id}
                  onClick={() => setSelectedFinding(f)}
                  className={`border-t border-gray-700 hover:bg-gray-700/40 cursor-pointer transition-colors ${
                    selectedFinding?.id === f.id ? "bg-blue-900/20" : ""
                  }`}
                >
                  <td className="px-4 py-3 font-medium max-w-xs">
                    <div className="truncate">{f.title}</div>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-0.5 rounded text-xs capitalize ${findingTypeColor[f.finding_type]}`}>
                      {f.finding_type}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-gray-400 text-xs">{f.source_tool}</td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-0.5 rounded text-xs font-medium capitalize ${severityColor[f.severity]}`}>
                      {f.severity}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2">
                      <div className="w-12 bg-gray-700 rounded-full h-1.5">
                        <div
                          className={`h-1.5 rounded-full ${f.cvss_score >= 9 ? "bg-red-500" : f.cvss_score >= 7 ? "bg-orange-500" : f.cvss_score >= 4 ? "bg-yellow-500" : "bg-blue-500"}`}
                          style={{ width: `${(f.cvss_score / 10) * 100}%` }}
                        />
                      </div>
                      <span className="text-xs text-gray-300">{f.cvss_score}</span>
                    </div>
                  </td>
                  <td className="px-4 py-3 font-mono text-teal-300 text-xs">{f.asset_id}</td>
                  <td className="px-4 py-3">
                    <span className={`px-2 py-0.5 rounded text-xs ${statusColor[f.status]}`}>
                      {f.status.replace(/_/g," ")}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-gray-400 text-center">{f.occurrence_count}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
