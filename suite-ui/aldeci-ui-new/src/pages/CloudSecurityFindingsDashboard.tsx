/**
 * Cloud Security Findings Dashboard
 *
 * Provider tabs (AWS/Azure/GCP/Alibaba/OCI/IBM), findings table with severity badges,
 * resolve/suppress actions, remediation tracking, top affected resources, summary cards,
 * bulk ingest button.
 *
 * Route: /cloud-findings
 */

import { useState, useEffect } from "react";
import { Cloud, AlertTriangle, CheckCircle, XCircle, RefreshCw, Upload } from "lucide-react";
import { cn } from "@/lib/utils";

const API_BASE = import.meta.env.VITE_API_URL || "";
const API_KEY = (typeof window !== "undefined" && window.localStorage.getItem("aldeci_api_key")) || import.meta.env.VITE_API_KEY || "demo-key";
const ORG_ID = "aldeci-demo";
async function apiFetch(path: string) {
  const r = await fetch(`${API_BASE}${path}?org_id=default`, { headers: { "X-API-Key": API_KEY, "Content-Type": "application/json" } });
  if (!r.ok) throw new Error(`${r.status}`);
  return r.json();
}

// ── Mock data ──────────────────────────────────────────────────────────────────

const PROVIDERS = ["AWS", "Azure", "GCP", "Alibaba", "OCI", "IBM"];

const MOCK_FINDINGS = [
  { id: "cf-001", provider: "AWS",     account_id: "123456789012", region: "us-east-1",   resource_type: "S3 Bucket",        severity: "critical", status: "open",        cvss_score: 9.1, detected_at: "2026-04-14", resource_id: "s3://prod-data-bucket"          },
  { id: "cf-002", provider: "AWS",     account_id: "123456789012", region: "us-west-2",   resource_type: "IAM Role",         severity: "high",     status: "open",        cvss_score: 7.8, detected_at: "2026-04-15", resource_id: "arn:aws:iam::123/role/AdminRole" },
  { id: "cf-003", provider: "Azure",   account_id: "sub-0abc1234", region: "eastus",      resource_type: "Storage Account",  severity: "critical", status: "open",        cvss_score: 9.3, detected_at: "2026-04-13", resource_id: "stgprodaccount01"               },
  { id: "cf-004", provider: "Azure",   account_id: "sub-0abc1234", region: "westeurope",  resource_type: "VM",               severity: "medium",   status: "suppressed",  cvss_score: 5.4, detected_at: "2026-04-12", resource_id: "vm-prod-web-01"                 },
  { id: "cf-005", provider: "GCP",     account_id: "proj-fix-001", region: "us-central1", resource_type: "GCS Bucket",       severity: "high",     status: "open",        cvss_score: 7.2, detected_at: "2026-04-14", resource_id: "gs://gcp-backup-prod"           },
  { id: "cf-006", provider: "GCP",     account_id: "proj-fix-001", region: "europe-west1","resource_type": "Firewall Rule",  severity: "low",      status: "resolved",    cvss_score: 3.1, detected_at: "2026-04-10", resource_id: "fw-rule-allow-all"              },
  { id: "cf-007", provider: "Alibaba", account_id: "acs-1234abcd", region: "cn-hangzhou", resource_type: "OSS Bucket",       severity: "critical", status: "open",        cvss_score: 9.5, detected_at: "2026-04-15", resource_id: "oss://prod-archive"             },
  { id: "cf-008", provider: "OCI",     account_id: "ocid1.ten.oc1", region: "us-ashburn", resource_type: "Object Storage",   severity: "medium",   status: "open",        cvss_score: 5.9, detected_at: "2026-04-13", resource_id: "bucket-oci-prod"                },
  { id: "cf-009", provider: "IBM",     account_id: "ibm-acct-99",  region: "us-south",    resource_type: "Cloud Object Stor",severity: "high",     status: "open",        cvss_score: 7.5, detected_at: "2026-04-14", resource_id: "cos-prod-bucket"                },
  { id: "cf-010", provider: "AWS",     account_id: "123456789012", region: "eu-west-1",   resource_type: "RDS Instance",     severity: "high",     status: "open",        cvss_score: 7.9, detected_at: "2026-04-15", resource_id: "rds-mysql-prod"                 },
];

const MOCK_REMEDIATIONS = [
  { id: "rem-001", finding_id: "cf-001", assignee: "Alice Chen",  due_date: "2026-04-17", status: "in_progress", overdue: false },
  { id: "rem-002", finding_id: "cf-003", assignee: "Bob Kumar",   due_date: "2026-04-14", status: "pending",     overdue: true  },
  { id: "rem-003", finding_id: "cf-002", assignee: "Carol Davis", due_date: "2026-04-20", status: "in_progress", overdue: false },
  { id: "rem-004", finding_id: "cf-007", assignee: "Dave Park",   due_date: "2026-04-13", status: "pending",     overdue: true  },
  { id: "rem-005", finding_id: "cf-010", assignee: "Eve Martin",  due_date: "2026-04-22", status: "scheduled",   overdue: false },
];

const MOCK_TOP_RESOURCES = [
  { resource_id: "s3://prod-data-bucket",      finding_count: 5 },
  { resource_id: "arn:aws:iam::123/AdminRole", finding_count: 4 },
  { resource_id: "stgprodaccount01",           finding_count: 3 },
  { resource_id: "oss://prod-archive",         finding_count: 3 },
  { resource_id: "rds-mysql-prod",             finding_count: 2 },
];

const PROVIDER_COUNTS: Record<string, number> = {
  AWS: 3, Azure: 2, GCP: 2, Alibaba: 1, OCI: 1, IBM: 1,
};

// ── Badge helpers ──────────────────────────────────────────────────────────────

function SeverityBadge({ s }: { s: string }) {
  const cls: Record<string, string> = {
    critical: "bg-red-500/20 text-red-400 border border-red-500/30",
    high:     "bg-orange-500/20 text-orange-400 border border-orange-500/30",
    medium:   "bg-yellow-500/20 text-yellow-400 border border-yellow-500/30",
    low:      "bg-blue-500/20 text-blue-400 border border-blue-500/30",
  };
  return <span className={cn("px-2 py-0.5 rounded text-xs font-medium", cls[s] ?? "bg-gray-700 text-gray-300")}>{s}</span>;
}

function StatusBadge({ s }: { s: string }) {
  const cls: Record<string, string> = {
    open:       "bg-red-500/20 text-red-400",
    resolved:   "bg-green-500/20 text-green-400",
    suppressed: "bg-gray-700 text-gray-400",
    in_progress:"bg-blue-500/20 text-blue-400",
    pending:    "bg-yellow-500/20 text-yellow-400",
    scheduled:  "bg-purple-500/20 text-purple-400",
  };
  return <span className={cn("px-2 py-0.5 rounded text-xs font-medium", cls[s] ?? "bg-gray-700 text-gray-300")}>{s.replace("_"," ")}</span>;
}

function ProviderBadge({ p }: { p: string }) {
  const cls: Record<string, string> = {
    AWS:     "bg-orange-500/20 text-orange-300",
    Azure:   "bg-blue-500/20 text-blue-300",
    GCP:     "bg-green-500/20 text-green-300",
    Alibaba: "bg-red-500/20 text-red-300",
    OCI:     "bg-rose-500/20 text-rose-300",
    IBM:     "bg-indigo-500/20 text-indigo-300",
  };
  return <span className={cn("px-2 py-0.5 rounded text-xs font-medium", cls[p] ?? "bg-gray-700 text-gray-300")}>{p}</span>;
}

function dayAge(dateStr: string) {
  const d = new Date(dateStr);
  const now = new Date("2026-04-16");
  return Math.round((now.getTime() - d.getTime()) / 86400000);
}

// ── Main Component ─────────────────────────────────────────────────────────────

export default function CloudSecurityFindingsDashboard() {
  const [activeProvider, setActiveProvider] = useState("All");
  const [loading, setLoading] = useState(true);
  const [findings, setFindings] = useState<any[]>([]);
  const [ingesting, setIngesting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    apiFetch(`/api/v1/cloud-findings/findings?org_id=${ORG_ID}`).then((d) => {
      if (Array.isArray(d?.findings)) setFindings(d.findings);
      else if (Array.isArray(d)) setFindings(d);
    }).catch((e) => setError(e?.message || 'Failed to load data'))
      .finally(() => setLoading(false));
  }, []);

  const displayed = activeProvider === "All" ? findings : findings.filter(f => f.provider === activeProvider);
  const total = findings.length;
  const criticalOpen = findings.filter(f => f.severity === "critical" && f.status === "open").length;
  const overdueRem = MOCK_REMEDIATIONS.filter(r => r.overdue).length;
  const maxBar = Math.max(...MOCK_TOP_RESOURCES.map(r => r.finding_count));

  function resolveAction(id: string) {
    setFindings(prev => prev.map(f => f.id === id ? { ...f, status: "resolved" } : f));
  }
  function suppressAction(id: string) {
    setFindings(prev => prev.map(f => f.id === id ? { ...f, status: "suppressed" } : f));
  }
  function bulkIngest() {
    setIngesting(true);
    setTimeout(() => setIngesting(false), 1500);
  }


  if (loading) return <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div></div>;


  return (
    <div className="min-h-screen bg-[#0f172a] text-white p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-blue-500/10 rounded-lg">
            <Cloud className="w-6 h-6 text-blue-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white">Cloud Security Findings</h1>
            <p className="text-sm text-gray-400">Multi-cloud security posture findings across all providers</p>
          </div>
        </div>
        <button
          onClick={bulkIngest}
          disabled={ingesting}
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 rounded-lg text-sm font-medium transition-all disabled:opacity-60"
        >
          <Upload className="w-4 h-4" />
          {ingesting ? "Ingesting..." : "Bulk Ingest"}
        </button>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {[
          { label: "Total Findings", value: total,       icon: <AlertTriangle className="w-5 h-5 text-gray-400" />, color: "text-white" },
          { label: "Critical Open",  value: criticalOpen, icon: <XCircle className="w-5 h-5 text-red-400" />,       color: "text-red-400" },
          { label: "Overdue Remeds", value: overdueRem,  icon: <RefreshCw className="w-5 h-5 text-orange-400" />,  color: "text-orange-400" },
          { label: "Resolved",       value: findings.filter(f=>f.status==="resolved").length, icon: <CheckCircle className="w-5 h-5 text-green-400" />, color: "text-green-400" },
        ].map(c => (
          <div key={c.label} className="bg-gray-800 rounded-lg p-4 flex items-center gap-3">
            {c.icon}
            <div>
              <p className="text-xs text-gray-400">{c.label}</p>
              <p className={cn("text-2xl font-bold", c.color)}>{c.value}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Provider tabs */}
      <div className="flex gap-2 flex-wrap">
        {["All", ...PROVIDERS].map(p => (
          <button
            key={p}
            onClick={() => setActiveProvider(p)}
            className={cn(
              "px-3 py-1.5 rounded-lg text-sm font-medium transition-all",
              activeProvider === p ? "bg-blue-600 text-white" : "bg-gray-800 text-gray-400 hover:bg-gray-700"
            )}
          >
            {p}
            {p !== "All" && (
              <span className="ml-1.5 text-xs bg-gray-700 rounded px-1">{PROVIDER_COUNTS[p] ?? 0}</span>
            )}
          </button>
        ))}
      </div>

      {/* Findings table */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h2 className="text-lg font-semibold text-white mb-4">Findings ({displayed.length})</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-700">
                {["Provider", "Account", "Region", "Resource Type", "Severity", "Status", "CVSS", "Age", "Actions"].map(h => (
                  <th key={h} className="text-left text-gray-400 font-medium py-2 pr-4 whitespace-nowrap">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {displayed.map(f => (
                <tr key={f.id} className="border-b border-gray-700/40 hover:bg-gray-700/30">
                  <td className="py-2.5 pr-4"><ProviderBadge p={f.provider} /></td>
                  <td className="py-2.5 pr-4 text-xs text-gray-300 font-mono">{f.account_id.slice(0, 12)}</td>
                  <td className="py-2.5 pr-4 text-xs text-gray-300">{f.region}</td>
                  <td className="py-2.5 pr-4 text-xs text-gray-200">{f.resource_type}</td>
                  <td className="py-2.5 pr-4"><SeverityBadge s={f.severity} /></td>
                  <td className="py-2.5 pr-4"><StatusBadge s={f.status} /></td>
                  <td className="py-2.5 pr-4 text-xs font-mono text-yellow-300">{f.cvss_score.toFixed(1)}</td>
                  <td className="py-2.5 pr-4 text-xs text-gray-400">{dayAge(f.detected_at)}d</td>
                  <td className="py-2.5 flex gap-1">
                    {f.status === "open" && (
                      <>
                        <button onClick={() => resolveAction(f.id)} className="px-2 py-0.5 bg-green-600/30 hover:bg-green-600/50 text-green-400 rounded text-xs">Resolve</button>
                        <button onClick={() => suppressAction(f.id)} className="px-2 py-0.5 bg-gray-700 hover:bg-gray-600 text-gray-300 rounded text-xs">Suppress</button>
                      </>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Bottom row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Remediation tracking */}
        <div className="bg-gray-800 rounded-lg p-6">
          <h2 className="text-lg font-semibold text-white mb-4">Remediation Tracking</h2>
          <div className="space-y-2">
            {MOCK_REMEDIATIONS.map(r => (
              <div key={r.id} className={cn("flex items-center justify-between p-3 rounded-lg", r.overdue ? "bg-red-900/20 border border-red-500/20" : "bg-gray-700/30")}>
                <div>
                  <p className="text-sm text-white font-medium">{r.finding_id}</p>
                  <p className="text-xs text-gray-400">{r.assignee} · due {r.due_date}</p>
                </div>
                <div className="flex items-center gap-2">
                  {r.overdue && <span className="text-xs text-red-400 font-bold">OVERDUE</span>}
                  <StatusBadge s={r.status} />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Top affected resources */}
        <div className="bg-gray-800 rounded-lg p-6">
          <h2 className="text-lg font-semibold text-white mb-4">Top Affected Resources</h2>
          <div className="space-y-3">
            {MOCK_TOP_RESOURCES.map(r => (
              <div key={r.resource_id}>
                <div className="flex justify-between text-xs mb-1">
                  <span className="text-gray-300 font-mono truncate max-w-[200px]" title={r.resource_id}>{r.resource_id}</span>
                  <span className="text-gray-400 ml-2">{r.finding_count} findings</span>
                </div>
                <div className="w-full bg-gray-700 rounded-full h-2">
                  <div className="h-2 rounded-full bg-orange-500" style={{ width: `${(r.finding_count / maxBar) * 100}%` }} />
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}
