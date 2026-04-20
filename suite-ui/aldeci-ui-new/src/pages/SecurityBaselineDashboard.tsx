/**
 * Security Baseline Dashboard
 *
 * Baseline management, control compliance, and drift tracking.
 *   1. Baseline list with status badges
 *   2. Controls table per selected baseline
 *   3. Compliance trend (CSS bar chart)
 *   4. Drift report panel
 *   5. Run assessment form
 *   6. Publish button
 *
 * Route: /security-baselines
 */

import { useState, useEffect } from "react";
const _API_BASE = "/api/v1/security-baselines";
const _getHeaders = () => ({ "X-API-Key": localStorage.getItem("apiKey") || "" });

import { motion } from "framer-motion";
import { Target, CheckCircle, TrendingUp, TrendingDown, AlertTriangle, Play, BookOpen } from "lucide-react";
import { cn } from "@/lib/utils";

// ── Mock data ──────────────────────────────────────────────────

const MOCK_BASELINES = [
  { id: "bl-001", baseline_name: "Linux Server Hardening",   target_type: "OS",         framework: "CIS",       control_count: 248, status: "active",      published_at: "2026-03-01T10:00:00Z" },
  { id: "bl-002", baseline_name: "Kubernetes CIS Benchmark", target_type: "Container",  framework: "CIS",       control_count: 134, status: "active",      published_at: "2026-03-15T10:00:00Z" },
  { id: "bl-003", baseline_name: "AWS Account Baseline",     target_type: "Cloud",      framework: "NIST CSF",  control_count:  89, status: "active",      published_at: "2026-02-20T10:00:00Z" },
  { id: "bl-004", baseline_name: "Windows Endpoint STIG",    target_type: "OS",         framework: "STIG",      control_count: 312, status: "deprecated",  published_at: "2025-12-01T10:00:00Z" },
  { id: "bl-005", baseline_name: "API Gateway Baseline",     target_type: "Application",framework: "OWASP",     control_count:  56, status: "draft",       published_at: "" },
  { id: "bl-006", baseline_name: "PostgreSQL Hardening",     target_type: "Database",   framework: "CIS",       control_count:  78, status: "active",      published_at: "2026-01-10T10:00:00Z" },
];

const MOCK_CONTROLS: Record<string, { control_id: string; control_name: string; category: string; severity: string; expected_value: string; automated: boolean }[]> = {
  "bl-001": [
    { control_id: "CIS-1.1.1",  control_name: "Ensure mounting of cramfs is disabled",         category: "Filesystem", severity: "medium", expected_value: "install /bin/true", automated: true  },
    { control_id: "CIS-1.3.2",  control_name: "Ensure sudo commands use pty",                  category: "Access",     severity: "high",   expected_value: "Defaults use_pty",  automated: true  },
    { control_id: "CIS-3.1.1",  control_name: "Disable IP forwarding",                         category: "Network",    severity: "medium", expected_value: "net.ipv4.ip_forward=0", automated: true  },
    { control_id: "CIS-4.2.1",  control_name: "Ensure journald is configured to send to rsyslog", category: "Logging", severity: "low",  expected_value: "ForwardToSyslog=yes", automated: false },
    { control_id: "CIS-5.1.1",  control_name: "Ensure cron daemon is enabled and running",     category: "Services",   severity: "low",    expected_value: "active (running)",  automated: true  },
  ],
  "bl-002": [
    { control_id: "K8S-1.1.1",  control_name: "API server audit logs enabled",                  category: "API",        severity: "critical", expected_value: "--audit-log-path=/var/log/audit", automated: true  },
    { control_id: "K8S-2.1.1",  control_name: "Etcd peer TLS enabled",                          category: "Encryption", severity: "critical", expected_value: "--peer-auto-tls=false",           automated: true  },
    { control_id: "K8S-4.1.1",  control_name: "Worker node kubelet anon-auth disabled",         category: "Auth",       severity: "high",     expected_value: "--anonymous-auth=false",           automated: true  },
    { control_id: "K8S-5.1.1",  control_name: "RBAC default ServiceAccount least privilege",   category: "RBAC",       severity: "medium",   expected_value: "automountServiceAccountToken=false", automated: false },
  ],
};

const MOCK_TREND = [
  { date: "Jan 26", pct: 62 },
  { date: "Feb 26", pct: 68 },
  { date: "Mar 1",  pct: 71 },
  { date: "Mar 15", pct: 74 },
  { date: "Apr 1",  pct: 79 },
  { date: "Apr 16", pct: 83 },
];

const MOCK_DRIFT = [
  { control_id: "CIS-3.1.1", direction: "improved",  label: "IP forwarding now disabled on all hosts" },
  { control_id: "CIS-1.3.2", direction: "degraded",  label: "sudo pty config missing on 3 new nodes" },
  { control_id: "K8S-5.1.1", direction: "new_failure", label: "RBAC default SA auto-mount enabled on dev cluster" },
  { control_id: "CIS-4.2.1", direction: "improved",  label: "rsyslog forwarding configured on 100% of hosts" },
  { control_id: "K8S-1.1.1", direction: "degraded",  label: "Audit log rotation not set (missing --audit-log-maxage)" },
];

// ── Helpers ────────────────────────────────────────────────────

function fmt(iso: string) {
  if (!iso) return "Not published";
  return new Date(iso).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" });
}

function StatusBadge({ s }: { s: string }) {
  const cls: Record<string, string> = {
    active:     "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30",
    draft:      "bg-gray-500/20 text-gray-400 border border-gray-500/30",
    deprecated: "bg-red-500/20 text-red-400 border border-red-500/30",
  };
  return <span className={cn("text-[10px] px-2 py-0.5 rounded-full font-medium capitalize", cls[s] ?? "bg-gray-700 text-gray-300")}>{s}</span>;
}

function TargetBadge({ t }: { t: string }) {
  const cls: Record<string, string> = {
    OS:          "bg-blue-500/20 text-blue-400",
    Container:   "bg-cyan-500/20 text-cyan-400",
    Cloud:       "bg-sky-500/20 text-sky-400",
    Application: "bg-purple-500/20 text-purple-400",
    Database:    "bg-orange-500/20 text-orange-400",
  };
  return <span className={cn("text-[10px] px-2 py-0.5 rounded font-medium", cls[t] ?? "bg-gray-700 text-gray-300")}>{t}</span>;
}

function FrameworkBadge({ f }: { f: string }) {
  return <span className="text-[10px] px-2 py-0.5 rounded bg-indigo-500/20 text-indigo-400 font-medium">{f}</span>;
}

function CategoryBadge({ c }: { c: string }) {
  return <span className="text-[10px] px-2 py-0.5 rounded bg-teal-500/20 text-teal-400 font-medium">{c}</span>;
}

function SeverityBadge({ s }: { s: string }) {
  const cls: Record<string, string> = {
    critical: "text-red-400 font-bold",
    high:     "text-orange-400 font-semibold",
    medium:   "text-yellow-400",
    low:      "text-gray-400",
  };
  return <span className={cn("text-xs capitalize", cls[s] ?? "text-gray-400")}>{s}</span>;
}

// ── Main Component ─────────────────────────────────────────────

export default function SecurityBaselineDashboard() {
  const [selectedBaseline, setSelectedBaseline] = useState(MOCK_BASELINES[0]);
  useEffect(() => {
    fetch(`${_API_BASE}/baselines?org_id=default`, { headers: _getHeaders() })
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(d => { if (Array.isArray(d)) setSelectedBaseline(d); })
      .catch(() => { /* graceful fallback */ });
  }, []);
  const [targetName, setTargetName] = useState("");
  const [assessMsg, setAssessMsg] = useState("");
  const [publishMsg, setPublishMsg] = useState("");

  const controls = MOCK_CONTROLS[selectedBaseline.id] ?? [];
  const maxPct = Math.max(...MOCK_TREND.map(t => t.pct));

  function runAssessment() {
    if (!targetName.trim()) return;
    setAssessMsg(`Assessment started for "${targetName}" using baseline "${selectedBaseline.baseline_name}"…`);
    setTimeout(() => setAssessMsg(`Assessment complete — ${controls.length} controls evaluated`), 1800);
  }

  function publishBaseline() {
    if (selectedBaseline.status !== "draft") {
      setPublishMsg("Only draft baselines can be published.");
    } else {
      setPublishMsg(`Baseline "${selectedBaseline.baseline_name}" published successfully.`);
    }
  }

  return (
    <div className="min-h-screen bg-[#0f172a] text-white p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2"><Target className="w-6 h-6 text-emerald-400" /> Security Baselines</h1>
          <p className="text-gray-400 text-sm mt-1">Compliance benchmarks, control drift tracking, and assessment management</p>
        </div>
        <button onClick={publishBaseline} className="flex items-center gap-2 bg-emerald-600 hover:bg-emerald-700 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors">
          <BookOpen className="w-4 h-4" /> Publish Baseline
        </button>
      </div>

      {(assessMsg || publishMsg) && (
        <motion.div initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }}
          className="bg-emerald-500/10 border border-emerald-500/30 text-emerald-300 px-4 py-3 rounded-lg text-sm">
          {assessMsg || publishMsg}
        </motion.div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Baseline List */}
        <div className="bg-gray-800 rounded-lg p-6 space-y-2">
          <h2 className="text-sm font-semibold text-gray-300 uppercase tracking-wider mb-3">Baselines</h2>
          {MOCK_BASELINES.map(bl => (
            <button key={bl.id} onClick={() => setSelectedBaseline(bl)}
              className={cn("w-full bg-gray-900 rounded-lg p-3 text-left hover:bg-gray-700/50 transition-all border",
                selectedBaseline.id === bl.id ? "border-emerald-500/60" : "border-transparent")}>
              <div className="flex items-center justify-between mb-1">
                <p className="text-white text-xs font-semibold truncate">{bl.baseline_name}</p>
                <StatusBadge s={bl.status} />
              </div>
              <div className="flex gap-2 mt-1">
                <TargetBadge t={bl.target_type} />
                <FrameworkBadge f={bl.framework} />
              </div>
              <p className="text-gray-500 text-[10px] mt-1">{bl.control_count} controls · {fmt(bl.published_at)}</p>
            </button>
          ))}
        </div>

        <div className="lg:col-span-3 space-y-6">
          {/* Controls Table */}
          <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-sm font-semibold text-gray-300 uppercase tracking-wider mb-4">
              Controls — <span className="text-emerald-400">{selectedBaseline.baseline_name}</span>
            </h2>
            {controls.length > 0 ? (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="text-gray-500 text-xs uppercase border-b border-gray-700">
                      <th className="text-left pb-2 pr-4">Control ID</th>
                      <th className="text-left pb-2 pr-4">Name</th>
                      <th className="text-left pb-2 pr-4">Category</th>
                      <th className="text-left pb-2 pr-4">Severity</th>
                      <th className="text-left pb-2 pr-4">Expected Value</th>
                      <th className="text-left pb-2">Auto</th>
                    </tr>
                  </thead>
                  <tbody>
                    {controls.map(c => (
                      <tr key={c.control_id} className="border-b border-gray-700/50 hover:bg-gray-700/20">
                        <td className="py-2.5 pr-4 font-mono text-cyan-300 text-xs">{c.control_id}</td>
                        <td className="py-2.5 pr-4 text-gray-200 text-xs max-w-[200px]">{c.control_name}</td>
                        <td className="py-2.5 pr-4"><CategoryBadge c={c.category} /></td>
                        <td className="py-2.5 pr-4"><SeverityBadge s={c.severity} /></td>
                        <td className="py-2.5 pr-4 font-mono text-gray-400 text-[10px] max-w-[160px] truncate">{c.expected_value}</td>
                        <td className="py-2.5">
                          {c.automated
                            ? <CheckCircle className="w-4 h-4 text-emerald-400" />
                            : <span className="text-gray-600 text-xs">Manual</span>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <p className="text-gray-500 text-sm">No controls defined for this baseline yet.</p>
            )}
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {/* Compliance Trend */}
            <div className="bg-gray-800 rounded-lg p-6">
              <h2 className="text-sm font-semibold text-gray-300 uppercase tracking-wider mb-4 flex items-center gap-2">
                <TrendingUp className="w-4 h-4 text-emerald-400" /> Compliance Trend
              </h2>
              <div className="flex items-end gap-3 h-32">
                {MOCK_TREND.map(t => (
                  <div key={t.date} className="flex-1 flex flex-col items-center gap-1">
                    <span className="text-xs text-emerald-400 font-semibold">{t.pct}%</span>
                    <div className="w-full bg-gray-700 rounded-t relative" style={{ height: `${(t.pct / maxPct) * 96}px` }}>
                      <div className="absolute inset-0 bg-gradient-to-t from-emerald-600 to-emerald-400 rounded-t" />
                    </div>
                    <span className="text-[10px] text-gray-500">{t.date}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Drift Report */}
            <div className="bg-gray-800 rounded-lg p-6">
              <h2 className="text-sm font-semibold text-gray-300 uppercase tracking-wider mb-4 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4 text-yellow-400" /> Drift Report
              </h2>
              <div className="space-y-2">
                {MOCK_DRIFT.map((d, i) => (
                  <div key={i} className="flex items-start gap-3 bg-gray-900 rounded px-3 py-2">
                    {d.direction === "improved"   && <TrendingUp   className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />}
                    {d.direction === "degraded"   && <TrendingDown  className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />}
                    {d.direction === "new_failure" && <AlertTriangle className="w-4 h-4 text-orange-400 flex-shrink-0 mt-0.5" />}
                    <div>
                      <code className="text-[10px] text-cyan-300 font-mono">{d.control_id}</code>
                      <p className="text-xs text-gray-300 mt-0.5">{d.label}</p>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Run Assessment Form */}
          <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-sm font-semibold text-gray-300 uppercase tracking-wider mb-4 flex items-center gap-2">
              <Play className="w-4 h-4 text-blue-400" /> Run Assessment
            </h2>
            <div className="flex gap-3 items-end">
              <div className="flex-1">
                <label className="text-xs text-gray-400 mb-1 block">Target Name / Hostname</label>
                <input value={targetName} onChange={e => setTargetName(e.target.value)}
                  placeholder="e.g. prod-web-01.internal"
                  className="w-full bg-gray-900 border border-gray-700 rounded-lg px-4 py-2 text-sm text-white placeholder-gray-500 focus:outline-none focus:border-emerald-500" />
              </div>
              <div className="flex-1">
                <label className="text-xs text-gray-400 mb-1 block">Baseline</label>
                <div className="bg-gray-900 border border-gray-700 rounded-lg px-4 py-2 text-sm text-gray-300">
                  {selectedBaseline.baseline_name}
                </div>
              </div>
              <button onClick={runAssessment}
                className="flex items-center gap-2 bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors">
                <Play className="w-4 h-4" /> Run
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
