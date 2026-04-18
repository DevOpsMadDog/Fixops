/**
 * Vulnerability Scoring Dashboard
 *
 * Priority queue, composite score breakdown, scoring model weights,
 * override history, distribution donut (CSS), asset risk scores.
 *
 * Route: /vuln-scoring
 */

import { useState, useEffect } from "react";
import { ShieldAlert, BarChart2, SlidersHorizontal, RefreshCw, AlertTriangle } from "lucide-react";

// ── Types ─────────────────────────────────────────────────────────────────────

type Priority = "P1" | "P2" | "P3" | "P4";

interface VulnEntry {
  id: string;
  cve: string;
  title: string;
  priority: Priority;
  composite_score: number;
  cvss: number;
  epss: number;
  kev: boolean;
  exposure: number; // 0-100
  assets_affected: number;
  status: "open" | "in-progress" | "resolved";
}

interface Override {
  id: string;
  cve: string;
  original_score: number;
  override_score: number;
  reason: string;
  overridden_by: string;
  date: string;
}

interface AssetRisk {
  asset: string;
  asset_type: string;
  risk_score: number;
  open_vulns: number;
  critical_count: number;
}

// ── Mock data ─────────────────────────────────────────────────────────────────

const MOCK_VULNS: VulnEntry[] = [
  { id: "v001", cve: "CVE-2025-3109", title: "Cisco IOS XE Auth Bypass",            priority: "P1", composite_score: 97, cvss: 9.8, epss: 0.94, kev: true,  exposure: 92, assets_affected: 14, status: "open" },
  { id: "v002", cve: "CVE-2025-1842", title: "OpenSSL Buffer Overflow",             priority: "P1", composite_score: 93, cvss: 9.1, epss: 0.88, kev: true,  exposure: 85, assets_affected: 32, status: "in-progress" },
  { id: "v003", cve: "CVE-2025-2201", title: "Apache Log4j2 RCE (Variant)",         priority: "P1", composite_score: 91, cvss: 9.0, epss: 0.81, kev: true,  exposure: 79, assets_affected: 8,  status: "open" },
  { id: "v004", cve: "CVE-2024-9971", title: "GitLab Improper Access Control",      priority: "P2", composite_score: 78, cvss: 8.2, epss: 0.67, kev: false, exposure: 65, assets_affected: 5,  status: "open" },
  { id: "v005", cve: "CVE-2024-8812", title: "Kubernetes RBAC Privilege Escalation", priority: "P2", composite_score: 74, cvss: 7.9, epss: 0.61, kev: false, exposure: 72, assets_affected: 21, status: "in-progress" },
  { id: "v006", cve: "CVE-2024-7654", title: "nginx HTTP/2 Denial of Service",      priority: "P2", composite_score: 68, cvss: 7.5, epss: 0.55, kev: false, exposure: 58, assets_affected: 9,  status: "open" },
  { id: "v007", cve: "CVE-2024-5501", title: "MySQL Injection via Prepared Stmt",   priority: "P3", composite_score: 52, cvss: 6.3, epss: 0.38, kev: false, exposure: 44, assets_affected: 3,  status: "open" },
  { id: "v008", cve: "CVE-2024-4499", title: "Redis Unauthorized Command Exec",     priority: "P3", composite_score: 48, cvss: 5.9, epss: 0.31, kev: false, exposure: 39, assets_affected: 7,  status: "in-progress" },
  { id: "v009", cve: "CVE-2024-3311", title: "Python urllib Path Traversal",        priority: "P4", composite_score: 27, cvss: 4.1, epss: 0.12, kev: false, exposure: 22, assets_affected: 2,  status: "open" },
  { id: "v010", cve: "CVE-2024-2102", title: "npm tar Symlink Attack",              priority: "P4", composite_score: 21, cvss: 3.7, epss: 0.08, kev: false, exposure: 18, assets_affected: 1,  status: "resolved" },
];

const MOCK_OVERRIDES: Override[] = [
  { id: "ov-001", cve: "CVE-2025-3109", original_score: 87, override_score: 97, reason: "Asset is externally reachable — bumped to P1",             overridden_by: "Alice Chen",   date: "2026-04-14" },
  { id: "ov-002", cve: "CVE-2024-9971", original_score: 83, override_score: 78, reason: "Internal-only GitLab instance — exposure reduced",          overridden_by: "Bob Smith",    date: "2026-04-10" },
  { id: "ov-003", cve: "CVE-2024-7654", original_score: 55, override_score: 68, reason: "Load balancer affects 9 production services — re-scored",   overridden_by: "Carol Wu",     date: "2026-04-08" },
  { id: "ov-004", cve: "CVE-2024-3311", original_score: 35, override_score: 27, reason: "Mitigating WAF rule deployed — score lowered",              overridden_by: "Dan Lee",      date: "2026-04-12" },
];

const MOCK_ASSET_RISKS: AssetRisk[] = [
  { asset: "prod-api-gateway",   asset_type: "API Gateway",    risk_score: 94, open_vulns: 6,  critical_count: 3 },
  { asset: "k8s-master-cluster", asset_type: "Kubernetes",     risk_score: 88, open_vulns: 9,  critical_count: 2 },
  { asset: "db-postgres-prod",   asset_type: "Database",       risk_score: 76, open_vulns: 4,  critical_count: 1 },
  { asset: "nginx-lb-01",        asset_type: "Load Balancer",  risk_score: 68, open_vulns: 3,  critical_count: 0 },
  { asset: "redis-cache-prod",   asset_type: "Cache",          risk_score: 55, open_vulns: 5,  critical_count: 0 },
  { asset: "gitlab-internal",    asset_type: "DevTools",       risk_score: 48, open_vulns: 2,  critical_count: 0 },
];

// Scoring model weights
const MODEL_WEIGHTS = [
  { component: "CVSS Base Score", weight: 30 },
  { component: "EPSS Probability", weight: 25 },
  { component: "KEV Status", weight: 25 },
  { component: "Exposure Score", weight: 20 },
];

// ── Helpers ───────────────────────────────────────────────────────────────────

function priorityColor(p: Priority): { bg: string; text: string; border: string } {
  return p === "P1"
    ? { bg: "bg-red-500/20",    text: "text-red-300",    border: "border-red-500" }
    : p === "P2"
    ? { bg: "bg-orange-500/20", text: "text-orange-300", border: "border-orange-400" }
    : p === "P3"
    ? { bg: "bg-yellow-500/20", text: "text-yellow-300", border: "border-yellow-400" }
    : { bg: "bg-gray-500/20",   text: "text-gray-400",   border: "border-gray-500" };
}

function scoreColor(s: number): string {
  return s >= 80 ? "text-red-400" : s >= 60 ? "text-orange-400" : s >= 40 ? "text-yellow-400" : "text-green-400";
}

function scoreBarColor(s: number): string {
  return s >= 80 ? "bg-red-500" : s >= 60 ? "bg-orange-400" : s >= 40 ? "bg-yellow-400" : "bg-green-500";
}

function statusBadge(s: string): string {
  return s === "open" ? "bg-red-500/20 text-red-300" : s === "in-progress" ? "bg-blue-500/20 text-blue-300" : "bg-green-500/20 text-green-300";
}

// Donut segments
const distribution = [
  { label: "P1 Critical", count: MOCK_VULNS.filter(v => v.priority === "P1").length, color: "#ef4444" },
  { label: "P2 High",     count: MOCK_VULNS.filter(v => v.priority === "P2").length, color: "#f97316" },
  { label: "P3 Medium",   count: MOCK_VULNS.filter(v => v.priority === "P3").length, color: "#eab308" },
  { label: "P4 Low",      count: MOCK_VULNS.filter(v => v.priority === "P4").length, color: "#6b7280" },
];

// ── Component ─────────────────────────────────────────────────────────────────

export default function VulnScoringDashboard() {
  const [selectedId, setSelectedId] = useState<string | null>("v001");
  useEffect(() => {
    fetch("/api/v1/vuln-scoring", { headers: { "X-API-Key": localStorage.getItem("apiKey") || "" } })
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(() => { /* live data available */ })
      .catch(() => { setError('Failed to load data'); });
  }, []);
  const [filterPriority, setFilterPriority] = useState<string>("all");

  const selected = MOCK_VULNS.find(v => v.id === selectedId) ?? null;

  const filtered = filterPriority === "all"
    ? MOCK_VULNS
    : MOCK_VULNS.filter(v => v.priority === filterPriority);

  // Donut CSS approach: stacked bars as proxy
  const total = distribution.reduce((s, d) => s + d.count, 0);

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <ShieldAlert className="w-6 h-6 text-orange-400" />
            Vulnerability Scoring
          </h1>
          <p className="text-gray-400 text-sm mt-1">Composite risk prioritization — CVSS + EPSS + KEV + Exposure</p>
        </div>
        <button className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm transition-colors">
          <RefreshCw className="w-4 h-4" /> Refresh
        </button>
      </div>

      {/* KPIs */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {[
          { label: "Total",       value: MOCK_VULNS.length,                                           color: "text-white" },
          { label: "P1 Critical", value: MOCK_VULNS.filter(v => v.priority === "P1").length,          color: "text-red-400" },
          { label: "KEV Listed",  value: MOCK_VULNS.filter(v => v.kev).length,                        color: "text-orange-400" },
          { label: "Avg Score",   value: Math.round(MOCK_VULNS.reduce((s, v) => s + v.composite_score, 0) / MOCK_VULNS.length), color: "text-amber-400" },
        ].map(k => (
          <div key={k.label} className="bg-gray-800 rounded-lg p-4 text-center">
            <div className={`text-3xl font-bold ${k.color}`}>{k.value}</div>
            <div className="text-gray-400 text-xs mt-1">{k.label}</div>
          </div>
        ))}
      </div>

      {/* Priority filter */}
      <div className="flex gap-2">
        {["all", "P1", "P2", "P3", "P4"].map(p => (
          <button
            key={p}
            onClick={() => setFilterPriority(p)}
            className={`px-3 py-1 rounded-full text-xs font-medium transition-colors ${filterPriority === p ? "bg-indigo-600 text-white" : "bg-gray-700 text-gray-300 hover:bg-gray-600"}`}
          >
            {p === "all" ? "All" : p}
          </button>
        ))}
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Priority queue */}
        <div className="xl:col-span-2 bg-gray-800 rounded-lg overflow-hidden">
          <div className="p-4 border-b border-gray-700">
            <h2 className="font-semibold text-white">Priority Queue</h2>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-700 text-gray-400 text-xs uppercase">
                  <th className="text-left p-3">Priority</th>
                  <th className="text-left p-3">CVE</th>
                  <th className="text-left p-3 hidden sm:table-cell">Title</th>
                  <th className="text-left p-3">Score</th>
                  <th className="text-left p-3 hidden md:table-cell">KEV</th>
                  <th className="text-left p-3">Status</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map(v => {
                  const pc = priorityColor(v.priority);
                  return (
                    <tr
                      key={v.id}
                      onClick={() => setSelectedId(v.id)}
                      className={`border-b border-gray-700/50 cursor-pointer hover:bg-gray-700/40 transition-colors ${selectedId === v.id ? "bg-gray-700/60" : ""}`}
                    >
                      <td className="p-3">
                        <span className={`px-2 py-0.5 rounded-full text-xs font-bold ${pc.bg} ${pc.text}`}>{v.priority}</span>
                      </td>
                      <td className="p-3 text-gray-300 font-mono text-xs">{v.cve}</td>
                      <td className="p-3 text-gray-200 hidden sm:table-cell max-w-[180px] truncate">{v.title}</td>
                      <td className="p-3">
                        <div className="flex items-center gap-2">
                          <span className={`font-bold text-sm ${scoreColor(v.composite_score)}`}>{v.composite_score}</span>
                          <div className="w-16 bg-gray-700 rounded-full h-1.5 hidden sm:block">
                            <div className={`h-1.5 rounded-full ${scoreBarColor(v.composite_score)}`} style={{ width: `${v.composite_score}%` }} />
                          </div>
                        </div>
                      </td>
                      <td className="p-3 hidden md:table-cell">
                        {v.kev ? <span className="bg-red-500/20 text-red-300 text-xs px-2 py-0.5 rounded-full font-medium">KEV</span> : <span className="text-gray-600 text-xs">—</span>}
                      </td>
                      <td className="p-3">
                        <span className={`text-xs px-2 py-0.5 rounded-full capitalize ${statusBadge(v.status)}`}>{v.status}</span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        {/* Right column */}
        <div className="space-y-4">
          {/* Composite score breakdown */}
          {selected && (
            <div className="bg-gray-800 rounded-lg p-5">
              <h2 className="font-semibold text-white text-sm mb-3">Score Breakdown: {selected.cve}</h2>
              <div className={`text-4xl font-bold mb-4 ${scoreColor(selected.composite_score)}`}>{selected.composite_score}<span className="text-lg text-gray-400">/100</span></div>
              <div className="space-y-3">
                {[
                  { label: "CVSS",     value: Math.round(selected.cvss * 10), display: selected.cvss.toFixed(1) },
                  { label: "EPSS",     value: Math.round(selected.epss * 100), display: `${(selected.epss * 100).toFixed(0)}%` },
                  { label: "KEV",      value: selected.kev ? 100 : 0,         display: selected.kev ? "Listed" : "Not Listed" },
                  { label: "Exposure", value: selected.exposure,               display: `${selected.exposure}%` },
                ].map(c => (
                  <div key={c.label}>
                    <div className="flex justify-between text-xs mb-1">
                      <span className="text-gray-400">{c.label}</span>
                      <span className="text-gray-300 font-medium">{c.display}</span>
                    </div>
                    <div className="w-full bg-gray-700 rounded-full h-2">
                      <div className={`h-2 rounded-full ${scoreBarColor(c.value)}`} style={{ width: `${c.value}%` }} />
                    </div>
                  </div>
                ))}
              </div>
              <div className="mt-3 text-xs text-gray-400">
                Assets affected: <span className="text-white font-semibold">{selected.assets_affected}</span>
              </div>
            </div>
          )}

          {/* Scoring model weights */}
          <div className="bg-gray-800 rounded-lg p-5">
            <h2 className="font-semibold text-white text-sm mb-3 flex items-center gap-2">
              <SlidersHorizontal className="w-4 h-4 text-indigo-400" /> Model Weights
            </h2>
            <div className="space-y-3">
              {MODEL_WEIGHTS.map(w => (
                <div key={w.component}>
                  <div className="flex justify-between text-xs mb-1">
                    <span className="text-gray-400">{w.component}</span>
                    <span className="text-gray-300">{w.weight}%</span>
                  </div>
                  <div className="w-full bg-gray-700 rounded-full h-1.5">
                    <div className="h-1.5 rounded-full bg-indigo-500" style={{ width: `${w.weight}%` }} />
                  </div>
                </div>
              ))}
            </div>
          </div>

          {/* Distribution donut (CSS) */}
          <div className="bg-gray-800 rounded-lg p-5">
            <h2 className="font-semibold text-white text-sm mb-3 flex items-center gap-2">
              <BarChart2 className="w-4 h-4 text-orange-400" /> Distribution
            </h2>
            <div className="space-y-2">
              {distribution.map(d => (
                <div key={d.label} className="flex items-center gap-3">
                  <div className="w-3 h-3 rounded-full flex-shrink-0" style={{ backgroundColor: d.color }} />
                  <div className="flex-1">
                    <div className="flex justify-between text-xs mb-0.5">
                      <span className="text-gray-300">{d.label}</span>
                      <span className="text-gray-400">{d.count}/{total}</span>
                    </div>
                    <div className="w-full bg-gray-700 rounded-full h-2">
                      <div className="h-2 rounded-full" style={{ backgroundColor: d.color, width: `${(d.count / total) * 100}%` }} />
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Override history + asset risk table */}
      <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
        {/* Override history */}
        <div className="bg-gray-800 rounded-lg overflow-hidden">
          <div className="p-4 border-b border-gray-700">
            <h2 className="font-semibold text-white text-sm">Override History</h2>
          </div>
          <div className="divide-y divide-gray-700/50">
            {MOCK_OVERRIDES.map(ov => (
              <div key={ov.id} className="p-4">
                <div className="flex items-center gap-2 mb-1">
                  <span className="font-mono text-xs text-gray-300">{ov.cve}</span>
                  <span className="text-gray-500 text-xs">{ov.original_score} → <span className="text-white font-semibold">{ov.override_score}</span></span>
                </div>
                <p className="text-gray-400 text-xs">{ov.reason}</p>
                <div className="text-gray-500 text-xs mt-1">{ov.overridden_by} · {ov.date}</div>
              </div>
            ))}
          </div>
        </div>

        {/* Asset risk scores */}
        <div className="bg-gray-800 rounded-lg overflow-hidden">
          <div className="p-4 border-b border-gray-700">
            <h2 className="font-semibold text-white text-sm">Asset Risk Scores</h2>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-700 text-gray-400 text-xs uppercase">
                  <th className="text-left p-3">Asset</th>
                  <th className="text-left p-3">Type</th>
                  <th className="text-left p-3">Risk</th>
                  <th className="text-left p-3">Vulns</th>
                </tr>
              </thead>
              <tbody>
                {MOCK_ASSET_RISKS.map(a => (
                  <tr key={a.asset} className="border-b border-gray-700/50">
                    <td className="p-3 text-gray-200 font-mono text-xs">{a.asset}</td>
                    <td className="p-3 text-gray-400 text-xs">{a.asset_type}</td>
                    <td className="p-3">
                      <div className="flex items-center gap-2">
                        <span className={`font-bold text-sm ${scoreColor(a.risk_score)}`}>{a.risk_score}</span>
                        <div className="w-12 bg-gray-700 rounded-full h-1.5">
                          <div className={`h-1.5 rounded-full ${scoreBarColor(a.risk_score)}`} style={{ width: `${a.risk_score}%` }} />
                        </div>
                      </div>
                    </td>
                    <td className="p-3">
                      <span className="text-gray-300 text-xs">{a.open_vulns}</span>
                      {a.critical_count > 0 && <span className="text-red-400 text-xs ml-1">({a.critical_count} crit)</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  );
}
