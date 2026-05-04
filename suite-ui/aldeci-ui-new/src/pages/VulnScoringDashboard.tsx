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



// ── API helpers ───────────────────────────────────────────────────────────────

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}`, { headers: { "X-API-Key": API_KEY } });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function VulnScoringDashboard() {
  const [vulns, setVulns] = useState<VulnEntry[]>([]);
  const [overrides, setOverrides] = useState<Override[]>([]);
  const [assetRisks, setAssetRisks] = useState<AssetRisk[]>([]);
  const [loading, setLoading] = useState(true);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [filterPriority, setFilterPriority] = useState<string>("all");

  useEffect(() => {
    Promise.allSettled([
      apiFetch(`/api/v1/vuln-scoring/vulns?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/vuln-scoring/overrides?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/vuln-scoring/asset-risks?org_id=${ORG_ID}`),
    ]).then(([vulnsRes, overridesRes, assetsRes]) => {
      const v: VulnEntry[] = vulnsRes.status === "fulfilled" ? (vulnsRes.value as VulnEntry[]) : [];
      const o: Override[]  = overridesRes.status === "fulfilled" ? (overridesRes.value as Override[]) : [];
      const a: AssetRisk[] = assetsRes.status === "fulfilled" ? (assetsRes.value as AssetRisk[]) : [];
      setVulns(v);
      setOverrides(o);
      setAssetRisks(a);
      if (v.length > 0) setSelectedId(v[0].id);
    }).finally(() => setLoading(false));
  }, []);

  const selected = vulns.find(v => v.id === selectedId) ?? null;

  const filtered = filterPriority === "all"
    ? vulns
    : vulns.filter(v => v.priority === filterPriority);

  const distribution = [
    { label: "P1 Critical", count: vulns.filter(v => v.priority === "P1").length, color: "#ef4444" },
    { label: "P2 High",     count: vulns.filter(v => v.priority === "P2").length, color: "#f97316" },
    { label: "P3 Medium",   count: vulns.filter(v => v.priority === "P3").length, color: "#eab308" },
    { label: "P4 Low",      count: vulns.filter(v => v.priority === "P4").length, color: "#6b7280" },
  ];

  // Donut CSS approach: stacked bars as proxy
  const total = distribution.reduce((s, d) => s + d.count, 0);

  if (loading) return (
    <div className="min-h-screen bg-[#0f172a] p-6 space-y-4">
      {[1, 2, 3].map(i => <div key={i} className="h-24 rounded-lg bg-zinc-800/50 animate-pulse" />)}
    </div>
  );

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
          { label: "Total",       value: vulns.length,                                                                                                                      color: "text-white" },
          { label: "P1 Critical", value: vulns.filter(v => v.priority === "P1").length,                                                                                    color: "text-red-400" },
          { label: "KEV Listed",  value: vulns.filter(v => v.kev).length,                                                                                                  color: "text-orange-400" },
          { label: "Avg Score",   value: vulns.length > 0 ? Math.round(vulns.reduce((s, v) => s + v.composite_score, 0) / vulns.length) : 0,                              color: "text-amber-400" },
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
            {overrides.length === 0 ? (
              <div className="p-8 text-center text-gray-500 text-sm">No override history available</div>
            ) : overrides.map(ov => (
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
                {assetRisks.length === 0 ? (
                  <tr><td colSpan={4} className="p-8 text-center text-gray-500 text-sm">No asset risk data available</td></tr>
                ) : assetRisks.map(a => (
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
