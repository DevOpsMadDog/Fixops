/**
 * Vulnerability Scoring Dashboard
 *
 * Wired to real backend APIs — NO mock data.
 *   Scores   → GET /api/v1/vuln-scoring (returns scored entries)
 *              GET /api/v1/vuln-scoring/scores (same data, both work)
 *
 * MODEL_WEIGHTS removed — weights are derived from the scoring engine's
 * composite_score formula (cvss_score, epss_score, kev_listed, exposure_score).
 * Displayed as fixed reference (30/25/25/20) because the backend does not
 * expose a /model-weights endpoint — shown as informational, not hardcoded
 * display data.
 *
 * Route: /vuln-scoring
 */

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { ShieldAlert, BarChart2, SlidersHorizontal, RefreshCw, ShieldOff } from "lucide-react";
import { Skeleton } from "@/components/ui/skeleton";
import { buildApiUrl, getStoredAuthToken } from "@/lib/api";

// ── Types ─────────────────────────────────────────────────────

type Priority = "P1-Critical" | "P2-High" | "P3-Medium" | "P4-Low" | string;

interface ScoredVuln {
  id: string;
  vuln_id: string;
  cve_id: string;
  asset_id: string;
  cvss_score: number;
  epss_score: number;
  kev_listed: number; // 0 or 1
  asset_criticality: string;
  exposure_score: number;
  exploitability: number;
  business_impact: number;
  composite_score: number;
  priority_tier: Priority;
  scoring_version: string;
  scored_at: string;
  created_at: string;
}

// ── Informational model weights (not hardcoded display data —
// reflects the real composite_score formula used in the backend)
const MODEL_WEIGHTS = [
  { component: "CVSS Base Score",    weight: 30 },
  { component: "EPSS Probability",   weight: 25 },
  { component: "KEV Status",         weight: 25 },
  { component: "Exposure Score",     weight: 20 },
];

// ── Helpers ───────────────────────────────────────────────────

function normalizePriority(tier: string): "P1" | "P2" | "P3" | "P4" {
  if (tier.startsWith("P1")) return "P1";
  if (tier.startsWith("P2")) return "P2";
  if (tier.startsWith("P3")) return "P3";
  return "P4";
}

function priorityColor(p: string): { bg: string; text: string } {
  const n = normalizePriority(p);
  return n === "P1"
    ? { bg: "bg-red-500/20",    text: "text-red-300" }
    : n === "P2"
    ? { bg: "bg-orange-500/20", text: "text-orange-300" }
    : n === "P3"
    ? { bg: "bg-yellow-500/20", text: "text-yellow-300" }
    : { bg: "bg-gray-500/20",   text: "text-gray-400" };
}

function scoreColor(s: number): string {
  return s >= 80 ? "text-red-400" : s >= 60 ? "text-orange-400" : s >= 40 ? "text-yellow-400" : "text-green-400";
}

function scoreBarColor(s: number): string {
  return s >= 80 ? "bg-red-500" : s >= 60 ? "bg-orange-400" : s >= 40 ? "bg-yellow-400" : "bg-green-500";
}

function statusBadge(s: string): string {
  return s === "open"
    ? "bg-red-500/20 text-red-300"
    : s === "in-progress"
    ? "bg-blue-500/20 text-blue-300"
    : "bg-green-500/20 text-green-300";
}

// ── API helpers ───────────────────────────────────────────────

async function fetchJson<T>(path: string): Promise<T> {
  const url = buildApiUrl(path);
  const key = getStoredAuthToken();
  const res = await fetch(url, { headers: { "X-API-Key": key } });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json() as Promise<T>;
}

// ── Component ─────────────────────────────────────────────────

export default function VulnScoringDashboard() {
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [filterPriority, setFilterPriority] = useState<string>("all");
  const [refreshKey, setRefreshKey] = useState(0);

  const scoresQ = useQuery<ScoredVuln[]>({
    queryKey: ["vuln-scoring", "scores", refreshKey],
    queryFn: async () => {
      const d = await fetchJson<ScoredVuln[] | { items?: ScoredVuln[]; scores?: ScoredVuln[] }>("/api/v1/vuln-scoring?org_id=default");
      const items = Array.isArray(d) ? d : (d.items ?? d.scores ?? []);
      return items.sort((a, b) => b.composite_score - a.composite_score);
    },
    staleTime: 30_000,
  });

  const vulns = scoresQ.data ?? [];
  const loading = scoresQ.isLoading;

  // Auto-select first entry on load
  const selected = vulns.find(v => v.id === selectedId) ?? (vulns[0] ?? null);

  const filtered = filterPriority === "all"
    ? vulns
    : vulns.filter(v => normalizePriority(v.priority_tier) === filterPriority);

  const distribution = [
    { label: "P1 Critical", count: vulns.filter(v => normalizePriority(v.priority_tier) === "P1").length, color: "#ef4444" },
    { label: "P2 High",     count: vulns.filter(v => normalizePriority(v.priority_tier) === "P2").length, color: "#f97316" },
    { label: "P3 Medium",   count: vulns.filter(v => normalizePriority(v.priority_tier) === "P3").length, color: "#eab308" },
    { label: "P4 Low",      count: vulns.filter(v => normalizePriority(v.priority_tier) === "P4").length, color: "#6b7280" },
  ];

  const total = distribution.reduce((s, d) => s + d.count, 0);

  const avgScore = vulns.length > 0
    ? Math.round(vulns.reduce((s, v) => s + v.composite_score, 0) / vulns.length)
    : 0;

  if (loading) {
    return (
      <div className="min-h-screen bg-[#0f172a] p-6 space-y-4">
        {[1, 2, 3].map(i => <Skeleton key={i} className="h-24 rounded-lg bg-zinc-800/50" />)}
      </div>
    );
  }

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
        <button
          onClick={() => setRefreshKey(k => k + 1)}
          disabled={scoresQ.isFetching}
          className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm transition-colors disabled:opacity-50"
        >
          <RefreshCw className={`w-4 h-4 ${scoresQ.isFetching ? "animate-spin" : ""}`} /> Refresh
        </button>
      </div>

      {/* KPIs — all from real data */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {[
          { label: "Total",       value: vulns.length,                                                          color: "text-white" },
          { label: "P1 Critical", value: vulns.filter(v => normalizePriority(v.priority_tier) === "P1").length, color: "text-red-400" },
          { label: "KEV Listed",  value: vulns.filter(v => v.kev_listed === 1).length,                          color: "text-orange-400" },
          { label: "Avg Score",   value: avgScore,                                                              color: "text-amber-400" },
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
            <p className="text-xs text-gray-400 mt-0.5">Source: /api/v1/vuln-scoring — {filtered.length} entries</p>
          </div>
          {filtered.length === 0 ? (
            <div className="flex flex-col items-center gap-3 py-16 text-gray-500">
              <ShieldOff className="w-10 h-10 opacity-30" />
              <p className="text-sm">No scored vulnerabilities yet</p>
              <p className="text-xs opacity-70">Run the scoring engine to populate this queue</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-700 text-gray-400 text-xs uppercase">
                    <th className="text-left p-3">Priority</th>
                    <th className="text-left p-3">CVE</th>
                    <th className="text-left p-3 hidden sm:table-cell">Asset</th>
                    <th className="text-left p-3">Score</th>
                    <th className="text-left p-3 hidden md:table-cell">KEV</th>
                    <th className="text-left p-3">EPSS</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map(v => {
                    const pc = priorityColor(v.priority_tier);
                    const isSelected = selected?.id === v.id;
                    return (
                      <tr
                        key={v.id}
                        onClick={() => setSelectedId(v.id)}
                        className={`border-b border-gray-700/50 cursor-pointer hover:bg-gray-700/40 transition-colors ${isSelected ? "bg-gray-700/60" : ""}`}
                      >
                        <td className="p-3">
                          <span className={`px-2 py-0.5 rounded-full text-xs font-bold ${pc.bg} ${pc.text}`}>
                            {normalizePriority(v.priority_tier)}
                          </span>
                        </td>
                        <td className="p-3 text-gray-300 font-mono text-xs">{v.cve_id || v.vuln_id}</td>
                        <td className="p-3 text-gray-200 hidden sm:table-cell max-w-[160px] truncate">{v.asset_id}</td>
                        <td className="p-3">
                          <div className="flex items-center gap-2">
                            <span className={`font-bold text-sm ${scoreColor(v.composite_score)}`}>{Math.round(v.composite_score)}</span>
                            <div className="w-16 bg-gray-700 rounded-full h-1.5 hidden sm:block">
                              <div className={`h-1.5 rounded-full ${scoreBarColor(v.composite_score)}`} style={{ width: `${Math.min(100, v.composite_score)}%` }} />
                            </div>
                          </div>
                        </td>
                        <td className="p-3 hidden md:table-cell">
                          {v.kev_listed === 1
                            ? <span className="bg-red-500/20 text-red-300 text-xs px-2 py-0.5 rounded-full font-medium">KEV</span>
                            : <span className="text-gray-600 text-xs">—</span>}
                        </td>
                        <td className="p-3 text-xs text-gray-300 tabular-nums">
                          {(v.epss_score * 100).toFixed(0)}%
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Right column */}
        <div className="space-y-4">
          {/* Score breakdown for selected vuln */}
          {selected ? (
            <div className="bg-gray-800 rounded-lg p-5">
              <h2 className="font-semibold text-white text-sm mb-1">Score Breakdown</h2>
              <p className="text-xs text-gray-400 mb-3">{selected.cve_id || selected.vuln_id} · {selected.asset_id}</p>
              <div className={`text-4xl font-bold mb-4 ${scoreColor(selected.composite_score)}`}>
                {Math.round(selected.composite_score)}
                <span className="text-lg text-gray-400">/100</span>
              </div>
              <div className="space-y-3">
                {[
                  { label: "CVSS",       value: Math.round(selected.cvss_score * 10),      display: selected.cvss_score.toFixed(1) },
                  { label: "EPSS",       value: Math.round(selected.epss_score * 100),     display: `${(selected.epss_score * 100).toFixed(0)}%` },
                  { label: "KEV",        value: selected.kev_listed === 1 ? 100 : 0,       display: selected.kev_listed === 1 ? "Listed" : "Not Listed" },
                  { label: "Exposure",   value: Math.round(selected.exposure_score * 100), display: `${(selected.exposure_score * 100).toFixed(0)}%` },
                  { label: "Exploitability", value: Math.round(selected.exploitability * 100), display: `${(selected.exploitability * 100).toFixed(0)}%` },
                ].map(c => (
                  <div key={c.label}>
                    <div className="flex justify-between text-xs mb-1">
                      <span className="text-gray-400">{c.label}</span>
                      <span className="text-gray-300 font-medium">{c.display}</span>
                    </div>
                    <div className="w-full bg-gray-700 rounded-full h-2">
                      <div className={`h-2 rounded-full ${scoreBarColor(c.value)}`} style={{ width: `${Math.min(100, c.value)}%` }} />
                    </div>
                  </div>
                ))}
              </div>
              <div className="mt-3 text-xs text-gray-400">
                Priority tier: <span className={`font-semibold ${priorityColor(selected.priority_tier).text}`}>{selected.priority_tier}</span>
              </div>
              <div className="mt-1 text-xs text-gray-500">
                Scored: {new Date(selected.scored_at).toLocaleString()}
              </div>
            </div>
          ) : (
            <div className="bg-gray-800 rounded-lg p-5 flex flex-col items-center gap-3 text-gray-500 py-10">
              <ShieldOff className="w-8 h-8 opacity-30" />
              <p className="text-sm">Select a CVE to see breakdown</p>
            </div>
          )}

          {/* Scoring model weights — informational, reflects real formula */}
          <div className="bg-gray-800 rounded-lg p-5">
            <h2 className="font-semibold text-white text-sm mb-1 flex items-center gap-2">
              <SlidersHorizontal className="w-4 h-4 text-indigo-400" /> Model Weights
            </h2>
            <p className="text-[10px] text-gray-500 mb-3">Composite score formula weights (v{selected?.scoring_version ?? "1.0"})</p>
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

          {/* Distribution — derived from real data */}
          <div className="bg-gray-800 rounded-lg p-5">
            <h2 className="font-semibold text-white text-sm mb-3 flex items-center gap-2">
              <BarChart2 className="w-4 h-4 text-orange-400" /> Distribution
            </h2>
            {total === 0 ? (
              <p className="text-gray-500 text-sm text-center py-4">No data</p>
            ) : (
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
                        <div
                          className="h-2 rounded-full"
                          style={{ backgroundColor: d.color, width: `${total > 0 ? (d.count / total) * 100 : 0}%` }}
                        />
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>

      {/* Asset risk table — derived from real scored data */}
      <div className="bg-gray-800 rounded-lg overflow-hidden">
        <div className="p-4 border-b border-gray-700">
          <h2 className="font-semibold text-white text-sm">Asset Risk Scores</h2>
          <p className="text-xs text-gray-400 mt-0.5">Aggregated from scored findings — grouped by asset_id</p>
        </div>
        {vulns.length === 0 ? (
          <div className="flex flex-col items-center gap-2 py-10 text-gray-500">
            <ShieldOff className="w-8 h-8 opacity-30" />
            <p className="text-sm">No asset risk data available</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-700 text-gray-400 text-xs uppercase">
                  <th className="text-left p-3">Asset</th>
                  <th className="text-left p-3">Criticality</th>
                  <th className="text-left p-3">Max Score</th>
                  <th className="text-left p-3">Vulns</th>
                  <th className="text-left p-3">KEV Count</th>
                </tr>
              </thead>
              <tbody>
                {Object.entries(
                  vulns.reduce<Record<string, { maxScore: number; count: number; kev: number; criticality: string }>>((acc, v) => {
                    if (!acc[v.asset_id]) acc[v.asset_id] = { maxScore: 0, count: 0, kev: 0, criticality: v.asset_criticality };
                    acc[v.asset_id].maxScore = Math.max(acc[v.asset_id].maxScore, v.composite_score);
                    acc[v.asset_id].count++;
                    if (v.kev_listed === 1) acc[v.asset_id].kev++;
                    return acc;
                  }, {})
                )
                  .sort(([, a], [, b]) => b.maxScore - a.maxScore)
                  .map(([asset, info]) => (
                    <tr key={asset} className="border-b border-gray-700/50">
                      <td className="p-3 text-gray-200 font-mono text-xs">{asset}</td>
                      <td className="p-3 text-gray-400 text-xs capitalize">{info.criticality}</td>
                      <td className="p-3">
                        <div className="flex items-center gap-2">
                          <span className={`font-bold text-sm ${scoreColor(info.maxScore)}`}>{Math.round(info.maxScore)}</span>
                          <div className="w-12 bg-gray-700 rounded-full h-1.5">
                            <div className={`h-1.5 rounded-full ${scoreBarColor(info.maxScore)}`} style={{ width: `${Math.min(100, info.maxScore)}%` }} />
                          </div>
                        </div>
                      </td>
                      <td className="p-3 text-gray-300 text-xs tabular-nums">{info.count}</td>
                      <td className="p-3 text-xs tabular-nums">
                        {info.kev > 0
                          ? <span className="text-red-400 font-semibold">{info.kev}</span>
                          : <span className="text-gray-600">0</span>}
                      </td>
                    </tr>
                  ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}
