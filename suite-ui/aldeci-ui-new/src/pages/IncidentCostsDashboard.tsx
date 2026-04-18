/**
 * Incident Costs Dashboard
 *
 * Track financial cost of security incidents: total cost, breakdown by
 * category, benchmark comparison, most expensive incident highlight.
 *
 * Route: /incident-costs
 */

import { useState, useEffect } from "react";
import { DollarSign, TrendingUp, TrendingDown, RefreshCw, AlertCircle, BarChart2 } from "lucide-react";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY = (typeof window !== "undefined" && window.localStorage.getItem("aldeci_api_key")) || import.meta.env.VITE_API_KEY || "demo-key";
const ORG_ID = "aldeci-demo";
async function apiFetch(path: string) {
  const r = await fetch(`${API_BASE}${path}`, { headers: { "X-API-Key": API_KEY, "Content-Type": "application/json" } });
  if (!r.ok) throw new Error(`${r.status}`);
  return r.json();
}

// == Types =====================================================================

type IncidentType = "ransomware" | "data-breach" | "insider-threat" | "ddos" | "supply-chain" | "phishing" | "account-compromise";
type Severity = "critical" | "high" | "medium" | "low";
type BenchmarkStatus = "above" | "within-range" | "below";

interface IncidentCost {
  id: string;
  incident_name: string;
  incident_type: IncidentType;
  severity: Severity;
  estimated_cost: number;
  actual_cost: number | null;
  duration_hours: number;
  date: string;
  status: "closed" | "open" | "investigating";
  categories: Record<string, number>; // cost breakdown
}

interface CategoryBreakdown {
  category: string;
  total: number;
  color: string;
}

// == Mock data =================================================================

const MOCK_INCIDENTS: IncidentCost[] = [
  {
    id: "ic-001", incident_name: "RansomHub Ransomware Attack",    incident_type: "ransomware",         severity: "critical",
    estimated_cost: 2800000, actual_cost: 3150000, duration_hours: 312,
    date: "2026-02-14", status: "closed",
    categories: { "Downtime": 1200000, "Forensics": 350000, "Legal": 480000, "Recovery": 620000, "Regulatory Fines": 500000 }
  },
  {
    id: "ic-002", incident_name: "Customer PII Data Breach",       incident_type: "data-breach",        severity: "critical",
    estimated_cost: 1500000, actual_cost: 1720000, duration_hours: 168,
    date: "2026-01-22", status: "closed",
    categories: { "Notification": 180000, "Legal": 540000, "Regulatory Fines": 650000, "PR": 200000, "Forensics": 150000 }
  },
  {
    id: "ic-003", incident_name: "Finance Insider Data Exfil",     incident_type: "insider-threat",     severity: "high",
    estimated_cost: 420000, actual_cost: 390000, duration_hours: 96,
    date: "2026-03-08", status: "closed",
    categories: { "Investigation": 120000, "Legal": 180000, "Recovery": 60000, "Monitoring": 30000 }
  },
  {
    id: "ic-004", incident_name: "DDoS on API Gateway",            incident_type: "ddos",               severity: "high",
    estimated_cost: 85000, actual_cost: 92000, duration_hours: 18,
    date: "2026-03-19", status: "closed",
    categories: { "Downtime": 60000, "Mitigation": 22000, "PR": 10000 }
  },
  {
    id: "ic-005", incident_name: "Supply Chain Backdoor (npm)",    incident_type: "supply-chain",       severity: "critical",
    estimated_cost: 380000, actual_cost: null, duration_hours: 72,
    date: "2026-04-11", status: "investigating",
    categories: { "Forensics": 80000, "Recovery": 150000, "Legal": 100000, "Downtime": 50000 }
  },
  {
    id: "ic-006", incident_name: "CEO Spear-phishing Compromise",  incident_type: "phishing",           severity: "high",
    estimated_cost: 210000, actual_cost: 185000, duration_hours: 48,
    date: "2026-02-28", status: "closed",
    categories: { "Forensics": 45000, "Response": 80000, "Legal": 40000, "PR": 20000 }
  },
  {
    id: "ic-007", incident_name: "Privileged Account Takeover",    incident_type: "account-compromise", severity: "medium",
    estimated_cost: 65000, actual_cost: 58000, duration_hours: 24,
    date: "2026-04-03", status: "closed",
    categories: { "Forensics": 25000, "Recovery": 20000, "Monitoring": 13000 }
  },
];

// Benchmark data (vs industry averages)
const BENCHMARKS: Record<IncidentType, { industry_avg: number; status: BenchmarkStatus }> = {
  "ransomware":         { industry_avg: 4500000, status: "below" },
  "data-breach":        { industry_avg: 4450000, status: "below" },
  "insider-threat":     { industry_avg: 680000,  status: "below" },
  "ddos":               { industry_avg: 50000,   status: "above" },
  "supply-chain":       { industry_avg: 440000,  status: "within-range" },
  "phishing":           { industry_avg: 135000,  status: "above" },
  "account-compromise": { industry_avg: 74000,   status: "below" },
};

// == Helpers ===================================================================

function fmt(n: number): string {
  if (n >= 1000000) return `$${(n / 1000000).toFixed(2)}M`;
  if (n >= 1000)    return `$${(n / 1000).toFixed(0)}K`;
  return `$${n}`;
}

function severityColor(s: Severity): string {
  return s === "critical" ? "bg-red-500/20 text-red-300" : s === "high" ? "bg-orange-500/20 text-orange-300" : s === "medium" ? "bg-yellow-500/20 text-yellow-300" : "bg-gray-500/20 text-gray-300";
}

function typeBadge(t: IncidentType): string {
  const map: Record<IncidentType, string> = {
    "ransomware":         "bg-red-500/20 text-red-300",
    "data-breach":        "bg-purple-500/20 text-purple-300",
    "insider-threat":     "bg-pink-500/20 text-pink-300",
    "ddos":               "bg-blue-500/20 text-blue-300",
    "supply-chain":       "bg-amber-500/20 text-amber-300",
    "phishing":           "bg-orange-500/20 text-orange-300",
    "account-compromise": "bg-cyan-500/20 text-cyan-300",
  };
  return map[t];
}

function benchmarkBadge(s: BenchmarkStatus): { cls: string; label: string } {
  return s === "below"        ? { cls: "bg-green-500/20 text-green-300",  label: "Below Avg" }
       : s === "within-range" ? { cls: "bg-blue-500/20 text-blue-300",   label: "Within Range" }
       :                        { cls: "bg-red-500/20 text-red-300",      label: "Above Avg" };
}

function statusBadge(s: string): string {
  return s === "closed" ? "bg-gray-500/20 text-gray-400" : s === "open" ? "bg-red-500/20 text-red-300" : "bg-blue-500/20 text-blue-300";
}

// Category aggregation across all incidents
const CAT_COLORS = ["#6366f1", "#f97316", "#ef4444", "#eab308", "#22c55e", "#06b6d4", "#a855f7", "#ec4899", "#14b8a6", "#f43f5e"];

function buildCategoryBreakdown(): CategoryBreakdown[] {
  const acc: Record<string, number> = {};
  MOCK_INCIDENTS.forEach(inc => {
    Object.entries(inc.categories).forEach(([cat, val]) => {
      acc[cat] = (acc[cat] ?? 0) + val;
    });
  });
  return Object.entries(acc)
    .sort((a, b) => b[1] - a[1])
    .map(([cat, total], i) => ({ category: cat, total, color: CAT_COLORS[i % CAT_COLORS.length] }));
}

const CATEGORY_BREAKDOWN = buildCategoryBreakdown();
const MAX_CAT = CATEGORY_BREAKDOWN[0]?.total ?? 1;

// == Component =================================================================

export default function IncidentCostsDashboard() {
  const [selectedId, setSelectedId] = useState<string | null>("ic-001");

  const [fetchError, setFetchError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);

  const loadData = () => {
    setFetchError(null);
    apiFetch(`/api/v1/incident-costs/costs?org_id=${ORG_ID}`).catch((err) => {
      setFetchError(err instanceof Error ? err.message : "Failed to load incident costs data");
    });
  };

  useEffect(() => {
    loadData();}, []);

  const selected = MOCK_INCIDENTS.find(i => i.id === selectedId) ?? null;

  const totalActual  = MOCK_INCIDENTS.reduce((s, i) => s + (i.actual_cost ?? i.estimated_cost), 0);
  const totalEstim   = MOCK_INCIDENTS.reduce((s, i) => s + i.estimated_cost, 0);
  const mostExpensive = [...MOCK_INCIDENTS].sort((a, b) => (b.actual_cost ?? b.estimated_cost) - (a.actual_cost ?? a.estimated_cost))[0];

  const byType: Record<string, number> = {};
  MOCK_INCIDENTS.forEach(i => {
    byType[i.incident_type] = (byType[i.incident_type] ?? 0) + (i.actual_cost ?? i.estimated_cost);
  });

  if (loading) return (
    <div className="space-y-4 p-6">
      {[1, 2, 3].map((i) => (
        <div key={i} className="h-24 rounded-lg bg-zinc-800/50 animate-pulse" />
      ))}
    </div>
  );

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <DollarSign className="w-6 h-6 text-green-400" />
            Incident Costs
          </h1>
          <p className="text-gray-400 text-sm mt-1">Financial impact tracking = YTD 2026</p>
        </div>
        <button className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm transition-colors">
          <RefreshCw className="w-4 h-4" /> Refresh
        </button>
      </div>

      {/* Fetch Error Banner */}
      {fetchError && (
        <div className="bg-red-500/10 border border-red-500/30 text-red-300 px-4 py-3 rounded-lg flex items-center justify-between" role="status" aria-live="polite">
          <span className="text-sm">Failed to load live data: {fetchError}</span>
          <button onClick={loadData} className="ml-4 px-3 py-1 bg-red-500/20 hover:bg-red-500/30 text-red-300 text-xs rounded transition-colors" aria-label="Refresh data">Retry</button>
        </div>
      )}

      {/* KPIs */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {[
          { label: "Total Spent (Actual)",  value: fmt(totalActual),          color: "text-red-400" },
          { label: "Total Estimated",       value: fmt(totalEstim),           color: "text-orange-400" },
          { label: "Incidents Tracked",     value: MOCK_INCIDENTS.length,     color: "text-white" },
          { label: "Avg Cost / Incident",   value: fmt(Math.round(totalActual / MOCK_INCIDENTS.length)), color: "text-amber-400" },
        ].map(k => (
          <div key={k.label} className="bg-gray-800 rounded-lg p-4 text-center">
            <div className={`text-2xl font-bold ${k.color}`}>{k.value}</div>
            <div className="text-gray-400 text-xs mt-1">{k.label}</div>
          </div>
        ))}
      </div>

      {/* Most expensive highlight */}
      <div className="bg-red-900/20 border border-red-700/30 rounded-lg p-4 flex items-center gap-4" role="status" aria-live="polite">
        <AlertCircle className="w-6 h-6 text-red-400 flex-shrink-0" />
        <div className="flex-1 min-w-0">
          <div className="text-red-300 font-semibold text-sm" role="status" aria-live="polite">{mostExpensive.incident_name}</div>
          <div className="text-gray-400 text-xs mt-0.5">Most expensive incident YTD</div>
        </div>
        <div className="text-right flex-shrink-0">
          <div className="text-red-400 font-bold text-lg" role="status" aria-live="polite">{fmt(mostExpensive.actual_cost ?? mostExpensive.estimated_cost)}</div>
          <div className="text-gray-500 text-xs">{mostExpensive.duration_hours}h duration</div>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Incident cost table */}
        <div className="xl:col-span-2 bg-gray-800 rounded-lg overflow-hidden">
          <div className="p-4 border-b border-gray-700">
            <h2 className="font-semibold text-white">Cost Tracker</h2>
          </div>
          <div className="overflow-x-auto">
            <table role="table" className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-700 text-gray-400 text-xs uppercase">
                  <th className="text-left p-3">Incident</th>
                  <th className="text-left p-3">Type</th>
                  <th className="text-left p-3">Severity</th>
                  <th className="text-left p-3">Estimated</th>
                  <th className="text-left p-3">Actual</th>
                  <th className="text-left p-3">Hours</th>
                  <th className="text-left p-3">Status</th>
                </tr>
              </thead>
              <tbody>
                {MOCK_INCIDENTS.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  MOCK_INCIDENTS.map(inc => {
                  const actual = inc.actual_cost ?? inc.estimated_cost;
                  const over = inc.actual_cost !== null && inc.actual_cost > inc.estimated_cost;
                  return (
                    <tr
                      key={inc.id}
                      onClick={() => setSelectedId(inc.id)}
                      className={`border-b border-gray-700/50 cursor-pointer hover:bg-gray-700/40 transition-colors ${selectedId === inc.id ? "bg-gray-700/60" : ""}`}
                    >
                      <td className="p-3 text-gray-200 max-w-[160px] truncate text-xs">{inc.incident_name}</td>
                      <td className="p-3"><span className={`text-xs px-1.5 py-0.5 rounded-full ${typeBadge(inc.incident_type)}`}>{inc.incident_type}</span></td>
                      <td className="p-3"><span className={`text-xs px-1.5 py-0.5 rounded-full capitalize ${severityColor(inc.severity)}`}>{inc.severity}</span></td>
                      <td className="p-3 text-gray-400 text-xs">{fmt(inc.estimated_cost)}</td>
                      <td className={`p-3 text-xs font-semibold ${over ? "text-red-400" : "text-green-400"}`}>
                        {inc.actual_cost !== null ? fmt(actual) : <span className="text-gray-500">Pending</span>}
                        {over && <TrendingUp className="w-3 h-3 inline ml-1" />}
                        {!over && inc.actual_cost !== null && <TrendingDown className="w-3 h-3 inline ml-1" />}
                      </td>
                      <td className="p-3 text-gray-400 text-xs">{inc.duration_hours}h</td>
                      <td className="p-3"><span className={`text-xs px-1.5 py-0.5 rounded-full capitalize ${statusBadge(inc.status)}`}>{inc.status}</span></td>
                    </tr>
                  );
                })
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Right panels */}
        <div className="space-y-4">
          {/* Detail: estimated vs actual split bars */}
          {selected && (
            <div className="bg-gray-800 rounded-lg p-5">
              <h2 className="font-semibold text-white text-sm mb-3">{selected.incident_name}</h2>
              <div className="space-y-2 mb-4">
                {Object.entries(selected.categories).map(([cat, val]) => {
                  const pct = (val / (selected.actual_cost ?? selected.estimated_cost)) * 100;
                  return (
                    <div key={cat}>
                      <div className="flex justify-between text-xs mb-1">
                        <span className="text-gray-400">{cat}</span>
                        <span className="text-gray-300">{fmt(val)}</span>
                      </div>
                      <div className="w-full bg-gray-700 rounded-full h-1.5">
                        <div className="h-1.5 rounded-full bg-indigo-500" style={{ width: `${pct}%` }} />
                      </div>
                    </div>
                  );
                })
                )}
              </div>
              {/* Benchmark */}
              {(() => {
                const bm = BENCHMARKS[selected.incident_type];
                const badge = benchmarkBadge(bm.status);
                return (
                  <div className="border-t border-gray-700 pt-3">
                    <div className="flex justify-between items-center">
                      <span className="text-gray-400 text-xs">Industry avg: {fmt(bm.industry_avg)}</span>
                      <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${badge.cls}`}>{badge.label}</span>
                    </div>
                  </div>
                );
              })()}
            </div>
          )}

          {/* By-type breakdown */}
          <div className="bg-gray-800 rounded-lg p-5">
            <h2 className="font-semibold text-white text-sm mb-3 flex items-center gap-2">
              <BarChart2 className="w-4 h-4 text-indigo-400" /> Cost by Type
            </h2>
            <div className="space-y-3">
              {Object.entries(byType).sort((a, b) => b[1] - a[1]).map(([type, total]) => {
                const maxVal = Math.max(...Object.values(byType));
                return (
                  <div key={type}>
                    <div className="flex justify-between text-xs mb-1">
                      <span className="text-gray-300 capitalize">{type}</span>
                      <span className="text-gray-400">{fmt(total)}</span>
                    </div>
                    <div className="w-full bg-gray-700 rounded-full h-2">
                      <div className="h-2 rounded-full bg-gradient-to-r from-red-500 to-orange-400" style={{ width: `${(total / maxVal) * 100}%` }} />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>

      {/* Category breakdown stacked bars */}
      <div className="bg-gray-800 rounded-lg p-5">
        <h2 className="font-semibold text-white text-sm mb-4">Cost by Category (All Incidents)</h2>
        <div className="space-y-3">
          {CATEGORY_BREAKDOWN.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
              <p className="text-lg font-medium">No data available</p>
              <p className="text-sm">Data will appear here once available</p>
            </div>
          ) : (
            CATEGORY_BREAKDOWN.map(c => (
            <div key={c.category}>
              <div className="flex justify-between text-xs mb-1">
                <span className="text-gray-300">{c.category}</span>
                <span className="text-gray-400">{fmt(c.total)}</span>
              </div>
              <div className="w-full bg-gray-700 rounded-full h-3">
                <div className="h-3 rounded-full" style={{ backgroundColor: c.color, width: `${(c.total / MAX_CAT) * 100}%` }} />
              </div>
            </div>
          )))}
        </div>
      </div>
    </div>
  );
}
