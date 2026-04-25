/**
 * Posture Trends Dashboard - Live API
 * Route: /posture-trends
 * API: GET /api/v1/posture-trends/trends
 */

import { useState, useEffect } from "react";
import { TrendingUp, RefreshCw } from "lucide-react";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";

async function apiFetch<T>(path: string): Promise<T> {
  const orgId = getStoredOrgId() || "verify-test";
  const url = buildApiUrl(path, { org_id: orgId });
  const res = await fetch(url, { headers: { "X-API-Key": getStoredAuthToken(), "X-Org-ID": orgId } });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

type Velocity = "improving" | "declining" | "stable";

const categoryLabels: Record<string, string> = {
  vulnerability_management: "Vuln Mgmt",
  identity_access: "Identity",
  cloud_security: "Cloud",
  endpoint_protection: "Endpoint",
  network_security: "Network",
  data_security: "Data",
  incident_response: "IR",
  compliance: "Compliance",
};

function velocityIndicator(v: Velocity, higherIsBetter: boolean): { symbol: string; color: string } {
  if (v === "stable") return { symbol: "→", color: "text-gray-400" };
  const improving = (v === "improving" && higherIsBetter) || (v === "declining" && !higherIsBetter);
  if (improving) return { symbol: "↑", color: "text-green-400" };
  return { symbol: "↓", color: "text-red-400" };
}

function sparklinePath(points: number[]): string {
  if (points.length < 2) return "";
  const min = Math.min(...points);
  const max = Math.max(...points);
  const range = max - min || 1;
  const W = 80, H = 28, step = W / (points.length - 1);
  return points.map((v, i) => `${i === 0 ? "M" : "L"} ${(i * step).toFixed(1)} ${(H - ((v - min) / range) * H).toFixed(1)}`).join(" ");
}

function sparklineColor(velocity: Velocity, higherIsBetter: boolean): string {
  const good = (velocity === "improving" && higherIsBetter) || (velocity === "declining" && !higherIsBetter);
  const bad = (velocity === "declining" && higherIsBetter) || (velocity === "improving" && !higherIsBetter);
  if (good) return "#22c55e";
  if (bad) return "#ef4444";
  return "#6b7280";
}

export default function PostureTrendsDashboard() {
  const [trends, setTrends] = useState<any[]>([]);
  const [targets, setTargets] = useState<any[]>([]);
  const [filterCategory, setFilterCategory] = useState<string>("all");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const [trRes, tgRes] = await Promise.allSettled([
        apiFetch<any>("/api/v1/posture-trends/trends"),
        apiFetch<any>("/api/v1/posture-trends/targets"),
      ]);
      if (trRes.status === "fulfilled") {
        const v = trRes.value;
        setTrends(Array.isArray(v) ? v : (v.trends ?? v.items ?? []));
      }
      if (tgRes.status === "fulfilled") {
        const v = tgRes.value;
        setTargets(Array.isArray(v) ? v : (v.targets ?? v.items ?? []));
      }
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  const filteredTrends = filterCategory === "all" ? trends : trends.filter(t => t.category === filterCategory);
  const stagnating = trends.filter(t => t.stagnating);
  const improving = trends.filter(t => velocityIndicator(t.velocity, t.higher_is_better).symbol === "↑");
  const declining = trends.filter(t => velocityIndicator(t.velocity, t.higher_is_better).symbol === "↓");
  const fastestImproving = improving.reduce<any>((best, t) => !best || Math.abs(t.change_pct) > Math.abs(best.change_pct) ? t : best, null);
  const fastestDeclining = declining.reduce<any>((best, t) => !best || Math.abs(t.change_pct) > Math.abs(best.change_pct) ? t : best, null);
  const categories = [...new Set(trends.map(t => t.category))];

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2"><TrendingUp className="w-6 h-6 text-teal-400" /> Posture Trends</h1>
          <p className="text-gray-400 mt-1">Security posture velocity, metric trajectories, and target progress</p>
        </div>
        <button onClick={load} className="flex items-center gap-2 px-4 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm"><RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} /> Refresh</button>
      </div>

      {loading ? <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-teal-500"></div></div>
        : error ? <ErrorState message={error} onRetry={load} />
        : trends.length === 0 && targets.length === 0 ? <EmptyState icon={TrendingUp} title="No posture trends" description="No posture metric trends or targets recorded yet." />
        : <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              { label: "Improving", value: improving.length, color: "text-green-400" },
              { label: "Declining", value: declining.length, color: "text-red-400" },
              { label: "Stable", value: trends.filter(t => t.velocity === "stable").length, color: "text-gray-400" },
              { label: "Stagnating", value: stagnating.length, color: "text-amber-400" },
            ].map(s => (
              <div key={s.label} className="bg-gray-800 rounded-lg p-5">
                <p className="text-gray-400 text-sm">{s.label}</p>
                <p className={`text-3xl font-bold mt-1 ${s.color}`}>{s.value}</p>
                <p className="text-gray-500 text-xs mt-1">metrics</p>
              </div>
            ))}
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {fastestImproving && (
              <div className="bg-green-900/20 border border-green-700 rounded-lg p-4">
                <p className="text-green-400 text-xs font-semibold uppercase tracking-wide mb-1">Fastest Improving</p>
                <p className="text-white font-medium">{fastestImproving.metric_name}</p>
                <p className="text-green-400 text-sm">+{Math.abs(fastestImproving.change_pct).toFixed(1)}% change</p>
              </div>
            )}
            {fastestDeclining && (
              <div className="bg-red-900/20 border border-red-700 rounded-lg p-4">
                <p className="text-red-400 text-xs font-semibold uppercase tracking-wide mb-1">Fastest Declining</p>
                <p className="text-white font-medium">{fastestDeclining.metric_name}</p>
                <p className="text-red-400 text-sm">{fastestDeclining.change_pct.toFixed(1)}% change</p>
              </div>
            )}
          </div>

          {stagnating.length > 0 && (
            <div className="bg-amber-900/20 border border-amber-700 rounded-lg p-4">
              <p className="text-amber-400 font-semibold text-sm mb-2">Stagnating Metrics — No meaningful change detected</p>
              <div className="flex flex-wrap gap-2">{stagnating.map(m => (
                <span key={m.id} className="bg-amber-800/40 text-amber-200 px-2 py-1 rounded text-xs">{m.metric_name} ({m.current_value} {m.unit})</span>
              ))}</div>
            </div>
          )}

          {categories.length > 0 && <div className="flex gap-2 flex-wrap">
            <button onClick={() => setFilterCategory("all")} className={`px-3 py-1.5 rounded text-xs font-medium ${filterCategory === "all" ? "bg-blue-600 text-white" : "bg-gray-800 text-gray-400 hover:text-white"}`}>All</button>
            {categories.map(cat => (
              <button key={cat} onClick={() => setFilterCategory(cat)} className={`px-3 py-1.5 rounded text-xs font-medium ${filterCategory === cat ? "bg-blue-600 text-white" : "bg-gray-800 text-gray-400 hover:text-white"}`}>{categoryLabels[cat] ?? cat}</button>
            ))}
          </div>}

          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">{filteredTrends.map(metric => {
            const ind = velocityIndicator(metric.velocity, metric.higher_is_better);
            const sColor = sparklineColor(metric.velocity, metric.higher_is_better);
            const datapoints: number[] = Array.isArray(metric.datapoints) ? metric.datapoints : [];
            const path = sparklinePath(datapoints);
            return (
              <div key={metric.id} className="bg-gray-800 rounded-lg p-5 space-y-3">
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <p className="text-gray-500 text-xs">{categoryLabels[metric.category] ?? metric.category}</p>
                    <p className="text-white text-sm font-semibold mt-0.5">{metric.metric_name}</p>
                  </div>
                  <span className={`text-2xl font-bold ${ind.color}`}>{ind.symbol}</span>
                </div>
                <div className="flex items-baseline gap-2">
                  <span className="text-2xl font-bold text-white">{metric.current_value}</span>
                  <span className="text-gray-400 text-sm">{metric.unit}</span>
                  <span className={`text-xs font-medium px-1.5 py-0.5 rounded ${ind.symbol === "↑" ? "bg-green-900 text-green-300" : ind.symbol === "↓" ? "bg-red-900 text-red-300" : "bg-gray-700 text-gray-300"}`}>{(metric.change_pct ?? 0) > 0 ? "+" : ""}{(metric.change_pct ?? 0).toFixed(1)}%</span>
                </div>
                {datapoints.length >= 2 && <svg width="80" height="28" className="overflow-visible">
                  <path d={path} fill="none" stroke={sColor} strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" />
                </svg>}
                <div className="flex items-center justify-between text-xs text-gray-500">
                  <span>Confidence: <span className="text-gray-300 font-medium">{metric.confidence ?? 0}%</span></span>
                  <span>Prev: {metric.previous_value} {metric.unit}</span>
                </div>
              </div>
            );
          })}</div>

          {targets.length > 0 && <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold text-white mb-4">Targets Progress</h2>
            <div className="overflow-x-auto"><table className="w-full text-sm">
              <thead><tr className="text-gray-500 text-xs uppercase border-b border-gray-700"><th className="text-left pb-2 pr-4">Metric</th><th className="text-left pb-2 pr-4">Current</th><th className="text-left pb-2 pr-4">Target</th><th className="text-left pb-2 pr-4">Gap</th><th className="text-left pb-2 pr-4">ETA</th><th className="text-left pb-2">Status</th></tr></thead>
              <tbody className="divide-y divide-gray-700/50">{targets.map(tp => (
                <tr key={tp.id} className="hover:bg-gray-700/30">
                  <td className="py-2.5 pr-4 text-gray-200 font-medium">{tp.metric_name}</td>
                  <td className="py-2.5 pr-4 text-white font-semibold">{tp.current} <span className="text-gray-500 text-xs font-normal">{tp.unit}</span></td>
                  <td className="py-2.5 pr-4 text-gray-400">{tp.target} <span className="text-gray-600 text-xs">{tp.unit}</span></td>
                  <td className="py-2.5 pr-4 text-amber-400">{tp.gap} {tp.unit}</td>
                  <td className="py-2.5 pr-4 text-gray-400">{tp.eta_days}d</td>
                  <td className="py-2.5"><span className={`px-2 py-0.5 rounded text-xs font-medium ${tp.on_track ? "bg-green-700 text-green-100" : "bg-red-700 text-red-100"}`}>{tp.on_track ? "On Track" : "At Risk"}</span></td>
                </tr>
              ))}</tbody>
            </table></div>
          </div>}
        </>}
    </div>
  );
}
