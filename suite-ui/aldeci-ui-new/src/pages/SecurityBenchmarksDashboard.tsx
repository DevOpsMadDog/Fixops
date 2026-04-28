// REPLACED by FindingsExplorerView config 2026-04-27
// Wave 4 Pattern-2 mechanical collapse (UX Phase 3)
/**
 * Security Benchmarks Dashboard - Live API
 * Route: /security-benchmarks
 * API: GET /api/v1/security-benchmarks/metrics
 */
import { useState, useEffect } from "react";
import { TrendingUp, TrendingDown, Minus, RefreshCw, Target } from "lucide-react";
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

function performanceBadge(p: string) {
  return p === "above-average" ? "bg-green-500/20 text-green-300"
    : p === "average" ? "bg-blue-500/20 text-blue-300"
    : p === "below-average" ? "bg-amber-500/20 text-amber-300"
    : "bg-red-500/20 text-red-300";
}
function sourceBadge(s: string) {
  const map: Record<string, string> = {
    "Gartner": "bg-purple-500/20 text-purple-300",
    "Verizon-DBIR": "bg-red-500/20 text-red-300",
    "SANS": "bg-orange-500/20 text-orange-300",
    "NIST": "bg-blue-500/20 text-blue-300",
    "Mandiant": "bg-cyan-500/20 text-cyan-300",
    "IBM": "bg-indigo-500/20 text-indigo-300",
  };
  return map[s] ?? "bg-gray-500/20 text-gray-300";
}

function percentilePosition(m: any) {
  const our = m.our_value ?? 0, p25 = m.p25 ?? 0, p90 = m.p90 ?? 100;
  const lower = m.lower_is_better;
  if (lower) {
    const range = Math.abs(p25 - p90) || 1;
    return Math.min(100, Math.max(0, ((p25 - our) / range) * 100));
  }
  const range = Math.abs(p90 - p25) || 1;
  return Math.min(100, Math.max(0, ((our - p25) / range) * 100));
}

function Sparkline({ values }: { values: number[] }) {
  if (!values.length) return null;
  const min = Math.min(...values);
  const max = Math.max(...values);
  const range = (max - min) || 1;
  const pts = values.map((v, i) => ({ x: (i / (values.length - 1 || 1)) * 60, y: 24 - ((v - min) / range) * 24 }));
  const path = pts.map((p, i) => `${i === 0 ? "M" : "L"}${p.x},${p.y}`).join(" ");
  return <svg width="60" height="24" className="flex-shrink-0"><path d={path} fill="none" stroke="#6366f1" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" /></svg>;
}

function GapToMedian({ m }: { m: any }) {
  const gap = m.lower_is_better ? (m.our_value ?? 0) - (m.p50 ?? 0) : (m.p50 ?? 0) - (m.our_value ?? 0);
  if (gap < 0) return <span className="text-green-400 text-xs flex items-center gap-1"><TrendingUp className="w-3 h-3" />{Math.abs(gap).toFixed(1)}{m.unit ?? ""} ahead</span>;
  if (gap === 0) return <span className="text-blue-400 text-xs flex items-center gap-1"><Minus className="w-3 h-3" />At median</span>;
  return <span className="text-amber-400 text-xs flex items-center gap-1"><TrendingDown className="w-3 h-3" />{gap.toFixed(1)}{m.unit ?? ""} behind</span>;
}

export default function SecurityBenchmarksDashboard() {
  const [metrics, setMetrics] = useState<any[]>([]);
  const [sectorFilter, setSectorFilter] = useState("all");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const v = await apiFetch<any>("/api/v1/security-benchmarks/metrics");
      const arr = Array.isArray(v) ? v : (v.metrics ?? v.items ?? []);
      setMetrics(arr);
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  const sectors = Array.from(new Set(metrics.flatMap(m => Array.isArray(m.sectors) ? m.sectors : []))).filter(Boolean);
  const filtered = sectorFilter === "all" ? metrics : metrics.filter(m => Array.isArray(m.sectors) && (m.sectors.includes(sectorFilter) || m.sectors.includes("all")));
  const overallPct = filtered.length ? Math.round(filtered.reduce((s, m) => s + percentilePosition(m), 0) / filtered.length) : 0;
  const perfCounts = {
    "above-average": filtered.filter(m => m.performance === "above-average").length,
    "average": filtered.filter(m => m.performance === "average").length,
    "below-average": filtered.filter(m => m.performance === "below-average").length,
    "lagging": filtered.filter(m => m.performance === "lagging").length,
  };

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2"><Target className="w-6 h-6 text-purple-400" /> Security Benchmarks</h1>
          <p className="text-gray-400 text-sm mt-1">Industry percentile comparison</p>
        </div>
        <button onClick={load} className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm"><RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} /> Refresh</button>
      </div>

      {loading ? <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-purple-500"></div></div>
        : error ? <ErrorState message={error} onRetry={load} />
        : metrics.length === 0 ? <EmptyState icon={Target} title="No benchmark metrics" description="Industry benchmark metrics will appear once configured." />
        : <>
          <div className="bg-gradient-to-r from-purple-900/40 to-indigo-900/40 border border-purple-700/30 rounded-lg p-5">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-gray-400 text-xs mb-1">Overall Security Percentile</div>
                <div className="text-5xl font-bold text-purple-300">{overallPct}<span className="text-2xl text-gray-400">th</span></div>
                <div className="text-gray-400 text-xs mt-1">vs industry peers · {filtered.length} metrics tracked</div>
              </div>
              <div className="grid grid-cols-2 gap-3 text-center">
                {Object.entries(perfCounts).map(([k, v]) => (
                  <div key={k}>
                    <div className={`text-xl font-bold ${k === "above-average" ? "text-green-400" : k === "average" ? "text-blue-400" : k === "below-average" ? "text-amber-400" : "text-red-400"}`}>{v}</div>
                    <div className="text-gray-500 text-xs capitalize">{k.replace("-", " ")}</div>
                  </div>
                ))}
              </div>
            </div>
            <div className="mt-4">
              <div className="relative w-full bg-gray-700 rounded-full h-3"><div className="absolute inset-y-0 left-0 rounded-full bg-gradient-to-r from-red-500 via-yellow-400 to-green-500" style={{ width: "100%", opacity: 0.3 }} /><div className="absolute top-1/2 -translate-y-1/2 w-3 h-3 rounded-full bg-white border-2 border-purple-400" style={{ left: `calc(${overallPct}% - 6px)` }} /></div>
            </div>
          </div>

          {sectors.length > 0 && <div className="flex gap-2 flex-wrap">{["all", ...sectors].map(s => (
            <button key={s} onClick={() => setSectorFilter(s)} className={`px-3 py-1 rounded-full text-xs font-medium capitalize ${sectorFilter === s ? "bg-purple-600 text-white" : "bg-gray-700 text-gray-300 hover:bg-gray-600"}`}>{s === "all" ? "All Sectors" : s}</button>
          ))}</div>}

          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">{filtered.map(m => {
            const pct = percentilePosition(m);
            return (
              <div key={m.id} className="bg-gray-800 rounded-lg p-4">
                <div className="flex items-start justify-between mb-2">
                  <div className="flex-1 min-w-0">
                    <div className="font-medium text-white text-sm truncate">{m.metric_name ?? m.name}</div>
                    <div className="text-gray-500 text-xs mt-0.5">{m.category}</div>
                  </div>
                  <div className="flex flex-col items-end gap-1 ml-2">
                    <span className={`px-2 py-0.5 rounded-full text-xs font-medium capitalize ${performanceBadge(m.performance)}`}>{(m.performance ?? "").replace("-", " ")}</span>
                    {m.source && <span className={`px-2 py-0.5 rounded-full text-xs ${sourceBadge(m.source)}`}>{m.source}</span>}
                  </div>
                </div>
                <div className="flex items-end gap-1 mb-3"><span className="text-2xl font-bold text-white">{m.our_value}</span><span className="text-gray-400 text-sm mb-0.5">{m.unit}</span></div>
                <div className="mb-2">
                  <div className="flex justify-between text-xs text-gray-500 mb-1"><span>p25: {m.p25}</span><span>p50: {m.p50}</span><span>p75: {m.p75}</span><span>p90: {m.p90}</span></div>
                  <div className="relative w-full bg-gray-700 rounded-full h-2"><div className="absolute inset-y-0 left-0 rounded-full bg-gradient-to-r from-red-500 via-yellow-400 to-green-500" style={{ width: "100%", opacity: 0.4 }} /><div className="absolute top-1/2 -translate-y-1/2 w-2.5 h-2.5 rounded-full bg-white border-2 border-indigo-400" style={{ left: `calc(${pct}% - 5px)` }} /></div>
                </div>
                <div className="flex items-center justify-between mt-2"><GapToMedian m={m} /><Sparkline values={Array.isArray(m.trend) ? m.trend : []} /></div>
              </div>
            );
          })}</div>
        </>}
    </div>
  );
}
