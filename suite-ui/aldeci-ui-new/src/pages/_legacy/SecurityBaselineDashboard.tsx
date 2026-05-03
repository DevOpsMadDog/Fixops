// REPLACED by FindingsExplorerView config 2026-04-27
// Wave 4 Pattern-2 mechanical collapse (UX Phase 3)
/**
 * Security Baseline Dashboard - Live API
 * Route: /security-baselines
 * API: GET /api/v1/security-baselines/baselines
 */

import { useState, useEffect } from "react";
import { Target, CheckCircle, TrendingUp, TrendingDown, AlertTriangle, BookOpen, RefreshCw } from "lucide-react";
import { cn } from "@/lib/utils";
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

function fmt(iso: string) {
  if (!iso) return "Not published";
  try { return new Date(iso).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" }); } catch { return iso; }
}
function StatusBadge({ s }: { s: string }) {
  const cls: Record<string, string> = { active: "bg-emerald-500/20 text-emerald-400 border border-emerald-500/30", draft: "bg-gray-500/20 text-gray-400 border border-gray-500/30", deprecated: "bg-red-500/20 text-red-400 border border-red-500/30" };
  return <span className={cn("text-[10px] px-2 py-0.5 rounded-full font-medium capitalize", cls[s] ?? "bg-gray-700 text-gray-300")}>{s}</span>;
}
function TargetBadge({ t }: { t: string }) {
  const cls: Record<string, string> = { OS: "bg-blue-500/20 text-blue-400", Container: "bg-cyan-500/20 text-cyan-400", Cloud: "bg-sky-500/20 text-sky-400", Application: "bg-purple-500/20 text-purple-400", Database: "bg-orange-500/20 text-orange-400" };
  return <span className={cn("text-[10px] px-2 py-0.5 rounded font-medium", cls[t] ?? "bg-gray-700 text-gray-300")}>{t}</span>;
}
function FrameworkBadge({ f }: { f: string }) { return <span className="text-[10px] px-2 py-0.5 rounded bg-indigo-500/20 text-indigo-400 font-medium">{f}</span>; }
function CategoryBadge({ c }: { c: string }) { return <span className="text-[10px] px-2 py-0.5 rounded bg-teal-500/20 text-teal-400 font-medium">{c}</span>; }
function SeverityBadge({ s }: { s: string }) {
  const cls: Record<string, string> = { critical: "text-red-400 font-bold", high: "text-orange-400 font-semibold", medium: "text-yellow-400", low: "text-gray-400" };
  return <span className={cn("text-xs capitalize", cls[s] ?? "text-gray-400")}>{s}</span>;
}

export default function SecurityBaselineDashboard() {
  const [baselines, setBaselines] = useState<any[]>([]);
  const [controlsByBaseline, setControlsByBaseline] = useState<Record<string, any[]>>({});
  const [trend, setTrend] = useState<{ date: string; pct: number }[]>([]);
  const [drift, setDrift] = useState<any[]>([]);
  const [selectedBaseline, setSelectedBaseline] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const [blRes, trendRes, driftRes] = await Promise.allSettled([
        apiFetch<any>("/api/v1/security-baselines/baselines"),
        apiFetch<any>("/api/v1/security-baselines/trend"),
        apiFetch<any>("/api/v1/security-baselines/drift"),
      ]);
      if (blRes.status === "fulfilled") {
        const v = blRes.value;
        const arr = Array.isArray(v) ? v : (v.baselines ?? v.items ?? []);
        setBaselines(arr);
        const cmap: Record<string, any[]> = {};
        arr.forEach((bl: any) => { if (Array.isArray(bl.controls)) cmap[bl.id] = bl.controls; });
        setControlsByBaseline(cmap);
        if (arr.length && !selectedBaseline) setSelectedBaseline(arr[0]);
      }
      if (trendRes.status === "fulfilled") {
        const v = trendRes.value;
        setTrend(Array.isArray(v) ? v : (v.trend ?? v.items ?? []));
      }
      if (driftRes.status === "fulfilled") {
        const v = driftRes.value;
        setDrift(Array.isArray(v) ? v : (v.drift ?? v.items ?? []));
      }
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  const controls = selectedBaseline ? (controlsByBaseline[selectedBaseline.id] ?? []) : [];
  const maxPct = trend.length ? Math.max(...trend.map(t => t.pct), 1) : 1;

  return (
    <div className="min-h-screen bg-[#0f172a] text-white p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2"><Target className="w-6 h-6 text-emerald-400" /> Security Baselines</h1>
          <p className="text-gray-400 text-sm mt-1">Compliance benchmarks, control drift tracking, and assessment management</p>
        </div>
        <button onClick={load} className="flex items-center gap-2 bg-gray-800 hover:bg-gray-700 text-white px-4 py-2 rounded-lg text-sm font-medium"><RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} /> Refresh</button>
      </div>

      {loading ? <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-emerald-500"></div></div>
        : error ? <ErrorState message={error} onRetry={load} />
        : baselines.length === 0 ? <EmptyState icon={Target} title="No security baselines" description="Publish a baseline to start tracking compliance." />
        : <>
          <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
            <div className="bg-gray-800 rounded-lg p-6 space-y-2">
              <h2 className="text-sm font-semibold text-gray-300 uppercase tracking-wider mb-3">Baselines</h2>
              {baselines.map(bl => (
                <button key={bl.id} onClick={() => setSelectedBaseline(bl)} className={cn("w-full bg-gray-900 rounded-lg p-3 text-left hover:bg-gray-700/50 border", selectedBaseline?.id === bl.id ? "border-emerald-500/60" : "border-transparent")}>
                  <div className="flex items-center justify-between mb-1">
                    <p className="text-white text-xs font-semibold truncate">{bl.baseline_name ?? bl.name}</p>
                    <StatusBadge s={bl.status ?? "draft"} />
                  </div>
                  <div className="flex gap-2 mt-1">
                    {bl.target_type && <TargetBadge t={bl.target_type} />}
                    {bl.framework && <FrameworkBadge f={bl.framework} />}
                  </div>
                  <p className="text-gray-500 text-[10px] mt-1">{bl.control_count ?? 0} controls · {fmt(bl.published_at)}</p>
                </button>
              ))}
            </div>

            <div className="lg:col-span-3 space-y-6">
              <div className="bg-gray-800 rounded-lg p-6">
                <h2 className="text-sm font-semibold text-gray-300 uppercase tracking-wider mb-4">Controls — <span className="text-emerald-400">{selectedBaseline?.baseline_name ?? selectedBaseline?.name}</span></h2>
                {controls.length === 0 ? <p className="text-gray-500 text-sm">No controls defined for this baseline yet.</p>
                  : <div className="overflow-x-auto"><table className="w-full text-sm">
                    <thead><tr className="text-gray-500 text-xs uppercase border-b border-gray-700"><th className="text-left pb-2 pr-4">Control ID</th><th className="text-left pb-2 pr-4">Name</th><th className="text-left pb-2 pr-4">Category</th><th className="text-left pb-2 pr-4">Severity</th><th className="text-left pb-2 pr-4">Expected Value</th><th className="text-left pb-2">Auto</th></tr></thead>
                    <tbody>{controls.map((c: any) => (
                      <tr key={c.control_id} className="border-b border-gray-700/50 hover:bg-gray-700/20">
                        <td className="py-2.5 pr-4 font-mono text-cyan-300 text-xs">{c.control_id}</td>
                        <td className="py-2.5 pr-4 text-gray-200 text-xs max-w-[200px]">{c.control_name}</td>
                        <td className="py-2.5 pr-4">{c.category && <CategoryBadge c={c.category} />}</td>
                        <td className="py-2.5 pr-4"><SeverityBadge s={c.severity ?? "—"} /></td>
                        <td className="py-2.5 pr-4 font-mono text-gray-400 text-[10px] max-w-[160px] truncate">{c.expected_value ?? "—"}</td>
                        <td className="py-2.5">{c.automated ? <CheckCircle className="w-4 h-4 text-emerald-400" /> : <span className="text-gray-600 text-xs">Manual</span>}</td>
                      </tr>
                    ))}</tbody>
                  </table></div>}
              </div>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {trend.length > 0 && <div className="bg-gray-800 rounded-lg p-6">
                  <h2 className="text-sm font-semibold text-gray-300 uppercase tracking-wider mb-4 flex items-center gap-2"><TrendingUp className="w-4 h-4 text-emerald-400" /> Compliance Trend</h2>
                  <div className="flex items-end gap-3 h-32">{trend.map(t => (
                    <div key={t.date} className="flex-1 flex flex-col items-center gap-1">
                      <span className="text-xs text-emerald-400 font-semibold">{t.pct}%</span>
                      <div className="w-full bg-gray-700 rounded-t relative" style={{ height: `${(t.pct / maxPct) * 96}px` }}>
                        <div className="absolute inset-0 bg-gradient-to-t from-emerald-600 to-emerald-400 rounded-t" />
                      </div>
                      <span className="text-[10px] text-gray-500">{t.date}</span>
                    </div>
                  ))}</div>
                </div>}

                {drift.length > 0 && <div className="bg-gray-800 rounded-lg p-6">
                  <h2 className="text-sm font-semibold text-gray-300 uppercase tracking-wider mb-4 flex items-center gap-2"><AlertTriangle className="w-4 h-4 text-yellow-400" /> Drift Report</h2>
                  <div className="space-y-2">{drift.map((d, i) => (
                    <div key={i} className="flex items-start gap-3 bg-gray-900 rounded px-3 py-2">
                      {d.direction === "improved" && <TrendingUp className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />}
                      {d.direction === "degraded" && <TrendingDown className="w-4 h-4 text-red-400 flex-shrink-0 mt-0.5" />}
                      {d.direction === "new_failure" && <AlertTriangle className="w-4 h-4 text-orange-400 flex-shrink-0 mt-0.5" />}
                      <div><code className="text-[10px] text-cyan-300 font-mono">{d.control_id}</code><p className="text-xs text-gray-300 mt-0.5">{d.label}</p></div>
                    </div>
                  ))}</div>
                </div>}
              </div>

              <div className="bg-gray-800 rounded-lg p-6">
                <div className="flex items-center gap-2"><BookOpen className="w-4 h-4 text-blue-400" /><h2 className="text-sm font-semibold text-gray-300 uppercase tracking-wider">Baseline Status</h2></div>
                <p className="text-gray-400 text-xs mt-2">Selected baseline: <span className="text-white">{selectedBaseline?.baseline_name ?? "—"}</span> · {selectedBaseline?.status ?? "—"}</p>
              </div>
            </div>
          </div>
        </>}
    </div>
  );
}
