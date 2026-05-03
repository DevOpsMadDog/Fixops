// REPLACED by FindingsExplorerView config 2026-04-27
// Wave 4 Pattern-2 mechanical collapse (UX Phase 3)
/**
 * Posture History Dashboard - Live API
 * Route: /posture-history
 * API: GET /api/v1/posture-history/{snapshots,domains,trend}
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

type Period = "weekly" | "monthly" | "quarterly";

function trendIcon(t: string) {
  if (t === "improving") return <span className="text-green-400">↑</span>;
  if (t === "declining") return <span className="text-red-400">↓</span>;
  return <span className="text-gray-400">→</span>;
}
const scoreColor = (s: number) => s >= 80 ? "text-green-400" : s >= 65 ? "text-amber-400" : "text-red-400";
const scoreBarColor = (s: number) => s >= 80 ? "bg-green-500" : s >= 65 ? "bg-amber-500" : "bg-red-500";

export default function PostureHistoryDashboard() {
  const [domains, setDomains] = useState<any[]>([]);
  const [snapshots, setSnapshots] = useState<any[]>([]);
  const [trendData, setTrendData] = useState<Record<string, number[]>>({});
  const [selectedDomain, setSelectedDomain] = useState<string>("");
  const [period, setPeriod] = useState<Period>("weekly");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const [d, s, t] = await Promise.allSettled([
        apiFetch<any>("/api/v1/posture-history/domains"),
        apiFetch<any>("/api/v1/posture-history/snapshots"),
        apiFetch<any>(`/api/v1/posture-history/trend?period=${period}`),
      ]);
      if (d.status === "fulfilled") {
        const v = d.value as any;
        const arr = Array.isArray(v) ? v : (v.domains ?? v.items ?? []);
        setDomains(arr);
        if (arr.length && !selectedDomain) setSelectedDomain(arr[0].domain ?? arr[0].name);
      }
      if (s.status === "fulfilled") {
        const v = s.value as any;
        setSnapshots(Array.isArray(v) ? v : (v.snapshots ?? v.items ?? []));
      }
      if (t.status === "fulfilled") {
        const v = t.value as any;
        setTrendData(v && typeof v === "object" && !Array.isArray(v) ? (v.trends ?? v) : {});
      }
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); /* eslint-disable-next-line react-hooks/exhaustive-deps */ }, [period]);

  const trendPoints: number[] = trendData[selectedDomain] ?? [];
  const maxVal = trendPoints.length ? Math.max(...trendPoints) : 0;
  const minVal = trendPoints.length ? Math.min(...trendPoints) : 0;
  const range = (maxVal - minVal) || 1;

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2"><TrendingUp className="w-6 h-6 text-blue-400" /> Posture History</h1>
          <p className="text-gray-400 mt-1">Security posture score trends across all domains</p>
        </div>
        <div className="flex gap-2 items-center">
          <div className="flex gap-2 bg-gray-800 rounded-lg p-1">
            {(["weekly", "monthly", "quarterly"] as Period[]).map(p => (
              <button key={p} onClick={() => setPeriod(p)} className={`px-4 py-1.5 rounded text-sm font-medium ${period === p ? "bg-blue-600 text-white" : "text-gray-400 hover:text-white"}`}>{p[0].toUpperCase() + p.slice(1)}</button>
            ))}
          </div>
          <button onClick={load} className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm"><RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} /> Refresh</button>
        </div>
      </div>

      {loading ? <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div></div>
        : error ? <ErrorState message={error} onRetry={load} />
        : domains.length === 0 ? <EmptyState icon={TrendingUp} title="No posture history" description="Posture snapshots will appear here once collected." />
        : <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {domains.map(ds => {
              const key = ds.domain ?? ds.name;
              const latest = ds.latest_score ?? ds.score ?? 0;
              const baseline = ds.baseline_score ?? 0;
              const gap = latest - baseline;
              return (
                <div key={key} onClick={() => setSelectedDomain(key)} className={`bg-gray-800 rounded-lg p-5 cursor-pointer border-2 ${selectedDomain === key ? "border-blue-500" : "border-transparent hover:border-gray-600"}`}>
                  <div className="flex items-center justify-between mb-2">
                    <p className="text-gray-400 text-sm">{ds.label ?? key}</p>
                    <span className="text-lg">{trendIcon(ds.trend ?? "stable")}</span>
                  </div>
                  <p className={`text-3xl font-bold ${scoreColor(latest)}`}>{latest}</p>
                  <div className="mt-2 w-full bg-gray-700 rounded-full h-1.5"><div className={`h-1.5 rounded-full ${scoreBarColor(latest)}`} style={{ width: `${latest}%` }} /></div>
                  <div className="mt-2 flex items-center justify-between text-xs">
                    <span className="text-gray-500">Baseline: {baseline}</span>
                    <span className={gap > 0 ? "text-green-400" : gap < 0 ? "text-red-400" : "text-gray-400"}>{gap > 0 ? "+" : ""}{gap} vs baseline</span>
                  </div>
                </div>
              );
            })}
          </div>

          {trendPoints.length > 0 && (
            <div className="bg-gray-800 rounded-lg p-6">
              <h2 className="text-lg font-semibold text-white mb-1">{selectedDomain} — Score Trend ({period})</h2>
              <p className="text-gray-400 text-sm mb-6">Click a domain card above to change view</p>
              <div className="flex items-end gap-2 h-40">
                {trendPoints.map((val, i) => {
                  const heightPct = range === 0 ? 50 : ((val - minVal) / range) * 80 + 10;
                  return (
                    <div key={i} className="flex-1 flex flex-col items-center gap-1">
                      <span className="text-xs text-gray-400">{val}</span>
                      <div className={`w-full rounded-t ${scoreBarColor(val)}`} style={{ height: `${heightPct}%` }} />
                      <span className="text-xs text-gray-500">{i + 1}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          )}

          <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold text-white mb-4">Snapshot History</h2>
            {snapshots.length === 0 ? <p className="text-gray-500 text-sm">No snapshots recorded.</p>
              : <div className="overflow-x-auto"><table className="w-full text-sm">
                <thead><tr className="border-b border-gray-700 text-gray-400 text-left"><th className="pb-3 pr-4">Date</th><th className="pb-3 pr-4">Domain</th><th className="pb-3 pr-4">Score</th><th className="pb-3">Source</th></tr></thead>
                <tbody className="divide-y divide-gray-700">{snapshots.map((sn: any) => (
                  <tr key={sn.id} className="hover:bg-gray-700/50">
                    <td className="py-3 pr-4 text-gray-300">{sn.date ?? sn.created_at}</td>
                    <td className="py-3 pr-4"><span className="bg-gray-700 text-gray-300 px-2 py-0.5 rounded text-xs capitalize">{sn.domain}</span></td>
                    <td className="py-3 pr-4"><div className="flex items-center gap-2"><div className="w-16 bg-gray-700 rounded-full h-1.5"><div className={`h-1.5 rounded-full ${scoreBarColor(sn.score)}`} style={{ width: `${sn.score}%` }} /></div><span className={`font-medium ${scoreColor(sn.score)}`}>{sn.score}</span></div></td>
                    <td className="py-3 text-gray-400 text-xs">{sn.source ?? "—"}</td>
                  </tr>
                ))}</tbody>
              </table></div>}
          </div>
        </>}
    </div>
  );
}
