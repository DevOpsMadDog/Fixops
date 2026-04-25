/**
 * Security Operations Metrics Dashboard - Live API
 * Route: /soc-metrics
 * API: GET /api/v1/soc-metrics/summary
 */

import { useState, useEffect } from "react";
import { Activity, Clock, Users, AlertOctagon, CheckCircle, RefreshCw } from "lucide-react";
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

function SeverityBadge({ s }: { s: string }) {
  const cls: Record<string, string> = { critical: "bg-red-500/20 text-red-400 border border-red-500/30", high: "bg-orange-500/20 text-orange-400 border border-orange-500/30", medium: "bg-yellow-500/20 text-yellow-400 border border-yellow-500/30", low: "bg-blue-500/20 text-blue-400 border border-blue-500/30" };
  return <span className={cn("px-2 py-0.5 rounded text-xs font-medium", cls[s] ?? "bg-gray-700 text-gray-300")}>{s}</span>;
}
function StatusBadge({ s }: { s: string }) {
  const cls: Record<string, string> = { open: "bg-red-500/20 text-red-400", acknowledged: "bg-yellow-500/20 text-yellow-400", resolved: "bg-green-500/20 text-green-400" };
  return <span className={cn("px-2 py-0.5 rounded text-xs font-medium", cls[s] ?? "bg-gray-700 text-gray-300")}>{s}</span>;
}
function EfficiencyBadge({ e }: { e: string }) {
  const cls: Record<string, string> = { excellent: "bg-green-500/20 text-green-400", good: "bg-teal-500/20 text-teal-400", average: "bg-yellow-500/20 text-yellow-400", below_avg: "bg-red-500/20 text-red-400" };
  return <span className={cn("px-2 py-0.5 rounded text-xs font-medium", cls[e] ?? "bg-gray-700 text-gray-300")}>{(e ?? "").replace("_", " ")}</span>;
}
function timeAge(iso: string) {
  try {
    const d = new Date(iso);
    const mins = Math.round((Date.now() - d.getTime()) / 60000);
    if (mins < 60) return `${mins}m ago`;
    return `${Math.floor(mins / 60)}h ${mins % 60}m ago`;
  } catch { return iso; }
}

function MetricGauge({ label, value, max, unit, color }: { label: string; value: number; max: number; unit: string; color: string }) {
  const pct = Math.min(value / max, 1);
  const r = 70, cx = 90, cy = 90;
  const startAngle = -210, sweepAngle = 240;
  const toRad = (d: number) => (d * Math.PI) / 180;
  const arcX = (a: number) => cx + r * Math.cos(toRad(a));
  const arcY = (a: number) => cy + r * Math.sin(toRad(a));
  const endAngle = startAngle + sweepAngle * pct;
  const largeArc = sweepAngle * pct > 180 ? 1 : 0;
  const trackEnd = startAngle + sweepAngle;
  return (
    <div className="flex flex-col items-center">
      <svg viewBox="0 0 180 140" className="w-44 h-32">
        <path d={`M ${arcX(startAngle)} ${arcY(startAngle)} A ${r} ${r} 0 1 1 ${arcX(trackEnd)} ${arcY(trackEnd)}`} fill="none" stroke="#1e293b" strokeWidth="14" strokeLinecap="round" />
        {pct > 0.01 && <path d={`M ${arcX(startAngle)} ${arcY(startAngle)} A ${r} ${r} 0 ${largeArc} 1 ${arcX(endAngle)} ${arcY(endAngle)}`} fill="none" stroke={color} strokeWidth="14" strokeLinecap="round" />}
        <text x="90" y="92" textAnchor="middle" fill={color} fontSize="22" fontWeight="bold">{value}</text>
        <text x="90" y="108" textAnchor="middle" fill="#94a3b8" fontSize="9">{unit}</text>
      </svg>
      <p className="text-sm text-gray-300 font-medium -mt-2">{label}</p>
    </div>
  );
}

function TrendChart({ data }: { data: { date: string; mttd: number; mttr: number }[] }) {
  if (!data.length) return <p className="text-gray-500 text-sm">No snapshot history.</p>;
  const maxMttd = Math.max(...data.map(d => d.mttd), 1);
  const maxMttr = Math.max(...data.map(d => d.mttr), 1);
  return (
    <div className="space-y-4">{data.map(d => (
      <div key={d.date} className="grid grid-cols-[60px_1fr_1fr] gap-3 items-center text-xs">
        <span className="text-gray-400">{d.date}</span>
        <div className="flex items-center gap-1"><div className="flex-1 bg-gray-700 rounded h-2"><div className="h-2 rounded bg-teal-500" style={{ width: `${(d.mttd / maxMttd) * 100}%` }} /></div><span className="text-teal-400 w-8 text-right">{d.mttd}m</span></div>
        <div className="flex items-center gap-1"><div className="flex-1 bg-gray-700 rounded h-2"><div className="h-2 rounded bg-orange-500" style={{ width: `${(d.mttr / maxMttr) * 100}%` }} /></div><span className="text-orange-400 w-10 text-right">{d.mttr}m</span></div>
      </div>
    ))}<div className="grid grid-cols-[60px_1fr_1fr] gap-3 text-xs text-gray-500 border-t border-gray-700 pt-2"><span /><span className="text-teal-500">MTTD</span><span className="text-orange-500">MTTR</span></div></div>
  );
}

export default function SecurityOperationsMetricsDashboard() {
  const [stats, setStats] = useState<any | null>(null);
  const [snapshots, setSnapshots] = useState<any[]>([]);
  const [analysts, setAnalysts] = useState<any[]>([]);
  const [queue, setQueue] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const summary: any = await apiFetch<any>("/api/v1/soc-metrics/summary");
      setStats(summary?.stats ?? summary?.metrics ?? summary);
      setSnapshots(Array.isArray(summary?.snapshots) ? summary.snapshots : []);
      setAnalysts(Array.isArray(summary?.analysts) ? summary.analysts : []);
      setQueue(Array.isArray(summary?.queue) ? summary.queue : (Array.isArray(summary?.alerts) ? summary.alerts : []));
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  const isEmpty = !stats && snapshots.length === 0 && analysts.length === 0 && queue.length === 0;

  return (
    <div className="min-h-screen bg-[#0f172a] text-white p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-teal-500/10 rounded-lg"><Activity className="w-6 h-6 text-teal-400" /></div>
          <div><h1 className="text-2xl font-bold text-white">SOC Operations Metrics</h1><p className="text-sm text-gray-400">Mean time to detect &amp; respond, analyst performance, alert queue</p></div>
        </div>
        <button onClick={load} className="flex items-center gap-2 px-4 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm"><RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} /> Refresh</button>
      </div>

      {loading ? <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-teal-500"></div></div>
        : error ? <ErrorState message={error} onRetry={load} />
        : isEmpty ? <EmptyState icon={Activity} title="No SOC metrics" description="No SOC operational metrics recorded yet." />
        : <>
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            {[
              { label: "Total Alerts", value: stats?.total_alerts ?? 0, suffix: "", color: "text-white", icon: <AlertOctagon className="w-5 h-5 text-gray-400" /> },
              { label: "Critical", value: stats?.critical_alerts ?? 0, suffix: "", color: "text-red-400", icon: <AlertOctagon className="w-5 h-5 text-red-400" /> },
              { label: "False Positive Rate", value: Number(stats?.false_positive_rate ?? 0).toFixed(1), suffix: "%", color: "text-yellow-400", icon: <Clock className="w-5 h-5 text-yellow-400" /> },
              { label: "Resolution Rate", value: Number(stats?.resolution_rate ?? 0).toFixed(1), suffix: "%", color: "text-green-400", icon: <CheckCircle className="w-5 h-5 text-green-400" /> },
            ].map(c => (
              <div key={c.label} className="bg-gray-800 rounded-lg p-4 flex items-center gap-3">
                {c.icon}
                <div><p className="text-xs text-gray-400">{c.label}</p><p className={cn("text-2xl font-bold", c.color)}>{c.value}{c.suffix}</p></div>
              </div>
            ))}
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="bg-gray-800 rounded-lg p-6 flex items-center justify-around">
              <MetricGauge label="MTTD" value={stats?.mttd_minutes ?? 0} max={120} unit="minutes" color="#14b8a6" />
              <MetricGauge label="MTTR" value={stats?.mttr_minutes ?? 0} max={480} unit="minutes" color="#f97316" />
            </div>
            <div className="lg:col-span-2 bg-gray-800 rounded-lg p-6">
              <h2 className="text-lg font-semibold text-white mb-4">Snapshot Trend</h2>
              <TrendChart data={snapshots} />
            </div>
          </div>

          {analysts.length > 0 && <div className="bg-gray-800 rounded-lg p-6">
            <div className="flex items-center gap-2 mb-4"><Users className="w-5 h-5 text-blue-400" /><h2 className="text-lg font-semibold text-white">Analyst Leaderboard</h2></div>
            <div className="overflow-x-auto"><table className="w-full text-sm">
              <thead><tr className="border-b border-gray-700"><th className="text-left text-gray-400 font-medium py-2 pr-4">Rank</th><th className="text-left text-gray-400 font-medium py-2 pr-4">Analyst</th><th className="text-left text-gray-400 font-medium py-2 pr-4">Alerts Resolved</th><th className="text-left text-gray-400 font-medium py-2 pr-4">Avg Resolution</th><th className="text-left text-gray-400 font-medium py-2">Efficiency</th></tr></thead>
              <tbody>{analysts.map((a, i) => (
                <tr key={a.name} className="border-b border-gray-700/40 hover:bg-gray-700/30">
                  <td className="py-2.5 pr-4"><span className={cn("w-6 h-6 rounded-full flex items-center justify-center text-xs font-bold", i === 0 ? "bg-yellow-500/20 text-yellow-400" : i === 1 ? "bg-gray-400/20 text-gray-300" : "bg-gray-700 text-gray-400")}>#{i + 1}</span></td>
                  <td className="py-2.5 pr-4 font-medium text-white">{a.name}</td>
                  <td className="py-2.5 pr-4 text-teal-400 font-bold">{a.alerts_resolved ?? 0}</td>
                  <td className="py-2.5 pr-4 text-gray-300">{a.avg_resolution_mins ?? 0} min</td>
                  <td className="py-2.5"><EfficiencyBadge e={a.efficiency ?? "average"} /></td>
                </tr>
              ))}</tbody>
            </table></div>
          </div>}

          {queue.length > 0 && <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold text-white mb-4">Alert Queue</h2>
            <div className="overflow-x-auto"><table className="w-full text-sm">
              <thead><tr className="border-b border-gray-700">{["Severity", "Category", "Source", "Age", "Status", "Assigned To"].map(h => <th key={h} className="text-left text-gray-400 font-medium py-2 pr-4 whitespace-nowrap">{h}</th>)}</tr></thead>
              <tbody>{queue.map(a => (
                <tr key={a.id} className="border-b border-gray-700/40 hover:bg-gray-700/30">
                  <td className="py-2.5 pr-4"><SeverityBadge s={a.severity} /></td>
                  <td className="py-2.5 pr-4 text-gray-200">{a.category}</td>
                  <td className="py-2.5 pr-4"><span className="px-2 py-0.5 bg-gray-700 rounded text-xs text-gray-300">{a.source}</span></td>
                  <td className="py-2.5 pr-4 text-xs text-gray-400">{a.detected_at ? timeAge(a.detected_at) : "—"}</td>
                  <td className="py-2.5 pr-4"><StatusBadge s={a.status} /></td>
                  <td className="py-2.5 pr-4 text-xs text-gray-300">{a.assigned_to ?? "Unassigned"}</td>
                </tr>
              ))}</tbody>
            </table></div>
          </div>}
        </>}
    </div>
  );
}
