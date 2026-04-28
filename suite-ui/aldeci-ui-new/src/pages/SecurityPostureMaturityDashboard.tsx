// REPLACED by FindingsExplorerView config 2026-04-27
// Wave 4 Pattern-2 mechanical collapse (UX Phase 3)
/**
 * Security Posture Maturity Dashboard - Live API
 * Route: /posture-maturity
 * API: GET /api/v1/posture-maturity/overview
 */

import { useState, useEffect } from "react";
import { Shield, Star, AlertTriangle, ChevronRight, TrendingUp, Clock, RefreshCw } from "lucide-react";
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

function domainColor(level: number) { return level >= 4 ? "text-green-400" : level >= 3 ? "text-teal-400" : level >= 2 ? "text-yellow-400" : "text-red-400"; }
function domainBg(level: number) { return level >= 4 ? "bg-green-400" : level >= 3 ? "bg-teal-400" : level >= 2 ? "bg-yellow-400" : "bg-red-400"; }
function priorityBadge(p: string) { return ({ critical: "bg-red-500/20 text-red-400 border border-red-500/30", high: "bg-orange-500/20 text-orange-400 border border-orange-500/30", medium: "bg-yellow-500/20 text-yellow-400 border border-yellow-500/30", low: "bg-blue-500/20 text-blue-400 border border-blue-500/30" } as Record<string, string>)[p] ?? "bg-gray-700 text-gray-300"; }
function effortBadge(e: string) { return ({ high: "bg-purple-500/20 text-purple-400", medium: "bg-blue-500/20 text-blue-400", low: "bg-gray-700 text-gray-300" } as Record<string, string>)[e] ?? "bg-gray-700 text-gray-300"; }
function statusBadge(s: string) { return ({ planned: "bg-gray-700 text-gray-300", in_progress: "bg-blue-500/20 text-blue-400", completed: "bg-green-500/20 text-green-400" } as Record<string, string>)[s] ?? "bg-gray-700 text-gray-300"; }

function Stars({ level }: { level: number }) {
  return <span className="flex gap-0.5">{[1, 2, 3, 4, 5].map(i => (<Star key={i} className={cn("w-3.5 h-3.5", i <= Math.round(level) ? "fill-yellow-400 text-yellow-400" : "text-gray-600")} />))}</span>;
}

function MaturityGauge({ value }: { value: number }) {
  const min = 1, max = 5;
  const pct = Math.max(0, Math.min(1, (value - min) / (max - min)));
  const r = 80, cx = 100, cy = 100;
  const startAngle = -210, sweepAngle = 240;
  const toRad = (d: number) => (d * Math.PI) / 180;
  const arcX = (a: number) => cx + r * Math.cos(toRad(a));
  const arcY = (a: number) => cy + r * Math.sin(toRad(a));
  const endAngle = startAngle + sweepAngle * pct;
  const largeArc = sweepAngle * pct > 180 ? 1 : 0;
  const trackEnd = startAngle + sweepAngle;
  const color = pct >= 0.8 ? "#22c55e" : pct >= 0.6 ? "#14b8a6" : pct >= 0.4 ? "#eab308" : "#ef4444";
  return (
    <svg viewBox="0 0 200 160" className="w-48 h-36">
      <path d={`M ${arcX(startAngle)} ${arcY(startAngle)} A ${r} ${r} 0 1 1 ${arcX(trackEnd)} ${arcY(trackEnd)}`} fill="none" stroke="#1e293b" strokeWidth="16" strokeLinecap="round" />
      {pct > 0.01 && <path d={`M ${arcX(startAngle)} ${arcY(startAngle)} A ${r} ${r} 0 ${largeArc} 1 ${arcX(endAngle)} ${arcY(endAngle)}`} fill="none" stroke={color} strokeWidth="16" strokeLinecap="round" />}
      <text x="100" y="108" textAnchor="middle" fill={color} fontSize="28" fontWeight="bold">{value.toFixed(1)}</text>
      <text x="100" y="125" textAnchor="middle" fill="#94a3b8" fontSize="10">/ 5.0 Maturity</text>
    </svg>
  );
}

function Sparkline({ data }: { data: { date: string; level: number }[] }) {
  if (data.length < 2) return null;
  const vals = data.map(d => d.level);
  const min = Math.min(...vals) - 0.2;
  const max = Math.max(...vals) + 0.2;
  const W = 300, H = 60;
  const pts = data.map((d, i) => `${(i / (data.length - 1)) * W},${H - ((d.level - min) / (max - min || 1)) * H}`);
  return (
    <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-16">
      <polyline points={pts.join(" ")} fill="none" stroke="#14b8a6" strokeWidth="2" strokeLinejoin="round" />
      {data.map((d, i) => {
        const x = (i / (data.length - 1)) * W;
        const y = H - ((d.level - min) / (max - min || 1)) * H;
        return <g key={i}><circle cx={x} cy={y} r="3" fill="#14b8a6" /><text x={x} y={H - 2} textAnchor="middle" fill="#64748b" fontSize="7">{d.date}</text></g>;
      })}
    </svg>
  );
}

export default function SecurityPostureMaturityDashboard() {
  const [overall, setOverall] = useState<number | null>(null);
  const [domains, setDomains] = useState<any[]>([]);
  const [roadmap, setRoadmap] = useState<any[]>([]);
  const [overdue, setOverdue] = useState<any[]>([]);
  const [history, setHistory] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const data: any = await apiFetch<any>("/api/v1/posture-maturity/overview");
      setOverall(typeof data?.overall === "number" ? data.overall : (typeof data?.overall_level === "number" ? data.overall_level : null));
      setDomains(Array.isArray(data?.domains) ? data.domains : []);
      setRoadmap(Array.isArray(data?.roadmap) ? data.roadmap : []);
      setOverdue(Array.isArray(data?.overdue) ? data.overdue : []);
      setHistory(Array.isArray(data?.history) ? data.history : []);
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  const isEmpty = overall === null && domains.length === 0 && roadmap.length === 0;

  return (
    <div className="min-h-screen bg-[#0f172a] text-white p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-teal-500/10 rounded-lg"><Shield className="w-6 h-6 text-teal-400" /></div>
          <div>
            <h1 className="text-2xl font-bold text-white">Security Posture Maturity</h1>
            <p className="text-sm text-gray-400">Capability maturity model across security domains</p>
          </div>
        </div>
        <button onClick={load} className="flex items-center gap-2 px-4 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm"><RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} /> Refresh</button>
      </div>

      {loading ? <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-teal-500"></div></div>
        : error ? <ErrorState message={error} onRetry={load} />
        : isEmpty ? <EmptyState icon={Shield} title="No maturity data" description="Run a maturity assessment to populate this dashboard." />
        : <>
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="bg-gray-800 rounded-lg p-6 flex flex-col items-center justify-center">
              <p className="text-xs text-gray-400 uppercase tracking-wider mb-2">Overall Maturity Level</p>
              {overall !== null && <><MaturityGauge value={overall} /><p className="text-sm text-gray-400 mt-2">{overall >= 4 ? "Optimized" : overall >= 3 ? "Defined" : overall >= 2 ? "Developing" : "Initial"}</p></>}
            </div>

            <div className="bg-gray-800 rounded-lg p-6">
              <div className="flex items-center gap-2 mb-4"><AlertTriangle className="w-5 h-5 text-orange-400" /><h3 className="font-semibold text-orange-400">Overdue Reviews</h3></div>
              {overdue.length === 0 ? <p className="text-gray-500 text-sm">No overdue reviews.</p>
                : overdue.map(o => (
                  <div key={o.domain} className="flex items-center justify-between py-2 border-b border-gray-700/50 last:border-0">
                    <div><p className="text-sm font-medium text-white">{o.domain}</p><p className="text-xs text-gray-400">Last: {o.last_review}</p></div>
                    <span className="px-2 py-1 rounded text-xs font-bold bg-red-500/20 text-red-400 border border-red-500/30">{o.days_overdue}d overdue</span>
                  </div>
                ))}
            </div>

            <div className="bg-gray-800 rounded-lg p-6">
              <div className="flex items-center gap-2 mb-4"><TrendingUp className="w-5 h-5 text-teal-400" /><h3 className="font-semibold text-white">Maturity Trend</h3></div>
              {history.length >= 2 ? <>
                <Sparkline data={history} />
                <p className="text-xs text-gray-400 mt-2 text-center">{(history[history.length - 1].level - history[0].level).toFixed(1)} pts over {history.length} periods</p>
              </> : <p className="text-gray-500 text-sm">Not enough history yet.</p>}
            </div>
          </div>

          {domains.length > 0 && <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold text-white mb-4">Domain Breakdown</h2>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">{domains.map(d => (
              <div key={d.name} className="bg-gray-900 rounded-lg p-4">
                <p className="text-xs text-gray-400 mb-1 truncate" title={d.name}>{d.name}</p>
                <p className={cn("text-2xl font-bold", domainColor(d.avg_level ?? 0))}>{Number(d.avg_level ?? 0).toFixed(1)}</p>
                <Stars level={d.avg_level ?? 0} />
                <div className="mt-2 w-full bg-gray-700 rounded-full h-1.5"><div className={cn("h-1.5 rounded-full", domainBg(d.avg_level ?? 0))} style={{ width: `${(((d.avg_level ?? 1) - 1) / 4) * 100}%` }} /></div>
                <p className="text-xs text-gray-500 mt-1">{d.capability_count ?? 0} capabilities</p>
              </div>
            ))}</div>
          </div>}

          {roadmap.length > 0 && <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold text-white mb-4">Capability Roadmap</h2>
            <div className="overflow-x-auto"><table className="w-full text-sm">
              <thead><tr className="border-b border-gray-700">
                <th className="text-left text-gray-400 font-medium py-2 pr-4">Capability</th><th className="text-left text-gray-400 font-medium py-2 pr-4">Level</th><th className="text-left text-gray-400 font-medium py-2 pr-4">Priority</th><th className="text-left text-gray-400 font-medium py-2 pr-4">Effort</th><th className="text-left text-gray-400 font-medium py-2 pr-4">Status</th><th className="text-left text-gray-400 font-medium py-2 pr-4">Timeline</th><th className="text-left text-gray-400 font-medium py-2">Owner</th>
              </tr></thead>
              <tbody>{roadmap.map(r => (
                <tr key={r.capability} className="border-b border-gray-700/40 hover:bg-gray-700/30">
                  <td className="py-2.5 pr-4 font-medium text-white">{r.capability}</td>
                  <td className="py-2.5 pr-4"><div className="flex items-center gap-1 text-xs text-gray-300"><span className="text-yellow-400 font-bold">{r.current}</span><ChevronRight className="w-3 h-3 text-gray-500" /><span className="text-green-400 font-bold">{r.target}</span></div></td>
                  <td className="py-2.5 pr-4"><span className={cn("px-2 py-0.5 rounded text-xs font-medium", priorityBadge(r.priority))}>{r.priority}</span></td>
                  <td className="py-2.5 pr-4"><span className={cn("px-2 py-0.5 rounded text-xs font-medium", effortBadge(r.effort))}>{r.effort}</span></td>
                  <td className="py-2.5 pr-4"><span className={cn("px-2 py-0.5 rounded text-xs font-medium", statusBadge(r.status))}>{(r.status ?? "").replace("_", " ")}</span></td>
                  <td className="py-2.5 pr-4 text-gray-300 flex items-center gap-1"><Clock className="w-3 h-3 text-gray-500" />{r.timeline ?? "—"}</td>
                  <td className="py-2.5 text-gray-400 text-xs">{r.owner ?? "—"}</td>
                </tr>
              ))}</tbody>
            </table></div>
          </div>}
        </>}
    </div>
  );
}
