/**
 * Security Health Scorecard Dashboard - Live API
 * Route: /health-scorecard
 * API: GET /api/v1/health-scorecard/{domains,snapshots,grade-trend,targets}
 */
import { useState, useEffect } from "react";
import { ShieldCheck, TrendingUp, Target, AlertTriangle, Clock, RefreshCw } from "lucide-react";
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

function computeOverall(domains: any[]) {
  if (!domains.length) return 0;
  const tw = domains.reduce((s, d) => s + (d.weight ?? 1), 0);
  const w = domains.reduce((s, d) => s + ((d.score ?? 0) / (d.max_score ?? 100)) * (d.weight ?? 1), 0);
  return Math.round((w / tw) * 100);
}
function scoreToGrade(s: number) {
  if (s >= 90) return { grade: "A", color: "text-green-400", bg: "bg-green-500/20 border border-green-500/40" };
  if (s >= 80) return { grade: "B", color: "text-teal-400", bg: "bg-teal-500/20 border border-teal-500/40" };
  if (s >= 70) return { grade: "C", color: "text-yellow-400", bg: "bg-yellow-500/20 border border-yellow-500/40" };
  if (s >= 60) return { grade: "D", color: "text-orange-400", bg: "bg-orange-500/20 border border-orange-500/40" };
  return { grade: "F", color: "text-red-400", bg: "bg-red-500/20 border border-red-500/40" };
}
function statusDot(s: string) {
  const cls = s === "green" ? "bg-green-400" : s === "amber" ? "bg-yellow-400" : "bg-red-400";
  return <span className={`inline-block w-2.5 h-2.5 rounded-full ${cls}`} />;
}

function Sparkline({ data }: { data: any[] }) {
  if (data.length < 2) return null;
  const W = 320, H = 60, P = 8;
  const scores = data.map(d => d.score ?? 0);
  const min = Math.min(...scores) - 2;
  const max = Math.max(...scores) + 2;
  const toX = (i: number) => P + (i / (data.length - 1)) * (W - P * 2);
  const toY = (v: number) => P + ((max - v) / (max - min || 1)) * (H - P * 2);
  const pts = data.map((d, i) => `${toX(i)},${toY(d.score ?? 0)}`).join(" ");
  return <svg viewBox={`0 0 ${W} ${H}`} className="w-full h-16">
    <polyline points={pts} fill="none" stroke="#38bdf8" strokeWidth="2" strokeLinejoin="round" />
    {data.map((d, i) => <circle key={i} cx={toX(i)} cy={toY(d.score ?? 0)} r="3" fill="#38bdf8" />)}
  </svg>;
}

export default function SecurityHealthScorecardDashboard() {
  const [domains, setDomains] = useState<any[]>([]);
  const [snapshots, setSnapshots] = useState<any[]>([]);
  const [gradeTrend, setGradeTrend] = useState<any[]>([]);
  const [targets, setTargets] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const [d, s, g, t] = await Promise.allSettled([
        apiFetch<any>("/api/v1/health-scorecard/domains"),
        apiFetch<any>("/api/v1/health-scorecard/snapshots"),
        apiFetch<any>("/api/v1/health-scorecard/grade-trend"),
        apiFetch<any>("/api/v1/health-scorecard/targets"),
      ]);
      if (d.status === "fulfilled") { const v = d.value as any; setDomains(Array.isArray(v) ? v : (v.domains ?? v.items ?? [])); }
      if (s.status === "fulfilled") { const v = s.value as any; setSnapshots(Array.isArray(v) ? v : (v.snapshots ?? v.items ?? [])); }
      if (g.status === "fulfilled") { const v = g.value as any; setGradeTrend(Array.isArray(v) ? v : (v.trend ?? v.items ?? [])); }
      if (t.status === "fulfilled") { const v = t.value as any; setTargets(Array.isArray(v) ? v : (v.targets ?? v.items ?? [])); }
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  const overall = computeOverall(domains);
  const { grade, color, bg } = scoreToGrade(overall);
  const redDomains = domains.filter(d => d.status === "red");
  const greenDomains = domains.filter(d => d.status === "green");
  const amberDomains = domains.filter(d => d.status === "amber");

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <ShieldCheck className="text-sky-400" size={28} />
          <div>
            <h1 className="text-2xl font-bold">Security Health Scorecard</h1>
            <p className="text-gray-400 text-sm">Weighted domain scoring across all security pillars</p>
          </div>
        </div>
        <button onClick={load} className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm"><RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} /> Refresh</button>
      </div>

      {loading ? <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-sky-500"></div></div>
        : error ? <ErrorState message={error} onRetry={load} />
        : domains.length === 0 ? <EmptyState icon={ShieldCheck} title="No scorecard data" description="Domain scoring will appear here once configured." />
        : <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className={`bg-gray-800 rounded-lg p-6 flex flex-col items-center justify-center md:col-span-1 ${bg}`}>
              <div className={`text-7xl font-black ${color}`}>{grade}</div>
              <div className="text-gray-300 text-sm mt-1">Overall Grade</div>
              <div className="text-3xl font-bold text-white mt-1">{overall}</div>
              <div className="text-gray-400 text-xs">/ 100</div>
            </div>
            <div className="bg-gray-800 rounded-lg p-6 flex flex-col justify-center"><div className="text-gray-400 text-sm mb-1">Domains Healthy</div><div className="text-3xl font-bold text-green-400">{greenDomains.length}<span className="text-gray-500 text-lg">/{domains.length}</span></div></div>
            <div className="bg-gray-800 rounded-lg p-6 flex flex-col justify-center"><div className="text-gray-400 text-sm mb-1">Needs Attention</div><div className="text-3xl font-bold text-yellow-400">{amberDomains.length}</div></div>
            <div className="bg-gray-800 rounded-lg p-6 flex flex-col justify-center"><div className="text-gray-400 text-sm mb-1">Critical Gaps</div><div className="text-3xl font-bold text-red-400">{redDomains.length}</div></div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-2 bg-gray-800 rounded-lg p-6">
              <h2 className="text-lg font-semibold mb-4 flex items-center gap-2"><ShieldCheck size={18} className="text-sky-400" /> Domain Breakdown</h2>
              <div className="space-y-3">{domains.map(d => {
                const pct = Math.round(((d.score ?? 0) / (d.max_score ?? 100)) * 100);
                const barColor = d.status === "green" ? "bg-green-500" : d.status === "amber" ? "bg-yellow-500" : "bg-red-500";
                return (
                  <div key={d.domain_name ?? d.name} className="grid grid-cols-12 items-center gap-2 text-sm">
                    <div className="col-span-4 font-medium text-gray-200 truncate">{d.domain_name ?? d.name}</div>
                    <div className="col-span-2"><span className="px-2 py-0.5 rounded text-xs bg-gray-600 text-gray-300">{d.category}</span></div>
                    <div className="col-span-4"><div className="bg-gray-700 rounded-full h-2"><div className={`${barColor} rounded-full h-2`} style={{ width: `${pct}%` }} /></div></div>
                    <div className="col-span-1 text-right text-gray-300">{d.score ?? 0}</div>
                    <div className="col-span-1 flex justify-center">{statusDot(d.status)}</div>
                  </div>
                );
              })}</div>
            </div>
            <div className="space-y-4">
              <div className="bg-gray-800 rounded-lg p-6">
                <h2 className="text-sm font-semibold mb-3 flex items-center gap-2"><TrendingUp size={16} className="text-sky-400" /> Score History</h2>
                {snapshots.length === 0 ? <p className="text-gray-500 text-xs">No snapshots yet.</p> : <Sparkline data={snapshots} />}
              </div>
              <div className="bg-gray-800 rounded-lg p-6">
                <h2 className="text-sm font-semibold mb-3 flex items-center gap-2"><AlertTriangle size={16} className="text-red-400" /> Improvement Areas</h2>
                {redDomains.length === 0 ? <p className="text-gray-400 text-xs">No critical gaps — all domains passing.</p>
                  : <div className="space-y-2">{redDomains.map(d => (
                    <div key={d.domain_name ?? d.name} className="flex items-center justify-between text-sm">
                      <span className="text-red-300">{d.domain_name ?? d.name}</span>
                      <span className="text-red-400 font-bold">−{(d.max_score ?? 100) - (d.score ?? 0)}</span>
                    </div>
                  ))}</div>}
              </div>
            </div>
          </div>

          {gradeTrend.length > 0 && <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold mb-4 flex items-center gap-2"><TrendingUp size={18} className="text-sky-400" /> Grade Trend</h2>
            <table className="w-full text-sm"><thead><tr className="text-gray-400 border-b border-gray-700"><th className="text-left py-2">Period</th><th className="text-center py-2">Grade</th><th className="text-right py-2">Score</th><th className="text-right py-2">Change</th></tr></thead>
              <tbody>{gradeTrend.map(r => { const g = scoreToGrade(r.score ?? 0); return (
                <tr key={r.period} className="border-b border-gray-700/50">
                  <td className="py-2 text-gray-200">{r.period}</td>
                  <td className="py-2 text-center"><span className={`font-bold text-lg ${g.color}`}>{r.grade ?? g.grade}</span></td>
                  <td className="py-2 text-right text-gray-200">{r.score}</td>
                  <td className="py-2 text-right">{(r.change ?? 0) === 0 ? <span className="text-gray-500">—</span> : <span className={(r.change ?? 0) > 0 ? "text-green-400" : "text-red-400"}>{(r.change ?? 0) > 0 ? "+" : ""}{r.change}</span>}</td>
                </tr>
              );})}</tbody>
            </table>
          </div>}

          {targets.length > 0 && <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold mb-4 flex items-center gap-2"><Target size={18} className="text-sky-400" /> Target Tracking</h2>
            <table className="w-full text-sm"><thead><tr className="text-gray-400 border-b border-gray-700"><th className="text-left py-2">Domain</th><th className="text-right py-2">Current</th><th className="text-right py-2">Target</th><th className="text-right py-2">Gap</th><th className="text-left py-2 pl-4">Deadline</th><th className="text-left py-2">Owner</th></tr></thead>
              <tbody>{targets.map(t => {
                const gap = (t.target_score ?? 0) - (t.current_score ?? 0);
                return (
                  <tr key={t.domain} className="border-b border-gray-700/50">
                    <td className="py-2 text-gray-200">{t.domain}</td>
                    <td className="py-2 text-right text-gray-300">{t.current_score}</td>
                    <td className="py-2 text-right text-sky-300">{t.target_score}</td>
                    <td className="py-2 text-right text-red-400 font-medium">−{gap}</td>
                    <td className="py-2 pl-4"><div className="flex items-center gap-1 text-gray-400"><Clock size={12} /> {t.deadline}</div></td>
                    <td className="py-2"><span className="px-2 py-0.5 bg-gray-700 rounded text-gray-300">{t.owner}</span></td>
                  </tr>
                );
              })}</tbody>
            </table>
          </div>}
        </>}
    </div>
  );
}
