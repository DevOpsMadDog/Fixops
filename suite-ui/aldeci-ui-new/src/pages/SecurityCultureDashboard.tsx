/**
 * Security Culture Dashboard - Live API
 * Route: /security-culture
 * API: GET /api/v1/security-culture/summary
 */

import { useState, useEffect } from "react";
import { Heart, TrendingUp, TrendingDown, Minus, RefreshCw, Users, ClipboardList, BarChart2 } from "lucide-react";
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

type Trend = "up" | "down" | "flat";

function maturityColor(m: string) {
  return m === "optimized" ? "bg-purple-500/20 text-purple-300"
    : m === "managed" ? "bg-blue-500/20 text-blue-300"
    : m === "defined" ? "bg-green-500/20 text-green-300"
    : m === "developing" ? "bg-amber-500/20 text-amber-300"
    : "bg-red-500/20 text-red-300";
}
function statusBadge(s: string) {
  return s === "active" ? "bg-green-500/20 text-green-300"
    : s === "completed" ? "bg-gray-500/20 text-gray-400"
    : s === "planned" ? "bg-blue-500/20 text-blue-300"
    : "bg-amber-500/20 text-amber-300";
}
function scoreColor(s: number) { return s >= 80 ? "text-green-400" : s >= 65 ? "text-blue-400" : s >= 50 ? "text-amber-400" : "text-red-400"; }
function scoreBarColor(s: number) { return s >= 80 ? "bg-green-500" : s >= 65 ? "bg-blue-400" : s >= 50 ? "bg-amber-400" : "bg-red-500"; }

function TrendIcon({ trend, delta }: { trend: Trend; delta: number }) {
  if (trend === "up") return <span className="text-green-400 text-xs flex items-center gap-0.5"><TrendingUp className="w-3 h-3" />+{delta}pp</span>;
  if (trend === "down") return <span className="text-red-400 text-xs flex items-center gap-0.5"><TrendingDown className="w-3 h-3" />{delta}pp</span>;
  return <span className="text-gray-400 text-xs flex items-center gap-0.5"><Minus className="w-3 h-3" />0pp</span>;
}

function CircleProgress({ pct }: { pct: number }) {
  const r = 20, circ = 2 * Math.PI * r, filled = (pct / 100) * circ;
  const color = pct >= 80 ? "#22c55e" : pct >= 50 ? "#6366f1" : "#f97316";
  return (
    <svg width="52" height="52" className="flex-shrink-0">
      <circle cx="26" cy="26" r={r} fill="none" stroke="#374151" strokeWidth="4" />
      <circle cx="26" cy="26" r={r} fill="none" stroke={color} strokeWidth="4" strokeDasharray={`${filled} ${circ - filled}`} strokeDashoffset={circ / 4} strokeLinecap="round" />
      <text x="26" y="30" textAnchor="middle" fontSize="10" fill="white" fontWeight="bold">{pct}%</text>
    </svg>
  );
}

export default function SecurityCultureDashboard() {
  const [metrics, setMetrics] = useState<any[]>([]);
  const [initiatives, setInitiatives] = useState<any[]>([]);
  const [assessments, setAssessments] = useState<any[]>([]);
  const [deptScores, setDeptScores] = useState<any[]>([]);
  const [selectedAssessment, setSelectedAssessment] = useState<string>("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const summary = await apiFetch<any>("/api/v1/security-culture/summary");
      const ms = Array.isArray(summary?.metrics) ? summary.metrics : [];
      const inis = Array.isArray(summary?.initiatives) ? summary.initiatives : [];
      const asms = Array.isArray(summary?.assessments) ? summary.assessments : [];
      const depts = Array.isArray(summary?.departments) ? summary.departments : (Array.isArray(summary?.dept_scores) ? summary.dept_scores : []);
      setMetrics(ms);
      setInitiatives(inis);
      setAssessments(asms);
      setDeptScores(depts);
      if (asms.length && !selectedAssessment) setSelectedAssessment(asms[0].id);
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  const isEmpty = metrics.length === 0 && initiatives.length === 0 && assessments.length === 0 && deptScores.length === 0;
  const selAsmn = assessments.find(a => a.id === selectedAssessment) ?? assessments[0];
  const avgCulture = deptScores.length ? Math.round(deptScores.reduce((s, d) => s + (d.culture_score ?? 0), 0) / deptScores.length) : 0;
  const avgMetric = metrics.length ? Math.round(metrics.reduce((s, m) => s + (m.value ?? 0), 0) / metrics.length) : 0;

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2"><Heart className="w-6 h-6 text-pink-400" /> Security Culture</h1>
          <p className="text-gray-400 text-sm mt-1">Organizational security culture metrics, initiatives, and maturity assessments</p>
        </div>
        <button onClick={load} className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm"><RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} /> Refresh</button>
      </div>

      {loading ? <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div></div>
        : error ? <ErrorState message={error} onRetry={load} />
        : isEmpty ? <EmptyState icon={Heart} title="No security culture data" description="No culture metrics, initiatives, or assessments recorded yet." />
        : <>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            {[
              { label: "Avg Culture Score", value: `${avgCulture}%`, color: "text-pink-400" },
              { label: "Avg Metric vs Target", value: `${avgMetric}%`, color: "text-white" },
              { label: "Active Initiatives", value: initiatives.filter(i => i.status === "active").length, color: "text-green-400" },
              { label: "Current Maturity", value: assessments[0]?.maturity_level ?? "—", color: "text-blue-400" },
            ].map(k => (
              <div key={k.label} className="bg-gray-800 rounded-lg p-4 text-center">
                <div className={`text-2xl font-bold capitalize ${k.color}`}>{k.value}</div>
                <div className="text-gray-400 text-xs mt-1">{k.label}</div>
              </div>
            ))}
          </div>

          {metrics.length > 0 && <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
            {metrics.map(metric => {
              const value = metric.value ?? 0;
              const target = metric.target ?? 100;
              const pct = target > 0 ? Math.round((value / target) * 100) : 0;
              const gap = target - value;
              return (
                <div key={metric.category ?? metric.label} className="bg-gray-800 rounded-lg p-4">
                  <div className="flex items-start justify-between mb-3">
                    <div>
                      <div className="font-medium text-white text-sm">{metric.label}</div>
                      <TrendIcon trend={metric.trend ?? "flat"} delta={metric.trend_delta ?? 0} />
                    </div>
                    <div className="text-right">
                      <div className={`text-xl font-bold ${scoreColor(value)}`}>{value}%</div>
                      <div className="text-gray-500 text-xs">tgt: {target}%</div>
                    </div>
                  </div>
                  <div className="relative w-full bg-gray-700 rounded-full h-2 mb-1">
                    <div className={`h-2 rounded-full ${scoreBarColor(value)}`} style={{ width: `${value}%` }} />
                    <div className="absolute top-0 h-2 w-0.5 bg-white/60" style={{ left: `${target}%` }} />
                  </div>
                  <div className="flex justify-between text-xs text-gray-500"><span>{pct}% of target</span>{gap > 0 && <span className="text-amber-400">{gap}pp gap</span>}</div>
                </div>
              );
            })}
          </div>}

          <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
            {initiatives.length > 0 && <div className="xl:col-span-1 bg-gray-800 rounded-lg overflow-hidden">
              <div className="p-4 border-b border-gray-700"><h2 className="font-semibold text-white flex items-center gap-2"><ClipboardList className="w-4 h-4 text-indigo-400" /> Initiatives</h2></div>
              <div className="divide-y divide-gray-700/50">{initiatives.map(ini => (
                <div key={ini.id} className="p-4 flex items-center gap-3">
                  <CircleProgress pct={ini.completion_rate ?? 0} />
                  <div className="flex-1 min-w-0">
                    <div className="text-gray-200 text-sm font-medium truncate">{ini.name}</div>
                    <div className="flex items-center gap-2 mt-1">
                      <span className="bg-gray-700 text-gray-400 text-xs px-1.5 py-0.5 rounded">{ini.type}</span>
                      <span className={`text-xs px-1.5 py-0.5 rounded-full capitalize ${statusBadge(ini.status)}`}>{ini.status}</span>
                    </div>
                    <div className="text-gray-500 text-xs mt-1">{(ini.participants ?? 0) > 0 ? `${ini.participants.toLocaleString()} participants` : "Not started"} · {ini.quarter ?? ""}</div>
                  </div>
                </div>
              ))}</div>
            </div>}

            {assessments.length > 0 && <div className="xl:col-span-2 space-y-4">
              <div className="bg-gray-800 rounded-lg overflow-hidden">
                <div className="p-4 border-b border-gray-700"><h2 className="font-semibold text-white flex items-center gap-2"><BarChart2 className="w-4 h-4 text-purple-400" /> Assessment History</h2></div>
                <div className="divide-y divide-gray-700/50">{assessments.map(asm => (
                  <div key={asm.id} onClick={() => setSelectedAssessment(asm.id)} className={`p-4 cursor-pointer hover:bg-gray-700/40 ${selectedAssessment === asm.id ? "bg-gray-700/60" : ""}`}>
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex-1 min-w-0">
                        <div className="font-medium text-white text-sm">{asm.title}</div>
                        <div className="text-gray-400 text-xs mt-0.5">{asm.date} · {asm.assessor}</div>
                      </div>
                      <div className="flex items-center gap-2 flex-shrink-0">
                        <span className={`text-2xl font-bold ${scoreColor(asm.score ?? 0)}`}>{asm.score ?? 0}</span>
                        <span className={`text-xs px-2 py-0.5 rounded-full font-medium capitalize ${maturityColor(asm.maturity_level ?? "")}`}>{asm.maturity_level ?? "—"}</span>
                      </div>
                    </div>
                    {selectedAssessment === asm.id && <div className="mt-3 grid grid-cols-2 gap-3">
                      <div><div className="text-xs text-green-400 font-medium mb-1">Strengths</div><ul className="space-y-1">{(asm.strengths ?? []).map((s: string) => (<li key={s} className="text-gray-300 text-xs flex items-start gap-1"><span className="text-green-400 mt-0.5">✓</span> {s}</li>))}</ul></div>
                      <div><div className="text-xs text-red-400 font-medium mb-1">Weaknesses</div><ul className="space-y-1">{(asm.weaknesses ?? []).map((w: string) => (<li key={w} className="text-gray-300 text-xs flex items-start gap-1"><span className="text-red-400 mt-0.5">✗</span> {w}</li>))}</ul></div>
                    </div>}
                  </div>
                ))}</div>
              </div>
              {assessments.length > 1 && <div className="bg-gray-800 rounded-lg p-4">
                <div className="text-xs text-gray-400 mb-2">Score Trend</div>
                <div className="flex items-end gap-3 h-16">
                  {assessments.slice().reverse().map((a, i, arr) => {
                    const h = Math.round(((a.score ?? 0) / 100) * 64);
                    return (
                      <div key={a.id} className="flex flex-col items-center gap-1 flex-1">
                        <div className="w-full rounded-t" style={{ height: `${h}px`, backgroundColor: i === arr.length - 1 ? "#6366f1" : "#374151" }} />
                        <span className="text-xs text-gray-500">{a.score}</span>
                      </div>
                    );
                  })}
                </div>
              </div>}
            </div>}
          </div>

          {deptScores.length > 0 && <div className="bg-gray-800 rounded-lg overflow-hidden">
            <div className="p-4 border-b border-gray-700"><h2 className="font-semibold text-white flex items-center gap-2"><Users className="w-4 h-4 text-cyan-400" /> Department Culture Scores</h2></div>
            <div className="overflow-x-auto"><table className="w-full text-sm">
              <thead><tr className="border-b border-gray-700 text-gray-400 text-xs uppercase">
                <th className="text-left p-3">Department</th><th className="text-left p-3">Headcount</th><th className="text-left p-3">Culture Score</th><th className="text-left p-3 hidden sm:table-cell">Training Rate</th><th className="text-left p-3 hidden md:table-cell">Phishing Pass</th><th className="text-left p-3 hidden lg:table-cell">Reporting Rate</th>
              </tr></thead>
              <tbody>{deptScores.slice().sort((a, b) => (b.culture_score ?? 0) - (a.culture_score ?? 0)).map(dept => (
                <tr key={dept.department} className="border-b border-gray-700/50 hover:bg-gray-700/30">
                  <td className="p-3 text-gray-200 font-medium">{dept.department}</td>
                  <td className="p-3 text-gray-400 text-xs">{dept.headcount ?? 0}</td>
                  <td className="p-3"><div className="flex items-center gap-2"><span className={`font-bold ${scoreColor(dept.culture_score ?? 0)}`}>{dept.culture_score ?? 0}%</span><div className="w-20 bg-gray-700 rounded-full h-1.5"><div className={`h-1.5 rounded-full ${scoreBarColor(dept.culture_score ?? 0)}`} style={{ width: `${dept.culture_score ?? 0}%` }} /></div></div></td>
                  <td className="p-3 hidden sm:table-cell"><span className={`text-xs font-medium ${scoreColor(dept.training_rate ?? 0)}`}>{dept.training_rate ?? 0}%</span></td>
                  <td className="p-3 hidden md:table-cell"><span className={`text-xs font-medium ${scoreColor(dept.phishing_pass ?? 0)}`}>{dept.phishing_pass ?? 0}%</span></td>
                  <td className="p-3 hidden lg:table-cell"><span className={`text-xs font-medium ${scoreColor(dept.reporting_rate ?? 0)}`}>{dept.reporting_rate ?? 0}%</span></td>
                </tr>
              ))}</tbody>
            </table></div>
          </div>}
        </>}
    </div>
  );
}
