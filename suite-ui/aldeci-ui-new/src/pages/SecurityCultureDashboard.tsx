/**
 * Security Culture Dashboard - Live API
 * Route: /security-culture
 * API: GET /api/v1/security-culture/{summary,departments,assessments/latest}
 */

import { useState, useEffect } from "react";
import { Heart, RefreshCw, Users } from "lucide-react";
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

const scoreColor = (s: number) => s >= 80 ? "text-green-400" : s >= 65 ? "text-blue-400" : s >= 50 ? "text-amber-400" : "text-red-400";
const scoreBarColor = (s: number) => s >= 80 ? "bg-green-500" : s >= 65 ? "bg-blue-400" : s >= 50 ? "bg-amber-400" : "bg-red-500";

export default function SecurityCultureDashboard() {
  const [metrics, setMetrics] = useState<any[]>([]);
  const [initiatives, setInitiatives] = useState<any[]>([]);
  const [assessments, setAssessments] = useState<any[]>([]);
  const [departments, setDepartments] = useState<any[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const [s, d] = await Promise.allSettled([
        apiFetch<any>("/api/v1/security-culture/summary"),
        apiFetch<any>("/api/v1/security-culture/departments"),
      ]);
      if (s.status === "fulfilled") {
        const v = s.value as any;
        setMetrics(v.metrics ?? []); setInitiatives(v.initiatives ?? []); setAssessments(v.assessments ?? []);
      }
      if (d.status === "fulfilled") {
        const v = d.value as any;
        setDepartments(Array.isArray(v) ? v : (v.departments ?? v.items ?? []));
      }
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  const avgCulture = departments.length ? Math.round(departments.reduce((s, d) => s + (d.culture_score ?? 0), 0) / departments.length) : 0;
  const empty = !metrics.length && !initiatives.length && !assessments.length && !departments.length;

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2"><Heart className="w-6 h-6 text-pink-400" /> Security Culture</h1>
          <p className="text-gray-400 text-sm mt-1">Organizational security culture metrics, initiatives, maturity</p>
        </div>
        <button onClick={load} className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm">
          <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} /> Refresh
        </button>
      </div>

      {loading ? <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div></div>
        : error ? <ErrorState message={error} onRetry={load} />
        : empty ? <EmptyState icon={Heart} title="No culture data" description="Once metrics, initiatives or assessments are recorded, they appear here." />
        : <>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            <div className="bg-gray-800 rounded-lg p-4 text-center"><div className="text-2xl font-bold text-pink-400">{avgCulture}%</div><div className="text-gray-400 text-xs mt-1">Avg Culture Score</div></div>
            <div className="bg-gray-800 rounded-lg p-4 text-center"><div className="text-2xl font-bold text-white">{metrics.length}</div><div className="text-gray-400 text-xs mt-1">Metrics</div></div>
            <div className="bg-gray-800 rounded-lg p-4 text-center"><div className="text-2xl font-bold text-green-400">{initiatives.filter((i:any) => i.status === "active").length}</div><div className="text-gray-400 text-xs mt-1">Active Initiatives</div></div>
            <div className="bg-gray-800 rounded-lg p-4 text-center"><div className="text-2xl font-bold capitalize text-blue-400">{assessments[0]?.maturity_level ?? "—"}</div><div className="text-gray-400 text-xs mt-1">Current Maturity</div></div>
          </div>

          {departments.length > 0 && (
            <div className="bg-gray-800 rounded-lg overflow-hidden">
              <div className="p-4 border-b border-gray-700"><h2 className="font-semibold text-white flex items-center gap-2"><Users className="w-4 h-4 text-cyan-400" /> Department Culture Scores</h2></div>
              <div className="overflow-x-auto"><table className="w-full text-sm">
                <thead><tr className="border-b border-gray-700 text-gray-400 text-xs uppercase">
                  <th className="text-left p-3">Department</th><th className="text-left p-3">Headcount</th><th className="text-left p-3">Culture</th>
                  <th className="text-left p-3 hidden sm:table-cell">Training</th><th className="text-left p-3 hidden md:table-cell">Phishing</th>
                </tr></thead>
                <tbody>{[...departments].sort((a:any,b:any) => (b.culture_score ?? 0) - (a.culture_score ?? 0)).map((dept:any) => (
                  <tr key={dept.department} className="border-b border-gray-700/50 hover:bg-gray-700/30">
                    <td className="p-3 text-gray-200 font-medium">{dept.department}</td>
                    <td className="p-3 text-gray-400 text-xs">{dept.headcount}</td>
                    <td className="p-3"><div className="flex items-center gap-2"><span className={`font-bold ${scoreColor(dept.culture_score)}`}>{dept.culture_score}%</span><div className="w-20 bg-gray-700 rounded-full h-1.5"><div className={`h-1.5 rounded-full ${scoreBarColor(dept.culture_score)}`} style={{ width: `${dept.culture_score}%` }} /></div></div></td>
                    <td className="p-3 hidden sm:table-cell"><span className={`text-xs font-medium ${scoreColor(dept.training_rate)}`}>{dept.training_rate}%</span></td>
                    <td className="p-3 hidden md:table-cell"><span className={`text-xs font-medium ${scoreColor(dept.phishing_pass)}`}>{dept.phishing_pass}%</span></td>
                  </tr>
                ))}</tbody>
              </table></div>
            </div>
          )}

          {assessments.length > 0 && (
            <div className="bg-gray-800 rounded-lg overflow-hidden">
              <div className="p-4 border-b border-gray-700"><h2 className="font-semibold text-white">Recent Assessments</h2></div>
              <div className="divide-y divide-gray-700/50">{assessments.map((a:any) => (
                <div key={a.id} className="p-4">
                  <div className="flex items-start justify-between gap-3">
                    <div><div className="font-medium text-white text-sm">{a.title}</div><div className="text-gray-400 text-xs mt-0.5">{a.date} · {a.assessor}</div></div>
                    <div className="flex items-center gap-2"><span className={`text-2xl font-bold ${scoreColor(a.score)}`}>{a.score}</span><span className="text-xs px-2 py-0.5 rounded-full font-medium capitalize bg-blue-500/20 text-blue-300">{a.maturity_level}</span></div>
                  </div>
                </div>
              ))}</div>
            </div>
          )}
        </>}
    </div>
  );
}
