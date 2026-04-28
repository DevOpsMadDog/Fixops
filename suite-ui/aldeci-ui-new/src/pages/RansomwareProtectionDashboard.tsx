// REPLACED by GenericDashboard config in dashboardRoutes.ts 2026-04-27
/**
 * Ransomware Protection Dashboard - Live API
 * Route: /ransomware-protection
 * API: GET /api/v1/ransomware-protection/{patterns,backup-status}
 */
import { useState, useEffect } from "react";
import { AlertTriangle, Lock, RefreshCw, Database } from "lucide-react";
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

const severityColor: Record<string, string> = {
  critical: "bg-red-800 text-red-200",
  high: "bg-orange-800 text-orange-200",
  medium: "bg-amber-800 text-amber-200",
  low: "bg-green-800 text-green-200",
};

export default function RansomwareProtectionDashboard() {
  const [patterns, setPatterns] = useState<any[]>([]);
  const [backup, setBackup] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const [p, b] = await Promise.allSettled([
        apiFetch<any>("/api/v1/ransomware-protection/patterns"),
        apiFetch<any>("/api/v1/ransomware-protection/backup-status"),
      ]);
      if (p.status === "fulfilled") {
        const v = p.value as any;
        setPatterns(Array.isArray(v) ? v : (v.patterns ?? v.items ?? []));
      }
      if (b.status === "fulfilled") {
        const v = b.value as any;
        setBackup(v && typeof v === "object" && !Array.isArray(v) ? v : null);
      }
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  const enabled = patterns.filter(p => p.enabled).length;
  const totalMatches = patterns.reduce((s, p) => s + (p.match_count ?? 0), 0);
  const criticalPatterns = patterns.filter(p => p.severity === "critical").length;
  const cov = backup?.backup_coverage_pct ?? 0;

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2"><Lock className="w-6 h-6 text-red-400" /> Ransomware Protection</h1>
          <p className="text-gray-400 text-sm mt-1">Detection patterns, backup coverage, containment status</p>
        </div>
        <button onClick={load} className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm"><RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} /> Refresh</button>
      </div>

      {loading ? <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-red-500"></div></div>
        : error ? <ErrorState message={error} onRetry={load} />
        : patterns.length === 0 && !backup ? <EmptyState icon={Lock} title="No detection data" description="Ransomware patterns and backup coverage will appear here." />
        : <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              { label: "Active Patterns", value: enabled, color: "text-green-400" },
              { label: "Critical Patterns", value: criticalPatterns, color: "text-red-400" },
              { label: "Total Matches", value: totalMatches, color: "text-orange-400" },
              { label: "Backup Coverage", value: backup ? `${Number(cov).toFixed(1)}%` : "—", color: "text-blue-400" },
            ].map(s => (
              <div key={s.label} className="bg-gray-800 rounded-lg p-5"><p className="text-gray-400 text-sm">{s.label}</p><p className={`text-3xl font-bold mt-1 ${s.color}`}>{s.value}</p></div>
            ))}
          </div>
          {backup && (
            <div className="bg-gray-800 rounded-lg p-6">
              <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2"><Database className="w-4 h-4 text-blue-400" /> Backup Coverage</h2>
              <div className="flex items-center gap-4">
                <div className="flex-1">
                  <div className="flex justify-between text-sm mb-2"><span className="text-gray-400">{backup.systems_with_backup ?? 0} / {backup.total_systems ?? 0} systems protected</span><span className="text-blue-400 font-bold">{Number(cov).toFixed(1)}%</span></div>
                  <div className="w-full bg-gray-700 rounded-full h-3"><div className="h-3 rounded-full bg-blue-500" style={{ width: `${cov}%` }} /></div>
                </div>
                {backup.last_verified && <div className="text-xs text-gray-500">Last verified: {backup.last_verified}</div>}
              </div>
            </div>
          )}
          <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold text-white mb-4 flex items-center gap-2"><AlertTriangle className="w-4 h-4 text-red-400" /> Detection Patterns</h2>
            {patterns.length === 0 ? <p className="text-gray-500 text-sm">No patterns configured.</p>
              : <div className="space-y-3">{patterns.map(p => (
                <div key={p.id} className={`p-4 rounded-lg border flex items-center justify-between ${p.enabled ? "border-gray-600 bg-gray-700/30" : "border-gray-700 bg-gray-700/10 opacity-60"}`}>
                  <div className="flex items-center gap-3">
                    <span className={`px-2 py-0.5 rounded text-xs font-bold ${severityColor[p.severity] || "bg-gray-700 text-gray-200"}`}>{p.severity}</span>
                    <div>
                      <p className="text-white font-medium text-sm">{p.pattern_name ?? p.name}</p>
                      <p className="text-gray-400 text-xs">{p.pattern_type ?? "—"} · {p.match_count ?? 0} matches</p>
                    </div>
                  </div>
                  <span className={`text-xs px-2 py-1 rounded ${p.enabled ? "bg-green-800/50 text-green-300" : "bg-gray-700 text-gray-400"}`}>{p.enabled ? "Enabled" : "Disabled"}</span>
                </div>
              ))}</div>}
          </div>
        </>}
    </div>
  );
}
