// FOLDED into UpgradePathsHub (dep-risk tab) 2026-05-02 — preserve for git history
// REPLACED by FindingsExplorerView config 2026-04-27
// Wave 4 Pattern-2 mechanical collapse (UX Phase 3)
/**
 * Security Dependency Risk Dashboard - Live API
 * Route: /dependency-risk  (now redirects to /remediate/upgrade?tab=dep-risk)
 * API: GET /api/v1/dependency-risk/summary
 */

import { useState, useEffect } from "react";
import { Package, AlertTriangle, Shield, AlertOctagon, RefreshCw } from "lucide-react";
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

const ECOSYSTEMS = ["npm", "pypi", "maven", "nuget", "cargo", "go"] as const;
type Ecosystem = typeof ECOSYSTEMS[number];

function riskColor(score: number) { return score >= 7 ? "#ef4444" : score >= 5 ? "#f97316" : score >= 3 ? "#eab308" : "#22c55e"; }
function RiskBar({ score }: { score: number }) {
  const color = riskColor(score);
  return (
    <div className="flex items-center gap-2 min-w-[100px]">
      <div className="flex-1 bg-gray-700 rounded-full h-2"><div className="h-2 rounded-full" style={{ width: `${(score / 10) * 100}%`, backgroundColor: color }} /></div>
      <span className="text-xs font-mono w-8 text-right" style={{ color }}>{score.toFixed(1)}</span>
    </div>
  );
}
function SeverityBadge({ s }: { s: string }) {
  const cls: Record<string, string> = { critical: "bg-red-500/20 text-red-400 border border-red-500/30", high: "bg-orange-500/20 text-orange-400 border border-orange-500/30", medium: "bg-yellow-500/20 text-yellow-400 border border-yellow-500/30", low: "bg-blue-500/20 text-blue-400 border border-blue-500/30" };
  return <span className={cn("px-2 py-0.5 rounded text-xs font-medium", cls[s] ?? "bg-gray-700 text-gray-300")}>{s}</span>;
}
function EcoBadge({ e }: { e: string }) {
  const cls: Record<string, string> = { npm: "bg-red-500/20 text-red-300", pypi: "bg-blue-500/20 text-blue-300", maven: "bg-orange-500/20 text-orange-300", nuget: "bg-purple-500/20 text-purple-300", cargo: "bg-yellow-500/20 text-yellow-300", go: "bg-teal-500/20 text-teal-300" };
  return <span className={cn("px-2 py-0.5 rounded text-xs font-medium", cls[e] ?? "bg-gray-700 text-gray-300")}>{e}</span>;
}
function LicenseRiskBadge({ level }: { level: string }) {
  const cls: Record<string, string> = { critical: "bg-red-500/20 text-red-400 border border-red-500/30", high: "bg-orange-500/20 text-orange-400 border border-orange-500/30", medium: "bg-yellow-500/20 text-yellow-400 border border-yellow-500/30" };
  return <span className={cn("px-2 py-0.5 rounded text-xs font-medium", cls[level] ?? "bg-gray-700 text-gray-300")}>{level}</span>;
}

export default function SecurityDependencyRiskDashboard() {
  const [deps, setDeps] = useState<any[]>([]);
  const [vulns, setVulns] = useState<any[]>([]);
  const [licenseConflicts, setLicenseConflicts] = useState<any[]>([]);
  const [transitive, setTransitive] = useState<any[]>([]);
  const [summary, setSummary] = useState<any>({ total: 0, direct: 0, transitive: 0, high_risk: 0 });
  const [activeEco, setActiveEco] = useState<"All" | Ecosystem>("All");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const data: any = await apiFetch<any>("/api/v1/dependency-risk/summary");
      setDeps(Array.isArray(data?.dependencies) ? data.dependencies : []);
      setVulns(Array.isArray(data?.vulnerabilities) ? data.vulnerabilities : []);
      setLicenseConflicts(Array.isArray(data?.license_conflicts) ? data.license_conflicts : []);
      setTransitive(Array.isArray(data?.transitive) ? data.transitive : []);
      setSummary(data?.summary ?? {
        total: data?.total ?? 0, direct: data?.direct ?? 0, transitive: data?.transitive_count ?? 0, high_risk: data?.high_risk ?? 0,
      });
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  const filteredDeps = activeEco === "All" ? deps : deps.filter(d => d.ecosystem === activeEco);
  const filteredDepsIds = new Set(filteredDeps.map(d => d.id));
  const filteredVulns = vulns.filter(v => filteredDepsIds.has(v.dep_id));
  const isEmpty = deps.length === 0 && vulns.length === 0 && licenseConflicts.length === 0;

  return (
    <div className="min-h-screen bg-[#0f172a] text-white p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-yellow-500/10 rounded-lg"><Package className="w-6 h-6 text-yellow-400" /></div>
          <div><h1 className="text-2xl font-bold text-white">Dependency Risk</h1><p className="text-sm text-gray-400">Software composition analysis across all ecosystems</p></div>
        </div>
        <button onClick={load} className="flex items-center gap-2 px-4 py-2 bg-gray-800 hover:bg-gray-700 rounded-lg text-sm"><RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} /> Refresh</button>
      </div>

      {loading ? <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-yellow-500"></div></div>
        : error ? <ErrorState message={error} onRetry={load} />
        : isEmpty ? <EmptyState icon={Package} title="No dependency data" description="No SCA / dependency data ingested yet." />
        : <>
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            {[
              { label: "Total Dependencies", value: summary.total ?? 0, color: "text-white", icon: <Package className="w-5 h-5 text-gray-400" /> },
              { label: "Direct", value: summary.direct ?? 0, color: "text-blue-400", icon: <Shield className="w-5 h-5 text-blue-400" /> },
              { label: "Transitive", value: summary.transitive ?? 0, color: "text-purple-400", icon: <Package className="w-5 h-5 text-purple-400" /> },
              { label: "High Risk", value: summary.high_risk ?? 0, color: "text-red-400", icon: <AlertOctagon className="w-5 h-5 text-red-400" /> },
            ].map(c => (
              <div key={c.label} className="bg-gray-800 rounded-lg p-4 flex items-center gap-3">
                {c.icon}
                <div><p className="text-xs text-gray-400">{c.label}</p><p className={cn("text-2xl font-bold", c.color)}>{c.value}</p></div>
              </div>
            ))}
          </div>

          <div className="flex gap-2 flex-wrap">
            {(["All", ...ECOSYSTEMS] as Array<"All" | Ecosystem>).map(e => (
              <button key={e} onClick={() => setActiveEco(e)} className={cn("px-3 py-1.5 rounded-lg text-sm font-medium", activeEco === e ? "bg-yellow-600 text-white" : "bg-gray-800 text-gray-400 hover:bg-gray-700")}>{e}</button>
            ))}
          </div>

          {filteredDeps.length > 0 && <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold text-white mb-4">Risky Dependencies ({filteredDeps.length})</h2>
            <div className="overflow-x-auto"><table className="w-full text-sm">
              <thead><tr className="border-b border-gray-700">{["Package", "Version", "Ecosystem", "Risk Score", "Vulns", "Critical", "License"].map(h => <th key={h} className="text-left text-gray-400 font-medium py-2 pr-4 whitespace-nowrap">{h}</th>)}</tr></thead>
              <tbody>{filteredDeps.slice().sort((a, b) => (b.risk_score ?? 0) - (a.risk_score ?? 0)).map(d => (
                <tr key={d.id} className="border-b border-gray-700/40 hover:bg-gray-700/30">
                  <td className="py-2.5 pr-4 font-mono text-sm text-white">{d.package_name}</td>
                  <td className="py-2.5 pr-4 text-xs text-gray-400 font-mono">{d.version}</td>
                  <td className="py-2.5 pr-4"><EcoBadge e={d.ecosystem ?? "—"} /></td>
                  <td className="py-2.5 pr-4 min-w-[130px]"><RiskBar score={d.risk_score ?? 0} /></td>
                  <td className="py-2.5 pr-4 text-center text-yellow-400">{d.vuln_count ?? 0}</td>
                  <td className="py-2.5 pr-4 text-center text-red-400 font-bold">{d.critical_vuln_count ?? 0}</td>
                  <td className="py-2.5 text-xs text-gray-400">{d.license ?? "—"}</td>
                </tr>
              ))}</tbody>
            </table></div>
          </div>}

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            {filteredVulns.length > 0 && <div className="bg-gray-800 rounded-lg p-6">
              <h2 className="text-lg font-semibold text-white mb-4">Vulnerabilities ({filteredVulns.length})</h2>
              <div className="space-y-2">{filteredVulns.map(v => {
                const dep = deps.find(d => d.id === v.dep_id);
                return (
                  <div key={v.id} className="flex items-center justify-between p-3 bg-gray-700/30 rounded-lg">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-xs font-mono text-blue-300">{v.cve_id}</span>
                        <SeverityBadge s={v.severity ?? "—"} />
                        <span className="text-xs text-gray-500 font-mono">CVSS {Number(v.cvss_score ?? 0).toFixed(1)}</span>
                      </div>
                      <p className="text-xs text-gray-400 mt-0.5">{dep?.package_name ?? v.dep_id} · fix: {v.fixed_version ?? "—"}</p>
                    </div>
                    {v.patched ? <span className="px-2 py-0.5 bg-green-500/20 text-green-400 rounded text-xs font-medium">patched</span>
                      : <span className="px-2 py-0.5 bg-orange-500/20 text-orange-400 rounded text-xs font-medium">pending</span>}
                  </div>
                );
              })}</div>
            </div>}

            <div className="space-y-4">
              {licenseConflicts.length > 0 && <div className="bg-gray-800 rounded-lg p-6">
                <div className="flex items-center gap-2 mb-4"><AlertTriangle className="w-5 h-5 text-yellow-400" /><h2 className="text-lg font-semibold text-white">License Conflicts</h2></div>
                <div className="space-y-2">{licenseConflicts.map(l => (
                  <div key={l.package_name} className="flex items-center justify-between p-3 bg-gray-700/30 rounded-lg">
                    <div>
                      <p className="text-sm font-medium text-white">{l.package_name}</p>
                      <div className="flex items-center gap-2 mt-0.5"><span className="text-xs text-gray-400">{l.license_name}</span>{l.copyleft && <span className="text-xs text-red-400 flex items-center gap-0.5"><AlertOctagon className="w-3 h-3" /> copyleft</span>}</div>
                    </div>
                    <LicenseRiskBadge level={l.risk_level} />
                  </div>
                ))}</div>
              </div>}

              {transitive.length > 0 && <div className="bg-gray-800 rounded-lg p-6">
                <h2 className="text-lg font-semibold text-white mb-4">Transitive Dependencies</h2>
                <div className="space-y-3">{transitive.map(t => (
                  <div key={t.parent}>
                    <div className="flex items-center gap-2 text-sm mb-1"><Package className="w-3.5 h-3.5 text-yellow-400" /><span className="font-mono text-yellow-300">{t.parent}</span></div>
                    <div className="ml-5 space-y-1">{(t.children ?? []).map((c: string) => (
                      <div key={c} className="flex items-center gap-2 text-xs text-gray-400"><span className="text-gray-600">└─</span><span className="font-mono text-gray-300">{c}</span></div>
                    ))}</div>
                  </div>
                ))}</div>
              </div>}
            </div>
          </div>
        </>}
    </div>
  );
}
