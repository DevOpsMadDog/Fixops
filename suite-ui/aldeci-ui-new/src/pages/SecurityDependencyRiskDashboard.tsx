/**
 * Security Dependency Risk Dashboard
 * Route: /dependency-risk
 * API: GET /api/v1/dependency-risk/{summary,risky,license-conflicts,vulns}
 */

import { useState, useEffect } from "react";
import { Package, AlertTriangle, Shield, CheckCircle, AlertOctagon } from "lucide-react";
import { cn } from "@/lib/utils";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";

interface Dependency {
  id: string;
  package_name: string;
  version: string;
  ecosystem: string;
  risk_score: number;
  vuln_count: number;
  critical_vuln_count: number;
  license: string;
}

interface VulnRow {
  id: string;
  dep_id: string;
  cve_id: string;
  severity: string;
  cvss_score: number;
  fixed_version: string;
  patched: boolean;
}

interface LicenseRisk { package_name: string; license_name: string; risk_level: string; copyleft: boolean; }
interface Summary { total: number; direct: number; transitive: number; high_risk: number; }

const ECOSYSTEMS = ["npm", "pypi", "maven", "nuget", "cargo", "go"];

async function apiFetch<T>(path: string, opts: RequestInit = {}): Promise<T> {
  const orgId = getStoredOrgId() || "verify-test";
  const url = buildApiUrl(path, { org_id: orgId });
  const res = await fetch(url, { ...opts, headers: { "X-API-Key": getStoredAuthToken(), "X-Org-ID": orgId, "Content-Type": "application/json", ...(opts.headers ?? {}) } });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

const riskColor = (s: number) => s >= 7 ? "#ef4444" : s >= 5 ? "#f97316" : s >= 3 ? "#eab308" : "#22c55e";
const RiskBar = ({ score }: { score: number }) => {
  const c = riskColor(score);
  return (
    <div className="flex items-center gap-2 min-w-[100px]">
      <div className="flex-1 bg-gray-700 rounded-full h-2"><div className="h-2 rounded-full" style={{ width: `${(score / 10) * 100}%`, backgroundColor: c }} /></div>
      <span className="text-xs font-mono w-8 text-right" style={{ color: c }}>{score.toFixed(1)}</span>
    </div>
  );
};
const SeverityBadge = ({ s }: { s: string }) => {
  const cls: Record<string, string> = { critical: "bg-red-500/20 text-red-400 border border-red-500/30", high: "bg-orange-500/20 text-orange-400 border border-orange-500/30", medium: "bg-yellow-500/20 text-yellow-400 border border-yellow-500/30", low: "bg-blue-500/20 text-blue-400 border border-blue-500/30" };
  return <span className={cn("px-2 py-0.5 rounded text-xs font-medium", cls[s] ?? "bg-gray-700 text-gray-300")}>{s}</span>;
};
const EcoBadge = ({ e }: { e: string }) => {
  const cls: Record<string, string> = { npm: "bg-red-500/20 text-red-300", pypi: "bg-blue-500/20 text-blue-300", maven: "bg-orange-500/20 text-orange-300", nuget: "bg-purple-500/20 text-purple-300", cargo: "bg-yellow-500/20 text-yellow-300", go: "bg-teal-500/20 text-teal-300" };
  return <span className={cn("px-2 py-0.5 rounded text-xs font-medium", cls[e] ?? "bg-gray-700 text-gray-300")}>{e}</span>;
};
const LicenseRiskBadge = ({ level }: { level: string }) => {
  const cls: Record<string, string> = { critical: "bg-red-500/20 text-red-400 border border-red-500/30", high: "bg-orange-500/20 text-orange-400 border border-orange-500/30", medium: "bg-yellow-500/20 text-yellow-400 border border-yellow-500/30" };
  return <span className={cn("px-2 py-0.5 rounded text-xs font-medium", cls[level] ?? "bg-gray-700 text-gray-300")}>{level}</span>;
};

export default function SecurityDependencyRiskDashboard() {
  const [activeEco, setActiveEco] = useState<string>("All");
  const [deps, setDeps] = useState<Dependency[]>([]);
  const [vulns, setVulns] = useState<VulnRow[]>([]);
  const [licenseConflicts, setLicenseConflicts] = useState<LicenseRisk[]>([]);
  const [summary, setSummary] = useState<Summary>({ total: 0, direct: 0, transitive: 0, high_risk: 0 });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const [sum, risky, lic, vlns] = await Promise.allSettled([
        apiFetch<any>("/api/v1/dependency-risk/summary"),
        apiFetch<any>("/api/v1/dependency-risk/risky"),
        apiFetch<any>("/api/v1/dependency-risk/license-conflicts"),
        apiFetch<any>("/api/v1/dependency-risk/vulns"),
      ]);
      if (sum.status === "fulfilled") {
        const v = sum.value as any;
        setSummary({
          total: v.total ?? 0, direct: v.direct ?? 0,
          transitive: v.transitive ?? 0, high_risk: v.high_risk ?? 0,
        });
      }
      if (risky.status === "fulfilled") {
        const v = risky.value as any;
        setDeps(Array.isArray(v) ? v : (v.dependencies ?? v.items ?? []));
      }
      if (lic.status === "fulfilled") {
        const v = lic.value as any;
        setLicenseConflicts(Array.isArray(v) ? v : (v.conflicts ?? v.items ?? []));
      }
      if (vlns.status === "fulfilled") {
        const v = vlns.value as any;
        setVulns(Array.isArray(v) ? v : (v.vulns ?? v.items ?? []));
      }
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  };

  useEffect(() => { load(); }, []);

  const filteredDeps = activeEco === "All" ? deps : deps.filter(d => d.ecosystem === activeEco);
  const filteredDepsIds = new Set(filteredDeps.map(d => d.id));
  const filteredVulns = vulns.filter(v => filteredDepsIds.has(v.dep_id));

  async function patchVuln(id: string) {
    setVulns(prev => prev.map(v => v.id === id ? { ...v, patched: true } : v));
  }

  const empty = deps.length === 0 && vulns.length === 0 && licenseConflicts.length === 0 && summary.total === 0;

  return (
    <div className="min-h-screen bg-[#0f172a] text-white p-6 space-y-6">
      <div className="flex items-center gap-3">
        <div className="p-2 bg-yellow-500/10 rounded-lg"><Package className="w-6 h-6 text-yellow-400" /></div>
        <div>
          <h1 className="text-2xl font-bold text-white">Dependency Risk</h1>
          <p className="text-sm text-gray-400">Software composition analysis across all ecosystems</p>
        </div>
      </div>

      {loading ? (
        <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div></div>
      ) : error ? (
        <ErrorState message={error} onRetry={load} />
      ) : empty ? (
        <EmptyState icon={Package} title="No dependencies analyzed" description="Once SCA scans complete, dependency risk and vulnerabilities will appear here." />
      ) : (
        <>
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            {[
              { label: "Total Dependencies", value: summary.total, color: "text-white", icon: <Package className="w-5 h-5 text-gray-400" /> },
              { label: "Direct", value: summary.direct, color: "text-blue-400", icon: <Shield className="w-5 h-5 text-blue-400" /> },
              { label: "Transitive", value: summary.transitive, color: "text-purple-400", icon: <Package className="w-5 h-5 text-purple-400" /> },
              { label: "High Risk", value: summary.high_risk, color: "text-red-400", icon: <AlertOctagon className="w-5 h-5 text-red-400" /> },
            ].map(c => (
              <div key={c.label} className="bg-gray-800 rounded-lg p-4 flex items-center gap-3">
                {c.icon}
                <div>
                  <p className="text-xs text-gray-400">{c.label}</p>
                  <p className={cn("text-2xl font-bold", c.color)}>{c.value}</p>
                </div>
              </div>
            ))}
          </div>

          <div className="flex gap-2 flex-wrap">
            {(["All", ...ECOSYSTEMS]).map(e => (
              <button key={e} onClick={() => setActiveEco(e)}
                className={cn("px-3 py-1.5 rounded-lg text-sm font-medium transition-all", activeEco === e ? "bg-yellow-600 text-white" : "bg-gray-800 text-gray-400 hover:bg-gray-700")}>{e}</button>
            ))}
          </div>

          <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold text-white mb-4">Risky Dependencies ({filteredDeps.length})</h2>
            {filteredDeps.length === 0 ? <p className="text-gray-500 text-sm">No risky dependencies in this ecosystem.</p> : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-gray-700">
                      {["Package", "Version", "Ecosystem", "Risk Score", "Vulns", "Critical", "License"].map(h => (
                        <th key={h} className="text-left text-gray-400 font-medium py-2 pr-4 whitespace-nowrap">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {[...filteredDeps].sort((a, b) => b.risk_score - a.risk_score).map(d => (
                      <tr key={d.id} className="border-b border-gray-700/40 hover:bg-gray-700/30">
                        <td className="py-2.5 pr-4 font-mono text-sm text-white">{d.package_name}</td>
                        <td className="py-2.5 pr-4 text-xs text-gray-400 font-mono">{d.version}</td>
                        <td className="py-2.5 pr-4"><EcoBadge e={d.ecosystem} /></td>
                        <td className="py-2.5 pr-4 min-w-[130px]"><RiskBar score={d.risk_score} /></td>
                        <td className="py-2.5 pr-4 text-center text-yellow-400">{d.vuln_count}</td>
                        <td className="py-2.5 pr-4 text-center text-red-400 font-bold">{d.critical_vuln_count}</td>
                        <td className="py-2.5 text-xs text-gray-400">{d.license}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <div className="bg-gray-800 rounded-lg p-6">
              <h2 className="text-lg font-semibold text-white mb-4">Vulnerabilities ({filteredVulns.length})</h2>
              {filteredVulns.length === 0 ? <p className="text-gray-500 text-sm">No vulnerabilities for this filter.</p> : (
                <div className="space-y-2">
                  {filteredVulns.map(v => {
                    const dep = deps.find(d => d.id === v.dep_id);
                    return (
                      <div key={v.id} className="flex items-center justify-between p-3 bg-gray-700/30 rounded-lg">
                        <div>
                          <div className="flex items-center gap-2">
                            <span className="text-xs font-mono text-blue-300">{v.cve_id}</span>
                            <SeverityBadge s={v.severity} />
                            <span className="text-xs text-gray-500 font-mono">CVSS {v.cvss_score?.toFixed(1)}</span>
                          </div>
                          <p className="text-xs text-gray-400 mt-0.5">{dep?.package_name ?? v.dep_id} · fix: {v.fixed_version}</p>
                        </div>
                        <div className="flex items-center gap-2 ml-4 flex-shrink-0">
                          {v.patched
                            ? <span className="flex items-center gap-1 px-2 py-0.5 bg-green-500/20 text-green-400 rounded text-xs font-medium"><CheckCircle className="w-3 h-3" /> patched</span>
                            : <>
                                <span className="flex items-center gap-1 px-2 py-0.5 bg-orange-500/20 text-orange-400 rounded text-xs font-medium">pending</span>
                                <button onClick={() => patchVuln(v.id)} className="px-2 py-0.5 bg-blue-600/40 hover:bg-blue-600/70 text-blue-300 rounded text-xs">Patch</button>
                              </>}
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {licenseConflicts.length > 0 && (
              <div className="bg-gray-800 rounded-lg p-6">
                <div className="flex items-center gap-2 mb-4">
                  <AlertTriangle className="w-5 h-5 text-yellow-400" />
                  <h2 className="text-lg font-semibold text-white">License Conflicts</h2>
                </div>
                <div className="space-y-2">
                  {licenseConflicts.map(l => (
                    <div key={l.package_name} className="flex items-center justify-between p-3 bg-gray-700/30 rounded-lg">
                      <div>
                        <p className="text-sm font-medium text-white">{l.package_name}</p>
                        <div className="flex items-center gap-2 mt-0.5">
                          <span className="text-xs text-gray-400">{l.license_name}</span>
                          {l.copyleft && <span className="text-xs text-red-400 flex items-center gap-0.5"><AlertOctagon className="w-3 h-3" /> copyleft</span>}
                        </div>
                      </div>
                      <LicenseRiskBadge level={l.risk_level} />
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </>
      )}
    </div>
  );
}
