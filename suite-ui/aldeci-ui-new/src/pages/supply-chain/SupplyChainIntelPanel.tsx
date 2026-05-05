/**
 * SupplyChainIntelPanel — wired to /api/v1/supply-chain-intel/{stats,packages,vulns,malicious}
 * Tab: SupplyChainHub > intel
 */

import { useEffect, useState, useCallback } from "react";
import { motion } from "framer-motion";
import { Radar, RefreshCw, Package, ShieldAlert, Bug } from "lucide-react";

import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";

// ── Types ──────────────────────────────────────────────────────────────────────

interface ScPackage {
  id: string;
  name: string;
  ecosystem?: string;
  version?: string;
  risk_level?: string;
  is_direct?: boolean;
  license?: string;
}

interface ScVuln {
  id: string;
  cve_id?: string;
  severity?: string;
  cvss_score?: number;
  patched?: boolean;
  published_at?: string;
}

interface MaliciousPkg {
  id: string;
  name: string;
  ecosystem?: string;
  version?: string;
  malware_type?: string;
  confidence?: number;
  source?: string;
  reported_at?: string;
}

interface IntelStats {
  total_packages?: number;
  total_vulnerabilities?: number;
  total_malicious?: number;
  risky_packages?: number;
}

type FetchState = "idle" | "loading" | "ok" | "error";
type ActiveView = "packages" | "vulns" | "malicious";

// ── Helpers ────────────────────────────────────────────────────────────────────

function riskColor(level?: string): string {
  switch ((level ?? "").toLowerCase()) {
    case "critical": return "bg-red-500/15 text-red-400 border-red-500/30";
    case "high":     return "bg-orange-500/15 text-orange-400 border-orange-500/30";
    case "risky":    return "bg-amber-500/15 text-amber-400 border-amber-500/30";
    case "safe":     return "bg-green-500/15 text-green-400 border-green-500/30";
    default:         return "bg-slate-500/15 text-slate-400 border-slate-500/30";
  }
}

function severityColor(s?: string): string {
  switch ((s ?? "").toLowerCase()) {
    case "critical": return "bg-red-500/15 text-red-400 border-red-500/30";
    case "high":     return "bg-orange-500/15 text-orange-400 border-orange-500/30";
    case "medium":   return "bg-amber-500/15 text-amber-400 border-amber-500/30";
    case "low":      return "bg-blue-500/15 text-blue-400 border-blue-500/30";
    default:         return "bg-slate-500/15 text-slate-400 border-slate-500/30";
  }
}

function formatDate(iso?: string): string {
  if (!iso) return "—";
  try { return new Date(iso).toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" }); }
  catch { return iso; }
}

// ── Component ──────────────────────────────────────────────────────────────────

export function SupplyChainIntelPanel() {
  const [state, setState] = useState<FetchState>("idle");
  const [packages, setPackages] = useState<ScPackage[]>([]);
  const [vulns, setVulns] = useState<ScVuln[]>([]);
  const [malicious, setMalicious] = useState<MaliciousPkg[]>([]);
  const [stats, setStats] = useState<IntelStats>({});
  const [view, setView] = useState<ActiveView>("packages");
  const [error, setError] = useState<string>("");

  const fetchData = useCallback(async () => {
    setState("loading");
    setError("");
    const headers: HeadersInit = {
      "X-API-Key": getStoredAuthToken(),
      "X-Org-ID": getStoredOrgId(),
    };
    const orgId = getStoredOrgId();

    try {
      const [pkgRes, vulnRes, malRes, statsRes] = await Promise.all([
        fetch(buildApiUrl("/api/v1/supply-chain-intel/packages", { org_id: orgId }), { headers }),
        fetch(buildApiUrl("/api/v1/supply-chain-intel/vulns", { org_id: orgId }), { headers }),
        fetch(buildApiUrl("/api/v1/supply-chain-intel/malicious", { org_id: orgId }), { headers }),
        fetch(buildApiUrl("/api/v1/supply-chain-intel/stats", { org_id: orgId }), { headers }),
      ]);

      if (!pkgRes.ok) throw new Error(`Packages: ${pkgRes.status} ${pkgRes.statusText}`);

      const toArr = (j: unknown) =>
        Array.isArray(j) ? j
        : Array.isArray((j as Record<string,unknown>)?.packages) ? (j as Record<string,unknown[]>).packages
        : Array.isArray((j as Record<string,unknown>)?.items) ? (j as Record<string,unknown[]>).items
        : [];

      const pkgJson = await pkgRes.json();
      const vulnJson = vulnRes.ok ? await vulnRes.json() : [];
      const malJson = malRes.ok ? await malRes.json() : [];
      const statsJson = statsRes.ok ? await statsRes.json() : {};

      setPackages(toArr(pkgJson) as ScPackage[]);
      setVulns(
        Array.isArray(vulnJson) ? vulnJson
        : Array.isArray(vulnJson?.vulnerabilities) ? vulnJson.vulnerabilities
        : Array.isArray(vulnJson?.items) ? vulnJson.items
        : []
      );
      setMalicious(
        Array.isArray(malJson) ? malJson
        : Array.isArray(malJson?.packages) ? malJson.packages
        : Array.isArray(malJson?.items) ? malJson.items
        : []
      );
      setStats(statsJson ?? {});
      setState("ok");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setState("error");
    }
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  if (state === "loading" || state === "idle") return <PageSkeleton />;
  if (state === "error") return <ErrorState message={error} onRetry={fetchData} />;

  const kpis = [
    { label: "Tracked Packages", value: stats.total_packages ?? packages.length, color: "text-blue-400" },
    { label: "Vulnerabilities", value: stats.total_vulnerabilities ?? vulns.length, color: "text-orange-400" },
    { label: "Malicious Detected", value: stats.total_malicious ?? malicious.length, color: "text-red-400" },
    { label: "Risky Packages", value: stats.risky_packages ?? packages.filter(p => !["safe"].includes((p.risk_level ?? "").toLowerCase())).length, color: "text-amber-400" },
  ];

  const views: { key: ActiveView; label: string }[] = [
    { key: "packages", label: "Packages" },
    { key: "vulns", label: "Vulnerabilities" },
    { key: "malicious", label: "Malicious" },
  ];

  return (
    <motion.div
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25 }}
      className="flex flex-col gap-6"
    >
      {/* KPI bar */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        {kpis.map(k => (
          <div key={k.label} className="rounded-lg border border-slate-700 bg-slate-800/60 px-4 py-3 flex flex-col gap-1">
            <span className="text-xs text-muted-foreground">{k.label}</span>
            <span className={`text-xl font-semibold tabular-nums ${k.color}`}>{k.value}</span>
          </div>
        ))}
      </div>

      {/* View toggle + refresh */}
      <div className="flex items-center justify-between">
        <div className="flex gap-1 rounded-md border border-slate-700 p-0.5 bg-slate-800/40">
          {views.map(v => (
            <button
              key={v.key}
              onClick={() => setView(v.key)}
              className={`px-3 py-1 text-xs rounded transition-colors ${view === v.key ? "bg-indigo-600 text-white" : "text-muted-foreground hover:text-slate-200"}`}
            >
              {v.label}
            </button>
          ))}
        </div>
        <Button variant="ghost" size="sm" onClick={fetchData} className="gap-1.5 text-xs">
          <RefreshCw className="h-3.5 w-3.5" />Refresh
        </Button>
      </div>

      {/* Packages table */}
      {view === "packages" && (
        packages.length === 0 ? (
          <EmptyState icon={Package} title="No packages tracked" description="Track packages via the supply-chain intel engine to monitor risk levels and license compliance." />
        ) : (
          <div className="rounded-lg border border-slate-700 overflow-hidden">
            <table className="w-full text-sm">
              <thead className="bg-slate-800/80 text-xs text-muted-foreground">
                <tr>
                  <th className="px-4 py-2.5 text-left font-medium">Package</th>
                  <th className="px-4 py-2.5 text-left font-medium">Ecosystem</th>
                  <th className="px-4 py-2.5 text-left font-medium">Version</th>
                  <th className="px-4 py-2.5 text-left font-medium">License</th>
                  <th className="px-4 py-2.5 text-left font-medium">Risk</th>
                  <th className="px-4 py-2.5 text-left font-medium">Scope</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/50">
                {packages.map((p, i) => (
                  <tr key={p.id ?? i} className="hover:bg-slate-800/40 transition-colors">
                    <td className="px-4 py-3 font-medium text-slate-200">{p.name}</td>
                    <td className="px-4 py-3 text-xs text-muted-foreground capitalize">{p.ecosystem ?? "—"}</td>
                    <td className="px-4 py-3 text-xs text-muted-foreground font-mono">{p.version || "—"}</td>
                    <td className="px-4 py-3 text-xs text-muted-foreground">{p.license || "—"}</td>
                    <td className="px-4 py-3">
                      <Badge className={`text-[10px] border ${riskColor(p.risk_level)}`}>{p.risk_level ?? "unknown"}</Badge>
                    </td>
                    <td className="px-4 py-3 text-xs text-muted-foreground">{p.is_direct ? "Direct" : "Transitive"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      )}

      {/* Vulnerabilities table */}
      {view === "vulns" && (
        vulns.length === 0 ? (
          <EmptyState icon={Bug} title="No vulnerabilities recorded" description="Add vulnerability records to tracked packages to monitor CVE exposure across your supply chain." />
        ) : (
          <div className="rounded-lg border border-slate-700 overflow-hidden">
            <table className="w-full text-sm">
              <thead className="bg-slate-800/80 text-xs text-muted-foreground">
                <tr>
                  <th className="px-4 py-2.5 text-left font-medium">CVE</th>
                  <th className="px-4 py-2.5 text-left font-medium">Severity</th>
                  <th className="px-4 py-2.5 text-right font-medium">CVSS</th>
                  <th className="px-4 py-2.5 text-left font-medium">Patched</th>
                  <th className="px-4 py-2.5 text-left font-medium">Published</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/50">
                {vulns.map((v, i) => (
                  <tr key={v.id ?? i} className="hover:bg-slate-800/40 transition-colors">
                    <td className="px-4 py-3 font-mono text-xs text-slate-200">{v.cve_id || "—"}</td>
                    <td className="px-4 py-3">
                      <Badge className={`text-[10px] border ${severityColor(v.severity)}`}>{v.severity ?? "unknown"}</Badge>
                    </td>
                    <td className="px-4 py-3 text-right tabular-nums text-slate-300">{v.cvss_score != null ? v.cvss_score.toFixed(1) : "—"}</td>
                    <td className="px-4 py-3">
                      {v.patched
                        ? <Badge className="text-[10px] border bg-green-500/15 text-green-400 border-green-500/30">Patched</Badge>
                        : <Badge className="text-[10px] border bg-red-500/15 text-red-400 border-red-500/30">Unpatched</Badge>}
                    </td>
                    <td className="px-4 py-3 text-xs text-muted-foreground">{formatDate(v.published_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      )}

      {/* Malicious packages table */}
      {view === "malicious" && (
        malicious.length === 0 ? (
          <EmptyState icon={ShieldAlert} title="No malicious packages detected" description="The supply-chain intel engine will flag malicious packages as they are identified." />
        ) : (
          <div className="rounded-lg border border-slate-700 overflow-hidden">
            <table className="w-full text-sm">
              <thead className="bg-slate-800/80 text-xs text-muted-foreground">
                <tr>
                  <th className="px-4 py-2.5 text-left font-medium">Package</th>
                  <th className="px-4 py-2.5 text-left font-medium">Ecosystem</th>
                  <th className="px-4 py-2.5 text-left font-medium">Malware Type</th>
                  <th className="px-4 py-2.5 text-right font-medium">Confidence</th>
                  <th className="px-4 py-2.5 text-left font-medium">Source</th>
                  <th className="px-4 py-2.5 text-left font-medium">Reported</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/50">
                {malicious.map((m, i) => (
                  <tr key={m.id ?? i} className="hover:bg-slate-800/40 transition-colors">
                    <td className="px-4 py-3 font-medium text-red-300">{m.name}</td>
                    <td className="px-4 py-3 text-xs text-muted-foreground capitalize">{m.ecosystem ?? "—"}</td>
                    <td className="px-4 py-3 text-xs text-muted-foreground capitalize">{m.malware_type ?? "—"}</td>
                    <td className="px-4 py-3 text-right tabular-nums text-slate-300">
                      {m.confidence != null ? `${(m.confidence * 100).toFixed(0)}%` : "—"}
                    </td>
                    <td className="px-4 py-3 text-xs text-muted-foreground">{m.source || "—"}</td>
                    <td className="px-4 py-3 text-xs text-muted-foreground">{formatDate(m.reported_at)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      )}
    </motion.div>
  );
}
