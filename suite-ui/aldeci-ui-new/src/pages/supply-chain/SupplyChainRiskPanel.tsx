/**
 * SupplyChainRiskPanel — wired to /api/v1/supply-chain/{suppliers,components,stats}
 * Tab: SupplyChainHub > risk
 */

import { useEffect, useState, useCallback } from "react";
import { motion } from "framer-motion";
import { Network, RefreshCw, Building2, Package } from "lucide-react";

import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";

// ── Types ──────────────────────────────────────────────────────────────────────

interface Supplier {
  id: string;
  name: string;
  category?: string;
  country?: string;
  risk_tier?: string;
  compliance_score?: number;
  last_assessed?: string;
}

interface Component {
  id: string;
  name: string;
  version?: string;
  component_type?: string;
  license?: string;
  cve_count?: number;
  is_eol?: boolean;
  supplier_id?: string;
}

interface SupplyChainStats {
  total_suppliers?: number;
  total_components?: number;
  total_risks?: number;
  eol_components?: number;
  critical_suppliers?: number;
}

type FetchState = "idle" | "loading" | "ok" | "error";
type ActiveView = "suppliers" | "components";

// ── Helpers ────────────────────────────────────────────────────────────────────

function tierColor(tier?: string): string {
  switch ((tier ?? "").toLowerCase()) {
    case "critical": return "bg-red-500/15 text-red-400 border-red-500/30";
    case "high":     return "bg-orange-500/15 text-orange-400 border-orange-500/30";
    case "medium":   return "bg-amber-500/15 text-amber-400 border-amber-500/30";
    case "low":      return "bg-green-500/15 text-green-400 border-green-500/30";
    default:         return "bg-slate-500/15 text-slate-400 border-slate-500/30";
  }
}

// ── Component ──────────────────────────────────────────────────────────────────

export function SupplyChainRiskPanel() {
  const [state, setState] = useState<FetchState>("idle");
  const [suppliers, setSuppliers] = useState<Supplier[]>([]);
  const [components, setComponents] = useState<Component[]>([]);
  const [stats, setStats] = useState<SupplyChainStats>({});
  const [view, setView] = useState<ActiveView>("suppliers");
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
      const [suppRes, compRes, statsRes] = await Promise.all([
        fetch(buildApiUrl("/api/v1/supply-chain/suppliers", { org_id: orgId }), { headers }),
        fetch(buildApiUrl("/api/v1/supply-chain/components", { org_id: orgId }), { headers }),
        fetch(buildApiUrl("/api/v1/supply-chain/stats", { org_id: orgId }), { headers }),
      ]);

      if (!suppRes.ok) throw new Error(`Suppliers: ${suppRes.status} ${suppRes.statusText}`);

      const suppJson = await suppRes.json();
      const compJson = compRes.ok ? await compRes.json() : [];
      const statsJson = statsRes.ok ? await statsRes.json() : {};

      const toArr = (j: unknown) =>
        Array.isArray(j) ? j
        : Array.isArray((j as Record<string,unknown>)?.items) ? (j as Record<string,unknown[]>).items
        : [];

      setSuppliers(toArr(suppJson) as Supplier[]);
      setComponents(toArr(compJson) as Component[]);
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
    { label: "Suppliers", value: stats.total_suppliers ?? suppliers.length, color: "text-blue-400" },
    { label: "Components", value: stats.total_components ?? components.length, color: "text-indigo-400" },
    { label: "EOL Components", value: stats.eol_components ?? components.filter(c => c.is_eol).length, color: "text-orange-400" },
    { label: "Critical Suppliers", value: stats.critical_suppliers ?? suppliers.filter(s => (s.risk_tier ?? "").toLowerCase() === "critical").length, color: "text-red-400" },
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
          {(["suppliers", "components"] as ActiveView[]).map(v => (
            <button
              key={v}
              onClick={() => setView(v)}
              className={`px-3 py-1 text-xs rounded capitalize transition-colors ${view === v ? "bg-indigo-600 text-white" : "text-muted-foreground hover:text-slate-200"}`}
            >
              {v}
            </button>
          ))}
        </div>
        <Button variant="ghost" size="sm" onClick={fetchData} className="gap-1.5 text-xs">
          <RefreshCw className="h-3.5 w-3.5" />Refresh
        </Button>
      </div>

      {/* Suppliers table */}
      {view === "suppliers" && (
        suppliers.length === 0 ? (
          <EmptyState icon={Building2} title="No suppliers registered" description="Register suppliers to track third-party vendor risk and compliance scores." />
        ) : (
          <div className="rounded-lg border border-slate-700 overflow-hidden">
            <table className="w-full text-sm">
              <thead className="bg-slate-800/80 text-xs text-muted-foreground">
                <tr>
                  <th className="px-4 py-2.5 text-left font-medium">Supplier</th>
                  <th className="px-4 py-2.5 text-left font-medium">Category</th>
                  <th className="px-4 py-2.5 text-left font-medium">Country</th>
                  <th className="px-4 py-2.5 text-left font-medium">Risk Tier</th>
                  <th className="px-4 py-2.5 text-right font-medium">Compliance</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/50">
                {suppliers.map((s, i) => (
                  <tr key={s.id ?? i} className="hover:bg-slate-800/40 transition-colors">
                    <td className="px-4 py-3 font-medium text-slate-200">{s.name}</td>
                    <td className="px-4 py-3 text-xs text-muted-foreground capitalize">{s.category ?? "—"}</td>
                    <td className="px-4 py-3 text-xs text-muted-foreground">{s.country || "—"}</td>
                    <td className="px-4 py-3">
                      <Badge className={`text-[10px] border ${tierColor(s.risk_tier)}`}>{s.risk_tier ?? "—"}</Badge>
                    </td>
                    <td className="px-4 py-3 text-right tabular-nums text-slate-300">
                      {s.compliance_score != null ? `${(s.compliance_score * 100).toFixed(0)}%` : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      )}

      {/* Components table */}
      {view === "components" && (
        components.length === 0 ? (
          <EmptyState icon={Package} title="No components tracked" description="Add software components to monitor EOL status, license compliance, and CVE exposure." />
        ) : (
          <div className="rounded-lg border border-slate-700 overflow-hidden">
            <table className="w-full text-sm">
              <thead className="bg-slate-800/80 text-xs text-muted-foreground">
                <tr>
                  <th className="px-4 py-2.5 text-left font-medium">Component</th>
                  <th className="px-4 py-2.5 text-left font-medium">Version</th>
                  <th className="px-4 py-2.5 text-left font-medium">Type</th>
                  <th className="px-4 py-2.5 text-left font-medium">License</th>
                  <th className="px-4 py-2.5 text-right font-medium">CVEs</th>
                  <th className="px-4 py-2.5 text-left font-medium">EOL</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-slate-700/50">
                {components.map((c, i) => (
                  <tr key={c.id ?? i} className="hover:bg-slate-800/40 transition-colors">
                    <td className="px-4 py-3 font-medium text-slate-200">{c.name}</td>
                    <td className="px-4 py-3 text-xs text-muted-foreground font-mono">{c.version || "—"}</td>
                    <td className="px-4 py-3 text-xs text-muted-foreground capitalize">{c.component_type ?? "—"}</td>
                    <td className="px-4 py-3 text-xs text-muted-foreground">{c.license || "—"}</td>
                    <td className="px-4 py-3 text-right tabular-nums">
                      <span className={(c.cve_count ?? 0) > 0 ? "text-red-400 font-semibold" : "text-slate-400"}>{c.cve_count ?? 0}</span>
                    </td>
                    <td className="px-4 py-3">
                      {c.is_eol
                        ? <Badge className="text-[10px] border bg-red-500/15 text-red-400 border-red-500/30">EOL</Badge>
                        : <Badge className="text-[10px] border bg-green-500/15 text-green-400 border-green-500/30">Active</Badge>}
                    </td>
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
