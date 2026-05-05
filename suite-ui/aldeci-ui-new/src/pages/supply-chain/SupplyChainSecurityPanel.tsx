/**
 * SupplyChainSecurityPanel — wired to /api/v1/supply-chain/{risks,stats}
 * Tab: SupplyChainHub > security
 */

import { useEffect, useState, useCallback } from "react";
import { motion } from "framer-motion";
import { ShieldCheck, RefreshCw, AlertTriangle, CheckCircle2, XCircle } from "lucide-react";

import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";

// ── Types ──────────────────────────────────────────────────────────────────────

interface SupplyChainRisk {
  id: string;
  risk_type?: string;
  severity?: string;
  description?: string;
  status?: string;
  supplier_id?: string;
  created_at?: string;
}

interface SupplyChainStats {
  total_suppliers?: number;
  total_components?: number;
  total_risks?: number;
  open_risks?: number;
  critical_suppliers?: number;
  eol_components?: number;
}

type FetchState = "idle" | "loading" | "ok" | "error";

// ── Helpers ────────────────────────────────────────────────────────────────────

function severityColor(s?: string): string {
  switch ((s ?? "").toLowerCase()) {
    case "critical": return "bg-red-500/15 text-red-400 border-red-500/30";
    case "high":     return "bg-orange-500/15 text-orange-400 border-orange-500/30";
    case "medium":   return "bg-amber-500/15 text-amber-400 border-amber-500/30";
    case "low":      return "bg-blue-500/15 text-blue-400 border-blue-500/30";
    default:         return "bg-slate-500/15 text-slate-400 border-slate-500/30";
  }
}

function statusIcon(status?: string) {
  switch ((status ?? "").toLowerCase()) {
    case "open":     return <AlertTriangle className="h-3.5 w-3.5 text-amber-400" />;
    case "resolved": return <CheckCircle2 className="h-3.5 w-3.5 text-green-400" />;
    case "closed":   return <XCircle className="h-3.5 w-3.5 text-slate-400" />;
    default:         return <AlertTriangle className="h-3.5 w-3.5 text-slate-400" />;
  }
}

function formatDate(iso?: string): string {
  if (!iso) return "—";
  try { return new Date(iso).toLocaleDateString(undefined, { month: "short", day: "numeric", year: "numeric" }); }
  catch { return iso; }
}

// ── Component ──────────────────────────────────────────────────────────────────

export function SupplyChainSecurityPanel() {
  const [state, setState] = useState<FetchState>("idle");
  const [risks, setRisks] = useState<SupplyChainRisk[]>([]);
  const [stats, setStats] = useState<SupplyChainStats>({});
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
      const [risksRes, statsRes] = await Promise.all([
        fetch(buildApiUrl("/api/v1/supply-chain/risks", { org_id: orgId }), { headers }),
        fetch(buildApiUrl("/api/v1/supply-chain/stats", { org_id: orgId }), { headers }),
      ]);

      if (!risksRes.ok) throw new Error(`Risks: ${risksRes.status} ${risksRes.statusText}`);

      const risksJson = await risksRes.json();
      const statsJson = statsRes.ok ? await statsRes.json() : {};

      const items: SupplyChainRisk[] = Array.isArray(risksJson)
        ? risksJson
        : Array.isArray(risksJson?.risks) ? risksJson.risks
        : Array.isArray(risksJson?.items) ? risksJson.items
        : [];

      setRisks(items);
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
    { label: "Total Risks", value: stats.total_risks ?? risks.length, color: "text-red-400" },
    { label: "Open", value: stats.open_risks ?? risks.filter(r => (r.status ?? "").toLowerCase() === "open").length, color: "text-amber-400" },
    { label: "Suppliers", value: stats.total_suppliers ?? "—", color: "text-blue-400" },
    { label: "EOL Components", value: stats.eol_components ?? "—", color: "text-orange-400" },
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

      {/* Header */}
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-medium text-muted-foreground">{risks.length} risk{risks.length !== 1 ? "s" : ""}</h3>
        <Button variant="ghost" size="sm" onClick={fetchData} className="gap-1.5 text-xs">
          <RefreshCw className="h-3.5 w-3.5" />Refresh
        </Button>
      </div>

      {risks.length === 0 ? (
        <EmptyState icon={ShieldCheck} title="No supply-chain risks" description="No supply-chain risks detected. Onboard suppliers and components to begin tracking." />
      ) : (
        <div className="rounded-lg border border-slate-700 overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-slate-800/80 text-xs text-muted-foreground">
              <tr>
                <th className="px-4 py-2.5 text-left font-medium">Description</th>
                <th className="px-4 py-2.5 text-left font-medium">Type</th>
                <th className="px-4 py-2.5 text-left font-medium">Severity</th>
                <th className="px-4 py-2.5 text-left font-medium">Status</th>
                <th className="px-4 py-2.5 text-left font-medium">Created</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-700/50">
              {risks.map((r, i) => (
                <tr key={r.id ?? i} className="hover:bg-slate-800/40 transition-colors">
                  <td className="px-4 py-3 max-w-xs">
                    <span className="line-clamp-2 text-slate-200">{r.description || "—"}</span>
                  </td>
                  <td className="px-4 py-3 text-xs text-muted-foreground">{r.risk_type ?? "—"}</td>
                  <td className="px-4 py-3">
                    <Badge className={`text-[10px] border ${severityColor(r.severity)}`}>{r.severity ?? "unknown"}</Badge>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-1.5">
                      {statusIcon(r.status)}
                      <span className="text-xs text-slate-300">{r.status ?? "—"}</span>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-xs text-muted-foreground">{formatDate(r.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </motion.div>
  );
}
