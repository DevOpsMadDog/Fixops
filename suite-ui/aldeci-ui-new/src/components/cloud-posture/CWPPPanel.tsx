/**
 * CWPPPanel — platform tab
 * GET /api/v1/cwpp/workloads + /threats + /summary
 */

import { useEffect, useState } from "react";
import { Layers, AlertCircle, Server, ShieldAlert } from "lucide-react";
import { EmptyState } from "@/components/shared/EmptyState";

interface CwppSummary {
  total_workloads?: number;
  active_threats?: number;
  policies_active?: number;
  compliance_rate?: number;
  [key: string]: unknown;
}

interface CwppWorkload {
  workload_id: string;
  name?: string;
  type?: string;
  status?: string;
  protection_enabled?: boolean;
}

interface CwppThreat {
  threat_id: string;
  type?: string;
  severity?: string;
  status?: string;
}

function StatCard({
  label,
  value,
  icon: Icon,
  accent,
}: {
  label: string;
  value: string | number;
  icon: React.ComponentType<{ className?: string }>;
  accent: string;
}) {
  return (
    <div className="flex flex-col gap-2 rounded-xl border border-border/60 bg-card p-4 shadow-sm">
      <div className="flex items-center gap-2 text-muted-foreground text-xs font-medium uppercase tracking-wider">
        <Icon className={`h-4 w-4 ${accent}`} />
        {label}
      </div>
      <p className="text-2xl font-bold text-foreground">{value}</p>
    </div>
  );
}

export function CWPPPanel() {
  const [summary, setSummary] = useState<CwppSummary | null>(null);
  const [workloads, setWorkloads] = useState<CwppWorkload[]>([]);
  const [threats, setThreats] = useState<CwppThreat[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    Promise.all([
      fetch("/api/v1/cwpp/summary?org_id=default").then(r => r.json()).catch(() => ({})),
      fetch("/api/v1/cwpp/workloads?org_id=default&limit=8").then(r => r.json()).catch(() => ({ items: [] })),
      fetch("/api/v1/cwpp/threats?org_id=default&limit=5").then(r => r.json()).catch(() => ({ items: [] })),
    ]).then(([sumData, wlData, threatData]) => {
      if (cancelled) return;
      setSummary(sumData as CwppSummary);
      const wlRaw = wlData as { items?: CwppWorkload[] };
      const tRaw = threatData as { items?: CwppThreat[] };
      setWorkloads(wlRaw?.items ?? (Array.isArray(wlData) ? (wlData as CwppWorkload[]) : []));
      setThreats(tRaw?.items ?? (Array.isArray(threatData) ? (threatData as CwppThreat[]) : []));
      setLoading(false);
    }).catch(e => {
      if (!cancelled) { setError(String(e)); setLoading(false); }
    });
    return () => { cancelled = true; };
  }, []);

  if (loading) {
    return (
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        {[...Array(4)].map((_, i) => (
          <div key={i} className="h-24 rounded-xl bg-muted/40 animate-pulse" />
        ))}
      </div>
    );
  }

  if (error) {
    return <EmptyState icon={AlertCircle} title="Failed to load CWPP data" description={error} />;
  }

  const compRate = typeof summary?.compliance_rate === "number"
    ? `${Math.round(summary.compliance_rate * 100)}%`
    : "—";

  const SEVERITY_COLOR: Record<string, string> = {
    critical: "text-red-500",
    high: "text-orange-500",
    medium: "text-amber-500",
    low: "text-blue-400",
  };

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <StatCard label="Total Workloads" value={summary?.total_workloads ?? workloads.length} icon={Server} accent="text-indigo-400" />
        <StatCard label="Active Threats" value={summary?.active_threats ?? threats.length} icon={ShieldAlert} accent="text-red-500" />
        <StatCard label="Policies Active" value={summary?.policies_active ?? "—"} icon={Layers} accent="text-green-500" />
        <StatCard label="Compliance Rate" value={compRate} icon={AlertCircle} accent="text-amber-400" />
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div className="rounded-xl border border-border/60 bg-card overflow-hidden">
          <div className="px-4 py-3 border-b border-border/40">
            <h3 className="text-sm font-semibold">Platform Workloads</h3>
          </div>
          {workloads.length === 0 ? (
            <EmptyState icon={Server} title="No workloads registered" description="Add workloads to the CWPP platform to monitor them." />
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border/40 bg-muted/30">
                  <th className="px-4 py-2 text-left text-xs text-muted-foreground font-medium">Name</th>
                  <th className="px-4 py-2 text-left text-xs text-muted-foreground font-medium">Type</th>
                  <th className="px-4 py-2 text-left text-xs text-muted-foreground font-medium">Status</th>
                </tr>
              </thead>
              <tbody>
                {workloads.map(w => (
                  <tr key={w.workload_id} className="border-b border-border/20 hover:bg-muted/20 transition-colors">
                    <td className="px-4 py-2 font-medium truncate max-w-[160px]">{w.name ?? w.workload_id}</td>
                    <td className="px-4 py-2 text-muted-foreground capitalize">{w.type ?? "—"}</td>
                    <td className="px-4 py-2 capitalize text-muted-foreground">{w.status ?? "active"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        <div className="rounded-xl border border-border/60 bg-card overflow-hidden">
          <div className="px-4 py-3 border-b border-border/40">
            <h3 className="text-sm font-semibold">Threat Events</h3>
          </div>
          {threats.length === 0 ? (
            <EmptyState icon={ShieldAlert} title="No threats detected" description="CWPP platform is clean — no active threat events." />
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border/40 bg-muted/30">
                  <th className="px-4 py-2 text-left text-xs text-muted-foreground font-medium">Type</th>
                  <th className="px-4 py-2 text-left text-xs text-muted-foreground font-medium">Severity</th>
                  <th className="px-4 py-2 text-left text-xs text-muted-foreground font-medium">Status</th>
                </tr>
              </thead>
              <tbody>
                {threats.map(t => (
                  <tr key={t.threat_id} className="border-b border-border/20 hover:bg-muted/20 transition-colors">
                    <td className="px-4 py-2 font-medium capitalize">{t.type ?? t.threat_id}</td>
                    <td className={`px-4 py-2 capitalize font-medium ${SEVERITY_COLOR[t.severity?.toLowerCase() ?? ""] ?? "text-foreground"}`}>
                      {t.severity ?? "—"}
                    </td>
                    <td className="px-4 py-2 capitalize text-muted-foreground">{t.status ?? "active"}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
}
