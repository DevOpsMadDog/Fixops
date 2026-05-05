/**
 * WorkloadProtectionPanel — workloads tab
 * GET /api/v1/cwp/stats + /workloads + /threats
 */

import { useEffect, useState } from "react";
import { ShieldCheck, AlertCircle, Server, Siren } from "lucide-react";
import { EmptyState } from "@/components/shared/EmptyState";

interface CwpStats {
  total_workloads?: number;
  protected?: number;
  unprotected?: number;
  threats_detected?: number;
  [key: string]: unknown;
}

interface Workload {
  workload_id: string;
  name?: string;
  type?: string;
  status?: string;
  protection_enabled?: boolean;
}

interface Threat {
  threat_id: string;
  type?: string;
  severity?: string;
  workload_id?: string;
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

export function WorkloadProtectionPanel() {
  const [stats, setStats] = useState<CwpStats | null>(null);
  const [workloads, setWorkloads] = useState<Workload[]>([]);
  const [threats, setThreats] = useState<Threat[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    Promise.all([
      fetch("/api/v1/cwp/stats?org_id=default").then(r => r.json()).catch(() => ({})),
      fetch("/api/v1/cwp/workloads?org_id=default&limit=8").then(r => r.json()).catch(() => ({ items: [] })),
      fetch("/api/v1/cwp/threats?org_id=default&limit=5").then(r => r.json()).catch(() => ({ items: [] })),
    ]).then(([statsData, wlData, threatData]) => {
      if (cancelled) return;
      setStats(statsData as CwpStats);
      const wlRaw = wlData as { items?: Workload[] };
      const tRaw = threatData as { items?: Threat[] };
      setWorkloads(wlRaw?.items ?? (Array.isArray(wlData) ? (wlData as Workload[]) : []));
      setThreats(tRaw?.items ?? (Array.isArray(threatData) ? (threatData as Threat[]) : []));
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
    return <EmptyState icon={AlertCircle} title="Failed to load workload data" description={error} />;
  }

  const SEVERITY_COLOR: Record<string, string> = {
    critical: "text-red-500",
    high: "text-orange-500",
    medium: "text-amber-500",
    low: "text-blue-400",
  };

  return (
    <div className="flex flex-col gap-6">
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <StatCard label="Total Workloads" value={stats?.total_workloads ?? 0} icon={Server} accent="text-indigo-400" />
        <StatCard label="Protected" value={stats?.protected ?? 0} icon={ShieldCheck} accent="text-green-500" />
        <StatCard label="Unprotected" value={stats?.unprotected ?? 0} icon={AlertCircle} accent="text-red-500" />
        <StatCard label="Threats Detected" value={stats?.threats_detected ?? threats.length} icon={Siren} accent="text-amber-400" />
      </div>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <div className="rounded-xl border border-border/60 bg-card overflow-hidden">
          <div className="px-4 py-3 border-b border-border/40">
            <h3 className="text-sm font-semibold">Workloads</h3>
          </div>
          {workloads.length === 0 ? (
            <EmptyState icon={Server} title="No workloads" description="Register workloads to begin protection." />
          ) : (
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border/40 bg-muted/30">
                  <th className="px-4 py-2 text-left text-xs text-muted-foreground font-medium">Name</th>
                  <th className="px-4 py-2 text-left text-xs text-muted-foreground font-medium">Type</th>
                  <th className="px-4 py-2 text-left text-xs text-muted-foreground font-medium">Protected</th>
                </tr>
              </thead>
              <tbody>
                {workloads.map(w => (
                  <tr key={w.workload_id} className="border-b border-border/20 hover:bg-muted/20 transition-colors">
                    <td className="px-4 py-2 font-medium truncate max-w-[160px]">{w.name ?? w.workload_id}</td>
                    <td className="px-4 py-2 text-muted-foreground capitalize">{w.type ?? "—"}</td>
                    <td className="px-4 py-2">
                      {w.protection_enabled
                        ? <span className="text-green-500 font-medium">Yes</span>
                        : <span className="text-red-400 font-medium">No</span>}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>

        <div className="rounded-xl border border-border/60 bg-card overflow-hidden">
          <div className="px-4 py-3 border-b border-border/40">
            <h3 className="text-sm font-semibold">Active Threats</h3>
          </div>
          {threats.length === 0 ? (
            <EmptyState icon={Siren} title="No active threats" description="No runtime threats detected." />
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
