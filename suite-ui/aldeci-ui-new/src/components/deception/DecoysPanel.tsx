/**
 * DecoysPanel — wires GET /api/v1/threat-deception/decoys + /stats
 * Used by DeceptionHub "decoys" tab.
 */

import { useEffect, useState } from "react";
import { Bot, Shield, Wifi, FileText, Crosshair } from "lucide-react";
import { threatDeceptionApi } from "@/lib/api";

interface Decoy {
  id: string;
  name: string;
  decoy_type: string;
  ip_address: string;
  port: number;
  active: boolean;
  interaction_count?: number;
  campaign_id?: string;
  created_at?: string;
}

interface DeceptionStats {
  total_decoys: number;
  active_decoys: number;
  total_interactions: number;
  unique_attackers: number;
  hottest_decoy?: string;
}

const TYPE_ICON: Record<string, React.ComponentType<{ className?: string }>> = {
  honeypot: Shield,
  honeytoken: FileText,
  honeydoc: FileText,
  fake_service: Wifi,
  canary_endpoint: Crosshair,
};

const TYPE_COLOR: Record<string, string> = {
  honeypot: "text-amber-400",
  honeytoken: "text-blue-400",
  honeydoc: "text-purple-400",
  fake_service: "text-green-400",
  canary_endpoint: "text-red-400",
};

function StatBadge({ label, value }: { label: string; value: number | string }) {
  return (
    <div className="flex flex-col gap-1 rounded-xl border border-border/60 bg-card p-4 shadow-sm min-w-[110px]">
      <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">{label}</p>
      <p className="text-2xl font-bold text-foreground">{value}</p>
    </div>
  );
}

export function DecoysPanel() {
  const [decoys, setDecoys] = useState<Decoy[]>([]);
  const [stats, setStats] = useState<DeceptionStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    Promise.all([threatDeceptionApi.listDecoys(), threatDeceptionApi.stats()])
      .then(([decoysRes, statsRes]) => {
        if (cancelled) return;
        const raw = decoysRes.data;
        setDecoys(Array.isArray(raw) ? raw : (raw?.decoys ?? raw?.items ?? []));
        setStats(statsRes.data ?? null);
        setError(null);
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "Failed to load decoys");
      })
      .finally(() => { if (!cancelled) setLoading(false); });
    return () => { cancelled = true; };
  }, []);

  if (loading) {
    return (
      <div className="space-y-3 pt-2">
        {[1, 2, 3].map(i => (
          <div key={i} className="h-12 animate-pulse rounded-lg bg-muted/40" />
        ))}
      </div>
    );
  }

  if (error) {
    return (
      <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-4 text-sm text-red-400">
        {error}
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-6 pt-2">
      {/* Stats row */}
      {stats && (
        <div className="flex flex-wrap gap-3">
          <StatBadge label="Total Decoys" value={stats.total_decoys ?? decoys.length} />
          <StatBadge label="Active" value={stats.active_decoys ?? decoys.filter(d => d.active).length} />
          <StatBadge label="Interactions" value={stats.total_interactions ?? 0} />
          <StatBadge label="Unique Attackers" value={stats.unique_attackers ?? 0} />
        </div>
      )}

      {/* Decoy table */}
      {decoys.length === 0 ? (
        <div className="flex flex-col items-center gap-3 rounded-xl border border-dashed border-border/60 py-12 text-center">
          <Bot className="h-10 w-10 text-muted-foreground/40" />
          <p className="text-sm font-medium text-muted-foreground">No decoys deployed</p>
          <p className="text-xs text-muted-foreground/60">
            Deploy honeypots, canary tokens, or fake services to attract attackers.
          </p>
        </div>
      ) : (
        <div className="overflow-x-auto rounded-xl border border-border/60">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border/60 bg-muted/20">
                <th className="px-4 py-2.5 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">Name</th>
                <th className="px-4 py-2.5 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">Type</th>
                <th className="px-4 py-2.5 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">IP:Port</th>
                <th className="px-4 py-2.5 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">Interactions</th>
                <th className="px-4 py-2.5 text-left text-xs font-medium text-muted-foreground uppercase tracking-wider">Status</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/40">
              {decoys.map(d => {
                const Icon = TYPE_ICON[d.decoy_type] ?? Bot;
                const iconColor = TYPE_COLOR[d.decoy_type] ?? "text-muted-foreground";
                return (
                  <tr key={d.id} className="hover:bg-muted/10 transition-colors">
                    <td className="px-4 py-3 font-medium text-foreground flex items-center gap-2">
                      <Icon className={`h-4 w-4 ${iconColor} shrink-0`} />
                      {d.name}
                    </td>
                    <td className="px-4 py-3 text-muted-foreground capitalize">
                      {d.decoy_type.replace(/_/g, " ")}
                    </td>
                    <td className="px-4 py-3 font-mono text-xs text-muted-foreground">
                      {d.ip_address || "—"}{d.port ? `:${d.port}` : ""}
                    </td>
                    <td className="px-4 py-3 text-foreground">
                      {d.interaction_count ?? 0}
                    </td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-xs font-medium ${
                        d.active
                          ? "bg-green-500/15 text-green-400"
                          : "bg-muted/40 text-muted-foreground"
                      }`}>
                        <span className={`h-1.5 w-1.5 rounded-full ${d.active ? "bg-green-400" : "bg-muted-foreground"}`} />
                        {d.active ? "Active" : "Inactive"}
                      </span>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
