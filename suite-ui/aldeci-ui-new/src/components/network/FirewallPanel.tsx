/**
 * FirewallPanel — wires GET /api/v1/firewall-policy/stats and
 * GET /api/v1/firewall-policy/firewalls (with per-firewall rules).
 * Used by NetworkSegmentationHub "firewall" tab.
 */

import { useEffect, useState } from "react";
import { AlertTriangle, ShieldCheck, Flame, ListChecks, Eye } from "lucide-react";
import api from "@/lib/api";

interface FirewallStats {
  total_firewalls?: number;
  total_rules?: number;
  unused_rules?: number;
  conflicting_rules?: number;
  firewalls?: Firewall[];
}

interface Firewall {
  id: string;
  name: string;
  fw_type?: string;
  management_ip?: string;
  description?: string;
  rule_count?: number;
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

const TYPE_COLOR: Record<string, string> = {
  paloalto: "bg-orange-500/20 text-orange-400",
  cisco: "bg-sky-500/20 text-sky-400",
  fortinet: "bg-red-500/20 text-red-400",
  checkpoint: "bg-purple-500/20 text-purple-400",
  iptables: "bg-emerald-500/20 text-emerald-400",
  pfsense: "bg-indigo-500/20 text-indigo-400",
};

export function FirewallPanel() {
  const [stats, setStats] = useState<FirewallStats | null>(null);
  const [firewalls, setFirewalls] = useState<Firewall[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    Promise.all([
      api.get<FirewallStats>("/api/v1/firewall-policy/stats").catch(() => null),
      api.get<Firewall[] | { firewalls?: Firewall[]; items?: Firewall[] }>(
        "/api/v1/firewall-policy/firewalls"
      ).catch(() => null),
    ])
      .then(([statsRes, fwRes]) => {
        if (cancelled) return;
        if (statsRes?.data) setStats(statsRes.data);

        const raw = fwRes?.data;
        const list: Firewall[] = raw
          ? Array.isArray(raw)
            ? (raw as Firewall[])
            : ((raw as { firewalls?: Firewall[]; items?: Firewall[] }).firewalls ??
               (raw as { firewalls?: Firewall[]; items?: Firewall[] }).items ??
               [])
          : [];
        setFirewalls(list);
      })
      .catch((err: unknown) => {
        if (!cancelled)
          setError(err instanceof Error ? err.message : "Failed to load firewall data");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => { cancelled = true; };
  }, []);

  if (loading) {
    return (
      <div className="flex flex-col gap-4 animate-pulse">
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="h-24 rounded-xl border border-border/40 bg-muted/30" />
          ))}
        </div>
        <div className="h-56 rounded-xl border border-border/40 bg-muted/30" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center gap-2 rounded-xl border border-destructive/40 bg-destructive/10 p-4 text-destructive text-sm">
        <AlertTriangle className="h-4 w-4 shrink-0" />
        {error}
      </div>
    );
  }

  if (!stats && firewalls.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center gap-3 rounded-xl border border-dashed border-border/60 py-16 text-center text-muted-foreground">
        <Flame className="h-8 w-8 opacity-40" />
        <p className="text-sm font-medium">No firewalls registered</p>
        <p className="text-xs opacity-70">
          Register a firewall via POST /api/v1/firewall-policy/firewalls to begin rule analysis.
        </p>
      </div>
    );
  }

  const unusedRules = stats?.unused_rules ?? 0;
  const conflictingRules = stats?.conflicting_rules ?? 0;

  return (
    <div className="flex flex-col gap-6">
      {/* KPI row */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <StatCard
          label="Firewalls"
          value={stats?.total_firewalls ?? firewalls.length}
          icon={ShieldCheck}
          accent="text-indigo-400"
        />
        <StatCard
          label="Total Rules"
          value={stats?.total_rules ?? "—"}
          icon={ListChecks}
          accent="text-sky-400"
        />
        <StatCard
          label="Unused Rules"
          value={unusedRules}
          icon={Eye}
          accent={unusedRules > 0 ? "text-amber-400" : "text-emerald-400"}
        />
        <StatCard
          label="Conflicts"
          value={conflictingRules}
          icon={AlertTriangle}
          accent={conflictingRules > 0 ? "text-red-400" : "text-emerald-400"}
        />
      </div>

      {/* Firewalls table */}
      {firewalls.length > 0 && (
        <div className="rounded-xl border border-border/60 bg-card shadow-sm overflow-hidden">
          <div className="px-4 py-3 border-b border-border/50">
            <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Registered Firewalls
            </p>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border/40 bg-muted/20">
                  <th className="px-4 py-2 text-left text-xs font-medium text-muted-foreground">Name</th>
                  <th className="px-4 py-2 text-left text-xs font-medium text-muted-foreground">Type</th>
                  <th className="px-4 py-2 text-left text-xs font-medium text-muted-foreground">Management IP</th>
                  <th className="px-4 py-2 text-left text-xs font-medium text-muted-foreground">Rules</th>
                  <th className="px-4 py-2 text-left text-xs font-medium text-muted-foreground">Description</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/30">
                {firewalls.slice(0, 12).map((fw) => (
                  <tr key={fw.id} className="hover:bg-muted/20 transition-colors">
                    <td className="px-4 py-2.5 font-medium text-foreground">{fw.name}</td>
                    <td className="px-4 py-2.5">
                      <span
                        className={`inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium capitalize ${
                          TYPE_COLOR[fw.fw_type?.toLowerCase() ?? ""] ??
                          "bg-muted/40 text-muted-foreground"
                        }`}
                      >
                        {fw.fw_type ?? "unknown"}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 font-mono text-xs text-muted-foreground">
                      {fw.management_ip || "—"}
                    </td>
                    <td className="px-4 py-2.5 text-muted-foreground">
                      {fw.rule_count ?? "—"}
                    </td>
                    <td className="px-4 py-2.5 text-xs text-muted-foreground max-w-xs truncate">
                      {fw.description || "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
