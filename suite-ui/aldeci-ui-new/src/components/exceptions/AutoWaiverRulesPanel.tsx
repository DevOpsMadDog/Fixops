/**
 * AutoWaiverRulesPanel — live auto-waiver rules from /api/v1/auto-waiver/rules
 * Shows waiver rules with conditions, expiry, approvers, and aggregate stats.
 */

import { useEffect, useState } from "react";
import { ListChecks, RefreshCw, CheckCircle, XCircle } from "lucide-react";
import { autoWaiverApi } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";

interface AutoWaiverRule {
  rule_key: string;
  conditions: Record<string, unknown>;
  max_active_count: number;
  approvers: string[];
  expires_days: number;
  enabled?: boolean;
  active_count?: number;
  created_at?: string;
}

interface AutoWaiverStats {
  total_rules: number;
  enabled_rules: number;
  disabled_rules: number;
  total_auto_waivers: number;
  active_auto_waivers: number;
}

export function AutoWaiverRulesPanel() {
  const [rules, setRules] = useState<AutoWaiverRule[]>([]);
  const [stats, setStats] = useState<AutoWaiverStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [showEnabled, setShowEnabled] = useState<boolean | null>(null);

  const load = () => {
    setLoading(true);
    setError(null);
    Promise.all([
      autoWaiverApi.rules("default"),
      autoWaiverApi.stats("default"),
    ])
      .then(([rulesRes, statsRes]) => {
        const raw = rulesRes.data;
        setRules(Array.isArray(raw) ? raw : raw?.rules ?? []);
        setStats(statsRes.data as AutoWaiverStats);
      })
      .catch((e: Error) => setError(e.message ?? "Failed to load auto-waiver rules"))
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, []);

  if (loading) {
    return (
      <div className="space-y-3 mt-4">
        {[...Array(4)].map((_, i) => (
          <div key={i} className="h-20 rounded-lg bg-muted/40 animate-pulse" />
        ))}
      </div>
    );
  }

  if (error) return <ErrorState message={error} onRetry={load} />;

  const filtered = showEnabled === null
    ? rules
    : rules.filter(r => (r.enabled ?? true) === showEnabled);

  return (
    <div className="space-y-4 mt-2">
      {/* Stats bar */}
      {stats && (
        <div className="grid grid-cols-5 gap-3">
          {[
            { label: "Total Rules", value: stats.total_rules, color: "text-slate-300" },
            { label: "Enabled", value: stats.enabled_rules, color: "text-green-400" },
            { label: "Disabled", value: stats.disabled_rules, color: "text-slate-500" },
            { label: "Auto-Waivers", value: stats.total_auto_waivers, color: "text-indigo-400" },
            { label: "Active", value: stats.active_auto_waivers, color: "text-amber-400" },
          ].map(s => (
            <div key={s.label} className="rounded-lg bg-muted/30 border border-border p-3 text-center">
              <div className={`text-2xl font-bold ${s.color}`}>{s.value ?? 0}</div>
              <div className="text-xs text-muted-foreground mt-0.5">{s.label}</div>
            </div>
          ))}
        </div>
      )}

      {/* Filter row */}
      <div className="flex items-center gap-2">
        {[
          { label: "All", value: null },
          { label: "Enabled", value: true },
          { label: "Disabled", value: false },
        ].map(f => (
          <button
            key={String(f.value)}
            onClick={() => setShowEnabled(f.value)}
            className={`px-3 py-1 rounded-full text-xs font-medium transition-colors ${
              showEnabled === f.value
                ? "bg-primary text-primary-foreground"
                : "bg-muted/40 text-muted-foreground hover:bg-muted/60"
            }`}
          >
            {f.label}
          </button>
        ))}
        <button
          onClick={load}
          className="ml-auto p-1.5 rounded-md hover:bg-muted/40 text-muted-foreground"
          aria-label="Refresh"
        >
          <RefreshCw className="h-4 w-4" />
        </button>
      </div>

      {/* Rules list */}
      {filtered.length === 0 ? (
        <EmptyState
          icon={ListChecks}
          title="No auto-waiver rules"
          description="No auto-waiver rules have been configured yet."
        />
      ) : (
        <div className="rounded-lg border border-border overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-muted/30">
              <tr>
                <th className="text-left px-4 py-2 text-xs font-medium text-muted-foreground">Rule Key</th>
                <th className="text-left px-4 py-2 text-xs font-medium text-muted-foreground">Conditions</th>
                <th className="text-left px-4 py-2 text-xs font-medium text-muted-foreground">Expires (days)</th>
                <th className="text-left px-4 py-2 text-xs font-medium text-muted-foreground">Max Count</th>
                <th className="text-left px-4 py-2 text-xs font-medium text-muted-foreground">Active</th>
                <th className="text-left px-4 py-2 text-xs font-medium text-muted-foreground">Enabled</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {filtered.map(rule => (
                <tr key={rule.rule_key} className="hover:bg-muted/20 transition-colors">
                  <td className="px-4 py-3 font-mono text-xs">{rule.rule_key}</td>
                  <td className="px-4 py-3 text-xs text-muted-foreground max-w-[200px] truncate">
                    {Object.entries(rule.conditions ?? {})
                      .map(([k, v]) => `${k}=${JSON.stringify(v)}`)
                      .join(", ") || "—"}
                  </td>
                  <td className="px-4 py-3 text-xs">{rule.expires_days}</td>
                  <td className="px-4 py-3 text-xs">{rule.max_active_count}</td>
                  <td className="px-4 py-3 text-xs">{rule.active_count ?? "—"}</td>
                  <td className="px-4 py-3">
                    {(rule.enabled ?? true) ? (
                      <CheckCircle className="h-4 w-4 text-green-400" />
                    ) : (
                      <XCircle className="h-4 w-4 text-slate-500" />
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <p className="text-xs text-muted-foreground text-right">
        {filtered.length} of {rules.length} rules
      </p>
    </div>
  );
}
