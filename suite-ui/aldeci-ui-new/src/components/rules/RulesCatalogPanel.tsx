/**
 * RulesCatalogPanel — catalog tab for RulesCatalogHub
 * Fetches GET /api/v1/rules/unified with domain/enabled filters.
 * Supports enable/disable toggle per rule.
 */

import { useCallback, useEffect, useState } from "react";
import { ToggleLeft, ToggleRight, Filter, RefreshCw, AlertCircle, ListChecks } from "lucide-react";
import { unifiedRulesApi, type UnifiedRule } from "@/lib/api";

const SEVERITY_COLOR: Record<string, string> = {
  critical: "text-red-500 bg-red-500/10",
  high: "text-orange-500 bg-orange-500/10",
  medium: "text-amber-500 bg-amber-500/10",
  low: "text-blue-400 bg-blue-400/10",
  info: "text-slate-400 bg-slate-400/10",
};

const DOMAIN_OPTIONS = ["", "sast", "dast", "secrets", "iac", "container", "cspm", "api_security"];

function SeverityBadge({ severity }: { severity: string }) {
  const cls = SEVERITY_COLOR[severity.toLowerCase()] ?? "text-slate-400 bg-slate-400/10";
  return (
    <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${cls}`}>
      {severity}
    </span>
  );
}

export function RulesCatalogPanel() {
  const [rules, setRules] = useState<UnifiedRule[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [domain, setDomain] = useState("");
  const [enabledFilter, setEnabledFilter] = useState<"" | "true" | "false">("");
  const [toggling, setToggling] = useState<string | null>(null);

  const load = useCallback(() => {
    setLoading(true);
    setError(null);
    unifiedRulesApi
      .list({
        ...(domain ? { domain } : {}),
        ...(enabledFilter !== "" ? { enabled: enabledFilter === "true" } : {}),
      })
      .then((res) => {
        const data = Array.isArray(res.data) ? res.data : [];
        setRules(data);
      })
      .catch((err) => {
        setError(err?.response?.data?.detail ?? err?.message ?? "Failed to load rules");
      })
      .finally(() => setLoading(false));
  }, [domain, enabledFilter]);

  useEffect(() => { load(); }, [load]);

  const toggle = async (rule: UnifiedRule) => {
    setToggling(rule.rule_key);
    try {
      if (rule.enabled) {
        await unifiedRulesApi.disable(rule.rule_key);
      } else {
        await unifiedRulesApi.enable(rule.rule_key);
      }
      setRules((prev) =>
        prev.map((r) => r.rule_key === rule.rule_key ? { ...r, enabled: !r.enabled } : r)
      );
    } catch {
      // leave state unchanged on error
    } finally {
      setToggling(null);
    }
  };

  return (
    <div className="flex flex-col gap-4">
      {/* Filter bar */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
          <Filter className="h-3.5 w-3.5" />
          Filters:
        </div>
        <select
          value={domain}
          onChange={(e) => setDomain(e.target.value)}
          className="rounded-md border border-border bg-card px-2 py-1 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
          aria-label="Filter by domain"
        >
          {DOMAIN_OPTIONS.map((d) => (
            <option key={d} value={d}>{d === "" ? "All domains" : d}</option>
          ))}
        </select>
        <select
          value={enabledFilter}
          onChange={(e) => setEnabledFilter(e.target.value as "" | "true" | "false")}
          className="rounded-md border border-border bg-card px-2 py-1 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
          aria-label="Filter by enabled state"
        >
          <option value="">All states</option>
          <option value="true">Enabled</option>
          <option value="false">Disabled</option>
        </select>
        <button
          onClick={load}
          disabled={loading}
          className="ml-auto flex items-center gap-1 rounded-md border border-border px-2.5 py-1 text-xs text-muted-foreground hover:text-foreground disabled:opacity-50"
          aria-label="Refresh rules"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
          Refresh
        </button>
      </div>

      {/* Error state */}
      {error && !loading && (
        <div className="flex items-center gap-2 rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
          <AlertCircle className="h-4 w-4 shrink-0" />
          {error}
        </div>
      )}

      {/* Loading skeleton */}
      {loading && (
        <div className="space-y-2">
          {Array.from({ length: 6 }).map((_, i) => (
            <div key={i} className="h-10 animate-pulse rounded-lg bg-muted/40" />
          ))}
        </div>
      )}

      {/* Empty state */}
      {!loading && !error && rules.length === 0 && (
        <div className="flex flex-col items-center gap-3 rounded-xl border border-border/60 bg-card py-16 text-center">
          <ListChecks className="h-10 w-10 text-muted-foreground/40" />
          <p className="text-sm font-medium text-muted-foreground">No rules found</p>
          <p className="text-xs text-muted-foreground/60">
            Adjust filters or register rules via POST /api/v1/rules/unified
          </p>
        </div>
      )}

      {/* Rules table */}
      {!loading && rules.length > 0 && (
        <div className="overflow-x-auto rounded-xl border border-border/60">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border/60 bg-muted/30 text-left text-muted-foreground">
                <th className="px-3 py-2.5 font-medium">Rule Key</th>
                <th className="px-3 py-2.5 font-medium">Domain</th>
                <th className="px-3 py-2.5 font-medium">Category</th>
                <th className="px-3 py-2.5 font-medium">Severity</th>
                <th className="px-3 py-2.5 font-medium">Type</th>
                <th className="px-3 py-2.5 font-medium">Engine</th>
                <th className="px-3 py-2.5 font-medium text-center">Enabled</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/40">
              {rules.map((rule) => (
                <tr
                  key={rule.rule_key}
                  className="bg-card transition-colors hover:bg-muted/20"
                >
                  <td className="max-w-[220px] truncate px-3 py-2 font-mono text-foreground" title={rule.rule_key}>
                    {rule.rule_key}
                  </td>
                  <td className="px-3 py-2 text-muted-foreground">{rule.domain}</td>
                  <td className="px-3 py-2 text-muted-foreground">{rule.category}</td>
                  <td className="px-3 py-2">
                    <SeverityBadge severity={rule.severity} />
                  </td>
                  <td className="px-3 py-2 text-muted-foreground">{rule.rule_type}</td>
                  <td className="px-3 py-2 text-muted-foreground">{rule.source_engine}</td>
                  <td className="px-3 py-2 text-center">
                    <button
                      onClick={() => toggle(rule)}
                      disabled={toggling === rule.rule_key}
                      aria-label={rule.enabled ? "Disable rule" : "Enable rule"}
                      className="inline-flex items-center justify-center disabled:opacity-50"
                    >
                      {rule.enabled ? (
                        <ToggleRight className="h-5 w-5 text-green-500" />
                      ) : (
                        <ToggleLeft className="h-5 w-5 text-muted-foreground" />
                      )}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
          <p className="border-t border-border/40 bg-muted/20 px-3 py-2 text-[10px] text-muted-foreground">
            {rules.length} rule{rules.length !== 1 ? "s" : ""} loaded
          </p>
        </div>
      )}
    </div>
  );
}
