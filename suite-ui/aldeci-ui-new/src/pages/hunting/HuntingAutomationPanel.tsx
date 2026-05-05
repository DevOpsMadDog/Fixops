/**
 * HuntingAutomationPanel — wired to /api/v1/hunting-automation
 * Tab: HuntingHub > automation
 * Backends:
 *   GET /api/v1/hunting-automation/summary
 *   GET /api/v1/hunting-automation/executions
 *   GET /api/v1/hunting-automation/high-yield
 */

import { useEffect, useState, useCallback } from "react";
import { motion } from "framer-motion";
import { Bot, RefreshCw, Zap, TrendingUp, Activity, CheckCircle2 } from "lucide-react";

import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";

// ── Types ─────────────────────────────────────────────────────────────────────

interface HuntSummary {
  total_hypotheses?: number;
  validated_hypotheses?: number;
  total_executions?: number;
  high_yield_queries?: number;
  success_rate?: number;
}

interface Execution {
  id?: string;
  query_id?: string;
  hypothesis_id?: string;
  status?: string;
  findings_count?: number;
  duration_ms?: number;
  executed_at?: string;
  query_text?: string;
}

interface HighYieldQuery {
  id?: string;
  query_text?: string;
  hypothesis_id?: string;
  yield_score?: number;
  execution_count?: number;
  avg_findings?: number;
}

type FetchState = "idle" | "loading" | "ok" | "error";

// ── Helpers ───────────────────────────────────────────────────────────────────

function execStatusColor(status?: string): string {
  switch ((status ?? "").toLowerCase()) {
    case "completed":
    case "success":
      return "bg-green-500/15 text-green-400 border-green-500/30";
    case "running":
    case "in_progress":
      return "bg-blue-500/15 text-blue-400 border-blue-500/30";
    case "failed":
    case "error":
      return "bg-red-500/15 text-red-400 border-red-500/30";
    default:
      return "bg-slate-500/15 text-slate-400 border-slate-500/30";
  }
}

function formatMs(ms?: number): string {
  if (ms == null) return "—";
  if (ms < 1000) return `${ms}ms`;
  return `${(ms / 1000).toFixed(1)}s`;
}

function formatDate(iso?: string): string {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleString(undefined, {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
    });
  } catch {
    return iso;
  }
}

// ── Component ─────────────────────────────────────────────────────────────────

export function HuntingAutomationPanel() {
  const [state, setState] = useState<FetchState>("idle");
  const [summary, setSummary] = useState<HuntSummary>({});
  const [executions, setExecutions] = useState<Execution[]>([]);
  const [highYield, setHighYield] = useState<HighYieldQuery[]>([]);
  const [error, setError] = useState<string>("");

  const fetchData = useCallback(async () => {
    setState("loading");
    setError("");
    const token = getStoredAuthToken();
    const orgId = getStoredOrgId();
    const headers: HeadersInit = {
      "X-API-Key": token,
      "X-Org-ID": orgId,
    };

    try {
      const [sumRes, execRes, hyRes] = await Promise.all([
        fetch(buildApiUrl("/api/v1/hunting-automation/summary"), { headers }),
        fetch(buildApiUrl("/api/v1/hunting-automation/executions"), { headers }),
        fetch(buildApiUrl("/api/v1/hunting-automation/high-yield"), { headers }),
      ]);

      if (!sumRes.ok) throw new Error(`Summary: ${sumRes.status} ${sumRes.statusText}`);

      const sumJson: HuntSummary = sumRes.ok ? await sumRes.json() : {};
      const execJson = execRes.ok ? await execRes.json() : [];
      const hyJson = hyRes.ok ? await hyRes.json() : [];

      const execItems: Execution[] = Array.isArray(execJson)
        ? execJson
        : Array.isArray(execJson?.executions)
        ? execJson.executions
        : Array.isArray(execJson?.items)
        ? execJson.items
        : [];

      const hyItems: HighYieldQuery[] = Array.isArray(hyJson)
        ? hyJson
        : Array.isArray(hyJson?.queries)
        ? hyJson.queries
        : Array.isArray(hyJson?.items)
        ? hyJson.items
        : [];

      setSummary(sumJson ?? {});
      setExecutions(execItems);
      setHighYield(hyItems);
      setState("ok");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setState("error");
    }
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  if (state === "loading" || state === "idle") return <PageSkeleton />;
  if (state === "error") return <ErrorState message={error} onRetry={fetchData} />;

  const successPct =
    summary.success_rate != null
      ? `${(summary.success_rate * 100).toFixed(0)}%`
      : executions.length > 0
      ? `${Math.round(
          (executions.filter(e =>
            ["completed", "success"].includes((e.status ?? "").toLowerCase())
          ).length /
            executions.length) *
            100
        )}%`
      : "—";

  const kpis = [
    {
      label: "Hypotheses",
      value: summary.total_hypotheses ?? "—",
      icon: Bot,
      color: "text-indigo-400",
    },
    {
      label: "Validated",
      value: summary.validated_hypotheses ?? "—",
      icon: CheckCircle2,
      color: "text-green-400",
    },
    {
      label: "Executions",
      value: summary.total_executions ?? executions.length,
      icon: Activity,
      color: "text-blue-400",
    },
    {
      label: "Success Rate",
      value: successPct,
      icon: TrendingUp,
      color: "text-amber-400",
    },
  ];

  const hasData = executions.length > 0 || highYield.length > 0;

  return (
    <motion.div
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25 }}
      className="flex flex-col gap-6"
    >
      {/* KPI bar */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        {kpis.map(k => {
          const Icon = k.icon;
          return (
            <div
              key={k.label}
              className="rounded-lg border border-slate-700 bg-slate-800/60 px-4 py-3 flex flex-col gap-1"
            >
              <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
                <Icon className={`h-3.5 w-3.5 ${k.color}`} />
                {k.label}
              </div>
              <span className="text-xl font-semibold tabular-nums">{String(k.value)}</span>
            </div>
          );
        })}
      </div>

      <div className="flex items-center justify-between">
        <h3 className="text-sm font-medium text-muted-foreground">Automation telemetry</h3>
        <Button variant="ghost" size="sm" onClick={fetchData} className="gap-1.5 text-xs">
          <RefreshCw className="h-3.5 w-3.5" />
          Refresh
        </Button>
      </div>

      {!hasData ? (
        <EmptyState
          title="No automation data"
          description="Run hypothesis-driven automated hunts to populate execution telemetry here."
          icon={Bot}
        />
      ) : (
        <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
          {/* Recent Executions */}
          <div className="flex flex-col gap-3">
            <h4 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground flex items-center gap-1.5">
              <Activity className="h-3.5 w-3.5 text-blue-400" />
              Recent Executions
            </h4>
            {executions.length === 0 ? (
              <p className="text-xs text-muted-foreground">No executions recorded.</p>
            ) : (
              <div className="rounded-lg border border-slate-700 overflow-hidden">
                <table className="w-full text-sm">
                  <thead className="bg-slate-800/80 text-xs text-muted-foreground">
                    <tr>
                      <th className="px-3 py-2 text-left font-medium">Status</th>
                      <th className="px-3 py-2 text-right font-medium">Findings</th>
                      <th className="px-3 py-2 text-right font-medium">Duration</th>
                      <th className="px-3 py-2 text-left font-medium">Executed</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-slate-700/50">
                    {executions.slice(0, 8).map((ex, i) => (
                      <tr key={ex.id ?? i} className="hover:bg-slate-800/40 transition-colors">
                        <td className="px-3 py-2.5">
                          <Badge className={`text-[10px] border ${execStatusColor(ex.status)}`}>
                            {ex.status ?? "unknown"}
                          </Badge>
                        </td>
                        <td className="px-3 py-2.5 text-right tabular-nums text-slate-300">
                          {ex.findings_count ?? 0}
                        </td>
                        <td className="px-3 py-2.5 text-right text-xs text-muted-foreground">
                          {formatMs(ex.duration_ms)}
                        </td>
                        <td className="px-3 py-2.5 text-xs text-muted-foreground">
                          {formatDate(ex.executed_at)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>

          {/* High-Yield Queries */}
          <div className="flex flex-col gap-3">
            <h4 className="text-xs font-semibold uppercase tracking-wide text-muted-foreground flex items-center gap-1.5">
              <Zap className="h-3.5 w-3.5 text-amber-400" />
              High-Yield Queries
            </h4>
            {highYield.length === 0 ? (
              <p className="text-xs text-muted-foreground">No high-yield queries identified yet.</p>
            ) : (
              <div className="flex flex-col gap-2">
                {highYield.slice(0, 6).map((q, i) => (
                  <div
                    key={q.id ?? i}
                    className="rounded-lg border border-slate-700 bg-slate-800/40 px-3 py-2.5 flex flex-col gap-1"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="text-xs font-medium text-slate-200 line-clamp-1">
                        {q.query_text ?? `Query ${i + 1}`}
                      </span>
                      {q.yield_score != null && (
                        <span className="text-[10px] font-semibold text-amber-400 shrink-0">
                          {(q.yield_score * 100).toFixed(0)}% yield
                        </span>
                      )}
                    </div>
                    <div className="flex items-center gap-3 text-[10px] text-muted-foreground">
                      <span>{q.execution_count ?? 0} runs</span>
                      {q.avg_findings != null && (
                        <span>{q.avg_findings.toFixed(1)} avg findings</span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </motion.div>
  );
}
