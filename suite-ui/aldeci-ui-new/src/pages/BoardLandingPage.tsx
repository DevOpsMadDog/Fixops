/**
 * BoardLandingPage — P24 Board Member persona landing (/board)
 * Composes: Risk Posture + Financial Impact + Compliance Scorecard + Board Metrics
 * All data from real API endpoints — NO mocks.
 */

import { useEffect, useState } from "react";
import {
  riskApi,
  fairApi,
  securityBudgetApi,
  incidentCostsApi,
  complianceApi,
  execReportingApi,
} from "@/lib/api";
import { cn } from "@/lib/utils";
import {
  AlertTriangle,
  BarChart3,
  CheckCircle2,
  Clock,
  DollarSign,
  Shield,
  TrendingDown,
  TrendingUp,
  XCircle,
} from "lucide-react";

// ── Types ──────────────────────────────────────────────────────────────────

interface TopRisk {
  id?: string;
  title?: string;
  name?: string;
  severity?: string;
  risk_level?: string;
  score?: number;
  risk_score?: number;
  category?: string;
}

interface ComplianceFramework {
  framework?: string;
  name?: string;
  score?: number;
  percentage?: number;
  status?: string;
}

interface ExecSummary {
  mttr_hours?: number;
  mttd_hours?: number;
  sla_compliance_pct?: number;
  open_critical?: number;
  resolved_last_30d?: number;
  risk_score?: number;
  composite_risk_score?: number;
}

interface FinanceSummary {
  total_budget?: number;
  spent?: number;
  insurance_coverage?: number;
  incident_cost_ytd?: number;
  roi_pct?: number;
}

// ── Helpers ────────────────────────────────────────────────────────────────

function severityColor(severity?: string): string {
  switch ((severity ?? "").toLowerCase()) {
    case "critical": return "text-red-400";
    case "high":     return "text-orange-400";
    case "medium":   return "text-amber-400";
    case "low":      return "text-emerald-400";
    default:         return "text-zinc-400";
  }
}

function severityBg(severity?: string): string {
  switch ((severity ?? "").toLowerCase()) {
    case "critical": return "bg-red-500/10 border-red-500/30";
    case "high":     return "bg-orange-500/10 border-orange-500/30";
    case "medium":   return "bg-amber-500/10 border-amber-500/30";
    case "low":      return "bg-emerald-500/10 border-emerald-500/30";
    default:         return "bg-zinc-700/20 border-zinc-600/30";
  }
}

function scoreColor(score: number): string {
  if (score >= 80) return "text-emerald-400";
  if (score >= 60) return "text-amber-400";
  return "text-red-400";
}

function formatCurrency(n?: number): string {
  if (n === undefined || n === null) return "—";
  if (n >= 1_000_000) return `$${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `$${(n / 1_000).toFixed(0)}K`;
  return `$${n}`;
}

// ── Sub-components ─────────────────────────────────────────────────────────

function SectionCard({
  title,
  icon: Icon,
  children,
  loading,
  empty,
}: {
  title: string;
  icon: React.ElementType;
  children: React.ReactNode;
  loading?: boolean;
  empty?: boolean;
}) {
  return (
    <div className="rounded-xl border border-zinc-700/60 bg-zinc-800/60 p-5 flex flex-col gap-4">
      <div className="flex items-center gap-2 text-zinc-300 font-semibold text-sm tracking-wide">
        <Icon className="w-4 h-4 text-indigo-400 shrink-0" />
        {title}
      </div>
      {loading ? (
        <div className="space-y-2 animate-pulse">
          <div className="h-4 bg-zinc-700/60 rounded w-3/4" />
          <div className="h-4 bg-zinc-700/60 rounded w-1/2" />
          <div className="h-4 bg-zinc-700/60 rounded w-2/3" />
        </div>
      ) : empty ? (
        <p className="text-xs text-zinc-500 italic">No data available from backend.</p>
      ) : (
        children
      )}
    </div>
  );
}

function MetricPill({
  label,
  value,
  sub,
  color,
}: {
  label: string;
  value: string;
  sub?: string;
  color?: string;
}) {
  return (
    <div className="flex flex-col gap-0.5 rounded-lg bg-zinc-900/50 border border-zinc-700/40 px-4 py-3">
      <span className="text-xs text-zinc-500 uppercase tracking-wider">{label}</span>
      <span className={cn("text-xl font-bold tabular-nums", color ?? "text-zinc-100")}>{value}</span>
      {sub && <span className="text-xs text-zinc-500">{sub}</span>}
    </div>
  );
}

// ── Main page ──────────────────────────────────────────────────────────────

export default function BoardLandingPage() {
  const [topRisks, setTopRisks] = useState<TopRisk[]>([]);
  const [compositeScore, setCompositeScore] = useState<number | null>(null);
  const [risksLoading, setRisksLoading] = useState(true);

  const [finance, setFinance] = useState<FinanceSummary | null>(null);
  const [financeLoading, setFinanceLoading] = useState(true);

  const [frameworks, setFrameworks] = useState<ComplianceFramework[]>([]);
  const [complianceLoading, setComplianceLoading] = useState(true);

  const [execSummary, setExecSummary] = useState<ExecSummary | null>(null);
  const [execLoading, setExecLoading] = useState(true);

  // Risk posture
  useEffect(() => {
    setRisksLoading(true);
    riskApi
      .topRisks(5)
      .then((res) => {
        const data = res.data;
        const risks: TopRisk[] = Array.isArray(data)
          ? data
          : data?.risks ?? data?.items ?? data?.top_risks ?? [];
        setTopRisks(risks.slice(0, 5));
        const score = data?.composite_risk_score ?? data?.risk_score ?? null;
        if (typeof score === "number") setCompositeScore(score);
      })
      .catch(() => {
        setTopRisks([]);
      })
      .finally(() => setRisksLoading(false));
  }, []);

  // Financial impact — combine budget stats + incident costs
  useEffect(() => {
    setFinanceLoading(true);
    Promise.allSettled([
      securityBudgetApi.stats(),
      incidentCostsApi.analytics(),
      fairApi.stats(),
    ]).then(([budgetRes, costsRes, fairRes]) => {
      const budget =
        budgetRes.status === "fulfilled" ? budgetRes.value.data : null;
      const costs =
        costsRes.status === "fulfilled" ? costsRes.value.data : null;
      const fair =
        fairRes.status === "fulfilled" ? fairRes.value.data : null;

      const merged: FinanceSummary = {
        total_budget:
          budget?.total_budget ?? budget?.allocated ?? budget?.budget_total ?? undefined,
        spent: budget?.spent ?? budget?.utilized ?? undefined,
        insurance_coverage:
          costs?.insurance_coverage ?? fair?.insurance_coverage ?? undefined,
        incident_cost_ytd:
          costs?.total_cost_ytd ?? costs?.ytd_total ?? costs?.total ?? undefined,
        roi_pct: fair?.roi_pct ?? budget?.roi_pct ?? undefined,
      };

      const hasAnyValue = Object.values(merged).some((v) => v !== undefined);
      setFinance(hasAnyValue ? merged : null);
    }).finally(() => setFinanceLoading(false));
  }, []);

  // Compliance scorecard
  useEffect(() => {
    setComplianceLoading(true);
    complianceApi
      .overallStatus()
      .then((res) => {
        const data = res.data;
        const list: ComplianceFramework[] = Array.isArray(data)
          ? data
          : data?.frameworks ?? data?.items ?? [];
        setFrameworks(list.slice(0, 6));
      })
      .catch(() => setFrameworks([]))
      .finally(() => setComplianceLoading(false));
  }, []);

  // Board / exec metrics
  useEffect(() => {
    setExecLoading(true);
    execReportingApi
      .summary()
      .then((res) => {
        const data = res.data;
        setExecSummary(data?.summary ?? data ?? null);
      })
      .catch(() => setExecSummary(null))
      .finally(() => setExecLoading(false));
  }, []);

  // Derived
  const riskEmpty = !risksLoading && topRisks.length === 0 && compositeScore === null;
  const financeEmpty = !financeLoading && finance === null;
  const complianceEmpty = !complianceLoading && frameworks.length === 0;
  const execEmpty = !execLoading && execSummary === null;

  return (
    <div className="min-h-screen bg-zinc-900 text-zinc-100 p-6 space-y-6">
      {/* Page header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-zinc-50">Board Overview</h1>
          <p className="text-sm text-zinc-400 mt-1">
            Consolidated security posture for board-level review — P24 Board Member view
          </p>
        </div>
        <span className="text-xs font-medium px-2.5 py-1 rounded-full bg-indigo-500/15 text-indigo-300 border border-indigo-500/30 shrink-0">
          P24 Board Member
        </span>
      </div>

      {/* Grid: 2 columns on md+ */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-5">

        {/* 1. Risk Posture */}
        <SectionCard title="Risk Posture" icon={Shield} loading={risksLoading} empty={riskEmpty}>
          {compositeScore !== null && (
            <div className="flex items-center gap-3 pb-2 border-b border-zinc-700/40">
              <span className="text-xs text-zinc-400 uppercase tracking-wider">Composite Score</span>
              <span className={cn("text-3xl font-bold tabular-nums", scoreColor(compositeScore))}>
                {compositeScore.toFixed(0)}
              </span>
              <span className="text-xs text-zinc-500">/ 100</span>
            </div>
          )}
          <ul className="space-y-2">
            {topRisks.map((risk, i) => {
              const severity = risk.severity ?? risk.risk_level ?? "medium";
              const label = risk.title ?? risk.name ?? `Risk ${i + 1}`;
              const score = risk.score ?? risk.risk_score;
              return (
                <li
                  key={risk.id ?? i}
                  className={cn(
                    "flex items-center justify-between gap-3 rounded-lg border px-3 py-2 text-sm",
                    severityBg(severity)
                  )}
                >
                  <span className="flex items-center gap-2 truncate">
                    <AlertTriangle className={cn("w-3.5 h-3.5 shrink-0", severityColor(severity))} />
                    <span className="truncate text-zinc-200">{label}</span>
                  </span>
                  <span className={cn("shrink-0 font-semibold tabular-nums text-xs", severityColor(severity))}>
                    {score !== undefined ? score.toFixed(0) : severity.toUpperCase()}
                  </span>
                </li>
              );
            })}
          </ul>
        </SectionCard>

        {/* 2. Financial Impact */}
        <SectionCard title="Financial Impact" icon={DollarSign} loading={financeLoading} empty={financeEmpty}>
          <div className="grid grid-cols-2 gap-3">
            <MetricPill
              label="Security Budget"
              value={formatCurrency(finance?.total_budget)}
              sub="annual allocation"
              color="text-indigo-300"
            />
            <MetricPill
              label="Budget Utilized"
              value={formatCurrency(finance?.spent)}
              sub="year-to-date"
            />
            <MetricPill
              label="Incident Cost YTD"
              value={formatCurrency(finance?.incident_cost_ytd)}
              sub="remediation + downtime"
              color={finance?.incident_cost_ytd && finance.incident_cost_ytd > 0 ? "text-red-400" : undefined}
            />
            <MetricPill
              label="Insurance Coverage"
              value={formatCurrency(finance?.insurance_coverage)}
              sub="cyber policy limit"
              color="text-emerald-400"
            />
          </div>
          {finance?.roi_pct !== undefined && (
            <div className="flex items-center gap-2 text-xs text-zinc-400 mt-1">
              {finance.roi_pct >= 0 ? (
                <TrendingUp className="w-4 h-4 text-emerald-400" />
              ) : (
                <TrendingDown className="w-4 h-4 text-red-400" />
              )}
              <span>
                Security ROI:{" "}
                <span className={finance.roi_pct >= 0 ? "text-emerald-400 font-semibold" : "text-red-400 font-semibold"}>
                  {finance.roi_pct > 0 ? "+" : ""}{finance.roi_pct.toFixed(1)}%
                </span>
              </span>
            </div>
          )}
        </SectionCard>

        {/* 3. Compliance Scorecard */}
        <SectionCard title="Compliance Scorecard" icon={CheckCircle2} loading={complianceLoading} empty={complianceEmpty}>
          <div className="space-y-2.5">
            {frameworks.map((fw, i) => {
              const name = fw.framework ?? fw.name ?? `Framework ${i + 1}`;
              const pct = fw.score ?? fw.percentage ?? 0;
              const barColor =
                pct >= 80 ? "bg-emerald-500" : pct >= 60 ? "bg-amber-500" : "bg-red-500";
              const textColor = scoreColor(pct);
              return (
                <div key={name + i} className="space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-zinc-300 font-medium">{name}</span>
                    <span className={cn("font-bold tabular-nums", textColor)}>{pct.toFixed(0)}%</span>
                  </div>
                  <div className="h-1.5 rounded-full bg-zinc-700/50 overflow-hidden">
                    <div
                      className={cn("h-full rounded-full transition-all duration-700", barColor)}
                      style={{ width: `${Math.min(pct, 100)}%` }}
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </SectionCard>

        {/* 4. Board Metrics */}
        <SectionCard title="Board Metrics" icon={BarChart3} loading={execLoading} empty={execEmpty}>
          <div className="grid grid-cols-2 gap-3">
            <MetricPill
              label="MTTR"
              value={execSummary?.mttr_hours !== undefined ? `${execSummary.mttr_hours.toFixed(1)}h` : "—"}
              sub="mean time to remediate"
              color={
                execSummary?.mttr_hours !== undefined
                  ? execSummary.mttr_hours <= 24 ? "text-emerald-400" : execSummary.mttr_hours <= 72 ? "text-amber-400" : "text-red-400"
                  : undefined
              }
            />
            <MetricPill
              label="MTTD"
              value={execSummary?.mttd_hours !== undefined ? `${execSummary.mttd_hours.toFixed(1)}h` : "—"}
              sub="mean time to detect"
              color={
                execSummary?.mttd_hours !== undefined
                  ? execSummary.mttd_hours <= 4 ? "text-emerald-400" : execSummary.mttd_hours <= 24 ? "text-amber-400" : "text-red-400"
                  : undefined
              }
            />
            <MetricPill
              label="SLA Compliance"
              value={execSummary?.sla_compliance_pct !== undefined ? `${execSummary.sla_compliance_pct.toFixed(1)}%` : "—"}
              sub="within SLA targets"
              color={
                execSummary?.sla_compliance_pct !== undefined
                  ? scoreColor(execSummary.sla_compliance_pct)
                  : undefined
              }
            />
            <MetricPill
              label="Open Critical"
              value={execSummary?.open_critical !== undefined ? String(execSummary.open_critical) : "—"}
              sub="unresolved critical findings"
              color={
                execSummary?.open_critical !== undefined
                  ? execSummary.open_critical === 0 ? "text-emerald-400" : "text-red-400"
                  : undefined
              }
            />
          </div>
          {execSummary?.resolved_last_30d !== undefined && (
            <div className="flex items-center gap-2 text-xs text-zinc-400 mt-1">
              <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
              <span>
                <span className="text-emerald-400 font-semibold">{execSummary.resolved_last_30d}</span>{" "}
                findings resolved in the last 30 days
              </span>
            </div>
          )}
          {execSummary === null && !execLoading && (
            <div className="flex items-center gap-2 text-xs text-zinc-500">
              <XCircle className="w-3.5 h-3.5" />
              Exec reporting endpoint returned no data.
            </div>
          )}
        </SectionCard>
      </div>

      {/* Footer */}
      <p className="text-xs text-zinc-600 text-center pt-2">
        Data sourced live from ALdeci backend — refreshed on page load.
      </p>
    </div>
  );
}
