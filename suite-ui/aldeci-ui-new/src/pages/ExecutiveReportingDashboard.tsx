/**
 * Executive Reporting Dashboard
 *
 * Board-level reporting, KPI tracking, and executive summaries.
 *   1. KPI cards from /api/v1/exec-reporting/summary
 *   2. Reports table (list from /api/v1/exec-reporting/reports)
 *   3. KPI panel (from /api/v1/exec-reporting/kpis)
 *   4. Board presentations panel (from /api/v1/exec-reporting/board-presentations)
 *
 * API: GET /api/v1/exec-reporting/{reports,kpis,board-presentations,summary}
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  BarChart3, FileText, TrendingUp, TrendingDown, Minus,
  RefreshCw, Users, CheckCircle, AlertTriangle, Clock,
  Presentation, Target,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── API helpers ────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "X-API-Key": API_KEY },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ── Mock data (fallback) ───────────────────────────────────────

const MOCK_REPORTS = [
  { id: "RPT-001", report_type: "monthly",    title: "April 2026 Security Summary",           period_start: "2026-04-01", period_end: "2026-04-30", status: "draft",     created_by: "CISO",     created_at: "2026-04-16T08:00:00Z" },
  { id: "RPT-002", report_type: "board",      title: "Q1 2026 Board Security Briefing",       period_start: "2026-01-01", period_end: "2026-03-31", status: "published", created_by: "CISO",     created_at: "2026-04-01T10:00:00Z" },
  { id: "RPT-003", report_type: "quarterly",  title: "Q1 2026 Security Operations Report",    period_start: "2026-01-01", period_end: "2026-03-31", status: "published", created_by: "SecOps",   created_at: "2026-04-05T09:00:00Z" },
  { id: "RPT-004", report_type: "ciso",       title: "CISO Weekly — Week 15",                 period_start: "2026-04-07", period_end: "2026-04-13", status: "published", created_by: "CISO",     created_at: "2026-04-14T07:30:00Z" },
  { id: "RPT-005", report_type: "weekly",     title: "Week 14 Security Operations",           period_start: "2026-03-31", period_end: "2026-04-06", status: "archived",  created_by: "SecOps",   created_at: "2026-04-07T08:00:00Z" },
  { id: "RPT-006", report_type: "monthly",    title: "March 2026 Security Summary",           period_start: "2026-03-01", period_end: "2026-03-31", status: "published", created_by: "CISO",     created_at: "2026-04-01T08:00:00Z" },
];

const MOCK_KPIS = [
  { id: "KPI-001", kpi_name: "MTTD",                kpi_value: 2.4,  target_value: 4.0,   kpi_unit: "hours",   status: "on_track",  trend: "improving" },
  { id: "KPI-002", kpi_name: "MTTR",                kpi_value: 18.5, target_value: 24.0,  kpi_unit: "hours",   status: "on_track",  trend: "improving" },
  { id: "KPI-003", kpi_name: "Patch Compliance",    kpi_value: 87.0, target_value: 95.0,  kpi_unit: "%",       status: "at_risk",   trend: "stable"    },
  { id: "KPI-004", kpi_name: "Vuln Closure Rate",   kpi_value: 94.0, target_value: 90.0,  kpi_unit: "%",       status: "on_track",  trend: "improving" },
  { id: "KPI-005", kpi_name: "Security Awareness",  kpi_value: 71.0, target_value: 85.0,  kpi_unit: "%",       status: "at_risk",   trend: "stable"    },
  { id: "KPI-006", kpi_name: "Critical Vulns Open", kpi_value: 12.0, target_value: 5.0,   kpi_unit: "count",   status: "off_track", trend: "declining" },
  { id: "KPI-007", kpi_name: "MFA Coverage",        kpi_value: 98.2, target_value: 100.0, kpi_unit: "%",       status: "on_track",  trend: "improving" },
  { id: "KPI-008", kpi_name: "Risk Score",          kpi_value: 42.0, target_value: 30.0,  kpi_unit: "score",   status: "at_risk",   trend: "stable"    },
];

const MOCK_BOARD_PRESENTATIONS = [
  { id: "BP-001", title: "Q1 2026 Board Security Update", presentation_date: "2026-04-15", audience: "board",           risk_summary: "Ransomware threat landscape elevated. Critical vuln backlog at 12 items.", action_items: ["Approve $500K IR retainer", "Review cyber insurance renewal"], created_at: "2026-04-10T09:00:00Z" },
  { id: "BP-002", title: "Audit Committee Briefing Q1",   presentation_date: "2026-04-08", audience: "audit_committee", risk_summary: "SOC 2 Type II audit on track. Evidence collection 94% complete.",            action_items: ["Approve SOC 2 auditor engagement", "Review access control policy"], created_at: "2026-04-04T10:00:00Z" },
  { id: "BP-003", title: "Investor Security Due Diligence", presentation_date: "2026-03-20", audience: "investor",      risk_summary: "Security maturity at Level 3. Zero material breaches in 18 months.",       action_items: ["Provide pentest report summary"], created_at: "2026-03-15T11:00:00Z" },
];

const MOCK_SUMMARY = {
  kpi_summary: { on_track: 4, at_risk: 3, off_track: 1 },
  recent_reports: MOCK_REPORTS.slice(0, 3),
  board_presentations_count: 3,
  posture_trend: "stable",
};

// ── Helpers ────────────────────────────────────────────────────

function ReportTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    weekly:    "border-slate-500/30 text-slate-400 bg-slate-500/10",
    monthly:   "border-blue-500/30 text-blue-400 bg-blue-500/10",
    quarterly: "border-purple-500/30 text-purple-400 bg-purple-500/10",
    board:     "border-amber-500/30 text-amber-400 bg-amber-500/10",
    ciso:      "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[type] ?? "border-border text-muted-foreground")}>
      {type}
    </Badge>
  );
}

function ReportStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    draft:     "border-amber-500/30 text-amber-400 bg-amber-500/10",
    published: "border-green-500/30 text-green-400 bg-green-500/10",
    archived:  "border-slate-500/30 text-slate-400 bg-slate-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border text-muted-foreground")}>
      {status}
    </Badge>
  );
}

function KpiStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    on_track:  "border-green-500/30 text-green-400 bg-green-500/10",
    at_risk:   "border-amber-500/30 text-amber-400 bg-amber-500/10",
    off_track: "border-red-500/30 text-red-400 bg-red-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border", map[status] ?? "border-border text-muted-foreground")}>
      {status.replace(/_/g, " ")}
    </Badge>
  );
}

function TrendIcon({ trend }: { trend: string }) {
  if (trend === "improving") return <TrendingUp className="h-3.5 w-3.5 text-green-400" />;
  if (trend === "declining") return <TrendingDown className="h-3.5 w-3.5 text-red-400" />;
  return <Minus className="h-3.5 w-3.5 text-muted-foreground" />;
}

function AudienceBadge({ audience }: { audience: string }) {
  const map: Record<string, string> = {
    board:           "border-purple-500/30 text-purple-400 bg-purple-500/10",
    audit_committee: "border-blue-500/30 text-blue-400 bg-blue-500/10",
    executive:       "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
    investor:        "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[audience] ?? "border-border text-muted-foreground")}>
      {audience.replace(/_/g, " ")}
    </Badge>
  );
}

// ── Interfaces ─────────────────────────────────────────────────

interface ExecReport {
  id: string;
  report_type: string;
  title: string;
  period_start: string;
  period_end: string;
  status: string;
  created_by: string;
  created_at: string;
}

interface ExecKpi {
  id: string;
  kpi_name: string;
  kpi_value: number;
  target_value: number;
  kpi_unit: string;
  status: string;
  trend: string;
}

interface BoardPresentation {
  id: string;
  title: string;
  presentation_date: string;
  audience: string;
  risk_summary?: string;
  action_items?: string[];
  created_at: string;
}

interface ExecSummary {
  kpi_summary: { on_track: number; at_risk: number; off_track: number };
  recent_reports: ExecReport[];
  board_presentations_count: number;
  posture_trend: string;
}

// ── Component ──────────────────────────────────────────────────

export default function ExecutiveReportingDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [dataLoading, setDataLoading] = useState(false);
  const [liveData, setLiveData] = useState<{
  const [loading, setLoading] = useState(true);
    reports: ExecReport[] | null;
    kpis: ExecKpi[] | null;
    boards: BoardPresentation[] | null;
    summary: ExecSummary | null;
  }>({ reports: null, kpis: null, boards: null, summary: null });

  const fetchData = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/exec-reporting/reports?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/exec-reporting/kpis?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/exec-reporting/board-presentations?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/exec-reporting/summary?org_id=${ORG_ID}`),
    ]).then(([reportsRes, kpisRes, boardsRes, summaryRes]) => {
      setLiveData({
        reports: reportsRes.status  === "fulfilled" ? reportsRes.value  : null,
        kpis:    kpisRes.status     === "fulfilled" ? kpisRes.value     : null,
        boards:  boardsRes.status   === "fulfilled" ? boardsRes.value   : null,
        summary: summaryRes.status  === "fulfilled" ? summaryRes.value  : null,
      });
    }).finally(() => setDataLoading(false));
  };

  useEffect(() => { fetchData(); }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchData();
    setTimeout(() => setRefreshing(false), 800);
  };

  // Resolved data — live ?? mock
  const reports = liveData.reports ?? MOCK_REPORTS;
  const kpis    = liveData.kpis    ?? MOCK_KPIS;
  const boards  = liveData.boards  ?? MOCK_BOARD_PRESENTATIONS;
  const summary = liveData.summary ?? MOCK_SUMMARY;

  const publishedCount = reports.filter((r: ExecReport) => r.status === "published").length;
  const draftCount     = reports.filter((r: ExecReport) => r.status === "draft").length;
  const onTrackKpis    = summary?.kpi_summary?.on_track  ?? kpis.filter((k: ExecKpi) => k.status === "on_track").length;
  const atRiskKpis     = summary?.kpi_summary?.at_risk   ?? kpis.filter((k: ExecKpi) => k.status === "at_risk").length;
  const offTrackKpis   = summary?.kpi_summary?.off_track ?? kpis.filter((k: ExecKpi) => k.status === "off_track").length;

  if (loading) return (
    <div className="space-y-4 p-6">
      {[1, 2, 3].map((i) => (
        <div key={i} className="h-24 rounded-lg bg-zinc-800/50 animate-pulse" />
      ))}
    </div>
  );

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      {/* Header */}
      <PageHeader
        title="Executive Reporting"
        description="Board-level security reporting, KPI tracking, and executive briefings"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        
    setLoading(false);}
      />

      {/* KPI cards */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Published Reports"  value={publishedCount}                                 icon={FileText}      trend="up"     />
        <KpiCard title="KPIs On Track"      value={`${onTrackKpis} / ${kpis.length}`}             icon={CheckCircle}   trend="stable" className="border-green-500/20" />
        <KpiCard title="KPIs At Risk"       value={atRiskKpis}                                    icon={AlertTriangle} trend="down"   className="border-amber-500/20" />
        <KpiCard title="Board Decks"        value={summary?.board_presentations_count ?? boards.length} icon={Presentation} trend="stable" className="border-purple-500/20" />
      </div>

      {/* Reports Table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <FileText className="h-4 w-4 text-blue-400" />
              Executive Reports
            </CardTitle>
            <div className="flex items-center gap-2">
              {draftCount > 0 && (
                <Badge className="text-[10px] border border-amber-500/30 text-amber-400 bg-amber-500/10">
                  {draftCount} draft
                </Badge>
              )}
              <Badge className="text-[10px] border border-border text-muted-foreground">
                {reports.length} total
              </Badge>
            </div>
          </div>
          <CardDescription className="text-xs">Security reports for all audiences — board, CISO, audit committee</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Title</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Period</TableHead>
                  <TableHead className="text-[11px] h-8">Created By</TableHead>
                  <TableHead className="text-[11px] h-8">Created</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {reports.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  reports.map((r: ExecReport) => (
                  <TableRow key={r.id} className="hover:bg-muted/30">
                    <TableCell className="py-2 text-xs font-medium max-w-[240px] truncate">{r.title}</TableCell>
                    <TableCell className="py-2"><ReportTypeBadge type={r.report_type ?? "monthly"} /></TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground whitespace-nowrap">
                      {r.period_start} → {r.period_end}
                    </TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{r.created_by}</TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">
                      {r.created_at ? new Date(r.created_at).toLocaleDateString() : "—"}
                    </TableCell>
                    <TableCell className="py-2"><ReportStatusBadge status={r.status ?? "draft"} /></TableCell>
                  </TableRow>
                ))}
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* KPIs + Board Presentations */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* KPI Panel */}
        <Card>
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <Target className="h-4 w-4 text-cyan-400" />
                Key Performance Indicators
              </CardTitle>
              <div className="flex items-center gap-1.5 text-[10px]">
                <span className="text-green-400 font-semibold">{onTrackKpis} on track</span>
                <span className="text-muted-foreground">·</span>
                <span className="text-amber-400 font-semibold">{atRiskKpis} at risk</span>
                <span className="text-muted-foreground">·</span>
                <span className="text-red-400 font-semibold">{offTrackKpis} off track</span>
              </div>
            </div>
            <CardDescription className="text-xs">Security KPIs vs targets with trend tracking</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">KPI</TableHead>
                    <TableHead className="text-[11px] h-8 text-right">Value</TableHead>
                    <TableHead className="text-[11px] h-8 text-right">Target</TableHead>
                    <TableHead className="text-[11px] h-8 text-center">Trend</TableHead>
                    <TableHead className="text-[11px] h-8">Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {kpis.length === 0 ? (
                    <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                      <p className="text-lg font-medium">No data available</p>
                      <p className="text-sm">Data will appear here once available</p>
                    </div>
                  ) : (
                    kpis.map((k: ExecKpi) => (
                    <TableRow key={k.id ?? k.kpi_name} className="hover:bg-muted/30">
                      <TableCell className="py-2 text-xs font-medium">{k.kpi_name}</TableCell>
                      <TableCell className="py-2 text-right">
                        <span className={cn("text-xs font-bold tabular-nums", k.status === "on_track" ? "text-green-400" : k.status === "at_risk" ? "text-amber-400" : "text-red-400")}>
                          {k.kpi_value}{k.kpi_unit && k.kpi_unit !== "count" ? k.kpi_unit : ""}
                        </span>
                      </TableCell>
                      <TableCell className="py-2 text-right text-[11px] text-muted-foreground tabular-nums">
                        {k.target_value}{k.kpi_unit && k.kpi_unit !== "count" ? k.kpi_unit : ""}
                      </TableCell>
                      <TableCell className="py-2 text-center">
                        <div className="flex items-center justify-center">
                          <TrendIcon trend={k.trend ?? "stable"} />
                        </div>
                      </TableCell>
                      <TableCell className="py-2"><KpiStatusBadge status={k.status ?? "on_track"} /></TableCell>
                    </TableRow>
                  ))}
                  )}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>

        {/* Board Presentations */}
        <Card className="border-purple-500/20">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-purple-400">
              <Presentation className="h-4 w-4" />
              Board Presentations
            </CardTitle>
            <CardDescription className="text-xs">Recent board and executive security briefings</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {boards.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                <p className="text-lg font-medium">No data available</p>
                <p className="text-sm">Data will appear here once available</p>
              </div>
            ) : (
              boards.map((bp: BoardPresentation) => (
              <div key={bp.id} className="rounded-lg border border-border bg-muted/20 p-3 space-y-2">
                <div className="flex items-start justify-between gap-2">
                  <span className="text-xs font-semibold leading-tight">{bp.title}</span>
                  <AudienceBadge audience={bp.audience ?? "board"} />
                </div>
                <div className="flex items-center gap-3 text-[11px] text-muted-foreground">
                  <span className="flex items-center gap-1">
                    <Clock className="h-3 w-3" />
                    {bp.presentation_date}
                  </span>
                  <span className="flex items-center gap-1">
                    <Users className="h-3 w-3" />
                    {(bp.audience ?? "board").replace(/_/g, " ")}
                  </span>
                </div>
                {bp.risk_summary && (
                  <p className="text-[11px] text-muted-foreground leading-relaxed line-clamp-2">
                    {bp.risk_summary}
                  </p>
                )}
                {bp.action_items && bp.action_items.length > 0 && (
                  <div className="space-y-1">
                    {bp.action_items.slice(0, 2).map((item: string, i: number) => (
                      <div key={i} className="flex items-center gap-1.5 text-[10px] text-muted-foreground">
                        <CheckCircle className="h-2.5 w-2.5 shrink-0 text-green-400" />
                        {item}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ))}
            )}
          </CardContent>
        </Card>
      </div>

      {/* Posture Summary */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <BarChart3 className="h-4 w-4 text-green-400" />
            Executive Summary
          </CardTitle>
          <CardDescription className="text-xs">High-level security posture snapshot for leadership</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
            <div className="rounded-lg border border-green-500/20 bg-green-500/5 p-3 text-center">
              <div className="text-2xl font-bold text-green-400">{onTrackKpis}</div>
              <div className="text-[10px] text-muted-foreground mt-1">KPIs On Track</div>
            </div>
            <div className="rounded-lg border border-amber-500/20 bg-amber-500/5 p-3 text-center">
              <div className="text-2xl font-bold text-amber-400">{atRiskKpis}</div>
              <div className="text-[10px] text-muted-foreground mt-1">KPIs At Risk</div>
            </div>
            <div className="rounded-lg border border-red-500/20 bg-red-500/5 p-3 text-center">
              <div className="text-2xl font-bold text-red-400">{offTrackKpis}</div>
              <div className="text-[10px] text-muted-foreground mt-1">KPIs Off Track</div>
            </div>
            <div className="rounded-lg border border-purple-500/20 bg-purple-500/5 p-3 text-center">
              <div className="flex items-center justify-center gap-1.5">
                <div className="text-2xl font-bold text-purple-400 capitalize">
                  {summary?.posture_trend ?? "stable"}
                </div>
                {summary?.posture_trend === "improving" ? (
                  <TrendingUp className="h-5 w-5 text-purple-400" />
                ) : summary?.posture_trend === "declining" ? (
                  <TrendingDown className="h-5 w-5 text-purple-400" />
                ) : (
                  <Minus className="h-5 w-5 text-purple-400" />
                )}
              </div>
              <div className="text-[10px] text-muted-foreground mt-1">Posture Trend</div>
            </div>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
