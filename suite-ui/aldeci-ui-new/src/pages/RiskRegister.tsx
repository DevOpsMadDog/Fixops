/**
 * Risk Register = Enterprise Risk Management Board
 *
 * 1. Header: title + subtitle
 * 2. KPIs: Total Risks, Critical Risks, Risks Accepted, Avg Risk Score
 * 3. Risk Matrix: 5=5 CSS grid (likelihood vs impact), color zones + dots
 * 4. Risk Register table: 12 rows with full risk attributes
 * 5. Risk Trend: 6-month bar chart using div heights
 * 6. Risk by Category: CSS donut-style distribution
 * 7. Add Risk placeholder panel
 *
 * API: GET /api/v1/risk-register/risks
 * Fallback: mock data when API unavailable
 */

import { useState, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  AlertTriangle,
  ShieldAlert,
  CheckCircle2,
  BarChart3,
  Plus,
  RefreshCw,
  TrendingUp,
  ClipboardList,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ScrollArea } from "@/components/ui/scroll-area";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

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

// ===========================================================
// Types
// ===========================================================

type RiskCategory =
  | "Technical"
  | "Operational"
  | "Compliance"
  | "Strategic"
  | "Financial"
  | "Reputational";

type RiskStatus = "Open" | "Mitigating" | "Accepted" | "Closed";

interface Risk {
  risk_id: string;
  risk_title: string;
  category: RiskCategory;
  likelihood: number;
  impact: number;
  risk_score: number;
  owner: string;
  status: RiskStatus;
  due_date: string;
}

// ===========================================================
// Mock data
// ===========================================================

const MOCK_RISKS: Risk[] = [
  {
    risk_id: "RSK-001",
    risk_title: "Critical infrastructure ransomware attack",
    category: "Technical",
    likelihood: 3,
    impact: 5,
    risk_score: 15,
    owner: "CISO",
    status: "Open",
    due_date: "2026-05-15",
  },
  {
    risk_id: "RSK-002",
    risk_title: "Key person dependency = CISO",
    category: "Strategic",
    likelihood: 4,
    impact: 4,
    risk_score: 16,
    owner: "CEO",
    status: "Open",
    due_date: "2026-06-01",
  },
  {
    risk_id: "RSK-003",
    risk_title: "PCI-DSS compliance violation",
    category: "Compliance",
    likelihood: 2,
    impact: 5,
    risk_score: 10,
    owner: "Compliance Team",
    status: "Mitigating",
    due_date: "2026-04-30",
  },
  {
    risk_id: "RSK-004",
    risk_title: "Vendor data breach",
    category: "Operational",
    likelihood: 3,
    impact: 4,
    risk_score: 12,
    owner: "Vendor Manager",
    status: "Open",
    due_date: "2026-05-20",
  },
  {
    risk_id: "RSK-005",
    risk_title: "Insider threat = privileged user",
    category: "Technical",
    likelihood: 2,
    impact: 5,
    risk_score: 10,
    owner: "SOC Lead",
    status: "Mitigating",
    due_date: "2026-05-01",
  },
  {
    risk_id: "RSK-006",
    risk_title: "Regulatory fine for GDPR",
    category: "Compliance",
    likelihood: 2,
    impact: 4,
    risk_score: 8,
    owner: "Legal",
    status: "Accepted",
    due_date: "2026-12-31",
  },
  {
    risk_id: "RSK-007",
    risk_title: "DDoS disrupting customer portal",
    category: "Technical",
    likelihood: 3,
    impact: 3,
    risk_score: 9,
    owner: "Infra Team",
    status: "Open",
    due_date: "2026-05-10",
  },
  {
    risk_id: "RSK-008",
    risk_title: "Cloud misconfiguration exposure",
    category: "Technical",
    likelihood: 4,
    impact: 3,
    risk_score: 12,
    owner: "Cloud Security",
    status: "Mitigating",
    due_date: "2026-04-25",
  },
  {
    risk_id: "RSK-009",
    risk_title: "Budget overrun on security tooling",
    category: "Financial",
    likelihood: 3,
    impact: 2,
    risk_score: 6,
    owner: "CFO",
    status: "Accepted",
    due_date: "2026-12-31",
  },
  {
    risk_id: "RSK-010",
    risk_title: "Brand damage from public breach",
    category: "Reputational",
    likelihood: 2,
    impact: 5,
    risk_score: 10,
    owner: "CMO",
    status: "Open",
    due_date: "2026-06-30",
  },
  {
    risk_id: "RSK-011",
    risk_title: "Supply chain software tampering",
    category: "Operational",
    likelihood: 2,
    impact: 4,
    risk_score: 8,
    owner: "DevSecOps",
    status: "Mitigating",
    due_date: "2026-05-15",
  },
  {
    risk_id: "RSK-012",
    risk_title: "Expired TLS certificates on APIs",
    category: "Technical",
    likelihood: 3,
    impact: 2,
    risk_score: 6,
    owner: "Platform Team",
    status: "Closed",
    due_date: "2026-04-10",
  },
];

const TREND_DATA = [
  { month: "Nov", critical: 5, high: 10, medium: 14 },
  { month: "Dec", critical: 6, high: 11, medium: 13 },
  { month: "Jan", critical: 7, high: 12, medium: 15 },
  { month: "Feb", critical: 6, high: 11, medium: 14 },
  { month: "Mar", critical: 8, high: 13, medium: 16 },
  { month: "Apr", critical: 8, high: 12, medium: 15 },
];

const CATEGORY_DATA: { name: RiskCategory; count: number; color: string }[] = [
  { name: "Technical", count: 5, color: "bg-blue-500" },
  { name: "Compliance", count: 2, color: "bg-purple-500" },
  { name: "Operational", count: 2, color: "bg-amber-500" },
  { name: "Strategic", count: 1, color: "bg-red-500" },
  { name: "Financial", count: 1, color: "bg-green-500" },
  { name: "Reputational", count: 1, color: "bg-pink-500" },
];

// ===========================================================
// Helpers
// ===========================================================

function scoreColor(score: number): string {
  if (score >= 15) return "text-red-400";
  if (score >= 10) return "text-orange-400";
  if (score >= 5) return "text-amber-400";
  return "text-emerald-400";
}

function scoreBg(score: number): string {
  if (score >= 15) return "bg-red-500/15 text-red-400 border-red-500/30";
  if (score >= 10) return "bg-orange-500/15 text-orange-400 border-orange-500/30";
  if (score >= 5) return "bg-amber-500/15 text-amber-400 border-amber-500/30";
  return "bg-emerald-500/15 text-emerald-400 border-emerald-500/30";
}

function statusBadge(status: RiskStatus): string {
  const map: Record<RiskStatus, string> = {
    Open: "bg-red-500/15 text-red-400 border-red-500/30",
    Mitigating: "bg-blue-500/15 text-blue-400 border-blue-500/30",
    Accepted: "bg-amber-500/15 text-amber-400 border-amber-500/30",
    Closed: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
  };
  return map[status];
}

function categoryBadge(cat: RiskCategory): string {
  const map: Record<RiskCategory, string> = {
    Technical: "bg-blue-500/15 text-blue-400 border-blue-500/30",
    Compliance: "bg-purple-500/15 text-purple-400 border-purple-500/30",
    Operational: "bg-amber-500/15 text-amber-400 border-amber-500/30",
    Strategic: "bg-red-500/15 text-red-400 border-red-500/30",
    Financial: "bg-green-500/15 text-green-400 border-green-500/30",
    Reputational: "bg-pink-500/15 text-pink-400 border-pink-500/30",
  };
  return map[cat];
}

/** Return the CSS background class for a matrix cell given row (impact 5=1) and col (likelihood 1=5) */
function matrixCellColor(row: number, col: number): string {
  const score = row * col;
  if (score >= 15) return "bg-red-600/60";
  if (score >= 10) return "bg-orange-500/60";
  if (score >= 5) return "bg-amber-400/50";
  return "bg-emerald-600/40";
}

// Dots placed on matrix: [likelihood, impact] pairs for representative risks
const MATRIX_DOTS: { l: number; i: number; label: string }[] = [
  { l: 3, i: 5, label: "RSK-001" },
  { l: 4, i: 4, label: "RSK-002" },
  { l: 2, i: 5, label: "RSK-003" },
  { l: 3, i: 4, label: "RSK-004" },
  { l: 3, i: 3, label: "RSK-007" },
  { l: 4, i: 3, label: "RSK-008" },
  { l: 2, i: 4, label: "RSK-006" },
  { l: 3, i: 2, label: "RSK-009" },
];

// ===========================================================
// API
// ===========================================================

async function fetchRisks(): Promise<Risk[]> {
  // GET /api/v1/risks = risk_register_router (prefix /api/v1/risks)
  const res = await fetch(`${API_BASE}/api/v1/risks?org_id=${ORG_ID}&limit=50`, {
    headers: { "X-API-Key": API_KEY },
  });
  if (!res.ok) throw new Error(`${res.status}`);
  const data = await res.json();
  // Router returns array of Risk model_dump(); normalise field names to UI shape
  const raw: any[] = Array.isArray(data) ? data : (data.risks ?? data.items ?? []);
  if (raw.length === 0) return MOCK_RISKS;
  return raw.map((r: any): Risk => ({
    risk_id:    r.risk_id    ?? r.id     ?? "RSK-???",
    risk_title: r.risk_title ?? r.title  ?? "Unknown Risk",
    category:   r.category               ?? "Technical",
    likelihood: r.likelihood             ?? 3,
    impact:     r.impact                 ?? 3,
    risk_score: r.risk_score ?? (r.likelihood ?? 3) * (r.impact ?? 3),
    owner:      r.owner                  ?? "",
    status:     r.status                 ?? "Open",
    due_date:   r.due_date ?? r.target_date ?? "",
  }));
}

// ===========================================================
// Main Component
// ===========================================================

export default function RiskRegister() {
  const [showAddPanel, setShowAddPanel] = useState(false);
  const [liveStats, setLiveStats] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.allSettled([
      apiFetch(`/api/v1/vendor-risk/assessments?org_id=${ORG_ID}&limit=50`),
      apiFetch(`/api/v1/vendor-risk/stats?org_id=${ORG_ID}`),
    ]).then(([assessmentsResult, vendorStatsResult]) => {
      const assessments = assessmentsResult.status === "fulfilled" ? assessmentsResult.value : null;
      const vendorStats = vendorStatsResult.status === "fulfilled" ? vendorStatsResult.value : null;
      if (assessments || vendorStats) {
        setLiveStats({ riskStats: vendorStats, vendorStats, assessments });
      }
    })
      .finally(() => setLoading(false));
  }, []);

  const { data, isLoading, refetch } = useQuery({
    queryKey: ["risk-register-risks"],
    queryFn: fetchRisks,
    staleTime: 60000,
    retry: false,
  });

  const risks = data ?? MOCK_RISKS;

  const totalRisks    = liveStats?.riskStats?.total_risks    ?? liveStats?.riskStats?.total    ?? risks.length;
  const criticalRisks = liveStats?.riskStats?.critical_risks ?? liveStats?.riskStats?.critical ?? risks.filter((r) => r.risk_score >= 15).length;
  const acceptedRisks = liveStats?.riskStats?.accepted_risks ?? liveStats?.riskStats?.accepted ?? risks.filter((r) => r.status === "Accepted").length;
  const avgScore = liveStats?.riskStats?.avg_score
    ?? liveStats?.riskStats?.average_score
    ?? (risks.reduce((s, r) => s + r.risk_score, 0) / risks.length).toFixed(1);

  const trendMax =
    Math.max(...TREND_DATA.map((d) => d.critical + d.high + d.medium)) || 1;

  const categoryTotal = CATEGORY_DATA.reduce((s, c) => s + c.count, 0);

  if (loading) return (
    <div className="space-y-4 p-6">
      {[1, 2, 3].map((i) => (
        <div key={i} className="h-24 rounded-lg bg-zinc-800/50 animate-pulse" />
      ))}
    </div>
  );

  return (
    <>
      <PageHeader
        title="Risk Register"
        subtitle="Enterprise-wide risk inventory with likelihood and impact scoring"
        icon={ClipboardList}
      />

      <div className="space-y-6 p-6">
        {/* KPIs */}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <KpiCard
            title="Total Risks"
            value={totalRisks}
            icon={BarChart3}
            trend="flat"
          />
          <KpiCard
            title="Critical Risks"
            value={criticalRisks}
            icon={AlertTriangle}
            trend={criticalRisks > 0 ? "down" : "up"}
          />
          <KpiCard
            title="Risks Accepted"
            value={acceptedRisks}
            icon={CheckCircle2}
            trend="flat"
          />
          <KpiCard
            title="Avg Risk Score"
            value={avgScore}
            icon={ShieldAlert}
            trend="flat"
          />
        </div>

        {/* Risk Matrix + Category donut */}
        <div className="grid gap-6 lg:grid-cols-3">
          {/* 5=5 Risk Matrix */}
          <div className="lg:col-span-2">
            <Card className="border-slate-700 bg-slate-800/50">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-base">
                  <ShieldAlert className="h-5 w-5 text-orange-400" />
                  Risk Matrix = Likelihood vs Impact
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex gap-3">
                  {/* Y-axis label */}
                  <div className="flex flex-col items-center justify-center gap-0 w-5">
                    <span
                      className="text-xs text-slate-400 tracking-widest"
                      style={{ writingMode: "vertical-rl", transform: "rotate(180deg)" }}
                    >
                      IMPACT =
                    </span>
                  </div>

                  <div className="flex-1">
                    {/* Grid: rows = impact 5=1, cols = likelihood 1=5 */}
                    <div
                      className="grid"
                      style={{ gridTemplateColumns: "24px repeat(5, 1fr)", gridTemplateRows: "repeat(5, 1fr)" }}
                    >
                      {[5, 4, 3, 2, 1].map((impact) =>
                        [0, 1, 2, 3, 4, 5].map((col) => {
                          if (col === 0) {
                            // row label
                            return (
                              <div
                                key={`label-${impact}`}
                                className="flex items-center justify-center text-xs text-slate-400 font-semibold h-12"
                              >
                                {impact}
                              </div>
                            );
                          }
                          const likelihood = col; // col 1=5
                          const cellColor = matrixCellColor(impact, likelihood);
                          // Find dots for this cell
                          const dots = MATRIX_DOTS.filter(
                            (d) => d.l === likelihood && d.i === impact
                          );
                          return (
                            <div
                              key={`${impact}-${likelihood}`}
                              className={cn(
                                "relative flex items-center justify-center h-12 border border-slate-700/50 rounded-sm m-0.5",
                                cellColor
                              )}
                            >
                              {dots.length > 0 && (
                                <div className="flex flex-wrap gap-0.5 items-center justify-center">
                                  {dots.map((d) => (
                                    <span
                                      key={d.label}
                                      className="h-2.5 w-2.5 rounded-full bg-white shadow-sm shadow-black/50"
                                      title={d.label}
                                    />
                                  ))}
                                </div>
                              )}
                              {dots.length > 1 && (
                                <span className="absolute bottom-0.5 right-1 text-[9px] text-white/70">
                                  {dots.length}
                                </span>
                              )}
                            </div>
                          );
                        })
                      )}
                    </div>

                    {/* X-axis: likelihood labels */}
                    <div
                      className="grid mt-1"
                      style={{ gridTemplateColumns: "24px repeat(5, 1fr)" }}
                    >
                      <div />
                      {[1, 2, 3, 4, 5].map((l) => (
                        <div key={l} className="text-center text-xs text-slate-400 font-semibold">
                          {l}
                        </div>
                      ))}
                    </div>
                    <p className="text-center text-xs text-slate-400 mt-1">LIKELIHOOD =</p>
                  </div>
                </div>

                {/* Legend */}
                <div className="mt-4 flex flex-wrap gap-3">
                  {[
                    { label: "Critical (=15)", color: "bg-red-600/60" },
                    { label: "High (10=14)", color: "bg-orange-500/60" },
                    { label: "Medium (5=9)", color: "bg-amber-400/50" },
                    { label: "Low (<5)", color: "bg-emerald-600/40" },
                  ].map((l) => (
                    <div key={l.label} className="flex items-center gap-1.5">
                      <span className={cn("h-3 w-3 rounded-sm", l.color)} />
                      <span className="text-xs text-slate-400">{l.label}</span>
                    </div>
                  ))}
                  <div className="flex items-center gap-1.5">
                    <span className="h-2.5 w-2.5 rounded-full bg-white shadow-sm" />
                    <span className="text-xs text-slate-400">Risk dot</span>
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Risk by Category */}
          <Card className="border-slate-700 bg-slate-800/50">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-base">
                <TrendingUp className="h-5 w-5 text-blue-400" />
                Risk by Category
              </CardTitle>
            </CardHeader>
            <CardContent>
              {/* Simple donut using conic-gradient */}
              <div className="flex justify-center mb-4">
                <div
                  className="h-32 w-32 rounded-full"
                  style={{
                    background: (() => {
                      let pct = 0;
                      const colors = [
                        "#3b82f6", "#a855f7", "#f59e0b",
                        "#ef4444", "#22c55e", "#ec4899",
                      ];
                      const segments = CATEGORY_DATA.map((c, i) => {
                        const share = (c.count / categoryTotal) * 100;
                        const seg = `${colors[i]} ${pct}% ${pct + share}%`;
                        pct += share;
                        return seg;
                      });
                      return `conic-gradient(${segments.join(", ")})`;
                    })(),
                  }}
                >
                  <div className="h-full w-full rounded-full flex items-center justify-center"
                    style={{ background: "radial-gradient(circle, #1e293b 55%, transparent 56%)" }}>
                    <span className="text-xs text-slate-400">Total</span>
                  </div>
                </div>
              </div>

              <div className="space-y-2">
                {CATEGORY_DATA.map((cat) => (
                  <div key={cat.name} className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <span className={cn("h-2.5 w-2.5 rounded-sm", cat.color)} />
                      <span className="text-sm text-slate-300">{cat.name}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <div className="w-20 h-1.5 rounded-full bg-slate-700 overflow-hidden">
                        <div
                          className={cn("h-full rounded-full", cat.color)}
                          style={{ width: `${(cat.count / categoryTotal) * 100}%` }}
                        />
                      </div>
                      <span className="text-sm text-slate-400 w-4 text-right">{cat.count}</span>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Risk Register Table */}
        <Card className="border-slate-700 bg-slate-800/50">
          <CardHeader>
            <div className="flex items-center justify-between">
              <CardTitle className="flex items-center gap-2">
                <ClipboardList className="h-5 w-5 text-slate-400" />
                Risk Inventory
              </CardTitle>
              <div className="flex items-center gap-2">
                <Button
                  size="sm"
                  variant="ghost"
                  className="text-slate-400 hover:text-slate-200"
                  onClick={() => refetch()}
                >
                  <RefreshCw className="h-4 w-4" />
                </Button>
                <Button
                  size="sm"
                  className="bg-blue-600 hover:bg-blue-700 text-white"
                  onClick={() => setShowAddPanel((p) => !p)}
                >
                  <Plus className="mr-1 h-4 w-4" />
                  Add Risk
                </Button>
              </div>
            </div>
          </CardHeader>
          <CardContent>
            {/* Add Risk placeholder panel */}
            {showAddPanel && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: "auto" }}
                exit={{ opacity: 0, height: 0 }}
                className="mb-4 rounded-lg border border-blue-500/30 bg-blue-500/5 p-4"
              >
                <p className="text-sm font-medium text-blue-300">
                  Add Risk = coming soon
                </p>
                <p className="mt-1 text-xs text-slate-400">
                  Risk creation form will POST to /api/v1/risk-register/risks
                </p>
              </motion.div>
            )}

            <ScrollArea className="h-[480px]">
              <Table>
                <TableHeader>
                  <TableRow className="border-slate-700 hover:bg-transparent">
                    <TableHead className="text-slate-300 w-24">ID</TableHead>
                    <TableHead className="text-slate-300">Risk Title</TableHead>
                    <TableHead className="text-slate-300">Category</TableHead>
                    <TableHead className="text-center text-slate-300 w-10">L</TableHead>
                    <TableHead className="text-center text-slate-300 w-10">I</TableHead>
                    <TableHead className="text-center text-slate-300 w-16">Score</TableHead>
                    <TableHead className="text-slate-300">Owner</TableHead>
                    <TableHead className="text-slate-300">Status</TableHead>
                    <TableHead className="text-slate-300">Due</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {risks.map((risk, idx) => (
                    <motion.tr
                      key={risk.risk_id}
                      initial={{ opacity: 0, x: -8 }}
                      animate={{ opacity: 1, x: 0 }}
                      transition={{ delay: idx * 0.03 }}
                      className="border-slate-700 hover:bg-slate-700/30 transition-colors"
                    >
                      <TableCell className="font-mono text-xs text-slate-400">
                        {risk.risk_id}
                      </TableCell>
                      <TableCell className="font-medium text-slate-100 max-w-[220px]">
                        <span className="line-clamp-2">{risk.risk_title}</span>
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className={categoryBadge(risk.category)}>
                          {risk.category}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-center text-slate-300 font-semibold">
                        {risk.likelihood}
                      </TableCell>
                      <TableCell className="text-center text-slate-300 font-semibold">
                        {risk.impact}
                      </TableCell>
                      <TableCell className="text-center">
                        <Badge variant="outline" className={scoreBg(risk.risk_score)}>
                          {risk.risk_score}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-slate-300 text-sm">
                        {risk.owner}
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className={statusBadge(risk.status)}>
                          {risk.status}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-slate-400 text-sm whitespace-nowrap">
                        {risk.due_date}
                      </TableCell>
                    </motion.tr>
                  ))}
                </TableBody>
              </Table>
            </ScrollArea>
          </CardContent>
        </Card>

        {/* Risk Trend = 6-month bar chart */}
        <Card className="border-slate-700 bg-slate-800/50">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <BarChart3 className="h-5 w-5 text-purple-400" />
              Risk Trend = Last 6 Months
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex items-end gap-4 h-36">
              {TREND_DATA.map((d) => {
                const total = d.critical + d.high + d.medium;
                const maxH = 120; // px
                const totalH = (total / trendMax) * maxH;
                const critH = (d.critical / total) * totalH;
                const highH = (d.high / total) * totalH;
                const medH = (d.medium / total) * totalH;
                return (
                  <div key={d.month} className="flex-1 flex flex-col items-center gap-1">
                    <span className="text-xs text-slate-400">{total}</span>
                    <div className="w-full flex flex-col-reverse rounded-sm overflow-hidden" style={{ height: `${totalH}px` }}>
                      <div style={{ height: `${medH}px` }} className="bg-amber-400/70 w-full" title={`Medium: ${d.medium}`} />
                      <div style={{ height: `${highH}px` }} className="bg-orange-500/70 w-full" title={`High: ${d.high}`} />
                      <div style={{ height: `${critH}px` }} className="bg-red-500/80 w-full" title={`Critical: ${d.critical}`} / role="status" aria-live="polite">
                    </div>
                    <span className="text-xs text-slate-400">{d.month}</span>
                  </div>
                );
              })}
            </div>
            <div className="mt-3 flex gap-4">
              {[
                { label: "Critical", color: "bg-red-500/80" },
                { label: "High", color: "bg-orange-500/70" },
                { label: "Medium", color: "bg-amber-400/70" },
              ].map((l) => (
                <div key={l.label} className="flex items-center gap-1.5">
                  <span className={cn("h-2.5 w-2.5 rounded-sm", l.color)} />
                  <span className="text-xs text-slate-400">{l.label}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>
    </>
  );
}
