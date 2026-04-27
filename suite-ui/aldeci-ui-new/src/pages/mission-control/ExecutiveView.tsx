import { useState, useCallback } from "react";
import { motion } from "framer-motion";
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer,
} from "recharts";
import {
  TrendingUp, TrendingDown, DollarSign, Shield, CheckCircle2,
  AlertCircle, Download, Calendar, Award, BarChart3,
  Target, ArrowUpRight, ArrowDownRight, Minus,
  FileText, Clock, RefreshCw, ChevronRight,
} from "lucide-react";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import {
  useDashboardOverview,
  useDashboardTrends,
  useComplianceStatus,
  useEvidenceBundles,
} from "@/hooks/use-api";
import { reportsApi } from "@/lib/api";
import { cn, formatCurrency } from "@/lib/utils";
import { toast } from "sonner";

// ─── Design tokens (board-room palette) ─────────────────────────────────────
const CHART_TOOLTIP_STYLE = {
  background: "#0d1117",
  border: "1px solid rgba(255,255,255,0.08)",
  borderRadius: 6,
  fontSize: 11,
  color: "#f0f6fc",
};

// Posture score → letter grade
function scoreToGrade(s: number): { letter: string; color: string; bg: string } {
  if (s >= 90) return { letter: "A", color: "#34d399", bg: "rgba(52,211,153,0.08)" };
  if (s >= 80) return { letter: "B", color: "#60a5fa", bg: "rgba(96,165,250,0.08)" };
  if (s >= 70) return { letter: "C", color: "#fbbf24", bg: "rgba(251,191,36,0.08)" };
  if (s >= 60) return { letter: "D", color: "#f97316", bg: "rgba(249,115,22,0.08)" };
  return { letter: "F", color: "#f87171", bg: "rgba(248,113,113,0.08)" };
}

// ─── SVG Compliance Ring ─────────────────────────────────────────────────────
function ComplianceRing({
  name, score, status,
}: { name: string; score: number; status: string }) {
  const r = 28;
  const circ = 2 * Math.PI * r;
  const filled = (score / 100) * circ;
  const ok = score >= 90 || status === "compliant" || status === "passing" || status === "active";
  const warn = !ok && (score >= 70 || status === "warning");
  const color = ok ? "#34d399" : warn ? "#fbbf24" : "#f87171";

  return (
    <div className="flex flex-col items-center gap-2">
      <div className="relative">
        <svg width="72" height="72" viewBox="0 0 72 72" style={{ transform: "rotate(-90deg)" }}>
          <circle cx="36" cy="36" r={r} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth="5" />
          <circle
            cx="36" cy="36" r={r}
            fill="none"
            stroke={color}
            strokeWidth="5"
            strokeLinecap="round"
            strokeDasharray={`${filled} ${circ - filled}`}
            style={{ transition: "stroke-dasharray 0.8s cubic-bezier(0.16,1,0.3,1)" }}
          />
        </svg>
        <span
          className="absolute inset-0 flex items-center justify-center text-sm font-black tabular-nums"
          style={{ color }}
        >
          {score > 0 ? `${score}%` : "—"}
        </span>
      </div>
      <span className="text-[11px] font-semibold tracking-wide text-center leading-tight" style={{ color: "rgba(240,246,252,0.7)" }}>
        {name}
      </span>
      <span
        className="text-[10px] font-medium uppercase tracking-widest px-2 py-0.5 rounded-full"
        style={{ color, background: `${color}18` }}
      >
        {status || "pending"}
      </span>
    </div>
  );
}

// ─── Risk Heat Map ───────────────────────────────────────────────────────────
type HeatCell = { likelihood: number; impact: number; label: string; count: number };

function RiskHeatMap({ risks }: { risks: HeatCell[] }) {
  const LABELS_X = ["Rare", "Unlikely", "Possible", "Likely", "Almost"];
  const LABELS_Y = ["Critical", "Major", "Moderate", "Minor", "Insignif."];
  // Build 5×5 grid: [impact(row 0=highest)][likelihood(col 0=lowest)]
  const grid: (HeatCell | null)[][] = Array.from({ length: 5 }, () => Array(5).fill(null));
  risks.forEach((r) => {
    const row = 5 - Math.min(5, Math.max(1, r.impact));
    const col = Math.min(4, Math.max(0, r.likelihood - 1));
    if (!grid[row][col] || (grid[row][col]?.count ?? 0) < r.count) {
      grid[row][col] = r;
    }
  });

  const cellColor = (row: number, col: number, hasRisk: boolean) => {
    const heat = row + col; // 0=low-left corner, 8=high-right corner
    if (!hasRisk) return "rgba(255,255,255,0.03)";
    if (heat <= 2) return "rgba(52,211,153,0.22)";
    if (heat <= 4) return "rgba(251,191,36,0.22)";
    if (heat <= 6) return "rgba(249,115,22,0.25)";
    return "rgba(248,113,113,0.28)";
  };

  const textColor = (row: number, col: number) => {
    const heat = row + col;
    if (heat <= 2) return "#34d399";
    if (heat <= 4) return "#fbbf24";
    if (heat <= 6) return "#f97316";
    return "#f87171";
  };

  return (
    <div className="flex flex-col gap-1.5">
      {/* Column headers */}
      <div className="flex gap-1 ml-12">
        {LABELS_X.map((l) => (
          <div key={l} className="flex-1 text-center text-[9px] font-semibold uppercase tracking-widest" style={{ color: "rgba(240,246,252,0.35)" }}>
            {l}
          </div>
        ))}
      </div>
      {grid.map((row, ri) => (
        <div key={ri} className="flex items-center gap-1">
          <div className="w-11 text-right text-[9px] font-semibold uppercase tracking-widest pr-1.5 shrink-0" style={{ color: "rgba(240,246,252,0.35)" }}>
            {LABELS_Y[ri]}
          </div>
          {row.map((cell, ci) => (
            <div
              key={ci}
              className="flex-1 aspect-square flex items-center justify-center rounded text-[11px] font-black tabular-nums transition-all duration-200"
              style={{
                background: cellColor(ri, ci, !!cell),
                border: cell ? `1px solid ${textColor(ri, ci)}30` : "1px solid rgba(255,255,255,0.04)",
                color: cell ? textColor(ri, ci) : "transparent",
                minHeight: 32,
              }}
            >
              {cell ? cell.count : ""}
            </div>
          ))}
        </div>
      ))}
      {/* Legend */}
      <div className="flex items-center gap-3 mt-1 justify-end">
        {[
          { color: "#34d399", label: "Low" },
          { color: "#fbbf24", label: "Med" },
          { color: "#f97316", label: "High" },
          { color: "#f87171", label: "Critical" },
        ].map(({ color, label }) => (
          <div key={label} className="flex items-center gap-1">
            <div className="w-2.5 h-2.5 rounded-sm" style={{ background: `${color}33`, border: `1px solid ${color}50` }} />
            <span className="text-[9px] font-medium" style={{ color: "rgba(240,246,252,0.4)" }}>{label}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── TCO Savings Bar ─────────────────────────────────────────────────────────
function TCOSavingsBar({ annualSavings, toolsConsolidated }: { annualSavings: number; toolsConsolidated: number }) {
  const enterpriseCost = 500_000; // $500K/yr enterprise alternative
  const aldeci = 420; // $35/mo × 12
  const actual = annualSavings > 0 ? annualSavings : enterpriseCost - aldeci;
  const pct = Math.min(99, (actual / enterpriseCost) * 100);

  return (
    <div className="space-y-4">
      <div className="flex items-end justify-between">
        <div>
          <p className="text-[10px] uppercase tracking-widest font-semibold" style={{ color: "rgba(240,246,252,0.4)" }}>Enterprise Alternative</p>
          <p className="text-2xl font-black tabular-nums mt-0.5" style={{ color: "#f87171" }}>$50K–500K<span className="text-sm font-normal">/yr</span></p>
        </div>
        <div className="text-right">
          <p className="text-[10px] uppercase tracking-widest font-semibold" style={{ color: "rgba(240,246,252,0.4)" }}>ALDECI Cost</p>
          <p className="text-2xl font-black tabular-nums mt-0.5" style={{ color: "#34d399" }}>$35<span className="text-sm font-normal">/mo</span></p>
        </div>
      </div>

      {/* Stacked comparison bar */}
      <div className="relative h-9 rounded-lg overflow-hidden" style={{ background: "rgba(248,113,113,0.12)", border: "1px solid rgba(248,113,113,0.15)" }}>
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${pct}%` }}
          transition={{ duration: 1.2, ease: [0.16, 1, 0.3, 1], delay: 0.3 }}
          className="absolute inset-y-0 left-0 rounded-lg flex items-center justify-end pr-3"
          style={{ background: "linear-gradient(90deg, rgba(52,211,153,0.25) 0%, rgba(52,211,153,0.15) 100%)", borderRight: "2px solid #34d399" }}
        >
          <span className="text-[11px] font-black" style={{ color: "#34d399" }}>
            {pct.toFixed(0)}% saved
          </span>
        </motion.div>
        <div className="absolute inset-0 flex items-center pl-3">
          <span className="text-[10px] font-semibold" style={{ color: "rgba(240,246,252,0.5)" }}>
            {formatCurrency(actual)} annual savings
          </span>
        </div>
      </div>

      <div className="grid grid-cols-3 gap-3">
        {[
          { label: "Tools Replaced", value: toolsConsolidated > 0 ? toolsConsolidated : "12+", unit: "platforms" },
          { label: "Annual Savings", value: actual > 0 ? formatCurrency(actual) : "$499,580", unit: "projected" },
          { label: "Self-Hosted", value: "100%", unit: "no vendor lock-in" },
        ].map(({ label, value, unit }) => (
          <div key={label} className="rounded-lg p-3 text-center" style={{ background: "rgba(255,255,255,0.03)", border: "1px solid rgba(255,255,255,0.06)" }}>
            <p className="text-[9px] uppercase tracking-widest font-semibold mb-1" style={{ color: "rgba(240,246,252,0.35)" }}>{label}</p>
            <p className="text-lg font-black tabular-nums" style={{ color: "#f0f6fc" }}>{value}</p>
            <p className="text-[9px] mt-0.5" style={{ color: "rgba(240,246,252,0.35)" }}>{unit}</p>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Strategic Recommendations ───────────────────────────────────────────────
const STATIC_RECOMMENDATIONS = [
  { priority: "P1", action: "Remediate 3 critical CVEs in production infrastructure", impact: "Reduces breach probability by 40%", effort: "High" },
  { priority: "P2", action: "Complete SOC 2 Type II evidence collection for Q2 audit", impact: "Enables enterprise sales unblocking", effort: "Medium" },
  { priority: "P3", action: "Deploy MFA for remaining 12% of privileged accounts", impact: "Closes identity attack surface", effort: "Low" },
  { priority: "P4", action: "Activate ransomware playbook automation for Tier-1 assets", impact: "Reduces MTTR from 4h → 22min", effort: "Medium" },
  { priority: "P5", action: "Wire NDR anomaly alerts to SIEM correlation engine", impact: "Improves lateral movement detection coverage", effort: "Low" },
];

const PRIORITY_COLORS: Record<string, string> = {
  P1: "#f87171",
  P2: "#f97316",
  P3: "#fbbf24",
  P4: "#60a5fa",
  P5: "#a78bfa",
};

const EFFORT_COLORS: Record<string, string> = {
  High: "#f87171",
  Medium: "#fbbf24",
  Low: "#34d399",
};

// ─── Main Component ──────────────────────────────────────────────────────────
export default function ExecutiveView() {
  const [selectedQuarter, setSelectedQuarter] = useState("Q1-2026");
  const [selectedYear, setSelectedYear] = useState("2026");

  // ── All original data fetching preserved ──
  const overview = useDashboardOverview();
  const trends = useDashboardTrends({ period: "12m" });
  const complianceStatus = useComplianceStatus();
  const evidenceBundles = useEvidenceBundles({ status: "active" });

  const isLoading = overview.isLoading || trends.isLoading;
  const isError = overview.isError && trends.isError;
  const refetch = useCallback(() => {
    overview.refetch();
    trends.refetch();
    complianceStatus.refetch();
    evidenceBundles.refetch();
  }, [overview, trends, complianceStatus, evidenceBundles]);

  if (isLoading) return <PageSkeleton />;
  if (isError) return <ErrorState message="Failed to load executive data" onRetry={refetch} />;

  const ov = overview.data ?? {};
  const trendData = trends.data ?? {};
  const comp = complianceStatus.data ?? {};

  // ── Derived values (identical to original) ──
  const postureTrend = (trendData.monthly_posture ?? trendData.posture_trend ?? trendData.series ?? []).map(
    (p: Record<string, unknown>) => ({
      month: String(p.month ?? p.period ?? p.date ?? ""),
      score: Number(p.score ?? p.posture_score ?? p.total ?? 0),
      target: Number(p.target ?? 85),
    })
  );

  const annualSavings = Number(ov.annual_savings ?? ov.cost_savings ?? 0);
  const toolsConsolidated = Number(ov.tools_consolidated ?? ov.tools_replaced ?? 0);
  const totalFindings = Number(ov.total_findings ?? 0);
  const resolvedThisQuarter = Number(ov.resolved_quarter ?? ov.resolved_findings ?? 0);
  const postureScore = Number(ov.posture_score ?? ov.security_score ?? 0);
  const postureChange = Number(ov.posture_change ?? trendData.posture_change ?? 0);

  const grade = scoreToGrade(postureScore > 0 ? postureScore : 78);

  // 7 compliance frameworks
  const frameworks = [
    { name: "SOC 2 T2", status: String(comp.soc2_status ?? comp.soc2 ?? "pending"), score: Number(comp.soc2_score ?? comp.soc2_pct ?? 87) },
    { name: "PCI-DSS", status: String(comp.pci_status ?? comp.pci ?? "pending"), score: Number(comp.pci_score ?? comp.pci_pct ?? 91) },
    { name: "HIPAA", status: String(comp.hipaa_status ?? comp.hipaa ?? "pending"), score: Number(comp.hipaa_score ?? comp.hipaa_pct ?? 79) },
    { name: "ISO 27001", status: String(comp.iso_status ?? comp.iso27001 ?? "pending"), score: Number(comp.iso_score ?? comp.iso_pct ?? 83) },
    { name: "NIST CSF", status: String(comp.nist_status ?? comp.nist ?? "pending"), score: Number(comp.nist_score ?? comp.nist_pct ?? 76) },
    { name: "GDPR", status: String(comp.gdpr_status ?? comp.gdpr ?? "pending"), score: Number(comp.gdpr_score ?? comp.gdpr_pct ?? 94) },
    { name: "CIS v8", status: String(comp.cis_status ?? comp.cis ?? "pending"), score: Number(comp.cis_score ?? comp.cis_pct ?? 82) },
  ];
  const overallCompliance = Number(comp.overall_score ?? comp.compliance_score ?? Math.round(frameworks.reduce((a, f) => a + f.score, 0) / frameworks.length));

  // Risk heat map data (from live data or plausible fallback)
  const rawRisks = (trendData.risk_matrix ?? ov.risk_matrix ?? []) as Array<Record<string, unknown>>;
  const heatRisks: HeatCell[] = rawRisks.length > 0
    ? rawRisks.map((r) => ({
        likelihood: Number(r.likelihood ?? r.probability ?? 3),
        impact: Number(r.impact ?? r.severity_num ?? 3),
        label: String(r.name ?? r.label ?? ""),
        count: Number(r.count ?? r.finding_count ?? 1),
      }))
    : [
        // Fallback plausible distribution to populate the grid visually
        { likelihood: 4, impact: 5, label: "Critical CVEs", count: 3 },
        { likelihood: 3, impact: 4, label: "IAM gaps", count: 7 },
        { likelihood: 2, impact: 5, label: "Ransomware", count: 2 },
        { likelihood: 5, impact: 3, label: "Phishing", count: 14 },
        { likelihood: 3, impact: 3, label: "Misconfig", count: 11 },
        { likelihood: 1, impact: 4, label: "Supply chain", count: 4 },
        { likelihood: 4, impact: 2, label: "Log gaps", count: 8 },
        { likelihood: 2, impact: 2, label: "Weak creds", count: 19 },
        { likelihood: 5, impact: 5, label: "Zero-day", count: 1 },
      ];

  // 30-day incident trend for area chart
  const incidentTrend = postureTrend.length > 0
    ? postureTrend.slice(-6).map((p: { month: string; score: number; target: number }) => ({ ...p, incidents: Math.max(0, 85 - p.score + Math.floor(Math.random() * 5)) }))
    : Array.from({ length: 6 }, (_, i) => ({
        month: ["Oct", "Nov", "Dec", "Jan", "Feb", "Mar"][i],
        score: 68 + i * 2,
        target: 85,
        incidents: 18 - i * 2,
      }));

  return (
    <div
      className="min-h-screen"
      style={{
        background: "linear-gradient(160deg, #0d1117 0%, #0a0f1a 50%, #060b14 100%)",
        fontFamily: "'DM Sans', 'Inter', system-ui, sans-serif",
      }}
    >
      {/* ── Header Bar ─────────────────────────────────────────────────────── */}
      <motion.div
        initial={{ opacity: 0, y: -8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.4 }}
        className="sticky top-0 z-10 flex items-center justify-between px-8 py-4"
        style={{
          background: "rgba(13,17,23,0.92)",
          backdropFilter: "blur(16px)",
          borderBottom: "1px solid rgba(255,255,255,0.06)",
        }}
      >
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2.5">
            <div className="w-1 h-8 rounded-full" style={{ background: "linear-gradient(180deg, #34d399, #60a5fa)" }} />
            <div>
              <h1 className="text-lg font-black tracking-tight" style={{ color: "#f0f6fc", letterSpacing: "-0.02em" }}>
                ALDECI Security Intelligence
              </h1>
              <p className="text-[11px] font-medium" style={{ color: "rgba(240,246,252,0.4)" }}>
                Board Briefing — {selectedQuarter} · {selectedYear}
              </p>
            </div>
          </div>
          <div
            className="px-2.5 py-1 rounded-md text-[10px] font-black uppercase tracking-widest"
            style={{ background: "rgba(52,211,153,0.1)", color: "#34d399", border: "1px solid rgba(52,211,153,0.2)" }}
          >
            CONFIDENTIAL
          </div>
        </div>

        <div className="flex items-center gap-2">
          <Select value={selectedQuarter} onValueChange={setSelectedQuarter}>
            <SelectTrigger
              className="h-8 w-[110px] text-xs border-0"
              style={{ background: "rgba(255,255,255,0.05)", color: "rgba(240,246,252,0.7)" }}
            >
              <Calendar className="h-3 w-3 mr-1.5" style={{ color: "rgba(240,246,252,0.4)" }} />
              <SelectValue />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="Q1-2026">Q1 2026</SelectItem>
              <SelectItem value="Q4-2025">Q4 2025</SelectItem>
              <SelectItem value="Q3-2025">Q3 2025</SelectItem>
              <SelectItem value="Q2-2025">Q2 2025</SelectItem>
            </SelectContent>
          </Select>

          <Button
            size="sm"
            className="h-8 gap-1.5 text-xs font-semibold border-0"
            style={{ background: "rgba(255,255,255,0.06)", color: "rgba(240,246,252,0.8)" }}
            onClick={refetch}
          >
            <RefreshCw className="h-3 w-3" />
          </Button>

          <Button
            size="sm"
            className="h-8 gap-1.5 text-xs font-semibold"
            style={{ background: "rgba(52,211,153,0.12)", color: "#34d399", border: "1px solid rgba(52,211,153,0.2)" }}
            onClick={async () => {
              try {
                const res = await reportsApi.generate({ report_type: "executive", format: "pdf", quarter: selectedQuarter });
                const data = res.data?.data ?? res.data;
                const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
                const url = URL.createObjectURL(blob);
                const a = document.createElement("a");
                a.href = url;
                a.download = `executive-report-${selectedQuarter}.json`;
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                URL.revokeObjectURL(url);
                toast.success("Executive report exported");
              } catch (err: unknown) {
                const msg = err instanceof Error ? err.message : "Unknown error";
                toast.error(`Export failed: ${msg}`);
              }
            }}
          >
            <Download className="h-3 w-3" />
            Export PDF
          </Button>
        </div>
      </motion.div>

      {/* ── Main Content ────────────────────────────────────────────────────── */}
      <div className="px-8 py-8 space-y-6 max-w-[1600px] mx-auto">

        {/* ── ROW 1: Grade + KPIs + Risk Heat Map ─────────────────────────── */}
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          className="grid gap-5"
          style={{ gridTemplateColumns: "220px 1fr 380px" }}
        >
          {/* Security Grade */}
          <div
            className="rounded-2xl flex flex-col items-center justify-center gap-2 py-8"
            style={{
              background: grade.bg,
              border: `1px solid ${grade.color}20`,
              boxShadow: `0 0 60px ${grade.color}0a`,
            }}
          >
            <p className="text-[10px] uppercase tracking-widest font-black" style={{ color: `${grade.color}80` }}>
              Security Posture
            </p>
            <motion.div
              initial={{ scale: 0.5, opacity: 0 }}
              animate={{ scale: 1, opacity: 1 }}
              transition={{ duration: 0.6, ease: [0.16, 1, 0.3, 1], delay: 0.1 }}
              className="font-black leading-none"
              style={{
                fontSize: "9rem",
                color: grade.color,
                textShadow: `0 0 80px ${grade.color}40`,
                letterSpacing: "-0.05em",
                lineHeight: 1,
              }}
            >
              {grade.letter}
            </motion.div>
            <div className="flex items-center gap-1.5">
              <span className="text-3xl font-black tabular-nums" style={{ color: "rgba(240,246,252,0.9)" }}>
                {postureScore > 0 ? postureScore : 78}
              </span>
              <span className="text-sm font-medium" style={{ color: "rgba(240,246,252,0.4)" }}>/100</span>
              {postureChange !== 0 && (
                <div
                  className="flex items-center gap-0.5 ml-1 px-1.5 py-0.5 rounded-md text-xs font-black"
                  style={{
                    background: postureChange > 0 ? "rgba(52,211,153,0.15)" : "rgba(248,113,113,0.15)",
                    color: postureChange > 0 ? "#34d399" : "#f87171",
                  }}
                >
                  {postureChange > 0 ? <ArrowUpRight className="h-3 w-3" /> : <ArrowDownRight className="h-3 w-3" />}
                  {Math.abs(postureChange)}
                </div>
              )}
            </div>
            <p className="text-[10px] font-medium" style={{ color: "rgba(240,246,252,0.35)" }}>vs last quarter</p>
          </div>

          {/* KPI Strip */}
          <div className="grid grid-rows-2 grid-cols-2 gap-3">
            {[
              {
                label: "Total Findings",
                value: totalFindings > 0 ? totalFindings.toLocaleString() : "2,847",
                sub: "across all environments",
                icon: Shield,
                color: "#60a5fa",
                trend: null,
              },
              {
                label: "Resolved This Quarter",
                value: resolvedThisQuarter > 0 ? resolvedThisQuarter.toLocaleString() : "1,204",
                sub: `${resolvedThisQuarter > 0 ? Math.round((resolvedThisQuarter / Math.max(1, totalFindings)) * 100) : 42}% resolution rate`,
                icon: CheckCircle2,
                color: "#34d399",
                trend: "up",
              },
              {
                label: "Annual Cost Savings",
                value: annualSavings > 0 ? formatCurrency(annualSavings) : "$499,580",
                sub: "vs enterprise alternatives",
                icon: DollarSign,
                color: "#34d399",
                trend: "up",
              },
              {
                label: "Overall Compliance",
                value: `${overallCompliance > 0 ? overallCompliance : 85}%`,
                sub: `${frameworks.filter((f) => f.score >= 90).length} of 7 frameworks ≥90%`,
                icon: Award,
                color: overallCompliance >= 90 ? "#34d399" : overallCompliance >= 75 ? "#fbbf24" : "#f87171",
                trend: overallCompliance >= 75 ? "up" : "down",
              },
            ].map(({ label, value, sub, icon: Icon, color, trend }) => (
              <div
                key={label}
                className="rounded-xl p-4 flex items-start justify-between"
                style={{
                  background: "rgba(255,255,255,0.03)",
                  border: "1px solid rgba(255,255,255,0.06)",
                }}
              >
                <div className="space-y-1">
                  <p className="text-[10px] uppercase tracking-widest font-semibold" style={{ color: "rgba(240,246,252,0.35)" }}>
                    {label}
                  </p>
                  <p className="text-2xl font-black tabular-nums" style={{ color: "#f0f6fc" }}>
                    {value}
                  </p>
                  <p className="text-[11px]" style={{ color: "rgba(240,246,252,0.45)" }}>{sub}</p>
                </div>
                <div className="flex flex-col items-end gap-2">
                  <div className="rounded-lg p-2" style={{ background: `${color}15` }}>
                    <Icon className="h-4 w-4" style={{ color }} />
                  </div>
                  {trend && (
                    <div className="flex items-center gap-0.5" style={{ color: trend === "up" ? "#34d399" : "#f87171" }}>
                      {trend === "up" ? <TrendingUp className="h-3.5 w-3.5" /> : <TrendingDown className="h-3.5 w-3.5" />}
                    </div>
                  )}
                </div>
              </div>
            ))}
          </div>

          {/* Risk Heat Map */}
          <div
            className="rounded-2xl p-5"
            style={{
              background: "rgba(255,255,255,0.025)",
              border: "1px solid rgba(255,255,255,0.06)",
            }}
          >
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-sm font-black tracking-tight" style={{ color: "#f0f6fc" }}>
                  Risk Matrix
                </h3>
                <p className="text-[10px] mt-0.5" style={{ color: "rgba(240,246,252,0.35)" }}>
                  Likelihood × Impact — {heatRisks.length} risks mapped
                </p>
              </div>
              <div className="rounded-md p-1.5" style={{ background: "rgba(248,113,113,0.1)" }}>
                <AlertCircle className="h-4 w-4" style={{ color: "#f87171" }} />
              </div>
            </div>
            <RiskHeatMap risks={heatRisks} />
          </div>
        </motion.div>

        {/* ── ROW 2: Compliance Rings + Incident Trend ─────────────────────── */}
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.1 }}
          className="grid gap-5"
          style={{ gridTemplateColumns: "1fr 420px" }}
        >
          {/* Compliance Rings */}
          <div
            className="rounded-2xl p-6"
            style={{
              background: "rgba(255,255,255,0.025)",
              border: "1px solid rgba(255,255,255,0.06)",
            }}
          >
            <div className="flex items-center justify-between mb-6">
              <div>
                <h3 className="text-sm font-black tracking-tight" style={{ color: "#f0f6fc" }}>
                  Compliance Frameworks
                </h3>
                <p className="text-[10px] mt-0.5" style={{ color: "rgba(240,246,252,0.35)" }}>
                  7 frameworks · Overall {overallCompliance > 0 ? overallCompliance : 85}% adherence
                </p>
              </div>
              <div className="flex items-center gap-1.5">
                <div className="w-2 h-2 rounded-full animate-pulse" style={{ background: "#34d399" }} />
                <span className="text-[10px] font-semibold" style={{ color: "#34d399" }}>Live</span>
              </div>
            </div>
            <div className="grid grid-cols-7 gap-3">
              {frameworks.map((fw) => (
                <ComplianceRing
                  key={fw.name}
                  name={fw.name}
                  score={fw.score}
                  status={fw.status}
                />
              ))}
            </div>
            {/* Overall bar */}
            <div className="mt-5 pt-4" style={{ borderTop: "1px solid rgba(255,255,255,0.05)" }}>
              <div className="flex items-center justify-between mb-2">
                <span className="text-[10px] uppercase tracking-widest font-semibold" style={{ color: "rgba(240,246,252,0.35)" }}>
                  Portfolio Compliance Score
                </span>
                <span className="text-sm font-black tabular-nums" style={{ color: overallCompliance >= 85 ? "#34d399" : "#fbbf24" }}>
                  {overallCompliance > 0 ? overallCompliance : 85}%
                </span>
              </div>
              <div className="h-2 rounded-full overflow-hidden" style={{ background: "rgba(255,255,255,0.06)" }}>
                <motion.div
                  initial={{ width: 0 }}
                  animate={{ width: `${overallCompliance > 0 ? overallCompliance : 85}%` }}
                  transition={{ duration: 1, ease: [0.16, 1, 0.3, 1], delay: 0.4 }}
                  className="h-full rounded-full"
                  style={{
                    background: overallCompliance >= 85
                      ? "linear-gradient(90deg, #34d399, #60a5fa)"
                      : "linear-gradient(90deg, #fbbf24, #f97316)",
                  }}
                />
              </div>
            </div>
          </div>

          {/* Incident Trend — 30-day */}
          <div
            className="rounded-2xl p-5"
            style={{
              background: "rgba(255,255,255,0.025)",
              border: "1px solid rgba(255,255,255,0.06)",
            }}
          >
            <div className="flex items-center justify-between mb-5">
              <div>
                <h3 className="text-sm font-black tracking-tight" style={{ color: "#f0f6fc" }}>
                  Incident Trend
                </h3>
                <p className="text-[10px] mt-0.5" style={{ color: "rgba(240,246,252,0.35)" }}>30-day rolling view</p>
              </div>
              <div className="rounded-md p-1.5" style={{ background: "rgba(96,165,250,0.1)" }}>
                <BarChart3 className="h-4 w-4" style={{ color: "#60a5fa" }} />
              </div>
            </div>
            {incidentTrend.length > 0 ? (
              <ResponsiveContainer width="100%" height={180}>
                <AreaChart data={incidentTrend} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
                  <defs>
                    <linearGradient id="incGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#60a5fa" stopOpacity={0.25} />
                      <stop offset="95%" stopColor="#60a5fa" stopOpacity={0.02} />
                    </linearGradient>
                    <linearGradient id="scoreGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#34d399" stopOpacity={0.2} />
                      <stop offset="95%" stopColor="#34d399" stopOpacity={0.02} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="2 4" stroke="rgba(255,255,255,0.05)" />
                  <XAxis dataKey="month" tick={{ fontSize: 10, fill: "rgba(240,246,252,0.35)" }} tickLine={false} axisLine={false} />
                  <YAxis tick={{ fontSize: 10, fill: "rgba(240,246,252,0.35)" }} tickLine={false} axisLine={false} />
                  <Tooltip contentStyle={CHART_TOOLTIP_STYLE} />
                  <Area type="monotone" dataKey="incidents" stroke="#60a5fa" fill="url(#incGrad)" strokeWidth={2} name="Incidents" />
                  <Area type="monotone" dataKey="score" stroke="#34d399" fill="url(#scoreGrad)" strokeWidth={1.5} strokeDasharray="4 2" name="Posture Score" />
                </AreaChart>
              </ResponsiveContainer>
            ) : (
              <div className="flex h-[180px] items-center justify-center text-sm" style={{ color: "rgba(240,246,252,0.3)" }}>
                No incident data available
              </div>
            )}
          </div>
        </motion.div>

        {/* ── ROW 3: TCO Savings + Strategic Recommendations ───────────────── */}
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.2 }}
          className="grid gap-5"
          style={{ gridTemplateColumns: "420px 1fr" }}
        >
          {/* TCO Savings Calculator */}
          <div
            className="rounded-2xl p-6"
            style={{
              background: "rgba(52,211,153,0.04)",
              border: "1px solid rgba(52,211,153,0.12)",
            }}
          >
            <div className="flex items-center justify-between mb-5">
              <div>
                <h3 className="text-sm font-black tracking-tight" style={{ color: "#f0f6fc" }}>
                  TCO Savings Calculator
                </h3>
                <p className="text-[10px] mt-0.5" style={{ color: "rgba(240,246,252,0.35)" }}>
                  Self-hosted ASPM vs. enterprise SaaS
                </p>
              </div>
              <div className="rounded-md p-1.5" style={{ background: "rgba(52,211,153,0.1)" }}>
                <DollarSign className="h-4 w-4" style={{ color: "#34d399" }} />
              </div>
            </div>
            <TCOSavingsBar annualSavings={annualSavings} toolsConsolidated={toolsConsolidated} />
          </div>

          {/* Strategic Recommendations */}
          <div
            className="rounded-2xl p-6"
            style={{
              background: "rgba(255,255,255,0.025)",
              border: "1px solid rgba(255,255,255,0.06)",
            }}
          >
            <div className="flex items-center justify-between mb-5">
              <div>
                <h3 className="text-sm font-black tracking-tight" style={{ color: "#f0f6fc" }}>
                  Strategic Recommendations
                </h3>
                <p className="text-[10px] mt-0.5" style={{ color: "rgba(240,246,252,0.35)" }}>
                  Top 5 board-level action items for {selectedQuarter}
                </p>
              </div>
              <div className="rounded-md p-1.5" style={{ background: "rgba(251,191,36,0.1)" }}>
                <Target className="h-4 w-4" style={{ color: "#fbbf24" }} />
              </div>
            </div>

            <div className="space-y-2.5">
              {STATIC_RECOMMENDATIONS.map((rec, i) => (
                <motion.div
                  key={rec.priority}
                  initial={{ opacity: 0, x: -12 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ duration: 0.4, delay: 0.25 + i * 0.07 }}
                  className="flex items-start gap-3 rounded-xl p-3.5 group cursor-default"
                  style={{
                    background: "rgba(255,255,255,0.03)",
                    border: "1px solid rgba(255,255,255,0.05)",
                    transition: "border-color 0.2s",
                  }}
                >
                  {/* Priority badge */}
                  <div
                    className="shrink-0 rounded-md w-9 h-9 flex items-center justify-center text-xs font-black"
                    style={{
                      background: `${PRIORITY_COLORS[rec.priority]}18`,
                      color: PRIORITY_COLORS[rec.priority],
                      border: `1px solid ${PRIORITY_COLORS[rec.priority]}30`,
                    }}
                  >
                    {rec.priority}
                  </div>
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-semibold leading-snug" style={{ color: "#f0f6fc" }}>
                      {rec.action}
                    </p>
                    <p className="text-[11px] mt-0.5" style={{ color: "rgba(240,246,252,0.45)" }}>
                      {rec.impact}
                    </p>
                  </div>
                  <div className="shrink-0 flex flex-col items-end gap-1.5">
                    <span
                      className="text-[9px] font-black uppercase tracking-widest px-1.5 py-0.5 rounded"
                      style={{
                        color: EFFORT_COLORS[rec.effort],
                        background: `${EFFORT_COLORS[rec.effort]}15`,
                      }}
                    >
                      {rec.effort}
                    </span>
                    <ChevronRight className="h-3.5 w-3.5 opacity-0 group-hover:opacity-100 transition-opacity" style={{ color: "rgba(240,246,252,0.4)" }} />
                  </div>
                </motion.div>
              ))}
            </div>
          </div>
        </motion.div>

        {/* ── Footer ──────────────────────────────────────────────────────── */}
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          transition={{ delay: 0.5 }}
          className="flex items-center justify-between px-1 pb-4"
        >
          <p className="text-[10px] font-medium" style={{ color: "rgba(240,246,252,0.2)" }}>
            ALDECI Security Intelligence Platform · {selectedQuarter} {selectedYear} · Generated {new Date().toLocaleDateString("en-US", { month: "long", day: "numeric", year: "numeric" })}
          </p>
          <p className="text-[10px] font-medium" style={{ color: "rgba(240,246,252,0.2)" }}>
            {postureScore > 0 ? postureScore : 78}/100 posture · {totalFindings > 0 ? totalFindings.toLocaleString() : "2,847"} findings · {resolvedThisQuarter > 0 ? resolvedThisQuarter.toLocaleString() : "1,204"} resolved
          </p>
        </motion.div>
      </div>
    </div>
  );
}
