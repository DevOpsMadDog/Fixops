/**
 * Risk Overview — Premium Enterprise Redesign
 *
 * Aesthetic: "Threat Operations Center"
 * - Dark glass-morphism panels with sharp amber/red accent system
 * - Animated 5x5 risk heatmap as the centrepiece visual
 * - Monospace data values, editorial weight typography
 * - KRI cards with threshold pulse animation
 * - Treatment status with segmented progress bars
 */

import { useState, useCallback, useEffect, useRef } from "react";
import { motion, AnimatePresence, useInView } from "framer-motion";
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, PieChart, Pie, Cell,
} from "recharts";
import {
  Shield, AlertTriangle, TrendingUp, TrendingDown, RefreshCw,
  Target, Activity, ArrowUp, ArrowDown, Minus, BarChart3,
  Building2, Eye, ChevronUp, ChevronDown, Layers,
  Zap, TriangleAlert, CircleAlert, CheckCircle2, Clock,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Tooltip as UITooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { PageHeader } from "@/components/shared/page-header";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import {
  useDashboardOverview,
  useDashboardTopRisks,
  useDashboardTrends,
} from "@/hooks/use-api";
import { cn } from "@/lib/utils";

// ─── Design Tokens ────────────────────────────────────────────

const SEVERITY = {
  critical: { bg: "bg-red-500/20", border: "border-red-500/50", text: "text-red-400", glow: "shadow-red-500/30", hex: "#ef4444", label: "Critical" },
  high:     { bg: "bg-orange-500/20", border: "border-orange-500/50", text: "text-orange-400", glow: "shadow-orange-500/30", hex: "#f97316", label: "High" },
  medium:   { bg: "bg-amber-500/20", border: "border-amber-500/50", text: "text-amber-400", glow: "shadow-amber-500/30", hex: "#f59e0b", label: "Medium" },
  low:      { bg: "bg-emerald-500/20", border: "border-emerald-500/50", text: "text-emerald-400", glow: "shadow-emerald-500/30", hex: "#10b981", label: "Low" },
  none:     { bg: "bg-slate-800/40", border: "border-slate-700/30", text: "text-slate-500", glow: "", hex: "#334155", label: "None" },
} as const;

type SeverityKey = keyof typeof SEVERITY;

const CHART_STYLE = {
  background: "oklch(0.17 0.01 250)",
  border: "1px solid oklch(0.25 0.01 250)",
  borderRadius: 8,
  fontSize: 11,
  color: "oklch(0.80 0.005 250)",
};

// ─── Heatmap ────────────────────────────────────────────────

const HEATMAP_ROWS = ["Very High", "High", "Medium", "Low", "Very Low"];
const HEATMAP_COLS = ["Rare", "Unlikely", "Possible", "Likely", "Almost\nCertain"];

function cellSeverity(row: number, col: number): SeverityKey {
  const score = (4 - row) + col;
  if (score >= 7) return "critical";
  if (score >= 5) return "high";
  if (score >= 3) return "medium";
  if (score >= 1) return "low";
  return "none";
}

function RiskHeatmap({ activeCell }: { activeCell: [number, number] | null }) {
  const ref = useRef<HTMLDivElement>(null);
  const inView = useInView(ref, { once: true, margin: "-40px" });

  return (
    <div ref={ref} className="w-full">
      {/* Column headers */}
      <div className="grid mb-1" style={{ gridTemplateColumns: "72px repeat(5, 1fr)" }}>
        <div />
        {HEATMAP_COLS.map((c, i) => (
          <div key={i} className="text-center text-[9px] font-semibold tracking-widest uppercase text-slate-500 px-0.5 leading-tight whitespace-pre-line">
            {c}
          </div>
        ))}
      </div>
      {/* Rows */}
      {HEATMAP_ROWS.map((rowLabel, row) => (
        <div key={row} className="grid gap-1 mb-1" style={{ gridTemplateColumns: "72px repeat(5, 1fr)" }}>
          <div className="flex items-center justify-end pr-2">
            <span className="text-[9px] font-semibold tracking-widest uppercase text-slate-500 text-right leading-tight">{rowLabel}</span>
          </div>
          {HEATMAP_COLS.map((_, col) => {
            const sev = cellSeverity(row, col);
            const s = SEVERITY[sev];
            const isActive = activeCell?.[0] === row && activeCell?.[1] === col;
            const delay = inView ? (row * 5 + col) * 0.03 : 0;
            return (
              <motion.div
                key={col}
                initial={{ opacity: 0, scale: 0.6 }}
                animate={inView ? { opacity: 1, scale: 1 } : {}}
                transition={{ delay, duration: 0.3, ease: [0.16, 1, 0.3, 1] }}
                className={cn(
                  "relative aspect-square rounded-[5px] border cursor-default transition-all duration-200",
                  s.bg, s.border,
                  isActive && "ring-2 ring-white/40 scale-105",
                  sev === "critical" && "shadow-[0_0_10px_rgba(239,68,68,0.35)]",
                  sev === "high" && "shadow-[0_0_8px_rgba(249,115,22,0.25)]",
                )}
              >
                {/* Subtle grid letter */}
                <span className={cn("absolute inset-0 flex items-center justify-center text-[10px] font-bold tabular-nums", s.text, "opacity-60")}>
                  {s.label[0]}
                </span>
              </motion.div>
            );
          })}
        </div>
      ))}
      {/* Legend */}
      <div className="flex items-center gap-3 mt-3 justify-end">
        {(["critical", "high", "medium", "low"] as SeverityKey[]).map((k) => (
          <div key={k} className="flex items-center gap-1.5">
            <span className={cn("h-2 w-2 rounded-sm border", SEVERITY[k].bg, SEVERITY[k].border)} />
            <span className="text-[9px] uppercase tracking-widest font-semibold text-slate-500">{SEVERITY[k].label}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Org Risk Gauge ─────────────────────────────────────────

function OrgRiskGauge({ score, change }: { score: number; change: number }) {
  const pct = Math.min(100, Math.max(0, score));
  const sev: SeverityKey = pct >= 80 ? "critical" : pct >= 60 ? "high" : pct >= 40 ? "medium" : "low";
  const s = SEVERITY[sev];

  const r = 52;
  const cx = 70;
  const cy = 70;
  const startAngle = -210;
  const endAngle = 30;
  const totalArc = endAngle - startAngle;
  const fillAngle = startAngle + (totalArc * pct) / 100;
  const toRad = (deg: number) => (deg * Math.PI) / 180;
  const arcPath = (a1: number, a2: number) => {
    const x1 = cx + r * Math.cos(toRad(a1));
    const y1 = cy + r * Math.sin(toRad(a1));
    const x2 = cx + r * Math.cos(toRad(a2));
    const y2 = cy + r * Math.sin(toRad(a2));
    const large = Math.abs(a2 - a1) > 180 ? 1 : 0;
    return `M ${x1} ${y1} A ${r} ${r} 0 ${large} 1 ${x2} ${y2}`;
  };

  return (
    <div className="flex flex-col items-center">
      <svg width={140} height={110} viewBox="0 0 140 110">
        {/* Track */}
        <path d={arcPath(startAngle, endAngle)} fill="none" stroke="oklch(0.25 0.01 250)" strokeWidth={8} strokeLinecap="round" />
        {/* Filled arc */}
        <path d={arcPath(startAngle, fillAngle)} fill="none" stroke={s.hex} strokeWidth={8} strokeLinecap="round"
          style={{ filter: `drop-shadow(0 0 6px ${s.hex}88)` }} />
        {/* Score */}
        <text x={cx} y={cy + 6} textAnchor="middle" fill={s.hex} fontSize={30} fontWeight="800" fontFamily="'JetBrains Mono', monospace">
          {pct}
        </text>
        <text x={cx} y={cy + 22} textAnchor="middle" fill="oklch(0.55 0.01 250)" fontSize={10} fontWeight="600" letterSpacing="0.1em" fontFamily="inherit">
          {s.label.toUpperCase()}
        </text>
      </svg>
      <div className="flex items-center gap-1.5 text-[11px] font-medium mt-0.5">
        {change > 0 ? (
          <><ArrowUp className="h-3 w-3 text-red-400" /><span className="text-red-400 font-mono">+{change}</span></>
        ) : change < 0 ? (
          <><ArrowDown className="h-3 w-3 text-emerald-400" /><span className="text-emerald-400 font-mono">{change}</span></>
        ) : (
          <><Minus className="h-3 w-3 text-slate-500" /><span className="text-slate-500">Unchanged</span></>
        )}
        <span className="text-slate-600">vs prior period</span>
      </div>
      <p className="text-[9px] font-bold uppercase tracking-[0.18em] text-slate-600 mt-1">Org Risk Score</p>
    </div>
  );
}

// ─── KRI Card ────────────────────────────────────────────────

interface KRICardProps {
  label: string;
  value: number;
  threshold: number;
  unit?: string;
  icon: React.ElementType;
  description: string;
  lowerIsBetter?: boolean;
}

function KRICard({ label, value, threshold, unit = "", icon: Icon, description, lowerIsBetter = true }: KRICardProps) {
  const breached = lowerIsBetter ? value > threshold : value < threshold;
  const pct = Math.min(100, lowerIsBetter ? (value / (threshold * 1.5)) * 100 : (value / threshold) * 100);
  const [pulse, setPulse] = useState(false);

  useEffect(() => {
    if (breached) {
      const id = setInterval(() => setPulse(p => !p), 1800);
      return () => clearInterval(id);
    }
  }, [breached]);

  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
      className={cn(
        "relative rounded-xl border p-4 overflow-hidden transition-all duration-300",
        breached
          ? "border-red-500/40 bg-red-500/[0.06]"
          : "border-slate-700/50 bg-slate-800/30",
        breached && pulse && "shadow-[0_0_20px_rgba(239,68,68,0.15)]",
      )}
    >
      {/* Ambient glow top-right */}
      {breached && (
        <div className="absolute -top-4 -right-4 h-16 w-16 rounded-full bg-red-500/20 blur-xl pointer-events-none" />
      )}
      <div className="flex items-start justify-between mb-3">
        <div className={cn(
          "rounded-lg p-2 transition-colors",
          breached ? "bg-red-500/15" : "bg-slate-700/40"
        )}>
          <Icon className={cn("h-4 w-4", breached ? "text-red-400" : "text-slate-400")} />
        </div>
        <Badge className={cn(
          "text-[9px] font-bold tracking-widest border px-1.5 py-0.5",
          breached
            ? "border-red-500/40 text-red-400 bg-red-500/10"
            : "border-emerald-500/30 text-emerald-400 bg-emerald-500/10"
        )}>
          {breached ? "BREACH" : "NORMAL"}
        </Badge>
      </div>
      <p className="text-[10px] font-bold uppercase tracking-[0.15em] text-slate-500 mb-1">{label}</p>
      <p className={cn("text-2xl font-black tabular-nums font-mono leading-none", breached ? "text-red-300" : "text-slate-100")}>
        {value.toLocaleString()}<span className="text-xs font-medium text-slate-500 ml-1">{unit}</span>
      </p>
      <p className="text-[10px] text-slate-600 mt-1">Threshold: <span className="font-mono text-slate-500">{threshold}{unit}</span></p>
      {/* Mini bar */}
      <div className="mt-3 h-1 rounded-full bg-slate-700/50 overflow-hidden">
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${pct}%` }}
          transition={{ duration: 0.8, ease: [0.16, 1, 0.3, 1], delay: 0.2 }}
          className={cn("h-full rounded-full", breached ? "bg-red-500" : "bg-emerald-500")}
        />
      </div>
      <p className="text-[9px] text-slate-600 mt-2 leading-tight">{description}</p>
    </motion.div>
  );
}

// ─── Treatment Progress ──────────────────────────────────────

interface TreatmentBarProps {
  label?: string;
  title?: string;
  mitigated: number;
  accepted: number;
  transferred: number;
  avoided: number;
}

function TreatmentBar({ label, title, mitigated, accepted, transferred, avoided }: TreatmentBarProps) {
  const _label = label ?? title ?? "";
  const total = mitigated + accepted + transferred + avoided || 1;
  const segments = [
    { label: "Mitigated", value: mitigated, color: "bg-emerald-500" },
    { label: "Accepted", value: accepted, color: "bg-amber-500" },
    { label: "Transferred", value: transferred, color: "bg-blue-500" },
    { label: "Avoided", value: avoided, color: "bg-slate-500" },
  ];

  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between">
        <span className="text-[11px] font-semibold text-slate-300">{_label}</span>
        <span className="text-[10px] font-mono text-slate-500">{total} risks</span>
      </div>
      <div className="flex h-2 rounded-full overflow-hidden gap-px">
        {segments.map((seg) => {
          const pct = (seg.value / total) * 100;
          if (pct === 0) return null;
          return (
            <motion.div
              key={seg.label}
              initial={{ width: 0 }}
              animate={{ width: `${pct}%` }}
              transition={{ duration: 0.8, ease: [0.16, 1, 0.3, 1] }}
              className={cn("h-full", seg.color)}
              title={`${seg.label}: ${seg.value}`}
            />
          );
        })}
      </div>
      <div className="flex items-center gap-3 flex-wrap">
        {segments.filter(s => s.value > 0).map((seg) => (
          <div key={seg.label} className="flex items-center gap-1">
            <span className={cn("h-1.5 w-1.5 rounded-full", seg.color)} />
            <span className="text-[9px] text-slate-600">{seg.label}: <span className="font-mono text-slate-500">{seg.value}</span></span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ─── Risk Score Bar ──────────────────────────────────────────

function RiskScoreBar({ score, max = 100 }: { score: number; max?: number }) {
  const pct = Math.min(100, (score / max) * 100);
  const sev: SeverityKey = pct >= 80 ? "critical" : pct >= 60 ? "high" : pct >= 40 ? "medium" : "low";
  return (
    <div className="flex items-center gap-2">
      <span className={cn("text-xs font-black tabular-nums font-mono w-7 text-right", SEVERITY[sev].text)}>
        {score.toFixed(0)}
      </span>
      <div className="relative flex-1 h-1.5 rounded-full bg-slate-700/50 overflow-hidden">
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${pct}%` }}
          transition={{ duration: 0.7, ease: [0.16, 1, 0.3, 1] }}
          className="h-full rounded-full"
          style={{ backgroundColor: SEVERITY[sev].hex, boxShadow: `0 0 6px ${SEVERITY[sev].hex}66` }}
        />
      </div>
    </div>
  );
}

// ─── SLA Badge ───────────────────────────────────────────────

function SlaStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    compliant: "border-emerald-500/30 text-emerald-400 bg-emerald-500/10",
    at_risk: "border-amber-500/30 text-amber-400 bg-amber-500/10",
    breached: "border-red-500/40 text-red-400 bg-red-500/10",
  };
  return (
    <Badge className={cn("text-[9px] font-bold tracking-wide border uppercase px-1.5", map[status] ?? "border-slate-700/40 text-slate-500")}>
      {status?.replace("_", " ") || "—"}
    </Badge>
  );
}

// ─── Stat Chip ────────────────────────────────────────────────

function StatChip({ label, value, sev, change }: {
  label: string; value: number; sev: SeverityKey; change?: number;
}) {
  const s = SEVERITY[sev];
  return (
    <motion.div
      initial={{ opacity: 0, scale: 0.92 }}
      animate={{ opacity: 1, scale: 1 }}
      transition={{ duration: 0.35, ease: [0.16, 1, 0.3, 1] }}
      className={cn(
        "relative rounded-xl border p-4 overflow-hidden",
        s.border,
        sev === "critical" ? "bg-red-500/[0.07]" : sev === "high" ? "bg-orange-500/[0.07]" : "bg-slate-800/30"
      )}
    >
      {/* Glow dot top-left */}
      {(sev === "critical" || sev === "high") && (
        <div className={cn("absolute top-3 right-3 h-1.5 w-1.5 rounded-full", sev === "critical" ? "bg-red-400" : "bg-orange-400")}
          style={{ boxShadow: `0 0 6px ${s.hex}` }} />
      )}
      <p className="text-[9px] font-bold uppercase tracking-[0.18em] text-slate-500 mb-1">{label}</p>
      <p className={cn("text-3xl font-black tabular-nums font-mono leading-none", s.text)}>{value.toLocaleString()}</p>
      {change !== undefined && (
        <div className={cn("flex items-center gap-0.5 mt-2 text-[10px] font-semibold", change > 0 ? "text-red-400" : change < 0 ? "text-emerald-400" : "text-slate-600")}>
          {change > 0 ? <ArrowUp className="h-3 w-3" /> : change < 0 ? <ArrowDown className="h-3 w-3" /> : <Minus className="h-3 w-3" />}
          <span className="font-mono">{change > 0 ? "+" : ""}{change}%</span>
        </div>
      )}
    </motion.div>
  );
}

// ─── Types ───────────────────────────────────────────────────

interface AppRiskRow {
  name: string;
  riskScore: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  slaStatus: string;
  likelihood?: number;
  impact?: number;
}

// ─── Custom Tooltip ───────────────────────────────────────────

function CustomAreaTooltip({ active, payload, label }: {
  active?: boolean; payload?: Array<{ name: string; value: number; color: string }>; label?: string;
}) {
  if (!active || !payload?.length) return null;
  return (
    <div className="rounded-lg border border-slate-700/60 bg-slate-900/95 px-3 py-2 shadow-xl">
      <p className="text-[10px] font-mono text-slate-500 mb-1.5">{label}</p>
      {payload.map((p) => (
        <div key={p.name} className="flex items-center gap-2 text-[11px]">
          <span className="h-1.5 w-1.5 rounded-full" style={{ backgroundColor: p.color }} />
          <span className="text-slate-400 capitalize">{p.name}:</span>
          <span className="font-mono font-bold text-slate-200">{p.value}</span>
        </div>
      ))}
    </div>
  );
}

// ─── Main Component ──────────────────────────────────────────

export default function RiskOverview() {
  const [trendPeriod, setTrendPeriod] = useState("30d");
  const [sortField, setSortField] = useState<keyof AppRiskRow>("riskScore");
  const [sortAsc, setSortAsc] = useState(false);
  const [activeHeatmapCell, setActiveHeatmapCell] = useState<[number, number] | null>(null);

  const overview = useDashboardOverview();
  const topRisks = useDashboardTopRisks();
  const trends = useDashboardTrends({ period: trendPeriod });

  const isLoading = overview.isLoading || topRisks.isLoading;
  const isError = overview.isError && topRisks.isError;
  const refetch = useCallback(() => {
    overview.refetch();
    topRisks.refetch();
    trends.refetch();
  }, [overview, topRisks, trends]);

  if (isLoading) return <PageSkeleton />;
  if (isError) return <ErrorState message="Failed to load risk data" onRetry={refetch} />;

  const ov = overview.data ?? {};
  const trendData = trends.data ?? {};
  const risksData = topRisks.data ?? {};

  const orgRiskScore = Number(ov.risk_score ?? ov.posture_score ?? 0);
  const riskChange = Number(ov.risk_change ?? ov.posture_change ?? 0);
  const criticalCount = Number(ov.critical_findings ?? 0);
  const highCount = Number(ov.high_findings ?? 0);
  const mediumCount = Number(ov.medium_findings ?? 0);
  const lowCount = Number(ov.low_findings ?? 0);
  const totalFindings = criticalCount + highCount + mediumCount + lowCount;

  const rawRisks: Record<string, unknown>[] = risksData.risks ?? risksData.top_risks ?? risksData.apps ?? [];
  const appRows: AppRiskRow[] = rawRisks.slice(0, 10).map((r) => ({
    name: String(r.name ?? r.app_name ?? r.title ?? r.component ?? "Unknown"),
    riskScore: Number(r.risk_score ?? r.cvss_score ?? r.score ?? 0),
    critical: Number(r.critical ?? r.critical_count ?? 0),
    high: Number(r.high ?? r.high_count ?? 0),
    medium: Number(r.medium ?? r.medium_count ?? 0),
    low: Number(r.low ?? r.low_count ?? 0),
    slaStatus: String(r.sla_status ?? r.status ?? "—"),
    likelihood: Number(r.likelihood ?? 3),
    impact: Number(r.impact ?? 3),
  }));

  const sortedAppRows = [...appRows].sort((a, b) => {
    const av = a[sortField];
    const bv = b[sortField];
    if (typeof av === "number" && typeof bv === "number") return sortAsc ? av - bv : bv - av;
    return sortAsc ? String(av).localeCompare(String(bv)) : String(bv).localeCompare(String(av));
  });

  // Pie data
  const pieData = [
    { name: "Critical", value: criticalCount, hex: SEVERITY.critical.hex },
    { name: "High",     value: highCount,     hex: SEVERITY.high.hex },
    { name: "Medium",   value: mediumCount,   hex: SEVERITY.medium.hex },
    { name: "Low",      value: lowCount,      hex: SEVERITY.low.hex },
  ].filter((d) => d.value > 0);

  // Trend chart
  const riskTrend = (trendData.risk_trend ?? trendData.series ?? []).map((d: Record<string, unknown>) => ({
    date: String(d.date ?? d.period ?? ""),
    score: Number(d.risk_score ?? d.score ?? d.total ?? 0),
    critical: Number(d.critical ?? 0),
    high: Number(d.high ?? 0),
  }));

  // Business impact areas
  const impactAreas = [
    { label: "Data Exposure",       value: Number(ov.data_exposure_risk ?? 0),  description: "Sensitive data compromise risk" },
    { label: "Service Availability",value: Number(ov.availability_risk ?? 0),   description: "Uptime and continuity risk" },
    { label: "Compliance Exposure", value: Number(ov.compliance_risk ?? 0),     description: "Regulatory and audit risk" },
    { label: "Reputation Impact",   value: Number(ov.reputation_risk ?? 0),     description: "Potential reputational damage" },
  ];

  // KRI data (derived from available data)
  const kriItems: KRICardProps[] = [
    {
      label: "Critical Findings",
      value: criticalCount,
      threshold: 5,
      icon: TriangleAlert,
      description: "Open critical-severity findings requiring immediate action",
      lowerIsBetter: true,
    },
    {
      label: "High Severity",
      value: highCount,
      threshold: 20,
      icon: CircleAlert,
      description: "High severity findings pending remediation",
      lowerIsBetter: true,
    },
    {
      label: "Risk Score",
      value: orgRiskScore,
      threshold: 60,
      icon: Shield,
      description: "Composite organisational risk score (0–100)",
      lowerIsBetter: true,
    },
    {
      label: "Total Findings",
      value: totalFindings,
      threshold: 100,
      icon: Layers,
      description: "Aggregated finding count across all severity levels",
      lowerIsBetter: true,
    },
    {
      label: "Risky Assets",
      value: appRows.length,
      threshold: 8,
      icon: Building2,
      description: "Applications or assets above risk threshold",
      lowerIsBetter: true,
    },
    {
      label: "Compliant Assets",
      value: appRows.filter((a) => a.slaStatus === "compliant").length,
      threshold: Math.max(1, Math.floor(appRows.length * 0.7)),
      icon: CheckCircle2,
      description: "Assets meeting SLA compliance requirements",
      lowerIsBetter: false,
    },
  ];

  const handleSort = (field: keyof AppRiskRow) => {
    if (sortField === field) setSortAsc(!sortAsc);
    else { setSortField(field); setSortAsc(false); }
  };

  const SortIcon = ({ field }: { field: keyof AppRiskRow }) => {
    if (sortField !== field) return <ChevronDown className="h-3 w-3 opacity-25 inline ml-0.5" />;
    return sortAsc
      ? <ChevronUp className="h-3 w-3 inline ml-0.5 text-primary" />
      : <ChevronDown className="h-3 w-3 inline ml-0.5 text-primary" />;
  };

  return (
    <TooltipProvider>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        transition={{ duration: 0.4 }}
        className="flex flex-col gap-6 pb-8"
      >
        {/* ── Header ── */}
        <PageHeader
          title="Risk Overview"
          description="Organisational risk posture, threat heatmap, and key risk indicators"
          actions={
            <div className="flex items-center gap-2">
              <Select value={trendPeriod} onValueChange={setTrendPeriod}>
                <SelectTrigger className="h-8 w-[100px] text-xs border-slate-700/50 bg-slate-800/40">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="30d">30 days</SelectItem>
                  <SelectItem value="60d">60 days</SelectItem>
                  <SelectItem value="90d">90 days</SelectItem>
                </SelectContent>
              </Select>
              <Button variant="outline" size="sm" onClick={refetch}
                className="border-slate-700/50 bg-slate-800/40 hover:bg-slate-700/50 h-8">
                <RefreshCw className={cn("h-3.5 w-3.5", overview.isFetching && "animate-spin")} />
              </Button>
            </div>
          }
        />

        {/* ── Row 1: Gauge + Stat chips + Heatmap ── */}
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-12">

          {/* Gauge + Stat chips */}
          <motion.div
            initial={{ opacity: 0, x: -16 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.45, ease: [0.16, 1, 0.3, 1] }}
            className="lg:col-span-3 flex flex-col gap-4"
          >
            {/* Gauge card */}
            <div className="rounded-xl border border-slate-700/40 bg-slate-800/30 p-5 flex flex-col items-center justify-center">
              <OrgRiskGauge score={orgRiskScore} change={riskChange} />
            </div>
            {/* 4 stat chips */}
            <div className="grid grid-cols-2 gap-3">
              <StatChip label="Critical" value={criticalCount} sev="critical" />
              <StatChip label="High" value={highCount} sev="high" />
              <StatChip label="Medium" value={mediumCount} sev="medium" />
              <StatChip label="Low" value={lowCount} sev="low" />
            </div>
          </motion.div>

          {/* Heatmap */}
          <motion.div
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.45, delay: 0.08, ease: [0.16, 1, 0.3, 1] }}
            className="lg:col-span-5"
          >
            <div className="h-full rounded-xl border border-slate-700/40 bg-slate-800/30 p-5">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className="text-xs font-bold uppercase tracking-[0.16em] text-slate-300 flex items-center gap-2">
                    <Target className="h-3.5 w-3.5 text-amber-400" />
                    Risk Heatmap
                  </h3>
                  <p className="text-[10px] text-slate-600 mt-0.5">Likelihood × Impact matrix</p>
                </div>
                <div className="flex items-center gap-1.5 text-[9px] font-mono text-slate-600 bg-slate-700/30 rounded px-2 py-1">
                  <span>5×5</span>
                </div>
              </div>
              <RiskHeatmap activeCell={activeHeatmapCell} />
            </div>
          </motion.div>

          {/* Donut chart */}
          <motion.div
            initial={{ opacity: 0, x: 16 }}
            animate={{ opacity: 1, x: 0 }}
            transition={{ duration: 0.45, delay: 0.12, ease: [0.16, 1, 0.3, 1] }}
            className="lg:col-span-4"
          >
            <div className="h-full rounded-xl border border-slate-700/40 bg-slate-800/30 p-5">
              <div className="flex items-center justify-between mb-3">
                <div>
                  <h3 className="text-xs font-bold uppercase tracking-[0.16em] text-slate-300 flex items-center gap-2">
                    <BarChart3 className="h-3.5 w-3.5 text-blue-400" />
                    Risk by Category
                  </h3>
                  <p className="text-[10px] text-slate-600 mt-0.5">{totalFindings.toLocaleString()} total findings</p>
                </div>
              </div>
              {pieData.length > 0 ? (
                <>
                  <ResponsiveContainer width="100%" height={170}>
                    <PieChart>
                      <Pie
                        data={pieData}
                        cx="50%"
                        cy="50%"
                        innerRadius={48}
                        outerRadius={72}
                        paddingAngle={3}
                        dataKey="value"
                        strokeWidth={0}
                        animationBegin={200}
                        animationDuration={800}
                      >
                        {pieData.map((entry, i) => (
                          <Cell key={i} fill={entry.hex} fillOpacity={0.85} />
                        ))}
                      </Pie>
                      <Tooltip content={({ active, payload }) => {
                        if (!active || !payload?.length) return null;
                        const p = payload[0];
                        const pct = totalFindings > 0 ? ((p.value as number) / totalFindings * 100).toFixed(1) : "0";
                        return (
                          <div className="rounded-lg border border-slate-700/60 bg-slate-900/95 px-3 py-2 shadow-xl">
                            <p className="text-[11px] font-semibold text-slate-200">{p.name}</p>
                            <p className="text-[10px] font-mono text-slate-400">{(p.value as number).toLocaleString()} · {pct}%</p>
                          </div>
                        );
                      }} />
                    </PieChart>
                  </ResponsiveContainer>
                  <div className="grid grid-cols-2 gap-x-4 gap-y-2 mt-1">
                    {pieData.map((d) => {
                      const pct = totalFindings > 0 ? ((d.value / totalFindings) * 100).toFixed(0) : "0";
                      return (
                        <div key={d.name} className="flex items-center justify-between">
                          <div className="flex items-center gap-1.5">
                            <span className="h-2 w-2 rounded-sm" style={{ backgroundColor: d.hex }} />
                            <span className="text-[10px] text-slate-500">{d.name}</span>
                          </div>
                          <div className="flex items-center gap-1">
                            <span className="text-[10px] font-black font-mono text-slate-300">{d.value}</span>
                            <span className="text-[9px] text-slate-600">({pct}%)</span>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </>
              ) : (
                <div className="flex h-[200px] items-center justify-center flex-col gap-3">
                  <Eye className="h-8 w-8 text-slate-700" />
                  <p className="text-[11px] text-slate-600">No finding data available</p>
                </div>
              )}
            </div>
          </motion.div>
        </div>

        {/* ── Row 2: Risk Trend Chart ── */}
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.45, delay: 0.16, ease: [0.16, 1, 0.3, 1] }}
          className="rounded-xl border border-slate-700/40 bg-slate-800/30 p-5"
        >
          <div className="flex items-center justify-between mb-4">
            <div>
              <h3 className="text-xs font-bold uppercase tracking-[0.16em] text-slate-300 flex items-center gap-2">
                <Activity className="h-3.5 w-3.5 text-red-400" />
                Risk Trend
              </h3>
              <p className="text-[10px] text-slate-600 mt-0.5">Critical & high severity volume · {trendPeriod} window</p>
            </div>
            <div className="flex items-center gap-3">
              {[{ label: "Critical", color: SEVERITY.critical.hex }, { label: "High", color: SEVERITY.high.hex }].map((item) => (
                <div key={item.label} className="flex items-center gap-1.5 text-[10px] text-slate-500">
                  <span className="h-2 w-3 rounded-sm" style={{ backgroundColor: item.color, opacity: 0.7 }} />
                  {item.label}
                </div>
              ))}
            </div>
          </div>
          {riskTrend.length > 0 ? (
            <ResponsiveContainer width="100%" height={220}>
              <AreaChart data={riskTrend} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
                <defs>
                  <linearGradient id="gradCrit" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#ef4444" stopOpacity={0.35} />
                    <stop offset="100%" stopColor="#ef4444" stopOpacity={0.02} />
                  </linearGradient>
                  <linearGradient id="gradHigh" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#f97316" stopOpacity={0.25} />
                    <stop offset="100%" stopColor="#f97316" stopOpacity={0.02} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="2 4" stroke="oklch(0.25 0.01 250)" strokeOpacity={0.6} />
                <XAxis dataKey="date" tick={{ fontSize: 10, fill: "oklch(0.50 0.01 250)", fontFamily: "JetBrains Mono, monospace" }} tickLine={false} axisLine={false} />
                <YAxis tick={{ fontSize: 10, fill: "oklch(0.50 0.01 250)", fontFamily: "JetBrains Mono, monospace" }} tickLine={false} axisLine={false} />
                <Tooltip content={<CustomAreaTooltip />} />
                <Area type="monotone" dataKey="high" stackId="1" stroke="#f97316" fill="url(#gradHigh)" strokeWidth={1.5} name="high" />
                <Area type="monotone" dataKey="critical" stackId="1" stroke="#ef4444" fill="url(#gradCrit)" strokeWidth={1.5} name="critical" />
              </AreaChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex h-[220px] items-center justify-center flex-col gap-3">
              <BarChart3 className="h-8 w-8 text-slate-700" />
              <p className="text-[11px] text-slate-600">Run scans to populate trend data</p>
            </div>
          )}
        </motion.div>

        {/* ── Row 3: Top Risks Table ── */}
        <motion.div
          initial={{ opacity: 0, y: 16 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.45, delay: 0.2, ease: [0.16, 1, 0.3, 1] }}
          className="rounded-xl border border-slate-700/40 bg-slate-800/30 overflow-hidden"
        >
          <div className="flex items-center justify-between px-5 py-4 border-b border-slate-700/40">
            <div>
              <h3 className="text-xs font-bold uppercase tracking-[0.16em] text-slate-300 flex items-center gap-2">
                <Building2 className="h-3.5 w-3.5 text-orange-400" />
                Top Risks
              </h3>
              <p className="text-[10px] text-slate-600 mt-0.5">Likelihood × Impact scoring · click headers to sort</p>
            </div>
            <Badge className="border-slate-700/40 bg-slate-700/30 text-slate-400 text-[9px] font-mono px-2">
              {appRows.length} assets
            </Badge>
          </div>
          {sortedAppRows.length > 0 ? (
            <ScrollArea className="h-[340px]">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent border-b border-slate-700/30">
                    <TableHead className="text-[9px] font-bold uppercase tracking-widest text-slate-600 h-9 pl-5">#</TableHead>
                    <TableHead className="text-[9px] font-bold uppercase tracking-widest text-slate-600 h-9">Asset / Application</TableHead>
                    <TableHead
                      className="text-[9px] font-bold uppercase tracking-widest text-slate-600 h-9 cursor-pointer hover:text-slate-300 transition-colors"
                      onClick={() => handleSort("riskScore")}
                    >
                      Risk Score <SortIcon field="riskScore" />
                    </TableHead>
                    <TableHead
                      className="text-[9px] font-bold uppercase tracking-widest text-slate-600 h-9 cursor-pointer hover:text-slate-300 transition-colors"
                      onClick={() => handleSort("likelihood")}
                    >
                      L×I <SortIcon field="likelihood" />
                    </TableHead>
                    <TableHead
                      className="text-[9px] font-bold uppercase tracking-widest text-slate-600 h-9 cursor-pointer hover:text-slate-300 transition-colors"
                      onClick={() => handleSort("critical")}
                    >
                      Crit <SortIcon field="critical" />
                    </TableHead>
                    <TableHead
                      className="text-[9px] font-bold uppercase tracking-widest text-slate-600 h-9 cursor-pointer hover:text-slate-300 transition-colors"
                      onClick={() => handleSort("high")}
                    >
                      High <SortIcon field="high" />
                    </TableHead>
                    <TableHead
                      className="text-[9px] font-bold uppercase tracking-widest text-slate-600 h-9 cursor-pointer hover:text-slate-300 transition-colors"
                      onClick={() => handleSort("medium")}
                    >
                      Med <SortIcon field="medium" />
                    </TableHead>
                    <TableHead className="text-[9px] font-bold uppercase tracking-widest text-slate-600 h-9">SLA</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {sortedAppRows.map((row, i) => {
                    const lxiScore = (row.likelihood ?? 3) * (row.impact ?? 3);
                    const rowSev: SeverityKey = row.riskScore >= 80 ? "critical" : row.riskScore >= 60 ? "high" : row.riskScore >= 40 ? "medium" : "low";
                    return (
                      <TableRow
                        key={i}
                        className="border-b border-slate-700/20 hover:bg-slate-700/20 transition-colors"
                        onMouseEnter={() => setActiveHeatmapCell([(row.impact ?? 3) >= 4 ? 0 : (row.impact ?? 3) >= 3 ? 1 : 2, (row.likelihood ?? 3) >= 4 ? 4 : (row.likelihood ?? 3) >= 3 ? 3 : 2])}
                        onMouseLeave={() => setActiveHeatmapCell(null)}
                      >
                        <TableCell className="py-3 pl-5">
                          <span className="text-[10px] font-mono font-black text-slate-600">
                            {String(i + 1).padStart(2, "0")}
                          </span>
                        </TableCell>
                        <TableCell className="py-3">
                          <div className="flex items-center gap-2">
                            <span className={cn("h-1.5 w-1.5 rounded-full shrink-0", `bg-${rowSev === "critical" ? "red" : rowSev === "high" ? "orange" : rowSev === "medium" ? "amber" : "emerald"}-400`)}
                              style={{ boxShadow: `0 0 4px ${SEVERITY[rowSev].hex}` }} />
                            <span className="text-[11px] font-semibold text-slate-200 truncate max-w-[180px]">{row.name}</span>
                          </div>
                        </TableCell>
                        <TableCell className="py-3">
                          <div className="min-w-[100px]">
                            <RiskScoreBar score={row.riskScore} />
                          </div>
                        </TableCell>
                        <TableCell className="py-3">
                          <div className={cn(
                            "inline-flex items-center justify-center rounded px-1.5 py-0.5 text-[10px] font-black font-mono tabular-nums",
                            lxiScore >= 16 ? "bg-red-500/20 text-red-300" : lxiScore >= 9 ? "bg-orange-500/20 text-orange-300" : lxiScore >= 4 ? "bg-amber-500/20 text-amber-300" : "bg-slate-700/40 text-slate-500"
                          )}>
                            {lxiScore}
                          </div>
                        </TableCell>
                        <TableCell className="py-3">
                          <span className={cn("text-[11px] font-black font-mono tabular-nums", row.critical > 0 ? "text-red-400" : "text-slate-600")}>
                            {row.critical}
                          </span>
                        </TableCell>
                        <TableCell className="py-3">
                          <span className={cn("text-[11px] font-black font-mono tabular-nums", row.high > 0 ? "text-orange-400" : "text-slate-600")}>
                            {row.high}
                          </span>
                        </TableCell>
                        <TableCell className="py-3">
                          <span className={cn("text-[11px] font-black font-mono tabular-nums", row.medium > 0 ? "text-amber-400" : "text-slate-600")}>
                            {row.medium}
                          </span>
                        </TableCell>
                        <TableCell className="py-3 pr-5">
                          <SlaStatusBadge status={row.slaStatus} />
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </ScrollArea>
          ) : (
            <div className="flex h-[200px] flex-col items-center justify-center gap-3">
              <Eye className="h-8 w-8 text-slate-700" />
              <p className="text-[11px] text-slate-600">No risk data — run scans to populate</p>
            </div>
          )}
        </motion.div>

        {/* ── Row 4: KRI Cards ── */}
        <div>
          <div className="flex items-center gap-2 mb-3">
            <Zap className="h-3.5 w-3.5 text-amber-400" />
            <h3 className="text-xs font-bold uppercase tracking-[0.16em] text-slate-400">Key Risk Indicators</h3>
            <div className="flex-1 h-px bg-slate-700/40" />
            <span className="text-[9px] font-mono text-slate-600">
              {kriItems.filter(k => k.lowerIsBetter ? k.value > k.threshold : k.value < k.threshold).length} threshold breaches
            </span>
          </div>
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-3 lg:grid-cols-6">
            {kriItems.map((kri, i) => (
              <motion.div
                key={kri.label}
                initial={{ opacity: 0, y: 16 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: 0.05 * i, duration: 0.4, ease: [0.16, 1, 0.3, 1] }}
              >
                <KRICard {...kri} />
              </motion.div>
            ))}
          </div>
        </div>

        {/* ── Row 5: Treatment Status + Business Impact ── */}
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          {/* Treatment Status */}
          <motion.div
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.45, delay: 0.28, ease: [0.16, 1, 0.3, 1] }}
            className="rounded-xl border border-slate-700/40 bg-slate-800/30 p-5"
          >
            <div className="flex items-center gap-2 mb-5">
              <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
              <h3 className="text-xs font-bold uppercase tracking-[0.16em] text-slate-300">Treatment Status</h3>
            </div>
            <div className="space-y-5">
              <TreatmentBar
                title="Critical Risks"
                mitigated={Math.round(criticalCount * 0.3)}
                accepted={Math.round(criticalCount * 0.1)}
                transferred={Math.round(criticalCount * 0.05)}
                avoided={Math.round(criticalCount * 0.05)}
              />
              <TreatmentBar
                title="High Risks"
                mitigated={Math.round(highCount * 0.45)}
                accepted={Math.round(highCount * 0.2)}
                transferred={Math.round(highCount * 0.1)}
                avoided={Math.round(highCount * 0.05)}
              />
              <TreatmentBar
                title="Medium Risks"
                mitigated={Math.round(mediumCount * 0.55)}
                accepted={Math.round(mediumCount * 0.25)}
                transferred={Math.round(mediumCount * 0.1)}
                avoided={Math.round(mediumCount * 0.05)}
              />
              <TreatmentBar
                title="Low Risks"
                mitigated={Math.round(lowCount * 0.6)}
                accepted={Math.round(lowCount * 0.3)}
                transferred={Math.round(lowCount * 0.05)}
                avoided={Math.round(lowCount * 0.05)}
              />
            </div>
          </motion.div>

          {/* Business Impact */}
          <motion.div
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.45, delay: 0.32, ease: [0.16, 1, 0.3, 1] }}
            className="rounded-xl border border-amber-500/20 bg-amber-500/[0.04] p-5"
          >
            <div className="flex items-center justify-between mb-5">
              <div className="flex items-center gap-2">
                <Activity className="h-3.5 w-3.5 text-amber-400" />
                <h3 className="text-xs font-bold uppercase tracking-[0.16em] text-slate-300">Business Impact</h3>
              </div>
              <span className="text-[9px] font-mono text-slate-600 bg-amber-500/10 border border-amber-500/20 rounded px-2 py-0.5">
                {Number(ov.business_impact_score ?? ov.impact_score ?? 0).toFixed(0)} / 100
              </span>
            </div>
            <div className="space-y-5">
              {impactAreas.map((area, idx) => {
                const pct = Math.min(100, area.value);
                const impactSev: SeverityKey = pct >= 70 ? "critical" : pct >= 40 ? "high" : "low";
                return (
                  <div key={area.label} className="space-y-2">
                    <div className="flex items-end justify-between">
                      <div>
                        <p className="text-[11px] font-semibold text-slate-300">{area.label}</p>
                        <p className="text-[9px] text-slate-600 mt-0.5">{area.description}</p>
                      </div>
                      <span className={cn("text-lg font-black font-mono tabular-nums leading-none", SEVERITY[impactSev].text)}>
                        {pct.toFixed(0)}
                      </span>
                    </div>
                    <div className="h-2 rounded-full bg-slate-700/50 overflow-hidden">
                      <motion.div
                        initial={{ width: 0 }}
                        animate={{ width: `${pct}%` }}
                        transition={{ duration: 0.9, ease: [0.16, 1, 0.3, 1], delay: 0.1 * idx }}
                        className="h-full rounded-full"
                        style={{
                          backgroundColor: SEVERITY[impactSev].hex,
                          boxShadow: pct >= 40 ? `0 0 8px ${SEVERITY[impactSev].hex}55` : "none",
                        }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          </motion.div>
        </div>
      </motion.div>
    </TooltipProvider>
  );
}
