/**
 * Compliance Dashboard — P07 Persona (Compliance Officer)
 * Enterprise-grade GRC platform redesign.
 *
 * Sections:
 *   1. Hero — overall compliance score with animated radial gauge + trend sparkline
 *   2. Framework cards — animated SVG donut rings, status badge, last-assessed date
 *   3. Controls gap analysis — severity-ranked rows with risk heat indicators
 *   4. Evidence collection — per-framework progress bars with status breakdown
 *   5. Audit timeline — vertical milestones with connector lines
 *
 * API: GET /api/v1/compliance/status, /api/v1/compliance/gaps, /api/v1/evidence/list
 * Fallback: mock data when API is unavailable.
 * All data-fetching logic is preserved exactly from original.
 */

import { useState, useCallback, useEffect, useRef } from "react";
import { useQuery } from "@tanstack/react-query";
import { motion, useInView, useMotionValue, useSpring, animate } from "framer-motion";
import {
  RadialBarChart, RadialBar, ResponsiveContainer,
  AreaChart, Area, XAxis, YAxis, Tooltip, CartesianGrid,
} from "recharts";
import {
  ShieldCheck, AlertTriangle, CheckCircle2, XCircle, Clock,
  FileText, Lock, Layers, Server, Globe, Package,
  Upload, ExternalLink, RefreshCw, Download,
  Calendar, TrendingUp, AlertCircle, ChevronRight,
  ClipboardList, Target, BarChart3, Shield, ArrowUpRight,
  Zap, Activity, Info, ChevronDown,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Separator } from "@/components/ui/separator";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { cn } from "@/lib/utils";
import { usePageTitle } from "@/hooks/use-page-title";
import { EntityLink } from "@/components/EntityLink";

const API_BASE = import.meta.env.VITE_API_URL || "";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";
const ORG_ID = "aldeci-demo";

// ══════════════════════════════════════════════════════════════
// Types (unchanged)
// ══════════════════════════════════════════════════════════════

type FrameworkStatus = "in_progress" | "certified" | "gap";
type EvidenceStatus = "Collected" | "Missing" | "Expired";
type RiskLevel = "critical" | "high" | "medium" | "low";

interface Framework {
  id: string;
  name: string;
  progress: number;
  status: FrameworkStatus;
  controls_total: number;
  controls_passing: number;
}

interface EvidenceItem {
  id: string;
  control_id: string;
  framework: string;
  description: string;
  status: EvidenceStatus;
  last_updated: string;
}

interface ComplianceGap {
  id: string;
  control: string;
  framework: string;
  description: string;
  risk_level: RiskLevel;
  remediation_url: string;
}

interface AuditMilestone {
  id: string;
  label: string;
  date: string;
  type: "past" | "upcoming" | "next";
  framework: string;
}

// ══════════════════════════════════════════════════════════════
// Mock Data (unchanged)
// ══════════════════════════════════════════════════════════════

const MOCK_FRAMEWORKS: Framework[] = [
  { id: "soc2", name: "SOC 2 Type II", progress: 78, status: "in_progress", controls_total: 64, controls_passing: 50 },
  { id: "pci", name: "PCI DSS 4.0", progress: 92, status: "certified", controls_total: 251, controls_passing: 231 },
  { id: "iso27001", name: "ISO 27001", progress: 45, status: "gap", controls_total: 93, controls_passing: 42 },
  { id: "nist", name: "NIST CSF", progress: 67, status: "in_progress", controls_total: 108, controls_passing: 72 },
  { id: "hipaa", name: "HIPAA", progress: 88, status: "in_progress", controls_total: 42, controls_passing: 37 },
  { id: "cis", name: "CIS Controls v8", progress: 55, status: "gap", controls_total: 153, controls_passing: 84 },
];

const MOCK_EVIDENCE: EvidenceItem[] = [
  { id: "ev1", control_id: "SOC2-CC6.1", framework: "SOC 2", description: "Logical access security controls documentation", status: "Collected", last_updated: "2026-04-08" },
  { id: "ev2", control_id: "PCI-DSS-6.5", framework: "PCI DSS", description: "Penetration test report Q1 2026", status: "Missing", last_updated: "2026-01-20" },
  { id: "ev3", control_id: "ISO-A.8.3", framework: "ISO 27001", description: "Media handling and disposal procedures", status: "Expired", last_updated: "2025-10-01" },
  { id: "ev4", control_id: "NIST-PR.AC-4", framework: "NIST CSF", description: "Access permissions and authorizations policy", status: "Missing", last_updated: "2026-02-14" },
  { id: "ev5", control_id: "HIPAA-164.308", framework: "HIPAA", description: "Annual risk analysis report", status: "Collected", last_updated: "2026-03-30" },
  { id: "ev6", control_id: "CIS-2.1", framework: "CIS Controls", description: "Software asset inventory export", status: "Expired", last_updated: "2025-09-15" },
  { id: "ev7", control_id: "SOC2-CC7.2", framework: "SOC 2", description: "Incident response test walkthrough recording", status: "Missing", last_updated: "2026-03-01" },
  { id: "ev8", control_id: "PCI-DSS-10.2", framework: "PCI DSS", description: "Audit log review records March 2026", status: "Collected", last_updated: "2026-04-05" },
  { id: "ev9", control_id: "CIS-4.2", framework: "CIS Controls", description: "Privileged account service inventory", status: "Expired", last_updated: "2025-08-20" },
  { id: "ev10", control_id: "ISO-A.9.1", framework: "ISO 27001", description: "Access control policy v3 board approval", status: "Missing", last_updated: "2025-12-10" },
];

const MOCK_GAPS: ComplianceGap[] = [
  { id: "g1", control: "CIS-2.1 Software Asset Inventory", framework: "CIS Controls v8", description: "No maintained software asset inventory. Automated discovery tooling not deployed.", risk_level: "high", remediation_url: "/comply/evidence" },
  { id: "g2", control: "PCI-DSS-6.5 Secure Development", framework: "PCI DSS 4.0", description: "Penetration test overdue by 83 days. Required quarterly for cardholder data environment.", risk_level: "critical", remediation_url: "/validate/mpte" },
  { id: "g3", control: "ISO-A.8.3 Media Handling", framework: "ISO 27001", description: "Media disposal procedures not documented. Last reviewed October 2025.", risk_level: "medium", remediation_url: "/comply/evidence" },
  { id: "g4", control: "NIST-PR.AC-4 Access Permissions", framework: "NIST CSF", description: "Privileged access reviews not completed for Q1 2026. 14 accounts unreviewed.", risk_level: "high", remediation_url: "/settings/users" },
  { id: "g5", control: "CIS-4.2 Service Account Inventory", framework: "CIS Controls v8", description: "Service account inventory is 8 months stale. Requires quarterly refresh.", risk_level: "critical", remediation_url: "/settings/users" },
  { id: "g6", control: "ISO-A.9.1 Access Control Policy", framework: "ISO 27001", description: "Access control policy v3 pending board ratification. Blocking ISO recertification.", risk_level: "medium", remediation_url: "/comply/evidence" },
];

const MOCK_MILESTONES: AuditMilestone[] = [
  { id: "m1", label: "HIPAA Annual Review", date: "2025-12-08", type: "past", framework: "HIPAA" },
  { id: "m2", label: "PCI DSS Certification", date: "2026-01-15", type: "past", framework: "PCI DSS" },
  { id: "m3", label: "SOC 2 Interim Assessment", date: "2026-02-20", type: "past", framework: "SOC 2" },
  { id: "m4", label: "ISO 27001 Gap Analysis", date: "2026-03-10", type: "past", framework: "ISO 27001" },
  { id: "m5", label: "CIS Controls Re-assessment", date: "2026-03-30", type: "past", framework: "CIS" },
  { id: "m6", label: "NIST CSF Review Due", date: "2026-04-14", type: "next", framework: "NIST CSF" },
  { id: "m7", label: "PCI DSS Renewal Audit", date: "2026-05-20", type: "upcoming", framework: "PCI DSS" },
  { id: "m8", label: "SOC 2 Type II Audit", date: "2026-07-15", type: "upcoming", framework: "SOC 2" },
  { id: "m9", label: "HIPAA Annual Renewal", date: "2026-08-01", type: "upcoming", framework: "HIPAA" },
];

// Trend sparkline data for hero section
const TREND_DATA = [
  { month: "Nov", score: 61 },
  { month: "Dec", score: 63 },
  { month: "Jan", score: 67 },
  { month: "Feb", score: 70 },
  { month: "Mar", score: 71 },
  { month: "Apr", score: 71 },
];

// ══════════════════════════════════════════════════════════════
// Design tokens
// ══════════════════════════════════════════════════════════════

const FRAMEWORK_META: Record<string, {
  Icon: React.ElementType;
  color: string;       // ring / accent color
  bg: string;          // icon bg
  abbr: string;
  lastAssessed: string;
}> = {
  soc2:    { Icon: ShieldCheck, color: "#10b981", bg: "bg-emerald-500/10", abbr: "SOC2", lastAssessed: "2026-02-20" },
  pci:     { Icon: Lock,        color: "#3b82f6", bg: "bg-blue-500/10",    abbr: "PCI",  lastAssessed: "2026-01-15" },
  iso27001:{ Icon: Layers,      color: "#f59e0b", bg: "bg-amber-500/10",   abbr: "ISO",  lastAssessed: "2026-03-10" },
  nist:    { Icon: Server,      color: "#a78bfa", bg: "bg-violet-500/10",  abbr: "NIST", lastAssessed: "2026-04-14" },
  hipaa:   { Icon: FileText,    color: "#06b6d4", bg: "bg-cyan-500/10",    abbr: "HIPAA",lastAssessed: "2025-12-08" },
  cis:     { Icon: Package,     color: "#f97316", bg: "bg-orange-500/10",  abbr: "CIS",  lastAssessed: "2026-03-30" },
};

const STATUS_LABEL: Record<FrameworkStatus, { text: string; cls: string }> = {
  certified:   { text: "Certified",   cls: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30" },
  in_progress: { text: "In Progress", cls: "bg-amber-500/15 text-amber-400 border-amber-500/30" },
  gap:         { text: "Gap",         cls: "bg-red-500/15 text-red-400 border-red-500/30" },
};

const RISK_CONFIG: Record<RiskLevel, { cls: string; bar: string; label: string; dot: string }> = {
  critical: { cls: "bg-red-500/15 text-red-400 border-red-500/30",    bar: "bg-red-500",    label: "Critical", dot: "bg-red-500" },
  high:     { cls: "bg-orange-500/15 text-orange-400 border-orange-500/30", bar: "bg-orange-500", label: "High", dot: "bg-orange-400" },
  medium:   { cls: "bg-amber-500/15 text-amber-400 border-amber-500/30",  bar: "bg-amber-500",  label: "Medium", dot: "bg-amber-400" },
  low:      { cls: "bg-blue-500/15 text-blue-400 border-blue-500/30",    bar: "bg-blue-500",   label: "Low",  dot: "bg-blue-400" },
};

const EVIDENCE_CONFIG: Record<EvidenceStatus, { cls: string; Icon: React.ElementType; bar: string }> = {
  Collected: { cls: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30", Icon: CheckCircle2, bar: "bg-emerald-500" },
  Missing:   { cls: "bg-red-500/15 text-red-400 border-red-500/30",            Icon: XCircle,      bar: "bg-red-500" },
  Expired:   { cls: "bg-amber-500/15 text-amber-400 border-amber-500/30",      Icon: Clock,        bar: "bg-amber-500" },
};

// ══════════════════════════════════════════════════════════════
// API fetch helpers (unchanged from original)
// ══════════════════════════════════════════════════════════════

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}?org_id=default`, {
    headers: { "X-API-Key": API_KEY },
  });
  if (!res.ok) throw new Error(`${res.status}`);
  return res.json();
}

async function fetchComplianceStatus(): Promise<Framework[]> {
  try {
    const data = await apiFetch(`/api/v1/compliance-scanner/scans?org_id=${ORG_ID}&limit=10`);
    const items = Array.isArray(data) ? data : data.items ?? data.scans ?? [];
    if (items.length > 0) return items;
  } catch {
    // fall through to legacy
  }
  const data = await apiFetch(`/api/v1/compliance/status`);
  return Array.isArray(data) ? data : data.frameworks ?? data.data ?? MOCK_FRAMEWORKS;
}

async function fetchGaps(): Promise<ComplianceGap[]> {
  try {
    const data = await apiFetch(`/api/v1/compliance-scanner/findings?org_id=${ORG_ID}&status=open&limit=20`);
    const items = Array.isArray(data) ? data : data.items ?? data.findings ?? [];
    if (items.length > 0) return items;
  } catch {
    // fall through to legacy
  }
  const data = await apiFetch(`/api/v1/compliance/gaps`);
  return Array.isArray(data) ? data : data.gaps ?? data.data ?? MOCK_GAPS;
}

async function fetchEvidence(): Promise<EvidenceItem[]> {
  const data = await apiFetch(`/api/v1/evidence/list`);
  return Array.isArray(data) ? data : data.items ?? data.data ?? MOCK_EVIDENCE;
}

async function fetchScannerStats(): Promise<Record<string, unknown>> {
  return apiFetch(`/api/v1/compliance-scanner/stats?org_id=${ORG_ID}`);
}

// ══════════════════════════════════════════════════════════════
// Animated counter hook
// ══════════════════════════════════════════════════════════════

function useCountUp(target: number, duration = 1.2) {
  const [display, setDisplay] = useState(0);
  const ref = useRef<ReturnType<typeof animate> | null>(null);

  useEffect(() => {
    ref.current?.stop();
    ref.current = animate(0, target, {
      duration,
      ease: [0.16, 1, 0.3, 1],
      onUpdate: (v) => setDisplay(Math.round(v)),
    });
    return () => ref.current?.stop();
  }, [target, duration]);

  return display;
}

// ══════════════════════════════════════════════════════════════
// SVG Donut Ring — animated compliance circle
// ══════════════════════════════════════════════════════════════

interface DonutRingProps {
  score: number;
  color: string;
  size?: number;
  strokeWidth?: number;
  delay?: number;
}

function DonutRing({ score, color, size = 72, strokeWidth = 6, delay = 0 }: DonutRingProps) {
  const r = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * r;
  const [offset, setOffset] = useState(circumference);
  const ref = useRef<HTMLDivElement>(null);
  const inView = useInView(ref, { once: true, margin: "-40px" });

  useEffect(() => {
    if (!inView) return;
    const timer = setTimeout(() => {
      setOffset(circumference - (score / 100) * circumference);
    }, delay * 1000 + 80);
    return () => clearTimeout(timer);
  }, [inView, score, circumference, delay]);

  return (
    <div ref={ref} style={{ width: size, height: size }} className="relative shrink-0">
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="-rotate-90">
        {/* Track */}
        <circle
          cx={size / 2} cy={size / 2} r={r}
          fill="none"
          stroke="rgba(255,255,255,0.06)"
          strokeWidth={strokeWidth}
        />
        {/* Progress */}
        <circle
          cx={size / 2} cy={size / 2} r={r}
          fill="none"
          stroke={color}
          strokeWidth={strokeWidth}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          style={{ transition: `stroke-dashoffset 1s cubic-bezier(0.16, 1, 0.3, 1) ${delay * 0.1}s` }}
        />
      </svg>
      {/* Center score */}
      <div className="absolute inset-0 flex items-center justify-center">
        <span className="text-sm font-bold tabular-nums" style={{ color }}>
          {score}%
        </span>
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// Hero Radial Gauge
// ══════════════════════════════════════════════════════════════

function HeroGauge({ score }: { score: number }) {
  const displayed = useCountUp(score, 1.4);
  const size = 180;
  const strokeWidth = 12;
  const r = (size - strokeWidth) / 2;
  const circumference = 2 * Math.PI * r;
  const [offset, setOffset] = useState(circumference);

  useEffect(() => {
    const t = setTimeout(() => {
      setOffset(circumference - (score / 100) * circumference);
    }, 300);
    return () => clearTimeout(t);
  }, [score, circumference]);

  const grade = score >= 90 ? "A" : score >= 80 ? "B" : score >= 70 ? "C" : score >= 60 ? "D" : "F";
  const gradeColor = score >= 80 ? "#10b981" : score >= 65 ? "#f59e0b" : "#ef4444";
  const ringColor = gradeColor;

  return (
    <div className="relative flex items-center justify-center" style={{ width: size, height: size }}>
      {/* Outer glow */}
      <div
        className="absolute inset-0 rounded-full opacity-20 blur-xl"
        style={{ background: ringColor }}
      />
      <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="-rotate-90 relative z-10">
        <circle
          cx={size / 2} cy={size / 2} r={r}
          fill="none"
          stroke="rgba(255,255,255,0.05)"
          strokeWidth={strokeWidth}
        />
        <circle
          cx={size / 2} cy={size / 2} r={r}
          fill="none"
          stroke={ringColor}
          strokeWidth={strokeWidth}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          style={{ transition: "stroke-dashoffset 1.6s cubic-bezier(0.16, 1, 0.3, 1) 0.2s", filter: `drop-shadow(0 0 8px ${ringColor}88)` }}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center z-20">
        <span className="text-4xl font-black tabular-nums tracking-tight" style={{ color: ringColor }}>
          {displayed}%
        </span>
        <span className="text-xs text-zinc-500 font-medium uppercase tracking-widest mt-0.5">Overall</span>
        <div
          className="mt-2 h-6 w-6 rounded-full flex items-center justify-center text-xs font-black"
          style={{ background: `${ringColor}22`, color: ringColor, border: `1px solid ${ringColor}44` }}
        >
          {grade}
        </div>
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// Framework Card — premium donut + metadata
// ══════════════════════════════════════════════════════════════

function FrameworkCard({ fw, index }: { fw: Framework; index: number }) {
  const meta = FRAMEWORK_META[fw.id] ?? {
    Icon: Shield, color: "#6366f1", bg: "bg-indigo-500/10", abbr: fw.id.toUpperCase(), lastAssessed: "—",
  };
  const { Icon } = meta;
  const statusInfo = STATUS_LABEL[fw.status];
  const gaps = fw.controls_total - fw.controls_passing;

  return (
    <motion.div
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4, delay: index * 0.07, ease: [0.16, 1, 0.3, 1] }}
    >
      <Card className="relative overflow-hidden group hover:border-white/10 transition-all duration-300 hover:shadow-lg hover:shadow-black/20 bg-zinc-900/60 border-white/[0.06]">
        {/* Top accent line */}
        <div
          className="absolute top-0 left-0 right-0 h-px"
          style={{ background: `linear-gradient(90deg, transparent, ${meta.color}88, transparent)` }}
        />

        <CardContent className="p-5">
          <div className="flex items-start gap-4">
            {/* Donut ring */}
            <DonutRing score={fw.progress} color={meta.color} size={72} strokeWidth={5} delay={index} />

            {/* Info column */}
            <div className="flex-1 min-w-0 pt-0.5">
              <div className="flex items-start justify-between gap-2 mb-2">
                <div className="flex items-center gap-2 min-w-0">
                  <div className={cn("rounded-md p-1.5 shrink-0", meta.bg)}>
                    <Icon className="h-3.5 w-3.5" style={{ color: meta.color }} />
                  </div>
                  <span className="text-sm font-semibold leading-tight text-zinc-100 truncate">
                    {fw.name}
                  </span>
                </div>
              </div>

              <div className="flex items-center gap-1.5 flex-wrap">
                <span className={cn(
                  "inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase tracking-wide",
                  statusInfo.cls
                )}>
                  {fw.status === "certified" && <CheckCircle2 className="h-2.5 w-2.5 mr-1" />}
                  {fw.status === "in_progress" && <Activity className="h-2.5 w-2.5 mr-1" />}
                  {fw.status === "gap" && <AlertCircle className="h-2.5 w-2.5 mr-1" />}
                  {statusInfo.text}
                </span>
              </div>

              {/* Controls stat */}
              <div className="mt-3 grid grid-cols-3 gap-2 text-center">
                <div>
                  <div className="text-base font-bold tabular-nums text-zinc-100">{fw.controls_passing}</div>
                  <div className="text-[10px] text-zinc-500 uppercase tracking-wide">Pass</div>
                </div>
                <div>
                  <div className="text-base font-bold tabular-nums text-red-400">{gaps}</div>
                  <div className="text-[10px] text-zinc-500 uppercase tracking-wide">Gap</div>
                </div>
                <div>
                  <div className="text-base font-bold tabular-nums text-zinc-400">{fw.controls_total}</div>
                  <div className="text-[10px] text-zinc-500 uppercase tracking-wide">Total</div>
                </div>
              </div>
            </div>
          </div>

          {/* Last assessed footer */}
          <div className="mt-4 pt-3 border-t border-white/[0.05] flex items-center justify-between text-[10px] text-zinc-500">
            <span className="flex items-center gap-1">
              <Calendar className="h-3 w-3" />
              Assessed {meta.lastAssessed}
            </span>
            <span className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition-opacity text-zinc-400 cursor-pointer hover:text-zinc-200">
              View controls <ChevronRight className="h-3 w-3" />
            </span>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}

// ══════════════════════════════════════════════════════════════
// Controls Gap Analysis
// ══════════════════════════════════════════════════════════════

function GapRow({ gap, index }: { gap: ComplianceGap; index: number }) {
  const risk = RISK_CONFIG[gap.risk_level];
  const riskOrder = { critical: 4, high: 3, medium: 2, low: 1 };
  const barWidth = (riskOrder[gap.risk_level] / 4) * 100;

  return (
    <motion.div
      initial={{ opacity: 0, x: -12 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ duration: 0.3, delay: index * 0.05, ease: [0.16, 1, 0.3, 1] }}
      className="group"
    >
      <div className="relative rounded-lg border border-white/[0.05] bg-zinc-900/40 p-4 hover:bg-zinc-800/40 hover:border-white/[0.10] transition-all duration-200 overflow-hidden">
        {/* Left severity bar */}
        <div className={cn("absolute left-0 top-0 bottom-0 w-0.5", risk.bar)} />

        <div className="flex items-start gap-3 pl-2">
          {/* Severity dot + label */}
          <div className="mt-0.5 shrink-0">
            <div className={cn("h-2 w-2 rounded-full", risk.dot, gap.risk_level === "critical" && "animate-pulse")} />
          </div>

          <div className="flex-1 min-w-0">
            <div className="flex items-start justify-between gap-3 mb-1.5">
              <div className="min-w-0">
                <EntityLink type="control" id={gap.id} className="text-sm font-semibold text-zinc-100 hover:text-cyan-300 leading-tight truncate block transition-colors">
                  {gap.control}
                </EntityLink>
                <p className="text-[11px] text-zinc-500 mt-0.5 font-mono">{gap.framework}</p>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <span className={cn(
                  "inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-bold uppercase tracking-wide",
                  risk.cls
                )}>
                  {risk.label}
                </span>
                <a
                  href={gap.remediation_url}
                  aria-label={`Remediate ${gap.control}`}
                  className="inline-flex items-center gap-1 text-[10px] text-zinc-500 hover:text-emerald-400 transition-colors opacity-0 group-hover:opacity-100"
                >
                  Remediate <ExternalLink className="h-3 w-3" />
                </a>
              </div>
            </div>
            <p className="text-xs text-zinc-400 leading-relaxed">{gap.description}</p>
          </div>
        </div>
      </div>
    </motion.div>
  );
}

function GapsSection({ gaps }: { gaps: ComplianceGap[] }) {
  const sortedGaps = [...gaps].sort((a, b) => {
    const order = { critical: 4, high: 3, medium: 2, low: 1 };
    return order[b.risk_level] - order[a.risk_level];
  });

  const counts = {
    critical: gaps.filter((g) => g.risk_level === "critical").length,
    high: gaps.filter((g) => g.risk_level === "high").length,
    medium: gaps.filter((g) => g.risk_level === "medium").length,
    low: gaps.filter((g) => g.risk_level === "low").length,
  };

  return (
    <Card className="bg-zinc-900/60 border-white/[0.06]">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm flex items-center gap-2.5 text-zinc-100">
            <div className="h-5 w-5 rounded bg-red-500/15 flex items-center justify-center">
              <AlertTriangle className="h-3 w-3 text-red-400" />
            </div>
            Controls Gap Analysis
            <span className="ml-1 rounded-full bg-red-500/15 text-red-400 border border-red-500/30 px-2 py-px text-[10px] font-bold">
              {gaps.length} open
            </span>
          </CardTitle>
          <div className="flex items-center gap-3 text-[10px]">
            {(Object.entries(counts) as [RiskLevel, number][]).map(([level, count]) => (
              count > 0 && (
                <span key={level} className="flex items-center gap-1 text-zinc-400">
                  <div className={cn("h-1.5 w-1.5 rounded-full", RISK_CONFIG[level].dot)} />
                  {count} {level}
                </span>
              )
            ))}
          </div>
        </div>
      </CardHeader>
      <CardContent className="space-y-2.5">
        {sortedGaps.map((gap, i) => (
          <GapRow key={gap.id} gap={gap} index={i} />
        ))}
      </CardContent>
    </Card>
  );
}

// ══════════════════════════════════════════════════════════════
// Evidence Collection — per-framework progress bars
// ══════════════════════════════════════════════════════════════

function EvidenceSection({ items, onUpload }: { items: EvidenceItem[]; onUpload: (id: string) => void }) {
  // Group by framework
  const byFramework = items.reduce<Record<string, EvidenceItem[]>>((acc, item) => {
    if (!acc[item.framework]) acc[item.framework] = [];
    acc[item.framework].push(item);
    return acc;
  }, {});

  const totalCollected = items.filter((e) => e.status === "Collected").length;
  const totalMissing = items.filter((e) => e.status === "Missing").length;
  const totalExpired = items.filter((e) => e.status === "Expired").length;
  const collectionRate = Math.round((totalCollected / items.length) * 100);

  return (
    <Card className="bg-zinc-900/60 border-white/[0.06]">
      <CardHeader className="pb-4">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm flex items-center gap-2.5 text-zinc-100">
            <div className="h-5 w-5 rounded bg-blue-500/15 flex items-center justify-center">
              <ClipboardList className="h-3 w-3 text-blue-400" />
            </div>
            Evidence Collection
          </CardTitle>
          {/* Summary pills */}
          <div className="flex items-center gap-2 text-[10px]">
            <span className="flex items-center gap-1 bg-emerald-500/10 border border-emerald-500/20 rounded-full px-2 py-0.5 text-emerald-400">
              <CheckCircle2 className="h-3 w-3" />
              {totalCollected} collected
            </span>
            <span className="flex items-center gap-1 bg-amber-500/10 border border-amber-500/20 rounded-full px-2 py-0.5 text-amber-400">
              <Clock className="h-3 w-3" />
              {totalExpired} expired
            </span>
            <span className="flex items-center gap-1 bg-red-500/10 border border-red-500/20 rounded-full px-2 py-0.5 text-red-400">
              <XCircle className="h-3 w-3" />
              {totalMissing} missing
            </span>
          </div>
        </div>

        {/* Overall collection rate bar */}
        <div className="mt-4">
          <div className="flex items-center justify-between text-[11px] text-zinc-400 mb-1.5">
            <span>Overall collection rate</span>
            <span className="font-bold text-zinc-200 tabular-nums">{collectionRate}%</span>
          </div>
          <div className="h-1.5 bg-white/[0.05] rounded-full overflow-hidden">
            <motion.div
              className="h-full bg-emerald-500 rounded-full"
              initial={{ width: 0 }}
              animate={{ width: `${collectionRate}%` }}
              transition={{ duration: 1, delay: 0.3, ease: [0.16, 1, 0.3, 1] }}
            />
          </div>
        </div>
      </CardHeader>

      <CardContent>
        {/* Per-framework breakdown */}
        <div className="space-y-4 mb-6">
          {Object.entries(byFramework).map(([fw, fwItems], i) => {
            const collected = fwItems.filter((e) => e.status === "Collected").length;
            const expired = fwItems.filter((e) => e.status === "Expired").length;
            const missing = fwItems.filter((e) => e.status === "Missing").length;
            const rate = Math.round((collected / fwItems.length) * 100);

            return (
              <motion.div
                key={fw}
                initial={{ opacity: 0, x: -8 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ delay: i * 0.06, duration: 0.3 }}
              >
                <div className="flex items-center justify-between text-xs mb-1.5">
                  <span className="font-medium text-zinc-300">{fw}</span>
                  <div className="flex items-center gap-3 text-[10px] text-zinc-500">
                    <span className="text-emerald-400">{collected}✓</span>
                    <span className="text-amber-400">{expired}⏰</span>
                    <span className="text-red-400">{missing}✗</span>
                    <span className="font-bold text-zinc-300 tabular-nums w-8 text-right">{rate}%</span>
                  </div>
                </div>
                {/* Stacked bar */}
                <div className="h-1.5 bg-white/[0.05] rounded-full overflow-hidden flex">
                  <motion.div
                    className="h-full bg-emerald-500"
                    initial={{ width: 0 }}
                    animate={{ width: `${(collected / fwItems.length) * 100}%` }}
                    transition={{ duration: 0.8, delay: 0.2 + i * 0.06 }}
                  />
                  <motion.div
                    className="h-full bg-amber-500"
                    initial={{ width: 0 }}
                    animate={{ width: `${(expired / fwItems.length) * 100}%` }}
                    transition={{ duration: 0.8, delay: 0.3 + i * 0.06 }}
                  />
                  <motion.div
                    className="h-full bg-red-500"
                    initial={{ width: 0 }}
                    animate={{ width: `${(missing / fwItems.length) * 100}%` }}
                    transition={{ duration: 0.8, delay: 0.4 + i * 0.06 }}
                  />
                </div>
              </motion.div>
            );
          })}
        </div>

        <Separator className="bg-white/[0.05] mb-4" />

        {/* Evidence table */}
        <div className="rounded-lg border border-white/[0.05] overflow-hidden">
          <Table>
            <TableHeader>
              <TableRow className="border-white/[0.05] hover:bg-transparent">
                {["Control ID", "Framework", "Description", "Status", "Updated", ""].map((h) => (
                  <TableHead key={h} className="text-[10px] uppercase tracking-widest text-zinc-500 font-semibold">
                    {h}
                  </TableHead>
                ))}
              </TableRow>
            </TableHeader>
            <TableBody>
              {items.map((item, i) => {
                const ev = EVIDENCE_CONFIG[item.status];
                const StatusIcon = ev.Icon;
                return (
                  <motion.tr
                    key={item.id}
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ duration: 0.2, delay: i * 0.025 }}
                    className="border-white/[0.04] hover:bg-white/[0.02] transition-colors group/row"
                  >
                    <TableCell className="font-mono text-[11px] py-2.5">
                      <EntityLink type="control" id={item.control_id}>
                        {item.control_id}
                      </EntityLink>
                    </TableCell>
                    <TableCell className="py-2.5">
                      <span className="text-[11px] bg-white/[0.04] border border-white/[0.07] rounded px-1.5 py-0.5 text-zinc-400">
                        {item.framework}
                      </span>
                    </TableCell>
                    <TableCell className="text-xs max-w-[200px] truncate text-zinc-400 py-2.5" title={item.description}>
                      {item.description}
                    </TableCell>
                    <TableCell className="py-2.5">
                      <span className={cn(
                        "inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-[10px] font-medium",
                        ev.cls
                      )}>
                        <StatusIcon className="h-2.5 w-2.5" />
                        {item.status}
                      </span>
                    </TableCell>
                    <TableCell className="text-[11px] text-zinc-500 tabular-nums py-2.5">{item.last_updated}</TableCell>
                    <TableCell className="py-2.5 text-right">
                      <Button
                        size="sm"
                        variant="outline"
                        className="h-6 text-[10px] gap-1 border-white/[0.08] hover:bg-white/[0.05] hover:border-white/20 text-zinc-400 hover:text-zinc-200 opacity-0 group-hover/row:opacity-100 transition-all"
                        onClick={() => onUpload(item.id)}
                        aria-label={`Upload evidence for ${item.control_id}`}
                      >
                        <Upload className="h-2.5 w-2.5" />
                        Upload
                      </Button>
                    </TableCell>
                  </motion.tr>
                );
              })}
            </TableBody>
          </Table>
        </div>
      </CardContent>
    </Card>
  );
}

// ══════════════════════════════════════════════════════════════
// Audit Timeline — vertical layout
// ══════════════════════════════════════════════════════════════

function AuditTimeline({ milestones }: { milestones: AuditMilestone[] }) {
  const typeStyle = {
    past: {
      dot: "bg-emerald-500 border-emerald-400 shadow-emerald-500/30",
      connector: "bg-emerald-500/30",
      label: "text-zinc-400",
      date: "text-zinc-500",
      badge: "bg-emerald-500/10 border-emerald-500/20 text-emerald-400",
    },
    next: {
      dot: "bg-amber-400 border-amber-300 shadow-amber-400/50",
      connector: "bg-amber-400/20",
      label: "text-amber-300 font-semibold",
      date: "text-amber-400",
      badge: "bg-amber-500/10 border-amber-500/20 text-amber-400",
    },
    upcoming: {
      dot: "bg-zinc-700 border-zinc-600",
      connector: "bg-zinc-700/50",
      label: "text-zinc-500",
      date: "text-zinc-600",
      badge: "bg-zinc-800/60 border-zinc-700 text-zinc-500",
    },
  };

  return (
    <Card className="bg-zinc-900/60 border-white/[0.06] h-full">
      <CardHeader className="pb-3">
        <CardTitle className="text-sm flex items-center gap-2.5 text-zinc-100">
          <div className="h-5 w-5 rounded bg-blue-500/15 flex items-center justify-center">
            <Calendar className="h-3 w-3 text-blue-400" />
          </div>
          Audit Timeline
        </CardTitle>
        {/* Legend */}
        <div className="flex items-center gap-4 text-[10px] text-zinc-500 mt-1">
          <span className="flex items-center gap-1.5"><div className="h-1.5 w-1.5 rounded-full bg-emerald-500" />Completed</span>
          <span className="flex items-center gap-1.5"><div className="h-1.5 w-1.5 rounded-full bg-amber-400" />Next due</span>
          <span className="flex items-center gap-1.5"><div className="h-1.5 w-1.5 rounded-full bg-zinc-600" />Scheduled</span>
        </div>
      </CardHeader>
      <CardContent>
        <div className="relative">
          {milestones.map((m, i) => {
            const style = typeStyle[m.type];
            const isLast = i === milestones.length - 1;
            return (
              <motion.div
                key={m.id}
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.05, duration: 0.3 }}
                className="relative flex gap-3 pb-1"
              >
                {/* Connector column */}
                <div className="relative flex flex-col items-center w-4 shrink-0">
                  <div
                    className={cn(
                      "h-3.5 w-3.5 rounded-full border-2 shrink-0 shadow-md z-10 mt-0.5",
                      style.dot,
                      m.type === "next" && "ring-2 ring-amber-400/20 ring-offset-1 ring-offset-zinc-900"
                    )}
                  />
                  {!isLast && (
                    <div className={cn("flex-1 w-px mt-1", style.connector)} style={{ minHeight: 32 }} />
                  )}
                </div>

                {/* Content */}
                <div className="pb-5 flex-1 min-w-0">
                  <div className="flex items-start justify-between gap-2 flex-wrap">
                    <p className={cn("text-xs leading-tight", style.label)}>{m.label}</p>
                    <span className={cn(
                      "inline-flex items-center rounded border px-1.5 py-px text-[9px] font-medium shrink-0",
                      style.badge
                    )}>
                      {m.framework}
                    </span>
                  </div>
                  <p className={cn("text-[10px] tabular-nums mt-0.5", style.date)}>{m.date}</p>
                </div>
              </motion.div>
            );
          })}
        </div>
      </CardContent>
    </Card>
  );
}

// ══════════════════════════════════════════════════════════════
// Hero Section — overall score + sparkline trend
// ══════════════════════════════════════════════════════════════

interface HeroSectionProps {
  avgProgress: number;
  certifiedCount: number;
  totalFrameworks: number;
  criticalGaps: number;
  missingEvidence: number;
  onRefresh: () => void;
}

function HeroSection({ avgProgress, certifiedCount, totalFrameworks, criticalGaps, missingEvidence, onRefresh }: HeroSectionProps) {
  const trendWithCurrent = [
    ...TREND_DATA.slice(0, -1),
    { month: "Apr", score: avgProgress },
  ];
  const delta = avgProgress - TREND_DATA[0].score;

  return (
    <Card className="bg-zinc-900/60 border-white/[0.06] overflow-hidden">
      {/* Subtle grid background */}
      <div
        className="absolute inset-0 opacity-[0.02]"
        style={{
          backgroundImage: "repeating-linear-gradient(0deg, #fff 0px, #fff 1px, transparent 1px, transparent 40px), repeating-linear-gradient(90deg, #fff 0px, #fff 1px, transparent 1px, transparent 40px)",
        }}
      />
      <CardContent className="relative p-6">
        <div className="flex flex-col lg:flex-row items-center gap-8">
          {/* Gauge */}
          <div className="shrink-0 flex flex-col items-center gap-3">
            <HeroGauge score={avgProgress} />
            <div className="flex items-center gap-1.5 text-xs">
              <TrendingUp className="h-3.5 w-3.5 text-emerald-400" />
              <span className="text-emerald-400 font-semibold tabular-nums">+{delta}%</span>
              <span className="text-zinc-500">since Nov 2025</span>
            </div>
          </div>

          {/* Sparkline */}
          <div className="flex-1 min-w-0">
            <div className="mb-3">
              <h2 className="text-lg font-bold text-zinc-100 tracking-tight">Compliance Posture</h2>
              <p className="text-xs text-zinc-500 mt-0.5">6-month trajectory across all frameworks</p>
            </div>
            <div className="h-28">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={trendWithCurrent} margin={{ top: 4, right: 4, left: -32, bottom: 0 }}>
                  <defs>
                    <linearGradient id="scoreGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#10b981" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#10b981" stopOpacity={0.02} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid stroke="rgba(255,255,255,0.04)" strokeDasharray="3 3" vertical={false} />
                  <XAxis
                    dataKey="month" tick={{ fill: "#52525b", fontSize: 10 }}
                    axisLine={false} tickLine={false}
                  />
                  <YAxis
                    domain={[50, 100]} tick={{ fill: "#52525b", fontSize: 10 }}
                    axisLine={false} tickLine={false}
                  />
                  <Tooltip
                    contentStyle={{ background: "#18181b", border: "1px solid rgba(255,255,255,0.08)", borderRadius: 8, fontSize: 11 }}
                    labelStyle={{ color: "#a1a1aa" }}
                    itemStyle={{ color: "#10b981" }}
                    formatter={(v: number) => [`${v}%`, "Score"]}
                  />
                  <Area
                    type="monotone" dataKey="score"
                    stroke="#10b981" strokeWidth={2}
                    fill="url(#scoreGrad)"
                    dot={false}
                    activeDot={{ r: 4, fill: "#10b981", stroke: "#052e16" }}
                  />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Right stat column */}
          <div className="flex flex-row lg:flex-col gap-3 shrink-0 lg:min-w-[140px]">
            {[
              { label: "Certified", value: `${certifiedCount}/${totalFrameworks}`, color: "text-emerald-400", bg: "bg-emerald-500/10", border: "border-emerald-500/20" },
              { label: "Critical Gaps", value: criticalGaps, color: "text-red-400", bg: "bg-red-500/10", border: "border-red-500/20" },
              { label: "Evidence Issues", value: missingEvidence, color: "text-amber-400", bg: "bg-amber-500/10", border: "border-amber-500/20" },
            ].map((stat) => (
              <div
                key={stat.label}
                className={cn("rounded-lg border px-4 py-3 text-center lg:text-left", stat.bg, stat.border)}
              >
                <div className={cn("text-xl font-black tabular-nums", stat.color)}>{stat.value}</div>
                <div className="text-[10px] text-zinc-500 uppercase tracking-wide mt-0.5">{stat.label}</div>
              </div>
            ))}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// ══════════════════════════════════════════════════════════════
// Main Component
// ══════════════════════════════════════════════════════════════

export default function ComplianceDashboard() {
  usePageTitle("Compliance");
  const [uploadingId, setUploadingId] = useState<string | null>(null);

  // ── Queries (all preserved exactly) ─────────────────────────

  const { data: frameworks, isLoading: fwLoading } = useQuery<Framework[]>({
    queryKey: ["compliance-status"],
    queryFn: fetchComplianceStatus,
    retry: 1,
    placeholderData: MOCK_FRAMEWORKS,
  });

  const { data: gaps, isLoading: gapsLoading } = useQuery<ComplianceGap[]>({
    queryKey: ["compliance-gaps"],
    queryFn: fetchGaps,
    retry: 1,
    placeholderData: MOCK_GAPS,
  });

  const { data: evidence, isLoading: evLoading, refetch: refetchEvidence } = useQuery<EvidenceItem[]>({
    queryKey: ["evidence-list"],
    queryFn: fetchEvidence,
    retry: 1,
    placeholderData: MOCK_EVIDENCE,
  });

  const { data: scannerStats } = useQuery<Record<string, unknown>>({
    queryKey: ["compliance-scanner-stats"],
    queryFn: fetchScannerStats,
    retry: 1,
  });

  const handleUpload = useCallback((id: string) => {
    setUploadingId(id);
    setTimeout(() => setUploadingId(null), 1500);
  }, []);

  const isLoading = fwLoading || gapsLoading || evLoading;
  if (isLoading && !frameworks?.length) return <PageSkeleton />;

  // ── KPI derivations (unchanged) ──────────────────────────────

  const fwData = frameworks ?? MOCK_FRAMEWORKS;
  const gapsData = gaps ?? MOCK_GAPS;
  const evidenceData = evidence ?? MOCK_EVIDENCE;

  const avgProgress = scannerStats?.compliance_rate != null
    ? Math.round(scannerStats.compliance_rate as number)
    : Math.round(fwData.reduce((s, f) => s + f.progress, 0) / fwData.length);
  const certifiedCount = fwData.filter((f) => f.status === "certified").length;
  const gapCount = scannerStats?.failed != null
    ? (scannerStats.failed as number)
    : fwData.filter((f) => f.status === "gap").length;
  const missingEvidence = evidenceData.filter((e) => e.status === "Missing" || e.status === "Expired").length;
  const criticalGaps = gapsData.filter((g) => g.risk_level === "critical").length;

  return (
    <div className="space-y-6 p-6 max-w-screen-2xl mx-auto">
      {/* ── Page Header ─────────────────────────────── */}
      <PageHeader
        title="Compliance Dashboard"
        description="GRC posture, evidence collection, and audit readiness — Compliance Officer view"
        badge="P07"
        actions={
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              className="gap-1.5 border-white/[0.08] hover:bg-white/[0.05] text-xs text-zinc-400 hover:text-zinc-200"
              onClick={() => refetchEvidence()}
              aria-label="Refresh compliance data"
            >
              <RefreshCw className="h-3.5 w-3.5" />
              Refresh
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="gap-1.5 border-white/[0.08] hover:bg-white/[0.05] text-xs text-zinc-400 hover:text-zinc-200"
              aria-label="Export compliance report"
            >
              <Download className="h-3.5 w-3.5" />
              Export
            </Button>
          </div>
        }
      />

      {/* ── Hero Section ─────────────────────────────── */}
      <HeroSection
        avgProgress={avgProgress}
        certifiedCount={certifiedCount}
        totalFrameworks={fwData.length}
        criticalGaps={criticalGaps}
        missingEvidence={missingEvidence}
        onRefresh={() => refetchEvidence()}
      />

      {/* ── Framework Cards ──────────────────────────── */}
      <section aria-labelledby="fw-grid-heading">
        <div className="flex items-center gap-3 mb-4">
          <div className="h-4 w-4 rounded-sm bg-violet-500/15 flex items-center justify-center">
            <Target className="h-3 w-3 text-violet-400" />
          </div>
          <h2 id="fw-grid-heading" className="text-xs font-bold uppercase tracking-widest text-zinc-400">
            Framework Status
          </h2>
          <div className="flex-1 h-px bg-white/[0.05]" />
          <span className="text-[10px] text-zinc-600 uppercase tracking-widest">{fwData.length} frameworks</span>
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-4">
          {fwData.map((fw, i) => (
            <FrameworkCard key={fw.id} fw={fw} index={i} />
          ))}
        </div>
      </section>

      {/* ── Gap Analysis + Timeline side-by-side ─────── */}
      <div className="grid grid-cols-1 xl:grid-cols-5 gap-6">
        <section className="xl:col-span-3" aria-labelledby="gaps-heading">
          <GapsSection gaps={gapsData} />
        </section>

        <section className="xl:col-span-2" aria-labelledby="timeline-heading">
          <AuditTimeline milestones={MOCK_MILESTONES} />
        </section>
      </div>

      {/* ── Evidence Collection ───────────────────────── */}
      <section aria-labelledby="evidence-heading">
        <EvidenceSection items={evidenceData} onUpload={handleUpload} />
      </section>
    </div>
  );
}
