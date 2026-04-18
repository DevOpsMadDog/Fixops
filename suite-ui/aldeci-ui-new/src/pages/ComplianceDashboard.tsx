/**
 * Compliance Dashboard — P07 Persona (Compliance Officer)
 *
 * Single-page dashboard showing all compliance data simultaneously:
 *   1. Framework Status Grid — 6 cards with progress + status badges
 *   2. Evidence Collection Table — control evidence with status + upload actions
 *   3. Compliance Gaps Panel — failing controls with risk level + remediation
 *   4. Audit Timeline — horizontal rail with last/next audit milestones
 *
 * API: GET /api/v1/compliance/status, /api/v1/compliance/gaps, /api/v1/evidence/list
 * Fallback: mock data when API is unavailable
 */

import { useState, useCallback } from "react";
import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  ShieldCheck, AlertTriangle, CheckCircle2, XCircle, Clock,
  FileText, Lock, Layers, Server, Globe, Package,
  Upload, ExternalLink, RefreshCw, Download,
  Calendar, TrendingUp, AlertCircle, ChevronRight,
  ClipboardList, Target, BarChart3,
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

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";
const ORG_ID = "aldeci-demo";

// ══════════════════════════════════════════════════════════════
// Types
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
// Mock Data
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

// ══════════════════════════════════════════════════════════════
// Helpers
// ══════════════════════════════════════════════════════════════

function progressColor(pct: number): string {
  if (pct >= 80) return "bg-emerald-500";
  if (pct >= 50) return "bg-amber-500";
  return "bg-red-500";
}

function progressTextColor(pct: number): string {
  if (pct >= 80) return "text-emerald-400";
  if (pct >= 50) return "text-amber-400";
  return "text-red-400";
}

function statusBadge(status: FrameworkStatus) {
  const map: Record<FrameworkStatus, { label: string; className: string }> = {
    certified: { label: "Certified", className: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30" },
    in_progress: { label: "In Progress", className: "bg-amber-500/15 text-amber-400 border-amber-500/30" },
    gap: { label: "Gap", className: "bg-red-500/15 text-red-400 border-red-500/30" },
  };
  return map[status];
}

function evidenceBadge(status: EvidenceStatus) {
  const map: Record<EvidenceStatus, { className: string; icon: React.ElementType }> = {
    Collected: { className: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30", icon: CheckCircle2 },
    Missing: { className: "bg-red-500/15 text-red-400 border-red-500/30", icon: XCircle },
    Expired: { className: "bg-amber-500/15 text-amber-400 border-amber-500/30", icon: Clock },
  };
  return map[status];
}

function riskBadge(level: RiskLevel) {
  const map: Record<RiskLevel, string> = {
    critical: "bg-red-500/15 text-red-400 border-red-500/30",
    high: "bg-orange-500/15 text-orange-400 border-orange-500/30",
    medium: "bg-amber-500/15 text-amber-400 border-amber-500/30",
    low: "bg-blue-500/15 text-blue-400 border-blue-500/30",
  };
  return map[level];
}

const FRAMEWORK_ICONS: Record<string, React.ElementType> = {
  soc2: ShieldCheck,
  pci: Lock,
  iso27001: Layers,
  nist: Server,
  hipaa: FileText,
  cis: Package,
};

// ══════════════════════════════════════════════════════════════
// API fetch helpers
// ══════════════════════════════════════════════════════════════

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "X-API-Key": API_KEY },
  });
  if (!res.ok) throw new Error(`${res.status}`);
  return res.json();
}

async function fetchComplianceStatus(): Promise<Framework[]> {
  // Try new compliance-scanner endpoint first, fall back to legacy
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
  // Try new compliance-scanner findings endpoint
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

async function fetchScannerStats(): Promise<Record<string, any>> {
  return apiFetch(`/api/v1/compliance-scanner/stats?org_id=${ORG_ID}`);
}

// ══════════════════════════════════════════════════════════════
// Sub-components
// ══════════════════════════════════════════════════════════════

function FrameworkCard({ fw }: { fw: Framework }) {
  const Icon = FRAMEWORK_ICONS[fw.id] ?? ShieldCheck;
  const badge = statusBadge(fw.status);
  const gaps = fw.controls_total - fw.controls_passing;

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3, ease: [0.16, 1, 0.3, 1] }}
    >
      <Card className="relative overflow-hidden group hover:border-white/10 transition-colors">
        {/* accent stripe */}
        <div
          className={cn(
            "absolute inset-y-0 left-0 w-0.5",
            fw.progress >= 80 ? "bg-emerald-500" : fw.progress >= 50 ? "bg-amber-500" : "bg-red-500"
          )}
        />
        <CardContent className="p-5">
          <div className="flex items-start justify-between mb-4">
            <div className="flex items-center gap-2.5">
              <div className={cn(
                "rounded-md p-1.5",
                fw.progress >= 80 ? "bg-emerald-500/10" : fw.progress >= 50 ? "bg-amber-500/10" : "bg-red-500/10"
              )}>
                <Icon className={cn(
                  "h-4 w-4",
                  fw.progress >= 80 ? "text-emerald-400" : fw.progress >= 50 ? "text-amber-400" : "text-red-400"
                )} />
              </div>
              <span className="text-sm font-semibold leading-tight">{fw.name}</span>
            </div>
            <span className={cn(
              "inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium",
              badge.className
            )}>
              {badge.label}
            </span>
          </div>

          {/* Progress */}
          <div className="space-y-2 mb-4">
            <div className="flex items-end justify-between">
              <span className={cn("text-3xl font-bold tabular-nums tracking-tight", progressTextColor(fw.progress))}>
                {fw.progress}%
              </span>
              <span className="text-xs text-muted-foreground">
                {fw.controls_passing}/{fw.controls_total} controls
              </span>
            </div>
            <div className="h-1.5 rounded-full bg-white/5 overflow-hidden">
              <motion.div
                className={cn("h-full rounded-full", progressColor(fw.progress))}
                initial={{ width: 0 }}
                animate={{ width: `${fw.progress}%` }}
                transition={{ duration: 0.8, delay: 0.1, ease: [0.16, 1, 0.3, 1] }}
              />
            </div>
          </div>

          {/* Stats row */}
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <span className="flex items-center gap-1">
              <CheckCircle2 className="h-3 w-3 text-emerald-500" />
              {fw.controls_passing} passing
            </span>
            {gaps > 0 && (
              <span className="flex items-center gap-1 text-red-400">
                <AlertCircle className="h-3 w-3" />
                {gaps} gap{gaps !== 1 ? "s" : ""}
              </span>
            )}
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}

// ──────────────────────────────────────────────────────────────

interface EvidenceTableProps {
  items: EvidenceItem[];
  onUpload: (id: string) => void;
}

function EvidenceTable({ items, onUpload }: EvidenceTableProps) {
  return (
    <div className="rounded-lg border border-white/5 overflow-hidden">
      <Table>
        <TableHeader>
          <TableRow className="border-white/5 hover:bg-transparent">
            <TableHead className="text-xs uppercase tracking-wider text-muted-foreground">Control ID</TableHead>
            <TableHead className="text-xs uppercase tracking-wider text-muted-foreground">Framework</TableHead>
            <TableHead className="text-xs uppercase tracking-wider text-muted-foreground">Description</TableHead>
            <TableHead className="text-xs uppercase tracking-wider text-muted-foreground">Status</TableHead>
            <TableHead className="text-xs uppercase tracking-wider text-muted-foreground">Last Updated</TableHead>
            <TableHead className="text-xs uppercase tracking-wider text-muted-foreground text-right">Action</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {items.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
              <p className="text-lg font-medium">No data available</p>
              <p className="text-sm">Data will appear here once available</p>
            </div>
          ) : (
            items.map((item, i) => {
            const badge = evidenceBadge(item.status);
            const StatusIcon = badge.icon;
            return (
              <motion.tr
                key={item.id}
                initial={{ opacity: 0 }}
                animate={{ opacity: 1 }}
                transition={{ duration: 0.2, delay: i * 0.03 }}
                className="border-white/5 hover:bg-white/2.5 transition-colors"
              >
                <TableCell className="font-mono text-xs text-blue-400">{item.control_id}</TableCell>
                <TableCell>
                  <span className="text-xs bg-white/5 border border-white/8 rounded px-1.5 py-0.5">
                    {item.framework}
                  </span>
                </TableCell>
                <TableCell className="text-sm max-w-xs truncate" title={item.description}>
                  {item.description}
                </TableCell>
                <TableCell>
                  <span className={cn(
                    "inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs font-medium",
                    badge.className
                  )}>
                    <StatusIcon className="h-3 w-3" />
                    {item.status}
                  </span>
                </TableCell>
                <TableCell className="text-xs text-muted-foreground tabular-nums">
                  {item.last_updated}
                </TableCell>
                <TableCell className="text-right">
                  <Button
                    size="sm"
                    variant="outline"
                    className="h-7 text-xs gap-1 border-white/10 hover:bg-white/5"
                    onClick={() => onUpload(item.id)}
                    aria-label={`Upload evidence for ${item.control_id}`}
                  >
                    <Upload className="h-3 w-3" />
                    Upload
                  </Button>
                </TableCell>
              </motion.tr>
            );
          })}
        </TableBody>
      </Table>
    </div>
  );
}

// ──────────────────────────────────────────────────────────────

function GapsPanel({ gaps }: { gaps: ComplianceGap[] }) {
  return (
    <div className="space-y-2.5">
      {gaps.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
          <p className="text-lg font-medium">No data available</p>
          <p className="text-sm">Data will appear here once available</p>
        </div>
      ) : (
        gaps.map((gap, i) => (
        <motion.div
          key={gap.id}
          initial={{ opacity: 0, x: -8 }}
          animate={{ opacity: 1, x: 0 }}
          transition={{ duration: 0.25, delay: i * 0.05 }}
        >
          <div className="rounded-lg border border-white/5 bg-white/2.5 p-4 hover:bg-white/5 transition-colors group">
            <div className="flex items-start justify-between gap-3 mb-2">
              <div className="flex items-start gap-2.5 min-w-0">
                <AlertTriangle className={cn(
                  "h-4 w-4 mt-0.5 shrink-0",
                  gap.risk_level === "critical" ? "text-red-400" :
                  gap.risk_level === "high" ? "text-orange-400" :
                  gap.risk_level === "medium" ? "text-amber-400" : "text-blue-400"
                )} />
                <div className="min-w-0">
                  <p className="text-sm font-medium leading-tight truncate">{gap.control}</p>
                  <p className="text-xs text-muted-foreground mt-0.5">{gap.framework}</p>
                </div>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <span className={cn(
                  "inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium capitalize",
                  riskBadge(gap.risk_level)
                )}>
                  {gap.risk_level}
                </span>
                <Button
                  size="sm"
                  variant="ghost"
                  className="h-7 px-2 text-xs gap-1 opacity-0 group-hover:opacity-100 transition-opacity"
                  asChild
                >
                  <a href={gap.remediation_url} aria-label={`Remediate ${gap.control}`}>
                    <ExternalLink className="h-3 w-3" />
                    Remediate
                  </a>
                </Button>
              </div>
            </div>
            <p className="text-xs text-muted-foreground leading-relaxed pl-6.5">
              {gap.description}
            </p>
          </div>
        </motion.div>
      ))}
    </div>
  );
}

// ──────────────────────────────────────────────────────────────

function AuditTimeline({ milestones }: { milestones: AuditMilestone[] }) {
  const today = new Date("2026-04-13");

  const milestoneTypeStyle: Record<AuditMilestone["type"], { dot: string; label: string; line: string }> = {
    past: {
      dot: "bg-emerald-500 border-emerald-400",
      label: "text-muted-foreground",
      line: "bg-emerald-500/40",
    },
    next: {
      dot: "bg-amber-400 border-amber-300 ring-2 ring-amber-400/30 ring-offset-2 ring-offset-background animate-pulse",
      label: "text-amber-400 font-semibold",
      line: "bg-amber-500/40",
    },
    upcoming: {
      dot: "bg-white/20 border-white/20",
      label: "text-muted-foreground",
      line: "bg-white/10",
    },
  };

  return (
    <div className="relative">
      {/* Horizontal rail */}
      <div className="overflow-x-auto pb-4">
        <div className="relative min-w-max px-4">
          {/* Connector line */}
          <div className="absolute top-3 left-0 right-0 h-px bg-white/8" />

          <div className="flex items-start gap-0">
            {milestones.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                <p className="text-lg font-medium">No data available</p>
                <p className="text-sm">Data will appear here once available</p>
              </div>
            ) : (
              milestones.map((m, i) => {
              const style = milestoneTypeStyle[m.type];
              const isLast = i === milestones.length - 1;
              return (
                <div key={m.id} className="relative flex flex-col items-center" style={{ minWidth: 120 }}>
                  {/* Segment line */}
                  {!isLast && (
                    <div className={cn("absolute top-[11px] left-1/2 right-0 h-px", style.line)} />
                  )}
                  {/* Dot */}
                  <motion.div
                    initial={{ scale: 0 }}
                    animate={{ scale: 1 }}
                    transition={{ duration: 0.3, delay: i * 0.06 }}
                    className={cn(
                      "relative z-10 h-5 w-5 rounded-full border-2 shrink-0",
                      style.dot
                    )}
                  />
                  {/* Label */}
                  <div className="mt-3 px-1 text-center">
                    <p className={cn("text-[11px] leading-tight", style.label)}>
                      {m.label}
                    </p>
                    <p className="text-[10px] text-muted-foreground/60 mt-0.5 tabular-nums">
                      {m.date}
                    </p>
                    <span className="inline-block mt-1 text-[9px] bg-white/5 border border-white/8 rounded px-1 py-px text-muted-foreground/60">
                      {m.framework}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* Legend */}
      <div className="flex items-center gap-5 mt-2 text-xs text-muted-foreground">
        <div className="flex items-center gap-1.5">
          <div className="h-2.5 w-2.5 rounded-full bg-emerald-500" />
          Completed
        </div>
        <div className="flex items-center gap-1.5">
          <div className="h-2.5 w-2.5 rounded-full bg-amber-400" />
          Next due
        </div>
        <div className="flex items-center gap-1.5">
          <div className="h-2.5 w-2.5 rounded-full bg-white/20 border border-white/20" />
          Scheduled
        </div>
        <div className="ml-auto flex items-center gap-1.5">
          <Calendar className="h-3 w-3" />
          Today: {today.toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" })}
        </div>
      </div>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// Main Component
// ══════════════════════════════════════════════════════════════

export default function ComplianceDashboard() {
  const [uploadingId, setUploadingId] = useState<string | null>(null);

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

  const { data: scannerStats } = useQuery<Record<string, any>>({
    queryKey: ["compliance-scanner-stats"],
    queryFn: fetchScannerStats,
    retry: 1,
  });

  const handleUpload = useCallback((id: string) => {
    setUploadingId(id);
    // In production: open file picker / upload modal
    setTimeout(() => setUploadingId(null), 1500);
  }, []);

  const isLoading = fwLoading || gapsLoading || evLoading;
  if (isLoading && !frameworks?.length) return <PageSkeleton />;

  const fwData = frameworks ?? MOCK_FRAMEWORKS;
  const gapsData = gaps ?? MOCK_GAPS;
  const evidenceData = evidence ?? MOCK_EVIDENCE;

  // KPI derivations — prefer live scanner stats when available
  const avgProgress = scannerStats?.compliance_rate != null
    ? Math.round(scannerStats.compliance_rate)
    : Math.round(fwData.reduce((s, f) => s + f.progress, 0) / fwData.length);
  const certifiedCount = fwData.filter((f) => f.status === "certified").length;
  const gapCount = scannerStats?.failed != null ? scannerStats.failed : fwData.filter((f) => f.status === "gap").length;
  const missingEvidence = evidenceData.filter((e) => e.status === "Missing" || e.status === "Expired").length;
  const criticalGaps = gapsData.filter((g) => g.risk_level === "critical").length;

  return (
    <div className="space-y-8 p-6 max-w-screen-2xl mx-auto">
      {/* Header */}
      <PageHeader
        title="Compliance Dashboard"
        description="Framework status, evidence collection, and audit readiness — P07 Compliance Officer view"
        badge="P07"
        actions={
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              className="gap-1.5 border-white/10 hover:bg-white/5 text-xs"
              onClick={() => refetchEvidence()}
              aria-label="Refresh compliance data"
            >
              <RefreshCw className="h-3.5 w-3.5" />
              Refresh
            </Button>
            <Button
              variant="outline"
              size="sm"
              className="gap-1.5 border-white/10 hover:bg-white/5 text-xs"
              aria-label="Export compliance report"
            >
              <Download className="h-3.5 w-3.5" />
              Export Report
            </Button>
          </div>
        }
      />

      {/* KPI Strip */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        <KpiCard
          title="Avg. Compliance"
          value={`${avgProgress}%`}
          icon={BarChart3}
          trend={avgProgress >= 70 ? "up" : "down"}
          trendLabel="across all frameworks"
        />
        <KpiCard
          title="Certified"
          value={certifiedCount}
          icon={ShieldCheck}
          trendLabel={`of ${fwData.length} frameworks`}
          trend="up"
        />
        <KpiCard
          title="Critical Gaps"
          value={criticalGaps}
          icon={AlertTriangle}
          trend={criticalGaps > 0 ? "down" : "flat"}
          trendLabel="require immediate action"
        />
        <KpiCard
          title="Evidence Issues"
          value={missingEvidence}
          icon={ClipboardList}
          trend={missingEvidence > 3 ? "down" : "flat"}
          trendLabel="missing or expired"
        />
      </div>

      {/* Section 1: Framework Status Grid */}
      <section aria-labelledby="fw-grid-heading">
        <div className="flex items-center gap-3 mb-4">
          <Target className="h-4 w-4 text-primary" />
          <h2 id="fw-grid-heading" className="text-sm font-semibold uppercase tracking-wider text-muted-foreground">
            Framework Status
          </h2>
          <Separator className="flex-1" />
        </div>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {fwData.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
              <p className="text-lg font-medium">No data available</p>
              <p className="text-sm">Data will appear here once available</p>
            </div>
          ) : (
            fwData.map((fw) => (
            <FrameworkCard key={fw.id} fw={fw} />
          ))}
        </div>
      </section>

      {/* Section 2: Evidence Collection Table */}
      <section aria-labelledby="evidence-heading">
        <div className="flex items-center gap-3 mb-4">
          <ClipboardList className="h-4 w-4 text-primary" />
          <h2 id="evidence-heading" className="text-sm font-semibold uppercase tracking-wider text-muted-foreground">
            Evidence Collection
          </h2>
          <Separator className="flex-1" />
          <div className="flex items-center gap-2 text-xs text-muted-foreground shrink-0">
            <span className="flex items-center gap-1">
              <CheckCircle2 className="h-3 w-3 text-emerald-400" />
              {evidenceData.filter((e) => e.status === "Collected").length} collected
            </span>
            <span className="flex items-center gap-1">
              <Clock className="h-3 w-3 text-amber-400" />
              {evidenceData.filter((e) => e.status === "Expired").length} expired
            </span>
            <span className="flex items-center gap-1">
              <XCircle className="h-3 w-3 text-red-400" />
              {evidenceData.filter((e) => e.status === "Missing").length} missing
            </span>
          </div>
        </div>
        <EvidenceTable items={evidenceData} onUpload={handleUpload} />
      </section>

      {/* Section 3 + 4: Gaps + Timeline side by side on large screens */}
      <div className="grid grid-cols-1 xl:grid-cols-5 gap-6">
        {/* Compliance Gaps Panel */}
        <section className="xl:col-span-3" aria-labelledby="gaps-heading">
          <Card>
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm flex items-center gap-2">
                  <AlertTriangle className="h-4 w-4 text-red-400" />
                  Compliance Gaps
                  <span className="ml-1 rounded-full bg-red-500/15 text-red-400 border border-red-500/30 px-2 py-px text-xs font-medium">
                    {gapsData.length}
                  </span>
                </CardTitle>
                <Button
                  variant="ghost"
                  size="sm"
                  className="text-xs h-7 gap-1 text-muted-foreground"
                  asChild
                >
                  <a href="/comply/evidence">
                    View all <ChevronRight className="h-3 w-3" />
                  </a>
                </Button>
              </div>
            </CardHeader>
            <CardContent>
              <GapsPanel gaps={gapsData} />
            </CardContent>
          </Card>
        </section>

        {/* Audit Timeline */}
        <section className="xl:col-span-2" aria-labelledby="timeline-heading">
          <Card className="h-full">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm flex items-center gap-2">
                <Calendar className="h-4 w-4 text-blue-400" />
                Audit Timeline
              </CardTitle>
            </CardHeader>
            <CardContent>
              <AuditTimeline milestones={MOCK_MILESTONES} />

              {/* Upcoming summary */}
              <Separator className="my-4" />
              <div className="space-y-2">
                <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
                  Upcoming Audits
                </p>
                {MOCK_MILESTONES.filter((m) => m.type === "next" || m.type === "upcoming").map((m) => (
                  <div key={m.id} className="flex items-center justify-between text-xs">
                    <div className="flex items-center gap-2">
                      <div className={cn(
                        "h-1.5 w-1.5 rounded-full",
                        m.type === "next" ? "bg-amber-400" : "bg-white/20"
                      )} />
                      <span className={m.type === "next" ? "text-amber-400 font-medium" : "text-muted-foreground"}>
                        {m.label}
                      </span>
                    </div>
                    <span className="tabular-nums text-muted-foreground/60">{m.date}</span>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </section>
      </div>
    </div>
  );
}
