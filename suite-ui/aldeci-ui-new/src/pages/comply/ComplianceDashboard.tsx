/**
 * Compliance Dashboard — P07 Persona (Compliance Officer)
 *
 * Shows the full governance picture across 7 compliance frameworks:
 * - Framework status cards with circular progress + color coding
 * - Evidence collection progress with pending items + due dates
 * - Control mapping table with framework/status filtering
 * - 12-month compliance trend line chart
 *
 * Data: real API with graceful mock fallback (same pattern as CISODashboard)
 */

import { toArray } from "@/lib/api-utils";
import { useState, useCallback, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { motion, AnimatePresence } from "framer-motion";
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, Legend,
} from "recharts";
import {
  ShieldCheck, AlertTriangle, CheckCircle2, XCircle, Clock,
  FileText, Layers, Lock, Server, Globe, ChevronDown, ChevronRight,
  Download, RefreshCw, Upload, Plus, Filter, Calendar,
  TrendingUp, BarChart3, Package, Eye, FileCheck2, AlertCircle,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import {
  useComplianceStatus,
  useComplianceFrameworks,
  useComplianceGaps,
  useAssessCompliance,
} from "@/hooks/use-api";
import { cn } from "@/lib/utils";

// ══════════════════════════════════════════════════════════════
// Types
// ══════════════════════════════════════════════════════════════

interface Framework {
  id: string;
  name: string;
  shortName: string;
  score: number;
  controlsPassed: number;
  totalControls: number;
  status: "compliant" | "partial" | "non-compliant" | "not-assessed";
  lastAudit: string;
  nextAudit: string;
  evidenceCollected: number;
  evidenceRequired: number;
}

interface EvidenceItem {
  id: string;
  framework: string;
  controlId: string;
  title: string;
  dueDate: string;
  status: "pending" | "in-progress" | "collected" | "overdue";
  priority: "critical" | "high" | "medium" | "low";
  assignee: string;
}

interface Control {
  id: string;
  framework: string;
  controlId: string;
  description: string;
  status: "compliant" | "non-compliant" | "partial" | "not-assessed";
  evidenceCount: number;
  findingsCount: number;
  lastReviewed: string;
}

interface TrendPoint {
  month: string;
  SOC2: number;
  "PCI-DSS": number;
  HIPAA: number;
  ISO27001: number;
  "NIST-CSF": number;
  CIS: number;
  GDPR: number;
}

// ══════════════════════════════════════════════════════════════
// Mock Data (used as fallback when API is unavailable)
// ══════════════════════════════════════════════════════════════

const MOCK_FRAMEWORKS: Framework[] = [
  {
    id: "soc2",
    name: "SOC 2 Type II",
    shortName: "SOC2",
    score: 92,
    controlsPassed: 74,
    totalControls: 80,
    status: "compliant",
    lastAudit: "2026-01-15",
    nextAudit: "2026-07-15",
    evidenceCollected: 68,
    evidenceRequired: 74,
  },
  {
    id: "pci-dss",
    name: "PCI-DSS v4.0",
    shortName: "PCI-DSS",
    score: 81,
    controlsPassed: 49,
    totalControls: 60,
    status: "partial",
    lastAudit: "2025-11-20",
    nextAudit: "2026-05-20",
    evidenceCollected: 41,
    evidenceRequired: 55,
  },
  {
    id: "hipaa",
    name: "HIPAA",
    shortName: "HIPAA",
    score: 88,
    controlsPassed: 22,
    totalControls: 25,
    status: "compliant",
    lastAudit: "2025-12-08",
    nextAudit: "2026-06-08",
    evidenceCollected: 19,
    evidenceRequired: 22,
  },
  {
    id: "iso27001",
    name: "ISO 27001:2022",
    shortName: "ISO27001",
    score: 91,
    controlsPassed: 36,
    totalControls: 40,
    status: "compliant",
    lastAudit: "2026-02-01",
    nextAudit: "2027-02-01",
    evidenceCollected: 34,
    evidenceRequired: 36,
  },
  {
    id: "nist-csf",
    name: "NIST CSF 2.0",
    shortName: "NIST-CSF",
    score: 74,
    controlsPassed: 37,
    totalControls: 50,
    status: "partial",
    lastAudit: "2025-10-14",
    nextAudit: "2026-04-14",
    evidenceCollected: 29,
    evidenceRequired: 45,
  },
  {
    id: "cis",
    name: "CIS Controls v8",
    shortName: "CIS",
    score: 68,
    controlsPassed: 41,
    totalControls: 60,
    status: "partial",
    lastAudit: "2025-09-30",
    nextAudit: "2026-03-30",
    evidenceCollected: 35,
    evidenceRequired: 55,
  },
  {
    id: "gdpr",
    name: "GDPR",
    shortName: "GDPR",
    score: 95,
    controlsPassed: 47,
    totalControls: 50,
    status: "compliant",
    lastAudit: "2026-03-01",
    nextAudit: "2027-03-01",
    evidenceCollected: 46,
    evidenceRequired: 47,
  },
];

const MOCK_EVIDENCE_ITEMS: EvidenceItem[] = [
  { id: "e1", framework: "PCI-DSS", controlId: "PCI-DSS-6.5", title: "Penetration test report Q1 2026", dueDate: "2026-04-20", status: "in-progress", priority: "critical", assignee: "Alex Chen" },
  { id: "e2", framework: "NIST-CSF", controlId: "NIST-PR.AC-4", title: "Access control policy v3 approval", dueDate: "2026-04-18", status: "pending", priority: "high", assignee: "Maria Santos" },
  { id: "e3", framework: "CIS", controlId: "CIS-2.1", title: "Software asset inventory export", dueDate: "2026-04-15", status: "overdue", priority: "high", assignee: "Jordan Lee" },
  { id: "e4", framework: "PCI-DSS", controlId: "PCI-DSS-10.2", title: "Audit log review records March", dueDate: "2026-04-22", status: "pending", priority: "medium", assignee: "Alex Chen" },
  { id: "e5", framework: "NIST-CSF", controlId: "NIST-DE.CM-1", title: "Network monitoring configuration screenshots", dueDate: "2026-04-30", status: "in-progress", priority: "medium", assignee: "Sam Park" },
  { id: "e6", framework: "CIS", controlId: "CIS-4.2", title: "Privileged account inventory — updated list", dueDate: "2026-04-14", status: "overdue", priority: "critical", assignee: "Jordan Lee" },
  { id: "e7", framework: "SOC2", controlId: "SOC2-CC7.2", title: "Incident response test walkthrough recording", dueDate: "2026-05-10", status: "pending", priority: "medium", assignee: "Maria Santos" },
  { id: "e8", framework: "HIPAA", controlId: "HIPAA-164.308", title: "Risk analysis update (annual)", dueDate: "2026-06-01", status: "pending", priority: "low", assignee: "Sam Park" },
  { id: "e9", framework: "ISO27001", controlId: "ISO-A.8.3", title: "Media handling procedures document", dueDate: "2026-05-15", status: "collected", priority: "low", assignee: "Alex Chen" },
  { id: "e10", framework: "GDPR", controlId: "GDPR-Art32", title: "Data encryption certificate renewal", dueDate: "2026-07-01", status: "pending", priority: "medium", assignee: "Maria Santos" },
];

const MOCK_CONTROLS: Control[] = [
  { id: "c1", framework: "SOC2", controlId: "SOC2-CC6.1", description: "Logical access security software, infrastructure, and architectures", status: "compliant", evidenceCount: 4, findingsCount: 0, lastReviewed: "2026-03-15" },
  { id: "c2", framework: "SOC2", controlId: "SOC2-CC6.2", description: "New internal and external users provisioning restricted", status: "compliant", evidenceCount: 3, findingsCount: 0, lastReviewed: "2026-03-15" },
  { id: "c3", framework: "SOC2", controlId: "SOC2-CC7.2", description: "System components monitored to detect anomalies", status: "partial", evidenceCount: 2, findingsCount: 1, lastReviewed: "2026-02-28" },
  { id: "c4", framework: "PCI-DSS", controlId: "PCI-DSS-6.5", description: "Develop and maintain secure systems and applications", status: "non-compliant", evidenceCount: 0, findingsCount: 3, lastReviewed: "2026-01-20" },
  { id: "c5", framework: "PCI-DSS", controlId: "PCI-DSS-10.2", description: "Implement audit trails to link all access to system components", status: "partial", evidenceCount: 1, findingsCount: 2, lastReviewed: "2026-02-10" },
  { id: "c6", framework: "PCI-DSS", controlId: "PCI-DSS-11.3", description: "Implement a methodology for penetration testing", status: "non-compliant", evidenceCount: 0, findingsCount: 2, lastReviewed: "2025-12-01" },
  { id: "c7", framework: "HIPAA", controlId: "HIPAA-164.308", description: "Security management process — risk analysis and management", status: "compliant", evidenceCount: 5, findingsCount: 0, lastReviewed: "2026-03-01" },
  { id: "c8", framework: "HIPAA", controlId: "HIPAA-164.312", description: "Technical safeguards — access control and encryption", status: "compliant", evidenceCount: 4, findingsCount: 0, lastReviewed: "2026-03-01" },
  { id: "c9", framework: "ISO27001", controlId: "ISO-A.8.3", description: "Media handling — protection and disposal of physical media", status: "partial", evidenceCount: 1, findingsCount: 1, lastReviewed: "2026-02-20" },
  { id: "c10", framework: "ISO27001", controlId: "ISO-A.9.1", description: "Access control policy — establish, document and review", status: "compliant", evidenceCount: 3, findingsCount: 0, lastReviewed: "2026-03-10" },
  { id: "c11", framework: "NIST-CSF", controlId: "NIST-PR.AC-4", description: "Access permissions and authorizations managed", status: "partial", evidenceCount: 2, findingsCount: 2, lastReviewed: "2026-01-15" },
  { id: "c12", framework: "NIST-CSF", controlId: "NIST-DE.CM-1", description: "Network monitoring to detect potential cybersecurity events", status: "non-compliant", evidenceCount: 1, findingsCount: 3, lastReviewed: "2025-11-30" },
  { id: "c13", framework: "CIS", controlId: "CIS-2.1", description: "Establish and maintain a software asset inventory", status: "non-compliant", evidenceCount: 0, findingsCount: 2, lastReviewed: "2025-10-01" },
  { id: "c14", framework: "CIS", controlId: "CIS-4.2", description: "Establish and maintain a service account inventory", status: "non-compliant", evidenceCount: 0, findingsCount: 3, lastReviewed: "2025-10-01" },
  { id: "c15", framework: "GDPR", controlId: "GDPR-Art32", description: "Security of processing — encryption and pseudonymisation", status: "compliant", evidenceCount: 5, findingsCount: 0, lastReviewed: "2026-03-20" },
  { id: "c16", framework: "GDPR", controlId: "GDPR-Art25", description: "Data protection by design and by default", status: "compliant", evidenceCount: 4, findingsCount: 0, lastReviewed: "2026-03-20" },
  { id: "c17", framework: "SOC2", controlId: "SOC2-CC8.1", description: "Changes to infrastructure, data, and software controlled", status: "compliant", evidenceCount: 3, findingsCount: 0, lastReviewed: "2026-03-15" },
  { id: "c18", framework: "NIST-CSF", controlId: "NIST-RS.CO-2", description: "Incidents reported per established criteria", status: "not-assessed", evidenceCount: 0, findingsCount: 0, lastReviewed: "2025-09-01" },
];

function generateMockTrend(): TrendPoint[] {
  const months = ["May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec", "Jan", "Feb", "Mar", "Apr"];
  const bases = { SOC2: 84, "PCI-DSS": 71, HIPAA: 80, ISO27001: 83, "NIST-CSF": 63, CIS: 58, GDPR: 87 };
  return months.map((month, i) => {
    const bump = i * 0.7;
    return {
      month,
      SOC2: Math.min(100, Math.round(bases.SOC2 + bump + (Math.sin(i / 3) * 2))),
      "PCI-DSS": Math.min(100, Math.round(bases["PCI-DSS"] + bump + (Math.cos(i / 4) * 3))),
      HIPAA: Math.min(100, Math.round(bases.HIPAA + bump * 0.8 + (Math.sin(i / 5) * 1.5))),
      ISO27001: Math.min(100, Math.round(bases.ISO27001 + bump + (Math.cos(i / 3) * 2))),
      "NIST-CSF": Math.min(100, Math.round(bases["NIST-CSF"] + bump * 1.5 + (Math.sin(i / 4) * 2))),
      CIS: Math.min(100, Math.round(bases.CIS + bump * 1.4 + (Math.cos(i / 5) * 2))),
      GDPR: Math.min(100, Math.round(bases.GDPR + bump * 0.5 + (Math.sin(i / 6) * 1))),
    };
  });
}

// ══════════════════════════════════════════════════════════════
// Constants
// ══════════════════════════════════════════════════════════════

const FRAMEWORK_COLORS: Record<string, string> = {
  SOC2: "#6366f1",
  "PCI-DSS": "#f59e0b",
  HIPAA: "#10b981",
  ISO27001: "#3b82f6",
  "NIST-CSF": "#8b5cf6",
  CIS: "#ec4899",
  GDPR: "#14b8a6",
};

const FRAMEWORK_ICONS: Record<string, React.ElementType> = {
  SOC2: ShieldCheck,
  "PCI-DSS": Lock,
  HIPAA: FileText,
  ISO27001: Layers,
  "NIST-CSF": Server,
  CIS: Package,
  GDPR: Globe,
};

const CHART_TOOLTIP_STYLE = {
  background: "hsl(var(--card))",
  border: "1px solid hsl(var(--border))",
  borderRadius: 8,
  fontSize: 12,
  color: "hsl(var(--card-foreground))",
};

// ══════════════════════════════════════════════════════════════
// Score Ring — circular progress using SVG
// ══════════════════════════════════════════════════════════════

function ScoreRing({ score, size = 72 }: { score: number; size?: number }) {
  const radius = (size - 10) / 2;
  const circumference = 2 * Math.PI * radius;
  const filled = (score / 100) * circumference;
  const color = score >= 90 ? "#22c55e" : score >= 70 ? "#f59e0b" : "#ef4444";
  const cx = size / 2;
  const cy = size / 2;

  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`} className="shrink-0">
      <circle cx={cx} cy={cy} r={radius} fill="none" stroke="hsl(var(--muted))" strokeWidth="6" />
      <circle
        cx={cx} cy={cy} r={radius}
        fill="none"
        stroke={color}
        strokeWidth="6"
        strokeLinecap="round"
        strokeDasharray={`${filled} ${circumference}`}
        transform={`rotate(-90 ${cx} ${cy})`}
        style={{ transition: "stroke-dasharray 0.8s cubic-bezier(0.16,1,0.3,1)" }}
      />
      <text
        x={cx} y={cy + 1}
        textAnchor="middle"
        dominantBaseline="middle"
        fontSize={size <= 72 ? "15" : "20"}
        fontWeight="700"
        fill="currentColor"
      >
        {score}
      </text>
    </svg>
  );
}

// ══════════════════════════════════════════════════════════════
// Framework Card — expands to show control list
// ══════════════════════════════════════════════════════════════

function FrameworkCard({
  fw,
  controls,
  isExpanded,
  onToggle,
}: {
  fw: Framework;
  controls: Control[];
  isExpanded: boolean;
  onToggle: () => void;
}) {
  const Icon = FRAMEWORK_ICONS[fw.shortName] ?? ShieldCheck;
  const scoreColor = fw.score >= 90 ? "text-green-400" : fw.score >= 70 ? "text-yellow-400" : "text-red-400";
  const statusVariant = fw.status === "compliant" ? "default" : fw.status === "partial" ? "secondary" : "destructive";
  const frameworkControls = controls.filter((c) => c.framework === fw.shortName);

  const statusLabel = {
    compliant: "Compliant",
    partial: "Partial",
    "non-compliant": "Non-Compliant",
    "not-assessed": "Not Assessed",
  }[fw.status];

  return (
    <motion.div layout>
      <Card
        className={cn(
          "overflow-hidden transition-shadow",
          isExpanded && "ring-1 ring-primary/30 shadow-md"
        )}
      >
        {/* Card Header — always visible */}
        <button
          className="w-full text-left p-4 hover:bg-muted/20 transition-colors"
          onClick={onToggle}
          aria-expanded={isExpanded}
        >
          <div className="flex items-start gap-3">
            {/* Ring + score */}
            <div className="relative shrink-0">
              <ScoreRing score={fw.score} size={72} />
            </div>

            {/* Info */}
            <div className="flex-1 min-w-0 space-y-1.5">
              <div className="flex items-start justify-between gap-2">
                <div className="flex items-center gap-2 min-w-0">
                  <Icon className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                  <span className="text-sm font-semibold leading-tight truncate">{fw.name}</span>
                </div>
                <div className="flex items-center gap-1.5 shrink-0">
                  <Badge variant={statusVariant} className="text-xs capitalize">{statusLabel}</Badge>
                  {isExpanded
                    ? <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" />
                    : <ChevronRight className="h-3.5 w-3.5 text-muted-foreground" />
                  }
                </div>
              </div>

              <div className="text-xs text-muted-foreground">
                <span className={cn("font-semibold", scoreColor)}>{fw.controlsPassed}</span>
                <span>/{fw.totalControls} controls</span>
              </div>

              <Progress
                value={(fw.controlsPassed / fw.totalControls) * 100}
                className="h-1.5"
              />

              <div className="flex items-center justify-between text-xs text-muted-foreground">
                <span className="flex items-center gap-1">
                  <Calendar className="h-3 w-3" />
                  Audited {fw.lastAudit}
                </span>
                <span>Next: {fw.nextAudit}</span>
              </div>
            </div>
          </div>
        </button>

        {/* Expanded control list */}
        <AnimatePresence>
          {isExpanded && frameworkControls.length > 0 && (
            <motion.div
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: "auto", opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              transition={{ duration: 0.25, ease: [0.16, 1, 0.3, 1] }}
              className="overflow-hidden"
            >
              <Separator />
              <div className="p-3 space-y-1.5">
                <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide mb-2">
                  Controls ({frameworkControls.length})
                </p>
                {frameworkControls.map((ctrl) => (
                  <div
                    key={ctrl.id}
                    className="flex items-center gap-2 text-xs py-1.5 px-2 rounded hover:bg-muted/30 transition-colors"
                  >
                    <ControlStatusIcon status={ctrl.status} className="h-3.5 w-3.5 shrink-0" />
                    <span className="font-mono text-muted-foreground w-28 shrink-0">{ctrl.controlId}</span>
                    <span className="flex-1 truncate text-foreground/80">{ctrl.description}</span>
                  </div>
                ))}
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </Card>
    </motion.div>
  );
}

// ══════════════════════════════════════════════════════════════
// Control Status Icon
// ══════════════════════════════════════════════════════════════

function ControlStatusIcon({ status, className }: { status: Control["status"]; className?: string }) {
  if (status === "compliant") return <CheckCircle2 className={cn("text-green-400", className)} />;
  if (status === "non-compliant") return <XCircle className={cn("text-red-400", className)} />;
  if (status === "partial") return <AlertCircle className={cn("text-yellow-400", className)} />;
  return <Clock className={cn("text-muted-foreground", className)} />;
}

// ══════════════════════════════════════════════════════════════
// Evidence Status Badge
// ══════════════════════════════════════════════════════════════

function EvidenceStatusBadge({ status }: { status: EvidenceItem["status"] }) {
  const configs = {
    collected:   { label: "Collected",   variant: "default"     as const },
    "in-progress": { label: "In Progress", variant: "secondary"   as const },
    pending:     { label: "Pending",     variant: "outline"     as const },
    overdue:     { label: "Overdue",     variant: "destructive" as const },
  };
  const { label, variant } = configs[status];
  return <Badge variant={variant} className="text-xs whitespace-nowrap">{label}</Badge>;
}

// ══════════════════════════════════════════════════════════════
// Priority Badge
// ══════════════════════════════════════════════════════════════

function PriorityBadge({ priority }: { priority: EvidenceItem["priority"] }) {
  const colors = {
    critical: "text-red-400 border-red-800/50",
    high:     "text-orange-400 border-orange-800/50",
    medium:   "text-yellow-400 border-yellow-800/50",
    low:      "text-blue-400 border-blue-800/50",
  };
  return (
    <Badge variant="outline" className={cn("text-xs capitalize border", colors[priority])}>
      {priority}
    </Badge>
  );
}

// ══════════════════════════════════════════════════════════════
// Evidence Collection Section
// ══════════════════════════════════════════════════════════════

function EvidenceSection({
  frameworks,
  items,
}: {
  frameworks: Framework[];
  items: EvidenceItem[];
}) {
  const pendingItems = useMemo(
    () => items
      .filter((i) => i.status !== "collected")
      .sort((a, b) => {
        const priorityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
        return priorityOrder[a.priority] - priorityOrder[b.priority];
      }),
    [items]
  );

  const overdueCount = items.filter((i) => i.status === "overdue").length;
  const dueThisWeek = items.filter((i) => {
    const due = new Date(i.dueDate);
    const now = new Date("2026-04-12");
    const diff = (due.getTime() - now.getTime()) / (1000 * 60 * 60 * 24);
    return diff >= 0 && diff <= 7 && i.status !== "collected";
  }).length;

  return (
    <div className="space-y-5">
      {/* Evidence progress bars per framework */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-base flex items-center gap-2">
            <FileCheck2 className="h-4 w-4 text-primary" />
            Evidence Collection Progress
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {frameworks.map((fw) => {
            const pct = fw.evidenceRequired > 0
              ? Math.round((fw.evidenceCollected / fw.evidenceRequired) * 100)
              : 100;
            const color = FRAMEWORK_COLORS[fw.shortName] ?? "hsl(var(--primary))";
            return (
              <div key={fw.id} className="space-y-1.5">
                <div className="flex items-center justify-between text-xs">
                  <div className="flex items-center gap-2">
                    <div
                      className="h-2 w-2 rounded-full shrink-0"
                      style={{ background: color }}
                    />
                    <span className="font-medium">{fw.name}</span>
                  </div>
                  <div className="flex items-center gap-3 text-muted-foreground">
                    <span>{fw.evidenceCollected}/{fw.evidenceRequired} items</span>
                    <span
                      className={cn(
                        "font-semibold",
                        pct >= 90 ? "text-green-400" : pct >= 70 ? "text-yellow-400" : "text-red-400"
                      )}
                    >
                      {pct}%
                    </span>
                  </div>
                </div>
                <div className="h-2 rounded-full overflow-hidden bg-muted">
                  <motion.div
                    className="h-full rounded-full"
                    style={{ background: color }}
                    initial={{ width: 0 }}
                    animate={{ width: `${pct}%` }}
                    transition={{ duration: 0.8, ease: [0.16, 1, 0.3, 1] }}
                  />
                </div>
              </div>
            );
          })}
        </CardContent>
      </Card>

      {/* Pending evidence items */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between flex-wrap gap-3">
            <div className="flex items-center gap-2">
              <CardTitle className="text-base flex items-center gap-2">
                <Clock className="h-4 w-4 text-orange-400" />
                Pending Evidence Items
              </CardTitle>
              {overdueCount > 0 && (
                <Badge variant="destructive" className="text-xs">{overdueCount} overdue</Badge>
              )}
              {dueThisWeek > 0 && (
                <Badge variant="secondary" className="text-xs">{dueThisWeek} due this week</Badge>
              )}
            </div>
            <div className="flex items-center gap-2">
              <Button variant="outline" size="sm" className="gap-1.5 text-xs h-7">
                <Upload className="h-3.5 w-3.5" />
                Upload Evidence
              </Button>
              <Button variant="outline" size="sm" className="gap-1.5 text-xs h-7">
                <Plus className="h-3.5 w-3.5" />
                Request Evidence
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent border-b border-border/40">
                  <TableHead className="text-xs pl-4">Framework</TableHead>
                  <TableHead className="text-xs">Control</TableHead>
                  <TableHead className="text-xs">Evidence Item</TableHead>
                  <TableHead className="text-xs">Due Date</TableHead>
                  <TableHead className="text-xs">Priority</TableHead>
                  <TableHead className="text-xs">Assignee</TableHead>
                  <TableHead className="text-xs">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {pendingItems.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={7} className="text-center py-10 text-muted-foreground text-sm">
                      All evidence items collected
                    </TableCell>
                  </TableRow>
                ) : (
                  pendingItems.map((item) => {
                    const isOverdue = item.status === "overdue";
                    const dueDate = new Date(item.dueDate);
                    const now = new Date("2026-04-12");
                    const daysUntil = Math.round((dueDate.getTime() - now.getTime()) / (1000 * 60 * 60 * 24));
                    return (
                      <TableRow
                        key={item.id}
                        className={cn(
                          "hover:bg-muted/20",
                          isOverdue && "bg-red-950/10"
                        )}
                      >
                        <TableCell className="pl-4">
                          <Badge
                            variant="outline"
                            className="text-xs"
                            style={{ borderColor: `${FRAMEWORK_COLORS[item.framework]}40`, color: FRAMEWORK_COLORS[item.framework] }}
                          >
                            {item.framework}
                          </Badge>
                        </TableCell>
                        <TableCell className="font-mono text-xs text-muted-foreground">{item.controlId}</TableCell>
                        <TableCell className="text-sm max-w-52 truncate">{item.title}</TableCell>
                        <TableCell className="text-xs">
                          <span className={cn(
                            "flex items-center gap-1",
                            isOverdue ? "text-red-400" : daysUntil <= 7 ? "text-yellow-400" : "text-muted-foreground"
                          )}>
                            <Calendar className="h-3 w-3" />
                            {isOverdue ? `${Math.abs(daysUntil)}d overdue` : daysUntil === 0 ? "Due today" : `${daysUntil}d`}
                          </span>
                        </TableCell>
                        <TableCell><PriorityBadge priority={item.priority} /></TableCell>
                        <TableCell className="text-xs text-muted-foreground">{item.assignee}</TableCell>
                        <TableCell><EvidenceStatusBadge status={item.status} /></TableCell>
                      </TableRow>
                    );
                  })
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

// ══════════════════════════════════════════════════════════════
// Control Mapping Table — filterable
// ══════════════════════════════════════════════════════════════

const STATUS_OPTIONS = [
  { value: "all", label: "All Statuses" },
  { value: "compliant", label: "Compliant" },
  { value: "partial", label: "Partial" },
  { value: "non-compliant", label: "Non-Compliant" },
  { value: "not-assessed", label: "Not Assessed" },
];

function ControlMappingTable({ controls }: { controls: Control[] }) {
  const [frameworkFilter, setFrameworkFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");

  const uniqueFrameworks = useMemo(
    () => ["all", ...Array.from(new Set(controls.map((c) => c.framework)))],
    [controls]
  );

  const filtered = useMemo(
    () => controls.filter((c) => {
      const fwOk = frameworkFilter === "all" || c.framework === frameworkFilter;
      const stOk = statusFilter === "all" || c.status === statusFilter;
      return fwOk && stOk;
    }),
    [controls, frameworkFilter, statusFilter]
  );

  const statusLabel: Record<Control["status"], string> = {
    compliant: "Compliant",
    "non-compliant": "Non-Compliant",
    partial: "Partial",
    "not-assessed": "Not Assessed",
  };

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between flex-wrap gap-3">
          <CardTitle className="text-base flex items-center gap-2">
            <BarChart3 className="h-4 w-4 text-primary" />
            Control Mapping
          </CardTitle>
          <div className="flex items-center gap-2">
            <Filter className="h-3.5 w-3.5 text-muted-foreground" />
            <Select value={frameworkFilter} onValueChange={setFrameworkFilter}>
              <SelectTrigger className="h-7 text-xs w-32">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all" className="text-xs">All Frameworks</SelectItem>
                {uniqueFrameworks.filter((f) => f !== "all").map((f) => (
                  <SelectItem key={f} value={f} className="text-xs">{f}</SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="h-7 text-xs w-36">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {STATUS_OPTIONS.map(({ value, label }) => (
                  <SelectItem key={value} value={value} className="text-xs">{label}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </div>
      </CardHeader>
      <CardContent className="p-0">
        <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent border-b border-border/40">
                <TableHead className="text-xs pl-4 w-32">Control ID</TableHead>
                <TableHead className="text-xs">Framework</TableHead>
                <TableHead className="text-xs">Description</TableHead>
                <TableHead className="text-xs w-28">Status</TableHead>
                <TableHead className="text-xs w-20 text-right">Evidence</TableHead>
                <TableHead className="text-xs w-20 text-right">Findings</TableHead>
                <TableHead className="text-xs w-28">Last Reviewed</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={7} className="text-center py-10 text-muted-foreground text-sm">
                    No controls match the current filters
                  </TableCell>
                </TableRow>
              ) : (
                filtered.map((ctrl) => (
                  <TableRow key={ctrl.id} className="hover:bg-muted/20 group">
                    <TableCell className="pl-4 font-mono text-xs text-primary">{ctrl.controlId}</TableCell>
                    <TableCell>
                      <Badge
                        variant="outline"
                        className="text-xs"
                        style={{
                          borderColor: `${FRAMEWORK_COLORS[ctrl.framework] ?? "hsl(var(--border))"}40`,
                          color: FRAMEWORK_COLORS[ctrl.framework],
                        }}
                      >
                        {ctrl.framework}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-sm max-w-xs">
                      <span className="line-clamp-2">{ctrl.description}</span>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-1.5">
                        <ControlStatusIcon status={ctrl.status} className="h-3.5 w-3.5" />
                        <span className={cn(
                          "text-xs",
                          ctrl.status === "compliant" && "text-green-400",
                          ctrl.status === "non-compliant" && "text-red-400",
                          ctrl.status === "partial" && "text-yellow-400",
                          ctrl.status === "not-assessed" && "text-muted-foreground",
                        )}>
                          {statusLabel[ctrl.status]}
                        </span>
                      </div>
                    </TableCell>
                    <TableCell className="text-right">
                      <span className="text-xs text-muted-foreground tabular-nums">
                        {ctrl.evidenceCount > 0
                          ? <span className="text-blue-400 font-medium">{ctrl.evidenceCount}</span>
                          : <span className="text-muted-foreground/40">—</span>
                        }
                      </span>
                    </TableCell>
                    <TableCell className="text-right">
                      <span className="text-xs tabular-nums">
                        {ctrl.findingsCount > 0
                          ? <span className="text-red-400 font-medium">{ctrl.findingsCount}</span>
                          : <span className="text-muted-foreground/40">—</span>
                        }
                      </span>
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">{ctrl.lastReviewed}</TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </div>
        <div className="px-4 py-2 border-t border-border/40 text-xs text-muted-foreground">
          Showing {filtered.length} of {controls.length} controls
        </div>
      </CardContent>
    </Card>
  );
}

// ══════════════════════════════════════════════════════════════
// Compliance Trend Chart — 12 months, one line per framework
// ══════════════════════════════════════════════════════════════

function TrendChart({ data }: { data: TrendPoint[] }) {
  const frameworks: (keyof Omit<TrendPoint, "month">)[] = [
    "SOC2", "PCI-DSS", "HIPAA", "ISO27001", "NIST-CSF", "CIS", "GDPR"
  ];

  return (
    <Card>
      <CardHeader className="pb-3">
        <CardTitle className="text-base flex items-center gap-2">
          <TrendingUp className="h-4 w-4 text-primary" />
          Compliance Score Trends — Last 12 Months
        </CardTitle>
      </CardHeader>
      <CardContent>
        <div className="h-[280px]">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={data} margin={{ top: 5, right: 16, left: -10, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" vertical={false} />
              <XAxis
                dataKey="month"
                tick={{ fontSize: 11, fill: "hsl(var(--muted-foreground))" }}
                axisLine={false}
                tickLine={false}
              />
              <YAxis
                domain={[50, 100]}
                tick={{ fontSize: 11, fill: "hsl(var(--muted-foreground))" }}
                axisLine={false}
                tickLine={false}
                tickFormatter={(v) => `${v}%`}
              />
              <Tooltip
                contentStyle={CHART_TOOLTIP_STYLE}
                formatter={(value: number, name: string) => [`${value}%`, name]}
              />
              <Legend
                wrapperStyle={{ fontSize: 11, paddingTop: 12 }}
                formatter={(value) => (
                  <span style={{ color: "hsl(var(--muted-foreground))" }}>{value}</span>
                )}
              />
              {frameworks.map((fw) => (
                <Line
                  key={fw}
                  type="monotone"
                  dataKey={fw}
                  stroke={FRAMEWORK_COLORS[fw]}
                  strokeWidth={2}
                  dot={false}
                  activeDot={{ r: 4, strokeWidth: 0 }}
                />
              ))}
            </LineChart>
          </ResponsiveContainer>
        </div>
      </CardContent>
    </Card>
  );
}

// ══════════════════════════════════════════════════════════════
// Main Component
// ══════════════════════════════════════════════════════════════

export default function ComplianceDashboard() {
  const navigate = useNavigate();
  const [expandedFramework, setExpandedFramework] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<"overview" | "evidence" | "controls" | "trends">("overview");

  // API hooks with graceful fallback
  const statusQuery = useComplianceStatus();
  const frameworksQuery = useComplianceFrameworks();
  const gapsQuery = useComplianceGaps();
  const assess = useAssessCompliance();

  const refetchAll = useCallback(() => {
    statusQuery.refetch();
    frameworksQuery.refetch();
    gapsQuery.refetch();
  }, [statusQuery, frameworksQuery, gapsQuery]);

  const isLoading = statusQuery.isLoading && frameworksQuery.isLoading;

  if (isLoading) return <PageSkeleton />;

  // Use API data where available, fall back to mock
  const rawFrameworks = toArray(frameworksQuery.data);
  const frameworks: Framework[] = rawFrameworks.length > 0
    ? rawFrameworks.map((f: any) => ({
        id: f.id ?? f.name,
        name: f.name ?? f.framework ?? "Unknown",
        shortName: (f.short_name ?? f.name ?? "").toUpperCase(),
        score: f.score ?? 0,
        controlsPassed: f.controls_passed ?? f.automated_controls ?? 0,
        totalControls: f.total_controls ?? f.controls ?? 0,
        status: f.status ?? "not-assessed",
        lastAudit: f.last_audit ?? "—",
        nextAudit: f.next_audit ?? "—",
        evidenceCollected: f.evidence_collected ?? 0,
        evidenceRequired: f.evidence_required ?? 0,
      }))
    : MOCK_FRAMEWORKS;

  const controls: Control[] = MOCK_CONTROLS; // Controls always from mock (not in API yet)
  const evidenceItems: EvidenceItem[] = MOCK_EVIDENCE_ITEMS;
  const trendData: TrendPoint[] = generateMockTrend();

  // Computed KPIs
  const compliantCount = frameworks.filter((f) => f.status === "compliant").length;
  const partialCount = frameworks.filter((f) => f.status === "partial" || f.status === "non-compliant").length;
  const overallScore = Math.round(frameworks.reduce((sum, f) => sum + f.score, 0) / frameworks.length);
  const totalControls = frameworks.reduce((sum, f) => sum + f.totalControls, 0);
  const passedControls = frameworks.reduce((sum, f) => sum + f.controlsPassed, 0);
  const overdueEvidence = evidenceItems.filter((i) => i.status === "overdue").length;

  const lastScan = new Date("2026-04-12T08:00:00").toLocaleString("en-US", {
    month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
  });

  const handleExport = () => {
    const exportData = {
      exported_at: new Date().toISOString(),
      overall_score: overallScore,
      frameworks,
      controls,
      evidence_items: evidenceItems,
    };
    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `compliance-report-${new Date().toISOString().slice(0, 10)}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      {/* Header */}
      <PageHeader
        title="Compliance & Governance"
        description={`P07 · Compliance Officer view · Last assessed ${lastScan}`}
        badge="P07"
      >
        <Button variant="outline" size="sm" className="gap-1.5" onClick={handleExport}>
          <Download className="h-3.5 w-3.5" />
          Export Report
        </Button>
        <Button variant="outline" size="sm" className="gap-1.5" onClick={refetchAll}>
          <RefreshCw className="h-3.5 w-3.5" />
          Refresh
        </Button>
        <Button
          size="sm"
          className="gap-1.5"
          onClick={() => assess.mutate(undefined)}
          disabled={assess.isPending}
        >
          <ShieldCheck className="h-3.5 w-3.5" />
          {assess.isPending ? "Assessing…" : "Assess All"}
        </Button>
      </PageHeader>

      {/* KPI Row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard
          title="Overall Score"
          value={`${overallScore}%`}
          icon={TrendingUp}         trend={overallScore >= 80 ? "up" : "down"}
          trendLabel={overallScore >= 80 ? "Above target" : "Below 80% target"}
        />
        <KpiCard
          title="Fully Compliant"
          value={`${compliantCount}/${frameworks.length}`}
          icon={CheckCircle2}         trend={compliantCount >= frameworks.length * 0.7 ? "up" : "down"}
          trendLabel="Frameworks"
        />
        <KpiCard
          title="Controls Passed"
          value={`${passedControls}/${totalControls}`}
          icon={FileCheck2}         trend="up"
          trendLabel={`${Math.round((passedControls / totalControls) * 100)}% pass rate`}
        />
        <KpiCard
          title="Evidence Overdue"
          value={overdueEvidence}
          icon={AlertTriangle}         trend={overdueEvidence === 0 ? "up" : "down"}
          trendLabel={overdueEvidence === 0 ? "All current" : "Action required"}
        />
      </div>

      {/* Tab Navigation */}
      <Tabs value={activeTab} onValueChange={(v) => setActiveTab(v as typeof activeTab)}>
        <TabsList className="h-9">
          <TabsTrigger value="overview" className="text-xs px-4">
            <Eye className="h-3.5 w-3.5 mr-1.5" />
            Framework Overview
          </TabsTrigger>
          <TabsTrigger value="evidence" className="text-xs px-4">
            <FileText className="h-3.5 w-3.5 mr-1.5" />
            Evidence Collection
            {overdueEvidence > 0 && (
              <span className="ml-1.5 bg-destructive text-destructive-foreground text-[10px] px-1.5 rounded-full">
                {overdueEvidence}
              </span>
            )}
          </TabsTrigger>
          <TabsTrigger value="controls" className="text-xs px-4">
            <BarChart3 className="h-3.5 w-3.5 mr-1.5" />
            Control Mapping
          </TabsTrigger>
          <TabsTrigger value="trends" className="text-xs px-4">
            <TrendingUp className="h-3.5 w-3.5 mr-1.5" />
            Trends
          </TabsTrigger>
        </TabsList>
      </Tabs>

      {/* Framework Overview */}
      {activeTab === "overview" && (
        <motion.div
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.2 }}
          className="space-y-4"
        >
          {/* Score summary bar */}
          <Card className="p-4">
            <div className="flex items-center gap-6 flex-wrap">
              {frameworks.map((fw) => (
                <div key={fw.id} className="flex items-center gap-2">
                  <div
                    className="h-2.5 w-2.5 rounded-full shrink-0"
                    style={{ background: FRAMEWORK_COLORS[fw.shortName] }}
                  />
                  <span className="text-xs text-muted-foreground">{fw.shortName}</span>
                  <span
                    className={cn(
                      "text-xs font-bold",
                      fw.score >= 90 ? "text-green-400" : fw.score >= 70 ? "text-yellow-400" : "text-red-400"
                    )}
                  >
                    {fw.score}%
                  </span>
                </div>
              ))}
            </div>
          </Card>

          {/* Framework cards grid */}
          <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-3 gap-4">
            {frameworks.map((fw) => (
              <FrameworkCard
                key={fw.id}
                fw={fw}
                controls={controls}
                isExpanded={expandedFramework === fw.id}
                onToggle={() => setExpandedFramework(expandedFramework === fw.id ? null : fw.id)}
              />
            ))}
          </div>

          {/* Control coverage overview */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm flex items-center gap-2">
                <Eye className="h-4 w-4 text-blue-400" />
                Control Coverage by Framework
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {frameworks.map((fw) => {
                const failed = fw.totalControls - fw.controlsPassed;
                const failedPct = (failed / fw.totalControls) * 100;
                const passedPct = (fw.controlsPassed / fw.totalControls) * 100;
                return (
                  <div key={fw.id} className="space-y-1">
                    <div className="flex items-center justify-between text-xs">
                      <span className="font-medium">{fw.name}</span>
                      <div className="flex items-center gap-3 text-muted-foreground">
                        <span className="text-green-400">{fw.controlsPassed} passed</span>
                        <span className="text-red-400">{failed} failed</span>
                      </div>
                    </div>
                    <div className="flex h-2 rounded-full overflow-hidden bg-muted">
                      <div className="bg-green-500 transition-all duration-700" style={{ width: `${passedPct}%` }} />
                      <div className="bg-red-500/60 transition-all duration-700" style={{ width: `${failedPct}%` }} />
                    </div>
                  </div>
                );
              })}
              <div className="flex items-center gap-4 pt-1 text-xs text-muted-foreground">
                <div className="flex items-center gap-1.5"><div className="h-2.5 w-2.5 rounded-sm bg-green-500" /> Passed</div>
                <div className="flex items-center gap-1.5"><div className="h-2.5 w-2.5 rounded-sm bg-red-500/60" /> Failed</div>
              </div>
            </CardContent>
          </Card>
        </motion.div>
      )}

      {/* Evidence Collection */}
      {activeTab === "evidence" && (
        <motion.div
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.2 }}
        >
          <EvidenceSection frameworks={frameworks} items={evidenceItems} />
        </motion.div>
      )}

      {/* Control Mapping */}
      {activeTab === "controls" && (
        <motion.div
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.2 }}
        >
          <ControlMappingTable controls={controls} />
        </motion.div>
      )}

      {/* Trends */}
      {activeTab === "trends" && (
        <motion.div
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.2 }}
        >
          <TrendChart data={trendData} />
        </motion.div>
      )}
    </motion.div>
  );
}
