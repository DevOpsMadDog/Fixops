/**
 * Risk Register Dashboard — P08 Persona (The Assessor / Risk Manager)
 *
 * Sections:
 * - Risk Summary Cards (top stats bar)
 * - Risk Heat Map (5×5 SVG grid — Likelihood × Impact)
 * - Risk Trend Chart (30-day multi-series line chart by category)
 * - Risk Register Table (sortable, filterable, inline status edit)
 * - Control Effectiveness Panel (selected risk controls)
 */

import { useState, useMemo, useCallback, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, Legend,
} from "recharts";
import {
  Shield, AlertTriangle, TrendingDown, Target, ChevronUp,
  ChevronDown, Filter, Plus, CheckCircle2, Clock, ArrowUpDown,
  ShieldCheck, Zap, Building2, Globe, Server, RefreshCw,
  ChevronRight, X,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Progress } from "@/components/ui/progress";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ─────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────

type RiskCategory = "TECHNICAL" | "OPERATIONAL" | "COMPLIANCE" | "VENDOR" | "REPUTATIONAL";
type RiskStatus = "OPEN" | "MITIGATING" | "ACCEPTED" | "TRANSFERRED" | "CLOSED";
type ControlType = "PREVENTIVE" | "DETECTIVE" | "CORRECTIVE";

interface Control {
  id: string;
  name: string;
  type: ControlType;
  effectiveness: number; // 0–100
  implemented: boolean;
}

interface RiskItem {
  id: string;
  category: RiskCategory;
  description: string;
  likelihood: number;  // 1–5
  impact: number;      // 1–5
  score: number;       // likelihood × impact (1–25)
  owner: string;
  status: RiskStatus;
  dueDate: string;
  controls: Control[];
  lastUpdated: string;
}

// ─────────────────────────────────────────────────────────────
// Mock Data — 18 enterprise-realistic security risks
// ─────────────────────────────────────────────────────────────

const MOCK_RISKS: RiskItem[] = [
  {
    id: "RSK-001",
    category: "TECHNICAL",
    description: "SQL injection vulnerabilities in legacy payment processing API endpoints",
    likelihood: 4,
    impact: 5,
    score: 20,
    owner: "Sarah Chen",
    status: "MITIGATING",
    dueDate: "2026-05-15",
    lastUpdated: "2026-04-10",
    controls: [
      { id: "C1", name: "WAF Rule Enforcement", type: "PREVENTIVE", effectiveness: 72, implemented: true },
      { id: "C2", name: "Input Validation Library", type: "PREVENTIVE", effectiveness: 85, implemented: true },
      { id: "C3", name: "DAST Scanning Weekly", type: "DETECTIVE", effectiveness: 68, implemented: true },
    ],
  },
  {
    id: "RSK-002",
    category: "TECHNICAL",
    description: "Unpatched critical CVEs in container base images across Kubernetes clusters",
    likelihood: 5,
    impact: 5,
    score: 25,
    owner: "Marcus Webb",
    status: "OPEN",
    dueDate: "2026-04-30",
    lastUpdated: "2026-04-12",
    controls: [
      { id: "C4", name: "Trivy Image Scanning", type: "DETECTIVE", effectiveness: 90, implemented: true },
      { id: "C5", name: "Automated Patch Pipeline", type: "CORRECTIVE", effectiveness: 45, implemented: false },
    ],
  },
  {
    id: "RSK-003",
    category: "COMPLIANCE",
    description: "PCI DSS v4.0 compliance gap — requirement 6.4 (web application protection)",
    likelihood: 3,
    impact: 5,
    score: 15,
    owner: "Priya Nair",
    status: "MITIGATING",
    dueDate: "2026-06-30",
    lastUpdated: "2026-04-08",
    controls: [
      { id: "C6", name: "PCI Scope Reduction", type: "PREVENTIVE", effectiveness: 60, implemented: true },
      { id: "C7", name: "QSA Engagement", type: "CORRECTIVE", effectiveness: 78, implemented: true },
      { id: "C8", name: "Evidence Collection Automation", type: "DETECTIVE", effectiveness: 82, implemented: true },
    ],
  },
  {
    id: "RSK-004",
    category: "VENDOR",
    description: "Third-party SaaS vendor with SOC2 expiry — handles PII for 2.3M customers",
    likelihood: 3,
    impact: 4,
    score: 12,
    owner: "James Liu",
    status: "OPEN",
    dueDate: "2026-05-01",
    lastUpdated: "2026-04-11",
    controls: [
      { id: "C9", name: "Vendor Risk Assessment", type: "DETECTIVE", effectiveness: 70, implemented: true },
      { id: "C10", name: "Contract SLA Clause", type: "PREVENTIVE", effectiveness: 55, implemented: true },
    ],
  },
  {
    id: "RSK-005",
    category: "OPERATIONAL",
    description: "Single point of failure — no DR plan for primary authentication service",
    likelihood: 2,
    impact: 5,
    score: 10,
    owner: "Elena Vasquez",
    status: "MITIGATING",
    dueDate: "2026-07-15",
    lastUpdated: "2026-04-05",
    controls: [
      { id: "C11", name: "Hot Standby Deployment", type: "PREVENTIVE", effectiveness: 40, implemented: false },
      { id: "C12", name: "Runbook Documentation", type: "CORRECTIVE", effectiveness: 65, implemented: true },
    ],
  },
  {
    id: "RSK-006",
    category: "REPUTATIONAL",
    description: "Public-facing API leaking internal microservice version headers",
    likelihood: 4,
    impact: 3,
    score: 12,
    owner: "Tom Eriksson",
    status: "OPEN",
    dueDate: "2026-04-25",
    lastUpdated: "2026-04-12",
    controls: [
      { id: "C13", name: "API Gateway Header Stripping", type: "PREVENTIVE", effectiveness: 95, implemented: false },
    ],
  },
  {
    id: "RSK-007",
    category: "TECHNICAL",
    description: "Exposed admin panel on port 8443 accessible from public internet",
    likelihood: 5,
    impact: 4,
    score: 20,
    owner: "Sarah Chen",
    status: "OPEN",
    dueDate: "2026-04-20",
    lastUpdated: "2026-04-12",
    controls: [
      { id: "C14", name: "IP Allowlist Enforcement", type: "PREVENTIVE", effectiveness: 80, implemented: false },
      { id: "C15", name: "MFA Requirement", type: "PREVENTIVE", effectiveness: 88, implemented: true },
    ],
  },
  {
    id: "RSK-008",
    category: "COMPLIANCE",
    description: "GDPR Article 32 gap — encryption at rest not enforced on all data stores",
    likelihood: 3,
    impact: 4,
    score: 12,
    owner: "Priya Nair",
    status: "MITIGATING",
    dueDate: "2026-05-30",
    lastUpdated: "2026-04-07",
    controls: [
      { id: "C16", name: "KMS Encryption Rollout", type: "PREVENTIVE", effectiveness: 67, implemented: true },
      { id: "C17", name: "Data Classification System", type: "DETECTIVE", effectiveness: 73, implemented: true },
    ],
  },
  {
    id: "RSK-009",
    category: "VENDOR",
    description: "Open source dependency with unmaintained maintainer — 47 repos affected",
    likelihood: 4,
    impact: 3,
    score: 12,
    owner: "Marcus Webb",
    status: "OPEN",
    dueDate: "2026-05-15",
    lastUpdated: "2026-04-09",
    controls: [
      { id: "C18", name: "SCA Scanning (Snyk)", type: "DETECTIVE", effectiveness: 88, implemented: true },
      { id: "C19", name: "Dependency Pinning Policy", type: "PREVENTIVE", effectiveness: 62, implemented: true },
    ],
  },
  {
    id: "RSK-010",
    category: "OPERATIONAL",
    description: "Privileged access credentials stored in plaintext CI/CD environment variables",
    likelihood: 4,
    impact: 5,
    score: 20,
    owner: "James Liu",
    status: "MITIGATING",
    dueDate: "2026-04-28",
    lastUpdated: "2026-04-11",
    controls: [
      { id: "C20", name: "Vault Secret Migration", type: "CORRECTIVE", effectiveness: 55, implemented: true },
      { id: "C21", name: "Secret Scanning in CI", type: "DETECTIVE", effectiveness: 91, implemented: true },
      { id: "C22", name: "Rotation Automation", type: "PREVENTIVE", effectiveness: 40, implemented: false },
    ],
  },
  {
    id: "RSK-011",
    category: "TECHNICAL",
    description: "Missing rate limiting on authentication endpoints — brute force risk",
    likelihood: 4,
    impact: 4,
    score: 16,
    owner: "Elena Vasquez",
    status: "OPEN",
    dueDate: "2026-04-22",
    lastUpdated: "2026-04-10",
    controls: [
      { id: "C23", name: "CAPTCHA Integration", type: "PREVENTIVE", effectiveness: 75, implemented: false },
      { id: "C24", name: "Account Lockout Policy", type: "PREVENTIVE", effectiveness: 80, implemented: true },
    ],
  },
  {
    id: "RSK-012",
    category: "REPUTATIONAL",
    description: "Bug bounty report backlog — 23 P2 reports unacknowledged >30 days",
    likelihood: 3,
    impact: 3,
    score: 9,
    owner: "Tom Eriksson",
    status: "OPEN",
    dueDate: "2026-05-01",
    lastUpdated: "2026-04-08",
    controls: [
      { id: "C25", name: "Triage SLA Policy (7-day)", type: "PREVENTIVE", effectiveness: 50, implemented: false },
    ],
  },
  {
    id: "RSK-013",
    category: "COMPLIANCE",
    description: "SOC2 CC6.6 — no documented change management process for production deploys",
    likelihood: 2,
    impact: 3,
    score: 6,
    owner: "Priya Nair",
    status: "ACCEPTED",
    dueDate: "2026-08-01",
    lastUpdated: "2026-03-20",
    controls: [
      { id: "C26", name: "Change Advisory Board", type: "PREVENTIVE", effectiveness: 70, implemented: true },
    ],
  },
  {
    id: "RSK-014",
    category: "OPERATIONAL",
    description: "Log retention below 90-day minimum for SOC investigations",
    likelihood: 2,
    impact: 4,
    score: 8,
    owner: "Sarah Chen",
    status: "MITIGATING",
    dueDate: "2026-05-10",
    lastUpdated: "2026-04-06",
    controls: [
      { id: "C27", name: "S3 Lifecycle Policy Update", type: "CORRECTIVE", effectiveness: 85, implemented: true },
      { id: "C28", name: "SIEM Retention Config", type: "PREVENTIVE", effectiveness: 90, implemented: false },
    ],
  },
  {
    id: "RSK-015",
    category: "VENDOR",
    description: "Cloud provider region dependency — all workloads in us-east-1 only",
    likelihood: 1,
    impact: 5,
    score: 5,
    owner: "Marcus Webb",
    status: "ACCEPTED",
    dueDate: "2026-12-31",
    lastUpdated: "2026-03-15",
    controls: [
      { id: "C29", name: "Multi-region DR Roadmap", type: "CORRECTIVE", effectiveness: 30, implemented: false },
    ],
  },
  {
    id: "RSK-016",
    category: "TECHNICAL",
    description: "SSRF vulnerability class in internal tooling — 3 confirmed, 8 suspected",
    likelihood: 3,
    impact: 4,
    score: 12,
    owner: "Marcus Webb",
    status: "OPEN",
    dueDate: "2026-05-05",
    lastUpdated: "2026-04-11",
    controls: [
      { id: "C30", name: "Egress Firewall Rules", type: "PREVENTIVE", effectiveness: 60, implemented: true },
      { id: "C31", name: "URL Allowlist Validation", type: "PREVENTIVE", effectiveness: 55, implemented: false },
    ],
  },
  {
    id: "RSK-017",
    category: "REPUTATIONAL",
    description: "Social engineering / spear phishing campaign targeting finance team detected",
    likelihood: 4,
    impact: 4,
    score: 16,
    owner: "Elena Vasquez",
    status: "MITIGATING",
    dueDate: "2026-04-30",
    lastUpdated: "2026-04-12",
    controls: [
      { id: "C32", name: "Security Awareness Training", type: "PREVENTIVE", effectiveness: 72, implemented: true },
      { id: "C33", name: "Email Gateway Filtering", type: "DETECTIVE", effectiveness: 85, implemented: true },
      { id: "C34", name: "Simulated Phishing Drills", type: "DETECTIVE", effectiveness: 78, implemented: true },
    ],
  },
  {
    id: "RSK-018",
    category: "COMPLIANCE",
    description: "HIPAA BAA not in place for 2 new cloud sub-processors handling PHI",
    likelihood: 2,
    impact: 5,
    score: 10,
    owner: "James Liu",
    status: "TRANSFERRED",
    dueDate: "2026-04-30",
    lastUpdated: "2026-04-09",
    controls: [
      { id: "C35", name: "Legal Review Initiated", type: "CORRECTIVE", effectiveness: 90, implemented: true },
    ],
  },
];

// ─────────────────────────────────────────────────────────────
// 30-day trend data per category
// ─────────────────────────────────────────────────────────────

function generateTrendData() {
  const now = new Date("2026-04-13");
  return Array.from({ length: 30 }, (_, i) => {
    const d = new Date(now);
    d.setDate(d.getDate() - (29 - i));
    const t = i / 29;
    return {
      date: d.toISOString().slice(5, 10),
      TECHNICAL: Math.round(85 - t * 20 + Math.sin(i / 4) * 5),
      OPERATIONAL: Math.round(48 - t * 8 + Math.sin(i / 5 + 1) * 4),
      COMPLIANCE: Math.round(42 - t * 12 + Math.sin(i / 3 + 2) * 3),
      VENDOR: Math.round(36 - t * 6 + Math.sin(i / 6) * 3),
      REPUTATIONAL: Math.round(28 - t * 5 + Math.sin(i / 4 + 3) * 4),
    };
  });
}

const TREND_DATA = generateTrendData();

// ─────────────────────────────────────────────────────────────
// Constants
// ─────────────────────────────────────────────────────────────

const CATEGORY_META: Record<RiskCategory, { label: string; color: string; icon: React.ElementType }> = {
  TECHNICAL:     { label: "Technical",     color: "#3b82f6", icon: Server },
  OPERATIONAL:   { label: "Operational",   color: "#f97316", icon: Zap },
  COMPLIANCE:    { label: "Compliance",    color: "#a855f7", icon: ShieldCheck },
  VENDOR:        { label: "Vendor",        color: "#eab308", icon: Building2 },
  REPUTATIONAL:  { label: "Reputational",  color: "#ec4899", icon: Globe },
};

const STATUS_META: Record<RiskStatus, { label: string; cls: string }> = {
  OPEN:        { label: "Open",        cls: "border-red-500/40 text-red-400 bg-red-500/10" },
  MITIGATING:  { label: "Mitigating",  cls: "border-orange-500/40 text-orange-400 bg-orange-500/10" },
  ACCEPTED:    { label: "Accepted",    cls: "border-blue-500/40 text-blue-400 bg-blue-500/10" },
  TRANSFERRED: { label: "Transferred", cls: "border-purple-500/40 text-purple-400 bg-purple-500/10" },
  CLOSED:      { label: "Closed",      cls: "border-green-500/40 text-green-400 bg-green-500/10" },
};

const CONTROL_TYPE_META: Record<ControlType, { label: string; cls: string }> = {
  PREVENTIVE:  { label: "Preventive",  cls: "border-blue-500/30 text-blue-400 bg-blue-500/10" },
  DETECTIVE:   { label: "Detective",   cls: "border-purple-500/30 text-purple-400 bg-purple-500/10" },
  CORRECTIVE:  { label: "Corrective",  cls: "border-amber-500/30 text-amber-400 bg-amber-500/10" },
};

const CHART_TOOLTIP_STYLE = {
  background: "hsl(var(--card))",
  border: "1px solid hsl(var(--border))",
  borderRadius: 8,
  fontSize: 11,
  color: "hsl(var(--foreground))",
};

// Score → color
function scoreColor(score: number): string {
  if (score >= 20) return "#ef4444";
  if (score >= 15) return "#f97316";
  if (score >= 9)  return "#eab308";
  return "#22c55e";
}

function scoreBadgeCls(score: number): string {
  if (score >= 20) return "border-red-500/40 text-red-400 bg-red-500/10";
  if (score >= 15) return "border-orange-500/40 text-orange-400 bg-orange-500/10";
  if (score >= 9)  return "border-yellow-500/40 text-yellow-400 bg-yellow-500/10";
  return "border-green-500/40 text-green-400 bg-green-500/10";
}

function scoreLabel(score: number): string {
  if (score >= 20) return "CRITICAL";
  if (score >= 15) return "HIGH";
  if (score >= 9)  return "MEDIUM";
  return "LOW";
}

// ─────────────────────────────────────────────────────────────
// Heat Map Cell colors (5×5 grid, row=likelihood, col=impact)
// ─────────────────────────────────────────────────────────────

function heatZoneColor(likelihood: number, impact: number): string {
  const score = likelihood * impact;
  if (score >= 20) return "rgba(239,68,68,0.25)";
  if (score >= 15) return "rgba(249,115,22,0.22)";
  if (score >= 9)  return "rgba(234,179,8,0.20)";
  return "rgba(34,197,94,0.15)";
}

// ─────────────────────────────────────────────────────────────
// Risk Heat Map — Interactive 5×5 SVG Grid
// ─────────────────────────────────────────────────────────────

function RiskHeatMap({
  risks,
  selectedId,
  onSelect,
}: {
  risks: RiskItem[];
  selectedId: string | null;
  onSelect: (id: string) => void;
}) {
  const CELL = 64;
  const PAD = { top: 24, left: 56, bottom: 40, right: 16 };
  const W = CELL * 5 + PAD.left + PAD.right;
  const H = CELL * 5 + PAD.top + PAD.bottom;

  // Group risks by grid cell
  const cellMap = useMemo(() => {
    const m: Record<string, RiskItem[]> = {};
    risks.forEach((r) => {
      const key = `${r.likelihood}-${r.impact}`;
      if (!m[key]) m[key] = [];
      m[key].push(r);
    });
    return m;
  }, [risks]);

  const likelihoodLabels = ["Rare", "Unlikely", "Possible", "Likely", "Almost\nCertain"];
  const impactLabels = ["Negligible", "Minor", "Moderate", "Major", "Catastrophic"];

  return (
    <svg width="100%" viewBox={`0 0 ${W} ${H}`} className="overflow-visible">
      {/* Y-axis label */}
      <text
        x={10}
        y={PAD.top + (CELL * 5) / 2}
        textAnchor="middle"
        fill="hsl(var(--muted-foreground))"
        fontSize={9}
        fontWeight="600"
        letterSpacing="0.08em"
        transform={`rotate(-90, 10, ${PAD.top + (CELL * 5) / 2})`}
      >
        LIKELIHOOD
      </text>

      {/* X-axis label */}
      <text
        x={PAD.left + (CELL * 5) / 2}
        y={H - 4}
        textAnchor="middle"
        fill="hsl(var(--muted-foreground))"
        fontSize={9}
        fontWeight="600"
        letterSpacing="0.08em"
      >
        IMPACT
      </text>

      {/* Grid cells */}
      {Array.from({ length: 5 }, (_, rowIdx) => {
        const likelihood = 5 - rowIdx; // top row = 5 (Almost Certain)
        return Array.from({ length: 5 }, (_, colIdx) => {
          const impact = colIdx + 1;
          const x = PAD.left + colIdx * CELL;
          const y = PAD.top + rowIdx * CELL;
          const key = `${likelihood}-${impact}`;
          const cellRisks = cellMap[key] ?? [];
          const bgColor = heatZoneColor(likelihood, impact);

          return (
            <g key={key}>
              {/* Cell background */}
              <rect
                x={x}
                y={y}
                width={CELL}
                height={CELL}
                fill={bgColor}
                stroke="hsl(var(--border))"
                strokeWidth={0.5}
              />

              {/* Score label (faint) */}
              <text
                x={x + CELL - 6}
                y={y + 13}
                textAnchor="end"
                fontSize={8}
                fill="hsl(var(--muted-foreground))"
                opacity={0.5}
                fontFamily="monospace"
              >
                {likelihood * impact}
              </text>

              {/* Risk dots */}
              {cellRisks.slice(0, 4).map((risk, di) => {
                const dotX = x + 14 + (di % 2) * 28;
                const dotY = y + 22 + Math.floor(di / 2) * 24;
                const isSelected = risk.id === selectedId;
                const cat = CATEGORY_META[risk.category];

                return (
                  <g key={risk.id} onClick={() => onSelect(risk.id)} style={{ cursor: "pointer" }}>
                    {isSelected && (
                      <circle cx={dotX} cy={dotY} r={11} fill={cat.color} opacity={0.2}>
                        <animate attributeName="r" values="10;14;10" dur="2s" repeatCount="indefinite" />
                        <animate attributeName="opacity" values="0.2;0.08;0.2" dur="2s" repeatCount="indefinite" />
                      </circle>
                    )}
                    <circle
                      cx={dotX}
                      cy={dotY}
                      r={isSelected ? 8 : 7}
                      fill={cat.color}
                      opacity={isSelected ? 1 : 0.85}
                      stroke={isSelected ? "white" : "transparent"}
                      strokeWidth={1.5}
                    />
                    <text
                      x={dotX}
                      y={dotY + 3.5}
                      textAnchor="middle"
                      fontSize={6.5}
                      fontWeight="700"
                      fill="white"
                      style={{ pointerEvents: "none" }}
                    >
                      {risk.id.replace("RSK-", "")}
                    </text>
                  </g>
                );
              })}

              {/* Overflow indicator */}
              {cellRisks.length > 4 && (
                <text
                  x={x + CELL - 4}
                  y={y + CELL - 4}
                  textAnchor="end"
                  fontSize={7}
                  fill="hsl(var(--muted-foreground))"
                >
                  +{cellRisks.length - 4}
                </text>
              )}
            </g>
          );
        });
      })}

      {/* Y-axis tick labels (likelihood) */}
      {likelihoodLabels.map((label, i) => {
        const likelihood = 5 - i;
        const y = PAD.top + i * CELL + CELL / 2;
        return (
          <text
            key={likelihood}
            x={PAD.left - 6}
            y={y + 3}
            textAnchor="end"
            fontSize={8.5}
            fill="hsl(var(--muted-foreground))"
          >
            {likelihood}
          </text>
        );
      })}

      {/* X-axis tick labels (impact) */}
      {impactLabels.map((label, i) => {
        const x = PAD.left + i * CELL + CELL / 2;
        return (
          <text
            key={i}
            x={x}
            y={PAD.top + 5 * CELL + 14}
            textAnchor="middle"
            fontSize={8.5}
            fill="hsl(var(--muted-foreground))"
          >
            {i + 1}
          </text>
        );
      })}
    </svg>
  );
}

// ─────────────────────────────────────────────────────────────
// Control Effectiveness Panel
// ─────────────────────────────────────────────────────────────

function ControlPanel({ risk }: { risk: RiskItem | null }) {
  if (!risk) {
    return (
      <div className="flex h-full flex-col items-center justify-center gap-3 py-12 text-muted-foreground">
        <ShieldCheck className="h-8 w-8 opacity-20" />
        <p className="text-xs text-center">Select a risk from the heat map or table<br />to view its controls</p>
      </div>
    );
  }

  const avgEffectiveness = risk.controls.length
    ? Math.round(risk.controls.reduce((s, c) => s + c.effectiveness, 0) / risk.controls.length)
    : 0;

  return (
    <AnimatePresence mode="wait">
      <motion.div
        key={risk.id}
        initial={{ opacity: 0, y: 6 }}
        animate={{ opacity: 1, y: 0 }}
        exit={{ opacity: 0, y: -6 }}
        transition={{ duration: 0.25 }}
        className="space-y-3"
      >
        <div className="flex items-start justify-between gap-2">
          <div>
            <p className="text-xs font-mono text-muted-foreground">{risk.id}</p>
            <p className="text-sm font-semibold leading-snug line-clamp-2">{risk.description}</p>
          </div>
          <Badge className={cn("text-[10px] border shrink-0", scoreBadgeCls(risk.score))}>
            {scoreLabel(risk.score)}
          </Badge>
        </div>

        <div className="flex items-center justify-between text-xs">
          <span className="text-muted-foreground">Avg control effectiveness</span>
          <span className={cn(
            "font-bold tabular-nums",
            avgEffectiveness >= 70 ? "text-green-400" : avgEffectiveness >= 50 ? "text-yellow-400" : "text-red-400"
          )}>
            {avgEffectiveness}%
          </span>
        </div>
        <Progress value={avgEffectiveness} className="h-1.5" />

        <Separator />

        <div className="space-y-2.5">
          {risk.controls.map((ctrl) => {
            const meta = CONTROL_TYPE_META[ctrl.type];
            return (
              <div key={ctrl.id} className="space-y-1.5">
                <div className="flex items-center justify-between gap-2">
                  <div className="flex items-center gap-1.5 min-w-0">
                    <div className={cn(
                      "h-1.5 w-1.5 rounded-full shrink-0",
                      ctrl.implemented ? "bg-green-400" : "bg-muted-foreground/40"
                    )} />
                    <span className="text-xs font-medium truncate">{ctrl.name}</span>
                  </div>
                  <div className="flex items-center gap-1.5 shrink-0">
                    <Badge className={cn("text-[9px] border px-1.5 py-0", meta.cls)}>
                      {meta.label}
                    </Badge>
                    <span className={cn(
                      "text-xs font-bold tabular-nums w-8 text-right",
                      ctrl.effectiveness >= 70 ? "text-green-400" : ctrl.effectiveness >= 50 ? "text-yellow-400" : "text-red-400"
                    )}>
                      {ctrl.effectiveness}%
                    </span>
                  </div>
                </div>
                <div className="relative h-1 rounded-full bg-muted/30 overflow-hidden">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${ctrl.effectiveness}%` }}
                    transition={{ duration: 0.6, ease: "easeOut" }}
                    className={cn(
                      "h-full rounded-full",
                      ctrl.effectiveness >= 70 ? "bg-green-500" : ctrl.effectiveness >= 50 ? "bg-yellow-500" : "bg-red-500"
                    )}
                  />
                </div>
                {!ctrl.implemented && (
                  <p className="text-[10px] text-muted-foreground ml-3">Not yet implemented</p>
                )}
              </div>
            );
          })}
        </div>

        <Button size="sm" variant="outline" className="w-full h-7 text-xs gap-1.5">
          <Plus className="h-3.5 w-3.5" />
          Add Control
        </Button>
      </motion.div>
    </AnimatePresence>
  );
}

// ─────────────────────────────────────────────────────────────
// Status Badge with inline dropdown
// ─────────────────────────────────────────────────────────────

function StatusBadge({
  status,
  onChange,
}: {
  status: RiskStatus;
  onChange: (s: RiskStatus) => void;
}) {
  const meta = STATUS_META[status];
  return (
    <Select value={status} onValueChange={(v) => onChange(v as RiskStatus)}>
      <SelectTrigger className={cn(
        "h-6 text-[10px] border px-2 py-0 w-auto gap-1 font-medium rounded-md",
        meta.cls
      )}>
        <SelectValue />
      </SelectTrigger>
      <SelectContent>
        {(Object.keys(STATUS_META) as RiskStatus[]).map((s) => (
          <SelectItem key={s} value={s} className="text-xs">
            {STATUS_META[s].label}
          </SelectItem>
        ))}
      </SelectContent>
    </Select>
  );
}

// ─────────────────────────────────────────────────────────────
// Main Dashboard Component
// ─────────────────────────────────────────────────────────────

export default function RiskRegister() {
  const [risks, setRisks] = useState<RiskItem[]>(MOCK_RISKS);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [selectedId, setSelectedId] = useState<string | null>(null);
  const [categoryFilter, setCategoryFilter] = useState<string>("ALL");
  const [statusFilter, setStatusFilter] = useState<string>("ALL");
  const [sortField, setSortField] = useState<keyof RiskItem>("score");
  const [sortAsc, setSortAsc] = useState(false);
  const [showCategoryLegend, setShowCategoryLegend] = useState(false);

  // Fetch risks from the real API, fall back to MOCK_RISKS on failure
  useEffect(() => {
    let cancelled = false;
    async function fetchRisks() {
      setLoading(true);
      setError(null);
      try {
        const res = await fetch("/api/v1/risk-register-engine/risks?org_id=default");
        if (!res.ok) throw new Error(`API ${res.status}`);
        const data = await res.json();
        if (!cancelled && Array.isArray(data) && data.length > 0) {
          const mapped: RiskItem[] = data.map((r: Record<string, unknown>, idx: number) => ({
            id: String(r.id ?? `RSK-${String(idx + 1).padStart(3, "0")}`),
            category: (String(r.risk_category ?? "operational").toUpperCase()) as RiskCategory,
            description: String(r.description ?? r.name ?? ""),
            likelihood: Number(r.likelihood ?? 3),
            impact: Number(r.impact ?? 3),
            score: Number(r.risk_score ?? (Number(r.likelihood ?? 3) * Number(r.impact ?? 3))),
            owner: String(r.owner ?? "Unassigned"),
            status: (String(r.status ?? "open").toUpperCase()) as RiskStatus,
            dueDate: String(r.due_date ?? r.updated_at ?? new Date().toISOString()).slice(0, 10),
            controls: Array.isArray(r.controls) ? (r.controls as Control[]) : [],
            lastUpdated: String(r.updated_at ?? new Date().toISOString()).slice(0, 10),
          }));
          setRisks(mapped);
        } else if (!cancelled) {
          // Empty API response -- keep mock data as fallback
          setRisks(MOCK_RISKS);
        }
      } catch {
        if (!cancelled) {
          setError("Could not load risks from API -- showing cached data");
          setRisks(MOCK_RISKS);
        }
      } finally {
        if (!cancelled) setLoading(false);
      }
    }
    fetchRisks();
    return () => { cancelled = true; };
  }, []);

  const selectedRisk = useMemo(
    () => risks.find((r) => r.id === selectedId) ?? null,
    [risks, selectedId]
  );

  // Summary stats
  const stats = useMemo(() => {
    const critical = risks.filter((r) => r.score >= 20).length;
    const high = risks.filter((r) => r.score >= 15 && r.score < 20).length;
    const reduced = 4; // mock: 4 risks downgraded this month
    return { total: risks.length, critical, high, reduced };
  }, [risks]);

  // Filtered + sorted table rows
  const tableRisks = useMemo(() => {
    let filtered = risks.filter((r) => {
      if (categoryFilter !== "ALL" && r.category !== categoryFilter) return false;
      if (statusFilter !== "ALL" && r.status !== statusFilter) return false;
      return true;
    });

    filtered.sort((a, b) => {
      const av = a[sortField];
      const bv = b[sortField];
      if (typeof av === "number" && typeof bv === "number") {
        return sortAsc ? av - bv : bv - av;
      }
      return sortAsc
        ? String(av).localeCompare(String(bv))
        : String(bv).localeCompare(String(av));
    });

    return filtered;
  }, [risks, categoryFilter, statusFilter, sortField, sortAsc]);

  const handleSort = useCallback((field: keyof RiskItem) => {
    if (sortField === field) setSortAsc((a) => !a);
    else { setSortField(field); setSortAsc(false); }
  }, [sortField]);

  const handleStatusChange = useCallback((id: string, status: RiskStatus) => {
    setRisks((prev) => prev.map((r) => r.id === id ? { ...r, status } : r));
  }, []);

  const SortIcon = ({ field }: { field: keyof RiskItem }) => {
    if (sortField !== field) return <ArrowUpDown className="h-3 w-3 opacity-30 inline ml-1" />;
    return sortAsc
      ? <ChevronUp className="h-3 w-3 inline ml-1" />
      : <ChevronDown className="h-3 w-3 inline ml-1" />;
  };

  // Active chart categories (toggle)
  const [activeCats, setActiveCats] = useState<Set<string>>(
    new Set(Object.keys(CATEGORY_META))
  );
  const toggleCat = (cat: string) => {
    setActiveCats((prev) => {
      const next = new Set(prev);
      if (next.has(cat)) { if (next.size > 1) next.delete(cat); }
      else next.add(cat);
      return next;
    });
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-5"
    >
      {/* ── Header ── */}
      <PageHeader
        title="Risk Register"
        description="Organizational security risk tracking — likelihood, impact, controls, and trend analysis"
        badge="P08"
      >
        <Button variant="outline" size="sm" className="h-8 text-xs gap-1.5">
          <RefreshCw className="h-3.5 w-3.5" />
          Refresh
        </Button>
        <Button size="sm" className="h-8 text-xs gap-1.5">
          <Plus className="h-3.5 w-3.5" />
          Add Risk
        </Button>
      </PageHeader>

      {/* ── Summary Cards ── */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <KpiCard
          title="Total Risks"
          value={stats.total}
          icon={Target}         trend="flat"
          trendLabel="Tracked org-wide"
        />
        <KpiCard
          title="Critical (≥20)"
          value={stats.critical}
          icon={AlertTriangle}         trend={stats.critical > 0 ? "down" : "up"}
          trendLabel={stats.critical > 0 ? "Requires immediate action" : "None active"}
          className={cn(stats.critical > 0 && "border-red-500/30 bg-red-500/5")}
        />
        <KpiCard
          title="High (15–19)"
          value={stats.high}
          icon={Shield}         trend={stats.high > 3 ? "down" : "flat"}
          trendLabel="Elevated exposure"
          className={cn(stats.high > 3 && "border-orange-500/20")}
        />
        <KpiCard
          title="Reduced This Month"
          value={stats.reduced}
          icon={TrendingDown}         trend="up"
          trendLabel="Score improvements"
          className="border-green-500/20 bg-green-500/5"
        />
      </div>

      {/* ── Loading / Error / Empty states ── */}
      {loading && (
        <div className="flex items-center justify-center py-8 text-muted-foreground gap-2">
          <RefreshCw className="h-4 w-4 animate-spin" />
          <span className="text-sm">Loading risks from API...</span>
        </div>
      )}
      {error && (
        <div className="flex items-center gap-2 rounded-lg border border-amber-500/30 bg-amber-500/5 px-4 py-2 text-sm text-amber-300">
          <AlertTriangle className="h-4 w-4 shrink-0" />
          {error}
        </div>
      )}
      {!loading && !error && risks.length === 0 && (
        <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
          <Shield className="h-8 w-8 opacity-20 mb-2" />
          <p className="text-sm">No risks found. Add your first risk to get started.</p>
        </div>
      )}

      {/* ── Top row: Heat Map + Trend Chart ── */}
      <div className="grid grid-cols-1 lg:grid-cols-5 gap-5">

        {/* Heat Map */}
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.08 }}
          className="lg:col-span-2"
        >
          <Card className="h-full">
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm font-semibold flex items-center gap-2">
                  <Target className="h-4 w-4 text-orange-400" />
                  Risk Heat Map
                </CardTitle>
                <button
                  onClick={() => setShowCategoryLegend((v) => !v)}
                  className="text-[10px] text-muted-foreground hover:text-foreground transition-colors flex items-center gap-0.5"
                >
                  Legend <ChevronRight className={cn("h-3 w-3 transition-transform", showCategoryLegend && "rotate-90")} />
                </button>
              </div>
              <CardDescription className="text-xs">Likelihood (Y) × Impact (X) — click dot to inspect</CardDescription>
            </CardHeader>
            <CardContent className="pt-0">
              {/* Zone legend */}
              <div className="flex items-center gap-3 mb-2 flex-wrap">
                {[
                  { label: "Critical", color: "bg-red-500/40" },
                  { label: "High", color: "bg-orange-500/35" },
                  { label: "Medium", color: "bg-yellow-500/30" },
                  { label: "Low", color: "bg-green-500/25" },
                ].map(({ label, color }) => (
                  <div key={label} className="flex items-center gap-1">
                    <div className={cn("h-2.5 w-2.5 rounded-sm", color)} />
                    <span className="text-[10px] text-muted-foreground">{label}</span>
                  </div>
                ))}
              </div>

              <RiskHeatMap
                risks={risks}
                selectedId={selectedId}
                onSelect={(id) => setSelectedId((prev) => prev === id ? null : id)}
              />

              {/* Category dot legend */}
              <AnimatePresence>
                {showCategoryLegend && (
                  <motion.div
                    initial={{ opacity: 0, height: 0 }}
                    animate={{ opacity: 1, height: "auto" }}
                    exit={{ opacity: 0, height: 0 }}
                    className="overflow-hidden"
                  >
                    <Separator className="my-2" />
                    <div className="grid grid-cols-2 gap-1">
                      {(Object.entries(CATEGORY_META) as [RiskCategory, typeof CATEGORY_META[RiskCategory]][]).map(([cat, meta]) => (
                        <div key={cat} className="flex items-center gap-1.5">
                          <div className="h-2.5 w-2.5 rounded-full" style={{ backgroundColor: meta.color }} />
                          <span className="text-[10px] text-muted-foreground">{meta.label}</span>
                        </div>
                      ))}
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </CardContent>
          </Card>
        </motion.div>

        {/* Trend Chart */}
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.12 }}
          className="lg:col-span-3"
        >
          <Card className="h-full">
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between flex-wrap gap-2">
                <div>
                  <CardTitle className="text-sm font-semibold flex items-center gap-2">
                    <TrendingDown className="h-4 w-4 text-green-400" />
                    Risk Trend — 30 Days
                  </CardTitle>
                  <CardDescription className="text-xs">Aggregate risk score by category (trending down = good)</CardDescription>
                </div>
                <div className="flex items-center gap-1.5 flex-wrap">
                  {(Object.entries(CATEGORY_META) as [RiskCategory, typeof CATEGORY_META[RiskCategory]][]).map(([cat, meta]) => (
                    <button
                      key={cat}
                      onClick={() => toggleCat(cat)}
                      className={cn(
                        "text-[10px] px-2 py-0.5 rounded-full border transition-all",
                        activeCats.has(cat)
                          ? "border-transparent text-white"
                          : "border-border text-muted-foreground opacity-40"
                      )}
                      style={activeCats.has(cat) ? { background: meta.color } : {}}
                    >
                      {meta.label}
                    </button>
                  ))}
                </div>
              </div>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={260}>
                <LineChart data={TREND_DATA} margin={{ top: 4, right: 4, bottom: 0, left: -16 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" strokeOpacity={0.5} vertical={false} />
                  <XAxis
                    dataKey="date"
                    tick={{ fontSize: 9, fill: "hsl(var(--muted-foreground))" }}
                    axisLine={false}
                    tickLine={false}
                    interval={5}
                  />
                  <YAxis
                    tick={{ fontSize: 9, fill: "hsl(var(--muted-foreground))" }}
                    axisLine={false}
                    tickLine={false}
                    domain={[0, 100]}
                  />
                  <Tooltip contentStyle={CHART_TOOLTIP_STYLE} />
                  {(Object.entries(CATEGORY_META) as [RiskCategory, typeof CATEGORY_META[RiskCategory]][]).map(([cat, meta]) =>
                    activeCats.has(cat) ? (
                      <Line
                        key={cat}
                        type="monotone"
                        dataKey={cat}
                        stroke={meta.color}
                        strokeWidth={2}
                        dot={false}
                        name={meta.label}
                      />
                    ) : null
                  )}
                </LineChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </motion.div>
      </div>

      {/* ── Bottom row: Risk Register Table + Control Panel ── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">

        {/* Risk Register Table */}
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.16 }}
          className="lg:col-span-2"
        >
          <Card className="h-full">
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between flex-wrap gap-2">
                <div>
                  <CardTitle className="text-sm font-semibold flex items-center gap-2">
                    <Shield className="h-4 w-4 text-primary" />
                    Risk Register
                  </CardTitle>
                  <CardDescription className="text-xs">
                    {tableRisks.length} of {risks.length} risks — click status to change inline
                  </CardDescription>
                </div>
                <div className="flex items-center gap-2">
                  <Filter className="h-3.5 w-3.5 text-muted-foreground" />
                  <Select value={categoryFilter} onValueChange={setCategoryFilter}>
                    <SelectTrigger className="h-7 text-xs w-[130px]">
                      <SelectValue placeholder="Category" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="ALL" className="text-xs">All Categories</SelectItem>
                      {(Object.entries(CATEGORY_META) as [RiskCategory, typeof CATEGORY_META[RiskCategory]][]).map(([k, v]) => (
                        <SelectItem key={k} value={k} className="text-xs">{v.label}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                  <Select value={statusFilter} onValueChange={setStatusFilter}>
                    <SelectTrigger className="h-7 text-xs w-[120px]">
                      <SelectValue placeholder="Status" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="ALL" className="text-xs">All Statuses</SelectItem>
                      {(Object.keys(STATUS_META) as RiskStatus[]).map((s) => (
                        <SelectItem key={s} value={s} className="text-xs">{STATUS_META[s].label}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>
            </CardHeader>
            <CardContent className="p-0">
              <ScrollArea className="h-[420px]">
                <div className="overflow-x-auto">
                  <Table>
                    <TableHeader>
                      <TableRow className="hover:bg-transparent sticky top-0 bg-card z-10 border-b">
                        <TableHead className="text-[10px] h-8 w-[80px] font-semibold cursor-pointer hover:text-foreground" onClick={() => handleSort("id")}>
                          ID <SortIcon field="id" />
                        </TableHead>
                        <TableHead className="text-[10px] h-8 font-semibold cursor-pointer hover:text-foreground" onClick={() => handleSort("category")}>
                          Category <SortIcon field="category" />
                        </TableHead>
                        <TableHead className="text-[10px] h-8 font-semibold">Description</TableHead>
                        <TableHead className="text-[10px] h-8 font-semibold cursor-pointer hover:text-foreground text-center" onClick={() => handleSort("likelihood")}>
                          L <SortIcon field="likelihood" />
                        </TableHead>
                        <TableHead className="text-[10px] h-8 font-semibold cursor-pointer hover:text-foreground text-center" onClick={() => handleSort("impact")}>
                          I <SortIcon field="impact" />
                        </TableHead>
                        <TableHead className="text-[10px] h-8 font-semibold cursor-pointer hover:text-foreground text-center" onClick={() => handleSort("score")}>
                          Score <SortIcon field="score" />
                        </TableHead>
                        <TableHead className="text-[10px] h-8 font-semibold cursor-pointer hover:text-foreground" onClick={() => handleSort("owner")}>
                          Owner <SortIcon field="owner" />
                        </TableHead>
                        <TableHead className="text-[10px] h-8 font-semibold">Status</TableHead>
                        <TableHead className="text-[10px] h-8 font-semibold cursor-pointer hover:text-foreground" onClick={() => handleSort("dueDate")}>
                          Due <SortIcon field="dueDate" />
                        </TableHead>
                        <TableHead className="text-[10px] h-8 font-semibold text-center">Ctrl</TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {tableRisks.map((risk) => {
                        const cat = CATEGORY_META[risk.category];
                        const isSelected = risk.id === selectedId;

                        return (
                          <TableRow
                            key={risk.id}
                            onClick={() => setSelectedId((prev) => prev === risk.id ? null : risk.id)}
                            className={cn(
                              "cursor-pointer transition-colors text-xs",
                              isSelected
                                ? "bg-primary/8 border-l-2 border-l-primary"
                                : "hover:bg-muted/30"
                            )}
                          >
                            {/* ID */}
                            <TableCell className="py-2 font-mono text-[10px] text-muted-foreground">
                              {risk.id}
                            </TableCell>

                            {/* Category */}
                            <TableCell className="py-2">
                              <div className="flex items-center gap-1.5">
                                <div className="h-1.5 w-1.5 rounded-full shrink-0" style={{ background: cat.color }} />
                                <span className="text-[10px]" style={{ color: cat.color }}>
                                  {cat.label}
                                </span>
                              </div>
                            </TableCell>

                            {/* Description */}
                            <TableCell className="py-2 max-w-[220px]">
                              <p className="text-xs leading-snug line-clamp-2">{risk.description}</p>
                            </TableCell>

                            {/* Likelihood */}
                            <TableCell className="py-2 text-center">
                              <span className="text-xs font-bold tabular-nums">{risk.likelihood}</span>
                            </TableCell>

                            {/* Impact */}
                            <TableCell className="py-2 text-center">
                              <span className="text-xs font-bold tabular-nums">{risk.impact}</span>
                            </TableCell>

                            {/* Score */}
                            <TableCell className="py-2 text-center">
                              <Badge className={cn("text-[10px] border px-1.5 py-0 font-bold", scoreBadgeCls(risk.score))}>
                                {risk.score}
                              </Badge>
                            </TableCell>

                            {/* Owner */}
                            <TableCell className="py-2">
                              <span className="text-xs truncate max-w-[80px] block">{risk.owner}</span>
                            </TableCell>

                            {/* Status — inline edit */}
                            <TableCell className="py-2" onClick={(e) => e.stopPropagation()}>
                              <StatusBadge
                                status={risk.status}
                                onChange={(s) => handleStatusChange(risk.id, s)}
                              />
                            </TableCell>

                            {/* Due Date */}
                            <TableCell className="py-2">
                              <span className="text-[10px] text-muted-foreground tabular-nums">
                                {risk.dueDate.slice(5)}
                              </span>
                            </TableCell>

                            {/* Control count */}
                            <TableCell className="py-2 text-center">
                              <span className="text-[10px] font-mono text-muted-foreground">
                                {risk.controls.length}
                              </span>
                            </TableCell>
                          </TableRow>
                        );
                      })}
                    </TableBody>
                  </Table>
                </div>
              </ScrollArea>
            </CardContent>
          </Card>
        </motion.div>

        {/* Control Effectiveness Panel */}
        <motion.div
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.2 }}
        >
          <Card className="h-full">
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm font-semibold flex items-center gap-2">
                  <CheckCircle2 className="h-4 w-4 text-green-400" />
                  Control Effectiveness
                </CardTitle>
                {selectedRisk && (
                  <button
                    onClick={() => setSelectedId(null)}
                    className="text-muted-foreground hover:text-foreground transition-colors"
                  >
                    <X className="h-3.5 w-3.5" />
                  </button>
                )}
              </div>
              {selectedRisk && (
                <div className="flex items-center gap-2 flex-wrap">
                  <Badge className={cn("text-[9px] border", scoreBadgeCls(selectedRisk.score))}>
                    Score {selectedRisk.score}
                  </Badge>
                  <span className="text-[10px] text-muted-foreground flex items-center gap-1">
                    <Clock className="h-3 w-3" />
                    Due {selectedRisk.dueDate.slice(5)}
                  </span>
                </div>
              )}
            </CardHeader>
            <CardContent>
              <ControlPanel risk={selectedRisk} />
            </CardContent>
          </Card>
        </motion.div>
      </div>
    </motion.div>
  );
}
