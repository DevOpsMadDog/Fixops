// FOLDED into Compliance hero 2026-04-27 — preserve for git history
// Tab path: /compliance?tab=regulatory-tracker
/**
 * RegulatoryTrackerDashboard
 *
 * Multi-jurisdiction change tracking, obligations, and compliance assessments.
 *   1. KPIs: Active Regulations, Pending Changes, Overdue Obligations, Avg Compliance
 *   2. Upcoming changes timeline — 10 regulatory changes
 *   3. Obligations table — 12 rows
 *   4. Assessment history — 8 assessments
 *   5. Regulation catalog — 10 regulations
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { ScrollText, AlertTriangle, ClipboardCheck, BarChart3, RefreshCw, Globe, Calendar } from "lucide-react";

// ── API helpers ────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}?org_id=default`, {
    headers: { "X-API-Key": API_KEY },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── Mock data ───────────────────────────────────────────────────

const UPCOMING_CHANGES = [
  { id: "RC-001", reg: "EU AI Act",            changeType: "new_requirement", impact: "critical", domains: ["AI/ML", "Data"], effectiveAt: "2026-05-01", daysUntil: 15 },
  { id: "RC-002", reg: "NIS2 Directive",       changeType: "enforcement",     impact: "high",     domains: ["Infra", "OT"],   effectiveAt: "2026-05-15", daysUntil: 29 },
  { id: "RC-003", reg: "SEC Cyber Rule",       changeType: "deadline",        impact: "high",     domains: ["Reporting"],     effectiveAt: "2026-06-01", daysUntil: 46 },
  { id: "RC-004", reg: "DORA",                 changeType: "amendment",       impact: "medium",   domains: ["DR/BCP", "3rd Party"], effectiveAt: "2026-06-15", daysUntil: 60 },
  { id: "RC-005", reg: "CCPA Amendment AB-2",  changeType: "new_requirement", impact: "medium",   domains: ["Privacy", "Data"], effectiveAt: "2026-07-01", daysUntil: 76 },
  { id: "RC-006", reg: "HIPAA Safe Harbor 2.0",changeType: "clarification",   impact: "medium",   domains: ["Healthcare"],    effectiveAt: "2026-07-15", daysUntil: 90 },
  { id: "RC-007", reg: "PCI DSS 4.0.1",        changeType: "deadline",        impact: "high",     domains: ["Payments"],      effectiveAt: "2026-08-01", daysUntil: 107 },
  { id: "RC-008", reg: "ISO 27001:2022",       changeType: "deadline",        impact: "medium",   domains: ["ISMS"],          effectiveAt: "2026-09-01", daysUntil: 138 },
  { id: "RC-009", reg: "Cyber Resilience Act", changeType: "new_requirement", impact: "high",     domains: ["Products", "IoT"], effectiveAt: "2026-10-01", daysUntil: 168 },
  { id: "RC-010", reg: "GDPR Fines Revision",  changeType: "amendment",       impact: "critical", domains: ["Privacy"],       effectiveAt: "2026-12-01", daysUntil: 229 },
];

const OBLIGATIONS = [
  { title: "Incident notification within 24h",    reg: "NIS2",       type: "operational",     deadline: "2026-05-15", status: "on_track",  owner: "SOC Team",   daysLeft: 29 },
  { title: "AI system risk assessment",            reg: "EU AI Act",  type: "technical",       deadline: "2026-05-01", status: "at_risk",   owner: "AI Team",    daysLeft: 15 },
  { title: "Material breach 4-day disclosure",     reg: "SEC Cyber",  type: "administrative",  deadline: "2026-06-01", status: "on_track",  owner: "Legal",      daysLeft: 46 },
  { title: "ICT third-party risk registers",       reg: "DORA",       type: "operational",     deadline: "2026-06-15", status: "on_track",  owner: "GRC",        daysLeft: 60 },
  { title: "Consumer data deletion workflow",      reg: "CCPA AB-2",  type: "technical",       deadline: "2026-07-01", status: "planned",   owner: "Eng",        daysLeft: 76 },
  { title: "PHI de-identification audit",          reg: "HIPAA",      type: "administrative",  deadline: "2026-07-15", status: "planned",   owner: "Compliance", daysLeft: 90 },
  { title: "SAQ-D completion + ASV scan",          reg: "PCI 4.0.1",  type: "technical",       deadline: "2026-08-01", status: "on_track",  owner: "PCI Team",   daysLeft: 107 },
  { title: "Annual ISMS internal audit",           reg: "ISO 27001",  type: "operational",     deadline: "2026-09-01", status: "planned",   owner: "GRC",        daysLeft: 138 },
  { title: "Vulnerability disclosure policy",      reg: "CRA",        type: "administrative",  deadline: "2026-10-01", status: "planned",   owner: "Product",    daysLeft: 168 },
  { title: "Records of processing activities",     reg: "GDPR",       type: "administrative",  deadline: "2026-04-20", status: "overdue",   owner: "DPO",        daysLeft: -4 },
  { title: "Penetration testing report",           reg: "SOC2",       type: "technical",       deadline: "2026-04-18", status: "overdue",   owner: "SecEng",     daysLeft: -2 },
  { title: "Board-level cyber risk briefing",      reg: "SEC Cyber",  type: "administrative",  deadline: "2026-04-30", status: "at_risk",   owner: "CISO",       daysLeft: 14 },
];

const ASSESSMENTS = [
  { reg: "SOC2 Type II",     compliancePct: 91, gaps: 4,  critGaps: 0, assessedAt: "2026-03-15", assessor: "Deloitte" },
  { reg: "ISO 27001",        compliancePct: 85, gaps: 12, critGaps: 2, assessedAt: "2026-02-20", assessor: "BSI" },
  { reg: "PCI DSS 4.0",      compliancePct: 78, gaps: 18, critGaps: 3, assessedAt: "2026-02-10", assessor: "Verizon QSA" },
  { reg: "HIPAA Security",   compliancePct: 82, gaps: 9,  critGaps: 1, assessedAt: "2026-01-28", assessor: "Internal" },
  { reg: "NIST CSF 2.0",     compliancePct: 74, gaps: 22, critGaps: 4, assessedAt: "2026-01-15", assessor: "Internal" },
  { reg: "GDPR",             compliancePct: 88, gaps: 7,  critGaps: 1, assessedAt: "2025-12-10", assessor: "TrustArc" },
  { reg: "CCPA",             compliancePct: 93, gaps: 3,  critGaps: 0, assessedAt: "2025-11-20", assessor: "Internal" },
  { reg: "NIS2",             compliancePct: 61, gaps: 31, critGaps: 6, assessedAt: "2025-11-05", assessor: "ENISA Partner" },
];

const CATALOG = [
  { name: "GDPR",              jurisdiction: "EU",   category: "privacy",      status: "active",   version: "2018/679" },
  { name: "NIS2 Directive",    jurisdiction: "EU",   category: "cybersecurity",status: "active",   version: "2022/2555" },
  { name: "EU AI Act",         jurisdiction: "EU",   category: "AI/ML",        status: "active",   version: "2024/1689" },
  { name: "DORA",              jurisdiction: "EU",   category: "financial",    status: "active",   version: "2022/2554" },
  { name: "CCPA",              jurisdiction: "US",   category: "privacy",      status: "active",   version: "AB-375" },
  { name: "HIPAA",             jurisdiction: "US",   category: "healthcare",   status: "active",   version: "45 CFR" },
  { name: "SEC Cyber Rule",    jurisdiction: "US",   category: "financial",    status: "active",   version: "33-11216" },
  { name: "UK Cyber Top 10",   jurisdiction: "UK",   category: "cybersecurity",status: "active",   version: "2024" },
  { name: "MAS TRM",           jurisdiction: "APAC", category: "financial",    status: "active",   version: "2021" },
  { name: "Cyber Resilience Act",jurisdiction:"EU",  category: "cybersecurity",status: "pending",  version: "Draft" },
];

// ── Helpers ─────────────────────────────────────────────────────

function ChangeTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    new_requirement: "border-red-500/30 text-red-400 bg-red-500/10",
    amendment:       "border-amber-500/30 text-amber-400 bg-amber-500/10",
    clarification:   "border-blue-500/30 text-blue-400 bg-blue-500/10",
    deadline:        "border-purple-500/30 text-purple-400 bg-purple-500/10",
    enforcement:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
  };
  const label: Record<string, string> = {
    new_requirement: "New Req",
    amendment:       "Amendment",
    clarification:   "Clarification",
    deadline:        "Deadline",
    enforcement:     "Enforcement",
  };
  return <Badge className={cn("text-[10px] border", map[type] ?? "border-border text-muted-foreground")}>{label[type] ?? type}</Badge>;
}

function ImpactBadge({ impact }: { impact: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-amber-500/30 text-amber-400 bg-amber-500/10",
    medium:   "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    low:      "border-border text-muted-foreground",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[impact] ?? "border-border text-muted-foreground")}>{impact}</Badge>;
}

function ObligStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    on_track:     "border-green-500/30 text-green-400 bg-green-500/10",
    at_risk:      "border-amber-500/30 text-amber-400 bg-amber-500/10",
    overdue:      "border-red-500/30 text-red-400 bg-red-500/10",
    planned:      "border-blue-500/30 text-blue-400 bg-blue-500/10",
  };
  const label: Record<string, string> = { on_track: "On Track", at_risk: "At Risk", overdue: "Overdue", planned: "Planned" };
  return <Badge className={cn("text-[10px] border", map[status] ?? "border-border text-muted-foreground")}>{label[status] ?? status}</Badge>;
}

function ObligTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    technical:      "border-blue-500/30 text-blue-400 bg-blue-500/10",
    administrative: "border-purple-500/30 text-purple-400 bg-purple-500/10",
    operational:    "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[type] ?? "border-border text-muted-foreground")}>{type}</Badge>;
}

function JurisdictionBadge({ j }: { j: string }) {
  const map: Record<string, string> = {
    EU:   "border-blue-500/30 text-blue-400 bg-blue-500/10",
    US:   "border-red-500/30 text-red-400 bg-red-500/10",
    UK:   "border-purple-500/30 text-purple-400 bg-purple-500/10",
    APAC: "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return <Badge className={cn("text-[10px] border", map[j] ?? "border-border text-muted-foreground")}>{j}</Badge>;
}

function CategoryBadge({ cat }: { cat: string }) {
  const map: Record<string, string> = {
    privacy:      "border-pink-500/30 text-pink-400 bg-pink-500/10",
    cybersecurity:"border-red-500/30 text-red-400 bg-red-500/10",
    financial:    "border-green-500/30 text-green-400 bg-green-500/10",
    healthcare:   "border-blue-500/30 text-blue-400 bg-blue-500/10",
    "AI/ML":      "border-purple-500/30 text-purple-400 bg-purple-500/10",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[cat] ?? "border-border text-muted-foreground")}>{cat}</Badge>;
}

function DaysUntilChip({ days }: { days: number }) {
  const cls = days < 30 ? "text-red-400" : days < 90 ? "text-amber-400" : "text-green-400";
  return <span className={cn("text-xs font-bold tabular-nums", cls)}>{days}d</span>;
}

function ComplianceBar({ pct }: { pct: number }) {
  const color = pct >= 90 ? "bg-green-500" : pct >= 75 ? "bg-amber-500" : "bg-red-500";
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 rounded-full bg-muted/30 overflow-hidden">
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${pct}%` }}
          transition={{ duration: 0.8, ease: "easeOut" }}
          className={cn("h-full rounded-full", color)}
        />
      </div>
      <span className={cn("text-xs font-bold tabular-nums w-8 text-right", pct >= 90 ? "text-green-400" : pct >= 75 ? "text-amber-400" : "text-red-400")}>{pct}%</span>
    </div>
  );
}

// ── Component ───────────────────────────────────────────────────

export default function RegulatoryTrackerDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);

  useEffect(() => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/regulatory/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/regulatory/regulations/upcoming?org_id=${ORG_ID}&limit=20`),
      apiFetch(`/api/v1/regulatory/regulations/active?org_id=${ORG_ID}&limit=20`),
    ]).then(([statsResult, upcomingResult, activeResult]) => {
      const stats    = statsResult.status    === "fulfilled" ? statsResult.value    : null;
      const upcoming = upcomingResult.status === "fulfilled" ? upcomingResult.value : null;
      const active   = activeResult.status   === "fulfilled" ? activeResult.value   : null;
      if (stats || upcoming || active) {
        setLiveData({ stats, upcoming, active });
      }
    }).finally(() => setDataLoading(false));
  }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    setTimeout(() => setRefreshing(false), 800);
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      <PageHeader
        title="Regulatory Tracker"
        description="Multi-jurisdiction change tracking, obligations, and compliance assessments"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Active Regulations"   value={liveData?.stats?.total_regulations ?? liveData?.active?.length ?? 24}    icon={ScrollText}     className="border-blue-500/20" />
        <KpiCard title="Pending Changes"      value={liveData?.stats?.pending_changes ?? liveData?.upcoming?.length ?? 8}     icon={Calendar}       trend="up" className="border-amber-500/20" />
        <KpiCard title="Overdue Obligations"  value={liveData?.stats?.overdue_obligations ?? 3}     icon={AlertTriangle}  trend="up" className="border-red-500/20" />
        <KpiCard title="Avg Compliance"       value={liveData?.stats?.avg_compliance ? `${liveData.stats.avg_compliance}%` : "78%"}   icon={BarChart3}      trend="down" className="border-yellow-500/20" />
      </div>

      {/* Upcoming changes timeline */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Calendar className="h-4 w-4 text-blue-400" />
              Upcoming Regulatory Changes
            </CardTitle>
            <Badge className="text-[10px] border border-border text-muted-foreground">{UPCOMING_CHANGES.length} changes</Badge>
          </div>
          <CardDescription className="text-xs">Sorted by effective date — impact to your compliance posture</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Regulation</TableHead>
                  <TableHead className="text-[11px] h-8">Change Type</TableHead>
                  <TableHead className="text-[11px] h-8">Impact</TableHead>
                  <TableHead className="text-[11px] h-8">Affected Domains</TableHead>
                  <TableHead className="text-[11px] h-8">Effective</TableHead>
                  <TableHead className="text-[11px] h-8">Days Until</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(liveData?.upcoming ?? UPCOMING_CHANGES).map((row: any, idx: number) => (
                  <TableRow key={row.id ?? idx} className="hover:bg-muted/30">
                    <TableCell className="text-xs font-medium py-2.5">{row.reg ?? row.regulation_name ?? row.name}</TableCell>
                    <TableCell className="py-2.5"><ChangeTypeBadge type={row.changeType ?? row.change_type ?? "amendment"} /></TableCell>
                    <TableCell className="py-2.5"><ImpactBadge impact={row.impact ?? row.impact_level ?? "medium"} /></TableCell>
                    <TableCell className="py-2.5">
                      <div className="flex flex-wrap gap-1">
                        {(row.domains ?? row.affected_domains ?? []).map((d: string) => (
                          <span key={d} className="text-[10px] rounded bg-muted/50 px-1.5 py-0.5 text-muted-foreground">{d}</span>
                        ))}
                      </div>
                    </TableCell>
                    <TableCell className="text-xs py-2.5 tabular-nums text-muted-foreground">{row.effectiveAt ?? row.effective_date ?? row.effective_at}</TableCell>
                    <TableCell className="py-2.5"><DaysUntilChip days={row.daysUntil ?? row.days_until ?? 0} /></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Obligations table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <ClipboardCheck className="h-4 w-4 text-purple-400" />
              Compliance Obligations
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">3 overdue</Badge>
          </div>
          <CardDescription className="text-xs">Active obligations across all tracked regulations</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Obligation</TableHead>
                  <TableHead className="text-[11px] h-8">Regulation</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Deadline</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8">Owner</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {OBLIGATIONS.map((row, i) => (
                  <TableRow key={i} className={cn("hover:bg-muted/30", row.status === "overdue" && "bg-red-500/5")}>
                    <TableCell className="text-xs py-2.5 max-w-[220px] truncate font-medium">{row.title}</TableCell>
                    <TableCell className="text-xs py-2.5 text-muted-foreground">{row.reg}</TableCell>
                    <TableCell className="py-2.5"><ObligTypeBadge type={row.type} /></TableCell>
                    <TableCell className="text-xs py-2.5 tabular-nums text-muted-foreground">{row.deadline}</TableCell>
                    <TableCell className="py-2.5"><ObligStatusBadge status={row.status} /></TableCell>
                    <TableCell className="text-xs py-2.5 text-muted-foreground">{row.owner}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Assessment history + Catalog */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Assessment history */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <BarChart3 className="h-4 w-4 text-green-400" />
              Assessment History
            </CardTitle>
            <CardDescription className="text-xs">Recent compliance assessments with gap counts</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {ASSESSMENTS.map((a, i) => (
              <div key={i} className="space-y-1">
                <div className="flex items-center justify-between text-xs">
                  <div className="flex items-center gap-2">
                    <span className="font-medium">{a.reg}</span>
                    {a.critGaps > 0 && (
                      <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">{a.critGaps} critical</Badge>
                    )}
                  </div>
                  <div className="flex items-center gap-2 text-muted-foreground">
                    <span>{a.gaps} gaps</span>
                    <span>·</span>
                    <span>{a.assessedAt}</span>
                  </div>
                </div>
                <ComplianceBar pct={a.compliancePct} />
                <p className="text-[10px] text-muted-foreground">Assessed by: {a.assessor}</p>
              </div>
            ))}
          </CardContent>
        </Card>

        {/* Regulation catalog */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Globe className="h-4 w-4 text-blue-400" />
              Regulation Catalog
            </CardTitle>
            <CardDescription className="text-xs">All tracked regulations by jurisdiction and category</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Regulation</TableHead>
                  <TableHead className="text-[11px] h-8">Jurisdiction</TableHead>
                  <TableHead className="text-[11px] h-8">Category</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8">Version</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {CATALOG.map((reg, i) => (
                  <TableRow key={i} className="hover:bg-muted/30">
                    <TableCell className="text-xs font-medium py-2">{reg.name}</TableCell>
                    <TableCell className="py-2"><JurisdictionBadge j={reg.jurisdiction} /></TableCell>
                    <TableCell className="py-2"><CategoryBadge cat={reg.category} /></TableCell>
                    <TableCell className="py-2">
                      <Badge className={cn("text-[10px] border capitalize",
                        reg.status === "active" ? "border-green-500/30 text-green-400 bg-green-500/10" : "border-amber-500/30 text-amber-400 bg-amber-500/10"
                      )}>{reg.status}</Badge>
                    </TableCell>
                    <TableCell className="text-xs py-2 text-muted-foreground font-mono">{reg.version}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </div>
    </motion.div>
  );
}
