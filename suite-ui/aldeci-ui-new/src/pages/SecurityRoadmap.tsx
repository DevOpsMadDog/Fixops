/**
 * Security Roadmap
 *
 * Strategic initiatives, milestones, and gap remediation.
 *   1. KPIs: Total Initiatives, In Progress, Completion Rate, Total Budget
 *   2. Initiative table = 10 rows with category, priority, status, progress bar
 *   3. Milestones timeline = 8 milestones as vertical timeline
 *   4. Gap analysis = 6 gaps with severity and linked initiative
 *   5. Budget breakdown = 4 category bars showing spend vs allocated
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Map, TrendingUp, CheckCircle, Clock, AlertTriangle, DollarSign, RefreshCw } from "lucide-react";

// == API ========================================================
const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string) {
  const key =
    (typeof window !== "undefined" && window.localStorage.getItem("aldeci_api_key")) ||
    (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
    import.meta.env.VITE_API_KEY ||
    "dev-key";
  const url = path.startsWith("/api") ? `${API_BASE}${path}` : `${API_BASE}/api/v1${path}`;
  const res = await fetch(url, { headers: { "X-API-Key": key } });
  if (!res.ok) throw new Error(`${res.status}`);
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

// == Mock data ==================================================

const INITIATIVES = [
  { title: "Zero Trust Architecture",        category: "technology",  priority: "critical", status: "in_progress", owner: "CloudSec",   budget: "$420K", target: "2026-06-30", progress: 62 },
  { title: "SOC Maturity Program",           category: "people",      priority: "high",     status: "in_progress", owner: "SecOps",     budget: "$180K", target: "2026-07-31", progress: 45 },
  { title: "GDPR Compliance Remediation",    category: "compliance",  priority: "critical", status: "in_progress", owner: "GRC Team",   budget: "$95K",  target: "2026-05-15", progress: 78 },
  { title: "Vulnerability Mgmt Automation",  category: "technology",  priority: "high",     status: "in_progress", owner: "AppSec",     budget: "$210K", target: "2026-08-31", progress: 33 },
  { title: "Security Awareness Training",    category: "people",      priority: "medium",   status: "completed",   owner: "HR & Sec",   budget: "$48K",  target: "2026-03-31", progress: 100 },
  { title: "SIEM Platform Upgrade",          category: "technology",  priority: "high",     status: "in_progress", owner: "InfraSec",   budget: "$310K", target: "2026-09-30", progress: 18 },
  { title: "Incident Response Playbooks",    category: "process",     priority: "medium",   status: "completed",   owner: "SecOps",     budget: "$32K",  target: "2026-02-28", progress: 100 },
  { title: "API Security Gateway",           category: "technology",  priority: "high",     status: "planned",     owner: "Platform",   budget: "$155K", target: "2026-10-31", progress: 5 },
  { title: "PCI-DSS v4.0 Transition",        category: "compliance",  priority: "critical", status: "in_progress", owner: "GRC Team",   budget: "$275K", target: "2026-06-30", progress: 41 },
  { title: "Secure SDLC Integration",        category: "process",     priority: "medium",   status: "planned",     owner: "Engineering", budget: "$88K", target: "2026-11-30", progress: 8 },
];

const MILESTONES = [
  { title: "GDPR Article 30 Records Complete",   date: "2026-03-15", status: "completed",   initiative: "GDPR Compliance Remediation" },
  { title: "SOC Analyst Hire (3 FTE)",            date: "2026-03-31", status: "completed",   initiative: "SOC Maturity Program" },
  { title: "Security Training Rollout = Wave 1",  date: "2026-04-01", status: "completed",   initiative: "Security Awareness Training" },
  { title: "Zero Trust Pilot = 3 workloads",      date: "2026-04-30", status: "in_progress", initiative: "Zero Trust Architecture" },
  { title: "PCI SAQ-D Submission",                date: "2026-05-15", status: "in_progress", initiative: "PCI-DSS v4.0 Transition" },
  { title: "SIEM Data Source Onboarding",         date: "2026-06-15", status: "pending",     initiative: "SIEM Platform Upgrade" },
  { title: "Zero Trust = Full Production",        date: "2026-06-30", status: "pending",     initiative: "Zero Trust Architecture" },
  { title: "API Gateway GA Release",              date: "2026-10-31", status: "pending",     initiative: "API Security Gateway" },
];

const GAPS = [
  { title: "No MFA enforcement on legacy VPN",        severity: "critical", type: "Identity",    initiative: "Zero Trust Architecture" },
  { title: "SIEM missing 12 log sources",              severity: "high",     type: "Visibility",  initiative: "SIEM Platform Upgrade" },
  { title: "API endpoints lack rate limiting",         severity: "high",     type: "AppSec",      initiative: "API Security Gateway" },
  { title: "Incident runbooks outdated (>6mo)",        severity: "medium",   type: "Process",     initiative: "Incident Response Playbooks" },
  { title: "Dev environment has prod data copies",     severity: "high",     type: "Data",        initiative: "GDPR Compliance Remediation" },
  { title: "No automated vuln patching pipeline",      severity: "medium",   type: "Automation",  initiative: "Vulnerability Mgmt Automation" },
];

const BUDGET = [
  { category: "Technology", allocated: 1095, spent: 612, color: "bg-blue-500" },
  { category: "People",     allocated: 228,  spent: 143, color: "bg-purple-500" },
  { category: "Compliance", allocated: 370,  spent: 188, color: "bg-amber-500" },
  { category: "Process",    allocated: 120,  spent: 48,  color: "bg-green-500" },
];

// == Helpers ====================================================

function CategoryBadge({ cat }: { cat: string }) {
  const styles: Record<string, string> = {
    people:      "border-purple-500/30 text-purple-400 bg-purple-500/10",
    process:     "border-blue-500/30 text-blue-400 bg-blue-500/10",
    technology:  "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
    compliance:  "border-amber-500/30 text-amber-400 bg-amber-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", styles[cat] ?? "border-border text-muted-foreground")}>
      {cat}
    </Badge>
  );
}

function PriorityBadge({ p }: { p: string }) {
  const styles: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-amber-500/30 text-amber-400 bg-amber-500/10",
    medium:   "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    low:      "border-border text-muted-foreground",
  };
  return <Badge className={cn("text-[10px] border capitalize", styles[p] ?? "border-border text-muted-foreground")}>{p}</Badge>;
}

function StatusBadge({ s }: { s: string }) {
  const styles: Record<string, string> = {
    completed:   "border-green-500/30 text-green-400 bg-green-500/10",
    in_progress: "border-blue-500/30 text-blue-400 bg-blue-500/10",
    planned:     "border-gray-500/30 text-gray-400 bg-gray-500/10",
  };
  const label = s.replace("_", " ");
  return <Badge className={cn("text-[10px] border capitalize", styles[s] ?? "border-border text-muted-foreground")}>{label}</Badge>;
}

function SeverityBadge({ sev }: { sev: string }) {
  const styles: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-amber-500/30 text-amber-400 bg-amber-500/10",
    medium:   "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
  };
  return <Badge className={cn("text-[10px] border capitalize", styles[sev] ?? "border-border text-muted-foreground")}>{sev}</Badge>;
}

function MilestoneIcon({ status }: { status: string }) {
  if (status === "completed")   return <CheckCircle className="h-4 w-4 text-green-400 shrink-0" />;
  if (status === "in_progress") return <Clock className="h-4 w-4 text-amber-400 shrink-0" />;
  if (status === "overdue")     return <AlertTriangle className="h-4 w-4 text-red-400 shrink-0" />;
  return <div className="h-4 w-4 rounded-full border-2 border-muted-foreground shrink-0" />;
}

const BUDGET_MAX = 1200; // K = for bar scaling

// == Component ==================================================

export default function SecurityRoadmap() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);
  const [loading, setLoading] = useState(true);

  const fetchData = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/security-roadmap/initiatives?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/security-roadmap/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/security-roadmap/gaps?org_id=${ORG_ID}`),
    ]).then(([initiativesRes, statsRes, gapsRes]) => {
      const initiatives = initiativesRes.status === "fulfilled" ? initiativesRes.value : null;
      const stats       = statsRes.status       === "fulfilled" ? statsRes.value       : null;
      const gaps        = gapsRes.status        === "fulfilled" ? gapsRes.value        : null;
      if (initiatives || stats || gaps) {
        setLiveData({ initiatives, stats, gaps });
      }
    }).finally(() => setDataLoading(false));
  };

  useEffect(() => { fetchData(); }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchData();
    setTimeout(() => setRefreshing(false), 800);
  };

  // Derive display values = prefer live, fall back to mock constants
  const liveInitiatives: typeof INITIATIVES = Array.isArray(liveData?.initiatives) && liveData.initiatives.length > 0
    ? liveData.initiatives.map((i: any) => ({
        title:    i.title    ?? "=",
        category: i.category ?? "technology",
        priority: i.priority ?? "medium",
        status:   i.status   ?? "planned",
        owner:    i.owner    ?? "=",
        budget:   i.budget_usd ? `$${Math.round(i.budget_usd / 1000)}K` : "=",
        target:   i.target_date ?? "=",
        progress: i.progress ?? 0,
      }))
    : INITIATIVES;

  const liveGaps: typeof GAPS = Array.isArray(liveData?.gaps) && liveData.gaps.length > 0
    ? liveData.gaps.map((g: any) => ({
        title:      g.title       ?? "=",
        severity:   g.severity    ?? "medium",
        type:       g.gap_type    ?? "=",
        initiative: g.linked_initiative_id ?? "=",
      }))
    : GAPS;

  const totalInitiatives  = liveData?.stats?.total_initiatives  ?? 24;
  const inProgress        = liveData?.stats?.in_progress        ?? 8;
  const completionRate    = liveData?.stats?.completion_rate != null
    ? `${Math.round(liveData.stats.completion_rate)}%`
    : "67%";
  const totalBudget       = liveData?.stats?.total_budget_usd != null
    ? `$${(liveData.stats.total_budget_usd / 1_000_000).toFixed(1)}M`
    : "$2.4M";

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
        title="Security Roadmap"
        description="Strategic initiatives, milestones, and gap remediation"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Initiatives" value={totalInitiatives} icon={Map} />
        <KpiCard title="In Progress"       value={inProgress}       icon={TrendingUp} trend="up" />
        <KpiCard title="Completion Rate"   value={completionRate}   icon={CheckCircle} className="border-green-500/20" />
        <KpiCard title="Total Budget"      value={totalBudget}      icon={DollarSign} />
      </div>

      {/* Initiative table */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Map className="h-4 w-4 text-blue-400" />
            Strategic Initiatives
          </CardTitle>
          <CardDescription className="text-xs">All active, planned, and completed security initiatives</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Initiative</TableHead>
                  <TableHead className="text-[11px] h-8">Category</TableHead>
                  <TableHead className="text-[11px] h-8">Priority</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8">Owner</TableHead>
                  <TableHead className="text-[11px] h-8">Budget</TableHead>
                  <TableHead className="text-[11px] h-8">Target</TableHead>
                  <TableHead className="text-[11px] h-8 w-28">Progress</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {liveInitiatives.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  liveInitiatives.map((row) => (
                  <TableRow key={row.title} className="hover:bg-muted/30">
                    <TableCell className="text-xs font-medium py-2.5 max-w-[200px] truncate">{row.title}</TableCell>
                    <TableCell className="py-2.5"><CategoryBadge cat={row.category} /></TableCell>
                    <TableCell className="py-2.5"><PriorityBadge p={row.priority} /></TableCell>
                    <TableCell className="py-2.5"><StatusBadge s={row.status} /></TableCell>
                    <TableCell className="text-xs py-2.5 text-muted-foreground">{row.owner}</TableCell>
                    <TableCell className="text-xs py-2.5 tabular-nums font-medium">{row.budget}</TableCell>
                    <TableCell className="text-xs py-2.5 tabular-nums text-muted-foreground">{row.target}</TableCell>
                    <TableCell className="py-2.5">
                      <div className="flex items-center gap-2">
                        <Progress value={row.progress} className="h-1.5 flex-1" />
                        <span className="text-[10px] tabular-nums text-muted-foreground w-7 text-right">{row.progress}%</span>
                      </div>
                    </TableCell>
                  </TableRow>
                )))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Milestones + Gap analysis */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Milestones timeline */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Clock className="h-4 w-4 text-amber-400" />
              Milestones Timeline
            </CardTitle>
            <CardDescription className="text-xs">Key program milestones and their current status</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="relative pl-6">
              {/* Vertical line */}
              <div className="absolute left-2 top-2 bottom-2 w-px bg-border" />
              <div className="space-y-4">
                {MILESTONES.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  MILESTONES.map((m, i) => (
                  <div key={i} className="relative flex items-start gap-3">
                    {/* Icon positioned over the line */}
                    <div className="absolute -left-4">
                      <MilestoneIcon status={m.status} />
                    </div>
                    <div className="flex-1 min-w-0 rounded-lg border border-border p-2.5 bg-muted/20">
                      <div className="text-xs font-medium">{m.title}</div>
                      <div className="text-[10px] text-muted-foreground mt-0.5">{m.initiative}</div>
                      <div className="text-[10px] text-muted-foreground">{m.date}</div>
                    </div>
                  </div>
                )))}
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Gap analysis + Budget breakdown */}
        <div className="flex flex-col gap-4">
          {/* Gap analysis */}
          <Card className="border-amber-500/20">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold flex items-center gap-2 text-amber-400">
                <AlertTriangle className="h-4 w-4" />
                Gap Analysis
              </CardTitle>
              <CardDescription className="text-xs">Security gaps linked to roadmap initiatives</CardDescription>
            </CardHeader>
            <CardContent className="space-y-2">
              {liveGaps.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                  <p className="text-lg font-medium">No data available</p>
                  <p className="text-sm">Data will appear here once available</p>
                </div>
              ) : (
                liveGaps.map((g, i) => (
                <div key={i} className="flex items-start gap-3 rounded-lg border border-border p-2.5 bg-muted/20">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <SeverityBadge sev={g.severity} />
                      <Badge className="text-[10px] border border-border text-muted-foreground">{g.type}</Badge>
                    </div>
                    <div className="text-xs font-medium mt-1 truncate">{g.title}</div>
                    <div className="text-[10px] text-muted-foreground truncate">= {g.initiative}</div>
                  </div>
                </div>
              )))}
            </CardContent>
          </Card>

          {/* Budget breakdown */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <DollarSign className="h-4 w-4 text-green-400" />
                Budget by Category
              </CardTitle>
              <CardDescription className="text-xs">Spend vs allocated (in $K)</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {BUDGET.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                  <p className="text-lg font-medium">No data available</p>
                  <p className="text-sm">Data will appear here once available</p>
                </div>
              ) : (
                BUDGET.map((b) => (
                <div key={b.category} className="space-y-1.5">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-medium">{b.category}</span>
                    <span className="tabular-nums text-muted-foreground">${b.spent}K / ${b.allocated}K</span>
                  </div>
                  {/* Allocated bar background */}
                  <div className="relative h-2 rounded-full bg-muted/30 overflow-hidden">
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${(b.spent / BUDGET_MAX) * 100}%` }}
                      transition={{ duration: 0.8, ease: "easeOut" }}
                      className={cn("h-full rounded-full", b.color)}
                    />
                    {/* Allocated marker */}
                    <div
                      className="absolute top-0 h-full w-px bg-white/30"
                      style={{ left: `${(b.allocated / BUDGET_MAX) * 100}%` }}
                    />
                  </div>
                  <div className="text-[10px] text-muted-foreground">
                    {Math.round((b.spent / b.allocated) * 100)}% of budget used
                  </div>
                </div>
              )))}
            </CardContent>
          </Card>
        </div>
      </div>
    </motion.div>
  );
}
