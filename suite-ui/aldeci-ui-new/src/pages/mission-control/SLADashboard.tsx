import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts";
import {
  Clock,
  AlertTriangle,
  Users,
  TrendingDown,
  ChevronRight,
  Filter,
  Calendar,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { DataTable } from "@/components/shared/data-table";
import { dashboardApi, remediationApi } from "@/lib/api";
import { toast } from "sonner";
import { cn } from "@/lib/utils";

// ─── Mock Data ────────────────────────────────────────────────────────────────

const MOCK_SLA_BY_SEVERITY = [
  { severity: "Critical", sla: "4h", compliance: 91, total: 47, onTime: 43, breached: 4 },
  { severity: "High", sla: "24h", compliance: 87, total: 183, onTime: 159, breached: 24 },
  { severity: "Medium", sla: "7d", compliance: 94, total: 412, onTime: 387, breached: 25 },
  { severity: "Low", sla: "30d", compliance: 98, total: 681, onTime: 667, breached: 14 },
];

const MOCK_SLA_BY_TEAM = [
  { team: "Platform Engineering", critical: 88, high: 84, medium: 95, low: 99, total: 312, owner: "Sarah K." },
  { team: "Application Security", critical: 94, high: 91, medium: 97, low: 98, total: 241, owner: "Marcus T." },
  { team: "Cloud Operations", critical: 89, high: 85, medium: 93, low: 97, total: 198, owner: "Priya N." },
  { team: "DevOps / SRE", critical: 92, high: 88, medium: 96, low: 99, total: 156, owner: "Jake W." },
  { team: "Identity & Access", critical: 95, high: 93, medium: 98, low: 100, total: 98, owner: "Chen L." },
  { team: "Data Engineering", critical: 83, high: 79, medium: 91, low: 96, total: 218, owner: "Amara D." },
];

const MOCK_AGING = [
  { range: "0–24h", critical: 3, high: 28, medium: 94, low: 182 },
  { range: "1–3d", critical: 1, high: 41, medium: 127, low: 203 },
  { range: "3–7d", critical: 0, high: 36, medium: 89, low: 156 },
  { range: "7–14d", critical: 0, high: 24, medium: 68, low: 98 },
  { range: "14–30d", critical: 0, high: 14, medium: 34, low: 42 },
  { range: ">30d", critical: 0, high: 8, medium: 12, low: 0 },
];

const MOCK_ESCALATION_QUEUE: Array<{
  id: string;
  title: string;
  app: string;
  team: string;
  severity: string;
  dueIn: string;
  age: string;
  slaRemaining: number;
}> = [
  { id: "SLA-8821", title: "CVE-2024-50379: Apache Tomcat RCE unpatched", app: "payments-gateway-prod", team: "Platform Eng", severity: "critical", dueIn: "47m", age: "3h 13m", slaRemaining: 20 },
  { id: "SLA-8820", title: "CVE-2024-49138: SQL injection auth bypass", app: "identity-service", team: "AppSec", severity: "critical", dueIn: "1h 22m", age: "2h 38m", slaRemaining: 35 },
  { id: "SLA-8815", title: "Exposed admin API without rate limiting", app: "admin-portal", team: "Platform Eng", severity: "high", dueIn: "2h 41m", age: "21h 19m", slaRemaining: 11 },
  { id: "SLA-8812", title: "Docker image using deprecated base OS (Ubuntu 18.04)", app: "data-pipeline", team: "DevOps/SRE", severity: "high", dueIn: "3h 05m", age: "20h 55m", slaRemaining: 13 },
  { id: "SLA-8808", title: "Unencrypted backup storage detected in ap-southeast-2", app: "customer-data-lake", team: "Cloud Ops", severity: "high", dueIn: "4h 17m", age: "19h 43m", slaRemaining: 18 },
  { id: "SLA-8801", title: "Node.js 16.x EOL runtime in 3 microservices", app: "checkout-service", team: "Platform Eng", severity: "high", dueIn: "5h 52m", age: "18h 08m", slaRemaining: 24 },
  { id: "SLA-8795", title: "Outdated IAM role with wildcard S3 permissions", app: "reporting-service", team: "Cloud Ops", severity: "high", dueIn: "6h 30m", age: "17h 30m", slaRemaining: 27 },
];

// Heatmap: teams × severity × age bucket
const HEATMAP_TEAMS = ["Platform Eng", "AppSec", "Cloud Ops", "DevOps/SRE", "Identity", "Data Eng"];
const HEATMAP_BUCKETS = ["<24h", "1–3d", "3–7d", "7–14d", ">14d"];

const MOCK_HEATMAP: Record<string, Record<string, number>> = {
  "Platform Eng": { "<24h": 82, "1–3d": 74, "3–7d": 61, "7–14d": 44, ">14d": 23 },
  "AppSec":       { "<24h": 91, "1–3d": 88, "3–7d": 80, "7–14d": 70, ">14d": 55 },
  "Cloud Ops":    { "<24h": 88, "1–3d": 80, "3–7d": 69, "7–14d": 50, ">14d": 30 },
  "DevOps/SRE":   { "<24h": 94, "1–3d": 90, "3–7d": 84, "7–14d": 71, ">14d": 52 },
  "Identity":     { "<24h": 97, "1–3d": 95, "3–7d": 93, "7–14d": 88, ">14d": 79 },
  "Data Eng":     { "<24h": 79, "1–3d": 71, "3–7d": 58, "7–14d": 40, ">14d": 18 },
};

// ─── Helpers ──────────────────────────────────────────────────────────────────

function heatColor(pct: number): string {
  if (pct >= 90) return "bg-green-500/70";
  if (pct >= 75) return "bg-green-500/40";
  if (pct >= 60) return "bg-yellow-500/50";
  if (pct >= 40) return "bg-orange-500/60";
  return "bg-red-500/70";
}

const severityColors: Record<string, string> = {
  critical: "text-red-400",
  high: "text-orange-400",
  medium: "text-yellow-400",
  low: "text-blue-400",
};

// ─── Component ────────────────────────────────────────────────────────────────

export default function SLADashboard() {
  const [teamFilter, setTeamFilter] = useState("all");
  const [timeRange, setTimeRange] = useState("30");
  const [selectedRow, setSelectedRow] = useState<(typeof MOCK_ESCALATION_QUEUE)[0] | null>(null);

  useQuery({
    queryKey: ["sla-dashboard", timeRange],
    queryFn: () => dashboardApi.summary(),
    retry: false,
  });

  useQuery({
    queryKey: ["remediation-tasks", teamFilter],
    queryFn: () => remediationApi.list({ team: teamFilter }),
    retry: false,
  });

  const filteredTeams = teamFilter === "all"
    ? MOCK_SLA_BY_TEAM
    : MOCK_SLA_BY_TEAM.filter((t) => t.team.toLowerCase().includes(teamFilter.toLowerCase()));

  const overallCompliance = Math.round(
    MOCK_SLA_BY_SEVERITY.reduce((acc, s) => acc + s.compliance, 0) / MOCK_SLA_BY_SEVERITY.length
  );

  const totalBreached = MOCK_SLA_BY_SEVERITY.reduce((acc, s) => acc + s.breached, 0);
  const approaching = MOCK_ESCALATION_QUEUE.length;

  const escalationColumns = [
    { key: "id", header: "ID", render: (row: typeof MOCK_ESCALATION_QUEUE[0]) => <span className="text-xs font-mono text-primary">{row.id}</span> },
    { key: "title", header: "Finding", render: (row: typeof MOCK_ESCALATION_QUEUE[0]) => <span className="text-xs font-medium">{row.title}</span> },
    { key: "team", header: "Team", render: (row: typeof MOCK_ESCALATION_QUEUE[0]) => <span className="text-xs text-muted-foreground">{row.team}</span> },
    { key: "severity", header: "Sev", render: (row: typeof MOCK_ESCALATION_QUEUE[0]) => <Badge variant={row.severity as "critical" | "high"} className="text-xs">{row.severity}</Badge> },
    {
      key: "dueIn",
      header: "Due In",
      render: (row: typeof MOCK_ESCALATION_QUEUE[0]) => (
        <div className="space-y-1">
          <p className={cn("text-xs font-bold", row.slaRemaining < 25 ? "text-red-400" : "text-yellow-400")}>{row.dueIn}</p>
          <Progress value={row.slaRemaining} className="h-1 w-16" />
        </div>
      ),
    },
  ];

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.4 }}
      className="space-y-6"
    >
      {/* Header */}
      <PageHeader
        title="SLA Dashboard"
        description="Service Level Agreement compliance by severity, team, and aging bucket"
        actions={
          <div className="flex items-center gap-2">
            <Select value={teamFilter} onValueChange={setTeamFilter}>
              <SelectTrigger className="w-[170px]">
                <Filter className="h-3.5 w-3.5 mr-1" />
                <SelectValue placeholder="All Teams" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Teams</SelectItem>
                <SelectItem value="platform">Platform Eng</SelectItem>
                <SelectItem value="appsec">App Security</SelectItem>
                <SelectItem value="cloud">Cloud Ops</SelectItem>
                <SelectItem value="devops">DevOps / SRE</SelectItem>
              </SelectContent>
            </Select>
            <Select value={timeRange} onValueChange={setTimeRange}>
              <SelectTrigger className="w-[120px]">
                <Calendar className="h-3.5 w-3.5 mr-1" />
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="30">30 days</SelectItem>
                <SelectItem value="60">60 days</SelectItem>
                <SelectItem value="90">90 days</SelectItem>
              </SelectContent>
            </Select>
          </div>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Overall SLA %" value={`${overallCompliance}%`} change={2.1} changeLabel="vs last period" trend="up" icon={Clock} />
        <KpiCard title="SLA Breaches" value={totalBreached} change={-14} changeLabel="vs last period" trend="up" icon={TrendingDown} />
        <KpiCard title="Approaching Breach" value={approaching} change={3} changeLabel="vs yesterday" trend="down" icon={AlertTriangle} />
        <KpiCard title="Teams Tracked" value={MOCK_SLA_BY_TEAM.length} trend="flat" icon={Users} />
      </div>

      {/* SLA by Severity */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <Card className="p-5">
          <CardHeader className="p-0 pb-4">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Clock className="h-4 w-4 text-primary" />
              SLA Compliance by Severity
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0 space-y-4">
            {MOCK_SLA_BY_SEVERITY.map((s) => (
              <div key={s.severity} className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <div className="flex items-center gap-2">
                    <span className={cn("text-sm font-semibold w-16", severityColors[s.severity.toLowerCase()])}>{s.severity}</span>
                    <span className="text-xs text-muted-foreground">SLA: {s.sla}</span>
                  </div>
                  <div className="flex items-center gap-3 text-xs">
                    <span className="text-muted-foreground">{s.onTime}/{s.total} on-time</span>
                    <span className={cn("font-bold tabular-nums", s.compliance >= 90 ? "text-green-400" : s.compliance >= 80 ? "text-yellow-400" : "text-red-400")}>
                      {s.compliance}%
                    </span>
                  </div>
                </div>
                <div className="h-2 rounded-full bg-muted overflow-hidden">
                  <motion.div
                    className={cn("h-full rounded-full", s.compliance >= 90 ? "bg-green-500" : s.compliance >= 80 ? "bg-yellow-500" : "bg-red-500")}
                    initial={{ width: 0 }}
                    animate={{ width: `${s.compliance}%` }}
                    transition={{ duration: 0.8, ease: "easeOut" }}
                  />
                </div>
                {s.breached > 0 && (
                  <p className="text-xs text-red-400">{s.breached} breached this period</p>
                )}
              </div>
            ))}
          </CardContent>
        </Card>

        {/* Aging Analysis Chart */}
        <Card className="p-5">
          <CardHeader className="p-0 pb-4">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-orange-400" />
              Aging Analysis — Open Findings
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0 h-[240px]">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={MOCK_AGING} margin={{ top: 5, right: 10, left: -20, bottom: 0 }} barSize={18}>
                <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border) / 0.3)" />
                <XAxis dataKey="range" tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }} axisLine={false} tickLine={false} />
                <YAxis tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }} axisLine={false} tickLine={false} />
                <Tooltip contentStyle={{ backgroundColor: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 8, fontSize: 12 }} />
                <Bar dataKey="critical" name="Critical" stackId="a" fill="#f87171" />
                <Bar dataKey="high" name="High" stackId="a" fill="#fb923c" />
                <Bar dataKey="medium" name="Medium" stackId="a" fill="#fbbf24" />
                <Bar dataKey="low" name="Low" stackId="a" fill="#60a5fa" radius={[3, 3, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      </div>

      {/* Team Breakdown */}
      <Card className="p-5">
        <CardHeader className="p-0 pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Users className="h-4 w-4 text-primary" />
            SLA Compliance by Team
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border/50">
                  <th className="text-left text-xs font-medium text-muted-foreground uppercase tracking-wider py-2 pr-4">Team</th>
                  <th className="text-left text-xs font-medium text-muted-foreground uppercase tracking-wider py-2 px-3">Critical</th>
                  <th className="text-left text-xs font-medium text-muted-foreground uppercase tracking-wider py-2 px-3">High</th>
                  <th className="text-left text-xs font-medium text-muted-foreground uppercase tracking-wider py-2 px-3">Medium</th>
                  <th className="text-left text-xs font-medium text-muted-foreground uppercase tracking-wider py-2 px-3">Low</th>
                  <th className="text-left text-xs font-medium text-muted-foreground uppercase tracking-wider py-2 px-3">Items</th>
                  <th className="text-left text-xs font-medium text-muted-foreground uppercase tracking-wider py-2 pl-3">Owner</th>
                </tr>
              </thead>
              <tbody>
                {filteredTeams.map((team, i) => (
                  <motion.tr
                    key={team.team}
                    initial={{ opacity: 0, x: -8 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: i * 0.05 }}
                    className="border-b border-border/30 hover:bg-muted/20 transition-colors"
                  >
                    <td className="py-3 pr-4 font-medium text-xs">{team.team}</td>
                    {[team.critical, team.high, team.medium, team.low].map((val, j) => (
                      <td key={j} className="py-3 px-3">
                        <div className="space-y-1">
                          <span className={cn("text-xs font-bold tabular-nums", val < 85 ? "text-orange-400" : val < 70 ? "text-red-400" : "text-foreground")}>{val}%</span>
                          <div className="h-1 w-14 rounded-full bg-muted overflow-hidden">
                            <div
                              className={cn("h-full rounded-full", val >= 90 ? "bg-green-500" : val >= 75 ? "bg-yellow-500" : "bg-red-500")}
                              style={{ width: `${val}%` }}
                            />
                          </div>
                        </div>
                      </td>
                    ))}
                    <td className="py-3 px-3 text-xs text-muted-foreground tabular-nums">{team.total}</td>
                    <td className="py-3 pl-3 text-xs text-muted-foreground">{team.owner}</td>
                  </motion.tr>
                ))}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>

      {/* Heatmap */}
      <Card className="p-5">
        <CardHeader className="p-0 pb-3">
          <CardTitle className="text-sm font-semibold">SLA Compliance Heatmap — Team × Age Bucket</CardTitle>
        </CardHeader>
        <CardContent className="p-0 overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr>
                <th className="text-left py-2 pr-4 text-muted-foreground font-medium">Team</th>
                {HEATMAP_BUCKETS.map((b) => (
                  <th key={b} className="text-center py-2 px-3 text-muted-foreground font-medium">{b}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {HEATMAP_TEAMS.map((team) => (
                <tr key={team} className="border-t border-border/20">
                  <td className="py-2 pr-4 font-medium">{team}</td>
                  {HEATMAP_BUCKETS.map((bucket) => {
                    const val = MOCK_HEATMAP[team]?.[bucket] ?? 0;
                    return (
                      <td key={bucket} className="py-2 px-3 text-center">
                        <div className={cn("inline-flex h-8 w-14 items-center justify-center rounded-md text-xs font-bold tabular-nums", heatColor(val))}>
                          {val}%
                        </div>
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
          <div className="mt-3 flex items-center gap-3 text-xs text-muted-foreground">
            <span>Legend:</span>
            {[{ label: "≥90%", cls: "bg-green-500/70" }, { label: "75–90%", cls: "bg-green-500/40" }, { label: "60–75%", cls: "bg-yellow-500/50" }, { label: "40–60%", cls: "bg-orange-500/60" }, { label: "<40%", cls: "bg-red-500/70" }].map((l) => (
              <div key={l.label} className="flex items-center gap-1">
                <div className={cn("h-3 w-3 rounded", l.cls)} />
                <span>{l.label}</span>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Escalation Queue */}
      <Card className="p-5">
        <CardHeader className="p-0 pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-red-400" />
              Escalation Queue
              <Badge variant="destructive" className="text-xs">{MOCK_ESCALATION_QUEUE.length} approaching</Badge>
            </CardTitle>
            <Button variant="outline" size="sm" onClick={() => toast.info("Escalating all approaching-breach items to team leads")}>
              Escalate All
            </Button>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          <DataTable
            columns={escalationColumns as Parameters<typeof DataTable>[0]["columns"]}
            data={MOCK_ESCALATION_QUEUE as unknown as Record<string, unknown>[]}
            onRowClick={(row) => {
              setSelectedRow(row as unknown as typeof MOCK_ESCALATION_QUEUE[0]);
              toast.info(`Viewing ${(row as { id: string }).id}`);
            }}
          />
        </CardContent>
      </Card>
    </motion.div>
  );
}
