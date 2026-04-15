/**
 * Red Team Operations
 *
 * Offensive security exercise tracking and live attack simulation feed.
 *   1. KPIs: Active Engagements, Findings Total, Critical Findings, Remediated
 *   2. Engagement table (6 rows) — name, type, status, dates, lead, findings
 *   3. Live attack simulation feed (8 events) — tactic, technique, target, status
 *   4. Finding severity breakdown — donut-style div grid
 *   5. Remediation progress — 5 finding cards with progress bars
 *
 * API stubs: GET /api/v1/red-team/engagements, /api/v1/red-team/feed, /api/v1/red-team/findings
 */

import { useState } from "react";
import { motion } from "framer-motion";
import {
  Swords,
  AlertTriangle,
  CheckCircle2,
  RefreshCw,
  Activity,
  Target,
  Shield,
  Zap,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── Mock data ──────────────────────────────────────────────────

const ENGAGEMENTS = [
  {
    name: "Q2 External Pentest",
    type: "pentest",
    status: "active",
    start: "2026-04-01",
    end: "2026-04-30",
    lead: "R. Torres",
    findings: 18,
  },
  {
    name: "Phishing Campaign Wave 3",
    type: "phishing",
    status: "active",
    start: "2026-04-10",
    end: "2026-04-17",
    lead: "K. Nakamura",
    findings: 7,
  },
  {
    name: "Social Engineering Audit",
    type: "social",
    status: "completed",
    start: "2026-03-15",
    end: "2026-03-28",
    lead: "A. Osei",
    findings: 12,
  },
  {
    name: "Physical Security Test",
    type: "physical",
    status: "completed",
    start: "2026-03-01",
    end: "2026-03-10",
    lead: "M. Ferreira",
    findings: 5,
  },
  {
    name: "Purple Team Exercise",
    type: "purple-team",
    status: "active",
    start: "2026-04-14",
    end: "2026-04-18",
    lead: "S. Patel",
    findings: 3,
  },
  {
    name: "BAS Continuous Assessment",
    type: "BAS",
    status: "planned",
    start: "2026-05-01",
    end: "2026-05-31",
    lead: "Auto",
    findings: 0,
  },
];

const FEED = [
  { ts: "14:32:11", tactic: "Initial Access",       tech: "T1190", target: "api-gateway-prod",  status: "evaded"   },
  { ts: "14:28:44", tactic: "Credential Access",    tech: "T1110", target: "auth-service-01",   status: "blocked"  },
  { ts: "14:21:07", tactic: "Lateral Movement",     tech: "T1021", target: "internal-jira",     status: "detected" },
  { ts: "14:17:55", tactic: "Privilege Escalation", tech: "T1068", target: "k8s-master-node",   status: "blocked"  },
  { ts: "14:09:33", tactic: "Discovery",            tech: "T1046", target: "10.0.0.0/16",       status: "evaded"   },
  { ts: "14:04:18", tactic: "Exfiltration",         tech: "T1048", target: "s3://corp-backups", status: "blocked"  },
  { ts: "13:58:02", tactic: "Command & Control",    tech: "T1071", target: "c2-beacon-02",      status: "detected" },
  { ts: "13:51:49", tactic: "Defense Evasion",      tech: "T1070", target: "siem-logs",         status: "evaded"   },
];

const SEVERITY_BREAKDOWN = [
  { label: "Critical", count: 8,  color: "bg-red-500",    text: "text-red-400",    border: "border-red-500/30" },
  { label: "High",     count: 14, color: "bg-amber-500",  text: "text-amber-400",  border: "border-amber-500/30" },
  { label: "Medium",   count: 19, color: "bg-yellow-500", text: "text-yellow-400", border: "border-yellow-500/30" },
  { label: "Low",      count: 6,  color: "bg-blue-500",   text: "text-blue-400",   border: "border-blue-500/30" },
];

const REMEDIATION = [
  { id: "RT-F001", title: "Unauthenticated RCE via API param injection",       severity: "Critical", pct: 85, team: "AppSec"   },
  { id: "RT-F002", title: "Password spray — 12 accounts compromised",           severity: "Critical", pct: 60, team: "IAM Team" },
  { id: "RT-F003", title: "Kerberoastable service account (SPN exposure)",      severity: "High",     pct: 40, team: "IAM Team" },
  { id: "RT-F004", title: "Lateral movement via PsExec over SMB",               severity: "High",     pct: 20, team: "InfraSec" },
  { id: "RT-F005", title: "Data exfil via DNS tunneling — undetected 6 hours",  severity: "Critical", pct: 10, team: "NetSec"   },
];

// ── Helpers ────────────────────────────────────────────────────

const TYPE_LABELS: Record<string, string> = {
  pentest:    "Pentest",
  phishing:   "Phishing",
  social:     "Social Eng.",
  physical:   "Physical",
  "purple-team": "Purple Team",
  BAS:        "BAS",
};

function TypeBadge({ type }: { type: string }) {
  const cls =
    type === "pentest"      ? "border-red-500/30 text-red-400 bg-red-500/10" :
    type === "phishing"     ? "border-amber-500/30 text-amber-400 bg-amber-500/10" :
    type === "social"       ? "border-purple-500/30 text-purple-400 bg-purple-500/10" :
    type === "physical"     ? "border-blue-500/30 text-blue-400 bg-blue-500/10" :
    type === "purple-team"  ? "border-indigo-500/30 text-indigo-400 bg-indigo-500/10" :
                              "border-border text-muted-foreground";
  return <Badge className={cn("text-[10px] border", cls)}>{TYPE_LABELS[type] ?? type}</Badge>;
}

function EngagementStatusBadge({ status }: { status: string }) {
  const cls =
    status === "active"    ? "border-green-500/30 text-green-400 bg-green-500/10" :
    status === "planned"   ? "border-blue-500/30 text-blue-400 bg-blue-500/10" :
                             "border-border text-muted-foreground";
  return <Badge className={cn("text-[10px] border", cls)}>{status}</Badge>;
}

function FeedStatusBadge({ status }: { status: string }) {
  const cls =
    status === "evaded"   ? "border-red-500/30 text-red-400 bg-red-500/10" :
    status === "detected" ? "border-amber-500/30 text-amber-400 bg-amber-500/10" :
                            "border-green-500/30 text-green-400 bg-green-500/10";
  return <Badge className={cn("text-[10px] border", cls)}>{status}</Badge>;
}

function SeverityBadge({ sev }: { sev: string }) {
  const cls =
    sev === "Critical" ? "border-red-500/30 text-red-400 bg-red-500/10" :
    sev === "High"     ? "border-amber-500/30 text-amber-400 bg-amber-500/10" :
    sev === "Medium"   ? "border-yellow-500/30 text-yellow-400 bg-yellow-500/10" :
                         "border-border text-muted-foreground";
  return <Badge className={cn("text-[10px] border", cls)}>{sev}</Badge>;
}

// ── Component ──────────────────────────────────────────────────

export default function RedTeamStatus() {
  const [refreshing, setRefreshing] = useState(false);

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
      {/* Header */}
      <PageHeader
        title="Red Team Operations"
        description="Offensive security exercise tracking"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Active Engagements" value={3}  icon={Swords}        trend="up"   className="border-red-500/20" />
        <KpiCard title="Findings Total"     value={47} icon={AlertTriangle} trend="up"   className="border-amber-500/20" />
        <KpiCard title="Critical Findings"  value={8}  icon={Zap}           trend="up"   className="border-red-500/20" />
        <KpiCard title="Remediated"         value="31 (66%)" icon={CheckCircle2} trend="up" className="border-green-500/20" />
      </div>

      {/* Engagement table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Target className="h-4 w-4 text-red-400" />
              Active &amp; Scheduled Engagements
            </CardTitle>
            <Badge className="text-[10px] border border-border text-muted-foreground">{ENGAGEMENTS.length} engagements</Badge>
          </div>
          <CardDescription className="text-xs">All offensive security exercises — pentest, phishing, purple team, BAS</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Engagement</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8">Start</TableHead>
                  <TableHead className="text-[11px] h-8">End</TableHead>
                  <TableHead className="text-[11px] h-8">Lead</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Findings</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {ENGAGEMENTS.map((eng) => (
                  <TableRow key={eng.name} className="hover:bg-muted/30">
                    <TableCell className="text-xs font-medium py-2.5">{eng.name}</TableCell>
                    <TableCell className="py-2.5"><TypeBadge type={eng.type} /></TableCell>
                    <TableCell className="py-2.5"><EngagementStatusBadge status={eng.status} /></TableCell>
                    <TableCell className="text-xs tabular-nums py-2.5 text-muted-foreground">{eng.start}</TableCell>
                    <TableCell className="text-xs tabular-nums py-2.5 text-muted-foreground">{eng.end}</TableCell>
                    <TableCell className="text-xs py-2.5">{eng.lead}</TableCell>
                    <TableCell className="text-xs tabular-nums py-2.5 text-right font-bold">
                      {eng.findings > 0
                        ? <span className={eng.findings >= 15 ? "text-red-400" : eng.findings >= 5 ? "text-amber-400" : "text-muted-foreground"}>{eng.findings}</span>
                        : <span className="text-muted-foreground">—</span>
                      }
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Live attack feed + Severity breakdown */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Live attack simulation feed */}
        <Card className="border-red-500/20">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
              <Activity className="h-4 w-4 animate-pulse" />
              Live Attack Simulation Feed
            </CardTitle>
            <CardDescription className="text-xs">Real-time MITRE ATT&amp;CK technique execution log</CardDescription>
          </CardHeader>
          <CardContent className="space-y-2 p-4">
            {FEED.map((evt, i) => (
              <motion.div
                key={i}
                initial={{ opacity: 0, x: -8 }}
                animate={{ opacity: 1, x: 0 }}
                transition={{ duration: 0.3, delay: i * 0.06 }}
                className="flex items-start gap-3 text-xs border border-border/50 rounded-md p-2 bg-muted/10"
              >
                <span className="tabular-nums text-[10px] text-muted-foreground font-mono flex-shrink-0 mt-0.5">{evt.ts}</span>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-semibold">{evt.tactic}</span>
                    <span className="font-mono text-[10px] text-blue-400 bg-blue-500/10 border border-blue-500/20 rounded px-1">{evt.tech}</span>
                  </div>
                  <div className="text-[10px] text-muted-foreground mt-0.5 truncate">Target: <span className="font-medium text-foreground">{evt.target}</span></div>
                </div>
                <FeedStatusBadge status={evt.status} />
              </motion.div>
            ))}
          </CardContent>
        </Card>

        {/* Finding severity breakdown */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Shield className="h-4 w-4 text-purple-400" />
              Finding Severity Breakdown
            </CardTitle>
            <CardDescription className="text-xs">Distribution of all red team findings by severity</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 gap-3">
              {SEVERITY_BREAKDOWN.map((s) => (
                <div
                  key={s.label}
                  className={cn(
                    "flex flex-col items-center justify-center gap-2 rounded-xl border p-4",
                    s.border,
                    "bg-muted/10"
                  )}
                >
                  <div className={cn("h-8 w-8 rounded-md flex items-center justify-center", s.color)}>
                    <span className="text-white text-sm font-bold">{s.count}</span>
                  </div>
                  <span className={cn("text-xs font-semibold", s.text)}>{s.label}</span>
                  <div className="w-full">
                    <Progress value={(s.count / 47) * 100} className="h-1.5" />
                  </div>
                  <span className="text-[10px] text-muted-foreground">
                    {Math.round((s.count / 47) * 100)}% of total
                  </span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Remediation progress */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <CheckCircle2 className="h-4 w-4 text-green-400" />
              Remediation Progress
            </CardTitle>
            <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">
              31 / 47 resolved
            </Badge>
          </div>
          <CardDescription className="text-xs">Top findings by severity — remediation status and ownership</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {REMEDIATION.map((f) => (
            <div key={f.id} className="space-y-2">
              <div className="flex items-start justify-between gap-3">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="text-[10px] font-mono text-muted-foreground">{f.id}</span>
                    <SeverityBadge sev={f.severity} />
                    <span className="text-[10px] text-muted-foreground">— {f.team}</span>
                  </div>
                  <p className="text-xs font-medium mt-0.5 truncate">{f.title}</p>
                </div>
                <span className={cn(
                  "text-xs font-bold tabular-nums flex-shrink-0",
                  f.pct >= 80 ? "text-green-400" : f.pct >= 40 ? "text-amber-400" : "text-red-400"
                )}>
                  {f.pct}%
                </span>
              </div>
              <div className="relative h-1.5 rounded-full bg-muted/30 overflow-hidden">
                <motion.div
                  initial={{ width: 0 }}
                  animate={{ width: `${f.pct}%` }}
                  transition={{ duration: 0.9, ease: "easeOut" }}
                  className={cn(
                    "h-full rounded-full",
                    f.pct >= 80 ? "bg-green-500" : f.pct >= 40 ? "bg-amber-500" : "bg-red-500"
                  )}
                />
              </div>
            </div>
          ))}
        </CardContent>
      </Card>
    </motion.div>
  );
}
