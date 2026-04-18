/**
 * Attack Simulation
 *
 * BAS, purple team, and MITRE ATT&CK coverage.
 *   1. KPIs: Simulations Run, Detection Rate, Avg Detection Time, Critical Findings
 *   2. Simulation table (8 rows)
 *   3. MITRE ATT&CK coverage heatmap (11 tactics)
 *   4. Attack path timeline (latest simulation)
 *   5. Finding prioritization table (10 findings)
 *
 * API stubs: GET /api/v1/attack-simulation/runs, /api/v1/attack-simulation/mitre-coverage
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Shield, Target, Clock, AlertTriangle, RefreshCw, Play, Eye } from "lucide-react";

// ── API helpers ────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "dev-key";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "X-API-Key": API_KEY },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── Mock data ──────────────────────────────────────────────────

const SIMULATIONS = [
  { name: "Q2 Full BAS Run",            type: "BAS",              scope: "All assets",           target: "Enterprise",     status: "completed", started: "2026-04-14", findings: 28 },
  { name: "Purple Team — Ransomware",   type: "purple_team",      scope: "Endpoint + Lateral",   target: "Production",     status: "completed", started: "2026-04-12", findings: 14 },
  { name: "CISO Tabletop — BEC",        type: "tabletop",         scope: "Email + Auth",         target: "Executives",     status: "completed", started: "2026-04-10", findings: 6  },
  { name: "External Pentest Q1",        type: "penetration_test", scope: "Internet-facing",      target: "Web + API",      status: "completed", started: "2026-03-28", findings: 19 },
  { name: "Cloud Privilege Escalation", type: "BAS",              scope: "AWS + GCP",            target: "Cloud infra",    status: "running",   started: "2026-04-16", findings: 4  },
  { name: "Insider Threat Simulation",  type: "purple_team",      scope: "Internal network",     target: "HR + Finance",   status: "scheduled", started: "2026-04-18", findings: 0  },
  { name: "Supply Chain BAS",           type: "BAS",              scope: "3rd-party APIs",       target: "Integrations",   status: "scheduled", started: "2026-04-20", findings: 0  },
  { name: "AD Kerberoasting Test",      type: "penetration_test", scope: "Active Directory",     target: "Identity infra", status: "completed", started: "2026-04-08", findings: 11 },
];

const MITRE_TACTICS = [
  { tactic: "Initial Access",     short: "Init",    pct: 82 },
  { tactic: "Execution",          short: "Exec",    pct: 91 },
  { tactic: "Persistence",        short: "Persist", pct: 67 },
  { tactic: "Privilege Esc.",     short: "PrivEsc", pct: 74 },
  { tactic: "Defense Evasion",    short: "DefEva",  pct: 55 },
  { tactic: "Credential Access",  short: "Cred",    pct: 48 },
  { tactic: "Discovery",          short: "Disc",    pct: 88 },
  { tactic: "Lateral Movement",   short: "Lateral", pct: 61 },
  { tactic: "Collection",         short: "Collect", pct: 72 },
  { tactic: "Exfiltration",       short: "Exfil",   pct: 43 },
  { tactic: "Impact",             short: "Impact",  pct: 79 },
];

const TIMELINE = [
  { tactic: "Initial Access",    technique: "T1566.001", name: "Spearphishing Attachment", success: true,  detected: true,  detectionTime: "2m 14s" },
  { tactic: "Execution",         technique: "T1204.002", name: "Malicious File",           success: true,  detected: true,  detectionTime: "0m 47s" },
  { tactic: "Persistence",       technique: "T1053.005", name: "Scheduled Task",           success: true,  detected: false, detectionTime: "—"      },
  { tactic: "Privilege Esc.",    technique: "T1055.012", name: "Process Hollowing",        success: true,  detected: false, detectionTime: "—"      },
  { tactic: "Defense Evasion",   technique: "T1027.001", name: "Binary Padding",           success: false, detected: true,  detectionTime: "1m 02s" },
  { tactic: "Credential Access", technique: "T1003.001", name: "LSASS Memory",             success: true,  detected: true,  detectionTime: "4m 38s" },
  { tactic: "Lateral Movement",  technique: "T1021.002", name: "SMB/Admin Shares",         success: true,  detected: false, detectionTime: "—"      },
  { tactic: "Exfiltration",      technique: "T1041",     name: "Exfil Over C2 Channel",   success: false, detected: true,  detectionTime: "0m 22s" },
];

const FINDINGS = [
  { id: "F-SIM-001", severity: "Critical", technique: "T1053.005", name: "Scheduled task persistence not detected", dwellTime: "72h", detectionMethod: "none"        },
  { id: "F-SIM-002", severity: "Critical", technique: "T1055.012", name: "Process hollowing evaded EDR",             dwellTime: "48h", detectionMethod: "none"        },
  { id: "F-SIM-003", severity: "High",     technique: "T1021.002", name: "SMB lateral movement undetected",          dwellTime: "18h", detectionMethod: "none"        },
  { id: "F-SIM-004", severity: "High",     technique: "T1003.001", name: "LSASS dump — slow detection (4m38s)",      dwellTime: "6h",  detectionMethod: "EDR alert"   },
  { id: "F-SIM-005", severity: "High",     technique: "T1078.004", name: "Valid cloud credentials abused",           dwellTime: "24h", detectionMethod: "SIEM"        },
  { id: "F-SIM-006", severity: "Medium",   technique: "T1562.001", name: "AV disabled without alert",                dwellTime: "12h", detectionMethod: "none"        },
  { id: "F-SIM-007", severity: "Medium",   technique: "T1087.002", name: "Domain account enumeration",               dwellTime: "2h",  detectionMethod: "SIEM"        },
  { id: "F-SIM-008", severity: "Medium",   technique: "T1190",     name: "Public-facing app exploited",              dwellTime: "4h",  detectionMethod: "WAF block"   },
  { id: "F-SIM-009", severity: "Low",      technique: "T1018",     name: "Remote system discovery not alerted",      dwellTime: "1h",  detectionMethod: "EDR alert"   },
  { id: "F-SIM-010", severity: "Low",      technique: "T1016",     name: "Network config enumeration",               dwellTime: "0.5h",detectionMethod: "EDR alert"   },
];

// ── Helpers ────────────────────────────────────────────────────

function SimTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    BAS:              "border-blue-500/30 text-blue-400 bg-blue-500/10",
    purple_team:      "border-purple-500/30 text-purple-400 bg-purple-500/10",
    tabletop:         "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
    penetration_test: "border-red-500/30 text-red-400 bg-red-500/10",
  };
  return <Badge className={cn("text-[10px] border", map[type] ?? "border-border text-muted-foreground")}>{type.replace("_", " ")}</Badge>;
}

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    completed: "border-green-500/30 text-green-400 bg-green-500/10",
    running:   "border-blue-500/30 text-blue-400 bg-blue-500/10",
    scheduled: "border-muted text-muted-foreground",
  };
  return <Badge className={cn("text-[10px] border", map[status] ?? "border-border text-muted-foreground")}>{status}</Badge>;
}

function SeverityBadge({ sev }: { sev: string }) {
  const cls =
    sev === "Critical" ? "border-red-500/30 text-red-400 bg-red-500/10" :
    sev === "High"     ? "border-amber-500/30 text-amber-400 bg-amber-500/10" :
    sev === "Medium"   ? "border-yellow-500/30 text-yellow-400 bg-yellow-500/10" :
                         "border-border text-muted-foreground";
  return <Badge className={cn("text-[10px] border", cls)}>{sev}</Badge>;
}

function coverageColor(pct: number) {
  if (pct >= 75) return "bg-green-500/80 text-green-100";
  if (pct >= 50) return "bg-amber-500/80 text-amber-100";
  return "bg-red-500/80 text-red-100";
}

// ── Component ──────────────────────────────────────────────────

export default function AttackSimulation() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);
  const [loading, setLoading] = useState(true);

  const loadData = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch("/api/v1/attack-sim/simulations?org_id=default&limit=20"),
      apiFetch("/api/v1/attack-sim/stats?org_id=default"),
    ]).then(([simulationsResult, statsResult]) => {
      const simulations = simulationsResult.status === "fulfilled" ? simulationsResult.value : null;
      const stats       = statsResult.status       === "fulfilled" ? statsResult.value       : null;
      if (simulations || stats) {
        setLiveData({ scenarios: simulations, campaigns: null, heatmap: null, stats });
      }
    }).finally(() => setDataLoading(false));
  };

  useEffect(() => { loadData(); }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    loadData();
    setTimeout(() => setRefreshing(false), 800);
  };

  // Derive KPI values from live data or fall back to mock constants
  const scenariosList: any[] = liveData?.scenarios ?? SIMULATIONS;
  const campaignsList: any[] = liveData?.campaigns ?? [];
  const totalSims = liveData?.scenarios?.length ?? 24;
  const completedCampaigns = campaignsList.filter((c: any) => c.status === "completed");
  const detectedSteps = completedCampaigns.reduce((acc: number, c: any) => acc + (c.steps_succeeded ?? 0), 0);
  const totalSteps    = completedCampaigns.reduce((acc: number, c: any) => acc + (c.steps_executed ?? 0), 0);
  const detectionRate = totalSteps > 0 ? `${((detectedSteps / totalSteps) * 100).toFixed(1)}%` : "73.4%";
  const criticalFindings = scenariosList.reduce((acc: number, s: any) => acc + (s.findings ?? 0), 0) || 18;

  // Map live scenarios to table rows shape — fall back to SIMULATIONS mock
  const tableRows = liveData?.scenarios
    ? scenariosList.map((s: any) => ({
        name:     s.name,
        type:     s.threat_actor ?? "BAS",
        scope:    s.target_assets?.join(", ") || "All assets",
        target:   s.complexity ?? "medium",
        status:   "completed",
        started:  s.created_at?.slice(0, 10) ?? "—",
        findings: s.objectives?.length ?? 0,
      }))
    : SIMULATIONS;

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
        title="Attack Simulation"
        description="BAS, purple team, and MITRE ATT&CK coverage"
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
              <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
            </Button>
            <Button size="sm" className="gap-1.5">
              <Play className="h-3.5 w-3.5" /> New Simulation
            </Button>
          </div>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Simulations Run"      value={totalSims}        icon={Target}        />
        <KpiCard title="Detection Rate"       value={detectionRate}    icon={Shield}        trend="up"   className="border-green-500/20" />
        <KpiCard title="Avg Detection Time"   value="4.2 min"          icon={Clock}         trend="down" className="border-blue-500/20" />
        <KpiCard title="Critical Findings"    value={criticalFindings} icon={AlertTriangle} trend="up"   className="border-red-500/20" />
      </div>

      {/* Simulation Table */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Target className="h-4 w-4 text-purple-400" />
            Simulation Runs
          </CardTitle>
          <CardDescription className="text-xs">All simulation campaigns — click View to inspect findings</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Name</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Scope</TableHead>
                  <TableHead className="text-[11px] h-8">Target</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8">Started</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Findings</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {tableRows.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  tableRows.map((row) => (
                  <TableRow key={row.name} className="hover:bg-muted/30">
                    <TableCell className="text-xs font-medium py-2.5 max-w-[180px] truncate">{row.name}</TableCell>
                    <TableCell className="py-2.5"><SimTypeBadge type={row.type} /></TableCell>
                    <TableCell className="text-xs py-2.5 text-muted-foreground max-w-[120px] truncate">{row.scope}</TableCell>
                    <TableCell className="text-xs py-2.5 text-muted-foreground">{row.target}</TableCell>
                    <TableCell className="py-2.5"><StatusBadge status={row.status} /></TableCell>
                    <TableCell className="text-xs tabular-nums py-2.5 text-muted-foreground">{row.started}</TableCell>
                    <TableCell className="text-xs tabular-nums py-2.5 text-right font-bold">{row.findings || "—"}</TableCell>
                    <TableCell className="py-2.5 text-right">
                      <Button variant="outline" size="sm" className="h-6 px-2 text-[10px]" disabled={row.status !== "completed"}>
                        <Eye className="h-3 w-3 mr-1" /> View
                      </Button>
                    </TableCell>
                  </TableRow>
                )))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* MITRE ATT&CK Heatmap */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Shield className="h-4 w-4 text-blue-400" />
            MITRE ATT&CK Coverage
          </CardTitle>
          <CardDescription className="text-xs">
            Detection coverage by tactic — <span className="text-red-400">red &lt;50%</span>, <span className="text-amber-400">yellow 50-75%</span>, <span className="text-green-400">green &gt;75%</span>
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-4 gap-2 sm:grid-cols-6 lg:grid-cols-11">
            {MITRE_TACTICS.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                <p className="text-lg font-medium">No data available</p>
                <p className="text-sm">Data will appear here once available</p>
              </div>
            ) : (
              MITRE_TACTICS.map((t) => (
              <div
                key={t.tactic}
                )))}
                title={`${t.tactic}: ${t.pct}% coverage`}
              >
                <div className="text-[10px] font-semibold leading-tight mb-1">{t.short}</div>
                <div className="text-sm font-bold tabular-nums">{t.pct}%</div>
              </div>
            )))}
          </div>
        </CardContent>
      </Card>

      {/* Timeline + Finding Prioritization */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Attack Path Timeline */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Clock className="h-4 w-4 text-cyan-400" />
              Attack Path Timeline — Q2 Full BAS Run
            </CardTitle>
            <CardDescription className="text-xs">Step-by-step execution trace for the latest simulation</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="relative space-y-0">
              {TIMELINE.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                  <p className="text-lg font-medium">No data available</p>
                  <p className="text-sm">Data will appear here once available</p>
                </div>
              ) : (
                TIMELINE.map((event, idx) => (
                <div key={event.technique} className="flex gap-3">
                  {/* vertical line */}
                  <div className="flex flex-col items-center">
                    <div className={cn(
                      "w-2.5 h-2.5 rounded-full mt-1 shrink-0 border-2",
                      event.success ? "bg-red-500 border-red-400" : "bg-muted border-border"
                    )} />
                    {idx < TIMELINE.length - 1 && <div className="w-px flex-1 bg-border min-h-[24px]" />}
                  </div>
                  <div className="pb-4 flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <Badge className="text-[9px] border border-blue-500/30 text-blue-400 bg-blue-500/10">{event.tactic}</Badge>
                      <span className="text-[10px] font-mono text-muted-foreground">{event.technique}</span>
                      {event.success
                        ? <Badge className="text-[9px] border border-red-500/30 text-red-400 bg-red-500/10">success</Badge>
                        : <Badge className="text-[9px] border border-green-500/30 text-green-400 bg-green-500/10">blocked</Badge>}
                      {event.detected
                        ? <Badge className="text-[9px] border border-green-500/30 text-green-400 bg-green-500/10">detected {event.detectionTime}</Badge>
                        : <Badge className="text-[9px] border border-red-500/30 text-red-400 bg-red-500/10">undetected</Badge>}
                    </div>
                    <div className="text-[11px] text-muted-foreground mt-0.5">{event.name}</div>
                  </div>
                </div>
              )))}
            </div>
          </CardContent>
        </Card>

        {/* Finding Prioritization */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-amber-400" />
              Finding Prioritization
            </CardTitle>
            <CardDescription className="text-xs">Top findings by remediation priority — sorted by severity + dwell time</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">ID</TableHead>
                  <TableHead className="text-[11px] h-8">Sev</TableHead>
                  <TableHead className="text-[11px] h-8">Technique</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Dwell</TableHead>
                  <TableHead className="text-[11px] h-8">Detection</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {FINDINGS.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  FINDINGS.map((f) => (
                  <TableRow key={f.id} className="hover:bg-muted/30">
                    <TableCell className="text-[10px] font-mono py-2">{f.id}</TableCell>
                    <TableCell className="py-2"><SeverityBadge sev={f.severity} /></TableCell>
                    <TableCell className="text-[10px] font-mono py-2 text-muted-foreground">{f.technique}</TableCell>
                    <TableCell className={cn("text-xs tabular-nums py-2 text-right font-medium", parseFloat(f.dwellTime) >= 24 ? "text-red-400" : "text-muted-foreground")}>
                      {f.dwellTime}
                    </TableCell>
                    <TableCell className="py-2">
                      <Badge className={cn("text-[9px] border", f.detectionMethod === "none" ? "border-red-500/30 text-red-400 bg-red-500/10" : "border-border text-muted-foreground")}>
                        {f.detectionMethod}
                      </Badge>
                    </TableCell>
                  </TableRow>
                )))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </div>
    </motion.div>
  );
}
