/**
 * Threat Hunting Dashboard
 *
 * Proactive hunt campaigns, queries, and findings.
 *   1. KPIs: Active Hunts, Total Findings, Critical Findings, Queries Run
 *   2. Active campaigns table (8 rows)
 *   3. Query runner panel (6 queries)
 *   4. Findings table (10 rows)
 *   5. Hunt playbooks (4 cards)
 *
 * API stubs: GET /api/v1/threat-hunting/campaigns, /api/v1/threat-hunting/queries, /api/v1/threat-hunting/findings
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Crosshair, AlertTriangle, Search, Play, RefreshCw, BookOpen, BarChart3, Shield } from "lucide-react";

// ── API helpers ────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";
const ORG_ID = "aldeci-demo";

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

const CAMPAIGNS = [
  { id: "HNT-001", name: "Lateral Movement via SMB", hunt_type: "lateral_movement", mitre_tactic: "TA0008", analyst: "A. Torres", status: "active",    start: "2026-04-10", findings: 6 },
  { id: "HNT-002", name: "PowerShell Encoded Cmds",  hunt_type: "behavior_pattern", mitre_tactic: "TA0002", analyst: "J. Park",   status: "active",    start: "2026-04-11", findings: 12 },
  { id: "HNT-003", name: "C2 Beacon Detection",      hunt_type: "ioc_match",        mitre_tactic: "TA0011", analyst: "M. Chen",   status: "active",    start: "2026-04-12", findings: 3 },
  { id: "HNT-004", name: "Data Exfil via DNS",        hunt_type: "exfiltration",     mitre_tactic: "TA0010", analyst: "S. Lee",    status: "paused",    start: "2026-04-09", findings: 7 },
  { id: "HNT-005", name: "Anomalous Auth Patterns",  hunt_type: "anomaly_correlation", mitre_tactic: "TA0006", analyst: "R. Gupta", status: "active", start: "2026-04-13", findings: 9 },
  { id: "HNT-006", name: "Ransomware Precursors",     hunt_type: "behavior_pattern", mitre_tactic: "TA0040", analyst: "A. Torres", status: "completed", start: "2026-04-08", findings: 4 },
  { id: "HNT-007", name: "Supply Chain Implants",    hunt_type: "ioc_match",        mitre_tactic: "TA0001", analyst: "J. Park",   status: "active",    start: "2026-04-14", findings: 1 },
  { id: "HNT-008", name: "Credential Dumping Signs", hunt_type: "behavior_pattern", mitre_tactic: "TA0006", analyst: "M. Chen",   status: "active",    start: "2026-04-15", findings: 1 },
];

const QUERIES = [
  { id: "QRY-01", name: "Mimikatz Lsass Access",      query_type: "KQL",   data_source: "Windows Events", last_run: "5m ago",  hits: 3,  max_hits: 20 },
  { id: "QRY-02", name: "SMB Lateral Spread Pattern", query_type: "SPL",   data_source: "NetFlow",        last_run: "12m ago", hits: 11, max_hits: 20 },
  { id: "QRY-03", name: "YARA C2 Beacon Signatures",  query_type: "YARA",  data_source: "EDR Telemetry",  last_run: "1h ago",  hits: 7,  max_hits: 20 },
  { id: "QRY-04", name: "EQL Process Injection",      query_type: "EQL",   data_source: "Sysmon",         last_run: "2h ago",  hits: 2,  max_hits: 20 },
  { id: "QRY-05", name: "SIGMA Suspicious Reg Keys",  query_type: "SIGMA", data_source: "Windows Events", last_run: "4h ago",  hits: 5,  max_hits: 20 },
  { id: "QRY-06", name: "DNS Exfil Entropy Check",    query_type: "KQL",   data_source: "DNS Logs",       last_run: "6h ago",  hits: 0,  max_hits: 20 },
];

const FINDINGS = [
  { id: "FND-H001", sev: "Critical", title: "Lsass dumped via procdump",        campaign: "HNT-002", iocs: 4,  assets: 2,  escalated: true  },
  { id: "FND-H002", sev: "Critical", title: "Encoded PS downloader detected",   campaign: "HNT-002", iocs: 6,  assets: 3,  escalated: true  },
  { id: "FND-H003", sev: "High",     title: "SMB pass-the-hash attempt",        campaign: "HNT-001", iocs: 2,  assets: 5,  escalated: false },
  { id: "FND-H004", sev: "High",     title: "Cobalt Strike beacon pattern",     campaign: "HNT-003", iocs: 8,  assets: 1,  escalated: true  },
  { id: "FND-H005", sev: "High",     title: "Anomalous admin logon 03:00 UTC",  campaign: "HNT-005", iocs: 1,  assets: 4,  escalated: false },
  { id: "FND-H006", sev: "High",     title: "Large DNS TXT record exfil",       campaign: "HNT-004", iocs: 3,  assets: 2,  escalated: false },
  { id: "FND-H007", sev: "Medium",   title: "Unusual svchost network outbound", campaign: "HNT-005", iocs: 2,  assets: 6,  escalated: false },
  { id: "FND-H008", sev: "Medium",   title: "Scheduled task persistence",       campaign: "HNT-006", iocs: 1,  assets: 3,  escalated: false },
  { id: "FND-H009", sev: "Medium",   title: "WMI lateral movement to DC",       campaign: "HNT-001", iocs: 3,  assets: 1,  escalated: false },
  { id: "FND-H010", sev: "Low",      title: "Dev tool proxy bypass attempt",    campaign: "HNT-007", iocs: 1,  assets: 1,  escalated: false },
];

const PLAYBOOKS = [
  { id: "PB-01", hunt_type: "lateral_movement", title: "East-West Lateral Hunt", steps: 8,  techniques: ["T1021.002", "T1550.002", "T1076"] },
  { id: "PB-02", hunt_type: "exfiltration",     title: "DNS Exfil Detection",    steps: 6,  techniques: ["T1048.003", "T1071.004"] },
  { id: "PB-03", hunt_type: "behavior_pattern", title: "Living Off the Land",    steps: 10, techniques: ["T1059.001", "T1218", "T1047"] },
  { id: "PB-04", hunt_type: "ioc_match",        title: "IOC Sweep & Enrich",     steps: 5,  techniques: ["T1566", "T1203", "T1190"] },
];

// ── Helpers ────────────────────────────────────────────────────

function HuntTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    ioc_match:           "border-blue-500/30 text-blue-400 bg-blue-500/10",
    behavior_pattern:    "border-purple-500/30 text-purple-400 bg-purple-500/10",
    lateral_movement:    "border-orange-500/30 text-orange-400 bg-orange-500/10",
    exfiltration:        "border-red-500/30 text-red-400 bg-red-500/10",
    anomaly_correlation: "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
  };
  return <Badge className={cn("text-[10px] border", map[type] ?? "border-border text-muted-foreground")}>{type.replace(/_/g, " ")}</Badge>;
}

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    active:    "border-green-500/30 text-green-400 bg-green-500/10",
    paused:    "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    completed: "border-muted text-muted-foreground",
  };
  return <Badge className={cn("text-[10px] border", map[status] ?? "border-border text-muted-foreground")}>{status}</Badge>;
}

function QueryTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    KQL:   "border-blue-500/30 text-blue-400 bg-blue-500/10",
    SPL:   "border-indigo-500/30 text-indigo-400 bg-indigo-500/10",
    EQL:   "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
    SIGMA: "border-purple-500/30 text-purple-400 bg-purple-500/10",
    YARA:  "border-amber-500/30 text-amber-400 bg-amber-500/10",
  };
  return <Badge className={cn("text-[10px] border font-mono", map[type] ?? "border-border text-muted-foreground")}>{type}</Badge>;
}

function SevDot({ sev }: { sev: string }) {
  const cls =
    sev === "Critical" ? "bg-red-500" :
    sev === "High"     ? "bg-amber-500" :
    sev === "Medium"   ? "bg-yellow-400" : "bg-green-500";
  return <span className={cn("inline-block w-2 h-2 rounded-full shrink-0", cls)} title={sev} />;
}

// ── Component ──────────────────────────────────────────────────

export default function ThreatHuntingDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);

  useEffect(() => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/threat-hunting/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/threat-hunting/hunts?org_id=${ORG_ID}&limit=20`),
    ]).then(([statsResult, huntsResult]) => {
      const stats = statsResult.status === "fulfilled" ? statsResult.value : null;
      const hunts = huntsResult.status === "fulfilled" ? huntsResult.value : null;
      if (stats || hunts) {
        setLiveData({ stats, sessions: hunts });
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
      {/* Header */}
      <PageHeader
        title="Threat Hunting"
        description="Proactive hunt campaigns, queries, and findings"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Active Hunts"     value={liveData?.stats?.active_sessions ?? liveData?.stats?.active_hunts ?? liveData?.stats?.hunt_count ?? 7}   icon={Crosshair}     trend="up"   className="border-blue-500/20" />
        <KpiCard title="Total Findings"   value={liveData?.stats?.total_findings ?? liveData?.stats?.findings ?? 43}  icon={Search}        trend="up"   className="border-amber-500/20" />
        <KpiCard title="Critical Findings" value={liveData?.stats?.critical_findings ?? 8}  icon={AlertTriangle} trend="up"   className="border-red-500/20" />
        <KpiCard title="Queries Run"      value={liveData?.stats?.queries_run ?? liveData?.queries?.length ?? 284} icon={BarChart3}     trend="up" />
      </div>

      {/* Active Campaigns */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Crosshair className="h-4 w-4 text-blue-400" />
              Active Campaigns
            </CardTitle>
            <Button variant="outline" size="sm" className="h-7 text-xs">New Hunt</Button>
          </div>
          <CardDescription className="text-xs">Current hunt operations by analyst and MITRE tactic</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">ID</TableHead>
                  <TableHead className="text-[11px] h-8">Campaign Name</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">MITRE Tactic</TableHead>
                  <TableHead className="text-[11px] h-8">Analyst</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8">Started</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Findings</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(liveData?.sessions?.items ?? liveData?.sessions ?? CAMPAIGNS).map((row: any) => (
                  <TableRow key={row.id} className="hover:bg-muted/30">
                    <TableCell className="text-xs font-mono py-2.5">{row.id}</TableCell>
                    <TableCell className="text-xs py-2.5 max-w-[180px] truncate font-medium">{row.name}</TableCell>
                    <TableCell className="py-2.5"><HuntTypeBadge type={row.hunt_type} /></TableCell>
                    <TableCell className="text-xs py-2.5 font-mono text-muted-foreground">{row.mitre_tactic}</TableCell>
                    <TableCell className="text-xs py-2.5 text-muted-foreground">{row.analyst}</TableCell>
                    <TableCell className="py-2.5"><StatusBadge status={row.status} /></TableCell>
                    <TableCell className="text-xs py-2.5 tabular-nums text-muted-foreground">{row.start}</TableCell>
                    <TableCell className="text-xs py-2.5 text-right font-bold">
                      <span className={row.findings > 5 ? "text-amber-400" : "text-muted-foreground"}>{row.findings}</span>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Query Runner */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Search className="h-4 w-4 text-purple-400" />
            Query Runner
          </CardTitle>
          <CardDescription className="text-xs">Saved hunt queries across KQL, SPL, EQL, SIGMA, YARA</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          {QUERIES.map((q) => (
            <div key={q.id} className="flex items-center gap-3 rounded-lg border border-border/50 bg-muted/20 p-3">
              <QueryTypeBadge type={q.query_type} />
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 mb-1">
                  <span className="text-xs font-medium truncate">{q.name}</span>
                  <span className="text-[10px] text-muted-foreground shrink-0">{q.data_source}</span>
                </div>
                <div className="flex items-center gap-2">
                  <div className="flex-1 h-1.5 rounded-full bg-muted/40 overflow-hidden">
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${(q.hits / q.max_hits) * 100}%` }}
                      transition={{ duration: 0.7, ease: "easeOut" }}
                      className={cn("h-full rounded-full", q.hits > 5 ? "bg-amber-500" : q.hits > 0 ? "bg-blue-500" : "bg-muted")}
                    />
                  </div>
                  <span className="text-[10px] tabular-nums text-muted-foreground w-12 text-right">{q.hits} hits</span>
                  <span className="text-[10px] text-muted-foreground">{q.last_run}</span>
                </div>
              </div>
              <Button variant="outline" size="sm" className="h-7 px-3 text-xs shrink-0">
                <Play className="h-3 w-3 mr-1" />Run
              </Button>
            </div>
          ))}
        </CardContent>
      </Card>

      {/* Findings table + Playbooks */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        {/* Findings — takes 2 cols */}
        <Card className="lg:col-span-2">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 text-amber-400" />
                Hunt Findings
              </CardTitle>
              <Badge className="text-[10px] border border-amber-500/30 text-amber-400 bg-amber-500/10">
                {FINDINGS.length} findings
              </Badge>
            </div>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8 w-6" />
                    <TableHead className="text-[11px] h-8">Finding</TableHead>
                    <TableHead className="text-[11px] h-8">Campaign</TableHead>
                    <TableHead className="text-[11px] h-8">IOCs</TableHead>
                    <TableHead className="text-[11px] h-8">Assets</TableHead>
                    <TableHead className="text-[11px] h-8">Escalated</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(liveData?.findings?.items ?? liveData?.findings ?? FINDINGS).map((row: any) => (
                    <TableRow key={row.id} className="hover:bg-muted/30">
                      <TableCell className="py-2.5 pl-4"><SevDot sev={row.sev} /></TableCell>
                      <TableCell className="text-xs py-2.5 max-w-[200px] truncate font-medium">{row.title}</TableCell>
                      <TableCell className="text-xs py-2.5 font-mono text-muted-foreground">{row.campaign}</TableCell>
                      <TableCell className="py-2.5">
                        <Badge className="text-[10px] border border-border text-muted-foreground">{row.iocs} IOCs</Badge>
                      </TableCell>
                      <TableCell className="text-xs py-2.5 text-muted-foreground">{row.assets}</TableCell>
                      <TableCell className="py-2.5">
                        {row.escalated
                          ? <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">Escalated</Badge>
                          : <span className="text-[10px] text-muted-foreground">—</span>}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>

        {/* Hunt Playbooks */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <BookOpen className="h-4 w-4 text-indigo-400" />
              Hunt Playbooks
            </CardTitle>
            <CardDescription className="text-xs">Reusable hunting procedures</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {PLAYBOOKS.map((pb) => (
              <div key={pb.id} className="rounded-lg border border-border/50 bg-muted/20 p-3 space-y-2">
                <div className="flex items-start justify-between gap-2">
                  <span className="text-xs font-medium leading-tight">{pb.title}</span>
                  <Badge className="text-[10px] border border-border text-muted-foreground shrink-0">{pb.steps} steps</Badge>
                </div>
                <HuntTypeBadge type={pb.hunt_type} />
                <div className="flex flex-wrap gap-1 mt-1">
                  {pb.techniques.map((t) => (
                    <span key={t} className="text-[9px] font-mono bg-muted/40 rounded px-1.5 py-0.5 text-muted-foreground">{t}</span>
                  ))}
                </div>
                <Button variant="outline" size="sm" className="h-6 px-2 text-[10px] w-full mt-1">
                  <Shield className="h-3 w-3 mr-1" />Run Playbook
                </Button>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
    </motion.div>
  );
}
