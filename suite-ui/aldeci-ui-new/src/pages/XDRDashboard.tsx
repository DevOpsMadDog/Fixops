/**
 * XDR Dashboard
 *
 * Extended Detection & Response — cross-domain signal correlation and unified incident management.
 *   1. KPIs: Signals Today, Active Incidents, Critical Incidents, Auto-Correlated
 *   2. Incident command center (6 active incidents)
 *   3. Kill chain coverage heat (11 MITRE tactics)
 *   4. Signal stream (20 recent signals)
 *   5. Correlation rules (8 active rules)
 *
 * API stubs: GET /api/v1/xdr/incidents, /api/v1/xdr/signals, /api/v1/xdr/rules
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Shield, AlertTriangle, Zap, GitMerge, RefreshCw, Activity, Layers } from "lucide-react";

// ── API helpers ────────────────────────────────────────────────
const ORG_ID = "default";

function getApiKey() {
  return (
    (typeof window !== "undefined" && localStorage.getItem("aldeci_api_key")) ||
    import.meta.env.VITE_API_KEY ||
    "dev-key"
  );
}

async function apiFetch(path: string) {
  const res = await fetch(`/api/v1${path}`, {
    headers: { "X-API-Key": getApiKey() },
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

const INCIDENTS = [
  {
    id: "INC-2024-001", title: "APT29 Lateral Movement Campaign",
    attack_stage: "lateral_movement", severity: "critical",
    signal_count: 47, affected_entities: ["10.4.22.17", "10.4.30.5", "WINDC-01"],
    first_seen: "2026-04-16 12:14", status: "active",
  },
  {
    id: "INC-2024-002", title: "Credential Harvesting via Phishing",
    attack_stage: "initial_access", severity: "critical",
    signal_count: 23, affected_entities: ["user@corp.com", "10.0.1.44"],
    first_seen: "2026-04-16 10:58", status: "investigating",
  },
  {
    id: "INC-2024-003", title: "Ransomware Staging Detected",
    attack_stage: "impact", severity: "high",
    signal_count: 31, affected_entities: ["FS-SERVER-02", "192.168.1.44", "BACKUP-SRV"],
    first_seen: "2026-04-16 09:33", status: "active",
  },
  {
    id: "INC-2024-004", title: "Cloud IAM Privilege Escalation",
    attack_stage: "privilege_escalation", severity: "high",
    signal_count: 18, affected_entities: ["aws:arn:iam::441234", "admin-svc-acct"],
    first_seen: "2026-04-16 08:21", status: "investigating",
  },
  {
    id: "INC-2024-005", title: "C2 Beacon via DNS Tunneling",
    attack_stage: "command_and_control", severity: "high",
    signal_count: 12, affected_entities: ["10.2.8.14", "ns1.evil-c2.ru"],
    first_seen: "2026-04-16 07:44", status: "active",
  },
  {
    id: "INC-2024-006", title: "Data Exfiltration via HTTPS",
    attack_stage: "exfiltration", severity: "medium",
    signal_count: 9, affected_entities: ["192.168.1.44", "203.0.113.99"],
    first_seen: "2026-04-16 06:15", status: "contained",
  },
];

const KILL_CHAIN = [
  { tactic: "Initial Access",        tag: "TA0001", count: 4 },
  { tactic: "Execution",             tag: "TA0002", count: 2 },
  { tactic: "Persistence",           tag: "TA0003", count: 1 },
  { tactic: "Privilege Escalation",  tag: "TA0004", count: 3 },
  { tactic: "Defense Evasion",       tag: "TA0005", count: 1 },
  { tactic: "Credential Access",     tag: "TA0006", count: 2 },
  { tactic: "Discovery",             tag: "TA0007", count: 0 },
  { tactic: "Lateral Movement",      tag: "TA0008", count: 5 },
  { tactic: "Collection",            tag: "TA0009", count: 1 },
  { tactic: "Exfiltration",          tag: "TA0010", count: 2 },
  { tactic: "Impact",                tag: "TA0011", count: 3 },
];

const SIGNALS = [
  { id: "SIG-001", source_type: "endpoint",     signal_type: "process_injection",    entity_id: "WINDC-01",       confidence: 95, severity: "critical", ingested_at: "14:32:11" },
  { id: "SIG-002", source_type: "network",      signal_type: "c2_beacon",            entity_id: "10.4.22.17",     confidence: 91, severity: "critical", ingested_at: "14:31:44" },
  { id: "SIG-003", source_type: "identity",     signal_type: "brute_force",          entity_id: "admin@corp.com", confidence: 88, severity: "high",     ingested_at: "14:30:22" },
  { id: "SIG-004", source_type: "cloud",        signal_type: "iam_anomaly",          entity_id: "aws-role-447",   confidence: 84, severity: "high",     ingested_at: "14:29:10" },
  { id: "SIG-005", source_type: "email",        signal_type: "phishing_click",       entity_id: "user@corp.com",  confidence: 97, severity: "high",     ingested_at: "14:28:05" },
  { id: "SIG-006", source_type: "endpoint",     signal_type: "lsass_dump",           entity_id: "WORKST-047",     confidence: 93, severity: "critical", ingested_at: "14:27:30" },
  { id: "SIG-007", source_type: "network",      signal_type: "port_scan",            entity_id: "10.5.12.100",    confidence: 72, severity: "medium",   ingested_at: "14:26:55" },
  { id: "SIG-008", source_type: "threat_intel", signal_type: "ioc_match",            entity_id: "185.220.101.34", confidence: 99, severity: "critical", ingested_at: "14:26:01" },
  { id: "SIG-009", source_type: "application",  signal_type: "sqli_attempt",         entity_id: "api.corp.com",   confidence: 81, severity: "high",     ingested_at: "14:25:14" },
  { id: "SIG-010", source_type: "cloud",        signal_type: "unusual_geo_login",    entity_id: "devops@corp.com",confidence: 76, severity: "medium",   ingested_at: "14:24:40" },
  { id: "SIG-011", source_type: "endpoint",     signal_type: "ransomware_behavior",  entity_id: "FS-SERVER-02",   confidence: 94, severity: "critical", ingested_at: "14:23:18" },
  { id: "SIG-012", source_type: "network",      signal_type: "dns_tunneling",        entity_id: "10.2.8.14",      confidence: 87, severity: "high",     ingested_at: "14:22:55" },
  { id: "SIG-013", source_type: "identity",     signal_type: "privilege_escalation", entity_id: "svc-backup",     confidence: 89, severity: "high",     ingested_at: "14:22:01" },
  { id: "SIG-014", source_type: "email",        signal_type: "malicious_attachment", entity_id: "finance@corp.com",confidence: 96, severity: "high",    ingested_at: "14:21:30" },
  { id: "SIG-015", source_type: "application",  signal_type: "xss_attempt",          entity_id: "app.corp.com",   confidence: 65, severity: "medium",   ingested_at: "14:20:44" },
  { id: "SIG-016", source_type: "threat_intel", signal_type: "domain_dga",           entity_id: "xk93hz.biz",     confidence: 82, severity: "high",     ingested_at: "14:19:22" },
  { id: "SIG-017", source_type: "endpoint",     signal_type: "lateral_tool_transfer",entity_id: "WORKST-012",     confidence: 78, severity: "medium",   ingested_at: "14:18:11" },
  { id: "SIG-018", source_type: "cloud",        signal_type: "s3_bucket_exposed",    entity_id: "s3://prod-data", confidence: 99, severity: "high",     ingested_at: "14:17:00" },
  { id: "SIG-019", source_type: "network",      signal_type: "data_exfil",           entity_id: "192.168.1.44",   confidence: 85, severity: "high",     ingested_at: "14:15:55" },
  { id: "SIG-020", source_type: "application",  signal_type: "auth_bypass",          entity_id: "sso.corp.com",   confidence: 70, severity: "medium",   ingested_at: "14:14:33" },
];

const RULES = [
  { name: "Multi-Source Lateral Movement",      conditions: "endpoint∧network signals, same src within 5m", severity: "critical", mitre_tactic: "Lateral Movement",       enabled: true },
  { name: "Credential Harvest + Exfil Chain",  conditions: "phishing_click → lsass_dump → data_exfil",     severity: "critical", mitre_tactic: "Credential Access",      enabled: true },
  { name: "IAM Anomaly + Cloud Data Access",   conditions: "iam_anomaly ∧ unusual_geo_login within 10m",   severity: "high",     mitre_tactic: "Privilege Escalation",   enabled: true },
  { name: "Ransomware Kill Chain",             conditions: "process_injection → file_encrypt → c2_beacon", severity: "critical", mitre_tactic: "Impact",                 enabled: true },
  { name: "DNS Tunneling + Beacon Combo",      conditions: "dns_tunneling ∧ c2_beacon same host",          severity: "high",     mitre_tactic: "Command & Control",      enabled: true },
  { name: "Brute Force → Privilege Escalation",conditions: "brute_force_success → priv_esc within 30m",   severity: "high",     mitre_tactic: "Privilege Escalation",   enabled: true },
  { name: "Insider Threat Exfiltration",       conditions: "large_upload ∧ off_hours ∧ new_dst_country",  severity: "medium",   mitre_tactic: "Exfiltration",           enabled: true },
  { name: "Supply Chain Compromise Indicator", conditions: "pkg_anomaly ∧ outbound_c2 ∧ ioc_match",       severity: "high",     mitre_tactic: "Initial Access",         enabled: false },
];

// ── Helpers ────────────────────────────────────────────────────

function StageBadge({ stage }: { stage: string }) {
  const map: Record<string, string> = {
    initial_access:        "border-blue-500/30 text-blue-400 bg-blue-500/10",
    execution:             "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
    persistence:           "border-teal-500/30 text-teal-400 bg-teal-500/10",
    privilege_escalation:  "border-purple-500/30 text-purple-400 bg-purple-500/10",
    defense_evasion:       "border-indigo-500/30 text-indigo-400 bg-indigo-500/10",
    credential_access:     "border-amber-500/30 text-amber-400 bg-amber-500/10",
    lateral_movement:      "border-orange-500/30 text-orange-400 bg-orange-500/10",
    command_and_control:   "border-rose-500/30 text-rose-400 bg-rose-500/10",
    exfiltration:          "border-red-400/30 text-red-300 bg-red-400/10",
    impact:                "border-red-500/30 text-red-400 bg-red-500/10",
  };
  const label = stage.replace(/_/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
  return <Badge className={cn("text-[10px] border", map[stage] ?? "border-border")}>{label}</Badge>;
}

function SeverityBadge({ sev }: { sev: string }) {
  const cls =
    sev === "critical" ? "border-red-500/30 text-red-400 bg-red-500/10" :
    sev === "high"     ? "border-amber-500/30 text-amber-400 bg-amber-500/10" :
    sev === "medium"   ? "border-yellow-500/30 text-yellow-400 bg-yellow-500/10" :
                         "border-border text-muted-foreground";
  return <Badge className={cn("text-[10px] border capitalize", cls)}>{sev}</Badge>;
}

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    active:        "border-red-500/30 text-red-400 bg-red-500/10",
    investigating: "border-amber-500/30 text-amber-400 bg-amber-500/10",
    contained:     "border-green-500/30 text-green-400 bg-green-500/10",
    closed:        "border-slate-500/30 text-slate-400 bg-slate-500/10",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border")}>{status}</Badge>;
}

function SourceBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    endpoint:     "border-blue-500/30 text-blue-400 bg-blue-500/10",
    network:      "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
    cloud:        "border-purple-500/30 text-purple-400 bg-purple-500/10",
    identity:     "border-indigo-500/30 text-indigo-400 bg-indigo-500/10",
    email:        "border-amber-500/30 text-amber-400 bg-amber-500/10",
    application:  "border-teal-500/30 text-teal-400 bg-teal-500/10",
    threat_intel: "border-red-500/30 text-red-400 bg-red-500/10",
  };
  return <Badge className={cn("text-[10px] border", map[type] ?? "border-border")}>{type.replace(/_/g, " ")}</Badge>;
}

function SevDot({ sev }: { sev: string }) {
  const cls = sev === "critical" ? "bg-red-500" : sev === "high" ? "bg-amber-500" : sev === "medium" ? "bg-yellow-400" : "bg-slate-400";
  return <span className={cn("inline-block h-2 w-2 rounded-full shrink-0", cls)} />;
}

function killChainColor(count: number) {
  if (count === 0) return "bg-muted/40 text-muted-foreground";
  if (count >= 3) return "bg-red-500/20 border-red-500/40 text-red-300";
  return "bg-amber-500/20 border-amber-500/40 text-amber-300";
}

// ── Component ──────────────────────────────────────────────────

export default function XDRDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);

  useEffect(() => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/xdr/stats?org_id=${ORG_ID}`),
      apiFetch(`/xdr/incidents?org_id=${ORG_ID}&limit=20`),
      apiFetch(`/xdr/signals?org_id=${ORG_ID}&limit=20`),
    ]).then(([statsResult, incidentsResult, signalsResult]) => {
      const stats     = statsResult.status     === "fulfilled" ? statsResult.value     : null;
      const incidents = incidentsResult.status === "fulfilled" ? incidentsResult.value : null;
      const signals   = signalsResult.status   === "fulfilled" ? signalsResult.value   : null;
      if (stats || incidents || signals) {
        setLiveData({ stats, incidents, signals });
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
        title="Extended Detection & Response"
        description="Cross-domain signal correlation and unified incident management"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Signals Today"     value={liveData?.stats?.total_incidents ?? liveData?.stats?.signals_today ?? "1,247"} icon={Activity}      trend="up"   />
        <KpiCard title="Active Incidents"  value={liveData?.stats?.active_incidents ?? 8}     icon={AlertTriangle} trend="up"   className="border-amber-500/20" />
        <KpiCard title="Mean Detect Time"  value={liveData?.stats?.mean_time_to_detect ?? 2}  icon={Shield}        trend="up"   className="border-red-500/20" />
        <KpiCard title="Auto-Correlated"   value={liveData?.stats?.alerts_correlated ?? 34}   icon={GitMerge}      trend="up"   className="border-purple-500/20" />
      </div>

      {/* Incident Command Center */}
      <Card className="border-red-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
              <Zap className="h-4 w-4" />
              Incident Command Center
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
              {(liveData?.incidents?.items ?? liveData?.incidents ?? INCIDENTS).filter((i: any) => i.status === "active").length} active
            </Badge>
          </div>
          <CardDescription className="text-xs">Active incidents with kill chain stage and signal counts</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">ID</TableHead>
                  <TableHead className="text-[11px] h-8">Title</TableHead>
                  <TableHead className="text-[11px] h-8">Stage</TableHead>
                  <TableHead className="text-[11px] h-8">Severity</TableHead>
                  <TableHead className="text-[11px] h-8">Signals</TableHead>
                  <TableHead className="text-[11px] h-8">Affected</TableHead>
                  <TableHead className="text-[11px] h-8">First Seen</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(liveData?.incidents?.items ?? liveData?.incidents ?? INCIDENTS).map((inc: any) => (
                  <TableRow key={inc.id} className="hover:bg-muted/30">
                    <TableCell className="py-2 text-xs font-mono text-muted-foreground">{inc.id}</TableCell>
                    <TableCell className="py-2 text-xs font-medium max-w-[200px] truncate">{inc.title}</TableCell>
                    <TableCell className="py-2"><StageBadge stage={inc.attack_stage} /></TableCell>
                    <TableCell className="py-2"><SeverityBadge sev={inc.severity} /></TableCell>
                    <TableCell className="py-2 text-xs tabular-nums font-bold text-amber-400">{inc.signal_count}</TableCell>
                    <TableCell className="py-2">
                      <div className="flex flex-wrap gap-1">
                        {inc.affected_entities.slice(0, 2).map((e: string) => (
                          <span key={e} className="font-mono text-[10px] bg-muted/40 px-1 py-0.5 rounded text-muted-foreground">{e}</span>
                        ))}
                        {inc.affected_entities.length > 2 && (
                          <span className="text-[10px] text-muted-foreground">+{inc.affected_entities.length - 2}</span>
                        )}
                      </div>
                    </TableCell>
                    <TableCell className="py-2 text-[11px] tabular-nums text-muted-foreground">{inc.first_seen}</TableCell>
                    <TableCell className="py-2"><StatusBadge status={inc.status} /></TableCell>
                    <TableCell className="py-2 text-right">
                      <Button variant="outline" size="sm" className="h-6 px-2 text-[10px] border-blue-500/30 text-blue-400 hover:bg-blue-500/10">
                        Investigate
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Kill Chain Heat + Correlation Rules */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Kill Chain Coverage Heat */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Layers className="h-4 w-4 text-orange-400" />
              MITRE Kill Chain Coverage
            </CardTitle>
            <CardDescription className="text-xs">Incident count per tactic — intensity indicates exposure</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-3 gap-2">
              {KILL_CHAIN.map((t) => (
                <motion.div
                  key={t.tag}
                  initial={{ opacity: 0, scale: 0.9 }}
                  animate={{ opacity: 1, scale: 1 }}
                  transition={{ duration: 0.3 }}
                  className={cn(
                    "rounded-lg border p-2.5 flex flex-col gap-1 cursor-default transition-colors",
                    killChainColor(t.count)
                  )}
                >
                  <div className="text-[10px] font-mono opacity-70">{t.tag}</div>
                  <div className="text-[11px] font-medium leading-tight">{t.tactic}</div>
                  <div className={cn("text-lg font-bold tabular-nums", t.count === 0 ? "text-muted-foreground" : t.count >= 3 ? "text-red-400" : "text-amber-400")}>
                    {t.count}
                  </div>
                </motion.div>
              ))}
            </div>
            <div className="flex items-center gap-4 mt-3 text-[10px] text-muted-foreground">
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-muted/40 inline-block border border-border" />None</span>
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-amber-500/20 inline-block border border-amber-500/40" />1-2</span>
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-red-500/20 inline-block border border-red-500/40" />3+</span>
            </div>
          </CardContent>
        </Card>

        {/* Correlation Rules */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <GitMerge className="h-4 w-4 text-purple-400" />
              Correlation Rules
            </CardTitle>
            <CardDescription className="text-xs">Active cross-domain detection rules</CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            {RULES.map((rule, i) => (
              <div key={i} className={cn("rounded-lg border bg-muted/20 p-3 space-y-1.5", !rule.enabled && "opacity-50")}>
                <div className="flex items-center justify-between gap-2">
                  <span className="text-xs font-semibold truncate">{rule.name}</span>
                  <div className="flex items-center gap-1.5 shrink-0">
                    <SeverityBadge sev={rule.severity} />
                    <span className={cn("h-1.5 w-1.5 rounded-full", rule.enabled ? "bg-green-500" : "bg-slate-500")} />
                  </div>
                </div>
                <div className="text-[10px] font-mono text-muted-foreground truncate">{rule.conditions}</div>
                <div className="text-[10px] text-blue-400">{rule.mitre_tactic}</div>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>

      {/* Signal Stream */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Activity className="h-4 w-4 text-cyan-400" />
              Signal Stream
            </CardTitle>
            <Badge className="text-[10px] border border-cyan-500/30 text-cyan-400 bg-cyan-500/10">Live</Badge>
          </div>
          <CardDescription className="text-xs">Most recent cross-domain telemetry signals</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8 w-4"></TableHead>
                  <TableHead className="text-[11px] h-8">Source</TableHead>
                  <TableHead className="text-[11px] h-8">Signal Type</TableHead>
                  <TableHead className="text-[11px] h-8">Entity</TableHead>
                  <TableHead className="text-[11px] h-8 min-w-[100px]">Confidence</TableHead>
                  <TableHead className="text-[11px] h-8">Time</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(liveData?.signals?.items ?? liveData?.signals ?? SIGNALS).map((s: any) => (
                  <TableRow key={s.id} className="hover:bg-muted/30">
                    <TableCell className="py-2"><SevDot sev={s.severity} /></TableCell>
                    <TableCell className="py-2"><SourceBadge type={s.source_type} /></TableCell>
                    <TableCell className="py-2 text-xs text-muted-foreground">{s.signal_type.replace(/_/g, " ")}</TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-foreground max-w-[140px] truncate">{s.entity_id}</TableCell>
                    <TableCell className="py-2">
                      <div className="flex items-center gap-2">
                        <div className="relative h-1.5 w-20 rounded-full bg-muted/30 overflow-hidden">
                          <div
                            className={cn("h-full rounded-full", s.confidence >= 90 ? "bg-red-500" : s.confidence >= 75 ? "bg-amber-500" : "bg-green-500")}
                            style={{ width: `${s.confidence}%` }}
                          />
                        </div>
                        <span className="text-[11px] tabular-nums text-muted-foreground">{s.confidence}%</span>
                      </div>
                    </TableCell>
                    <TableCell className="py-2 text-[11px] tabular-nums text-muted-foreground">{s.ingested_at}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
