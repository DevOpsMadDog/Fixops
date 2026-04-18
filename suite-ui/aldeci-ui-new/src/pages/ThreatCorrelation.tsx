/**
 * Threat Correlation Engine
 *
 * Cross-event pattern detection and alert correlation.
 *   1. KPIs: Active Rules, Events Ingested, Correlated Alerts, Auto-Closed %
 *   2. Correlation rules table (10 rows)
 *   3. Correlated alerts table (12 rows)
 *   4. Event stream feed (15 recent events)
 *   5. Detection timeline: 24-hour bar chart
 *
 * API stubs: GET /api/v1/correlation/rules, /api/v1/correlation/alerts, /api/v1/correlation/events
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { GitMerge, Zap, Bell, BarChart3, RefreshCw, Radio } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";
// ── API config ─────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "dev-key";
const ORG_ID = "default";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "X-API-Key": API_KEY },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ── Mock data ──────────────────────────────────────────────────

const RULES = [
  { name: "Brute Force Login",        events: ["auth_failure", "account_lockout"],           window: "5 min",  threshold: 10, severity: "High",     enabled: true,  hits: 14 },
  { name: "Lateral Movement",         events: ["rdp_login", "smb_access", "wmi_exec"],       window: "15 min", threshold: 3,  severity: "Critical", enabled: true,  hits: 3  },
  { name: "Data Exfiltration",        events: ["large_upload", "dns_tunnel"],                window: "10 min", threshold: 2,  severity: "Critical", enabled: true,  hits: 1  },
  { name: "Privilege Escalation",     events: ["sudo_usage", "token_impersonation"],         window: "2 min",  threshold: 2,  severity: "High",     enabled: true,  hits: 5  },
  { name: "C2 Beacon Pattern",        events: ["periodic_dns", "periodic_http"],             window: "1 hour", threshold: 5,  severity: "Critical", enabled: true,  hits: 2  },
  { name: "Credential Dumping",       events: ["lsass_access", "reg_export"],               window: "1 min",  threshold: 1,  severity: "Critical", enabled: false, hits: 0  },
  { name: "Recon Activity",           events: ["port_scan", "dns_enum", "ldap_query"],      window: "30 min", threshold: 20, severity: "Medium",   enabled: true,  hits: 8  },
  { name: "Impossible Travel",        events: ["geo_login_a", "geo_login_b"],               window: "1 hour", threshold: 2,  severity: "High",     enabled: true,  hits: 2  },
  { name: "Insider Threat Pattern",   events: ["off_hours_access", "bulk_download"],        window: "4 hours",threshold: 2,  severity: "Medium",   enabled: true,  hits: 4  },
  { name: "Supply Chain Indicator",   events: ["unsigned_binary", "unusual_parent"],        window: "5 min",  threshold: 1,  severity: "High",     enabled: true,  hits: 1  },
];

const ALERTS = [
  { id: "COR-2041", rule: "Brute Force Login",       matched: 23, severity: "High",     status: "Investigating", created: "2m ago"   },
  { id: "COR-2040", rule: "Lateral Movement",         matched: 5,  severity: "Critical", status: "Open",          created: "8m ago"   },
  { id: "COR-2039", rule: "Recon Activity",           matched: 31, severity: "Medium",   status: "Closed",        created: "14m ago"  },
  { id: "COR-2038", rule: "Insider Threat Pattern",   matched: 4,  severity: "Medium",   status: "Investigating", created: "22m ago"  },
  { id: "COR-2037", rule: "Privilege Escalation",     matched: 3,  severity: "High",     status: "Open",          created: "35m ago"  },
  { id: "COR-2036", rule: "Impossible Travel",        matched: 2,  severity: "High",     status: "Closed",        created: "41m ago"  },
  { id: "COR-2035", rule: "C2 Beacon Pattern",        matched: 7,  severity: "Critical", status: "Investigating", created: "58m ago"  },
  { id: "COR-2034", rule: "Data Exfiltration",        matched: 2,  severity: "Critical", status: "Open",          created: "1h ago"   },
  { id: "COR-2033", rule: "Supply Chain Indicator",   matched: 1,  severity: "High",     status: "Closed",        created: "1h 20m ago" },
  { id: "COR-2032", rule: "Brute Force Login",        matched: 18, severity: "High",     status: "Closed",        created: "2h ago"   },
  { id: "COR-2031", rule: "Recon Activity",           matched: 26, severity: "Medium",   status: "Closed",        created: "2h 30m ago" },
  { id: "COR-2030", rule: "Insider Threat Pattern",   matched: 3,  severity: "Medium",   status: "Closed",        created: "3h ago"   },
];

const EVENT_STREAM = [
  { type: "auth_failure",    source_ip: "192.168.4.82",   user_id: "jsmith",   asset: "srv-auth-01",  ts: "5s ago",  severity: "high"   },
  { type: "port_scan",       source_ip: "10.0.2.45",      user_id: "—",        asset: "net-edge",     ts: "12s ago", severity: "medium" },
  { type: "rdp_login",       source_ip: "172.16.8.22",    user_id: "bwilson",  asset: "ws-finance-3", ts: "28s ago", severity: "high"   },
  { type: "large_upload",    source_ip: "10.1.5.14",      user_id: "mlee",     asset: "s3-bucket-01", ts: "45s ago", severity: "critical"},
  { type: "sudo_usage",      source_ip: "10.0.3.99",      user_id: "devops1",  asset: "k8s-node-02",  ts: "1m ago",  severity: "medium" },
  { type: "dns_query",       source_ip: "192.168.2.11",   user_id: "—",        asset: "workstation",  ts: "1m ago",  severity: "low"    },
  { type: "lsass_access",    source_ip: "10.0.1.7",       user_id: "SYSTEM",   asset: "dc-01",        ts: "2m ago",  severity: "critical"},
  { type: "bulk_download",   source_ip: "10.2.4.55",      user_id: "agarcia",  asset: "nas-01",       ts: "2m ago",  severity: "high"   },
  { type: "geo_login",       source_ip: "185.234.12.66",  user_id: "cthomas",  asset: "vpn-gw",       ts: "3m ago",  severity: "high"   },
  { type: "wmi_exec",        source_ip: "172.16.3.44",    user_id: "ADMIN",    asset: "srv-db-02",    ts: "3m ago",  severity: "critical"},
  { type: "reg_export",      source_ip: "10.0.1.7",       user_id: "SYSTEM",   asset: "dc-01",        ts: "4m ago",  severity: "high"   },
  { type: "smb_access",      source_ip: "172.16.8.22",    user_id: "bwilson",  asset: "srv-files",    ts: "4m ago",  severity: "medium" },
  { type: "periodic_dns",    source_ip: "10.3.2.88",      user_id: "—",        asset: "workstation",  ts: "5m ago",  severity: "medium" },
  { type: "off_hrs_access",  source_ip: "10.0.4.21",      user_id: "rjones",   asset: "crm-app",      ts: "6m ago",  severity: "medium" },
  { type: "unsigned_binary", source_ip: "10.1.1.9",       user_id: "SYSTEM",   asset: "srv-build",    ts: "7m ago",  severity: "high"   },
];

// 24-hour bar chart data: events and correlated alerts per hour
const TIMELINE = Array.from({ length: 24 }, (_, i) => ({
  hour: i,
  events: Math.floor(Math.random() * 600 + 100),
  correlated: Math.floor(Math.random() * 8),
})).map((d, i) => {
  // deterministic pattern — spikes at certain hours
  const spike = [2, 3, 9, 10, 14, 15, 21, 22].includes(i);
  return { ...d, events: spike ? d.events + 400 : d.events, correlated: spike ? d.correlated + 5 : d.correlated };
});
const MAX_EVENTS = Math.max(...TIMELINE.map((d) => d.events));

// ── Helpers ────────────────────────────────────────────────────

function SeverityBadge({ sev }: { sev: string }) {
  const s = sev.toLowerCase();
  const cls =
    s === "critical" ? "border-red-500/30 text-red-400 bg-red-500/10" :
    s === "high"     ? "border-amber-500/30 text-amber-400 bg-amber-500/10" :
    s === "medium"   ? "border-yellow-500/30 text-yellow-400 bg-yellow-500/10" :
                       "border-border text-muted-foreground bg-muted/20";
  return <Badge className={cn("text-[10px] border capitalize", cls)}>{sev}</Badge>;
}

function StatusBadge({ status }: { status: string }) {
  const cls =
    status === "Open"          ? "border-red-500/30 text-red-400 bg-red-500/10" :
    status === "Investigating" ? "border-blue-500/30 text-blue-400 bg-blue-500/10" :
                                 "border-green-500/30 text-green-400 bg-green-500/10";
  return <Badge className={cn("text-[10px] border", cls)}>{status}</Badge>;
}

function SeverityDot({ sev }: { sev: string }) {
  const cls =
    sev === "critical" ? "bg-red-500" :
    sev === "high"     ? "bg-amber-500" :
    sev === "medium"   ? "bg-yellow-500" : "bg-green-500";
  return <span className={cn("inline-block w-2 h-2 rounded-full flex-shrink-0", cls)} />;
}

// ── Component ──────────────────────────────────────────────────

export default function ThreatCorrelation() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);

  const fetchAll = () =>
    Promise.allSettled([
      apiFetch(`/api/v1/incident-timeline/events?org_id=${ORG_ID}&limit=50`),
      apiFetch(`/api/v1/threat-feeds/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/threat-correlation/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/threat-correlation/rules?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/threat-sharing/stats`),
      apiFetch(`/api/v1/threat-sharing/indicators`),
    ]).then(([incidentEventsRes, feedStatsRes, statsRes, rulesRes, sharingStatsRes, indicatorsRes]) => {
      const incidents     = incidentEventsRes.status === "fulfilled" ? incidentEventsRes.value : null;
      const feedStats     = feedStatsRes.status      === "fulfilled" ? feedStatsRes.value      : null;
      const stats         = statsRes.status          === "fulfilled" ? statsRes.value          : null;
      const rules         = rulesRes.status          === "fulfilled" ? rulesRes.value          : null;
      const sharingStats  = sharingStatsRes.status   === "fulfilled" ? sharingStatsRes.value   : null;
      const indicators    = indicatorsRes.status     === "fulfilled" ? indicatorsRes.value     : null;
      // Merge feed stats into correlation stats for KPI display
      const mergedStats = stats ?? (feedStats ? { total_events: feedStats.total_feeds ?? feedStats.total_indicators, active_rules: feedStats.active_feeds } : null);
      if (incidents || feedStats || stats || rules || sharingStats || indicators) {
        setLiveData({ stats: mergedStats, rules, incidents: incidents ? { incidents: Array.isArray(incidents) ? incidents : [] } : null, signals: null, sharingStats, groups: null, indicators });
      }
    });

  useEffect(() => {
    setDataLoading(true);
    fetchAll().finally(() => setDataLoading(false));
  }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    setDataLoading(true);
    fetchAll().finally(() => { setRefreshing(false); setDataLoading(false); });
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
        title="Threat Correlation Engine"
        description="Cross-event pattern detection and alert correlation"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Active Rules"          value={liveData?.stats?.active_rules ?? liveData?.stats?.total_rules ?? 34}           icon={GitMerge} />
        <KpiCard title="Events Ingested Today" value={liveData?.stats?.total_events ?? liveData?.stats?.events_ingested ?? "8,247"} icon={Zap}       trend="up" />
        <KpiCard title="Correlated Alerts"     value={liveData?.stats?.total_alerts ?? liveData?.stats?.correlated_alerts ?? 23}    icon={Bell}      trend="up" className="border-amber-500/20" />
        <KpiCard title="Auto-Closed"           value={liveData?.stats?.auto_closed_pct ?? liveData?.stats?.auto_closed ?? "71.3%"} icon={BarChart3}  trend="up" className="border-green-500/20" />
      </div>

      {/* Correlation rules table */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <GitMerge className="h-4 w-4 text-purple-400" />
            Correlation Rules
          </CardTitle>
          <CardDescription className="text-xs">Active detection rules and hit counts for today</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Rule Name</TableHead>
                  <TableHead className="text-[11px] h-8">Event Types</TableHead>
                  <TableHead className="text-[11px] h-8">Window</TableHead>
                  <TableHead className="text-[11px] h-8">Threshold</TableHead>
                  <TableHead className="text-[11px] h-8">Severity</TableHead>
                  <TableHead className="text-[11px] h-8">Enabled</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Hits Today</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(liveData?.rules?.rules ?? RULES).map((rule: any) => (
                  <TableRow key={rule.name} className="hover:bg-muted/30">
                    <TableCell className="text-xs font-medium py-2.5">{rule.name}</TableCell>
                    <TableCell className="py-2.5 max-w-[220px]">
                      <div className="flex flex-wrap gap-1">
                        {(rule.event_types ?? rule.events ?? []).map((e: string) => (
                          <Badge key={e} className="text-[9px] border border-border bg-muted/30 text-muted-foreground px-1 py-0">{e}</Badge>
                        ))}
                      </div>
                    </TableCell>
                    <TableCell className="text-xs tabular-nums py-2.5 text-muted-foreground">
                      {rule.window ?? (rule.time_window_minutes != null ? `${rule.time_window_minutes} min` : "—")}
                    </TableCell>
                    <TableCell className="text-xs tabular-nums py-2.5">{rule.threshold}</TableCell>
                    <TableCell className="py-2.5"><SeverityBadge sev={rule.severity} /></TableCell>
                    <TableCell className="py-2.5">
                      <span className={cn("text-[10px] font-medium", rule.enabled ? "text-green-400" : "text-muted-foreground")}>
                        {rule.enabled ? "On" : "Off"}
                      </span>
                    </TableCell>
                    <TableCell className="text-xs tabular-nums py-2.5 text-right font-bold">{rule.hits ?? rule.hit_count ?? 0}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Correlated alerts table */}
      <Card className="border-amber-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <Bell className="h-4 w-4 text-amber-400" />
                Correlated Alerts
              </CardTitle>
              <CardDescription className="text-xs">Multi-event alerts grouped by triggered rule</CardDescription>
            </div>
            <Badge className="text-[10px] border border-amber-500/30 text-amber-400 bg-amber-500/10">{(liveData?.incidents?.incidents ?? ALERTS).length} alerts</Badge>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Alert ID</TableHead>
                  <TableHead className="text-[11px] h-8">Rule Triggered</TableHead>
                  <TableHead className="text-[11px] h-8">Matched Events</TableHead>
                  <TableHead className="text-[11px] h-8">Severity</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8">Created</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(liveData?.incidents?.incidents ?? ALERTS).map((alert: any) => (
                  <TableRow key={alert.id} className="hover:bg-muted/30">
                    <TableCell className="text-xs font-mono py-2.5">{alert.id}</TableCell>
                    <TableCell className="text-xs py-2.5 max-w-[160px] truncate">{alert.rule ?? alert.rule_name ?? alert.correlation_rule_id}</TableCell>
                    <TableCell className="text-xs tabular-nums py-2.5 font-bold">{alert.matched ?? alert.matched_events ?? alert.event_count ?? 0}</TableCell>
                    <TableCell className="py-2.5"><SeverityBadge sev={alert.severity} /></TableCell>
                    <TableCell className="py-2.5"><StatusBadge status={alert.status} /></TableCell>
                    <TableCell className="text-xs py-2.5 text-muted-foreground tabular-nums">{alert.created ?? alert.created_at}</TableCell>
                    <TableCell className="py-2.5 text-right">
                      <Button variant="outline" size="sm" className="h-6 px-2 text-[10px]">
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

      {/* Event stream + Detection timeline */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Event stream feed */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Radio className="h-4 w-4 text-green-400 animate-pulse" />
              Live Event Stream
            </CardTitle>
            <CardDescription className="text-xs">Last 15 ingested security events</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <div className="divide-y divide-border/40">
              {(liveData?.signals?.signals ?? EVENT_STREAM).map((ev: any, i: number) => (
                <div key={i} className="flex items-center gap-2 px-4 py-2 hover:bg-muted/20 transition-colors">
                  <SeverityDot sev={ev.severity ?? "low"} />
                  <Badge className="text-[9px] border border-border bg-muted/30 text-muted-foreground px-1 py-0 shrink-0 max-w-[100px] truncate">
                    {ev.type ?? ev.event_type}
                  </Badge>
                  <span className="text-[10px] font-mono text-muted-foreground w-28 shrink-0 truncate">{ev.source_ip}</span>
                  <span className="text-[10px] truncate flex-1 text-muted-foreground">{ev.user_id ?? ev.raw_data?.user_id ?? "—"} / {ev.asset ?? ev.asset_id ?? "—"}</span>
                  <span className="text-[10px] text-muted-foreground shrink-0">{ev.ts ?? ev.timestamp}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* Detection timeline — 24h bar chart */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <BarChart3 className="h-4 w-4 text-blue-400" />
              24-Hour Detection Timeline
            </CardTitle>
            <CardDescription className="text-xs">Event volume (blue) vs correlated alerts (red)</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex items-end gap-[2px] h-36">
              {TIMELINE.map((d) => (
                <div key={d.hour} className="flex-1 flex flex-col items-center gap-0 relative" title={`${d.hour}:00 — ${d.events} events, ${d.correlated} correlated`}>
                  <div className="w-full flex items-end gap-[1px] h-28 relative">
                    {/* event bar */}
                    <div
                      className="flex-1 rounded-t bg-blue-500/40 transition-all"
                      style={{ height: `${(d.events / MAX_EVENTS) * 100}%` }}
                    />
                    {/* correlated overlay */}
                    <div
                      className="absolute bottom-0 left-0 right-0 rounded-t bg-red-500/70 transition-all"
                      style={{ height: `${Math.min((d.correlated / 15) * 100, 100)}%` }}
                    />
                  </div>
                  <span className="text-[8px] text-muted-foreground">{d.hour % 6 === 0 ? `${d.hour}h` : ""}</span>
                </div>
              ))}
            </div>
            <div className="flex items-center gap-4 mt-2 text-[10px] text-muted-foreground">
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-blue-500/40 inline-block" />Events</span>
              <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-red-500/70 inline-block" />Correlated</span>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Threat Intel Sharing Panel */}
      <Card className="border-purple-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between flex-wrap gap-2">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Zap className="h-4 w-4 text-purple-400" />
              STIX Threat Intel Sharing
            </CardTitle>
            <div className="flex items-center gap-2">
              {liveData?.sharingStats && (
                <Badge className="text-[10px] border border-purple-500/30 text-purple-400 bg-purple-500/10">
                  {liveData.sharingStats.total_indicators ?? 0} indicators shared
                </Badge>
              )}
              {liveData?.groups && (
                <Badge className="text-[10px] border border-border text-muted-foreground">
                  {liveData.groups.length} sharing groups
                </Badge>
              )}
            </div>
          </div>
          <CardDescription className="text-xs">STIX 2.1 threat intelligence sharing groups and indicators ({`/api/v1/threat-sharing`})</CardDescription>
        </CardHeader>
        <CardContent>
          {liveData?.indicators && liveData.indicators.length > 0 ? (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Type</TableHead>
                    <TableHead className="text-[11px] h-8">Value</TableHead>
                    <TableHead className="text-[11px] h-8">Severity</TableHead>
                    <TableHead className="text-[11px] h-8">TLP</TableHead>
                    <TableHead className="text-[11px] h-8">Confidence</TableHead>
                    <TableHead className="text-[11px] h-8">Source</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {liveData.indicators.slice(0, 8).map((ind: any, i: number) => (
                    <TableRow key={i} className="hover:bg-muted/30">
                      <TableCell className="py-2">
                        <Badge className="text-[9px] border border-border bg-muted/30 text-muted-foreground">{ind.indicator_type ?? ind.type ?? "ip"}</Badge>
                      </TableCell>
                      <TableCell className="text-xs font-mono py-2 max-w-[180px] truncate">{ind.value ?? "—"}</TableCell>
                      <TableCell className="py-2"><SeverityBadge sev={ind.severity ?? "medium"} /></TableCell>
                      <TableCell className="py-2">
                        <Badge className="text-[9px] border border-amber-500/30 text-amber-400 bg-amber-500/10">{ind.tlp_marking ?? ind.tlp ?? "AMBER"}</Badge>
                      </TableCell>
                      <TableCell className="text-xs tabular-nums py-2">{Math.round((ind.confidence ?? 0.8) * 100)}%</TableCell>
                      <TableCell className="text-[10px] py-2 text-muted-foreground">{ind.source ?? "aldeci"}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          ) : (
            <div className="flex items-center gap-3 flex-wrap">
              {[
                { label: "Sharing Groups", value: liveData?.sharingStats?.total_groups ?? liveData?.groups?.length ?? 0 },
                { label: "Indicators Shared", value: liveData?.sharingStats?.total_indicators ?? 0 },
                { label: "Auto-share Policy", value: liveData?.sharingStats?.auto_share_enabled ? "Active" : "—" },
                { label: "STIX Bundles Exported", value: liveData?.sharingStats?.bundles_exported ?? 0 },
              ].map((item) => (
                <div key={item.label} className="flex flex-col items-center gap-1 rounded-lg border border-border bg-muted/10 px-4 py-3 min-w-[110px]">
                  <span className="text-lg font-black tabular-nums">{item.value}</span>
                  <span className="text-[10px] text-muted-foreground text-center">{item.label}</span>
                </div>
              ))}
              <p className="text-[10px] text-muted-foreground ml-2">No indicators shared yet — sharing groups will appear here once configured.</p>
            </div>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}
