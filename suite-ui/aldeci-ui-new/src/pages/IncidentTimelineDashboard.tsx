/**
 * Incident Timeline Dashboard
 *
 * NIST IR lifecycle tracking with MTTD, MTTR, and evidence chain.
 *   1. KPIs: Active Incidents, Avg MTTR, Avg MTTD, Affected Systems
 *   2. Active timelines table (8 rows)
 *   3. Timeline event viewer (vertical event list for selected incident)
 *   4. Affected systems panel (6 systems)
 *   5. Metrics panel: MTTD / MTTR / MTTC circles
 *
 * API stubs: GET /api/v1/incident-timeline, /api/v1/incident-timeline/{id}/events
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Siren, Clock, Activity, Server, RefreshCw, Shield,
  ChevronRight, AlertCircle, Eye,
} from "lucide-react";

// ── API helpers ────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "dev-key";
const ORG_ID = "default";

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
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── Mock data ──────────────────────────────────────────────────

const INCIDENTS = [
  { id: "INC-2024-001", title: "Ransomware outbreak — Finance subnet",    type: "ransomware", severity: "Critical", status: "Containment",  started: "2026-04-14 02:11", systems: 7,  events: 23 },
  { id: "INC-2024-002", title: "Data exfiltration via compromised account", type: "breach",     severity: "Critical", status: "Eradication", started: "2026-04-14 08:44", systems: 3,  events: 17 },
  { id: "INC-2024-003", title: "Phishing campaign — HR department",        type: "phishing",   severity: "High",     status: "Recovery",    started: "2026-04-14 10:05", systems: 2,  events: 11 },
  { id: "INC-2024-004", title: "Insider threat — privileged data access",  type: "insider",    severity: "High",     status: "Detection",   started: "2026-04-15 06:30", systems: 1,  events: 6  },
  { id: "INC-2024-005", title: "DDoS against public API gateway",          type: "ddos",       severity: "Medium",   status: "Mitigation",  started: "2026-04-15 13:20", systems: 2,  events: 9  },
  { id: "INC-2024-006", title: "Malware on developer workstation",         type: "breach",     severity: "High",     status: "Containment", started: "2026-04-15 15:00", systems: 1,  events: 8  },
  { id: "INC-2024-007", title: "BEC — wire fraud attempt",                 type: "phishing",   severity: "Critical", status: "Detection",   started: "2026-04-16 07:11", systems: 0,  events: 4  },
  { id: "INC-2024-008", title: "Lateral movement from contractor VPN",     type: "insider",    severity: "High",     status: "Analysis",    started: "2026-04-16 09:45", systems: 2,  events: 5  },
];

const EVENTS: Record<string, { type: string; actor: string; ts: string; desc: string; evidence: number }[]> = {
  "INC-2024-001": [
    { type: "detection",    actor: "EDR Agent",         ts: "2026-04-14 02:11", desc: "Anomalous file encryption activity detected on FIN-WS-04",            evidence: 3 },
    { type: "escalation",   actor: "SOC Tier 1",        ts: "2026-04-14 02:18", desc: "Alert escalated to Incident Response team — ransomware pattern confirmed", evidence: 1 },
    { type: "action",       actor: "IR Lead",           ts: "2026-04-14 02:31", desc: "Network segment isolated via VLAN policy push on core switch",        evidence: 2 },
    { type: "containment",  actor: "NetSec",            ts: "2026-04-14 02:45", desc: "7 affected endpoints quarantined; backup jobs suspended",             evidence: 4 },
    { type: "action",       actor: "Forensics",         ts: "2026-04-14 03:10", desc: "Memory images captured from FIN-WS-04 and FIN-SRV-02",               evidence: 6 },
    { type: "escalation",   actor: "CISO",              ts: "2026-04-14 04:00", desc: "Executive escalation — legal and insurance notified",                 evidence: 0 },
    { type: "eradication",  actor: "IR Lead",           ts: "2026-04-14 06:00", desc: "Malware family identified: LockBit 3.0. IOCs extracted and blocked",  evidence: 5 },
    { type: "action",       actor: "SOC Tier 2",        ts: "2026-04-14 08:30", desc: "Threat hunting sweep across all subnets — no further lateral movement", evidence: 2 },
  ],
  "INC-2024-002": [
    { type: "detection",   actor: "SIEM",       ts: "2026-04-14 08:44", desc: "Unusual S3 data transfer volume from svc-reporting account", evidence: 2 },
    { type: "action",      actor: "CloudOps",   ts: "2026-04-14 09:00", desc: "Access key revoked and session tokens invalidated",           evidence: 1 },
    { type: "escalation",  actor: "SOC Tier 2", ts: "2026-04-14 09:15", desc: "Confirmed exfiltration of 42 GB customer data",              evidence: 3 },
    { type: "containment", actor: "IR Lead",    ts: "2026-04-14 09:30", desc: "S3 bucket locked down; access logging enabled",              evidence: 2 },
  ],
};

const SYSTEMS = [
  { host: "FIN-WS-04",    ip: "10.20.4.104", type: "workstation",  affected: "2026-04-14 02:05", restored: null },
  { host: "FIN-SRV-02",   ip: "10.20.4.2",   type: "server",       affected: "2026-04-14 02:09", restored: null },
  { host: "FIN-WS-11",    ip: "10.20.4.111", type: "workstation",  affected: "2026-04-14 02:12", restored: null },
  { host: "FIN-WS-07",    ip: "10.20.4.107", type: "workstation",  affected: "2026-04-14 02:15", restored: "2026-04-14 14:30" },
  { host: "BKP-NAS-01",   ip: "10.20.10.5",  type: "nas",          affected: "2026-04-14 02:18", restored: "2026-04-14 16:00" },
  { host: "FIN-DC-01",    ip: "10.20.4.1",   type: "domain_ctrl",  affected: "2026-04-14 02:22", restored: null },
];

// ── Helpers ────────────────────────────────────────────────────

const TYPE_COLORS: Record<string, string> = {
  breach:     "border-red-500/30 text-red-400 bg-red-500/10",
  ransomware: "border-rose-500/30 text-rose-400 bg-rose-500/10",
  phishing:   "border-orange-500/30 text-orange-400 bg-orange-500/10",
  insider:    "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
  ddos:       "border-blue-500/30 text-blue-400 bg-blue-500/10",
};

const SEV_COLORS: Record<string, string> = {
  Critical: "border-red-500/30 text-red-400 bg-red-500/10",
  High:     "border-amber-500/30 text-amber-400 bg-amber-500/10",
  Medium:   "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
  Low:      "border-border text-muted-foreground",
};

const STATUS_COLORS: Record<string, string> = {
  Detection:   "border-blue-500/30 text-blue-400 bg-blue-500/10",
  Analysis:    "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
  Containment: "border-orange-500/30 text-orange-400 bg-orange-500/10",
  Eradication: "border-purple-500/30 text-purple-400 bg-purple-500/10",
  Mitigation:  "border-amber-500/30 text-amber-400 bg-amber-500/10",
  Recovery:    "border-green-500/30 text-green-400 bg-green-500/10",
};

const EVENT_COLORS: Record<string, string> = {
  detection:   "bg-blue-500/20 text-blue-300 border-blue-500/30",
  action:      "bg-green-500/20 text-green-300 border-green-500/30",
  escalation:  "bg-orange-500/20 text-orange-300 border-orange-500/30",
  containment: "bg-red-500/20 text-red-300 border-red-500/30",
  eradication: "bg-purple-500/20 text-purple-300 border-purple-500/30",
};

const METRIC_CIRCLES = [
  { label: "MTTD", value: "2.1", unit: "hrs",  color: "text-blue-400",   ring: "border-blue-500/40" },
  { label: "MTTR", value: "4.2", unit: "days", color: "text-amber-400",  ring: "border-amber-500/40" },
  { label: "MTTC", value: "1.3", unit: "hrs",  color: "text-purple-400", ring: "border-purple-500/40" },
];

// ── Component ──────────────────────────────────────────────────

export default function IncidentTimelineDashboard() {
  const [selected, setSelected] = useState<string>("INC-2024-001");
  const [refreshing, setRefreshing] = useState(false);
  const [liveData, setLiveData] = useState<any>(null);
  const [liveEvents, setLiveEvents] = useState<any[]>([]);
  const [liveSystems, setLiveSystems] = useState<any[]>([]);
  const [dataLoading, setDataLoading] = useState(false);

  const fetchData = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/incident-timeline/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/incident-timeline/events?org_id=${ORG_ID}&limit=50`),
    ]).then(([statsRes, eventsRes]) => {
      const stats  = statsRes.status  === "fulfilled" ? statsRes.value  : null;
      const events = eventsRes.status === "fulfilled" ? eventsRes.value : null;
      // Group events into timelines for the table view
      const timelines = Array.isArray(events) && events.length > 0
        ? Object.values(
            events.reduce((acc: any, ev: any) => {
              const id = ev.timeline_id ?? ev.incident_id ?? ev.id ?? "TL-unknown";
              if (!acc[id]) acc[id] = { id, title: ev.title ?? ev.description ?? "Incident", type: ev.incident_type ?? "breach", severity: ev.severity ?? "Medium", status: ev.status ?? "Detection", started: ev.event_time ?? ev.created_at ?? "—", systems: 0, events: 0 };
              acc[id].events++;
              return acc;
            }, {})
          )
        : null;
      if (stats || timelines) {
        setLiveData({ stats, timelines });
        const first = Array.isArray(timelines) && timelines.length > 0 ? (timelines as any[])[0] : null;
        if (first?.id) setSelected(first.id);
      }
    }).finally(() => setDataLoading(false));
  };

  useEffect(() => {
    fetchData();
  }, []);

  // Fetch events + systems whenever selected timeline changes
  useEffect(() => {
    if (!selected || selected.startsWith("INC-2024-")) return; // skip mock IDs
    Promise.allSettled([
      apiFetch(`/api/v1/incident-timeline/${selected}/events?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/incident-timeline/${selected}/systems?org_id=${ORG_ID}`),
    ]).then(([eventsRes, systemsRes]) => {
      if (eventsRes.status === "fulfilled") setLiveEvents(Array.isArray(eventsRes.value) ? eventsRes.value : []);
      if (systemsRes.status === "fulfilled") setLiveSystems(Array.isArray(systemsRes.value) ? systemsRes.value : []);
    });
  }, [selected]);

  // Resolve which data to show: live API or mock fallback
  const displayTimelines: typeof INCIDENTS = (() => {
    const raw = liveData?.timelines;
    if (Array.isArray(raw) && raw.length > 0) {
      return raw.slice(0, 10).map((tl: any) => ({
        id: tl.id ?? tl.timeline_id ?? "TL-???",
        title: tl.title ?? "Untitled",
        type: tl.incident_type ?? "breach",
        severity: tl.severity ?? "medium",
        status: tl.status ?? "open",
        started: tl.started_at ?? tl.created_at ?? "—",
        systems: tl.affected_system_count ?? 0,
        events: tl.event_count ?? 0,
      }));
    }
    return INCIDENTS;
  })();

  const displayEvents = liveEvents.length > 0
    ? liveEvents.map((ev: any) => ({
        type: ev.event_type ?? "action",
        actor: ev.actor ?? "System",
        ts: ev.event_time ?? ev.created_at ?? "—",
        desc: ev.description ?? ev.title ?? "",
        evidence: Array.isArray(ev.evidence_refs) ? ev.evidence_refs.length : 0,
      }))
    : (EVENTS[selected] ?? []);

  const displaySystems = liveSystems.length > 0
    ? liveSystems.map((s: any) => ({
        host: s.hostname ?? s.host ?? "Unknown",
        ip: s.ip_address ?? s.ip ?? "—",
        type: s.system_type ?? s.type ?? "server",
        affected: s.affected_at ?? "—",
        restored: s.restored_at ?? null,
      }))
    : SYSTEMS;

  const stats = liveData?.stats;
  const activeCount    = stats?.active_count ?? stats?.open ?? 3;
  const avgMttr        = stats?.avg_mttr_hours != null ? `${Number(stats.avg_mttr_hours).toFixed(1)}h` : "4.2 days";
  const avgMttd        = stats?.avg_mttd_hours != null ? `${Number(stats.avg_mttd_hours).toFixed(1)}h` : "2.1 hrs";
  const affectedSystems = stats?.total_affected_systems ?? 18;

  const handleRefresh = () => {
    setRefreshing(true);
    fetchData();
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
        title="Incident Timeline"
        description="NIST IR lifecycle tracking with MTTD, MTTR, and evidence chain"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Active Incidents"  value={activeCount}    icon={Siren}    trend="up"   className="border-red-500/20" />
        <KpiCard title="Avg MTTR"          value={avgMttr}        icon={Clock}    trend="down" />
        <KpiCard title="Avg MTTD"          value={avgMttd}        icon={Activity} trend="down" />
        <KpiCard title="Affected Systems"  value={affectedSystems} icon={Server}  trend="up"   className="border-amber-500/20" />
      </div>

      {/* Incident table */}
      <Card className="border-red-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
              <Siren className="h-4 w-4" />
              Active Incident Timelines
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
              {displayTimelines.length} incidents
            </Badge>
          </div>
          <CardDescription className="text-xs">Click a row to view event timeline</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">ID</TableHead>
                  <TableHead className="text-[11px] h-8">Title</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Severity</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8">Started</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Systems</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Events</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {displayTimelines.map((row) => (
                  <TableRow
                    key={row.id}
                    onClick={() => setSelected(row.id)}
                    className={cn(
                      "cursor-pointer hover:bg-muted/30 transition-colors",
                      selected === row.id && "bg-primary/5 border-l-2 border-l-primary"
                    )}
                  >
                    <TableCell className="text-xs font-mono py-2.5">{row.id}</TableCell>
                    <TableCell className="text-xs py-2.5 max-w-[200px] truncate">{row.title}</TableCell>
                    <TableCell className="py-2.5">
                      <Badge className={cn("text-[10px] border capitalize", TYPE_COLORS[row.type])}>{row.type}</Badge>
                    </TableCell>
                    <TableCell className="py-2.5">
                      <Badge className={cn("text-[10px] border", SEV_COLORS[row.severity])}>{row.severity}</Badge>
                    </TableCell>
                    <TableCell className="py-2.5">
                      <Badge className={cn("text-[10px] border", STATUS_COLORS[row.status])}>{row.status}</Badge>
                    </TableCell>
                    <TableCell className="text-xs tabular-nums py-2.5 text-muted-foreground">{row.started}</TableCell>
                    <TableCell className="text-xs tabular-nums py-2.5 text-right">{row.systems}</TableCell>
                    <TableCell className="text-xs tabular-nums py-2.5 text-right">{row.events}</TableCell>
                    <TableCell className="py-2.5 text-right">
                      <Button variant="outline" size="sm" className="h-6 px-2 text-[10px]" onClick={() => setSelected(row.id)}>
                        <Eye className="h-3 w-3 mr-1" />View
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Event viewer + Affected systems */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Event timeline */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Activity className="h-4 w-4 text-blue-400" />
              Event Timeline — {selected}
            </CardTitle>
            <CardDescription className="text-xs">NIST IR phase events, actors, and evidence</CardDescription>
          </CardHeader>
          <CardContent>
            {displayEvents.length === 0 ? (
              <p className="text-xs text-muted-foreground py-4 text-center">No events available for this incident</p>
            ) : (
              <div className="relative space-y-0">
                {displayEvents.map((ev, i) => (
                  <div key={i} className="flex gap-3 group">
                    {/* Timeline line */}
                    <div className="flex flex-col items-center">
                      <div className={cn("w-2.5 h-2.5 rounded-full mt-1 shrink-0 border", EVENT_COLORS[ev.type])} />
                      {i < displayEvents.length - 1 && <div className="w-px flex-1 bg-border/40 my-0.5" />}
                    </div>
                    {/* Content */}
                    <div className={cn("pb-3 flex-1", i === displayEvents.length - 1 && "pb-0")}>
                      <div className="flex items-center gap-2 mb-0.5 flex-wrap">
                        <Badge className={cn("text-[10px] border capitalize px-1.5", EVENT_COLORS[ev.type])}>{ev.type}</Badge>
                        <span className="text-[10px] font-medium">{ev.actor}</span>
                        <span className="text-[10px] text-muted-foreground ml-auto tabular-nums">{ev.ts}</span>
                      </div>
                      <p className="text-[11px] text-muted-foreground leading-relaxed">{ev.desc}</p>
                      {ev.evidence > 0 && (
                        <span className="inline-flex items-center gap-1 mt-1 text-[10px] text-purple-400">
                          <Shield className="h-2.5 w-2.5" />{ev.evidence} evidence ref{ev.evidence > 1 ? "s" : ""}
                        </span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        {/* Affected systems */}
        <div className="flex flex-col gap-4">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <Server className="h-4 w-4 text-orange-400" />
                Affected Systems — {selected}
              </CardTitle>
              <CardDescription className="text-xs">Hosts impacted and restoration status</CardDescription>
            </CardHeader>
            <CardContent className="p-0">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Hostname</TableHead>
                    <TableHead className="text-[11px] h-8">IP</TableHead>
                    <TableHead className="text-[11px] h-8">Type</TableHead>
                    <TableHead className="text-[11px] h-8 text-right">Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {displaySystems.map((s) => (
                    <TableRow key={s.host} className="hover:bg-muted/30">
                      <TableCell className="text-xs font-mono py-2">{s.host}</TableCell>
                      <TableCell className="text-xs py-2 tabular-nums text-muted-foreground">{s.ip}</TableCell>
                      <TableCell className="py-2">
                        <Badge className="text-[10px] border border-border capitalize">{s.type.replace("_", " ")}</Badge>
                      </TableCell>
                      <TableCell className="py-2 text-right">
                        {s.restored ? (
                          <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">Restored</Badge>
                        ) : (
                          <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">ACTIVE</Badge>
                        )}
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>

          {/* MTTD / MTTR / MTTC circles */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <AlertCircle className="h-4 w-4 text-muted-foreground" />
                IR Metrics
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex items-center justify-around py-2">
                {METRIC_CIRCLES.map((m) => (
                  <div key={m.label} className="flex flex-col items-center gap-2">
                    <div className={cn(
                      "w-20 h-20 rounded-full border-4 flex flex-col items-center justify-center",
                      m.ring
                    )}>
                      <span className={cn("text-xl font-bold tabular-nums", m.color)}>{m.value}</span>
                      <span className="text-[10px] text-muted-foreground">{m.unit}</span>
                    </div>
                    <span className="text-xs font-semibold text-muted-foreground">{m.label}</span>
                  </div>
                ))}
              </div>
              <div className="mt-3 grid grid-cols-3 gap-2 text-center">
                <div className="text-[10px] text-muted-foreground">Mean Time<br />To Detect</div>
                <div className="text-[10px] text-muted-foreground">Mean Time<br />To Respond</div>
                <div className="text-[10px] text-muted-foreground">Mean Time<br />To Contain</div>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </motion.div>
  );
}
