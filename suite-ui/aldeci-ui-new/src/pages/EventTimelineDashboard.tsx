/**
 * Event Timeline Dashboard
 *
 * Security incident timeline reconstruction — events, correlations, actor drill-down.
 *   1. Incident selector + create form
 *   2. Timeline event list (actor → target, outcome badge)
 *   3. Correlation view
 *   4. Stats (event_count, duration, status)
 *   5. Add event form
 *   6. Actor drill-down
 *
 * API: /api/v1/event-timeline
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Clock, ArrowRight, Activity, Plus, RefreshCw, User, Link2,
} from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string, opts?: RequestInit) {
  const res = await fetch(`${API_BASE}${path}?org_id=default`, {
    headers: { "X-API-Key": API_KEY, "Content-Type": "application/json" },
    ...opts,
  });
  if (!res.ok) throw new Error(`API ${res.status}`);
  return res.json();
}

// ── Mock data ─────────────────────────────────────────────────────────────────

const MOCK_INCIDENTS = [
  { id: "INC-2026-0041", title: "Ransomware Lateral Movement — Finance VLAN", status: "open",   event_count: 14, duration_mins: 187, start_time: "2026-04-14T02:11:00Z", end_time: "2026-04-14T05:18:00Z" },
  { id: "INC-2026-0039", title: "Credential Stuffing on VPN Portal",           status: "closed", event_count: 8,  duration_mins: 42,  start_time: "2026-04-11T14:03:00Z", end_time: "2026-04-11T14:45:00Z" },
  { id: "INC-2026-0037", title: "Data Exfil via Compromised Service Account",  status: "open",   event_count: 11, duration_mins: 310, start_time: "2026-04-09T22:50:00Z", end_time: "2026-04-10T04:00:00Z" },
];

const MOCK_EVENTS: Record<string, any[]> = {
  "INC-2026-0041": [
    { id: "e1", event_time: "02:11",  event_type: "authentication",   source_system: "AD",       actor: "svc-backup",    target: "DC01",        action: "Failed NTLM auth x47",       outcome: "failure", severity: "high",     tags: ["brute-force","ntlm"] },
    { id: "e2", event_time: "02:19",  event_type: "authentication",   source_system: "AD",       actor: "svc-backup",    target: "DC01",        action: "Successful NTLM auth",        outcome: "success", severity: "critical", tags: ["credential-access"] },
    { id: "e3", event_time: "02:24",  event_type: "lateral-movement", source_system: "EDR",      actor: "svc-backup",    target: "FIN-WS-04",   action: "PsExec remote execution",     outcome: "success", severity: "critical", tags: ["lateral-movement","psexec"] },
    { id: "e4", event_time: "02:31",  event_type: "execution",        source_system: "EDR",      actor: "FIN-WS-04",     target: "FIN-WS-04",   action: "Dropped payload: lsass.exe",  outcome: "success", severity: "critical", tags: ["execution","malware"] },
    { id: "e5", event_time: "02:38",  event_type: "data-collection",  source_system: "DLP",      actor: "lsass.exe",     target: "\\\\fileshare", action: "Enumerated 2,847 files",    outcome: "success", severity: "high",     tags: ["collection","staging"] },
    { id: "e6", event_time: "03:12",  event_type: "exfiltration",     source_system: "Firewall", actor: "FIN-WS-04",     target: "45.33.32.156", action: "TCP 443 bulk transfer 4.2GB",outcome: "success", severity: "critical", tags: ["exfiltration","c2"] },
    { id: "e7", event_time: "03:44",  event_type: "ransomware",       source_system: "EDR",      actor: "lsass.exe",     target: "FIN-WS-04",   action: "File encryption started",     outcome: "success", severity: "critical", tags: ["ransomware","impact"] },
    { id: "e8", event_time: "05:18",  event_type: "containment",      source_system: "SOAR",     actor: "SOC-L2",        target: "FIN-WS-04",   action: "Host isolated via EDR",       outcome: "success", severity: "medium",   tags: ["containment"] },
  ],
  "INC-2026-0039": [
    { id: "e1", event_time: "14:03", event_type: "authentication", source_system: "VPN",  actor: "external:87.249.x.x", target: "vpn.aldeci.io", action: "Failed auth x128 users",  outcome: "failure", severity: "high",   tags: ["cred-stuffing"] },
    { id: "e2", event_time: "14:11", event_type: "authentication", source_system: "VPN",  actor: "external:87.249.x.x", target: "vpn.aldeci.io", action: "4 accounts compromised",   outcome: "success", severity: "critical", tags: ["account-takeover"] },
    { id: "e3", event_time: "14:19", event_type: "detection",      source_system: "SIEM", actor: "SIEM-Rule-401",       target: "vpn.aldeci.io", action: "Alert: ATO pattern matched",outcome: "success", severity: "medium", tags: ["detection"] },
    { id: "e4", event_time: "14:45", event_type: "containment",    source_system: "SOAR", actor: "SOC-L1",              target: "4 accounts",    action: "Accounts force-locked",    outcome: "success", severity: "low",    tags: ["response"] },
  ],
  "INC-2026-0037": [
    { id: "e1", event_time: "22:50", event_type: "authentication",   source_system: "PAM",      actor: "svc-reporting",     target: "PAM",          action: "Privileged session opened", outcome: "success", severity: "medium", tags: ["privileged-access"] },
    { id: "e2", event_time: "23:04", event_type: "data-collection",  source_system: "DLP",      actor: "svc-reporting",     target: "customer-db",  action: "SELECT * on 3 tables",      outcome: "success", severity: "high",   tags: ["collection"] },
    { id: "e3", event_time: "23:41", event_type: "exfiltration",     source_system: "Firewall", actor: "svc-reporting",     target: "s3://ext-drop","action": "PUT 1.8GB archive",        outcome: "success", severity: "critical",tags: ["exfiltration","s3"] },
    { id: "e4", event_time: "04:00", event_type: "detection",        source_system: "UEBA",     actor: "UEBA-Model-v3",     target: "svc-reporting", action: "Anomaly: off-hours large S3",outcome: "success", severity: "high",  tags: ["detection","ueba"] },
  ],
};

const MOCK_CORRELATIONS = [
  { primary_id: "e1", correlated_id: "e2", correlation_type: "temporal", confidence: 0.92 },
  { primary_id: "e2", correlated_id: "e3", correlation_type: "causal",   confidence: 0.87 },
  { primary_id: "e3", correlated_id: "e6", correlation_type: "behavioral",confidence: 0.78 },
];

// ── Helpers ───────────────────────────────────────────────────────────────────

function EventTypeBadge({ t }: { t: string }) {
  const map: Record<string, string> = {
    authentication:   "border-blue-500/30 text-blue-400 bg-blue-500/10",
    "lateral-movement":"border-orange-500/30 text-orange-400 bg-orange-500/10",
    execution:        "border-red-500/30 text-red-400 bg-red-500/10",
    "data-collection":"border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    exfiltration:     "border-red-500/30 text-red-400 bg-red-500/10",
    ransomware:       "border-red-500/30 text-red-400 bg-red-500/10",
    containment:      "border-green-500/30 text-green-400 bg-green-500/10",
    detection:        "border-purple-500/30 text-purple-400 bg-purple-500/10",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[t] ?? "border-border text-muted-foreground")}>{t.replace(/-/g, " ")}</Badge>;
}

function SourceBadge({ s }: { s: string }) {
  return <Badge className="text-[10px] border border-cyan-500/30 text-cyan-400 bg-cyan-500/10 font-mono">{s}</Badge>;
}

function OutcomeBadge({ o }: { o: string }) {
  return (
    <Badge className={cn("text-[10px] border capitalize", o === "success" ? "border-green-500/30 text-green-400 bg-green-500/10" : "border-red-500/30 text-red-400 bg-red-500/10")}>
      {o}
    </Badge>
  );
}

function SevBadge({ s }: { s: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
    medium:   "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    low:      "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[s] ?? "border-border text-muted-foreground")}>{s}</Badge>;
}

function CorrelTypeBadge({ t }: { t: string }) {
  const map: Record<string, string> = {
    temporal:   "border-blue-500/30 text-blue-400 bg-blue-500/10",
    causal:     "border-purple-500/30 text-purple-400 bg-purple-500/10",
    behavioral: "border-orange-500/30 text-orange-400 bg-orange-500/10",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[t] ?? "border-border text-muted-foreground")}>{t}</Badge>;
}

function ConfBar({ val }: { val: number }) {
  return (
    <div className="flex items-center gap-2">
      <div className="w-16 h-1.5 bg-muted rounded-full overflow-hidden">
        <div className={cn("h-full rounded-full", val >= 0.85 ? "bg-green-500" : val >= 0.7 ? "bg-yellow-500" : "bg-red-500")} style={{ width: `${val * 100}%` }} />
      </div>
      <span className="text-[10px] text-muted-foreground">{(val * 100).toFixed(0)}%</span>
    </div>
  );
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function EventTimelineDashboard() {
  const [selectedIncident, setSelectedIncident] = useState<string>(MOCK_INCIDENTS[0].id);
  const [loading, setLoading] = useState(true);
  const [actorFilter, setActorFilter] = useState<string>("");
  const [showEventForm, setShowEventForm] = useState(false);

  useEffect(() => {
    apiFetch(`/api/v1/event-timeline/summary?org_id=${ORG_ID}`).catch((e) => setError(e?.message || 'Failed to load data'))
      .finally(() => setLoading(false));
  }, []);
  const [showIncidentForm, setShowIncidentForm] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [incidentForm, setIncidentForm] = useState({ incident_id: "", title: "" });
  const [eventForm, setEventForm] = useState({ event_type: "authentication", source_system: "", actor: "", target: "", action: "", outcome: "success", severity: "medium", tags: "" });
  const [error, setError] = useState<string | null>(null);

  const incident = MOCK_INCIDENTS.find(i => i.id === selectedIncident)!;
  const events = MOCK_EVENTS[selectedIncident] ?? [];
  const filteredEvents = actorFilter
    ? events.filter(e => e.actor.toLowerCase().includes(actorFilter.toLowerCase()))
    : events;

  const actors = [...new Set(events.map(e => e.actor))];

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Security Event Timeline"
        description="Incident timeline reconstruction — event sequences, correlations, and actor activity"
        actions={
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={() => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); }} disabled={refreshing}>
              <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
            </Button>
            <Button size="sm" variant="outline" onClick={() => setShowEventForm(v => !v)}>
              <Plus className="h-4 w-4 mr-1" /> Event
            </Button>
            <Button size="sm" onClick={() => setShowIncidentForm(v => !v)}>
              <Plus className="h-4 w-4 mr-1" /> Timeline
            </Button>
          </div>
        }
      />

      {/* Incident Selector */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Activity className="h-4 w-4 text-blue-400" /> Incident Selector
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap gap-2">
            {MOCK_INCIDENTS.map(inc => (
              <button
                key={inc.id}
                onClick={() => { setSelectedIncident(inc.id); setActorFilter(""); }}
                className={cn(
                  "rounded-lg border px-3 py-2 text-left transition-colors",
                  selectedIncident === inc.id ? "border-blue-500/50 bg-blue-500/10" : "border-border hover:bg-muted/50"
                )}
              >
                <div className="flex items-center gap-2 mb-1">
                  <span className="font-mono text-[10px] text-muted-foreground">{inc.id}</span>
                  <Badge className={cn("text-[9px] border", inc.status === "open" ? "border-red-500/30 text-red-400 bg-red-500/10" : "border-green-500/30 text-green-400 bg-green-500/10")}>
                    {inc.status}
                  </Badge>
                </div>
                <div className="text-[11px] font-medium max-w-[260px] truncate">{inc.title}</div>
                <div className="text-[10px] text-muted-foreground mt-0.5">{inc.event_count} events · {inc.duration_mins}m</div>
              </button>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Create Timeline / Add Event Forms */}
      {showIncidentForm && (
        <Card className="border-blue-500/20">
          <CardHeader className="pb-3"><CardTitle className="text-sm font-semibold">Create New Timeline</CardTitle></CardHeader>
          <CardContent>
            <form className="grid grid-cols-2 gap-3" onSubmit={async e => {
              e.preventDefault();
              try { await apiFetch(`/api/v1/event-timeline/timelines?org_id=${ORG_ID}`, { method: "POST", body: JSON.stringify({ ...incidentForm, org_id: ORG_ID }) }); } catch (_) {}
              setShowIncidentForm(false);
            }}>
              {[["incident_id","Incident ID"],["title","Title"]].map(([k, l]) => (
                <div key={k} className="flex flex-col gap-1">
                  <label className="text-[10px] text-muted-foreground">{l}</label>
                  <input className="h-8 rounded-md border border-border bg-background px-3 text-xs" value={(incidentForm as any)[k]} onChange={e => setIncidentForm(f => ({ ...f, [k]: e.target.value }))} required />
                </div>
              ))}
              <div className="col-span-2 flex gap-2 justify-end">
                <Button variant="outline" size="sm" type="button" onClick={() => setShowIncidentForm(false)}>Cancel</Button>
                <Button size="sm" type="submit">Create</Button>
              </div>
            </form>
          </CardContent>
        </Card>
      )}
      {showEventForm && (
        <Card className="border-purple-500/20">
          <CardHeader className="pb-3"><CardTitle className="text-sm font-semibold">Add Timeline Event</CardTitle></CardHeader>
          <CardContent>
            <form className="grid grid-cols-2 gap-3 md:grid-cols-4" onSubmit={async e => {
              e.preventDefault();
              try { await apiFetch(`/api/v1/event-timeline/events?org_id=${ORG_ID}`, { method: "POST", body: JSON.stringify({ ...eventForm, incident_id: selectedIncident, org_id: ORG_ID }) }); } catch (_) {}
              setShowEventForm(false);
            }}>
              {[["source_system","Source System"],["actor","Actor"],["target","Target"],["action","Action"],["tags","Tags (comma-sep)"]].map(([k, l]) => (
                <div key={k} className="flex flex-col gap-1">
                  <label className="text-[10px] text-muted-foreground">{l}</label>
                  <input className="h-8 rounded-md border border-border bg-background px-3 text-xs" value={(eventForm as any)[k]} onChange={e => setEventForm(f => ({ ...f, [k]: e.target.value }))} />
                </div>
              ))}
              {[["event_type","Type",["authentication","lateral-movement","execution","data-collection","exfiltration","ransomware","containment","detection"]],
                ["outcome","Outcome",["success","failure"]],
                ["severity","Severity",["critical","high","medium","low"]]
              ].map(([k, l, opts]) => (
                <div key={k as string} className="flex flex-col gap-1">
                  <label className="text-[10px] text-muted-foreground">{l as string}</label>
                  <select className="h-8 rounded-md border border-border bg-background px-3 text-xs" value={(eventForm as any)[k as string]} onChange={e => setEventForm(f => ({ ...f, [k as string]: e.target.value }))}>
                    {(opts as string[]).map(o => <option key={o} value={o}>{o}</option>)}
                  </select>
                </div>
              ))}
              <div className="col-span-2 md:col-span-4 flex gap-2 justify-end">
                <Button variant="outline" size="sm" type="button" onClick={() => setShowEventForm(false)}>Cancel</Button>
                <Button size="sm" type="submit">Add Event</Button>
              </div>
            </form>
          </CardContent>
        </Card>
      )}

      {/* KPIs for selected incident */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Events"       value={incident.event_count}  icon={Activity}   trend="flat" />
        <KpiCard title="Duration"     value={`${incident.duration_mins}m`} icon={Clock} trend="flat" />
        <KpiCard title="Start Time"   value={incident.start_time.split("T")[1].replace("Z","")} icon={Clock} trend="flat" />
        <KpiCard
          title="Status"
          value={incident.status.toUpperCase()}
          icon={Activity}
          trend="flat"
          className={incident.status === "open" ? "border-red-500/20" : "border-green-500/20"}
        />
      </div>

      {/* Timeline Events */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Clock className="h-4 w-4 text-blue-400" /> Event Timeline
              <Badge className="text-[10px] border border-blue-500/30 text-blue-400 bg-blue-500/10 font-mono">{selectedIncident}</Badge>
            </CardTitle>
            <div className="flex items-center gap-2">
              <input
                className="h-7 w-36 rounded-md border border-border bg-background px-2 text-[11px]"
                placeholder="Filter by actor..."
                value={actorFilter}
                onChange={e => setActorFilter(e.target.value)}
              />
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-2 p-4">
          {filteredEvents.map((ev, i) => (
            <div
              key={ev.id}
              className={cn(
                "relative flex gap-3 rounded-lg border p-3",
                ev.severity === "critical" ? "border-red-500/20 bg-red-500/5"
                : ev.severity === "high" ? "border-orange-500/20 bg-orange-500/5"
                : "border-border bg-muted/20"
              )}
            >
              {/* Timeline connector */}
              {i < filteredEvents.length - 1 && (
                <div className="absolute left-6 top-full h-2 w-px bg-border" />
              )}
              <div className="shrink-0 flex flex-col items-center gap-1">
                <span className="font-mono text-[10px] text-muted-foreground">{ev.event_time}</span>
              </div>
              <div className="flex-1 min-w-0 space-y-1.5">
                <div className="flex flex-wrap items-center gap-2">
                  <EventTypeBadge t={ev.event_type} />
                  <SourceBadge s={ev.source_system} />
                  <SevBadge s={ev.severity} />
                  <OutcomeBadge o={ev.outcome} />
                </div>
                <div className="flex items-center gap-1 text-[11px]">
                  <span className="font-semibold text-blue-300">{ev.actor}</span>
                  <ArrowRight className="h-3 w-3 text-muted-foreground" />
                  <span className="font-semibold text-purple-300">{ev.target}</span>
                </div>
                <p className="text-[11px] text-muted-foreground">{ev.action}</p>
                <div className="flex flex-wrap gap-1">
                  {ev.tags.map((t: string) => (
                    <Badge key={t} className="text-[9px] border border-border text-muted-foreground">{t}</Badge>
                  ))}
                </div>
              </div>
            </div>
          ))}
          {filteredEvents.length === 0 && (
            <p className="text-center text-xs text-muted-foreground py-8">No events match the current filter.</p>
          )}
        </CardContent>
      </Card>

      {/* Correlation View */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Link2 className="h-4 w-4 text-purple-400" /> Event Correlations
          </CardTitle>
          <CardDescription className="text-xs">Causal and temporal links between timeline events</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Primary Event</TableHead>
                  <TableHead className="text-[11px] h-8"></TableHead>
                  <TableHead className="text-[11px] h-8">Correlated Event</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8 min-w-[100px]">Confidence</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {MOCK_CORRELATIONS.map((c, i) => {
                  const pev = events.find(e => e.id === c.primary_id);
                  const cev = events.find(e => e.id === c.correlated_id);

                  if (loading) return <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div></div>;

                  return (
                    <TableRow key={i} className="hover:bg-muted/30">
                      <TableCell className="py-2 text-[11px] text-blue-300">{pev?.event_type ?? c.primary_id}</TableCell>
                      <TableCell className="py-2"><ArrowRight className="h-3 w-3 text-muted-foreground" /></TableCell>
                      <TableCell className="py-2 text-[11px] text-purple-300">{cev?.event_type ?? c.correlated_id}</TableCell>
                      <TableCell className="py-2"><CorrelTypeBadge t={c.correlation_type} /></TableCell>
                      <TableCell className="py-2 min-w-[100px]"><ConfBar val={c.confidence} /></TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Actor Activity Drill-down */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <User className="h-4 w-4 text-cyan-400" /> Actor Activity
          </CardTitle>
          <CardDescription className="text-xs">Select an actor to see their event sequence</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex flex-wrap gap-2 mb-4">
            <Button
              variant="outline"
              size="sm"
              className={cn("h-7 text-[11px]", !actorFilter && "border-blue-500/50 bg-blue-500/10")}
              onClick={() => setActorFilter("")}
            >All actors</Button>
            {actors.map(a => (
              <Button
                key={a}
                variant="outline"
                size="sm"
                className={cn("h-7 text-[11px] font-mono", actorFilter === a && "border-blue-500/50 bg-blue-500/10")}
                onClick={() => setActorFilter(f => f === a ? "" : a)}
              >{a}</Button>
            ))}
          </div>
          {actorFilter && (
            <div className="space-y-2">
              {events.filter(e => e.actor === actorFilter).map(ev => (
                <div key={ev.id} className="flex items-center gap-3 rounded-md border border-border p-2">
                  <span className="font-mono text-[10px] text-muted-foreground w-12 shrink-0">{ev.event_time}</span>
                  <EventTypeBadge t={ev.event_type} />
                  <span className="text-[11px] text-muted-foreground flex-1 truncate">{ev.action}</span>
                  <OutcomeBadge o={ev.outcome} />
                </div>
              ))}
            </div>
          )}
          {!actorFilter && (
            <p className="text-center text-xs text-muted-foreground py-4">Select an actor above to drill down.</p>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}
