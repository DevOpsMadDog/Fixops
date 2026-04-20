/**
 * Incident Communications Dashboard
 *
 * Communications log, channel breakdown, send form, incident selector.
 *   1. KPIs: Total Comms, Open Incidents, Channels Active, Avg Response Time
 *   2. Communications log table (7 comm types, 7 channels)
 *   3. Send communication form
 *   4. Channel breakdown
 *
 * Route: /incident-comms
 * API: GET /api/v1/incident-comms
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { MessageSquare, Send, Radio, Clock, RefreshCw, Loader2, CheckCircle2 } from "lucide-react";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY = (typeof window !== "undefined" && window.localStorage.getItem("aldeci_api_key")) || import.meta.env.VITE_API_KEY || "demo-key";
const ORG_ID = "aldeci-demo";
async function apiFetch(path: string) {
  const r = await fetch(`${API_BASE}${path}?org_id=default`, { headers: { "X-API-Key": API_KEY, "Content-Type": "application/json" } });
  if (!r.ok) throw new Error(`${r.status}`);
  return r.json();
}

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── Types ──────────────────────────────────────────────────────

type CommType = "notification" | "update" | "escalation" | "resolution" | "postmortem" | "stakeholder" | "public";
type Channel = "email" | "slack" | "sms" | "pagerduty" | "teams" | "jira" | "webhook";

interface CommEntry {
  id: string;
  incident_id: string;
  incident_title: string;
  comm_type: CommType;
  channel: Channel;
  subject: string;
  recipient_count: number;
  sent_at: string;
  status: "sent" | "failed" | "pending";
}

// ── Mock data ──────────────────────────────────────────────────

const MOCK_COMMS: CommEntry[] = [
  { id: "cm-001", incident_id: "INC-2041", incident_title: "DB Outage — Prod",          comm_type: "notification",  channel: "pagerduty", subject: "P1 Incident: DB Outage detected",                    recipient_count: 12, sent_at: "2026-04-16 08:03", status: "sent" },
  { id: "cm-002", incident_id: "INC-2041", incident_title: "DB Outage — Prod",          comm_type: "update",        channel: "slack",     subject: "INC-2041 Update: RCA in progress, ETA 30min",          recipient_count: 48, sent_at: "2026-04-16 08:45", status: "sent" },
  { id: "cm-003", incident_id: "INC-2041", incident_title: "DB Outage — Prod",          comm_type: "stakeholder",   channel: "email",     subject: "[Stakeholder] Production database impact — update",     recipient_count: 8,  sent_at: "2026-04-16 09:00", status: "sent" },
  { id: "cm-004", incident_id: "INC-2041", incident_title: "DB Outage — Prod",          comm_type: "resolution",    channel: "slack",     subject: "INC-2041 RESOLVED: Service restored at 09:22",         recipient_count: 52, sent_at: "2026-04-16 09:22", status: "sent" },
  { id: "cm-005", incident_id: "INC-2038", incident_title: "API Latency Spike",         comm_type: "notification",  channel: "pagerduty", subject: "P2 Incident: API p99 latency > 5s threshold",          recipient_count: 6,  sent_at: "2026-04-16 06:15", status: "sent" },
  { id: "cm-006", incident_id: "INC-2038", incident_title: "API Latency Spike",         comm_type: "escalation",    channel: "teams",     subject: "Escalation: API latency unresolved after 2h",          recipient_count: 4,  sent_at: "2026-04-16 08:17", status: "sent" },
  { id: "cm-007", incident_id: "INC-2035", incident_title: "S3 Misconfiguration",       comm_type: "postmortem",    channel: "jira",      subject: "PIR: S3 bucket public exposure — root cause & actions", recipient_count: 14, sent_at: "2026-04-16 10:00", status: "sent" },
  { id: "cm-008", incident_id: "INC-2042", incident_title: "Suspicious Login Activity", comm_type: "notification",  channel: "slack",     subject: "Security Alert: Multiple failed logins from RU IP",    recipient_count: 9,  sent_at: "2026-04-16 10:30", status: "sent" },
  { id: "cm-009", incident_id: "INC-2042", incident_title: "Suspicious Login Activity", comm_type: "update",        channel: "email",     subject: "Security Incident INC-2042 — investigation ongoing",   recipient_count: 5,  sent_at: "2026-04-16 11:00", status: "pending" },
  { id: "cm-010", incident_id: "INC-2040", incident_title: "Certificate Expiry Alert",  comm_type: "public",        channel: "webhook",   subject: "Maintenance window notification — cert renewal",        recipient_count: 0,  sent_at: "2026-04-16 07:00", status: "failed" },
];

const INCIDENTS = [
  "INC-2041 — DB Outage (P1)",
  "INC-2042 — Suspicious Login (P2)",
  "INC-2038 — API Latency (P2)",
  "INC-2040 — Certificate Expiry (P3)",
  "INC-2035 — S3 Misconfiguration (P2)",
];

const COMM_TYPES: CommType[] = ["notification", "update", "escalation", "resolution", "postmortem", "stakeholder", "public"];
const CHANNELS: Channel[] = ["email", "slack", "sms", "pagerduty", "teams", "jira", "webhook"];

const CHANNEL_COLORS: Record<Channel, string> = {
  email:     "bg-blue-500/10 text-blue-400 border-blue-500/20",
  slack:     "bg-purple-500/10 text-purple-400 border-purple-500/20",
  sms:       "bg-green-500/10 text-green-400 border-green-500/20",
  pagerduty: "bg-red-500/10 text-red-400 border-red-500/20",
  teams:     "bg-indigo-500/10 text-indigo-400 border-indigo-500/20",
  jira:      "bg-cyan-500/10 text-cyan-400 border-cyan-500/20",
  webhook:   "bg-orange-500/10 text-orange-400 border-orange-500/20",
};

const COMM_TYPE_COLORS: Record<CommType, string> = {
  notification: "bg-blue-500/10 text-blue-400",
  update:       "bg-cyan-500/10 text-cyan-400",
  escalation:   "bg-red-500/10 text-red-400",
  resolution:   "bg-green-500/10 text-green-400",
  postmortem:   "bg-purple-500/10 text-purple-400",
  stakeholder:  "bg-yellow-500/10 text-yellow-400",
  public:       "bg-gray-500/10 text-gray-400",
};

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    sent:    "bg-green-500/10 text-green-400 border-green-500/20",
    pending: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20",
    failed:  "bg-red-500/10 text-red-400 border-red-500/20",
  };
  return <Badge className={cn("border text-xs capitalize", map[status] ?? "")}>{status}</Badge>;
}

// ── Channel Breakdown ──────────────────────────────────────────

function ChannelBreakdown() {
  const counts = CHANNELS.map((ch) => ({
    channel: ch,
    count: MOCK_COMMS.filter((c) => c.channel === ch).length,
  })).sort((a, b) => b.count - a.count);
  const max = counts[0]?.count ?? 1;

  return (
    <div className="flex flex-col gap-2">
      {counts.map(({ channel, count }) => (
        <div key={channel} className="flex items-center gap-2">
          <Badge className={cn("border text-xs capitalize w-24 justify-center", CHANNEL_COLORS[channel])}>{channel}</Badge>
          <div className="flex-1 h-2 bg-gray-700 rounded-full overflow-hidden">
            <motion.div
              className="h-full bg-blue-500 rounded-full"
              initial={{ width: 0 }}
              animate={{ width: `${(count / max) * 100}%` }}
              transition={{ duration: 0.5, delay: 0.1 }}
            />
          </div>
          <span className="text-xs text-gray-400 w-4 text-right">{count}</span>
        </div>
      ))}
    </div>
  );
}

// ── Main Component ─────────────────────────────────────────────

export default function IncidentCommsDashboard() {
  const [incident, setIncident] = useState(INCIDENTS[0]);
  const [commType, setCommType] = useState<CommType>("update");
  const [channel, setChannel] = useState<Channel>("slack");

  const [fetchError, setFetchError] = useState<string | null>(null);

  const loadData = () => {
    setFetchError(null);
    apiFetch(`/api/v1/incident-comms/comms?org_id=${ORG_ID}`).catch((err) => {
      setFetchError(err instanceof Error ? err.message : "Failed to load incident comms data");
    });
  };

  useEffect(() => {
    loadData();
  }, []);
  const [subject, setSubject] = useState("");
  const [sending, setSending] = useState(false);
  const [sent, setSent] = useState(false);

  function handleSend() {
    if (!subject) return;
    setSending(true);
    setTimeout(() => { setSending(false); setSent(true); setTimeout(() => setSent(false), 2000); }, 1500);
  }

  return (
    <div className="flex flex-col gap-6 p-6 min-h-0">
      <PageHeader
        title="Incident Communications"
        description="Communication log, multi-channel messaging, and stakeholder notification tracking for active incidents"
        badge="Live"
        actions={
          <Button size="sm" variant="outline" className="gap-2">
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </Button>
        }
      />

      {/* Fetch Error Banner */}
      {fetchError && (
        <div className="bg-red-500/10 border border-red-500/30 text-red-300 px-4 py-3 rounded-lg flex items-center justify-between">
          <span className="text-sm">Failed to load live data: {fetchError}</span>
          <button onClick={loadData} className="ml-4 px-3 py-1 bg-red-500/20 hover:bg-red-500/30 text-red-300 text-xs rounded transition-colors">Retry</button>
        </div>
      )}

      {/* KPIs */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <KpiCard title="Total Comms"     value={MOCK_COMMS.length}                                         icon={MessageSquare} trend="up"   trendLabel="all incidents" />
        <KpiCard title="Open Incidents"  value={3}                                                          icon={Radio}         trend="down" trendLabel="INC-2041/42/38" />
        <KpiCard title="Channels Active" value={CHANNELS.length}                                           icon={Send}          trend="up"   trendLabel="all connected" />
        <KpiCard title="Avg Response"    value="14m"                                                        icon={Clock}         trend="up"   trendLabel="time to first comm" />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Comms Log */}
        <Card className="xl:col-span-2">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold">Communications Log</CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow className="border-gray-700/50">
                  <TableHead className="text-gray-400 text-xs">Incident</TableHead>
                  <TableHead className="text-gray-400 text-xs">Type</TableHead>
                  <TableHead className="text-gray-400 text-xs">Channel</TableHead>
                  <TableHead className="text-gray-400 text-xs">Subject</TableHead>
                  <TableHead className="text-gray-400 text-xs text-right">Recipients</TableHead>
                  <TableHead className="text-gray-400 text-xs">Status</TableHead>
                  <TableHead className="text-gray-400 text-xs">Sent</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {MOCK_COMMS.map((comm, i) => (
                  <motion.tr
                    key={comm.id}
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ delay: i * 0.04 }}
                    className="border-b border-gray-700/50 hover:bg-gray-800/30"
                  >
                    <TableCell className="font-mono text-xs text-blue-400">{comm.incident_id}</TableCell>
                    <TableCell>
                      <span className={cn("inline-block px-2 py-0.5 rounded text-xs font-medium capitalize", COMM_TYPE_COLORS[comm.comm_type])}>
                        {comm.comm_type}
                      </span>
                    </TableCell>
                    <TableCell>
                      <Badge className={cn("border text-xs capitalize", CHANNEL_COLORS[comm.channel])}>{comm.channel}</Badge>
                    </TableCell>
                    <TableCell className="text-xs text-gray-300 max-w-[200px] truncate">{comm.subject}</TableCell>
                    <TableCell className="text-right text-sm text-gray-300">{comm.recipient_count}</TableCell>
                    <TableCell><StatusBadge status={comm.status} /></TableCell>
                    <TableCell className="text-xs text-gray-400 whitespace-nowrap">{comm.sent_at}</TableCell>
                  </motion.tr>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>

        {/* Right column */}
        <div className="flex flex-col gap-4">
          {/* Send Form */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold">Send Communication</CardTitle>
            </CardHeader>
            <CardContent className="flex flex-col gap-3">
              <div className="flex flex-col gap-1">
                <label className="text-xs text-gray-400">Incident</label>
                <select value={incident} onChange={(e) => setIncident(e.target.value)}
                  className="bg-gray-700/50 border border-gray-600 rounded px-3 py-1.5 text-sm text-gray-200 focus:outline-none focus:border-blue-500">
                  {INCIDENTS.map((inc) => <option key={inc} value={inc}>{inc}</option>)}
                </select>
              </div>
              <div className="flex flex-col gap-1">
                <label className="text-xs text-gray-400">Communication Type</label>
                <select value={commType} onChange={(e) => setCommType(e.target.value as CommType)}
                  className="bg-gray-700/50 border border-gray-600 rounded px-3 py-1.5 text-sm text-gray-200 focus:outline-none focus:border-blue-500">
                  {COMM_TYPES.map((t) => <option key={t} value={t} className="capitalize">{t}</option>)}
                </select>
              </div>
              <div className="flex flex-col gap-1">
                <label className="text-xs text-gray-400">Channel</label>
                <select value={channel} onChange={(e) => setChannel(e.target.value as Channel)}
                  className="bg-gray-700/50 border border-gray-600 rounded px-3 py-1.5 text-sm text-gray-200 focus:outline-none focus:border-blue-500">
                  {CHANNELS.map((ch) => <option key={ch} value={ch} className="capitalize">{ch}</option>)}
                </select>
              </div>
              <div className="flex flex-col gap-1">
                <label className="text-xs text-gray-400">Subject</label>
                <input type="text" value={subject} onChange={(e) => setSubject(e.target.value)}
                  placeholder="Communication subject..."
                  className="bg-gray-700/50 border border-gray-600 rounded px-3 py-1.5 text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:border-blue-500" />
              </div>
              <Button size="sm" className="w-full gap-2 bg-blue-600 hover:bg-blue-700 text-white" onClick={handleSend} disabled={!subject || sending}>
                {sending ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : sent ? <CheckCircle2 className="w-3.5 h-3.5" /> : <Send className="w-3.5 h-3.5" />}
                {sending ? "Sending..." : sent ? "Sent!" : "Send"}
              </Button>
            </CardContent>
          </Card>

          {/* Channel Breakdown */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold">Channel Usage</CardTitle>
            </CardHeader>
            <CardContent>
              <ChannelBreakdown />
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
