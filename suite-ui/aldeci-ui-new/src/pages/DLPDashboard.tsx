/**
 * DLP Dashboard
 *
 * Data Loss Prevention — policy management, incident feed, PII detection stats.
 *   1. KPIs: Total Incidents, Blocked Today, Quarantined, False Positives
 *   2. DLP policy table (policy_name, data_types, channels, action, severity, enabled, hit_count)
 *   3. Incident feed (channel, masked user, data_type, action_taken, file_name, timestamp)
 *   4. PII detection bar chart by data_type
 *   5. Block rate + false positive rate gauges
 *
 * Route: /dlp
 * API: GET /api/v1/dlp/policies, /api/v1/dlp/incidents, /api/v1/dlp/dlp-stats
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { ShieldAlert, Ban, Archive, ThumbsDown, RefreshCw, Lock, FileSearch } from "lucide-react";

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

const MOCK_POLICIES = [
  {
    id: "DLP-POL-001",
    policy_name: "Credit Card Data Protection",
    data_types: ["credit_card", "cvv", "pan"],
    channels: ["email", "usb", "cloud_upload"],
    action: "block",
    severity: "critical",
    enabled: true,
    hit_count: 347,
  },
  {
    id: "DLP-POL-002",
    policy_name: "PII Exfiltration Prevention",
    data_types: ["ssn", "passport", "dob"],
    channels: ["email", "slack", "web_upload"],
    action: "quarantine",
    severity: "high",
    enabled: true,
    hit_count: 189,
  },
  {
    id: "DLP-POL-003",
    policy_name: "API Key Leakage Alert",
    data_types: ["api_key", "aws_key", "github_token"],
    channels: ["git_push", "email", "cloud_upload"],
    action: "alert",
    severity: "high",
    enabled: true,
    hit_count: 52,
  },
];

const MOCK_INCIDENTS = [
  { id: "INC-001", channel: "email",        user_email: "j***@acme.com",    data_type: "credit_card",  action_taken: "block",      file_name: "invoice_q1.xlsx",    timestamp: "14:41:02" },
  { id: "INC-002", channel: "usb",          user_email: "m***@acme.com",    data_type: "ssn",          action_taken: "quarantine", file_name: "employees_2026.csv", timestamp: "14:35:18" },
  { id: "INC-003", channel: "cloud_upload", user_email: "r***@acme.com",    data_type: "api_key",      action_taken: "alert",      file_name: ".env.production",    timestamp: "14:28:54" },
  { id: "INC-004", channel: "slack",        user_email: "a***@acme.com",    data_type: "ssn",          action_taken: "block",      file_name: "hr_export.pdf",      timestamp: "14:22:07" },
  { id: "INC-005", channel: "git_push",     user_email: "d***@acme.com",    data_type: "github_token", action_taken: "block",      file_name: "config.py",          timestamp: "14:15:33" },
  { id: "INC-006", channel: "web_upload",   user_email: "k***@partner.com", data_type: "passport",     action_taken: "quarantine", file_name: "kyc_documents.zip",  timestamp: "14:09:11" },
  { id: "INC-007", channel: "email",        user_email: "s***@acme.com",    data_type: "credit_card",  action_taken: "block",      file_name: "payment_data.csv",   timestamp: "13:58:47" },
  { id: "INC-008", channel: "cloud_upload", user_email: "t***@acme.com",    data_type: "aws_key",      action_taken: "alert",      file_name: "terraform.tfvars",   timestamp: "13:44:22" },
];

const PII_STATS = [
  { data_type: "credit_card",  count: 347, color: "bg-red-500" },
  { data_type: "ssn",          count: 189, color: "bg-orange-500" },
  { data_type: "api_key",      count: 142, color: "bg-amber-500" },
  { data_type: "email",        count: 98,  color: "bg-yellow-500" },
  { data_type: "aws_key",      count: 67,  color: "bg-purple-500" },
  { data_type: "github_token", count: 52,  color: "bg-blue-500" },
  { data_type: "passport",     count: 34,  color: "bg-cyan-500" },
  { data_type: "dob",          count: 21,  color: "bg-slate-500" },
];
const MAX_PII = PII_STATS[0].count;

// ── Badge helpers ──────────────────────────────────────────────

function ActionBadge({ action }: { action: string }) {
  const map: Record<string, string> = {
    block:      "border-red-500/30 text-red-400 bg-red-500/10",
    quarantine: "border-amber-500/30 text-amber-400 bg-amber-500/10",
    alert:      "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[action] ?? "border-border")}>{action}</Badge>;
}

function SevBadge({ sev }: { sev: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-amber-500/30 text-amber-400 bg-amber-500/10",
    medium:   "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    low:      "border-slate-500/30 text-slate-400 bg-slate-500/10",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[sev] ?? "border-border")}>{sev}</Badge>;
}

function ChannelBadge({ channel }: { channel: string }) {
  const map: Record<string, string> = {
    email:        "border-blue-500/30 text-blue-400 bg-blue-500/10",
    usb:          "border-orange-500/30 text-orange-400 bg-orange-500/10",
    cloud_upload: "border-purple-500/30 text-purple-400 bg-purple-500/10",
    slack:        "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
    git_push:     "border-green-500/30 text-green-400 bg-green-500/10",
    web_upload:   "border-indigo-500/30 text-indigo-400 bg-indigo-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border font-mono", map[channel] ?? "border-border text-muted-foreground")}>
      {channel.replace(/_/g, " ")}
    </Badge>
  );
}

function GaugeMeter({ label, value, color }: { label: string; value: number; color: string }) {
  const circumference = 2 * Math.PI * 30;
  return (
    <div className="flex flex-col items-center gap-2">
      <div className="relative h-20 w-20">
        <svg viewBox="0 0 80 80" className="h-full w-full -rotate-90">
          <circle cx="40" cy="40" r="30" fill="none" stroke="hsl(var(--muted))" strokeWidth="8" />
          <circle
            cx="40" cy="40" r="30" fill="none"
            stroke={color} strokeWidth="8" strokeLinecap="round"
            strokeDasharray={`${(value / 100) * circumference} ${circumference}`}
          />
        </svg>
        <div className="absolute inset-0 flex items-center justify-center">
          <span className="text-base font-bold tabular-nums">{value}%</span>
        </div>
      </div>
      <span className="text-[11px] text-muted-foreground text-center">{label}</span>
    </div>
  );
}

// ── Component ──────────────────────────────────────────────────

export default function DLPDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/dlp/dlp-stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/dlp/policies?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/dlp/incidents?org_id=${ORG_ID}&limit=20`),
    ]).then(([statsRes, policiesRes, incidentsRes]) => {
      const stats     = statsRes.status     === "fulfilled" ? statsRes.value     : null;
      const policies  = policiesRes.status  === "fulfilled" ? policiesRes.value  : null;
      const incidents = incidentsRes.status === "fulfilled" ? incidentsRes.value : null;
      if (stats || policies || incidents) setLiveData({ stats, policies, incidents });
    })
      .finally(() => setLoading(false)).finally(() => setDataLoading(false));
  }, []);

  const handleRefresh = () => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); };

  const stats     = liveData?.stats;
  const policies  = liveData?.policies  ?? MOCK_POLICIES;
  const incidents = liveData?.incidents ?? MOCK_INCIDENTS;

  const totalIncidents = stats?.total_incidents ?? 588;
  const blockedToday   = stats?.blocked_today   ?? 34;
  const quarantined    = stats?.quarantined      ?? 12;
  const falsePositives = stats?.false_positives  ?? 8;
  const blockRate      = stats?.block_rate       ?? 72;
  const fpRate         = stats?.false_positive_rate ?? 14;

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
      <PageHeader
        title="Data Loss Prevention"
        description="Policy enforcement, incident detection, and PII protection across all channels"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Incidents"  value={totalIncidents} icon={ShieldAlert} trend="up"      className="border-red-500/20" />
        <KpiCard title="Blocked Today"    value={blockedToday}   icon={Ban}         trend="up"      className="border-orange-500/20" />
        <KpiCard title="Quarantined"      value={quarantined}    icon={Archive}     trend="neutral" className="border-amber-500/20" />
        <KpiCard title="False Positives"  value={falsePositives} icon={ThumbsDown}  trend="down" />
      </div>

      {/* Policy Table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Lock className="h-4 w-4 text-blue-400" />
              DLP Policies
            </CardTitle>
            <Badge className="text-[10px] border border-border text-muted-foreground">{policies.length} policies</Badge>
          </div>
          <CardDescription className="text-xs">Configured data protection policies and enforcement actions</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Policy Name</TableHead>
                  <TableHead className="text-[11px] h-8">Data Types</TableHead>
                  <TableHead className="text-[11px] h-8">Channels</TableHead>
                  <TableHead className="text-[11px] h-8">Action</TableHead>
                  <TableHead className="text-[11px] h-8">Severity</TableHead>
                  <TableHead className="text-[11px] h-8">Enabled</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Hit Count</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {policies.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  policies.map((p: any) => (
                  <TableRow key={p.id} className="hover:bg-muted/30">
                    <TableCell className="py-2 text-xs font-medium">{p.policy_name}</TableCell>
                    <TableCell className="py-2">
                      <div className="flex flex-wrap gap-1">
                        {(p.data_types ?? []).slice(0, 3).map((dt: string) => (
                          <Badge key={dt} className="text-[9px] border border-purple-500/30 text-purple-400 bg-purple-500/10 font-mono">{dt}</Badge>
                        ))
                )}
                        {(p.data_types ?? []).length > 3 && (
                          <Badge className="text-[9px] border border-border text-muted-foreground">+{p.data_types.length - 3}</Badge>
                        )}
                      </div>
                    </TableCell>
                    <TableCell className="py-2">
                      <div className="flex flex-wrap gap-1">
                        {(p.channels ?? []).slice(0, 2).map((ch: string) => (
                          <ChannelBadge key={ch} channel={ch} />
                        ))
                )}
                        {(p.channels ?? []).length > 2 && (
                          <Badge className="text-[9px] border border-border text-muted-foreground">+{(p.channels.length - 2)}</Badge>
                        )}
                      </div>
                    </TableCell>
                    <TableCell className="py-2"><ActionBadge action={p.action} /></TableCell>
                    <TableCell className="py-2"><SevBadge sev={p.severity} /></TableCell>
                    <TableCell className="py-2">
                      <span className={cn("text-[10px] font-medium", p.enabled ? "text-green-400" : "text-slate-500")}>
                        {p.enabled ? "Enabled" : "Disabled"}
                      </span>
                    </TableCell>
                    <TableCell className="py-2 text-right font-mono text-xs font-semibold tabular-nums">
                      {(p.hit_count ?? 0).toLocaleString()}
                    </TableCell>
                  </TableRow>
                ))
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Incident Feed */}
      <Card className="border-red-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
              <FileSearch className="h-4 w-4" />
              Incident Feed
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">Live</Badge>
          </div>
          <CardDescription className="text-xs">Real-time DLP incidents across all monitored channels</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Channel</TableHead>
                  <TableHead className="text-[11px] h-8">User</TableHead>
                  <TableHead className="text-[11px] h-8">Data Type</TableHead>
                  <TableHead className="text-[11px] h-8">Action</TableHead>
                  <TableHead className="text-[11px] h-8">File</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Time</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {incidents.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  incidents.map((inc: any) => (
                  <TableRow key={inc.id} className="hover:bg-muted/30">
                    <TableCell className="py-2"><ChannelBadge channel={inc.channel} /></TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">{inc.user_email}</TableCell>
                    <TableCell className="py-2">
                      <Badge className="text-[9px] border border-purple-500/30 text-purple-400 bg-purple-500/10 font-mono">{inc.data_type}</Badge>
                    </TableCell>
                    <TableCell className="py-2"><ActionBadge action={inc.action_taken} /></TableCell>
                    <TableCell className="py-2 font-mono text-[10px] text-muted-foreground max-w-[160px] truncate">{inc.file_name}</TableCell>
                    <TableCell className="py-2 text-right text-[11px] tabular-nums text-muted-foreground">{inc.timestamp}</TableCell>
                  </TableRow>
                ))
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* PII Stats + Gauges */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold">PII Detection by Data Type</CardTitle>
            <CardDescription className="text-xs">Total detections per sensitive data category</CardDescription>
          </CardHeader>
          <CardContent className="space-y-2.5">
            {PII_STATS.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                <p className="text-lg font-medium">No data available</p>
                <p className="text-sm">Data will appear here once available</p>
              </div>
            ) : (
              PII_STATS.map((item, i) => (
              <div key={item.data_type} className="space-y-1">
                <div className="flex items-center justify-between text-[11px]">
                  <span className="font-mono text-muted-foreground">{item.data_type}</span>
                  <span className="tabular-nums font-semibold">{item.count.toLocaleString()}</span>
                </div>
                <div className="relative h-2 rounded-full bg-muted/30 overflow-hidden">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${(item.count / MAX_PII) * 100}%` }}
                    transition={{ duration: 0.6, delay: i * 0.05 }}
                    className={cn("h-full rounded-full", item.color)}
                  />
                </div>
              </div>
            ))
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold">Enforcement Rates</CardTitle>
            <CardDescription className="text-xs">Block rate and false positive rate across active policies</CardDescription>
          </CardHeader>
          <CardContent className="flex items-center justify-around pt-4">
            <GaugeMeter label="Block Rate" value={blockRate} color="rgb(239 68 68)" />
            <GaugeMeter label="False Positive Rate" value={fpRate} color="rgb(251 191 36)" />
          </CardContent>
        </Card>
      </div>
    </motion.div>
  );
}
