// FOLDED into AppLayerSecurityHub at /discover/app-security?tab=browser (Phase 3, 2026-05-02)
/**
 * Browser Security Dashboard
 *
 * Browser policy enforcement, event monitoring, and extension risk management.
 *   1. KPI cards: Total Policies, Active Policies, Total Events, Blocked Events
 *   2. Browser Events table
 *   3. Extensions table
 *
 * API: GET /api/v1/browser-security/{stats,events,extensions}
 */

import { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { motion } from "framer-motion";
import {
  Globe, RefreshCw, ShieldCheck, AlertTriangle, Puzzle, Ban,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { cn } from "@/lib/utils";

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

// ── Badge helpers ──────────────────────────────────────────────

function EventTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    data_upload:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
    malicious_site:  "border-red-500/30 text-red-400 bg-red-500/10",
    file_download:   "border-blue-500/30 text-blue-400 bg-blue-500/10",
    credential_leak: "border-red-500/30 text-red-400 bg-red-500/10",
    script_inject:   "border-purple-500/30 text-purple-400 bg-purple-500/10",
    extension_abuse: "border-amber-500/30 text-amber-400 bg-amber-500/10",
    clipboard_copy:  "border-gray-500/30 text-gray-400 bg-gray-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border", map[type] ?? "border-border text-muted-foreground")}>
      {type.replace(/_/g, " ")}
    </Badge>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
    medium:   "border-amber-500/30 text-amber-400 bg-amber-500/10",
    low:      "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[severity] ?? "border-border text-muted-foreground")}>
      {severity}
    </Badge>
  );
}

function RiskLevelBadge({ level }: { level: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
    medium:   "border-amber-500/30 text-amber-400 bg-amber-500/10",
    low:      "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[level] ?? "border-border text-muted-foreground")}>
      {level}
    </Badge>
  );
}

function ExtStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    approved: "border-green-500/30 text-green-400 bg-green-500/10",
    flagged:  "border-amber-500/30 text-amber-400 bg-amber-500/10",
    blocked:  "border-red-500/30 text-red-400 bg-red-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border text-muted-foreground")}>
      {status}
    </Badge>
  );
}

function BrowserBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    chrome:  "border-blue-500/30 text-blue-400 bg-blue-500/10",
    firefox: "border-orange-500/30 text-orange-400 bg-orange-500/10",
    edge:    "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
    safari:  "border-gray-500/30 text-gray-400 bg-gray-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[type] ?? "border-border text-muted-foreground")}>
      {type}
    </Badge>
  );
}

// ── Component ──────────────────────────────────────────────────

export default function BrowserSecurityDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [dataLoading, setDataLoading] = useState(false);
  const [loading, setLoading] = useState(true);
  const [liveData, setLiveData] = useState<{
    stats: any | null;
    events: any[] | null;
    extensions: any[] | null;
  }>({ stats: null, events: null, extensions: null });

  const fetchData = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/browser-security/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/browser-security/events?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/browser-security/extensions?org_id=${ORG_ID}`),
    ]).then(([statsRes, eventsRes, extRes]) => {
      setLiveData({
        stats:      statsRes.status  === "fulfilled" ? statsRes.value  : null,
        events:     eventsRes.status === "fulfilled" ? eventsRes.value : null,
        extensions: extRes.status    === "fulfilled" ? extRes.value    : null,
      });
    }).finally(() => setDataLoading(false));
  };

  useEffect(() => { fetchData(); 
    setLoading(false);}, []);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchData();
    setTimeout(() => setRefreshing(false), 800);
  };

  const stats      = liveData.stats      ?? null;
  const events     = liveData.events     ?? [];
  const extensions = liveData.extensions ?? [];
  const hasAnyData = Boolean(stats) || events.length > 0 || extensions.length > 0;

  if (loading) return (
    <div className="space-y-4 p-6">
      {[1, 2, 3].map((i) => (
        <div key={i} className="h-24 rounded-lg bg-zinc-800/50 animate-pulse" />
      ))}
    </div>
  );

  if (!hasAnyData) return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      <PageHeader
        title="Browser Security"
        description="Browser policy enforcement, event monitoring, and extension risk management"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />
      <EmptyState
        icon={Globe}
        title="No browser security data yet"
        description="Connect a browser endpoint or DLP source to populate this view."
        action={
          <Link to="/onboarding" className="inline-flex items-center gap-1 rounded-md bg-blue-600 px-3 py-1.5 text-xs font-medium text-white hover:bg-blue-500">
            Start onboarding
          </Link>
        }
      />
    </motion.div>
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
        title="Browser Security"
        description="Browser policy enforcement, event monitoring, and extension risk management"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Policies"   value={stats?.total_policies ?? "—"}     icon={Globe}         trend="flat" />
        <KpiCard title="Active Policies"  value={stats?.active_policies ?? "—"}    icon={ShieldCheck}   trend="up"   className="border-green-500/20" />
        <KpiCard title="Total Events"     value={stats?.total_events ?? "—"}       icon={AlertTriangle} trend="flat" />
        <KpiCard title="Blocked Events"   value={stats?.blocked_events ?? "—"}     icon={Ban}           trend="down" className="border-red-500/20" />
      </div>

      {/* Browser Events Table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Globe className="h-4 w-4 text-blue-400" />
              Browser Events
            </CardTitle>
            <Badge className="text-[10px] border border-border text-muted-foreground">
              {events.length} recent
            </Badge>
          </div>
          <CardDescription className="text-xs">Recent browser security events with severity and block status</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Event Type</TableHead>
                  <TableHead className="text-[11px] h-8">Severity</TableHead>
                  <TableHead className="text-[11px] h-8">User</TableHead>
                  <TableHead className="text-[11px] h-8">Device</TableHead>
                  <TableHead className="text-[11px] h-8 text-center">Blocked</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {events.length === 0 ? (
                  <TableRow className="hover:bg-transparent">
                    <TableCell colSpan={5} className="p-0">
                      <EmptyState
                        icon={Globe}
                        title="No browser events yet"
                        description="Events from the browser policy enforcement engine will appear here."
                      />
                    </TableCell>
                  </TableRow>
                ) : (
                  events.map((ev: any, i: number) => (
                  <TableRow key={i} className="hover:bg-muted/30">
                    <TableCell className="py-2"><EventTypeBadge type={ev.event_type ?? "unknown"} /></TableCell>
                    <TableCell className="py-2"><SeverityBadge severity={ev.severity ?? "low"} /></TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">{ev.user_id}</TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">{ev.device_id}</TableCell>
                    <TableCell className="py-2 text-center">
                      {ev.blocked
                        ? <Ban className="h-3.5 w-3.5 text-red-400 inline" />
                        : <span className="text-[10px] text-muted-foreground">—</span>}
                    </TableCell>
                  </TableRow>
                ))
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Extensions Table */}
      <Card className="border-purple-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-purple-400">
              <Puzzle className="h-4 w-4" />
              Browser Extensions
            </CardTitle>
            <Badge className="text-[10px] border border-purple-500/30 text-purple-400 bg-purple-500/10">
              {extensions.filter((e: any) => e.status === "blocked").length} blocked
            </Badge>
          </div>
          <CardDescription className="text-xs">Installed browser extensions with risk assessment and approval status</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Name</TableHead>
                  <TableHead className="text-[11px] h-8">Browser</TableHead>
                  <TableHead className="text-[11px] h-8">Risk</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8">Publisher</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {extensions.length === 0 ? (
                  <TableRow className="hover:bg-transparent">
                    <TableCell colSpan={5} className="p-0">
                      <EmptyState
                        icon={Puzzle}
                        title="No extensions tracked yet"
                        description="Browser extensions discovered by the agent will be listed here."
                      />
                    </TableCell>
                  </TableRow>
                ) : (
                  extensions.map((ext: any, i: number) => (
                  <TableRow key={ext.name ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 text-[11px] font-medium">{ext.name}</TableCell>
                    <TableCell className="py-2"><BrowserBadge type={ext.browser_type ?? "chrome"} /></TableCell>
                    <TableCell className="py-2"><RiskLevelBadge level={ext.risk_level ?? "low"} /></TableCell>
                    <TableCell className="py-2"><ExtStatusBadge status={ext.status ?? "flagged"} /></TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{ext.publisher}</TableCell>
                  </TableRow>
                ))
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
