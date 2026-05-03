/**
 * Incident Response Dashboard — management view
 *
 * Full lifecycle incident management and playbook execution.
 * NOTE: IncidentTimeline.tsx exists at route /incident-timeline (different page).
 * This is the management/command view at /incident-response.
 *
 *   1. KPIs: Active Incidents, P1 Critical, MTTR, SLA Compliance
 *   2. Incidents table (12 rows)
 *   3. Response timeline stepper for first incident (6 steps, progress at step 3)
 *   4. Task checklist panel (8 tasks for active incident)
 *   5. Artifact list (5 artifacts)
 *
 * Route: /incident-response
 * API stubs: GET /api/v1/incidents  GET /api/v1/incidents/{id}/tasks
 */

import { useState, useEffect, useCallback } from "react";
import { Link } from "react-router-dom";
import { useAutoRefresh } from "@/hooks/use-auto-refresh";
import { Pause, Play } from "lucide-react";
import { motion } from "framer-motion";
import {
  AlertTriangle,
  Clock,
  Shield,
  Activity,
  RefreshCw,
  ExternalLink,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { cn } from "@/lib/utils";
import { usePageTitle } from "@/hooks/use-page-title";
import { EntityLink } from "@/components/EntityLink";
import { LiveEventStream } from "@/components/shared/LiveEventStream";

// ── API helpers ────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}?org_id=default`, {
    headers: { "X-API-Key": API_KEY },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ── Types ──────────────────────────────────────────────────────

type IncidentRow = {
  id: string;
  title: string;
  type: string;
  sev: string;
  status: string;
  analyst: string;
  open: string;
  slaDue: string;
  slaBreach: boolean;
};

// ── Helpers ────────────────────────────────────────────────────

const TYPE_COLORS: Record<string, string> = {
  ransomware:  "border-red-500/30 text-red-400 bg-red-500/10",
  phishing:    "border-amber-500/30 text-amber-400 bg-amber-500/10",
  data_breach: "border-purple-500/30 text-purple-400 bg-purple-500/10",
  ddos:        "border-blue-500/30 text-blue-400 bg-blue-500/10",
  insider:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
};

const SEV_COLORS: Record<string, string> = {
  P1: "border-red-500/30 text-red-400 bg-red-500/10",
  P2: "border-amber-500/30 text-amber-400 bg-amber-500/10",
  P3: "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
  P4: "border-blue-500/30 text-blue-400 bg-blue-500/10",
};

const STATUS_COLORS: Record<string, string> = {
  active:        "border-red-500/30 text-red-400 bg-red-500/10",
  contained:     "border-amber-500/30 text-amber-400 bg-amber-500/10",
  investigating: "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
  mitigating:    "border-blue-500/30 text-blue-400 bg-blue-500/10",
  eradicated:    "border-purple-500/30 text-purple-400 bg-purple-500/10",
  resolved:      "border-green-500/30 text-green-400 bg-green-500/10",
};

// ── Component ──────────────────────────────────────────────────

export default function IncidentResponseDashboard() {
  usePageTitle("Incident Response");
  const [refreshing, setRefreshing] = useState(false);
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);

  const fetchData = useCallback(() => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/incidents/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/incidents?org_id=${ORG_ID}&limit=20`),
      apiFetch(`/api/v1/soar/playbooks?org_id=${ORG_ID}`),
    ]).then(([statsResult, incidentsResult, playbooksResult]) => {
      const stats     = statsResult.status     === "fulfilled" ? statsResult.value     : null;
      const incidents = incidentsResult.status === "fulfilled" ? incidentsResult.value : null;
      const playbooks = playbooksResult.status === "fulfilled" ? playbooksResult.value : null;
      if (stats || incidents || playbooks) {
        setLiveData({ stats, incidents, playbooks });
      }
    }).finally(() => setDataLoading(false));
  }, []);

  useEffect(() => { fetchData(); }, [fetchData]);

  const { isPaused, togglePause, secondsAgo } = useAutoRefresh(fetchData, 30_000);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchData();
    setTimeout(() => setRefreshing(false), 800);
  };

  const liveActiveCount = liveData?.stats?.active_count ?? liveData?.stats?.open ?? null;
  const liveP1Count     = liveData?.stats?.p1_count ?? liveData?.stats?.critical ?? null;
  const liveMttr        = liveData?.stats?.mttr ?? liveData?.stats?.avg_mttr ?? null;
  const liveSlaComp     = liveData?.stats?.sla_compliance ?? liveData?.stats?.sla_met ?? null;
  const liveIncidents: IncidentRow[] =
    Array.isArray(liveData?.incidents)
      ? liveData.incidents.slice(0, 12).map((inc: any) => ({
          id: inc.incident_id ?? inc.id ?? inc.title?.slice(0, 8) ?? "INC-???",
          title: inc.title ?? inc.name ?? "Unknown incident",
          type: inc.type ?? inc.incident_type ?? "phishing",
          sev: inc.severity ?? inc.priority ?? "P3",
          status: inc.status ?? "active",
          analyst: inc.assigned_to ?? inc.analyst ?? "Unassigned",
          open: inc.open_duration ?? inc.age ?? "—",
          slaDue: inc.sla_due ?? inc.due_date ?? "—",
          slaBreach: inc.sla_breached ?? false,
        }))
      : Array.isArray(liveData?.incidents?.incidents)
        ? liveData.incidents.incidents.slice(0, 12).map((inc: any) => ({
            id: inc.incident_id ?? inc.id ?? "INC-???",
            title: inc.title ?? "Unknown incident",
            type: inc.type ?? "phishing",
            sev: inc.severity ?? "P3",
            status: inc.status ?? "active",
            analyst: inc.assigned_to ?? "Unassigned",
            open: inc.open_duration ?? "—",
            slaDue: inc.sla_due ?? "—",
            slaBreach: inc.sla_breached ?? false,
          }))
        : [];

  const hasAnyData =
    liveActiveCount != null ||
    liveP1Count != null ||
    liveMttr != null ||
    liveSlaComp != null ||
    liveIncidents.length > 0;

  if (!hasAnyData) return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      <PageHeader
        title="Incident Response"
        description="Full lifecycle incident management and playbook execution"
        actions={
          <div className="flex items-center gap-2">
            <span className="text-xs text-zinc-500">Updated {secondsAgo}s ago</span>
            <Button variant="outline" size="sm" onClick={togglePause}>
              {isPaused ? <Play className="h-4 w-4" /> : <Pause className="h-4 w-4" />}
            </Button>
            <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
              <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
            </Button>
          </div>
        }
      />
      <EmptyState
        icon={AlertTriangle}
        title="No incidents yet"
        description="Connect a SIEM, EDR, or SOAR source to populate incident response data."
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
        title="Incident Response"
        description="Full lifecycle incident management and playbook execution"
        actions={
          <div className="flex items-center gap-2">
            <span className="text-xs text-zinc-500">Updated {secondsAgo}s ago</span>
            <Button variant="outline" size="sm" onClick={togglePause}>
              {isPaused ? <Play className="h-4 w-4" /> : <Pause className="h-4 w-4" />}
            </Button>
            <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
              <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
            </Button>
          </div>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Active Incidents"  value={liveActiveCount ?? "—"} icon={AlertTriangle} trend="up"   className="border-red-500/20" />
        <KpiCard title="P1 Critical"       value={liveP1Count ?? "—"}     icon={Shield}        trend="up"   className="border-red-500/20" />
        <KpiCard title="MTTR"              value={liveMttr ?? "—"}        icon={Clock}         trend="down" />
        <KpiCard title="SLA Compliance"    value={liveSlaComp ?? "—"}     icon={Activity}      trend="up"   className="border-green-500/20" />
      </div>

      {/* Real-time security event stream */}
      <LiveEventStream
        title="Live Incident & Threat Stream"
        eventTypes={["incident", "threat", "alert", "sla_breach"]}
        heightClass="h-48"
        onEvent={() => { handleRefresh(); }}
        emptyMessage="No incidents in the live stream. New incidents from the SOC will appear here."
      />

      {/* Incidents table */}
      <Card className="border-red-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
              <AlertTriangle className="h-4 w-4" />
              Active &amp; Recent Incidents
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
              {liveActiveCount ?? 0} active
            </Badge>
          </div>
          <CardDescription className="text-xs">Full incident list — sorted by severity and open time</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">ID</TableHead>
                  <TableHead className="text-[11px] h-8">Title</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Sev</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8">Analyst</TableHead>
                  <TableHead className="text-[11px] h-8">Open</TableHead>
                  <TableHead className="text-[11px] h-8">SLA Due</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {liveIncidents.length === 0 && (
                  <TableRow className="hover:bg-transparent">
                    <TableCell colSpan={9} className="p-0">
                      <EmptyState
                        icon={AlertTriangle}
                        title="No incidents"
                        description="Incidents from your SIEM/EDR/SOAR connectors will appear here."
                      />
                    </TableCell>
                  </TableRow>
                )}
                {liveIncidents.map((inc) => (
                  <TableRow
                    key={inc.id}
                    className={cn("hover:bg-muted/30", inc.slaBreach && "bg-red-500/5 border-l-2 border-l-red-500")}
                  >
                    <TableCell className="text-xs font-mono py-2.5">
                      <EntityLink type="incident" id={inc.id}>
                        {inc.id}
                      </EntityLink>
                    </TableCell>
                    <TableCell className="text-xs py-2.5 max-w-[200px] truncate">{inc.title}</TableCell>
                    <TableCell className="py-2.5">
                      <Badge className={cn("text-[10px] border", TYPE_COLORS[inc.type])}>
                        {inc.type.replace("_", " ")}
                      </Badge>
                    </TableCell>
                    <TableCell className="py-2.5">
                      <Badge className={cn("text-[10px] border font-bold", SEV_COLORS[inc.sev])}>
                        {inc.sev}
                      </Badge>
                    </TableCell>
                    <TableCell className="py-2.5">
                      <Badge className={cn("text-[10px] border capitalize", STATUS_COLORS[inc.status])}>
                        {inc.status}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-xs font-mono py-2.5 text-muted-foreground">{inc.analyst}</TableCell>
                    <TableCell className="text-xs tabular-nums py-2.5 text-muted-foreground">{inc.open}</TableCell>
                    <TableCell className={cn("text-xs tabular-nums py-2.5", inc.slaBreach ? "text-red-400 font-bold" : "text-muted-foreground")}>
                      {inc.slaDue.split(" ")[1]}
                      {inc.slaBreach && <span className="ml-1 text-[10px]">⚠ breached</span>}
                    </TableCell>
                    <TableCell className="py-2.5 text-right">
                      <Button variant="outline" size="sm" className="h-6 px-2 text-[10px]">
                        <ExternalLink className="h-3 w-3 mr-1" />Open
                      </Button>
                    </TableCell>
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
