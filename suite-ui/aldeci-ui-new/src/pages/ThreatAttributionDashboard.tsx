/**
 * Threat Attribution Dashboard
 *
 * Threat actor attribution analysis and incident linkage tracking.
 *   1. KPIs: Threat Actors, Active Actors, Total Attributions, Confirmed Attributions
 *   2. Attributions table (incident_id, actor_id, confidence, status, analyst, attribution_date)
 *
 * Route: /threat-attribution
 * API: GET /api/v1/threat-attribution
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Target, RefreshCw, Users, AlertTriangle, Link, CheckCircle } from "lucide-react";

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
  const res = await fetch(`${API_BASE}${path}`, {
    ...opts,
    headers: { "X-API-Key": API_KEY, "Content-Type": "application/json", ...(opts?.headers ?? {}) },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ── Mock data ──────────────────────────────────────────────────

const MOCK_ATTRIBUTIONS = [
  { id: "attr-001", incident_id: "INC-2026-0041", actor_id: "APT29",        confidence: "confirmed", status: "closed",      analyst: "j.chen",    attribution_date: "2026-04-14" },
  { id: "attr-002", incident_id: "INC-2026-0038", actor_id: "Lazarus Group", confidence: "likely",    status: "open",        analyst: "m.patel",   attribution_date: "2026-04-13" },
  { id: "attr-003", incident_id: "INC-2026-0035", actor_id: "FIN7",          confidence: "possible",  status: "under_review",analyst: "s.kim",     attribution_date: "2026-04-12" },
  { id: "attr-004", incident_id: "INC-2026-0031", actor_id: "APT41",         confidence: "confirmed", status: "closed",      analyst: "r.nguyen",  attribution_date: "2026-04-10" },
  { id: "attr-005", incident_id: "INC-2026-0028", actor_id: "Scattered Spider",confidence: "likely",  status: "open",        analyst: "j.chen",    attribution_date: "2026-04-09" },
  { id: "attr-006", incident_id: "INC-2026-0025", actor_id: "TA505",         confidence: "unlikely",  status: "closed",      analyst: "m.patel",   attribution_date: "2026-04-08" },
  { id: "attr-007", incident_id: "INC-2026-0022", actor_id: "Cozy Bear",     confidence: "confirmed", status: "closed",      analyst: "s.kim",     attribution_date: "2026-04-07" },
  { id: "attr-008", incident_id: "INC-2026-0019", actor_id: "REvil",         confidence: "possible",  status: "under_review",analyst: "r.nguyen",  attribution_date: "2026-04-06" },
  { id: "attr-009", incident_id: "INC-2026-0015", actor_id: "Sandworm",      confidence: "confirmed", status: "closed",      analyst: "j.chen",    attribution_date: "2026-04-04" },
  { id: "attr-010", incident_id: "INC-2026-0011", actor_id: "Lapsus$",       confidence: "likely",    status: "open",        analyst: "m.patel",   attribution_date: "2026-04-02" },
];

const MOCK_STATS = { threat_actors: 47, active_actors: 12, total_attributions: 183, confirmed_attributions: 74 };

// ── Badge helpers ──────────────────────────────────────────────

function ConfidenceBadge({ confidence }: { confidence: string }) {
  const map: Record<string, string> = {
    confirmed: "border-red-500/30 text-red-400 bg-red-500/10",
    likely:    "border-orange-500/30 text-orange-400 bg-orange-500/10",
    possible:  "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    unlikely:  "border-zinc-500/30 text-zinc-400 bg-zinc-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[confidence] ?? "border-border")}>
      {confidence}
    </Badge>
  );
}

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    closed:       "border-green-500/30 text-green-400 bg-green-500/10",
    open:         "border-red-500/30 text-red-400 bg-red-500/10",
    under_review: "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
  };
  const label: Record<string, string> = {
    closed:       "Closed",
    open:         "Open",
    under_review: "Under Review",
  };
  return (
    <Badge className={cn("text-[10px] border", map[status] ?? "border-border")}>
      {label[status] ?? status}
    </Badge>
  );
}

// ── Component ──────────────────────────────────────────────────

export default function ThreatAttributionDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveAttributions, setLiveAttributions] = useState<any[] | null>(null);
  const [liveStats, setLiveStats] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.allSettled([
      apiFetch(`/api/v1/threat-attribution/attributions?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/threat-attribution/stats?org_id=${ORG_ID}`),
    ]).then(([attrRes, statsRes]) => {
      if (attrRes.status === "fulfilled") setLiveAttributions(attrRes.value?.attributions ?? attrRes.value ?? null);
      if (statsRes.status === "fulfilled") setLiveStats(statsRes.value ?? null);
    })
      .finally(() => setLoading(false));
  }, []);

  const handleRefresh = () => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); };

  const attributions = liveAttributions ?? MOCK_ATTRIBUTIONS;
  const stats        = liveStats        ?? MOCK_STATS;

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
        title="Threat Attribution"
        description="Threat actor attribution analysis, incident linkage, and confidence-scored attribution lifecycle management"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Threat Actors"         value={stats.threat_actors}          icon={Users}         trend="flat" className="border-rose-500/20" />
        <KpiCard title="Active Actors"         value={stats.active_actors}          icon={AlertTriangle} trend="up"   className="border-red-500/20" />
        <KpiCard title="Total Attributions"    value={stats.total_attributions}     icon={Link}          trend="up"   className="border-rose-500/20" />
        <KpiCard title="Confirmed Attributions" value={stats.confirmed_attributions} icon={CheckCircle}   trend="up"   className="border-red-500/20" />
      </div>

      {/* Attributions Table */}
      <Card className="border-rose-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-rose-400">
              <Target className="h-4 w-4" />
              Attribution Records
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
              {attributions.filter((a: any) => a.status === "open").length} open
            </Badge>
          </div>
          <CardDescription className="text-xs">
            Incident-to-actor attributions with confidence scoring and analyst assignment
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Incident ID</TableHead>
                  <TableHead className="text-[11px] h-8">Threat Actor</TableHead>
                  <TableHead className="text-[11px] h-8">Confidence</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8">Analyst</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Attribution Date</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {attributions.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  attributions.map((attr: any, i: number) => (
                  <TableRow key={attr.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-mono text-[11px] text-rose-300">
                      {attr.incident_id ?? "—"}
                    </TableCell>
                    <TableCell className="py-2 font-semibold text-[11px] text-red-300">
                      {attr.actor_id ?? "—"}
                    </TableCell>
                    <TableCell className="py-2">
                      <ConfidenceBadge confidence={attr.confidence ?? "possible"} />
                    </TableCell>
                    <TableCell className="py-2">
                      <StatusBadge status={attr.status ?? "open"} />
                    </TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">
                      {attr.analyst ?? "—"}
                    </TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground text-right">
                      {attr.attribution_date ?? "—"}
                    </TableCell>
                  </TableRow>
                ))}
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
