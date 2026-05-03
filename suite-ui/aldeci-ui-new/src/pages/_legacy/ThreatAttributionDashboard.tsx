/**
 * Threat Attribution Dashboard
 * Route: /threat-attribution
 * API: GET /api/v1/threat-attribution/attributions
 *      GET /api/v1/threat-attribution/stats
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
import { EmptyState } from "@/components/shared/EmptyState";
import { cn } from "@/lib/utils";

const API_BASE = import.meta.env.VITE_API_URL || "";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";

async function apiFetch(path: string, opts?: RequestInit) {
  const res = await fetch(`${API_BASE}${path}`, {
    ...opts,
    headers: { "X-API-Key": API_KEY, "Content-Type": "application/json", ...(opts?.headers ?? {}) },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

interface Attribution {
  id?: string;
  incident_id?: string;
  actor_id?: string;
  confidence?: string;
  status?: string;
  analyst?: string;
  attribution_date?: string;
}

interface AttributionStats {
  threat_actors?: number;
  active_actors?: number;
  total_attributions?: number;
  confirmed_attributions?: number;
}

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
  const label: Record<string, string> = { closed: "Closed", open: "Open", under_review: "Under Review" };
  return (
    <Badge className={cn("text-[10px] border", map[status] ?? "border-border")}>
      {label[status] ?? status}
    </Badge>
  );
}

export default function ThreatAttributionDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [loading, setLoading] = useState(true);
  const [attributions, setAttributions] = useState<Attribution[]>([]);
  const [stats, setStats] = useState<AttributionStats>({});
  const [error, setError] = useState<string | null>(null);

  function load() {
    setLoading(true);
    setError(null);
    Promise.allSettled([
      apiFetch("/api/v1/threat-attribution/attributions?org_id=default"),
      apiFetch("/api/v1/threat-attribution/stats?org_id=default"),
    ]).then(([attrRes, statsRes]) => {
      if (attrRes.status === "fulfilled") {
        const val = attrRes.value;
        setAttributions(val?.attributions ?? val?.items ?? (Array.isArray(val) ? val : []));
      } else {
        setError("Attribution API unavailable");
      }
      if (statsRes.status === "fulfilled") setStats(statsRes.value ?? {});
      setLoading(false);
    });
  }

  useEffect(() => { load(); }, []);

  const handleRefresh = () => { setRefreshing(true); load(); setTimeout(() => setRefreshing(false), 800); };

  if (loading) return <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-rose-500" /></div>;

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Threat Attribution"
        description="Threat actor attribution analysis, incident linkage, and confidence-scored attribution lifecycle management"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Threat Actors"          value={stats.threat_actors ?? 0}          icon={Users}         trend="flat" className="border-rose-500/20" />
        <KpiCard title="Active Actors"          value={stats.active_actors ?? 0}          icon={AlertTriangle} trend="up"   className="border-red-500/20" />
        <KpiCard title="Total Attributions"     value={stats.total_attributions ?? 0}     icon={Link}          trend="up"   className="border-rose-500/20" />
        <KpiCard title="Confirmed Attributions" value={stats.confirmed_attributions ?? 0} icon={CheckCircle}   trend="up"   className="border-red-500/20" />
      </div>
      <Card className="border-rose-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-rose-400">
              <Target className="h-4 w-4" />Attribution Records
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
              {attributions.filter((a) => a.status === "open").length} open
            </Badge>
          </div>
          <CardDescription className="text-xs">Incident-to-actor attributions with confidence scoring and analyst assignment</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {error || attributions.length === 0 ? (
            <EmptyState icon={Target} title={error ?? "No attributions yet"} description="Attribution records will appear here once threat actors are linked to incidents." />
          ) : (
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
                  {attributions.map((attr, i) => (
                    <TableRow key={attr.id ?? i} className="hover:bg-muted/30">
                      <TableCell className="py-2 font-mono text-[11px] text-rose-300">{attr.incident_id ?? "—"}</TableCell>
                      <TableCell className="py-2 font-semibold text-[11px] text-red-300">{attr.actor_id ?? "—"}</TableCell>
                      <TableCell className="py-2"><ConfidenceBadge confidence={attr.confidence ?? "possible"} /></TableCell>
                      <TableCell className="py-2"><StatusBadge status={attr.status ?? "open"} /></TableCell>
                      <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">{attr.analyst ?? "—"}</TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground text-right">{attr.attribution_date ?? "—"}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}
