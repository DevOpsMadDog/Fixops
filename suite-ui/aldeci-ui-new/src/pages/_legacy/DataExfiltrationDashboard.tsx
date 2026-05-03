// FOLDED into DataDiscoveryHub at /discover/dspm?tab=exfiltration
/**
 * Data Exfiltration Dashboard
 *
 * Monitors and manages data exfiltration incidents across all detection vectors.
 *   1. KPI cards: Total Incidents, Confirmed, Blocked, Critical
 *   2. Incidents table
 *
 * API: GET /api/v1/data-exfiltration/{stats,incidents}
 */

import { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { motion } from "framer-motion";
import {
  ArrowUpFromLine, RefreshCw, ShieldAlert, Ban, AlertTriangle, CheckCircle,
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

function IncidentTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    cloud_upload:     "border-blue-500/30 text-blue-400 bg-blue-500/10",
    email_attachment: "border-orange-500/30 text-orange-400 bg-orange-500/10",
    usb_transfer:     "border-purple-500/30 text-purple-400 bg-purple-500/10",
    http_exfil:       "border-red-500/30 text-red-400 bg-red-500/10",
    dns_tunnel:       "border-red-500/30 text-red-400 bg-red-500/10",
    print_to_file:    "border-gray-500/30 text-gray-400 bg-gray-500/10",
    api_exfil:        "border-amber-500/30 text-amber-400 bg-amber-500/10",
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

function DataClassBadge({ cls }: { cls: string }) {
  const map: Record<string, string> = {
    PII:          "border-red-500/30 text-red-400 bg-red-500/10",
    PHI:          "border-red-500/30 text-red-400 bg-red-500/10",
    PCI:          "border-red-500/30 text-red-400 bg-red-500/10",
    Confidential: "border-orange-500/30 text-orange-400 bg-orange-500/10",
    IP:           "border-purple-500/30 text-purple-400 bg-purple-500/10",
    Financial:    "border-amber-500/30 text-amber-400 bg-amber-500/10",
    Internal:     "border-gray-500/30 text-gray-400 bg-gray-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border", map[cls] ?? "border-border text-muted-foreground")}>
      {cls}
    </Badge>
  );
}

function IncidentStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    confirmed:      "border-red-500/30 text-red-400 bg-red-500/10",
    blocked:        "border-green-500/30 text-green-400 bg-green-500/10",
    under_review:   "border-blue-500/30 text-blue-400 bg-blue-500/10",
    false_positive: "border-gray-500/30 text-gray-400 bg-gray-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border text-muted-foreground")}>
      {status.replace(/_/g, " ")}
    </Badge>
  );
}

// ── Component ──────────────────────────────────────────────────

export default function DataExfiltrationDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [dataLoading, setDataLoading] = useState(false);
  const [liveData, setLiveData] = useState<{
    stats: any | null;
    incidents: any[] | null;
  }>({ stats: null, incidents: null });

  const fetchData = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/data-exfiltration/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/data-exfiltration/incidents?org_id=${ORG_ID}`),
    ]).then(([statsRes, incRes]) => {
      setLiveData({
        stats:     statsRes.status === "fulfilled" ? statsRes.value : null,
        incidents: incRes.status   === "fulfilled" ? incRes.value   : null,
      });
    }).finally(() => setDataLoading(false));
  };

  useEffect(() => { fetchData(); }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchData();
    setTimeout(() => setRefreshing(false), 800);
  };

  const stats     = liveData.stats     ?? null;
  const incidents = liveData.incidents ?? [];
  const hasAnyData = Boolean(stats) || incidents.length > 0;

  if (!hasAnyData) return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      <PageHeader
        title="Data Exfiltration"
        description="Data loss prevention — exfiltration incident detection, classification, and response"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />
      <EmptyState
        icon={ArrowUpFromLine}
        title="No exfiltration incidents yet"
        description="Connect a DLP, CASB, or NDR source to populate this view."
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
        title="Data Exfiltration"
        description="Data loss prevention — exfiltration incident detection, classification, and response"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Incidents"    value={stats?.total_incidents ?? "—"}     icon={ArrowUpFromLine} trend="flat" />
        <KpiCard title="Confirmed"          value={stats?.confirmed_incidents ?? "—"} icon={ShieldAlert}     trend="down" className="border-red-500/20" />
        <KpiCard title="Blocked"            value={stats?.blocked_incidents ?? "—"}   icon={Ban}             trend="up"   className="border-green-500/20" />
        <KpiCard title="Critical"           value={stats?.critical_incidents ?? "—"}  icon={AlertTriangle}   trend="down" className="border-red-500/20" />
      </div>

      {/* Incidents Table */}
      <Card className="border-red-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
              <ArrowUpFromLine className="h-4 w-4" />
              Exfiltration Incidents
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
              {incidents.filter((inc: any) => inc.status === "confirmed").length} confirmed
            </Badge>
          </div>
          <CardDescription className="text-xs">Data exfiltration incidents with classification, detection method, and response status</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Incident Type</TableHead>
                  <TableHead className="text-[11px] h-8">Severity</TableHead>
                  <TableHead className="text-[11px] h-8">Data Class</TableHead>
                  <TableHead className="text-[11px] h-8">Detection</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {incidents.length === 0 ? (
                  <TableRow className="hover:bg-transparent">
                    <TableCell colSpan={5} className="p-0">
                      <EmptyState
                        icon={ArrowUpFromLine}
                        title="No exfiltration incidents"
                        description="Incidents from DLP/CASB/NDR detectors will appear here."
                      />
                    </TableCell>
                  </TableRow>
                ) : (
                  incidents.map((inc: any, i: number) => (
                    <TableRow key={i} className="hover:bg-muted/30">
                      <TableCell className="py-2"><IncidentTypeBadge type={inc.incident_type ?? "unknown"} /></TableCell>
                      <TableCell className="py-2"><SeverityBadge severity={inc.severity ?? "medium"} /></TableCell>
                      <TableCell className="py-2"><DataClassBadge cls={inc.data_classification ?? "Internal"} /></TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground">{inc.detection_method}</TableCell>
                      <TableCell className="py-2"><IncidentStatusBadge status={inc.status ?? "under_review"} /></TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Summary row */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        {[
          { label: "DLP",         color: "blue"   },
          { label: "CASB",        color: "purple" },
          { label: "NDR",         color: "orange" },
          { label: "API Gateway", color: "amber"  },
        ].map(({ label, color }) => {
          const count = incidents.filter((inc: any) => inc.detection_method === label).length;
          return (
            <Card key={label} className={`border-${color}-500/20`}>
              <CardContent className="pt-4 pb-3 text-center">
                <p className={`text-xl font-bold text-${color}-400`}>{count}</p>
                <p className="text-[11px] text-muted-foreground mt-0.5">{label} detections</p>
              </CardContent>
            </Card>
          );
        })}
      </div>
    </motion.div>
  );
}
