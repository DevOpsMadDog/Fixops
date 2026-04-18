/**
 * Cloud Workload Protection Dashboard
 *
 * Cloud workload runtime protection and threat detection.
 *   1. KPI cards: Total Workloads, Protected, Unprotected, Active Threats
 *   2. Workloads table
 *   3. Threats table
 *
 * API: GET /api/v1/cwp/{stats,workloads,threats}
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Cloud, RefreshCw, AlertTriangle, ShieldAlert, ShieldCheck, ShieldOff } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
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

// ── Mock data (fallback) ───────────────────────────────────────

const MOCK_STATS = {
  total_workloads: 287,
  protected_workloads: 251,
  unprotected_workloads: 36,
  active_threats: 9,
};

const MOCK_WORKLOADS = [
  { workload_name: "api-gateway-prod",   workload_type: "Container",   cloud_provider: "AWS",   region: "us-east-1",    risk_level: "low",    protection_status: "protected"    },
  { workload_name: "ml-training-gpu01",  workload_type: "VM",          cloud_provider: "GCP",   region: "us-central1",  risk_level: "medium", protection_status: "protected"    },
  { workload_name: "legacy-monolith",    workload_type: "VM",          cloud_provider: "Azure",  region: "eastus",       risk_level: "high",   protection_status: "unprotected"  },
  { workload_name: "data-pipeline-prod", workload_type: "Serverless",  cloud_provider: "AWS",   region: "eu-west-1",    risk_level: "medium", protection_status: "protected"    },
  { workload_name: "k8s-worker-node-05", workload_type: "Container",   cloud_provider: "GCP",   region: "europe-west4", risk_level: "critical",protection_status: "unprotected" },
  { workload_name: "compliance-scanner", workload_type: "Container",   cloud_provider: "AWS",   region: "us-west-2",    risk_level: "low",    protection_status: "protected"    },
];

const MOCK_THREATS = [
  { threat_type: "Cryptominer detected",       severity: "critical", detection_source: "Runtime",  workload_id: "k8s-worker-node-05", status: "active"   },
  { threat_type: "Lateral movement attempt",   severity: "high",     detection_source: "Network",  workload_id: "legacy-monolith",    status: "active"   },
  { threat_type: "Privilege escalation",       severity: "critical", detection_source: "Runtime",  workload_id: "ml-training-gpu01", status: "active"   },
  { threat_type: "Unusual outbound DNS",       severity: "medium",   detection_source: "Network",  workload_id: "api-gateway-prod",  status: "resolved" },
  { threat_type: "Container escape attempt",   severity: "critical", detection_source: "Runtime",  workload_id: "k8s-worker-node-05", status: "active"  },
  { threat_type: "Suspicious cron job added",  severity: "high",     detection_source: "File",     workload_id: "legacy-monolith",    status: "resolved" },
];

// ── Badge helpers ──────────────────────────────────────────────

function CloudProviderBadge({ provider }: { provider: string }) {
  const map: Record<string, string> = {
    AWS:   "border-orange-500/30 text-orange-400 bg-orange-500/10",
    GCP:   "border-blue-500/30 text-blue-400 bg-blue-500/10",
    Azure: "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border font-mono", map[provider] ?? "border-border text-muted-foreground")}>
      {provider}
    </Badge>
  );
}

function RiskBadge({ level }: { level: string }) {
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

function ProtectionStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    protected:   "border-green-500/30 text-green-400 bg-green-500/10",
    unprotected: "border-red-500/30 text-red-400 bg-red-500/10",
    partial:     "border-amber-500/30 text-amber-400 bg-amber-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border text-muted-foreground")}>
      {status}
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

function ThreatStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    active:   "border-red-500/30 text-red-400 bg-red-500/10",
    resolved: "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border text-muted-foreground")}>
      {status}
    </Badge>
  );
}

// ── Component ──────────────────────────────────────────────────

export default function CloudWorkloadProtectionDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [dataLoading, setDataLoading] = useState(false);
  const [liveData, setLiveData] = useState<{
  const [loading, setLoading] = useState(true);
    stats: any | null;
    workloads: any[] | null;
    threats: any[] | null;
  }>({ stats: null, workloads: null, threats: null });

  const fetchData = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/cwp/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/cwp/workloads?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/cwp/threats?org_id=${ORG_ID}`),
    ]).then(([statsRes, workloadsRes, threatsRes]) => {
      setLiveData({
        stats:     statsRes.status     === "fulfilled" ? statsRes.value     : null,
        workloads: workloadsRes.status === "fulfilled" ? workloadsRes.value : null,
        threats:   threatsRes.status   === "fulfilled" ? threatsRes.value   : null,
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

  const stats     = liveData.stats     ?? MOCK_STATS;
  const workloads = liveData.workloads ?? MOCK_WORKLOADS;
  const threats   = liveData.threats   ?? MOCK_THREATS;

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
      {/* Header */}
      <PageHeader
        title="Cloud Workload Protection"
        description="Runtime protection and threat detection across cloud workloads (CWPP)"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Workloads"    value={stats.total_workloads
    setLoading(false);}       icon={Cloud}       trend="flat" />
        <KpiCard title="Protected"          value={stats.protected_workloads}   icon={ShieldCheck} trend="up"   className="border-green-500/20" />
        <KpiCard title="Unprotected"        value={stats.unprotected_workloads} icon={ShieldOff}   trend="down" className="border-red-500/20" />
        <KpiCard title="Active Threats"     value={stats.active_threats}        icon={AlertTriangle} trend="down" className="border-amber-500/20" />
      </div>

      {/* Workloads Table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Cloud className="h-4 w-4 text-blue-400" />
              Cloud Workloads
            </CardTitle>
            <Badge className="text-[10px] border border-border text-muted-foreground">
              {workloads.length} workloads
            </Badge>
          </div>
          <CardDescription className="text-xs">Cloud workloads with protection status and risk posture</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Workload Name</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Provider</TableHead>
                  <TableHead className="text-[11px] h-8">Region</TableHead>
                  <TableHead className="text-[11px] h-8">Risk</TableHead>
                  <TableHead className="text-[11px] h-8">Protection</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {workloads.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  workloads.map((w: any, i: number) => (
                  <TableRow key={w.workload_name ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-mono text-[11px]">{w.workload_name}</TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{w.workload_type}</TableCell>
                    <TableCell className="py-2"><CloudProviderBadge provider={w.cloud_provider ?? "AWS"} /></TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{w.region}</TableCell>
                    <TableCell className="py-2"><RiskBadge level={w.risk_level ?? "low"} /></TableCell>
                    <TableCell className="py-2"><ProtectionStatusBadge status={w.protection_status ?? "protected"} /></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Threats Table */}
      <Card className="border-red-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
              <ShieldAlert className="h-4 w-4" />
              Active Threats
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
              {threats.filter((t: any) => t.status === "active").length} active
            </Badge>
          </div>
          <CardDescription className="text-xs">Runtime threats detected across protected workloads</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Threat Type</TableHead>
                  <TableHead className="text-[11px] h-8">Severity</TableHead>
                  <TableHead className="text-[11px] h-8">Detection Source</TableHead>
                  <TableHead className="text-[11px] h-8">Workload</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {threats.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  threats.map((t: any, i: number) => (
                  <TableRow key={i} className="hover:bg-muted/30">
                    <TableCell className="py-2 text-[11px] font-medium">{t.threat_type}</TableCell>
                    <TableCell className="py-2"><SeverityBadge severity={t.severity ?? "medium"} /></TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{t.detection_source}</TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">{t.workload_id}</TableCell>
                    <TableCell className="py-2"><ThreatStatusBadge status={t.status ?? "active"} /></TableCell>
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
