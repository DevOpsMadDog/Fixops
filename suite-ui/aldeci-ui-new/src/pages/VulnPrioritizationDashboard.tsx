/**
 * Vulnerability Prioritization Dashboard
 *
 * Risk-based vulnerability prioritization using CVSS, EPSS, and KEV data.
 *   1. KPIs: Total Vulns, Critical Priority, Exploited in Wild, Avg Priority Score
 *   2. Remediation queue table (cve_id, asset_id, priority_score, priority_level, cvss_score, epss_score, status)
 *
 * Route: /vuln-prioritization
 * API: GET /api/v1/vuln-prioritization/queue
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { ShieldAlert, RefreshCw, AlertTriangle, Flame, BarChart3 } from "lucide-react";

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
    ...opts,
    headers: { "X-API-Key": API_KEY, "Content-Type": "application/json", ...(opts?.headers ?? {}) },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ── Mock data ──────────────────────────────────────────────────

const MOCK_QUEUE = [
  { cve_id: "CVE-2024-3400",  asset_id: "prod-firewall-01",   priority_score: 98, priority_level: "critical", cvss_score: 10.0, epss_score: 0.94, status: "open" },
  { cve_id: "CVE-2024-1709",  asset_id: "connectwise-srv",    priority_score: 95, priority_level: "critical", cvss_score: 10.0, epss_score: 0.97, status: "open" },
  { cve_id: "CVE-2023-46805", asset_id: "ivanti-vpn-01",      priority_score: 91, priority_level: "critical", cvss_score: 8.2,  epss_score: 0.89, status: "in_progress" },
  { cve_id: "CVE-2024-21412", asset_id: "win-workstation-14", priority_score: 84, priority_level: "high",     cvss_score: 8.1,  epss_score: 0.71, status: "open" },
  { cve_id: "CVE-2023-44487", asset_id: "nginx-prod-02",      priority_score: 79, priority_level: "high",     cvss_score: 7.5,  epss_score: 0.65, status: "in_progress" },
  { cve_id: "CVE-2024-0519",  asset_id: "chrome-fleet",       priority_score: 72, priority_level: "high",     cvss_score: 8.8,  epss_score: 0.58, status: "open" },
  { cve_id: "CVE-2023-36025", asset_id: "win-server-08",      priority_score: 61, priority_level: "medium",   cvss_score: 7.8,  epss_score: 0.41, status: "open" },
  { cve_id: "CVE-2024-1086",  asset_id: "linux-host-22",      priority_score: 54, priority_level: "medium",   cvss_score: 7.8,  epss_score: 0.33, status: "resolved" },
];

const MOCK_STATS = { total_vulns: 3847, critical_priority: 127, exploited_in_wild: 43, avg_priority_score: 68 };

// ── Badge helpers ──────────────────────────────────────────────

function PriorityBadge({ level }: { level: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
    medium:   "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    low:      "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[level] ?? "border-border")}>
      {level}
    </Badge>
  );
}

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    open:        "border-red-500/30 text-red-400 bg-red-500/10",
    in_progress: "border-blue-500/30 text-blue-400 bg-blue-500/10",
    resolved:    "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border", map[status] ?? "border-border")}>
      {status.replace(/_/g, " ")}
    </Badge>
  );
}

function PriorityScore({ score }: { score: number }) {
  const color = score >= 80 ? "text-red-400" : score >= 60 ? "text-orange-400" : score >= 40 ? "text-yellow-400" : "text-green-400";
  return <span className={cn("font-mono font-bold text-[12px]", color)}>{score}</span>;
}

// ── Component ──────────────────────────────────────────────────

export default function VulnPrioritizationDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveQueue, setLiveQueue]   = useState<any[] | null>(null);
  const [liveStats, setLiveStats]   = useState<any | null>(null);

  useEffect(() => {
    Promise.allSettled([
      apiFetch(`/api/v1/vuln-prioritization/queue?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/vuln-prioritization/stats?org_id=${ORG_ID}`),
    ]).then(([queueRes, statsRes]) => {
      if (queueRes.status === "fulfilled") setLiveQueue(queueRes.value?.queue ?? queueRes.value ?? null);
      if (statsRes.status === "fulfilled") setLiveStats(statsRes.value ?? null);
    });
  }, []);

  const handleRefresh = () => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); };

  const queue = liveQueue ?? MOCK_QUEUE;
  const stats = liveStats ?? MOCK_STATS;

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      <PageHeader
        title="Vulnerability Prioritization"
        description="Risk-based vulnerability prioritization using CVSS, EPSS exploitation probability, and CISA KEV data"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Vulns"        value={stats.total_vulns}        icon={ShieldAlert}   trend="flat" />
        <KpiCard title="Critical Priority"  value={stats.critical_priority}  icon={AlertTriangle} trend="up"   className="border-red-500/20" />
        <KpiCard title="Exploited in Wild"  value={stats.exploited_in_wild}  icon={Flame}         trend="up"   className="border-rose-500/20" />
        <KpiCard title="Avg Priority Score" value={stats.avg_priority_score} icon={BarChart3}     trend="flat" className="border-orange-500/20" />
      </div>

      {/* Remediation Queue */}
      <Card className="border-red-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
              <ShieldAlert className="h-4 w-4" />
              Remediation Queue
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
              {queue.filter((v: any) => v.priority_level === "critical").length} critical
            </Badge>
          </div>
          <CardDescription className="text-xs">
            Prioritized by composite risk score — CVSS severity, EPSS exploitation probability, KEV status, and asset exposure
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">CVE ID</TableHead>
                  <TableHead className="text-[11px] h-8">Asset</TableHead>
                  <TableHead className="text-[11px] h-8">Priority Score</TableHead>
                  <TableHead className="text-[11px] h-8">Priority Level</TableHead>
                  <TableHead className="text-[11px] h-8">CVSS</TableHead>
                  <TableHead className="text-[11px] h-8">EPSS</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {queue.map((vuln: any, i: number) => (
                  <TableRow key={vuln.cve_id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-mono text-[11px] font-semibold text-rose-300">
                      {vuln.cve_id ?? "—"}
                    </TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground max-w-[140px] truncate">
                      {vuln.asset_id ?? "—"}
                    </TableCell>
                    <TableCell className="py-2">
                      <PriorityScore score={vuln.priority_score ?? 0} />
                    </TableCell>
                    <TableCell className="py-2">
                      <PriorityBadge level={vuln.priority_level ?? "medium"} />
                    </TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">
                      {(vuln.cvss_score ?? 0).toFixed(1)}
                    </TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">
                      {(vuln.epss_score ?? 0).toFixed(2)}
                    </TableCell>
                    <TableCell className="py-2 text-right">
                      <StatusBadge status={vuln.status ?? "open"} />
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
