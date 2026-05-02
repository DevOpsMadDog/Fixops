// FOLDED into VulnLifecyclePipelineHub hero (prioritize tab) 2026-05-02 — preserve for git history
/**
 * Vulnerability Prioritization Dashboard
 * Route: /vuln-prioritization
 * API: GET /api/v1/vuln-prioritization/queue
 *      GET /api/v1/vuln-prioritization/stats
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

interface VulnQueueItem {
  cve_id?: string;
  asset_id?: string;
  priority_score?: number;
  priority_level?: string;
  cvss_score?: number;
  epss_score?: number;
  status?: string;
}

interface VulnStats {
  total_vulns?: number;
  critical_priority?: number;
  exploited_in_wild?: number;
  avg_priority_score?: number;
}

function PriorityBadge({ level }: { level: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
    medium:   "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    low:      "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[level] ?? "border-border")}>{level}</Badge>;
}

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    open:        "border-red-500/30 text-red-400 bg-red-500/10",
    in_progress: "border-blue-500/30 text-blue-400 bg-blue-500/10",
    resolved:    "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return <Badge className={cn("text-[10px] border", map[status] ?? "border-border")}>{status.replace(/_/g, " ")}</Badge>;
}

function PriorityScore({ score }: { score: number }) {
  const color = score >= 80 ? "text-red-400" : score >= 60 ? "text-orange-400" : score >= 40 ? "text-yellow-400" : "text-green-400";
  return <span className={cn("font-mono font-bold text-[12px]", color)}>{score}</span>;
}

export default function VulnPrioritizationDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [loading, setLoading] = useState(true);
  const [queue, setQueue] = useState<VulnQueueItem[]>([]);
  const [stats, setStats] = useState<VulnStats>({});
  const [error, setError] = useState<string | null>(null);

  function load() {
    setLoading(true);
    setError(null);
    Promise.allSettled([
      apiFetch("/api/v1/vuln-prioritization/queue?org_id=default"),
      apiFetch("/api/v1/vuln-prioritization/stats?org_id=default"),
    ]).then(([queueRes, statsRes]) => {
      if (queueRes.status === "fulfilled") {
        const val = queueRes.value;
        setQueue(val?.queue ?? val?.items ?? (Array.isArray(val) ? val : []));
      } else {
        setError("Vulnerability prioritization API unavailable");
      }
      if (statsRes.status === "fulfilled") setStats(statsRes.value ?? {});
      setLoading(false);
    });
  }

  useEffect(() => { load(); }, []);

  const handleRefresh = () => { setRefreshing(true); load(); setTimeout(() => setRefreshing(false), 800); };

  if (loading) return <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-red-500" /></div>;

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Vulnerability Prioritization"
        description="Risk-based vulnerability prioritization using CVSS, EPSS exploitation probability, and CISA KEV data"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Vulns"        value={stats.total_vulns ?? 0}        icon={ShieldAlert}   trend="flat" />
        <KpiCard title="Critical Priority"  value={stats.critical_priority ?? 0}  icon={AlertTriangle} trend="up"   className="border-red-500/20" />
        <KpiCard title="Exploited in Wild"  value={stats.exploited_in_wild ?? 0}  icon={Flame}         trend="up"   className="border-rose-500/20" />
        <KpiCard title="Avg Priority Score" value={stats.avg_priority_score ?? 0} icon={BarChart3}     trend="flat" className="border-orange-500/20" />
      </div>
      <Card className="border-red-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
              <ShieldAlert className="h-4 w-4" />Remediation Queue
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
              {queue.filter((v) => v.priority_level === "critical").length} critical
            </Badge>
          </div>
          <CardDescription className="text-xs">Prioritized by composite risk score — CVSS severity, EPSS exploitation probability, KEV status, and asset exposure</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          {error || queue.length === 0 ? (
            <EmptyState icon={ShieldAlert} title={error ?? "No vulnerabilities queued"} description="The remediation queue will populate once vulnerability scans complete." />
          ) : (
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
                  {queue.map((vuln, i) => (
                    <TableRow key={vuln.cve_id ?? i} className="hover:bg-muted/30">
                      <TableCell className="py-2 font-mono text-[11px] font-semibold text-rose-300">{vuln.cve_id ?? "—"}</TableCell>
                      <TableCell className="py-2 font-mono text-[11px] text-muted-foreground max-w-[140px] truncate">{vuln.asset_id ?? "—"}</TableCell>
                      <TableCell className="py-2"><PriorityScore score={vuln.priority_score ?? 0} /></TableCell>
                      <TableCell className="py-2"><PriorityBadge level={vuln.priority_level ?? "medium"} /></TableCell>
                      <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">{(vuln.cvss_score ?? 0).toFixed(1)}</TableCell>
                      <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">{(vuln.epss_score ?? 0).toFixed(2)}</TableCell>
                      <TableCell className="py-2 text-right"><StatusBadge status={vuln.status ?? "open"} /></TableCell>
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
