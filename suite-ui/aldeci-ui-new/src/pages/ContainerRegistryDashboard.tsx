/**
 * Container Registry Dashboard
 *
 * Container image scanning — registries, scan results, policy enforcement.
 *   1. KPIs: Registries, Total Scans, Critical Images, Policy Violations
 *   2. Recent image scans table (image name, tag, vulnerabilities, scan score, policy result)
 *
 * Route: /container-registry
 * API: GET /api/v1/container-registry-security/stats
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Box, AlertTriangle, Shield, ShieldX, RefreshCw } from "lucide-react";

const API_BASE = import.meta.env.VITE_API_URL || "";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci_api_key")) ||
  import.meta.env.VITE_API_KEY ||
  "dev-key";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string, opts?: RequestInit) {
  const res = await fetch(`${API_BASE}${path}?org_id=default`, {
    ...opts,
    headers: { "X-API-Key": API_KEY, "Content-Type": "application/json", ...(opts?.headers ?? {}) },
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

const MOCK_SCANS = [
  { id: "IMG-001", image: "acme/api-gateway",     tag: "v2.4.1",   vulnerabilities: 3,  scan_score: 91, policy: "pass",    scanned_at: "5 min ago" },
  { id: "IMG-002", image: "acme/auth-service",    tag: "v1.8.0",   vulnerabilities: 12, scan_score: 54, policy: "fail",    scanned_at: "12 min ago" },
  { id: "IMG-003", image: "acme/data-processor",  tag: "latest",   vulnerabilities: 7,  scan_score: 72, policy: "warn",    scanned_at: "18 min ago" },
  { id: "IMG-004", image: "nginx",                tag: "1.25-alpine", vulnerabilities: 0, scan_score: 98, policy: "pass", scanned_at: "25 min ago" },
  { id: "IMG-005", image: "acme/ml-inference",    tag: "v3.0.0",   vulnerabilities: 24, scan_score: 31, policy: "fail",    scanned_at: "34 min ago" },
  { id: "IMG-006", image: "postgres",             tag: "15-alpine", vulnerabilities: 2, scan_score: 88, policy: "pass",    scanned_at: "41 min ago" },
  { id: "IMG-007", image: "acme/frontend",        tag: "v5.2.3",   vulnerabilities: 5,  scan_score: 79, policy: "pass",    scanned_at: "52 min ago" },
  { id: "IMG-008", image: "acme/legacy-worker",   tag: "v0.9.1",   vulnerabilities: 38, scan_score: 12, policy: "fail",    scanned_at: "1h ago" },
];

const MOCK_STATS = {
  registries: 4,
  total_scans: 247,
  critical_images: 3,
  policy_violations: 12,
};

// ── Badge helpers ──────────────────────────────────────────────

function PolicyBadge({ result }: { result: string }) {
  const map: Record<string, string> = {
    pass: "border-green-500/30 text-green-400 bg-green-500/10",
    fail: "border-red-500/30 text-red-400 bg-red-500/10",
    warn: "border-amber-500/30 text-amber-400 bg-amber-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[result] ?? "border-border")}>
      {result}
    </Badge>
  );
}

function ScoreBar({ score }: { score: number }) {
  return (
    <div className="flex items-center gap-2">
      <div className="relative h-1.5 flex-1 rounded-full bg-muted/30 overflow-hidden min-w-[60px]">
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${score}%` }}
          transition={{ duration: 0.6 }}
          className={cn(
            "h-full rounded-full",
            score >= 80 ? "bg-green-500" : score >= 50 ? "bg-amber-500" : "bg-red-500"
          )}
        />
      </div>
      <span
        className={cn(
          "text-[10px] font-bold tabular-nums w-6 text-right",
          score >= 80 ? "text-green-400" : score >= 50 ? "text-amber-400" : "text-red-400"
        )}
      >
        {score}
      </span>
    </div>
  );
}

// ── Component ──────────────────────────────────────────────────

export default function ContainerRegistryDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [loading, setLoading] = useState(true);
  const [liveData, setLiveData] = useState<any>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    apiFetch(`/api/v1/container-registry-security/stats?org_id=${ORG_ID}`)
      .then((d) => setLiveData(d))
      .catch((e) => setError(e?.message || 'Failed to load data'))
      .finally(() => setLoading(false));
  }, []);

  const stats = liveData ?? MOCK_STATS;
  const scans = liveData?.recent_scans ?? MOCK_SCANS;

  const handleRefresh = () => {
    setRefreshing(true);
    apiFetch(`/api/v1/container-registry-security/stats?org_id=${ORG_ID}`)
      .then((d) => setLiveData(d))
      .catch((e) => setError(e?.message || 'Failed to load data'))
      .finally(() => setRefreshing(false));
  };


  if (loading) return <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div></div>;


  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      <PageHeader
        title="Container Registry"
        description="Image scanning, vulnerability detection, and policy enforcement across registries"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Registries"        value={stats.registries ?? 4}         icon={Box}          trend="flat" />
        <KpiCard title="Total Scans"       value={stats.total_scans ?? 247}      icon={Shield}       trend="up" />
        <KpiCard title="Critical Images"   value={stats.critical_images ?? 3}    icon={AlertTriangle} trend="up" className="border-red-500/20" />
        <KpiCard title="Policy Violations" value={stats.policy_violations ?? 12} icon={ShieldX}      trend="up" className="border-amber-500/20" />
      </div>

      {/* Scan Results Table */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Box className="h-4 w-4 text-blue-400" />
            Recent Image Scans
          </CardTitle>
          <CardDescription className="text-xs">
            Latest container image scans with vulnerability counts and policy results
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Image</TableHead>
                  <TableHead className="text-[11px] h-8">Tag</TableHead>
                  <TableHead className="text-[11px] h-8 text-center">Vulnerabilities</TableHead>
                  <TableHead className="text-[11px] h-8 min-w-[120px]">Scan Score</TableHead>
                  <TableHead className="text-[11px] h-8">Policy</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Scanned</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {scans.map((scan: any) => (
                  <TableRow key={scan.id} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-mono text-xs text-foreground">{scan.image}</TableCell>
                    <TableCell className="py-2">
                      <Badge className="text-[10px] border border-slate-500/30 text-slate-400 bg-slate-500/10 font-mono">
                        {scan.tag}
                      </Badge>
                    </TableCell>
                    <TableCell className="py-2 text-center">
                      <span
                        className={cn(
                          "text-xs font-bold tabular-nums",
                          scan.vulnerabilities === 0
                            ? "text-green-400"
                            : scan.vulnerabilities >= 10
                            ? "text-red-400"
                            : "text-amber-400"
                        )}
                      >
                        {scan.vulnerabilities}
                      </span>
                    </TableCell>
                    <TableCell className="py-2">
                      <ScoreBar score={scan.scan_score} />
                    </TableCell>
                    <TableCell className="py-2">
                      <PolicyBadge result={scan.policy} />
                    </TableCell>
                    <TableCell className="py-2 text-right text-[11px] text-muted-foreground">
                      {scan.scanned_at}
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
