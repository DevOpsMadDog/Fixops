/**
 * Posture Benchmarking Dashboard
 *
 * Security posture benchmarking against industry standards and frameworks.
 *   1. KPI cards: Total Benchmarks, Active Benchmarks, Avg Score, Above Industry Avg
 *   2. Benchmarks table
 *   3. Failed Controls table
 *
 * API: GET /api/v1/posture-benchmarking/{stats,benchmarks,controls?result=fail}
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  BarChart2, RefreshCw, TrendingUp, CheckSquare, XSquare, Target,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// == API helpers ================================================
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

// == Mock data (fallback) =======================================

const MOCK_STATS = {
  total_benchmarks:    18,
  active_benchmarks:   14,
  avg_score:           73.4,
  above_industry_avg:  9,
};

const MOCK_BENCHMARKS = [
  { benchmark_name: "CIS AWS Foundations",     framework: "CIS",    category: "cloud",      score: 84.2, industry_avg_score: 71.0, percentile: 82 },
  { benchmark_name: "NIST CSF 2.0",            framework: "NIST",   category: "general",    score: 78.6, industry_avg_score: 68.5, percentile: 74 },
  { benchmark_name: "SOC 2 Type II",           framework: "SOC2",   category: "compliance", score: 91.3, industry_avg_score: 79.2, percentile: 89 },
  { benchmark_name: "PCI DSS v4.0",            framework: "PCI",    category: "payment",    score: 67.8, industry_avg_score: 72.1, percentile: 43 },
  { benchmark_name: "CIS Kubernetes",          framework: "CIS",    category: "containers", score: 61.4, industry_avg_score: 58.3, percentile: 56 },
  { benchmark_name: "ISO 27001:2022",          framework: "ISO",    category: "governance", score: 76.9, industry_avg_score: 65.4, percentile: 71 },
  { benchmark_name: "HIPAA Security Rule",     framework: "HIPAA",  category: "healthcare", score: 88.5, industry_avg_score: 77.0, percentile: 85 },
  { benchmark_name: "MITRE ATT&CK Coverage",  framework: "MITRE",  category: "detection",  score: 54.2, industry_avg_score: 49.8, percentile: 61 },
];

const MOCK_FAILED_CONTROLS = [
  { control_id: "CIS-2.1.4",  title: "Ensure MFA is enabled for root account",          severity: "critical", result: "fail", benchmark_id: "cis-aws" },
  { control_id: "PCI-8.3.6",  title: "Passwords must be at least 12 characters",         severity: "high",     result: "fail", benchmark_id: "pci-dss-4" },
  { control_id: "NIST-PR.AC-3", title: "Remote access managed",                          severity: "high",     result: "fail", benchmark_id: "nist-csf" },
  { control_id: "CIS-K8S-5.2",title: "Minimize wildcard use in Roles and ClusterRoles",  severity: "high",     result: "fail", benchmark_id: "cis-k8s" },
  { control_id: "SOC2-CC6.7", title: "Encryption in transit for all data",               severity: "medium",   result: "fail", benchmark_id: "soc2" },
  { control_id: "MITRE-T1078", title: "Valid Accounts detection coverage",               severity: "medium",   result: "fail", benchmark_id: "mitre" },
  { control_id: "ISO-A.9.4.2","title": "Secure log-on procedures",                       severity: "medium",   result: "fail", benchmark_id: "iso-27001" },
];

// == Badge helpers ==============================================

function SeverityBadge({ severity }: { severity: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
    medium:   "border-amber-500/30 text-amber-400 bg-amber-500/10",
    low:      "border-blue-500/30 text-blue-400 bg-blue-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[severity] ?? "border-border text-muted-foreground")}>
      {severity}
    </Badge>
  );
}

function scoreColor(score: number): string {
  if (score >= 80) return "text-green-400";
  if (score >= 65) return "text-amber-400";
  return "text-red-400";
}

function FrameworkBadge({ framework }: { framework: string }) {
  const map: Record<string, string> = {
    CIS:   "border-blue-500/30 text-blue-400 bg-blue-500/10",
    NIST:  "border-purple-500/30 text-purple-400 bg-purple-500/10",
    SOC2:  "border-green-500/30 text-green-400 bg-green-500/10",
    PCI:   "border-orange-500/30 text-orange-400 bg-orange-500/10",
    ISO:   "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
    HIPAA: "border-pink-500/30 text-pink-400 bg-pink-500/10",
    MITRE: "border-red-500/30 text-red-400 bg-red-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border font-mono", map[framework] ?? "border-border text-muted-foreground")}>
      {framework}
    </Badge>
  );
}

// == Component ==================================================

export default function PostureBenchmarkingDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [dataLoading, setDataLoading] = useState(false);
  const [liveData, setLiveData] = useState<{
  const [loading, setLoading] = useState(true);
    stats: any | null;
    benchmarks: any[] | null;
    controls: any[] | null;
  }>({ stats: null, benchmarks: null, controls: null });

  const fetchData = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/posture-benchmarking/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/posture-benchmarking/benchmarks?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/posture-benchmarking/controls?org_id=${ORG_ID}&result=fail`),
    ]).then(([statsRes, benchmarksRes, controlsRes]) => {
      setLiveData({
        stats:      statsRes.status      === "fulfilled" ? statsRes.value      : null,
        benchmarks: benchmarksRes.status === "fulfilled" ? benchmarksRes.value : null,
        controls:   controlsRes.status   === "fulfilled" ? controlsRes.value   : null,
      });
    }).finally(() => setDataLoading(false));
  };

  useEffect(() => { fetchData(); }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchData();
    setTimeout(() => setRefreshing(false), 800);
  };

  const stats      = liveData.stats      ?? MOCK_STATS;
  const benchmarks = liveData.benchmarks ?? MOCK_BENCHMARKS;
  const controls   = liveData.controls   ?? MOCK_FAILED_CONTROLS;

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
        title="Posture Benchmarking"
        description="Security posture benchmarking against industry frameworks and peer averages"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Benchmarks"   value={stats.total_benchmarks}                    icon={BarChart2}   trend="flat" />
        <KpiCard title="Active Benchmarks"  value={stats.active_benchmarks}                   icon={Target}      trend="up"   className="border-blue-500/20" />
        <KpiCard title="Avg Score"          value={`${stats.avg_score}%`}                     icon={TrendingUp}  trend="up"   className="border-green-500/20" />
        <KpiCard title="Above Industry Avg" value={stats.above_industry_avg}                  icon={CheckSquare} trend="up"   className="border-purple-500/20" />
      </div>

      {/* Benchmarks Table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <BarChart2 className="h-4 w-4 text-blue-400" />
              Benchmark Scores
            </CardTitle>
            <Badge className="text-[10px] border border-border text-muted-foreground">
              {benchmarks.length} frameworks
            </Badge>
          </div>
          <CardDescription className="text-xs">Organisation score vs industry average with percentile ranking</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Benchmark</TableHead>
                  <TableHead className="text-[11px] h-8">Framework</TableHead>
                  <TableHead className="text-[11px] h-8">Category</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Score</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Industry Avg</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Percentile</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {benchmarks.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  benchmarks.map((b: any, i: number) => (
                  <TableRow key={b.benchmark_name ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 text-[11px] font-medium">{b.benchmark_name}</TableCell>
                    <TableCell className="py-2"><FrameworkBadge framework={b.framework ?? "NIST"} /></TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground capitalize">{b.category}</TableCell>
                    <TableCell className={cn("py-2 text-right text-[11px] font-semibold", scoreColor(b.score))}>{b.score?.toFixed(1)}%</TableCell>
                    <TableCell className="py-2 text-right text-[11px] text-muted-foreground">{b.industry_avg_score?.toFixed(1)}%</TableCell>
                    <TableCell className="py-2 text-right text-[11px] text-muted-foreground">{b.percentile}th</TableCell>
                  </TableRow>
                )))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Failed Controls Table */}
      <Card className="border-red-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
              <XSquare className="h-4 w-4" />
              Failed Controls
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
              {controls.length} failures
            </Badge>
          </div>
          <CardDescription className="text-xs">Controls failing across active benchmarks requiring remediation</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Control ID</TableHead>
                  <TableHead className="text-[11px] h-8">Title</TableHead>
                  <TableHead className="text-[11px] h-8">Severity</TableHead>
                  <TableHead className="text-[11px] h-8">Result</TableHead>
                  <TableHead className="text-[11px] h-8">Benchmark</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {controls.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  controls.map((c: any, i: number) => (
                  <TableRow key={i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-mono text-[11px] text-blue-400">{c.control_id}</TableCell>
                    <TableCell className="py-2 text-[11px]">{c.title}</TableCell>
                    <TableCell className="py-2"><SeverityBadge severity={c.severity ?? "medium"} /></TableCell>
                    <TableCell className="py-2">
                      <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">fail</Badge>
                    </TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">{c.benchmark_id}</TableCell>
                  </TableRow>
                )))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
