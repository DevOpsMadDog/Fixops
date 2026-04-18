/**
 * Security Tool Inventory Dashboard
 *
 * Security tool portfolio management — coverage, cost, and effectiveness tracking.
 *   1. KPI cards: Total Tools, Active Tools, Annual Cost, Avg Coverage
 *   2. Tools table
 *   3. Recent Assessments table
 *
 * API: GET /api/v1/tool-inventory/{stats,tools,assessments}
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Wrench, RefreshCw, CheckCircle, DollarSign, BarChart2, ClipboardCheck,
} from "lucide-react";
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
  total_tools: 47,
  active_tools: 39,
  total_cost_annual: 284500,
  coverage_avg: 72.4,
};

const MOCK_TOOLS = [
  { name: "CrowdStrike Falcon",   vendor: "CrowdStrike",  tool_category: "EDR",     deployment_type: "cloud",  status: "active",   cost_annual: 48000 },
  { name: "Splunk SIEM",          vendor: "Splunk",       tool_category: "SIEM",    deployment_type: "on-prem", status: "active",  cost_annual: 62000 },
  { name: "Tenable.io",           vendor: "Tenable",      tool_category: "VAPT",    deployment_type: "cloud",  status: "active",   cost_annual: 24000 },
  { name: "Palo Alto NGFW",       vendor: "Palo Alto",    tool_category: "Firewall", deployment_type: "on-prem", status: "active", cost_annual: 35000 },
  { name: "Okta IAM",             vendor: "Okta",         tool_category: "IAM",     deployment_type: "cloud",  status: "active",   cost_annual: 19000 },
  { name: "Darktrace NDR",        vendor: "Darktrace",    tool_category: "NDR",     deployment_type: "on-prem", status: "active",  cost_annual: 41000 },
  { name: "Qualys WAS",           vendor: "Qualys",       tool_category: "DAST",    deployment_type: "cloud",  status: "active",   cost_annual: 16000 },
  { name: "Legacy AV Suite",      vendor: "OldVendor",    tool_category: "AV",      deployment_type: "on-prem", status: "decommissioned", cost_annual: 0 },
  { name: "Snyk Code",            vendor: "Snyk",         tool_category: "SAST",    deployment_type: "cloud",  status: "active",   cost_annual: 18000 },
  { name: "Zscaler ZIA",          vendor: "Zscaler",      tool_category: "SASE",    deployment_type: "cloud",  status: "trial",    cost_annual: 0 },
];

const MOCK_ASSESSMENTS = [
  { tool_id: "crowdstrike-falcon", coverage_score: 91, effectiveness_score: 88, utilization_pct: 76 },
  { tool_id: "splunk-siem",        coverage_score: 84, effectiveness_score: 79, utilization_pct: 91 },
  { tool_id: "tenable-io",         coverage_score: 78, effectiveness_score: 82, utilization_pct: 68 },
  { tool_id: "palo-alto-ngfw",     coverage_score: 95, effectiveness_score: 91, utilization_pct: 88 },
  { tool_id: "okta-iam",           coverage_score: 72, effectiveness_score: 85, utilization_pct: 94 },
  { tool_id: "darktrace-ndr",      coverage_score: 67, effectiveness_score: 74, utilization_pct: 55 },
  { tool_id: "qualys-was",         coverage_score: 61, effectiveness_score: 70, utilization_pct: 43 },
];

// ── Badge helpers ──────────────────────────────────────────────

function ToolStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    active:         "border-green-500/30 text-green-400 bg-green-500/10",
    trial:          "border-blue-500/30 text-blue-400 bg-blue-500/10",
    decommissioned: "border-gray-500/30 text-gray-400 bg-gray-500/10",
    planned:        "border-amber-500/30 text-amber-400 bg-amber-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border text-muted-foreground")}>
      {status}
    </Badge>
  );
}

function CategoryBadge({ cat }: { cat: string }) {
  const map: Record<string, string> = {
    EDR:     "border-red-500/30 text-red-400 bg-red-500/10",
    SIEM:    "border-orange-500/30 text-orange-400 bg-orange-500/10",
    VAPT:    "border-purple-500/30 text-purple-400 bg-purple-500/10",
    Firewall:"border-blue-500/30 text-blue-400 bg-blue-500/10",
    IAM:     "border-green-500/30 text-green-400 bg-green-500/10",
    NDR:     "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
    DAST:    "border-amber-500/30 text-amber-400 bg-amber-500/10",
    SAST:    "border-violet-500/30 text-violet-400 bg-violet-500/10",
    SASE:    "border-teal-500/30 text-teal-400 bg-teal-500/10",
    AV:      "border-gray-500/30 text-gray-400 bg-gray-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border font-mono", map[cat] ?? "border-border text-muted-foreground")}>
      {cat}
    </Badge>
  );
}

function DeploymentBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    cloud:   "border-blue-500/30 text-blue-400 bg-blue-500/10",
    "on-prem": "border-gray-500/30 text-gray-400 bg-gray-500/10",
    hybrid:  "border-purple-500/30 text-purple-400 bg-purple-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[type] ?? "border-border text-muted-foreground")}>
      {type}
    </Badge>
  );
}

function scoreBar(value: number): JSX.Element {
  const color = value >= 80 ? "bg-green-500" : value >= 60 ? "bg-amber-500" : "bg-red-500";
  return (
    <div className="flex items-center gap-2">
      <div className="w-16 h-1.5 bg-muted rounded-full overflow-hidden">
        <div className={cn("h-full rounded-full", color)} style={{ width: `${value}%` }} />
      </div>
      <span className="text-[11px] font-mono text-muted-foreground">{value}%</span>
    </div>
  );
}

function fmtCost(cost: number): string {
  if (cost === 0) return "—";
  return `$${cost.toLocaleString()}`;
}

// ── Component ──────────────────────────────────────────────────

export default function SecurityToolInventoryDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [dataLoading, setDataLoading] = useState(false);
  const [liveData, setLiveData] = useState<{
  const [loading, setLoading] = useState(true);
    stats: any | null;
    tools: any[] | null;
    assessments: any[] | null;
  }>({ stats: null, tools: null, assessments: null });

  const fetchData = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/tool-inventory/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/tool-inventory/tools?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/tool-inventory/assessments?org_id=${ORG_ID}`),
    ]).then(([statsRes, toolsRes, assessRes]) => {
      setLiveData({
        stats:       statsRes.status === "fulfilled" ? statsRes.value : null,
        tools:       toolsRes.status === "fulfilled" ? toolsRes.value : null,
        assessments: assessRes.status === "fulfilled" ? assessRes.value : null,
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

  const stats       = liveData.stats       ?? MOCK_STATS;
  const tools       = liveData.tools       ?? MOCK_TOOLS;
  const assessments = liveData.assessments ?? MOCK_ASSESSMENTS;

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
        title="Security Tool Inventory"
        description="Security tool portfolio — coverage, cost, effectiveness, and utilization tracking"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Tools"      value={stats.total_tools
    setLoading(false);}                              icon={Wrench}         trend="flat" />
        <KpiCard title="Active"           value={stats.active_tools}                             icon={CheckCircle}    trend="up"   className="border-green-500/20" />
        <KpiCard title="Annual Cost"      value={`$${(stats.total_cost_annual / 1000).toFixed(0)}K`} icon={DollarSign} trend="flat" className="border-amber-500/20" />
        <KpiCard title="Avg Coverage"     value={`${stats.coverage_avg}%`}                       icon={BarChart2}      trend="up"   className="border-blue-500/20" />
      </div>

      {/* Tools Table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Wrench className="h-4 w-4 text-blue-400" />
              Security Tools
            </CardTitle>
            <Badge className="text-[10px] border border-border text-muted-foreground">
              {tools.length} tools
            </Badge>
          </div>
          <CardDescription className="text-xs">Security tool portfolio with vendor, category, deployment, and annual cost</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Name</TableHead>
                  <TableHead className="text-[11px] h-8">Vendor</TableHead>
                  <TableHead className="text-[11px] h-8">Category</TableHead>
                  <TableHead className="text-[11px] h-8">Deployment</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Annual Cost</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {tools.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  tools.map((t: any, i: number) => (
                  <TableRow key={t.name ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 text-[11px] font-medium">{t.name}</TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{t.vendor}</TableCell>
                    <TableCell className="py-2"><CategoryBadge cat={t.tool_category ?? "Other"} /></TableCell>
                    <TableCell className="py-2"><DeploymentBadge type={t.deployment_type ?? "cloud"} /></TableCell>
                    <TableCell className="py-2"><ToolStatusBadge status={t.status ?? "active"} /></TableCell>
                    <TableCell className="py-2 text-right font-mono text-[11px] text-muted-foreground">
                      {fmtCost(t.cost_annual ?? 0)}
                    </TableCell>
                  </TableRow>
                ))
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Assessments Table */}
      <Card className="border-green-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-green-400">
              <ClipboardCheck className="h-4 w-4" />
              Recent Assessments
            </CardTitle>
            <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">
              {assessments.length} assessed
            </Badge>
          </div>
          <CardDescription className="text-xs">Tool effectiveness, coverage, and utilization assessment scores</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Tool ID</TableHead>
                  <TableHead className="text-[11px] h-8">Coverage</TableHead>
                  <TableHead className="text-[11px] h-8">Effectiveness</TableHead>
                  <TableHead className="text-[11px] h-8">Utilization</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {assessments.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  assessments.map((a: any, i: number) => (
                  <TableRow key={a.tool_id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">{a.tool_id}</TableCell>
                    <TableCell className="py-2">{scoreBar(a.coverage_score ?? 0)}</TableCell>
                    <TableCell className="py-2">{scoreBar(a.effectiveness_score ?? 0)}</TableCell>
                    <TableCell className="py-2">{scoreBar(a.utilization_pct ?? 0)}</TableCell>
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
