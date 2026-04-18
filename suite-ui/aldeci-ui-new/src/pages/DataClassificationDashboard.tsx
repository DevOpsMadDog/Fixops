/**
 * Data Classification Dashboard
 *
 * Data sensitivity classification and DLP oversight.
 *   1. KPIs: Classified Items, PII Detected, Unclassified, Policy Violations
 *   2. Classification breakdown (5 levels) — horizontal bars
 *   3. Data type distribution (8 types) — colored rows
 *   4. Violation table (12 rows)
 *   5. Recent scan results (6 scan cards)
 *
 * Route: /data-classification
 * API stubs: GET /api/v1/data-classification/summary, /api/v1/data-classification/violations, /api/v1/data-classification/scans
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Database, ShieldAlert, AlertTriangle, Search, RefreshCw, FileText, Lock } from "lucide-react";

// ── API helpers ────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "dev-key";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "X-API-Key": API_KEY },
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

const CLASSIFICATION_LEVELS = [
  { level: "TOP SECRET",  count: 1_247,   pct: 0.8,  color: "bg-red-600",    text: "text-red-500",    border: "border-red-500/30" },
  { level: "SECRET",      count: 8_412,   pct: 5.7,  color: "bg-red-400",    text: "text-red-400",    border: "border-red-400/30" },
  { level: "CONFIDENTIAL",count: 34_891,  pct: 23.5, color: "bg-amber-500",  text: "text-amber-400",  border: "border-amber-500/30" },
  { level: "INTERNAL",    count: 89_601,  pct: 60.4, color: "bg-blue-500",   text: "text-blue-400",   border: "border-blue-500/30" },
  { level: "PUBLIC",      count: 14_123,  pct: 9.5,  color: "bg-green-500",  text: "text-green-400",  border: "border-green-500/30" },
];

const DATA_TYPES = [
  { type: "PII",         count: 23_847, icon: "👤", color: "text-red-400",    bar: "bg-red-500"    },
  { type: "PHI",         count: 8_124,  icon: "🏥", color: "text-pink-400",   bar: "bg-pink-500"   },
  { type: "PCI",         count: 4_391,  icon: "💳", color: "text-amber-400",  bar: "bg-amber-500"  },
  { type: "Credentials", count: 1_203,  icon: "🔑", color: "text-red-500",    bar: "bg-red-600"    },
  { type: "IP / Source", count: 12_882, icon: "⚙️", color: "text-purple-400", bar: "bg-purple-500" },
  { type: "Classified",  count: 9_659,  icon: "🔒", color: "text-orange-400", bar: "bg-orange-500" },
  { type: "General",     count: 74_321, icon: "📄", color: "text-blue-400",   bar: "bg-blue-500"   },
  { type: "Unknown",     count: 13_847, icon: "❓", color: "text-muted-foreground", bar: "bg-muted-foreground" },
];

const VIOLATIONS = [
  { user: "u***2841", dataType: "PII",         violationType: "unauthorized_access", severity: "Critical", channel: "cloud",    status: "open"       },
  { user: "u***1104", dataType: "PCI",         violationType: "data_exfil",          severity: "Critical", channel: "email",    status: "open"       },
  { user: "u***3307", dataType: "Credentials", violationType: "policy_bypass",       severity: "Critical", channel: "endpoint", status: "open"       },
  { user: "u***0892", dataType: "PHI",         violationType: "unauthorized_access", severity: "High",     channel: "cloud",    status: "open"       },
  { user: "u***2215", dataType: "PII",         violationType: "data_exfil",          severity: "High",     channel: "email",    status: "remediated" },
  { user: "u***4481", dataType: "IP / Source", violationType: "unauthorized_access", severity: "High",     channel: "endpoint", status: "open"       },
  { user: "u***1739", dataType: "Classified",  violationType: "policy_bypass",       severity: "High",     channel: "cloud",    status: "open"       },
  { user: "u***3052", dataType: "PII",         violationType: "data_exfil",          severity: "Medium",   channel: "email",    status: "open"       },
  { user: "u***2667", dataType: "PCI",         violationType: "unauthorized_access", severity: "Medium",   channel: "cloud",    status: "remediated" },
  { user: "u***0143", dataType: "PHI",         violationType: "policy_bypass",       severity: "Medium",   channel: "endpoint", status: "open"       },
  { user: "u***1988", dataType: "General",     violationType: "data_exfil",          severity: "Low",      channel: "email",    status: "open"       },
  { user: "u***3724", dataType: "Unknown",     violationType: "unauthorized_access", severity: "Low",      channel: "cloud",    status: "remediated" },
];

const SCANS = [
  { name: "S3 Full Bucket Scan",       scope: "AWS S3 — all buckets",    itemsScanned: 284_112, violations: 47, scanTime: "4m 12s", status: "completed" },
  { name: "Email Archive DLP",         scope: "Exchange Online archive",  itemsScanned: 1_204_891, violations: 89, scanTime: "18m 04s", status: "completed" },
  { name: "Endpoint File Crawler",     scope: "Windows endpoints (412)",  itemsScanned: 9_281_444, violations: 34, scanTime: "1h 02m", status: "completed" },
  { name: "GitHub Secrets Scan",       scope: "All org repos",           itemsScanned: 48_221, violations: 12, scanTime: "2m 38s", status: "completed" },
  { name: "Database Column Profiler",  scope: "Production DBs (8)",      itemsScanned: 4_412_008, violations: 52, scanTime: "34m 51s", status: "running"   },
  { name: "SharePoint Content Audit",  scope: "SharePoint Online",       itemsScanned: 0, violations: 0, scanTime: "--", status: "scheduled" },
];

// ── Helpers ────────────────────────────────────────────────────

function SeverityBadge({ sev }: { sev: string }) {
  const cls =
    sev === "Critical" ? "border-red-500/30 text-red-400 bg-red-500/10" :
    sev === "High"     ? "border-amber-500/30 text-amber-400 bg-amber-500/10" :
    sev === "Medium"   ? "border-yellow-500/30 text-yellow-400 bg-yellow-500/10" :
                         "border-border text-muted-foreground";
  return <Badge className={cn("text-[10px] border", cls)}>{sev}</Badge>;
}

function DataTypeBadge({ type }: { type: string }) {
  const colorMap: Record<string, string> = {
    "PII":         "border-red-500/30 text-red-400 bg-red-500/10",
    "PHI":         "border-pink-500/30 text-pink-400 bg-pink-500/10",
    "PCI":         "border-amber-500/30 text-amber-400 bg-amber-500/10",
    "Credentials": "border-red-600/30 text-red-500 bg-red-600/10",
    "IP / Source": "border-purple-500/30 text-purple-400 bg-purple-500/10",
    "Classified":  "border-orange-500/30 text-orange-400 bg-orange-500/10",
    "General":     "border-blue-500/30 text-blue-400 bg-blue-500/10",
    "Unknown":     "border-border text-muted-foreground",
  };
  return <Badge className={cn("text-[10px] border", colorMap[type] ?? "border-border text-muted-foreground")}>{type}</Badge>;
}

function ViolationTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    unauthorized_access: "border-red-500/30 text-red-400 bg-red-500/10",
    data_exfil:          "border-amber-500/30 text-amber-400 bg-amber-500/10",
    policy_bypass:       "border-purple-500/30 text-purple-400 bg-purple-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border", map[type] ?? "border-border text-muted-foreground")}>
      {type.replace(/_/g, " ")}
    </Badge>
  );
}

function ChannelBadge({ ch }: { ch: string }) {
  const map: Record<string, string> = {
    email:    "border-blue-500/30 text-blue-400 bg-blue-500/10",
    endpoint: "border-green-500/30 text-green-400 bg-green-500/10",
    cloud:    "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[ch] ?? "border-border text-muted-foreground")}>{ch}</Badge>;
}

function ScanStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    completed: "border-green-500/30 text-green-400 bg-green-500/10",
    running:   "border-blue-500/30 text-blue-400 bg-blue-500/10",
    scheduled: "border-border text-muted-foreground bg-muted/20",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border text-muted-foreground")}>{status}</Badge>;
}

const MAX_TYPE_COUNT = Math.max(...DATA_TYPES.map(d => d.count));

// ── Component ──────────────────────────────────────────────────

export default function DataClassificationDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/classification/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/classification/assets?org_id=${ORG_ID}`),
    ]).then(([statsResult, assetsResult]) => {
      const stats = statsResult.status === "fulfilled" ? statsResult.value : null;
      const assets = assetsResult.status === "fulfilled" ? assetsResult.value : null;
      if (stats || assets) {
        setLiveData({ stats, assets });}
    }).finally(() => setDataLoading(false));
  }, []);

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
        title="Data Classification"
        description="Data sensitivity classification and DLP oversight"
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={() => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); }} disabled={refreshing || dataLoading}>
              <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
            </Button>
            <Button size="sm">Run Scan</Button>
          </div>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Classified Items"   value={liveData?.stats?.total_classified ?? liveData?.stats?.total_assets ?? "148,274"} icon={Database}    />
        <KpiCard title="PII Detected"       value={liveData?.stats?.pii_count ?? liveData?.stats?.by_category?.PII ?? "23,847"}  icon={Lock}        trend="up" className="border-amber-500/20" />
        <KpiCard title="Unclassified"       value={liveData?.stats?.unclassified_count ?? liveData?.stats?.unclassified ?? "4,123"}   icon={FileText}    trend="up" className="border-yellow-500/20" />
        <KpiCard title="Policy Violations"  value={liveData?.stats?.violations_count ?? liveData?.stats?.policy_violations ?? 234}     icon={ShieldAlert} trend="up" className="border-red-500/20" />
      </div>

      {/* Classification breakdown + Data type distribution */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Classification levels */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Lock className="h-4 w-4 text-red-400" />
              Classification Levels
            </CardTitle>
            <CardDescription className="text-xs">Data items by sensitivity level</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {CLASSIFICATION_LEVELS.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                <p className="text-lg font-medium">No data available</p>
                <p className="text-sm">Data will appear here once available</p>
              </div>
            ) : (
              CLASSIFICATION_LEVELS.map((lvl) => (
              <div key={lvl.level} className="space-y-1.5">
                <div className="flex items-center justify-between text-xs">
                  <div className="flex items-center gap-2">
                    <span className={cn("font-bold tracking-wide text-[10px]", lvl.text)}>{lvl.level}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-muted-foreground tabular-nums text-[10px]">{lvl.count.toLocaleString()}</span>
                    <span className="font-bold tabular-nums">{lvl.pct}%</span>
                  </div>
                </div>
                <div className="relative h-2 rounded-full bg-muted/30 overflow-hidden">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${lvl.pct}%` }}
                    transition={{ duration: 0.8, ease: "easeOut" }}
                    className={cn("h-full rounded-full", lvl.color)}
                  />
                </div>
              </div>
            ))}
          </CardContent>
        </Card>

        {/* Data type distribution */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Database className="h-4 w-4 text-blue-400" />
              Data Type Distribution
            </CardTitle>
            <CardDescription className="text-xs">Finding counts by data category</CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            {DATA_TYPES.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                <p className="text-lg font-medium">No data available</p>
                <p className="text-sm">Data will appear here once available</p>
              </div>
            ) : (
              DATA_TYPES.map((d) => (
              <div key={d.type} className="flex items-center gap-3">
                <span className="text-sm w-4 shrink-0">{d.icon}</span>
                <span className={cn("text-xs font-medium w-24 shrink-0", d.color)}>{d.type}</span>
                <div className="flex-1 relative h-2 rounded-full bg-muted/30 overflow-hidden">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${(d.count / MAX_TYPE_COUNT) * 100}%` }}
                    transition={{ duration: 0.8, ease: "easeOut" }}
                    className={cn("h-full rounded-full", d.bar)}
                  />
                </div>
                <span className="text-[10px] tabular-nums text-muted-foreground w-16 text-right shrink-0">
                  {d.count.toLocaleString()}
                </span>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>

      {/* Violation table */}
      <Card className="border-red-500/10">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-red-400" />
              Policy Violations
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
              {(liveData?.assets ?? VIOLATIONS).filter((v: any) => v.status === "open").length ?? VIOLATIONS.filter(v => v.status === "open").length} open
            </Badge>
          </div>
          <CardDescription className="text-xs">Data policy violations requiring remediation</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">User</TableHead>
                  <TableHead className="text-[11px] h-8">Data Type</TableHead>
                  <TableHead className="text-[11px] h-8">Violation</TableHead>
                  <TableHead className="text-[11px] h-8">Severity</TableHead>
                  <TableHead className="text-[11px] h-8">Channel</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {VIOLATIONS.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  VIOLATIONS.map((row, i) => (
                  <TableRow key={i} className="hover:bg-muted/30">
                    <TableCell className="text-xs font-mono py-2.5 text-muted-foreground">{row.user}</TableCell>
                    <TableCell className="py-2.5"><DataTypeBadge type={row.dataType} /></TableCell>
                    <TableCell className="py-2.5"><ViolationTypeBadge type={row.violationType} /></TableCell>
                    <TableCell className="py-2.5"><SeverityBadge sev={row.severity} /></TableCell>
                    <TableCell className="py-2.5"><ChannelBadge ch={row.channel} /></TableCell>
                    <TableCell className="py-2.5">
                      {row.status === "remediated"
                        ? <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">remediated</Badge>
                        : <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">open</Badge>
                      }
                    </TableCell>
                    <TableCell className="py-2.5 text-right">
                      <Button
                        variant="outline"
                        size="sm"
                        className={cn(
                          "h-6 px-2 text-[10px]",
                          row.status === "open" && "border-amber-500/30 text-amber-400 hover:bg-amber-500/10"
                        )}
                        disabled={row.status === "remediated"}
                      >
                        Remediate
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Recent scan results */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Search className="h-4 w-4 text-purple-400" />
            Recent Scan Results
          </CardTitle>
          <CardDescription className="text-xs">Classification scans across all data sources</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2 lg:grid-cols-3">
            {SCANS.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                <p className="text-lg font-medium">No data available</p>
                <p className="text-sm">Data will appear here once available</p>
              </div>
            ) : (
              SCANS.map((scan, i) => (
              <div
                key={i}
                className="rounded-lg border border-border bg-muted/10 p-4 flex flex-col gap-2 hover:bg-muted/20 transition-colors"
              >
                <div className="flex items-start justify-between gap-2">
                  <span className="text-xs font-semibold leading-tight">{scan.name}</span>
                  <ScanStatusBadge status={scan.status} />
                </div>
                <p className="text-[10px] text-muted-foreground">{scan.scope}</p>
                <div className="flex items-center justify-between text-xs mt-1">
                  <div className="flex flex-col gap-0.5">
                    <span className="text-muted-foreground text-[10px]">Items scanned</span>
                    <span className="font-bold tabular-nums">
                      {scan.itemsScanned > 0 ? scan.itemsScanned.toLocaleString() : "—"}
                    </span>
                  </div>
                  <div className="flex flex-col gap-0.5 text-right">
                    <span className="text-muted-foreground text-[10px]">Violations</span>
                    <span className={cn(
                      "font-bold tabular-nums",
                      scan.violations > 0 ? "text-red-400" : "text-green-400"
                    )}>
                      {scan.violations > 0 ? scan.violations : "—"}
                    </span>
                  </div>
                  <div className="flex flex-col gap-0.5 text-right">
                    <span className="text-muted-foreground text-[10px]">Scan time</span>
                    <span className="font-mono text-xs">{scan.scanTime}</span>
                  </div>
                </div>
              </div>
            ))
          )}
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
