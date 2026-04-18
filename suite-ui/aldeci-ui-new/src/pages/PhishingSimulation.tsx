/**
 * Phishing Simulation
 *
 * Campaign management and employee security awareness.
 *   1. KPIs: Campaigns Run, Employees Tested, Click Rate, Report Rate
 *   2. Campaign table (10 rows)
 *   3. Department click rate bars (8 depts)
 *   4. Template library (8 cards, 2-col)
 *   5. Employee training completion (5 modules with progress bars)
 *
 * API stubs: GET /api/v1/phishing/campaigns, /api/v1/phishing/templates, /api/v1/phishing/training
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";

// == API helpers ================================================
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
import { Mail, Users, MousePointer, Flag, RefreshCw, BookOpen, BarChart3 } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// == Mock data ==================================================

const CAMPAIGNS = [
  { id: "C-001", name: "Q2 CEO Fraud",         type: "spear_phishing", group: "Finance",    launched: "2026-04-01", targets: 45,  clicked: 8,  reported: 19, rate: 17.8, status: "completed" },
  { id: "C-002", name: "IT Password Reset",    type: "email",          group: "All Staff",  launched: "2026-04-03", targets: 320, clicked: 22, reported: 98, rate: 6.9,  status: "completed" },
  { id: "C-003", name: "HR Benefits Survey",   type: "email",          group: "HR",         launched: "2026-04-05", targets: 38,  clicked: 7,  reported: 12, rate: 18.4, status: "completed" },
  { id: "C-004", name: "DocuSign Lure",        type: "email",          group: "Legal",      launched: "2026-04-07", targets: 24,  clicked: 3,  reported: 10, rate: 12.5, status: "completed" },
  { id: "C-005", name: "Crypto Invoice",       type: "email",          group: "Finance",    launched: "2026-04-09", targets: 45,  clicked: 4,  reported: 18, rate: 8.9,  status: "completed" },
  { id: "C-006", name: "MFA Bypass SMS",       type: "sms",            group: "Engineering",launched: "2026-04-10", targets: 112, clicked: 5,  reported: 42, rate: 4.5,  status: "active"    },
  { id: "C-007", name: "LinkedIn CISO Spear",  type: "spear_phishing", group: "Executives", launched: "2026-04-11", targets: 12,  clicked: 1,  reported: 7,  rate: 8.3,  status: "active"    },
  { id: "C-008", name: "Zoom Credential Grab", type: "email",          group: "All Staff",  launched: "2026-04-14", targets: 320, clicked: 0,  reported: 0,  rate: 0.0,  status: "draft"     },
  { id: "C-009", name: "Vishing Follow-Up",    type: "sms",            group: "Sales",      launched: "2026-04-12", targets: 67,  clicked: 6,  reported: 21, rate: 9.0,  status: "paused"    },
  { id: "C-010", name: "Fake IT Helpdesk",     type: "email",          group: "All Staff",  launched: "2026-04-15", targets: 320, clicked: 0,  reported: 0,  rate: 0.0,  status: "draft"     },
];

const DEPT_RATES = [
  { dept: "HR",           rate: 18.4, color: "bg-red-500" },
  { dept: "Finance",      rate: 12.8, color: "bg-red-400" },
  { dept: "Legal",        rate: 10.2, color: "bg-red-400" },
  { dept: "Sales",        rate: 9.0,  color: "bg-amber-400" },
  { dept: "Operations",   rate: 7.8,  color: "bg-amber-500" },
  { dept: "Product",      rate: 6.1,  color: "bg-yellow-400" },
  { dept: "DevOps",       rate: 5.4,  color: "bg-green-400" },
  { dept: "Engineering",  rate: 4.2,  color: "bg-green-500" },
];

const TEMPLATES = [
  { id: 1, name: "CEO Wire Transfer",       type: "spear_phishing", difficulty: "expert", avgClick: "22.4%" },
  { id: 2, name: "IT Password Expiry",      type: "email",          difficulty: "low",    avgClick: "8.1%"  },
  { id: 3, name: "DocuSign Signature",      type: "email",          difficulty: "medium", avgClick: "13.7%" },
  { id: 4, name: "LinkedIn InMail",         type: "spear_phishing", difficulty: "high",   avgClick: "17.2%" },
  { id: 5, name: "SMS MFA Alert",           type: "sms",            difficulty: "medium", avgClick: "11.3%" },
  { id: 6, name: "Zoom Meeting Invite",     type: "email",          difficulty: "low",    avgClick: "6.8%"  },
  { id: 7, name: "AWS Billing Alert",       type: "email",          difficulty: "medium", avgClick: "9.5%"  },
  { id: 8, name: "Fake HR Benefits Form",   type: "email",          difficulty: "high",   avgClick: "15.9%" },
];

const TRAINING_MODULES = [
  { name: "Phishing Awareness Fundamentals", completion: 92, enrolled: 2847 },
  { name: "Social Engineering Defense",      completion: 78, enrolled: 2847 },
  { name: "CEO Fraud & BEC Recognition",     completion: 61, enrolled: 2847 },
  { name: "Safe Password Practices",         completion: 85, enrolled: 2847 },
  { name: "Incident Reporting Procedures",   completion: 47, enrolled: 2847 },
];

// == Helpers ====================================================

function TypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    email:          "border-blue-500/30 text-blue-400 bg-blue-500/10",
    sms:            "border-purple-500/30 text-purple-400 bg-purple-500/10",
    spear_phishing: "border-red-500/30 text-red-400 bg-red-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border", map[type] ?? "border-border text-muted-foreground")}>
      {type.replace("_", " ")}
    </Badge>
  );
}

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    active:    "border-green-500/30 text-green-400 bg-green-500/10",
    completed: "border-border text-muted-foreground bg-muted/20",
    draft:     "border-blue-500/30 text-blue-400 bg-blue-500/10",
    paused:    "border-amber-500/30 text-amber-400 bg-amber-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border text-muted-foreground")}>
      {status}
    </Badge>
  );
}

function DifficultyBadge({ diff }: { diff: string }) {
  const map: Record<string, string> = {
    low:    "border-green-500/30 text-green-400 bg-green-500/10",
    medium: "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    high:   "border-amber-500/30 text-amber-400 bg-amber-500/10",
    expert: "border-red-500/30 text-red-400 bg-red-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[diff] ?? "border-border text-muted-foreground")}>
      {diff}
    </Badge>
  );
}

// == Component ==================================================

export default function PhishingSimulation() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveData, setLiveData]     = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);
  const [loading, setLoading] = useState(true);

  const fetchData = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/phishing/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/phishing/campaigns?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/phishing/templates?org_id=${ORG_ID}`),
    ]).then(([statsResult, campaignsResult, templatesResult]) => {
      const stats     = statsResult.status     === "fulfilled" ? statsResult.value     : null;
      const campaigns = campaignsResult.status === "fulfilled" ? campaignsResult.value : null;
      const templates = templatesResult.status === "fulfilled" ? templatesResult.value : null;
      if (stats || campaigns || templates) {
        setLiveData({ stats, campaigns, templates });
      }
    }).finally(() => setDataLoading(false));
  };

  useEffect(() => { fetchData(); }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchData();
    setTimeout(() => setRefreshing(false), 800);
  };

  // Derive display values = live data takes precedence over mock
  const displayCampaigns = liveData?.campaigns ?? CAMPAIGNS;
  const displayTemplates = liveData?.templates ?? TEMPLATES;

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
        title="Phishing Simulation"
        description="Campaign management and employee security awareness"
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
              <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
            </Button>
            <Button size="sm">New Campaign</Button>
          </div>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Campaigns Run"     value={liveData?.stats?.total_campaigns ?? 47}    icon={Mail}         />
        <KpiCard title="Employees Tested"  value={liveData?.stats?.total_targets ?? "2,847"} icon={Users}        />
        <KpiCard title="Click Rate"        value={liveData?.stats?.click_rate != null ? `${liveData.stats.click_rate}%` : "8.3%"} icon={MousePointer} trend="down" className="border-amber-500/20" />
        <KpiCard title="Report Rate"       value={liveData?.stats?.report_rate != null ? `${liveData.stats.report_rate}%` : "34.7%"} icon={Flag} trend="up" className="border-green-500/20" />
      </div>

      {/* Campaign table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Mail className="h-4 w-4 text-blue-400" />
              Campaigns
            </CardTitle>
            <Badge className="text-[10px] border border-border text-muted-foreground">
              {displayCampaigns.length} total
            </Badge>
          </div>
          <CardDescription className="text-xs">All phishing campaigns with click and report metrics</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Name</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Group</TableHead>
                  <TableHead className="text-[11px] h-8">Launched</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Targets</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Clicked</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Reported</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Click %</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {displayCampaigns.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  displayCampaigns.map((row: any) => (
                  <TableRow key={row.id} className="hover:bg-muted/30">
                    <TableCell className="text-xs font-medium py-2.5 max-w-[160px] truncate">{row.name}</TableCell>
                    <TableCell className="py-2.5"><TypeBadge type={row.type} /></TableCell>
                    <TableCell className="text-xs py-2.5 text-muted-foreground">{row.group}</TableCell>
                    <TableCell className="text-xs py-2.5 tabular-nums text-muted-foreground">{row.launched}</TableCell>
                    <TableCell className="text-xs py-2.5 tabular-nums text-right">{row.targets}</TableCell>
                    <TableCell className="text-xs py-2.5 tabular-nums text-right text-amber-400">{row.clicked}</TableCell>
                    <TableCell className="text-xs py-2.5 tabular-nums text-right text-green-400">{row.reported}</TableCell>
                    <TableCell className={cn(
                      "text-xs py-2.5 tabular-nums font-bold text-right",
                      row.rate > 10 ? "text-red-400" : row.rate > 7 ? "text-amber-400" : "text-green-400"
                    )}>
                      {row.rate}%
                    </TableCell>
                    <TableCell className="py-2.5"><StatusBadge status={row.status} /></TableCell>
                    <TableCell className="py-2.5 text-right">
                      <Button variant="outline" size="sm" className="h-6 px-2 text-[10px]">View</Button>
                    </TableCell>
                  </TableRow>
                ))
              )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Dept bars + Template library */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Dept click rate bars */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <BarChart3 className="h-4 w-4 text-amber-400" />
              Department Click Rates
            </CardTitle>
            <CardDescription className="text-xs">Sorted by click rate = red &gt;10%, yellow &gt;7%</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {DEPT_RATES.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                <p className="text-lg font-medium">No data available</p>
                <p className="text-sm">Data will appear here once available</p>
              </div>
            ) : (
              DEPT_RATES.map((d) => (
              <div key={d.dept} className="space-y-1">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-medium">{d.dept}</span>
                  <span className={cn(
                    "font-bold tabular-nums",
                    d.rate > 10 ? "text-red-400" : d.rate > 7 ? "text-amber-400" : "text-green-400"
                  )}>
                    {d.rate}%
                  </span>
                </div>
                <div className="relative h-2 rounded-full bg-muted/30 overflow-hidden">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${(d.rate / 25) * 100}%` }}
                    transition={{ duration: 0.8, ease: "easeOut" }}
                    className={cn("h-full rounded-full", d.color)}
                  />
                </div>
              </div>
            ))
          )}
          </CardContent>
        </Card>

        {/* Template library */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Mail className="h-4 w-4 text-purple-400" />
              Template Library
            </CardTitle>
            <CardDescription className="text-xs">8 ready-to-use phishing templates</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 gap-2">
              {displayTemplates.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                  <p className="text-lg font-medium">No data available</p>
                  <p className="text-sm">Data will appear here once available</p>
                </div>
              ) : (
                displayTemplates.map((t: any) => (
                <div
                  key={t.id}
                  className="rounded-lg border border-border bg-muted/10 p-3 flex flex-col gap-2 hover:bg-muted/20 transition-colors"
                >
                  <div className="flex items-start justify-between gap-1">
                    <span className="text-xs font-medium leading-tight line-clamp-2">{t.name}</span>
                  </div>
                  <div className="flex items-center gap-1 flex-wrap">
                    <TypeBadge type={t.type} />
                    <DifficultyBadge diff={t.difficulty} />
                  </div>
                  <div className="flex items-center justify-between">
                    <span className="text-[10px] text-muted-foreground">Avg click: <span className="text-amber-400 font-bold">{t.avgClick}</span></span>
                    <Button variant="outline" size="sm" className="h-5 px-2 text-[9px]">Use</Button>
                  </div>
                </div>
              )))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Employee training completion */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <BookOpen className="h-4 w-4 text-green-400" />
            Employee Training Completion
          </CardTitle>
          <CardDescription className="text-xs">Security awareness module progress across {(2847).toLocaleString()} enrolled employees</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {TRAINING_MODULES.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
              <p className="text-lg font-medium">No data available</p>
              <p className="text-sm">Data will appear here once available</p>
            </div>
          ) : (
            TRAINING_MODULES.map((mod, idx) => (
            <div key={idx} className="space-y-1.5">
              <div className="flex items-center justify-between text-xs">
                <span className="font-medium">{mod.name}</span>
                <Badge className={cn(
                  "text-[10px] border",
                  mod.completion >= 80 ? "border-green-500/30 text-green-400 bg-green-500/10" :
                  mod.completion >= 60 ? "border-yellow-500/30 text-yellow-400 bg-yellow-500/10" :
                                        "border-red-500/30 text-red-400 bg-red-500/10"
                )}>
                  {mod.completion}%
                </Badge>
              </div>
              <div className="relative h-2 rounded-full bg-muted/30 overflow-hidden">
                <motion.div
                  initial={{ width: 0 }}
                  animate={{ width: `${mod.completion}%` }}
                  transition={{ duration: 0.9, ease: "easeOut", delay: idx * 0.08 }}
                  className={cn(
                    "h-full rounded-full",
                    mod.completion >= 80 ? "bg-green-500" :
                    mod.completion >= 60 ? "bg-yellow-500" : "bg-red-500"
                  )}
                />
              </div>
            </div>
          )))}
        </CardContent>
      </Card>
    </motion.div>
  );
}
