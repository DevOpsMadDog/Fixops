/**
 * Social Engineering Defense
 *
 * Phishing simulation and security awareness.
 *   1. KPIs: Campaigns Run, Employees Tested, Click Rate, Reported Rate
 *   2. Campaign table (8 rows)
 *   3. Click rate by department — horizontal bars
 *   4. Top phishing templates (6 cards)
 *   5. Training completion progress bars
 *
 * API stubs: GET /api/v1/phishing/campaigns, /api/v1/phishing/templates, /api/v1/training/completion
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";

// ── API helpers ────────────────────────────────────────────────
const API_KEY = localStorage.getItem("aldeci_api_key") || import.meta.env.VITE_API_KEY || "dev-key";
const ORG_ID  = "default";

async function apiFetch(path: string) {
  const res = await fetch(`/api/v1${path}`, {
    headers: { "X-API-Key": API_KEY },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}
import {
  Mail, Users, TrendingDown, TrendingUp, RefreshCw,
  BookOpen, ShieldCheck, AlertTriangle, BarChart3,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── Mock data ──────────────────────────────────────────────────

const CAMPAIGNS = [
  { name: "CEO Fraud Q1",        type: "pretexting", group: "Finance",     launched: "2026-04-01", sent: 48,  clicked: 12, reported: 8,  status: "completed" },
  { name: "IT Credential Reset", type: "phishing",   group: "All Staff",   launched: "2026-03-25", sent: 847, clicked: 62, reported: 291, status: "completed" },
  { name: "Vishing Payroll",     type: "vishing",    group: "HR",          launched: "2026-03-18", sent: 32,  clicked: 9,  reported: 14, status: "completed" },
  { name: "Package Delivery",    type: "smishing",   group: "All Staff",   launched: "2026-03-10", sent: 847, clicked: 71, reported: 268, status: "completed" },
  { name: "Board DocuSign",      type: "phishing",   group: "Executives",  launched: "2026-04-10", sent: 12,  clicked: 1,  reported: 8,  status: "active" },
  { name: "Cloud Login Alert",   type: "phishing",   group: "Engineering", launched: "2026-04-12", sent: 124, clicked: 5,  reported: 61, status: "active" },
  { name: "Helpdesk Callback",   type: "vishing",    group: "Operations",  launched: "2026-04-14", sent: 67,  clicked: 18, reported: 19, status: "active" },
  { name: "Benefits Update",     type: "phishing",   group: "HR",          launched: "2026-04-16", sent: 32,  clicked: 0,  reported: 0,  status: "scheduled" },
];

const DEPT_CLICK_RATES = [
  { dept: "HR",          rate: 18.4 },
  { dept: "Finance",     rate: 12.8 },
  { dept: "Operations",  rate: 10.6 },
  { dept: "Marketing",   rate: 9.1  },
  { dept: "Legal",       rate: 7.5  },
  { dept: "IT",          rate: 5.9  },
  { dept: "Sales",       rate: 5.3  },
  { dept: "Engineering", rate: 4.2  },
];

const TEMPLATES = [
  { name: "IT Password Expiry",   type: "phishing",   clickRate: 22.4, lastUsed: "2026-03-25" },
  { name: "Payroll Change Alert", type: "phishing",   clickRate: 18.7, lastUsed: "2026-03-01" },
  { name: "CEO Wire Request",     type: "pretexting", clickRate: 15.3, lastUsed: "2026-04-01" },
  { name: "DHL Package Alert",    type: "smishing",   clickRate: 8.4,  lastUsed: "2026-03-10" },
  { name: "DocuSign Document",    type: "phishing",   clickRate: 6.8,  lastUsed: "2026-04-10" },
  { name: "Cloud MFA Prompt",     type: "phishing",   clickRate: 4.0,  lastUsed: "2026-04-12" },
];

const TRAINING_MODULES = [
  { name: "Phishing Awareness Fundamentals",   completion: 94 },
  { name: "Social Engineering Red Flags",      completion: 81 },
  { name: "Password & MFA Best Practices",     completion: 88 },
  { name: "Vishing & Smishing Defense",        completion: 67 },
  { name: "Incident Reporting Procedures",     completion: 73 },
];

// ── Helpers ────────────────────────────────────────────────────

function CampaignTypeBadge({ type }: { type: string }) {
  const cls =
    type === "phishing"    ? "border-red-500/30 text-red-400 bg-red-500/10" :
    type === "vishing"     ? "border-amber-500/30 text-amber-400 bg-amber-500/10" :
    type === "smishing"    ? "border-orange-500/30 text-orange-400 bg-orange-500/10" :
                             "border-purple-500/30 text-purple-400 bg-purple-500/10";
  return <Badge className={cn("text-[10px] border capitalize", cls)}>{type}</Badge>;
}

function StatusBadge({ status }: { status: string }) {
  const cls =
    status === "active"    ? "border-green-500/30 text-green-400 bg-green-500/10" :
    status === "completed" ? "border-border text-muted-foreground" :
                             "border-blue-500/30 text-blue-400 bg-blue-500/10";
  return <Badge className={cn("text-[10px] border capitalize", cls)}>{status}</Badge>;
}

function ClickRateBadge({ rate }: { rate: number }) {
  const cls =
    rate > 10 ? "border-red-500/30 text-red-400 bg-red-500/10" :
    rate > 7  ? "border-amber-500/30 text-amber-400 bg-amber-500/10" :
                "border-green-500/30 text-green-400 bg-green-500/10";
  return <Badge className={cn("text-[10px] border tabular-nums", cls)}>{rate}% CR</Badge>;
}

const DEPT_MAX = Math.max(...DEPT_CLICK_RATES.map((d) => d.rate));

// ── Component ──────────────────────────────────────────────────

export default function SocialEngineering() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);

  const loadData = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/phishing/stats?org_id=${ORG_ID}`),
      apiFetch(`/phishing/campaigns?org_id=${ORG_ID}`),
      apiFetch(`/phishing/templates?org_id=${ORG_ID}`),
    ]).then(([statsRes, campaignsRes, templatesRes]) => {
      const stats     = statsRes.status     === "fulfilled" ? statsRes.value     : null;
      const campaigns = campaignsRes.status === "fulfilled" ? campaignsRes.value : null;
      const templates = templatesRes.status === "fulfilled" ? templatesRes.value : null;
      if (stats || campaigns || templates) {
        setLiveData({ stats, campaigns, templates });
      }
    }).finally(() => setDataLoading(false));
  };

  useEffect(() => { loadData(); }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    loadData();
    setTimeout(() => setRefreshing(false), 800);
  };

  // Resolve KPI values
  const kpiCampaignsRun    = liveData?.stats?.total_campaigns    ?? 47;
  const kpiEmployeesTested = liveData?.stats?.total_targets != null
    ? liveData.stats.total_targets.toLocaleString()
    : "2,847";
  const kpiClickRate       = liveData?.stats?.avg_click_rate != null
    ? `${liveData.stats.avg_click_rate.toFixed(1)}%`
    : "8.3%";
  const kpiReportedRate    = liveData?.stats?.avg_report_rate != null
    ? `${liveData.stats.avg_report_rate.toFixed(1)}%`
    : "34.7%";

  // Campaign table — map API shape to mock shape
  const liveCampaignsArr = Array.isArray(liveData?.campaigns) ? liveData.campaigns : null;
  const tableCampaigns = liveCampaignsArr && liveCampaignsArr.length > 0
    ? liveCampaignsArr.map((c: any) => ({
        name:     c.name ?? "—",
        type:     c.campaign_type ?? "phishing",
        group:    c.target_group ?? "—",
        launched: c.start_date ?? c.created_at ?? "—",
        sent:     c.total_targets   ?? c.sent     ?? 0,
        clicked:  c.total_clicked   ?? c.clicked  ?? 0,
        reported: c.total_reported  ?? c.reported ?? 0,
        status:   c.status ?? "draft",
      }))
    : CAMPAIGNS;

  // Templates — map API shape to mock shape
  const liveTemplatesArr = Array.isArray(liveData?.templates) ? liveData.templates : null;
  const tableTemplates = liveTemplatesArr && liveTemplatesArr.length > 0
    ? liveTemplatesArr.slice(0, 6).map((t: any) => ({
        name:      t.name ?? "—",
        type:      t.template_type ?? "phishing",
        clickRate: t.click_rate ?? t.avg_click_rate ?? 0,
        lastUsed:  t.last_used ?? t.created_at ?? "—",
      }))
    : TEMPLATES;

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      {/* Header */}
      <PageHeader
        title="Social Engineering Defense"
        description="Phishing simulation and security awareness"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Campaigns Run"    value={kpiCampaignsRun}    icon={Mail} />
        <KpiCard title="Employees Tested" value={kpiEmployeesTested}  icon={Users} />
        <KpiCard
          title="Click Rate"
          value={kpiClickRate}
          icon={AlertTriangle}         trend="down"
          description="-2.1% vs last quarter"
          className="border-amber-500/20"
        />
        <KpiCard
          title="Reported Rate"
          value={kpiReportedRate}
          icon={ShieldCheck}         trend="up"
          description="+5.2% vs last quarter"
          className="border-green-500/20"
        />
      </div>

      {/* Campaign table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Mail className="h-4 w-4 text-red-400" />
              Campaigns
            </CardTitle>
            <Button variant="outline" size="sm" className="h-7 text-xs">New Campaign</Button>
          </div>
          <CardDescription className="text-xs">All phishing simulation campaigns with click and report metrics</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Campaign</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Target Group</TableHead>
                  <TableHead className="text-[11px] h-8">Launched</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Sent</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Clicked</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Reported</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {tableCampaigns.map((c: { name: string; type: string; group: string; launched: string; sent: number; clicked: number; reported: number; status: string }) => {
                  const clickPct  = c.sent > 0 ? ((c.clicked / c.sent) * 100).toFixed(1) : "0.0";
                  const reportPct = c.sent > 0 ? ((c.reported / c.sent) * 100).toFixed(1) : "0.0";
                  return (
                    <TableRow key={c.name} className="hover:bg-muted/30">
                      <TableCell className="text-xs font-medium py-2.5 max-w-[160px] truncate">{c.name}</TableCell>
                      <TableCell className="py-2.5"><CampaignTypeBadge type={c.type} /></TableCell>
                      <TableCell className="text-xs py-2.5 text-muted-foreground">{c.group}</TableCell>
                      <TableCell className="text-xs py-2.5 tabular-nums text-muted-foreground">{c.launched}</TableCell>
                      <TableCell className="text-xs py-2.5 text-right tabular-nums">{c.sent}</TableCell>
                      <TableCell className={cn("text-xs py-2.5 text-right tabular-nums font-medium", parseFloat(clickPct) > 10 ? "text-red-400" : "text-amber-400")}>
                        {c.clicked} <span className="text-muted-foreground text-[10px]">({clickPct}%)</span>
                      </TableCell>
                      <TableCell className="text-xs py-2.5 text-right tabular-nums text-green-400 font-medium">
                        {c.reported} <span className="text-muted-foreground text-[10px]">({reportPct}%)</span>
                      </TableCell>
                      <TableCell className="py-2.5"><StatusBadge status={c.status} /></TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Dept click rates + Training */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Dept click rates */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <BarChart3 className="h-4 w-4 text-amber-400" />
              Click Rate by Department
            </CardTitle>
            <CardDescription className="text-xs">Sorted by click rate descending — red bars indicate high risk</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {DEPT_CLICK_RATES.map((d) => (
              <div key={d.dept} className="space-y-1">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-medium">{d.dept}</span>
                  <span className={cn("font-bold tabular-nums", d.rate > 10 ? "text-red-400" : d.rate > 7 ? "text-amber-400" : "text-green-400")}>
                    {d.rate}%
                  </span>
                </div>
                <div className="relative h-2 rounded-full bg-muted/30 overflow-hidden">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${(d.rate / DEPT_MAX) * 100}%` }}
                    transition={{ duration: 0.7, ease: "easeOut" }}
                    className={cn(
                      "h-full rounded-full",
                      d.rate > 10 ? "bg-red-500" : d.rate > 7 ? "bg-amber-500" : "bg-green-500"
                    )}
                  />
                </div>
              </div>
            ))}
          </CardContent>
        </Card>

        {/* Training completion */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <BookOpen className="h-4 w-4 text-indigo-400" />
              Training Completion
            </CardTitle>
            <CardDescription className="text-xs">Security awareness module completion rates</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {TRAINING_MODULES.map((m) => (
              <div key={m.name} className="space-y-1.5">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-medium truncate pr-2">{m.name}</span>
                  <span className={cn(
                    "font-bold tabular-nums shrink-0",
                    m.completion >= 90 ? "text-green-400" : m.completion >= 75 ? "text-yellow-400" : "text-red-400"
                  )}>
                    {m.completion}%
                  </span>
                </div>
                <Progress value={m.completion} className="h-1.5" />
              </div>
            ))}
          </CardContent>
        </Card>
      </div>

      {/* Phishing templates */}
      <div>
        <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
          <TrendingUp className="h-4 w-4 text-red-400" />
          Top Phishing Templates
        </h3>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3">
          {tableTemplates.map((t: { name: string; type: string; clickRate: number; lastUsed: string }) => (
            <Card key={t.name} className={cn("hover:border-border/80 transition-colors", t.clickRate > 10 && "border-red-500/20")}>
              <CardContent className="p-4 space-y-2">
                <div className="flex items-start justify-between gap-2">
                  <span className="text-sm font-semibold leading-tight">{t.name}</span>
                  <ClickRateBadge rate={t.clickRate} />
                </div>
                <div className="flex items-center justify-between text-xs text-muted-foreground">
                  <CampaignTypeBadge type={t.type} />
                  <span className="tabular-nums">Last: {t.lastUsed}</span>
                </div>
                {t.clickRate > 10 && (
                  <div className="flex items-center gap-1 text-[10px] text-red-400">
                    <TrendingDown className="h-3 w-3" />
                    High risk — prioritize retraining
                  </div>
                )}
              </CardContent>
            </Card>
          ))}
        </div>
      </div>
    </motion.div>
  );
}
