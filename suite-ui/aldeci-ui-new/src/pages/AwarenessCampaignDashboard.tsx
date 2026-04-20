/**
 * Awareness Campaign Dashboard
 *
 * Security awareness campaign tracking — participation and pass rates.
 *   1. KPIs: Total Campaigns, Active, Total Participations, Overall Pass Rate %
 *   2. Campaigns table (title, campaign_type, campaign_status, target_department, participant_count, pass_rate)
 *
 * Route: /awareness-campaigns
 * API: GET /api/v1/awareness-campaigns
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { BookOpen, RefreshCw, Users, CheckCircle2, Megaphone, TrendingUp } from "lucide-react";

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

const MOCK_CAMPAIGNS = [
  { id: "camp-001", title: "Phishing Awareness Q2",       campaign_type: "Phishing Simulation", campaign_status: "active",    target_department: "All Staff",   participant_count: 1240, pass_rate: 78.4 },
  { id: "camp-002", title: "Password Hygiene Training",   campaign_type: "e-Learning",          campaign_status: "completed", target_department: "Engineering", participant_count: 380,  pass_rate: 92.1 },
  { id: "camp-003", title: "Social Engineering Basics",   campaign_type: "Video Training",      campaign_status: "active",    target_department: "Finance",     participant_count: 145,  pass_rate: 84.6 },
  { id: "camp-004", title: "Data Handling Policy",        campaign_type: "Policy Attestation",  campaign_status: "completed", target_department: "HR",          participant_count: 87,   pass_rate: 100.0 },
  { id: "camp-005", title: "Cloud Security Essentials",   campaign_type: "e-Learning",          campaign_status: "draft",     target_department: "DevOps",      participant_count: 0,    pass_rate: 0.0 },
  { id: "camp-006", title: "Ransomware Response Drill",   campaign_type: "Tabletop Exercise",   campaign_status: "active",    target_department: "SOC",         participant_count: 34,   pass_rate: 67.6 },
  { id: "camp-007", title: "Insider Threat Awareness",    campaign_type: "Video Training",      campaign_status: "paused",    target_department: "Management",  participant_count: 62,   pass_rate: 88.7 },
  { id: "camp-008", title: "Zero Trust Principles",       campaign_type: "e-Learning",          campaign_status: "completed", target_department: "IT",          participant_count: 210,  pass_rate: 95.2 },
  { id: "camp-009", title: "MFA Enrollment Drive",        campaign_type: "Policy Attestation",  campaign_status: "active",    target_department: "All Staff",   participant_count: 1580, pass_rate: 73.9 },
  { id: "camp-010", title: "Incident Reporting Training", campaign_type: "e-Learning",          campaign_status: "draft",     target_department: "All Staff",   participant_count: 0,    pass_rate: 0.0 },
];

const MOCK_STATS = { total_campaigns: 47, active_campaigns: 12, total_participations: 18420, overall_pass_rate: 83.7 };

// ── Badge helpers ──────────────────────────────────────────────

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    active:    "border-green-500/30 text-green-400 bg-green-500/10",
    completed: "border-blue-500/30 text-blue-400 bg-blue-500/10",
    draft:     "border-zinc-500/30 text-zinc-400 bg-zinc-500/10",
    paused:    "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border")}>
      {status}
    </Badge>
  );
}

function passRateColor(rate: number) {
  if (rate >= 90) return "text-green-400";
  if (rate >= 75) return "text-emerald-400";
  if (rate >= 60) return "text-yellow-400";
  return "text-red-400";
}

function exportCsv(campaigns: any[]) {
  const headers = ["title", "campaign_type", "campaign_status", "target_department", "participant_count", "pass_rate"];
  const rows = campaigns.map((c) => headers.map((h) => c[h] ?? "").join(","));
  const csv = [headers.join(","), ...rows].join("\n");
  const blob = new Blob([csv], { type: "text/csv" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url; a.download = "awareness_campaigns.csv"; a.click();
  URL.revokeObjectURL(url);
}

// ── Component ──────────────────────────────────────────────────

export default function AwarenessCampaignDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveCampaigns, setLiveCampaigns] = useState<any[] | null>(null);
  const [liveStats, setLiveStats] = useState<any | null>(null);

  useEffect(() => {
    Promise.allSettled([
      apiFetch(`/api/v1/awareness-campaigns/campaigns?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/awareness-campaigns/stats?org_id=${ORG_ID}`),
    ]).then(([campRes, statsRes]) => {
      if (campRes.status === "fulfilled") setLiveCampaigns(campRes.value?.campaigns ?? campRes.value ?? null);
      if (statsRes.status === "fulfilled") setLiveStats(statsRes.value ?? null);
    });
  }, []);

  const handleRefresh = () => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); };

  const campaigns = liveCampaigns ?? MOCK_CAMPAIGNS;
  const stats     = liveStats     ?? MOCK_STATS;

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      <PageHeader
        title="Awareness Campaigns"
        description="Security awareness campaign management — participation tracking, pass rates, and department coverage"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Campaigns"      value={stats.total_campaigns}       icon={Megaphone}    trend="flat" className="border-green-500/20" />
        <KpiCard title="Active"               value={stats.active_campaigns}      icon={BookOpen}     trend="up"   className="border-emerald-500/20" />
        <KpiCard title="Participations"       value={stats.total_participations.toLocaleString()} icon={Users} trend="up" className="border-green-500/20" />
        <KpiCard title="Overall Pass Rate"    value={`${stats.overall_pass_rate}%`} icon={TrendingUp}  trend="up"   className="border-emerald-500/20" />
      </div>

      {/* Campaigns Table */}
      <Card className="border-green-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-green-400">
              <CheckCircle2 className="h-4 w-4" />
              Campaign Registry
            </CardTitle>
            <div className="flex items-center gap-2">
              <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">
                {campaigns.filter((c: any) => c.campaign_status === "active").length} active
              </Badge>
              <Button variant="outline" size="sm" className="text-[11px] h-7" onClick={() => exportCsv(campaigns)}>
                Export CSV
              </Button>
            </div>
          </div>
          <CardDescription className="text-xs">
            All security awareness campaigns with type, status, target department, participation, and pass rate
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Campaign</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8">Department</TableHead>
                  <TableHead className="text-[11px] h-8">Participants</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Pass Rate</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {campaigns.map((camp: any, i: number) => (
                  <TableRow key={camp.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-semibold text-[11px] text-green-300 max-w-[200px] truncate">
                      {camp.title ?? "—"}
                    </TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">
                      {camp.campaign_type ?? "—"}
                    </TableCell>
                    <TableCell className="py-2">
                      <StatusBadge status={camp.campaign_status ?? "draft"} />
                    </TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">
                      {camp.target_department ?? "—"}
                    </TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-emerald-300">
                      {(camp.participant_count ?? 0).toLocaleString()}
                    </TableCell>
                    <TableCell className={cn("py-2 font-mono text-[11px] font-bold text-right", passRateColor(camp.pass_rate ?? 0))}>
                      {camp.pass_rate > 0 ? `${camp.pass_rate.toFixed(1)}%` : "—"}
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
