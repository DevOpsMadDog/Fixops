/**
 * Threat Intel Automation Dashboard
 *
 * Automation rules, feed enrichments, trigger stats for the TI Automation engine.
 *   1. KPIs: Total Rules, Active Rules, Triggers Today, IOCs Enriched
 *   2. Automation rules table (name, trigger, action, last_run, status)
 *
 * Route: /threat-intel-automation
 * API: GET /api/v1/ti-automation/automations
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Zap, RefreshCw, CheckCircle2, Activity, ListChecks } from "lucide-react";

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
  const res = await fetch(`${API_BASE}${path}`, {
    ...opts,
    headers: { "X-API-Key": API_KEY, "Content-Type": "application/json", ...(opts?.headers ?? {}) },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ── Mock data ──────────────────────────────────────────────────

const MOCK_RULES = [
  { id: "TIA-001", name: "Auto-block Malicious IPs",       trigger: "ioc_match",       action: "block_ip",          last_run: "2 min ago",  status: "active" },
  { id: "TIA-002", name: "Enrich New CVEs via NVD",        trigger: "new_cve",         action: "enrich_nvd",        last_run: "15 min ago", status: "active" },
  { id: "TIA-003", name: "Hash IOC Dedup Check",           trigger: "feed_ingest",     action: "dedup_sha256",      last_run: "5 min ago",  status: "active" },
  { id: "TIA-004", name: "TLP:RED Report Notify CISO",     trigger: "tlp_red",         action: "notify_ciso",       last_run: "1 hr ago",   status: "active" },
  { id: "TIA-005", name: "Phishing URL Sandbox Submit",    trigger: "phish_url",       action: "sandbox_submit",    last_run: "8 min ago",  status: "active" },
  { id: "TIA-006", name: "Threat Actor Campaign Alert",    trigger: "actor_activity",  action: "create_incident",   last_run: "3 hr ago",   status: "paused" },
  { id: "TIA-007", name: "KEV Exploit Auto-escalate",      trigger: "kev_added",       action: "escalate_priority", last_run: "22 min ago", status: "active" },
  { id: "TIA-008", name: "Stale IOC Expiry Cleanup",       trigger: "schedule_daily",  action: "expire_iocs",       last_run: "6 hr ago",   status: "active" },
];

const MOCK_STATS = { total_rules: 8, active_rules: 7, triggers_today: 142, iocs_enriched: 3847 };

// ── Badge helpers ──────────────────────────────────────────────

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    active: "border-violet-500/30 text-violet-400 bg-violet-500/10",
    paused: "border-slate-500/30 text-slate-400 bg-slate-500/10",
    error:  "border-red-500/30 text-red-400 bg-red-500/10",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border")}>{status}</Badge>;
}

function TriggerBadge({ trigger }: { trigger: string }) {
  return (
    <Badge className="text-[10px] border border-purple-500/30 text-purple-400 bg-purple-500/10 font-mono">
      {trigger.replace(/_/g, " ")}
    </Badge>
  );
}

function ActionBadge({ action }: { action: string }) {
  return (
    <Badge className="text-[10px] border border-violet-500/30 text-violet-300 bg-violet-500/10 font-mono">
      {action.replace(/_/g, " ")}
    </Badge>
  );
}

// ── Component ──────────────────────────────────────────────────

export default function ThreatIntelAutomation() {
  const [refreshing, setRefreshing] = useState(false);
  const [loading, setLoading] = useState(true);
  const [liveRules, setLiveRules]   = useState<any[] | null>(null);
  const [liveStats, setLiveStats]   = useState<any | null>(null);

  useEffect(() => {
    Promise.allSettled([
      apiFetch(`/api/v1/ti-automation/automations?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/ti-automation/stats?org_id=${ORG_ID}`),
    ]).then(([rulesRes, statsRes]) => {
      if (rulesRes.status === "fulfilled") setLiveRules(rulesRes.value?.automations ?? rulesRes.value ?? null);
      if (statsRes.status === "fulfilled") setLiveStats(statsRes.value ?? null);
    })
      .finally(() => setLoading(false));
  }, []);

  const handleRefresh = () => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); };

  const rules = liveRules ?? MOCK_RULES;
  const stats = liveStats ?? MOCK_STATS;

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
      <PageHeader
        title="Threat Intel Automation"
        description="Automated enrichment, IOC processing, and threat intelligence pipeline rules"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Rules"     value={stats.total_rules}    icon={ListChecks}    trend="flat" />
        <KpiCard title="Active Rules"    value={stats.active_rules}   icon={CheckCircle2}  trend="up"   className="border-violet-500/20" />
        <KpiCard title="Triggers Today"  value={stats.triggers_today} icon={Zap}           trend="up"   className="border-purple-500/20" />
        <KpiCard title="IOCs Enriched"   value={stats.iocs_enriched}  icon={Activity}      trend="up"   className="border-violet-500/20" />
      </div>

      {/* Rules Table */}
      <Card className="border-violet-500/20">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2 text-violet-400">
            <Zap className="h-4 w-4" />
            Automation Rules
          </CardTitle>
          <CardDescription className="text-xs">
            Active automation rules — trigger → action pipeline
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">ID</TableHead>
                  <TableHead className="text-[11px] h-8">Name</TableHead>
                  <TableHead className="text-[11px] h-8">Trigger</TableHead>
                  <TableHead className="text-[11px] h-8">Action</TableHead>
                  <TableHead className="text-[11px] h-8">Last Run</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {rules.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  rules.map((rule: any, i: number) => (
                  <TableRow key={rule.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-mono text-[10px] text-muted-foreground">{rule.id}</TableCell>
                    <TableCell className="py-2 text-xs font-medium">{rule.name}</TableCell>
                    <TableCell className="py-2"><TriggerBadge trigger={rule.trigger ?? rule.trigger_type ?? "unknown"} /></TableCell>
                    <TableCell className="py-2"><ActionBadge action={rule.action ?? rule.action_type ?? "unknown"} /></TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{rule.last_run ?? rule.last_triggered ?? "—"}</TableCell>
                    <TableCell className="py-2 text-right"><StatusBadge status={rule.status ?? "active"} /></TableCell>
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
