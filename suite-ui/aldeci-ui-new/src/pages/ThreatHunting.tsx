/**
 * Threat Hunting — Proactive hypothesis-driven threat detection
 *
 * Sections:
 *   1. KPI row — Active Hunts, Hypotheses Validated, IOCs Discovered, Avg Duration
 *   2. Active Hunts table — name, MITRE tactic, status, hunter, started, findings
 *   3. Hypothesis Builder — textarea, tactic dropdown, data source, Start Hunt
 *   4. IOC Feed — recent IOCs discovered from hunts
 *   5. MITRE Coverage — 10-tactic grid with covered/uncovered badges
 *
 * API: GET /api/v1/threat-hunting/hunts (mock fallback)
 * Route: /threat-hunting
 */

import { useState } from "react";
import { toast } from "sonner";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  Crosshair, Activity, CheckCircle2, Clock, Search, Play,
  AlertTriangle, Shield, Eye, Target, Zap, Network,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { cn } from "@/lib/utils";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";

// ── Types ──────────────────────────────────────────────────────

interface Hunt {
  hunt_name: string;
  mitre_tactic: string;
  status: "active" | "complete";
  hunter: string;
  started_date: string;
  findings_count: number;
}

interface IOCEntry {
  ioc_type: string;
  value: string;
  hunt_name: string;
  confidence: "high" | "medium" | "low";
}

// ── Mock data ──────────────────────────────────────────────────

const MOCK_HUNTS: Hunt[] = [
  { hunt_name: "Living off the Land PowerShell abuse", mitre_tactic: "Execution",           status: "active",   hunter: "j.smith",   started_date: "2026-04-14", findings_count: 0 },
  { hunt_name: "Lateral movement via WMI",             mitre_tactic: "Lateral Movement",    status: "complete", hunter: "a.patel",   started_date: "2026-04-10", findings_count: 3 },
  { hunt_name: "C2 beacon via DNS tunneling",          mitre_tactic: "C2",                  status: "active",   hunter: "m.chen",    started_date: "2026-04-13", findings_count: 0 },
  { hunt_name: "Data staging before exfil",            mitre_tactic: "Collection",          status: "active",   hunter: "j.smith",   started_date: "2026-04-15", findings_count: 1 },
  { hunt_name: "Credential dumping via LSASS",         mitre_tactic: "Credential Access",   status: "complete", hunter: "r.nguyen",  started_date: "2026-04-09", findings_count: 1 },
];

const MOCK_IOCS: IOCEntry[] = [
  { ioc_type: "Domain",    value: "update-srv.legitcdn.net",  hunt_name: "C2 beacon via DNS tunneling",      confidence: "high"   },
  { ioc_type: "Hash",      value: "a3f1...d9c2",              hunt_name: "Credential dumping via LSASS",     confidence: "high"   },
  { ioc_type: "IP",        value: "185.220.101.47",           hunt_name: "Lateral movement via WMI",         confidence: "medium" },
  { ioc_type: "File Path", value: "C:\\Temp\\stage_7z.exe",   hunt_name: "Data staging before exfil",        confidence: "medium" },
  { ioc_type: "Registry",  value: "HKCU\\...\\Run\\svchost2", hunt_name: "Living off the Land PowerShell abuse", confidence: "low" },
];

const MITRE_TACTICS = [
  { name: "Reconnaissance",      covered: false },
  { name: "Resource Development",covered: false },
  { name: "Initial Access",      covered: false },
  { name: "Execution",           covered: true  },
  { name: "Persistence",         covered: false },
  { name: "Privilege Escalation",covered: false },
  { name: "Defense Evasion",     covered: false },
  { name: "Credential Access",   covered: true  },
  { name: "Discovery",           covered: false },
  { name: "Lateral Movement",    covered: true  },
  { name: "Collection",          covered: true  },
  { name: "C2",                  covered: true  },
  { name: "Exfiltration",        covered: false },
  { name: "Impact",              covered: false },
];

const DATA_SOURCES = ["Windows Event Logs", "DNS Logs", "Network Flow", "EDR Telemetry", "Proxy Logs", "Authentication Logs"];
const TACTIC_OPTIONS = ["Reconnaissance", "Initial Access", "Execution", "Persistence", "Privilege Escalation",
  "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement", "Collection", "C2", "Exfiltration", "Impact"];

// ── Helpers ────────────────────────────────────────────────────

function statusBadge(status: Hunt["status"]) {
  return status === "active"
    ? <Badge className="bg-blue-500/20 text-blue-400 border-blue-500/30">Active</Badge>
    : <Badge className="bg-emerald-500/20 text-emerald-400 border-emerald-500/30">Complete</Badge>;
}

function confidenceBadge(c: IOCEntry["confidence"]) {
  const map = {
    high:   "bg-red-500/20 text-red-400 border-red-500/30",
    medium: "bg-amber-500/20 text-amber-400 border-amber-500/30",
    low:    "bg-slate-500/20 text-slate-400 border-slate-500/30",
  };
  return <Badge className={cn("capitalize", map[c])}>{c}</Badge>;
}

// ── Component ──────────────────────────────────────────────────

export default function ThreatHuntingPage() {
  const queryClient = useQueryClient();
  const [hypothesis, setHypothesis] = useState("");
  const [tactic, setTactic] = useState("");
  const [dataSource, setDataSource] = useState("");

  const startHuntMutation = useMutation({
    mutationFn: async (params: { name: string; tactic: string; dataSource: string }) => {
      const res = await fetch(`${API_BASE}/api/v1/hunting/sessions`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: `${params.tactic}: ${params.name}`,
          hunter_email: "analyst@aldeci.local",
        }),
      });
      if (!res.ok) throw new Error("Failed to start hunt session");
      return res.json();
    },
    onSuccess: (_data: unknown, vars: { name: string; tactic: string; dataSource: string }) => {
      toast.success("Hunt session started", {
        description: `${vars.tactic} via ${vars.dataSource}`,
      });
      queryClient.invalidateQueries({ queryKey: ["threat-hunting-hunts"] });
    },
    onError: () => {
      toast.error("Failed to start hunt", {
        description: "Could not reach the hunting API. Please try again.",
      });
    },
  });

  const { data: hunts = MOCK_HUNTS, isLoading } = useQuery<Hunt[]>({
    queryKey: ["threat-hunting-hunts"],
    queryFn: async () => {
      const res = await fetch(`${API_BASE}/api/v1/threat-hunting/hunts`);
      if (!res.ok) throw new Error("API unavailable");
      return res.json();
    },
    retry: false,
    staleTime: 30_000,
    // fallback to mock on error handled by initialData not available — error boundary catches,
    // defaulting to MOCK_HUNTS via initialData below
    initialData: MOCK_HUNTS,
  });

  if (isLoading) return <PageSkeleton />;

  const activeCount    = hunts.filter(h => h.status === "active").length;
  const totalFindings  = hunts.reduce((s, h) => s + h.findings_count, 0);

  return (
    <div className="flex flex-col gap-6 p-6 min-h-screen bg-background">
      <PageHeader
        title="Threat Hunting"
        description="Proactive hypothesis-driven threat detection"
        icon={<Crosshair className="h-6 w-6 text-primary" />}
      />

      {/* KPI Row */}
      <motion.div
        className="grid grid-cols-2 gap-4 md:grid-cols-4"
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ duration: 0.3 }}
      >
        <KpiCard title="Active Hunts"          value="5"      icon={<Activity className="h-4 w-4" />}    trend="neutral" />
        <KpiCard title="Hypotheses Validated"  value="23"     icon={<CheckCircle2 className="h-4 w-4" />} trend="up"     />
        <KpiCard title="IOCs Discovered"       value="47"     icon={<Search className="h-4 w-4" />}       trend="up"     />
        <KpiCard title="Avg Duration"          value="3.2d"   icon={<Clock className="h-4 w-4" />}        trend="neutral"/>
      </motion.div>

      {/* Active Hunts Table */}
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1, duration: 0.3 }}>
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Target className="h-4 w-4 text-primary" />
              Active Hunts
              <Badge className="ml-2 bg-blue-500/20 text-blue-400 border-blue-500/30">{activeCount} active</Badge>
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Hunt Name</TableHead>
                  <TableHead>MITRE Tactic</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead>Hunter</TableHead>
                  <TableHead>Started</TableHead>
                  <TableHead className="text-right">Findings</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {hunts.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  hunts.map((h) => (
                  <TableRow key={h.hunt_name} className="hover:bg-muted/30">
                    <TableCell className="font-medium max-w-[260px] truncate">{h.hunt_name}</TableCell>
                    <TableCell>
                      <Badge variant="outline" className="text-xs">{h.mitre_tactic}</Badge>
                    </TableCell>
                    <TableCell>{statusBadge(h.status)}</TableCell>
                    <TableCell className="text-muted-foreground">{h.hunter}</TableCell>
                    <TableCell className="text-muted-foreground">{h.started_date}</TableCell>
                    <TableCell className="text-right">
                      <span className={cn("font-semibold", h.findings_count > 0 ? "text-red-400" : "text-muted-foreground")}>
                        {h.findings_count}
                      </span>
                    </TableCell>
                  </TableRow>
                ))}
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </motion.div>

      {/* Bottom Grid: Hypothesis Builder + IOC Feed */}
      <motion.div
        className="grid grid-cols-1 gap-4 md:grid-cols-2"
        initial={{ opacity: 0, y: 10 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2, duration: 0.3 }}
      >
        {/* Hypothesis Builder */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Zap className="h-4 w-4 text-primary" />
              Hypothesis Builder
            </CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-3">
            <textarea
              className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm placeholder:text-muted-foreground focus:outline-none focus:ring-2 focus:ring-primary/50 resize-none"
              rows={4}
              placeholder="Describe your hunt hypothesis... e.g. 'Attackers may be using PowerShell to bypass AppLocker via encoded commands'"
              value={hypothesis}
              onChange={(e) => setHypothesis(e.target.value)}
            />
            <select
              className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-primary/50"
              value={tactic}
              onChange={(e) => setTactic(e.target.value)}
            >
              <option value="">Select MITRE Tactic...</option>
              {TACTIC_OPTIONS.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                  <p className="text-lg font-medium">No data available</p>
                  <p className="text-sm">Data will appear here once available</p>
                </div>
              ) : (
                TACTIC_OPTIONS.map(t => <option key={t} value={t}>{t}</option>)}
            </select>
            <select
              className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm text-foreground focus:outline-none focus:ring-2 focus:ring-primary/50"
              value={dataSource}
              onChange={(e) => setDataSource(e.target.value)}
              )}
            >
              <option value="">Select Data Source...</option>
              {DATA_SOURCES.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                  <p className="text-lg font-medium">No data available</p>
                  <p className="text-sm">Data will appear here once available</p>
                </div>
              ) : (
                DATA_SOURCES.map(s => <option key={s} value={s}>{s}</option>)}
            </select>
            <Button
              className="w-full gap-2"
              disabled={!hypothesis.trim() || !tactic || !dataSource || startHuntMutation.isPending}
              )}
              onClick={() => {
                startHuntMutation.mutate({ name: hypothesis, tactic, dataSource });
                setHypothesis(""); setTactic(""); setDataSource("");
              }}
            >
              <Play className="h-4 w-4" />
              Start Hunt
            </Button>
          </CardContent>
        </Card>

        {/* IOC Feed */}
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Eye className="h-4 w-4 text-primary" />
              Recent IOC Discoveries
              <Badge className="ml-auto bg-red-500/20 text-red-400 border-red-500/30">{MOCK_IOCS.length} new</Badge>
            </CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-2">
            {MOCK_IOCS.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                <p className="text-lg font-medium">No data available</p>
                <p className="text-sm">Data will appear here once available</p>
              </div>
            ) : (
              MOCK_IOCS.map((ioc, i) => (
              <div key={i} className="flex items-center gap-3 rounded-md border border-border p-2 text-sm">
                <Badge variant="outline" className="shrink-0 text-xs w-20 justify-center">{ioc.ioc_type}</Badge>
                <span className="font-mono text-xs text-foreground truncate flex-1">{ioc.value}</span>
                <span className="text-muted-foreground text-xs truncate max-w-[120px]">{ioc.hunt_name}</span>
                {confidenceBadge(ioc.confidence)}
              </div>
            ))}
            )}
          </CardContent>
        </Card>
      </motion.div>

      {/* MITRE Coverage Grid */}
      <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3, duration: 0.3 }}>
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-base">
              <Network className="h-4 w-4 text-primary" />
              MITRE ATT&CK Coverage
              <span className="ml-auto text-xs text-muted-foreground">
                {MITRE_TACTICS.filter(t => t.covered).length}/{MITRE_TACTICS.length} tactics covered
              </span>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 md:grid-cols-4 lg:grid-cols-7">
              {MITRE_TACTICS.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                  <p className="text-lg font-medium">No data available</p>
                  <p className="text-sm">Data will appear here once available</p>
                </div>
              ) : (
                MITRE_TACTICS.map((t) => (
                <div
                  key={t.name}
                  className={cn(
                    "rounded-md border p-2 text-center text-xs font-medium transition-colors",
                    t.covered
                      ? "border-emerald-500/40 bg-emerald-500/10 text-emerald-400"
                      : "border-border bg-muted/20 text-muted-foreground"
                  )}
                >
                  <div className="truncate mb-1">{t.name}</div>
                  {t.covered
                    ? <Badge className="text-[10px] px-1 py-0 bg-emerald-500/20 text-emerald-400 border-emerald-500/30">Covered</Badge>
                    : <Badge variant="outline" className="text-[10px] px-1 py-0 text-muted-foreground">Uncovered</Badge>
                  }
                </div>
              ))}
              )}
            </div>
          </CardContent>
        </Card>
      </motion.div>
    </div>
  );
}
