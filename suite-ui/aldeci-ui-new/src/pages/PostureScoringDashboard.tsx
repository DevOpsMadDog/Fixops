/**
 * Posture Scoring Dashboard
 *
 * Security posture scoring with control implementation tracking.
 *   1. KPIs: Overall Score, Implemented Controls, Gap Controls, Score Level
 *   2. Controls table (name, domain, weight, control_status, last_assessed)
 *
 * Route: /posture-scoring
 * API: GET /api/v1/posture-scoring
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { ShieldCheck, RefreshCw, CheckCircle, XCircle, BarChart2 } from "lucide-react";

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

const MOCK_CONTROLS = [
  { id: "ctrl-001", name: "MFA Enforcement",          domain: "Identity",    weight: 10, control_status: "implemented",     last_assessed: "2026-04-15" },
  { id: "ctrl-002", name: "Data Encryption at Rest",  domain: "Data",        weight: 9,  control_status: "implemented",     last_assessed: "2026-04-14" },
  { id: "ctrl-003", name: "Patch Management",         domain: "Endpoint",    weight: 8,  control_status: "partial",         last_assessed: "2026-04-13" },
  { id: "ctrl-004", name: "Network Segmentation",     domain: "Network",     weight: 8,  control_status: "implemented",     last_assessed: "2026-04-12" },
  { id: "ctrl-005", name: "SIEM Deployment",          domain: "Detection",   weight: 7,  control_status: "implemented",     last_assessed: "2026-04-10" },
  { id: "ctrl-006", name: "Privileged Access Mgmt",   domain: "Identity",    weight: 9,  control_status: "partial",         last_assessed: "2026-04-09" },
  { id: "ctrl-007", name: "Incident Response Plan",   domain: "Response",    weight: 7,  control_status: "implemented",     last_assessed: "2026-04-08" },
  { id: "ctrl-008", name: "Vendor Risk Assessment",   domain: "Supply Chain",weight: 6,  control_status: "not_implemented", last_assessed: "2026-03-30" },
  { id: "ctrl-009", name: "Secure SDLC",              domain: "AppSec",      weight: 8,  control_status: "compensating",    last_assessed: "2026-04-05" },
  { id: "ctrl-010", name: "Zero Trust Architecture",  domain: "Network",     weight: 9,  control_status: "not_implemented", last_assessed: "2026-03-20" },
];

const MOCK_STATS = { overall_score: 74, implemented_controls: 5, gap_controls: 2, score_level: "Good" };

// ── Badge helpers ──────────────────────────────────────────────

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    implemented:     "border-green-500/30 text-green-400 bg-green-500/10",
    partial:         "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    not_implemented: "border-red-500/30 text-red-400 bg-red-500/10",
    compensating:    "border-blue-500/30 text-blue-400 bg-blue-500/10",
  };
  const label: Record<string, string> = {
    implemented:     "Implemented",
    partial:         "Partial",
    not_implemented: "Not Implemented",
    compensating:    "Compensating",
  };
  return (
    <Badge className={cn("text-[10px] border", map[status] ?? "border-border")}>
      {label[status] ?? status}
    </Badge>
  );
}

// ── Component ──────────────────────────────────────────────────

export default function PostureScoringDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveControls, setLiveControls] = useState<any[] | null>(null);
  const [liveStats, setLiveStats] = useState<any | null>(null);

  useEffect(() => {
    Promise.allSettled([
      apiFetch(`/api/v1/posture-scoring/controls?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/posture-scoring/stats?org_id=${ORG_ID}`),
    ]).then(([controlsRes, statsRes]) => {
      if (controlsRes.status === "fulfilled") setLiveControls(controlsRes.value?.controls ?? controlsRes.value ?? null);
      if (statsRes.status === "fulfilled") setLiveStats(statsRes.value ?? null);
    });
  }, []);

  const handleRefresh = () => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); };

  const controls = liveControls ?? MOCK_CONTROLS;
  const stats    = liveStats    ?? MOCK_STATS;

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      <PageHeader
        title="Posture Scoring"
        description="Security posture score tracking, control implementation status, and gap analysis across all domains"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Overall Score"        value={`${stats.overall_score}%`}      icon={BarChart2}   trend="up"   className="border-green-500/20" />
        <KpiCard title="Implemented Controls" value={stats.implemented_controls}     icon={CheckCircle} trend="up"   className="border-teal-500/20" />
        <KpiCard title="Gap Controls"         value={stats.gap_controls}             icon={XCircle}     trend="down" className="border-red-500/20" />
        <KpiCard title="Score Level"          value={stats.score_level}             icon={ShieldCheck}  trend="flat" className="border-emerald-500/20" />
      </div>

      {/* Controls Table */}
      <Card className="border-green-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-green-400">
              <ShieldCheck className="h-4 w-4" />
              Security Controls
            </CardTitle>
            <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">
              {controls.filter((c: any) => c.control_status === "implemented").length} implemented
            </Badge>
          </div>
          <CardDescription className="text-xs">
            Control implementation status, domain coverage, and last assessment dates
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Control Name</TableHead>
                  <TableHead className="text-[11px] h-8">Domain</TableHead>
                  <TableHead className="text-[11px] h-8">Weight</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Last Assessed</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {controls.map((ctrl: any, i: number) => (
                  <TableRow key={ctrl.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-semibold text-[11px] text-green-300">
                      {ctrl.name ?? "—"}
                    </TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">
                      {ctrl.domain ?? "—"}
                    </TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-teal-300">
                      {ctrl.weight ?? "—"}
                    </TableCell>
                    <TableCell className="py-2">
                      <StatusBadge status={ctrl.control_status ?? "not_implemented"} />
                    </TableCell>
                    <TableCell className="py-2 text-right text-[11px] text-muted-foreground">
                      {ctrl.last_assessed ?? "—"}
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
