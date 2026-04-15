/**
 * Risk Quantification
 *
 * Financial impact modeling and Monte Carlo simulation.
 *   1. KPIs: Total Scenarios, Total ALE, Highest Risk Scenario, Avg ROI of Controls
 *   2. Risk scenarios table with Monte Carlo button
 *   3. Monte Carlo result panel (p50/p95/p99)
 *   4. Treatment analysis table
 *   5. Financial impact history
 *
 * API stubs: GET /api/v1/risk-quantification/scenarios, /api/v1/risk-quantification/treatments
 */

import { useState } from "react";
import { motion } from "framer-motion";
import { DollarSign, BarChart3, TrendingUp, AlertTriangle, RefreshCw, Dice5 } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── Mock data ──────────────────────────────────────────────────

const SCENARIOS = [
  { name: "Ransomware Attack",         actor: "cybercriminal", likelihood: 68, min: 420000,  max: 1800000, expected: 847000,  ale: 575960,  treatment: "mitigate" },
  { name: "Supply Chain Compromise",   actor: "nation_state",  likelihood: 32, min: 800000,  max: 4200000, expected: 1950000, ale: 624000,  treatment: "mitigate" },
  { name: "Insider Data Theft",        actor: "insider",       likelihood: 24, min: 150000,  max: 650000,  expected: 310000,  ale: 74400,   treatment: "accept" },
  { name: "Cloud Misconfiguration",    actor: "cybercriminal", likelihood: 71, min: 80000,   max: 420000,  expected: 195000,  ale: 138450,  treatment: "mitigate" },
  { name: "Phishing + BEC",            actor: "cybercriminal", likelihood: 82, min: 60000,   max: 280000,  expected: 142000,  ale: 116440,  treatment: "mitigate" },
  { name: "Zero-Day Exploitation",     actor: "nation_state",  likelihood: 14, min: 500000,  max: 3500000, expected: 1400000, ale: 196000,  treatment: "transfer" },
  { name: "DDoS Campaign",             actor: "cybercriminal", likelihood: 55, min: 25000,   max: 180000,  expected: 78000,   ale: 42900,   treatment: "transfer" },
  { name: "Credential Stuffing",       actor: "cybercriminal", likelihood: 74, min: 20000,   max: 95000,   expected: 44000,   ale: 32560,   treatment: "mitigate" },
  { name: "Physical Breach",           actor: "insider",       likelihood: 8,  min: 120000,  max: 480000,  expected: 230000,  ale: 18400,   treatment: "accept" },
  { name: "Third-Party API Abuse",     actor: "cybercriminal", likelihood: 47, min: 15000,   max: 120000,  expected: 52000,   ale: 24440,   treatment: "mitigate" },
];

const MONTE_CARLO = { p50: 612000, p95: 1240000, p99: 2180000 };

const TREATMENTS = [
  { name: "EDR + MDR Service",          type: "mitigate",  cost: 84000,  reduction: 62, roi: 380 },
  { name: "Cyber Insurance Policy",     type: "transfer",  cost: 42000,  reduction: 45, roi: 290 },
  { name: "MFA Enforcement",            type: "mitigate",  cost: 12000,  reduction: 38, roi: 520 },
  { name: "SOC 24/7 Monitoring",        type: "mitigate",  cost: 156000, reduction: 71, roi: 310 },
  { name: "Backup + DR Program",        type: "mitigate",  cost: 38000,  reduction: 55, roi: 410 },
  { name: "Security Awareness Training",type: "mitigate",  cost: 22000,  reduction: 29, roi: 240 },
  { name: "Accept Insider Risk",        type: "accept",    cost: 0,      reduction: 0,  roi: 0   },
  { name: "DDoS Mitigation SaaS",       type: "transfer",  cost: 18000,  reduction: 82, roi: 185 },
];

const FINANCIAL_HISTORY = [
  { type: "Ransomware",         direct: 320000, fines: 0,      remediation: 145000, total: 465000, fy: "FY2021" },
  { type: "Phishing/BEC",       direct: 88000,  fines: 0,      remediation: 32000,  total: 120000, fy: "FY2021" },
  { type: "Data Breach (GDPR)", direct: 410000, fines: 180000, remediation: 290000, total: 880000, fy: "FY2022" },
  { type: "Cloud Exposure",     direct: 54000,  fines: 45000,  remediation: 68000,  total: 167000, fy: "FY2023" },
  { type: "Insider Theft",      direct: 215000, fines: 0,      remediation: 48000,  total: 263000, fy: "FY2024" },
  { type: "Supply Chain",       direct: 730000, fines: 125000, remediation: 380000, total: 1235000, fy: "FY2025" },
];

// ── Helpers ────────────────────────────────────────────────────

function ActorBadge({ actor }: { actor: string }) {
  const map: Record<string, string> = {
    nation_state:  "border-purple-500/30 text-purple-400 bg-purple-500/10",
    cybercriminal: "border-red-500/30 text-red-400 bg-red-500/10",
    insider:       "border-amber-500/30 text-amber-400 bg-amber-500/10",
  };
  return <Badge className={cn("text-[10px] border", map[actor] ?? "border-border text-muted-foreground")}>{actor.replace("_", " ")}</Badge>;
}

function TreatmentBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    mitigate: "border-blue-500/30 text-blue-400 bg-blue-500/10",
    transfer:  "border-green-500/30 text-green-400 bg-green-500/10",
    accept:    "border-amber-500/30 text-amber-400 bg-amber-500/10",
  };
  return <Badge className={cn("text-[10px] border", map[type] ?? "border-border text-muted-foreground")}>{type}</Badge>;
}

function fmt(n: number) {
  if (n >= 1000000) return `$${(n / 1000000).toFixed(1)}M`;
  if (n >= 1000) return `$${(n / 1000).toFixed(0)}K`;
  return `$${n}`;
}

// ── Component ──────────────────────────────────────────────────

export default function RiskQuantification() {
  const [refreshing, setRefreshing] = useState(false);
  const [runningMC, setRunningMC] = useState<string | null>(null);

  const handleRefresh = () => {
    setRefreshing(true);
    setTimeout(() => setRefreshing(false), 800);
  };

  const handleMonteCarlo = (name: string) => {
    setRunningMC(name);
    setTimeout(() => setRunningMC(null), 1200);
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      {/* Header */}
      <PageHeader
        title="Risk Quantification"
        description="Financial impact modeling and Monte Carlo simulation"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Scenarios"        value={18}          icon={BarChart3}    />
        <KpiCard title="Total ALE"              value="$2.4M/yr"    icon={DollarSign}   trend="up" className="border-red-500/20" />
        <KpiCard title="Highest Risk Scenario"  value="$847K"       icon={AlertTriangle} trend="up" className="border-amber-500/20" />
        <KpiCard title="Avg ROI of Controls"    value="340%"        icon={TrendingUp}   trend="up" className="border-green-500/20" />
      </div>

      {/* Risk Scenarios Table */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <AlertTriangle className="h-4 w-4 text-amber-400" />
            Risk Scenarios
          </CardTitle>
          <CardDescription className="text-xs">10 scenarios — ALE = likelihood × expected loss</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Scenario</TableHead>
                  <TableHead className="text-[11px] h-8">Threat Actor</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Likelihood</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Min Loss</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Max Loss</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Expected</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">ALE</TableHead>
                  <TableHead className="text-[11px] h-8">Treatment</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Simulate</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {SCENARIOS.map((row) => (
                  <TableRow key={row.name} className="hover:bg-muted/30">
                    <TableCell className="text-xs font-medium py-2.5 max-w-[160px] truncate">{row.name}</TableCell>
                    <TableCell className="py-2.5"><ActorBadge actor={row.actor} /></TableCell>
                    <TableCell className="text-xs tabular-nums py-2.5 text-right">
                      <span className={row.likelihood >= 60 ? "text-red-400 font-bold" : row.likelihood >= 40 ? "text-amber-400" : "text-muted-foreground"}>
                        {row.likelihood}%
                      </span>
                    </TableCell>
                    <TableCell className="text-xs tabular-nums py-2.5 text-right text-muted-foreground">{fmt(row.min)}</TableCell>
                    <TableCell className="text-xs tabular-nums py-2.5 text-right text-muted-foreground">{fmt(row.max)}</TableCell>
                    <TableCell className="text-xs tabular-nums py-2.5 text-right font-medium">{fmt(row.expected)}</TableCell>
                    <TableCell className="text-xs tabular-nums py-2.5 text-right font-bold text-red-400">{fmt(row.ale)}</TableCell>
                    <TableCell className="py-2.5"><TreatmentBadge type={row.treatment} /></TableCell>
                    <TableCell className="py-2.5 text-right">
                      <Button
                        variant="outline"
                        size="sm"
                        className="h-6 px-2 text-[10px]"
                        onClick={() => handleMonteCarlo(row.name)}
                        disabled={runningMC === row.name}
                      >
                        <Dice5 className="h-3 w-3 mr-1" />
                        {runningMC === row.name ? "Running…" : "MC"}
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Monte Carlo Result Panel + Treatment Analysis */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Monte Carlo results */}
        <Card className="border-purple-500/20">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Dice5 className="h-4 w-4 text-purple-400" />
              Monte Carlo Result — Ransomware Attack
            </CardTitle>
            <CardDescription className="text-xs">10,000-iteration simulation — financial loss distribution</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="grid grid-cols-3 gap-3">
              <div className="rounded-lg border border-green-500/30 bg-green-500/10 p-3 text-center">
                <div className="text-[10px] text-muted-foreground mb-1">p50 Median</div>
                <div className="text-lg font-bold text-green-400">{fmt(MONTE_CARLO.p50)}</div>
                <div className="text-[10px] text-muted-foreground mt-1">50% of outcomes below</div>
              </div>
              <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-center">
                <div className="text-[10px] text-muted-foreground mb-1">p95 Tail</div>
                <div className="text-lg font-bold text-amber-400">{fmt(MONTE_CARLO.p95)}</div>
                <div className="text-[10px] text-muted-foreground mt-1">95% of outcomes below</div>
              </div>
              <div className="rounded-lg border border-red-500/30 bg-red-500/10 p-3 text-center">
                <div className="text-[10px] text-muted-foreground mb-1">p99 Worst-Case</div>
                <div className="text-lg font-bold text-red-400">{fmt(MONTE_CARLO.p99)}</div>
                <div className="text-[10px] text-muted-foreground mt-1">99% of outcomes below</div>
              </div>
            </div>
            <div className="text-[11px] text-muted-foreground pt-1 border-t border-border">
              Simulation parameters: PERT distribution, 10K iterations, 95% CI. Click "MC" on any scenario row to re-simulate.
            </div>
          </CardContent>
        </Card>

        {/* Treatment Analysis */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <TrendingUp className="h-4 w-4 text-blue-400" />
              Treatment Analysis
            </CardTitle>
            <CardDescription className="text-xs">Cost vs. risk reduction and ROI for top controls</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Treatment</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Cost/yr</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Risk ↓</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">ROI</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {TREATMENTS.map((t) => (
                  <TableRow key={t.name} className="hover:bg-muted/30">
                    <TableCell className="text-xs py-2.5 max-w-[140px] truncate">{t.name}</TableCell>
                    <TableCell className="py-2.5"><TreatmentBadge type={t.type} /></TableCell>
                    <TableCell className="text-xs tabular-nums py-2.5 text-right text-muted-foreground">{t.cost ? fmt(t.cost) : "—"}</TableCell>
                    <TableCell className="text-xs tabular-nums py-2.5 text-right">{t.reduction ? `${t.reduction}%` : "—"}</TableCell>
                    <TableCell className="py-2.5 text-right">
                      {t.roi > 0 ? (
                        <Badge className={cn("text-[10px] border", t.roi >= 200 ? "border-green-500/30 text-green-400 bg-green-500/10" : "border-border text-muted-foreground")}>
                          {t.roi}%
                        </Badge>
                      ) : <span className="text-[11px] text-muted-foreground">—</span>}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </div>

      {/* Financial Impact History */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <DollarSign className="h-4 w-4 text-green-400" />
            Financial Impact History
          </CardTitle>
          <CardDescription className="text-xs">Realized losses by incident — direct costs, fines, and remediation</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Incident Type</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Direct Costs</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Fines/Penalties</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Remediation</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Total Loss</TableHead>
                  <TableHead className="text-[11px] h-8">Fiscal Year</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {FINANCIAL_HISTORY.map((row) => (
                  <TableRow key={`${row.type}-${row.fy}`} className="hover:bg-muted/30">
                    <TableCell className="text-xs font-medium py-2.5">{row.type}</TableCell>
                    <TableCell className="text-xs tabular-nums py-2.5 text-right text-muted-foreground">{fmt(row.direct)}</TableCell>
                    <TableCell className="text-xs tabular-nums py-2.5 text-right">
                      {row.fines ? <span className="text-red-400 font-medium">{fmt(row.fines)}</span> : <span className="text-muted-foreground">—</span>}
                    </TableCell>
                    <TableCell className="text-xs tabular-nums py-2.5 text-right text-muted-foreground">{fmt(row.remediation)}</TableCell>
                    <TableCell className="text-xs tabular-nums py-2.5 text-right font-bold">{fmt(row.total)}</TableCell>
                    <TableCell className="py-2.5">
                      <Badge className="text-[10px] border border-border text-muted-foreground">{row.fy}</Badge>
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
