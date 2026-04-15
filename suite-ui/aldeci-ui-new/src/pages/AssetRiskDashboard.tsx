/**
 * Asset Risk Dashboard
 *
 * Asset risk scoring, factor analysis, and prioritization.
 *   1. KPIs: Total Assets, Critical Risk, High Risk, Avg Score
 *   2. Risk heatmap: 5×4 grid (asset_type × criticality)
 *   3. Top 15 highest-risk assets table
 *   4. Risk factor breakdown (5 bars)
 *   5. 8 recently added assets
 *
 * API stubs: GET /api/v1/asset-risk/scores, /api/v1/asset-risk/heatmap
 */

import { useState } from "react";
import { motion } from "framer-motion";
import { HardDrive, AlertTriangle, RefreshCw, BarChart3, Globe, Shield } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── Mock data ──────────────────────────────────────────────────

// Heatmap: rows = criticality, cols = asset_type
// Values = composite risk score (0-100)
const ASSET_TYPES = ["Server", "Workstation", "Network", "Cloud", "Database"];
const CRITICALITY_LEVELS = ["Critical", "High", "Medium", "Low"];

const HEATMAP: Record<string, Record<string, number>> = {
  Critical:    { Server: 88, Workstation: 72, Network: 91, Cloud: 85, Database: 94 },
  High:        { Server: 67, Workstation: 55, Network: 71, Cloud: 63, Database: 76 },
  Medium:      { Server: 44, Workstation: 38, Network: 49, Cloud: 41, Database: 52 },
  Low:         { Server: 21, Workstation: 18, Network: 24, Cloud: 19, Database: 28 },
};

function heatColor(score: number): string {
  if (score >= 80) return "bg-red-500/80 text-white";
  if (score >= 65) return "bg-orange-500/70 text-white";
  if (score >= 45) return "bg-yellow-500/60 text-white";
  if (score >= 25) return "bg-amber-400/40 text-foreground";
  return "bg-green-500/30 text-foreground";
}

const TOP_ASSETS = [
  { id: "AST-001", name: "prod-db-primary",    type: "Database",    criticality: "Critical", exposure: "internal",      score: 94, top_factor: "Unpatched CVEs" },
  { id: "AST-002", name: "core-network-fw",    type: "Network",     criticality: "Critical", exposure: "internet_facing", score: 91, top_factor: "Exposure" },
  { id: "AST-003", name: "auth-server-01",     type: "Server",      criticality: "Critical", exposure: "internet_facing", score: 88, top_factor: "Weak credentials" },
  { id: "AST-004", name: "prod-db-replica",    type: "Database",    criticality: "High",     exposure: "internal",      score: 84, top_factor: "Missing encryption" },
  { id: "AST-005", name: "cloud-vpc-gateway",  type: "Cloud",       criticality: "Critical", exposure: "internet_facing", score: 85, top_factor: "Misconfiguration" },
  { id: "AST-006", name: "api-gateway-prod",   type: "Server",      criticality: "Critical", exposure: "internet_facing", score: 82, top_factor: "Threat intel hits" },
  { id: "AST-007", name: "finance-db-01",      type: "Database",    criticality: "High",     exposure: "internal",      score: 79, top_factor: "Compliance gap" },
  { id: "AST-008", name: "corp-vpn-endpoint",  type: "Network",     criticality: "High",     exposure: "internet_facing", score: 76, top_factor: "Outdated firmware" },
  { id: "AST-009", name: "dev-build-server",   type: "Server",      criticality: "High",     exposure: "internal",      score: 71, top_factor: "Supply chain risk" },
  { id: "AST-010", name: "s3-customer-data",   type: "Cloud",       criticality: "Critical", exposure: "internet_facing", score: 85, top_factor: "Public ACL" },
  { id: "AST-011", name: "hr-workstation-12",  type: "Workstation", criticality: "High",     exposure: "internal",      score: 67, top_factor: "Unpatched OS" },
  { id: "AST-012", name: "network-switch-dc1", type: "Network",     criticality: "High",     exposure: "internal",      score: 63, top_factor: "Default creds" },
  { id: "AST-013", name: "backup-server-01",   type: "Server",      criticality: "Medium",   exposure: "internal",      score: 58, top_factor: "No encryption" },
  { id: "AST-014", name: "analytics-cluster",  type: "Cloud",       criticality: "Medium",   exposure: "internal",      score: 54, top_factor: "Overprivileged IAM" },
  { id: "AST-015", name: "print-server-01",    type: "Server",      criticality: "Low",      exposure: "internal",      score: 38, top_factor: "EOL software" },
];

const RISK_FACTORS = [
  { label: "Vulnerability",     pct: 35, color: "bg-red-500" },
  { label: "Threat Intel",      pct: 25, color: "bg-amber-500" },
  { label: "Exposure",          pct: 20, color: "bg-orange-500" },
  { label: "Compliance",        pct: 15, color: "bg-yellow-500" },
  { label: "Misconfiguration",  pct: 5,  color: "bg-blue-500" },
];

const RECENT_ASSETS = [
  { name: "ecs-task-prod-12",    type: "Cloud",       score: 61, added: "2h ago" },
  { name: "dev-laptop-jpark",    type: "Workstation", score: 29, added: "4h ago" },
  { name: "mongo-analytics-01",  type: "Database",    score: 74, added: "6h ago" },
  { name: "vpn-concentrator-02", type: "Network",     score: 55, added: "8h ago" },
  { name: "k8s-node-worker-07",  type: "Server",      score: 48, added: "12h ago" },
  { name: "rds-reporting-db",    type: "Database",    score: 67, added: "1d ago" },
  { name: "azure-func-webhook",  type: "Cloud",       score: 42, added: "1d ago" },
  { name: "sec-scanner-host",    type: "Server",      score: 33, added: "2d ago" },
];

// ── Helpers ────────────────────────────────────────────────────

function TypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    Server:      "border-blue-500/30 text-blue-400 bg-blue-500/10",
    Workstation: "border-purple-500/30 text-purple-400 bg-purple-500/10",
    Network:     "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
    Cloud:       "border-sky-500/30 text-sky-400 bg-sky-500/10",
    Database:    "border-indigo-500/30 text-indigo-400 bg-indigo-500/10",
  };
  return <Badge className={cn("text-[10px] border", map[type] ?? "border-border text-muted-foreground")}>{type}</Badge>;
}

function CriticalityBadge({ c }: { c: string }) {
  const cls =
    c === "Critical" ? "border-red-500/30 text-red-400 bg-red-500/10" :
    c === "High"     ? "border-amber-500/30 text-amber-400 bg-amber-500/10" :
    c === "Medium"   ? "border-yellow-500/30 text-yellow-400 bg-yellow-500/10" :
                       "border-border text-muted-foreground";
  return <Badge className={cn("text-[10px] border", cls)}>{c}</Badge>;
}

function ExposureBadge({ exp }: { exp: string }) {
  if (exp === "internet_facing") {
    return <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10 flex items-center gap-1"><Globe className="h-2.5 w-2.5" />Internet</Badge>;
  }
  return <Badge className="text-[10px] border border-border text-muted-foreground">Internal</Badge>;
}

function ScoreBar({ score }: { score: number }) {
  const color =
    score >= 80 ? "bg-red-500" :
    score >= 60 ? "bg-orange-500" :
    score >= 40 ? "bg-yellow-500" : "bg-green-500";
  const textColor =
    score >= 80 ? "text-red-400" :
    score >= 60 ? "text-orange-400" :
    score >= 40 ? "text-yellow-400" : "text-green-400";
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 rounded-full bg-muted/40 overflow-hidden">
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${score}%` }}
          transition={{ duration: 0.6, ease: "easeOut" }}
          className={cn("h-full rounded-full", color)}
        />
      </div>
      <span className={cn("text-xs font-bold tabular-nums w-6 text-right", textColor)}>{score}</span>
    </div>
  );
}

function ScoreIndicator({ score }: { score: number }) {
  const cls =
    score >= 80 ? "bg-red-500" :
    score >= 60 ? "bg-orange-500" :
    score >= 40 ? "bg-yellow-500" : "bg-green-500";
  return (
    <div className="flex items-center gap-2">
      <span className={cn("inline-block w-2 h-2 rounded-full shrink-0", cls)} />
      <span className="text-xs font-bold tabular-nums">{score}</span>
    </div>
  );
}

// ── Component ──────────────────────────────────────────────────

export default function AssetRiskDashboard() {
  const [refreshing, setRefreshing] = useState(false);

  const handleRefresh = () => {
    setRefreshing(true);
    setTimeout(() => setRefreshing(false), 800);
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
        title="Asset Risk"
        description="Asset risk scoring, factor analysis, and prioritization"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Assets"   value={342}    icon={HardDrive}     className="border-blue-500/20" />
        <KpiCard title="Critical Risk"  value={18}     icon={AlertTriangle} trend="up"   className="border-red-500/20" />
        <KpiCard title="High Risk"      value={47}     icon={Shield}        trend="up"   className="border-amber-500/20" />
        <KpiCard title="Avg Score"      value="44.2"   icon={BarChart3}     trend="up" />
      </div>

      {/* Heatmap + Risk Factors */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        {/* Risk Heatmap */}
        <Card className="lg:col-span-2">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <BarChart3 className="h-4 w-4 text-red-400" />
              Risk Heatmap
            </CardTitle>
            <CardDescription className="text-xs">Composite risk score by asset type × criticality — darker = higher risk</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <table className="w-full text-xs border-collapse">
                <thead>
                  <tr>
                    <th className="text-left text-muted-foreground font-normal pb-2 w-24" />
                    {ASSET_TYPES.map((t) => (
                      <th key={t} className="text-center text-muted-foreground font-medium pb-2 px-1">{t}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {CRITICALITY_LEVELS.map((crit) => (
                    <tr key={crit}>
                      <td className="text-muted-foreground font-medium py-1 pr-2 text-right text-xs">{crit}</td>
                      {ASSET_TYPES.map((type) => {
                        const score = HEATMAP[crit][type];
                        return (
                          <td key={type} className="py-1 px-1">
                            <div className={cn("rounded-lg flex items-center justify-center h-10 font-bold tabular-nums", heatColor(score))}>
                              {score}
                            </div>
                          </td>
                        );
                      })}
                    </tr>
                  ))}
                </tbody>
              </table>
              <div className="flex items-center gap-3 mt-3 text-[10px] text-muted-foreground">
                <span className="flex items-center gap-1"><span className="w-3 h-3 rounded bg-green-500/30 inline-block" />Low (&lt;25)</span>
                <span className="flex items-center gap-1"><span className="w-3 h-3 rounded bg-yellow-500/60 inline-block" />Medium (25–44)</span>
                <span className="flex items-center gap-1"><span className="w-3 h-3 rounded bg-orange-500/70 inline-block" />High (45–79)</span>
                <span className="flex items-center gap-1"><span className="w-3 h-3 rounded bg-red-500/80 inline-block" />Critical (80+)</span>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Risk Factor Breakdown + Recently Added */}
        <div className="flex flex-col gap-4">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <Shield className="h-4 w-4 text-purple-400" />
                Risk Factor Breakdown
              </CardTitle>
              <CardDescription className="text-xs">Score contribution by factor type</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              {RISK_FACTORS.map((f) => (
                <div key={f.label} className="space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-muted-foreground">{f.label}</span>
                    <span className="font-bold tabular-nums">{f.pct}%</span>
                  </div>
                  <div className="relative h-1.5 rounded-full bg-muted/30 overflow-hidden">
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${f.pct}%` }}
                      transition={{ duration: 0.7, ease: "easeOut" }}
                      className={cn("h-full rounded-full", f.color)}
                    />
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <HardDrive className="h-4 w-4 text-cyan-400" />
                Recently Added
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              {RECENT_ASSETS.map((a) => (
                <div key={a.name} className="flex items-center gap-2">
                  <ScoreIndicator score={a.score} />
                  <div className="flex-1 min-w-0">
                    <span className="text-xs font-mono truncate block">{a.name}</span>
                  </div>
                  <TypeBadge type={a.type} />
                  <span className="text-[10px] text-muted-foreground shrink-0">{a.added}</span>
                </div>
              ))}
            </CardContent>
          </Card>
        </div>
      </div>

      {/* Top 15 Highest-Risk Assets */}
      <Card className="border-red-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
              <AlertTriangle className="h-4 w-4" />
              Top 15 Highest-Risk Assets
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">sorted by score</Badge>
          </div>
          <CardDescription className="text-xs">Assets requiring immediate risk reduction attention</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Asset Name</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Criticality</TableHead>
                  <TableHead className="text-[11px] h-8">Exposure</TableHead>
                  <TableHead className="text-[11px] h-8">Risk Score</TableHead>
                  <TableHead className="text-[11px] h-8">Top Risk Factor</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {TOP_ASSETS.map((row) => (
                  <TableRow key={row.id} className="hover:bg-muted/30">
                    <TableCell className="text-xs font-mono py-2.5">{row.name}</TableCell>
                    <TableCell className="py-2.5"><TypeBadge type={row.type} /></TableCell>
                    <TableCell className="py-2.5"><CriticalityBadge c={row.criticality} /></TableCell>
                    <TableCell className="py-2.5"><ExposureBadge exp={row.exposure} /></TableCell>
                    <TableCell className="py-2.5 w-32"><ScoreBar score={row.score} /></TableCell>
                    <TableCell className="text-xs py-2.5 text-muted-foreground">{row.top_factor}</TableCell>
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
