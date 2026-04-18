/**
 * MITRE ATT&CK Dashboard
 *
 * Coverage heatmap, gap analysis, and detection stats across 14 MITRE tactics.
 *
 * Data sources:
 *   GET /api/v1/mitre-attack/coverage?org_id=default
 *   GET /api/v1/mitre-attack/gaps?org_id=default
 *   GET /api/v1/mitre-attack/stats?org_id=default
 *
 * Route: /mitre-attack
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Shield,
  Target,
  AlertTriangle,
  CheckCircle2,
  RefreshCw,
} from "lucide-react";
import {
  Card,
  CardContent,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── API helpers ──────────────────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const apiKey =
  (typeof window !== "undefined" && localStorage.getItem("aldeci_api_key")) ||
  import.meta.env.VITE_API_KEY ||
  "dev-key";

const apiFetch = (path: string) =>
  fetch(`${API_BASE}/api/v1${path}`, {
    headers: { "X-API-Key": apiKey },
  }).then((r) => {
    if (!r.ok) throw new Error(`API error: ${r.status}`);
    return r.json();
  });

// ── Types ────────────────────────────────────────────────────────────────────
interface Tactic {
  tactic_id: string;
  tactic_name: string;
  technique_count: number;
  detected_count: number;
  coverage_pct: number;
}

interface CoverageData {
  coverage_pct: number;
  total_techniques: number;
  detected_techniques: number;
  tactics: Tactic[];
}

interface Gap {
  tactic_id: string;
  technique_id: string;
  technique_name: string;
  severity: string;
  recommendation: string;
}

interface GapsData {
  gaps: Gap[];
}

interface StatsData {
  total_mappings: number;
  tactics_covered: number;
  techniques_covered: number;
}

// ── Mock data ────────────────────────────────────────────────────────────────
const MOCK_COVERAGE: CoverageData = {
  coverage_pct: 42,
  total_techniques: 185,
  detected_techniques: 78,
  tactics: [
    { tactic_id: "TA0001", tactic_name: "Initial Access",       technique_count: 12, detected_count: 5,  coverage_pct: 42 },
    { tactic_id: "TA0002", tactic_name: "Execution",            technique_count: 14, detected_count: 8,  coverage_pct: 57 },
    { tactic_id: "TA0003", tactic_name: "Persistence",          technique_count: 20, detected_count: 6,  coverage_pct: 30 },
    { tactic_id: "TA0004", tactic_name: "Privilege Escalation", technique_count: 14, detected_count: 7,  coverage_pct: 50 },
    { tactic_id: "TA0005", tactic_name: "Defense Evasion",      technique_count: 42, detected_count: 10, coverage_pct: 24 },
    { tactic_id: "TA0006", tactic_name: "Credential Access",    technique_count: 17, detected_count: 12, coverage_pct: 71 },
    { tactic_id: "TA0007", tactic_name: "Discovery",            technique_count: 31, detected_count: 6,  coverage_pct: 19 },
    { tactic_id: "TA0008", tactic_name: "Lateral Movement",     technique_count: 9,  detected_count: 5,  coverage_pct: 56 },
    { tactic_id: "TA0009", tactic_name: "Collection",           technique_count: 17, detected_count: 4,  coverage_pct: 24 },
    { tactic_id: "TA0010", tactic_name: "Exfiltration",         technique_count: 9,  detected_count: 7,  coverage_pct: 78 },
    { tactic_id: "TA0011", tactic_name: "Command and Control",  technique_count: 16, detected_count: 5,  coverage_pct: 31 },
    { tactic_id: "TA0040", tactic_name: "Impact",               technique_count: 13, detected_count: 2,  coverage_pct: 15 },
    { tactic_id: "TA0042", tactic_name: "Resource Development", technique_count: 8,  detected_count: 1,  coverage_pct: 13 },
    { tactic_id: "TA0043", tactic_name: "Reconnaissance",       technique_count: 10, detected_count: 0,  coverage_pct: 0  },
  ],
};

const MOCK_GAPS: GapsData = {
  gaps: [
    { tactic_id: "TA0005", technique_id: "T1562", technique_name: "Impair Defenses",               severity: "critical", recommendation: "Deploy EDR with tamper protection and alert on security tool process termination." },
    { tactic_id: "TA0040", technique_id: "T1486", technique_name: "Data Encrypted for Impact",     severity: "critical", recommendation: "Enable ransomware protection on endpoints and backup validation alerts." },
    { tactic_id: "TA0043", technique_id: "T1595", technique_name: "Active Scanning",               severity: "high",     recommendation: "Deploy honeypots and network sensors to detect external reconnaissance." },
    { tactic_id: "TA0007", technique_id: "T1082", technique_name: "System Information Discovery",  severity: "high",     recommendation: "Baseline normal discovery behavior and alert on anomalous enumeration." },
    { tactic_id: "TA0009", technique_id: "T1560", technique_name: "Archive Collected Data",        severity: "high",     recommendation: "Monitor for unusual compression activity and large archive creation." },
    { tactic_id: "TA0003", technique_id: "T1547", technique_name: "Boot or Logon Autostart",       severity: "medium",   recommendation: "Audit registry run keys and startup folder changes via FIM." },
    { tactic_id: "TA0011", technique_id: "T1071", technique_name: "Application Layer Protocol",    severity: "medium",   recommendation: "Deploy network traffic analysis for unusual protocol usage patterns." },
    { tactic_id: "TA0042", technique_id: "T1583", technique_name: "Acquire Infrastructure",        severity: "medium",   recommendation: "Subscribe to threat intel feeds for adversary infrastructure tracking." },
  ],
};

const MOCK_STATS: StatsData = {
  total_mappings: 312,
  tactics_covered: 11,
  techniques_covered: 78,
};

// ── Helpers ──────────────────────────────────────────────────────────────────
function coverageColor(pct: number): string {
  if (pct >= 70) return "bg-emerald-500";
  if (pct >= 40) return "bg-amber-500";
  return "bg-red-500";
}

function coverageTextColor(pct: number): string {
  if (pct >= 70) return "text-emerald-400";
  if (pct >= 40) return "text-amber-400";
  return "text-red-400";
}

function severityVariant(sev: string): "destructive" | "secondary" | "outline" {
  if (sev === "critical") return "destructive";
  if (sev === "high")     return "secondary";
  return "outline";
}

function severityLabel(sev: string): string {
  return sev.charAt(0).toUpperCase() + sev.slice(1);
}

// ── Component ────────────────────────────────────────────────────────────────
export default function MITREAttackDashboard() {
  const [coverage, setCoverage]     = useState<CoverageData>(MOCK_COVERAGE);
  const [gaps, setGaps]             = useState<Gap[]>(MOCK_GAPS.gaps);
  const [stats, setStats]           = useState<StatsData>(MOCK_STATS);
  const [loading, setLoading]       = useState(true);
  const [lastRefresh, setLastRefresh] = useState(new Date());

  const load = async () => {
    setLoading(true);
    const [coverageRes, gapsRes, statsRes] = await Promise.allSettled([
      apiFetch("/mitre-attack/coverage?org_id=default"),
      apiFetch("/mitre-attack/gaps?org_id=default"),
      apiFetch("/mitre-attack/stats?org_id=default"),
    ]);

    if (coverageRes.status === "fulfilled") setCoverage(coverageRes.value);
    if (gapsRes.status === "fulfilled")     setGaps(gapsRes.value.gaps ?? []);
    if (statsRes.status === "fulfilled")    setStats(statsRes.value);

    setLastRefresh(new Date());
    setLoading(false);
  };

  useEffect(() => { load(); }, []);

  const openGaps = gaps.filter((g) =>
    g.severity === "critical" || g.severity === "high"
  ).length;

  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader
        title="MITRE ATT&CK Coverage"
        description="Detection coverage mapped across 14 ATT&CK tactics and technique gaps"
        actions={
          <div className="flex items-center gap-3">
            <span className="text-xs text-muted-foreground">
              Updated {lastRefresh.toLocaleTimeString()}
            </span>
            <Button
              variant="outline"
              size="sm"
              onClick={load}
              disabled={loading}
              className="gap-2"
            >
              <RefreshCw className={cn("h-4 w-4", loading && "animate-spin")} />
              Refresh
            </Button>
          </div>
        }
      />

      {/* KPI Row */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <KpiCard
          title="Coverage"
          value={`${coverage.coverage_pct}%`}
          icon={<Shield className="h-5 w-5 text-blue-400" />}
          trend={coverage.coverage_pct >= 50 ? "up" : "down"}
          trendLabel={coverage.coverage_pct >= 50 ? "On track" : "Below target"}
        />
        <KpiCard
          title="Total Techniques"
          value={coverage.total_techniques}
          icon={<Target className="h-5 w-5 text-purple-400" />}
        />
        <KpiCard
          title="Detected"
          value={coverage.detected_techniques}
          icon={<CheckCircle2 className="h-5 w-5 text-emerald-400" />}
        />
        <KpiCard
          title="Open Gaps"
          value={openGaps}
          icon={<AlertTriangle className="h-5 w-5 text-red-400" />}
          trend="down"
          trendLabel="Require remediation"
        />
      </div>

      {/* Tactic Coverage Table */}
      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
      >
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-base">
              <Shield className="h-4 w-4 text-blue-400" />
              Tactic Coverage
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Tactic Name</TableHead>
                  <TableHead>ID</TableHead>
                  <TableHead className="text-right">Techniques</TableHead>
                  <TableHead className="text-right">Detected</TableHead>
                  <TableHead>Coverage</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {coverage.tactics.map((tactic) => (
                  <TableRow key={tactic.tactic_id}>
                    <TableCell className="font-medium">
                      {tactic.tactic_name}
                    </TableCell>
                    <TableCell>
                      <span className="font-mono text-xs text-muted-foreground">
                        {tactic.tactic_id}
                      </span>
                    </TableCell>
                    <TableCell className="text-right">
                      {tactic.technique_count}
                    </TableCell>
                    <TableCell className="text-right">
                      <span className={coverageTextColor(tactic.coverage_pct)}>
                        {tactic.detected_count}
                      </span>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-2 min-w-[140px]">
                        <div className="relative flex-1 h-2 rounded-full bg-muted overflow-hidden">
                          <div
                            className={cn(
                              "absolute inset-y-0 left-0 rounded-full transition-all duration-500",
                              coverageColor(tactic.coverage_pct)
                            )}
                            style={{ width: `${tactic.coverage_pct}%` }}
                          />
                        </div>
                        <span
                          className={cn(
                            "text-xs font-semibold w-9 text-right tabular-nums",
                            coverageTextColor(tactic.coverage_pct)
                          )}
                        >
                          {tactic.coverage_pct}%
                        </span>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </motion.div>

      {/* Gaps Table */}
      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
      >
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="flex items-center gap-2 text-base">
              <AlertTriangle className="h-4 w-4 text-amber-400" />
              Detection Gaps
              <Badge variant="secondary" className="ml-auto">
                {gaps.length} gaps
              </Badge>
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Technique</TableHead>
                  <TableHead>Tactic</TableHead>
                  <TableHead>Severity</TableHead>
                  <TableHead>Recommendation</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {gaps.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  gaps.map((gap) => (
                  <TableRow key={gap.technique_id}>
                    <TableCell>
                      <div className="flex flex-col gap-0.5">
                        <span className="font-medium text-sm">
                          {gap.technique_name}
                        </span>
                        <span className="font-mono text-xs text-muted-foreground">
                          {gap.technique_id}
                        </span>
                      </div>
                    </TableCell>
                    <TableCell>
                      <span className="font-mono text-xs text-muted-foreground">
                        {gap.tactic_id}
                      </span>
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant={severityVariant(gap.severity)}
                        className={cn(
                          "capitalize",
                          gap.severity === "high" &&
                            "bg-orange-500/15 text-orange-400 border-orange-500/30",
                          gap.severity === "medium" &&
                            "bg-amber-500/15 text-amber-400 border-amber-500/30"
                        )}
                      >
                        {severityLabel(gap.severity)}
                      </Badge>
                    </TableCell>
                    <TableCell className="max-w-sm text-sm text-muted-foreground">
                      {gap.recommendation.length > 80
                        ? `${gap.recommendation.slice(0, 80)}…`
                        : gap.recommendation}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </motion.div>

      {/* Stats Footer */}
      <div className="grid grid-cols-3 gap-4">
        {[
          { label: "Total Mappings",      value: stats.total_mappings },
          { label: "Tactics Covered",     value: `${stats.tactics_covered} / 14` },
          { label: "Techniques Covered",  value: stats.techniques_covered },
        ].map((item) => (
          <Card key={item.label}>
            <CardContent className="flex flex-col items-center justify-center py-5 gap-1">
              <span className="text-2xl font-bold tabular-nums">{item.value}</span>
              <span className="text-xs text-muted-foreground">{item.label}</span>
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
