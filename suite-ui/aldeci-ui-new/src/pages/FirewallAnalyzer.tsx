/**
 * Firewall Rule Analyzer
 *
 * Detect shadow rules, overly permissive policies, and rule bloat:
 *   1. KPIs: Total Rules, Unused Rules, Overly Permissive, Shadow Rules
 *   2. Risk Findings Table: rule_id, rule_name, finding_type, severity, firewall, recommendation, Fix
 *   3. Firewall Inventory: 4 cards with vendor, rule_count, issues, last_audit, health
 *   4. Rule Complexity Trend: 12-month div-based chart
 *   5. Cleanup Impact summary
 *   6. Audit Export button
 *
 * Route: /firewall
 * API: GET /api/v1/firewall/rules, GET /api/v1/firewall/findings (mock fallback)
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Shield,
  AlertTriangle,
  Eye,
  Trash2,
  Download,
  CheckCircle2,
  AlertCircle,
  Clock,
  Server,
  TrendingUp,
  Wrench,
  DollarSign,
  RefreshCw,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
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

// ── API config ─────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "dev-key";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "X-API-Key": API_KEY },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ══════════════════════════════════════════════════════════════
// Types
// ══════════════════════════════════════════════════════════════

type FindingType = "Unused" | "Overly Permissive" | "Shadow" | "Any-Any" | "Expired";
type Severity = "critical" | "high" | "medium" | "low";
type HealthStatus = "healthy" | "warning" | "critical";
type Vendor = "Palo Alto" | "Cisco" | "Fortinet" | "Check Point";

interface FirewallFinding {
  rule_id: string;
  rule_name: string;
  finding_type: FindingType;
  severity: Severity;
  firewall_name: string;
  recommendation: string;
}

interface FirewallDevice {
  id: string;
  name: string;
  vendor: Vendor;
  rule_count: number;
  issues_count: number;
  last_audit: string;
  health: HealthStatus;
}

// ══════════════════════════════════════════════════════════════
// Mock Data
// ══════════════════════════════════════════════════════════════

const MOCK_FINDINGS: FirewallFinding[] = [
  {
    rule_id: "#447",
    rule_name: "Allow all outbound",
    finding_type: "Any-Any",
    severity: "critical",
    firewall_name: "FW-PROD-01",
    recommendation: "Restrict to required destination ports 80/443 only",
  },
  {
    rule_id: "#812",
    rule_name: "Old VPN access",
    finding_type: "Unused",
    severity: "high",
    firewall_name: "FW-EDGE-01",
    recommendation: "Remove — no hits in 180 days, VPN decommissioned",
  },
  {
    rule_id: "#156",
    rule_name: "Dev team access",
    finding_type: "Overly Permissive",
    severity: "high",
    firewall_name: "FW-INTERNAL-01",
    recommendation: "Restrict to required ports (22, 443) instead of any port",
  },
  {
    rule_id: "#334",
    rule_name: "Shadow rule - unreachable",
    finding_type: "Shadow",
    severity: "medium",
    firewall_name: "FW-PROD-01",
    recommendation: "Remove — rule is masked by #201 and never evaluated",
  },
  {
    rule_id: "#089",
    rule_name: "Legacy SMTP relay",
    finding_type: "Expired",
    severity: "high",
    firewall_name: "FW-DMZ-01",
    recommendation: "Remove — expired 2025-11-01, mail relay replaced",
  },
  {
    rule_id: "#723",
    rule_name: "Any-any internal permit",
    finding_type: "Any-Any",
    severity: "critical",
    firewall_name: "FW-INTERNAL-01",
    recommendation: "Segment with explicit allow rules per subnet pair",
  },
  {
    rule_id: "#501",
    rule_name: "Contractor inbound",
    finding_type: "Unused",
    severity: "medium",
    firewall_name: "FW-EDGE-01",
    recommendation: "Remove — contractor engagement ended, no traffic in 90d",
  },
  {
    rule_id: "#290",
    rule_name: "Backup server allow",
    finding_type: "Overly Permissive",
    severity: "medium",
    firewall_name: "FW-PROD-01",
    recommendation: "Limit to backup ports 9100-9102 from backup subnet only",
  },
  {
    rule_id: "#614",
    rule_name: "DMZ outbound catch-all",
    finding_type: "Shadow",
    severity: "low",
    firewall_name: "FW-DMZ-01",
    recommendation: "Remove shadow duplicate — identical rule #610 takes precedence",
  },
  {
    rule_id: "#038",
    rule_name: "Test lab permit",
    finding_type: "Expired",
    severity: "medium",
    firewall_name: "FW-INTERNAL-01",
    recommendation: "Remove — test lab decommissioned 2025-09-15",
  },
];

const MOCK_FIREWALLS: FirewallDevice[] = [
  {
    id: "fw1",
    name: "FW-PROD-01",
    vendor: "Palo Alto",
    rule_count: 412,
    issues_count: 18,
    last_audit: "2026-03-28",
    health: "warning",
  },
  {
    id: "fw2",
    name: "FW-EDGE-01",
    vendor: "Cisco",
    rule_count: 287,
    issues_count: 7,
    last_audit: "2026-04-02",
    health: "warning",
  },
  {
    id: "fw3",
    name: "FW-DMZ-01",
    vendor: "Fortinet",
    rule_count: 341,
    issues_count: 5,
    last_audit: "2026-04-10",
    health: "healthy",
  },
  {
    id: "fw4",
    name: "FW-INTERNAL-01",
    vendor: "Check Point",
    rule_count: 207,
    issues_count: 22,
    last_audit: "2026-02-14",
    health: "critical",
  },
];

// 12-month rule count trend (Jan–Dec 2025 → Apr 2026)
const TREND_DATA = [
  { month: "May", count: 1089 },
  { month: "Jun", count: 1112 },
  { month: "Jul", count: 1134 },
  { month: "Aug", count: 1158 },
  { month: "Sep", count: 1177 },
  { month: "Oct", count: 1194 },
  { month: "Nov", count: 1208 },
  { month: "Dec", count: 1215 },
  { month: "Jan", count: 1221 },
  { month: "Feb", count: 1229 },
  { month: "Mar", count: 1238 },
  { month: "Apr", count: 1247 },
];

// ══════════════════════════════════════════════════════════════
// Styling helpers
// ══════════════════════════════════════════════════════════════

const SEV_COLORS: Record<Severity, string> = {
  critical: "bg-red-500/10 text-red-400 border-red-500/30",
  high: "bg-orange-500/10 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/10 text-blue-400 border-blue-500/30",
};

const FINDING_COLORS: Record<FindingType, string> = {
  "Any-Any": "bg-red-500/10 text-red-400",
  "Unused": "bg-slate-500/10 text-slate-400",
  "Overly Permissive": "bg-orange-500/10 text-orange-400",
  "Shadow": "bg-purple-500/10 text-purple-400",
  "Expired": "bg-amber-500/10 text-amber-400",
};

const HEALTH_COLORS: Record<HealthStatus, string> = {
  healthy: "bg-green-500/10 text-green-400 border-green-500/30",
  warning: "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
  critical: "bg-red-500/10 text-red-400 border-red-500/30",
};

const VENDOR_COLORS: Record<Vendor, string> = {
  "Palo Alto": "text-orange-400",
  "Cisco": "text-blue-400",
  "Fortinet": "text-red-400",
  "Check Point": "text-green-400",
};

// ══════════════════════════════════════════════════════════════
// Main Component
// ══════════════════════════════════════════════════════════════

const ORG_ID = "default";

export default function FirewallAnalyzer() {
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);
  const [loading, setLoading] = useState(true);

  const fetchAll = () =>
    Promise.allSettled([
      apiFetch(`/api/v1/firewall-mgmt/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/firewall-mgmt/firewalls?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/firewall-mgmt/violations?org_id=${ORG_ID}`),
    ]).then(([statsRes, firewallsRes, violationsRes]) => {
      const stats      = statsRes.status      === "fulfilled" ? statsRes.value      : null;
      const firewalls  = firewallsRes.status  === "fulfilled" ? firewallsRes.value  : null;
      const violations = violationsRes.status === "fulfilled" ? violationsRes.value : null;
      if (stats || firewalls || violations) {
        setLiveData({ stats, firewalls, violations });
      }
    });

  useEffect(() => {
    setDataLoading(true);
    fetchAll().finally(() => setDataLoading(false));
  
    setLoading(false);}, []);

  const findings: FirewallFinding[] =
    (liveData?.violations?.items ?? liveData?.violations?.findings ?? liveData?.violations) ?? MOCK_FINDINGS;
  const firewallDevices: FirewallDevice[] =
    (liveData?.firewalls?.items ?? liveData?.firewalls?.firewalls ?? liveData?.firewalls) ?? MOCK_FIREWALLS;

  const handleRefresh = () => {
    setDataLoading(true);
    fetchAll().finally(() => setDataLoading(false));
  };

  const trendMax = Math.max(...TREND_DATA.map((d) => d.count));
  const trendMin = Math.min(...TREND_DATA.map((d) => d.count));
  const trendRange = trendMax - trendMin || 1;

  if (loading) return (
    <div className="space-y-4 p-6">
      {[1, 2, 3].map((i) => (
        <div key={i} className="h-24 rounded-lg bg-zinc-800/50 animate-pulse" />
      ))}
    </div>
  );

  return (
    <div className="min-h-screen bg-slate-900 p-8 space-y-8">
      {/* Header */}
      <PageHeader
        title="Firewall Rule Analyzer"
        description="Detect shadow rules, overly permissive policies, and rule bloat"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={dataLoading}>
            <RefreshCw className={cn("h-4 w-4", dataLoading && "animate-spin")} />
          </Button>
        
    setLoading(false);}
      />

      {/* KPIs */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard
          title="Total Rules"
          value={liveData?.stats?.total_rules ?? 1247}
          icon={Shield}
          change={9}
          changeLabel="vs last month"
        />
        <KpiCard
          title="Unused Rules"
          value={liveData?.stats?.unused_rules ?? 89}
          icon={Trash2}
          change={-3}
          changeLabel="vs last audit"
        />
        <KpiCard
          title="Overly Permissive"
          value={liveData?.stats?.overly_permissive ?? 34}
          icon={AlertTriangle}
        />
        <KpiCard
          title="Shadow Rules"
          value={liveData?.stats?.shadow_rules ?? 12}
          icon={Eye}
        />
      </div>

      {/* Risk Findings Table */}
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
      >
        <Card className="border-slate-700">
          <CardHeader className="border-b border-slate-700">
            <CardTitle className="flex items-center gap-2">
              <AlertCircle className="w-5 h-5 text-red-400" />
              Risk Findings — Top Priority
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <Table>
                <TableHeader className="bg-slate-800/50 border-b border-slate-700">
                  <TableRow>
                    <TableHead className="text-slate-300">Rule ID</TableHead>
                    <TableHead className="text-slate-300">Rule Name</TableHead>
                    <TableHead className="text-slate-300">Finding Type</TableHead>
                    <TableHead className="text-slate-300">Severity</TableHead>
                    <TableHead className="text-slate-300">Firewall</TableHead>
                    <TableHead className="text-slate-300">Recommendation</TableHead>
                    <TableHead className="text-slate-300 text-right">Action</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {findings.length === 0 ? (
                    <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                      <p className="text-lg font-medium">No data available</p>
                      <p className="text-sm">Data will appear here once available</p>
                    </div>
                  ) : (
                    findings.map((finding, idx) => (
                    <motion.tr
                      key={finding.rule_id}
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      transition={{ delay: idx * 0.04 }}
                      className="border-b border-slate-700/50 hover:bg-slate-800/30 transition-colors"
                    >
                      <TableCell className="text-slate-300 font-mono text-sm font-semibold">
                        {finding.rule_id}
                      </TableCell>
                      <TableCell className="text-slate-200 font-medium">
                        {finding.rule_name}
                      </TableCell>
                      <TableCell>
                        <Badge className={cn("text-xs font-semibold border-0", FINDING_COLORS[finding.finding_type])}>
                          {finding.finding_type}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Badge className={cn("text-xs font-semibold border", SEV_COLORS[finding.severity])}>
                          {finding.severity.toUpperCase()}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-slate-400 font-mono text-sm">
                        {finding.firewall_name}
                      </TableCell>
                      <TableCell className="text-slate-400 text-sm max-w-xs">
                        {finding.recommendation}
                      </TableCell>
                      <TableCell className="text-right">
                        <Button
                          size="sm"
                          variant="outline"
                          className="h-7 text-xs border-slate-600 hover:border-blue-500 hover:text-blue-400"
                        >
                          <Wrench className="w-3 h-3 mr-1" />
                          Fix
                        </Button>
                      </TableCell>
                    </motion.tr>
                  ))}
                  )}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* Firewall Inventory */}
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
      >
        <h2 className="text-lg font-semibold text-slate-200 mb-4 flex items-center gap-2">
          <Server className="w-5 h-5 text-cyan-400" />
          Firewall Inventory
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
          {firewallDevices.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
              <p className="text-lg font-medium">No data available</p>
              <p className="text-sm">Data will appear here once available</p>
            </div>
          ) : (
            firewallDevices.map((fw, idx) => (
            <motion.div
              key={fw.id}
              initial={{ opacity: 0, scale: 0.97 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: 0.2 + idx * 0.06 }}
            >
              <Card className="border-slate-700 hover:border-slate-500 transition-colors">
                <CardContent className="p-5 space-y-3">
                  <div className="flex items-start justify-between">
                    <div>
                      <p className="font-semibold text-slate-200 font-mono">{fw.name}</p>
                      <p className={cn("text-xs font-medium mt-0.5", VENDOR_COLORS[fw.vendor])}>
                        {fw.vendor}
                      </p>
                    </div>
                    <Badge className={cn("text-xs border capitalize", HEALTH_COLORS[fw.health])}>
                      {fw.health}
                    </Badge>
                  </div>
                  <div className="grid grid-cols-2 gap-2 text-sm">
                    <div>
                      <p className="text-slate-500 text-xs">Rules</p>
                      <p className="text-slate-200 font-semibold">{fw.rule_count}</p>
                    </div>
                    <div>
                      <p className="text-slate-500 text-xs">Issues</p>
                      <p className={cn(
                        "font-semibold",
                        fw.issues_count > 15 ? "text-red-400" :
                        fw.issues_count > 8 ? "text-orange-400" : "text-yellow-400"
                      )}>
                        {fw.issues_count}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-center gap-1 text-xs text-slate-500">
                    <Clock className="w-3 h-3" />
                    Last audit: {fw.last_audit}
                  </div>
                </CardContent>
              </Card>
            </motion.div>
          ))}
          )}
        </div>
      </motion.div>

      {/* Trend Chart + Cleanup Impact */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Rule Complexity Trend */}
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="lg:col-span-2"
        >
          <Card className="border-slate-700">
            <CardHeader className="border-b border-slate-700">
              <CardTitle className="flex items-center gap-2 text-base">
                <TrendingUp className="w-5 h-5 text-blue-400" />
                Rule Count Growth — 12 Months
              </CardTitle>
            </CardHeader>
            <CardContent className="p-6">
              <div className="flex items-end gap-2 h-40">
                {TREND_DATA.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  TREND_DATA.map((point, idx) => {
                  const heightPct = ((point.count - trendMin) / trendRange) * 80 + 10;
                  return (
                    <div key={point.month} className="flex-1 flex flex-col items-center gap-1">
                      <span className="text-xs text-slate-500 hidden sm:block">
                        {point.count}
                      </span>
                      <motion.div
                        initial={{ height: 0 }}
                        animate={{ height: `${heightPct}%` }}
                        transition={{ delay: 0.3 + idx * 0.04, duration: 0.4 }}
                        className={cn(
                          "w-full rounded-t",
                          idx === TREND_DATA.length - 1
                            ? "bg-blue-500"
                            : "bg-slate-600 hover:bg-slate-500 transition-colors"
                        )}
                        style={{ minHeight: "4px" }}
                        title={`${point.month}: ${point.count} rules`}
                      />
                      <span className="text-xs text-slate-500">{point.month}</span>
                    </div>
                  );
                })}
                )}
              </div>
              <p className="text-xs text-slate-500 mt-3 text-center">
                +158 rules added over 12 months (+14.5% rule bloat)
              </p>
            </CardContent>
          </Card>
        </motion.div>

        {/* Cleanup Impact */}
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.35 }}
        >
          <Card className="border-slate-700 h-full">
            <CardHeader className="border-b border-slate-700">
              <CardTitle className="flex items-center gap-2 text-base">
                <DollarSign className="w-5 h-5 text-green-400" />
                Cleanup Impact
              </CardTitle>
            </CardHeader>
            <CardContent className="p-6 space-y-4">
              <p className="text-sm text-slate-400 italic">
                If all recommended fixes applied:
              </p>
              <div className="space-y-3">
                <div className="flex items-center gap-3 p-3 rounded-lg bg-slate-800/50 border border-slate-700">
                  <Trash2 className="w-4 h-4 text-slate-400 shrink-0" />
                  <div>
                    <p className="text-sm font-semibold text-slate-200">-89 unused rules</p>
                    <p className="text-xs text-slate-500">7.1% reduction in ruleset</p>
                  </div>
                </div>
                <div className="flex items-center gap-3 p-3 rounded-lg bg-slate-800/50 border border-slate-700">
                  <Shield className="w-4 h-4 text-orange-400 shrink-0" />
                  <div>
                    <p className="text-sm font-semibold text-slate-200">-34 permissive rules</p>
                    <p className="text-xs text-slate-500">Attack surface reduction</p>
                  </div>
                </div>
                <div className="flex items-center gap-3 p-3 rounded-lg bg-green-500/5 border border-green-500/20">
                  <DollarSign className="w-4 h-4 text-green-400 shrink-0" />
                  <div>
                    <p className="text-sm font-semibold text-green-400">-$12K/yr</p>
                    <p className="text-xs text-slate-500">Policy management overhead</p>
                  </div>
                </div>
              </div>
              <div className="pt-2">
                <Button
                  variant="outline"
                  className="w-full border-slate-600 text-slate-400 hover:border-slate-500"
                  disabled
                >
                  <Download className="w-4 h-4 mr-2" />
                  Export Rule Audit Report
                </Button>
                <p className="text-xs text-slate-600 text-center mt-2">
                  Coming soon
                </p>
              </div>
            </CardContent>
          </Card>
        </motion.div>
      </div>
    </div>
  );
}
