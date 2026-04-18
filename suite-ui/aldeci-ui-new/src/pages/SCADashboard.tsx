/**
 * SCA Dashboard — Software Composition Analysis
 *
 * Open-source dependency scanning — vulnerable libs, license violations.
 *   1. KPIs: Projects, Scans, Vulnerable Dependencies, License Violations
 *   2. Projects table (language, last scan date, vuln count, risk level)
 *
 * Route: /sca
 * API: GET /api/v1/sca/stats
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Package, AlertTriangle, FileWarning, RefreshCw, Scale } from "lucide-react";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci_api_key")) ||
  import.meta.env.VITE_API_KEY ||
  "dev-key";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string, opts?: RequestInit) {
  const res = await fetch(`${API_BASE}${path}`, {
    ...opts,
    headers: { "X-API-Key": API_KEY, "Content-Type": "application/json", ...(opts?.headers ?? {}) },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── Mock data ──────────────────────────────────────────────────

const MOCK_PROJECTS = [
  { id: "PRJ-001", name: "api-gateway",      language: "Go",         last_scan: "2026-04-16", vuln_count: 3,  risk_level: "medium" },
  { id: "PRJ-002", name: "auth-service",     language: "Python",     last_scan: "2026-04-16", vuln_count: 17, risk_level: "critical" },
  { id: "PRJ-003", name: "frontend-app",     language: "TypeScript", last_scan: "2026-04-15", vuln_count: 8,  risk_level: "high" },
  { id: "PRJ-004", name: "data-pipeline",    language: "Python",     last_scan: "2026-04-15", vuln_count: 0,  risk_level: "low" },
  { id: "PRJ-005", name: "ml-inference",     language: "Python",     last_scan: "2026-04-14", vuln_count: 24, risk_level: "critical" },
  { id: "PRJ-006", name: "notification-svc", language: "Node.js",    last_scan: "2026-04-14", vuln_count: 5,  risk_level: "medium" },
  { id: "PRJ-007", name: "reporting-engine", language: "Java",       last_scan: "2026-04-13", vuln_count: 11, risk_level: "high" },
  { id: "PRJ-008", name: "mobile-backend",   language: "Kotlin",     last_scan: "2026-04-12", vuln_count: 2,  risk_level: "low" },
];

const MOCK_STATS = {
  projects: 8,
  scans: 142,
  vulnerable_dependencies: 70,
  license_violations: 9,
};

// ── Badge helpers ──────────────────────────────────────────────

function RiskBadge({ level }: { level: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-amber-500/30 text-amber-400 bg-amber-500/10",
    medium:   "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    low:      "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[level] ?? "border-border")}>
      {level}
    </Badge>
  );
}

function LangBadge({ lang }: { lang: string }) {
  const map: Record<string, string> = {
    Go:         "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
    Python:     "border-blue-500/30 text-blue-400 bg-blue-500/10",
    TypeScript: "border-indigo-500/30 text-indigo-400 bg-indigo-500/10",
    "Node.js":  "border-green-500/30 text-green-400 bg-green-500/10",
    Java:       "border-orange-500/30 text-orange-400 bg-orange-500/10",
    Kotlin:     "border-purple-500/30 text-purple-400 bg-purple-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border font-mono", map[lang] ?? "border-slate-500/30 text-slate-400 bg-slate-500/10")}>
      {lang}
    </Badge>
  );
}

// ── Component ──────────────────────────────────────────────────

export default function SCADashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveData, setLiveData] = useState<any>(null);

  useEffect(() => {
    apiFetch(`/api/v1/sca/stats?org_id=${ORG_ID}`)
      .then((d) => setLiveData(d))
      .catch(() => {});
  }, []);

  const stats    = liveData ?? MOCK_STATS;
  const projects = liveData?.projects ?? MOCK_PROJECTS;

  const handleRefresh = () => {
    setRefreshing(true);
    apiFetch(`/api/v1/sca/stats?org_id=${ORG_ID}`)
      .then((d) => setLiveData(d))
      .catch(() => {})
      .finally(() => setRefreshing(false));
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      {error && (
        <div className="bg-red-900/20 border border-red-500/30 rounded-lg p-4 flex items-center justify-between">
          <p className="text-red-400 text-sm">{error}</p>
          <button
            onClick={() => { setError(null); handleRefresh(); }}
            className="px-3 py-1 bg-red-600 hover:bg-red-700 text-white text-xs rounded transition-colors"
          >
            Retry
          </button>
        </div>
      )}
      <PageHeader
        title="Software Composition Analysis"
        description="Open-source dependency scanning for vulnerabilities and license compliance"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Projects"                value={stats.projects ?? 8}                icon={Package}      trend="flat" />
        <KpiCard title="Total Scans"             value={stats.scans ?? 142}                 icon={FileWarning}  trend="up" />
        <KpiCard title="Vulnerable Dependencies" value={stats.vulnerable_dependencies ?? 70} icon={AlertTriangle} trend="up" className="border-red-500/20" />
        <KpiCard title="License Violations"      value={stats.license_violations ?? 9}      icon={Scale}        trend="up" className="border-amber-500/20" />
      </div>

      {/* Projects Table */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Package className="h-4 w-4 text-blue-400" />
            Projects
          </CardTitle>
          <CardDescription className="text-xs">
            Scanned projects with dependency vulnerability counts and risk classification
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Project</TableHead>
                  <TableHead className="text-[11px] h-8">Language</TableHead>
                  <TableHead className="text-[11px] h-8">Last Scan</TableHead>
                  <TableHead className="text-[11px] h-8 text-center">Vulns</TableHead>
                  <TableHead className="text-[11px] h-8">Risk Level</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {projects.map((proj: any) => (
                  <TableRow key={proj.id} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-mono text-xs text-foreground">{proj.name}</TableCell>
                    <TableCell className="py-2">
                      <LangBadge lang={proj.language} />
                    </TableCell>
                    <TableCell className="py-2 text-[11px] tabular-nums text-muted-foreground">
                      {proj.last_scan}
                    </TableCell>
                    <TableCell className="py-2 text-center">
                      <span
                        className={cn(
                          "text-xs font-bold tabular-nums",
                          proj.vuln_count === 0
                            ? "text-green-400"
                            : proj.vuln_count >= 15
                            ? "text-red-400"
                            : proj.vuln_count >= 5
                            ? "text-amber-400"
                            : "text-yellow-400"
                        )}
                      >
                        {proj.vuln_count}
                      </span>
                    </TableCell>
                    <TableCell className="py-2">
                      <RiskBadge level={proj.risk_level} />
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
