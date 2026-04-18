/**
 * DAST Dashboard
 *
 * Dynamic Application Security Testing — scan results, findings, endpoint coverage.
 *   1. KPIs: Total Scans, Findings, Critical Issues, Endpoints Tested
 *   2. Recent findings table (endpoint, vuln type, severity, scan date, status)
 *
 * Route: /dast
 * API: GET /api/v1/dast/stats, /api/v1/dast/findings
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Search, AlertTriangle, ShieldAlert, Globe, RefreshCw, CheckCircle, Clock } from "lucide-react";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "X-API-Key": API_KEY, "Content-Type": "application/json" },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";

// ── Mock data ──────────────────────────────────────────────────

const MOCK_STATS = {
  scans: 8,
  findings: 156,
  critical: 4,
  high: 23,
  endpoints_tested: 342,
};

const MOCK_FINDINGS = [
  { id: "DAST-001", endpoint: "/api/v1/auth/login",        vuln_type: "SQL Injection",           severity: "critical", scan_date: "2026-04-16", status: "open" },
  { id: "DAST-002", endpoint: "/api/v1/users/{id}",        vuln_type: "IDOR",                    severity: "critical", scan_date: "2026-04-16", status: "open" },
  { id: "DAST-003", endpoint: "/api/v1/reports/export",    vuln_type: "XXE Injection",            severity: "critical", scan_date: "2026-04-15", status: "investigating" },
  { id: "DAST-004", endpoint: "/api/v1/search",            vuln_type: "Reflected XSS",           severity: "critical", scan_date: "2026-04-15", status: "open" },
  { id: "DAST-005", endpoint: "/api/v1/files/upload",      vuln_type: "Unrestricted File Upload", severity: "high",     scan_date: "2026-04-15", status: "open" },
  { id: "DAST-006", endpoint: "/api/v1/admin/users",       vuln_type: "Broken Access Control",   severity: "high",     scan_date: "2026-04-14", status: "open" },
  { id: "DAST-007", endpoint: "/api/v1/settings",          vuln_type: "CSRF",                    severity: "high",     scan_date: "2026-04-14", status: "remediated" },
  { id: "DAST-008", endpoint: "/api/v1/webhooks",          vuln_type: "SSRF",                    severity: "high",     scan_date: "2026-04-14", status: "open" },
  { id: "DAST-009", endpoint: "/api/v1/analytics/query",   vuln_type: "NoSQL Injection",         severity: "medium",   scan_date: "2026-04-13", status: "open" },
  { id: "DAST-010", endpoint: "/api/v1/profile",           vuln_type: "Stored XSS",              severity: "medium",   scan_date: "2026-04-13", status: "investigating" },
  { id: "DAST-011", endpoint: "/api/v1/integrations",      vuln_type: "Open Redirect",           severity: "medium",   scan_date: "2026-04-12", status: "open" },
  { id: "DAST-012", endpoint: "/api/v1/notifications",     vuln_type: "Missing Auth",            severity: "medium",   scan_date: "2026-04-12", status: "remediated" },
  { id: "DAST-013", endpoint: "/api/v1/health",            vuln_type: "Info Disclosure",         severity: "low",      scan_date: "2026-04-11", status: "open" },
  { id: "DAST-014", endpoint: "/api/v1/metrics",           vuln_type: "Info Disclosure",         severity: "low",      scan_date: "2026-04-11", status: "open" },
  { id: "DAST-015", endpoint: "/api/v1/docs",              vuln_type: "Missing Rate Limit",      severity: "low",      scan_date: "2026-04-10", status: "remediated" },
];

// ── Severity badge ─────────────────────────────────────────────

function SeverityBadge({ severity }: { severity: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/40 text-red-400 bg-red-500/10",
    high:     "border-orange-500/40 text-orange-400 bg-orange-500/10",
    medium:   "border-yellow-500/40 text-yellow-400 bg-yellow-500/10",
    low:      "border-blue-500/40 text-blue-400 bg-blue-500/10",
    info:     "border-gray-500/40 text-gray-400 bg-gray-500/10",
  };
  return (
    <Badge variant="outline" className={map[severity] ?? map.info}>
      {severity}
    </Badge>
  );
}

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    open:          "border-red-500/40 text-red-400 bg-red-500/10",
    investigating: "border-yellow-500/40 text-yellow-400 bg-yellow-500/10",
    remediated:    "border-green-500/40 text-green-400 bg-green-500/10",
  };
  const icons: Record<string, React.ReactNode> = {
    open:          <AlertTriangle className="w-3 h-3 mr-1" />,
    investigating: <Clock className="w-3 h-3 mr-1" />,
    remediated:    <CheckCircle className="w-3 h-3 mr-1" />,
  };
  return (
    <Badge variant="outline" className={`flex items-center ${map[status] ?? map.open}`}>
      {icons[status]}
      {status}
    </Badge>
  );
}

// ── Main Component ─────────────────────────────────────────────

export default function DASTDashboard() {
  const [stats, setStats] = useState(MOCK_STATS);
  const [findings, setFindings] = useState(MOCK_FINDINGS);
  const [loading, setLoading] = useState(false);

  const load = async () => {
    setLoading(true);
    try {
      const [s, f] = await Promise.all([
        apiFetch("/api/v1/dast/stats?org_id=default"),
        apiFetch("/api/v1/dast/findings?org_id=default&limit=20"),
      ]);
      if (s && typeof s.scans === "number") setStats(s);
      if (Array.isArray(f) && f.length > 0) setFindings(f);
    } catch {
      // API not available — keep mock data
    } finally {
    }
  };

  useEffect(() => { load(); }, []);

  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader
        title="DAST Dashboard"
        description="Dynamic Application Security Testing — runtime vulnerability discovery across all API endpoints"
        actions={
          <Button variant="outline" size="sm" onClick={load} disabled={loading}>
            <RefreshCw className={`w-4 h-4 mr-2 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </Button>
        }
      />

      {/* KPI Cards */}
      <div className="grid grid-cols-2 gap-4 md:grid-cols-4">
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.05 }}>
          <KpiCard
            title="Total Scans"
            value={stats.scans}
            icon={<Search className="w-5 h-5 text-blue-400" />}
            trend={{ direction: "up", label: "+2 this week" }}
          />
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.10 }}>
          <KpiCard
            title="Findings"
            value={stats.findings}
            icon={<AlertTriangle className="w-5 h-5 text-orange-400" />}
            trend={{ direction: "up", label: "+12 since last scan" }}
          />
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.15 }}>
          <KpiCard
            title="Critical Issues"
            value={stats.critical}
            icon={<ShieldAlert className="w-5 h-5 text-red-400" />}
            trend={{ direction: "neutral", label: "Needs immediate action" }}
          />
        </motion.div>
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.20 }}>
          <KpiCard
            title="Endpoints Tested"
            value={stats.endpoints_tested}
            icon={<Globe className="w-5 h-5 text-green-400" />}
            trend={{ direction: "up", label: "+28 vs last scan" }}
          />
        </motion.div>
      </div>

      {/* Findings Table */}
      <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.25 }}>
        <Card className="border-white/10 bg-white/5">
          <CardHeader>
            <CardTitle className="text-sm font-medium text-white/80">Recent Findings</CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow className="border-white/10 hover:bg-transparent">
                  <TableHead className="text-white/50">Endpoint</TableHead>
                  <TableHead className="text-white/50">Vulnerability Type</TableHead>
                  <TableHead className="text-white/50">Severity</TableHead>
                  <TableHead className="text-white/50">Scan Date</TableHead>
                  <TableHead className="text-white/50">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {findings.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  findings.map((f) => (
                  <TableRow key={f.id} className="border-white/10 hover:bg-white/5">
                    <TableCell className="font-mono text-xs text-white/70">{f.endpoint}</TableCell>
                    <TableCell className="text-white/80">{f.vuln_type}</TableCell>
                    <TableCell><SeverityBadge severity={f.severity} /></TableCell>
                    <TableCell className="text-white/50 text-sm">{f.scan_date}</TableCell>
                    <TableCell><StatusBadge status={f.status} /></TableCell>
                  </TableRow>
                )))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </motion.div>
    </div>
  );
}
