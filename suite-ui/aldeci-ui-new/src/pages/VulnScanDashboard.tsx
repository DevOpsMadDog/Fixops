/**
 * Vulnerability Scan Dashboard
 *
 * Scan history, active scans, findings severity breakdown, and scan trigger form.
 *   1. KPIs: Total Scans, Active Scans, Critical Findings, Avg Findings/Scan
 *   2. Scan history table (scanner_type, status, findings_count, critical_count, started_at)
 *   3. Findings severity breakdown bar chart (CSS bars)
 *   4. Trigger scan form
 *
 * Route: /vuln-scans
 * API: GET /api/v1/vuln-scans
 */

import { useState, useEffect } from "react";
const _API_BASE = "/api/v1/vuln-scans";
const _getHeaders = () => ({ "X-API-Key": localStorage.getItem("apiKey") || "" });

import { motion } from "framer-motion";
import { ScanLine, AlertTriangle, Activity, Play, RefreshCw, Clock, CheckCircle2, XCircle, Loader2 } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── Types ──────────────────────────────────────────────────────

interface Scan {
  id: string;
  scanner_type: string;
  target: string;
  status: "completed" | "running" | "failed" | "queued";
  findings_count: number;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  started_at: string;
  duration_min: number;
}

// ── Mock data ──────────────────────────────────────────────────

const MOCK_SCANS: Scan[] = [
  { id: "sc-001", scanner_type: "Nessus",       target: "10.0.0.0/16",        status: "completed", findings_count: 347, critical_count: 12, high_count: 48,  medium_count: 187, low_count: 100, started_at: "2026-04-16 08:00", duration_min: 42 },
  { id: "sc-002", scanner_type: "Qualys",        target: "web.prod.internal",   status: "running",   findings_count: 134, critical_count: 6,  high_count: 28,  medium_count: 72,  low_count: 28,  started_at: "2026-04-16 09:15", duration_min: 18 },
  { id: "sc-003", scanner_type: "OpenVAS",       target: "192.168.1.0/24",      status: "completed", findings_count: 218, critical_count: 4,  high_count: 31,  medium_count: 103, low_count: 80,  started_at: "2026-04-16 06:30", duration_min: 67 },
  { id: "sc-004", scanner_type: "Tenable.io",   target: "aws-prod-vpc",        status: "completed", findings_count: 512, critical_count: 23, high_count: 91,  medium_count: 241, low_count: 157, started_at: "2026-04-15 22:00", duration_min: 93 },
  { id: "sc-005", scanner_type: "Rapid7",        target: "api.example.com",     status: "failed",    findings_count: 0,   critical_count: 0,  high_count: 0,   medium_count: 0,   low_count: 0,   started_at: "2026-04-16 07:45", duration_min: 3  },
  { id: "sc-006", scanner_type: "Burp Suite",    target: "app.example.com",     status: "completed", findings_count: 89,  critical_count: 2,  high_count: 14,  medium_count: 48,  low_count: 25,  started_at: "2026-04-15 18:00", duration_min: 55 },
  { id: "sc-007", scanner_type: "OWASP ZAP",     target: "api-gateway.internal",status: "queued",    findings_count: 0,   critical_count: 0,  high_count: 0,   medium_count: 0,   low_count: 0,   started_at: "2026-04-16 10:00", duration_min: 0  },
  { id: "sc-008", scanner_type: "Trivy",         target: "docker-registry",     status: "completed", findings_count: 163, critical_count: 8,  high_count: 22,  medium_count: 87,  low_count: 46,  started_at: "2026-04-16 05:00", duration_min: 12 },
];

const SEVERITY_BREAKDOWN = [
  { label: "Critical", count: 55,  color: "bg-red-600",    textColor: "text-red-400" },
  { label: "High",     count: 234, color: "bg-orange-500", textColor: "text-orange-400" },
  { label: "Medium",   count: 738, color: "bg-yellow-500", textColor: "text-yellow-400" },
  { label: "Low",      count: 436, color: "bg-blue-500",   textColor: "text-blue-400" },
];

const SCANNER_TYPES = ["Nessus", "Qualys", "OpenVAS", "Tenable.io", "Rapid7", "Burp Suite", "OWASP ZAP", "Trivy"];

// ── Helpers ────────────────────────────────────────────────────

function ScanStatusBadge({ status }: { status: string }) {
  const map: Record<string, { cls: string; icon: React.ReactNode }> = {
    completed: { cls: "bg-green-500/10 text-green-400 border-green-500/20",  icon: <CheckCircle2 className="w-3 h-3" /> },
    running:   { cls: "bg-blue-500/10 text-blue-400 border-blue-500/20",    icon: <Loader2 className="w-3 h-3 animate-spin" /> },
    failed:    { cls: "bg-red-500/10 text-red-400 border-red-500/20",       icon: <XCircle className="w-3 h-3" /> },
    queued:    { cls: "bg-gray-500/10 text-gray-400 border-gray-500/20",    icon: <Clock className="w-3 h-3" /> },
  };
  const { cls, icon } = map[status] ?? { cls: "bg-gray-500/10 text-gray-400", icon: null };
  return (
    <Badge className={cn("border text-xs gap-1 capitalize", cls)}>
      {error && (
        <div className="bg-red-900/20 border border-red-500/30 rounded-lg p-4 flex items-center justify-between">
          <p className="text-red-400 text-sm">{error}</p>
          <button
            onClick={() => { setError(null); window.location.reload(); }}
            className="px-3 py-1 bg-red-600 hover:bg-red-700 text-white text-xs rounded transition-colors"
          >
            Retry
          </button>
        </div>
      )}
      {icon}{status}
    </Badge>
  );
}

// ── Main Component ─────────────────────────────────────────────

export default function VulnScanDashboard() {
  const [scans, setScans] = useState(MOCK_SCANS);

  useEffect(() => {
    fetch(`${_API_BASE}/scans`, { headers: _getHeaders() })
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(d => { if (Array.isArray(d)) setScans(d); })
      .catch(() => { setError('Failed to load data'); });
  }, []);

  const [scannerType, setScannerType] = useState("Nessus");
  useEffect(() => {
    fetch(`${_API_BASE}/scans`, { headers: _getHeaders() })
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(d => { if (Array.isArray(d)) setScans(d); })
      .catch(() => { setError('Failed to load data'); });
  }, []);
  const [target, setTarget] = useState("");
  const [triggering, setTriggering] = useState(false);

  const activeScanCount = MOCK_SCANS.filter((s) => s.status === "running").length;
  const totalFindings = MOCK_SCANS.reduce((s, sc) => s + sc.findings_count, 0);
  const totalCritical = MOCK_SCANS.reduce((s, sc) => s + sc.critical_count, 0);
  const avgFindings = Math.round(totalFindings / MOCK_SCANS.filter((s) => s.status === "completed").length);
  const maxSeverity = Math.max(...SEVERITY_BREAKDOWN.map((s) => s.count));

  function handleTrigger() {
    if (!target) return;
    setTriggering(true);
    setTimeout(() => setTriggering(false), 2000);
  }

  return (
    <div className="flex flex-col gap-6 p-6 min-h-0">
      <PageHeader
        title="Vulnerability Scans"
        description="Scan history, active scans progress, findings severity breakdown across all scanner types"
        badge="Live"
        actions={
          <Button size="sm" variant="outline" className="gap-2">
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <KpiCard title="Total Scans"     value={MOCK_SCANS.length} icon={ScanLine}     trend="up"   trendLabel="last 7 days" />
        <KpiCard title="Active Scans"    value={activeScanCount}   icon={Activity}     trend="up"   trendLabel="currently running" />
        <KpiCard title="Critical Findings" value={totalCritical}   icon={AlertTriangle} trend="down" trendLabel="requires action" />
        <KpiCard title="Avg Findings"    value={avgFindings}       icon={ScanLine}     trend="down" trendLabel="per completed scan" />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Scan History */}
        <Card className="xl:col-span-2">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold">Scan History</CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow className="border-gray-700/50">
                  <TableHead className="text-gray-400 text-xs">Scanner</TableHead>
                  <TableHead className="text-gray-400 text-xs">Target</TableHead>
                  <TableHead className="text-gray-400 text-xs">Status</TableHead>
                  <TableHead className="text-gray-400 text-xs text-right">Findings</TableHead>
                  <TableHead className="text-gray-400 text-xs text-right">Critical</TableHead>
                  <TableHead className="text-gray-400 text-xs">Started</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {MOCK_SCANS.map((scan, i) => (
                  <motion.tr
                    key={scan.id}
                    initial={{ opacity: 0 }}
                    animate={{ opacity: 1 }}
                    transition={{ delay: i * 0.04 }}
                    className="border-b border-gray-700/50 hover:bg-gray-800/30"
                  >
                    <TableCell className="text-sm font-medium text-gray-200">{scan.scanner_type}</TableCell>
                    <TableCell className="font-mono text-xs text-gray-400 max-w-[140px] truncate">{scan.target}</TableCell>
                    <TableCell><ScanStatusBadge status={scan.status} /></TableCell>
                    <TableCell className="text-right text-sm text-gray-300">{scan.findings_count > 0 ? scan.findings_count.toLocaleString() : "—"}</TableCell>
                    <TableCell className="text-right">
                      {scan.critical_count > 0 ? (
                        <span className="text-red-400 font-semibold text-sm">{scan.critical_count}</span>
                      ) : <span className="text-gray-500 text-sm">—</span>}
                    </TableCell>
                    <TableCell className="text-xs text-gray-400">{scan.started_at}</TableCell>
                  </motion.tr>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>

        {/* Right column */}
        <div className="flex flex-col gap-4">
          {/* Severity Breakdown */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold">Findings by Severity</CardTitle>
            </CardHeader>
            <CardContent className="flex flex-col gap-3">
              {SEVERITY_BREAKDOWN.map((sev) => (
                <div key={sev.label} className="flex flex-col gap-1">
                  <div className="flex justify-between text-xs">
                    <span className={sev.textColor}>{sev.label}</span>
                    <span className="text-gray-400">{sev.count.toLocaleString()}</span>
                  </div>
                  <div className="h-2 bg-gray-700 rounded-full overflow-hidden">
                    <motion.div
                      className={cn("h-full rounded-full", sev.color)}
                      initial={{ width: 0 }}
                      animate={{ width: `${(sev.count / maxSeverity) * 100}%` }}
                      transition={{ duration: 0.6, delay: 0.1 }}
                    />
                  </div>
                </div>
              ))}
              <div className="mt-2 pt-2 border-t border-gray-700/50 flex justify-between text-xs">
                <span className="text-gray-400">Total</span>
                <span className="text-gray-200 font-semibold">{SEVERITY_BREAKDOWN.reduce((s, sv) => s + sv.count, 0).toLocaleString()}</span>
              </div>
            </CardContent>
          </Card>

          {/* Trigger Scan Form */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold">Trigger Scan</CardTitle>
            </CardHeader>
            <CardContent className="flex flex-col gap-3">
              <div className="flex flex-col gap-1">
                <label className="text-xs text-gray-400">Scanner Type</label>
                <select
                  value={scannerType}
                  onChange={(e) => setScannerType(e.target.value)}
                  className="bg-gray-700/50 border border-gray-600 rounded px-3 py-1.5 text-sm text-gray-200 focus:outline-none focus:border-blue-500"
                >
                  {SCANNER_TYPES.map((s) => <option key={s} value={s}>{s}</option>)}
                </select>
              </div>
              <div className="flex flex-col gap-1">
                <label className="text-xs text-gray-400">Target (IP, CIDR, or hostname)</label>
                <input
                  type="text"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  placeholder="10.0.0.0/24"
                  className="bg-gray-700/50 border border-gray-600 rounded px-3 py-1.5 text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:border-blue-500"
                />
              </div>
              <Button
                size="sm"
                className="w-full gap-2 bg-blue-600 hover:bg-blue-700 text-white"
                onClick={handleTrigger}
                disabled={!target || triggering}
              >
                {triggering ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
                {triggering ? "Queuing..." : "Start Scan"}
              </Button>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
