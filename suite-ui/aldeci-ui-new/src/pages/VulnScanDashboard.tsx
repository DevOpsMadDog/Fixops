/**
 * Vulnerability Scan Dashboard
 * Route: /vuln-scans
 * API: GET /api/v1/vuln-scans/{scans,stats}; POST /scans
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { ScanLine, AlertTriangle, Activity, Play, RefreshCw, Clock, CheckCircle2, XCircle, Loader2 } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { cn } from "@/lib/utils";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";

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

interface SeverityRow { label: string; count: number; color: string; textColor: string; }

const SEVERITY_COLORS = [
  { label: "Critical", color: "bg-red-600", textColor: "text-red-400" },
  { label: "High", color: "bg-orange-500", textColor: "text-orange-400" },
  { label: "Medium", color: "bg-yellow-500", textColor: "text-yellow-400" },
  { label: "Low", color: "bg-blue-500", textColor: "text-blue-400" },
];

const SCANNER_TYPES = ["Nessus", "Qualys", "OpenVAS", "Tenable.io", "Rapid7", "Burp Suite", "OWASP ZAP", "Trivy"];

async function apiFetch<T>(path: string, opts: RequestInit = {}): Promise<T> {
  const orgId = getStoredOrgId() || "verify-test";
  const url = buildApiUrl(path, { org_id: orgId });
  const res = await fetch(url, { ...opts, headers: { "X-API-Key": getStoredAuthToken(), "X-Org-ID": orgId, "Content-Type": "application/json", ...(opts.headers ?? {}) } });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

function ScanStatusBadge({ status }: { status: string }) {
  const map: Record<string, { cls: string; icon: React.ReactNode }> = {
    completed: { cls: "bg-green-500/10 text-green-400 border-green-500/20", icon: <CheckCircle2 className="w-3 h-3" /> },
    running: { cls: "bg-blue-500/10 text-blue-400 border-blue-500/20", icon: <Loader2 className="w-3 h-3 animate-spin" /> },
    failed: { cls: "bg-red-500/10 text-red-400 border-red-500/20", icon: <XCircle className="w-3 h-3" /> },
    queued: { cls: "bg-gray-500/10 text-gray-400 border-gray-500/20", icon: <Clock className="w-3 h-3" /> },
  };
  const { cls, icon } = map[status] ?? { cls: "bg-gray-500/10 text-gray-400", icon: null };
  return <Badge className={cn("border text-xs gap-1 capitalize", cls)}>{icon}{status}</Badge>;
}

export default function VulnScanDashboard() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [scannerType, setScannerType] = useState("Nessus");
  const [target, setTarget] = useState("");
  const [triggering, setTriggering] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const v = await apiFetch<any>("/api/v1/vuln-scans/scans");
      const arr: Scan[] = Array.isArray(v) ? v : (v.scans ?? v.items ?? []);
      setScans(arr);
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  };

  useEffect(() => { load(); }, []);

  const completedScans = scans.filter(s => s.status === "completed");
  const activeScanCount = scans.filter(s => s.status === "running").length;
  const totalFindings = scans.reduce((s, sc) => s + (sc.findings_count ?? 0), 0);
  const totalCritical = scans.reduce((s, sc) => s + (sc.critical_count ?? 0), 0);
  const avgFindings = completedScans.length ? Math.round(totalFindings / completedScans.length) : 0;

  const severityBreakdown: SeverityRow[] = SEVERITY_COLORS.map(({ label, color, textColor }) => {
    const key = label.toLowerCase();
    const count = scans.reduce((s, sc) => {
      if (key === "critical") return s + (sc.critical_count ?? 0);
      if (key === "high") return s + (sc.high_count ?? 0);
      if (key === "medium") return s + (sc.medium_count ?? 0);
      return s + (sc.low_count ?? 0);
    }, 0);
    return { label, count, color, textColor };
  });
  const maxSeverity = Math.max(1, ...severityBreakdown.map(s => s.count));

  async function handleTrigger() {
    if (!target) return;
    setTriggering(true);
    try {
      await apiFetch("/api/v1/vuln-scans/scans", { method: "POST", body: JSON.stringify({ scanner_type: scannerType, target }) });
      setTarget("");
      await load();
    } catch (e) { setError((e as Error).message); }
    finally { setTriggering(false); }
  }

  return (
    <div className="flex flex-col gap-6 p-6 min-h-0">
      <PageHeader
        title="Vulnerability Scans"
        description="Scan history, active scans progress, findings severity breakdown across scanner types"
        badge="Live"
        actions={<Button size="sm" variant="outline" className="gap-2" onClick={load}><RefreshCw className={cn("w-3.5 h-3.5", loading && "animate-spin")} />Refresh</Button>}
      />

      {loading ? (
        <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div></div>
      ) : error ? (
        <ErrorState message={error} onRetry={load} />
      ) : scans.length === 0 ? (
        <EmptyState icon={ScanLine} title="No scans yet" description="Trigger your first scan below to populate this dashboard." />
      ) : (
        <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <KpiCard title="Total Scans" value={scans.length} icon={ScanLine} trend="up" trendLabel="last 7 days" />
            <KpiCard title="Active Scans" value={activeScanCount} icon={Activity} trend="up" trendLabel="currently running" />
            <KpiCard title="Critical Findings" value={totalCritical} icon={AlertTriangle} trend="down" trendLabel="requires action" />
            <KpiCard title="Avg Findings" value={avgFindings} icon={ScanLine} trend="down" trendLabel="per completed scan" />
          </div>

          <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
            <Card className="xl:col-span-2">
              <CardHeader className="pb-3"><CardTitle className="text-sm font-semibold">Scan History</CardTitle></CardHeader>
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
                    {scans.map((scan, i) => (
                      <motion.tr key={scan.id} initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: i * 0.04 }} className="border-b border-gray-700/50 hover:bg-gray-800/30">
                        <TableCell className="text-sm font-medium text-gray-200">{scan.scanner_type}</TableCell>
                        <TableCell className="font-mono text-xs text-gray-400 max-w-[140px] truncate">{scan.target}</TableCell>
                        <TableCell><ScanStatusBadge status={scan.status} /></TableCell>
                        <TableCell className="text-right text-sm text-gray-300">{(scan.findings_count ?? 0) > 0 ? scan.findings_count.toLocaleString() : "—"}</TableCell>
                        <TableCell className="text-right">{(scan.critical_count ?? 0) > 0 ? <span className="text-red-400 font-semibold text-sm">{scan.critical_count}</span> : <span className="text-gray-500 text-sm">—</span>}</TableCell>
                        <TableCell className="text-xs text-gray-400">{scan.started_at}</TableCell>
                      </motion.tr>
                    ))}
                  </TableBody>
                </Table>
              </CardContent>
            </Card>

            <div className="flex flex-col gap-4">
              <Card>
                <CardHeader className="pb-3"><CardTitle className="text-sm font-semibold">Findings by Severity</CardTitle></CardHeader>
                <CardContent className="flex flex-col gap-3">
                  {severityBreakdown.map(sev => (
                    <div key={sev.label} className="flex flex-col gap-1">
                      <div className="flex justify-between text-xs">
                        <span className={sev.textColor}>{sev.label}</span>
                        <span className="text-gray-400">{sev.count.toLocaleString()}</span>
                      </div>
                      <div className="h-2 bg-gray-700 rounded-full overflow-hidden">
                        <motion.div className={cn("h-full rounded-full", sev.color)} initial={{ width: 0 }} animate={{ width: `${(sev.count / maxSeverity) * 100}%` }} transition={{ duration: 0.6, delay: 0.1 }} />
                      </div>
                    </div>
                  ))}
                  <div className="mt-2 pt-2 border-t border-gray-700/50 flex justify-between text-xs">
                    <span className="text-gray-400">Total</span>
                    <span className="text-gray-200 font-semibold">{severityBreakdown.reduce((s, sv) => s + sv.count, 0).toLocaleString()}</span>
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader className="pb-3"><CardTitle className="text-sm font-semibold">Trigger Scan</CardTitle></CardHeader>
                <CardContent className="flex flex-col gap-3">
                  <div className="flex flex-col gap-1">
                    <label className="text-xs text-gray-400">Scanner Type</label>
                    <select value={scannerType} onChange={e => setScannerType(e.target.value)}
                      className="bg-gray-700/50 border border-gray-600 rounded px-3 py-1.5 text-sm text-gray-200 focus:outline-none focus:border-blue-500">
                      {SCANNER_TYPES.map(s => <option key={s} value={s}>{s}</option>)}
                    </select>
                  </div>
                  <div className="flex flex-col gap-1">
                    <label className="text-xs text-gray-400">Target</label>
                    <input type="text" value={target} onChange={e => setTarget(e.target.value)} placeholder="10.0.0.0/24"
                      className="bg-gray-700/50 border border-gray-600 rounded px-3 py-1.5 text-sm text-gray-200 placeholder-gray-500 focus:outline-none focus:border-blue-500" />
                  </div>
                  <Button size="sm" className="w-full gap-2 bg-blue-600 hover:bg-blue-700 text-white" onClick={handleTrigger} disabled={!target || triggering}>
                    {triggering ? <Loader2 className="w-3.5 h-3.5 animate-spin" /> : <Play className="w-3.5 h-3.5" />}
                    {triggering ? "Queuing..." : "Start Scan"}
                  </Button>
                </CardContent>
              </Card>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
