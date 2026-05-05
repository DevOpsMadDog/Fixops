/**
 * ProwlerPanel — IntegrationTargetsHub "prowler" tab
 *
 * Wired to real backend:
 *   GET /api/v1/prowler/summary        → KPI bar (total, pass, fail, critical)
 *   GET /api/v1/prowler/findings       → findings table (severity-filtered)
 *   GET /api/v1/prowler/status         → scanner health badge
 *   POST /api/v1/prowler/scan          → trigger scan button
 */

import { useState, useEffect, useCallback } from "react";
import { motion } from "framer-motion";
import { Cloud, RefreshCw, Play, CheckCircle2, XCircle, AlertTriangle } from "lucide-react";

import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

// ── Types ─────────────────────────────────────────────────────────────────────

interface ProwlerSummary {
  total_findings: number;
  pass_count: number;
  fail_count: number;
  critical_count: number;
  high_count?: number;
  medium_count?: number;
  low_count?: number;
}

interface ProwlerFinding {
  id: string;
  check_id?: string;
  title?: string;
  description?: string;
  severity: string;
  status: string;
  resource?: string;
  region?: string;
  provider?: string;
  timestamp?: string;
}

interface ProwlerStatus {
  status: string;
  prowler_available?: boolean;
  last_scan?: string;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const SEV_CLASS: Record<string, string> = {
  critical: "bg-red-700/80 text-red-100",
  high: "bg-orange-600/80 text-orange-100",
  medium: "bg-amber-600/80 text-amber-100",
  low: "bg-blue-600/80 text-blue-100",
  informational: "bg-slate-600/80 text-slate-200",
};

const STATUS_CLASS: Record<string, string> = {
  FAIL: "bg-red-700/70 text-red-100",
  PASS: "bg-emerald-700/70 text-emerald-100",
  MUTED: "bg-slate-600/70 text-slate-300",
};

async function apiFetch<T>(path: string, init?: RequestInit): Promise<T> {
  const orgId = getStoredOrgId() || "default";
  const url = buildApiUrl(path, { org_id: orgId });
  const res = await fetch(url, {
    ...init,
    headers: {
      "X-API-Key": getStoredAuthToken(),
      "X-Org-ID": orgId,
      ...(init?.headers ?? {}),
    },
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

function extractFindings(data: unknown): ProwlerFinding[] {
  if (Array.isArray(data)) return data as ProwlerFinding[];
  if (data && typeof data === "object") {
    const obj = data as Record<string, unknown>;
    for (const k of ["findings", "items", "results", "data"]) {
      if (Array.isArray(obj[k])) return obj[k] as ProwlerFinding[];
    }
  }
  return [];
}

// ── Component ─────────────────────────────────────────────────────────────────

const SEVERITY_FILTERS = ["all", "critical", "high", "medium", "low"];

export default function ProwlerPanel() {
  const [summary, setSummary] = useState<ProwlerSummary | null>(null);
  const [findings, setFindings] = useState<ProwlerFinding[]>([]);
  const [scannerStatus, setScannerStatus] = useState<ProwlerStatus | null>(null);
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [scanning, setScanning] = useState(false);
  const [scanMsg, setScanMsg] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [sum, find, stat] = await Promise.all([
        apiFetch<unknown>("/api/v1/prowler/summary"),
        apiFetch<unknown>("/api/v1/prowler/findings"),
        apiFetch<ProwlerStatus>("/api/v1/prowler/status"),
      ]);
      setSummary(sum as ProwlerSummary);
      setFindings(extractFindings(find));
      setScannerStatus(stat);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load Prowler data");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const triggerScan = async () => {
    setScanning(true);
    setScanMsg(null);
    try {
      const orgId = getStoredOrgId() || "default";
      await apiFetch("/api/v1/prowler/scan", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ org_id: orgId, provider: "aws" }),
      });
      setScanMsg("Scan triggered — findings will update shortly.");
      setTimeout(() => load(), 3000);
    } catch (e) {
      setScanMsg(`Scan failed: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setScanning(false);
    }
  };

  const filtered = severityFilter === "all"
    ? findings
    : findings.filter(f => f.severity?.toLowerCase() === severityFilter);

  if (loading) return <PageSkeleton />;
  if (error) return <ErrorState message={error} onRetry={load} />;

  const healthOk = scannerStatus?.status === "ok" || scannerStatus?.prowler_available === true;

  return (
    <motion.div
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25 }}
      className="flex flex-col gap-5"
    >
      {/* Header row */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-2">
          <Cloud className="h-5 w-5 text-indigo-400" />
          <span className="font-semibold text-sm">Prowler CSPM</span>
          <Badge
            variant="outline"
            className={healthOk
              ? "border-emerald-600 text-emerald-400"
              : "border-amber-600 text-amber-400"}
          >
            {healthOk ? "Healthy" : "Unavailable"}
          </Badge>
          {scannerStatus?.last_scan && (
            <span className="text-xs text-muted-foreground">
              Last scan: {new Date(scannerStatus.last_scan).toLocaleString()}
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={load} className="gap-1.5">
            <RefreshCw className="h-3.5 w-3.5" /> Refresh
          </Button>
          <Button
            size="sm"
            className="gap-1.5 bg-indigo-600 hover:bg-indigo-500"
            onClick={triggerScan}
            disabled={scanning}
          >
            <Play className="h-3.5 w-3.5" />
            {scanning ? "Triggering…" : "Run Scan"}
          </Button>
        </div>
      </div>

      {scanMsg && (
        <p className="text-xs text-muted-foreground bg-muted/40 px-3 py-2 rounded-md">
          {scanMsg}
        </p>
      )}

      {/* KPI bar */}
      {summary && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            { label: "Total Checks", value: summary.total_findings, icon: Cloud, color: "text-slate-300" },
            { label: "Passing", value: summary.pass_count, icon: CheckCircle2, color: "text-emerald-400" },
            { label: "Failing", value: summary.fail_count, icon: XCircle, color: "text-red-400" },
            { label: "Critical", value: summary.critical_count, icon: AlertTriangle, color: "text-red-500" },
          ].map(({ label, value, icon: Icon, color }) => (
            <div key={label} className="rounded-lg bg-muted/40 border border-border px-4 py-3 flex flex-col gap-1">
              <div className="flex items-center gap-1.5 text-muted-foreground">
                <Icon className={`h-3.5 w-3.5 ${color}`} />
                <span className="text-xs">{label}</span>
              </div>
              <span className={`text-2xl font-bold tabular-nums ${color}`}>
                {(value ?? 0).toLocaleString()}
              </span>
            </div>
          ))}
        </div>
      )}

      {/* Severity filter */}
      <div className="flex items-center gap-2 flex-wrap">
        {SEVERITY_FILTERS.map(f => (
          <button
            key={f}
            onClick={() => setSeverityFilter(f)}
            className={`px-3 py-1 rounded-full text-xs font-medium capitalize transition-colors ${
              severityFilter === f
                ? "bg-indigo-600 text-white"
                : "bg-muted/40 text-muted-foreground hover:bg-muted"
            }`}
          >
            {f}
          </button>
        ))}
        <span className="text-xs text-muted-foreground ml-auto">
          {filtered.length} finding{filtered.length !== 1 ? "s" : ""}
        </span>
      </div>

      {/* Findings table */}
      {filtered.length === 0 ? (
        <EmptyState
          icon={<CheckCircle2 className="h-8 w-8 text-emerald-400" />}
          title="No findings"
          description="No Prowler findings match the selected filter."
        />
      ) : (
        <div className="overflow-x-auto rounded-lg border border-border">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border bg-muted/30">
                {["Check / Title", "Severity", "Status", "Resource", "Region"].map(h => (
                  <th key={h} className="px-3 py-2 text-left font-medium text-muted-foreground">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.slice(0, 200).map((f, i) => (
                <tr
                  key={f.id ?? i}
                  className="border-b border-border/40 hover:bg-muted/20 transition-colors"
                >
                  <td className="px-3 py-2 max-w-xs truncate font-medium">
                    {f.title ?? f.check_id ?? f.id}
                  </td>
                  <td className="px-3 py-2">
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${SEV_CLASS[f.severity?.toLowerCase()] ?? SEV_CLASS.low}`}>
                      {f.severity ?? "—"}
                    </span>
                  </td>
                  <td className="px-3 py-2">
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold ${STATUS_CLASS[f.status] ?? "bg-muted/40 text-muted-foreground"}`}>
                      {f.status ?? "—"}
                    </span>
                  </td>
                  <td className="px-3 py-2 max-w-[160px] truncate text-muted-foreground">
                    {f.resource ?? "—"}
                  </td>
                  <td className="px-3 py-2 text-muted-foreground">{f.region ?? "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </motion.div>
  );
}
