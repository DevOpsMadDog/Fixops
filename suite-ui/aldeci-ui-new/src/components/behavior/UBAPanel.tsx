/**
 * UBAPanel — BehaviorAnalyticsHub "uba" tab
 *
 * Wired to real backend:
 *   GET /api/v1/uba/stats   → KPI bar (total_users, high_risk_users, open_alerts, anomalous_events)
 *   GET /api/v1/uba/users   → risk-scored user table
 *   GET /api/v1/uba/alerts  → open alerts list
 */

import { useState, useEffect, useCallback } from "react";
import { motion } from "framer-motion";
import { Users, AlertTriangle, Activity, RefreshCw, ShieldAlert } from "lucide-react";

import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

// ── Types ─────────────────────────────────────────────────────────────────────

interface UBAStats {
  total_users?: number;
  high_risk_users?: number;
  open_alerts?: number;
  anomalous_events?: number;
  org_id?: string;
}

interface UBAUser {
  user_id: string;
  username?: string;
  department?: string;
  role?: string;
  risk_score?: number;
  status?: string;
  last_seen?: string;
}

interface UBAAlert {
  alert_id: string;
  user_id?: string;
  alert_type?: string;
  severity?: string;
  description?: string;
  status?: string;
  created_at?: string;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const SEV_CLASS: Record<string, string> = {
  critical: "bg-red-700/80 text-red-100",
  high: "bg-orange-600/80 text-orange-100",
  medium: "bg-amber-600/80 text-amber-100",
  low: "bg-blue-600/80 text-blue-100",
};

const RISK_COLOR = (score: number) => {
  if (score >= 80) return "text-red-400";
  if (score >= 60) return "text-orange-400";
  if (score >= 40) return "text-amber-400";
  return "text-emerald-400";
};

async function apiFetch<T>(path: string, params?: Record<string, string>): Promise<T> {
  const orgId = getStoredOrgId() || "default";
  const url = buildApiUrl(path, { org_id: orgId, ...params });
  const res = await fetch(url, {
    headers: {
      "X-API-Key": getStoredAuthToken(),
      "X-Org-ID": orgId,
    },
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

function extractArray<T>(data: unknown): T[] {
  if (Array.isArray(data)) return data as T[];
  if (data && typeof data === "object") {
    const obj = data as Record<string, unknown>;
    for (const k of ["items", "users", "alerts", "results", "data"]) {
      if (Array.isArray(obj[k])) return obj[k] as T[];
    }
  }
  return [];
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function UBAPanel() {
  const [stats, setStats] = useState<UBAStats | null>(null);
  const [users, setUsers] = useState<UBAUser[]>([]);
  const [alerts, setAlerts] = useState<UBAAlert[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<"users" | "alerts">("users");

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [rawStats, rawUsers, rawAlerts] = await Promise.all([
        apiFetch<UBAStats>("/api/v1/uba/stats"),
        apiFetch<unknown>("/api/v1/uba/users"),
        apiFetch<unknown>("/api/v1/uba/alerts"),
      ]);
      setStats(rawStats);
      setUsers(extractArray<UBAUser>(rawUsers));
      setAlerts(extractArray<UBAAlert>(rawAlerts));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load UBA data");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  if (loading) return <PageSkeleton />;
  if (error) return <ErrorState message={error} onRetry={load} />;

  const kpis = [
    { label: "Total Users", value: stats?.total_users ?? 0, icon: Users, color: "text-slate-300" },
    { label: "High Risk", value: stats?.high_risk_users ?? 0, icon: ShieldAlert, color: "text-red-400" },
    { label: "Open Alerts", value: stats?.open_alerts ?? 0, icon: AlertTriangle, color: "text-orange-400" },
    { label: "Anomalous Events", value: stats?.anomalous_events ?? 0, icon: Activity, color: "text-amber-400" },
  ];

  return (
    <motion.div
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25 }}
      className="flex flex-col gap-5"
    >
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-2">
          <Users className="h-5 w-5 text-indigo-400" />
          <span className="font-semibold text-sm">User Behavior Analytics</span>
        </div>
        <Button variant="outline" size="sm" onClick={load} className="gap-1.5">
          <RefreshCw className="h-3.5 w-3.5" /> Refresh
        </Button>
      </div>

      {/* KPI bar */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {kpis.map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="rounded-lg bg-muted/40 border border-border px-4 py-3 flex flex-col gap-1">
            <div className="flex items-center gap-1.5 text-muted-foreground">
              <Icon className={`h-3.5 w-3.5 ${color}`} />
              <span className="text-xs">{label}</span>
            </div>
            <span className={`text-2xl font-bold tabular-nums ${color}`}>
              {value.toLocaleString()}
            </span>
          </div>
        ))}
      </div>

      {/* Sub-tab switcher */}
      <div className="flex gap-2">
        {(["users", "alerts"] as const).map(t => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-3 py-1 rounded-full text-xs font-medium capitalize transition-colors ${
              tab === t ? "bg-indigo-600 text-white" : "bg-muted/40 text-muted-foreground hover:bg-muted"
            }`}
          >
            {t === "users" ? `Users (${users.length})` : `Alerts (${alerts.length})`}
          </button>
        ))}
      </div>

      {/* Users table */}
      {tab === "users" && (
        users.length === 0 ? (
          <EmptyState icon={Users} title="No users tracked" description="UBA will populate once user events are ingested." />
        ) : (
          <div className="overflow-x-auto rounded-lg border border-border">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border bg-muted/30">
                  {["Username", "Department", "Role", "Risk Score", "Status", "Last Seen"].map(h => (
                    <th key={h} className="px-3 py-2 text-left font-medium text-muted-foreground">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {users.slice(0, 200).map((u, i) => (
                  <tr key={u.user_id ?? i} className="border-b border-border/40 hover:bg-muted/20 transition-colors">
                    <td className="px-3 py-2 font-medium">{u.username ?? u.user_id}</td>
                    <td className="px-3 py-2 text-muted-foreground">{u.department ?? "—"}</td>
                    <td className="px-3 py-2 text-muted-foreground">{u.role ?? "—"}</td>
                    <td className="px-3 py-2">
                      <span className={`font-bold tabular-nums ${RISK_COLOR(u.risk_score ?? 0)}`}>
                        {u.risk_score ?? 0}
                      </span>
                    </td>
                    <td className="px-3 py-2">
                      <Badge variant="outline" className="text-[10px]">{u.status ?? "—"}</Badge>
                    </td>
                    <td className="px-3 py-2 text-muted-foreground">
                      {u.last_seen ? new Date(u.last_seen).toLocaleString() : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      )}

      {/* Alerts table */}
      {tab === "alerts" && (
        alerts.length === 0 ? (
          <EmptyState icon={AlertTriangle} title="No alerts" description="UBA alerts will appear when anomalous user behavior is detected." />
        ) : (
          <div className="overflow-x-auto rounded-lg border border-border">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border bg-muted/30">
                  {["Type", "User", "Severity", "Status", "Description", "Created"].map(h => (
                    <th key={h} className="px-3 py-2 text-left font-medium text-muted-foreground">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {alerts.slice(0, 200).map((a, i) => (
                  <tr key={a.alert_id ?? i} className="border-b border-border/40 hover:bg-muted/20 transition-colors">
                    <td className="px-3 py-2 font-medium">{a.alert_type ?? "—"}</td>
                    <td className="px-3 py-2 text-muted-foreground">{a.user_id ?? "—"}</td>
                    <td className="px-3 py-2">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${SEV_CLASS[a.severity?.toLowerCase() ?? ""] ?? "bg-muted/40 text-muted-foreground"}`}>
                        {a.severity ?? "—"}
                      </span>
                    </td>
                    <td className="px-3 py-2">
                      <Badge variant="outline" className="text-[10px]">{a.status ?? "—"}</Badge>
                    </td>
                    <td className="px-3 py-2 max-w-xs truncate text-muted-foreground">{a.description ?? "—"}</td>
                    <td className="px-3 py-2 text-muted-foreground">
                      {a.created_at ? new Date(a.created_at).toLocaleString() : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      )}
    </motion.div>
  );
}
