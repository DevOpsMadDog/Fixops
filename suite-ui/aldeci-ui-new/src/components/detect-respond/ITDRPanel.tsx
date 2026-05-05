/**
 * ITDRPanel — DetectAndRespondHub "itdr" tab
 *
 * Wired to real backend:
 *   GET /api/v1/digital-identity/stats    → KPI bar
 *   GET /api/v1/digital-identity/profiles → identity profiles table
 */

import { useState, useEffect, useCallback } from "react";
import { motion } from "framer-motion";
import { ShieldAlert, UserCheck, UserX, Users, RefreshCw } from "lucide-react";

import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

// ── Types ─────────────────────────────────────────────────────────────────────

interface ITDRStats {
  total_profiles?: number;
  verified_profiles?: number;
  suspended_profiles?: number;
  pending_profiles?: number;
  org_id?: string;
}

interface IdentityProfile {
  user_id?: string;
  identity_level?: string;
  verification_status?: string;
  verification_method?: string;
  assurance_level?: string;
  created_at?: string;
  updated_at?: string;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const LEVEL_CLASS: Record<string, string> = {
  ial1: "bg-blue-600/80 text-blue-100",
  ial2: "bg-emerald-600/80 text-emerald-100",
  ial3: "bg-indigo-600/80 text-indigo-100",
};

const STATUS_CLASS: Record<string, string> = {
  verified: "text-emerald-400",
  suspended: "text-red-400",
  pending: "text-amber-400",
  unverified: "text-slate-400",
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
    for (const k of ["profiles", "items", "results", "data"]) {
      if (Array.isArray(obj[k])) return obj[k] as T[];
    }
  }
  return [];
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function ITDRPanel() {
  const [stats, setStats] = useState<ITDRStats | null>(null);
  const [profiles, setProfiles] = useState<IdentityProfile[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<string>("all");

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [rawStats, rawProfiles] = await Promise.all([
        apiFetch<ITDRStats>("/api/v1/digital-identity/stats"),
        apiFetch<unknown>("/api/v1/digital-identity/profiles"),
      ]);
      setStats(rawStats);
      setProfiles(extractArray<IdentityProfile>(rawProfiles));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load ITDR data");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  if (loading) return <PageSkeleton />;
  if (error) return <ErrorState message={error} onRetry={load} />;

  const kpis = [
    { label: "Total Identities", value: stats?.total_profiles ?? profiles.length, icon: Users, color: "text-slate-300" },
    { label: "Verified", value: stats?.verified_profiles ?? profiles.filter(p => p.verification_status === "verified").length, icon: UserCheck, color: "text-emerald-400" },
    { label: "Suspended", value: stats?.suspended_profiles ?? profiles.filter(p => p.verification_status === "suspended").length, icon: UserX, color: "text-red-400" },
    { label: "Pending", value: stats?.pending_profiles ?? profiles.filter(p => p.verification_status === "pending").length, icon: ShieldAlert, color: "text-amber-400" },
  ];

  const statuses = ["all", "verified", "pending", "suspended", "unverified"];
  const filtered = statusFilter === "all" ? profiles : profiles.filter(p => p.verification_status === statusFilter);

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
          <ShieldAlert className="h-5 w-5 text-indigo-400" />
          <span className="font-semibold text-sm">ITDR — Identity Threat Detection & Response</span>
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
              {typeof value === "number" ? value.toLocaleString() : value}
            </span>
          </div>
        ))}
      </div>

      {/* Status filter */}
      <div className="flex gap-2 flex-wrap">
        {statuses.map(s => (
          <button
            key={s}
            onClick={() => setStatusFilter(s)}
            className={`px-3 py-1 rounded-full text-xs font-medium capitalize transition-colors ${
              statusFilter === s ? "bg-indigo-600 text-white" : "bg-muted/40 text-muted-foreground hover:bg-muted"
            }`}
          >
            {s === "all" ? `All (${profiles.length})` : `${s} (${profiles.filter(p => p.verification_status === s).length})`}
          </button>
        ))}
      </div>

      {/* Profiles table */}
      {filtered.length === 0 ? (
        <EmptyState
          icon={Users}
          title="No identity profiles"
          description="Identity profiles will appear once users are enrolled via the digital identity engine."
        />
      ) : (
        <div className="overflow-x-auto rounded-lg border border-border">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border bg-muted/30">
                {["User ID", "Identity Level", "Status", "Method", "Assurance", "Created"].map(h => (
                  <th key={h} className="px-3 py-2 text-left font-medium text-muted-foreground">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {filtered.slice(0, 200).map((p, i) => (
                <tr key={p.user_id ?? i} className="border-b border-border/40 hover:bg-muted/20 transition-colors">
                  <td className="px-3 py-2 font-medium font-mono text-[10px]">{p.user_id ?? "—"}</td>
                  <td className="px-3 py-2">
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${LEVEL_CLASS[p.identity_level?.toLowerCase() ?? ""] ?? "bg-muted/40 text-muted-foreground"}`}>
                      {p.identity_level ?? "—"}
                    </span>
                  </td>
                  <td className="px-3 py-2">
                    <Badge variant="outline" className={`text-[10px] ${STATUS_CLASS[p.verification_status?.toLowerCase() ?? ""] ?? ""}`}>
                      {p.verification_status ?? "—"}
                    </Badge>
                  </td>
                  <td className="px-3 py-2 text-muted-foreground capitalize">{p.verification_method?.replace(/_/g, " ") ?? "—"}</td>
                  <td className="px-3 py-2 text-muted-foreground uppercase">{p.assurance_level ?? "—"}</td>
                  <td className="px-3 py-2 text-muted-foreground">
                    {p.created_at ? new Date(p.created_at).toLocaleString() : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </motion.div>
  );
}
