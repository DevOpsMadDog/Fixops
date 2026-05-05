/**
 * ZeroDayPanel — ExternalThreatIntelHub "zeroday" tab
 *
 * Wired to real backend:
 *   GET /api/v1/zero-day/stats          → KPI bar
 *   GET /api/v1/zero-day/vulns          → vulnerability table
 *   GET /api/v1/zero-day/threat-actors  → threat actor list
 */

import { useState, useEffect, useCallback } from "react";
import { motion } from "framer-motion";
import { Bug, ShieldAlert, Users, RefreshCw, AlertTriangle, Clock } from "lucide-react";

import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

// ── Types ─────────────────────────────────────────────────────────────────────

interface ZeroDayStats {
  total_vulns?: number;
  critical_vulns?: number;
  unpatched_vulns?: number;
  active_threat_actors?: number;
  org_id?: string;
}

interface ZeroDayVuln {
  vuln_id: string;
  cve_id?: string;
  title?: string;
  cvss_score?: number;
  exploitability_score?: number;
  patch_status?: string;
  exploitation_status?: string;
  disclosure_type?: string;
  created_at?: string;
}

interface ThreatActor {
  actor_id: string;
  name?: string;
  sophistication_level?: string;
  motivation?: string;
  origin_country?: string;
  active?: boolean;
  last_seen?: string;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const SEV_CLASS: Record<string, string> = {
  critical: "bg-red-700/80 text-red-100",
  high: "bg-orange-600/80 text-orange-100",
  medium: "bg-amber-600/80 text-amber-100",
  low: "bg-blue-600/80 text-blue-100",
};

const PATCH_CLASS: Record<string, string> = {
  patched: "bg-emerald-700/60 text-emerald-100",
  partial: "bg-amber-600/60 text-amber-100",
  unpatched: "bg-red-700/60 text-red-100",
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
    for (const k of ["items", "vulns", "vulnerabilities", "actors", "threat_actors", "results", "data"]) {
      if (Array.isArray(obj[k])) return obj[k] as T[];
    }
  }
  return [];
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function ZeroDayPanel() {
  const [stats, setStats] = useState<ZeroDayStats | null>(null);
  const [vulns, setVulns] = useState<ZeroDayVuln[]>([]);
  const [actors, setActors] = useState<ThreatActor[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [subTab, setSubTab] = useState<"vulns" | "actors">("vulns");

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [rawStats, rawVulns, rawActors] = await Promise.all([
        apiFetch<ZeroDayStats>("/api/v1/zero-day/stats"),
        apiFetch<unknown>("/api/v1/zero-day/vulns"),
        apiFetch<unknown>("/api/v1/zero-day/threat-actors"),
      ]);
      setStats(rawStats);
      setVulns(extractArray<ZeroDayVuln>(rawVulns));
      setActors(extractArray<ThreatActor>(rawActors));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load zero-day data");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  if (loading) return <PageSkeleton />;
  if (error) return <ErrorState message={error} onRetry={load} />;

  const kpis = [
    { label: "Total Vulns", value: stats?.total_vulns ?? 0, icon: Bug, color: "text-slate-300" },
    { label: "Critical", value: stats?.critical_vulns ?? 0, icon: AlertTriangle, color: "text-red-400" },
    { label: "Unpatched", value: stats?.unpatched_vulns ?? 0, icon: Clock, color: "text-orange-400" },
    { label: "Active Actors", value: stats?.active_threat_actors ?? 0, icon: Users, color: "text-purple-400" },
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
          <Bug className="h-5 w-5 text-red-400" />
          <span className="font-semibold text-sm">Zero-Day Intelligence</span>
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
        {(["vulns", "actors"] as const).map(t => (
          <button
            key={t}
            onClick={() => setSubTab(t)}
            className={`px-3 py-1 rounded-full text-xs font-medium capitalize transition-colors ${
              subTab === t ? "bg-indigo-600 text-white" : "bg-muted/40 text-muted-foreground hover:bg-muted"
            }`}
          >
            {t === "vulns" ? `Vulnerabilities (${vulns.length})` : `Threat Actors (${actors.length})`}
          </button>
        ))}
      </div>

      {/* Vulns table */}
      {subTab === "vulns" && (
        vulns.length === 0 ? (
          <EmptyState
            icon={Bug}
            title="No zero-day vulnerabilities"
            description="Zero-day and N-day vulnerabilities will appear once threat intelligence feeds are ingested."
          />
        ) : (
          <div className="overflow-x-auto rounded-lg border border-border">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border bg-muted/30">
                  {["CVE ID", "Title", "CVSS", "Exploitability", "Patch Status", "Exploitation", "Disclosure", "Discovered"].map(h => (
                    <th key={h} className="px-3 py-2 text-left font-medium text-muted-foreground">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {vulns.slice(0, 200).map((v, i) => (
                  <tr key={v.vuln_id ?? i} className="border-b border-border/40 hover:bg-muted/20 transition-colors">
                    <td className="px-3 py-2 font-mono font-medium text-indigo-300">{v.cve_id ?? "—"}</td>
                    <td className="px-3 py-2 max-w-xs truncate">{v.title ?? "—"}</td>
                    <td className="px-3 py-2 tabular-nums">
                      <span className={`font-bold ${(v.cvss_score ?? 0) >= 9 ? "text-red-400" : (v.cvss_score ?? 0) >= 7 ? "text-orange-400" : "text-amber-400"}`}>
                        {v.cvss_score?.toFixed(1) ?? "—"}
                      </span>
                    </td>
                    <td className="px-3 py-2 tabular-nums text-muted-foreground">
                      {v.exploitability_score?.toFixed(1) ?? "—"}
                    </td>
                    <td className="px-3 py-2">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${PATCH_CLASS[v.patch_status?.toLowerCase() ?? ""] ?? "bg-muted/40 text-muted-foreground"}`}>
                        {v.patch_status ?? "—"}
                      </span>
                    </td>
                    <td className="px-3 py-2">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${v.exploitation_status === "confirmed" ? "bg-red-700/80 text-red-100" : "bg-muted/40 text-muted-foreground"}`}>
                        {v.exploitation_status ?? "—"}
                      </span>
                    </td>
                    <td className="px-3 py-2 text-muted-foreground capitalize">{v.disclosure_type ?? "—"}</td>
                    <td className="px-3 py-2 text-muted-foreground">
                      {v.created_at ? new Date(v.created_at).toLocaleDateString() : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      )}

      {/* Actors table */}
      {subTab === "actors" && (
        actors.length === 0 ? (
          <EmptyState
            icon={ShieldAlert}
            title="No threat actors tracked"
            description="Threat actor profiles will populate from attribution feeds and intelligence sources."
          />
        ) : (
          <div className="overflow-x-auto rounded-lg border border-border">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border bg-muted/30">
                  {["Name", "Sophistication", "Motivation", "Origin", "Active", "Last Seen"].map(h => (
                    <th key={h} className="px-3 py-2 text-left font-medium text-muted-foreground">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {actors.slice(0, 200).map((a, i) => (
                  <tr key={a.actor_id ?? i} className="border-b border-border/40 hover:bg-muted/20 transition-colors">
                    <td className="px-3 py-2 font-medium">{a.name ?? a.actor_id}</td>
                    <td className="px-3 py-2 text-muted-foreground capitalize">{a.sophistication_level ?? "—"}</td>
                    <td className="px-3 py-2 text-muted-foreground capitalize">{a.motivation ?? "—"}</td>
                    <td className="px-3 py-2 text-muted-foreground">{a.origin_country ?? "—"}</td>
                    <td className="px-3 py-2">
                      <Badge variant="outline" className={`text-[10px] ${a.active ? "border-emerald-500 text-emerald-400" : "border-slate-500 text-slate-400"}`}>
                        {a.active ? "Active" : "Inactive"}
                      </Badge>
                    </td>
                    <td className="px-3 py-2 text-muted-foreground">
                      {a.last_seen ? new Date(a.last_seen).toLocaleString() : "—"}
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
