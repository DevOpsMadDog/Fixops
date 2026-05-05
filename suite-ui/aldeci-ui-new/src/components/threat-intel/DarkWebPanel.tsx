/**
 * DarkWebPanel — ExternalThreatIntelHub "darkweb" tab
 *
 * Wired to real backend:
 *   GET /api/v1/dark-web/stats      → KPI bar
 *   GET /api/v1/dark-web/mentions   → mentions table
 *   GET /api/v1/dark-web/exposures  → credential exposures table
 */

import { useState, useEffect, useCallback } from "react";
import { motion } from "framer-motion";
import { Eye, KeyRound, MessageSquareWarning, RefreshCw, Globe } from "lucide-react";

import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

// ── Types ─────────────────────────────────────────────────────────────────────

interface DarkWebStats {
  total_mentions?: number;
  active_alerts?: number;
  credential_exposures?: number;
  monitored_keywords?: number;
  org_id?: string;
}

interface DarkWebMention {
  mention_id: string;
  mention_type?: string;
  source_category?: string;
  keyword_matched?: string;
  severity?: string;
  content_preview?: string;
  status?: string;
  created_at?: string;
}

interface CredentialExposure {
  exposure_id: string;
  username?: string;
  email?: string;
  source?: string;
  exposure_type?: string;
  severity?: string;
  status?: string;
  discovered_at?: string;
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const SEV_CLASS: Record<string, string> = {
  critical: "bg-red-700/80 text-red-100",
  high: "bg-orange-600/80 text-orange-100",
  medium: "bg-amber-600/80 text-amber-100",
  low: "bg-blue-600/80 text-blue-100",
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
    for (const k of ["items", "mentions", "exposures", "credential_exposures", "results", "data"]) {
      if (Array.isArray(obj[k])) return obj[k] as T[];
    }
  }
  return [];
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function DarkWebPanel() {
  const [stats, setStats] = useState<DarkWebStats | null>(null);
  const [mentions, setMentions] = useState<DarkWebMention[]>([]);
  const [exposures, setExposures] = useState<CredentialExposure[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [subTab, setSubTab] = useState<"mentions" | "exposures">("mentions");

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [rawStats, rawMentions, rawExposures] = await Promise.all([
        apiFetch<DarkWebStats>("/api/v1/dark-web/stats"),
        apiFetch<unknown>("/api/v1/dark-web/mentions"),
        apiFetch<unknown>("/api/v1/dark-web/exposures"),
      ]);
      setStats(rawStats);
      setMentions(extractArray<DarkWebMention>(rawMentions));
      setExposures(extractArray<CredentialExposure>(rawExposures));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load dark web data");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  if (loading) return <PageSkeleton />;
  if (error) return <ErrorState message={error} onRetry={load} />;

  const kpis = [
    { label: "Total Mentions", value: stats?.total_mentions ?? 0, icon: MessageSquareWarning, color: "text-slate-300" },
    { label: "Active Alerts", value: stats?.active_alerts ?? 0, icon: Eye, color: "text-red-400" },
    { label: "Credential Exposures", value: stats?.credential_exposures ?? 0, icon: KeyRound, color: "text-orange-400" },
    { label: "Monitored Keywords", value: stats?.monitored_keywords ?? 0, icon: Globe, color: "text-indigo-400" },
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
          <Eye className="h-5 w-5 text-purple-400" />
          <span className="font-semibold text-sm">Dark Web Monitoring</span>
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
        {(["mentions", "exposures"] as const).map(t => (
          <button
            key={t}
            onClick={() => setSubTab(t)}
            className={`px-3 py-1 rounded-full text-xs font-medium capitalize transition-colors ${
              subTab === t ? "bg-indigo-600 text-white" : "bg-muted/40 text-muted-foreground hover:bg-muted"
            }`}
          >
            {t === "mentions" ? `Mentions (${mentions.length})` : `Credential Exposures (${exposures.length})`}
          </button>
        ))}
      </div>

      {/* Mentions table */}
      {subTab === "mentions" && (
        mentions.length === 0 ? (
          <EmptyState
            icon={Eye}
            title="No dark web mentions"
            description="Dark web keyword alerts and mentions will appear once monitoring feeds are active."
          />
        ) : (
          <div className="overflow-x-auto rounded-lg border border-border">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border bg-muted/30">
                  {["Type", "Source", "Keyword", "Severity", "Status", "Preview", "Detected"].map(h => (
                    <th key={h} className="px-3 py-2 text-left font-medium text-muted-foreground">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {mentions.slice(0, 200).map((m, i) => (
                  <tr key={m.mention_id ?? i} className="border-b border-border/40 hover:bg-muted/20 transition-colors">
                    <td className="px-3 py-2 font-medium capitalize">{m.mention_type ?? "—"}</td>
                    <td className="px-3 py-2 text-muted-foreground capitalize">{m.source_category ?? "—"}</td>
                    <td className="px-3 py-2 font-mono text-indigo-300">{m.keyword_matched ?? "—"}</td>
                    <td className="px-3 py-2">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${SEV_CLASS[m.severity?.toLowerCase() ?? ""] ?? "bg-muted/40 text-muted-foreground"}`}>
                        {m.severity ?? "—"}
                      </span>
                    </td>
                    <td className="px-3 py-2">
                      <Badge variant="outline" className="text-[10px]">{m.status ?? "—"}</Badge>
                    </td>
                    <td className="px-3 py-2 max-w-xs truncate text-muted-foreground">{m.content_preview ?? "—"}</td>
                    <td className="px-3 py-2 text-muted-foreground">
                      {m.created_at ? new Date(m.created_at).toLocaleDateString() : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      )}

      {/* Exposures table */}
      {subTab === "exposures" && (
        exposures.length === 0 ? (
          <EmptyState
            icon={KeyRound}
            title="No credential exposures"
            description="Exposed credentials found on dark web marketplaces and paste sites will appear here."
          />
        ) : (
          <div className="overflow-x-auto rounded-lg border border-border">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border bg-muted/30">
                  {["Username / Email", "Source", "Type", "Severity", "Status", "Discovered"].map(h => (
                    <th key={h} className="px-3 py-2 text-left font-medium text-muted-foreground">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {exposures.slice(0, 200).map((e, i) => (
                  <tr key={e.exposure_id ?? i} className="border-b border-border/40 hover:bg-muted/20 transition-colors">
                    <td className="px-3 py-2 font-medium">{e.email ?? e.username ?? "—"}</td>
                    <td className="px-3 py-2 text-muted-foreground">{e.source ?? "—"}</td>
                    <td className="px-3 py-2 capitalize text-muted-foreground">{e.exposure_type ?? "—"}</td>
                    <td className="px-3 py-2">
                      <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${SEV_CLASS[e.severity?.toLowerCase() ?? ""] ?? "bg-muted/40 text-muted-foreground"}`}>
                        {e.severity ?? "—"}
                      </span>
                    </td>
                    <td className="px-3 py-2">
                      <Badge variant="outline" className="text-[10px]">{e.status ?? "—"}</Badge>
                    </td>
                    <td className="px-3 py-2 text-muted-foreground">
                      {e.discovered_at ? new Date(e.discovered_at).toLocaleDateString() : "—"}
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
