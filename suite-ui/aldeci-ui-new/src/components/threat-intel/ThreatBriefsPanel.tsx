/**
 * ThreatBriefsPanel — distributed threat briefs with TLP classification
 * API: GET /api/v1/threat-briefs/briefs + /stats
 * Used by ThreatIntelOpsHub "briefs" tab.
 */

import { useEffect, useState } from "react";
import { FileText, AlertTriangle, RefreshCw, Lock } from "lucide-react";
import { threatBriefsApi } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";

interface Brief {
  brief_id?: string;
  id?: string;
  title?: string;
  brief_type?: string;
  tlp?: string;
  summary?: string;
  published_at?: string;
  recipient_count?: number;
  severity?: string;
  tags?: string[];
  author?: string;
}

interface BriefStats {
  total_briefs?: number;
  by_type?: Record<string, number>;
  by_tlp?: Record<string, number>;
  published_last_7d?: number;
  total_recipients?: number;
}

const TLP_PILL: Record<string, string> = {
  white:  "bg-gray-700/40 text-gray-300",
  green:  "bg-green-700/40 text-green-300",
  amber:  "bg-amber-700/40 text-amber-300",
  red:    "bg-red-700/40 text-red-300",
};

const SEV_PILL: Record<string, string> = {
  critical: "bg-red-700/40 text-red-300",
  high:     "bg-orange-700/40 text-orange-300",
  medium:   "bg-amber-700/40 text-amber-300",
  low:      "bg-green-700/40 text-green-300",
};

function tlpPill(tlp: string) {
  return TLP_PILL[tlp?.toLowerCase()] ?? "bg-gray-700/40 text-gray-400";
}

function sevPill(sev: string) {
  return SEV_PILL[sev?.toLowerCase()] ?? "bg-gray-700/40 text-gray-400";
}

export function ThreatBriefsPanel() {
  const [stats, setStats]   = useState<BriefStats | null>(null);
  const [briefs, setBriefs] = useState<Brief[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError]   = useState<string | null>(null);
  const [tlpFilter, setTlpFilter] = useState<string>("");

  const load = async (tlp?: string) => {
    setLoading(true);
    setError(null);
    try {
      const [statsRes, briefsRes] = await Promise.allSettled([
        threatBriefsApi.stats(),
        threatBriefsApi.list(undefined, tlp || undefined),
      ]);
      if (statsRes.status === "fulfilled") setStats(statsRes.value.data as BriefStats);
      if (briefsRes.status === "fulfilled") {
        const d = briefsRes.value.data;
        setBriefs(Array.isArray(d) ? d : (d?.briefs ?? d?.items ?? []));
      }
      if (statsRes.status === "rejected" && briefsRes.status === "rejected") {
        throw new Error("Failed to load threat briefs");
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  const applyTlpFilter = (tlp: string) => {
    setTlpFilter(tlp);
    load(tlp);
  };

  if (loading) {
    return (
      <div className="space-y-3 p-4 animate-pulse">
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[1, 2, 3, 4].map(i => <div key={i} className="h-20 rounded-lg bg-muted/40" />)}
        </div>
        {[1, 2, 3].map(i => <div key={i} className="h-24 rounded bg-muted/30" />)}
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center gap-2 rounded-xl border border-destructive/40 bg-destructive/10 p-4 text-destructive text-sm">
        <AlertTriangle className="h-4 w-4 shrink-0" />
        {error}
      </div>
    );
  }

  if (!stats && briefs.length === 0) {
    return (
      <EmptyState
        icon={FileText}
        title="No threat briefs"
        description="Publish a threat brief via POST /api/v1/threat-briefs/briefs."
      />
    );
  }

  const tlpOptions = stats?.by_tlp ? Object.keys(stats.by_tlp) : [];

  return (
    <div className="space-y-6">
      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            { label: "Total Briefs",    value: stats.total_briefs ?? briefs.length, color: "text-foreground" },
            { label: "Last 7 Days",     value: stats.published_last_7d ?? 0,        color: "text-indigo-400" },
            { label: "Total Recipients",value: (stats.total_recipients ?? 0).toLocaleString(), color: "text-sky-400" },
            { label: "Types",           value: Object.keys(stats.by_type ?? {}).length, color: "text-amber-400" },
          ].map(({ label, value, color }) => (
            <div key={label} className="rounded-lg border border-border bg-muted/30 p-3">
              <p className="text-xs text-muted-foreground">{label}</p>
              <p className={`text-2xl font-semibold mt-0.5 ${color}`}>{value}</p>
            </div>
          ))}
        </div>
      )}

      {/* TLP filter chips */}
      {tlpOptions.length > 0 && (
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-xs text-muted-foreground flex items-center gap-1">
            <Lock className="h-3 w-3" /> TLP:
          </span>
          <button
            onClick={() => applyTlpFilter("")}
            className={`rounded-full px-2.5 py-0.5 text-xs font-medium transition-colors ${
              !tlpFilter ? "bg-indigo-600 text-white" : "bg-muted/40 text-muted-foreground hover:bg-muted/60"
            }`}
          >
            All
          </button>
          {tlpOptions.map(tlp => (
            <button
              key={tlp}
              onClick={() => applyTlpFilter(tlp)}
              className={`rounded-full px-2.5 py-0.5 text-xs font-medium transition-colors ${
                tlpFilter === tlp ? tlpPill(tlp) + " ring-1 ring-current" : tlpPill(tlp) + " opacity-60 hover:opacity-100"
              }`}
            >
              TLP:{tlp.toUpperCase()} {stats?.by_tlp?.[tlp] != null ? `(${stats.by_tlp[tlp]})` : ""}
            </button>
          ))}
          <button
            onClick={() => load(tlpFilter)}
            className="ml-auto flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
          >
            <RefreshCw className="h-3 w-3" />
            Refresh
          </button>
        </div>
      )}

      {/* Briefs cards */}
      {briefs.length > 0 ? (
        <div className="space-y-3">
          {briefs.slice(0, 30).map((brief, i) => (
            <div
              key={brief.brief_id ?? brief.id ?? i}
              className="rounded-lg border border-border bg-card p-4 hover:border-indigo-700/50 transition-colors"
            >
              <div className="flex items-start justify-between gap-3">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1 flex-wrap">
                    {brief.tlp && (
                      <span className={`inline-block rounded px-1.5 py-0.5 text-xs font-mono font-semibold ${tlpPill(brief.tlp)}`}>
                        TLP:{brief.tlp.toUpperCase()}
                      </span>
                    )}
                    {brief.severity && (
                      <span className={`inline-block rounded px-1.5 py-0.5 text-xs font-medium ${sevPill(brief.severity)}`}>
                        {brief.severity}
                      </span>
                    )}
                    {brief.brief_type && (
                      <span className="inline-block rounded px-1.5 py-0.5 text-xs bg-muted/40 text-muted-foreground capitalize">
                        {brief.brief_type}
                      </span>
                    )}
                  </div>
                  <h4 className="font-medium text-sm text-foreground leading-snug truncate">
                    {brief.title ?? "Untitled Brief"}
                  </h4>
                  {brief.summary && (
                    <p className="text-xs text-muted-foreground mt-1 line-clamp-2">{brief.summary}</p>
                  )}
                  {brief.tags && brief.tags.length > 0 && (
                    <div className="flex flex-wrap gap-1 mt-2">
                      {brief.tags.slice(0, 5).map(tag => (
                        <span key={tag} className="rounded-full bg-muted/30 px-2 py-0.5 text-xs text-muted-foreground">
                          {tag}
                        </span>
                      ))}
                    </div>
                  )}
                </div>
                <div className="text-right shrink-0 space-y-1">
                  {brief.published_at && (
                    <div className="text-xs text-muted-foreground">
                      {new Date(brief.published_at).toLocaleDateString()}
                    </div>
                  )}
                  {brief.recipient_count != null && (
                    <div className="text-xs text-sky-400 font-mono">{brief.recipient_count} recipients</div>
                  )}
                  {brief.author && (
                    <div className="text-xs text-muted-foreground">by {brief.author}</div>
                  )}
                </div>
              </div>
            </div>
          ))}
        </div>
      ) : (
        <div className="text-sm text-muted-foreground text-center py-8">
          No briefs match the current filter.
        </div>
      )}
    </div>
  );
}
