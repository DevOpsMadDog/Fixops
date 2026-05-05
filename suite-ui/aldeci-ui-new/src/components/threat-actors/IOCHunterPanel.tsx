/**
 * IOCHunterPanel — wires GET /api/v1/ioc-enrichment/iocs + /stats
 * Interactive search + enrichment console.
 * Used by ThreatActorsHub "ioc-hunter" tab.
 */

import { useEffect, useRef, useState } from "react";
import { Search, AlertTriangle, Zap, Database, RefreshCw } from "lucide-react";
import { iocEnrichmentApi } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { Badge } from "@/components/ui/badge";

interface IOC {
  ioc_id?: string;
  id?: string;
  value: string;
  ioc_type?: string;
  type?: string;
  severity: string;
  confidence?: number;
  source?: string;
  tags?: string[];
  enriched?: boolean;
  verdict?: string;
}

interface IOCStats {
  total_iocs?: number;
  total?: number;
  enriched_count?: number;
  by_type?: Record<string, number>;
  by_severity?: Record<string, number>;
}

const SEV_COLOR: Record<string, string> = {
  critical: "bg-red-500/15 text-red-400 border-red-500/30",
  high:     "bg-orange-500/15 text-orange-400 border-orange-500/30",
  medium:   "bg-amber-500/15 text-amber-400 border-amber-500/30",
  low:      "bg-green-500/15 text-green-400 border-green-500/30",
};

export function IOCHunterPanel() {
  const [iocs, setIocs] = useState<IOC[]>([]);
  const [filtered, setFiltered] = useState<IOC[]>([]);
  const [stats, setStats] = useState<IOCStats>({});
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [enrichingId, setEnrichingId] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  const load = () => {
    let cancelled = false;
    setLoading(true);
    setError(null);
    Promise.all([
      iocEnrichmentApi.list().catch(() => ({ data: [] })),
      iocEnrichmentApi.stats().catch(() => ({ data: {} })),
    ])
      .then(([iocsRes, statsRes]) => {
        if (cancelled) return;
        const raw = iocsRes.data;
        const list: IOC[] = Array.isArray(raw) ? raw : (raw?.iocs ?? raw?.items ?? []);
        setIocs(list);
        setFiltered(list);
        setStats(statsRes.data ?? {});
      })
      .catch((e: unknown) => {
        if (!cancelled) setError(e instanceof Error ? e.message : "Failed to load IOCs");
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => { cancelled = true; };
  };

  useEffect(load, []);

  useEffect(() => {
    const q = query.trim().toLowerCase();
    setFiltered(q ? iocs.filter(i => i.value.toLowerCase().includes(q)) : iocs);
  }, [query, iocs]);

  const handleEnrich = async (ioc: IOC) => {
    const id = ioc.ioc_id ?? ioc.id;
    if (!id) return;
    setEnrichingId(id);
    try {
      await iocEnrichmentApi.enrich(id);
      load();
    } catch {
      // enrichment failure is non-fatal
    } finally {
      setEnrichingId(null);
    }
  };

  if (loading) {
    return (
      <div className="space-y-3 animate-pulse">
        <div className="h-10 rounded-lg bg-muted/50 w-full" />
        <div className="grid grid-cols-3 gap-3">
          {[...Array(3)].map((_, i) => <div key={i} className="h-20 rounded-lg bg-muted/50" />)}
        </div>
        {[...Array(5)].map((_, i) => <div key={i} className="h-12 rounded-lg bg-muted/40" />)}
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

  const totalIocs = stats.total_iocs ?? stats.total ?? iocs.length;
  const enrichedCount = stats.enriched_count ?? iocs.filter(i => i.enriched).length;

  return (
    <div className="space-y-4">
      {/* Search bar */}
      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
        <input
          ref={inputRef}
          type="text"
          placeholder="Search IOC value (IP, hash, domain…)"
          value={query}
          onChange={e => setQuery(e.target.value)}
          className="w-full rounded-lg border border-border bg-muted/30 pl-9 pr-4 py-2 text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500/50"
        />
      </div>

      {/* Stat cards */}
      <div className="grid grid-cols-3 gap-3">
        <div className="rounded-lg border border-border bg-card p-3">
          <div className="flex items-center gap-1.5 text-xs text-muted-foreground mb-1">
            <Database className="h-3.5 w-3.5" /> Total IOCs
          </div>
          <p className="text-2xl font-bold">{totalIocs}</p>
        </div>
        <div className="rounded-lg border border-border bg-card p-3">
          <div className="flex items-center gap-1.5 text-xs text-muted-foreground mb-1">
            <Zap className="h-3.5 w-3.5 text-indigo-400" /> Enriched
          </div>
          <p className="text-2xl font-bold text-indigo-400">{enrichedCount}</p>
        </div>
        <div className="rounded-lg border border-border bg-card p-3">
          <div className="flex items-center gap-1.5 text-xs text-muted-foreground mb-1">
            <Search className="h-3.5 w-3.5 text-amber-400" /> Matching
          </div>
          <p className="text-2xl font-bold text-amber-400">{filtered.length}</p>
        </div>
      </div>

      {filtered.length === 0 ? (
        <EmptyState
          icon={Search}
          title={query ? "No IOCs match your search" : "No IOCs in inventory"}
          description={
            query
              ? "Try a different value or clear the search."
              : "Add IOCs via the bulk-import endpoint or connector pipeline."
          }
        />
      ) : (
        <div className="rounded-lg border border-border overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/30">
                <th className="text-left px-4 py-2 font-medium text-muted-foreground">Value</th>
                <th className="text-left px-4 py-2 font-medium text-muted-foreground">Type</th>
                <th className="text-left px-4 py-2 font-medium text-muted-foreground">Severity</th>
                <th className="text-left px-4 py-2 font-medium text-muted-foreground">Source</th>
                <th className="text-right px-4 py-2 font-medium text-muted-foreground">Confidence</th>
                <th className="text-right px-4 py-2 font-medium text-muted-foreground">Enrich</th>
              </tr>
            </thead>
            <tbody>
              {filtered.slice(0, 50).map((ioc, i) => {
                const id = ioc.ioc_id ?? ioc.id ?? String(i);
                const type = ioc.ioc_type ?? ioc.type ?? "—";
                return (
                  <tr
                    key={id}
                    className="border-b border-border/50 hover:bg-muted/20 transition-colors"
                  >
                    <td className="px-4 py-2.5 font-mono text-xs max-w-[220px] truncate">{ioc.value}</td>
                    <td className="px-4 py-2.5 text-muted-foreground capitalize">{type}</td>
                    <td className="px-4 py-2.5">
                      <Badge className={`text-xs ${SEV_COLOR[ioc.severity] ?? "bg-muted/30"}`}>
                        {ioc.severity}
                      </Badge>
                    </td>
                    <td className="px-4 py-2.5 text-muted-foreground text-xs">{ioc.source || "—"}</td>
                    <td className="px-4 py-2.5 text-right font-mono text-xs">
                      {ioc.confidence !== undefined ? `${ioc.confidence}%` : "—"}
                    </td>
                    <td className="px-4 py-2.5 text-right">
                      <button
                        onClick={() => handleEnrich(ioc)}
                        disabled={enrichingId === id}
                        aria-label={`Enrich IOC ${ioc.value}`}
                        className="inline-flex items-center gap-1 rounded px-2 py-1 text-xs bg-indigo-500/15 text-indigo-400 hover:bg-indigo-500/25 disabled:opacity-50 transition-colors"
                      >
                        <RefreshCw className={`h-3 w-3 ${enrichingId === id ? "animate-spin" : ""}`} />
                        {enrichingId === id ? "…" : "Run"}
                      </button>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
