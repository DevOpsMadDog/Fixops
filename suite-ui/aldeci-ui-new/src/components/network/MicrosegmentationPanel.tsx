/**
 * MicrosegmentationPanel — wires GET /api/v1/microsegmentation/stats,
 * GET /api/v1/microsegmentation/segments and GET /api/v1/microsegmentation/violations.
 * Used by NetworkSegmentationHub "microseg" tab.
 */

import { useEffect, useState } from "react";
import { AlertTriangle, Network, ShieldAlert, CheckCircle2, XCircle } from "lucide-react";
import api from "@/lib/api";

interface MicrosegStats {
  total_segments?: number;
  total_policies?: number;
  total_violations?: number;
  compliant_segments?: number;
}

interface Segment {
  id: string;
  name: string;
  segment_type: string;
  cidr_range?: string;
  enforcement_mode?: string;
  status?: string;
}

interface Violation {
  id: string;
  segment_name?: string;
  src_ip?: string;
  dst_ip?: string;
  severity?: string;
  detected_at?: string;
}

interface ListResponse<T> {
  items?: T[];
  data?: T[];
  segments?: T[];
  violations?: T[];
}

const ENFORCEMENT_COLOR: Record<string, string> = {
  enforce: "bg-green-500/20 text-green-400",
  monitoring: "bg-amber-500/20 text-amber-400",
  audit: "bg-sky-500/20 text-sky-400",
};

const SEVERITY_COLOR: Record<string, string> = {
  critical: "text-red-500",
  high: "text-orange-500",
  medium: "text-amber-400",
  low: "text-sky-400",
};

function StatCard({
  label,
  value,
  icon: Icon,
  accent,
}: {
  label: string;
  value: string | number;
  icon: React.ComponentType<{ className?: string }>;
  accent: string;
}) {
  return (
    <div className="flex flex-col gap-2 rounded-xl border border-border/60 bg-card p-4 shadow-sm">
      <div className="flex items-center gap-2 text-muted-foreground text-xs font-medium uppercase tracking-wider">
        <Icon className={`h-4 w-4 ${accent}`} />
        {label}
      </div>
      <p className="text-2xl font-bold text-foreground">{value}</p>
    </div>
  );
}

export function MicrosegmentationPanel() {
  const [stats, setStats] = useState<MicrosegStats | null>(null);
  const [segments, setSegments] = useState<Segment[]>([]);
  const [violations, setViolations] = useState<Violation[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    Promise.all([
      api.get<MicrosegStats>("/api/v1/microsegmentation/stats").catch(() => null),
      api.get<ListResponse<Segment>>("/api/v1/microsegmentation/segments").catch(() => null),
      api.get<ListResponse<Violation>>("/api/v1/microsegmentation/violations").catch(() => null),
    ])
      .then(([statsRes, segRes, violRes]) => {
        if (cancelled) return;
        if (statsRes?.data) setStats(statsRes.data);

        const rawSeg = segRes?.data;
        const segList = rawSeg
          ? ((rawSeg as ListResponse<Segment>).segments ??
              (rawSeg as ListResponse<Segment>).items ??
              (Array.isArray(rawSeg) ? (rawSeg as Segment[]) : []))
          : [];
        setSegments(segList);

        const rawViol = violRes?.data;
        const violList = rawViol
          ? ((rawViol as ListResponse<Violation>).violations ??
              (rawViol as ListResponse<Violation>).items ??
              (Array.isArray(rawViol) ? (rawViol as Violation[]) : []))
          : [];
        setViolations(violList);
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(err instanceof Error ? err.message : "Failed to load microsegmentation data");
        }
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });

    return () => { cancelled = true; };
  }, []);

  if (loading) {
    return (
      <div className="flex flex-col gap-4 animate-pulse">
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          {[...Array(4)].map((_, i) => (
            <div key={i} className="h-24 rounded-xl border border-border/40 bg-muted/30" />
          ))}
        </div>
        <div className="h-56 rounded-xl border border-border/40 bg-muted/30" />
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

  if (!stats && segments.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center gap-3 rounded-xl border border-dashed border-border/60 py-16 text-center text-muted-foreground">
        <Network className="h-8 w-8 opacity-40" />
        <p className="text-sm font-medium">No microsegmentation segments defined</p>
        <p className="text-xs opacity-70">
          Create a segment via POST /api/v1/microsegmentation/segments to begin enforcement tracking.
        </p>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-6">
      {/* Stat cards */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <StatCard
          label="Segments"
          value={stats?.total_segments ?? segments.length}
          icon={Network}
          accent="text-indigo-400"
        />
        <StatCard
          label="Policies"
          value={stats?.total_policies ?? "—"}
          icon={CheckCircle2}
          accent="text-sky-400"
        />
        <StatCard
          label="Violations"
          value={stats?.total_violations ?? violations.length}
          icon={ShieldAlert}
          accent="text-red-400"
        />
        <StatCard
          label="Compliant"
          value={stats?.compliant_segments ?? "—"}
          icon={XCircle}
          accent="text-emerald-400"
        />
      </div>

      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Segments list */}
        {segments.length > 0 && (
          <div className="rounded-xl border border-border/60 bg-card shadow-sm overflow-hidden">
            <div className="px-4 py-3 border-b border-border/50">
              <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                Segments
              </p>
            </div>
            <div className="divide-y divide-border/30">
              {segments.slice(0, 8).map((s) => (
                <div
                  key={s.id}
                  className="flex items-center justify-between px-4 py-2.5 hover:bg-muted/20 transition-colors"
                >
                  <div className="min-w-0">
                    <p className="text-sm font-medium text-foreground truncate">{s.name}</p>
                    <p className="text-xs text-muted-foreground">{s.cidr_range || s.segment_type}</p>
                  </div>
                  <span
                    className={`shrink-0 ml-2 inline-flex items-center rounded-full px-2 py-0.5 text-xs font-medium ${
                      ENFORCEMENT_COLOR[s.enforcement_mode ?? ""] ?? "bg-muted/40 text-muted-foreground"
                    }`}
                  >
                    {s.enforcement_mode ?? s.segment_type}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Violations list */}
        {violations.length > 0 && (
          <div className="rounded-xl border border-border/60 bg-card shadow-sm overflow-hidden">
            <div className="px-4 py-3 border-b border-border/50">
              <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                Recent Violations
              </p>
            </div>
            <div className="divide-y divide-border/30">
              {violations.slice(0, 8).map((v) => (
                <div
                  key={v.id}
                  className="flex items-center justify-between px-4 py-2.5 hover:bg-muted/20 transition-colors"
                >
                  <div className="min-w-0">
                    <p className="text-sm font-medium text-foreground truncate">
                      {v.segment_name ?? v.id}
                    </p>
                    {(v.src_ip || v.dst_ip) && (
                      <p className="text-xs text-muted-foreground">
                        {v.src_ip} → {v.dst_ip}
                      </p>
                    )}
                  </div>
                  <span
                    className={`shrink-0 ml-2 text-xs font-semibold capitalize ${
                      SEVERITY_COLOR[v.severity ?? ""] ?? "text-muted-foreground"
                    }`}
                  >
                    {v.severity ?? "—"}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
