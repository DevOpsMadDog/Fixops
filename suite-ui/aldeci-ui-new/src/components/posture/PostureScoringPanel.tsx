/**
 * PostureScoringPanel — wires GET /api/v1/posture-scoring/stats
 * and GET /api/v1/posture-scoring/controls → domain breakdown + control list.
 * Used by PostureMetricsHub "scoring" tab.
 */

import { useEffect, useState } from "react";
import { AlertTriangle, ShieldCheck, Activity, XCircle, MinusCircle, CheckCircle2 } from "lucide-react";
import api from "@/lib/api";

interface PostureStats {
  overall_score?: number;
  total_controls?: number;
  implemented?: number;
  partial?: number;
  not_implemented?: number;
  domain_scores?: Record<string, number>;
}

interface Control {
  id: string;
  name?: string;
  domain?: string;
  control_status?: string;
  weight?: number;
  evidence_url?: string;
  last_assessed?: string;
}

interface ControlsResponse {
  controls?: Control[];
  items?: Control[];
  data?: Control[];
}

const STATUS_META: Record<string, { label: string; color: string; icon: React.ComponentType<{ className?: string }> }> = {
  implemented: { label: "Implemented", color: "text-emerald-400", icon: CheckCircle2 },
  partial: { label: "Partial", color: "text-amber-400", icon: MinusCircle },
  not_implemented: { label: "Not Implemented", color: "text-red-400", icon: XCircle },
  compensating: { label: "Compensating", color: "text-sky-400", icon: ShieldCheck },
};

function ScoreGauge({ score }: { score: number }) {
  const clamp = Math.max(0, Math.min(100, score));
  const color =
    clamp >= 80 ? "text-emerald-400" : clamp >= 60 ? "text-amber-400" : "text-red-400";
  const ring =
    clamp >= 80 ? "stroke-emerald-400" : clamp >= 60 ? "stroke-amber-400" : "stroke-red-400";
  const circumference = 2 * Math.PI * 40;
  const offset = circumference * (1 - clamp / 100);

  return (
    <div className="flex flex-col items-center gap-2">
      <svg width="100" height="100" viewBox="0 0 100 100" className="-rotate-90">
        <circle cx="50" cy="50" r="40" fill="none" stroke="currentColor" strokeWidth="8" className="text-muted/30" />
        <circle
          cx="50" cy="50" r="40" fill="none" strokeWidth="8"
          strokeDasharray={circumference} strokeDashoffset={offset}
          strokeLinecap="round" className={`${ring} transition-all duration-700`}
        />
      </svg>
      <div className="-mt-16 flex flex-col items-center">
        <span className={`text-3xl font-bold ${color}`}>{Math.round(clamp)}</span>
        <span className="text-xs text-muted-foreground">/ 100</span>
      </div>
      <p className="mt-8 text-xs font-medium text-muted-foreground uppercase tracking-wider">Overall Score</p>
    </div>
  );
}

function StatCard({
  label, value, icon: Icon, accent,
}: {
  label: string; value: string | number;
  icon: React.ComponentType<{ className?: string }>; accent: string;
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

export function PostureScoringPanel() {
  const [stats, setStats] = useState<PostureStats | null>(null);
  const [controls, setControls] = useState<Control[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    let cancelled = false;
    setLoading(true);
    setError(null);

    Promise.all([
      api.get<PostureStats>("/api/v1/posture-scoring/stats").catch(() => null),
      api.get<ControlsResponse>("/api/v1/posture-scoring/controls").catch(() => null),
    ])
      .then(([statsRes, ctrlRes]) => {
        if (cancelled) return;
        if (statsRes?.data) setStats(statsRes.data);
        const raw = ctrlRes?.data;
        const list: Control[] = raw
          ? ((raw as ControlsResponse).controls ??
              (raw as ControlsResponse).items ??
              (Array.isArray(raw) ? (raw as Control[]) : []))
          : [];
        setControls(list);
      })
      .catch((err: unknown) => {
        if (!cancelled)
          setError(err instanceof Error ? err.message : "Failed to load scoring data");
      })
      .finally(() => { if (!cancelled) setLoading(false); });

    return () => { cancelled = true; };
  }, []);

  if (loading) {
    return (
      <div className="flex flex-col gap-4 animate-pulse">
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
          {[...Array(4)].map((_, i) => <div key={i} className="h-24 rounded-xl border border-border/40 bg-muted/30" />)}
        </div>
        <div className="h-64 rounded-xl border border-border/40 bg-muted/30" />
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex items-center gap-2 rounded-xl border border-destructive/40 bg-destructive/10 p-4 text-destructive text-sm">
        <AlertTriangle className="h-4 w-4 shrink-0" />{error}
      </div>
    );
  }

  if (!stats && controls.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center gap-3 rounded-xl border border-dashed border-border/60 py-16 text-center text-muted-foreground">
        <ShieldCheck className="h-8 w-8 opacity-40" />
        <p className="text-sm font-medium">No scoring data yet</p>
        <p className="text-xs opacity-70">Register controls via POST /api/v1/posture-scoring/controls to populate this view.</p>
      </div>
    );
  }

  const domainScores = stats?.domain_scores ?? {};
  const domainEntries = Object.entries(domainScores);

  return (
    <div className="flex flex-col gap-6">
      <div className="flex flex-col sm:flex-row gap-6 items-start">
        {typeof stats?.overall_score === "number" && (
          <div className="flex-shrink-0">
            <ScoreGauge score={stats.overall_score} />
          </div>
        )}
        <div className="flex-1 grid grid-cols-2 gap-4 sm:grid-cols-3">
          <StatCard label="Total Controls" value={stats?.total_controls ?? controls.length} icon={Activity} accent="text-indigo-400" />
          <StatCard label="Implemented" value={stats?.implemented ?? controls.filter(c => c.control_status === "implemented").length} icon={CheckCircle2} accent="text-emerald-400" />
          <StatCard label="Partial" value={stats?.partial ?? controls.filter(c => c.control_status === "partial").length} icon={MinusCircle} accent="text-amber-400" />
          <StatCard label="Not Implemented" value={stats?.not_implemented ?? controls.filter(c => c.control_status === "not_implemented").length} icon={XCircle} accent="text-red-400" />
        </div>
      </div>

      {domainEntries.length > 0 && (
        <div className="rounded-xl border border-border/60 bg-card shadow-sm overflow-hidden">
          <div className="px-4 py-3 border-b border-border/50">
            <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Domain Scores</p>
          </div>
          <div className="divide-y divide-border/30">
            {domainEntries.map(([domain, score]) => {
              const pct = Math.max(0, Math.min(100, score));
              const barColor = pct >= 80 ? "bg-emerald-500" : pct >= 60 ? "bg-amber-400" : "bg-red-500";
              return (
                <div key={domain} className="flex items-center gap-4 px-4 py-3 hover:bg-muted/20 transition-colors">
                  <p className="text-sm font-medium text-foreground capitalize w-36 shrink-0">{domain}</p>
                  <div className="flex-1 h-2 rounded-full bg-muted/40 overflow-hidden">
                    <div className={`h-full rounded-full transition-all duration-500 ${barColor}`} style={{ width: `${pct}%` }} />
                  </div>
                  <span className="text-xs font-semibold text-foreground w-8 text-right">{Math.round(score)}</span>
                </div>
              );
            })}
          </div>
        </div>
      )}

      {controls.length > 0 && (
        <div className="rounded-xl border border-border/60 bg-card shadow-sm overflow-hidden">
          <div className="px-4 py-3 border-b border-border/50">
            <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Controls ({controls.length})</p>
          </div>
          <div className="divide-y divide-border/30">
            {controls.slice(0, 20).map((c) => {
              const meta = STATUS_META[c.control_status ?? ""] ?? STATUS_META["not_implemented"];
              const Icon = meta.icon;
              return (
                <div key={c.id} className="flex items-center gap-4 px-4 py-3 hover:bg-muted/20 transition-colors">
                  <Icon className={`h-4 w-4 shrink-0 ${meta.color}`} />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm font-medium text-foreground truncate">{c.name ?? c.id}</p>
                    {c.domain && <p className="text-xs text-muted-foreground capitalize">{c.domain}</p>}
                  </div>
                  <span className={`text-xs font-medium ${meta.color}`}>{meta.label}</span>
                  {typeof c.weight === "number" && (
                    <span className="text-xs text-muted-foreground hidden sm:block">w={c.weight}</span>
                  )}
                </div>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
