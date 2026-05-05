/**
 * ThreatResponsePanel — active threat-response incidents + driving playbooks
 * API: GET /api/v1/threat-response/incidents/active + /playbooks + /stats
 * Used by ThreatIntelOpsHub "response" tab.
 */

import { useEffect, useState } from "react";
import { Siren, AlertTriangle, RefreshCw, Shield, CheckCircle2, Clock } from "lucide-react";
import { threatResponseApi } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";

interface Incident {
  incident_id?: string;
  id?: string;
  title?: string;
  severity?: string;
  status?: string;
  phase?: string;
  started_at?: string;
  affected_assets?: number;
  playbook_id?: string;
  assigned_to?: string;
}

interface Playbook {
  playbook_id?: string;
  id?: string;
  name?: string;
  category?: string;
  status?: string;
  steps_total?: number;
  steps_completed?: number;
  last_run?: string;
  run_count?: number;
}

interface ResponseStats {
  active_incidents?: number;
  contained?: number;
  eradicated?: number;
  mttr_minutes?: number;
  playbooks_total?: number;
}

const SEV_PILL: Record<string, string> = {
  critical: "bg-red-700/40 text-red-300",
  high:     "bg-orange-700/40 text-orange-300",
  medium:   "bg-amber-700/40 text-amber-300",
  low:      "bg-green-700/40 text-green-300",
};

const STATUS_PILL: Record<string, string> = {
  active:      "bg-red-700/40 text-red-300",
  contained:   "bg-amber-700/40 text-amber-300",
  eradicated:  "bg-sky-700/40 text-sky-300",
  recovered:   "bg-green-700/40 text-green-300",
  closed:      "bg-gray-700/40 text-gray-400",
};

function sevPill(s: string) {
  return SEV_PILL[s?.toLowerCase()] ?? "bg-gray-700/40 text-gray-400";
}

function statusPill(s: string) {
  return STATUS_PILL[s?.toLowerCase()] ?? "bg-gray-700/40 text-gray-400";
}

function fmtMttr(minutes: number) {
  if (minutes < 60) return `${minutes}m`;
  if (minutes < 1440) return `${(minutes / 60).toFixed(1)}h`;
  return `${(minutes / 1440).toFixed(1)}d`;
}

export function ThreatResponsePanel() {
  const [stats, setStats]         = useState<ResponseStats | null>(null);
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [playbooks, setPlaybooks] = useState<Playbook[]>([]);
  const [loading, setLoading]     = useState(true);
  const [error, setError]         = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const [statsRes, incRes, pbRes] = await Promise.allSettled([
        threatResponseApi.stats(),
        threatResponseApi.activeIncidents(),
        threatResponseApi.playbooks(),
      ]);
      if (statsRes.status === "fulfilled") setStats(statsRes.value.data as ResponseStats);
      if (incRes.status === "fulfilled") {
        const d = incRes.value.data;
        setIncidents(Array.isArray(d) ? d : (d?.incidents ?? d?.items ?? []));
      }
      if (pbRes.status === "fulfilled") {
        const d = pbRes.value.data;
        setPlaybooks(Array.isArray(d) ? d : (d?.playbooks ?? d?.items ?? []));
      }
      if (statsRes.status === "rejected" && incRes.status === "rejected") {
        throw new Error("Failed to load threat response data");
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  if (loading) {
    return (
      <div className="space-y-3 p-4 animate-pulse">
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[1, 2, 3, 4].map(i => <div key={i} className="h-20 rounded-lg bg-muted/40" />)}
        </div>
        {[1, 2, 3].map(i => <div key={i} className="h-12 rounded bg-muted/30" />)}
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

  if (!stats && incidents.length === 0 && playbooks.length === 0) {
    return (
      <EmptyState
        icon={Siren}
        title="No active incidents"
        description="Active threat-response incidents will appear here once detected."
      />
    );
  }

  return (
    <div className="space-y-6">
      {/* Stats */}
      {stats && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            { label: "Active Incidents", value: stats.active_incidents ?? incidents.length, color: "text-red-400" },
            { label: "Contained",        value: stats.contained ?? 0,                       color: "text-amber-400" },
            { label: "Eradicated",       value: stats.eradicated ?? 0,                      color: "text-sky-400" },
            {
              label: "Avg MTTR",
              value: stats.mttr_minutes != null ? fmtMttr(stats.mttr_minutes) : "—",
              color: "text-foreground",
            },
          ].map(({ label, value, color }) => (
            <div key={label} className="rounded-lg border border-border bg-muted/30 p-3">
              <p className="text-xs text-muted-foreground">{label}</p>
              <p className={`text-2xl font-semibold mt-0.5 ${color}`}>{value}</p>
            </div>
          ))}
        </div>
      )}

      {/* Active incidents */}
      {incidents.length > 0 && (
        <div className="rounded-lg border border-red-800/40 overflow-hidden">
          <div className="flex items-center justify-between px-4 py-2 bg-red-900/10 border-b border-red-800/40">
            <h3 className="text-sm font-medium text-red-300 flex items-center gap-1.5">
              <Siren className="h-3.5 w-3.5" />
              Active Incidents ({incidents.length})
            </h3>
            <button
              onClick={load}
              className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
            >
              <RefreshCw className="h-3 w-3" />
              Refresh
            </button>
          </div>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/10 text-xs text-muted-foreground">
                <th className="text-left px-4 py-2 font-medium">Incident</th>
                <th className="text-left px-4 py-2 font-medium">Severity</th>
                <th className="text-left px-4 py-2 font-medium">Status / Phase</th>
                <th className="text-right px-4 py-2 font-medium">Assets</th>
                <th className="text-left px-4 py-2 font-medium">Assigned</th>
                <th className="text-left px-4 py-2 font-medium">Started</th>
              </tr>
            </thead>
            <tbody>
              {incidents.slice(0, 50).map((inc, i) => (
                <tr
                  key={inc.incident_id ?? inc.id ?? i}
                  className="border-b border-border/40 hover:bg-muted/10 transition-colors"
                >
                  <td className="px-4 py-2.5 font-medium text-sm max-w-[200px] truncate">
                    {inc.title ?? inc.incident_id ?? "—"}
                  </td>
                  <td className="px-4 py-2.5">
                    {inc.severity ? (
                      <span className={`inline-block rounded px-1.5 py-0.5 text-xs font-medium ${sevPill(inc.severity)}`}>
                        {inc.severity}
                      </span>
                    ) : "—"}
                  </td>
                  <td className="px-4 py-2.5">
                    {inc.status ? (
                      <span className={`inline-block rounded px-1.5 py-0.5 text-xs font-medium ${statusPill(inc.status)}`}>
                        {inc.status}
                      </span>
                    ) : "—"}
                    {inc.phase && (
                      <span className="ml-1.5 text-xs text-muted-foreground capitalize">{inc.phase}</span>
                    )}
                  </td>
                  <td className="px-4 py-2.5 text-right font-mono text-xs text-amber-400">
                    {inc.affected_assets ?? 0}
                  </td>
                  <td className="px-4 py-2.5 text-xs text-muted-foreground">{inc.assigned_to ?? "—"}</td>
                  <td className="px-4 py-2.5 text-xs text-muted-foreground">
                    {inc.started_at ? new Date(inc.started_at).toLocaleString() : "—"}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Playbooks */}
      {playbooks.length > 0 && (
        <div className="rounded-lg border border-border overflow-hidden">
          <div className="px-4 py-2 bg-muted/20 border-b border-border">
            <h3 className="text-sm font-medium flex items-center gap-1.5">
              <Shield className="h-3.5 w-3.5 text-indigo-400" />
              Response Playbooks ({playbooks.length})
            </h3>
          </div>
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border bg-muted/10 text-xs text-muted-foreground">
                <th className="text-left px-4 py-2 font-medium">Playbook</th>
                <th className="text-left px-4 py-2 font-medium">Category</th>
                <th className="text-left px-4 py-2 font-medium">Status</th>
                <th className="text-left px-4 py-2 font-medium">Progress</th>
                <th className="text-right px-4 py-2 font-medium">Runs</th>
                <th className="text-left px-4 py-2 font-medium">Last Run</th>
              </tr>
            </thead>
            <tbody>
              {playbooks.slice(0, 30).map((pb, i) => {
                const total = pb.steps_total ?? 0;
                const done  = pb.steps_completed ?? 0;
                const pct   = total > 0 ? Math.round((done / total) * 100) : 0;
                return (
                  <tr key={pb.playbook_id ?? pb.id ?? i} className="border-b border-border/40 hover:bg-muted/10 transition-colors">
                    <td className="px-4 py-2.5 font-medium text-sm">{pb.name ?? "—"}</td>
                    <td className="px-4 py-2.5 text-xs capitalize text-muted-foreground">{pb.category ?? "—"}</td>
                    <td className="px-4 py-2.5">
                      <span className="flex items-center gap-1 text-xs">
                        {pb.status === "active" ? (
                          <Clock className="h-3 w-3 text-amber-400" />
                        ) : (
                          <CheckCircle2 className="h-3 w-3 text-green-400" />
                        )}
                        {pb.status ?? "—"}
                      </span>
                    </td>
                    <td className="px-4 py-2.5">
                      {total > 0 ? (
                        <div className="flex items-center gap-2">
                          <div className="h-1.5 w-20 rounded-full bg-muted/40 overflow-hidden">
                            <div
                              className="h-full rounded-full bg-indigo-500 transition-all duration-700"
                              style={{ width: `${pct}%` }}
                            />
                          </div>
                          <span className="text-xs font-mono text-muted-foreground">{done}/{total}</span>
                        </div>
                      ) : "—"}
                    </td>
                    <td className="px-4 py-2.5 text-right font-mono text-xs text-sky-400">
                      {pb.run_count ?? 0}
                    </td>
                    <td className="px-4 py-2.5 text-xs text-muted-foreground">
                      {pb.last_run ? new Date(pb.last_run).toLocaleString() : "—"}
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
