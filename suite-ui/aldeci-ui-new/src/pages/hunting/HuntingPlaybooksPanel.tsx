/**
 * HuntingPlaybooksPanel — wired to /api/v1/hunting-playbooks
 * Tab: HuntingHub > playbooks
 * Backends: GET /api/v1/hunting-playbooks/ (list) + GET /api/v1/hunting-playbooks/stats
 */

import { useEffect, useState, useCallback } from "react";
import { motion } from "framer-motion";
import { BookOpen, RefreshCw, Play, CheckCircle2, Clock } from "lucide-react";

import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";

// ── Types ─────────────────────────────────────────────────────────────────────

interface Playbook {
  id: string;
  name: string;
  description?: string;
  status?: string;
  hypothesis_count?: number;
  execution_count?: number;
  last_executed?: string;
  created_at?: string;
  tags?: string[];
}

interface PlaybookStats {
  total_playbooks?: number;
  active_playbooks?: number;
  total_executions?: number;
  avg_hypothesis_count?: number;
}

type FetchState = "idle" | "loading" | "ok" | "error";

// ── Helpers ───────────────────────────────────────────────────────────────────

function statusColor(status?: string): string {
  switch ((status ?? "").toLowerCase()) {
    case "active":
      return "bg-green-500/15 text-green-400 border-green-500/30";
    case "draft":
      return "bg-amber-500/15 text-amber-400 border-amber-500/30";
    case "archived":
      return "bg-slate-500/15 text-slate-400 border-slate-500/30";
    default:
      return "bg-blue-500/15 text-blue-400 border-blue-500/30";
  }
}

function formatDate(iso?: string): string {
  if (!iso) return "—";
  try {
    return new Date(iso).toLocaleDateString(undefined, {
      month: "short",
      day: "numeric",
      year: "numeric",
    });
  } catch {
    return iso;
  }
}

// ── Component ─────────────────────────────────────────────────────────────────

export function HuntingPlaybooksPanel() {
  const [state, setState] = useState<FetchState>("idle");
  const [playbooks, setPlaybooks] = useState<Playbook[]>([]);
  const [stats, setStats] = useState<PlaybookStats>({});
  const [error, setError] = useState<string>("");

  const fetchData = useCallback(async () => {
    setState("loading");
    setError("");
    const token = getStoredAuthToken();
    const orgId = getStoredOrgId();
    const headers: HeadersInit = {
      "X-API-Key": token,
      "X-Org-ID": orgId,
    };

    try {
      const [listRes, statsRes] = await Promise.all([
        fetch(buildApiUrl("/api/v1/hunting-playbooks/playbooks", { org_id: orgId }), { headers }),
        fetch(buildApiUrl("/api/v1/hunting-playbooks/stats", { org_id: orgId }), { headers }),
      ]);

      if (!listRes.ok) throw new Error(`Playbooks list: ${listRes.status} ${listRes.statusText}`);

      const listJson = await listRes.json();
      const statsJson = statsRes.ok ? await statsRes.json() : {};

      const items: Playbook[] = Array.isArray(listJson)
        ? listJson
        : Array.isArray(listJson?.playbooks)
        ? listJson.playbooks
        : Array.isArray(listJson?.items)
        ? listJson.items
        : [];

      setPlaybooks(items);
      setStats(statsJson ?? {});
      setState("ok");
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
      setState("error");
    }
  }, []);

  useEffect(() => {
    fetchData();
  }, [fetchData]);

  if (state === "loading" || state === "idle") return <PageSkeleton />;
  if (state === "error") return <ErrorState message={error} onRetry={fetchData} />;

  const kpis = [
    {
      label: "Total Playbooks",
      value: stats.total_playbooks ?? playbooks.length,
      icon: BookOpen,
      color: "text-blue-400",
    },
    {
      label: "Active",
      value: stats.active_playbooks ?? playbooks.filter(p => (p.status ?? "").toLowerCase() === "active").length,
      icon: CheckCircle2,
      color: "text-green-400",
    },
    {
      label: "Total Executions",
      value: stats.total_executions ?? playbooks.reduce((s, p) => s + (p.execution_count ?? 0), 0),
      icon: Play,
      color: "text-indigo-400",
    },
    {
      label: "Avg Hypotheses",
      value: stats.avg_hypothesis_count != null
        ? stats.avg_hypothesis_count.toFixed(1)
        : playbooks.length > 0
        ? (playbooks.reduce((s, p) => s + (p.hypothesis_count ?? 0), 0) / playbooks.length).toFixed(1)
        : "—",
      icon: Clock,
      color: "text-amber-400",
    },
  ];

  return (
    <motion.div
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25 }}
      className="flex flex-col gap-6"
    >
      {/* KPI bar */}
      <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
        {kpis.map(k => {
          const Icon = k.icon;
          return (
            <div
              key={k.label}
              className="rounded-lg border border-slate-700 bg-slate-800/60 px-4 py-3 flex flex-col gap-1"
            >
              <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
                <Icon className={`h-3.5 w-3.5 ${k.color}`} />
                {k.label}
              </div>
              <span className="text-xl font-semibold tabular-nums">{k.value}</span>
            </div>
          );
        })}
      </div>

      {/* Header row */}
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-medium text-muted-foreground">
          {playbooks.length} playbook{playbooks.length !== 1 ? "s" : ""}
        </h3>
        <Button variant="ghost" size="sm" onClick={fetchData} className="gap-1.5 text-xs">
          <RefreshCw className="h-3.5 w-3.5" />
          Refresh
        </Button>
      </div>

      {/* Table */}
      {playbooks.length === 0 ? (
        <EmptyState
          title="No playbooks found"
          description="Create a hunting playbook to capture reusable investigation steps and queries."
          icon={BookOpen}
        />
      ) : (
        <div className="rounded-lg border border-slate-700 overflow-hidden">
          <table className="w-full text-sm">
            <thead className="bg-slate-800/80 text-xs text-muted-foreground">
              <tr>
                <th className="px-4 py-2.5 text-left font-medium">Playbook</th>
                <th className="px-4 py-2.5 text-left font-medium">Status</th>
                <th className="px-4 py-2.5 text-right font-medium">Hypotheses</th>
                <th className="px-4 py-2.5 text-right font-medium">Executions</th>
                <th className="px-4 py-2.5 text-left font-medium">Last Run</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-700/50">
              {playbooks.map((pb, i) => (
                <tr key={pb.id ?? i} className="hover:bg-slate-800/40 transition-colors">
                  <td className="px-4 py-3">
                    <div className="font-medium text-slate-100 leading-tight">{pb.name}</div>
                    {pb.description && (
                      <div className="text-xs text-muted-foreground mt-0.5 line-clamp-1">
                        {pb.description}
                      </div>
                    )}
                    {pb.tags && pb.tags.length > 0 && (
                      <div className="flex flex-wrap gap-1 mt-1">
                        {pb.tags.slice(0, 3).map(tag => (
                          <span
                            key={tag}
                            className="text-[10px] px-1.5 py-0.5 rounded bg-slate-700/60 text-slate-400"
                          >
                            {tag}
                          </span>
                        ))}
                      </div>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <Badge className={`text-[10px] border ${statusColor(pb.status)}`}>
                      {pb.status ?? "unknown"}
                    </Badge>
                  </td>
                  <td className="px-4 py-3 text-right tabular-nums text-slate-300">
                    {pb.hypothesis_count ?? 0}
                  </td>
                  <td className="px-4 py-3 text-right tabular-nums text-slate-300">
                    {pb.execution_count ?? 0}
                  </td>
                  <td className="px-4 py-3 text-xs text-muted-foreground">
                    {formatDate(pb.last_executed ?? pb.created_at)}
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
