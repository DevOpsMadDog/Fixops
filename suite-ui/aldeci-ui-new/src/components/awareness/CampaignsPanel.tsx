/**
 * CampaignsPanel — AwarenessHub "campaigns" tab
 *
 * Wired to real backend:
 *   GET /api/v1/awareness-campaigns/stats      → KPI bar
 *   GET /api/v1/awareness-campaigns/campaigns  → campaign list
 */

import { useState, useEffect, useCallback } from "react";
import { motion } from "framer-motion";
import { Megaphone, Users, CheckCircle, AlertTriangle, RefreshCw } from "lucide-react";

import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";

interface CampaignStats {
  total_campaigns?: number;
  active_campaigns?: number;
  total_participants?: number;
  completion_rate?: number;
}

interface Campaign {
  campaign_id: string;
  name?: string;
  status?: string;
  campaign_type?: string;
  start_date?: string;
  end_date?: string;
  participant_count?: number;
  completion_rate?: number;
}

const STATUS_CLASS: Record<string, string> = {
  active: "bg-emerald-700/80 text-emerald-100",
  completed: "bg-blue-700/80 text-blue-100",
  scheduled: "bg-amber-700/80 text-amber-100",
  cancelled: "bg-red-700/80 text-red-100",
};

async function apiFetch<T>(path: string, params?: Record<string, string>): Promise<T> {
  const orgId = getStoredOrgId() || "default";
  const url = buildApiUrl(path, { org_id: orgId, ...params });
  const res = await fetch(url, {
    headers: { "X-API-Key": getStoredAuthToken(), "X-Org-ID": orgId },
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

function extractArray<T>(data: unknown): T[] {
  if (Array.isArray(data)) return data as T[];
  if (data && typeof data === "object") {
    const obj = data as Record<string, unknown>;
    for (const k of ["campaigns", "items", "results", "data"]) {
      if (Array.isArray(obj[k])) return obj[k] as T[];
    }
  }
  return [];
}

export default function CampaignsPanel() {
  const [stats, setStats] = useState<CampaignStats | null>(null);
  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [rawStats, rawCampaigns] = await Promise.all([
        apiFetch<CampaignStats>("/api/v1/awareness-campaigns/stats"),
        apiFetch<unknown>("/api/v1/awareness-campaigns/campaigns"),
      ]);
      setStats(rawStats);
      setCampaigns(extractArray<Campaign>(rawCampaigns));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load campaigns");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  if (loading) return <PageSkeleton />;
  if (error) return <ErrorState message={error} onRetry={load} />;

  const kpis = [
    { label: "Total Campaigns", value: stats?.total_campaigns ?? 0, icon: Megaphone, color: "text-indigo-400" },
    { label: "Active", value: stats?.active_campaigns ?? 0, icon: AlertTriangle, color: "text-emerald-400" },
    { label: "Participants", value: stats?.total_participants ?? 0, icon: Users, color: "text-sky-400" },
    { label: "Completion Rate", value: `${stats?.completion_rate ?? 0}%`, icon: CheckCircle, color: "text-amber-400" },
  ];

  return (
    <motion.div
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25 }}
      className="flex flex-col gap-5"
    >
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-2">
          <Megaphone className="h-5 w-5 text-indigo-400" />
          <span className="font-semibold text-sm">Awareness Campaigns</span>
        </div>
        <Button variant="outline" size="sm" onClick={load} className="gap-1.5">
          <RefreshCw className="h-3.5 w-3.5" /> Refresh
        </Button>
      </div>

      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {kpis.map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="rounded-lg bg-muted/40 border border-border px-4 py-3 flex flex-col gap-1">
            <div className="flex items-center gap-1.5 text-muted-foreground">
              <Icon className={`h-3.5 w-3.5 ${color}`} />
              <span className="text-xs">{label}</span>
            </div>
            <span className={`text-2xl font-bold tabular-nums ${color}`}>{value}</span>
          </div>
        ))}
      </div>

      {campaigns.length === 0 ? (
        <EmptyState
          icon={Megaphone}
          title="No campaigns yet"
          description="Create a phishing simulation or awareness campaign to get started."
        />
      ) : (
        <div className="overflow-x-auto rounded-lg border border-border">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border bg-muted/30">
                {["Name", "Type", "Status", "Start", "End", "Participants", "Completion"].map(h => (
                  <th key={h} className="px-3 py-2 text-left font-medium text-muted-foreground">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {campaigns.slice(0, 200).map((c, i) => (
                <tr key={c.campaign_id ?? i} className="border-b border-border/40 hover:bg-muted/20 transition-colors">
                  <td className="px-3 py-2 font-medium">{c.name ?? c.campaign_id}</td>
                  <td className="px-3 py-2 text-muted-foreground capitalize">{c.campaign_type ?? "—"}</td>
                  <td className="px-3 py-2">
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase ${STATUS_CLASS[c.status?.toLowerCase() ?? ""] ?? "bg-muted/40 text-muted-foreground"}`}>
                      {c.status ?? "—"}
                    </span>
                  </td>
                  <td className="px-3 py-2 text-muted-foreground">{c.start_date ? new Date(c.start_date).toLocaleDateString() : "—"}</td>
                  <td className="px-3 py-2 text-muted-foreground">{c.end_date ? new Date(c.end_date).toLocaleDateString() : "—"}</td>
                  <td className="px-3 py-2 tabular-nums">{c.participant_count ?? 0}</td>
                  <td className="px-3 py-2 tabular-nums">{c.completion_rate != null ? `${c.completion_rate}%` : "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </motion.div>
  );
}
