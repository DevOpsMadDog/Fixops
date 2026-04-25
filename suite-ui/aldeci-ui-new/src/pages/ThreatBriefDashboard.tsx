/**
 * Threat Brief Dashboard
 * Route: /threat-briefs
 * API: GET /api/v1/threat-briefs/{briefs,stats}; POST /briefs/{id}/distribute
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { FileText, Send, Users, Clock, RefreshCw, Eye, AlertTriangle } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { cn } from "@/lib/utils";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";

type TLPLevel = "RED" | "AMBER" | "GREEN" | "WHITE";
type BriefType = "daily" | "weekly" | "monthly" | "incident" | "threat-actor" | "campaign";

interface ThreatBrief {
  id: string;
  title: string;
  brief_type: BriefType;
  tlp: TLPLevel;
  summary: string;
  recipient_count: number;
  distributed: boolean;
  created_at: string;
  author: string;
  threat_level: "critical" | "high" | "medium" | "low";
  tags: string[];
}

async function apiFetch<T>(path: string, opts: RequestInit = {}): Promise<T> {
  const orgId = getStoredOrgId() || "verify-test";
  const url = buildApiUrl(path, { org_id: orgId });
  const res = await fetch(url, { ...opts, headers: { "X-API-Key": getStoredAuthToken(), "X-Org-ID": orgId, "Content-Type": "application/json", ...(opts.headers ?? {}) } });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

const TLP_CONFIG: Record<TLPLevel, { cls: string; bg: string }> = {
  RED: { cls: "text-red-300 border-red-500/40", bg: "bg-red-600" },
  AMBER: { cls: "text-amber-300 border-amber-500/40", bg: "bg-amber-500" },
  GREEN: { cls: "text-green-300 border-green-500/40", bg: "bg-green-600" },
  WHITE: { cls: "text-gray-300 border-gray-500/40", bg: "bg-gray-500" },
};

const BRIEF_TYPE_LABELS: Record<BriefType, string> = {
  daily: "Daily", weekly: "Weekly", monthly: "Monthly", incident: "Incident", "threat-actor": "Threat Actor", campaign: "Campaign",
};

const THREAT_LEVEL_CONFIG: Record<string, string> = {
  critical: "bg-red-500/10 text-red-400 border-red-500/20",
  high: "bg-orange-500/10 text-orange-400 border-orange-500/20",
  medium: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20",
  low: "bg-green-500/10 text-green-400 border-green-500/20",
};

export default function ThreatBriefDashboard() {
  const [briefs, setBriefs] = useState<ThreatBrief[]>([]);
  const [selectedBrief, setSelectedBrief] = useState<ThreatBrief | null>(null);
  const [distributing, setDistributing] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const v = await apiFetch<any>("/api/v1/threat-briefs/briefs");
      const arr: ThreatBrief[] = Array.isArray(v) ? v : (v.briefs ?? v.items ?? []);
      setBriefs(arr);
      if (arr.length && !selectedBrief) setSelectedBrief(arr[0]);
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  };

  useEffect(() => { load(); }, []);

  const totalBriefs = briefs.length;
  const distributedToday = briefs.filter(b => b.distributed && b.created_at?.startsWith(new Date().toISOString().slice(0, 10))).length;
  const totalRecipients = briefs.filter(b => b.distributed).reduce((s, b) => s + (b.recipient_count ?? 0), 0);
  const pendingReview = briefs.filter(b => !b.distributed).length;

  async function handleDistribute(id: string) {
    setDistributing(id);
    try {
      await apiFetch(`/api/v1/threat-briefs/briefs/${encodeURIComponent(id)}/distribute`, { method: "POST" });
      setBriefs(prev => prev.map(b => b.id === id ? { ...b, distributed: true } : b));
    } catch {} finally { setDistributing(null); }
  }

  return (
    <div className="flex flex-col gap-6 p-6 min-h-0">
      <PageHeader
        title="Threat Briefs"
        description="Curated threat intelligence briefs by type with TLP classification and distribution tracking"
        badge="Live"
        actions={<Button size="sm" variant="outline" className="gap-2" onClick={load}><RefreshCw className={cn("w-3.5 h-3.5", loading && "animate-spin")} />Refresh</Button>}
      />

      {loading ? (
        <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div></div>
      ) : error ? (
        <ErrorState message={error} onRetry={load} />
      ) : briefs.length === 0 ? (
        <EmptyState icon={FileText} title="No threat briefs" description="Once threat intelligence briefs are authored, they'll appear here for distribution." />
      ) : (
        <>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <KpiCard title="Total Briefs" value={totalBriefs} icon={FileText} trend="up" trendLabel="this period" />
            <KpiCard title="Distributed Today" value={distributedToday} icon={Send} trend="up" trendLabel="sent" />
            <KpiCard title="Recipients Reached" value={totalRecipients} icon={Users} trend="up" trendLabel="across briefs" />
            <KpiCard title="Pending Review" value={pendingReview} icon={Clock} trend="down" trendLabel="awaiting distribution" />
          </div>

          <div className="grid grid-cols-1 xl:grid-cols-5 gap-6">
            <div className="xl:col-span-2 flex flex-col gap-3">
              <h2 className="text-xs font-semibold uppercase tracking-wider text-gray-400">All Briefs</h2>
              {briefs.map((brief, i) => (
                <motion.div key={brief.id} initial={{ opacity: 0, x: -8 }} animate={{ opacity: 1, x: 0 }} transition={{ delay: i * 0.06 }}
                  onClick={() => setSelectedBrief(brief)}
                  className={cn("p-4 rounded-lg border cursor-pointer transition-colors",
                    selectedBrief?.id === brief.id ? "bg-blue-500/10 border-blue-500/40" : "bg-gray-800/50 border-gray-700/50 hover:border-gray-600")}>
                  <div className="flex items-start justify-between gap-2 mb-2">
                    <p className="text-sm font-medium text-gray-100 leading-snug line-clamp-2">{brief.title}</p>
                    <div className={cn("flex-shrink-0 px-1.5 py-0.5 rounded text-[10px] font-bold border", TLP_CONFIG[brief.tlp]?.cls)}
                      style={{ background: `${TLP_CONFIG[brief.tlp]?.bg}20` }}>TLP:{brief.tlp}</div>
                  </div>
                  <div className="flex items-center gap-2 flex-wrap">
                    <Badge className="bg-gray-700/50 text-gray-300 border-gray-600 text-xs">{BRIEF_TYPE_LABELS[brief.brief_type] ?? brief.brief_type}</Badge>
                    <Badge className={cn("border text-xs capitalize", THREAT_LEVEL_CONFIG[brief.threat_level])}>{brief.threat_level}</Badge>
                    {brief.distributed
                      ? <span className="text-xs text-green-400 ml-auto flex items-center gap-1"><Send className="w-3 h-3" /> {brief.recipient_count}</span>
                      : <span className="text-xs text-gray-500 ml-auto">Not distributed</span>}
                  </div>
                </motion.div>
              ))}
            </div>

            <Card className="xl:col-span-3">
              {selectedBrief ? (
                <>
                  <CardHeader className="pb-3">
                    <div className="flex items-start justify-between gap-3">
                      <div>
                        <CardTitle className="text-sm font-semibold leading-snug">{selectedBrief.title}</CardTitle>
                        <p className="text-xs text-gray-400 mt-1">{selectedBrief.author} · {selectedBrief.created_at}</p>
                      </div>
                      <div className={cn("flex-shrink-0 px-2 py-1 rounded text-xs font-bold border", TLP_CONFIG[selectedBrief.tlp]?.cls)}
                        style={{ background: `${TLP_CONFIG[selectedBrief.tlp]?.bg}20` }}>TLP:{selectedBrief.tlp}</div>
                    </div>
                  </CardHeader>
                  <CardContent className="flex flex-col gap-4">
                    <div className="flex items-center gap-3 flex-wrap">
                      <Badge className="bg-gray-700/50 text-gray-300 border-gray-600 text-xs">{BRIEF_TYPE_LABELS[selectedBrief.brief_type] ?? selectedBrief.brief_type}</Badge>
                      <Badge className={cn("border text-xs capitalize", THREAT_LEVEL_CONFIG[selectedBrief.threat_level])}>
                        <AlertTriangle className="w-3 h-3 mr-1" />{selectedBrief.threat_level}
                      </Badge>
                      <span className="text-xs text-gray-400 flex items-center gap-1"><Users className="w-3 h-3" /> {selectedBrief.recipient_count} recipients</span>
                    </div>
                    <div className="bg-gray-800/50 rounded-lg p-4 border border-gray-700/50">
                      <p className="text-xs font-semibold text-gray-400 mb-2 uppercase tracking-wider">Summary</p>
                      <p className="text-sm text-gray-300 leading-relaxed">{selectedBrief.summary}</p>
                    </div>
                    {selectedBrief.tags && selectedBrief.tags.length > 0 && (
                      <div>
                        <p className="text-xs font-semibold text-gray-400 mb-2 uppercase tracking-wider">Tags</p>
                        <div className="flex flex-wrap gap-2">
                          {selectedBrief.tags.map(tag => <span key={tag} className="px-2 py-0.5 bg-gray-700/50 border border-gray-600/50 rounded text-xs text-gray-300">#{tag}</span>)}
                        </div>
                      </div>
                    )}
                    <div className="pt-2">
                      {selectedBrief.distributed ? (
                        <div className="flex items-center gap-2 text-green-400 text-sm">
                          <Send className="w-4 h-4" /> Distributed to {selectedBrief.recipient_count} recipients
                        </div>
                      ) : (
                        <Button className="gap-2 bg-blue-600 hover:bg-blue-700 text-white" onClick={() => handleDistribute(selectedBrief.id)} disabled={distributing === selectedBrief.id}>
                          <Send className="w-4 h-4" />{distributing === selectedBrief.id ? "Distributing..." : "Distribute Brief"}
                        </Button>
                      )}
                    </div>
                  </CardContent>
                </>
              ) : (
                <CardContent className="flex items-center justify-center h-64">
                  <div className="text-center text-gray-500">
                    <Eye className="w-8 h-8 mx-auto mb-2 opacity-50" />
                    <p className="text-sm">Select a brief to view details</p>
                  </div>
                </CardContent>
              )}
            </Card>
          </div>
        </>
      )}
    </div>
  );
}
