import { useState, useCallback, useMemo } from "react";
import { toast } from "sonner";
import { motion } from "framer-motion";
import {
  Rss, RefreshCw, Download, AlertTriangle, CheckCircle,
  Activity, Shield, TrendingUp, Zap, ToggleLeft, ToggleRight,
  Clock, Filter, ExternalLink, Brain, ChevronDown, ChevronRight,
  Search,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { Skeleton } from "@/components/ui/skeleton";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { ErrorState } from "@/components/shared/ErrorState";
import { useThreatFeeds, useThreatTrending } from "@/hooks/use-api";
import { copilotApi } from "@/lib/api";
import { cn } from "@/lib/utils";
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
} from "recharts";

interface ThreatFeed {
  id?: string;
  name?: string;
  type?: string;
  feed_type?: string;
  status?: string;
  enabled?: boolean;
  active?: boolean;
  last_updated?: string;
  last_synced?: string;
  item_count?: number;
  items?: number;
  description?: string;
  url?: string;
  error_message?: string;
}

interface TrendingCve {
  cve_id?: string;
  id?: string;
  severity?: string;
  epss_score?: number;
  kev?: boolean;
  in_kev?: boolean;
  description?: string;
  published?: string;
  product?: string;
  vendor?: string;
  cvss_score?: number;
}

function FeedStatusBadge({ status, enabled }: { status?: string; enabled?: boolean }) {
  if (enabled === false || status?.toLowerCase() === "disabled") {
    return <Badge className="bg-slate-500/10 text-slate-400 border-slate-500/20 border text-xs">Disabled</Badge>;
  }
  const s = (status || "").toLowerCase();
  const map: Record<string, string> = {
    active: "bg-green-500/10 text-green-400 border-green-500/20",
    error: "bg-red-500/10 text-red-400 border-red-500/20",
    syncing: "bg-blue-500/10 text-blue-400 border-blue-500/20",
    degraded: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20",
  };
  return <Badge className={cn("border text-xs", map[s] || map["active"])}>{status || "Active"}</Badge>;
}

function SeverityBadge({ severity }: { severity?: string }) {
  const s = (severity || "").toLowerCase();
  const map: Record<string, string> = {
    critical: "bg-red-500/15 text-red-400 border-red-500/30",
    high: "bg-orange-500/15 text-orange-400 border-orange-500/30",
    medium: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
    low: "bg-blue-500/15 text-blue-400 border-blue-500/30",
  };
  return <Badge className={cn("border text-xs font-semibold uppercase", map[s] || "bg-slate-500/15 text-slate-400 border-slate-500/20")}>{severity || "Unknown"}</Badge>;
}

const MITRE_FILLS: Record<string, string> = {
  "Initial Access": "#ef4444",
  "Execution": "#f97316",
  "Persistence": "#eab308",
  "Privilege Escalation": "#8b5cf6",
  "Defense Evasion": "#06b6d4",
  "Other": "#6b7280",
};

export default function ThreatFeeds() {
  const [statusFilter, setStatusFilter] = useState("all");
  const [typeFilter, setTypeFilter] = useState("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [feedStates, setFeedStates] = useState<Record<string, boolean>>({});

  const feedsQuery = useThreatFeeds();
  const trendingQuery = useThreatTrending();
  const refetch = useCallback(() => { feedsQuery.refetch(); trendingQuery.refetch(); }, [feedsQuery, trendingQuery]);

  const allFeeds: ThreatFeed[] = useMemo(() => {
    const d = feedsQuery.data;
    if (!d) return [];
    if (Array.isArray(d)) return d;
    if (Array.isArray(d?.feeds)) return d.feeds;
    if (Array.isArray(d?.items)) return d.items;
    if (Array.isArray(d?.data)) return d.data;
    return [];
  }, [feedsQuery.data]);

  const trendingCves: TrendingCve[] = useMemo(() => {
    const d = trendingQuery.data;
    if (!d) return [];
    if (Array.isArray(d)) return d;
    if (Array.isArray(d?.cves)) return d.cves;
    if (Array.isArray(d?.trending)) return d.trending;
    if (Array.isArray(d?.items)) return d.items;
    if (Array.isArray(d?.data)) return d.data;
    return [];
  }, [trendingQuery.data]);

  const filtered = useMemo(() => {
    let list = allFeeds;
    if (statusFilter !== "all") {
      list = list.filter((f) => {
        if (statusFilter === "active") return f.status?.toLowerCase() === "active" || f.enabled !== false;
        if (statusFilter === "error") return f.status?.toLowerCase() === "error";
        if (statusFilter === "disabled") return f.status?.toLowerCase() === "disabled" || f.enabled === false;
        return true;
      });
    }
    if (typeFilter !== "all") {
      list = list.filter((f) => (f.type || f.feed_type || "").toLowerCase() === typeFilter);
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      list = list.filter((f) => f.name?.toLowerCase().includes(q) || f.type?.toLowerCase().includes(q));
    }
    return list;
  }, [allFeeds, statusFilter, typeFilter, searchQuery]);

  const stats = useMemo(() => {
    const active = allFeeds.filter((f) => f.status?.toLowerCase() !== "disabled" && f.enabled !== false).length;
    const trendingCount = trendingCves.length;
    const kevCount = trendingCves.filter((c) => c.kev || c.in_kev).length;
    const highEpss = trendingCves.filter((c) => (c.epss_score || 0) > 0.9).length;
    return { active, trending: trendingCount, kev: kevCount, highEpss };
  }, [allFeeds, trendingCves]);

  const feedTypes = useMemo(() =>
    Array.from(new Set(allFeeds.map((f) => f.type || f.feed_type).filter(Boolean))),
    [allFeeds]
  );

  // Derive MITRE ATT&CK data from trending CVEs instead of hardcoded constants
  const mitreData = useMemo(() => {
    if (trendingCves.length === 0) return [];
    const counts: Record<string, number> = {};
    trendingCves.forEach((c) => {
      const tactic = (c as Record<string, unknown>).mitre_tactic as string | undefined;
      const key = tactic || "Other";
      counts[key] = (counts[key] || 0) + 1;
    });
    // If no MITRE tactic data, show a single "Uncategorized" entry
    if (Object.keys(counts).length === 0 || (Object.keys(counts).length === 1 && counts["Other"])) {
      return [{ name: "Uncategorized", value: trendingCves.length, fill: "#6b7280" }];
    }
    return Object.entries(counts).map(([name, value]) => ({
      name,
      value,
      fill: MITRE_FILLS[name] || MITRE_FILLS["Other"],
    }));
  }, [trendingCves]);

  function getFeedEnabled(feed: ThreatFeed): boolean {
    const id = feed.id || feed.name || "";
    if (id in feedStates) return feedStates[id];
    return feed.enabled !== false && feed.status?.toLowerCase() !== "disabled";
  }

  function toggleFeed(feed: ThreatFeed) {
    const id = feed.id || feed.name || "";
    const current = getFeedEnabled(feed);
    setFeedStates((prev) => ({ ...prev, [id]: !current }));
  }

  if (feedsQuery.isLoading) {
    return (
      <div className="space-y-6 p-6">
        <Skeleton className="h-10 w-64" />
        <div className="grid grid-cols-4 gap-4">
          {Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-28" />)}
        </div>
        <div className="grid grid-cols-2 gap-4">
          <Skeleton className="h-80" />
          <Skeleton className="h-80" />
        </div>
        <Skeleton className="h-64" />
      </div>
    );
  }

  if (feedsQuery.isError) {
    return <ErrorState message="Failed to load threat intelligence feeds." onRetry={refetch} />;
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      <PageHeader title="Threat Feeds" description="Threat intelligence management and trending CVE monitoring">
        <Button variant="outline" size="sm" onClick={refetch} className="gap-2">
          <RefreshCw className="h-4 w-4" /> Sync All
        </Button>
        <Button variant="outline" size="sm" className="gap-2" onClick={() => {
          const exportData = { feeds: allFeeds, trending: trendingCves };
          const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: "application/json" });
          const url = URL.createObjectURL(blob);
          const a = document.createElement("a"); a.href = url; a.download = "threat-feeds-export.json"; a.click();
          URL.revokeObjectURL(url);
          toast.success(`Exported ${allFeeds.length} feeds and ${trendingCves.length} trending CVEs`);
        }}>
          <Download className="h-4 w-4" /> Export
        </Button>
      </PageHeader>

      {/* KPI Row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Active Feeds" value={stats.active} icon={Rss} />
        <KpiCard title="Trending CVEs" value={stats.trending} icon={TrendingUp} className="border-orange-500/20" />
        <KpiCard title="KEV Count" value={stats.kev} icon={AlertTriangle} className="border-red-500/20" />
        <KpiCard title="EPSS > 0.9" value={stats.highEpss} icon={Zap} className="border-yellow-500/20" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Feed Status Table */}
        <div className="lg:col-span-2 space-y-4">
          {/* Filters */}
          <div className="flex flex-wrap gap-3">
            <div className="relative flex-1 min-w-[180px]">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search feeds..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-9"
              />
            </div>
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="w-36">
                <SelectValue placeholder="Status" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Status</SelectItem>
                <SelectItem value="active">Active</SelectItem>
                <SelectItem value="error">Error</SelectItem>
                <SelectItem value="disabled">Disabled</SelectItem>
              </SelectContent>
            </Select>
            {feedTypes.length > 0 && (
              <Select value={typeFilter} onValueChange={setTypeFilter}>
                <SelectTrigger className="w-36">
                  <SelectValue placeholder="Type" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Types</SelectItem>
                  {feedTypes.map((t) => (
                    <SelectItem key={t} value={t!}>{t}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            )}
          </div>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm text-muted-foreground">{filtered.length} feeds</CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead>Feed Name</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Last Updated</TableHead>
                    <TableHead className="text-right">Items</TableHead>
                    <TableHead className="text-center w-20">Enabled</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filtered.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={6} className="text-center py-12 text-muted-foreground">
                        <div className="flex flex-col items-center gap-2">
                          <Rss className="h-8 w-8 opacity-30" />
                          <p>No feeds found</p>
                        </div>
                      </TableCell>
                    </TableRow>
                  ) : (
                    filtered.map((feed, idx) => {
                      const id = feed.id || feed.name || String(idx);
                      const isEnabled = getFeedEnabled(feed);
                      return (
                        <TableRow key={id} className="hover:bg-muted/40">
                          <TableCell>
                            <div>
                              <p className="text-sm font-medium">{feed.name || "—"}</p>
                              {feed.description && (
                                <p className="text-xs text-muted-foreground truncate max-w-[200px]">{feed.description}</p>
                              )}
                            </div>
                          </TableCell>
                          <TableCell>
                            <Badge variant="outline" className="text-xs">{feed.type || feed.feed_type || "—"}</Badge>
                          </TableCell>
                          <TableCell>
                            <FeedStatusBadge status={feed.status} enabled={isEnabled} />
                            {feed.error_message && (
                              <p className="text-xs text-red-400 mt-0.5 truncate max-w-[150px]">{feed.error_message}</p>
                            )}
                          </TableCell>
                          <TableCell className="text-xs text-muted-foreground whitespace-nowrap">
                            <div className="flex items-center gap-1">
                              <Clock className="h-3 w-3" />
                              {feed.last_updated || feed.last_synced
                                ? new Date(feed.last_updated || feed.last_synced || "").toLocaleDateString()
                                : "—"}
                            </div>
                          </TableCell>
                          <TableCell className="text-right font-mono text-sm">
                            {(feed.item_count || feed.items || 0).toLocaleString()}
                          </TableCell>
                          <TableCell className="text-center">
                            <Switch
                              checked={isEnabled}
                              onCheckedChange={() => toggleFeed(feed)}
                              className="data-[state=checked]:bg-primary"
                            />
                          </TableCell>
                        </TableRow>
                      );
                    })
                  )}
                </TableBody>
              </Table>
              </div>
            </CardContent>
          </Card>

          {/* Trending CVEs Section */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm flex items-center justify-between">
                <span className="flex items-center gap-2">
                  <TrendingUp className="h-4 w-4 text-orange-400" />
                  Trending CVEs This Week
                </span>
                <Badge variant="outline" className="text-xs">{trendingCves.length} total</Badge>
              </CardTitle>
            </CardHeader>
            <CardContent>
              {trendingCves.length === 0 ? (
                <div className="text-center py-8 text-muted-foreground">
                  <TrendingUp className="h-8 w-8 opacity-30 mx-auto mb-2" />
                  <p className="text-sm">No trending CVEs available</p>
                </div>
              ) : (
                <div className="space-y-3">
                  {trendingCves.slice(0, 8).map((cve, i) => {
                    const cveId = cve.cve_id || cve.id || `CVE-${i}`;
                    const isKev = cve.kev || cve.in_kev;
                    return (
                      <div key={cveId} className="flex items-start gap-3 p-2 rounded-md hover:bg-muted/30 transition-colors">
                        <div className="shrink-0 mt-0.5">
                          <SeverityBadge severity={cve.severity} />
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="font-mono text-xs font-bold text-primary">{cveId}</span>
                            {isKev && (
                              <Badge className="bg-red-500/10 text-red-400 border-red-500/20 border text-xs">KEV</Badge>
                            )}
                            {cve.epss_score !== undefined && (
                              <Badge className={cn(
                                "border text-xs",
                                (cve.epss_score || 0) > 0.9 ? "bg-red-500/10 text-red-400 border-red-500/20" :
                                  (cve.epss_score || 0) > 0.5 ? "bg-orange-500/10 text-orange-400 border-orange-500/20" :
                                    "bg-slate-500/10 text-slate-400 border-slate-500/20"
                              )}>
                                EPSS {((cve.epss_score || 0) * 100).toFixed(1)}%
                              </Badge>
                            )}
                          </div>
                          {cve.description && (
                            <p className="text-xs text-muted-foreground truncate mt-0.5">{cve.description}</p>
                          )}
                          {(cve.product || cve.vendor) && (
                            <p className="text-xs text-muted-foreground">{cve.vendor} / {cve.product}</p>
                          )}
                        </div>
                        {cve.cvss_score !== undefined && (
                          <span className={cn(
                            "text-xs font-mono font-bold shrink-0",
                            (cve.cvss_score || 0) >= 9 ? "text-red-400" :
                              (cve.cvss_score || 0) >= 7 ? "text-orange-400" : "text-yellow-400"
                          )}>
                            CVSS {cve.cvss_score?.toFixed(1)}
                          </span>
                        )}
                        <Button variant="ghost" size="icon" className="h-6 w-6 shrink-0" onClick={() => {
                          const id = cve.cve_id || cve.id || "";
                          window.open(`https://nvd.nist.gov/vuln/detail/${id}`, "_blank");
                        }}>
                          <ExternalLink className="h-3 w-3" />
                        </Button>
                      </div>
                    );
                  })}
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        {/* Right Sidebar: MITRE ATT&CK + AI Briefing */}
        <div className="space-y-4">
          {/* MITRE ATT&CK Coverage */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm flex items-center gap-2">
                <Shield className="h-4 w-4 text-primary" />
                MITRE ATT&CK Coverage
              </CardTitle>
            </CardHeader>
            <CardContent>
              {mitreData.length > 0 ? (
              <>
              <ResponsiveContainer width="100%" height={200}>
                <PieChart>
                  <Pie
                    data={mitreData}
                    dataKey="value"
                    nameKey="name"
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={80}
                    paddingAngle={2}
                  >
                    {mitreData.map((entry, i) => (
                      <Cell key={i} fill={entry.fill} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{ background: "hsl(var(--popover))", border: "1px solid hsl(var(--border))", borderRadius: 8, fontSize: 11 }}
                  />
                </PieChart>
              </ResponsiveContainer>
              <div className="space-y-1 mt-2">
                {mitreData.map((item) => (
                  <div key={item.name} className="flex items-center justify-between text-xs">
                    <div className="flex items-center gap-1.5">
                      <div className="w-2 h-2 rounded-full" style={{ background: item.fill }} />
                      <span className="text-muted-foreground">{item.name}</span>
                    </div>
                    <span className="font-mono font-bold">{item.value}</span>
                  </div>
                ))}
              </div>
              </>
              ) : (
                <div className="flex flex-col items-center justify-center h-[200px] text-muted-foreground text-xs">
                  <Shield className="h-8 w-8 mb-2 opacity-30" />
                  <p>No MITRE ATT&CK data available</p>
                  <p className="text-[10px] mt-1">Requires trending CVE data with tactic mappings</p>
                </div>
              )}
            </CardContent>
          </Card>

          {/* AI Threat Briefing */}
          <Card className="border-primary/20">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm flex items-center gap-2">
                <Brain className="h-4 w-4 text-primary" />
                AI Threat Briefing
                <Badge className="bg-primary/15 text-primary border-primary/30 border text-xs ml-auto">AI</Badge>
              </CardTitle>
            </CardHeader>
            <CardContent>
              {trendingCves.length > 0 ? (
                <div className="space-y-3">
                  <div className="p-3 bg-primary/5 border border-primary/15 rounded-md">
                    <p className="text-xs leading-relaxed text-muted-foreground">
                      Based on current threat intelligence, <span className="text-foreground font-medium">{stats.kev} CVEs</span> are
                      listed in CISA's Known Exploited Vulnerabilities catalog.{" "}
                      {stats.highEpss > 0 && (
                        <>
                          <span className="text-orange-400 font-medium">{stats.highEpss} vulnerabilities</span> have an EPSS score above 0.9,
                          indicating high exploitation probability in the next 30 days.{" "}
                        </>
                      )}
                      Prioritize patching KEV-listed vulnerabilities and high EPSS-scored components immediately.
                    </p>
                  </div>
                  {stats.kev > 0 && (
                    <div className="flex items-start gap-2 p-2 bg-red-500/5 border border-red-500/20 rounded-md">
                      <AlertTriangle className="h-3.5 w-3.5 text-red-400 shrink-0 mt-0.5" />
                      <p className="text-xs text-red-400">
                        {stats.kev} active KEVs require immediate remediation per CISA mandate.
                      </p>
                    </div>
                  )}
                </div>
              ) : (
                <div className="p-3 bg-muted/20 rounded-md">
                  <p className="text-xs text-muted-foreground">
                    AI briefing will appear once threat feed data is available. Sync feeds to generate intelligence report.
                  </p>
                </div>
              )}
              <Button size="sm" variant="outline" className="w-full mt-3 gap-2" onClick={async () => {
                try {
                  toast.info("Generating AI threat briefing...");
                  await copilotApi.suggest({ context: "threat_briefing", feeds: allFeeds.map(f => f.name) });
                  toast.success("Threat briefing generated");
                  feedsQuery.refetch();
                } catch { toast.error("Briefing generation failed"); }
              }}>
                <Brain className="h-3.5 w-3.5" /> Generate Full Briefing
              </Button>
            </CardContent>
          </Card>

          {/* Feed Health Summary */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm">Feed Health</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              {[
                {
                  label: "Active", count: allFeeds.filter((f) => f.status?.toLowerCase() === "active" || f.enabled !== false).length,
                  icon: CheckCircle, color: "text-green-400"
                },
                {
                  label: "Error", count: allFeeds.filter((f) => f.status?.toLowerCase() === "error").length,
                  icon: AlertTriangle, color: "text-red-400"
                },
                {
                  label: "Disabled", count: allFeeds.filter((f) => f.status?.toLowerCase() === "disabled" || f.enabled === false).length,
                  icon: ToggleLeft, color: "text-slate-400"
                },
              ].map(({ label, count, icon: Icon, color }) => (
                <div key={label} className="flex items-center justify-between text-sm">
                  <div className="flex items-center gap-2">
                    <Icon className={cn("h-3.5 w-3.5", color)} />
                    <span className="text-muted-foreground">{label}</span>
                  </div>
                  <span className={cn("font-mono font-bold", color)}>{count}</span>
                </div>
              ))}
              <Separator />
              <div className="flex items-center justify-between text-sm">
                <span className="text-muted-foreground">Total</span>
                <span className="font-mono font-bold">{allFeeds.length}</span>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </motion.div>
  );
}
