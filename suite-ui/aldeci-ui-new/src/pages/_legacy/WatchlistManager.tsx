// FOLDED into ThreatIntelOpsHub at /attack/intel/ops?tab=watchlist
// Phase 3 UX consolidation 2026-05-02 — see docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.14.
// Direct route /watchlist now redirects to the hub. Component preserved and lazy-loaded by ThreatIntelOpsHub.
/**
 * Watchlist Manager
 *
 * Threat actor and IOC watchlist management.
 *   1. KPIs: Active Watchlists, Total Indicators, Matches Today, Auto-Blocked
 *   2. Watchlist table (8 rows)
 *   3. Recent matches feed (12 rows)
 *   4. Add to watchlist form (local state)
 *   5. Top matched IPs (5 cards)
 *
 * API stubs: GET /api/v1/watchlist, /api/v1/watchlist/matches, /api/v1/watchlist/add
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";

// ── API helpers ────────────────────────────────────────────────
const API_KEY = localStorage.getItem("aldeci_api_key") || import.meta.env.VITE_API_KEY || "dev-key";
const ORG_ID = "default";

async function apiFetch(path: string) {
  const res = await fetch(`/api/v1${path}`, {
    headers: { "X-API-Key": API_KEY },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}
import { Shield, Eye, Zap, List, Plus, Trash2, Pencil, RefreshCw } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── Mock data ───────────────────────────────────────────────────

const WATCHLISTS = [
  { id: "WL-001", name: "APT29 Indicators",        category: "threat_actor",  count: 842,  created: "2026-01-12", lastHit: "2026-04-16", action: "block",  status: "active" },
  { id: "WL-002", name: "Tor Exit Nodes",           category: "ip_block",      count: 1204, created: "2026-02-03", lastHit: "2026-04-16", action: "block",  status: "active" },
  { id: "WL-003", name: "Malware C2 Domains",       category: "domain_block",  count: 634,  created: "2026-02-14", lastHit: "2026-04-15", action: "block",  status: "active" },
  { id: "WL-004", name: "Known Malware Hashes",     category: "hash_block",    count: 1891, created: "2026-01-28", lastHit: "2026-04-14", action: "alert",  status: "active" },
  { id: "WL-005", name: "Insider Threat Watchlist", category: "user_monitor",  count: 14,   created: "2026-03-01", lastHit: "2026-04-12", action: "log",    status: "active" },
  { id: "WL-006", name: "Phishing Domains (Live)",  category: "domain_block",  count: 92,   created: "2026-03-15", lastHit: "2026-04-16", action: "block",  status: "active" },
  { id: "WL-007", name: "Credential Stuffing IPs",  category: "ip_block",      count: 67,   created: "2026-03-22", lastHit: "2026-04-13", action: "alert",  status: "active" },
  { id: "WL-008", name: "Shadow IT Applications",   category: "domain_block",  count: 38,   created: "2026-04-01", lastHit: "2026-04-10", action: "log",    status: "paused" },
];

const MATCHES = [
  { watchlist: "Tor Exit Nodes",       ioc: "185.220.101.47",          type: "ip",     source: "WAF",   action: "Blocked",  time: "04:12",  severity: "high"     },
  { watchlist: "Malware C2 Domains",   ioc: "update-cdn.evil.ru",      type: "domain", source: "DNS",   action: "Blocked",  time: "03:58",  severity: "critical"  },
  { watchlist: "APT29 Indicators",     ioc: "3f5a...c91b",             type: "hash",   source: "EDR",   action: "Alerted",  time: "03:44",  severity: "critical"  },
  { watchlist: "Phishing Domains",     ioc: "secure-login.paypa1.com", type: "domain", source: "Email", action: "Blocked",  time: "03:31",  severity: "high"      },
  { watchlist: "Tor Exit Nodes",       ioc: "194.165.16.10",           type: "ip",     source: "NDR",   action: "Blocked",  time: "03:18",  severity: "medium"    },
  { watchlist: "Insider Threat",       ioc: "svc_account_092",         type: "user",   source: "IAM",   action: "Logged",   time: "02:55",  severity: "high"      },
  { watchlist: "Known Malware Hashes", ioc: "d4e2...7a3f",             type: "hash",   source: "EDR",   action: "Alerted",  time: "02:39",  severity: "critical"  },
  { watchlist: "Credential Stuffing",  ioc: "45.134.26.174",           type: "ip",     source: "IAM",   action: "Alerted",  time: "02:22",  severity: "medium"    },
  { watchlist: "Malware C2 Domains",   ioc: "cdn.malware-stage.net",   type: "domain", source: "Proxy", action: "Blocked",  time: "02:08",  severity: "high"      },
  { watchlist: "Tor Exit Nodes",       ioc: "176.10.99.200",           type: "ip",     source: "WAF",   action: "Blocked",  time: "01:51",  severity: "medium"    },
  { watchlist: "APT29 Indicators",     ioc: "91.108.4.222",            type: "ip",     source: "SIEM",  action: "Alerted",  time: "01:34",  severity: "high"      },
  { watchlist: "Phishing Domains",     ioc: "docusign-verify.cc",      type: "domain", source: "DNS",   action: "Blocked",  time: "01:17",  severity: "high"      },
];

const TOP_IPS = [
  { ip: "185.220.101.47", count: 47, country: "🇩🇪", firstSeen: "2026-04-10", lastSeen: "2026-04-16", category: "ip_block" },
  { ip: "194.165.16.10",  count: 31, country: "🇷🇺", firstSeen: "2026-04-08", lastSeen: "2026-04-16", category: "ip_block" },
  { ip: "45.134.26.174",  count: 24, country: "🇧🇬", firstSeen: "2026-04-11", lastSeen: "2026-04-15", category: "threat_actor" },
  { ip: "176.10.99.200",  count: 19, country: "🇨🇭", firstSeen: "2026-04-09", lastSeen: "2026-04-16", category: "ip_block" },
  { ip: "91.108.4.222",   count: 14, country: "🇳🇱", firstSeen: "2026-04-12", lastSeen: "2026-04-15", category: "threat_actor" },
];

const WATCHLIST_OPTIONS = ["WL-001 APT29", "WL-002 Tor Exit", "WL-003 C2 Domains", "WL-004 Hashes", "WL-005 Insider"];
const TYPE_OPTIONS = ["ip", "domain", "hash", "url", "user"];

// ── Helpers ────────────────────────────────────────────────────

function CategoryBadge({ cat }: { cat: string }) {
  const map: Record<string, string> = {
    threat_actor:  "border-red-500/30 text-red-400 bg-red-500/10",
    ip_block:      "border-orange-500/30 text-orange-400 bg-orange-500/10",
    domain_block:  "border-purple-500/30 text-purple-400 bg-purple-500/10",
    hash_block:    "border-blue-500/30 text-blue-400 bg-blue-500/10",
    user_monitor:  "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
  };
  const labels: Record<string, string> = {
    threat_actor: "Threat Actor",
    ip_block:     "IP Block",
    domain_block: "Domain Block",
    hash_block:   "Hash Block",
    user_monitor: "User Monitor",
  };
  return <Badge className={cn("text-[10px] border whitespace-nowrap", map[cat] ?? "")}>{labels[cat] ?? cat}</Badge>;
}

function ActionBadge({ action }: { action: string }) {
  const map: Record<string, string> = {
    block: "border-red-500/30 text-red-400 bg-red-500/10",
    alert: "border-amber-500/30 text-amber-400 bg-amber-500/10",
    log:   "border-border text-muted-foreground",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[action] ?? "")}>{action}</Badge>;
}

function SeverityBadge({ sev }: { sev: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
    medium:   "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    low:      "border-border text-muted-foreground",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[sev] ?? "")}>{sev}</Badge>;
}

// ── Component ──────────────────────────────────────────────────

export default function WatchlistManager() {
  const [refreshing, setRefreshing]   = useState(false);
  const [iocInput, setIocInput]       = useState("");
  const [iocType, setIocType]         = useState("ip");
  const [targetList, setTargetList]   = useState(WATCHLIST_OPTIONS[0]);
  const [added, setAdded]             = useState<string[]>([]);
  const [liveData, setLiveData]       = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);

  const fetchData = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/ioc-enrichment/stats?org_id=${ORG_ID}`),
      apiFetch(`/ioc-enrichment/iocs?org_id=${ORG_ID}&limit=50`),
      apiFetch(`/threat-actors?org_id=${ORG_ID}&limit=20`),
    ]).then(([statsResult, iocsResult, actorsResult]) => {
      const stats   = statsResult.status   === "fulfilled" ? statsResult.value   : null;
      const iocs    = iocsResult.status    === "fulfilled" ? iocsResult.value    : null;
      const actors  = actorsResult.status  === "fulfilled" ? actorsResult.value  : null;
      if (stats || iocs || actors) {
        setLiveData({ stats, iocs, actors });
      }
    }).finally(() => setDataLoading(false));
  };

  useEffect(() => { fetchData(); }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchData();
    setTimeout(() => setRefreshing(false), 800);
  };

  const handleAdd = () => {
    if (!iocInput.trim()) return;
    setAdded((prev) => [`${iocInput} → ${targetList}`, ...prev]);
    setIocInput("");
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      {/* Header */}
      <PageHeader
        title="Watchlist Manager"
        description="Threat actor and IOC watchlist management"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Active Watchlists"   value={liveData?.stats?.watchlist_count ?? 12}    icon={List}   trend="up" />
        <KpiCard title="Total Indicators"    value={liveData?.stats?.total ?? "4,782"}         icon={Shield} trend="up" />
        <KpiCard title="Matches Today"       value={liveData?.stats?.by_severity ? ((liveData.stats.by_severity.critical ?? 0) + (liveData.stats.by_severity.high ?? 0)) : 23} icon={Eye} trend="up" className="border-amber-500/20" />
        <KpiCard title="Auto-Blocked"        value={liveData?.stats?.enriched_count ?? 187}    icon={Zap}    trend="up" className="border-green-500/20" />
      </div>

      {/* Watchlist Table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <List className="h-4 w-4 text-blue-400" />
              Active Watchlists
            </CardTitle>
            <Badge className="text-[10px] border border-border text-muted-foreground">
              {WATCHLISTS.length} lists
            </Badge>
          </div>
          <CardDescription className="text-xs">Managed IOC lists with automatic enforcement actions</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">ID</TableHead>
                  <TableHead className="text-[11px] h-8">Name</TableHead>
                  <TableHead className="text-[11px] h-8">Category</TableHead>
                  <TableHead className="text-[11px] h-8">Indicators</TableHead>
                  <TableHead className="text-[11px] h-8">Created</TableHead>
                  <TableHead className="text-[11px] h-8">Last Hit</TableHead>
                  <TableHead className="text-[11px] h-8">Auto-Action</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {WATCHLISTS.map((row) => (
                  <TableRow key={row.id} className="hover:bg-muted/30">
                    <TableCell className="text-xs font-mono py-2 text-muted-foreground">{row.id}</TableCell>
                    <TableCell className="text-xs py-2 font-medium">{row.name}</TableCell>
                    <TableCell className="py-2"><CategoryBadge cat={row.category} /></TableCell>
                    <TableCell className="text-xs py-2 tabular-nums font-bold">{row.count.toLocaleString()}</TableCell>
                    <TableCell className="text-xs py-2 tabular-nums text-muted-foreground">{row.created}</TableCell>
                    <TableCell className="text-xs py-2 tabular-nums text-muted-foreground">{row.lastHit}</TableCell>
                    <TableCell className="py-2"><ActionBadge action={row.action} /></TableCell>
                    <TableCell className="py-2">
                      <Badge className={cn(
                        "text-[10px] border capitalize",
                        row.status === "active"
                          ? "border-green-500/30 text-green-400 bg-green-500/10"
                          : "border-border text-muted-foreground"
                      )}>
                        {row.status}
                      </Badge>
                    </TableCell>
                    <TableCell className="py-2 text-right">
                      <div className="flex items-center justify-end gap-1">
                        <Button variant="ghost" size="sm" className="h-6 w-6 p-0 text-muted-foreground hover:text-foreground">
                          <Pencil className="h-3 w-3" />
                        </Button>
                        <Button variant="ghost" size="sm" className="h-6 w-6 p-0 text-muted-foreground hover:text-red-400">
                          <Trash2 className="h-3 w-3" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Recent Matches + Add to Watchlist */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        {/* Recent Matches Feed — spans 2 cols */}
        <Card className="lg:col-span-2">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Eye className="h-4 w-4 text-amber-400" />
              Recent Matches
            </CardTitle>
            <CardDescription className="text-xs">IOC hits against active watchlists — last 6 hours</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Watchlist</TableHead>
                    <TableHead className="text-[11px] h-8">Matched IOC</TableHead>
                    <TableHead className="text-[11px] h-8">Type</TableHead>
                    <TableHead className="text-[11px] h-8">Source</TableHead>
                    <TableHead className="text-[11px] h-8">Action</TableHead>
                    <TableHead className="text-[11px] h-8">Time</TableHead>
                    <TableHead className="text-[11px] h-8">Severity</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {MATCHES.map((row, idx) => (
                    <TableRow key={idx} className="hover:bg-muted/30">
                      <TableCell className="text-xs py-2 max-w-[120px] truncate">{row.watchlist}</TableCell>
                      <TableCell className="text-xs py-2 font-mono max-w-[140px] truncate text-muted-foreground">
                        {row.ioc}
                      </TableCell>
                      <TableCell className="py-2">
                        <Badge className="text-[10px] border border-border text-muted-foreground capitalize">{row.type}</Badge>
                      </TableCell>
                      <TableCell className="py-2">
                        <Badge className="text-[10px] border border-border text-muted-foreground">{row.source}</Badge>
                      </TableCell>
                      <TableCell className="text-xs py-2 text-muted-foreground">{row.action}</TableCell>
                      <TableCell className="text-xs py-2 tabular-nums text-muted-foreground">{row.time}</TableCell>
                      <TableCell className="py-2"><SeverityBadge sev={row.severity} /></TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>

        {/* Add to Watchlist Form */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Plus className="h-4 w-4 text-green-400" />
              Add Indicator
            </CardTitle>
            <CardDescription className="text-xs">Manually add an IOC to a watchlist</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col gap-3">
            <div className="flex flex-col gap-1.5">
              <label className="text-[11px] text-muted-foreground font-medium">IOC Value</label>
              <Input
                placeholder="e.g. 192.168.1.1, evil.com"
                value={iocInput}
                onChange={(e) => setIocInput(e.target.value)}
                className="h-8 text-xs"
              />
            </div>
            <div className="flex flex-col gap-1.5">
              <label className="text-[11px] text-muted-foreground font-medium">Type</label>
              <select
                value={iocType}
                onChange={(e) => setIocType(e.target.value)}
                className="h-8 rounded-md border border-border bg-background px-2 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-ring"
              >
                {TYPE_OPTIONS.map((t) => (
                  <option key={t} value={t}>{t}</option>
                ))}
              </select>
            </div>
            <div className="flex flex-col gap-1.5">
              <label className="text-[11px] text-muted-foreground font-medium">Watchlist</label>
              <select
                value={targetList}
                onChange={(e) => setTargetList(e.target.value)}
                className="h-8 rounded-md border border-border bg-background px-2 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-ring"
              >
                {WATCHLIST_OPTIONS.map((w) => (
                  <option key={w} value={w}>{w}</option>
                ))}
              </select>
            </div>
            <Button size="sm" className="h-8 text-xs" onClick={handleAdd}>
              <Plus className="h-3 w-3 mr-1" />
              Add Indicator
            </Button>
            {added.length > 0 && (
              <div className="mt-1 space-y-1">
                <p className="text-[10px] text-muted-foreground font-medium">Recently added:</p>
                {added.slice(0, 4).map((entry, idx) => (
                  <div key={idx} className="text-[10px] text-green-400 font-mono truncate">{entry}</div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Top Matched IPs */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Zap className="h-4 w-4 text-red-400" />
            Top Matched IPs
          </CardTitle>
          <CardDescription className="text-xs">Highest-frequency IP matches across all watchlists</CardDescription>
        </CardHeader>
        <CardContent className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-5">
          {TOP_IPS.map((ip) => (
            <div
              key={ip.ip}
              className="rounded-lg border border-border bg-muted/10 p-3 flex flex-col gap-2"
            >
              <div className="flex items-center justify-between">
                <span className="text-lg">{ip.country}</span>
                <span className="text-xl font-bold tabular-nums text-red-400">{ip.count}</span>
              </div>
              <div className="font-mono text-xs font-semibold truncate">{ip.ip}</div>
              <CategoryBadge cat={ip.category} />
              <div className="space-y-0.5">
                <div className="text-[9px] text-muted-foreground">First: {ip.firstSeen}</div>
                <div className="text-[9px] text-muted-foreground">Last: {ip.lastSeen}</div>
              </div>
            </div>
          ))}
        </CardContent>
      </Card>
    </motion.div>
  );
}
