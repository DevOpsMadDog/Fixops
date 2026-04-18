/**
 * Threat Feed Dashboard
 *
 * Aggregated threat intelligence from 28+ sources.
 *   1. 4 KPI cards
 *   2. Feed source table (12 rows)
 *   3. Recent threat items feed (15 rows)
 *   4. IOC search (text + type filter + mock results)
 *   5. Feed type distribution bars
 *   6. Top APT campaigns (6 cards)
 *
 * Route: /threat-feeds
 * API stubs: GET /api/v1/feeds/status, /api/v1/feeds/iocs
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Rss, Shield, AlertTriangle, Activity, Search,
  RefreshCw, BarChart3, Globe, Bug, Crosshair, Filter,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── Mock data ──────────────────────────────────────────────────

const FEEDS = [
  { name: "NVD CVE Feed",           type: "cve",          format: "JSON",  freq: "Hourly",  lastFetched: "2m ago",   items: 234871, reliability: 98, enabled: true  },
  { name: "CISA KEV Catalog",       type: "cve",          format: "JSON",  freq: "Daily",   lastFetched: "1h ago",   items: 1071,   reliability: 99, enabled: true  },
  { name: "Feodo C2 Tracker",       type: "ip_blocklist", format: "CSV",   freq: "6h",      lastFetched: "3h ago",   items: 12493,  reliability: 95, enabled: true  },
  { name: "AbuseIPDB",              type: "ip_blocklist", format: "JSON",  freq: "Realtime",lastFetched: "30s ago",  items: 847293, reliability: 91, enabled: true  },
  { name: "URLhaus",                type: "domain",       format: "CSV",   freq: "5m",      lastFetched: "4m ago",   items: 98421,  reliability: 94, enabled: true  },
  { name: "OTX AlienVault",         type: "apt_campaign", format: "STIX",  freq: "Hourly",  lastFetched: "52m ago",  items: 3841,   reliability: 88, enabled: true  },
  { name: "MITRE ATT&CK",           type: "apt_campaign", format: "STIX",  freq: "Weekly",  lastFetched: "2d ago",   items: 14263,  reliability: 99, enabled: true  },
  { name: "OSV Vulnerability DB",   type: "cve",          format: "JSON",  freq: "Daily",   lastFetched: "6h ago",   items: 71208,  reliability: 97, enabled: true  },
  { name: "PhishTank",              type: "domain",       format: "CSV",   freq: "Hourly",  lastFetched: "48m ago",  items: 28493,  reliability: 82, enabled: true  },
  { name: "Shodan InternetDB",      type: "osint",        format: "JSON",  freq: "Realtime",lastFetched: "1m ago",   items: 0,      reliability: 93, enabled: true  },
  { name: "Malware Bazaar",         type: "malware",      format: "JSON",  freq: "15m",     lastFetched: "11m ago",  items: 58721,  reliability: 96, enabled: true  },
  { name: "Threat Fox IOCs",        type: "malware",      format: "JSON",  freq: "Hourly",  lastFetched: "31m ago",  items: 24198,  reliability: 93, enabled: false },
];

const RECENT_ITEMS = [
  { sev: "critical", title: "RCE exploit in-the-wild for CVE-2025-29927",          source: "NVD",            iocs: 3,  time: "2m ago"  },
  { sev: "critical", title: "LockBit 4.0 ransomware new C2 infrastructure detected",source: "OTX AlienVault",iocs: 47, time: "8m ago"  },
  { sev: "high",     title: "Mass phishing campaign targeting SaaS credentials",     source: "PhishTank",     iocs: 892,time: "14m ago" },
  { sev: "high",     title: "Cobalt Strike beacon C2: 194.165.16.10",              source: "Feodo Tracker",  iocs: 1,  time: "19m ago" },
  { sev: "high",     title: "APT29 spear-phishing via malicious Office macros",     source: "MITRE ATT&CK",  iocs: 12, time: "23m ago" },
  { sev: "high",     title: "Critical vuln in OpenSSH CVE-2026-0118 PoC released", source: "OSV DB",        iocs: 2,  time: "31m ago" },
  { sev: "medium",   title: "New magecart skimmer targeting e-commerce checkouts",  source: "URLhaus",       iocs: 18, time: "44m ago" },
  { sev: "medium",   title: "Exposed Redis instances targeted by cryptominer botnet",source: "Shodan",       iocs: 23, time: "51m ago" },
  { sev: "medium",   title: "Emotet resurgence: new malspam campaign detected",     source: "Malware Bazaar",iocs: 6,  time: "1h ago"  },
  { sev: "medium",   title: "Log4Shell exploitation attempts still active in 2026",  source: "AbuseIPDB",    iocs: 341,time: "1h ago"  },
  { sev: "low",      title: "TLS certificate abuse for phishing domains registered", source: "URLhaus",      iocs: 4,  time: "2h ago"  },
  { sev: "low",      title: "Automated credential stuffing from AS57317 botnet",     source: "AbuseIPDB",    iocs: 12, time: "2h ago"  },
  { sev: "low",      title: "Proxyware installation attempts on Linux servers",       source: "Threat Fox",   iocs: 8,  time: "3h ago"  },
  { sev: "low",      title: "New CVEs with low EPSS score published (17 total)",      source: "NVD",          iocs: 0,  time: "3h ago"  },
  { sev: "info",     title: "CISA adds 3 new KEV entries for ICS vulnerabilities",   source: "CISA KEV",     iocs: 0,  time: "4h ago"  },
];

const IOC_RESULTS = [
  { ioc: "194.165.16.10",          type: "IP",     confidence: "High", tags: ["C2", "Cobalt Strike"], seen: "8m ago" },
  { ioc: "malware-cdn.xyz",        type: "Domain", confidence: "High", tags: ["Phishing", "Emotet"],  seen: "1h ago" },
  { ioc: "d41d8cd98f00b204e9800998ecf8427e", type: "MD5", confidence: "Medium", tags: ["Malware"], seen: "3h ago" },
];

const FEED_TYPES = [
  { type: "CVE / Vulnerability",   count: 307150, color: "bg-red-500"    },
  { type: "IP Blocklist",          count: 859786, color: "bg-amber-500"  },
  { type: "Domain / URL",          count: 126914, color: "bg-orange-500" },
  { type: "Malware Samples",       count: 82919,  color: "bg-purple-500" },
  { type: "APT / Campaign",        count: 18104,  color: "bg-blue-500"   },
  { type: "OSINT",                 count: 4201,   color: "bg-cyan-500"   },
  { type: "Other",                 count: 1219,   color: "bg-muted"      },
];

const TYPE_MAX = 859786;

const APT_CAMPAIGNS = [
  { name: "FANCY BEAR",    actor: "APT28 (Russia)", tactics: 9,  first: "2019-03", last: "2026-04" },
  { name: "COZY BEAR",     actor: "APT29 (Russia)", tactics: 11, first: "2014-07", last: "2026-03" },
  { name: "LAZARUS",       actor: "APT38 (DPRK)",   tactics: 7,  first: "2015-11", last: "2026-02" },
  { name: "SANDWORM",      actor: "GRU (Russia)",   tactics: 8,  first: "2017-01", last: "2026-01" },
  { name: "VOLT TYPHOON",  actor: "APT41 (China)",  tactics: 6,  first: "2021-05", last: "2025-12" },
  { name: "SCATTERED SPIDER", actor: "UNC3944 (FIN)", tactics: 5, first: "2022-09", last: "2026-04" },
];

const IOC_TYPES = ["All", "IP", "Domain", "Hash", "URL"];

// ── Helpers ────────────────────────────────────────────────────

const TYPE_COLORS: Record<string, string> = {
  cve:          "border-red-500/30 text-red-400 bg-red-500/10",
  ip_blocklist: "border-amber-500/30 text-amber-400 bg-amber-500/10",
  domain:       "border-orange-500/30 text-orange-400 bg-orange-500/10",
  malware:      "border-purple-500/30 text-purple-400 bg-purple-500/10",
  apt_campaign: "border-blue-500/30 text-blue-400 bg-blue-500/10",
  osint:        "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
  vulnerability:"border-red-500/30 text-red-400 bg-red-500/10",
};

function TypeBadge({ type }: { type: string }) {
  return (
    <Badge className={cn("text-[10px] border capitalize", TYPE_COLORS[type] ?? "border-border text-muted-foreground")}>
      {error && (
        <div className="bg-red-900/20 border border-red-500/30 rounded-lg p-4 flex items-center justify-between">
          <p className="text-red-400 text-sm">{error}</p>
          <button
            onClick={() => { setError(null); window.location.reload(); }}
            className="px-3 py-1 bg-red-600 hover:bg-red-700 text-white text-xs rounded transition-colors"
          >
            Retry
          </button>
        </div>
      )}
      {type.replace("_", " ")}
    </Badge>
  );
}

function SevDot({ sev }: { sev: string }) {
  const cls =
    sev === "critical" ? "bg-red-500"    :
    sev === "high"     ? "bg-amber-500"  :
    sev === "medium"   ? "bg-yellow-500" :
    sev === "low"      ? "bg-blue-400"   : "bg-muted-foreground";
  return <span className={cn("inline-block w-2 h-2 rounded-full flex-shrink-0 mt-0.5", cls)} />;
}

function fmtCount(n: number) {
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(1) + "M";
  if (n >= 1_000)     return (n / 1_000).toFixed(0) + "K";
  return n.toString();
}

// ── Component ──────────────────────────────────────────────────

export default function ThreatFeedDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [iocQuery, setIocQuery] = useState("");
  const [iocType, setIocType] = useState("All");

  useEffect(() => {
    apiFetch(`/api/v1/feeds/status?org_id=${ORG_ID}`).catch(() => { setError('Failed to load data'); });
  }, []);
  const [showResults, setShowResults] = useState(false);

  const handleSearch = () => {
    if (iocQuery.trim()) setShowResults(true);
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
        title="Threat Feed Intelligence"
        description="Aggregated threat intelligence from 28+ sources"
        actions={
          <Button variant="outline" size="sm" onClick={() => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); }} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Active Feeds"    value={28}          icon={Rss}           trend="up"   className="border-blue-500/20" />
        <KpiCard title="IOCs Collected"  value="847,293"     icon={Shield}        trend="up"   className="border-purple-500/20" />
        <KpiCard title="Alerts Today"    value={234}         icon={AlertTriangle} trend="up"   className="border-amber-500/20" />
        <KpiCard title="Feed Health"     value="96.4%"       icon={Activity}      trend="up"   className="border-green-500/20" />
      </div>

      {/* Feed source table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <Rss className="h-4 w-4 text-blue-400" />
                Feed Sources
              </CardTitle>
              <CardDescription className="text-xs">12 configured intelligence feeds</CardDescription>
            </div>
            <Button variant="outline" size="sm" className="h-7 text-xs gap-1.5">
              <Filter className="h-3 w-3" />
              Manage Feeds
            </Button>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Feed Name</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Format</TableHead>
                  <TableHead className="text-[11px] h-8">Frequency</TableHead>
                  <TableHead className="text-[11px] h-8">Last Fetch</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Items</TableHead>
                  <TableHead className="text-[11px] h-8">Reliability</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {FEEDS.map((f) => (
                  <TableRow key={f.name} className="hover:bg-muted/30">
                    <TableCell className="text-xs font-medium py-2.5 max-w-[160px] truncate">{f.name}</TableCell>
                    <TableCell className="py-2.5"><TypeBadge type={f.type} /></TableCell>
                    <TableCell className="text-xs py-2.5 text-muted-foreground">{f.format}</TableCell>
                    <TableCell className="text-xs py-2.5 text-muted-foreground">{f.freq}</TableCell>
                    <TableCell className="text-xs py-2.5 tabular-nums text-muted-foreground">{f.lastFetched}</TableCell>
                    <TableCell className="text-xs py-2.5 tabular-nums text-right font-medium">{fmtCount(f.items)}</TableCell>
                    <TableCell className="py-2.5">
                      <div className="flex items-center gap-1.5">
                        <div className="relative h-1.5 w-16 rounded-full bg-muted/30 overflow-hidden">
                          <div
                            className={cn("h-full rounded-full", f.reliability >= 95 ? "bg-green-500" : f.reliability >= 88 ? "bg-amber-500" : "bg-red-500")}
                            style={{ width: `${f.reliability}%` }}
                          />
                        </div>
                        <span className="text-[10px] tabular-nums text-muted-foreground">{f.reliability}%</span>
                      </div>
                    </TableCell>
                    <TableCell className="py-2.5">
                      <Badge className={cn(
                        "text-[10px] border",
                        f.enabled
                          ? "border-green-500/30 text-green-400 bg-green-500/10"
                          : "border-border text-muted-foreground bg-muted/10"
                      )}>
                        {f.enabled ? "Active" : "Disabled"}
                      </Badge>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Recent threat items + IOC search */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        {/* Recent items */}
        <Card className="lg:col-span-2">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Activity className="h-4 w-4 text-amber-400" />
              Recent Threat Items
            </CardTitle>
            <CardDescription className="text-xs">Latest intelligence across all feeds</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <div className="divide-y divide-border">
              {RECENT_ITEMS.map((item, i) => (
                <div key={i} className="flex items-start gap-2.5 px-4 py-2.5 hover:bg-muted/20 transition-colors">
                  <SevDot sev={item.sev} />
                  <p className="flex-1 text-xs text-foreground truncate">{item.title}</p>
                  <div className="flex items-center gap-2 flex-shrink-0">
                    <Badge className="text-[9px] border border-border text-muted-foreground bg-transparent">{item.source}</Badge>
                    {item.iocs > 0 && (
                      <span className="text-[10px] tabular-nums text-muted-foreground">{item.iocs} IOC{item.iocs !== 1 && "s"}</span>
                    )}
                    <span className="text-[10px] text-muted-foreground w-12 text-right">{item.time}</span>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>

        {/* IOC search */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Search className="h-4 w-4 text-cyan-400" />
              IOC Search
            </CardTitle>
            <CardDescription className="text-xs">Search across all collected indicators</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="space-y-2">
              <Input
                placeholder="IP, domain, hash, URL..."
                value={iocQuery}
                onChange={(e) => setIocQuery(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleSearch()}
                className="h-8 text-xs"
              />
              <div className="flex gap-1 flex-wrap">
                {IOC_TYPES.map((t) => (
                  <button
                    key={t}
                    onClick={() => setIocType(t)}
                    className={cn(
                      "px-2 py-0.5 rounded text-[10px] border transition-colors",
                      iocType === t
                        ? "border-blue-500/50 text-blue-400 bg-blue-500/10"
                        : "border-border text-muted-foreground hover:bg-muted/20"
                    )}
                  >
                    {t}
                  </button>
                ))}
              </div>
              <Button size="sm" className="w-full h-7 text-xs gap-1.5" onClick={handleSearch}>
                <Search className="h-3 w-3" />
                Search IOCs
              </Button>
            </div>

            {showResults && (
              <div className="space-y-2 pt-1 border-t border-border">
                <p className="text-[10px] text-muted-foreground">3 results for &ldquo;{iocQuery}&rdquo;</p>
                {IOC_RESULTS.map((r) => (
                  <div key={r.ioc} className="rounded-lg border border-border bg-muted/10 p-2.5 space-y-1">
                    <div className="flex items-center justify-between">
                      <code className="text-[10px] font-mono text-foreground truncate">{r.ioc}</code>
                      <Badge className="text-[9px] border border-border text-muted-foreground bg-transparent">{r.type}</Badge>
                    </div>
                    <div className="flex items-center gap-1.5 flex-wrap">
                      {r.tags.map((tag) => (
                        <Badge key={tag} className="text-[9px] border border-red-500/30 text-red-400 bg-red-500/10">{tag}</Badge>
                      ))}
                      <span className="text-[9px] text-muted-foreground ml-auto">Seen {r.seen}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {!showResults && (
              <div className="py-4 text-center text-[11px] text-muted-foreground">
                Enter an IP, domain, hash, or URL to search 847K+ indicators
              </div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Feed type distribution + APT campaigns */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Distribution */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <BarChart3 className="h-4 w-4 text-purple-400" />
              IOC Type Distribution
            </CardTitle>
            <CardDescription className="text-xs">Total indicators by category</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {FEED_TYPES.map((f) => (
              <div key={f.type} className="space-y-1">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-muted-foreground">{f.type}</span>
                  <span className="font-bold tabular-nums">{fmtCount(f.count)}</span>
                </div>
                <div className="relative h-2 rounded-full bg-muted/30 overflow-hidden">
                  <motion.div
                    initial={{ width: 0 }}
                    animate={{ width: `${(f.count / TYPE_MAX) * 100}%` }}
                    transition={{ duration: 0.8, ease: "easeOut" }}
                    className={cn("h-full rounded-full", f.color)}
                  />
                </div>
              </div>
            ))}
          </CardContent>
        </Card>

        {/* APT campaigns */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Crosshair className="h-4 w-4 text-red-400" />
              Top APT Campaigns
            </CardTitle>
            <CardDescription className="text-xs">Active nation-state threat actors tracked</CardDescription>
          </CardHeader>
          <CardContent className="grid grid-cols-1 gap-2">
            {APT_CAMPAIGNS.map((c) => (
              <div
                key={c.name}
                className="flex items-center gap-3 p-2.5 rounded-lg border border-border bg-muted/10 hover:bg-muted/20 transition-colors"
              >
                <div className="flex-shrink-0">
                  <Bug className="h-4 w-4 text-red-400" />
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-xs font-bold text-foreground">{c.name}</span>
                    <Badge className="text-[9px] border border-red-500/30 text-red-400 bg-red-500/10">{c.tactics} tactics</Badge>
                  </div>
                  <p className="text-[10px] text-muted-foreground mt-0.5">{c.actor}</p>
                </div>
                <div className="text-right flex-shrink-0">
                  <p className="text-[9px] text-muted-foreground">First: {c.first}</p>
                  <p className="text-[9px] text-muted-foreground">Last: {c.last}</p>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
    </motion.div>
  );
}
