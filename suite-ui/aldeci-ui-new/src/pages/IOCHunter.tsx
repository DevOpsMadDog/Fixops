/**
 * IOC Hunter
 *
 * Indicator of Compromise enrichment and threat hunting.
 *   1. KPIs: Total IOCs, Enriched, Malicious, On Watchlist
 *   2. IOC search bar with type selector + Import CSV
 *   3. IOC table (15 rows)
 *   4. Enrichment detail panel (always visible, first row)
 *   5. Watchlists (3 cards)
 *   6. Recent additions feed (8 entries)
 *
 * API stubs: GET /api/v1/ioc/search, /api/v1/ioc/watchlists, /api/v1/ioc/recent
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";

// ── API helpers ────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "dev-key";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "X-API-Key": API_KEY },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}
import {
  Search, Shield, AlertTriangle, Eye, RefreshCw,
  Upload, Globe, Hash, Mail, Link, MapPin, Crosshair,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Progress } from "@/components/ui/progress";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── Mock data ──────────────────────────────────────────────────

const IOC_TYPES = ["All", "IP", "Domain", "Hash", "URL", "Email"];

const IOCS = [
  { value: "185.220.101.47",           type: "IP",     source: "Feodo C2",     confidence: 95, severity: "Critical", verdict: "malicious",  lastSeen: "2026-04-16 08:12" },
  { value: "evil-update.ru",           type: "Domain", source: "URLhaus",      confidence: 88, severity: "High",     verdict: "malicious",  lastSeen: "2026-04-15 22:44" },
  { value: "3a4b5c6d7e8f9012...",      type: "Hash",   source: "MalwareBazaar", confidence: 99, severity: "Critical", verdict: "malicious", lastSeen: "2026-04-15 18:30" },
  { value: "http://cdn.phish.io/hook", type: "URL",    source: "PhishTank",    confidence: 76, severity: "High",     verdict: "malicious",  lastSeen: "2026-04-15 14:22" },
  { value: "attacker@evil-corp.net",   type: "Email",  source: "OpenPhish",    confidence: 82, severity: "High",     verdict: "malicious",  lastSeen: "2026-04-15 11:05" },
  { value: "91.108.4.0/22",           type: "IP",     source: "AbuseIPDB",    confidence: 67, severity: "Medium",   verdict: "suspicious", lastSeen: "2026-04-15 09:38" },
  { value: "update-service.net",       type: "Domain", source: "OSINT",        confidence: 55, severity: "Medium",   verdict: "suspicious", lastSeen: "2026-04-14 23:19" },
  { value: "ab12cd34ef56gh78...",      type: "Hash",   source: "VirusTotal",   confidence: 41, severity: "Low",      verdict: "suspicious", lastSeen: "2026-04-14 20:01" },
  { value: "https://legit-cdn.com/js", type: "URL",    source: "Manual",       confidence: 20, severity: "Low",      verdict: "benign",     lastSeen: "2026-04-14 16:44" },
  { value: "no-reply@company.com",     type: "Email",  source: "Internal",     confidence: 5,  severity: "Low",      verdict: "benign",     lastSeen: "2026-04-14 12:30" },
  { value: "45.142.212.100",           type: "IP",     source: "Shodan",       confidence: 73, severity: "High",     verdict: "malicious",  lastSeen: "2026-04-14 09:55" },
  { value: "cdn-proxy.xyz",            type: "Domain", source: "OSINT",        confidence: 61, severity: "Medium",   verdict: "suspicious", lastSeen: "2026-04-13 22:10" },
  { value: "ff00112233445566...",      type: "Hash",   source: "MalwareBazaar", confidence: 97, severity: "Critical", verdict: "malicious", lastSeen: "2026-04-13 18:44" },
  { value: "http://malware.cc/drop",   type: "URL",    source: "URLhaus",      confidence: 91, severity: "Critical", verdict: "malicious",  lastSeen: "2026-04-13 14:22" },
  { value: "spam@botnet-domain.ru",   type: "Email",  source: "Spamhaus",     confidence: 84, severity: "High",     verdict: "malicious",  lastSeen: "2026-04-13 10:05" },
];

const WATCHLISTS = [
  { name: "APT29 Indicators",    count: 87,  updated: "2026-04-16 06:00" },
  { name: "Ransomware C2 IPs",   count: 234, updated: "2026-04-15 22:30" },
  { name: "Phishing Domains",    count: 512, updated: "2026-04-16 01:15" },
];

const RECENT_ADDITIONS = [
  { value: "198.51.100.42",          type: "IP",     source: "Feodo C2",     ts: "8m ago" },
  { value: "malicious-payload.ru",   type: "Domain", source: "URLhaus",      ts: "22m ago" },
  { value: "bc614e...",              type: "Hash",   source: "MalwareBazaar", ts: "41m ago" },
  { value: "http://evil.cc/p",       type: "URL",    source: "PhishTank",    ts: "1h ago" },
  { value: "spear@apt-group.ru",     type: "Email",  source: "OpenPhish",    ts: "2h ago" },
  { value: "192.0.2.88",            type: "IP",     source: "AbuseIPDB",    ts: "3h ago" },
  { value: "fake-microsoft-cdn.net", type: "Domain", source: "OSINT",        ts: "4h ago" },
  { value: "dead0ff...",             type: "Hash",   source: "VirusTotal",   ts: "5h ago" },
];

// ── Helpers ────────────────────────────────────────────────────

function TypeIcon({ type }: { type: string }) {
  const props = { className: "h-3.5 w-3.5 shrink-0" };
  if (type === "IP")     return <Globe {...props} />;
  if (type === "Domain") return <Globe {...props} />;
  if (type === "Hash")   return <Hash {...props} />;
  if (type === "URL")    return <Link {...props} />;
  if (type === "Email")  return <Mail {...props} />;
  return <Search {...props} />;
}

function TypeBadge({ type }: { type: string }) {
  const cls =
    type === "IP"     ? "border-blue-500/30 text-blue-400 bg-blue-500/10" :
    type === "Domain" ? "border-purple-500/30 text-purple-400 bg-purple-500/10" :
    type === "Hash"   ? "border-indigo-500/30 text-indigo-400 bg-indigo-500/10" :
    type === "URL"    ? "border-cyan-500/30 text-cyan-400 bg-cyan-500/10" :
                        "border-pink-500/30 text-pink-400 bg-pink-500/10";
  return <Badge className={cn("text-[10px] border", cls)}>{type}</Badge>;
}

function VerdictBadge({ verdict }: { verdict: string }) {
  const cls =
    verdict === "malicious"  ? "border-red-500/30 text-red-400 bg-red-500/10" :
    verdict === "suspicious" ? "border-amber-500/30 text-amber-400 bg-amber-500/10" :
                               "border-green-500/30 text-green-400 bg-green-500/10";
  return <Badge className={cn("text-[10px] border capitalize", cls)}>{verdict}</Badge>;
}

function SeverityBadge({ sev }: { sev: string }) {
  const cls =
    sev === "Critical" ? "border-red-500/30 text-red-400 bg-red-500/10" :
    sev === "High"     ? "border-amber-500/30 text-amber-400 bg-amber-500/10" :
    sev === "Medium"   ? "border-yellow-500/30 text-yellow-400 bg-yellow-500/10" :
                         "border-border text-muted-foreground";
  return <Badge className={cn("text-[10px] border", cls)}>{sev}</Badge>;
}

// ── Component ──────────────────────────────────────────────────

export default function IOCHunter() {
  const [refreshing, setRefreshing] = useState(false);
  const [query, setQuery]           = useState("");
  const [iocType, setIocType]       = useState("All");
  const [liveData, setLiveData]     = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);

  const fetchData = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/ioc-enrichment/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/ioc-enrichment/iocs?org_id=${ORG_ID}&limit=50`),
    ]).then(([statsResult, iocsResult]) => {
      const stats = statsResult.status === "fulfilled" ? statsResult.value : null;
      const iocs  = iocsResult.status  === "fulfilled" ? iocsResult.value  : null;
      if (stats || iocs) {
        setLiveData({ stats, iocs });
      }
    }).finally(() => setDataLoading(false));
  };

  useEffect(() => { fetchData(); }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchData();
    setTimeout(() => setRefreshing(false), 800);
  };

  // Derive display values — live data takes precedence over mock
  const displayIocs = liveData?.iocs ?? IOCS;
  const firstIoc = displayIocs[0] ?? IOCS[0];

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      {/* Header */}
      <PageHeader
        title="IOC Hunter"
        description="Indicator of Compromise enrichment and threat hunting"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total IOCs"   value={liveData?.stats?.total_iocs ?? "4,782"} icon={Crosshair} />
        <KpiCard title="Enriched"     value={liveData?.stats?.enriched_count ?? "3,421"} icon={Search} description="71.5% coverage" />
        <KpiCard title="Malicious"    value={liveData?.stats?.malicious_count ?? 892} icon={AlertTriangle} trend="up" className="border-red-500/20" />
        <KpiCard title="On Watchlist" value={liveData?.stats?.watchlist_count ?? 234} icon={Eye} />
      </div>

      {/* Search bar */}
      <Card>
        <CardContent className="p-4">
          <div className="flex items-center gap-2 flex-wrap">
            <div className="flex rounded-md border border-border overflow-hidden">
              {IOC_TYPES.map((t) => (
                <button
                  key={t}
                  onClick={() => setIocType(t)}
                  className={cn(
                    "px-3 py-1.5 text-xs transition-colors",
                    iocType === t
                      ? "bg-primary text-primary-foreground"
                      : "text-muted-foreground hover:bg-muted/50"
                  )}
                >
                  {t}
                </button>
              ))}
            </div>
            <Input
              placeholder="Enter IP, domain, hash, URL, or email…"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              className="h-8 text-xs flex-1 min-w-[220px]"
            />
            <Button size="sm" className="h-8 text-xs gap-1.5">
              <Search className="h-3.5 w-3.5" />
              Search
            </Button>
            <Button variant="outline" size="sm" className="h-8 text-xs gap-1.5">
              <Upload className="h-3.5 w-3.5" />
              Import CSV
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* IOC table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Crosshair className="h-4 w-4 text-red-400" />
              IOC Library
            </CardTitle>
            <Badge className="text-[10px] border border-border text-muted-foreground">
              {displayIocs.length} results
            </Badge>
          </div>
          <CardDescription className="text-xs">All tracked indicators with enrichment and verdict</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Indicator</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Source</TableHead>
                  <TableHead className="text-[11px] h-8 w-24">Confidence</TableHead>
                  <TableHead className="text-[11px] h-8">Severity</TableHead>
                  <TableHead className="text-[11px] h-8">Verdict</TableHead>
                  <TableHead className="text-[11px] h-8">Last Seen</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {displayIocs.map((ioc: any, i: number) => (
                  <TableRow key={i} className="hover:bg-muted/30">
                    <TableCell className="text-xs font-mono py-2.5 max-w-[180px] truncate">{ioc.value}</TableCell>
                    <TableCell className="py-2.5"><TypeBadge type={ioc.type} /></TableCell>
                    <TableCell className="text-xs py-2.5 text-muted-foreground">{ioc.source}</TableCell>
                    <TableCell className="py-2.5">
                      <div className="flex items-center gap-2">
                        <Progress value={ioc.confidence} className="h-1.5 w-14" />
                        <span className="text-[10px] tabular-nums text-muted-foreground">{ioc.confidence}%</span>
                      </div>
                    </TableCell>
                    <TableCell className="py-2.5"><SeverityBadge sev={ioc.severity} /></TableCell>
                    <TableCell className="py-2.5"><VerdictBadge verdict={ioc.verdict} /></TableCell>
                    <TableCell className="text-xs py-2.5 tabular-nums text-muted-foreground">{ioc.lastSeen}</TableCell>
                    <TableCell className="py-2.5 text-right">
                      <div className="flex items-center justify-end gap-1">
                        <Button variant="outline" size="sm" className="h-6 px-2 text-[10px]">Enrich</Button>
                        <Button variant="outline" size="sm" className="h-6 px-2 text-[10px]">Watchlist</Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Enrichment detail + Watchlists */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Enrichment panel */}
        <Card className="border-red-500/20">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
              <Search className="h-4 w-4" />
              Enrichment Detail
            </CardTitle>
            <CardDescription className="text-xs font-mono">{firstIoc.value}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="grid grid-cols-2 gap-3">
              <div className="rounded-md bg-muted/30 p-3 space-y-0.5">
                <p className="text-[10px] uppercase tracking-wide text-muted-foreground">Reputation Score</p>
                <p className="text-lg font-bold text-red-400">95/100</p>
                <p className="text-[10px] text-muted-foreground">High confidence malicious</p>
              </div>
              <div className="rounded-md bg-muted/30 p-3 space-y-0.5">
                <p className="text-[10px] uppercase tracking-wide text-muted-foreground">Geolocation</p>
                <div className="flex items-center gap-1 mt-0.5">
                  <MapPin className="h-3 w-3 text-muted-foreground" />
                  <p className="text-xs font-medium">Netherlands, EU</p>
                </div>
                <p className="text-[10px] text-muted-foreground">AS-12345 Tor exit node</p>
              </div>
            </div>
            <div className="rounded-md bg-muted/30 p-3 space-y-2">
              <p className="text-[10px] uppercase tracking-wide text-muted-foreground">Associated Campaigns</p>
              <div className="flex flex-wrap gap-1">
                {["UNC2452", "COZY BEAR", "SolarWinds-APT"].map((c) => (
                  <Badge key={c} className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">{c}</Badge>
                ))}
              </div>
            </div>
            <div className="rounded-md bg-muted/30 p-3 space-y-2">
              <p className="text-[10px] uppercase tracking-wide text-muted-foreground">Malware Families</p>
              <div className="flex flex-wrap gap-1">
                {["Cobalt Strike", "SUNBURST", "Mimikatz"].map((m) => (
                  <Badge key={m} className="text-[10px] border border-amber-500/30 text-amber-400 bg-amber-500/10">{m}</Badge>
                ))}
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Watchlists */}
        <div className="space-y-3">
          <h3 className="text-sm font-semibold flex items-center gap-2">
            <Eye className="h-4 w-4 text-indigo-400" />
            Watchlists
          </h3>
          {WATCHLISTS.map((wl) => (
            <Card key={wl.name} className="hover:border-border/80 transition-colors">
              <CardContent className="p-4 flex items-center justify-between gap-4">
                <div className="space-y-0.5 min-w-0">
                  <p className="text-sm font-semibold truncate">{wl.name}</p>
                  <p className="text-xs text-muted-foreground">Updated {wl.updated}</p>
                </div>
                <div className="flex items-center gap-3 shrink-0">
                  <span className="text-sm font-bold tabular-nums">{wl.count} IOCs</span>
                  <Button variant="outline" size="sm" className="h-7 text-xs">View</Button>
                </div>
              </CardContent>
            </Card>
          ))}

          {/* Recent additions */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-semibold">Recent Additions</CardTitle>
            </CardHeader>
            <CardContent className="space-y-1.5">
              {RECENT_ADDITIONS.map((r, i) => (
                <div key={i} className="flex items-center gap-2 py-1 border-b border-border/30 last:border-0">
                  <TypeIcon type={r.type} />
                  <span className="text-xs font-mono flex-1 truncate">{r.value}</span>
                  <span className="text-[10px] text-muted-foreground shrink-0">{r.source}</span>
                  <span className="text-[10px] text-muted-foreground/60 shrink-0 tabular-nums">{r.ts}</span>
                </div>
              ))}
            </CardContent>
          </Card>
        </div>
      </div>
    </motion.div>
  );
}
