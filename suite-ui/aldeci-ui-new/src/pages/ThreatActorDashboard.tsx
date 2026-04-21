/**
 * Threat Actor Dashboard
 *
 * APT group tracking, campaign analysis, and IOC watchlist management.
 *   1. KPIs: Active Threat Actors, Active Campaigns, IOCs Tracked, Watchlisted Actors
 *   2. Threat actor table — 15 rows sorted by threat_score desc
 *   3. Active campaigns panel — 8 campaign cards
 *   4. IOC section — top 20 IOCs
 *   5. Watchlist — 8 watched actors
 *   6. Stats panel — type donut (text), sophistication bars, top targeted sectors
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Radar, Globe, Shield, Eye, AlertTriangle, RefreshCw, Search, Flag } from "lucide-react";

// ── API helpers ────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}?org_id=default`, {
    headers: { "X-API-Key": API_KEY },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── Mock data ──────────────────────────────────────────────────

const THREAT_ACTORS = [
  { name: "APT29 / Cozy Bear",   type: "nation_state",     country: "Russia",    sophistication: "advanced", motivation: "Espionage",            score: 96, last_observed: "2026-04-15", active: true },
  { name: "APT41",               type: "nation_state",     country: "China",     sophistication: "advanced", motivation: "Financial + Espionage", score: 94, last_observed: "2026-04-14", active: true },
  { name: "Lazarus Group",       type: "nation_state",     country: "DPRK",      sophistication: "advanced", motivation: "Financial",            score: 92, last_observed: "2026-04-13", active: true },
  { name: "Sandworm",            type: "nation_state",     country: "Russia",    sophistication: "advanced", motivation: "Disruption",           score: 91, last_observed: "2026-04-12", active: true },
  { name: "Volt Typhoon",        type: "nation_state",     country: "China",     sophistication: "advanced", motivation: "Espionage",            score: 89, last_observed: "2026-04-11", active: true },
  { name: "REvil",               type: "cybercriminal",   country: "Russia",    sophistication: "high",     motivation: "Financial",            score: 88, last_observed: "2026-04-10", active: false },
  { name: "Charming Kitten",     type: "nation_state",     country: "Iran",      sophistication: "high",     motivation: "Espionage",            score: 83, last_observed: "2026-04-09", active: true },
  { name: "BlackCat / ALPHV",    type: "cybercriminal",   country: "Russia",    sophistication: "high",     motivation: "Financial",            score: 85, last_observed: "2026-04-08", active: true },
  { name: "Earth Preta",         type: "nation_state",     country: "China",     sophistication: "high",     motivation: "Espionage",            score: 80, last_observed: "2026-04-07", active: true },
  { name: "TA505",               type: "cybercriminal",   country: "Russia",    sophistication: "high",     motivation: "Financial",            score: 82, last_observed: "2026-04-06", active: true },
  { name: "Scattered Spider",    type: "cybercriminal",   country: "Unknown",   sophistication: "medium",   motivation: "Financial",            score: 78, last_observed: "2026-04-05", active: true },
  { name: "MuddyWater",          type: "apt",              country: "Iran",      sophistication: "medium",   motivation: "Espionage",            score: 76, last_observed: "2026-04-04", active: true },
  { name: "WizardSpider",        type: "ransomware_group", country: "Russia",    sophistication: "high",     motivation: "Financial",            score: 74, last_observed: "2026-04-03", active: false },
  { name: "DarkHydrus",          type: "cybercriminal",   country: "Unknown",   sophistication: "medium",   motivation: "Financial",            score: 71, last_observed: "2026-04-02", active: false },
  { name: "Magecart",            type: "cybercriminal",   country: "Various",   sophistication: "low",      motivation: "Financial",            score: 69, last_observed: "2026-04-01", active: true },
];

const CAMPAIGNS = [
  { name: "Operation Ghost Write",  actor: "APT29 / Cozy Bear",  sectors: ["Energy", "Defense"],           status: "active",  impact: "Critical", ttps: 42 },
  { name: "Dragon Heist 2026",      actor: "APT41",              sectors: ["Finance", "Tech"],             status: "active",  impact: "Critical", ttps: 38 },
  { name: "Lazarus Rising",         actor: "Lazarus Group",      sectors: ["Finance", "Healthcare"],       status: "active",  impact: "High",     ttps: 31 },
  { name: "Blackout Protocol",      actor: "Sandworm",           sectors: ["Energy", "Defense"],           status: "dormant", impact: "Critical", ttps: 27 },
  { name: "Silk Typhoon Wave 3",    actor: "Volt Typhoon",       sectors: ["Defense", "Tech"],             status: "active",  impact: "High",     ttps: 24 },
  { name: "Phantom Ransomware",     actor: "BlackCat / ALPHV",   sectors: ["Healthcare", "Finance"],       status: "active",  impact: "High",     ttps: 19 },
  { name: "Fox Tail",               actor: "Charming Kitten",    sectors: ["Energy", "Government"],        status: "active",  impact: "Medium",   ttps: 16 },
  { name: "GreenDragon Intel",      actor: "Earth Preta",        sectors: ["Government", "Tech", "Energy"], status: "dormant", impact: "Medium",  ttps: 13 },
];

const IOCS = [
  { type: "ip",     value: "185.234.219.47",                       confidence: 98, actor: "APT29 / Cozy Bear", last_seen: "2026-04-15", active: true },
  { type: "domain", value: "cdn-static-updates[.]com",             confidence: 97, actor: "APT41",             last_seen: "2026-04-14", active: true },
  { type: "hash",   value: "e3b0c44298fc1c149afb...a8", confidence: 95, actor: "Lazarus Group",      last_seen: "2026-04-13", active: true },
  { type: "ip",     value: "91.108.56.130",                        confidence: 94, actor: "Sandworm",          last_seen: "2026-04-13", active: true },
  { type: "url",    value: "https://malicious-cdn[.]ru/payload",   confidence: 93, actor: "Volt Typhoon",      last_seen: "2026-04-12", active: true },
  { type: "domain", value: "auth-microsoft-sso[.]net",             confidence: 91, actor: "APT29 / Cozy Bear", last_seen: "2026-04-12", active: true },
  { type: "ip",     value: "103.22.200.88",                        confidence: 90, actor: "Charming Kitten",   last_seen: "2026-04-11", active: true },
  { type: "email",  value: "admin@secure-portal[.]xyz",            confidence: 89, actor: "Charming Kitten",   last_seen: "2026-04-11", active: false },
  { type: "hash",   value: "5d41402abc4b2a76b9719...1a", confidence: 88, actor: "BlackCat / ALPHV",   last_seen: "2026-04-10", active: true },
  { type: "url",    value: "http://update-service[.]io/dl",        confidence: 86, actor: "APT41",             last_seen: "2026-04-10", active: false },
  { type: "domain", value: "vpn-gateway-secure[.]com",             confidence: 85, actor: "Earth Preta",       last_seen: "2026-04-09", active: true },
  { type: "ip",     value: "45.142.212.51",                        confidence: 84, actor: "TA505",             last_seen: "2026-04-09", active: true },
  { type: "hash",   value: "aabbcc1234567890fedc...ba", confidence: 83, actor: "WizardSpider",       last_seen: "2026-04-08", active: false },
  { type: "url",    value: "https://fake-portal[.]org/login",      confidence: 82, actor: "Scattered Spider",  last_seen: "2026-04-08", active: true },
  { type: "domain", value: "telemetry-hub[.]net",                  confidence: 81, actor: "Volt Typhoon",      last_seen: "2026-04-07", active: true },
  { type: "ip",     value: "194.165.16.77",                        confidence: 79, actor: "MuddyWater",        last_seen: "2026-04-07", active: true },
  { type: "email",  value: "support@helpdesk-portal[.]co",         confidence: 78, actor: "Scattered Spider",  last_seen: "2026-04-06", active: true },
  { type: "domain", value: "backup-sync-cloud[.]ru",               confidence: 77, actor: "Sandworm",          last_seen: "2026-04-05", active: false },
  { type: "ip",     value: "77.91.68.23",                          confidence: 74, actor: "DarkHydrus",        last_seen: "2026-04-04", active: false },
  { type: "url",    value: "http://cdn-assets[.]pw/inject.js",     confidence: 72, actor: "Magecart",          last_seen: "2026-04-03", active: true },
];

const WATCHLIST = [
  { name: "APT29 / Cozy Bear",  priority: "critical", reason: "Active campaign targeting energy sector — new C2 infrastructure detected", alert: true },
  { name: "Sandworm",           priority: "critical", reason: "Observed pre-positioning near critical infrastructure OT/ICS networks",    alert: true },
  { name: "APT41",              priority: "high",     reason: "Financial sector attacks correlated with recent credential dump",           alert: true },
  { name: "Lazarus Group",      priority: "high",     reason: "New SWIFT banking targeting TTPs observed in partner ISAC feed",            alert: false },
  { name: "Volt Typhoon",       priority: "high",     reason: "Living-off-the-land activity near defense contractor supply chain",         alert: true },
  { name: "BlackCat / ALPHV",   priority: "medium",   reason: "Healthcare ransomware RaaS affiliate activity escalating",                 alert: false },
  { name: "Charming Kitten",    priority: "medium",   reason: "Spear-phishing targeting energy sector executives",                        alert: false },
  { name: "Scattered Spider",   priority: "low",      reason: "Social engineering against helpdesk personnel — ongoing monitoring",        alert: false },
];

const SECTOR_TARGETS = [
  { sector: "Energy",      count: 34 },
  { sector: "Finance",     count: 29 },
  { sector: "Defense",     count: 27 },
  { sector: "Healthcare",  count: 22 },
  { sector: "Technology",  count: 19 },
  { sector: "Government",  count: 16 },
];

const BY_TYPE = [
  { label: "Nation State",      count: 6, color: "bg-red-500" },
  { label: "Cybercriminal",     count: 6, color: "bg-orange-500" },
  { label: "Ransomware Group",  count: 1, color: "bg-purple-500" },
  { label: "APT",               count: 1, color: "bg-yellow-500" },
  { label: "Hacktivist",        count: 1, color: "bg-blue-500" },
];

const BY_SOPHISTICATION = [
  { label: "Advanced", count: 5, color: "bg-red-500" },
  { label: "High",     count: 6, color: "bg-orange-500" },
  { label: "Medium",   count: 3, color: "bg-yellow-500" },
  { label: "Low",      count: 1, color: "bg-gray-500" },
];

// ── Helpers ──────────────────────────────────────────────────────

function ActorTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    nation_state:     "border-red-500/30 text-red-400 bg-red-500/10",
    cybercriminal:    "border-orange-500/30 text-orange-400 bg-orange-500/10",
    hacktivist:       "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    apt:              "border-purple-500/30 text-purple-400 bg-purple-500/10",
    ransomware_group: "border-red-500/30 text-red-400 bg-red-500/10",
  };
  const labels: Record<string, string> = {
    nation_state:     "Nation State",
    cybercriminal:    "Cybercriminal",
    hacktivist:       "Hacktivist",
    apt:              "APT",
    ransomware_group: "Ransomware",
  };
  return <Badge className={cn("text-[10px] border", map[type] ?? "border-border text-muted-foreground")}>{labels[type] ?? type}</Badge>;
}

function SophisticationBadge({ level }: { level: string }) {
  const map: Record<string, string> = {
    advanced: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
    medium:   "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    low:      "border-border text-muted-foreground bg-muted/20",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[level] ?? "")}>{level}</Badge>;
}

function IOCTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    ip:     "border-blue-500/30 text-blue-400 bg-blue-500/10",
    domain: "border-purple-500/30 text-purple-400 bg-purple-500/10",
    hash:   "border-gray-500/30 text-gray-400 bg-gray-500/10",
    url:    "border-orange-500/30 text-orange-400 bg-orange-500/10",
    email:  "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return <Badge className={cn("text-[10px] border uppercase", map[type] ?? "")}>{type}</Badge>;
}

function PriorityBadge({ priority }: { priority: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
    medium:   "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    low:      "border-border text-muted-foreground bg-muted/20",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[priority] ?? "")}>{priority}</Badge>;
}

function ImpactBadge({ level }: { level: string }) {
  const map: Record<string, string> = {
    Critical: "border-red-500/30 text-red-400 bg-red-500/10",
    High:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
    Medium:   "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    Low:      "border-border text-muted-foreground",
  };
  return <Badge className={cn("text-[10px] border", map[level] ?? "")}>{level}</Badge>;
}

function ThreatScoreBar({ score }: { score: number }) {
  const color = score >= 90 ? "bg-red-500" : score >= 80 ? "bg-orange-500" : score >= 70 ? "bg-yellow-500" : "bg-gray-500";
  return (
    <div className="flex items-center gap-2">
      <div className="relative h-1.5 w-20 rounded-full bg-muted/30 overflow-hidden">
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${score}%` }}
          transition={{ duration: 0.7, ease: "easeOut" }}
          className={cn("h-full rounded-full", color)}
        />
      </div>
      <span className={cn("text-xs font-bold tabular-nums", score >= 90 ? "text-red-400" : score >= 80 ? "text-orange-400" : score >= 70 ? "text-yellow-400" : "text-muted-foreground")}>
        {score}
      </span>
    </div>
  );
}

// ── Component ──────────────────────────────────────────────────

export default function ThreatActorDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [search, setSearch] = useState("");
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);

  useEffect(() => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/threat-actors/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/threat-actors/actors?org_id=${ORG_ID}&limit=20`),
      apiFetch(`/api/v1/threat-actors/watchlist?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/threat-actors/iocs?org_id=${ORG_ID}&limit=20`),
    ]).then(([statsResult, actorsResult, watchlistResult, iocsResult]) => {
      const stats     = statsResult.status     === "fulfilled" ? statsResult.value     : null;
      const actors    = actorsResult.status    === "fulfilled" ? actorsResult.value    : null;
      const watchlist = watchlistResult.status === "fulfilled" ? watchlistResult.value : null;
      const iocs      = iocsResult.status      === "fulfilled" ? iocsResult.value      : null;
      if (stats || actors || watchlist || iocs) {
        setLiveData({ stats, actors, watchlist, iocs });
      }
    }).finally(() => setDataLoading(false));
  }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    setTimeout(() => setRefreshing(false), 800);
  };

  const actorSource: typeof THREAT_ACTORS = liveData?.actors?.items ?? liveData?.actors ?? THREAT_ACTORS;
  const filteredActors = actorSource.filter((a: any) =>
    search === "" || a.name.toLowerCase().includes(search.toLowerCase()) || a.country.toLowerCase().includes(search.toLowerCase())
  );

  const maxSector = Math.max(...SECTOR_TARGETS.map((s) => s.count));
  const maxSoph = Math.max(...BY_SOPHISTICATION.map((s) => s.count));

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      {/* Header */}
      <PageHeader
        title="Threat Actor Intelligence"
        description="APT group tracking, campaign analysis, and IOC watchlist management"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Active Threat Actors"  value={liveData?.stats?.actor_count ?? 47}    icon={Radar}          trend="up"   className="border-red-500/20" />
        <KpiCard title="Active Campaigns"       value={liveData?.stats?.active_campaigns ?? 12}    icon={Flag}           trend="up"   className="border-orange-500/20" />
        <KpiCard title="IOCs Tracked"           value={liveData?.stats?.total_iocs ?? "2,841"} icon={Eye}            trend="up"   className="border-yellow-500/20" />
        <KpiCard title="Watchlisted Actors"     value={liveData?.stats?.watchlist_size ?? 8}     icon={AlertTriangle}  trend="flat" className="border-purple-500/20" />
      </div>

      {/* Threat Actor Table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between gap-4 flex-wrap">
            <div>
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <Radar className="h-4 w-4 text-red-400" />
                Threat Actor Registry
              </CardTitle>
              <CardDescription className="text-xs">Sorted by threat score — {THREAT_ACTORS.length} tracked groups</CardDescription>
            </div>
            <div className="relative">
              <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-3 w-3 text-muted-foreground" />
              <input
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                placeholder="Search actors…"
                className="h-7 pl-6 pr-3 text-xs rounded-md border border-border bg-background focus:outline-none focus:ring-1 focus:ring-ring"
              />
            </div>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Actor</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Origin</TableHead>
                  <TableHead className="text-[11px] h-8">Sophistication</TableHead>
                  <TableHead className="text-[11px] h-8">Motivation</TableHead>
                  <TableHead className="text-[11px] h-8">Threat Score</TableHead>
                  <TableHead className="text-[11px] h-8">Last Observed</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredActors.map((actor) => (
                  <TableRow key={actor.name} className="hover:bg-muted/30">
                    <TableCell className="text-xs font-semibold py-2.5">{actor.name}</TableCell>
                    <TableCell className="py-2.5"><ActorTypeBadge type={actor.type} /></TableCell>
                    <TableCell className="text-xs py-2.5 text-muted-foreground">{actor.country}</TableCell>
                    <TableCell className="py-2.5"><SophisticationBadge level={actor.sophistication} /></TableCell>
                    <TableCell className="text-xs py-2.5 text-muted-foreground">{actor.motivation}</TableCell>
                    <TableCell className="py-2.5"><ThreatScoreBar score={actor.score} /></TableCell>
                    <TableCell className="text-xs py-2.5 tabular-nums text-muted-foreground">{actor.last_observed}</TableCell>
                    <TableCell className="py-2.5">
                      {actor.active
                        ? <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">Active</Badge>
                        : <Badge className="text-[10px] border border-border text-muted-foreground bg-muted/20">Dormant</Badge>
                      }
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Active Campaigns */}
      <div>
        <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
          <Flag className="h-4 w-4 text-orange-400" />
          Active Campaigns
        </h3>
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {CAMPAIGNS.map((c) => (
            <Card key={c.name} className={cn(c.status === "active" ? "border-orange-500/20" : "border-border/40")}>
              <CardHeader className="pb-2">
                <div className="flex items-start justify-between gap-2">
                  <CardTitle className="text-xs font-semibold leading-tight">{c.name}</CardTitle>
                  {c.status === "active"
                    ? <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10 shrink-0">Active</Badge>
                    : <Badge className="text-[10px] border border-border text-muted-foreground bg-muted/20 shrink-0">Dormant</Badge>
                  }
                </div>
                <p className="text-[10px] text-muted-foreground">{c.actor}</p>
              </CardHeader>
              <CardContent className="pt-0 space-y-2">
                <div className="flex flex-wrap gap-1">
                  {c.sectors.map((s) => (
                    <span key={s} className="text-[9px] px-1.5 py-0.5 rounded bg-muted/40 text-muted-foreground border border-border/50">{s}</span>
                  ))}
                </div>
                <div className="flex items-center justify-between">
                  <ImpactBadge level={c.impact} />
                  <span className="text-[10px] text-muted-foreground">{c.ttps} TTPs</span>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>

      {/* IOC Section */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <Eye className="h-4 w-4 text-blue-400" />
                Top IOCs
              </CardTitle>
              <CardDescription className="text-xs">Most recently observed indicators of compromise</CardDescription>
            </div>
            <Badge className="text-[10px] border border-blue-500/30 text-blue-400 bg-blue-500/10">
              {IOCS.length} shown of 2,841
            </Badge>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Value</TableHead>
                  <TableHead className="text-[11px] h-8">Confidence</TableHead>
                  <TableHead className="text-[11px] h-8">Actor</TableHead>
                  <TableHead className="text-[11px] h-8">Last Seen</TableHead>
                  <TableHead className="text-[11px] h-8">Active</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(liveData?.iocs?.items ?? liveData?.iocs ?? IOCS).map((ioc: any, i: number) => (
                  <TableRow key={i} className="hover:bg-muted/30">
                    <TableCell className="py-2"><IOCTypeBadge type={ioc.type} /></TableCell>
                    <TableCell className="text-xs font-mono py-2 max-w-[220px] truncate text-muted-foreground">{ioc.value}</TableCell>
                    <TableCell className="text-xs py-2 tabular-nums font-bold text-green-400">{ioc.confidence}%</TableCell>
                    <TableCell className="text-xs py-2">{ioc.actor}</TableCell>
                    <TableCell className="text-xs py-2 tabular-nums text-muted-foreground">{ioc.last_seen}</TableCell>
                    <TableCell className="py-2">
                      {ioc.active
                        ? <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">Yes</Badge>
                        : <Badge className="text-[10px] border border-border text-muted-foreground bg-muted/20">No</Badge>
                      }
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Watchlist + Stats */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Watchlist */}
        <Card className="border-red-500/20">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
              <AlertTriangle className="h-4 w-4" />
              Watchlist
            </CardTitle>
            <CardDescription className="text-xs">Priority-monitored threat actors with alert status</CardDescription>
          </CardHeader>
          <CardContent className="space-y-2.5">
            {(liveData?.watchlist?.items ?? liveData?.watchlist ?? WATCHLIST).map((w: any) => (
              <div key={w.name} className="flex items-start gap-3 p-2.5 rounded-lg bg-muted/20 border border-border/40">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-0.5">
                    <span className="text-xs font-semibold">{w.name}</span>
                    <PriorityBadge priority={w.priority} />
                  </div>
                  <p className="text-[10px] text-muted-foreground leading-snug">{w.reason}</p>
                </div>
                <div className="shrink-0">
                  {w.alert
                    ? <Badge className="text-[9px] border border-red-500/30 text-red-400 bg-red-500/10">Alert Active</Badge>
                    : <Badge className="text-[9px] border border-border text-muted-foreground bg-muted/20">Monitoring</Badge>
                  }
                </div>
              </div>
            ))}
          </CardContent>
        </Card>

        {/* Stats */}
        <div className="flex flex-col gap-4">
          {/* By type */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">By Actor Type</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              {BY_TYPE.map((t) => (
                <div key={t.label} className="flex items-center gap-2 text-xs">
                  <span className={cn("w-2.5 h-2.5 rounded-sm shrink-0", t.color)} />
                  <span className="flex-1 text-muted-foreground">{t.label}</span>
                  <span className="font-bold tabular-nums">{t.count}</span>
                </div>
              ))}
            </CardContent>
          </Card>

          {/* By sophistication */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">By Sophistication</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2.5">
              {BY_SOPHISTICATION.map((s) => (
                <div key={s.label} className="space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-muted-foreground">{s.label}</span>
                    <span className="font-bold tabular-nums">{s.count}</span>
                  </div>
                  <div className="relative h-1.5 rounded-full bg-muted/30 overflow-hidden">
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${(s.count / maxSoph) * 100}%` }}
                      transition={{ duration: 0.7, ease: "easeOut" }}
                      className={cn("h-full rounded-full", s.color)}
                    />
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>

          {/* Top targeted sectors */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">Top Targeted Sectors</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2.5">
              {SECTOR_TARGETS.map((s) => (
                <div key={s.sector} className="space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-muted-foreground">{s.sector}</span>
                    <span className="font-bold tabular-nums">{s.count}</span>
                  </div>
                  <div className="relative h-1.5 rounded-full bg-muted/30 overflow-hidden">
                    <motion.div
                      initial={{ width: 0 }}
                      animate={{ width: `${(s.count / maxSector) * 100}%` }}
                      transition={{ duration: 0.7, ease: "easeOut" }}
                      className="h-full rounded-full bg-indigo-500"
                    />
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>
        </div>
      </div>
    </motion.div>
  );
}
