/**
 * IP Reputation Dashboard
 *
 * IP threat scoring, blocklist management, and reputation feed.
 *   1. KPIs: IPs Tracked, Blocked IPs, Critical Reputation (<20), Avg Score
 *   2. Blocklist table: IP, reason, threat type, date blocked
 *   3. Recent lookups feed: IP, score bar, category
 *
 * API: GET /api/v1/ip-reputation/...
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { AlertTriangle, Ban, RefreshCw, Search, Shield } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

const API_BASE = import.meta.env.VITE_API_URL || "";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}?org_id=default`, { headers: { "X-API-Key": API_KEY } });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ── Mock data ──────────────────────────────────────────────────

const MOCK_BLOCKLIST = [
  { ip: "185.220.101.34", reason: "Tor exit node / C2 relay",    threat_type: "c2",        blocked_at: "2026-04-15" },
  { ip: "45.33.32.156",   reason: "SSH brute-force campaigns",    threat_type: "brute_force", blocked_at: "2026-04-14" },
  { ip: "203.0.113.99",   reason: "Data exfiltration endpoint",   threat_type: "exfil",     blocked_at: "2026-04-14" },
  { ip: "91.108.4.175",   reason: "Telegram C2 infrastructure",   threat_type: "c2",        blocked_at: "2026-04-13" },
  { ip: "77.88.55.60",    reason: "Phishing kit hosting",         threat_type: "phishing",  blocked_at: "2026-04-12" },
  { ip: "104.21.44.99",   reason: "Malware distribution",         threat_type: "malware",   blocked_at: "2026-04-11" },
  { ip: "198.51.100.22",  reason: "Port scan origin",             threat_type: "recon",     blocked_at: "2026-04-10" },
  { ip: "10.5.12.100",    reason: "Internal compromised host",    threat_type: "lateral",   blocked_at: "2026-04-09" },
];

const MOCK_LOOKUPS = [
  { ip: "185.220.101.34", score: 4,   category: "Tor / C2"       },
  { ip: "45.33.32.156",   score: 11,  category: "Brute Force"    },
  { ip: "8.8.8.8",        score: 98,  category: "Clean / DNS"    },
  { ip: "1.1.1.1",        score: 97,  category: "Clean / DNS"    },
  { ip: "203.0.113.99",   score: 7,   category: "Exfiltration"   },
  { ip: "91.108.4.175",   score: 15,  category: "C2 Infra"       },
  { ip: "10.0.1.5",       score: 85,  category: "Internal"       },
  { ip: "77.88.55.60",    score: 22,  category: "Phishing"       },
];

const MOCK_STATS = {
  ips_tracked: 142847,
  blocked_ips: 3241,
  critical_reputation: 187,
  avg_score: 61,
};

// ── Helpers ──────────────────────────────────────────────────

function ThreatTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    c2:          "border-purple-500/30 text-purple-400 bg-purple-500/10",
    brute_force: "border-red-500/30 text-red-400 bg-red-500/10",
    exfil:       "border-orange-500/30 text-orange-400 bg-orange-500/10",
    phishing:    "border-amber-500/30 text-amber-400 bg-amber-500/10",
    malware:     "border-pink-500/30 text-pink-400 bg-pink-500/10",
    recon:       "border-blue-500/30 text-blue-400 bg-blue-500/10",
    lateral:     "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border", map[type] ?? "border-border text-muted-foreground")}>
      {type.replace(/_/g, " ")}
    </Badge>
  );
}

function scoreColor(score: number) {
  if (score < 20) return { bar: "bg-red-500", text: "text-red-400" };
  if (score < 50) return { bar: "bg-amber-500", text: "text-amber-400" };
  return { bar: "bg-green-500", text: "text-green-400" };
}

// ── Component ────────────────────────────────────────────────

export default function IPReputationDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);

  useEffect(() => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/ip-reputation/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/ip-reputation/blocklist?org_id=${ORG_ID}&limit=50`),
    ]).then(([statsR, blockR]) => {
      const stats     = statsR.status === "fulfilled" ? statsR.value : null;
      const blocklist = blockR.status === "fulfilled" ? blockR.value : null;
      if (stats || blocklist) setLiveData({ stats, blocklist });
    }).finally(() => setDataLoading(false));
  }, []);

  const handleRefresh = () => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); };

  const stats     = liveData?.stats ?? MOCK_STATS;
  const blocklist = liveData?.blocklist?.items ?? liveData?.blocklist ?? MOCK_BLOCKLIST;
  const lookups   = MOCK_LOOKUPS;

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      <PageHeader
        title="IP Reputation"
        description="Threat scoring, blocklist management, and reputation feed"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="IPs Tracked"            value={stats.ips_tracked.toLocaleString()}  icon={Search}        trend="up"   />
        <KpiCard title="Blocked IPs"            value={stats.blocked_ips.toLocaleString()}   icon={Ban}           trend="up"   className="border-red-500/20" />
        <KpiCard title="Critical (<20 score)"   value={stats.critical_reputation}            icon={AlertTriangle} trend="up"   className="border-orange-500/20" />
        <KpiCard title="Avg Reputation Score"   value={stats.avg_score}                      icon={Shield}        trend="down" />
      </div>

      {/* Two-panel layout */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Blocklist */}
        <Card className="border-red-500/20">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
              <Ban className="h-4 w-4" />
              Blocklist
            </CardTitle>
            <CardDescription className="text-xs">Recently blocked IPs with threat classification</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">IP Address</TableHead>
                  <TableHead className="text-[11px] h-8">Threat Type</TableHead>
                  <TableHead className="text-[11px] h-8">Reason</TableHead>
                  <TableHead className="text-[11px] h-8">Blocked</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {blocklist.map((b: any, i: number) => (
                  <TableRow key={b.ip ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-mono text-[11px]">{b.ip}</TableCell>
                    <TableCell className="py-2"><ThreatTypeBadge type={b.threat_type} /></TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground max-w-[160px] truncate">{b.reason}</TableCell>
                    <TableCell className="py-2 text-[11px] tabular-nums text-muted-foreground">{b.blocked_at}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>

        {/* Recent Lookups / Reputation Scores */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Search className="h-4 w-4 text-blue-400" />
              Recent Lookups
            </CardTitle>
            <CardDescription className="text-xs">IP reputation scores (0 = malicious, 100 = clean)</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">IP Address</TableHead>
                  <TableHead className="text-[11px] h-8">Category</TableHead>
                  <TableHead className="text-[11px] h-8 min-w-[120px]">Score</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {lookups.map((l: any, i: number) => {
                  const colors = scoreColor(l.score);
                  return (
                    <TableRow key={l.ip ?? i} className="hover:bg-muted/30">
                      <TableCell className="py-2 font-mono text-[11px]">{l.ip}</TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground">{l.category}</TableCell>
                      <TableCell className="py-2">
                        <div className="flex items-center gap-2">
                          <div className="relative flex-1 h-1.5 rounded-full bg-muted/30 overflow-hidden min-w-[70px]">
                            <motion.div
                              initial={{ width: 0 }}
                              animate={{ width: `${l.score}%` }}
                              transition={{ duration: 0.5, delay: i * 0.05 }}
                              className={cn("h-full rounded-full", colors.bar)}
                            />
                          </div>
                          <span className={cn("text-xs font-bold tabular-nums w-6 text-right", colors.text)}>{l.score}</span>
                        </div>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </div>
    </motion.div>
  );
}
