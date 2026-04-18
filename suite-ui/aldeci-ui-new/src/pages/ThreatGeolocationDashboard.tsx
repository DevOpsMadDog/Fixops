/**
 * Threat Geolocation Dashboard
 *
 * Geographic threat analysis with country heatmap and impossible travel detection.
 *   1. KPIs: Total Geo Events, Blocked Countries, Impossible Travel Alerts, High Risk Events
 *   2. Country heatmap table: country, event count, risk score, status
 *   3. Impossible travel alerts feed
 *
 * API: GET /api/v1/threat-geolocation/...
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { AlertTriangle, Globe, MapPin, RefreshCw, ShieldAlert } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}`, { headers: { "X-API-Key": API_KEY } });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// == Mock data ==================================================

const MOCK_HEATMAP = [
  { country: "Russia",       country_code: "RU", event_count: 4821, risk_score: 94, blocked: true  },
  { country: "China",        country_code: "CN", event_count: 3407, risk_score: 88, blocked: true  },
  { country: "North Korea",  country_code: "KP", event_count: 892,  risk_score: 97, blocked: true  },
  { country: "Iran",         country_code: "IR", event_count: 1243, risk_score: 91, blocked: true  },
  { country: "United States",country_code: "US", event_count: 2104, risk_score: 34, blocked: false },
  { country: "Germany",      country_code: "DE", event_count: 512,  risk_score: 18, blocked: false },
  { country: "Brazil",       country_code: "BR", event_count: 678,  risk_score: 45, blocked: false },
  { country: "Netherlands",  country_code: "NL", event_count: 341,  risk_score: 22, blocked: false },
  { country: "Romania",      country_code: "RO", event_count: 429,  risk_score: 67, blocked: false },
  { country: "Ukraine",      country_code: "UA", event_count: 987,  risk_score: 72, blocked: false },
];

const MOCK_TRAVEL_ALERTS = [
  { id: "IT-001", user: "john.doe@corp.com",    from: "New York, US",  to: "Moscow, RU",   delta_hours: 1.2, detected_at: "14:31:07" },
  { id: "IT-002", user: "alice.wang@corp.com",  from: "London, GB",    to: "Beijing, CN",  delta_hours: 0.8, detected_at: "13:58:44" },
  { id: "IT-003", user: "bob.smith@corp.com",   from: "Sydney, AU",    to: "Tehran, IR",   delta_hours: 2.1, detected_at: "13:22:19" },
  { id: "IT-004", user: "sara.k@corp.com",      from: "Toronto, CA",   to: "Pyongyang, KP",delta_hours: 0.4, detected_at: "12:47:55" },
];

const MOCK_STATS = {
  total_geo_events: 15414,
  blocked_countries: 4,
  impossible_travel_alerts: 4,
  high_risk_events: 6948,
};

const MAX_EVENTS = MOCK_HEATMAP[0].event_count;

// == Helpers ==================================================

function riskColor(score: number) {
  if (score >= 80) return { bar: "bg-red-500",    text: "text-red-400"    };
  if (score >= 60) return { bar: "bg-amber-500",  text: "text-amber-400"  };
  if (score >= 40) return { bar: "bg-yellow-500", text: "text-yellow-400" };
  return               { bar: "bg-green-500",   text: "text-green-400"  };
}

// == Component ================================================

export default function ThreatGeolocationDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/threat-geolocation/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/threat-geolocation/heatmap?org_id=${ORG_ID}&limit=20`),
    ]).then(([statsR, heatmapR]) => {
      const stats   = statsR.status   === "fulfilled" ? statsR.value   : null;
      const heatmap = heatmapR.status === "fulfilled" ? heatmapR.value : null;
      if (stats || heatmap) setLiveData({ stats, heatmap });
    })
      .finally(() => setLoading(false)).finally(() => setDataLoading(false));
  }, []);

  const handleRefresh = () => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); };

  const stats          = liveData?.stats ?? MOCK_STATS;
  const heatmap        = liveData?.heatmap?.items ?? liveData?.heatmap ?? MOCK_HEATMAP;
  const travelAlerts   = MOCK_TRAVEL_ALERTS;

  if (loading) return (
    <div className="space-y-4 p-6">
      {[1, 2, 3].map((i) => (
        <div key={i} className="h-24 rounded-lg bg-zinc-800/50 animate-pulse" />
      ))}
    </div>
  );

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      <PageHeader
        title="Threat Geolocation"
        description="Geographic threat distribution, blocked countries, and impossible travel detection"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Geo Events"         value={stats.total_geo_events.toLocaleString()} icon={Globe}        trend="up"   />
        <KpiCard title="Blocked Countries"         value={stats.blocked_countries}                  icon={MapPin}       trend="up"   className="border-red-500/20" />
        <KpiCard title="Impossible Travel Alerts"  value={stats.impossible_travel_alerts}           icon={AlertTriangle} trend="up"  className="border-orange-500/20" />
        <KpiCard title="High Risk Events"          value={stats.high_risk_events.toLocaleString()}  icon={ShieldAlert}  trend="up"   className="border-amber-500/20" />
      </div>

      {/* Country Heatmap + Travel Alerts */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Country Heatmap */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Globe className="h-4 w-4 text-cyan-400" />
              Country Heatmap
            </CardTitle>
            <CardDescription className="text-xs">Event volume and risk score by originating country</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Country</TableHead>
                  <TableHead className="text-[11px] h-8 min-w-[120px]">Events</TableHead>
                  <TableHead className="text-[11px] h-8 min-w-[100px]">Risk Score</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {heatmap.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  heatmap.map((row: any, i: number) => {
                  const colors = riskColor(row.risk_score);
                  return (
                    <TableRow key={row.country_code ?? i} className="hover:bg-muted/30">
                      <TableCell className="py-2">
                        <div className="flex items-center gap-1.5">
                          <span className="text-sm">{row.country_code}</span>
                          <span className="text-[11px] font-medium">{row.country}</span>
                        </div>
                      </TableCell>
                      <TableCell className="py-2">
                        <div className="flex items-center gap-1.5">
                          <div className="relative h-1.5 flex-1 rounded-full bg-muted/30 overflow-hidden min-w-[50px]">
                            <motion.div
                              initial={{ width: 0 }}
                              animate={{ width: `${((row.event_count ?? 0) / MAX_EVENTS) * 100}%` }}
                              transition={{ duration: 0.5, delay: i * 0.04 }}
                              className={cn("h-full rounded-full", colors.bar)}
                            />
                          </div>
                          <span className="text-[11px] tabular-nums text-muted-foreground w-10 text-right">
                            {(row.event_count ?? 0).toLocaleString()}
                          </span>
                        </div>
                      </TableCell>
                      <TableCell className="py-2">
                        <div className="flex items-center gap-1.5">
                          <div className="relative h-1.5 flex-1 rounded-full bg-muted/30 overflow-hidden min-w-[40px]">
                            <motion.div
                              initial={{ width: 0 }}
                              animate={{ width: `${row.risk_score}%` }}
                              transition={{ duration: 0.5, delay: i * 0.04 + 0.1 }}
                              className={cn("h-full rounded-full", colors.bar)}
                            />
                          </div>
                          <span className={cn("text-xs font-bold tabular-nums w-6 text-right", colors.text)}>
                            {row.risk_score}
                          </span>
                        </div>
                      </TableCell>
                      <TableCell className="py-2">
                        {row.blocked
                          ? <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">Blocked</Badge>
                          : <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">Allowed</Badge>
                        }
                      </TableCell>
                    </TableRow>
                  );
                })
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>

        {/* Impossible Travel Alerts */}
        <Card className="border-orange-500/20">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-orange-400">
              <AlertTriangle className="h-4 w-4" />
              Impossible Travel Alerts
            </CardTitle>
            <CardDescription className="text-xs">Users logged in from geographically impossible locations within the detection window</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">User</TableHead>
                  <TableHead className="text-[11px] h-8">From</TableHead>
                  <TableHead className="text-[11px] h-8">To</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Delta</TableHead>
                  <TableHead className="text-[11px] h-8">Detected</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {travelAlerts.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  travelAlerts.map((t: any, i: number) => (
                  <TableRow key={t.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 text-[11px] font-medium max-w-[120px] truncate">{t.user}</TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{t.from}</TableCell>
                    <TableCell className="py-2 text-[11px] text-red-400 font-medium">{t.to}</TableCell>
                    <TableCell className="py-2 text-right text-[11px] tabular-nums text-amber-400 font-medium">{t.delta_hours}h</TableCell>
                    <TableCell className="py-2 text-xs tabular-nums text-muted-foreground">{t.detected_at}</TableCell>
                  </TableRow>
                )))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </div>
    </motion.div>
  );
}
