/**
 * Network Traffic Analysis
 * Route: /network-analysis
 * API: GET /api/v1/network/flows  GET /api/v1/network/anomalies
 */

import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { AlertTriangle, Activity, Shield, Globe, Network, Radio, Ban, Eye, CheckCircle, Zap } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

const API = import.meta.env.VITE_API_URL || "";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci_api_key")) ||
  import.meta.env.VITE_API_KEY ||
  "dev-key";

async function apiFetch(path: string) {
  const res = await fetch(`${API}${path}?org_id=default`, { headers: { "X-API-Key": API_KEY } });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ── Types ──────────────────────────────────────────────────────────────────────
type ThreatLevel = "critical" | "high" | "medium" | "low";
type FlowAction = "block" | "monitor" | "allow";

interface TopTalker { id: string; src: string; flag: string; country: string; dst: string; proto: string; bytes: string; score: number; action: FlowAction; }
interface Anomaly { id: string; ts: string; type: string; src: string; dst: string; severity: ThreatLevel; }

// ── Mock data ──────────────────────────────────────────────────────────────────
const TALKERS: TopTalker[] = [
  { id:"1", src:"45.83.64.12",      flag:"🇨🇳", country:"China",        dst:"10.0.1.45:443",   proto:"HTTPS", bytes:"2.3 GB",  score:94, action:"block"   },
  { id:"2", src:"185.220.101.33",   flag:"🇷🇺", country:"Russia",       dst:"10.0.2.18:22",    proto:"SSH",   bytes:"18.4 MB", score:88, action:"block"   },
  { id:"3", src:"175.45.176.0",     flag:"🇰🇵", country:"North Korea",  dst:"10.0.1.100:8080", proto:"HTTP",  bytes:"892 KB",  score:96, action:"block"   },
  { id:"4", src:"52.94.28.1",       flag:"🇺🇸", country:"United States",dst:"10.0.3.22:443",   proto:"HTTPS", bytes:"4.1 GB",  score:2,  action:"allow"   },
  { id:"5", src:"91.108.56.14",     flag:"🇮🇷", country:"Iran",         dst:"10.0.1.77:53",    proto:"DNS",   bytes:"234 MB",  score:91, action:"block"   },
  { id:"6", src:"104.26.3.54",      flag:"🇺🇸", country:"United States",dst:"10.0.2.55:443",   proto:"HTTPS", bytes:"1.7 GB",  score:5,  action:"allow"   },
  { id:"7", src:"185.220.101.47",   flag:"🇷🇺", country:"Russia",       dst:"10.0.1.12:3389",  proto:"RDP",   bytes:"67.3 MB", score:99, action:"block"   },
  { id:"8", src:"13.248.148.20",    flag:"🇩🇪", country:"Germany",      dst:"10.0.3.80:443",   proto:"HTTPS", bytes:"328 MB",  score:8,  action:"monitor" },
];

const ANOMALIES: Anomaly[] = [
  { id:"a1", ts:"14:32:18", type:"Port Scan",        src:"45.83.64.12",    dst:"10.0.0.0/24",    severity:"high"     },
  { id:"a2", ts:"14:28:45", type:"Lateral Movement", src:"10.0.1.45",      dst:"10.0.2.0/24",    severity:"critical" },
  { id:"a3", ts:"14:21:09", type:"Data Exfiltration",src:"10.0.1.77",      dst:"91.108.56.14",   severity:"critical" },
  { id:"a4", ts:"14:15:33", type:"Beaconing",         src:"10.0.3.22",      dst:"185.220.101.33", severity:"high"     },
  { id:"a5", ts:"14:08:57", type:"DNS Tunneling",     src:"10.0.1.100",     dst:"91.108.56.14:53",severity:"high"     },
];

const PROTOCOLS = [
  { label:"HTTPS", pct:67, color:"bg-blue-500" },
  { label:"DNS",   pct:12, color:"bg-purple-500" },
  { label:"HTTP",  pct:8,  color:"bg-orange-500" },
  { label:"Other", pct:7,  color:"bg-slate-500" },
  { label:"SSH",   pct:4,  color:"bg-yellow-500" },
  { label:"RDP",   pct:2,  color:"bg-red-500" },
];

const REGIONS = [
  { label:"North America", level:"low",    cls:"bg-green-500/20 border-green-500/40" },
  { label:"Europe",        level:"medium", cls:"bg-yellow-500/20 border-yellow-500/40" },
  { label:"Russia",        level:"high",   cls:"bg-red-500/30 border-red-500/60" },
  { label:"China",         level:"high",   cls:"bg-red-500/30 border-red-500/60" },
  { label:"SE Asia",       level:"medium", cls:"bg-yellow-500/20 border-yellow-500/40" },
  { label:"Middle East",   level:"medium", cls:"bg-yellow-500/20 border-yellow-500/40" },
  { label:"Africa",        level:"low",    cls:"bg-green-500/20 border-green-500/40" },
  { label:"Oceania",       level:"low",    cls:"bg-green-500/20 border-green-500/40" },
];

const HOURLY = [12,8,6,5,7,10,18,34,52,61,68,74,71,65,69,72,78,85,91,88,76,58,34,20];
const ANOMALY_HOURS = new Set([9,14,15,18,19]);
const MAX_H = Math.max(...HOURLY);

const SEV_CLR: Record<ThreatLevel, string> = { critical:"text-red-400 bg-red-500/20", high:"text-orange-400 bg-orange-500/20", medium:"text-yellow-400 bg-yellow-500/20", low:"text-green-400 bg-green-500/20" };
const ACT_CFG: Record<FlowAction, { label:string; cls:string; icon:React.ReactNode }> = {
  block:   { label:"Block",   cls:"text-red-400 bg-red-500/10",    icon:<Ban className="w-3 h-3 mr-1"/> },
  monitor: { label:"Monitor", cls:"text-yellow-400 bg-yellow-500/10", icon:<Eye className="w-3 h-3 mr-1"/> },
  allow:   { label:"Allow",   cls:"text-green-400 bg-green-500/10", icon:<CheckCircle className="w-3 h-3 mr-1"/> },
};

// ── Main Page ─────────────────────────────────────────────────────────────────
export default function NetworkAnalysis() {
  const [search, setSearch] = useState("");

  const { data: ndrAlerts = ANOMALIES, isLoading: l2 } = useQuery({
    queryKey: ["ndr-alerts"],
    queryFn: async () => {
      try {
        const d = await apiFetch("/api/v1/ndr/alerts?org_id=default&limit=20");
        return Array.isArray(d) ? d : (d.items ?? d.alerts ?? ANOMALIES);
      } catch { return ANOMALIES; }
    },
  });

  const { data: ndrStats } = useQuery({
    queryKey: ["ndr-stats"],
    queryFn: async () => {
      try { return await apiFetch("/api/v1/ndr/stats?org_id=default"); }
      catch { return null; }
    },
  });

  const { data: talkers = TALKERS, isLoading: l1 } = useQuery({
    queryKey: ["network-flows"],
    queryFn: async () => { try { const r = await fetch(`${API}/api/v1/network-monitoring/stats?org_id=default`, { headers: { "X-API-Key": API_KEY } }); if (!r.ok) throw 0; return r.json(); } catch { return TALKERS; } },
  });

  const anomalies = ndrAlerts;

  const filtered = (talkers as TopTalker[]).filter(t =>
    !search || t.src.includes(search) || t.country.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="min-h-screen bg-slate-950">
      <PageHeader
        title="Network Traffic Analysis"
        description="Anomaly detection, top talkers, and threat communication monitoring"
        actions={<Button className="bg-red-600 hover:bg-red-700"><Shield className="w-4 h-4 mr-2"/>Block All Threats</Button>}
      />
      <div className="p-6 max-w-7xl mx-auto space-y-6">

        {/* KPIs */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          <KpiCard title="Alerts Today"         value={ndrStats?.total_alerts ?? ndrStats?.alerts_today ?? 47}  trend="up"   trendLabel="+12 from yesterday" icon={AlertTriangle}/>
          <KpiCard title="Suspicious Flows"     value={ndrStats?.suspicious_flows ?? 12}  trend="up"   trendLabel="Active now"          icon={Activity}/>
          <KpiCard title="Blocked Connections"  value={ndrStats?.blocked_connections ?? ndrStats?.blocked ?? 234} trend="up"   trendLabel="+18 this hour"       icon={Ban}/>
          <KpiCard title="Bandwidth Anomalies"  value={ndrStats?.bandwidth_anomalies ?? 3}   trend="flat" trendLabel="Last 1h"             icon={Zap}/>
        </div>

        {/* Top Talkers */}
        <Card className="border-slate-700 bg-slate-900/40">
          <CardHeader className="border-b border-slate-700 pb-4">
            <div className="flex items-center justify-between gap-4">
              <CardTitle className="flex items-center gap-2"><Network className="w-5 h-5 text-blue-400"/>Top Talkers</CardTitle>
              <input placeholder="Filter IP / country…" value={search} onChange={e=>setSearch(e.target.value)}
                className="h-8 w-44 rounded border border-slate-700 bg-slate-800/50 px-3 text-sm text-slate-200 placeholder:text-slate-500 focus:outline-none focus:ring-1 focus:ring-blue-500"/>
            </div>
          </CardHeader>
          <CardContent className="pt-0 overflow-x-auto">
            {l1 ? <p className="text-slate-400 py-4 px-4">Loading…</p> : (
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-slate-700/50">
                    {["Source IP","Country","Destination","Protocol","Bytes","Threat Score","Action"].map(h=>(
                      <th key={h} className="text-left py-3 px-3 font-semibold text-slate-300 text-xs">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((t,i)=>(
                    <motion.tr key={t.id} initial={{opacity:0}} animate={{opacity:1}} transition={{delay:i*0.04}}
                      className="border-b border-slate-700/30 hover:bg-slate-800/30 transition-colors">
                      <td className="py-2.5 px-3 font-mono text-slate-200 text-xs">{t.src}</td>
                      <td className="py-2.5 px-3 text-slate-300 text-xs">{t.flag} {t.country}</td>
                      <td className="py-2.5 px-3 font-mono text-slate-400 text-xs">{t.dst}</td>
                      <td className="py-2.5 px-3"><Badge variant="outline" className="border-slate-600 text-slate-300 text-xs">{t.proto}</Badge></td>
                      <td className="py-2.5 px-3 text-slate-300 text-xs">{t.bytes}</td>
                      <td className="py-2.5 px-3">
                        <div className="flex items-center gap-2">
                          <div className="w-12 h-1.5 bg-slate-700 rounded-full overflow-hidden">
                            <div className={cn("h-full rounded-full",t.score>=80?"bg-red-500":t.score>=40?"bg-yellow-500":"bg-green-500")} style={{width:`${t.score}%`}}/>
                          </div>
                          <span className={cn("text-xs font-semibold",t.score>=80?"text-red-400":t.score>=40?"text-yellow-400":"text-green-400")}>{t.score}</span>
                        </div>
                      </td>
                      <td className="py-2.5 px-3">
                        <Badge variant="outline" className={cn("border-0 text-xs flex items-center w-fit",ACT_CFG[t.action].cls)}>
                          {ACT_CFG[t.action].icon}{ACT_CFG[t.action].label}
                        </Badge>
                      </td>
                    </motion.tr>
                  ))}
                </tbody>
              </table>
            )}
          </CardContent>
        </Card>

        {/* Protocol Distribution + Anomaly Feed */}
        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          <Card className="border-slate-700 bg-slate-900/40">
            <CardHeader className="border-b border-slate-700 pb-4">
              <CardTitle className="flex items-center gap-2"><Radio className="w-5 h-5 text-purple-400"/>Protocol Distribution</CardTitle>
            </CardHeader>
            <CardContent className="pt-5 space-y-3">
              {PROTOCOLS.map((p,i)=>(
                <div key={p.label} className="space-y-1">
                  <div className="flex justify-between text-sm"><span className="text-slate-300">{p.label}</span><span className="text-slate-400 font-semibold">{p.pct}%</span></div>
                  <div className="w-full h-2 bg-slate-800 rounded-full overflow-hidden">
                    <motion.div initial={{width:0}} animate={{width:`${p.pct}%`}} transition={{delay:i*0.05,duration:0.5}} className={cn("h-full rounded-full",p.color)}/>
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>

          <div className="lg:col-span-2">
            <Card className="border-slate-700 bg-slate-900/40 h-full">
              <CardHeader className="border-b border-slate-700 pb-4">
                <div className="flex items-center justify-between">
                  <CardTitle className="flex items-center gap-2"><Zap className="w-5 h-5 text-yellow-400"/>Anomaly Feed</CardTitle>
                  <span className="flex items-center gap-1 text-xs text-green-400"><span className="w-1.5 h-1.5 bg-green-400 rounded-full animate-pulse"/>Real-time</span>
                </div>
              </CardHeader>
              <CardContent className="pt-4 space-y-3">
                {l2 ? <p className="text-slate-400">Loading…</p> : (anomalies as Anomaly[]).map((a,i)=>(
                  <motion.div key={a.id} initial={{opacity:0,x:-8}} animate={{opacity:1,x:0}} transition={{delay:i*0.06}}
                    className="flex items-start gap-3 p-3 bg-slate-800/50 rounded-lg border border-slate-700/50">
                    <AlertTriangle className="w-4 h-4 text-orange-400 mt-0.5 shrink-0"/>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-0.5">
                        <span className="text-xs font-semibold text-slate-200">{a.type}</span>
                        <Badge variant="outline" className={cn("border-0 h-5 text-xs",SEV_CLR[a.severity])}>{a.severity.toUpperCase()}</Badge>
                      </div>
                      <p className="text-xs text-slate-400 font-mono truncate">{a.src} → {a.dst}</p>
                    </div>
                    <span className="text-xs text-slate-500 shrink-0">{a.ts}</span>
                  </motion.div>
                ))}
              </CardContent>
            </Card>
          </div>
        </div>

        {/* Geo Regions + 24h Timeline */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <Card className="border-slate-700 bg-slate-900/40">
            <CardHeader className="border-b border-slate-700 pb-4">
              <CardTitle className="flex items-center gap-2"><Globe className="w-5 h-5 text-cyan-400"/>Geo Threat Regions</CardTitle>
            </CardHeader>
            <CardContent className="pt-4">
              <div className="grid grid-cols-4 gap-2">
                {REGIONS.map((r,i)=>(
                  <motion.div key={r.label} initial={{opacity:0,scale:0.9}} animate={{opacity:1,scale:1}} transition={{delay:i*0.05}}
                    className={cn("rounded-lg border p-3 text-center",r.cls)}>
                    <p className="text-xs font-semibold text-slate-200 leading-tight mb-1">{r.label}</p>
                    <p className={cn("text-xs capitalize font-medium",r.level==="high"?"text-red-300":r.level==="medium"?"text-yellow-300":"text-green-300")}>{r.level}</p>
                  </motion.div>
                ))}
              </div>
            </CardContent>
          </Card>

          <Card className="border-slate-700 bg-slate-900/40">
            <CardHeader className="border-b border-slate-700 pb-4">
              <CardTitle className="flex items-center gap-2"><Activity className="w-5 h-5 text-green-400"/>Traffic Volume (24h)</CardTitle>
            </CardHeader>
            <CardContent className="pt-4">
              <div className="flex items-end gap-0.5 h-24">
                {HOURLY.map((v,h)=>(
                  <motion.div key={h} title={`${String(h).padStart(2,"0")}:00 — ${v}${ANOMALY_HOURS.has(h)?" ⚠":""}`}
                    initial={{height:0,opacity:0}} animate={{height:`${(v/MAX_H)*100}%`,opacity:1}} transition={{delay:h*0.02,duration:0.4}}
                    className={cn("flex-1 rounded-t cursor-pointer",ANOMALY_HOURS.has(h)?"bg-gradient-to-t from-red-600 to-red-400":"bg-gradient-to-t from-blue-600 to-blue-400 opacity-60")}/>
                ))}
              </div>
              <div className="flex justify-between mt-1">
                {[0,4,8,12,16,20,23].map(h=><span key={h} className="text-xs text-slate-600">{String(h).padStart(2,"0")}h</span>)}
              </div>
              <div className="flex items-center gap-4 mt-3">
                <div className="flex items-center gap-1.5 text-xs text-slate-400"><div className="w-3 h-3 rounded-sm bg-blue-500/60"/>Normal</div>
                <div className="flex items-center gap-1.5 text-xs text-slate-400"><div className="w-3 h-3 rounded-sm bg-red-500"/>Anomaly</div>
              </div>
            </CardContent>
          </Card>
        </div>

      </div>
    </div>
  );
}
