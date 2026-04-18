/**
 * Capacity Planning Dashboard
 *
 * Security team capacity planning — FTE utilization, demand vs supply, skills.
 *   1. KPI cards: total_fte, utilized_fte, demand_fte, gap_fte (red if >0)
 *   2. Resources table (skills chips, utilization bar)
 *   3. Demands table (gap alert)
 *   4. Utilization snapshot chart
 *   5. Add resource / add demand forms
 *
 * API: /api/v1/capacity-planning
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Users, TrendingUp, AlertTriangle, RefreshCw, Plus, Activity,
} from "lucide-react";

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

async function apiFetch(path: string, opts?: RequestInit) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "X-API-Key": API_KEY, "Content-Type": "application/json" },
    ...opts,
  });
  if (!res.ok) throw new Error(`API ${res.status}`);
  return res.json();
}

// ── Mock data ─────────────────────────────────────────────────────────────────

const MOCK_RESOURCES = [
  { id: "r1", resource_name: "Alice Chen",       role: "SOC Analyst L2",         team: "SOC",         fte: 1.0, utilization_pct: 92, skills: ["SIEM","Threat Hunting","Python"],       status: "active" },
  { id: "r2", resource_name: "Bob Martinez",     role: "Penetration Tester",     team: "Red Team",    fte: 1.0, utilization_pct: 78, skills: ["Burp Suite","OSCP","Cloud Pentest"],    status: "active" },
  { id: "r3", resource_name: "Carol Singh",      role: "Cloud Security Architect",team: "Cloud",      fte: 1.0, utilization_pct: 85, skills: ["AWS","Terraform","IAM","CSPM"],         status: "active" },
  { id: "r4", resource_name: "David Kim",        role: "GRC Analyst",            team: "Compliance",  fte: 0.8, utilization_pct: 65, skills: ["ISO 27001","SOC2","GDPR"],              status: "active" },
  { id: "r5", resource_name: "Eva Johansson",    role: "Security Engineer",      team: "AppSec",      fte: 1.0, utilization_pct: 97, skills: ["SAST","DAST","DevSecOps","K8s"],       status: "active" },
  { id: "r6", resource_name: "Frank Nguyen",     role: "Incident Responder",     team: "SOC",         fte: 1.0, utilization_pct: 55, skills: ["DFIR","Volatility","Splunk"],          status: "active" },
  { id: "r7", resource_name: "Grace Okonkwo",    role: "Threat Intel Analyst",   team: "Intel",       fte: 0.5, utilization_pct: 72, skills: ["MISP","STIX","Python","OpenCTI"],      status: "active" },
];

const MOCK_DEMANDS = [
  { id: "d1", demand_name: "Cloud WAF Implementation",       domain: "cloud",      priority: "critical", required_fte: 1.5, gap_fte: 0.5,  status: "partially_fulfilled", timeline: "Q2 2026" },
  { id: "d2", demand_name: "SOC 24/7 Coverage Expansion",   domain: "soc",        priority: "high",     required_fte: 2.0, gap_fte: 2.0,  status: "open",                timeline: "Q3 2026" },
  { id: "d3", demand_name: "Red Team Quarterly Ops",         domain: "red-team",   priority: "high",     required_fte: 1.0, gap_fte: 0.0,  status: "fulfilled",           timeline: "Q2 2026" },
  { id: "d4", demand_name: "PCI DSS 4.0 Gap Assessment",    domain: "compliance", priority: "critical", required_fte: 0.8, gap_fte: 0.8,  status: "open",                timeline: "Q2 2026" },
  { id: "d5", demand_name: "AppSec SDLC Integration",        domain: "appsec",     priority: "medium",   required_fte: 0.5, gap_fte: 0.0,  status: "fulfilled",           timeline: "Q2 2026" },
  { id: "d6", demand_name: "Threat Intel Platform Build-out",domain: "intel",      priority: "high",     required_fte: 1.0, gap_fte: 0.5,  status: "partially_fulfilled", timeline: "Q3 2026" },
];

const MOCK_SNAPSHOTS = [
  { snapshot_date: "2026-01-31", utilization_rate: 68 },
  { snapshot_date: "2026-02-28", utilization_rate: 74 },
  { snapshot_date: "2026-03-31", utilization_rate: 81 },
  { snapshot_date: "2026-04-15", utilization_rate: 78 },
];

const TOTAL_FTE    = MOCK_RESOURCES.reduce((s, r) => s + r.fte, 0);
const UTILIZED_FTE = parseFloat((TOTAL_FTE * (MOCK_RESOURCES.reduce((s, r) => s + r.utilization_pct, 0) / MOCK_RESOURCES.length / 100)).toFixed(1));
const DEMAND_FTE   = MOCK_DEMANDS.reduce((s, d) => s + d.required_fte, 0);
const GAP_FTE      = parseFloat((DEMAND_FTE - TOTAL_FTE).toFixed(1));

// ── Helpers ───────────────────────────────────────────────────────────────────

function RoleBadge({ role }: { role: string }) {
  return <Badge className="text-[10px] border border-blue-500/30 text-blue-400 bg-blue-500/10">{role}</Badge>;
}

function TeamBadge({ team }: { team: string }) {
  const map: Record<string, string> = {
    SOC:        "border-purple-500/30 text-purple-400 bg-purple-500/10",
    "Red Team": "border-red-500/30 text-red-400 bg-red-500/10",
    Cloud:      "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
    Compliance: "border-green-500/30 text-green-400 bg-green-500/10",
    AppSec:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
    Intel:      "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
  };
  return <Badge className={cn("text-[10px] border", map[team] ?? "border-border text-muted-foreground")}>{team}</Badge>;
}

function PriorityBadge({ p }: { p: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
    medium:   "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    low:      "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[p] ?? "border-border text-muted-foreground")}>{p}</Badge>;
}

function StatusBadge({ s }: { s: string }) {
  const map: Record<string, string> = {
    fulfilled:            "border-green-500/30 text-green-400 bg-green-500/10",
    partially_fulfilled:  "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    open:                 "border-red-500/30 text-red-400 bg-red-500/10",
    active:               "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[s] ?? "border-border text-muted-foreground")}>{s.replace(/_/g, " ")}</Badge>;
}

function UtilBar({ pct }: { pct: number }) {
  const color = pct > 80 ? "bg-red-500" : pct > 60 ? "bg-yellow-500" : "bg-green-500";
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 bg-muted rounded-full overflow-hidden">
        <div className={cn("h-full rounded-full", color)} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-[10px] text-muted-foreground w-8 text-right">{pct}%</span>
    </div>
  );
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function CapacityPlanningDashboard() {
  const [showResourceForm, setShowResourceForm] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [showDemandForm, setShowDemandForm] = useState(false);
  const [refreshing, setRefreshing] = useState(false);


  const fetchData = () => {
    setError(null);
    apiFetch(`/api/v1/capacity-planning/resources?org_id=${ORG_ID}`).catch(err => setError(err.message || 'Failed to load data'));
  };

  useEffect(() => { fetchData(); }, []);
  const [resourceForm, setResourceForm] = useState({ resource_name: "", role: "", team: "SOC", fte: "1.0", status: "active" });
  const [demandForm, setDemandForm] = useState({ demand_name: "", domain: "cloud", priority: "high", required_fte: "1.0", timeline: "" });

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      {error && (
        <div className="rounded-lg border border-red-200 bg-red-50 p-4 text-red-800">
          <p className="font-medium">Error loading data</p>
          <p className="text-sm">{error}</p>
          <button onClick={() => { setError(null); fetchData(); }} className="mt-2 text-sm underline">Retry</button>
        </div>
      )}
      <PageHeader
        title="Security Capacity Planning"
        description="Security team FTE utilization, demand vs supply gaps, and skills inventory"
        actions={
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={() => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); }} disabled={refreshing}>
              <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
            </Button>
            <Button size="sm" variant="outline" onClick={() => setShowDemandForm(v => !v)}>
              <Plus className="h-4 w-4 mr-1" /> Demand
            </Button>
            <Button size="sm" onClick={() => setShowResourceForm(v => !v)}>
              <Plus className="h-4 w-4 mr-1" /> Resource
            </Button>
          </div>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total FTE"    value={TOTAL_FTE}    icon={Users}        trend="up" />
        <KpiCard title="Utilized FTE" value={UTILIZED_FTE} icon={Activity}     trend="flat" className="border-blue-500/20" />
        <KpiCard title="Demand FTE"   value={DEMAND_FTE}   icon={TrendingUp}   trend="up" className="border-orange-500/20" />
        <KpiCard
          title="Gap FTE"
          value={GAP_FTE > 0 ? `+${GAP_FTE}` : GAP_FTE.toString()}
          icon={AlertTriangle}
          trend={GAP_FTE > 0 ? "down" : "up"}
          className={GAP_FTE > 0 ? "border-red-500/20" : "border-green-500/20"}
        />
      </div>

      {/* Add Resource Form */}
      {showResourceForm && (
        <Card className="border-blue-500/20">
          <CardHeader className="pb-3"><CardTitle className="text-sm font-semibold">Add Security Resource</CardTitle></CardHeader>
          <CardContent>
            <form className="grid grid-cols-2 gap-3 md:grid-cols-4" onSubmit={async e => {
              e.preventDefault();
              try { await apiFetch(`/api/v1/capacity-planning/resources?org_id=${ORG_ID}`, { method: "POST", body: JSON.stringify({ ...resourceForm, org_id: ORG_ID }) }); } catch (_) {}
              setShowResourceForm(false);
            }}>
              {[["resource_name","Name"],["role","Role"],["fte","FTE"]].map(([k, l]) => (
                <div key={k} className="flex flex-col gap-1">
                  <label className="text-[10px] text-muted-foreground">{l}</label>
                  <input className="h-8 rounded-md border border-border bg-background px-3 text-xs" value={(resourceForm as any)[k]} onChange={e => setResourceForm(f => ({ ...f, [k]: e.target.value }))} required />
                </div>
              ))}
              <div className="flex flex-col gap-1">
                <label className="text-[10px] text-muted-foreground">Team</label>
                <select className="h-8 rounded-md border border-border bg-background px-3 text-xs" value={resourceForm.team} onChange={e => setResourceForm(f => ({ ...f, team: e.target.value }))}>
                  {["SOC","Red Team","Cloud","Compliance","AppSec","Intel"].map(t => <option key={t} value={t}>{t}</option>)}
                </select>
              </div>
              <div className="col-span-2 md:col-span-4 flex gap-2 justify-end">
                <Button variant="outline" size="sm" type="button" onClick={() => setShowResourceForm(false)}>Cancel</Button>
                <Button size="sm" type="submit">Add Resource</Button>
              </div>
            </form>
          </CardContent>
        </Card>
      )}

      {/* Add Demand Form */}
      {showDemandForm && (
        <Card className="border-orange-500/20">
          <CardHeader className="pb-3"><CardTitle className="text-sm font-semibold">Add Capacity Demand</CardTitle></CardHeader>
          <CardContent>
            <form className="grid grid-cols-2 gap-3 md:grid-cols-4" onSubmit={async e => {
              e.preventDefault();
              try { await apiFetch(`/api/v1/capacity-planning/demands?org_id=${ORG_ID}`, { method: "POST", body: JSON.stringify({ ...demandForm, org_id: ORG_ID }) }); } catch (_) {}
              setShowDemandForm(false);
            }}>
              <div className="flex flex-col gap-1 col-span-2">
                <label className="text-[10px] text-muted-foreground">Demand Name</label>
                <input className="h-8 rounded-md border border-border bg-background px-3 text-xs" value={demandForm.demand_name} onChange={e => setDemandForm(f => ({ ...f, demand_name: e.target.value }))} required />
              </div>
              {[["required_fte","Required FTE"],["timeline","Timeline"]].map(([k, l]) => (
                <div key={k} className="flex flex-col gap-1">
                  <label className="text-[10px] text-muted-foreground">{l}</label>
                  <input className="h-8 rounded-md border border-border bg-background px-3 text-xs" value={(demandForm as any)[k]} onChange={e => setDemandForm(f => ({ ...f, [k]: e.target.value }))} required />
                </div>
              ))}
              {[["domain","Domain",["cloud","soc","red-team","compliance","appsec","intel"]],["priority","Priority",["critical","high","medium","low"]]].map(([k, l, opts]) => (
                <div key={k as string} className="flex flex-col gap-1">
                  <label className="text-[10px] text-muted-foreground">{l as string}</label>
                  <select className="h-8 rounded-md border border-border bg-background px-3 text-xs" value={(demandForm as any)[k as string]} onChange={e => setDemandForm(f => ({ ...f, [k as string]: e.target.value }))}>
                    {(opts as string[]).map(o => <option key={o} value={o}>{o}</option>)}
                  </select>
                </div>
              ))}
              <div className="col-span-2 md:col-span-4 flex gap-2 justify-end">
                <Button variant="outline" size="sm" type="button" onClick={() => setShowDemandForm(false)}>Cancel</Button>
                <Button size="sm" type="submit">Add Demand</Button>
              </div>
            </form>
          </CardContent>
        </Card>
      )}

      {/* Resources Table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Users className="h-4 w-4 text-blue-400" /> Security Resources
            </CardTitle>
            <Badge className="text-[10px] border border-border text-muted-foreground">{MOCK_RESOURCES.length} people</Badge>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Name</TableHead>
                  <TableHead className="text-[11px] h-8">Role</TableHead>
                  <TableHead className="text-[11px] h-8">Team</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">FTE</TableHead>
                  <TableHead className="text-[11px] h-8 min-w-[140px]">Utilization</TableHead>
                  <TableHead className="text-[11px] h-8">Skills</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {MOCK_RESOURCES.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  MOCK_RESOURCES.map(r => (
                  <TableRow key={r.id} className="hover:bg-muted/30">
                    <TableCell className="py-2 text-[11px] font-medium">{r.resource_name}</TableCell>
                    <TableCell className="py-2"><RoleBadge role={r.role} /></TableCell>
                    <TableCell className="py-2"><TeamBadge team={r.team} /></TableCell>
                    <TableCell className="py-2 text-right text-[11px]">{r.fte}</TableCell>
                    <TableCell className="py-2 min-w-[140px]"><UtilBar pct={r.utilization_pct} /></TableCell>
                    <TableCell className="py-2">
                      <div className="flex flex-wrap gap-1">
                        {r.skills.map(s => (
                          <Badge key={s} className="text-[9px] border border-border text-muted-foreground">{s}</Badge>
                        ))
                )}
                      </div>
                    </TableCell>
                    <TableCell className="py-2"><StatusBadge s={r.status} /></TableCell>
                  </TableRow>
                ))
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Demands Table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-orange-400" /> Capacity Demands
            </CardTitle>
            <Badge className="text-[10px] border border-orange-500/30 text-orange-400 bg-orange-500/10">
              {MOCK_DEMANDS.filter(d => d.gap_fte > 0).length} with gaps
            </Badge>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Demand</TableHead>
                  <TableHead className="text-[11px] h-8">Domain</TableHead>
                  <TableHead className="text-[11px] h-8">Priority</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Required FTE</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Gap FTE</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8">Timeline</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {MOCK_DEMANDS.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  MOCK_DEMANDS.map(d => (
                  <TableRow key={d.id} className="hover:bg-muted/30">
                    <TableCell className="py-2 text-[11px] font-medium">{d.demand_name}</TableCell>
                    <TableCell className="py-2">
                      <Badge className="text-[10px] border border-cyan-500/30 text-cyan-400 bg-cyan-500/10 capitalize">{d.domain}</Badge>
                    </TableCell>
                    <TableCell className="py-2"><PriorityBadge p={d.priority} /></TableCell>
                    <TableCell className="py-2 text-right text-[11px]">{d.required_fte}</TableCell>
                    <TableCell className="py-2 text-right text-[11px]">
                      {d.gap_fte > 0
                        ? <span className="flex items-center justify-end gap-1 text-red-400 font-semibold">
                            <AlertTriangle className="h-3 w-3" />{d.gap_fte}
                          </span>
                        : <span className="text-green-400">0.0</span>}
                    </TableCell>
                    <TableCell className="py-2"><StatusBadge s={d.status} /></TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{d.timeline}</TableCell>
                  </TableRow>
                ))
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Utilization Snapshots */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <TrendingUp className="h-4 w-4 text-purple-400" /> Utilization Trend
          </CardTitle>
          <CardDescription className="text-xs">Monthly average team utilization rate</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {MOCK_SNAPSHOTS.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                <p className="text-lg font-medium">No data available</p>
                <p className="text-sm">Data will appear here once available</p>
              </div>
            ) : (
              MOCK_SNAPSHOTS.map((snap, i) => (
              <div key={i} className="flex items-center gap-3">
                <span className="text-[11px] text-muted-foreground w-24 shrink-0">{snap.snapshot_date}</span>
                <div className="flex-1 h-6 bg-muted rounded overflow-hidden relative">
                  <div
                    className={cn("h-full rounded transition-all", snap.utilization_rate > 80 ? "bg-red-500/70" : snap.utilization_rate > 60 ? "bg-yellow-500/70" : "bg-green-500/70")}
                    style={{ width: `${snap.utilization_rate}%` }}
                  />
                  <span className="absolute inset-0 flex items-center px-2 text-[10px] font-semibold text-white">{snap.utilization_rate}%</span>
                </div>
              </div>
            ))
            )}
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
