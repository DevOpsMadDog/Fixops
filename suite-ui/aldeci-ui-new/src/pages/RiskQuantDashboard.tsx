/**
 * Risk Quant Dashboard
 *
 * FAIR risk quantification — ALE/SLE scenarios, control ROI, portfolio snapshots.
 *   1. KPI cards: Total ALE, Critical Scenarios, Avg ALE, Top Control ROI
 *   2. Scenarios table (threat_type, risk_level badges)
 *   3. Controls panel with effectiveness bars and ROI
 *   4. Snapshots timeline
 *   5. Add scenario form
 *
 * API: /api/v1/risk-quant
 */

import { useState } from "react";
import { motion } from "framer-motion";
import {
  DollarSign, AlertTriangle, TrendingUp, Shield, RefreshCw,
  ChevronDown, Plus, BarChart2,
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

const MOCK_SCENARIOS = [
  { id: "s1", scenario_name: "Ransomware Attack on Core Infrastructure", asset_name: "ERP System", threat_actor: "LockBit", threat_type: "ransomware", asset_value: 4500000, sle: 1800000, aro: 0.35, ale: 630000, risk_level: "critical" },
  { id: "s2", scenario_name: "Data Breach via SQL Injection", asset_name: "Customer DB", threat_actor: "Unknown APT", threat_type: "data-breach", asset_value: 6200000, sle: 950000, aro: 0.55, ale: 522500, risk_level: "critical" },
  { id: "s3", scenario_name: "Supply Chain Compromise", asset_name: "CI/CD Pipeline", threat_actor: "SolarStorm", threat_type: "supply-chain", asset_value: 2800000, sle: 560000, aro: 0.15, ale: 84000, risk_level: "high" },
  { id: "s4", scenario_name: "Credential Stuffing on VPN", asset_name: "Remote Access", threat_actor: "Generic", threat_type: "credential-attack", asset_value: 1200000, sle: 180000, aro: 0.70, ale: 126000, risk_level: "high" },
  { id: "s5", scenario_name: "Insider Threat Data Exfiltration", asset_name: "IP Repository", threat_actor: "Disgruntled Employee", threat_type: "insider-threat", asset_value: 3100000, sle: 620000, aro: 0.08, ale: 49600, risk_level: "medium" },
  { id: "s6", scenario_name: "DDoS on Public API", asset_name: "API Gateway", threat_actor: "Hacktivist", threat_type: "ddos", asset_value: 800000, sle: 80000, aro: 0.45, ale: 36000, risk_level: "medium" },
  { id: "s7", scenario_name: "Phishing Campaign HR Staff", asset_name: "HR System", threat_actor: "TA505", threat_type: "phishing", asset_value: 950000, sle: 95000, aro: 0.90, ale: 85500, risk_level: "high" },
];

const MOCK_CONTROLS = [
  { id: "c1", scenario_id: "s1", control_name: "EDR with Rollback", control_type: "preventive", implementation_cost: 120000, annual_cost: 48000, effectiveness_pct: 85, roi: 4.2, recommended: true },
  { id: "c2", scenario_id: "s2", control_name: "WAF + SQL Injection Rules", control_type: "preventive", implementation_cost: 35000, annual_cost: 18000, effectiveness_pct: 78, roi: 7.8, recommended: true },
  { id: "c3", scenario_id: "s3", control_name: "SBOM + Dependency Scanning", control_type: "detective", implementation_cost: 60000, annual_cost: 24000, effectiveness_pct: 62, roi: 0.8, recommended: false },
  { id: "c4", scenario_id: "s4", control_name: "MFA Enforcement + UEBA", control_type: "preventive", implementation_cost: 25000, annual_cost: 12000, effectiveness_pct: 92, roi: 5.9, recommended: true },
  { id: "c5", scenario_id: "s5", control_name: "PAM + Session Recording", control_type: "detective", implementation_cost: 80000, annual_cost: 32000, effectiveness_pct: 71, roi: -0.3, recommended: false },
  { id: "c6", scenario_id: "s6", control_name: "CDN + Rate Limiting", control_type: "preventive", implementation_cost: 15000, annual_cost: 8000, effectiveness_pct: 88, roi: 1.6, recommended: true },
  { id: "c7", scenario_id: "s7", control_name: "Email Sandboxing + DMARC", control_type: "preventive", implementation_cost: 20000, annual_cost: 9600, effectiveness_pct: 80, roi: 2.5, recommended: true },
];

const MOCK_SNAPSHOTS = [
  { snapshot_date: "2026-01-31", total_ale: 1850000, critical_scenarios: 3 },
  { snapshot_date: "2026-02-28", total_ale: 1640000, critical_scenarios: 3 },
  { snapshot_date: "2026-03-31", total_ale: 1480000, critical_scenarios: 2 },
  { snapshot_date: "2026-04-15", total_ale: 1533600, critical_scenarios: 2 },
];

const TOTAL_ALE = MOCK_SCENARIOS.reduce((s, r) => s + r.ale, 0);
const AVG_ALE = TOTAL_ALE / MOCK_SCENARIOS.length;
const CRITICAL = MOCK_SCENARIOS.filter(s => s.risk_level === "critical").length;
const TOP_ROI = Math.max(...MOCK_CONTROLS.map(c => c.roi));

// ── Helpers ───────────────────────────────────────────────────────────────────

function fmt$(n: number) {
  if (n >= 1_000_000) return `$${(n / 1_000_000).toFixed(2)}M`;
  if (n >= 1_000) return `$${(n / 1_000).toFixed(0)}K`;
  return `$${n}`;
}

function RiskBadge({ level }: { level: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
    medium:   "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    low:      "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[level] ?? "border-border text-muted-foreground")}>
      {level}
    </Badge>
  );
}

function ThreatBadge({ type }: { type: string }) {
  return (
    <Badge className="text-[10px] border border-purple-500/30 text-purple-400 bg-purple-500/10 capitalize">
      {type.replace(/-/g, " ")}
    </Badge>
  );
}

function TypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    preventive: "border-blue-500/30 text-blue-400 bg-blue-500/10",
    detective:  "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
    corrective: "border-amber-500/30 text-amber-400 bg-amber-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[type] ?? "border-border text-muted-foreground")}>
      {type}
    </Badge>
  );
}

function PctBar({ pct, color = "bg-blue-500" }: { pct: number; color?: string }) {
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 bg-muted rounded-full overflow-hidden">
        <div className={cn("h-full rounded-full", color)} style={{ width: `${Math.min(100, pct)}%` }} />
      </div>
      <span className="text-[10px] text-muted-foreground w-8 text-right">{pct}%</span>
    </div>
  );
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function RiskQuantDashboard() {
  const [scenarioFilter, setScenarioFilter] = useState<string>("all");
  const [showForm, setShowForm] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [form, setForm] = useState({
    scenario_name: "", asset_name: "", threat_actor: "", threat_type: "ransomware",
    asset_value: "", sle: "", aro: "", risk_level: "high",
  });

  const handleRefresh = () => {
    setRefreshing(true);
    setTimeout(() => setRefreshing(false), 800);
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await apiFetch(`/api/v1/risk-quant/scenarios?org_id=${ORG_ID}`, {
        method: "POST",
        body: JSON.stringify({ ...form, org_id: ORG_ID }),
      });
    } catch (_) { /* use mock */ }
    setShowForm(false);
    setForm({ scenario_name: "", asset_name: "", threat_actor: "", threat_type: "ransomware", asset_value: "", sle: "", aro: "", risk_level: "high" });
  };

  const filteredControls = scenarioFilter === "all"
    ? MOCK_CONTROLS
    : MOCK_CONTROLS.filter(c => c.scenario_id === scenarioFilter);

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="FAIR Risk Quantification"
        description="Financial risk quantification using FAIR methodology — ALE, SLE, and control ROI analysis"
        actions={
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
              <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
            </Button>
            <Button size="sm" onClick={() => setShowForm(v => !v)}>
              <Plus className="h-4 w-4 mr-1" /> New Scenario
            </Button>
          </div>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total ALE"          value={fmt$(TOTAL_ALE)}  icon={DollarSign}    trend="down" className="border-red-500/20" />
        <KpiCard title="Critical Scenarios" value={CRITICAL}          icon={AlertTriangle} trend="flat" className="border-orange-500/20" />
        <KpiCard title="Avg ALE / Scenario" value={fmt$(AVG_ALE)}    icon={BarChart2}     trend="down" />
        <KpiCard title="Top Control ROI"    value={`${TOP_ROI}x`}    icon={TrendingUp}    trend="up"   className="border-green-500/20" />
      </div>

      {/* Add Scenario Form */}
      {showForm && (
        <Card className="border-blue-500/20">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold">New FAIR Scenario</CardTitle>
          </CardHeader>
          <CardContent>
            <form onSubmit={handleSubmit} className="grid grid-cols-2 gap-3 md:grid-cols-4">
              {[
                ["scenario_name", "Scenario Name"], ["asset_name", "Asset Name"],
                ["threat_actor", "Threat Actor"],   ["asset_value", "Asset Value ($)"],
                ["sle", "SLE ($)"],                 ["aro", "ARO (0-1)"],
              ].map(([k, label]) => (
                <div key={k} className="flex flex-col gap-1">
                  <label className="text-[10px] text-muted-foreground">{label}</label>
                  <input
                    className="h-8 rounded-md border border-border bg-background px-3 text-xs"
                    value={(form as any)[k]}
                    onChange={e => setForm(f => ({ ...f, [k]: e.target.value }))}
                    required
                  />
                </div>
              ))}
              <div className="flex flex-col gap-1">
                <label className="text-[10px] text-muted-foreground">Threat Type</label>
                <select className="h-8 rounded-md border border-border bg-background px-3 text-xs" value={form.threat_type} onChange={e => setForm(f => ({ ...f, threat_type: e.target.value }))}>
                  {["ransomware","data-breach","supply-chain","credential-attack","insider-threat","ddos","phishing"].map(t => <option key={t} value={t}>{t}</option>)}
                </select>
              </div>
              <div className="flex flex-col gap-1">
                <label className="text-[10px] text-muted-foreground">Risk Level</label>
                <select className="h-8 rounded-md border border-border bg-background px-3 text-xs" value={form.risk_level} onChange={e => setForm(f => ({ ...f, risk_level: e.target.value }))}>
                  {["critical","high","medium","low"].map(r => <option key={r} value={r}>{r}</option>)}
                </select>
              </div>
              <div className="col-span-2 md:col-span-4 flex gap-2 justify-end">
                <Button variant="outline" size="sm" type="button" onClick={() => setShowForm(false)}>Cancel</Button>
                <Button size="sm" type="submit">Create Scenario</Button>
              </div>
            </form>
          </CardContent>
        </Card>
      )}

      {/* Scenarios Table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-orange-400" /> Risk Scenarios
            </CardTitle>
            <Badge className="text-[10px] border border-border text-muted-foreground">{MOCK_SCENARIOS.length} scenarios</Badge>
          </div>
          <CardDescription className="text-xs">FAIR-based loss scenarios with SLE, ARO, and ALE calculations</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Scenario</TableHead>
                  <TableHead className="text-[11px] h-8">Asset</TableHead>
                  <TableHead className="text-[11px] h-8">Threat Actor</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Asset Value</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">SLE</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">ALE</TableHead>
                  <TableHead className="text-[11px] h-8">Risk</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {MOCK_SCENARIOS.map(s => (
                  <TableRow
                    key={s.id}
                    className={cn("hover:bg-muted/30 cursor-pointer", scenarioFilter === s.id && "bg-muted/20")}
                    onClick={() => setScenarioFilter(f => f === s.id ? "all" : s.id)}
                  >
                    <TableCell className="py-2 text-[11px] font-medium max-w-[220px] truncate">{s.scenario_name}</TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{s.asset_name}</TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{s.threat_actor}</TableCell>
                    <TableCell className="py-2"><ThreatBadge type={s.threat_type} /></TableCell>
                    <TableCell className="py-2 text-right text-[11px]">{fmt$(s.asset_value)}</TableCell>
                    <TableCell className="py-2 text-right text-[11px] text-amber-400">{fmt$(s.sle)}</TableCell>
                    <TableCell className="py-2 text-right text-[11px] font-semibold text-red-400">{fmt$(s.ale)}</TableCell>
                    <TableCell className="py-2"><RiskBadge level={s.risk_level} /></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
          {scenarioFilter !== "all" && (
            <div className="px-4 py-2 border-t border-border">
              <Button variant="ghost" size="sm" className="text-[10px] h-6 text-muted-foreground" onClick={() => setScenarioFilter("all")}>
                <ChevronDown className="h-3 w-3 mr-1" /> Clear filter — show all controls
              </Button>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Controls Panel */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Shield className="h-4 w-4 text-blue-400" /> Security Controls &amp; ROI
            </CardTitle>
            <Badge className="text-[10px] border border-border text-muted-foreground">
              {filteredControls.length} controls
              {scenarioFilter !== "all" && " (filtered)"}
            </Badge>
          </div>
          <CardDescription className="text-xs">Click a scenario row to filter controls. ROI = (risk reduction − cost) / cost</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Control</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Impl. Cost</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Annual Cost</TableHead>
                  <TableHead className="text-[11px] h-8 min-w-[140px]">Effectiveness</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">ROI</TableHead>
                  <TableHead className="text-[11px] h-8">Rec.</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredControls.map(c => (
                  <TableRow key={c.id} className="hover:bg-muted/30">
                    <TableCell className="py-2 text-[11px] font-medium">{c.control_name}</TableCell>
                    <TableCell className="py-2"><TypeBadge type={c.control_type} /></TableCell>
                    <TableCell className="py-2 text-right text-[11px]">{fmt$(c.implementation_cost)}</TableCell>
                    <TableCell className="py-2 text-right text-[11px] text-muted-foreground">{fmt$(c.annual_cost)}/yr</TableCell>
                    <TableCell className="py-2 min-w-[140px]">
                      <PctBar
                        pct={c.effectiveness_pct}
                        color={c.effectiveness_pct >= 80 ? "bg-green-500" : c.effectiveness_pct >= 60 ? "bg-amber-500" : "bg-red-500"}
                      />
                    </TableCell>
                    <TableCell className={cn("py-2 text-right text-[11px] font-semibold", c.roi >= 0 ? "text-green-400" : "text-red-400")}>
                      {c.roi >= 0 ? "+" : ""}{c.roi}x
                    </TableCell>
                    <TableCell className="py-2">
                      {c.recommended
                        ? <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">recommended</Badge>
                        : <span className="text-[10px] text-muted-foreground">—</span>}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Snapshots Timeline */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <TrendingUp className="h-4 w-4 text-purple-400" /> Portfolio ALE Timeline
          </CardTitle>
          <CardDescription className="text-xs">Monthly portfolio risk snapshots</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-3">
            {MOCK_SNAPSHOTS.map((snap, i) => {
              const maxAle = Math.max(...MOCK_SNAPSHOTS.map(s => s.total_ale));
              const pct = (snap.total_ale / maxAle) * 100;
              return (
                <div key={i} className="flex items-center gap-3">
                  <span className="text-[11px] text-muted-foreground w-24 shrink-0">{snap.snapshot_date}</span>
                  <div className="flex-1 h-6 bg-muted rounded overflow-hidden relative">
                    <div
                      className="h-full bg-gradient-to-r from-red-600/80 to-red-500/60 rounded transition-all duration-500"
                      style={{ width: `${pct}%` }}
                    />
                    <span className="absolute inset-0 flex items-center px-2 text-[10px] font-semibold text-white">{fmt$(snap.total_ale)}</span>
                  </div>
                  <Badge className={cn("text-[10px] border shrink-0", snap.critical_scenarios > 2 ? "border-red-500/30 text-red-400 bg-red-500/10" : "border-orange-500/30 text-orange-400 bg-orange-500/10")}>
                    {snap.critical_scenarios} critical
                  </Badge>
                </div>
              );
            })}
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
