/**
 * TPRM Exchange Dashboard
 *
 * Third-Party Risk Management = vendor profiles, assessments, incidents.
 *   1. KPI cards: total vendors, tier-1 count, active assessments, high_risk alert
 *   2. Vendor profiles table
 *   3. Assessment panel with complete button
 *   4. Incidents table
 *   5. Add vendor form
 *
 * API: /api/v1/tprm-exchange
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Building2, ShieldAlert, ClipboardCheck, AlertTriangle, RefreshCw, Plus, CheckCircle2,
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

// == Mock data =================================================================

const MOCK_VENDORS = [
  { id: "v1", vendor_name: "CloudStrike Corp",    category: "cloud-provider",  criticality: "critical", risk_tier: "tier-1", compliance_score: 82, contract_value: 480000, status: "active" },
  { id: "v2", vendor_name: "DataFlow Analytics",  category: "data-processor",  criticality: "high",     risk_tier: "tier-2", compliance_score: 71, contract_value: 120000, status: "active" },
  { id: "v3", vendor_name: "SecurePay Gateway",   category: "payment",         criticality: "critical", risk_tier: "tier-1", compliance_score: 91, contract_value: 360000, status: "active" },
  { id: "v4", vendor_name: "SwiftShip Logistics", category: "logistics",       criticality: "medium",   risk_tier: "tier-3", compliance_score: 64, contract_value: 75000,  status: "under-review" },
  { id: "v5", vendor_name: "OfficeSupply Co",     category: "facilities",      criticality: "low",      risk_tier: "tier-4", compliance_score: 88, contract_value: 12000,  status: "active" },
  { id: "v6", vendor_name: "TalentBridge HR",     category: "hr-services",     criticality: "high",     risk_tier: "tier-2", compliance_score: 59, contract_value: 96000,  status: "active" },
  { id: "v7", vendor_name: "NetSec Managed SOC",  category: "security",        criticality: "critical", risk_tier: "tier-1", compliance_score: 88, contract_value: 540000, status: "active" },
];

const MOCK_ASSESSMENTS = [
  { id: "a1", vendor_id: "v1", assessment_type: "security-questionnaire", status: "in-progress", overall_score: 74, risk_level: "medium", assessor: "alice@aldeci.io", start_date: "2026-04-01", end_date: "2026-04-20" },
  { id: "a2", vendor_id: "v6", assessment_type: "on-site-audit",          status: "pending",     overall_score: 0,  risk_level: "high",   assessor: "bob@aldeci.io",   start_date: "2026-04-15", end_date: "2026-04-30" },
  { id: "a3", vendor_id: "v4", assessment_type: "doc-review",             status: "in-progress", overall_score: 55, risk_level: "high",   assessor: "carol@aldeci.io", start_date: "2026-03-20", end_date: "2026-04-10" },
  { id: "a4", vendor_id: "v3", assessment_type: "penetration-test",       status: "completed",   overall_score: 91, risk_level: "low",    assessor: "dave@aldeci.io",  start_date: "2026-03-01", end_date: "2026-03-28" },
  { id: "a5", vendor_id: "v7", assessment_type: "security-questionnaire", status: "in-progress", overall_score: 83, risk_level: "low",    assessor: "eva@aldeci.io",   start_date: "2026-04-10", end_date: "2026-04-25" },
];

const MOCK_INCIDENTS = [
  { id: "i1", vendor_id: "v6", incident_type: "data-leak",        severity: "high",     status: "investigating", reported_date: "2026-04-02" },
  { id: "i2", vendor_id: "v4", incident_type: "access-violation", severity: "medium",   status: "open",          reported_date: "2026-04-08" },
  { id: "i3", vendor_id: "v2", incident_type: "breach",           severity: "critical", status: "resolved",      reported_date: "2026-03-15" },
  { id: "i4", vendor_id: "v1", incident_type: "misconfiguration", severity: "low",      status: "resolved",      reported_date: "2026-02-28" },
];

const TIER1_COUNT   = MOCK_VENDORS.filter(v => v.risk_tier === "tier-1").length;
const ACTIVE_ASSESS = MOCK_ASSESSMENTS.filter(a => a.status !== "completed").length;
const HIGH_RISK     = MOCK_VENDORS.filter(v => v.compliance_score < 65).length;

// == Helpers ===================================================================

function TierBadge({ tier }: { tier: string }) {
  const map: Record<string, string> = {
    "tier-1": "border-red-500/30 text-red-400 bg-red-500/10",
    "tier-2": "border-orange-500/30 text-orange-400 bg-orange-500/10",
    "tier-3": "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    "tier-4": "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return <Badge className={cn("text-[10px] border font-mono", map[tier] ?? "border-border text-muted-foreground")}>{tier}</Badge>;
}

function CriticalityBadge({ c }: { c: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
    medium:   "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    low:      "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[c] ?? "border-border text-muted-foreground")}>{c}</Badge>;
}

function CatBadge({ cat }: { cat: string }) {
  return <Badge className="text-[10px] border border-blue-500/30 text-blue-400 bg-blue-500/10 capitalize">{cat.replace(/-/g, " ")}</Badge>;
}

function AssessTypeBadge({ t }: { t: string }) {
  return <Badge className="text-[10px] border border-purple-500/30 text-purple-400 bg-purple-500/10 capitalize">{t.replace(/-/g, " ")}</Badge>;
}

function AssessStatusBadge({ s }: { s: string }) {
  const map: Record<string, string> = {
    "in-progress": "border-blue-500/30 text-blue-400 bg-blue-500/10",
    pending:       "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    completed:     "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[s] ?? "border-border text-muted-foreground")}>{s.replace(/-/g, " ")}</Badge>;
}

function IncidentStatusBadge({ s }: { s: string }) {
  const map: Record<string, string> = {
    open:          "border-red-500/30 text-red-400 bg-red-500/10",
    investigating: "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    resolved:      "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[s] ?? "border-border text-muted-foreground")}>{s}</Badge>;
}

function SeverityBadge({ s }: { s: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
    medium:   "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    low:      "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[s] ?? "border-border text-muted-foreground")}>{s}</Badge>;
}

function ScoreBar({ score }: { score: number }) {
  if (score === 0) return <span className="text-[10px] text-muted-foreground">=</span>;
  const color = score >= 80 ? "bg-green-500" : score >= 60 ? "bg-yellow-500" : "bg-red-500";
  return (
    <div className="flex items-center gap-2">
      {error && (
        <div className="bg-red-900/20 border border-red-500/30 rounded-lg p-4 flex items-center justify-between" role="status" aria-live="polite">
          <p className="text-red-400 text-sm">{error}</p>
          <button
            onClick={() => { setError(null); window.location.reload(); }}
            className="px-3 py-1 bg-red-600 hover:bg-red-700 text-white text-xs rounded transition-colors"
           aria-label="Refresh data">
            Retry
          </button>
        </div>
      )}
      <div className="flex-1 h-1.5 bg-muted rounded-full overflow-hidden">
        <div className={cn("h-full rounded-full", color)} style={{ width: `${score}%` }} />
      </div>
      <span className="text-[10px] w-8 text-right text-muted-foreground">{score}</span>
    </div>
  );
}

function fmt$(n: number) {
  if (n >= 1_000_000) return `$${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `$${(n / 1_000).toFixed(0)}K`;
  return `$${n}`;
}

// == Component =================================================================

export default function TprmExchangeDashboard() {
  const [vendorFilter, setVendorFilter] = useState<string>("all");
  const [completedAssessments, setCompletedAssessments] = useState<Set<string>>(
    new Set(MOCK_ASSESSMENTS.filter(a => a.status === "completed").map(a => a.id));

  useEffect(() => {
    apiFetch(`/api/v1/tprm-exchange/vendors?org_id=${ORG_ID}`).catch(() => { setError('Failed to load data'); })
      .finally(() => setLoading(false));
  }, []);
  const [showForm, setShowForm] = useState(false);
  const [refreshing, setRefreshing] = useState(false);
  const [form, setForm] = useState({ vendor_name: "", category: "cloud-provider", criticality: "high", contract_value: "" });
  const [loading, setLoading] = useState(true);

  const handleComplete = async (assessId: string) => {
    try { await apiFetch(`/api/v1/tprm-exchange/assessments/${assessId}/complete?org_id=${ORG_ID}`, { method: "POST" }); } catch (_) {}
    setCompletedAssessments(s => new Set([...s, assessId]));
  };

  const filteredAssessments = vendorFilter === "all"
    ? MOCK_ASSESSMENTS
    : MOCK_ASSESSMENTS.filter(a => a.vendor_id === vendorFilter);

  const filteredIncidents = vendorFilter === "all"
    ? MOCK_INCIDENTS
    : MOCK_INCIDENTS.filter(i => i.vendor_id === vendorFilter);

  const vendorName = (vid: string) => MOCK_VENDORS.find(v => v.id === vid)?.vendor_name ?? vid;

  if (loading) return (
    <div className="space-y-4 p-6">
      {[1, 2, 3].map((i) => (
        <div key={i} className="h-24 rounded-lg bg-zinc-800/50 animate-pulse" />
      ))}
    </div>
  );

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="TPRM Exchange"
        description="Third-Party Risk Management = vendor profiles, assessments, and incident tracking"
        actions={
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={() => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); }} disabled={refreshing}>
              <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
            </Button>
            <Button size="sm" onClick={() => setShowForm(v => !v)}>
              <Plus className="h-4 w-4 mr-1" /> Add Vendor
            </Button>
          </div>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Vendors"       value={MOCK_VENDORS.length} icon={Building2}     trend="up" />
        <KpiCard title="Tier-1 Vendors"      value={TIER1_COUNT}         icon={ShieldAlert}   trend="flat" className="border-red-500/20" />
        <KpiCard title="Active Assessments"  value={ACTIVE_ASSESS}       icon={ClipboardCheck} trend="flat" className="border-blue-500/20" />
        <KpiCard title="High Risk Vendors"   value={HIGH_RISK}           icon={AlertTriangle}  trend="down" className={HIGH_RISK > 0 ? "border-red-500/20" : "border-green-500/20"} />
      </div>

      {/* Add Vendor Form */}
      {showForm && (
        <Card className="border-blue-500/20">
          <CardHeader className="pb-3"><CardTitle className="text-sm font-semibold">Register New Vendor</CardTitle></CardHeader>
          <CardContent>
            <form className="grid grid-cols-2 gap-3 md:grid-cols-4" onSubmit={async e => {
              e.preventDefault();
              try { await apiFetch(`/api/v1/tprm-exchange/vendors?org_id=${ORG_ID}`, { method: "POST", body: JSON.stringify({ ...form, org_id: ORG_ID }) }); } catch (_) {}
              setShowForm(false);
            }}>
              <div className="flex flex-col gap-1 col-span-2">
                <label className="text-[10px] text-muted-foreground">Vendor Name</label>
                <input className="h-8 rounded-md border border-border bg-background px-3 text-xs" value={form.vendor_name} onChange={e => setForm(f => ({ ...f, vendor_name: e.target.value }))} required />
              </div>
              <div className="flex flex-col gap-1">
                <label className="text-[10px] text-muted-foreground">Contract Value ($)</label>
                <input className="h-8 rounded-md border border-border bg-background px-3 text-xs" value={form.contract_value} onChange={e => setForm(f => ({ ...f, contract_value: e.target.value }))} required />
              </div>
              {[["category","Category",["cloud-provider","data-processor","payment","logistics","facilities","hr-services","security"]],["criticality","Criticality",["critical","high","medium","low"]]].map(([k, l, opts]) => (
                <div key={k as string} className="flex flex-col gap-1">
                  <label className="text-[10px] text-muted-foreground">{l as string}</label>
                  <select className="h-8 rounded-md border border-border bg-background px-3 text-xs" value={(form as any)[k as string]} onChange={e => setForm(f => ({ ...f, [k as string]: e.target.value }))}>
                    {(opts as string[]).map(o => <option key={o} value={o}>{o}</option>)}
                  </select>
                </div>
              ))}
              <div className="col-span-2 md:col-span-4 flex gap-2 justify-end">
                <Button variant="outline" size="sm" type="button" onClick={() => setShowForm(false)}>Cancel</Button>
                <Button size="sm" type="submit">Register Vendor</Button>
              </div>
            </form>
          </CardContent>
        </Card>
      )}

      {/* Vendor Profiles */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Building2 className="h-4 w-4 text-blue-400" /> Vendor Profiles
            </CardTitle>
            <Badge className="text-[10px] border border-border text-muted-foreground">{MOCK_VENDORS.length} vendors</Badge>
          </div>
          <CardDescription className="text-xs">Click a vendor to filter assessments and incidents</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Vendor</TableHead>
                  <TableHead className="text-[11px] h-8">Category</TableHead>
                  <TableHead className="text-[11px] h-8">Criticality</TableHead>
                  <TableHead className="text-[11px] h-8">Risk Tier</TableHead>
                  <TableHead className="text-[11px] h-8 min-w-[120px]">Compliance Score</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Contract Value</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {MOCK_VENDORS.map(v => (
                  <TableRow
                    key={v.id}
                    className={cn("hover:bg-muted/30 cursor-pointer", vendorFilter === v.id && "bg-muted/20")}
                    onClick={() => setVendorFilter(f => f === v.id ? "all" : v.id)}
                  >
                    <TableCell className="py-2 text-[11px] font-medium">{v.vendor_name}</TableCell>
                    <TableCell className="py-2"><CatBadge cat={v.category} /></TableCell>
                    <TableCell className="py-2"><CriticalityBadge c={v.criticality} /></TableCell>
                    <TableCell className="py-2"><TierBadge tier={v.risk_tier} /></TableCell>
                    <TableCell className="py-2 min-w-[120px]"><ScoreBar score={v.compliance_score} /></TableCell>
                    <TableCell className="py-2 text-right text-[11px]">{fmt$(v.contract_value)}</TableCell>
                    <TableCell className="py-2">
                      <Badge className={cn("text-[10px] border capitalize", v.status === "active" ? "border-green-500/30 text-green-400 bg-green-500/10" : "border-yellow-500/30 text-yellow-400 bg-yellow-500/10")}>
                        {v.status.replace(/-/g, " ")}
                      </Badge>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Assessments */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <ClipboardCheck className="h-4 w-4 text-purple-400" /> Assessments
              {vendorFilter !== "all" && <Badge className="text-[10px] border border-blue-500/30 text-blue-400 bg-blue-500/10">{vendorName(vendorFilter)}</Badge>}
            </CardTitle>
            <Badge className="text-[10px] border border-border text-muted-foreground">{filteredAssessments.length} assessments</Badge>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Vendor</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8 min-w-[120px]">Score</TableHead>
                  <TableHead className="text-[11px] h-8">Risk Level</TableHead>
                  <TableHead className="text-[11px] h-8">Assessor</TableHead>
                  <TableHead className="text-[11px] h-8">End Date</TableHead>
                  <TableHead className="text-[11px] h-8"></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredAssessments.map(a => {
                  const done = completedAssessments.has(a.id);
                  return (
                    <TableRow key={a.id} className="hover:bg-muted/30">
                      <TableCell className="py-2 text-[11px] font-medium">{vendorName(a.vendor_id)}</TableCell>
                      <TableCell className="py-2"><AssessTypeBadge t={a.assessment_type} /></TableCell>
                      <TableCell className="py-2"><AssessStatusBadge s={done ? "completed" : a.status} /></TableCell>
                      <TableCell className="py-2 min-w-[120px]"><ScoreBar score={a.overall_score} /></TableCell>
                      <TableCell className="py-2"><CriticalityBadge c={a.risk_level} /></TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground">{a.assessor}</TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground">{a.end_date}</TableCell>
                      <TableCell className="py-2">
                        {!done && (
                          <Button size="sm" className="h-6 text-[10px] px-2" onClick={() => handleComplete(a.id)}>
                            <CheckCircle2 className="h-3 w-3 mr-1" /> Complete
                          </Button>
                        )}
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Incidents */}
      <Card className="border-red-500/10">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
              <AlertTriangle className="h-4 w-4" /> Vendor Incidents
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
              {filteredIncidents.filter(i => i.status !== "resolved").length} open
            </Badge>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Vendor</TableHead>
                  <TableHead className="text-[11px] h-8">Incident Type</TableHead>
                  <TableHead className="text-[11px] h-8">Severity</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8">Reported</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filteredIncidents.map(i => (
                  <TableRow key={i.id} className="hover:bg-muted/30">
                    <TableCell className="py-2 text-[11px] font-medium">{vendorName(i.vendor_id)}</TableCell>
                    <TableCell className="py-2">
                      <Badge className="text-[10px] border border-orange-500/30 text-orange-400 bg-orange-500/10 capitalize">{i.incident_type.replace(/-/g, " ")}</Badge>
                    </TableCell>
                    <TableCell className="py-2"><SeverityBadge s={i.severity} /></TableCell>
                    <TableCell className="py-2"><IncidentStatusBadge s={i.status} /></TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{i.reported_date}</TableCell>
                  </TableRow>
                ))}
                {filteredIncidents.length === 0 && (
                  <TableRow><TableCell colSpan={5} className="text-center text-xs text-muted-foreground py-6">No incidents for selected vendor.</TableCell></TableRow>
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
