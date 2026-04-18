/**
 * Service Catalog Dashboard
 *
 * Security service catalog with request tracking, SLA performance, and outage management.
 * Route: /service-catalog
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  BookOpen, CheckCircle2, XCircle, Clock, AlertTriangle,
  TrendingUp, Activity, Users, PlusCircle, Zap,
} from "lucide-react";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY = (typeof window !== "undefined" && window.localStorage.getItem("aldeci_api_key")) || import.meta.env.VITE_API_KEY || "demo-key";
const ORG_ID = "aldeci-demo";
async function apiFetch(path: string) {
  const r = await fetch(`${API_BASE}${path}`, { headers: { "X-API-Key": API_KEY, "Content-Type": "application/json" } });
  if (!r.ok) throw new Error(`${r.status}`);
  return r.json();
}
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── Mock Data ──────────────────────────────────────────────────

const MOCK_SERVICES = [
  { id: "svc-001", service_name: "Vulnerability Scanning", category: "assessment", owner_team: "SecOps", sla_response_hours: 4, sla_resolution_hours: 48, request_count: 284, availability_pct: 99.8, status: "active" },
  { id: "svc-002", service_name: "Penetration Testing", category: "offensive-security", owner_team: "Red Team", sla_response_hours: 24, sla_resolution_hours: 336, request_count: 47, availability_pct: 98.2, status: "active" },
  { id: "svc-003", service_name: "Security Awareness Training", category: "training", owner_team: "GRC", sla_response_hours: 8, sla_resolution_hours: 72, request_count: 621, availability_pct: 99.9, status: "active" },
  { id: "svc-004", service_name: "Firewall Rule Change", category: "network-security", owner_team: "NetSec", sla_response_hours: 2, sla_resolution_hours: 24, request_count: 193, availability_pct: 99.5, status: "active" },
  { id: "svc-005", service_name: "DLP Policy Exception", category: "data-security", owner_team: "Data Sec", sla_response_hours: 4, sla_resolution_hours: 48, request_count: 88, availability_pct: 97.4, status: "active" },
  { id: "svc-006", service_name: "Certificate Provisioning", category: "pki", owner_team: "Crypto Ops", sla_response_hours: 1, sla_resolution_hours: 8, request_count: 342, availability_pct: 99.7, status: "active" },
  { id: "svc-007", service_name: "Legacy SIEM (v1)", category: "monitoring", owner_team: "SOC", sla_response_hours: 4, sla_resolution_hours: 24, request_count: 12, availability_pct: 91.2, status: "deprecated" },
  { id: "svc-008", service_name: "Cloud Access Review", category: "iam", owner_team: "IAM Team", sla_response_hours: 8, sla_resolution_hours: 120, request_count: 156, availability_pct: 99.1, status: "active" },
];

const MOCK_REQUESTS = [
  { id: "req-001", service_name: "Vulnerability Scanning", requester: "m.jones", dept: "Engineering", priority: "critical", status: "in_progress", response_hrs: 1.2, resolution_hrs: null, sla_met: null, created_at: "2026-04-16T09:00:00Z" },
  { id: "req-002", service_name: "Firewall Rule Change", requester: "r.patel", dept: "Operations", priority: "high", status: "resolved", response_hrs: 0.8, resolution_hrs: 18, sla_met: true, created_at: "2026-04-15T14:00:00Z" },
  { id: "req-003", service_name: "Penetration Testing", requester: "ciso@company.com", dept: "Executive", priority: "medium", status: "submitted", response_hrs: null, resolution_hrs: null, sla_met: null, created_at: "2026-04-16T10:30:00Z" },
  { id: "req-004", service_name: "Certificate Provisioning", requester: "devops-bot", dept: "DevOps", priority: "high", status: "resolved", response_hrs: 0.3, resolution_hrs: 2.1, sla_met: true, created_at: "2026-04-16T08:00:00Z" },
  { id: "req-005", service_name: "DLP Policy Exception", requester: "b.chen", dept: "Finance", priority: "critical", status: "resolved", response_hrs: 5.2, resolution_hrs: 52, sla_met: false, created_at: "2026-04-14T10:00:00Z" },
  { id: "req-006", service_name: "Security Awareness Training", requester: "hr-system", dept: "HR", priority: "low", status: "in_progress", response_hrs: 2.0, resolution_hrs: null, sla_met: null, created_at: "2026-04-15T09:00:00Z" },
  { id: "req-007", service_name: "Cloud Access Review", requester: "a.kumar", dept: "Cloud Ops", priority: "medium", status: "submitted", response_hrs: null, resolution_hrs: null, sla_met: null, created_at: "2026-04-16T10:45:00Z" },
  { id: "req-008", service_name: "Firewall Rule Change", requester: "n.wilson", dept: "Network", priority: "high", status: "resolved", response_hrs: 1.5, resolution_hrs: 22, sla_met: true, created_at: "2026-04-13T16:00:00Z" },
];

const MOCK_OUTAGES = [
  { id: "out-001", service_name: "Legacy SIEM (v1)", outage_type: "unplanned", severity: "major", duration_mins: 187, affected_users: 43, started_at: "2026-04-14T03:22:00Z" },
  { id: "out-002", service_name: "Certificate Provisioning", outage_type: "planned", severity: "minor", duration_mins: 45, affected_users: 0, started_at: "2026-04-13T02:00:00Z" },
  { id: "out-003", service_name: "DLP Policy Exception", outage_type: "unplanned", severity: "moderate", duration_mins: 62, affected_users: 15, started_at: "2026-04-12T11:30:00Z" },
];

// ── Helpers ────────────────────────────────────────────────────

const CATEGORY_COLORS: Record<string, string> = {
  assessment:        "bg-blue-500/15 text-blue-400 border-blue-500/30",
  "offensive-security":"bg-red-500/15 text-red-400 border-red-500/30",
  training:          "bg-green-500/15 text-green-400 border-green-500/30",
  "network-security":"bg-cyan-500/15 text-cyan-400 border-cyan-500/30",
  "data-security":   "bg-purple-500/15 text-purple-400 border-purple-500/30",
  pki:               "bg-teal-500/15 text-teal-400 border-teal-500/30",
  monitoring:        "bg-indigo-500/15 text-indigo-400 border-indigo-500/30",
  iam:               "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
};

const PRIORITY_COLORS: Record<string, string> = {
  critical: "bg-red-500/15 text-red-400 border-red-500/30",
  high:     "bg-orange-500/15 text-orange-400 border-orange-500/30",
  medium:   "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  low:      "bg-zinc-500/15 text-zinc-400 border-zinc-500/30",
};

const REQUEST_STATUS_COLORS: Record<string, string> = {
  submitted:   "bg-blue-500/15 text-blue-400 border-blue-500/30",
  in_progress: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  resolved:    "bg-green-500/15 text-green-400 border-green-500/30",
  cancelled:   "bg-zinc-500/15 text-zinc-400 border-zinc-500/30",
};

const OUTAGE_TYPE_COLORS: Record<string, string> = {
  planned:   "bg-blue-500/15 text-blue-400 border-blue-500/30",
  unplanned: "bg-red-500/15 text-red-400 border-red-500/30",
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-500/15 text-red-400 border-red-500/30",
  major:    "bg-orange-500/15 text-orange-400 border-orange-500/30",
  moderate: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  minor:    "bg-zinc-500/15 text-zinc-400 border-zinc-500/30",
};

const DEPT_COLORS: Record<string, string> = {
  Engineering: "bg-blue-500/15 text-blue-400 border-blue-500/30",
  Operations:  "bg-teal-500/15 text-teal-400 border-teal-500/30",
  Executive:   "bg-purple-500/15 text-purple-400 border-purple-500/30",
  DevOps:      "bg-cyan-500/15 text-cyan-400 border-cyan-500/30",
  Finance:     "bg-green-500/15 text-green-400 border-green-500/30",
  HR:          "bg-pink-500/15 text-pink-400 border-pink-500/30",
  "Cloud Ops": "bg-sky-500/15 text-sky-400 border-sky-500/30",
  Network:     "bg-indigo-500/15 text-indigo-400 border-indigo-500/30",
};

function AvailabilityGauge({ pct }: { pct: number }) {
  const color = pct >= 99.5 ? "text-green-400" : pct >= 98 ? "text-yellow-400" : "text-red-400";
  const strokeColor = pct >= 99.5 ? "#22c55e" : pct >= 98 ? "#eab308" : "#ef4444";
  const r = 12; const circ = 2 * Math.PI * r;
  const offset = circ - (pct / 100) * circ;
  return (
    <div className="flex items-center gap-1.5">
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
      <svg width="30" height="30" viewBox="0 0 30 30">
        <circle cx="15" cy="15" r={r} fill="none" stroke="#374151" strokeWidth="3" />
        <circle cx="15" cy="15" r={r} fill="none" stroke={strokeColor} strokeWidth="3"
          strokeDasharray={circ} strokeDashoffset={offset} strokeLinecap="round"
          transform="rotate(-90 15 15)" />
      </svg>
      <span className={cn("text-[10px] font-mono", color)}>{pct}%</span>
    </div>
  );
}

// ── Main Component ─────────────────────────────────────────────

export default function ServiceCatalogDashboard() {
  const [showRequestForm, setShowRequestForm] = useState(false);
  const [requestForm, setRequestForm] = useState({ service: "", requester: "", dept: "Engineering", priority: "medium", notes: "" });
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    apiFetch(`/api/v1/service-catalog/services?org_id=${ORG_ID}`).catch(() => { setError('Failed to load data'); })
      .finally(() => setLoading(false));
  }, []);

  const activeServices = MOCK_SERVICES.filter(s => s.status === "active").length;
  const totalRequests = MOCK_REQUESTS.length;
  const openRequests = MOCK_REQUESTS.filter(r => r.status !== "resolved").length;
  const slaCompliance = Math.round(
    (MOCK_REQUESTS.filter(r => r.sla_met === true).length / MOCK_REQUESTS.filter(r => r.sla_met !== null).length) * 100
  );

  // SLA performance table data
  const slaStats = MOCK_SERVICES.map(svc => {
    const reqs = MOCK_REQUESTS.filter(r => r.service_name === svc.service_name);
    const met = reqs.filter(r => r.sla_met === true).length;
    const total = reqs.filter(r => r.sla_met !== null).length;
    return { ...svc, req_count: reqs.length, sla_met: met, total_measured: total, compliance: total ? Math.round((met / total) * 100) : null };
  });

  if (loading) return (
    <div className="space-y-4 p-6">
      {[1, 2, 3].map((i) => (
        <div key={i} className="h-24 rounded-lg bg-zinc-800/50 animate-pulse" />
      ))}
    </div>
  );

  return (
    <div className="min-h-screen bg-[#0f172a] text-white p-6 space-y-6">
      <PageHeader
        title="Service Catalog"
        description="Security service catalog with SLA tracking, request management, and availability monitoring"
      />

      {/* KPI Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Active Services" value={activeServices} icon={<Zap className="h-5 w-5 text-blue-400" />} />
        <KpiCard title="Total Requests" value={totalRequests} icon={<Activity className="h-5 w-5" />} />
        <KpiCard title="Open Requests" value={openRequests} icon={<Clock className="h-5 w-5 text-yellow-400" />} />
        <KpiCard title="SLA Compliance" value={`${slaCompliance}%`} icon={<CheckCircle2 className="h-5 w-5 text-green-400" />} />
      </div>

      {/* Request Form Toggle */}
      <div className="flex justify-end">
        <Button size="sm" variant="outline" className="border-zinc-700 text-zinc-300 text-xs" onClick={() => setShowRequestForm(v => !v)}>
          <PlusCircle className="h-3 w-3 mr-1" /> Submit Request
        </Button>
      </div>

      {showRequestForm && (
        <motion.div initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }}>
          <Card className="bg-gray-800 border-zinc-700">
            <CardHeader className="pb-2"><CardTitle className="text-sm text-zinc-200">New Service Request</CardTitle></CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 lg:grid-cols-3 gap-3 mb-3">
                <div>
                  <label className="text-[10px] text-zinc-500 mb-1 block">Service</label>
                  <select className="w-full bg-zinc-900 border border-zinc-700 rounded px-2 py-1.5 text-xs text-white"
                    value={requestForm.service} onChange={e => setRequestForm(p => ({ ...p, service: e.target.value }))}>
                    <option value="">Select service…</option>
                    {MOCK_SERVICES.filter(s => s.status === "active").map(s => <option key={s.id}>{s.service_name}</option>)}
                  </select>
                </div>
                <div>
                  <label className="text-[10px] text-zinc-500 mb-1 block">Requester</label>
                  <input className="w-full bg-zinc-900 border border-zinc-700 rounded px-2 py-1.5 text-xs text-white placeholder-zinc-600" placeholder="username or email" value={requestForm.requester} onChange={e => setRequestForm(p => ({ ...p, requester: e.target.value }))} />
                </div>
                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <label className="text-[10px] text-zinc-500 mb-1 block">Dept</label>
                    <select className="w-full bg-zinc-900 border border-zinc-700 rounded px-2 py-1.5 text-xs text-white"
                      value={requestForm.dept} onChange={e => setRequestForm(p => ({ ...p, dept: e.target.value }))}>
                      {Object.keys(DEPT_COLORS).map(d => <option key={d}>{d}</option>)}
                    </select>
                  </div>
                  <div>
                    <label className="text-[10px] text-zinc-500 mb-1 block">Priority</label>
                    <select className="w-full bg-zinc-900 border border-zinc-700 rounded px-2 py-1.5 text-xs text-white"
                      value={requestForm.priority} onChange={e => setRequestForm(p => ({ ...p, priority: e.target.value }))}>
                      {["critical","high","medium","low"].map(p => <option key={p}>{p}</option>)}
                    </select>
                  </div>
                </div>
              </div>
              <textarea className="w-full bg-zinc-900 border border-zinc-700 rounded px-2 py-1.5 text-xs text-white placeholder-zinc-600 resize-none" rows={2} placeholder="Notes / business justification…" value={requestForm.notes} onChange={e => setRequestForm(p => ({ ...p, notes: e.target.value }))} />
              <Button size="sm" className="mt-3 bg-blue-600 hover:bg-blue-700 text-xs" onClick={() => setShowRequestForm(false)}>Submit Request</Button>
            </CardContent>
          </Card>
        </motion.div>
      )}

      {/* Service List */}
      <Card className="bg-gray-800 border-zinc-700">
        <CardHeader className="pb-2"><CardTitle className="text-sm text-zinc-200">Services</CardTitle></CardHeader>
        <CardContent>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-zinc-700">
                  {["Service", "Category", "Owner", "SLA Response", "SLA Resolution", "Requests", "Availability", "Status"].map(h => (
                    <th key={h} className="text-left py-2 px-2 text-zinc-500 font-medium whitespace-nowrap">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {MOCK_SERVICES.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  MOCK_SERVICES.map(s => (
                  <tr key={s.id} className="border-b border-zinc-700/50 hover:bg-zinc-700/20">
                    <td className="py-2 px-2 text-zinc-200 font-medium">{s.service_name}</td>
                    <td className="py-2 px-2"><Badge className={cn("text-[9px] border whitespace-nowrap", CATEGORY_COLORS[s.category] ?? "border-zinc-600 text-zinc-400")}>{s.category.replace("-"," ")}</Badge></td>
                    <td className="py-2 px-2 text-zinc-400">{s.owner_team}</td>
                    <td className="py-2 px-2 text-zinc-400 font-mono">{s.sla_response_hours}h</td>
                    <td className="py-2 px-2 text-zinc-400 font-mono">{s.sla_resolution_hours}h</td>
                    <td className="py-2 px-2 text-zinc-300 font-mono">{s.request_count}</td>
                    <td className="py-2 px-2"><AvailabilityGauge pct={s.availability_pct} /></td>
                    <td className="py-2 px-2">
                      <Badge className={cn("text-[9px] border capitalize", s.status === "active" ? "border-green-500/30 text-green-400 bg-green-500/10" : "border-red-500/30 text-red-400 bg-red-500/10")}>{s.status}</Badge>
                    </td>
                  </tr>
                )))}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Service Requests */}
        <Card className="bg-gray-800 border-zinc-700">
          <CardHeader className="pb-2"><CardTitle className="text-sm text-zinc-200">Service Requests</CardTitle></CardHeader>
          <CardContent>
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-zinc-700">
                    {["Requester", "Dept", "Service", "Priority", "Status", "Response", "Resolution", "SLA"].map(h => (
                      <th key={h} className="text-left py-2 px-1 text-zinc-500 font-medium whitespace-nowrap">{h}</th>
                    ))
                  )}
                  </tr>
                </thead>
                <tbody>
                  {MOCK_REQUESTS.length === 0 ? (
                    <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                      <p className="text-lg font-medium">No data available</p>
                      <p className="text-sm">Data will appear here once available</p>
                    </div>
                  ) : (
                    MOCK_REQUESTS.map(r => (
                    <tr key={r.id} className="border-b border-zinc-700/50 hover:bg-zinc-700/20">
                      <td className="py-2 px-1 text-zinc-300">{r.requester}</td>
                      <td className="py-2 px-1"><Badge className={cn("text-[9px] border", DEPT_COLORS[r.dept] ?? "border-zinc-600 text-zinc-400")}>{r.dept}</Badge></td>
                      <td className="py-2 px-1 text-zinc-400 max-w-[120px] truncate">{r.service_name}</td>
                      <td className="py-2 px-1"><Badge className={cn("text-[9px] border capitalize", PRIORITY_COLORS[r.priority])}>{r.priority}</Badge></td>
                      <td className="py-2 px-1"><Badge className={cn("text-[9px] border capitalize", REQUEST_STATUS_COLORS[r.status])}>{r.status.replace("_"," ")}</Badge></td>
                      <td className="py-2 px-1 text-zinc-400 font-mono">{r.response_hrs ? `${r.response_hrs}h` : "—"}</td>
                      <td className="py-2 px-1 text-zinc-400 font-mono">{r.resolution_hrs ? `${r.resolution_hrs}h` : "—"}</td>
                      <td className="py-2 px-1">
                        {r.sla_met === true && <Badge className="text-[9px] border border-green-500/30 text-green-400 bg-green-500/10">Met</Badge>}
                        {r.sla_met === false && <Badge className="text-[9px] border border-red-500/30 text-red-400 bg-red-500/10">Missed</Badge>}
                        {r.sla_met === null && <span className="text-zinc-600">—</span>}
                      </td>
                    </tr>
                  )))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>

        {/* SLA Performance + Outages */}
        <div className="space-y-4">
          <Card className="bg-gray-800 border-zinc-700">
            <CardHeader className="pb-2"><CardTitle className="text-sm text-zinc-200">SLA Performance</CardTitle></CardHeader>
            <CardContent className="space-y-3">
              {slaStats.filter(s => s.req_count > 0).map(s => (
                <div key={s.id}>
                  <div className="flex justify-between text-[10px] mb-1">
                    <span className="text-zinc-300 truncate max-w-[180px]">{s.service_name}</span>
                    <span className="text-zinc-400 ml-2">{s.total_measured > 0 ? `${s.compliance}%` : "N/A"} ({s.req_count} reqs)</span>
                  </div>
                  {s.total_measured > 0 && (
                    <div className="h-1.5 bg-zinc-700 rounded-full overflow-hidden">
                      <div className={cn("h-full rounded-full", (s.compliance ?? 0) >= 90 ? "bg-green-500" : (s.compliance ?? 0) >= 70 ? "bg-yellow-500" : "bg-red-500")}
                        style={{ width: `${s.compliance ?? 0}%` }} />
                    </div>
                  )}
                </div>
              ))}
            </CardContent>
          </Card>

          <Card className="bg-gray-800 border-zinc-700">
            <CardHeader className="pb-2"><CardTitle className="text-sm text-zinc-200 flex items-center gap-2"><AlertTriangle className="h-4 w-4 text-orange-400" />Outages</CardTitle></CardHeader>
            <CardContent className="space-y-3">
              {MOCK_OUTAGES.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                  <p className="text-lg font-medium">No data available</p>
                  <p className="text-sm">Data will appear here once available</p>
                </div>
              ) : (
                MOCK_OUTAGES.map(o => (
                <div key={o.id} className="bg-zinc-900 rounded-lg p-3 border border-zinc-700 space-y-2">
                  <div className="flex items-start justify-between gap-2">
                    <p className="text-xs text-zinc-200">{o.service_name}</p>
                    <div className="flex gap-1 shrink-0">
                      <Badge className={cn("text-[9px] border capitalize", OUTAGE_TYPE_COLORS[o.outage_type])}>{o.outage_type}</Badge>
                      <Badge className={cn("text-[9px] border capitalize", SEVERITY_COLORS[o.severity])}>{o.severity}</Badge>
                    </div>
                  </div>
                  <div className="flex items-center gap-4 text-[10px] text-zinc-500">
                    <span>{o.duration_mins} min</span>
                    <span>{o.affected_users} users affected</span>
                    <span className="ml-auto">{o.started_at.slice(0, 10)}</span>
                  </div>
                </div>
              )))}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
