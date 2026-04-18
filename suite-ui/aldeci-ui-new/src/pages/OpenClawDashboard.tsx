/**
 * OpenClaw Autonomous Pentest Dashboard
 *
 * Displays autonomous red team campaigns managed by the OpenClaw engine.
 *   1. KPIs: Active Campaigns, Total Findings, Critical Findings, Avg Risk Score
 *   2. Campaign table (10 rows) with status badges and risk scores
 *   3. Campaign details panel = tasks + findings for selected campaign
 *   4. Authorization status bar
 *   5. New campaign creation form
 *
 * API: GET /api/v1/openclaw/campaigns, /api/v1/openclaw/stats,
 *      /api/v1/openclaw/campaigns/{id}/tasks, /api/v1/openclaw/findings
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Shield, AlertTriangle, Target, Activity, RefreshCw,
  Play, Pause, CheckCircle, Lock, Plus, ChevronRight, X,
} from "lucide-react";

// == API helpers ================================================
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

// == Mock data ==================================================

const MOCK_CAMPAIGNS = [
  { id: "OC-001", name: "Q2 Network Pentest",         campaign_type: "network_pentest",    phase: "lateral_movement",  status: "active",    operators_count: 3, findings_count: 12, risk_score: 82, authorized_by: "CISO",  started_at: "2026-04-15 09:00", authorization_token: "AUTH-7F2A" },
  { id: "OC-002", name: "Web App Security Assessment", campaign_type: "web_app",            phase: "exploitation",      status: "active",    operators_count: 2, findings_count: 8,  risk_score: 74, authorized_by: "CTO",   started_at: "2026-04-15 14:30", authorization_token: "AUTH-3D9B" },
  { id: "OC-003", name: "Cloud Infrastructure Audit",  campaign_type: "cloud_security",     phase: "reconnaissance",    status: "paused",    operators_count: 4, findings_count: 5,  risk_score: 61, authorized_by: "CISO",  started_at: "2026-04-14 10:00", authorization_token: "AUTH-1E5C" },
  { id: "OC-004", name: "Social Engineering Test",     campaign_type: "social_engineering", phase: "delivery",          status: "completed", operators_count: 2, findings_count: 19, risk_score: 91, authorized_by: "Board", started_at: "2026-04-12 08:00", authorization_token: "AUTH-9A4F" },
  { id: "OC-005", name: "Full Red Team Exercise",      campaign_type: "full_red_team",      phase: "command_control",   status: "active",    operators_count: 5, findings_count: 31, risk_score: 95, authorized_by: "CISO",  started_at: "2026-04-13 07:00", authorization_token: "AUTH-2B8D" },
  { id: "OC-006", name: "Physical Access Test",        campaign_type: "physical_access",    phase: "initial_access",    status: "planned",   operators_count: 2, findings_count: 0,  risk_score: 0,  authorized_by: "Exec",  started_at: "2026-04-17 09:00", authorization_token: "AUTH-6G3H" },
  { id: "OC-007", name: "Mobile App Pentest",          campaign_type: "web_app",            phase: "post_exploitation", status: "completed", operators_count: 2, findings_count: 14, risk_score: 78, authorized_by: "CTO",   started_at: "2026-04-10 11:00", authorization_token: "AUTH-4K7L" },
  { id: "OC-008", name: "API Security Review",         campaign_type: "web_app",            phase: "exploitation",      status: "active",    operators_count: 3, findings_count: 9,  risk_score: 69, authorized_by: "CISO",  started_at: "2026-04-15 16:00", authorization_token: "AUTH-5M2N" },
  { id: "OC-009", name: "Supply Chain Attack Sim",     campaign_type: "full_red_team",      phase: "reconnaissance",    status: "planned",   operators_count: 3, findings_count: 0,  risk_score: 0,  authorized_by: "Board", started_at: "2026-04-18 09:00", authorization_token: "AUTH-8P1Q" },
  { id: "OC-010", name: "Insider Threat Exercise",     campaign_type: "social_engineering", phase: "data_exfiltration", status: "completed", operators_count: 2, findings_count: 22, risk_score: 88, authorized_by: "CISO",  started_at: "2026-04-08 08:00", authorization_token: "AUTH-0R6S" },
];

const MOCK_STATS = { active_campaigns: 4, total_findings: 120, critical_findings: 18, avg_risk_score: 73 };

const MOCK_TASKS: Record<string, any[]> = {
  "OC-001": [
    { id: "T-001", name: "Network enumeration scan",      phase: "reconnaissance",   status: "completed", assigned_operator: "Op-Alpha", mitre_technique: "T1046" },
    { id: "T-002", name: "SMB relay attack",              phase: "lateral_movement", status: "in_progress", assigned_operator: "Op-Beta",  mitre_technique: "T1557.001" },
    { id: "T-003", name: "Kerberoasting attempt",         phase: "lateral_movement", status: "pending",   assigned_operator: "Op-Gamma", mitre_technique: "T1558.003" },
  ],
  "OC-002": [
    { id: "T-004", name: "SQL injection scanning",        phase: "exploitation",     status: "completed", assigned_operator: "Op-Alpha", mitre_technique: "T1190" },
    { id: "T-005", name: "XSS payload delivery",          phase: "exploitation",     status: "in_progress", assigned_operator: "Op-Beta",  mitre_technique: "T1059.007" },
  ],
  "OC-005": [
    { id: "T-006", name: "Phishing campaign launch",      phase: "delivery",         status: "completed", assigned_operator: "Op-Alpha", mitre_technique: "T1566.001" },
    { id: "T-007", name: "C2 beacon establishment",       phase: "command_control",  status: "in_progress", assigned_operator: "Op-Delta",  mitre_technique: "T1071.001" },
    { id: "T-008", name: "Privilege escalation via CVE",  phase: "exploitation",     status: "completed", assigned_operator: "Op-Gamma", mitre_technique: "T1068" },
    { id: "T-009", name: "Domain controller compromise",  phase: "lateral_movement", status: "pending",   assigned_operator: "Op-Epsilon", mitre_technique: "T1003.001" },
  ],
};

const MOCK_FINDINGS: Record<string, any[]> = {
  "OC-001": [
    { id: "F-001", title: "Unpatched SMBv1 on 14 hosts",      severity: "critical", status: "open",      mitre: "T1210",     cvss: 9.8 },
    { id: "F-002", title: "Weak Kerberos delegation policy",  severity: "high",     status: "open",      mitre: "T1558",     cvss: 7.5 },
    { id: "F-003", title: "NTLMv1 allowed on domain",         severity: "high",     status: "accepted",  mitre: "T1557",     cvss: 7.1 },
  ],
  "OC-005": [
    { id: "F-004", title: "Domain admin via phishing",         severity: "critical", status: "open",      mitre: "T1566",     cvss: 10.0 },
    { id: "F-005", title: "C2 exfil via DNS tunneling",        severity: "critical", status: "open",      mitre: "T1071.004", cvss: 9.1 },
    { id: "F-006", title: "No EDR on 8 servers",               severity: "high",     status: "open",      mitre: "T1562",     cvss: 8.2 },
  ],
};

// == Badge helpers ==============================================

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    active:    "border-green-500/30 text-green-400 bg-green-500/10",
    paused:    "border-amber-500/30 text-amber-400 bg-amber-500/10",
    completed: "border-blue-500/30 text-blue-400 bg-blue-500/10",
    planned:   "border-slate-500/30 text-slate-400 bg-slate-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border")}>
      {status}
    </Badge>
  );
}

function TypeBadge({ type }: { type: string }) {
  const label = type.replace(/_/g, " ");
  const map: Record<string, string> = {
    network_pentest:    "border-purple-500/30 text-purple-400 bg-purple-500/10",
    web_app:            "border-blue-500/30 text-blue-400 bg-blue-500/10",
    cloud_security:     "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
    social_engineering: "border-orange-500/30 text-orange-400 bg-orange-500/10",
    physical_access:    "border-red-500/30 text-red-400 bg-red-500/10",
    full_red_team:      "border-rose-500/30 text-rose-400 bg-rose-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[type] ?? "border-border")}>
      {label}
    </Badge>
  );
}

function SevDot({ sev }: { sev: string }) {
  const cls =
    sev === "critical" ? "bg-red-500" :
    sev === "high"     ? "bg-amber-500" :
    sev === "medium"   ? "bg-yellow-400" :
                         "bg-slate-400";
  return <span className={cn("inline-block h-2 w-2 rounded-full shrink-0", cls)} />;
}

function TaskStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    completed:   "border-green-500/30 text-green-400 bg-green-500/10",
    in_progress: "border-amber-500/30 text-amber-400 bg-amber-500/10",
    pending:     "border-slate-500/30 text-slate-400 bg-slate-500/10",
    failed:      "border-red-500/30 text-red-400 bg-red-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border", map[status] ?? "border-border")}>
      {status.replace(/_/g, " ")}
    </Badge>
  );
}

function RiskScore({ score }: { score: number }) {
  const cls =
    score >= 85 ? "text-red-400" :
    score >= 65 ? "text-amber-400" :
    score >= 40 ? "text-yellow-400" :
                  "text-slate-400";
  return (
    <span className={cn("text-xs font-bold tabular-nums", cls)}>
      {score > 0 ? score : "="}
    </span>
  );
}

// == New Campaign Form ==========================================

function NewCampaignForm({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [form, setForm] = useState({
    name: "",
    campaign_type: "network_pentest",
    target_scope: "",
    attack_tactics: "",
    operators_count: 3,
    authorized_by: "",
    authorization_token: "",
  });
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setError("");
    try {
      await apiFetch(`/api/v1/openclaw/campaigns?org_id=${ORG_ID}`, {
        method: "POST",
        body: JSON.stringify({
          name: form.name,
          campaign_type: form.campaign_type,
          target_scope: form.target_scope.split(",").map((s) => s.trim()).filter(Boolean),
          attack_tactics: form.attack_tactics.split(",").map((s) => s.trim()).filter(Boolean),
          operators_count: form.operators_count,
          authorized_by: form.authorized_by,
          authorization_token: form.authorization_token,
        }),
      });
      onCreated();
      onClose();
    } catch {
      setError("Failed to create campaign = check API connection.");
    } finally {
      setSubmitting(false);
    }
  };

  const inp = "w-full rounded-md border border-border bg-muted/30 px-3 py-1.5 text-xs text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary";

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        className="w-full max-w-lg rounded-xl border border-border bg-background p-6 shadow-2xl"
      >
        <div className="flex items-center justify-between mb-4">
          <h2 className="text-sm font-semibold flex items-center gap-2">
            <Plus className="h-4 w-4 text-primary" />
            New Pentest Campaign
          </h2>
          <Button variant="ghost" size="sm" onClick={onClose} className="h-6 w-6 p-0">
            <X className="h-4 w-4" />
          </Button>
        </div>

        <form onSubmit={handleSubmit} className="space-y-3">
          <div>
            <label className="text-[11px] text-muted-foreground mb-1 block">Campaign Name *</label>
            <input className={inp} value={form.name} onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))} placeholder="Q3 Web App Assessment" required />
          </div>

          <div>
            <label className="text-[11px] text-muted-foreground mb-1 block">Campaign Type</label>
            <select className={inp} value={form.campaign_type} onChange={(e) => setForm((f) => ({ ...f, campaign_type: e.target.value }))}>
              <option value="network_pentest">Network Pentest</option>
              <option value="web_app">Web App</option>
              <option value="cloud_security">Cloud Security</option>
              <option value="social_engineering">Social Engineering</option>
              <option value="physical_access">Physical Access</option>
              <option value="full_red_team">Full Red Team</option>
            </select>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-[11px] text-muted-foreground mb-1 block">Target Scope (comma-sep)</label>
              <input className={inp} value={form.target_scope} onChange={(e) => setForm((f) => ({ ...f, target_scope: e.target.value }))} placeholder="10.0.0.0/24, api.example.com" />
            </div>
            <div>
              <label className="text-[11px] text-muted-foreground mb-1 block">Operators</label>
              <input className={inp} type="number" min={1} max={5} value={form.operators_count} onChange={(e) => setForm((f) => ({ ...f, operators_count: parseInt(e.target.value) || 1 }))} />
            </div>
          </div>

          <div>
            <label className="text-[11px] text-muted-foreground mb-1 block">Attack Tactics (comma-sep)</label>
            <input className={inp} value={form.attack_tactics} onChange={(e) => setForm((f) => ({ ...f, attack_tactics: e.target.value }))} placeholder="recon, exploitation, lateral_movement" />
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="text-[11px] text-muted-foreground mb-1 block">Authorized By *</label>
              <input className={inp} value={form.authorized_by} onChange={(e) => setForm((f) => ({ ...f, authorized_by: e.target.value }))} placeholder="CISO / CTO / Board" required />
            </div>
            <div>
              <label className="text-[11px] text-muted-foreground mb-1 block">Authorization Token *</label>
              <input className={inp} value={form.authorization_token} onChange={(e) => setForm((f) => ({ ...f, authorization_token: e.target.value }))} placeholder="AUTH-XXXXXXXX" required />
            </div>
          </div>

          {error && <p className="text-[11px] text-red-400">{error}</p>}

          <div className="flex items-center justify-end gap-2 pt-2">
            <Button type="button" variant="outline" size="sm" onClick={onClose}>Cancel</Button>
            <Button type="submit" size="sm" disabled={submitting}>
              {submitting ? "Creating=" : "Create Campaign"}
            </Button>
          </div>
        </form>
      </motion.div>
    </div>
  );
}

// == Component ==================================================

export default function OpenClawDashboard() {
  const [campaigns, setCampaigns] = useState<any[]>(MOCK_CAMPAIGNS);
  const [stats, setStats] = useState(MOCK_STATS);
  const [selectedCampaign, setSelectedCampaign] = useState<any | null>(null);
  const [tasks, setTasks] = useState<any[]>([]);
  const [findings, setFindings] = useState<any[]>([]);
  const [refreshing, setRefreshing] = useState(false);
  const [showForm, setShowForm] = useState(false);
  const [dataLoading, setDataLoading] = useState(false);
  const [loading, setLoading] = useState(true);

  const loadData = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/openclaw/campaigns?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/openclaw/stats?org_id=${ORG_ID}`),
    ]).then(([campsResult, statsResult]) => {
      if (campsResult.status === "fulfilled" && Array.isArray(campsResult.value)) {
        setCampaigns(campsResult.value);
      }
      if (statsResult.status === "fulfilled") {
        setStats(statsResult.value);
      }
    }).finally(() => setDataLoading(false));
  };

  useEffect(() => { loadData(); }, []);

  const loadCampaignDetail = (campaign: any) => {
    setSelectedCampaign(campaign);
    // Load tasks + findings from mock or API
    const mockTasks = MOCK_TASKS[campaign.id] || [];
    const mockFinds = MOCK_FINDINGS[campaign.id] || [];
    setTasks(mockTasks);
    setFindings(mockFinds);

    Promise.allSettled([
      apiFetch(`/api/v1/openclaw/campaigns/${campaign.id}/tasks?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/openclaw/findings?org_id=${ORG_ID}&campaign_id=${campaign.id}`),
    ]).then(([tasksRes, findingsRes]) => {
      if (tasksRes.status === "fulfilled" && Array.isArray(tasksRes.value) && tasksRes.value.length > 0) setTasks(tasksRes.value);
      if (findingsRes.status === "fulfilled" && Array.isArray(findingsRes.value) && findingsRes.value.length > 0) setFindings(findingsRes.value);
    });
  };

  const handleRefresh = () => {
    setRefreshing(true);
    loadData();
    setTimeout(() => setRefreshing(false), 800);
  };

  const authorizedCount = campaigns.filter((c) => c.authorization_token).length;

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
      {showForm && (
        <NewCampaignForm onClose={() => setShowForm(false)} onCreated={loadData} />
      )}

      {/* Header */}
      <PageHeader
        title="OpenClaw Autonomous Pentest"
        description="AI-driven red team campaigns = autonomous attack simulation across network, web, cloud, and social vectors"
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
              <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
            </Button>
            <Button size="sm" onClick={() => setShowForm(true)}>
              <Plus className="h-4 w-4 mr-1" />
              New Campaign
            </Button>
          </div>
        }
      />

      {/* Authorization status bar */}
      <div className="flex items-center gap-3 rounded-lg border border-green-500/20 bg-green-500/5 px-4 py-2.5">
        <Lock className="h-4 w-4 text-green-400 shrink-0" />
        <span className="text-xs text-green-300 font-medium">
          {authorizedCount} of {campaigns.length} campaigns carry valid authorization tokens = all pentest activity is pre-approved
        </span>
        <Badge className="ml-auto text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">
          Authorized
        </Badge>
      </div>

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Active Campaigns"  value={stats.active_campaigns}  icon={Target}        trend="up" />
        <KpiCard title="Total Findings"    value={stats.total_findings}    icon={AlertTriangle} trend="up" className="border-amber-500/20" />
        <KpiCard title="Critical Findings" value={stats.critical_findings} icon={Shield}        trend="up" className="border-red-500/20" />
        <KpiCard title="Avg Risk Score"    value={`${stats.avg_risk_score}/100`} icon={Activity} trend="down" className="border-orange-500/20" />
      </div>

      {/* Campaign table */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Target className="h-4 w-4 text-purple-400" />
            Pentest Campaigns
          </CardTitle>
          <CardDescription className="text-xs">All autonomous red team operations = click a row to view tasks and findings</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Name</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Phase</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8 text-center">Operators</TableHead>
                  <TableHead className="text-[11px] h-8 text-center">Findings</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Risk Score</TableHead>
                  <TableHead className="text-[11px] h-8">Auth</TableHead>
                  <TableHead className="text-[11px] h-8">Started</TableHead>
                  <TableHead className="text-[11px] h-8 w-8"></TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {campaigns.slice(0, 10).map((c) => (
                  <TableRow
                    key={c.id}
                    className={cn("hover:bg-muted/30 cursor-pointer", selectedCampaign?.id === c.id && "bg-muted/40")}
                    onClick={() => loadCampaignDetail(c)}
                  >
                    <TableCell className="py-2 text-xs font-medium max-w-[180px] truncate">{c.name}</TableCell>
                    <TableCell className="py-2"><TypeBadge type={c.campaign_type} /></TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground capitalize">{c.phase?.replace(/_/g, " ")}</TableCell>
                    <TableCell className="py-2"><StatusBadge status={c.status} /></TableCell>
                    <TableCell className="py-2 text-center text-xs tabular-nums">{c.operators_count}</TableCell>
                    <TableCell className="py-2 text-center text-xs tabular-nums font-medium">
                      <span className={c.findings_count > 10 ? "text-amber-400" : ""}>{c.findings_count}</span>
                    </TableCell>
                    <TableCell className="py-2 text-right"><RiskScore score={c.risk_score} /></TableCell>
                    <TableCell className="py-2">
                      <span className="font-mono text-[10px] text-green-400 bg-green-500/10 px-1.5 py-0.5 rounded">
                        {c.authorization_token}
                      </span>
                    </TableCell>
                    <TableCell className="py-2 text-[11px] tabular-nums text-muted-foreground">{c.started_at}</TableCell>
                    <TableCell className="py-2 text-right">
                      <ChevronRight className="h-3.5 w-3.5 text-muted-foreground" />
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Campaign details panel */}
      {selectedCampaign && (
        <motion.div
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          className="grid grid-cols-1 gap-4 lg:grid-cols-2"
        >
          {/* Tasks */}
          <Card className="border-purple-500/20">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm font-semibold flex items-center gap-2 text-purple-400">
                  <Play className="h-4 w-4" />
                  Tasks = {selectedCampaign.name}
                </CardTitle>
                <Button variant="ghost" size="sm" className="h-6 w-6 p-0" onClick={() => setSelectedCampaign(null)}>
                  <X className="h-3.5 w-3.5" />
                </Button>
              </div>
            </CardHeader>
            <CardContent className="space-y-2">
              {tasks.length === 0 && (
                <p className="text-xs text-muted-foreground">No tasks for this campaign yet.</p>
              )}
              {tasks.map((t) => (
                <div key={t.id} className="rounded-lg border border-border bg-muted/20 p-3 space-y-1.5">
                  <div className="flex items-center justify-between gap-2">
                    <span className="text-xs font-medium truncate">{t.name}</span>
                    <TaskStatusBadge status={t.status} />
                  </div>
                  <div className="flex items-center gap-3 text-[10px] text-muted-foreground">
                    <span className="capitalize">{t.phase?.replace(/_/g, " ")}</span>
                    <span className="font-mono bg-muted/40 px-1.5 py-0.5 rounded text-blue-400">{t.mitre_technique}</span>
                    <span className="ml-auto">{t.assigned_operator}</span>
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>

          {/* Findings */}
          <Card className="border-red-500/20">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
                <AlertTriangle className="h-4 w-4" />
                Findings = {selectedCampaign.name}
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              {findings.length === 0 && (
                <p className="text-xs text-muted-foreground">No findings recorded yet.</p>
              )}
              {findings.map((f) => (
                <div key={f.id} className="rounded-lg border border-border bg-muted/20 p-3 space-y-1.5">
                  <div className="flex items-center gap-2">
                    <SevDot sev={f.severity} />
                    <span className="text-xs font-medium flex-1 truncate">{f.title}</span>
                    <span className={cn(
                      "text-[10px] font-bold tabular-nums",
                      f.cvss >= 9 ? "text-red-400" : f.cvss >= 7 ? "text-amber-400" : "text-yellow-400"
                    )}>
                      CVSS {f.cvss}
                    </span>
                  </div>
                  <div className="flex items-center gap-3 text-[10px] text-muted-foreground">
                    <span className="font-mono bg-muted/40 px-1.5 py-0.5 rounded text-blue-400">{f.mitre}</span>
                    <Badge className={cn(
                      "text-[10px] border capitalize",
                      f.status === "open"      ? "border-red-500/30 text-red-400 bg-red-500/10" :
                      f.status === "accepted"  ? "border-amber-500/30 text-amber-400 bg-amber-500/10" :
                                                 "border-green-500/30 text-green-400 bg-green-500/10"
                    )}>
                      {f.status}
                    </Badge>
                  </div>
                </div>
              ))}
            </CardContent>
          </Card>
        </motion.div>
      )}

      {/* Campaign action bar */}
      {selectedCampaign && selectedCampaign.status === "active" && (
        <div className="flex items-center gap-3 rounded-lg border border-border bg-muted/20 px-4 py-3">
          <span className="text-xs text-muted-foreground flex-1">
            Campaign <span className="text-foreground font-medium">{selectedCampaign.name}</span> is active = Phase: <span className="text-amber-400 capitalize">{selectedCampaign.phase?.replace(/_/g, " ")}</span>
          </span>
          <Button variant="outline" size="sm" className="border-amber-500/30 text-amber-400 hover:bg-amber-500/10">
            <Pause className="h-3.5 w-3.5 mr-1" />
            Pause
          </Button>
          <Button variant="outline" size="sm" className="border-green-500/30 text-green-400 hover:bg-green-500/10">
            <CheckCircle className="h-3.5 w-3.5 mr-1" />
            Complete
          </Button>
        </div>
      )}
    </motion.div>
  );
}
