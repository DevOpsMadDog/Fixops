/**
 * Privacy & GDPR Dashboard
 *
 * Data privacy compliance — DSRs, consents, incidents, processing activities.
 *   1. KPIs: Open DSRs, Overdue DSRs, Active Consents, Open Incidents
 *   2. DSR table: type, subject (masked), regulation, status, due date, fulfilled
 *   3. Consent management table: purpose, given/withdrawn counts
 *   4. Privacy incidents panel: type, severity, records affected, DPA notified
 *   5. Processing activities (RoPA): name, legal basis, data categories, retention
 *
 * API: GET /api/v1/privacy/...
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  ShieldCheck,
  AlertTriangle,
  Users,
  FileText,
  RefreshCw,
  Plus,
  Lock,
  Database,
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

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}?org_id=default`, { headers: { "X-API-Key": API_KEY } });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ── Mock data ──────────────────────────────────────────────────

const DSRS = [
  { id: "DSR-001", type: "access",      email: "j***@example.com",    regulation: "GDPR",  status: "open",      due_date: "2026-04-18", fulfilled_date: null,        overdue: false },
  { id: "DSR-002", type: "erasure",     email: "m***@acmecorp.io",    regulation: "GDPR",  status: "overdue",   due_date: "2026-04-12", fulfilled_date: null,        overdue: true  },
  { id: "DSR-003", type: "portability", email: "s***@gmail.com",      regulation: "CCPA",  status: "fulfilled", due_date: "2026-04-10", fulfilled_date: "2026-04-09", overdue: false },
  { id: "DSR-004", type: "rectification",email: "t***@corp.net",      regulation: "GDPR",  status: "in_progress",due_date:"2026-04-22",fulfilled_date: null,         overdue: false },
  { id: "DSR-005", type: "access",      email: "a***@startup.co",     regulation: "LGPD",  status: "overdue",   due_date: "2026-04-11", fulfilled_date: null,        overdue: true  },
  { id: "DSR-006", type: "objection",   email: "r***@university.edu", regulation: "GDPR",  status: "open",      due_date: "2026-04-25", fulfilled_date: null,        overdue: false },
];

const CONSENTS = [
  { id: "C-001", purpose: "Marketing Emails",          legal_basis: "Consent",           given: 8420, withdrawn: 312,  active: true  },
  { id: "C-002", purpose: "Analytics & Tracking",      legal_basis: "Consent",           given: 5891, withdrawn: 1204, active: true  },
  { id: "C-003", purpose: "Third-party Data Sharing",  legal_basis: "Consent",           given: 2103, withdrawn: 879,  active: true  },
  { id: "C-004", purpose: "Service Delivery",          legal_basis: "Contractual",       given: 18200,withdrawn: 44,   active: true  },
  { id: "C-005", purpose: "Fraud Prevention",          legal_basis: "Legitimate Interest",given: 18200,withdrawn: 8,   active: true  },
];

const INCIDENTS = [
  { id: "PI-001", type: "data_breach",       severity: "critical", records: 12400, dpa_notified: true,  status: "investigating", detected: "2026-04-14" },
  { id: "PI-002", type: "unauthorized_access",severity: "high",    records: 340,   dpa_notified: false, status: "open",          detected: "2026-04-15" },
];

const PROCESSING_ACTIVITIES = [
  { id: "PA-001", activity: "Customer Order Management",    legal_basis: "Contract",    categories: "Name, Email, Payment",         retention: "7 years" },
  { id: "PA-002", activity: "HR & Payroll Processing",      legal_basis: "Legal obligation",categories: "NI, Bank, Salary, DOB",    retention: "6 years" },
  { id: "PA-003", activity: "Marketing Campaigns",          legal_basis: "Consent",     categories: "Email, Preferences, Behavior", retention: "3 years" },
];

// ── Helpers ────────────────────────────────────────────────────

function DSRTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    access:        "border-blue-500/30 text-blue-400 bg-blue-500/10",
    erasure:       "border-red-500/30 text-red-400 bg-red-500/10",
    portability:   "border-purple-500/30 text-purple-400 bg-purple-500/10",
    rectification: "border-amber-500/30 text-amber-400 bg-amber-500/10",
    objection:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[type] ?? "border-border text-muted-foreground")}>
      {type}
    </Badge>
  );
}

function DSRStatusBadge({ status, overdue }: { status: string; overdue: boolean }) {
  if (overdue) return <Badge className="text-[10px] border border-red-500/50 text-red-400 bg-red-500/10">Overdue</Badge>;
  const map: Record<string, string> = {
    open:        "border-amber-500/30 text-amber-400 bg-amber-500/10",
    in_progress: "border-blue-500/30 text-blue-400 bg-blue-500/10",
    fulfilled:   "border-green-500/30 text-green-400 bg-green-500/10",
  };
  const labels: Record<string, string> = { open: "Open", in_progress: "In Progress", fulfilled: "Fulfilled" };
  return <Badge className={cn("text-[10px] border", map[status] ?? "border-border")}>{labels[status] ?? status}</Badge>;
}

function SevBadge({ sev }: { sev: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-amber-500/30 text-amber-400 bg-amber-500/10",
    medium:   "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    low:      "border-slate-500/30 text-slate-400 bg-slate-500/10",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[sev] ?? "border-border")}>{sev}</Badge>;
}

function RegBadge({ reg }: { reg: string }) {
  const map: Record<string, string> = {
    GDPR: "border-blue-500/30 text-blue-400 bg-blue-500/10",
    CCPA: "border-purple-500/30 text-purple-400 bg-purple-500/10",
    LGPD: "border-amber-500/30 text-amber-400 bg-amber-500/10",
  };
  return <Badge className={cn("text-[10px] border font-mono", map[reg] ?? "border-border text-muted-foreground")}>{reg}</Badge>;
}

// ── Component ──────────────────────────────────────────────────

export default function PrivacyGDPRDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [loading, setLoading] = useState(true);
  const [liveData, setLiveData] = useState<any>(null);

  useEffect(() => {
    Promise.allSettled([
      apiFetch(`/api/v1/privacy/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/privacy/dsrs?org_id=${ORG_ID}&limit=20`),
      apiFetch(`/api/v1/privacy/consents?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/privacy/incidents?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/privacy/processing-activities?org_id=${ORG_ID}`),
    ]).then(([statsR, dsrsR, consentsR, incidentsR, activitiesR]) => {
      const stats      = statsR.status      === "fulfilled" ? statsR.value      : null;
      const dsrs       = dsrsR.status       === "fulfilled" ? dsrsR.value       : null;
      const consents   = consentsR.status   === "fulfilled" ? consentsR.value   : null;
      const incidents  = incidentsR.status  === "fulfilled" ? incidentsR.value  : null;
      const activities = activitiesR.status === "fulfilled" ? activitiesR.value : null;
      if (stats || dsrs || consents || incidents || activities) {
        setLiveData({ stats, dsrs, consents, incidents, activities });
      }
    });
    setLoading(false);
  }, []);

  const openDSRs    = DSRS.filter((d) => d.status === "open" || d.status === "in_progress").length;
  const overdueDSRs = DSRS.filter((d) => d.overdue).length;
  const activeConsents = CONSENTS.reduce((s, c) => s + (c.active ? c.given : 0), 0);
  const openIncidents  = INCIDENTS.filter((i) => i.status !== "closed").length;

  const handleRefresh = () => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); };


  if (loading) return <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div></div>;


  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      {/* Header */}
      <PageHeader
        title="Privacy & GDPR"
        description="Data subject requests, consent management, privacy incidents, and processing activities"
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
              <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
            </Button>
            <Button variant="outline" size="sm" className="gap-1.5 border-amber-500/30 text-amber-400 hover:bg-amber-500/10">
              <AlertTriangle className="h-4 w-4" />
              Report Incident
            </Button>
            <Button size="sm" className="gap-1.5">
              <Plus className="h-4 w-4" />
              Submit DSR
            </Button>
          </div>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Open DSRs"       value={liveData?.stats?.open_dsrs       ?? openDSRs}       icon={FileText}   trend="up"   className="border-amber-500/20" />
        <KpiCard title="Overdue DSRs"    value={liveData?.stats?.overdue_dsrs    ?? overdueDSRs}    icon={AlertTriangle} trend="up" className="border-red-500/20" />
        <KpiCard title="Active Consents" value={liveData?.stats?.active_consents ?? activeConsents.toLocaleString()} icon={Users} trend="up" className="border-green-500/20" />
        <KpiCard title="Open Incidents"  value={liveData?.stats?.open_incidents  ?? openIncidents}  icon={ShieldCheck} trend="down" className="border-orange-500/20" />
      </div>

      {/* DSR Table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <FileText className="h-4 w-4 text-blue-400" />
              Data Subject Requests (DSRs)
            </CardTitle>
            <Badge className="text-[10px] border border-blue-500/30 text-blue-400 bg-blue-500/10">{DSRS.length} total</Badge>
          </div>
          <CardDescription className="text-xs">Access, erasure, portability, and objection requests</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">ID</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Subject</TableHead>
                  <TableHead className="text-[11px] h-8">Regulation</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8">Due Date</TableHead>
                  <TableHead className="text-[11px] h-8">Fulfilled</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(liveData?.dsrs?.items ?? liveData?.dsrs ?? DSRS).map((d: any) => (
                  <TableRow key={d.id} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">{d.id}</TableCell>
                    <TableCell className="py-2"><DSRTypeBadge type={d.type} /></TableCell>
                    <TableCell className="py-2 font-mono text-[11px]">{d.email}</TableCell>
                    <TableCell className="py-2"><RegBadge reg={d.regulation} /></TableCell>
                    <TableCell className="py-2"><DSRStatusBadge status={d.status} overdue={d.overdue} /></TableCell>
                    <TableCell className={cn("py-2 text-xs tabular-nums", d.overdue ? "text-red-400 font-semibold" : "text-muted-foreground")}>
                      {d.due_date}
                    </TableCell>
                    <TableCell className="py-2 text-xs tabular-nums text-muted-foreground">
                      {d.fulfilled_date ?? "—"}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Consent + Incidents side by side */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Consent Management */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Lock className="h-4 w-4 text-green-400" />
              Consent Management
            </CardTitle>
            <CardDescription className="text-xs">Purpose-level consent given vs withdrawn counts</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Purpose</TableHead>
                  <TableHead className="text-[11px] h-8">Legal Basis</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Given</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Withdrawn</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(liveData?.consents ?? CONSENTS).map((c: any) => (
                  <TableRow key={c.id ?? c.consent_id} className="hover:bg-muted/30">
                    <TableCell className="py-2 text-xs font-medium max-w-[140px] truncate">{c.purpose ?? c.subject_email}</TableCell>
                    <TableCell className="py-2 text-[10px] text-muted-foreground">{c.legal_basis ?? (c.consent_given ? "Consent" : "Withdrawn")}</TableCell>
                    <TableCell className="py-2 text-right text-xs tabular-nums text-green-400 font-semibold">{(c.given ?? (c.consent_given ? 1 : 0)).toLocaleString()}</TableCell>
                    <TableCell className="py-2 text-right text-xs tabular-nums text-red-400">{(c.withdrawn ?? (!c.consent_given ? 1 : 0)).toLocaleString()}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </CardContent>
        </Card>

        {/* Privacy Incidents */}
        <Card className="border-red-500/20">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
              <AlertTriangle className="h-4 w-4" />
              Privacy Incidents
            </CardTitle>
            <CardDescription className="text-xs">Breaches, unauthorized access, and DPA notification status</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {(liveData?.incidents ?? INCIDENTS).map((inc: any) => (
              <div key={inc.id} className="rounded-lg border border-border bg-muted/20 p-3 space-y-2">
                <div className="flex items-center justify-between gap-2">
                  <span className="font-mono text-[11px] text-muted-foreground">{inc.id}</span>
                  <SevBadge sev={inc.severity} />
                </div>
                <div className="text-xs font-medium capitalize">{inc.type.replace(/_/g, " ")}</div>
                <div className="flex items-center justify-between text-[11px] text-muted-foreground">
                  <span>Records affected: <span className="text-foreground font-semibold tabular-nums">{inc.records.toLocaleString()}</span></span>
                  <span>Detected: {inc.detected}</span>
                </div>
                <div className="flex items-center justify-between">
                  <Badge className={cn("text-[10px] border", inc.dpa_notified ? "border-green-500/30 text-green-400 bg-green-500/10" : "border-amber-500/30 text-amber-400 bg-amber-500/10")}>
                    {inc.dpa_notified ? "DPA Notified" : "DPA Not Notified"}
                  </Badge>
                  <Badge className={cn("text-[10px] border capitalize", inc.status === "investigating" ? "border-amber-500/30 text-amber-400 bg-amber-500/10" : "border-red-500/30 text-red-400 bg-red-500/10")}>
                    {inc.status}
                  </Badge>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>

      {/* Processing Activities (RoPA) */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Database className="h-4 w-4 text-purple-400" />
            Processing Activities (RoPA)
          </CardTitle>
          <CardDescription className="text-xs">Record of Processing Activities — legal basis, data categories, retention</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Activity</TableHead>
                  <TableHead className="text-[11px] h-8">Legal Basis</TableHead>
                  <TableHead className="text-[11px] h-8">Data Categories</TableHead>
                  <TableHead className="text-[11px] h-8">Retention</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {(liveData?.activities ?? PROCESSING_ACTIVITIES).map((pa: any) => (
                  <TableRow key={pa.id ?? pa.activity_id} className="hover:bg-muted/30">
                    <TableCell className="py-2 text-xs font-medium">{pa.activity ?? pa.activity_name}</TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{pa.legal_basis}</TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground max-w-[200px] truncate">{pa.categories ?? (Array.isArray(pa.data_categories) ? pa.data_categories.join(", ") : pa.data_categories)}</TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{pa.retention ?? (pa.retention_period_days ? `${pa.retention_period_days} days` : "—")}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
