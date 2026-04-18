/**
 * Breach Response
 *
 * Data breach case management and regulatory notification tracking.
 *   1. KPIs: Active Cases, Confirmed Breaches, Records Affected, Notifications Sent
 *   2. Breach cases table (10 rows)
 *   3. Notification log (8 rows)
 *   4. Regulatory reports (6 rows)
 *   5. Response timeline = horizontal stepper
 *
 * API stubs: GET /api/v1/breach/cases, /api/v1/breach/notifications, /api/v1/breach/reports
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { AlertTriangle, Bell, FileText, Clock, RefreshCw, Shield } from "lucide-react";

// == API helpers ================================================
const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "dev-key";
const ORG_ID   = "aldeci-demo";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}`, {
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

// == Mock data ===================================================

const BREACH_CASES = [
  { id: "BR-2026-001", title: "Customer PII exfiltration via API",       type: "external_attack", discovered: "2026-04-01", status: "reported",   records: 18420, notifiable: true,  deadline: "2026-04-04" },
  { id: "BR-2026-002", title: "S3 bucket misconfiguration = health data", type: "accidental",      discovered: "2026-04-03", status: "contained",  records: 9102,  notifiable: true,  deadline: "2026-04-06" },
  { id: "BR-2026-003", title: "Insider downloads of financial records",    type: "insider",         discovered: "2026-04-05", status: "confirmed",  records: 4300,  notifiable: true,  deadline: "2026-04-08" },
  { id: "BR-2026-004", title: "Vendor credential leak = prod DB",          type: "vendor_breach",   discovered: "2026-04-07", status: "confirmed",  records: 7200,  notifiable: true,  deadline: "2026-04-10" },
  { id: "BR-2026-005", title: "Ransomware = HR file server",               type: "external_attack", discovered: "2026-04-08", status: "contained",  records: 2810,  notifiable: false, deadline: "2026-04-11" },
  { id: "BR-2026-006", title: "Email mis-delivery = legal documents",      type: "accidental",      discovered: "2026-04-10", status: "reported",   records: 94,    notifiable: false, deadline: "2026-04-13" },
  { id: "BR-2026-007", title: "Third-party SaaS breach = payroll data",    type: "vendor_breach",   discovered: "2026-04-11", status: "confirmed",  records: 3200,  notifiable: true,  deadline: "2026-04-14" },
  { id: "BR-2026-008", title: "Phishing = executive email takeover",       type: "external_attack", discovered: "2026-04-12", status: "suspected",  records: 0,     notifiable: false, deadline: "2026-04-19" },
  { id: "BR-2026-009", title: "USB exfiltration = trade secrets",          type: "insider",         discovered: "2026-04-13", status: "suspected",  records: 0,     notifiable: false, deadline: "2026-04-20" },
  { id: "BR-2026-010", title: "Cloud storage sync = unencrypted backups",  type: "accidental",      discovered: "2026-04-14", status: "suspected",  records: 2697,  notifiable: true,  deadline: "2026-04-21" },
];

const NOTIFICATIONS = [
  { caseId: "BR-2026-001", party: "ICO (UK)",            type: "regulatory", sent: "2026-04-04 09:12", status: "delivered" },
  { caseId: "BR-2026-001", party: "Affected Customers",  type: "customer",   sent: "2026-04-05 14:30", status: "delivered" },
  { caseId: "BR-2026-002", party: "HHS / OCR",           type: "regulatory", sent: "2026-04-06 10:00", status: "delivered" },
  { caseId: "BR-2026-002", party: "Internal Leadership", type: "internal",   sent: "2026-04-03 16:45", status: "delivered" },
  { caseId: "BR-2026-003", party: "SEC",                 type: "regulatory", sent: "2026-04-08 11:00", status: "pending"   },
  { caseId: "BR-2026-004", party: "PCI DSS Council",     type: "regulatory", sent: "2026-04-10 08:00", status: "delivered" },
  { caseId: "BR-2026-007", party: "Media Statement",     type: "media",      sent: "2026-04-12 15:00", status: "delivered" },
  { caseId: "BR-2026-007", party: "Employee Notice",     type: "internal",   sent: "2026-04-12 09:00", status: "failed"    },
];

const REGULATORY_REPORTS = [
  { regulator: "GDPR",  caseId: "BR-2026-001", due: "2026-04-04", daysLeft: -12, status: "accepted" },
  { regulator: "HIPAA", caseId: "BR-2026-002", due: "2026-04-06", daysLeft: -10, status: "submitted" },
  { regulator: "CCPA",  caseId: "BR-2026-003", due: "2026-04-23", daysLeft: 7,   status: "draft" },
  { regulator: "SEC",   caseId: "BR-2026-003", due: "2026-04-19", daysLeft: 3,   status: "draft" },
  { regulator: "FTC",   caseId: "BR-2026-004", due: "2026-04-24", daysLeft: 8,   status: "draft" },
  { regulator: "PCI",   caseId: "BR-2026-004", due: "2026-04-10", daysLeft: -6,  status: "submitted" },
];

const TIMELINE_STEPS = [
  { label: "Discover",   done: true  },
  { label: "Assess",     done: true  },
  { label: "Contain",    done: true  },
  { label: "Notify",     done: false },
  { label: "Remediate",  done: false },
  { label: "Review",     done: false },
];

// == Helpers ====================================================

function BreachTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    external_attack: "border-red-500/30 text-red-400 bg-red-500/10",
    insider:         "border-orange-500/30 text-orange-400 bg-orange-500/10",
    vendor_breach:   "border-purple-500/30 text-purple-400 bg-purple-500/10",
    accidental:      "border-blue-500/30 text-blue-400 bg-blue-500/10",
  };
  const labels: Record<string, string> = {
    external_attack: "External Attack",
    insider:         "Insider",
    vendor_breach:   "Vendor Breach",
    accidental:      "Accidental",
  };
  return <Badge className={cn("text-[10px] border whitespace-nowrap", map[type] ?? "")}>{labels[type] ?? type}</Badge>;
}

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    suspected:  "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    confirmed:  "border-red-500/30 text-red-400 bg-red-500/10",
    contained:  "border-amber-500/30 text-amber-400 bg-amber-500/10",
    reported:   "border-green-500/30 text-green-400 bg-green-500/10",
    delivered:  "border-green-500/30 text-green-400 bg-green-500/10",
    pending:    "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    failed:     "border-red-500/30 text-red-400 bg-red-500/10",
    draft:      "border-muted-foreground/30 text-muted-foreground bg-muted/20",
    submitted:  "border-blue-500/30 text-blue-400 bg-blue-500/10",
    accepted:   "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[status] ?? "")}>{status}</Badge>;
}

function NotifTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    regulatory: "border-purple-500/30 text-purple-400 bg-purple-500/10",
    customer:   "border-blue-500/30 text-blue-400 bg-blue-500/10",
    media:      "border-amber-500/30 text-amber-400 bg-amber-500/10",
    internal:   "border-muted-foreground/30 text-muted-foreground bg-muted/20",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[type] ?? "")}>{type}</Badge>;
}

// == Component ==================================================

export default function BreachResponse() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);
  const [loading, setLoading] = useState(true);

  const loadData = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/breach-response/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/breach-response/cases?org_id=${ORG_ID}`),
    ]).then(([statsRes, casesRes]) => {
      const stats = statsRes.status === "fulfilled" ? statsRes.value : null;
      const cases = casesRes.status === "fulfilled" ? casesRes.value : null;
      if (stats || cases) setLiveData({ stats, cases });
    }).finally(() => setDataLoading(false));
  };

  useEffect(() => { loadData(); }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    loadData();
    setTimeout(() => setRefreshing(false), 800);
  };

  // Resolve KPI values = engine returns: total_cases, confirmed, notifications_sent
  const kpiActiveCases       = liveData?.stats?.total_cases        ?? liveData?.stats?.active_cases  ?? 7;
  const kpiConfirmedBreaches  = liveData?.stats?.confirmed          ?? liveData?.stats?.confirmed_breaches ?? 3;
  const kpiRecordsAffected   = liveData?.stats?.total_records_affected
    ? liveData.stats.total_records_affected.toLocaleString()
    : "47,823";
  const kpiNotificationsSent = liveData?.stats?.notifications_sent ?? 12;

  // Live cases table = map API shape to mock shape
  const liveCasesArr = liveData?.cases?.cases ?? liveData?.cases;
  const tableCases = Array.isArray(liveCasesArr) && liveCasesArr.length > 0
    ? liveCasesArr.map((c: any) => ({
        id:          c.case_id ?? c.id ?? "=",
        title:       c.title ?? "=",
        type:        c.breach_type ?? "external_attack",
        discovered:  c.discovered_at ?? c.created_at ?? "=",
        status:      c.status ?? "suspected",
        records:     c.estimated_records_affected ?? 0,
        notifiable:  c.notifiable ?? false,
        deadline:    c.regulatory_deadline ?? "=",
      }))
    : BREACH_CASES;

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
      {/* Header */}
      <PageHeader
        title="Data Breach Response"
        description="Breach case management and regulatory notification tracking"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Active Cases"       value={kpiActiveCases}       icon={AlertTriangle} trend="up"   className="border-red-500/20" />
        <KpiCard title="Confirmed Breaches" value={kpiConfirmedBreaches}  icon={Shield}        trend="up"   className="border-red-500/20" />
        <KpiCard title="Records Affected"   value={kpiRecordsAffected}   icon={FileText}      trend="up"   className="border-amber-500/20" />
        <KpiCard title="Notifications Sent" value={kpiNotificationsSent} icon={Bell}          trend="down" />
      </div>

      {/* Response Timeline */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Clock className="h-4 w-4 text-blue-400" />
            Response Timeline = BR-2026-001
          </CardTitle>
          <CardDescription className="text-xs">Current active case progress through mandatory response stages</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="flex items-center gap-0">
            {TIMELINE_STEPS.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                <p className="text-lg font-medium">No data available</p>
                <p className="text-sm">Data will appear here once available</p>
              </div>
            ) : (
              TIMELINE_STEPS.map((step, idx) => (
              <div key={step.label} className="flex items-center flex-1 min-w-0">
                <div className="flex flex-col items-center gap-1.5 flex-1">
                  <div className={cn(
                    "w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold border-2 shrink-0",
                    step.done
                      ? "bg-green-500/20 border-green-500 text-green-400"
                      : idx === TIMELINE_STEPS.findIndex(s => !s.done)
                        ? "bg-blue-500/20 border-blue-500 text-blue-400 animate-pulse"
                        : "bg-muted/30 border-border text-muted-foreground"
                  )}>
                    {step.done ? "=" : idx + 1}
                  </div>
                  <span className={cn(
                    "text-[10px] font-medium text-center",
                    step.done ? "text-green-400" : "text-muted-foreground"
                  )}>
                    {step.label}
                  </span>
                </div>
                {idx < TIMELINE_STEPS.length - 1 && (
                  <div className={cn(
                    "h-0.5 flex-1 mx-1 mb-5",
                    step.done ? "bg-green-500/50" : "bg-border"
                  )} />
                )}
              </div>
            )))}
          </div>
        </CardContent>
      </Card>

      {/* Breach Cases Table */}
      <Card className="border-red-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
              <AlertTriangle className="h-4 w-4" />
              Breach Cases
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
              {tableCases.length} cases
            </Badge>
          </div>
          <CardDescription className="text-xs">All active and resolved breach cases with notification status</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Case ID</TableHead>
                  <TableHead className="text-[11px] h-8">Title</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Discovered</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8">Records</TableHead>
                  <TableHead className="text-[11px] h-8">Notifiable</TableHead>
                  <TableHead className="text-[11px] h-8">Deadline</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {tableCases.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  tableCases.map((row) => (
                  <TableRow key={row.id} className="hover:bg-muted/30">
                    <TableCell className="text-xs font-mono py-2">{row.id}</TableCell>
                    <TableCell className="text-xs py-2 max-w-[180px] truncate">{row.title}</TableCell>
                    <TableCell className="py-2"><BreachTypeBadge type={row.type} /></TableCell>
                    <TableCell className="text-xs py-2 tabular-nums text-muted-foreground">{row.discovered}</TableCell>
                    <TableCell className="py-2"><StatusBadge status={row.status} /></TableCell>
                    <TableCell className="text-xs py-2 tabular-nums font-medium">
                      {row.records > 0 ? row.records.toLocaleString() : "="}
                    </TableCell>
                    <TableCell className="py-2">
                      {row.notifiable
                        ? <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">Yes</Badge>
                        : <Badge className="text-[10px] border border-border text-muted-foreground">No</Badge>}
                    </TableCell>
                    <TableCell className="text-xs py-2 tabular-nums text-muted-foreground">{row.deadline}</TableCell>
                    <TableCell className="py-2 text-right">
                      <Button variant="outline" size="sm" className="h-6 px-2 text-[10px]">View</Button>
                    </TableCell>
                  </TableRow>
                )))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Notification Log + Regulatory Reports */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Notification Log */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Bell className="h-4 w-4 text-blue-400" />
              Notification Log
            </CardTitle>
            <CardDescription className="text-xs">Regulatory, customer, media and internal notifications sent</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Case</TableHead>
                    <TableHead className="text-[11px] h-8">Notified Party</TableHead>
                    <TableHead className="text-[11px] h-8">Type</TableHead>
                    <TableHead className="text-[11px] h-8">Sent</TableHead>
                    <TableHead className="text-[11px] h-8">Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {NOTIFICATIONS.length === 0 ? (
                    <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                      <p className="text-lg font-medium">No data available</p>
                      <p className="text-sm">Data will appear here once available</p>
                    </div>
                  ) : (
                    NOTIFICATIONS.map((row, idx) => (
                    <TableRow key={idx} className="hover:bg-muted/30">
                      <TableCell className="text-xs font-mono py-2">{row.caseId}</TableCell>
                      <TableCell className="text-xs py-2 max-w-[120px] truncate">{row.party}</TableCell>
                      <TableCell className="py-2"><NotifTypeBadge type={row.type} /></TableCell>
                      <TableCell className="text-xs py-2 tabular-nums text-muted-foreground whitespace-nowrap">{row.sent}</TableCell>
                      <TableCell className="py-2"><StatusBadge status={row.status} /></TableCell>
                    </TableRow>
                  )))}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>

        {/* Regulatory Reports */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <FileText className="h-4 w-4 text-purple-400" />
              Regulatory Reports
            </CardTitle>
            <CardDescription className="text-xs">Mandatory regulator filings and submission deadlines</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Regulator</TableHead>
                    <TableHead className="text-[11px] h-8">Case</TableHead>
                    <TableHead className="text-[11px] h-8">Due Date</TableHead>
                    <TableHead className="text-[11px] h-8">Days Left</TableHead>
                    <TableHead className="text-[11px] h-8">Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {REGULATORY_REPORTS.length === 0 ? (
                    <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                      <p className="text-lg font-medium">No data available</p>
                      <p className="text-sm">Data will appear here once available</p>
                    </div>
                  ) : (
                    REGULATORY_REPORTS.map((row, idx) => (
                    <TableRow key={idx} className="hover:bg-muted/30">
                      <TableCell className="text-xs font-bold py-2">{row.regulator}</TableCell>
                      <TableCell className="text-xs font-mono py-2">{row.caseId}</TableCell>
                      <TableCell className="text-xs py-2 tabular-nums text-muted-foreground">{row.due}</TableCell>
                      <TableCell className={cn(
                        "text-xs py-2 font-bold tabular-nums",
                        row.daysLeft < 0 ? "text-muted-foreground" : row.daysLeft < 7 ? "text-red-400" : "text-green-400"
                      )}>
                        {row.daysLeft < 0 ? `${Math.abs(row.daysLeft)}d ago` : `${row.daysLeft}d`}
                      </TableCell>
                      <TableCell className="py-2"><StatusBadge status={row.status} /></TableCell>
                    </TableRow>
                  )))}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>
      </div>
    </motion.div>
  );
}
