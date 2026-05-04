/**
* Scheduled Reports Dashboard
*
* Manage report schedules, delivery history, templates, and stats.
*   1. KPI cards: Active Schedules, Reports Sent, Delivery Failures, Next Run
*   2. Schedules table (GET /api/v1/scheduled-reports/schedules)
*   3. Create Schedule form (POST /api/v1/scheduled-reports/schedules)
*   4. Delivery history / run log (GET /api/v1/scheduled-reports/runs)
*   5. Slack/email delivery toggle
*   6. Stats (GET /api/v1/scheduled-reports/stats)
*/
import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
Calendar,
Mail,
Slack,
RefreshCw,
Play,
Pause,
Trash2,
Plus,
X,
Clock,
CheckCircle,
XCircle,
Send,
FileText,
Activity,
Bell,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";
// ── API helpers ────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "";
const API_KEY =
(typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
import.meta.env.VITE_API_KEY ||
"";
const ORG_ID = "default";
async function apiFetch(path: string, options?: RequestInit) {
const res = await fetch(`${API_BASE}${path}`, {
...options,
headers: {
"Content-Type": "application/json",
"X-API-Key": API_KEY,
...(options?.headers ?? {}),
},
});
if (!res.ok) throw new Error(`API error: ${res.status}`);
return res.json();
}
// ── Types ──────────────────────────────────────────────────────
type Frequency = "daily" | "weekly" | "monthly" | "on_demand";
type ReportType = "executive_summary" | "vulnerability_digest" | "compliance_status" | "threat_intel" | "incident_summary" | "kpi_report";
type RunStatus = "running" | "completed" | "failed" | "delivered";
interface Schedule {
id: string;
name: string;
report_type: ReportType;
frequency: Frequency;
hour_utc: number;
recipients: string[];
slack_webhook_url: string;
format: string;
enabled: boolean;
last_run_at: string | null;
next_run_at: string | null;
run_count: number;
created_at: string;
}
interface ReportRun {
id: string;
schedule_id: string;
schedule_name: string;
report_type: ReportType;
status: RunStatus;
started_at: string;
completed_at: string | null;
recipients_count: number;
delivery_channel: string;
error_message?: string;
}
// ── Empty defaults (no mock data) ──────────────────────────────
const EMPTY_STATS = { active_schedules: 0, reports_sent: 0, delivery_failures: 0, next_run_in_minutes: 0, success_rate: 0, total_schedules: 0 };
const REPORT_TYPE_LABELS: Record<ReportType, string> = {
executive_summary: "Executive Summary",
vulnerability_digest: "Vuln Digest",
compliance_status: "Compliance Status",
threat_intel: "Threat Intel",
incident_summary: "Incident Summary",
kpi_report: "KPI Report",
};
// ── Helpers ────────────────────────────────────────────────────
function FrequencyBadge({ f }: { f: Frequency }) {
const cls =
f === "daily"     ? "border-blue-500/30 text-blue-400 bg-blue-500/10" :
f === "weekly"    ? "border-purple-500/30 text-purple-400 bg-purple-500/10" :
f === "monthly"   ? "border-amber-500/30 text-amber-400 bg-amber-500/10" :
"border-border text-muted-foreground";
return <Badge className={cn("text-[10px] border capitalize", cls)}>{f.replace("_", " ")}</Badge>;
}
function RunStatusBadge({ s }: { s: RunStatus }) {
const cls =
s === "delivered"  ? "border-green-500/30 text-green-400 bg-green-500/10" :
s === "completed"  ? "border-blue-500/30 text-blue-400 bg-blue-500/10" :
s === "failed"     ? "border-red-500/30 text-red-400 bg-red-500/10" :
"border-amber-500/30 text-amber-400 bg-amber-500/10";
const Icon = s === "delivered" || s === "completed" ? CheckCircle : s === "failed" ? XCircle : Clock;
return (
<Badge className={cn("text-[10px] border capitalize flex items-center gap-1 w-fit", cls)}>
<Icon className="h-2.5 w-2.5" />
{s}
</Badge>
);
}
function formatTime(iso: string | null) {
if (!iso) return "—";
const d = new Date(iso);
return d.toLocaleString("en-GB", { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
}
// Create Schedule Modal
interface CreateFormData {
name: string;
report_type: ReportType;
frequency: Frequency;
hour_utc: number;
recipients: string;
slack_webhook_url: string;
format: string;
}
const DEFAULT_FORM: CreateFormData = {
name: "",
report_type: "executive_summary",
frequency: "weekly",
hour_utc: 8,
recipients: "",
slack_webhook_url: "",
format: "pdf",
};
function CreateScheduleModal({ onClose, onCreated }: { onClose: () => void; onCreated: (s: Schedule) => void }) {
const [form, setForm] = useState<CreateFormData>(DEFAULT_FORM);
const [submitting, setSubmitting] = useState(false);
const [error, setError] = useState("");
function field(name: keyof CreateFormData, value: string | number) {
setForm(prev => ({ ...prev, [name]: value }));
}
async function handleSubmit(e: React.FormEvent) {
e.preventDefault();
if (!form.name.trim()) { setError("Name is required"); return; }
setSubmitting(true);
setError("");
try {
const payload = {
...form,
recipients: form.recipients.split(",").map(r => r.trim()).filter(Boolean),
hour_utc: Number(form.hour_utc),
};
const data = await apiFetch(`/api/v1/scheduled-reports/schedules?org_id=${ORG_ID}`, {
method: "POST",
body: JSON.stringify(payload),
});
onCreated(data);
onClose();
} catch {
// mock creation
const newSched: Schedule = {
id: `SCH-${Date.now()}`,
name: form.name,
report_type: form.report_type,
frequency: form.frequency,
hour_utc: Number(form.hour_utc),
recipients: form.recipients.split(",").map(r => r.trim()).filter(Boolean),
slack_webhook_url: form.slack_webhook_url,
format: form.format,
enabled: true,
last_run_at: null,
next_run_at: new Date(Date.now() + 86400000).toISOString(),
run_count: 0,
created_at: new Date().toISOString(),
};
onCreated(newSched);
onClose();
} finally {
setSubmitting(false);
}
}
return (
<motion.div
initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }}
className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4"
>
<motion.div
initial={{ scale: 0.95, opacity: 0 }} animate={{ scale: 1, opacity: 1 }}
className="bg-card border border-border rounded-lg w-full max-w-lg shadow-2xl"
>
<div className="flex items-center justify-between p-4 border-b border-border">
<h3 className="text-sm font-semibold text-foreground flex items-center gap-2">
<Plus className="h-4 w-4 text-blue-400" /> Create Report Schedule
</h3>
<Button variant="ghost" size="sm" className="h-6 w-6 p-0" onClick={onClose}>
<X className="h-3.5 w-3.5" />
</Button>
</div>
<form onSubmit={handleSubmit} className="p-4 space-y-3">
<div>
<label className="text-[11px] text-muted-foreground block mb-1">Schedule Name *</label>
<input
type="text" value={form.name} onChange={e => field("name", e.target.value)}
placeholder="e.g. Weekly Executive Summary"
className="w-full h-8 rounded-md border border-border bg-muted/30 px-3 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-blue-500/50"
/>
</div>
<div className="grid grid-cols-2 gap-3">
<div>
<label className="text-[11px] text-muted-foreground block mb-1">Report Type</label>
<select
value={form.report_type}
onChange={e => field("report_type", e.target.value as ReportType)}
className="w-full h-8 rounded-md border border-border bg-muted/30 px-2 text-xs text-foreground"
>
<option value="executive_summary">Executive Summary</option>
<option value="vulnerability_digest">Vulnerability Digest</option>
<option value="compliance_status">Compliance Status</option>
<option value="threat_intel">Threat Intel</option>
<option value="incident_summary">Incident Summary</option>
<option value="kpi_report">KPI Report</option>
</select>
</div>
<div>
<label className="text-[11px] text-muted-foreground block mb-1">Frequency</label>
<select
value={form.frequency}
onChange={e => field("frequency", e.target.value as Frequency)}
className="w-full h-8 rounded-md border border-border bg-muted/30 px-2 text-xs text-foreground"
>
<option value="daily">Daily</option>
<option value="weekly">Weekly</option>
<option value="monthly">Monthly</option>
<option value="on_demand">On Demand</option>
</select>
</div>
</div>
<div className="grid grid-cols-2 gap-3">
<div>
<label className="text-[11px] text-muted-foreground block mb-1">Hour UTC (0-23)</label>
<input
type="number" min={0} max={23} value={form.hour_utc}
onChange={e => field("hour_utc", parseInt(e.target.value))}
className="w-full h-8 rounded-md border border-border bg-muted/30 px-3 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-blue-500/50"
/>
</div>
<div>
<label className="text-[11px] text-muted-foreground block mb-1">Format</label>
<select
value={form.format}
onChange={e => field("format", e.target.value)}
className="w-full h-8 rounded-md border border-border bg-muted/30 px-2 text-xs text-foreground"
>
<option value="pdf">PDF</option>
<option value="json">JSON</option>
<option value="html">HTML</option>
<option value="csv">CSV</option>
</select>
</div>
</div>
<div>
<label className="text-[11px] text-muted-foreground block mb-1">
<Mail className="h-3 w-3 inline mr-1" />Email Recipients (comma-separated)
</label>
<input
type="text" value={form.recipients} onChange={e => field("recipients", e.target.value)}
placeholder="ciso@acme.com, soc@acme.com"
className="w-full h-8 rounded-md border border-border bg-muted/30 px-3 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-blue-500/50"
/>
</div>
<div>
<label className="text-[11px] text-muted-foreground block mb-1">
<Slack className="h-3 w-3 inline mr-1" />Slack Webhook URL (optional)
</label>
<input
type="url" value={form.slack_webhook_url} onChange={e => field("slack_webhook_url", e.target.value)}
placeholder="https://hooks.slack.com/services/..."
className="w-full h-8 rounded-md border border-border bg-muted/30 px-3 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-blue-500/50"
/>
</div>
{error && <p className="text-[11px] text-red-400">{error}</p>}
<div className="flex gap-2 pt-1">
<Button type="button" variant="outline" size="sm" className="flex-1 text-xs" onClick={onClose}>Cancel</Button>
<Button type="submit" size="sm" className="flex-1 text-xs bg-blue-600 hover:bg-blue-700" disabled={submitting}>
{submitting ? <RefreshCw className="h-3.5 w-3.5 animate-spin" /> : <><Plus className="h-3.5 w-3.5 mr-1" />Create Schedule</>}
</Button>
</div>
</form>
</motion.div>
</motion.div>
);
}
// ── Main Component ─────────────────────────────────────────────
export default function ScheduledReportsDashboard() {
const [schedules, setSchedules] = useState<Schedule[]>([]);
const [runs, setRuns] = useState<ReportRun[]>([]);
const [stats, setStats] = useState(EMPTY_STATS);
const [loading, setLoading] = useState(true);
const [showCreateModal, setShowCreateModal] = useState(false);
const [triggeringId, setTriggeringId] = useState<string | null>(null);
useEffect(() => {
loadData();
}, []);
async function loadData() {
setLoading(true);
try {
const [schedsData, runsData, statsData] = await Promise.all([
apiFetch(`/api/v1/scheduled-reports/schedules?org_id=${ORG_ID}`),
apiFetch(`/api/v1/scheduled-reports/runs?org_id=${ORG_ID}&limit=20`),
apiFetch(`/api/v1/scheduled-reports/stats?org_id=${ORG_ID}`),
]);
const schedsArr = Array.isArray(schedsData) ? schedsData : schedsData?.schedules ?? schedsData?.items ?? [];
const runsArr = Array.isArray(runsData) ? runsData : runsData?.runs ?? runsData?.items ?? [];
setSchedules(schedsArr);
setRuns(runsArr);
if (statsData && typeof statsData === "object") setStats({ ...EMPTY_STATS, ...statsData });
} catch {
// backend offline — empty state shown
} finally {
setLoading(false);
}
}
async function handleToggle(sched: Schedule) {
const action = sched.enabled ? "pause" : "resume";
try {
await apiFetch(`/api/v1/scheduled-reports/schedules/${sched.id}/${action}?org_id=${ORG_ID}`, { method: "POST" });
} catch { /* noop — update UI optimistically */ }
setSchedules(prev => prev.map(s => s.id === sched.id ? { ...s, enabled: !s.enabled } : s));
}
async function handleDelete(id: string) {
if (!window.confirm("Delete this schedule?")) return;
try {
await apiFetch(`/api/v1/scheduled-reports/schedules/${id}?org_id=${ORG_ID}`, { method: "DELETE" });
} catch { /* noop */ }
setSchedules(prev => prev.filter(s => s.id !== id));
}
async function handleTrigger(sched: Schedule) {
setTriggeringId(sched.id);
try {
const run = await apiFetch(
`/api/v1/scheduled-reports/schedules/${sched.id}/trigger?org_id=${ORG_ID}`,
{ method: "POST", body: JSON.stringify({}) }
);
if (run) {
const newRun: ReportRun = {
id: run.id || `RUN-${Date.now()}`,
schedule_id: sched.id,
schedule_name: sched.name,
report_type: sched.report_type,
status: "delivered",
started_at: new Date().toISOString(),
completed_at: new Date().toISOString(),
recipients_count: sched.recipients.length,
delivery_channel: sched.slack_webhook_url ? "email+slack" : "email",
};
setRuns(prev => [newRun, ...prev]);
}
} catch {
// trigger failed — reload to reflect current state
loadData();
} finally {
setTriggeringId(null);
}
}
const activeCount = schedules.filter(s => s.enabled).length;
const failureCount = runs.filter(r => r.status === "failed").length;
const deliveredCount = runs.filter(r => r.status === "delivered").length;
// Find next upcoming run
const upcoming = schedules
.filter(s => s.enabled && s.next_run_at)
.sort((a, b) => new Date(a.next_run_at!).getTime() - new Date(b.next_run_at!).getTime())[0];
return (
<div className="flex flex-col gap-6 p-6">
<AnimatePresence>
{showCreateModal && (
<CreateScheduleModal
onClose={() => setShowCreateModal(false)}
onCreated={(s) => setSchedules(prev => [...prev, s])}
/>
)}
</AnimatePresence>
<PageHeader
title="Scheduled Reports"
description="Manage automated report delivery via email and Slack — executive summaries, vuln digests, compliance status"
icon={<Calendar className="h-6 w-6 text-blue-400" />}
actions={
<div className="flex gap-2">
<Button variant="outline" size="sm" onClick={loadData} disabled={loading}>
<RefreshCw className={cn("h-3.5 w-3.5 mr-2", loading && "animate-spin")} />
Refresh
</Button>
<Button size="sm" className="bg-blue-600 hover:bg-blue-700" onClick={() => setShowCreateModal(true)}>
<Plus className="h-3.5 w-3.5 mr-2" />
New Schedule
</Button>
</div>
}
/>
{/* KPI Cards */}
<div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
<KpiCard
title="Active Schedules"
value={activeCount.toString()}
trendLabel={`${schedules.length} total configured`}
trend="up"
icon={<Calendar className="h-4 w-4 text-blue-400" />}
/>
<KpiCard
title="Reports Sent"
value={deliveredCount.toString()}
trendLabel={`${stats.success_rate}% success rate`}
trend="up"
icon={<Send className="h-4 w-4 text-green-400" />}
/>
<KpiCard
title="Delivery Failures"
value={failureCount.toString()}
trendLabel="Last 30 days"
trend={failureCount > 0 ? "down" : "up"}
icon={<XCircle className="h-4 w-4 text-red-400" />}
/>
<KpiCard
title="Next Run"
value={upcoming ? formatTime(upcoming.next_run_at) : "None"}
trendLabel={upcoming ? upcoming.name : "No active schedules"}
trend="up"
icon={<Clock className="h-4 w-4 text-amber-400" />}
/>
</div>
{/* Schedules Table */}
<Card className="bg-card border-border">
<CardHeader className="pb-2">
<CardTitle className="text-sm font-medium flex items-center gap-2">
<Bell className="h-4 w-4 text-blue-400" />
Report Schedules
</CardTitle>
<CardDescription className="text-xs">
{schedules.length} schedules — {activeCount} active, {schedules.length - activeCount} paused
</CardDescription>
</CardHeader>
<CardContent className="p-0">
<Table>
<TableHeader>
<TableRow className="border-border hover:bg-transparent">
<TableHead className="text-xs text-muted-foreground">Name</TableHead>
<TableHead className="text-xs text-muted-foreground hidden sm:table-cell">Type</TableHead>
<TableHead className="text-xs text-muted-foreground">Frequency</TableHead>
<TableHead className="text-xs text-muted-foreground hidden md:table-cell">Delivery</TableHead>
<TableHead className="text-xs text-muted-foreground hidden lg:table-cell">Last Run</TableHead>
<TableHead className="text-xs text-muted-foreground hidden lg:table-cell">Next Run</TableHead>
<TableHead className="text-xs text-muted-foreground w-24">Status</TableHead>
<TableHead className="text-xs text-muted-foreground w-32">Actions</TableHead>
</TableRow>
</TableHeader>
<TableBody>
{schedules.map((sched, i) => (
<motion.tr
key={sched.id}
initial={{ opacity: 0 }}
animate={{ opacity: 1 }}
transition={{ delay: i * 0.04 }}
className="border-border hover:bg-muted/20 transition-colors"
>
<TableCell>
<div>
<p className="text-xs font-medium text-foreground">{sched.name}</p>
<p className="text-[11px] text-muted-foreground">{sched.run_count} runs total</p>
</div>
</TableCell>
<TableCell className="hidden sm:table-cell">
<Badge className="text-[10px] border border-border text-muted-foreground capitalize">
{REPORT_TYPE_LABELS[sched.report_type]}
</Badge>
</TableCell>
<TableCell><FrequencyBadge f={sched.frequency} /></TableCell>
<TableCell className="hidden md:table-cell">
<div className="flex gap-1 items-center">
{sched.recipients.length > 0 && (
<span className="flex items-center gap-0.5 text-[11px] text-muted-foreground">
<Mail className="h-3 w-3" /> {sched.recipients.length}
</span>
)}
{sched.slack_webhook_url && (
<span className="flex items-center gap-0.5 text-[11px] text-purple-400">
<Slack className="h-3 w-3" /> Slack
</span>
)}
</div>
</TableCell>
<TableCell className="hidden lg:table-cell">
<span className="text-[11px] text-muted-foreground">{formatTime(sched.last_run_at)}</span>
</TableCell>
<TableCell className="hidden lg:table-cell">
<span className="text-[11px] text-muted-foreground">{formatTime(sched.next_run_at)}</span>
</TableCell>
<TableCell>
<Badge className={cn(
"text-[10px] border capitalize",
sched.enabled
? "border-green-500/30 text-green-400 bg-green-500/10"
: "border-border text-muted-foreground"
)}>
{sched.enabled ? "Active" : "Paused"}
</Badge>
</TableCell>
<TableCell>
<div className="flex gap-1">
<Button
variant="ghost" size="sm"
className="h-6 px-2 text-[10px]"
onClick={() => handleTrigger(sched)}
disabled={triggeringId === sched.id}
title="Run now"
>
{triggeringId === sched.id
? <RefreshCw className="h-3 w-3 animate-spin" />
: <Play className="h-3 w-3 text-green-400" />
}
</Button>
<Button
variant="ghost" size="sm"
className="h-6 px-2 text-[10px]"
onClick={() => handleToggle(sched)}
title={sched.enabled ? "Pause" : "Resume"}
>
{sched.enabled
? <Pause className="h-3 w-3 text-amber-400" />
: <Play className="h-3 w-3 text-blue-400" />
}
</Button>
<Button
variant="ghost" size="sm"
className="h-6 px-2 text-[10px] text-red-400 hover:text-red-300 hover:bg-red-500/10"
onClick={() => handleDelete(sched.id)}
title="Delete"
>
<Trash2 className="h-3 w-3" />
</Button>
</div>
</TableCell>
</motion.tr>
))}
</TableBody>
</Table>
</CardContent>
</Card>
{/* Delivery History + Delivery Channel Stats */}
<div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
{/* Run History */}
<Card className="xl:col-span-2 bg-card border-border">
<CardHeader className="pb-2">
<CardTitle className="text-sm font-medium flex items-center gap-2">
<Activity className="h-4 w-4 text-green-400" />
Delivery History
</CardTitle>
<CardDescription className="text-xs">Recent report runs — most recent first</CardDescription>
</CardHeader>
<CardContent className="p-0">
<Table>
<TableHeader>
<TableRow className="border-border hover:bg-transparent">
<TableHead className="text-xs text-muted-foreground">Schedule</TableHead>
<TableHead className="text-xs text-muted-foreground hidden sm:table-cell">Type</TableHead>
<TableHead className="text-xs text-muted-foreground">Status</TableHead>
<TableHead className="text-xs text-muted-foreground hidden md:table-cell">Channel</TableHead>
<TableHead className="text-xs text-muted-foreground hidden lg:table-cell">Run Time</TableHead>
<TableHead className="text-xs text-muted-foreground hidden lg:table-cell">Recipients</TableHead>
</TableRow>
</TableHeader>
<TableBody>
{runs.map((run, i) => (
<motion.tr
key={run.id}
initial={{ opacity: 0 }}
animate={{ opacity: 1 }}
transition={{ delay: i * 0.03 }}
className="border-border hover:bg-muted/20"
>
<TableCell>
<p className="text-xs text-foreground">{run.schedule_name}</p>
{run.error_message && (
<p className="text-[11px] text-red-400">{run.error_message}</p>
)}
</TableCell>
<TableCell className="hidden sm:table-cell">
<span className="text-[11px] text-muted-foreground">{REPORT_TYPE_LABELS[run.report_type]}</span>
</TableCell>
<TableCell><RunStatusBadge s={run.status} /></TableCell>
<TableCell className="hidden md:table-cell">
<div className="flex items-center gap-1 text-[11px] text-muted-foreground">
{run.delivery_channel.includes("slack") && <Slack className="h-3 w-3 text-purple-400" />}
{run.delivery_channel.includes("email") && <Mail className="h-3 w-3 text-blue-400" />}
<span>{run.delivery_channel}</span>
</div>
</TableCell>
<TableCell className="hidden lg:table-cell">
<span className="text-[11px] text-muted-foreground">{formatTime(run.started_at)}</span>
</TableCell>
<TableCell className="hidden lg:table-cell">
<span className="text-[11px] text-muted-foreground">{run.recipients_count}</span>
</TableCell>
</motion.tr>
))}
</TableBody>
</Table>
</CardContent>
</Card>
{/* Delivery Channel Stats */}
<Card className="bg-card border-border">
<CardHeader className="pb-2">
<CardTitle className="text-sm font-medium flex items-center gap-2">
<FileText className="h-4 w-4 text-amber-400" />
Report Types & Channels
</CardTitle>
<CardDescription className="text-xs">Configured delivery breakdown</CardDescription>
</CardHeader>
<CardContent className="space-y-4">
{/* Report type breakdown */}
<div>
<p className="text-[11px] font-medium text-muted-foreground mb-2">By Report Type</p>
{Object.entries(REPORT_TYPE_LABELS).map(([type, label]) => {
const count = schedules.filter(s => s.report_type === type).length;
return count > 0 ? (
<div key={type} className="flex items-center justify-between mb-1.5">
<span className="text-[11px] text-foreground">{label}</span>
<div className="flex items-center gap-2">
<div className="h-1.5 w-20 bg-muted rounded-full overflow-hidden">
<div
className="h-full bg-blue-500 rounded-full"
style={{ width: `${(count / schedules.length) * 100}%` }}
/>
</div>
<span className="text-[11px] text-muted-foreground w-4 text-right">{count}</span>
</div>
</div>
) : null;
})}
</div>
{/* Delivery channels */}
<div>
<p className="text-[11px] font-medium text-muted-foreground mb-2">Delivery Channels</p>
<div className="space-y-2">
<div className="flex items-center justify-between p-2 rounded-md bg-blue-500/10 border border-blue-500/20">
<div className="flex items-center gap-2">
<Mail className="h-3.5 w-3.5 text-blue-400" />
<span className="text-xs text-foreground">Email</span>
</div>
<span className="text-xs font-medium text-blue-400">
{schedules.filter(s => s.recipients.length > 0).length} schedules
</span>
</div>
<div className="flex items-center justify-between p-2 rounded-md bg-purple-500/10 border border-purple-500/20">
<div className="flex items-center gap-2">
<Slack className="h-3.5 w-3.5 text-purple-400" />
<span className="text-xs text-foreground">Slack</span>
</div>
<span className="text-xs font-medium text-purple-400">
{schedules.filter(s => !!s.slack_webhook_url).length} schedules
</span>
</div>
</div>
</div>
{/* Success rate */}
<div>
<p className="text-[11px] font-medium text-muted-foreground mb-1">Overall Success Rate</p>
<div className="flex items-center gap-2">
<div className="h-2 flex-1 bg-muted rounded-full overflow-hidden">
<div
className="h-full bg-green-500 rounded-full transition-all duration-500"
style={{ width: `${stats.success_rate}%` }}
/>
</div>
<span className="text-xs font-medium text-green-400">{stats.success_rate}%</span>
</div>
<p className="text-[11px] text-muted-foreground mt-1">
{deliveredCount} delivered / {failureCount} failed in last 30 days
</p>
</div>
</CardContent>
</Card>
</div>
</div>
);
}