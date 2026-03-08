import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectTrigger, SelectContent, SelectItem, SelectValue } from "@/components/ui/select";
import { Progress } from "@/components/ui/progress";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import {
  Search, Filter, Clock, AlertTriangle, CheckCircle2, ArrowRight,
  User, Users, SlidersHorizontal, ChevronDown, ClipboardCheck
} from "lucide-react";
import { remediationApi } from "@/lib/api";
import { toast } from "sonner";

// ── Types ──────────────────────────────────────────────────────────────────
type TaskStatus = "Open" | "In Progress" | "In Review" | "Fixed" | "Verified";
type SeverityType = "Critical" | "High" | "Medium" | "Low";
type SlaStatus = "Breached" | "At Risk" | "On Track";

interface RemediationTask {
  id: string;
  title: string;
  findingId: string;
  severity: SeverityType;
  status: TaskStatus;
  assignee: string;
  assigneeInitials: string;
  assigneeColor: string;
  team: string;
  slaDeadline: string;
  slaRemaining: string;
  slaStatus: SlaStatus;
  component: string;
  cveId?: string;
  createdAt: string;
  selected?: boolean;
}

// ── Mock Data ──────────────────────────────────────────────────────────────
const MOCK_TASKS: RemediationTask[] = [
  { id: "rt-1",  title: "Patch Apache Log4Shell in logging-service",       findingId: "FIND-8821", severity: "Critical", status: "In Progress", assignee: "Sophia Chen",    assigneeInitials: "SC", assigneeColor: "bg-purple-500", team: "Platform",        slaDeadline: "2025-06-11 EOD", slaRemaining: "8h",   slaStatus: "At Risk",  component: "logging-service",  cveId: "CVE-2021-44228", createdAt: "2025-06-08" },
  { id: "rt-2",  title: "Remediate SSRF in payment-svc",                   findingId: "FIND-8801", severity: "Critical", status: "Open",        assignee: "Arjun Patel",    assigneeInitials: "AP", assigneeColor: "bg-blue-500",   team: "Backend",         slaDeadline: "2025-06-12 EOD", slaRemaining: "1d 8h", slaStatus: "On Track", component: "payment-svc",      cveId: "CVE-2022-9876",  createdAt: "2025-06-09" },
  { id: "rt-3",  title: "Remove cleartext FTP endpoint",                   findingId: "FIND-8755", severity: "Critical", status: "In Review",   assignee: "Rachel Okafor",  assigneeInitials: "RO", assigneeColor: "bg-green-500",  team: "Ops",             slaDeadline: "2025-06-10 EOD", slaRemaining: "2h",   slaStatus: "Breached", component: "files.corp.com",                    createdAt: "2025-06-07" },
  { id: "rt-4",  title: "Rotate exposed GitHub token",                     findingId: "FIND-8700", severity: "High",     status: "Fixed",       assignee: "James Kim",      assigneeInitials: "JK", assigneeColor: "bg-orange-500", team: "DevSec",          slaDeadline: "2025-06-13 EOD", slaRemaining: "3d",   slaStatus: "On Track", component: "ci-pipeline",                       createdAt: "2025-06-09" },
  { id: "rt-5",  title: "Upgrade Spring Boot in api-gateway (CVE-2022-22965)", findingId: "FIND-8690", severity: "High", status: "In Progress", assignee: "Sophia Chen",    assigneeInitials: "SC", assigneeColor: "bg-purple-500", team: "Platform",        slaDeadline: "2025-06-12 EOD", slaRemaining: "1d",   slaStatus: "On Track", component: "api-gateway",      cveId: "CVE-2022-22965", createdAt: "2025-06-09" },
  { id: "rt-6",  title: "Disable Prometheus unauthenticated endpoint",     findingId: "FIND-8622", severity: "High",     status: "Open",        assignee: "Lena Müller",    assigneeInitials: "LM", assigneeColor: "bg-teal-500",   team: "Ops",             slaDeadline: "2025-06-14 EOD", slaRemaining: "3d",   slaStatus: "On Track", component: "metrics.corp.com",                  createdAt: "2025-06-10" },
  { id: "rt-7",  title: "Patch Jenkins CVE-2023-27898",                    findingId: "FIND-8601", severity: "High",     status: "Verified",    assignee: "Arjun Patel",    assigneeInitials: "AP", assigneeColor: "bg-blue-500",   team: "DevSec",          slaDeadline: "2025-06-09 EOD", slaRemaining: "Done", slaStatus: "On Track", component: "ci.corp.com",      cveId: "CVE-2023-27898", createdAt: "2025-06-06" },
  { id: "rt-8",  title: "Enable TLS on mail-relay SMTP",                   findingId: "FIND-8589", severity: "Medium",   status: "Open",        assignee: "Rachel Okafor",  assigneeInitials: "RO", assigneeColor: "bg-green-500",  team: "Ops",             slaDeadline: "2025-06-17 EOD", slaRemaining: "7d",   slaStatus: "On Track", component: "mail.corp.com",                     createdAt: "2025-06-10" },
  { id: "rt-9",  title: "Update npm lodash to latest (RCE fix)",           findingId: "FIND-8540", severity: "Medium",   status: "In Progress", assignee: "James Kim",      assigneeInitials: "JK", assigneeColor: "bg-orange-500", team: "Frontend",        slaDeadline: "2025-06-15 EOD", slaRemaining: "5d",   slaStatus: "On Track", component: "web-app-frontend",                  createdAt: "2025-06-08" },
  { id: "rt-10", title: "Remove debug endpoints from admin portal",        findingId: "FIND-8501", severity: "Medium",   status: "In Review",   assignee: "Lena Müller",    assigneeInitials: "LM", assigneeColor: "bg-teal-500",   team: "Backend",         slaDeadline: "2025-06-13 EOD", slaRemaining: "3d",   slaStatus: "On Track", component: "admin-portal",                      createdAt: "2025-06-07" },
  { id: "rt-11", title: "Fix insecure deserialization in message-broker",  findingId: "FIND-8470", severity: "Critical", status: "Open",        assignee: "Unassigned",     assigneeInitials: "?", assigneeColor: "bg-muted",      team: "Platform",        slaDeadline: "2025-06-11 EOD", slaRemaining: "6h",   slaStatus: "Breached", component: "message-broker",   cveId: "CVE-2023-5432",  createdAt: "2025-06-07" },
  { id: "rt-12", title: "Enforce CSP headers on customer portal",          findingId: "FIND-8401", severity: "Low",      status: "Fixed",       assignee: "Sophia Chen",    assigneeInitials: "SC", assigneeColor: "bg-purple-500", team: "Frontend",        slaDeadline: "2025-06-20 EOD", slaRemaining: "Done", slaStatus: "On Track", component: "customer-portal",                   createdAt: "2025-06-05" },
];

const STATUS_WORKFLOW: TaskStatus[] = ["Open", "In Progress", "In Review", "Fixed", "Verified"];

const severityConfig: Record<SeverityType, string> = {
  Critical: "bg-red-500/10 text-red-400 border-red-500/30",
  High:     "bg-orange-500/10 text-orange-400 border-orange-500/30",
  Medium:   "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
  Low:      "bg-blue-500/10 text-blue-400 border-blue-500/30",
};

const statusConfig: Record<TaskStatus, string> = {
  "Open":        "bg-muted text-muted-foreground border-border",
  "In Progress": "bg-blue-500/10 text-blue-400 border-blue-500/30",
  "In Review":   "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
  "Fixed":       "bg-green-500/10 text-green-400 border-green-500/30",
  "Verified":    "bg-primary/10 text-primary border-primary/30",
};

const slaConfig: Record<SlaStatus, string> = {
  Breached: "text-red-400",
  "At Risk": "text-orange-400",
  "On Track": "text-green-400",
};

// ── Task Row ───────────────────────────────────────────────────────────────
function TaskRow({ task, selected, onSelect, onStatusChange }: {
  task: RemediationTask;
  selected: boolean;
  onSelect: (id: string) => void;
  onStatusChange: (id: string, status: TaskStatus) => void;
}) {
  const currentIdx = STATUS_WORKFLOW.indexOf(task.status);
  return (
    <tr className="border-b border-border/50 hover:bg-muted/20 transition-colors group">
      <td className="p-3">
        <input type="checkbox" checked={selected} onChange={() => onSelect(task.id)} className="rounded accent-primary" />
      </td>
      <td className="p-3">
        <div>
          <p className="text-sm font-medium line-clamp-1">{task.title}</p>
          <p className="text-xs text-muted-foreground font-mono mt-0.5">{task.findingId} {task.cveId && `· ${task.cveId}`}</p>
        </div>
      </td>
      <td className="p-3">
        <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${severityConfig[task.severity]}`}>{task.severity}</span>
      </td>
      <td className="p-3">
        <div className="flex items-center gap-1.5">
          <div className={`h-6 w-6 rounded-full ${task.assigneeColor} flex items-center justify-center text-white text-[10px] font-bold shrink-0`}>
            {task.assigneeInitials}
          </div>
          <span className="text-xs text-muted-foreground">{task.assignee}</span>
        </div>
      </td>
      <td className="p-3">
        <span className="text-xs text-muted-foreground">{task.team}</span>
      </td>
      <td className="p-3">
        <Select value={task.status} onValueChange={(v) => onStatusChange(task.id, v as TaskStatus)}>
          <SelectTrigger className="h-7 text-xs border-0 bg-transparent p-0 gap-1 w-auto focus:ring-0">
            <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${statusConfig[task.status]}`}>{task.status}</span>
            <ChevronDown className="h-3 w-3 text-muted-foreground" />
          </SelectTrigger>
          <SelectContent>
            {STATUS_WORKFLOW.map(s => <SelectItem key={s} value={s}>{s}</SelectItem>)}
          </SelectContent>
        </Select>
      </td>
      <td className="p-3">
        <div>
          <p className={`text-xs font-medium ${slaConfig[task.slaStatus]}`}>{task.slaRemaining}</p>
          <p className="text-[10px] text-muted-foreground">{task.slaDeadline}</p>
        </div>
      </td>
      <td className="p-3">
        <div className="flex items-center gap-1">
          {STATUS_WORKFLOW.map((s, i) => (
            <div key={s} className={`h-1.5 w-4 rounded-full transition-colors ${i <= currentIdx ? "bg-primary" : "bg-muted"}`} />
          ))}
        </div>
      </td>
    </tr>
  );
}

// ── Main Component ─────────────────────────────────────────────────────────
export default function RemediationCenter() {
  const queryClient = useQueryClient();
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("All");
  const [teamFilter, setTeamFilter] = useState("All");
  const [slaFilter, setSlaFilter] = useState("All");
  const [statusFilter, setStatusFilter] = useState("All");

  const { data } = useQuery({
    queryKey: ["remediation-tasks", { severity: severityFilter, team: teamFilter }],
    queryFn: () => remediationApi.list({ severity: severityFilter !== "All" ? severityFilter : undefined }),
  });

  const updateMutation = useMutation({
    mutationFn: ({ id, status }: { id: string; status: string }) => remediationApi.update(id, { status }),
    onSuccess: () => { toast.success("Status updated"); queryClient.invalidateQueries({ queryKey: ["remediation-tasks"] }); },
    onError: () => toast.error("Update failed"),
  });

  const tasks: RemediationTask[] = (data as any)?.data ?? MOCK_TASKS;

  const filtered = tasks.filter(t => {
    const matchSearch = t.title.toLowerCase().includes(search.toLowerCase()) || t.findingId.toLowerCase().includes(search.toLowerCase());
    const matchSev = severityFilter === "All" || t.severity === severityFilter;
    const matchTeam = teamFilter === "All" || t.team === teamFilter;
    const matchSla = slaFilter === "All" || t.slaStatus === slaFilter;
    const matchStatus = statusFilter === "All" || t.status === statusFilter;
    return matchSearch && matchSev && matchTeam && matchSla && matchStatus;
  });

  const allSelected = filtered.length > 0 && filtered.every(t => selected.has(t.id));
  const toggleAll = () => {
    if (allSelected) setSelected(new Set());
    else setSelected(new Set(filtered.map(t => t.id)));
  };

  const openCount    = tasks.filter(t => t.status === "Open").length;
  const criticalOpen = tasks.filter(t => t.severity === "Critical" && t.status !== "Verified" && t.status !== "Fixed").length;
  const slaBreached  = tasks.filter(t => t.slaStatus === "Breached").length;
  const verifiedCount = tasks.filter(t => t.status === "Verified").length;

  const teams = ["All", ...Array.from(new Set(tasks.map(t => t.team)))];

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="space-y-6">
      <PageHeader
        title="Remediation Center"
        description="Track, assign, and drive all remediation tasks from open to verified"
        badge="REMEDIATE"
        actions={
          selected.size > 0 ? (
            <Button size="sm" variant="outline" onClick={() => toast.info(`${selected.size} tasks selected for bulk action`)}>
              Bulk Actions ({selected.size})
            </Button>
          ) : undefined
        }
      />

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Open Tasks" value={openCount} icon={ClipboardCheck} trend="down" change={-8} changeLabel="vs last week" />
        <KpiCard title="Critical Open" value={criticalOpen} icon={AlertTriangle} trend="down" change={-2} changeLabel="vs last week" />
        <KpiCard title="SLA Breached" value={slaBreached} icon={Clock} trend="down" change={-1} changeLabel="vs yesterday" />
        <KpiCard title="Verified Fixed" value={verifiedCount} icon={CheckCircle2} trend="up" change={14} changeLabel="this sprint" />
      </div>

      {/* Filter Bar */}
      <Card className="border-border/50">
        <CardContent className="p-3">
          <div className="flex flex-wrap gap-3 items-center">
            <div className="relative flex-1 min-w-[220px]">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
              <Input placeholder="Search tasks, findings..." className="pl-8 text-sm h-8" value={search} onChange={e => setSearch(e.target.value)} />
            </div>
            <Select value={severityFilter} onValueChange={setSeverityFilter}>
              <SelectTrigger className="w-32 h-8 text-xs"><SelectValue placeholder="Severity" /></SelectTrigger>
              <SelectContent>
                <SelectItem value="All">All Severities</SelectItem>
                {["Critical","High","Medium","Low"].map(s => <SelectItem key={s} value={s}>{s}</SelectItem>)}
              </SelectContent>
            </Select>
            <Select value={teamFilter} onValueChange={setTeamFilter}>
              <SelectTrigger className="w-32 h-8 text-xs"><SelectValue placeholder="Team" /></SelectTrigger>
              <SelectContent>
                {teams.map(t => <SelectItem key={t} value={t}>{t}</SelectItem>)}
              </SelectContent>
            </Select>
            <Select value={slaFilter} onValueChange={setSlaFilter}>
              <SelectTrigger className="w-32 h-8 text-xs"><SelectValue placeholder="SLA" /></SelectTrigger>
              <SelectContent>
                <SelectItem value="All">All SLA</SelectItem>
                {["Breached","At Risk","On Track"].map(s => <SelectItem key={s} value={s}>{s}</SelectItem>)}
              </SelectContent>
            </Select>
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="w-32 h-8 text-xs"><SelectValue placeholder="Status" /></SelectTrigger>
              <SelectContent>
                <SelectItem value="All">All Status</SelectItem>
                {STATUS_WORKFLOW.map(s => <SelectItem key={s} value={s}>{s}</SelectItem>)}
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      {/* Tasks Table */}
      <Card className="border-border/50 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-border/50 bg-muted/30">
                <th className="p-3 w-8">
                  <input type="checkbox" checked={allSelected} onChange={toggleAll} className="rounded accent-primary" />
                </th>
                <th className="p-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">Task</th>
                <th className="p-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">Severity</th>
                <th className="p-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">Assignee</th>
                <th className="p-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">Team</th>
                <th className="p-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">Status</th>
                <th className="p-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">SLA</th>
                <th className="p-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">Progress</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(task => (
                <TaskRow
                  key={task.id}
                  task={task}
                  selected={selected.has(task.id)}
                  onSelect={id => setSelected(prev => { const n = new Set(prev); n.has(id) ? n.delete(id) : n.add(id); return n; })}
                  onStatusChange={(id, status) => updateMutation.mutate({ id, status })}
                />
              ))}
              {filtered.length === 0 && (
                <tr><td colSpan={8} className="p-12 text-center text-sm text-muted-foreground">No tasks match your filters</td></tr>
              )}
            </tbody>
          </table>
        </div>
        <div className="px-3 py-2 border-t border-border/50 bg-muted/10 text-xs text-muted-foreground">
          {filtered.length} of {tasks.length} tasks · {selected.size} selected
        </div>
      </Card>
    </motion.div>
  );
}
