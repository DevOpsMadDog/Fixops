import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectTrigger, SelectContent, SelectItem, SelectValue } from "@/components/ui/select";
import { Progress } from "@/components/ui/progress";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import {
  CheckSquare, Filter, Download, UserCheck, Tag, ArrowRight,
  AlertTriangle, CheckCircle2, X, Search, ChevronDown, Users, Layers
} from "lucide-react";
import { findingsApi, remediationApi } from "@/lib/api";
import { toast } from "sonner";

// ── Types ──────────────────────────────────────────────────────────────────
type BulkAction = "triage" | "assign" | "status_change" | "export";

interface BulkFinding {
  id: string;
  title: string;
  severity: "Critical" | "High" | "Medium" | "Low";
  status: string;
  component: string;
  team: string;
  assignee?: string;
  cveId?: string;
  age: string;
}

// ── Mock Data ──────────────────────────────────────────────────────────────
const MOCK_FINDINGS: BulkFinding[] = [
  { id: "FIND-8901", title: "RCE via unsafe deserialization in order-svc",     severity: "Critical", status: "New",         component: "order-svc",         team: "Backend",  cveId: "CVE-2023-44487", age: "1h" },
  { id: "FIND-8900", title: "SQL injection in user search endpoint",            severity: "Critical", status: "New",         component: "user-api",          team: "Backend",  cveId: "CVE-2023-1234",  age: "2h" },
  { id: "FIND-8898", title: "SSRF via webhook URL parameter",                   severity: "High",     status: "New",         component: "integration-hub",   team: "Platform", cveId: "CVE-2022-9876",  age: "3h" },
  { id: "FIND-8895", title: "XSS stored in comment field",                      severity: "High",     status: "Triaged",     component: "customer-portal",   team: "Frontend",                          age: "5h" },
  { id: "FIND-8890", title: "Hardcoded AWS credentials in S3 client",           severity: "Critical", status: "New",         component: "data-pipeline",     team: "Data",                              age: "6h" },
  { id: "FIND-8885", title: "Path traversal in file upload handler",            severity: "High",     status: "New",         component: "media-svc",         team: "Backend",                           age: "8h" },
  { id: "FIND-8880", title: "Outdated openssl with CVE-2023-0215",              severity: "Medium",   status: "New",         component: "infra-base-image",  team: "Ops",      cveId: "CVE-2023-0215",  age: "10h" },
  { id: "FIND-8875", title: "Missing HSTS header on API subdomain",             severity: "Medium",   status: "New",         component: "api.corp.com",      team: "Ops",                               age: "12h" },
  { id: "FIND-8870", title: "Insecure cookie flags on auth tokens",             severity: "Medium",   status: "Triaged",     component: "auth-service",      team: "Backend",  assignee: "s.chen@corp", age: "1d" },
  { id: "FIND-8865", title: "Open redirect in login callback",                  severity: "Low",      status: "New",         component: "sso.corp.com",      team: "Backend",                           age: "1d" },
  { id: "FIND-8860", title: "CSP header missing img-src restriction",           severity: "Low",      status: "New",         component: "customer-portal",   team: "Frontend",                          age: "2d" },
  { id: "FIND-8855", title: "Verbose error messages leak stack traces",         severity: "Low",      status: "New",         component: "api-gateway",       team: "Platform",                          age: "2d" },
  { id: "FIND-8850", title: "Dependency: npm minimist < 1.2.6",                severity: "High",     status: "New",         component: "web-app-frontend",  team: "Frontend", cveId: "CVE-2021-44906", age: "3d" },
  { id: "FIND-8845", title: "JWT algorithm confusion (none attack surface)",    severity: "Critical", status: "New",         component: "auth-service",      team: "Backend",                           age: "3d" },
  { id: "FIND-8840", title: "Redis instance exposed without auth",              severity: "High",     status: "New",         component: "cache.corp.internal",team: "Ops",                              age: "4d" },
];

const TEAMS = ["Backend", "Frontend", "Platform", "Ops", "Data", "DevSec"];

const severityConfig: Record<string, string> = {
  Critical: "bg-red-500/10 text-red-400 border-red-500/30",
  High:     "bg-orange-500/10 text-orange-400 border-orange-500/30",
  Medium:   "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
  Low:      "bg-blue-500/10 text-blue-400 border-blue-500/30",
};

// ── Confirmation Dialog ────────────────────────────────────────────────────
function ConfirmDialog({
  action, selectedCount, value, onConfirm, onCancel
}: {
  action: BulkAction; selectedCount: number; value: string;
  onConfirm: () => void; onCancel: () => void;
}) {
  const labels: Record<BulkAction, string> = {
    triage: "Triage",
    assign: "Assign",
    status_change: "Status Change",
    export: "Export",
  };
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <motion.div initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} className="w-full max-w-sm">
        <Card className="border-border/50">
          <CardHeader>
            <CardTitle className="text-base">Confirm Bulk {labels[action]}</CardTitle>
            <CardDescription className="text-sm">
              Apply <strong>{labels[action]}: {value}</strong> to <strong>{selectedCount}</strong> selected finding{selectedCount !== 1 ? "s" : ""}.
              This action cannot be undone.
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex gap-2 justify-end">
              <Button variant="outline" size="sm" onClick={onCancel}>Cancel</Button>
              <Button size="sm" onClick={onConfirm}>
                <CheckCircle2 className="h-3.5 w-3.5 mr-1.5" /> Confirm
              </Button>
            </div>
          </CardContent>
        </Card>
      </motion.div>
    </div>
  );
}

// ── Main Component ─────────────────────────────────────────────────────────
export default function BulkOperations() {
  const queryClient = useQueryClient();
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("All");
  const [statusFilter, setStatusFilter] = useState("All");
  const [bulkAction, setBulkAction] = useState<BulkAction>("triage");
  const [bulkValue, setBulkValue] = useState("");
  const [showConfirm, setShowConfirm] = useState(false);
  const [isExecuting, setIsExecuting] = useState(false);
  const [progress, setProgress] = useState(0);

  const { data } = useQuery({
    queryKey: ["bulk-findings"],
    queryFn: () => findingsApi.list({ limit: 50 }),
  });

  const bulkAssignMutation = useMutation({
    mutationFn: (data: unknown) => remediationApi.bulkAssign(data),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["bulk-findings"] }),
  });

  const bulkTriageMutation = useMutation({
    mutationFn: ({ ids, action }: { ids: string[]; action: string }) =>
      findingsApi.bulkTriage(ids, action),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ["bulk-findings"] }),
  });

  const findings: BulkFinding[] = (data as any)?.data ?? MOCK_FINDINGS;

  const filtered = findings.filter(f => {
    const matchSearch = f.title.toLowerCase().includes(search.toLowerCase()) || f.id.toLowerCase().includes(search.toLowerCase());
    const matchSev = severityFilter === "All" || f.severity === severityFilter;
    const matchStatus = statusFilter === "All" || f.status === statusFilter;
    return matchSearch && matchSev && matchStatus;
  });

  const allSelected = filtered.length > 0 && filtered.every(f => selected.has(f.id));
  const toggleAll = () => allSelected ? setSelected(new Set()) : setSelected(new Set(filtered.map(f => f.id)));

  const selectedItems = findings.filter(f => selected.has(f.id));
  const bySeverity = {
    Critical: selectedItems.filter(f => f.severity === "Critical").length,
    High:     selectedItems.filter(f => f.severity === "High").length,
    Medium:   selectedItems.filter(f => f.severity === "Medium").length,
    Low:      selectedItems.filter(f => f.severity === "Low").length,
  };

  const executeAction = async () => {
    setShowConfirm(false);
    setIsExecuting(true);
    setProgress(0);

    // Simulate progress
    const interval = setInterval(() => {
      setProgress(p => Math.min(p + 15, 90));
    }, 200);

    try {
      if (bulkAction === "triage") {
        await bulkTriageMutation.mutateAsync({ ids: Array.from(selected), action: bulkValue });
      } else if (bulkAction === "assign") {
        await bulkAssignMutation.mutateAsync({ finding_ids: Array.from(selected), assignee: bulkValue });
      }
      setProgress(100);
      toast.success(`Bulk ${bulkAction} applied to ${selected.size} findings`);
      setSelected(new Set());
      setBulkValue("");
    } catch {
      toast.error(`Bulk ${bulkAction} failed — some items may be unchanged`);
    } finally {
      clearInterval(interval);
      setTimeout(() => { setIsExecuting(false); setProgress(0); }, 1000);
    }
  };

  const newCount     = findings.filter(f => f.status === "New").length;
  const criticalNew  = findings.filter(f => f.severity === "Critical" && f.status === "New").length;

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="space-y-6">
      {showConfirm && (
        <ConfirmDialog
          action={bulkAction}
          selectedCount={selected.size}
          value={bulkValue}
          onConfirm={executeAction}
          onCancel={() => setShowConfirm(false)}
        />
      )}

      <PageHeader
        title="Bulk Operations"
        description="Mass triage, assign, and status change across hundreds of findings simultaneously"
        badge="REMEDIATE"
      />

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Total Findings" value={findings.length} icon={Layers} trend="down" change={-12} changeLabel="vs last week" />
        <KpiCard title="New / Untriaged" value={newCount} icon={AlertTriangle} trend="down" change={-8} changeLabel="vs last week" />
        <KpiCard title="Critical New" value={criticalNew} icon={CheckSquare} trend="down" change={-2} changeLabel="vs yesterday" />
        <KpiCard title="Selected" value={selected.size} icon={Users} trend="flat" />
      </div>

      {/* Bulk Action Bar */}
      {selected.size > 0 && (
        <motion.div initial={{ opacity: 0, y: -8 }} animate={{ opacity: 1, y: 0 }}>
          <Card className="border-primary/40 bg-primary/5">
            <CardContent className="p-4">
              <div className="flex flex-wrap items-center gap-4">
                {/* Selection summary */}
                <div className="flex items-center gap-2">
                  <CheckSquare className="h-4 w-4 text-primary" />
                  <span className="text-sm font-semibold">{selected.size} selected</span>
                  <div className="flex gap-1.5">
                    {(["Critical","High","Medium","Low"] as const).filter(s => bySeverity[s] > 0).map(s => (
                      <span key={s} className={`inline-flex items-center rounded-full border px-1.5 py-0.5 text-[10px] font-medium ${severityConfig[s]}`}>
                        {bySeverity[s]} {s}
                      </span>
                    ))}
                  </div>
                </div>
                <div className="flex flex-1 flex-wrap gap-2 items-center">
                  <Select value={bulkAction} onValueChange={v => { setBulkAction(v as BulkAction); setBulkValue(""); }}>
                    <SelectTrigger className="w-40 h-8 text-xs"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="triage">Triage</SelectItem>
                      <SelectItem value="assign">Assign</SelectItem>
                      <SelectItem value="status_change">Status Change</SelectItem>
                      <SelectItem value="export">Export</SelectItem>
                    </SelectContent>
                  </Select>
                  {bulkAction === "triage" && (
                    <Select value={bulkValue} onValueChange={setBulkValue}>
                      <SelectTrigger className="w-40 h-8 text-xs"><SelectValue placeholder="Select action..." /></SelectTrigger>
                      <SelectContent>
                        {["accept_risk","false_positive","duplicate","prioritize","defer_30d"].map(a => <SelectItem key={a} value={a}>{a}</SelectItem>)}
                      </SelectContent>
                    </Select>
                  )}
                  {bulkAction === "assign" && (
                    <Select value={bulkValue} onValueChange={setBulkValue}>
                      <SelectTrigger className="w-40 h-8 text-xs"><SelectValue placeholder="Select team..." /></SelectTrigger>
                      <SelectContent>
                        {TEAMS.map(t => <SelectItem key={t} value={t}>{t}</SelectItem>)}
                      </SelectContent>
                    </Select>
                  )}
                  {bulkAction === "status_change" && (
                    <Select value={bulkValue} onValueChange={setBulkValue}>
                      <SelectTrigger className="w-40 h-8 text-xs"><SelectValue placeholder="Select status..." /></SelectTrigger>
                      <SelectContent>
                        {["Open","In Progress","In Review","Fixed"].map(s => <SelectItem key={s} value={s}>{s}</SelectItem>)}
                      </SelectContent>
                    </Select>
                  )}
                  {bulkAction === "export" && <span className="text-xs text-muted-foreground">Export to CSV/JSON</span>}
                  <Button
                    size="sm" className="h-8"
                    disabled={bulkAction !== "export" && !bulkValue}
                    onClick={() => bulkAction === "export" ? toast.success("Export queued") : setShowConfirm(true)}
                  >
                    {bulkAction === "export" ? <Download className="h-3.5 w-3.5 mr-1.5" /> : <ArrowRight className="h-3.5 w-3.5 mr-1.5" />}
                    Apply
                  </Button>
                </div>
                <Button size="sm" variant="ghost" className="h-7 w-7 p-0 text-muted-foreground" onClick={() => setSelected(new Set())}>
                  <X className="h-3.5 w-3.5" />
                </Button>
              </div>
              {isExecuting && (
                <div className="mt-3 space-y-1">
                  <Progress value={progress} className="h-1.5" />
                  <p className="text-xs text-muted-foreground">Processing {selected.size} findings... {progress}%</p>
                </div>
              )}
            </CardContent>
          </Card>
        </motion.div>
      )}

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
          <Input placeholder="Search findings..." className="pl-8 h-8 text-sm" value={search} onChange={e => setSearch(e.target.value)} />
        </div>
        <Select value={severityFilter} onValueChange={setSeverityFilter}>
          <SelectTrigger className="w-36 h-8 text-xs"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="All">All Severities</SelectItem>
            {["Critical","High","Medium","Low"].map(s => <SelectItem key={s} value={s}>{s}</SelectItem>)}
          </SelectContent>
        </Select>
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-32 h-8 text-xs"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="All">All Status</SelectItem>
            {["New","Triaged","In Progress","Fixed"].map(s => <SelectItem key={s} value={s}>{s}</SelectItem>)}
          </SelectContent>
        </Select>
      </div>

      {/* Findings Table */}
      <Card className="border-border/50 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-border/50 bg-muted/30">
                <th className="p-3 w-8">
                  <input type="checkbox" checked={allSelected} onChange={toggleAll} className="rounded accent-primary" />
                </th>
                <th className="p-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">Finding</th>
                <th className="p-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">Severity</th>
                <th className="p-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">Component</th>
                <th className="p-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">Team</th>
                <th className="p-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">Status</th>
                <th className="p-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">Age</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(f => (
                <tr key={f.id} className={`border-b border-border/50 hover:bg-muted/10 transition-colors ${selected.has(f.id) ? "bg-primary/5" : ""}`}>
                  <td className="p-3">
                    <input type="checkbox" checked={selected.has(f.id)} onChange={() => {
                      setSelected(prev => { const n = new Set(prev); n.has(f.id) ? n.delete(f.id) : n.add(f.id); return n; });
                    }} className="rounded accent-primary" />
                  </td>
                  <td className="p-3">
                    <p className="text-sm font-medium line-clamp-1">{f.title}</p>
                    <p className="text-xs text-muted-foreground font-mono mt-0.5">{f.id} {f.cveId && `· ${f.cveId}`}</p>
                  </td>
                  <td className="p-3">
                    <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${severityConfig[f.severity]}`}>{f.severity}</span>
                  </td>
                  <td className="p-3 text-xs text-muted-foreground font-mono">{f.component}</td>
                  <td className="p-3 text-xs text-muted-foreground">{f.team}</td>
                  <td className="p-3"><Badge variant="outline" className="text-xs">{f.status}</Badge></td>
                  <td className="p-3 text-xs text-muted-foreground">{f.age}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        <div className="px-3 py-2 border-t border-border/50 bg-muted/10 text-xs text-muted-foreground">
          {filtered.length} of {findings.length} findings · {selected.size} selected
        </div>
      </Card>
    </motion.div>
  );
}
