import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { DataTable } from "@/components/shared/data-table";
import {
  BookOpen, Play, Clock, CheckCircle2, AlertTriangle, Search,
  Plus, Tag, Calendar, User, Code2, Filter
} from "lucide-react";
import { playbooks as playbooksApi } from "@/lib/api";
import { toast } from "sonner";

// ── Types ──────────────────────────────────────────────────────────────────
type PlaybookStatus = "active" | "draft" | "deprecated";
type PlaybookCategory = "Triage" | "Remediation" | "Investigation" | "Escalation" | "Compliance" | "Response";
type RunStatus = "success" | "failed" | "running" | "partial";

interface Playbook {
  id: string;
  name: string;
  description: string;
  category: PlaybookCategory;
  status: PlaybookStatus;
  stepCount: number;
  lastRun?: string;
  runCount: number;
  successRate: number;
  author: string;
  tags: string[];
  version: string;
}

interface PlaybookRun {
  id: string;
  playbookName: string;
  triggeredBy: string;
  status: RunStatus;
  duration: string;
  stepsCompleted: number;
  totalSteps: number;
  startedAt: string;
  findingId?: string;
}

// ── Mock Data ──────────────────────────────────────────────────────────────
const MOCK_PLAYBOOKS: Playbook[] = [
  { id: "pb-1", name: "Critical CVE Triage", description: "Auto-triage CVSSv3 ≥9.0 findings: asset enrichment, blast radius, owner notify.", category: "Triage", status: "active", stepCount: 12, lastRun: "2h ago", runCount: 247, successRate: 96, author: "sec-platform-team", tags: ["CVE", "Auto", "CVSS"], version: "2.4.1" },
  { id: "pb-2", name: "OWASP Top 10 Response", description: "Structured response workflow for OWASP Top 10 categories with escalation paths.", category: "Response", status: "active", stepCount: 18, lastRun: "1d ago", runCount: 88, successRate: 91, author: "appsec-team", tags: ["OWASP", "Web", "Escalation"], version: "1.9.0" },
  { id: "pb-3", name: "Container Escape Containment", description: "Isolate affected pods, capture forensics, notify SRE on-call, create Jira ticket.", category: "Response", status: "active", stepCount: 14, lastRun: "3d ago", runCount: 12, successRate: 100, author: "cloud-security", tags: ["K8s", "Container", "Forensics"], version: "1.2.3" },
  { id: "pb-4", name: "Dependency Vuln Patch Cycle", description: "Open PR with bumped version, run SAST checks, assign to dep owner, SLA tracking.", category: "Remediation", status: "active", stepCount: 9, lastRun: "4h ago", runCount: 1420, successRate: 88, author: "devsec-bot", tags: ["SCA", "Dependency", "PR", "Auto"], version: "3.1.0" },
  { id: "pb-5", name: "Insider Threat Investigation", description: "DLP alert handling: user activity export, manager notify, HR escalation gate.", category: "Investigation", status: "active", stepCount: 22, lastRun: "12d ago", runCount: 5, successRate: 80, author: "dlp-team", tags: ["DLP", "HR", "Investigation"], version: "1.0.2" },
  { id: "pb-6", name: "PCI DSS Finding Response", description: "Map finding to PCI control, generate evidence, update compliance tracker.", category: "Compliance", status: "active", stepCount: 16, lastRun: "2d ago", runCount: 34, successRate: 97, author: "compliance-team", tags: ["PCI", "Compliance", "Evidence"], version: "2.0.0" },
  { id: "pb-7", name: "Secret Leak Rotation", description: "Detect exposed secrets, revoke tokens, trigger rotation pipeline, notify owners.", category: "Remediation", status: "active", stepCount: 10, lastRun: "6h ago", runCount: 63, successRate: 98, author: "secrets-mgmt", tags: ["Secrets", "Rotation", "GitOps"], version: "1.5.1" },
  { id: "pb-8", name: "Shadow IT Discovery Triage", description: "Process shadow asset findings, classify risk, assign to business owner.", category: "Triage", status: "draft", stepCount: 7, runCount: 0, successRate: 0, author: "asset-team", tags: ["ASM", "Shadow IT", "Draft"], version: "0.3.0" },
  { id: "pb-9", name: "Third-Party Risk Escalation", description: "[Deprecated] Use OWASP Top 10 Response instead.", category: "Escalation", status: "deprecated", stepCount: 8, lastRun: "90d ago", runCount: 15, successRate: 73, author: "risk-team", tags: ["Third-party", "Legacy"], version: "1.0.0" },
];

const MOCK_RUN_HISTORY: PlaybookRun[] = [
  { id: "run-1", playbookName: "Dependency Vuln Patch Cycle", triggeredBy: "Auto (SCA scan)", status: "success", duration: "4m 12s", stepsCompleted: 9, totalSteps: 9, startedAt: "2025-06-10 14:22", findingId: "FIND-8821" },
  { id: "run-2", playbookName: "Critical CVE Triage", triggeredBy: "j.kim@corp", status: "success", duration: "2m 55s", stepsCompleted: 12, totalSteps: 12, startedAt: "2025-06-10 12:01", findingId: "FIND-8801" },
  { id: "run-3", playbookName: "Secret Leak Rotation", triggeredBy: "Auto (SAST)", status: "running", duration: "1m 07s", stepsCompleted: 6, totalSteps: 10, startedAt: "2025-06-10 14:55" },
  { id: "run-4", playbookName: "OWASP Top 10 Response", triggeredBy: "a.patel@corp", status: "partial", duration: "8m 40s", stepsCompleted: 14, totalSteps: 18, startedAt: "2025-06-10 09:30", findingId: "FIND-8755" },
  { id: "run-5", playbookName: "Container Escape Containment", triggeredBy: "Auto (K8s policy)", status: "success", duration: "3m 22s", stepsCompleted: 14, totalSteps: 14, startedAt: "2025-06-09 22:14", findingId: "FIND-8700" },
  { id: "run-6", playbookName: "Critical CVE Triage", triggeredBy: "r.okafor@corp", status: "failed", duration: "1m 05s", stepsCompleted: 4, totalSteps: 12, startedAt: "2025-06-09 16:40", findingId: "FIND-8690" },
];

// ── Helpers ────────────────────────────────────────────────────────────────
const statusConfig: Record<PlaybookStatus, string> = {
  active:     "bg-green-500/10 text-green-400 border-green-500/30",
  draft:      "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
  deprecated: "bg-muted text-muted-foreground border-border",
};

const runStatusConfig: Record<RunStatus, string> = {
  success: "bg-green-500/10 text-green-400 border-green-500/30",
  failed:  "bg-red-500/10 text-red-400 border-red-500/30",
  running: "bg-blue-500/10 text-blue-400 border-blue-500/30",
  partial: "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
};

const ALL_CATEGORIES: PlaybookCategory[] = ["Triage", "Remediation", "Investigation", "Escalation", "Compliance", "Response"];

// ── Playbook Card ──────────────────────────────────────────────────────────
function PlaybookCard({ pb, onRun }: { pb: Playbook; onRun: (id: string) => void }) {
  return (
    <Card className="border-border/50 hover:border-primary/40 transition-colors flex flex-col">
      <CardHeader className="pb-2">
        <div className="flex items-start justify-between gap-2">
          <div className="flex-1">
            <div className="flex items-center gap-2 flex-wrap">
              <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-medium ${statusConfig[pb.status]}`}>{pb.status}</span>
              <span className="text-[10px] text-muted-foreground font-mono">v{pb.version}</span>
            </div>
            <CardTitle className="text-sm font-semibold mt-1.5">{pb.name}</CardTitle>
          </div>
          <Badge variant="outline" className="shrink-0 text-[10px]">{pb.category}</Badge>
        </div>
        <CardDescription className="text-xs line-clamp-2 mt-1">{pb.description}</CardDescription>
      </CardHeader>
      <CardContent className="flex-1 space-y-3">
        <div className="flex gap-3 text-xs text-muted-foreground">
          <span className="flex items-center gap-1"><Code2 className="h-3 w-3" /> {pb.stepCount} steps</span>
          <span className="flex items-center gap-1"><Play className="h-3 w-3" /> {pb.runCount} runs</span>
          {pb.successRate > 0 && <span className="flex items-center gap-1 text-green-400"><CheckCircle2 className="h-3 w-3" /> {pb.successRate}%</span>}
        </div>
        <div className="flex flex-wrap gap-1">
          {pb.tags.map(t => (
            <span key={t} className="inline-flex items-center rounded bg-muted px-1.5 py-0.5 text-[10px] font-medium text-muted-foreground">
              {t}
            </span>
          ))}
        </div>
        <div className="flex items-center justify-between pt-1">
          <div className="flex items-center gap-1 text-xs text-muted-foreground">
            <User className="h-3 w-3" />
            <span className="truncate max-w-[100px]">{pb.author}</span>
          </div>
          {pb.status !== "deprecated" && (
            <Button size="sm" variant="outline" className="h-7 text-xs" onClick={() => onRun(pb.id)}
              disabled={pb.status === "draft"}>
              <Play className="h-3 w-3 mr-1" /> Run
            </Button>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

// ── Main Component ─────────────────────────────────────────────────────────
export default function Playbooks() {
  const queryClient = useQueryClient();
  const [search, setSearch] = useState("");
  const [category, setCategory] = useState<PlaybookCategory | "All">("All");

  const { data } = useQuery({
    queryKey: ["playbooks-list"],
    queryFn: () => playbooksApi.list(),
  });

  const runMutation = useMutation({
    mutationFn: (id: string) => playbooksApi.run(id),
    onSuccess: (_, id) => {
      const pb = MOCK_PLAYBOOKS.find(p => p.id === id);
      toast.success(`Playbook launched: ${pb?.name ?? id}`);
      queryClient.invalidateQueries({ queryKey: ["playbooks-list"] });
    },
    onError: () => toast.error("Failed to run playbook"),
  });

  const items: Playbook[] = (data as any)?.data ?? MOCK_PLAYBOOKS;
  const filtered = items.filter(pb => {
    const matchSearch = pb.name.toLowerCase().includes(search.toLowerCase()) || pb.description.toLowerCase().includes(search.toLowerCase());
    const matchCat = category === "All" || pb.category === category;
    return matchSearch && matchCat;
  });

  const activeCount = items.filter(p => p.status === "active").length;
  const totalRuns = items.reduce((s, p) => s + p.runCount, 0);
  const avgSuccess = Math.round(items.filter(p => p.successRate > 0).reduce((s, p) => s + p.successRate, 0) / items.filter(p => p.successRate > 0).length);

  const runColumns = [
    { key: "playbookName", header: "Playbook" },
    { key: "triggeredBy", header: "Triggered By" },
    {
      key: "status", header: "Status",
      render: (r: PlaybookRun) => <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${runStatusConfig[r.status]}`}>{r.status}</span>,
    },
    {
      key: "stepsCompleted", header: "Progress",
      render: (r: PlaybookRun) => (
        <div className="flex items-center gap-2">
          <div className="h-1.5 w-16 rounded-full bg-muted">
            <div className="h-1.5 rounded-full bg-primary" style={{ width: `${(r.stepsCompleted / r.totalSteps) * 100}%` }} />
          </div>
          <span className="text-xs text-muted-foreground">{r.stepsCompleted}/{r.totalSteps}</span>
        </div>
      ),
    },
    { key: "duration", header: "Duration" },
    { key: "findingId", header: "Finding", render: (r: PlaybookRun) => r.findingId ? <span className="font-mono text-xs text-primary">{r.findingId}</span> : <span className="text-muted-foreground text-xs">—</span> },
    { key: "startedAt", header: "Started" },
  ];

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="space-y-6">
      <PageHeader
        title="Playbooks"
        description="YAML playbook library — browse, filter, and one-click run security automation playbooks"
        badge="VALIDATE"
        actions={
          <Button size="sm">
            <Plus className="h-3.5 w-3.5 mr-1.5" /> New Playbook
          </Button>
        }
      />

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Active Playbooks" value={activeCount} icon={BookOpen} trend="up" change={3} changeLabel="this quarter" />
        <KpiCard title="Total Runs" value={totalRuns} icon={Play} trend="up" change={22} changeLabel="this month" />
        <KpiCard title="Avg Success Rate" value={`${avgSuccess}%`} icon={CheckCircle2} trend="up" change={2} changeLabel="vs last month" />
        <KpiCard title="Automated" value="78%" icon={Tag} trend="up" change={12} changeLabel="of runs" />
      </div>

      <Tabs defaultValue="library">
        <TabsList>
          <TabsTrigger value="library">Library</TabsTrigger>
          <TabsTrigger value="history">Execution History</TabsTrigger>
        </TabsList>

        <TabsContent value="library" className="mt-4 space-y-4">
          {/* Filter bar */}
          <div className="flex flex-wrap gap-3 items-center">
            <div className="relative flex-1 min-w-[200px]">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
              <Input
                placeholder="Search playbooks..."
                className="pl-8 text-sm h-8"
                value={search}
                onChange={e => setSearch(e.target.value)}
              />
            </div>
            <div className="flex gap-1.5 flex-wrap">
              {(["All", ...ALL_CATEGORIES] as const).map(cat => (
                <Button
                  key={cat}
                  size="sm"
                  variant={category === cat ? "default" : "outline"}
                  className="h-7 text-xs"
                  onClick={() => setCategory(cat)}
                >
                  {cat}
                </Button>
              ))}
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
            {filtered.map(pb => (
              <PlaybookCard key={pb.id} pb={pb} onRun={id => runMutation.mutate(id)} />
            ))}
            {filtered.length === 0 && (
              <div className="col-span-3 py-16 text-center text-sm text-muted-foreground">
                No playbooks match your filters
              </div>
            )}
          </div>
        </TabsContent>

        <TabsContent value="history" className="mt-4">
          <DataTable
            columns={runColumns}
            data={MOCK_RUN_HISTORY}
            emptyMessage="No runs recorded"
          />
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
