import { useState, useCallback } from "react";
import { toArray } from "@/lib/api-utils";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Checkbox } from "@/components/ui/checkbox";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { motion } from "framer-motion";
import {
  Wand2,
  CheckCircle,
  XCircle,
  Clock,
  Code,
  GitPullRequest,
  Play,
  Search,
  ChevronDown,
  ChevronUp,
  TrendingUp,
  AlertTriangle,
  Zap,
} from "lucide-react";
import { useRemediationTasks, useAutofix } from "@/hooks/use-api";
import { autofixApi } from "@/lib/api";
import { cn } from "@/lib/utils";
import { toast } from "sonner";

const FIX_TYPE_CONFIG = {
  AST: { label: "AST Transform", color: "#6366f1", description: "Abstract Syntax Tree-based fix" },
  Pattern: { label: "Pattern Match", color: "#8b5cf6", description: "Regex/pattern-based fix" },
  AI: { label: "AI Generated", color: "#3b82f6", description: "LLM-generated fix" },
  Manual: { label: "Manual", color: "#6b7280", description: "Human-written fix" },
};

const AUTOFIX_STATUS = {
  pending_review: { label: "Pending Review", variant: "outline" as const, color: "#f59e0b" },
  approved: { label: "Approved", variant: "secondary" as const, color: "#22c55e" },
  applied: { label: "Applied", variant: "secondary" as const, color: "#22c55e" },
  rejected: { label: "Rejected", variant: "destructive" as const, color: "#ef4444" },
  failed: { label: "Failed", variant: "destructive" as const, color: "#ef4444" },
  generating: { label: "Generating", variant: "default" as const, color: "#3b82f6" },
};

function FixTypeBadge({ fixType }: { fixType: string }) {
  const cfg = FIX_TYPE_CONFIG[fixType as keyof typeof FIX_TYPE_CONFIG] ?? {
    label: fixType,
    color: "#6b7280",
  };
  return (
    <Badge variant="outline" style={{ borderColor: cfg.color + "44", color: cfg.color }}>
      {cfg.label}
    </Badge>
  );
}

function StatusBadge({ status }: { status: string }) {
  const cfg = AUTOFIX_STATUS[status as keyof typeof AUTOFIX_STATUS] ?? {
    label: status,
    variant: "outline" as const,
  };
  return <Badge variant={cfg.variant}>{cfg.label}</Badge>;
}

function CodeDiffView({
  before,
  after,
  language,
}: {
  before: string;
  after: string;
  language: string;
}) {
  return (
    <div className="space-y-3">
      <div>
        <div className="flex items-center gap-2 mb-1">
          <div className="h-2 w-2 rounded-full bg-destructive" />
          <span className="text-xs font-medium text-destructive">Before</span>
          <Badge variant="outline" className="text-[10px] ml-auto">
            {language}
          </Badge>
        </div>
        <pre className="bg-destructive/10 border border-destructive/20 rounded-md p-3 text-xs overflow-x-auto font-mono text-foreground leading-relaxed">
          <code>{before || "// Original code not available"}</code>
        </pre>
      </div>
      <div>
        <div className="flex items-center gap-2 mb-1">
          <div className="h-2 w-2 rounded-full bg-green-500" />
          <span className="text-xs font-medium text-green-500">After</span>
        </div>
        <pre className="bg-green-500/10 border border-green-500/20 rounded-md p-3 text-xs overflow-x-auto font-mono text-foreground leading-relaxed">
          <code>{after || "// Fixed code not available"}</code>
        </pre>
      </div>
    </div>
  );
}

function FixPreviewDialog({
  fix,
  open,
  onClose,
  onApprove,
  onReject,
  onApply,
}: {
  fix: Record<string, unknown> | null;
  open: boolean;
  onClose: () => void;
  onApprove: () => void;
  onReject: () => void;
  onApply: () => void;
}) {
  if (!fix) return null;
  const testResults = (fix.test_results as Record<string, unknown>[]) ?? [];

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-3xl max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Wand2 className="h-5 w-5 text-primary" />
            AutoFix Preview
          </DialogTitle>
        </DialogHeader>
        <div className="space-y-5">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
            <div>
              <p className="text-xs text-muted-foreground">Finding</p>
              <p className="font-medium truncate">{(fix.finding as string) ?? "—"}</p>
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Fix Type</p>
              <FixTypeBadge fixType={(fix.fix_type as string) ?? "AI"} />
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Language</p>
              <Badge variant="outline">{(fix.language as string) ?? "—"}</Badge>
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Status</p>
              <StatusBadge status={(fix.status as string) ?? "pending_review"} />
            </div>
          </div>

          {/* Code Diff */}
          <CodeDiffView
            before={(fix.code_before as string) ?? ""}
            after={(fix.code_after as string) ?? ""}
            language={(fix.language as string) ?? "code"}
          />

          {/* Test Results */}
          {testResults.length > 0 && (
            <div>
              <p className="text-xs text-muted-foreground font-medium mb-2">CI/Test Results</p>
              <div className="space-y-1.5">
                {testResults.map((result, i) => (
                  <div
                    key={i}
                    className="flex items-center gap-2 p-2 rounded bg-muted/30 text-xs"
                  >
                    {(result.passed as boolean) ? (
                      <CheckCircle className="h-3.5 w-3.5 text-green-500 shrink-0" />
                    ) : (
                      <XCircle className="h-3.5 w-3.5 text-destructive shrink-0" />
                    )}
                    <span className="flex-1">{(result.name as string) ?? `Test ${i + 1}`}</span>
                    <span
                      className={
                        (result.passed as boolean) ? "text-green-500" : "text-destructive"
                      }
                    >
                      {(result.passed as boolean) ? "PASS" : "FAIL"}
                    </span>
                    {!!result.duration && (
                      <span className="text-muted-foreground">{String(result.duration)}</span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* PR Link */}
          {!!fix.pr_link && (
            <div className="flex items-center gap-2 text-sm">
              <GitPullRequest className="h-4 w-4 text-muted-foreground" />
              <a
                href={fix.pr_link as string}
                target="_blank"
                rel="noopener noreferrer"
                className="text-primary hover:underline"
              >
                {fix.pr_link as string}
              </a>
            </div>
          )}
        </div>
        <DialogFooter className="flex-wrap gap-2">
          <Button variant="outline" onClick={onClose}>Close</Button>
          <Button
            variant="outline"
            className="text-destructive border-destructive/30"
            onClick={() => { onReject(); onClose(); }}
            disabled={(fix.status as string) === "rejected"}
          >
            <XCircle className="h-4 w-4 mr-2" />
            Reject
          </Button>
          <Button
            variant="outline"
            onClick={() => { onApprove(); onClose(); }}
            disabled={(fix.status as string) === "approved"}
          >
            <CheckCircle className="h-4 w-4 mr-2" />
            Approve
          </Button>
          <Button
            onClick={() => { onApply(); onClose(); }}
            disabled={(fix.status as string) === "applied"}
          >
            <GitPullRequest className="h-4 w-4 mr-2" />
            Apply (Create PR)
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default function AutoFix() {
  const tasksQuery = useRemediationTasks();
  const autofixMutation = useAutofix();

  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [fixTypeFilter, setFixTypeFilter] = useState("all");
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [previewFix, setPreviewFix] = useState<Record<string, unknown> | null>(null);
  const [previewOpen, setPreviewOpen] = useState(false);
  const [sortField, setSortField] = useState("status");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("asc");

  const refetch = useCallback(() => tasksQuery.refetch(), [tasksQuery]);

  if (tasksQuery.isLoading) return <PageSkeleton />;
  if (tasksQuery.isError)
    return <ErrorState message="Failed to load autofix data" onRetry={refetch} />;

  const allTasks: Record<string, unknown>[] = toArray(tasksQuery.data);

  // Derive autofixes from tasks that have autofix data
  const autofixes = allTasks
    .filter((t) => t.autofix || t.fix_type || t.code_after)
    .map((t, idx) => ({
      id: (t.id as string) ?? `autofix-${idx}`,
      finding: (t.title as string) ?? "—",
      fix_type: (t.fix_type as string) ?? "AI",
      language: (t.language as string) ?? "Python",
      status: (t.autofix_status as string) ?? "pending_review",
      pr_link: t.pr_link as string,
      code_before: t.code_before as string,
      code_after: t.code_after as string,
      test_results: t.test_results as Record<string, unknown>[],
      created_at: t.created_at as string,
      ...(t as Record<string, unknown>),
    }));

  const generated = autofixes.length;
  const applied = autofixes.filter((f) => f.status === "applied").length;
  const pendingReview = autofixes.filter((f) => f.status === "pending_review").length;
  const successRate =
    generated > 0 ? Math.round((applied / generated) * 100) : 0;

  const filtered = autofixes.filter((f) => {
    const matchSearch =
      !search ||
      (f.finding as string)?.toLowerCase().includes(search.toLowerCase());
    const matchStatus = statusFilter === "all" || f.status === statusFilter;
    const matchType = fixTypeFilter === "all" || f.fix_type === fixTypeFilter;
    return matchSearch && matchStatus && matchType;
  });

  const sorted = [...filtered].sort((a, b) => {
    const av = (a as Record<string, unknown>)[sortField] as string;
    const bv = (b as Record<string, unknown>)[sortField] as string;
    return sortDir === "asc"
      ? String(av).localeCompare(String(bv))
      : String(bv).localeCompare(String(av));
  });

  const toggleSort = (field: string) => {
    if (sortField === field) setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    else { setSortField(field); setSortDir("asc"); }
  };

  const SortIcon = ({ field }: { field: string }) =>
    sortField === field ? (
      sortDir === "desc" ? <ChevronDown className="h-3 w-3" /> : <ChevronUp className="h-3 w-3" />
    ) : (
      <ChevronDown className="h-3 w-3 opacity-30" />
    );

  const allSelected =
    sorted.length > 0 && sorted.every((f) => selectedIds.has(f.id as string));

  const handleBatchApprove = async () => {
    try {
      const ids = Array.from(selectedIds);
      const resp = await fetch((import.meta.env.VITE_API_URL || '') + '/api/v1/autofix/batch-approve', {
        method: 'POST',
        headers: { 'X-API-Key': import.meta.env.VITE_API_KEY || '', 'Content-Type': 'application/json' },
        body: JSON.stringify({ fix_ids: ids }),
      });
      const data = await resp.json();
      toast.success(`Approved ${data.approved_count ?? ids.length} autofixes — PRs queued for creation`);
    } catch {
      toast.error(`Failed to approve autofixes`);
    }
    setSelectedIds(new Set());
    tasksQuery.refetch();
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      <PageHeader
        title="AutoFix"
        description="AI-powered automated fix generation — AST transforms, pattern matching, and LLM-generated patches"
      >
        <Button
          variant="outline"
          onClick={async () => {
            toast.info("Generating autofixes for all eligible findings...");
            try {
              await fetch((import.meta.env.VITE_API_URL || '') + '/api/v1/autofix/generate-all', {
                method: 'POST',
                headers: { 'X-API-Key': import.meta.env.VITE_API_KEY || '', 'Content-Type': 'application/json' },
                body: JSON.stringify({ scope: 'all_open' }),
              });
              toast.success("AutoFix generation pipeline started for all eligible findings");
              tasksQuery.refetch();
            } catch { toast.error("Failed to start AutoFix generation"); }
          }}
        >
          <Wand2 className="h-4 w-4 mr-2" />
          Generate All
        </Button>
      </PageHeader>

      {/* KPI Row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard
          title="AutoFixes Generated"
          value={generated}
          icon={<Wand2 className="h-4 w-4" />}
        />
        <KpiCard
          title="Applied"
          value={applied}
          icon={<CheckCircle className="h-4 w-4" />}
        />
        <KpiCard
          title="Pending Review"
          value={pendingReview}
          icon={<Clock className="h-4 w-4" />}
          trend="flat"
          trendLabel="awaiting action"
        />
        <KpiCard
          title="Success Rate"
          value={`${successRate}%`}
          icon={<TrendingUp className="h-4 w-4" />}
        />
      </div>

      <Tabs defaultValue="autofixes">
        <TabsList>
          <TabsTrigger value="autofixes">AutoFix List</TabsTrigger>
          <TabsTrigger value="pending">
            Pending Review
            {pendingReview > 0 && (
              <Badge variant="secondary" className="ml-2 text-[10px]">
                {pendingReview}
              </Badge>
            )}
          </TabsTrigger>
        </TabsList>

        <TabsContent value="autofixes" className="space-y-4">
          {/* Filters */}
          <Card>
            <CardContent className="pt-4">
              <div className="flex flex-wrap gap-3 items-center">
                <div className="relative flex-1 min-w-[200px]">
                  <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
                  <Input
                    className="pl-8"
                    placeholder="Search findings..."
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                  />
                </div>
                <Select value={statusFilter} onValueChange={setStatusFilter}>
                  <SelectTrigger className="w-40">
                    <SelectValue placeholder="Status" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Statuses</SelectItem>
                    {Object.keys(AUTOFIX_STATUS).map((s) => (
                      <SelectItem key={s} value={s}>
                        {AUTOFIX_STATUS[s as keyof typeof AUTOFIX_STATUS].label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <Select value={fixTypeFilter} onValueChange={setFixTypeFilter}>
                  <SelectTrigger className="w-40">
                    <SelectValue placeholder="Fix Type" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Types</SelectItem>
                    {Object.keys(FIX_TYPE_CONFIG).map((t) => (
                      <SelectItem key={t} value={t}>
                        {FIX_TYPE_CONFIG[t as keyof typeof FIX_TYPE_CONFIG].label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </CardContent>
          </Card>

          {/* Bulk Actions */}
          {selectedIds.size > 0 && (
            <motion.div
              initial={{ opacity: 0, y: -8 }}
              animate={{ opacity: 1, y: 0 }}
              className="flex items-center gap-3 p-3 bg-primary/10 border border-primary/30 rounded-lg"
            >
              <span className="text-sm font-medium">
                {selectedIds.size} fix{selectedIds.size !== 1 ? "es" : ""} selected
              </span>
              <Button size="sm" onClick={handleBatchApprove}>
                <CheckCircle className="h-3.5 w-3.5 mr-1" />
                Batch Approve
              </Button>
              <Button size="sm" variant="outline" onClick={() => setSelectedIds(new Set())}>
                Clear
              </Button>
            </motion.div>
          )}

          <Card>
            <CardContent className="p-0">
              <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-10">
                      <Checkbox
                        checked={allSelected}
                        onCheckedChange={(checked) => {
                          if (checked) setSelectedIds(new Set(sorted.map((f) => f.id as string)));
                          else setSelectedIds(new Set());
                        }}
                      />
                    </TableHead>
                    <TableHead
                      className="cursor-pointer select-none"
                      onClick={() => toggleSort("finding")}
                    >
                      <span className="flex items-center gap-1">
                        Finding <SortIcon field="finding" />
                      </span>
                    </TableHead>
                    <TableHead>Fix Type</TableHead>
                    <TableHead>Language</TableHead>
                    <TableHead
                      className="cursor-pointer select-none"
                      onClick={() => toggleSort("status")}
                    >
                      <span className="flex items-center gap-1">
                        Status <SortIcon field="status" />
                      </span>
                    </TableHead>
                    <TableHead>PR Link</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {sorted.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={7} className="text-center py-10 text-muted-foreground">
                        {autofixes.length === 0
                          ? "No autofixes generated yet. Run AutoFix on findings to generate patches."
                          : "No autofixes match your filters"}
                      </TableCell>
                    </TableRow>
                  ) : (
                    sorted.map((fix) => (
                      <TableRow
                        key={fix.id as string}
                        className={cn(
                          "hover:bg-muted/30",
                          selectedIds.has(fix.id as string) && "bg-primary/5"
                        )}
                      >
                        <TableCell>
                          <Checkbox
                            checked={selectedIds.has(fix.id as string)}
                            onCheckedChange={(checked) => {
                              setSelectedIds((prev) => {
                                const next = new Set(prev);
                                if (checked) next.add(fix.id as string);
                                else next.delete(fix.id as string);
                                return next;
                              });
                            }}
                          />
                        </TableCell>
                        <TableCell className="font-medium max-w-[200px] truncate">
                          {fix.finding as string}
                        </TableCell>
                        <TableCell>
                          <FixTypeBadge fixType={fix.fix_type as string} />
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline" className="font-mono text-xs">
                            {(fix.language as string) ?? "—"}
                          </Badge>
                        </TableCell>
                        <TableCell>
                          <StatusBadge status={fix.status as string} />
                        </TableCell>
                        <TableCell>
                          {fix.pr_link ? (
                            <a
                              href={fix.pr_link as string}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="flex items-center gap-1 text-xs text-primary hover:underline"
                            >
                              <GitPullRequest className="h-3 w-3" />
                              PR
                            </a>
                          ) : (
                            <span className="text-xs text-muted-foreground">—</span>
                          )}
                        </TableCell>
                        <TableCell className="text-right">
                          <div className="flex items-center justify-end gap-2">
                            <Button
                              variant="ghost"
                              size="sm"
                              onClick={() => {
                                setPreviewFix(fix as Record<string, unknown>);
                                setPreviewOpen(true);
                              }}
                            >
                              <Code className="h-3.5 w-3.5 mr-1" />
                              Preview
                            </Button>
                            {(fix.status as string) === "approved" && (
                              <Button size="sm" variant="outline" onClick={async () => {
                                try {
                                  await autofixApi.apply(fix.id as string);
                                  toast.success("Fix applied successfully");
                                  tasksQuery.refetch();
                                } catch { toast.error("Failed to apply fix"); }
                              }}>
                                <Play className="h-3.5 w-3.5 mr-1" />
                                Apply
                              </Button>
                            )}
                          </div>
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
              </Table>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="pending">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 text-amber-500" />
                Pending Review
              </CardTitle>
              <CardDescription className="text-xs">
                AutoFixes awaiting human approval before application
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              {autofixes.filter((f) => f.status === "pending_review").length === 0 ? (
                <p className="text-center py-8 text-muted-foreground text-sm">
                  No autofixes pending review
                </p>
              ) : (
                autofixes
                  .filter((f) => f.status === "pending_review")
                  .map((fix) => (
                    <Card key={fix.id as string} className="border-amber-500/20">
                      <CardContent className="pt-4">
                        <div className="flex items-start justify-between gap-4">
                          <div className="flex-1">
                            <p className="font-medium text-sm">{fix.finding as string}</p>
                            <div className="flex items-center gap-2 mt-1">
                              <FixTypeBadge fixType={fix.fix_type as string} />
                              <Badge variant="outline" className="font-mono text-xs">
                                {(fix.language as string) ?? "—"}
                              </Badge>
                            </div>
                          </div>
                          <div className="flex gap-2">
                            <Button
                              variant="outline"
                              size="sm"
                              className="text-destructive border-destructive/30"
                              onClick={() => toast.info("Fix rejected")}
                            >
                              <XCircle className="h-3.5 w-3.5 mr-1" />
                              Reject
                            </Button>
                            <Button
                              size="sm"
                              onClick={() => {
                                setPreviewFix(fix as Record<string, unknown>);
                                setPreviewOpen(true);
                              }}
                            >
                              <Zap className="h-3.5 w-3.5 mr-1" />
                              Review & Apply
                            </Button>
                          </div>
                        </div>
                      </CardContent>
                    </Card>
                  ))
                  )}
              </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      <FixPreviewDialog
        fix={previewFix}
        open={previewOpen}
        onClose={() => setPreviewOpen(false)}
        onApprove={async () => {
          try {
            const fixId = previewFix?.id || previewFix?.fix_id;
            if (fixId) await fetch((import.meta.env.VITE_API_URL || '') + `/api/v1/autofix/approve`, { method: 'POST', headers: { 'X-API-Key': import.meta.env.VITE_API_KEY || '', 'Content-Type': 'application/json' }, body: JSON.stringify({ fix_id: fixId }) });
            toast.success("AutoFix approved — ready for deployment");
            tasksQuery.refetch();
          } catch { toast.error("Failed to approve AutoFix"); }
        }}
        onReject={async () => {
          try {
            const fixId = previewFix?.id || previewFix?.fix_id;
            if (fixId) await fetch((import.meta.env.VITE_API_URL || '') + `/api/v1/autofix/reject`, { method: 'POST', headers: { 'X-API-Key': import.meta.env.VITE_API_KEY || '', 'Content-Type': 'application/json' }, body: JSON.stringify({ fix_id: fixId }) });
            toast.error("AutoFix rejected");
            tasksQuery.refetch();
          } catch { toast.error("AutoFix rejected"); }
        }}
        onApply={async () => {
          try {
            const fixId = previewFix?.id || previewFix?.fix_id;
            if (fixId) await fetch((import.meta.env.VITE_API_URL || '') + `/api/v1/autofix/apply`, { method: 'POST', headers: { 'X-API-Key': import.meta.env.VITE_API_KEY || '', 'Content-Type': 'application/json' }, body: JSON.stringify({ fix_id: fixId }) });
            toast.success("Pull request created successfully — check your Git provider");
            tasksQuery.refetch();
          } catch { toast.error("Failed to create pull request"); }
        }}
      />
    </motion.div>
  );
}
