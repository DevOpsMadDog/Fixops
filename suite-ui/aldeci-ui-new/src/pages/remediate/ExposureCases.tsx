import { toArray } from "@/lib/api-utils";
import { useState, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Progress } from "@/components/ui/progress";
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
  FolderOpen,
  Search,
  Link,
  ChevronRight,
  CheckCircle,
  AlertTriangle,
  RefreshCw,
  Shield,
  Clock,
  User,
} from "lucide-react";
import { useCases, useTriageCase } from "@/hooks/use-api";
import { cn } from "@/lib/utils";

const LIFECYCLE_STATES = ["Open", "Triaged", "Decided", "Resolved"] as const;
type LifecycleState = (typeof LIFECYCLE_STATES)[number];

const STATE_COLORS: Record<LifecycleState, string> = {
  Open: "#6b7280",
  Triaged: "#3b82f6",
  Decided: "#8b5cf6",
  Resolved: "#22c55e",
};

const SEVERITY_CONFIG = {
  critical: { color: "#ef4444", label: "Critical" },
  high: { color: "#f97316", label: "High" },
  medium: { color: "#f59e0b", label: "Medium" },
  low: { color: "#22c55e", label: "Low" },
  info: { color: "#6b7280", label: "Info" },
};

const DECISION_OPTIONS = [
  "Accepted Risk",
  "False Positive",
  "Confirmed Vulnerability",
  "Wontfix",
  "Deferred",
  "Fixed",
];

function SeverityBadge({ severity }: { severity: string }) {
  const cfg = SEVERITY_CONFIG[severity as keyof typeof SEVERITY_CONFIG] ?? {
    color: "#6b7280",
    label: severity,
  };
  return (
    <Badge variant="outline" style={{ borderColor: cfg.color + "66", color: cfg.color }}>
      {cfg.label}
    </Badge>
  );
}

function LifecycleBadge({ state }: { state: string }) {
  const color = STATE_COLORS[state as LifecycleState] ?? "#6b7280";
  return (
    <Badge variant="outline" style={{ borderColor: color + "44", color }}>
      {state}
    </Badge>
  );
}

function LifecycleProgress({ state }: { state: string }) {
  const idx = LIFECYCLE_STATES.indexOf(state as LifecycleState);
  const pct = idx >= 0 ? Math.round(((idx + 1) / LIFECYCLE_STATES.length) * 100) : 0;
  return (
    <div className="space-y-1">
      <div className="flex items-center gap-0 overflow-x-auto">
        {LIFECYCLE_STATES.map((s, i) => (
          <div key={s} className="flex items-center">
            <div
              className={cn(
                "text-[10px] px-2 py-0.5 rounded-sm font-medium whitespace-nowrap",
                i <= idx
                  ? "text-foreground"
                  : "text-muted-foreground opacity-40"
              )}
              style={{
                background: i <= idx ? STATE_COLORS[s] + "22" : undefined,
                color: i <= idx ? STATE_COLORS[s] : undefined,
              }}
            >
              {s}
            </div>
            {i < LIFECYCLE_STATES.length - 1 && (
              <ChevronRight
                className="h-3 w-3 shrink-0"
                style={{ color: i < idx ? STATE_COLORS[s] : "hsl(var(--muted-foreground))", opacity: i < idx ? 1 : 0.3 }}
              />
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

function CaseDetailDialog({
  caseData: caseItem,
  open,
  onClose,
  onTriage,
}: {
  caseData: Record<string, unknown> | null;
  open: boolean;
  onClose: () => void;
  onTriage: (id: string, action: string) => void;
}) {
  const [decision, setDecision] = useState("");
  if (!caseItem) return null;

  const linkedFindings = Array.isArray(caseItem.linked_findings) ? caseItem.linked_findings as Record<string, unknown>[] : [];
  const decisionHistory = Array.isArray(caseItem.decision_history) ? caseItem.decision_history as Record<string, unknown>[] : [];
  const evidence = Array.isArray(caseItem.evidence) ? caseItem.evidence as Record<string, unknown>[] : [];
  const tags = Array.isArray(caseItem.tags) ? caseItem.tags as string[] : [];

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-2xl max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <FolderOpen className="h-5 w-5 text-primary" />
            Case: {(caseItem.case_id as string) ?? (caseItem.id as string) ?? "Unknown"}
          </DialogTitle>
        </DialogHeader>
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <p className="text-xs text-muted-foreground">Title</p>
              <p className="font-medium">{String(caseItem.title ?? "—")}</p>
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Priority</p>
              <SeverityBadge severity={String(caseItem.priority ?? caseItem.severity ?? "info")} />
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Status</p>
              <LifecycleBadge state={String(caseItem.status ?? "open")} />
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Assigned To</p>
              <p>{String(caseItem.assigned_to ?? caseItem.assigned_team ?? "Unassigned")}</p>
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Findings Count</p>
              <p className="font-semibold">{Number(caseItem.finding_count ?? linkedFindings.length)}</p>
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Risk Score</p>
              <p className="font-semibold">{caseItem.risk_score != null ? Number(caseItem.risk_score).toFixed(1) : "—"}</p>
            </div>
            {!!caseItem.root_cve && (
              <div>
                <p className="text-xs text-muted-foreground">Root CVE</p>
                <p className="font-mono text-xs">{String(caseItem.root_cve)}</p>
              </div>
            )}
            {tags.length > 0 && (
              <div>
                <p className="text-xs text-muted-foreground">Tags</p>
                <div className="flex gap-1 flex-wrap">
                  {tags.map((t, i) => (
                    <Badge key={i} variant="outline" className="text-[10px]">{t}</Badge>
                  ))}
                </div>
              </div>
            )}
            {!!caseItem.sla_breached && (
              <div>
                <p className="text-xs text-muted-foreground">SLA</p>
                <Badge variant="destructive" className="text-[10px]">BREACHED</Badge>
              </div>
            )}
          </div>

          <div>
            <p className="text-xs text-muted-foreground font-medium mb-2">Lifecycle</p>
            <LifecycleProgress state={(caseItem.status as string) ?? "Open"} />
          </div>

          {/* Linked Findings */}
          {linkedFindings.length > 0 && (
            <div>
              <p className="text-xs text-muted-foreground font-medium mb-2 flex items-center gap-1">
                <Link className="h-3 w-3" /> Linked Findings ({linkedFindings.length})
              </p>
              <div className="space-y-1.5 max-h-40 overflow-y-auto">
                {linkedFindings.map((f, i) => (
                  <div key={i} className="flex items-center gap-2 p-2 bg-muted/30 rounded text-xs">
                    <SeverityBadge severity={(f.severity as string) ?? "info"} />
                    <span className="flex-1 truncate">{(f.title as string) ?? `Finding ${i + 1}`}</span>
                    {!!f.cvss_score && (
                      <span className="text-muted-foreground">CVSS {Number(f.cvss_score)}</span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Evidence */}
          {evidence.length > 0 && (
            <div>
              <p className="text-xs text-muted-foreground font-medium mb-2">Evidence</p>
              <div className="space-y-1">
                {evidence.map((ev, i) => (
                  <div key={i} className="text-xs flex gap-2 p-2 bg-muted/20 rounded">
                    <Shield className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                    <span>{(ev.description as string) ?? JSON.stringify(ev)}</span>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Decision history */}
          {decisionHistory.length > 0 && (
            <div>
              <p className="text-xs text-muted-foreground font-medium mb-2">Decision History</p>
              <div className="space-y-1.5">
                {decisionHistory.map((d, i) => (
                  <div key={i} className="flex items-center gap-3 text-xs p-2 bg-muted/20 rounded">
                    <Clock className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                    <span className="text-muted-foreground">{(d.timestamp as string) ?? "—"}</span>
                    <span className="font-medium">{(d.decision as string) ?? "—"}</span>
                    {!!d.by && <span className="text-muted-foreground">by {String(d.by)}</span>}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Make decision */}
          <div className="border-t pt-3 space-y-2">
            <p className="text-xs font-medium text-muted-foreground">Update Decision</p>
            <div className="flex gap-2">
              <Select value={decision} onValueChange={setDecision}>
                <SelectTrigger className="flex-1">
                  <SelectValue placeholder="Select decision..." />
                </SelectTrigger>
                <SelectContent>
                  {DECISION_OPTIONS.map((d) => (
                    <SelectItem key={d} value={d}>
                      {d}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Button
                size="sm"
                disabled={!decision}
                onClick={() => {
                  onTriage((caseItem.id as string) ?? "", decision);
                  onClose();
                }}
              >
                Apply
              </Button>
            </div>
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Close</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default function ExposureCases() {
  const casesQuery = useCases();
  const triageCase = useTriageCase();

  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [selectedCase, setSelectedCase] = useState<Record<string, unknown> | null>(null);
  const [detailOpen, setDetailOpen] = useState(false);

  const refetch = useCallback(() => casesQuery.refetch(), [casesQuery]);

  if (casesQuery.isLoading) return <PageSkeleton />;
  if (casesQuery.isError)
    return <ErrorState message="Failed to load exposure cases" onRetry={refetch} />;

  const allCases: Record<string, unknown>[] =
    toArray(casesQuery.data);

  const totalCases = allCases.length;
  const openCases = allCases.filter((c) => {
    const s = String(c.status ?? "").toLowerCase();
    return s === "open" || !s;
  }).length;
  const resolvedCases = allCases.filter((c) => String(c.status ?? "").toLowerCase() === "resolved").length;
  const avgFindingsPerCase =
    allCases.length > 0
      ? (
          allCases.reduce(
            (acc, c) =>
              acc + (Number(c.finding_count ?? c.findings_count ?? 0)),
            0
          ) / allCases.length
        ).toFixed(1)
      : "0";

  const filtered = allCases.filter((c) => {
    const matchSearch =
      !search ||
      String(c.title ?? "").toLowerCase().includes(search.toLowerCase()) ||
      String(c.case_id ?? "").toLowerCase().includes(search.toLowerCase());
    const matchStatus = statusFilter === "all" || String(c.status ?? "").toLowerCase() === statusFilter.toLowerCase();
    const sev = String(c.priority ?? c.severity ?? "").toLowerCase();
    const matchSev = severityFilter === "all" || sev === severityFilter.toLowerCase();
    return matchSearch && matchStatus && matchSev;
  });

  const handleTriage = (id: string, action: string) => {
    triageCase.mutate({ id, action });
  };

  // Build lifecycle chart data — match case-insensitively since API uses lowercase
  const lifecycleData = LIFECYCLE_STATES.map((state) => ({
    state,
    count: allCases.filter((c) => (c.status as string)?.toLowerCase() === state.toLowerCase()).length,
    color: STATE_COLORS[state],
  }));

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      <PageHeader
        title="Exposure Cases"
        description="Deduplicated finding groups — lifecycle tracking from discovery to decision"
      >
        <Button variant="outline" onClick={refetch}>
          <RefreshCw className="h-4 w-4 mr-2" />
          Refresh
        </Button>
      </PageHeader>

      {/* KPI Row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard
          title="Total Cases"
          value={totalCases}
          icon={<FolderOpen className="h-4 w-4" />}
        />
        <KpiCard
          title="Open"
          value={openCases}
          icon={<AlertTriangle className="h-4 w-4" />}
          trend="flat"
        />
        <KpiCard
          title="Resolved"
          value={resolvedCases}
          icon={<CheckCircle className="h-4 w-4" />}
        />
        <KpiCard
          title="Avg Findings/Case"
          value={avgFindingsPerCase}
          icon={<Link className="h-4 w-4" />}
        />
      </div>

      {/* Lifecycle Overview */}
      <Card>
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium">Lifecycle Distribution</CardTitle>
        </CardHeader>
        <CardContent>
          <div className="flex items-end gap-3 flex-wrap">
            {lifecycleData.map((d) => (
              <div key={d.state} className="flex flex-col items-center gap-1 min-w-[80px]">
                <span className="text-2xl font-bold" style={{ color: d.color }}>
                  {d.count}
                </span>
                <div
                  className="w-full rounded-sm h-2"
                  style={{
                    background: d.color + "33",
                    border: `1px solid ${d.color}44`,
                  }}
                >
                  <div
                    className="h-full rounded-sm transition-all"
                    style={{
                      background: d.color,
                      width: totalCases > 0 ? `${(d.count / totalCases) * 100}%` : "0%",
                    }}
                  />
                </div>
                <LifecycleBadge state={d.state} />
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Filters */}
      <Card>
        <CardContent className="pt-4">
          <div className="flex flex-wrap gap-3 items-center">
            <div className="relative flex-1 min-w-[200px]">
              <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
              <Input
                className="pl-8"
                placeholder="Search cases..."
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
                {LIFECYCLE_STATES.map((s) => (
                  <SelectItem key={s} value={s}>
                    {s}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <Select value={severityFilter} onValueChange={setSeverityFilter}>
              <SelectTrigger className="w-36">
                <SelectValue placeholder="Severity" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Severities</SelectItem>
                {Object.keys(SEVERITY_CONFIG).map((s) => (
                  <SelectItem key={s} value={s}>
                    {SEVERITY_CONFIG[s as keyof typeof SEVERITY_CONFIG].label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            <span className="text-sm text-muted-foreground">
              {filtered.length} case{filtered.length !== 1 ? "s" : ""}
            </span>
          </div>
        </CardContent>
      </Card>

      {/* Cases Table */}
      <Card>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Case ID</TableHead>
                <TableHead>Title</TableHead>
                <TableHead>Findings</TableHead>
                <TableHead>Severity</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Decision</TableHead>
                <TableHead>Assignee</TableHead>
                <TableHead className="text-right">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={8} className="text-center py-10 text-muted-foreground">
                    No cases found
                  </TableCell>
                </TableRow>
              ) : (
                filtered.map((caseItem, i) => (
                  <TableRow
                    key={(caseItem.id as string) ?? i}
                    className="hover:bg-muted/30 cursor-pointer"
                    onClick={() => {
                      setSelectedCase(caseItem);
                      setDetailOpen(true);
                    }}
                  >
                    <TableCell className="font-mono text-xs text-muted-foreground">
                      {String(caseItem.case_id ?? `CASE-${String(caseItem.id ?? i).slice(-6).toUpperCase()}`)}
                    </TableCell>
                    <TableCell className="font-medium max-w-[200px]">
                      <p className="truncate">{String(caseItem.title ?? "—")}</p>
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-1.5">
                        <Link className="h-3 w-3 text-muted-foreground" />
                        <span className="text-sm font-semibold">
                          {Number(caseItem.finding_count ?? caseItem.findings_count ?? 0)}
                        </span>
                      </div>
                    </TableCell>
                    <TableCell>
                      <SeverityBadge severity={String(caseItem.priority ?? caseItem.severity ?? "info")} />
                    </TableCell>
                    <TableCell>
                      <LifecycleBadge state={String(caseItem.status ?? "open")} />
                    </TableCell>
                    <TableCell>
                      {caseItem.remediation_plan ? (
                        <Badge variant="outline" className="text-xs">
                          {String(caseItem.remediation_plan)}
                        </Badge>
                      ) : (
                        <span className="text-xs text-muted-foreground">Pending</span>
                      )}
                    </TableCell>
                    <TableCell className="text-xs">
                      {caseItem.assigned_to ? (
                        <div className="flex items-center gap-1.5">
                          <User className="h-3 w-3 text-muted-foreground" />
                          {String(caseItem.assigned_to)}
                        </div>
                      ) : caseItem.assigned_team ? (
                        <div className="flex items-center gap-1.5">
                          <User className="h-3 w-3 text-muted-foreground" />
                          {String(caseItem.assigned_team)}
                        </div>
                      ) : (
                        <span className="text-muted-foreground">—</span>
                      )}
                    </TableCell>
                    <TableCell className="text-right">
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={(e) => {
                          e.stopPropagation();
                          setSelectedCase(caseItem);
                          setDetailOpen(true);
                        }}
                      >
                        Details
                      </Button>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
          </div>
        </CardContent>
      </Card>

      <CaseDetailDialog
        caseData={selectedCase}
        open={detailOpen}
        onClose={() => setDetailOpen(false)}
        onTriage={handleTriage}
      />
    </motion.div>
  );
}
