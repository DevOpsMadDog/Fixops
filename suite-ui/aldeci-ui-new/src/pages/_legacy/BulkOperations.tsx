import { toArray } from "@/lib/api-utils";
import { useState, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import { Progress } from "@/components/ui/progress";
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
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { motion, AnimatePresence } from "framer-motion";
import {
  Layers,
  Users,
  ArrowRight,
  Download,
  Search,
  Filter,
  CheckCircle,
  AlertTriangle,
  Play,
  X,
} from "lucide-react";
import { useFindings } from "@/hooks/use-api";
import { bulkApi } from "@/lib/api";
import { cn } from "@/lib/utils";
import { toast } from "sonner";

type OperationType = "triage" | "assign" | "status_change" | "export";

const OPERATIONS = [
  {
    id: "triage" as OperationType,
    label: "Mass Triage",
    description: "Triage multiple findings at once",
    icon: <AlertTriangle className="h-5 w-5" />,
    color: "#f59e0b",
  },
  {
    id: "assign" as OperationType,
    label: "Mass Assign",
    description: "Assign findings to a team member",
    icon: <Users className="h-5 w-5" />,
    color: "#3b82f6",
  },
  {
    id: "status_change" as OperationType,
    label: "Mass Status Change",
    description: "Update status for multiple findings",
    icon: <ArrowRight className="h-5 w-5" />,
    color: "#8b5cf6",
  },
  {
    id: "export" as OperationType,
    label: "Mass Export",
    description: "Export findings to CSV / PDF",
    icon: <Download className="h-5 w-5" />,
    color: "#22c55e",
  },
];

const SEVERITY_CONFIG = {
  critical: { color: "#ef4444", label: "Critical" },
  high: { color: "#f97316", label: "High" },
  medium: { color: "#f59e0b", label: "Medium" },
  low: { color: "#22c55e", label: "Low" },
  info: { color: "#6b7280", label: "Info" },
};

function SeverityBadge({ severity }: { severity: string }) {
  const cfg = SEVERITY_CONFIG[severity as keyof typeof SEVERITY_CONFIG] ?? { color: "#6b7280", label: severity };
  return (
    <Badge variant="outline" style={{ borderColor: cfg.color + "66", color: cfg.color }}>
      {cfg.label}
    </Badge>
  );
}

function OperationCard({
  op,
  selected,
  onClick,
}: {
  op: (typeof OPERATIONS)[0];
  selected: boolean;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className={cn(
        "flex items-start gap-3 p-4 rounded-xl border text-left transition-all w-full",
        selected
          ? "border-primary bg-primary/10"
          : "border-border hover:border-muted-foreground/40 hover:bg-muted/30"
      )}
    >
      <div
        className="h-8 w-8 rounded-lg flex items-center justify-center shrink-0"
        style={{ background: op.color + "22", color: op.color }}
      >
        {op.icon}
      </div>
      <div>
        <p className="text-sm font-medium">{op.label}</p>
        <p className="text-xs text-muted-foreground mt-0.5">{op.description}</p>
      </div>
      {selected && <CheckCircle className="h-4 w-4 text-primary ml-auto mt-0.5 shrink-0" />}
    </button>
  );
}

function ConfirmDialog({
  open,
  onClose,
  operation,
  selectedCount,
  config,
  onConfirm,
  isRunning,
  progress,
}: {
  open: boolean;
  onClose: () => void;
  operation: OperationType | null;
  selectedCount: number;
  config: Record<string, string>;
  onConfirm: () => void;
  isRunning: boolean;
  progress: number;
}) {
  const op = OPERATIONS.find((o) => o.id === operation);
  if (!op) return null;

  return (
    <Dialog open={open} onOpenChange={isRunning ? undefined : onClose}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <div
              className="h-6 w-6 rounded flex items-center justify-center"
              style={{ background: op.color + "22", color: op.color }}
            >
              {op.icon}
            </div>
            Confirm {op.label}
          </DialogTitle>
        </DialogHeader>
        <div className="space-y-4">
          <div className="bg-muted/50 rounded-lg p-3 space-y-2">
            <div className="flex justify-between text-sm">
              <span className="text-muted-foreground">Operation</span>
              <span className="font-medium">{op.label}</span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-muted-foreground">Findings affected</span>
              <span className="font-semibold text-primary">{selectedCount}</span>
            </div>
            {Object.entries(config).map(([k, v]) => (
              <div key={k} className="flex justify-between text-sm">
                <span className="text-muted-foreground capitalize">{k.replace(/_/g, " ")}</span>
                <span>{v}</span>
              </div>
            ))}
          </div>
          {isRunning && (
            <div className="space-y-2">
              <div className="flex justify-between text-xs text-muted-foreground">
                <span>Processing...</span>
                <span>{progress}%</span>
              </div>
              <Progress value={progress} className="h-2" />
            </div>
          )}
          {!isRunning && (
            <p className="text-xs text-muted-foreground">
              This action will be applied to {selectedCount} finding{selectedCount !== 1 ? "s" : ""}.
              This cannot be undone.
            </p>
          )}
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose} disabled={isRunning}>
            Cancel
          </Button>
          <Button onClick={onConfirm} disabled={isRunning}>
            {isRunning ? "Running..." : (
              <>
                <Play className="h-4 w-4 mr-2" />
                Execute
              </>
            )}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default function BulkOperations() {
  const findingsQuery = useFindings();

  const [selectedOp, setSelectedOp] = useState<OperationType | null>(null);
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [isRunning, setIsRunning] = useState(false);
  const [progress, setProgress] = useState(0);
  const [results, setResults] = useState<{ success: number; failed: number } | null>(null);

  // Operation-specific config
  const [assignee, setAssignee] = useState("");
  const [newStatus, setNewStatus] = useState("in_progress");
  const [triageAction, setTriageAction] = useState("confirm");
  const [exportFormat, setExportFormat] = useState("csv");

  const refetch = useCallback(() => findingsQuery.refetch(), [findingsQuery]);

  if (findingsQuery.isLoading) return <PageSkeleton />;
  if (findingsQuery.isError)
    return <ErrorState message="Failed to load findings" onRetry={refetch} />;

  const allFindings: Record<string, unknown>[] =
    toArray(findingsQuery.data);

  const filtered = allFindings.filter((f) => {
    const matchSearch =
      !search ||
      (f.title as string)?.toLowerCase().includes(search.toLowerCase()) ||
      (f.asset as string)?.toLowerCase().includes(search.toLowerCase());
    const matchSev = severityFilter === "all" || f.severity === severityFilter;
    const matchStatus = statusFilter === "all" || f.status === statusFilter;
    return matchSearch && matchSev && matchStatus;
  });

  const allSelected = filtered.length > 0 && filtered.every((f) => selectedIds.has((f.id as string) ?? ""));

  const toggleAll = () => {
    if (allSelected) setSelectedIds(new Set());
    else setSelectedIds(new Set(filtered.map((f) => (f.id as string) ?? "")));
  };

  const getOpConfig = (): Record<string, string> => {
    if (selectedOp === "assign") return { assignee: assignee || "TBD" };
    if (selectedOp === "status_change") return { new_status: newStatus };
    if (selectedOp === "triage") return { action: triageAction };
    if (selectedOp === "export") return { format: exportFormat };
    return {};
  };

  const handleExecute = async () => {
    setIsRunning(true);
    setProgress(10);
    const ids = Array.from(selectedIds);
    try {
      if (selectedOp === "triage") {
        setProgress(30);
        await bulkApi.triage(ids, triageAction);
      } else if (selectedOp === "assign") {
        setProgress(30);
        await bulkApi.assignFindings(ids, assignee);
      } else if (selectedOp === "status_change") {
        setProgress(30);
        await bulkApi.updateFindings(ids, { status: newStatus });
      } else if (selectedOp === "export") {
        setProgress(30);
        // Client-side export — no API needed
        const selectedFindings = allFindings.filter((f) => ids.includes((f.id as string) ?? ""));
        let content: string;
        let mimeType: string;
        let ext: string;
        if (exportFormat === "json") {
          content = JSON.stringify(selectedFindings, null, 2);
          mimeType = "application/json";
          ext = "json";
        } else {
          // CSV
          const headers = ["id", "title", "severity", "status", "asset", "assignee", "created_at"];
          const rows = selectedFindings.map((f) =>
            headers.map((h) => String((f as any)[h] ?? "").replace(/,/g, ";")).join(",")
          );
          content = [headers.join(","), ...rows].join("\n");
          mimeType = "text/csv";
          ext = "csv";
        }
        const blob = new Blob([content], { type: mimeType });
        const url = URL.createObjectURL(blob);
        const a = document.createElement("a");
        a.href = url;
        a.download = `findings-export-${ids.length}.${ext}`;
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        URL.revokeObjectURL(url);
      }
      setProgress(100);
      setResults({ success: ids.length, failed: 0 });
      setSelectedIds(new Set());
      toast.success(`${selectedOp} applied to ${ids.length} findings`);
      refetch();
    } catch (err: any) {
      setResults({ success: 0, failed: ids.length });
      toast.error(`Bulk operation failed: ${err?.response?.data?.detail ?? err.message}`);
    } finally {
      setIsRunning(false);
      setConfirmOpen(false);
    }
  };

  const uniqueStatuses = [...new Set(allFindings.map((f) => (f.status as string)).filter(Boolean))];

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      <PageHeader
        title="Bulk Operations"
        description="Mass triage, assignment, status changes, and export for multiple findings simultaneously"
      />

      <div className="grid grid-cols-1 xl:grid-cols-4 gap-6">
        {/* Left: Operation selector */}
        <div className="xl:col-span-1 space-y-4">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">Select Operation</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              {OPERATIONS.map((op) => (
                <OperationCard
                  key={op.id}
                  op={op}
                  selected={selectedOp === op.id}
                  onClick={() => setSelectedOp(op.id)}
                />
              ))}
            </CardContent>
          </Card>

          {/* Operation config */}
          <AnimatePresence mode="wait">
            {selectedOp && (
              <motion.div
                key={selectedOp}
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, y: -8 }}
              >
                <Card>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm font-medium">Configuration</CardTitle>
                  </CardHeader>
                  <CardContent className="space-y-3">
                    {selectedOp === "assign" && (
                      <div className="space-y-1.5">
                        <Label className="text-xs">Assignee</Label>
                        <Input
                          placeholder="Enter username or email"
                          value={assignee}
                          onChange={(e) => setAssignee(e.target.value)}
                        />
                      </div>
                    )}
                    {selectedOp === "status_change" && (
                      <div className="space-y-1.5">
                        <Label className="text-xs">New Status</Label>
                        <Select value={newStatus} onValueChange={setNewStatus}>
                          <SelectTrigger>
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="open">Open</SelectItem>
                            <SelectItem value="in_progress">In Progress</SelectItem>
                            <SelectItem value="fix_applied">Fix Applied</SelectItem>
                            <SelectItem value="verified">Verified</SelectItem>
                            <SelectItem value="closed">Closed</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                    )}
                    {selectedOp === "triage" && (
                      <div className="space-y-1.5">
                        <Label className="text-xs">Triage Action</Label>
                        <Select value={triageAction} onValueChange={setTriageAction}>
                          <SelectTrigger>
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="confirm">Confirm Finding</SelectItem>
                            <SelectItem value="false_positive">Mark False Positive</SelectItem>
                            <SelectItem value="accepted_risk">Accept Risk</SelectItem>
                            <SelectItem value="escalate">Escalate</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                    )}
                    {selectedOp === "export" && (
                      <div className="space-y-1.5">
                        <Label className="text-xs">Export Format</Label>
                        <Select value={exportFormat} onValueChange={setExportFormat}>
                          <SelectTrigger>
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="csv">CSV</SelectItem>
                            <SelectItem value="json">JSON</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                    )}
                    <Button
                      className="w-full"
                      disabled={selectedIds.size === 0}
                      onClick={() => setConfirmOpen(true)}
                    >
                      <Play className="h-4 w-4 mr-2" />
                      Execute ({selectedIds.size})
                    </Button>
                  </CardContent>
                </Card>
              </motion.div>
            )}
          </AnimatePresence>
        </div>

        {/* Right: Findings table */}
        <div className="xl:col-span-3 space-y-4">
          {/* Results summary */}
          <AnimatePresence>
            {results && (
              <motion.div
                initial={{ opacity: 0, y: -8 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0 }}
                className="flex items-center gap-3 p-3 bg-green-500/10 border border-green-500/30 rounded-lg"
              >
                <CheckCircle className="h-4 w-4 text-green-500" />
                <span className="text-sm font-medium">
                  Operation complete: {results.success} succeeded, {results.failed} failed
                </span>
                <Button
                  variant="ghost"
                  size="sm"
                  className="ml-auto h-6 w-6 p-0"
                  onClick={() => setResults(null)}
                >
                  <X className="h-3.5 w-3.5" />
                </Button>
              </motion.div>
            )}
          </AnimatePresence>

          {/* Filter bar */}
          <Card>
            <CardContent className="pt-4">
              <div className="flex flex-wrap gap-3 items-center">
                <div className="relative flex-1 min-w-[200px]">
                  <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
                  <Input
                    className="pl-8"
                    placeholder="Filter findings..."
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                  />
                </div>
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
                <Select value={statusFilter} onValueChange={setStatusFilter}>
                  <SelectTrigger className="w-36">
                    <SelectValue placeholder="Status" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Statuses</SelectItem>
                    {uniqueStatuses.map((s) => (
                      <SelectItem key={s} value={s}>
                        {s}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {selectedIds.size > 0 && (
                  <Badge variant="secondary">
                    {selectedIds.size} selected
                  </Badge>
                )}
              </div>
            </CardContent>
          </Card>

          {/* Selection status bar */}
          {selectedIds.size > 0 && (
            <div className="flex items-center gap-3 text-sm">
              <span className="text-primary font-medium">
                {selectedIds.size} finding{selectedIds.size !== 1 ? "s" : ""} selected
              </span>
              <Button
                variant="ghost"
                size="sm"
                className="h-6 text-xs"
                onClick={() => setSelectedIds(new Set())}
              >
                Clear selection
              </Button>
            </div>
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
                        onCheckedChange={toggleAll}
                      />
                    </TableHead>
                    <TableHead>Finding</TableHead>
                    <TableHead>Asset</TableHead>
                    <TableHead>Severity</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Assignee</TableHead>
                    <TableHead>Created</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filtered.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={7} className="text-center py-10 text-muted-foreground">
                        No findings match your filters
                      </TableCell>
                    </TableRow>
                  ) : (
                    filtered.map((finding, i) => {
                      const fid = (finding.id as string) ?? String(i);
                      return (
                        <TableRow
                          key={fid}
                          className={cn(
                            "hover:bg-muted/30 cursor-pointer",
                            selectedIds.has(fid) && "bg-primary/5"
                          )}
                          onClick={() => {
                            setSelectedIds((prev) => {
                              const next = new Set(prev);
                              if (next.has(fid)) next.delete(fid);
                              else next.add(fid);
                              return next;
                            });
                          }}
                        >
                          <TableCell onClick={(e) => e.stopPropagation()}>
                            <Checkbox
                              checked={selectedIds.has(fid)}
                              onCheckedChange={(checked) => {
                                setSelectedIds((prev) => {
                                  const next = new Set(prev);
                                  if (checked) next.add(fid);
                                  else next.delete(fid);
                                  return next;
                                });
                              }}
                            />
                          </TableCell>
                          <TableCell className="font-medium max-w-[200px]">
                            <p className="truncate">{(finding.title as string) ?? "—"}</p>
                          </TableCell>
                          <TableCell className="font-mono text-xs text-muted-foreground">
                            {(finding.asset as string) ?? "—"}
                          </TableCell>
                          <TableCell>
                            <SeverityBadge severity={(finding.severity as string) ?? "info"} />
                          </TableCell>
                          <TableCell>
                            <Badge variant="outline" className="text-xs">
                              {(finding.status as string) ?? "—"}
                            </Badge>
                          </TableCell>
                          <TableCell className="text-xs text-muted-foreground">
                            {(finding.assignee as string) ?? "—"}
                          </TableCell>
                          <TableCell className="text-xs text-muted-foreground">
                            {(finding.created_at as string) ?? "—"}
                          </TableCell>
                        </TableRow>
                      );
                    })
                  )}
                </TableBody>
              </Table>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>

      <ConfirmDialog
        open={confirmOpen}
        onClose={() => setConfirmOpen(false)}
        operation={selectedOp}
        selectedCount={selectedIds.size}
        config={getOpConfig()}
        onConfirm={handleExecute}
        isRunning={isRunning}
        progress={Math.min(progress, 100)}
      />
    </motion.div>
  );
}
