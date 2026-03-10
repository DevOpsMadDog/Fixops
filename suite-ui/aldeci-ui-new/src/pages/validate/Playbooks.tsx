import { toArray } from "@/lib/api-utils";
import { useState, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
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
  BookOpen,
  Play,
  Plus,
  Search,
  Clock,
  CheckCircle,
  Tag,
  List,
  Grid,
  AlertCircle,
} from "lucide-react";
import { usePlaybooks } from "@/hooks/use-api";

const CATEGORIES = [
  "All",
  "Incident Response",
  "Compliance",
  "Remediation",
  "Threat Hunting",
  "Onboarding",
] as const;

type Category = (typeof CATEGORIES)[number];

const STATUS_MAP = {
  active: { variant: "secondary" as const, label: "Active" },
  inactive: { variant: "outline" as const, label: "Inactive" },
  draft: { variant: "outline" as const, label: "Draft" },
  archived: { variant: "outline" as const, label: "Archived" },
};

function PlaybookStatusBadge({ status }: { status: string }) {
  const cfg = STATUS_MAP[status as keyof typeof STATUS_MAP] ?? {
    variant: "outline" as const,
    label: status,
  };
  return <Badge variant={cfg.variant}>{cfg.label}</Badge>;
}

function PlaybookCard({
  playbook,
  onRun,
  onDetail,
}: {
  playbook: Record<string, unknown>;
  onRun: (id: string) => void;
  onDetail: (pb: Record<string, unknown>) => void;
}) {
  return (
    <Card className="group hover:border-primary/40 transition-all cursor-pointer" onClick={() => onDetail(playbook)}>
      <CardHeader className="pb-2">
        <div className="flex items-start justify-between gap-2">
          <div className="flex-1 min-w-0">
            <CardTitle className="text-sm font-semibold truncate">
              {(playbook.name as string) ?? "Unnamed Playbook"}
            </CardTitle>
            {!!playbook.category && (
              <Badge variant="outline" className="text-[10px] mt-1">
                <Tag className="h-2.5 w-2.5 mr-1" />
                {String(playbook.category)}
              </Badge>
            )}
          </div>
          <PlaybookStatusBadge status={(playbook.status as string) ?? "draft"} />
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        <p className="text-xs text-muted-foreground line-clamp-2">
          {(playbook.description as string) ?? "No description provided."}
        </p>
        <div className="flex items-center gap-4 text-xs text-muted-foreground">
          <span className="flex items-center gap-1">
            <List className="h-3 w-3" />
            {(playbook.steps_count as number) ?? (Array.isArray(playbook.steps) ? (playbook.steps as unknown[]).length : 0)} steps
          </span>
          {!!playbook.trigger && (
            <span className="flex items-center gap-1">
              <AlertCircle className="h-3 w-3" />
              {String(playbook.trigger)}
            </span>
          )}
          {!!playbook.last_run && (
            <span className="flex items-center gap-1">
              <Clock className="h-3 w-3" />
              {String(playbook.last_run)}
            </span>
          )}
        </div>
        <div className="flex items-center gap-2 pt-1">
          <Button
            size="sm"
            className="flex-1"
            onClick={(e) => {
              e.stopPropagation();
              onRun((playbook.id as string) ?? "");
            }}
          >
            <Play className="h-3 w-3 mr-1" />
            Run
          </Button>
          <Button
            size="sm"
            variant="outline"
            onClick={(e) => {
              e.stopPropagation();
              onDetail(playbook);
            }}
          >
            Details
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

function RunConfirmDialog({
  playbook,
  open,
  onClose,
  onConfirm,
}: {
  playbook: Record<string, unknown> | null;
  open: boolean;
  onClose: () => void;
  onConfirm: () => void;
}) {
  if (!playbook) return null;
  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Run Playbook</DialogTitle>
        </DialogHeader>
        <div className="space-y-3">
          <p className="text-sm">
            You are about to execute:
          </p>
          <div className="bg-muted/50 rounded-lg p-3">
            <p className="font-semibold text-sm">{playbook.name as string}</p>
            <p className="text-xs text-muted-foreground mt-1">
              {playbook.description as string}
            </p>
          </div>
          <div className="flex items-center gap-4 text-xs text-muted-foreground">
            <span>{(playbook.steps_count as number) ?? 0} steps</span>
            {!!playbook.avg_execution_time && (
              <span>
                <Clock className="h-3 w-3 inline mr-1" />
                ~{String(playbook.avg_execution_time)}
              </span>
            )}
          </div>
          <p className="text-xs text-muted-foreground">
            This will execute all playbook steps in sequence. Ensure the target environment is ready.
          </p>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button onClick={onConfirm}>
            <Play className="h-4 w-4 mr-2" />
            Confirm & Run
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function PlaybookDetailDialog({
  playbook,
  open,
  onClose,
}: {
  playbook: Record<string, unknown> | null;
  open: boolean;
  onClose: () => void;
}) {
  if (!playbook) return null;
  const steps = (playbook.steps as Record<string, unknown>[]) ?? [];
  const execHistory = (playbook.execution_history as Record<string, unknown>[]) ?? [];
  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <BookOpen className="h-5 w-5 text-primary" />
            {(playbook.name as string) ?? "Playbook"}
          </DialogTitle>
        </DialogHeader>
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4 text-sm">
            <div>
              <p className="text-xs text-muted-foreground">Category</p>
              <p>{(playbook.category as string) ?? "—"}</p>
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Status</p>
              <PlaybookStatusBadge status={(playbook.status as string) ?? "draft"} />
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Trigger</p>
              <p>{(playbook.trigger as string) ?? "Manual"}</p>
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Avg Exec Time</p>
              <p>{(playbook.avg_execution_time as string) ?? "—"}</p>
            </div>
          </div>
          {!!playbook.description && (
            <p className="text-sm text-muted-foreground">{String(playbook.description)}</p>
          )}
          {steps.length > 0 && (
            <div>
              <p className="text-xs text-muted-foreground mb-2 font-medium">Steps</p>
              <div className="space-y-2">
                {steps.map((step, i) => (
                  <div key={i} className="flex items-start gap-2 p-2 bg-muted/30 rounded-md">
                    <span className="text-xs text-muted-foreground shrink-0 w-5">{i + 1}.</span>
                    <div>
                      <p className="text-xs font-medium">{(step.name as string) ?? `Step ${i + 1}`}</p>
                      {!!step.action && (
                        <p className="text-[10px] text-muted-foreground">{String(step.action)}</p>
                      )}
                    </div>
                    {!!step.type && (
                      <Badge variant="outline" className="ml-auto text-[10px]">{String(step.type)}</Badge>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
          {execHistory.length > 0 && (
            <div>
              <p className="text-xs text-muted-foreground mb-2 font-medium">Execution History</p>
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Date</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Duration</TableHead>
                    <TableHead>Triggered By</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {execHistory.map((exec, i) => (
                    <TableRow key={i}>
                      <TableCell className="text-xs">{(exec.date as string) ?? "—"}</TableCell>
                      <TableCell>
                        <Badge variant={(exec.status as string) === "success" ? "secondary" : "destructive"}>
                          {(exec.status as string) ?? "—"}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-xs">{(exec.duration as string) ?? "—"}</TableCell>
                      <TableCell className="text-xs">{(exec.triggered_by as string) ?? "—"}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            </div>
          )}
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Close</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default function Playbooks() {
  const navigate = useNavigate();
  const playbooksQuery = usePlaybooks();

  const [search, setSearch] = useState("");
  const [category, setCategory] = useState<Category>("All");
  const [viewMode, setViewMode] = useState<"grid" | "list">("grid");
  const [runTarget, setRunTarget] = useState<Record<string, unknown> | null>(null);
  const [runDialogOpen, setRunDialogOpen] = useState(false);
  const [detailTarget, setDetailTarget] = useState<Record<string, unknown> | null>(null);
  const [detailOpen, setDetailOpen] = useState(false);

  const refetch = useCallback(() => playbooksQuery.refetch(), [playbooksQuery]);

  if (playbooksQuery.isLoading) return <PageSkeleton />;
  if (playbooksQuery.isError)
    return <ErrorState message="Failed to load playbooks" onRetry={refetch} />;

  const allPlaybooks: Record<string, unknown>[] =
    toArray(playbooksQuery.data);

  const totalPlaybooks = allPlaybooks.length;
  const activePlaybooks = allPlaybooks.filter((p) => (p.status as string) === "active").length;
  const executionsThisWeek = allPlaybooks.reduce(
    (acc, p) => acc + ((p.executions_this_week as number) ?? 0),
    0
  );
  const avgExecTime =
    allPlaybooks.length > 0
      ? allPlaybooks
          .map((p) => (p.avg_execution_time as string) ?? "—")
          .filter((t) => t !== "—")[0] ?? "—"
      : "—";

  const filtered = allPlaybooks.filter((p) => {
    const matchSearch =
      !search ||
      (p.name as string)?.toLowerCase().includes(search.toLowerCase()) ||
      (p.description as string)?.toLowerCase().includes(search.toLowerCase());
    const matchCat =
      category === "All" || (p.category as string) === category;
    return matchSearch && matchCat;
  });

  const handleRun = (id: string) => {
    const pb = allPlaybooks.find((p) => (p.id as string) === id) ?? null;
    setRunTarget(pb);
    setRunDialogOpen(true);
  };

  const handleConfirmRun = () => {
    setRunDialogOpen(false);
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      <PageHeader
        title="Playbooks"
        description="Security automation playbook library — incident response, compliance, and remediation"
      >
        <Button variant="outline" onClick={() => navigate("/validate/playbook-editor")}>
          <Plus className="h-4 w-4 mr-2" />
          Create Playbook
        </Button>
      </PageHeader>

      {/* KPI Row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard
          title="Total Playbooks"
          value={totalPlaybooks}
          icon={<BookOpen className="h-4 w-4" />}
        />
        <KpiCard
          title="Active"
          value={activePlaybooks}
          icon={<CheckCircle className="h-4 w-4" />}
        />
        <KpiCard
          title="Executions This Week"
          value={executionsThisWeek}
          icon={<Play className="h-4 w-4" />}
        />
        <KpiCard
          title="Avg Execution Time"
          value={avgExecTime}
          icon={<Clock className="h-4 w-4" />}
        />
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3 items-center">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
          <Input
            className="pl-8"
            placeholder="Search playbooks..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <div className="flex gap-1">
          {CATEGORIES.map((cat) => (
            <Button
              key={cat}
              size="sm"
              variant={category === cat ? "default" : "outline"}
              onClick={() => setCategory(cat)}
            >
              {cat}
            </Button>
          ))}
        </div>
        <div className="flex gap-1 border rounded-md p-0.5">
          <Button
            size="sm"
            variant={viewMode === "grid" ? "secondary" : "ghost"}
            className="h-7 px-2"
            onClick={() => setViewMode("grid")}
          >
            <Grid className="h-3.5 w-3.5" />
          </Button>
          <Button
            size="sm"
            variant={viewMode === "list" ? "secondary" : "ghost"}
            className="h-7 px-2"
            onClick={() => setViewMode("list")}
          >
            <List className="h-3.5 w-3.5" />
          </Button>
        </div>
        <span className="text-sm text-muted-foreground">
          {filtered.length} playbook{filtered.length !== 1 ? "s" : ""}
        </span>
      </div>

      {viewMode === "grid" ? (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {filtered.length === 0 ? (
            <div className="col-span-3 flex items-center justify-center py-16 text-muted-foreground text-sm">
              No playbooks match your search
            </div>
          ) : (
            filtered.map((pb, i) => (
              <PlaybookCard
                key={(pb.id as string) ?? i}
                playbook={pb}
                onRun={handleRun}
                onDetail={(p) => {
                  setDetailTarget(p);
                  setDetailOpen(true);
                }}
              />
            ))
          )}
        </div>
      ) : (
        <Card>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>Name</TableHead>
                  <TableHead>Category</TableHead>
                  <TableHead>Trigger</TableHead>
                  <TableHead>Steps</TableHead>
                  <TableHead>Last Run</TableHead>
                  <TableHead>Status</TableHead>
                  <TableHead className="text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {filtered.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={7} className="text-center py-10 text-muted-foreground">
                      No playbooks found
                    </TableCell>
                  </TableRow>
                ) : (
                  filtered.map((pb, i) => (
                    <TableRow key={(pb.id as string) ?? i} className="hover:bg-muted/30 cursor-pointer">
                      <TableCell
                        className="font-medium"
                        onClick={() => {
                          setDetailTarget(pb);
                          setDetailOpen(true);
                        }}
                      >
                        {(pb.name as string) ?? "—"}
                      </TableCell>
                      <TableCell>
                        {pb.category ? (
                          <Badge variant="outline" className="text-xs">
                            {pb.category as string}
                          </Badge>
                        ) : (
                          <span className="text-muted-foreground text-xs">—</span>
                        )}
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {(pb.trigger as string) ?? "Manual"}
                      </TableCell>
                      <TableCell className="text-xs">
                        {(pb.steps_count as number) ??
                          (Array.isArray(pb.steps) ? (pb.steps as unknown[]).length : 0)}
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {(pb.last_run as string) ?? "Never"}
                      </TableCell>
                      <TableCell>
                        <PlaybookStatusBadge status={(pb.status as string) ?? "draft"} />
                      </TableCell>
                      <TableCell className="text-right">
                        <Button size="sm" variant="ghost" onClick={() => handleRun((pb.id as string) ?? "")}>
                          <Play className="h-3.5 w-3.5 mr-1" />
                          Run
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}

      <RunConfirmDialog
        playbook={runTarget}
        open={runDialogOpen}
        onClose={() => setRunDialogOpen(false)}
        onConfirm={handleConfirmRun}
      />
      <PlaybookDetailDialog
        playbook={detailTarget}
        open={detailOpen}
        onClose={() => setDetailOpen(false)}
      />
    </motion.div>
  );
}
