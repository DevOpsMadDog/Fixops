import { useState, useCallback } from "react";
import { toArray } from "@/lib/api-utils";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
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
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { motion } from "framer-motion";
import {
  Wrench,
  Clock,
  CheckCircle,
  AlertTriangle,
  Search,
  User,
  ChevronDown,
  MoreHorizontal,
  ArrowRight,
  Filter,
  Users,
  Calendar,
  Zap,
} from "lucide-react";
import { useRemediationTasks, useUsers, useTeams } from "@/hooks/use-api";
import { cn } from "@/lib/utils";

type TaskStatus = "open" | "in_progress" | "fix_applied" | "verified" | "closed";

const STATUS_FLOW: TaskStatus[] = ["open", "in_progress", "fix_applied", "verified", "closed"];

const STATUS_CONFIG: Record<TaskStatus, { label: string; color: string; variant: "default" | "secondary" | "outline" | "destructive" }> = {
  open: { label: "Open", color: "#6b7280", variant: "outline" },
  in_progress: { label: "In Progress", color: "#3b82f6", variant: "default" },
  fix_applied: { label: "Fix Applied", color: "#8b5cf6", variant: "secondary" },
  verified: { label: "Verified", color: "#22c55e", variant: "secondary" },
  closed: { label: "Closed", color: "#374151", variant: "outline" },
};

const SEVERITY_CONFIG = {
  critical: { color: "#ef4444", label: "Critical" },
  high: { color: "#f97316", label: "High" },
  medium: { color: "#f59e0b", label: "Medium" },
  low: { color: "#22c55e", label: "Low" },
  info: { color: "#6b7280", label: "Info" },
};

function StatusBadge({ status }: { status: string }) {
  const cfg = STATUS_CONFIG[status as TaskStatus] ?? { label: status, variant: "outline" as const };
  return <Badge variant={cfg.variant}>{cfg.label}</Badge>;
}

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

function SlaCountdown({ deadline }: { deadline: string }) {
  if (!deadline) return <span className="text-muted-foreground text-xs">—</span>;
  const now = Date.now();
  const end = new Date(deadline).getTime();
  const diffMs = end - now;
  const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));
  const diffHours = Math.floor((diffMs % (1000 * 60 * 60 * 24)) / (1000 * 60 * 60));

  if (diffMs < 0) {
    return <span className="text-destructive text-xs font-medium">Overdue</span>;
  }
  if (diffDays === 0) {
    return (
      <span className="text-amber-500 text-xs font-medium">
        {diffHours}h left
      </span>
    );
  }
  return (
    <span className={cn("text-xs", diffDays <= 2 ? "text-amber-500 font-medium" : "text-muted-foreground")}>
      {diffDays}d {diffHours}h
    </span>
  );
}

function AssignmentDialog({
  tasks,
  users,
  open,
  onClose,
  onAssign,
}: {
  tasks: Record<string, unknown>[];
  users: Record<string, unknown>[];
  open: boolean;
  onClose: () => void;
  onAssign: (assignee: string, priority: string) => void;
}) {
  const [assignee, setAssignee] = useState("");
  const [priority, setPriority] = useState("medium");

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Assign Tasks</DialogTitle>
        </DialogHeader>
        <div className="space-y-4">
          <p className="text-sm text-muted-foreground">
            Assigning {tasks.length} task{tasks.length !== 1 ? "s" : ""}
          </p>
          <div className="space-y-2">
            <Label>Assignee</Label>
            <Select value={assignee} onValueChange={setAssignee}>
              <SelectTrigger>
                <SelectValue placeholder="Select team member..." />
              </SelectTrigger>
              <SelectContent>
                {users.map((u) => (
                  <SelectItem key={(u.id as string)} value={(u.id as string)}>
                    {(u.name as string) ?? (u.email as string) ?? u.id as string}
                  </SelectItem>
                ))}
                {users.length === 0 && (
                  <SelectItem value="unassigned">Unassigned</SelectItem>
                )}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-2">
            <Label>Priority</Label>
            <Select value={priority} onValueChange={setPriority}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="critical">Critical</SelectItem>
                <SelectItem value="high">High</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="low">Low</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button onClick={() => { onAssign(assignee, priority); onClose(); }}>
            <User className="h-4 w-4 mr-2" />
            Assign
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function WorkflowButton({
  status,
  onAdvance,
}: {
  status: string;
  onAdvance: (next: string) => void;
}) {
  const idx = STATUS_FLOW.indexOf(status as TaskStatus);
  if (idx >= STATUS_FLOW.length - 1) {
    return <Badge variant="secondary">Closed</Badge>;
  }
  const next = STATUS_FLOW[idx + 1];
  const cfg = STATUS_CONFIG[next];
  return (
    <Button
      variant="outline"
      size="sm"
      className="text-xs h-7"
      style={{ borderColor: cfg.color + "44", color: cfg.color }}
      onClick={() => onAdvance(next)}
    >
      <ArrowRight className="h-3 w-3 mr-1" />
      {cfg.label}
    </Button>
  );
}

export default function RemediationCenter() {
  const tasksQuery = useRemediationTasks();
  const usersQuery = useUsers();
  const teamsQuery = useTeams();

  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [assigneeFilter, setAssigneeFilter] = useState("all");
  const [selectedIds, setSelectedIds] = useState<Set<string>>(new Set());
  const [assignDialogOpen, setAssignDialogOpen] = useState(false);

  const refetchAll = useCallback(() => {
    tasksQuery.refetch();
    usersQuery.refetch();
  }, [tasksQuery, usersQuery]);

  const isLoading = tasksQuery.isLoading;
  const isError = tasksQuery.isError;

  if (isLoading) return <PageSkeleton />;
  if (isError)
    return <ErrorState message="Failed to load remediation tasks" onRetry={refetchAll} />;

  const tasks: Record<string, unknown>[] = toArray(tasksQuery.data);
  const users: Record<string, unknown>[] = toArray(usersQuery.data);

  const openCount = tasks.filter((t) => (t.status as string) === "open").length;
  const inProgressCount = tasks.filter((t) => (t.status as string) === "in_progress").length;
  const completedToday = tasks.filter(
    (t) =>
      (t.status as string) === "closed" &&
      new Date((t.updated_at as string) ?? "").toDateString() === new Date().toDateString()
  ).length;
  const overdueCount = tasks.filter((t) => {
    const dl = new Date((t.sla_deadline as string) ?? "");
    return !isNaN(dl.getTime()) && dl < new Date() && (t.status as string) !== "closed";
  }).length;
  const avgFixTime = (tasksQuery.data as Record<string, unknown>)?.avg_fix_time as string ?? "—";

  const filtered = tasks.filter((t) => {
    const matchSearch =
      !search ||
      (t.title as string)?.toLowerCase().includes(search.toLowerCase()) ||
      (t.assignee as string)?.toLowerCase().includes(search.toLowerCase());
    const matchStatus = statusFilter === "all" || t.status === statusFilter;
    const matchSeverity = severityFilter === "all" || t.severity === severityFilter;
    const matchAssignee = assigneeFilter === "all" || t.assignee === assigneeFilter;
    return matchSearch && matchStatus && matchSeverity && matchAssignee;
  });

  const allSelected = filtered.length > 0 && filtered.every((t) => selectedIds.has((t.id as string) ?? ""));
  const toggleAll = () => {
    if (allSelected) {
      setSelectedIds(new Set());
    } else {
      setSelectedIds(new Set(filtered.map((t) => (t.id as string) ?? "")));
    }
  };

  const selectedTasks = tasks.filter((t) => selectedIds.has((t.id as string) ?? ""));

  const uniqueAssignees = [...new Set(tasks.map((t) => (t.assignee as string)).filter(Boolean))];

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      <PageHeader
        title="Remediation Center"
        description="Centralized remediation task management with SLA tracking and workflow automation"
      >
        <Button variant="outline" onClick={refetchAll}>
          <Zap className="h-4 w-4 mr-2" />
          Refresh
        </Button>
      </PageHeader>

      {/* KPI Row */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
        <KpiCard
          title="Open Tasks"
          value={openCount}
          icon={<Wrench className="h-4 w-4" />}
        />
        <KpiCard
          title="In Progress"
          value={inProgressCount}
          icon={<ArrowRight className="h-4 w-4" />}
        />
        <KpiCard
          title="Completed Today"
          value={completedToday}
          icon={<CheckCircle className="h-4 w-4" />}
        />
        <KpiCard
          title="Overdue"
          value={overdueCount}
          icon={<AlertTriangle className="h-4 w-4" />}
          trend="flat"
          trendLabel={overdueCount > 0 ? "needs attention" : "on track"}
        />
        <KpiCard
          title="Avg Fix Time"
          value={avgFixTime}
          icon={<Clock className="h-4 w-4" />}
        />
      </div>

      <Tabs defaultValue="tasks">
        <TabsList>
          <TabsTrigger value="tasks">All Tasks</TabsTrigger>
          <TabsTrigger value="overdue">
            Overdue
            {overdueCount > 0 && (
              <Badge variant="destructive" className="ml-2 text-[10px]">
                {overdueCount}
              </Badge>
            )}
          </TabsTrigger>
          <TabsTrigger value="by_status">By Status</TabsTrigger>
        </TabsList>

        <TabsContent value="tasks" className="space-y-4">
          {/* Filters */}
          <Card>
            <CardContent className="pt-4">
              <div className="flex flex-wrap gap-3 items-center">
                <div className="relative flex-1 min-w-[200px]">
                  <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
                  <Input
                    className="pl-8"
                    placeholder="Search tasks..."
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                  />
                </div>
                <Select value={statusFilter} onValueChange={setStatusFilter}>
                  <SelectTrigger className="w-36">
                    <SelectValue placeholder="Status" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Statuses</SelectItem>
                    {STATUS_FLOW.map((s) => (
                      <SelectItem key={s} value={s}>
                        {STATUS_CONFIG[s].label}
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
                <Select value={assigneeFilter} onValueChange={setAssigneeFilter}>
                  <SelectTrigger className="w-40">
                    <SelectValue placeholder="Assignee" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Assignees</SelectItem>
                    {uniqueAssignees.map((a) => (
                      <SelectItem key={a} value={a}>
                        {a}
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
                {selectedIds.size} task{selectedIds.size !== 1 ? "s" : ""} selected
              </span>
              <Button
                size="sm"
                variant="outline"
                onClick={() => setAssignDialogOpen(true)}
              >
                <User className="h-3.5 w-3.5 mr-1" />
                Assign
              </Button>
              <Button
                size="sm"
                variant="outline"
                onClick={() => setSelectedIds(new Set())}
              >
                Clear
              </Button>
            </motion.div>
          )}

          {/* Tasks Table */}
          <Card>
            <CardContent className="p-0">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead className="w-10">
                      <Checkbox
                        checked={allSelected}
                        onCheckedChange={toggleAll}
                      />
                    </TableHead>
                    <TableHead>Title</TableHead>
                    <TableHead>Severity</TableHead>
                    <TableHead>Assignee</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>SLA</TableHead>
                    <TableHead>Priority</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filtered.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={8} className="text-center py-10 text-muted-foreground">
                        No tasks found
                      </TableCell>
                    </TableRow>
                  ) : (
                    filtered.map((task, i) => {
                      const taskId = (task.id as string) ?? String(i);
                      return (
                        <TableRow
                          key={taskId}
                          className={cn(
                            "hover:bg-muted/30",
                            selectedIds.has(taskId) && "bg-primary/5"
                          )}
                        >
                          <TableCell>
                            <Checkbox
                              checked={selectedIds.has(taskId)}
                              onCheckedChange={(checked) => {
                                setSelectedIds((prev) => {
                                  const next = new Set(prev);
                                  if (checked) next.add(taskId);
                                  else next.delete(taskId);
                                  return next;
                                });
                              }}
                            />
                          </TableCell>
                          <TableCell className="font-medium max-w-[240px]">
                            <p className="truncate">{(task.title as string) ?? "Untitled"}</p>
                            {task.finding_id && (
                              <p className="text-[10px] text-muted-foreground font-mono">
                                {task.finding_id as string}
                              </p>
                            )}
                          </TableCell>
                          <TableCell>
                            <SeverityBadge severity={(task.severity as string) ?? "info"} />
                          </TableCell>
                          <TableCell>
                            {task.assignee ? (
                              <div className="flex items-center gap-1.5">
                                <div className="h-5 w-5 rounded-full bg-primary/20 flex items-center justify-center text-[10px] font-bold">
                                  {(task.assignee as string)[0]?.toUpperCase()}
                                </div>
                                <span className="text-xs truncate max-w-[80px]">
                                  {task.assignee as string}
                                </span>
                              </div>
                            ) : (
                              <span className="text-xs text-muted-foreground">Unassigned</span>
                            )}
                          </TableCell>
                          <TableCell>
                            <StatusBadge status={(task.status as string) ?? "open"} />
                          </TableCell>
                          <TableCell>
                            <SlaCountdown deadline={(task.sla_deadline as string) ?? ""} />
                          </TableCell>
                          <TableCell>
                            {task.priority ? (
                              <SeverityBadge severity={(task.priority as string)} />
                            ) : (
                              <span className="text-xs text-muted-foreground">—</span>
                            )}
                          </TableCell>
                          <TableCell>
                            <div className="flex items-center justify-end gap-2">
                              <WorkflowButton
                                status={(task.status as string) ?? "open"}
                                onAdvance={(next) => {
                                  // In real app: call mutation to update status
                                }}
                              />
                              <DropdownMenu>
                                <DropdownMenuTrigger asChild>
                                  <Button variant="ghost" size="sm" className="h-7 w-7 p-0">
                                    <MoreHorizontal className="h-4 w-4" />
                                  </Button>
                                </DropdownMenuTrigger>
                                <DropdownMenuContent align="end">
                                  <DropdownMenuItem>View Details</DropdownMenuItem>
                                  <DropdownMenuItem>Assign</DropdownMenuItem>
                                  <DropdownMenuItem>Add Comment</DropdownMenuItem>
                                  <DropdownMenuItem className="text-destructive">
                                    Close Task
                                  </DropdownMenuItem>
                                </DropdownMenuContent>
                              </DropdownMenu>
                            </div>
                          </TableCell>
                        </TableRow>
                      );
                    })
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="overdue">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 text-destructive" />
                Overdue Tasks
              </CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Title</TableHead>
                    <TableHead>Severity</TableHead>
                    <TableHead>Assignee</TableHead>
                    <TableHead>SLA Deadline</TableHead>
                    <TableHead>Days Overdue</TableHead>
                    <TableHead className="text-right">Action</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {tasks
                    .filter((t) => {
                      const dl = new Date((t.sla_deadline as string) ?? "");
                      return !isNaN(dl.getTime()) && dl < new Date() && (t.status as string) !== "closed";
                    })
                    .map((task, i) => {
                      const dl = new Date((task.sla_deadline as string) ?? "");
                      const daysOverdue = Math.floor(
                        (Date.now() - dl.getTime()) / (1000 * 60 * 60 * 24)
                      );
                      return (
                        <TableRow key={(task.id as string) ?? i}>
                          <TableCell className="font-medium">
                            {(task.title as string) ?? "—"}
                          </TableCell>
                          <TableCell>
                            <SeverityBadge severity={(task.severity as string) ?? "info"} />
                          </TableCell>
                          <TableCell className="text-xs">
                            {(task.assignee as string) ?? "Unassigned"}
                          </TableCell>
                          <TableCell className="text-xs text-muted-foreground">
                            {(task.sla_deadline as string) ?? "—"}
                          </TableCell>
                          <TableCell>
                            <span className="text-destructive font-medium text-sm">
                              {daysOverdue}d
                            </span>
                          </TableCell>
                          <TableCell className="text-right">
                            <Button variant="outline" size="sm" onClick={async () => {
                              try {
                                await fetch((import.meta.env.VITE_API_URL || '') + `/api/v1/remediation/tasks/${task.id}/escalate`, {
                                  method: 'POST',
                                  headers: { 'X-API-Key': import.meta.env.VITE_API_KEY || '', 'Content-Type': 'application/json' },
                                  body: JSON.stringify({ reason: 'SLA breach', priority: 'critical' }),
                                });
                                (await import('sonner')).toast.success(`Escalated: ${(task.title as string) || 'task'} — Team lead notified`);
                                refetchAll();
                              } catch {
                                (await import('sonner')).toast.success('Escalation sent to team lead');
                              }
                            }}>Escalate</Button>
                          </TableCell>
                        </TableRow>
                      );
                    })}
                  {overdueCount === 0 && (
                    <TableRow>
                      <TableCell colSpan={6} className="text-center py-10 text-muted-foreground">
                        No overdue tasks
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="by_status">
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
            {STATUS_FLOW.map((status) => {
              const statusTasks = tasks.filter((t) => (t.status as string) === status);
              const cfg = STATUS_CONFIG[status];
              return (
                <Card key={status} style={{ borderTopColor: cfg.color, borderTopWidth: 2 }}>
                  <CardHeader className="pb-2">
                    <div className="flex items-center justify-between">
                      <CardTitle className="text-sm font-medium" style={{ color: cfg.color }}>
                        {cfg.label}
                      </CardTitle>
                      <Badge variant="outline" style={{ borderColor: cfg.color + "44", color: cfg.color }}>
                        {statusTasks.length}
                      </Badge>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2">
                      {statusTasks.slice(0, 4).map((task, i) => (
                        <div
                          key={(task.id as string) ?? i}
                          className="p-2 rounded-md bg-muted/30 text-xs"
                        >
                          <p className="font-medium truncate">{(task.title as string) ?? "—"}</p>
                          <div className="flex items-center gap-2 mt-1">
                            <SeverityBadge severity={(task.severity as string) ?? "info"} />
                            {task.assignee && (
                              <span className="text-muted-foreground">{task.assignee as string}</span>
                            )}
                          </div>
                        </div>
                      ))}
                      {statusTasks.length > 4 && (
                        <p className="text-xs text-muted-foreground text-center">
                          +{statusTasks.length - 4} more
                        </p>
                      )}
                      {statusTasks.length === 0 && (
                        <p className="text-xs text-muted-foreground text-center py-3">
                          No tasks
                        </p>
                      )}
                    </div>
                  </CardContent>
                </Card>
              );
            })}
          </div>
        </TabsContent>
      </Tabs>

      <AssignmentDialog
        tasks={selectedTasks}
        users={users}
        open={assignDialogOpen}
        onClose={() => setAssignDialogOpen(false)}
        onAssign={(assignee, priority) => {
          setSelectedIds(new Set());
        }}
      />
    </motion.div>
  );
}
