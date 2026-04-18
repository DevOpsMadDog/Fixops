import { toArray } from "@/lib/api-utils";
import { useState, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
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
import { motion, AnimatePresence } from "framer-motion";
import {
  Workflow,
  Plus,
  Zap,
  GitBranch,
  Activity,
  Search,
  Play,
  Pause,
  ChevronRight,
  Clock,
  MoreHorizontal,
  Copy,
  Trash2,
  Edit,
  TrendingUp,
  Calendar,
} from "lucide-react";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { useWorkflowRules, useCreateWorkflow, useUpdateWorkflow, useDeleteWorkflow } from "@/hooks/use-api";
import { cn } from "@/lib/utils";
import { toast } from "sonner";

const TRIGGER_OPTIONS = [
  { value: "finding_created", label: "Finding Created" },
  { value: "finding_severity_change", label: "Finding Severity Changed" },
  { value: "sla_approaching", label: "SLA Approaching" },
  { value: "sla_breached", label: "SLA Breached" },
  { value: "scan_completed", label: "Scan Completed" },
  { value: "cve_published", label: "CVE Published" },
  { value: "remediation_stalled", label: "Remediation Stalled" },
  { value: "schedule", label: "Schedule (Cron)" },
];

const CONDITION_OPTIONS = [
  { value: "severity_critical", label: "Severity == Critical" },
  { value: "severity_gte_high", label: "Severity >= High" },
  { value: "internet_exposed", label: "Asset Internet Exposed" },
  { value: "cvss_gte_9", label: "CVSS Score >= 9.0" },
  { value: "unassigned", label: "Assignee Is Empty" },
  { value: "overdue_7d", label: "Overdue > 7 Days" },
  { value: "no_remediation", label: "No Remediation Task" },
  { value: "always", label: "Always (No Condition)" },
];

const ACTION_OPTIONS = [
  { value: "create_task", label: "Create Remediation Task" },
  { value: "assign_team", label: "Assign to Security Team" },
  { value: "send_slack", label: "Send Slack Notification" },
  { value: "send_email", label: "Send Email Alert" },
  { value: "open_jira", label: "Open Jira Ticket" },
  { value: "escalate", label: "Escalate to Manager" },
  { value: "run_playbook", label: "Execute Playbook" },
  { value: "generate_evidence", label: "Generate Evidence Bundle" },
  { value: "run_mpte", label: "Trigger MPTE Scan" },
];

const TEMPLATES = [
  {
    id: "t1",
    name: "Critical Finding Auto-Response",
    trigger: "finding_created",
    condition: "severity_critical",
    actions: ["create_task", "send_slack", "escalate"],
    description: "Automatically create task and escalate for all critical findings",
  },
  {
    id: "t2",
    name: "SLA Breach Alert",
    trigger: "sla_breached",
    condition: "always",
    actions: ["send_email", "escalate"],
    description: "Email and escalate when SLA is breached",
  },
  {
    id: "t3",
    name: "Internet Exposure Response",
    trigger: "finding_created",
    condition: "internet_exposed",
    actions: ["create_task", "run_mpte", "open_jira"],
    description: "Auto-validate and ticket internet-exposed findings",
  },
  {
    id: "t4",
    name: "CVE Publication Alert",
    trigger: "cve_published",
    condition: "cvss_gte_9",
    actions: ["send_slack", "create_task", "run_mpte"],
    description: "Alert and validate critical CVEs as published",
  },
];

function RuleCard({
  rule,
  onToggle,
  onEdit,
  onDuplicate,
  onDelete,
}: {
  rule: Record<string, unknown>;
  onToggle: (id: string, enabled: boolean) => void;
  onEdit: (rule: Record<string, unknown>) => void;
  onDuplicate: (rule: Record<string, unknown>) => void;
  onDelete: (id: string) => void;
}) {
  const ruleId = (rule.id as string) ?? "";
  const isEnabled = (rule.enabled as boolean) ?? true;
  const trigger = TRIGGER_OPTIONS.find((t) => t.value === rule.trigger)?.label ?? (rule.trigger as string) ?? "—";
  const condition = CONDITION_OPTIONS.find((c) => c.value === rule.condition)?.label ?? (rule.condition as string) ?? "—";
  const actions = ((rule.actions as string[]) ?? []).map(
    (a) => ACTION_OPTIONS.find((opt) => opt.value === a)?.label ?? a
  );
  const executions = (rule.total_executions as number) ?? (rule.executions as number) ?? 0;
  const lastTriggered = (rule.last_triggered as string) ?? (rule.last_run as string) ?? "Never";

  return (
    <Card className={cn("transition-all", !isEnabled && "opacity-60")}>
      <CardContent className="pt-4">
        <div className="flex items-start justify-between gap-4">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-2">
              <h3 className="font-semibold text-sm truncate">
                {(rule.name as string) ?? "Unnamed Rule"}
              </h3>
              <Badge variant={isEnabled ? "secondary" : "outline"} className="text-[10px] shrink-0">
                {isEnabled ? "Active" : "Inactive"}
              </Badge>
            </div>

            {/* IF...THEN logic display */}
            <div className="flex items-start gap-1.5 flex-wrap text-xs mt-2">
              <span className="px-1.5 py-0.5 rounded bg-indigo-500/10 text-indigo-400 font-medium">
                IF
              </span>
              <span className="px-1.5 py-0.5 rounded bg-muted text-foreground">
                {trigger}
              </span>
              <span className="px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-400 font-medium">
                AND
              </span>
              <span className="px-1.5 py-0.5 rounded bg-muted text-foreground">
                {condition}
              </span>
              <span className="px-1.5 py-0.5 rounded bg-green-500/10 text-green-400 font-medium">
                THEN
              </span>
              <div className="flex gap-1 flex-wrap">
                {actions.slice(0, 3).map((action, i) => (
                  <span key={i} className="flex items-center gap-0.5">
                    <span className="px-1.5 py-0.5 rounded bg-muted text-foreground">
                      {action}
                    </span>
                    {i < actions.slice(0, 3).length - 1 && (
                      <ChevronRight className="h-3 w-3 text-muted-foreground" />
                    )}
                  </span>
                ))}
                {actions.length > 3 && (
                  <span className="text-muted-foreground">
                    +{actions.length - 3} more
                  </span>
                )}
              </div>
            </div>

            <div className="flex items-center gap-4 mt-3 text-xs text-muted-foreground">
              <span className="flex items-center gap-1">
                <Zap className="h-3 w-3" />
                {executions} triggers
              </span>
              <span className="flex items-center gap-1">
                <Clock className="h-3 w-3" />
                Last: {lastTriggered}
              </span>
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <Switch
              checked={isEnabled}
              onCheckedChange={(checked) => onToggle(ruleId, checked)}
            />
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <Button variant="ghost" size="sm" className="h-7 w-7 p-0">
                  <MoreHorizontal className="h-4 w-4" />
                </Button>
              </DropdownMenuTrigger>
              <DropdownMenuContent align="end">
                <DropdownMenuItem onClick={() => onEdit(rule)}>
                  <Edit className="h-3.5 w-3.5 mr-2" />
                  Edit
                </DropdownMenuItem>
                <DropdownMenuItem onClick={() => onDuplicate(rule)}>
                  <Copy className="h-3.5 w-3.5 mr-2" />
                  Duplicate
                </DropdownMenuItem>
                <DropdownMenuItem
                  className="text-destructive"
                  onClick={() => onDelete(ruleId)}
                >
                  <Trash2 className="h-3.5 w-3.5 mr-2" />
                  Delete
                </DropdownMenuItem>
              </DropdownMenuContent>
            </DropdownMenu>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function CreateRuleDialog({
  onConfirm,
}: {
  onConfirm: (rule: Record<string, unknown>) => void;
}) {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [trigger, setTrigger] = useState("");
  const [condition, setCondition] = useState("");
  const [actions, setActions] = useState<string[]>(["create_task"]);

  const addAction = () => setActions((prev) => [...prev, ""]);
  const updateAction = (index: number, value: string) =>
    setActions((prev) => prev.map((a, i) => (i === index ? value : a)));
  const removeAction = (index: number) =>
    setActions((prev) => prev.filter((_, i) => i !== index));

  const handleConfirm = () => {
    onConfirm({
      id: `rule_${Date.now()}`,
      name,
      trigger,
      condition,
      actions: actions.filter(Boolean),
      enabled: true,
      total_executions: 0,
      last_triggered: "Never",
      created_at: new Date().toISOString(),
    });
    setOpen(false);
    setName("");
    setTrigger("");
    setCondition("");
    setActions(["create_task"]);
    // toast handled by mutation hook
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button>
          <Plus className="h-4 w-4 mr-2" />
          Create Rule
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-lg max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Workflow className="h-5 w-5 text-primary" />
            Create Workflow Rule
          </DialogTitle>
        </DialogHeader>
        <div className="space-y-4">
          <div className="space-y-2">
            <Label>Rule Name</Label>
            <Input
              placeholder="e.g. Critical Finding Auto-Response"
              value={name}
              onChange={(e) => setName(e.target.value)}
            />
          </div>
          <div className="space-y-2">
            <Label className="flex items-center gap-1.5">
              <span className="px-1.5 py-0.5 rounded bg-indigo-500/10 text-indigo-400 text-xs font-medium">IF</span>
              Trigger
            </Label>
            <Select value={trigger} onValueChange={setTrigger}>
              <SelectTrigger>
                <SelectValue placeholder="When this happens..." />
              </SelectTrigger>
              <SelectContent>
                {TRIGGER_OPTIONS.map((t) => (
                  <SelectItem key={t.value} value={t.value}>
                    {t.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-2">
            <Label className="flex items-center gap-1.5">
              <span className="px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-400 text-xs font-medium">AND</span>
              Condition
            </Label>
            <Select value={condition} onValueChange={setCondition}>
              <SelectTrigger>
                <SelectValue placeholder="Only if this is true..." />
              </SelectTrigger>
              <SelectContent>
                {CONDITION_OPTIONS.map((c) => (
                  <SelectItem key={c.value} value={c.value}>
                    {c.label}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <Label className="flex items-center gap-1.5">
                <span className="px-1.5 py-0.5 rounded bg-green-500/10 text-green-400 text-xs font-medium">THEN</span>
                Action Chain
              </Label>
              <Button variant="ghost" size="sm" className="h-6 text-xs" onClick={addAction}>
                <Plus className="h-3 w-3 mr-1" />
                Add
              </Button>
            </div>
            {actions.map((action, i) => (
              <div key={i} className="flex gap-2 items-center">
                <Select value={action} onValueChange={(v) => updateAction(i, v)}>
                  <SelectTrigger className="flex-1">
                    <SelectValue placeholder="Select action..." />
                  </SelectTrigger>
                  <SelectContent>
                    {ACTION_OPTIONS.map((a) => (
                      <SelectItem key={a.value} value={a.value}>
                        {a.label}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {actions.length > 1 && (
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-8 w-8 p-0 text-destructive"
                    onClick={() => removeAction(i)}
                  >
                    <Trash2 className="h-3.5 w-3.5" />
                  </Button>
                )}
              </div>
            ))}
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => setOpen(false)}>Cancel</Button>
          <Button
            onClick={handleConfirm}
            disabled={!name || !trigger || !condition || actions.every((a) => !a)}
          >
            Create Rule
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default function Workflows() {
  const rulesQuery = useWorkflowRules();
  const createMutation = useCreateWorkflow();
  const updateMutation = useUpdateWorkflow();
  const deleteMutation = useDeleteWorkflow();

  const [search, setSearch] = useState("");
  const [showActive, setShowActive] = useState(false);
  const [selectedRule, setSelectedRule] = useState<Record<string, unknown> | null>(null);

  const refetch = useCallback(() => rulesQuery.refetch(), [rulesQuery]);

  if (rulesQuery.isLoading) return <PageSkeleton />;
  if (rulesQuery.isError) return <ErrorState message="Failed to load workflow rules" onRetry={refetch} />;

  const allRules: Record<string, unknown>[] =
    toArray(rulesQuery.data);

  const activeCount = allRules.filter((r) => (r.enabled as boolean) ?? true).length;
  const totalTriggers = allRules.reduce(
    (acc, r) => acc + ((r.total_executions as number) ?? 0),
    0
  );
  const lastTriggered =
    allRules
      .filter((r) => (r.last_triggered as string) && (r.last_triggered as string) !== "Never")
      .sort(
        (a, b) =>
          new Date(b.last_triggered as string).getTime() -
          new Date(a.last_triggered as string).getTime()
      )[0]?.last_triggered as string ?? "—";
  const createdThisMonth = allRules.filter((r) => {
    const d = new Date((r.created_at as string) ?? "");
    const now = new Date();
    return d.getMonth() === now.getMonth() && d.getFullYear() === now.getFullYear();
  }).length;

  const filteredRules = allRules.filter((r) => {
    const matchSearch =
      !search ||
      (r.name as string)?.toLowerCase().includes(search.toLowerCase());
    const matchActive = !showActive || ((r.enabled as boolean) ?? true);
    return matchSearch && matchActive;
  });

  const handleToggle = (id: string, enabled: boolean) => {
    updateMutation.mutate({ id, data: { enabled } });
  };

  const handleDuplicate = (rule: Record<string, unknown>) => {
    const { id: _id, ...rest } = rule;
    createMutation.mutate({
      ...rest,
      name: `${(rule.name as string) ?? "Rule"} (Copy)`,
      total_executions: 0,
      last_triggered: "Never",
    });
  };

  const handleDelete = (id: string) => {
    deleteMutation.mutate(id);
  };

  const handleCreateRule = (rule: Record<string, unknown>) => {
    createMutation.mutate(rule);
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      <PageHeader
        title="Workflows"
        description="Automation rules — trigger-condition-action chains for security event response"
      >
        <CreateRuleDialog onConfirm={handleCreateRule} />
      </PageHeader>

      {/* KPI Row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard
          title="Active Rules"
          value={activeCount}
          icon={<Workflow className="h-4 w-4" />}
        />
        <KpiCard
          title="Total Triggers"
          value={totalTriggers}
          icon={<Zap className="h-4 w-4" />}
        />
        <KpiCard
          title="Last Triggered"
          value={lastTriggered !== "—" ? lastTriggered : "None"}
          icon={<Clock className="h-4 w-4" />}
        />
        <KpiCard
          title="Created This Month"
          value={createdThisMonth}
          icon={<Calendar className="h-4 w-4" />}
        />
      </div>

      <Tabs defaultValue="rules">
        <TabsList>
          <TabsTrigger value="rules">Rules</TabsTrigger>
          <TabsTrigger value="templates">Templates</TabsTrigger>
          <TabsTrigger value="history">Execution History</TabsTrigger>
        </TabsList>

        <TabsContent value="rules" className="space-y-4">
          <div className="flex flex-wrap gap-3 items-center">
            <div className="relative flex-1 min-w-[200px]">
              <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
              <Input
                className="pl-8"
                placeholder="Search rules..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
            </div>
            <label className="flex items-center gap-2 text-sm cursor-pointer">
              <Switch
                checked={showActive}
                onCheckedChange={setShowActive}
              />
              Active only
            </label>
            <span className="text-sm text-muted-foreground">
              {filteredRules.length} rule{filteredRules.length !== 1 ? "s" : ""}
            </span>
          </div>

          {filteredRules.length === 0 ? (
            <Card>
              <CardContent className="flex flex-col items-center justify-center py-16 text-muted-foreground">
                <Workflow className="h-8 w-8 mb-3 opacity-30" />
                <p className="text-sm">No workflow rules yet</p>
                <p className="text-xs mt-1">Create a rule to automate security response</p>
                <CreateRuleDialog onConfirm={handleCreateRule} />
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-3">
              {filteredRules.map((rule, i) => (
                <RuleCard
                  key={(rule.id as string) ?? i}
                  rule={rule}
                  onToggle={handleToggle}
                  onEdit={setSelectedRule}
                  onDuplicate={handleDuplicate}
                  onDelete={handleDelete}
                />
              ))
            )}
            </div>
          )}
        </TabsContent>

        <TabsContent value="templates">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {TEMPLATES.map((template) => {
              const triggerLabel = TRIGGER_OPTIONS.find((t) => t.value === template.trigger)?.label ?? template.trigger;
              const condLabel = CONDITION_OPTIONS.find((c) => c.value === template.condition)?.label ?? template.condition;
              const actionLabels = template.actions.map(
                (a) => ACTION_OPTIONS.find((opt) => opt.value === a)?.label ?? a
              );
              return (
                <Card key={template.id} className="hover:border-primary/40 transition-all">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm font-medium">{template.name}</CardTitle>
                    <CardDescription className="text-xs">{template.description}</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <div className="flex items-start gap-1.5 flex-wrap text-xs mb-3">
                      <span className="px-1.5 py-0.5 rounded bg-indigo-500/10 text-indigo-400 font-medium">IF</span>
                      <span className="px-1.5 py-0.5 rounded bg-muted">{triggerLabel}</span>
                      <span className="px-1.5 py-0.5 rounded bg-amber-500/10 text-amber-400 font-medium">AND</span>
                      <span className="px-1.5 py-0.5 rounded bg-muted">{condLabel}</span>
                      <span className="px-1.5 py-0.5 rounded bg-green-500/10 text-green-400 font-medium">THEN</span>
                      {actionLabels.map((a, i) => (
                        <span key={i} className="px-1.5 py-0.5 rounded bg-muted">{a}</span>
                      ))}
                    </div>
                    <Button
                      variant="outline"
                      size="sm"
                      className="w-full"
                      onClick={() => {
                        handleCreateRule({
                          id: `rule_from_template_${Date.now()}`,
                          name: template.name,
                          trigger: template.trigger,
                          condition: template.condition,
                          actions: template.actions,
                          enabled: true,
                          total_executions: 0,
                          last_triggered: "Never",
                          created_at: new Date().toISOString(),
                        });
                        // toast handled by mutation hook
                      }}
                    >
                      <Plus className="h-3.5 w-3.5 mr-2" />
                      Use Template
                    </Button>
                  </CardContent>
                </Card>
              );
            })}
          </div>
        </TabsContent>

        <TabsContent value="history">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <Activity className="h-4 w-4" />
                Execution History
              </CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Rule Name</TableHead>
                    <TableHead>Triggered At</TableHead>
                    <TableHead>Trigger Event</TableHead>
                    <TableHead>Actions Taken</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Duration</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {allRules.flatMap((rule) => {
                    const history = (rule.execution_history as Record<string, unknown>[]) ?? [];
                    return history.map((exec, i) => (
                      <TableRow key={`${rule.id}-${i}`}>
                        <TableCell className="font-medium text-sm">
                          {(rule.name as string) ?? "—"}
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground">
                          {(exec.triggered_at as string) ?? "—"}
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline" className="text-xs">
                            {(exec.trigger_event as string) ?? (rule.trigger as string) ?? "—"}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-xs">
                          {(exec.actions_taken as number) ?? "—"} actions
                        </TableCell>
                        <TableCell>
                          <Badge
                            variant={
                              (exec.status as string) === "success"
                                ? "secondary"
                                : "destructive"
                            }
                          >
                            {(exec.status as string) ?? "—"}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground">
                          {(exec.duration as string) ?? "—"}
                        </TableCell>
                      </TableRow>
                    ));
                  })}
                  {allRules.every((r) => !((r.execution_history as unknown[])?.length > 0)) && (
                    <TableRow>
                      <TableCell colSpan={6} className="text-center py-10 text-muted-foreground">
                        No execution history yet
                      </TableCell>
                    </TableRow>
                  )}
                </TableBody>
              </Table>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
