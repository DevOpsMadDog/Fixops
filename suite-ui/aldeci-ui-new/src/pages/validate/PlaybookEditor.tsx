import { toArray } from "@/lib/api-utils";
import { useState, useCallback, useEffect } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Textarea } from "@/components/ui/textarea";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
import { PageHeader } from "@/components/shared/page-header";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { motion } from "framer-motion";
import {
  Plus,
  Trash2,
  ChevronUp,
  ChevronDown,
  Save,
  Play,
  ArrowLeft,
  Zap,
  GitBranch,
  Activity,
  Code,
  Eye,
} from "lucide-react";
import { usePlaybooks, useCreatePlaybook, useUpdatePlaybook, useRunPlaybook } from "@/hooks/use-api";
import { toast } from "sonner";

type StepType = "trigger" | "condition" | "action" | "notification" | "wait";

interface PlaybookStep {
  id: string;
  type: StepType;
  name: string;
  config: string;
  description?: string;
}

const STEP_TYPES: { value: StepType; label: string; icon: React.ReactNode; color: string }[] = [
  { value: "trigger", label: "Trigger", icon: <Zap className="h-3.5 w-3.5" />, color: "#6366f1" },
  { value: "condition", label: "Condition", icon: <GitBranch className="h-3.5 w-3.5" />, color: "#f59e0b" },
  { value: "action", label: "Action", icon: <Activity className="h-3.5 w-3.5" />, color: "#22c55e" },
  { value: "notification", label: "Notification", icon: <Eye className="h-3.5 w-3.5" />, color: "#3b82f6" },
  { value: "wait", label: "Wait", icon: <Code className="h-3.5 w-3.5" />, color: "#8b5cf6" },
];

const TRIGGER_OPTIONS = [
  "Finding Created",
  "Severity Threshold Crossed",
  "SLA Approaching",
  "CVE Published",
  "Scan Completed",
  "Manual Trigger",
  "Schedule (Cron)",
  "Webhook",
];

const ACTION_OPTIONS = [
  "Create Remediation Task",
  "Send Slack Notification",
  "Send Email",
  "Open Jira Ticket",
  "Update Finding Status",
  "Run MPTE Scan",
  "Generate Evidence Bundle",
  "Assign to Team Member",
  "Escalate to Manager",
  "Run Script",
];

const CONDITION_OPTIONS = [
  "Severity == Critical",
  "Severity >= High",
  "Asset.exposure == Internet",
  "Days Since Discovery > 7",
  "CVSS Score > 9",
  "Tag Contains",
  "Assignee Is Empty",
  "Status == Open",
];

function getStepOptions(type: StepType): string[] {
  if (type === "trigger") return TRIGGER_OPTIONS;
  if (type === "action") return ACTION_OPTIONS;
  if (type === "condition") return CONDITION_OPTIONS;
  return [];
}

function generateYaml(name: string, description: string, steps: PlaybookStep[]): string {
  const lines: string[] = [
    `name: "${name || "Untitled Playbook"}"`,
    `description: "${description || ""}"`,
    `version: "1.0"`,
    `steps:`,
  ];
  steps.forEach((step, i) => {
    lines.push(`  - id: step_${i + 1}`);
    lines.push(`    type: ${step.type}`);
    lines.push(`    name: "${step.name || `Step ${i + 1}`}"`);
    if (step.config) lines.push(`    config: "${step.config}"`);
    if (step.description) lines.push(`    description: "${step.description}"`);
  });
  return lines.join("\n");
}

function StepCard({
  step,
  index,
  total,
  onChange,
  onDelete,
  onMoveUp,
  onMoveDown,
}: {
  step: PlaybookStep;
  index: number;
  total: number;
  onChange: (updated: PlaybookStep) => void;
  onDelete: () => void;
  onMoveUp: () => void;
  onMoveDown: () => void;
}) {
  const typeCfg = STEP_TYPES.find((t) => t.value === step.type);
  const options = getStepOptions(step.type);

  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      exit={{ opacity: 0, y: -8 }}
      className="relative"
    >
      <Card
        className="border"
        style={{ borderLeftColor: typeCfg?.color, borderLeftWidth: 3 }}
      >
        <CardHeader className="pb-2">
          <div className="flex items-center gap-2">
            <span
              className="flex items-center gap-1 text-xs font-medium px-2 py-0.5 rounded"
              style={{ color: typeCfg?.color, background: typeCfg?.color + "22" }}
            >
              {typeCfg?.icon}
              {typeCfg?.label ?? step.type}
            </span>
            <span className="text-xs text-muted-foreground">Step {index + 1}</span>
            <div className="ml-auto flex items-center gap-1">
              <Button
                variant="ghost"
                size="sm"
                className="h-6 w-6 p-0"
                disabled={index === 0}
                onClick={onMoveUp}
              >
                <ChevronUp className="h-3.5 w-3.5" />
              </Button>
              <Button
                variant="ghost"
                size="sm"
                className="h-6 w-6 p-0"
                disabled={index === total - 1}
                onClick={onMoveDown}
              >
                <ChevronDown className="h-3.5 w-3.5" />
              </Button>
              <Button
                variant="ghost"
                size="sm"
                className="h-6 w-6 p-0 text-destructive hover:text-destructive"
                onClick={onDelete}
              >
                <Trash2 className="h-3.5 w-3.5" />
              </Button>
            </div>
          </div>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div className="space-y-1.5">
              <Label className="text-xs">Step Name</Label>
              <Input
                placeholder={`${typeCfg?.label ?? "Step"} name`}
                value={step.name}
                onChange={(e) => onChange({ ...step, name: e.target.value })}
              />
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs">Type</Label>
              <Select
                value={step.type}
                onValueChange={(v) => onChange({ ...step, type: v as StepType, config: "" })}
              >
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {STEP_TYPES.map((t) => (
                    <SelectItem key={t.value} value={t.value}>
                      {t.label}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>
          {options.length > 0 && (
            <div className="space-y-1.5">
              <Label className="text-xs">Configuration</Label>
              <Select
                value={step.config}
                onValueChange={(v) => onChange({ ...step, config: v })}
              >
                <SelectTrigger>
                  <SelectValue placeholder="Select configuration..." />
                </SelectTrigger>
                <SelectContent>
                  {options.map((opt) => (
                    <SelectItem key={opt} value={opt}>
                      {opt}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          )}
          <div className="space-y-1.5">
            <Label className="text-xs">Description (optional)</Label>
            <Input
              placeholder="What does this step do?"
              value={step.description ?? ""}
              onChange={(e) => onChange({ ...step, description: e.target.value })}
            />
          </div>
        </CardContent>
      </Card>
      {index < total - 1 && (
        <div className="flex justify-center my-1">
          <div className="w-px h-4 bg-border" />
        </div>
      )}
    </motion.div>
  );
}

export default function PlaybookEditor() {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const editId = searchParams.get("id");
  const playbooksQuery = usePlaybooks();

  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [category, setCategory] = useState("Incident Response");
  const [trigger, setTrigger] = useState("Manual Trigger");
  const [steps, setSteps] = useState<PlaybookStep[]>([]);
  const [testDialogOpen, setTestDialogOpen] = useState(false);
  const [testRunning, setTestRunning] = useState(false);

  const refetch = useCallback(() => playbooksQuery.refetch(), [playbooksQuery]);

  // Load existing playbook if editing
  useEffect(() => {
    if (editId && playbooksQuery.data) {
      const existing: Record<string, unknown>[] =
        toArray(playbooksQuery.data);
      const pb = existing.find((p) => (p.id as string) === editId);
      if (pb) {
        setName((pb.name as string) ?? "");
        setDescription((pb.description as string) ?? "");
        setCategory((pb.category as string) ?? "Incident Response");
        setTrigger((pb.trigger as string) ?? "Manual Trigger");
        const loadedSteps = (pb.steps as PlaybookStep[]) ?? [];
        setSteps(loadedSteps);
      }
    }
  }, [editId, playbooksQuery.data]);

  if (playbooksQuery.isLoading && editId) return <PageSkeleton />;
  if (playbooksQuery.isError && editId)
    return <ErrorState message="Failed to load playbook" onRetry={refetch} />;

  const addStep = (type: StepType = "action") => {
    setSteps((prev) => [
      ...prev,
      {
        id: `step_${Date.now()}`,
        type,
        name: "",
        config: "",
      },
    ]);
  };

  const updateStep = (index: number, updated: PlaybookStep) => {
    setSteps((prev) => prev.map((s, i) => (i === index ? updated : s)));
  };

  const deleteStep = (index: number) => {
    setSteps((prev) => prev.filter((_, i) => i !== index));
  };

  const moveStep = (index: number, direction: "up" | "down") => {
    setSteps((prev) => {
      const next = [...prev];
      const swapIdx = direction === "up" ? index - 1 : index + 1;
      [next[index], next[swapIdx]] = [next[swapIdx], next[index]];
      return next;
    });
  };

  const createPlaybook = useCreatePlaybook();
  const updatePlaybook = useUpdatePlaybook();
  const runPlaybook = useRunPlaybook();

  const handleSave = () => {
    if (!name.trim()) {
      toast.error("Playbook name is required");
      return;
    }
    const payload = { name, description, steps, category, trigger };
    if (editId) {
      updatePlaybook.mutate({ id: editId, data: payload });
    } else {
      createPlaybook.mutate(payload);
    }
  };

  const handleTest = () => {
    if (editId) {
      runPlaybook.mutate(editId);
    } else {
      toast.error("Save the playbook first before testing");
    }
  };

  const yaml = generateYaml(name, description, steps);

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      <PageHeader
        title={editId ? "Edit Playbook" : "Create Playbook"}
        description="Visual playbook editor — build automation workflows with triggers, conditions, and actions"
      >
        <div className="flex gap-2">
          <Button variant="outline" onClick={() => navigate("/validate/playbooks")}>
            <ArrowLeft className="h-4 w-4 mr-2" />
            Back
          </Button>
          <Button variant="outline" onClick={() => setTestDialogOpen(true)}>
            <Play className="h-4 w-4 mr-2" />
            Test
          </Button>
          <Button onClick={handleSave}>
            <Save className="h-4 w-4 mr-2" />
            Save Playbook
          </Button>
        </div>
      </PageHeader>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Left: Editor */}
        <div className="xl:col-span-2 space-y-4">
          {/* Metadata */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">Playbook Details</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <Label>Playbook Name *</Label>
                  <Input
                    placeholder="e.g. Critical Finding Response"
                    value={name}
                    onChange={(e) => setName(e.target.value)}
                  />
                </div>
                <div className="space-y-1.5">
                  <Label>Category</Label>
                  <Select value={category} onValueChange={setCategory}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="Incident Response">Incident Response</SelectItem>
                      <SelectItem value="Compliance">Compliance</SelectItem>
                      <SelectItem value="Remediation">Remediation</SelectItem>
                      <SelectItem value="Threat Hunting">Threat Hunting</SelectItem>
                      <SelectItem value="Onboarding">Onboarding</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-1.5 md:col-span-2">
                  <Label>Description</Label>
                  <Textarea
                    placeholder="Describe what this playbook does..."
                    value={description}
                    onChange={(e) => setDescription(e.target.value)}
                    rows={2}
                  />
                </div>
                <div className="space-y-1.5">
                  <Label>Default Trigger</Label>
                  <Select value={trigger} onValueChange={setTrigger}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {TRIGGER_OPTIONS.map((t) => (
                        <SelectItem key={t} value={t}>
                          {t}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Steps */}
          <Card>
            <CardHeader className="pb-2">
              <div className="flex items-center justify-between">
                <CardTitle className="text-sm font-medium">
                  Steps
                  <Badge variant="secondary" className="ml-2 text-xs">
                    {steps.length}
                  </Badge>
                </CardTitle>
                <div className="flex gap-2">
                  {STEP_TYPES.map((t) => (
                    <Button
                      key={t.value}
                      variant="outline"
                      size="sm"
                      className="h-7 text-xs"
                      style={{ borderColor: t.color + "44", color: t.color }}
                      onClick={() => addStep(t.value)}
                    >
                      <Plus className="h-3 w-3 mr-1" />
                      {t.label}
                    </Button>
                  ))}
                </div>
              </div>
            </CardHeader>
            <CardContent>
              {steps.length === 0 ? (
                <div className="text-center py-12 text-muted-foreground">
                  <p className="text-sm">No steps yet.</p>
                  <p className="text-xs mt-1">
                    Add a Trigger, Condition, or Action to get started.
                  </p>
                  <Button
                    variant="outline"
                    size="sm"
                    className="mt-4"
                    onClick={() => addStep("trigger")}
                  >
                    <Plus className="h-4 w-4 mr-2" />
                    Add First Step
                  </Button>
                </div>
              ) : (
                <div className="space-y-0">
                  {steps.map((step, i) => (
                    <StepCard
                      key={step.id}
                      step={step}
                      index={i}
                      total={steps.length}
                      onChange={(updated) => updateStep(i, updated)}
                      onDelete={() => deleteStep(i)}
                      onMoveUp={() => moveStep(i, "up")}
                      onMoveDown={() => moveStep(i, "down")}
                    />
                  ))
                  )}
                <div className="flex justify-center mt-3">
                    <Button
                      variant="outline"
                      size="sm"
                      className="border-dashed"
                      onClick={() => addStep("action")}
                    >
                      <Plus className="h-4 w-4 mr-2" />
                      Add Step
                    </Button>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        {/* Right: YAML Preview */}
        <div className="space-y-4">
          <Card className="sticky top-4">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <Code className="h-4 w-4" />
                YAML Preview
              </CardTitle>
            </CardHeader>
            <CardContent>
              <pre className="text-[11px] bg-muted/50 p-3 rounded-md overflow-x-auto whitespace-pre-wrap font-mono leading-relaxed max-h-[60vh] overflow-y-auto">
                {yaml}
              </pre>
              <Button
                variant="outline"
                size="sm"
                className="w-full mt-3"
                onClick={() => {
                  navigator.clipboard.writeText(yaml);
                  toast.success("YAML copied to clipboard");
                }}
              >
                Copy YAML
              </Button>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium">Summary</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              {[
                {
                  label: "Steps",
                  val: steps.length,
                },
                {
                  label: "Triggers",
                  val: steps.filter((s) => s.type === "trigger").length,
                },
                {
                  label: "Conditions",
                  val: steps.filter((s) => s.type === "condition").length,
                },
                {
                  label: "Actions",
                  val: steps.filter((s) => s.type === "action").length,
                },
              ].map((item) => (
                <div key={item.label} className="flex items-center justify-between text-sm">
                  <span className="text-muted-foreground">{item.label}</span>
                  <span className="font-semibold">{item.val}</span>
                </div>
              ))}
            </CardContent>
          </Card>
        </div>
      </div>

      {/* Test Dialog */}
      <Dialog open={testDialogOpen} onOpenChange={setTestDialogOpen}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Test Playbook</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <p className="text-sm text-muted-foreground">
              Dry-run this playbook in a sandbox environment. No real actions will be taken.
            </p>
            <div className="bg-muted/50 rounded-lg p-3">
              <p className="font-semibold text-sm">{name || "Untitled Playbook"}</p>
              <p className="text-xs text-muted-foreground mt-1">{steps.length} steps</p>
            </div>
            {testRunning && (
              <div className="space-y-2">
                {steps.slice(0, 3).map((step, i) => (
                  <div key={step.id} className="flex items-center gap-2 text-xs">
                    <div className="h-1.5 w-1.5 rounded-full bg-primary animate-pulse" />
                    Running: {step.name || `Step ${i + 1}`}
                  </div>
                ))}
                {steps.length > 3 && (
                  <p className="text-xs text-muted-foreground">
                    +{steps.length - 3} more steps...
                  </p>
                )}
              </div>
            )}
            {!testRunning && (
              <p className="text-xs text-muted-foreground">
                Click "Run Test" to begin dry-run execution.
              </p>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setTestDialogOpen(false)}>Cancel</Button>
            <Button onClick={handleTest} disabled={testRunning || steps.length === 0}>
              {testRunning ? "Running..." : "Run Test"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </motion.div>
  );
}
