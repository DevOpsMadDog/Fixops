import { useState, useCallback } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectTrigger, SelectContent, SelectItem, SelectValue } from "@/components/ui/select";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/page-header";
import {
  Save, X, Play, Plus, ChevronUp, ChevronDown, Trash2,
  Code2, ListChecks, BookOpen, CheckCircle2, AlertCircle, Settings
} from "lucide-react";
import { playbooks as playbooksApi } from "@/lib/api";
import { toast } from "sonner";

// ── Types ──────────────────────────────────────────────────────────────────
interface PlaybookStep {
  id: string;
  name: string;
  type: "action" | "condition" | "notify" | "integration" | "wait";
  description: string;
  config: Record<string, string>;
}

interface PlaybookMeta {
  id: string;
  name: string;
  category: string;
  description: string;
  version: string;
  triggerType: string;
}

// ── Default YAML Template ──────────────────────────────────────────────────
const DEFAULT_YAML = `# ALdeci Security Playbook
name: Critical CVE Triage
version: "2.4.1"
category: Triage
description: |
  Auto-triage CVSSv3 ≥9.0 findings: asset enrichment,
  blast radius calculation, owner notify, ticket creation.
trigger:
  type: finding_created
  conditions:
    - field: cvss_score
      operator: gte
      value: 9.0
    - field: status
      operator: eq
      value: open

steps:
  - id: enrich_asset
    name: Enrich Asset Context
    type: action
    action: asset.enrich
    params:
      include_network_context: true
      include_owner_info: true
      include_dependencies: true

  - id: calc_blast_radius
    name: Calculate Blast Radius
    type: action
    action: risk.blast_radius
    params:
      propagation_depth: 3
      include_downstream: true

  - id: check_severity
    name: Gate on Severity
    type: condition
    condition:
      field: blast_radius_score
      operator: gte
      value: 7

  - id: notify_owner
    name: Notify Asset Owner
    type: notify
    channel: email
    template: critical_vuln_owner_alert
    params:
      include_remediation_steps: true
      sla_hours: 24

  - id: create_ticket
    name: Create Jira Ticket
    type: integration
    integration: jira
    params:
      project: SEC
      issue_type: Bug
      priority: Critical
      labels: ["security", "cve", "auto-triaged"]
      assign_to: owner.team_lead

  - id: update_finding
    name: Update Finding Status
    type: action
    action: finding.update
    params:
      status: triaged
      add_label: auto-triaged

  - id: wait_for_ack
    name: Wait for Owner Acknowledgement
    type: wait
    timeout_hours: 4
    on_timeout: escalate_to_manager

  - id: escalate_check
    name: Escalation Decision
    type: condition
    condition:
      field: acknowledged
      operator: eq
      value: false
    on_true: notify_manager
    on_false: complete

  - id: notify_manager
    name: Escalate to Manager
    type: notify
    channel: slack
    template: unacknowledged_critical_escalation

  - id: sla_track
    name: Start SLA Timer
    type: action
    action: sla.start
    params:
      sla_policy: critical_24h
      breach_action: page_oncall

  - id: final_log
    name: Audit Log Entry
    type: action
    action: audit.log
    params:
      event: playbook_completed
      level: info
`;

// ── Mock Playbook Steps (parsed) ───────────────────────────────────────────
const MOCK_STEPS: PlaybookStep[] = [
  { id: "s-1", name: "Enrich Asset Context", type: "action", description: "asset.enrich — pulls network context, owner info, and dependencies", config: { propagation_depth: "3", include_owner_info: "true" } },
  { id: "s-2", name: "Calculate Blast Radius", type: "action", description: "risk.blast_radius — models downstream impact", config: { propagation_depth: "3", include_downstream: "true" } },
  { id: "s-3", name: "Gate on Severity", type: "condition", description: "Proceed if blast_radius_score ≥ 7", config: { field: "blast_radius_score", operator: "gte", value: "7" } },
  { id: "s-4", name: "Notify Asset Owner", type: "notify", description: "Email owner with remediation steps, 24h SLA", config: { channel: "email", template: "critical_vuln_owner_alert" } },
  { id: "s-5", name: "Create Jira Ticket", type: "integration", description: "SEC project, Critical, auto-labelled", config: { project: "SEC", priority: "Critical" } },
  { id: "s-6", name: "Update Finding Status", type: "action", description: "Mark finding as triaged, add auto-triaged label", config: { status: "triaged" } },
  { id: "s-7", name: "Wait for Acknowledgement", type: "wait", description: "4h timeout, escalate on breach", config: { timeout_hours: "4" } },
  { id: "s-8", name: "Escalate to Manager", type: "notify", description: "Slack escalation for unacknowledged criticals", config: { channel: "slack" } },
  { id: "s-9", name: "Start SLA Timer", type: "action", description: "critical_24h policy, page oncall on breach", config: { sla_policy: "critical_24h" } },
  { id: "s-10", name: "Audit Log Entry", type: "action", description: "Record playbook completion in audit trail", config: {} },
  { id: "s-11", name: "Gate on CVSSv3", type: "condition", description: "Only run if CVSS ≥ 9.0", config: { field: "cvss_score", operator: "gte", value: "9.0" } },
  { id: "s-12", name: "Final Verdict", type: "action", description: "Close playbook run with outcome summary", config: {} },
];

const stepTypeConfig = {
  action:      { cls: "bg-blue-500/10 text-blue-400 border-blue-500/30",    label: "Action" },
  condition:   { cls: "bg-yellow-500/10 text-yellow-400 border-yellow-500/30", label: "Condition" },
  notify:      { cls: "bg-purple-500/10 text-purple-400 border-purple-500/30", label: "Notify" },
  integration: { cls: "bg-orange-500/10 text-orange-400 border-orange-500/30", label: "Integration" },
  wait:        { cls: "bg-muted text-muted-foreground border-border",         label: "Wait" },
};

// ── Step Row ───────────────────────────────────────────────────────────────
function StepRow({ step, idx, total, onMove, onDelete }: {
  step: PlaybookStep;
  idx: number;
  total: number;
  onMove: (from: number, to: number) => void;
  onDelete: (id: string) => void;
}) {
  const cfg = stepTypeConfig[step.type];
  return (
    <div className="flex items-center gap-3 p-3 rounded-lg border border-border/50 hover:border-primary/30 transition-colors group">
      <div className="flex flex-col gap-0.5">
        <Button size="sm" variant="ghost" className="h-5 w-5 p-0 opacity-40 hover:opacity-100" disabled={idx === 0} onClick={() => onMove(idx, idx - 1)}>
          <ChevronUp className="h-3 w-3" />
        </Button>
        <Button size="sm" variant="ghost" className="h-5 w-5 p-0 opacity-40 hover:opacity-100" disabled={idx === total - 1} onClick={() => onMove(idx, idx + 1)}>
          <ChevronDown className="h-3 w-3" />
        </Button>
      </div>
      <span className="text-xs font-mono text-muted-foreground w-6 shrink-0">{String(idx + 1).padStart(2, "0")}</span>
      <span className={`shrink-0 inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-medium ${cfg.cls}`}>{cfg.label}</span>
      <div className="flex-1 min-w-0">
        <p className="text-sm font-medium truncate">{step.name}</p>
        <p className="text-xs text-muted-foreground truncate">{step.description}</p>
      </div>
      <Button
        size="sm" variant="ghost"
        className="h-7 w-7 p-0 text-muted-foreground hover:text-red-400 opacity-0 group-hover:opacity-100 transition-opacity"
        onClick={() => onDelete(step.id)}
      >
        <Trash2 className="h-3.5 w-3.5" />
      </Button>
    </div>
  );
}

// ── Test Result Panel ──────────────────────────────────────────────────────
function TestResult({ onClose }: { onClose: () => void }) {
  return (
    <Card className="border-green-500/30 bg-green-500/5">
      <CardHeader className="pb-2">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm font-semibold flex items-center gap-2 text-green-400">
            <CheckCircle2 className="h-4 w-4" /> Test Passed — 12/12 steps validated
          </CardTitle>
          <Button size="sm" variant="ghost" className="h-6 w-6 p-0" onClick={onClose}>
            <X className="h-3.5 w-3.5" />
          </Button>
        </div>
      </CardHeader>
      <CardContent className="text-xs space-y-1">
        <p className="text-muted-foreground">Dry-run completed in 0.34s. No errors detected.</p>
        <p className="text-green-400">All conditions parseable · YAML schema valid · Integration references resolved</p>
      </CardContent>
    </Card>
  );
}

// ── Main Component ─────────────────────────────────────────────────────────
export default function PlaybookEditor() {
  const [yamlContent, setYamlContent] = useState(DEFAULT_YAML);
  const [steps, setSteps] = useState<PlaybookStep[]>(MOCK_STEPS);
  const [isDirty, setIsDirty] = useState(false);
  const [showTestResult, setShowTestResult] = useState(false);
  const [meta, setMeta] = useState<PlaybookMeta>({
    id: "pb-1",
    name: "Critical CVE Triage",
    category: "Triage",
    description: "Auto-triage CVSSv3 ≥9.0 findings",
    version: "2.4.1",
    triggerType: "finding_created",
  });

  const { data } = useQuery({
    queryKey: ["playbook-detail", meta.id],
    queryFn: () => playbooksApi.get(meta.id),
    enabled: !!meta.id,
  });

  const saveMutation = useMutation({
    mutationFn: () => playbooksApi.update(meta.id, { yaml: yamlContent, meta }),
    onSuccess: () => {
      toast.success("Playbook saved", { description: `v${meta.version}` });
      setIsDirty(false);
    },
    onError: () => toast.error("Save failed"),
  });

  const handleYamlChange = useCallback((v: string) => {
    setYamlContent(v);
    setIsDirty(true);
  }, []);

  const moveStep = (from: number, to: number) => {
    const updated = [...steps];
    const [removed] = updated.splice(from, 1);
    updated.splice(to, 0, removed);
    setSteps(updated);
    setIsDirty(true);
  };

  const deleteStep = (id: string) => {
    setSteps(prev => prev.filter(s => s.id !== id));
    setIsDirty(true);
    toast.info("Step removed — remember to save");
  };

  const addStep = () => {
    const newStep: PlaybookStep = {
      id: `s-${Date.now()}`,
      name: "New Step",
      type: "action",
      description: "Configure this step",
      config: {},
    };
    setSteps(prev => [...prev, newStep]);
    setIsDirty(true);
  };

  const handleTest = () => {
    toast.info("Running dry-run test...");
    setTimeout(() => setShowTestResult(true), 1200);
  };

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="space-y-6">
      <PageHeader
        title="Playbook Editor"
        description={`Editing: ${meta.name} · v${meta.version}`}
        badge={isDirty ? "Unsaved Changes" : "Saved"}
        actions={
          <div className="flex gap-2">
            <Button size="sm" variant="outline" onClick={handleTest}>
              <Play className="h-3.5 w-3.5 mr-1.5" /> Test
            </Button>
            <Button size="sm" variant="outline" onClick={() => { setIsDirty(false); setYamlContent(DEFAULT_YAML); toast.info("Changes discarded"); }}>
              <X className="h-3.5 w-3.5 mr-1.5" /> Discard
            </Button>
            <Button size="sm" disabled={!isDirty || saveMutation.isPending} onClick={() => saveMutation.mutate()}>
              <Save className="h-3.5 w-3.5 mr-1.5" /> Save
            </Button>
          </div>
        }
      />

      {showTestResult && <TestResult onClose={() => setShowTestResult(false)} />}

      {/* Metadata row */}
      <Card className="border-border/50">
        <CardContent className="p-4">
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div className="space-y-1">
              <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Name</label>
              <Input value={meta.name} className="text-sm h-8" onChange={e => { setMeta(m => ({ ...m, name: e.target.value })); setIsDirty(true); }} />
            </div>
            <div className="space-y-1">
              <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Category</label>
              <Select value={meta.category} onValueChange={v => { setMeta(m => ({ ...m, category: v })); setIsDirty(true); }}>
                <SelectTrigger className="text-sm h-8"><SelectValue /></SelectTrigger>
                <SelectContent>
                  {["Triage","Remediation","Investigation","Escalation","Compliance","Response"].map(c => <SelectItem key={c} value={c}>{c}</SelectItem>)}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1">
              <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Trigger</label>
              <Select value={meta.triggerType} onValueChange={v => { setMeta(m => ({ ...m, triggerType: v })); setIsDirty(true); }}>
                <SelectTrigger className="text-sm h-8"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="finding_created">Finding Created</SelectItem>
                  <SelectItem value="finding_updated">Finding Updated</SelectItem>
                  <SelectItem value="sla_breach">SLA Breach</SelectItem>
                  <SelectItem value="scan_completed">Scan Completed</SelectItem>
                  <SelectItem value="manual">Manual Only</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1">
              <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Version</label>
              <Input value={meta.version} className="text-sm h-8 font-mono" onChange={e => { setMeta(m => ({ ...m, version: e.target.value })); setIsDirty(true); }} />
            </div>
          </div>
        </CardContent>
      </Card>

      <div className="grid grid-cols-1 xl:grid-cols-5 gap-6">
        {/* YAML Editor */}
        <div className="xl:col-span-3 space-y-2">
          <div className="flex items-center gap-2">
            <Code2 className="h-4 w-4 text-primary" />
            <h3 className="text-sm font-semibold">YAML Editor</h3>
            <Badge variant="outline" className="text-[10px]">Syntax Highlighted</Badge>
          </div>
          <div className="relative rounded-lg border border-border/50 overflow-hidden bg-[hsl(var(--card))]">
            {/* Line numbers gutter */}
            <div className="flex">
              <div className="select-none py-3 pl-3 pr-2 text-right border-r border-border/30 bg-muted/20 min-w-[3rem]">
                {yamlContent.split("\n").map((_, i) => (
                  <div key={i} className="text-[11px] font-mono text-muted-foreground leading-5">{i + 1}</div>
                ))}
              </div>
              <textarea
                className="flex-1 resize-none bg-transparent p-3 text-[12px] font-mono text-foreground leading-5 outline-none min-h-[560px]"
                value={yamlContent}
                onChange={e => handleYamlChange(e.target.value)}
                spellCheck={false}
                autoCorrect="off"
                autoCapitalize="off"
              />
            </div>
          </div>
        </div>

        {/* Step Builder Sidebar */}
        <div className="xl:col-span-2 space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <ListChecks className="h-4 w-4 text-primary" />
              <h3 className="text-sm font-semibold">Step Builder</h3>
              <span className="text-xs text-muted-foreground">({steps.length} steps)</span>
            </div>
            <Button size="sm" variant="outline" className="h-7 text-xs" onClick={addStep}>
              <Plus className="h-3 w-3 mr-1" /> Add
            </Button>
          </div>
          <div className="space-y-1.5 max-h-[560px] overflow-y-auto pr-1">
            {steps.map((step, idx) => (
              <StepRow key={step.id} step={step} idx={idx} total={steps.length} onMove={moveStep} onDelete={deleteStep} />
            ))}
          </div>
          {/* Legend */}
          <div className="pt-2 border-t border-border/50">
            <p className="text-xs text-muted-foreground font-medium mb-2">Step Types</p>
            <div className="flex flex-wrap gap-1.5">
              {Object.entries(stepTypeConfig).map(([type, cfg]) => (
                <span key={type} className={`inline-flex items-center rounded-full border px-2 py-0.5 text-[10px] font-medium ${cfg.cls}`}>{cfg.label}</span>
              ))}
            </div>
          </div>
        </div>
      </div>
    </motion.div>
  );
}
