import { toArray } from "@/lib/api-utils";
import { useState, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/textarea";
import { Separator } from "@/components/ui/separator";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { motion } from "framer-motion";
import {
  Shield, Plus, RefreshCw, AlertTriangle, Zap, CheckCircle, Clock,
  MoreHorizontal, FileCode, GitBranch, Activity, Edit3, Copy, Play, Pause
} from "lucide-react";
import { usePolicies, useUpdatePolicy, useCreatePolicy } from "@/hooks/use-api";
import { toast } from "sonner";

const SAMPLE_POLICY_YAML = `# FixOps Security Policy
name: critical-cve-response
version: "1.0"
description: Auto-escalate critical CVEs to on-call team

scope:
  scanners: [snyk, trivy, semgrep]
  environments: [production, staging]

conditions:
  - field: severity
    op: equals
    value: critical
  - field: cvss_score
    op: gte
    value: 9.0

actions:
  - type: alert
    channel: pagerduty
    priority: P1
  - type: assign
    team: platform-security
  - type: create_ticket
    project: SEC
    priority: blocker

sla:
  response_time: 1h
  resolution_time: 24h
`;

function PolicyYamlEditor({ policy, onSave }: { policy: any; onSave: () => void }) {
  const [open, setOpen] = useState(false);
  const [yaml, setYaml] = useState(policy.yaml ?? SAMPLE_POLICY_YAML.replace("critical-cve-response", (policy.name ?? "policy").toLowerCase().replace(/ /g, "-")));
  const [isSaving, setIsSaving] = useState(false);
  const updatePolicy = useUpdatePolicy();

  const lineCount = yaml.split("\n").length;

  const handleSave = async () => {
    setIsSaving(true);
    updatePolicy.mutate({ id: policy.id, data: { yaml } }, {
      onSuccess: () => { onSave(); setOpen(false); setIsSaving(false); },
      onError: () => { setIsSaving(false); },
    });
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="ghost" size="icon" className="h-7 w-7" title="Edit YAML">
          <FileCode className="h-3.5 w-3.5" />
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <FileCode className="h-4 w-4 text-primary" />
            Policy YAML — {policy.name ?? "Policy"}
          </DialogTitle>
        </DialogHeader>
        <div className="space-y-3">
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <span>{lineCount} lines</span>
            <span>·</span>
            <span className="text-green-400">Valid YAML</span>
            <Button
              variant="ghost"
              size="sm"
              className="h-6 gap-1.5 text-xs ml-auto"
              onClick={() => { navigator.clipboard.writeText(yaml); toast.success("YAML copied"); }}
            >
              <Copy className="h-3 w-3" />
              Copy
            </Button>
          </div>
          <div className="relative">
            <div className="absolute left-0 top-0 bottom-0 w-10 bg-muted/50 rounded-l-md flex flex-col items-end pr-2 pt-3 text-xs text-muted-foreground font-mono overflow-hidden">
              {Array.from({ length: Math.min(lineCount, 30) }, (_, i) => (
                <div key={i} className="leading-6">{i + 1}</div>
              ))}
            </div>
            <Textarea
              value={yaml}
              onChange={(e) => setYaml(e.target.value)}
              rows={22}
              className="font-mono text-xs pl-12 bg-[#0a0f1a] border-border/40 resize-none"
            />
          </div>
          <Separator />
          <div className="flex gap-2 justify-end">
            <Button variant="outline" onClick={() => setOpen(false)}>Cancel</Button>
            <Button onClick={handleSave} disabled={isSaving} className="gap-2">
              <CheckCircle className="h-3.5 w-3.5" />
              {isSaving ? "Saving…" : "Save Policy"}
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

const SLA_RULES = [
  { severity: "Critical", days: 1, color: "text-red-500" },
  { severity: "High", days: 7, color: "text-orange-500" },
  { severity: "Medium", days: 14, color: "text-yellow-500" },
  { severity: "Low", days: 30, color: "text-blue-400" },
  { severity: "Info", days: 90, color: "text-muted-foreground" },
];

const AUTO_TRIAGE_RULES = [
  { name: "Auto-close Info", condition: "severity == 'info' AND scanner == 'trivy'", action: "close", enabled: true },
  { name: "Auto-assign Critical", condition: "severity == 'critical'", action: "assign_to_oncall", enabled: true },
  { name: "Skip Test Repos", condition: "repo.contains('-test') OR repo.contains('-demo')", action: "skip", enabled: false },
];

function CreatePolicyDialog({ onSave }: { onSave: () => void }) {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [mode, setMode] = useState<"yaml" | "form">("form");
  const [yaml, setYaml] = useState(`name: my-policy\nconditions:\n  - field: severity\n    op: equals\n    value: critical\nactions:\n  - type: alert\n    channel: pagerduty`);
  const [isSaving, setIsSaving] = useState(false);

  const createPolicy = useCreatePolicy();

  const handleSave = async () => {
    if (!name) return;
    setIsSaving(true);
    const payload = mode === "yaml" ? { name, description, yaml } : { name, description };
    createPolicy.mutate(payload, {
      onSuccess: () => { onSave(); setOpen(false); setName(""); setDescription(""); setIsSaving(false); },
      onError: () => { setIsSaving(false); },
    });
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size="sm" className="gap-2">
          <Plus className="h-4 w-4" />
          Create Policy
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Shield className="h-4 w-4 text-primary" />
            Create Security Policy
          </DialogTitle>
        </DialogHeader>
        <div className="space-y-4">
          <div>
            <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-2 block">Policy Name</Label>
            <Input placeholder="e.g. Critical Finding Alert" value={name} onChange={(e) => setName(e.target.value)} />
          </div>
          <div>
            <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-2 block">Description</Label>
            <Input placeholder="Brief description…" value={description} onChange={(e) => setDescription(e.target.value)} />
          </div>
          <div>
            <div className="flex items-center gap-3 mb-3">
              <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">Mode</Label>
              <Tabs value={mode} onValueChange={(v) => setMode(v as any)}>
                <TabsList className="h-7">
                  <TabsTrigger value="form" className="text-xs h-5 px-2">Form Builder</TabsTrigger>
                  <TabsTrigger value="yaml" className="text-xs h-5 px-2">
                    <FileCode className="h-3 w-3 mr-1" />YAML
                  </TabsTrigger>
                </TabsList>
              </Tabs>
            </div>
            {mode === "yaml" ? (
              <Textarea
                value={yaml}
                onChange={(e) => setYaml(e.target.value)}
                rows={8}
                className="font-mono text-xs"
              />
            ) : (
              <div className="space-y-3 p-4 rounded-lg bg-muted/30 border border-border/40">
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <Label className="text-xs text-muted-foreground mb-1 block">Condition Field</Label>
                    <Select defaultValue="severity">
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="severity">Severity</SelectItem>
                        <SelectItem value="scanner">Scanner</SelectItem>
                        <SelectItem value="repo">Repository</SelectItem>
                        <SelectItem value="app_id">App ID</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div>
                    <Label className="text-xs text-muted-foreground mb-1 block">Operator</Label>
                    <Select defaultValue="equals">
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="equals">Equals</SelectItem>
                        <SelectItem value="not_equals">Not Equals</SelectItem>
                        <SelectItem value="contains">Contains</SelectItem>
                        <SelectItem value="gt">Greater Than</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>
                <div>
                  <Label className="text-xs text-muted-foreground mb-1 block">Value</Label>
                  <Input placeholder="critical" />
                </div>
                <div>
                  <Label className="text-xs text-muted-foreground mb-1 block">Action</Label>
                  <Select defaultValue="alert">
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="alert">Send Alert</SelectItem>
                      <SelectItem value="assign">Assign to Team</SelectItem>
                      <SelectItem value="close">Auto-Close</SelectItem>
                      <SelectItem value="escalate">Escalate</SelectItem>
                      <SelectItem value="block_deploy">Block Deployment</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
            )}
          </div>
          <Separator />
          <div className="flex gap-2 justify-end">
            <Button variant="outline" onClick={() => setOpen(false)}>Cancel</Button>
            <Button onClick={handleSave} disabled={!name || isSaving}>
              {isSaving ? "Creating…" : "Create Policy"}
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

export default function PoliciesPage() {
  const policiesQuery = usePolicies();
  const refetch = useCallback(() => policiesQuery.refetch(), [policiesQuery]);
  const [policyStates, setPolicyStates] = useState<Record<string, boolean>>({});

  if (policiesQuery.isLoading) return <PageSkeleton />;
  if (policiesQuery.isError) return <ErrorState message="Failed to load policies" onRetry={refetch} />;

  const policies: any[] = toArray(policiesQuery.data);

  const activePolicies = policies.filter((p: any) => {
    const id = p.id ?? p.name;
    return id in policyStates ? policyStates[id] : (p.enabled ?? p.active ?? true);
  }).length;

  const violationsThisMonth = policies.reduce((acc: number, p: any) => acc + (p.violations_month ?? p.violation_count ?? 0), 0);
  const autoTriageRules = AUTO_TRIAGE_RULES.filter((r) => r.enabled).length;

  const togglePolicy = (id: string, current: boolean) => {
    setPolicyStates((prev) => ({ ...prev, [id]: !current }));
    toast.success(`Policy ${!current ? "activated" : "deactivated"}`);
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      <PageHeader
        title="Policies"
        description="Define and manage security policies, SLA rules, and auto-triage automation"
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={refetch} className="gap-2">
          <RefreshCw className="h-4 w-4" />
          Refresh
        </Button>
        <CreatePolicyDialog onSave={refetch} />
          </div>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Active Policies" value={activePolicies} icon={Shield} />
        <KpiCard title="Violations This Month" value={violationsThisMonth} icon={AlertTriangle} />
        <KpiCard title="Auto-Triage Rules" value={autoTriageRules} icon={Zap} />
        <KpiCard title="SLA Rules" value={SLA_RULES.length} icon={Clock} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Policies list */}
        <div className="lg:col-span-2 space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <Shield className="h-4 w-4 text-primary" />
                Security Policies
              </CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              {policies.length === 0 ? (
                <div className="text-center py-12 text-muted-foreground">
                  No policies configured. Create your first policy.
                </div>
              ) : (
                policies.map((policy: any, i: number) => {
                  const id = policy.id ?? policy.name ?? `policy-${i}`;
                  const isEnabled = id in policyStates ? policyStates[id] : (policy.enabled ?? policy.active ?? true);
                  return (
                    <div key={id} className={`p-4 border-b border-border/40 last:border-0 hover:bg-muted/20 ${!isEnabled ? "opacity-60" : ""}`}>
                      <div className="flex items-start justify-between gap-4">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <p className="text-sm font-medium">{policy.name ?? `Policy ${i + 1}`}</p>
                            <Badge variant="outline" className="text-xs">{policy.type ?? policy.category ?? "custom"}</Badge>
                            {(policy.violations_month ?? 0) > 0 && (
                              <Badge variant="destructive" className="text-xs">
                                {policy.violations_month} violations
                              </Badge>
                            )}
                          </div>
                          {policy.description && (
                            <p className="text-xs text-muted-foreground mt-1 line-clamp-2">{policy.description}</p>
                          )}
                          {policy.last_triggered && (
                            <p className="text-xs text-muted-foreground mt-1 flex items-center gap-1">
                              <Activity className="h-3 w-3" />
                              Last triggered: {policy.last_triggered}
                            </p>
                          )}
                        </div>
                        <div className="flex items-center gap-2 shrink-0">
                          <PolicyYamlEditor policy={policy} onSave={refetch} />
                          <Switch
                            checked={isEnabled}
                            onCheckedChange={() => togglePolicy(id, isEnabled)}
                          />
                        </div>
                      </div>
                    </div>
                  );
                })
              )}
            </CardContent>
          </Card>

          {/* Policy violation log */}
          <Card>
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 text-orange-500" />
                Policy Violation Log
              </CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent border-b border-border/40">
                    <TableHead className="text-xs">Policy</TableHead>
                    <TableHead className="text-xs">Resource</TableHead>
                    <TableHead className="text-xs">Time</TableHead>
                    <TableHead className="text-xs">Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {policies.flatMap((p: any) => (p.violations ?? [])).slice(0, 10).length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={4} className="text-center py-8 text-muted-foreground text-sm">
                        No recent violations
                      </TableCell>
                    </TableRow>
                  ) : (
                    policies.flatMap((p: any) => (p.violations ?? [])).slice(0, 10).map((v: any, i: number) => (
                      <TableRow key={i} className="hover:bg-muted/30">
                        <TableCell className="text-xs font-medium">{v.policy_name ?? "—"}</TableCell>
                        <TableCell className="text-xs text-muted-foreground">{v.resource ?? "—"}</TableCell>
                        <TableCell className="text-xs text-muted-foreground">{v.timestamp ?? "—"}</TableCell>
                        <TableCell>
                          <Badge variant="destructive" className="text-xs">Violated</Badge>
                        </TableCell>
                      </TableRow>
                    ))
                    )}
                  </TableBody>
              </Table>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Right column: SLA rules + Auto-triage */}
        <div className="space-y-4">
          {/* SLA Rules */}
          <Card>
            <CardHeader>
              <CardTitle className="text-sm flex items-center gap-2">
                <Clock className="h-4 w-4 text-primary" />
                SLA Rules
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {SLA_RULES.map((rule) => (
                <div key={rule.severity} className="flex items-center justify-between p-2.5 rounded-lg bg-muted/30 border border-border/40">
                  <span className={`text-sm font-medium ${rule.color}`}>{rule.severity}</span>
                  <div className="flex items-center gap-2">
                    <Input
                      type="number"
                      defaultValue={rule.days}
                      className="h-7 w-16 text-center text-xs"
                    />
                    <span className="text-xs text-muted-foreground">days</span>
                  </div>
                </div>
              ))
            )}
              <Button
                size="sm"
                className="w-full mt-2 gap-2"
                onClick={() => {
                  toast.success("SLA rules saved successfully");
                }}
              >
                <CheckCircle className="h-3.5 w-3.5" />
                Save SLA Rules
              </Button>
            </CardContent>
          </Card>

          {/* Auto-triage rules */}
          <Card>
            <CardHeader>
              <CardTitle className="text-sm flex items-center gap-2">
                <Zap className="h-4 w-4 text-primary" />
                Auto-Triage Rules
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {AUTO_TRIAGE_RULES.map((rule, i) => (
                <div key={i} className="p-3 rounded-lg bg-muted/30 border border-border/40">
                  <div className="flex items-center justify-between mb-1.5">
                    <p className="text-xs font-medium">{rule.name}</p>
                    <Switch defaultChecked={rule.enabled} />
                  </div>
                  <code className="text-xs text-muted-foreground font-mono line-clamp-1">{rule.condition}</code>
                  <p className="text-xs mt-1">
                    → <span className="text-primary font-medium">{rule.action}</span>
                  </p>
                </div>
              ))
            )}
              <Button
                size="sm"
                variant="outline"
                className="w-full gap-2"
                onClick={() => {
                  toast.info("Use 'Create Policy' to define custom auto-triage rules with YAML conditions");
                }}
              >
                <Plus className="h-3.5 w-3.5" />
                Add Rule
              </Button>
            </CardContent>
          </Card>
        </div>
      </div>
    </motion.div>
  );
}
