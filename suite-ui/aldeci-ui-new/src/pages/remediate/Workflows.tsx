import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Select, SelectTrigger, SelectContent, SelectItem, SelectValue } from "@/components/ui/select";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { DataTable } from "@/components/shared/data-table";
import {
  Zap, Plus, ArrowRight, Play, Pause, Trash2, CheckCircle2,
  AlertTriangle, Clock, Settings, Activity, ToggleLeft, ToggleRight, ChevronRight
} from "lucide-react";
import { workflowsApi } from "@/lib/api";
import { toast } from "sonner";

// ── Types ──────────────────────────────────────────────────────────────────
interface AutoRule {
  id: string;
  name: string;
  description: string;
  trigger: string;
  condition: string;
  action: string;
  enabled: boolean;
  runCount: number;
  lastRun: string;
  successRate: number;
  category: "Triage" | "Notify" | "Ticket" | "Escalation" | "Remediation";
}

interface ExecLog {
  id: string;
  ruleName: string;
  trigger: string;
  status: "success" | "failed" | "skipped";
  findingId?: string;
  detail: string;
  timestamp: string;
  duration: string;
}

interface RuleTemplate {
  id: string;
  name: string;
  description: string;
  category: "Triage" | "Notify" | "Ticket" | "Escalation" | "Remediation";
  trigger: string;
  action: string;
}

// ── Mock Data ──────────────────────────────────────────────────────────────
const MOCK_RULES: AutoRule[] = [
  { id: "rule-1", name: "Auto-triage Critical CVEs",       description: "When CVSSv3 ≥9.0 and asset is prod → set priority P1, notify owner", trigger: "finding.created",    condition: "cvss_score >= 9.0 AND environment == 'prod'", action: "set_priority(P1) + notify_owner(email)",  enabled: true,  runCount: 847,  lastRun: "5m ago",  successRate: 98, category: "Triage" },
  { id: "rule-2", name: "Create Jira for High/Critical",   description: "Auto-create Jira SEC ticket for H/C findings with SLA metadata", trigger: "finding.triaged",   condition: "severity IN ['Critical', 'High']",             action: "create_jira_ticket(SEC, Critical)",        enabled: true,  runCount: 1243, lastRun: "12m ago", successRate: 97, category: "Ticket" },
  { id: "rule-3", name: "SLA Breach Escalation",           description: "Escalate to manager if SLA breached and status still Open",      trigger: "sla.breached",      condition: "status == 'Open'",                             action: "notify_manager(slack) + page_oncall",     enabled: true,  runCount: 34,   lastRun: "1h ago",  successRate: 100, category: "Escalation" },
  { id: "rule-4", name: "Dependency Auto-PR",              description: "For SCA findings with known fix version → generate auto-fix PR",  trigger: "finding.created",   condition: "type == 'SCA' AND fix_available == true",      action: "generate_autofix_pr()",                   enabled: true,  runCount: 312,  lastRun: "4h ago",  successRate: 88, category: "Remediation" },
  { id: "rule-5", name: "False Positive Feedback Loop",    description: "If MPTE verdict is NOT_APPLICABLE → set finding to false_positive", trigger: "mpte.verdict",    condition: "verdict == 'NOT_APPLICABLE'",                  action: "update_finding(status=false_positive)",   enabled: true,  runCount: 67,   lastRun: "2d ago",  successRate: 100, category: "Triage" },
  { id: "rule-6", name: "Notify CTO on Data Breach Risk",  description: "Alert CTO email if data_breach risk_score > 90",                 trigger: "risk.updated",      condition: "data_breach_score > 90",                       action: "notify_executive(cto@corp, email)",       enabled: false, runCount: 3,    lastRun: "14d ago", successRate: 100, category: "Notify" },
  { id: "rule-7", name: "Auto-close Verified Findings",    description: "Auto-close finding when MPTE verifies remediation",             trigger: "mpte.verdict",      condition: "verdict == 'MITIGATED'",                       action: "update_finding(status=closed)",           enabled: true,  runCount: 89,   lastRun: "3h ago",  successRate: 96, category: "Triage" },
];

const MOCK_EXEC_LOG: ExecLog[] = [
  { id: "el-1", ruleName: "Auto-triage Critical CVEs",     trigger: "finding.created FIND-8901",   status: "success", findingId: "FIND-8901", detail: "Priority set to P1, owner notified via email", timestamp: "14:22:08", duration: "1.2s" },
  { id: "el-2", ruleName: "Create Jira for High/Critical", trigger: "finding.triaged FIND-8901",   status: "success", findingId: "FIND-8901", detail: "Jira SEC-1289 created and assigned",            timestamp: "14:22:11", duration: "2.1s" },
  { id: "el-3", ruleName: "Auto-triage Critical CVEs",     trigger: "finding.created FIND-8900",   status: "success", findingId: "FIND-8900", detail: "Priority set to P1, owner notified via email", timestamp: "14:18:44", duration: "0.9s" },
  { id: "el-4", ruleName: "Dependency Auto-PR",            trigger: "finding.created FIND-8850",   status: "success", findingId: "FIND-8850", detail: "PR #449 raised: autofix/minimist-bump-8850",    timestamp: "14:10:22", duration: "4.5s" },
  { id: "el-5", ruleName: "Auto-close Verified Findings",  trigger: "mpte.verdict FIND-8690",      status: "success", findingId: "FIND-8690", detail: "Finding closed: MITIGATED verdict",             timestamp: "13:55:01", duration: "0.8s" },
  { id: "el-6", ruleName: "Create Jira for High/Critical", trigger: "finding.triaged FIND-8622",   status: "failed",  findingId: "FIND-8622", detail: "Jira API error: 429 rate limit exceeded",       timestamp: "13:44:18", duration: "5.0s" },
  { id: "el-7", ruleName: "SLA Breach Escalation",         trigger: "sla.breached FIND-8755",      status: "success", findingId: "FIND-8755", detail: "Manager notified via Slack, oncall paged",      timestamp: "12:00:00", duration: "1.5s" },
];

const MOCK_TEMPLATES: RuleTemplate[] = [
  { id: "tmpl-1", name: "Critical CVE Triage",      description: "Auto-triage CVSS ≥9 findings with owner notification",     category: "Triage",      trigger: "finding.created",   action: "set_priority + notify_owner" },
  { id: "tmpl-2", name: "Jira Auto-ticket",         description: "Create Jira ticket for every triaged High/Critical",       category: "Ticket",      trigger: "finding.triaged",   action: "create_jira_ticket" },
  { id: "tmpl-3", name: "SLA Escalation",           description: "Escalate to manager when SLA is breached",                category: "Escalation",  trigger: "sla.breached",      action: "notify_manager + page_oncall" },
  { id: "tmpl-4", name: "Auto-close Mitigated",     description: "Auto-close findings when MPTE returns MITIGATED verdict",  category: "Triage",      trigger: "mpte.verdict",      action: "update_finding(closed)" },
  { id: "tmpl-5", name: "Slack Critical Alerts",    description: "Send Slack message to #sec-alerts for every Critical",    category: "Notify",      trigger: "finding.created",   action: "notify_channel(slack, #sec-alerts)" },
  { id: "tmpl-6", name: "Auto-fix Dependency PRs",  description: "Generate AutoFix PR when SCA vuln has known fix version", category: "Remediation", trigger: "finding.created",   action: "generate_autofix_pr" },
];

const categoryConfig = {
  Triage:      "bg-blue-500/10 text-blue-400 border-blue-500/30",
  Notify:      "bg-purple-500/10 text-purple-400 border-purple-500/30",
  Ticket:      "bg-orange-500/10 text-orange-400 border-orange-500/30",
  Escalation:  "bg-red-500/10 text-red-400 border-red-500/30",
  Remediation: "bg-green-500/10 text-green-400 border-green-500/30",
};

const logStatusConfig = {
  success: "bg-green-500/10 text-green-400 border-green-500/30",
  failed:  "bg-red-500/10 text-red-400 border-red-500/30",
  skipped: "bg-muted text-muted-foreground border-border",
};

// ── Rule Builder Panel ─────────────────────────────────────────────────────
function RuleBuilder({ onSave }: { onSave: () => void }) {
  const [trigger, setTrigger] = useState("finding.created");
  const [condition, setCondition] = useState("cvss_score >= 9.0");
  const [action, setAction] = useState("notify_owner");
  const [name, setName] = useState("New Rule");

  return (
    <Card className="border-border/50">
      <CardHeader className="pb-3">
        <CardTitle className="text-sm font-semibold">Rule Builder</CardTitle>
        <CardDescription className="text-xs">Visual Trigger → Condition → Action pipeline</CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Name */}
        <div className="space-y-1.5">
          <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Rule Name</label>
          <input value={name} onChange={e => setName(e.target.value)} className="w-full rounded-md border border-border bg-transparent px-3 py-1.5 text-sm outline-none focus:border-primary/50 transition-colors" />
        </div>

        {/* Pipeline visual */}
        <div className="flex items-center gap-2 flex-wrap">
          {/* Trigger */}
          <div className="flex-1 min-w-[140px] space-y-1.5">
            <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Trigger</label>
            <Select value={trigger} onValueChange={setTrigger}>
              <SelectTrigger className="text-xs h-9 border-blue-500/40 text-blue-400 bg-blue-500/5"><SelectValue /></SelectTrigger>
              <SelectContent>
                {["finding.created","finding.triaged","finding.updated","sla.breached","mpte.verdict","scan.completed","risk.updated"].map(t => <SelectItem key={t} value={t} className="text-xs">{t}</SelectItem>)}
              </SelectContent>
            </Select>
          </div>
          <ArrowRight className="h-4 w-4 text-muted-foreground shrink-0 mt-5" />
          {/* Condition */}
          <div className="flex-1 min-w-[140px] space-y-1.5">
            <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Condition</label>
            <input value={condition} onChange={e => setCondition(e.target.value)}
              className="w-full rounded-md border border-yellow-500/40 bg-yellow-500/5 text-yellow-300 px-3 py-2 text-xs outline-none focus:border-yellow-500/60 font-mono" />
          </div>
          <ArrowRight className="h-4 w-4 text-muted-foreground shrink-0 mt-5" />
          {/* Action */}
          <div className="flex-1 min-w-[140px] space-y-1.5">
            <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Action</label>
            <Select value={action} onValueChange={setAction}>
              <SelectTrigger className="text-xs h-9 border-green-500/40 text-green-400 bg-green-500/5"><SelectValue /></SelectTrigger>
              <SelectContent>
                {["notify_owner","notify_manager","create_jira_ticket","generate_autofix_pr","set_priority","update_finding","page_oncall","notify_channel"].map(a => <SelectItem key={a} value={a} className="text-xs">{a}</SelectItem>)}
              </SelectContent>
            </Select>
          </div>
        </div>

        <Button className="w-full" size="sm" onClick={onSave}>
          <Plus className="h-3.5 w-3.5 mr-1.5" /> Create Rule
        </Button>
      </CardContent>
    </Card>
  );
}

// ── Main Component ─────────────────────────────────────────────────────────
export default function Workflows() {
  const queryClient = useQueryClient();
  const [rules, setRules] = useState<AutoRule[]>(MOCK_RULES);

  const { data } = useQuery({
    queryKey: ["workflow-rules"],
    queryFn: () => workflowsApi.list(),
  });

  const deleteMutation = useMutation({
    mutationFn: (id: string) => workflowsApi.delete(id),
    onSuccess: (_, id) => {
      setRules(prev => prev.filter(r => r.id !== id));
      toast.success("Rule deleted");
    },
    onError: () => toast.error("Delete failed"),
  });

  const apiRules: AutoRule[] = (data as any)?.data ?? MOCK_RULES;
  const displayRules = apiRules.length ? apiRules : rules;

  const enabledCount = displayRules.filter(r => r.enabled).length;
  const totalRuns = displayRules.reduce((s, r) => s + r.runCount, 0);
  const avgSuccess = Math.round(displayRules.reduce((s, r) => s + r.successRate, 0) / displayRules.length);

  const toggleRule = (id: string) => {
    setRules(prev => prev.map(r => r.id === id ? { ...r, enabled: !r.enabled } : r));
    toast.success("Rule toggled");
  };

  const logColumns = [
    { key: "ruleName",  header: "Rule", render: (r: ExecLog) => <span className="text-xs font-medium">{r.ruleName}</span> },
    { key: "trigger",   header: "Trigger", render: (r: ExecLog) => <span className="text-[10px] font-mono text-muted-foreground">{r.trigger}</span> },
    { key: "status",    header: "Status",  render: (r: ExecLog) => <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${logStatusConfig[r.status]}`}>{r.status}</span> },
    { key: "detail",    header: "Detail", render: (r: ExecLog) => <span className="text-xs text-muted-foreground">{r.detail}</span> },
    { key: "duration",  header: "Duration" },
    { key: "timestamp", header: "Time" },
  ];

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="space-y-6">
      <PageHeader
        title="Workflows"
        description="Automation rules — configure trigger→condition→action pipelines for security orchestration"
        badge="REMEDIATE"
        actions={
          <Button size="sm" variant="outline" onClick={() => toast.info("Opening rule builder")}>
            <Plus className="h-3.5 w-3.5 mr-1.5" /> New Rule
          </Button>
        }
      />

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Active Rules" value={enabledCount} icon={Zap} trend="up" change={2} changeLabel="this month" />
        <KpiCard title="Total Executions" value={totalRuns} icon={Activity} trend="up" change={18} changeLabel="this week" />
        <KpiCard title="Avg Success Rate" value={`${avgSuccess}%`} icon={CheckCircle2} trend="up" change={1} changeLabel="vs last month" />
        <KpiCard title="Templates Available" value={MOCK_TEMPLATES.length} icon={Settings} trend="flat" />
      </div>

      <Tabs defaultValue="rules">
        <TabsList>
          <TabsTrigger value="rules">Active Rules</TabsTrigger>
          <TabsTrigger value="builder">Rule Builder</TabsTrigger>
          <TabsTrigger value="templates">Templates</TabsTrigger>
          <TabsTrigger value="log">Execution Log</TabsTrigger>
        </TabsList>

        <TabsContent value="rules" className="mt-4 space-y-3">
          {displayRules.map(rule => (
            <Card key={rule.id} className="border-border/50">
              <CardContent className="p-4">
                <div className="flex items-start gap-4">
                  {/* Toggle */}
                  <button onClick={() => toggleRule(rule.id)} className="mt-0.5">
                    {rule.enabled
                      ? <ToggleRight className="h-5 w-5 text-primary" />
                      : <ToggleLeft className="h-5 w-5 text-muted-foreground" />}
                  </button>
                  {/* Main content */}
                  <div className="flex-1 min-w-0 space-y-2">
                    <div className="flex items-start justify-between gap-2 flex-wrap">
                      <div>
                        <p className="text-sm font-semibold">{rule.name}</p>
                        <p className="text-xs text-muted-foreground mt-0.5">{rule.description}</p>
                      </div>
                      <span className={`shrink-0 inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${categoryConfig[rule.category]}`}>{rule.category}</span>
                    </div>
                    {/* Pipeline */}
                    <div className="flex items-center gap-1.5 text-xs flex-wrap">
                      <span className="rounded bg-blue-500/10 text-blue-400 border border-blue-500/20 px-2 py-0.5 font-mono text-[10px]">
                        {rule.trigger}
                      </span>
                      <ArrowRight className="h-3 w-3 text-muted-foreground shrink-0" />
                      <span className="rounded bg-yellow-500/10 text-yellow-400 border border-yellow-500/20 px-2 py-0.5 font-mono text-[10px]">
                        {rule.condition.length > 50 ? rule.condition.slice(0, 50) + "…" : rule.condition}
                      </span>
                      <ArrowRight className="h-3 w-3 text-muted-foreground shrink-0" />
                      <span className="rounded bg-green-500/10 text-green-400 border border-green-500/20 px-2 py-0.5 font-mono text-[10px]">
                        {rule.action}
                      </span>
                    </div>
                    <div className="flex gap-4 text-xs text-muted-foreground">
                      <span className="flex items-center gap-1"><Activity className="h-3 w-3" /> {rule.runCount.toLocaleString()} runs</span>
                      <span className="flex items-center gap-1 text-green-400"><CheckCircle2 className="h-3 w-3" /> {rule.successRate}%</span>
                      <span className="flex items-center gap-1"><Clock className="h-3 w-3" /> {rule.lastRun}</span>
                    </div>
                  </div>
                  <Button size="sm" variant="ghost" className="h-7 w-7 p-0 text-muted-foreground hover:text-red-400 shrink-0" onClick={() => deleteMutation.mutate(rule.id)}>
                    <Trash2 className="h-3.5 w-3.5" />
                  </Button>
                </div>
              </CardContent>
            </Card>
          ))}
        </TabsContent>

        <TabsContent value="builder" className="mt-4">
          <div className="max-w-2xl">
            <RuleBuilder onSave={() => toast.success("Rule created")} />
          </div>
        </TabsContent>

        <TabsContent value="templates" className="mt-4">
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
            {MOCK_TEMPLATES.map(tmpl => (
              <Card key={tmpl.id} className="border-border/50 hover:border-primary/40 transition-colors">
                <CardHeader className="pb-2">
                  <div className="flex items-start justify-between gap-2">
                    <CardTitle className="text-sm font-semibold">{tmpl.name}</CardTitle>
                    <span className={`shrink-0 inline-flex items-center rounded-full border px-1.5 py-0.5 text-[10px] font-medium ${categoryConfig[tmpl.category]}`}>{tmpl.category}</span>
                  </div>
                  <CardDescription className="text-xs">{tmpl.description}</CardDescription>
                </CardHeader>
                <CardContent className="space-y-2">
                  <div className="flex items-center gap-1.5 text-[10px] flex-wrap">
                    <span className="rounded bg-blue-500/10 text-blue-400 border border-blue-500/20 px-1.5 py-0.5 font-mono">{tmpl.trigger}</span>
                    <ArrowRight className="h-2.5 w-2.5 text-muted-foreground" />
                    <span className="rounded bg-green-500/10 text-green-400 border border-green-500/20 px-1.5 py-0.5 font-mono">{tmpl.action}</span>
                  </div>
                  <Button size="sm" variant="outline" className="w-full h-7 text-xs" onClick={() => toast.success(`Template "${tmpl.name}" applied`)}>
                    Use Template
                  </Button>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="log" className="mt-4">
          <DataTable columns={logColumns} data={MOCK_EXEC_LOG} emptyMessage="No executions recorded" />
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
