import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  Lock,
  Plus,
  CheckCircle,
  XCircle,
  Clock,
  Zap,
  AlignLeft,
  Save,
  ChevronRight,
  ToggleLeft,
  ToggleRight,
  AlertCircle,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { policiesApi } from "@/lib/api";
import { toast } from "sonner";

// ─── Mock data ───────────────────────────────────────────────────────────────
const MOCK_POLICIES = [
  { id: "pol-001", name: "Critical Severity SLA", type: "SLA", status: "active", scope: "all", description: "Critical findings must be triaged within 4 hours and remediated within 48 hours.", violations: 2, last_updated: "2026-02-15" },
  { id: "pol-002", name: "High Severity SLA", type: "SLA", status: "active", scope: "all", description: "High findings must be triaged within 24 hours and remediated within 7 days.", violations: 8, last_updated: "2026-02-15" },
  { id: "pol-003", name: "Auto-Triage: CVSS ≥ 9.0", type: "Auto-Triage", status: "active", scope: "all", description: "Automatically escalate findings with CVSS score ≥ 9.0 to Critical priority.", violations: 0, last_updated: "2026-01-20" },
  { id: "pol-004", name: "Dependency Age Policy", type: "SLA", status: "active", scope: "code", description: "Flag dependencies older than 2 years with known CVEs as high priority.", violations: 14, last_updated: "2026-02-01" },
  { id: "pol-005", name: "Container Base Image", type: "Compliance", status: "active", scope: "containers", description: "All container images must use approved base images from the internal registry.", violations: 3, last_updated: "2026-03-01" },
  { id: "pol-006", name: "Secret Detection Auto-Block", type: "Auto-Triage", status: "active", scope: "secrets", description: "Automatically block PRs containing hardcoded secrets and notify team lead.", violations: 0, last_updated: "2026-02-28" },
  { id: "pol-007", name: "IaC Mandatory Controls", type: "Compliance", status: "active", scope: "iac", description: "Enforce CIS Benchmark Level 2 controls on all Terraform and CloudFormation.", violations: 7, last_updated: "2026-01-15" },
  { id: "pol-008", name: "Third-Party License Check", type: "Compliance", status: "draft", scope: "code", description: "Block GPL-licensed dependencies in commercial product repositories.", violations: 0, last_updated: "2026-03-05" },
  { id: "pol-009", name: "DAST Coverage Requirement", type: "Compliance", status: "active", scope: "dast", description: "All public-facing APIs must have DAST coverage with Nuclei or OWASP ZAP weekly.", violations: 2, last_updated: "2026-02-10" },
  { id: "pol-010", name: "Evidence Collection SLA", type: "SLA", status: "active", scope: "compliance", description: "SOC2 evidence must be collected within 5 days of period end.", violations: 0, last_updated: "2026-01-30" },
  { id: "pol-011", name: "AI Model Security Review", type: "Compliance", status: "draft", scope: "ml", description: "All AI/ML models must pass security review before production deployment.", violations: 0, last_updated: "2026-03-07" },
  { id: "pol-012", name: "Reachability Scoring", type: "Auto-Triage", status: "active", scope: "all", description: "Deprioritize findings with FAIL reachability score < 0.2 to informational.", violations: 0, last_updated: "2026-02-20" },
];

const SLA_RULES = [
  { severity: "Critical", triage_hours: 4, remediation_days: 2, escalation_hours: 6, color: "text-red-400" },
  { severity: "High", triage_hours: 24, remediation_days: 7, escalation_hours: 48, color: "text-orange-400" },
  { severity: "Medium", triage_hours: 72, remediation_days: 30, escalation_hours: 96, color: "text-yellow-400" },
  { severity: "Low", triage_hours: 168, remediation_days: 90, escalation_hours: 336, color: "text-blue-400" },
];

const SAMPLE_POLICY_YAML = `name: critical-severity-sla
version: "1.0"
type: sla
scope: all
enabled: true

sla:
  triage:
    max_hours: 4
    notify: [slack, pagerduty]
  remediation:
    max_hours: 48
    escalate_after_hours: 6
    auto_assign: security-lead

triggers:
  - severity: critical
  - cvss_score: ">= 9.0"
  - tags:
      - rce
      - sqli
      - auth_bypass

actions:
  on_breach:
    - create_jira_ticket
    - notify_ciso
    - escalate_pagerduty
  on_resolve:
    - close_ticket
    - log_audit_event`;

export default function Policies() {
  const [selectedPolicy, setSelectedPolicy] = useState<string | null>("pol-001");
  const [editorContent, setEditorContent] = useState(SAMPLE_POLICY_YAML);
  const [typeFilter, setTypeFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");

  const { data } = useQuery({
    queryKey: ["policies"],
    queryFn: () => policiesApi.list(),
  });

  const policies = (data?.data as any[]) ?? MOCK_POLICIES;

  const saveMutation = useMutation({
    mutationFn: async () => {
      await new Promise((r) => setTimeout(r, 600));
    },
    onSuccess: () => toast.success("Policy saved successfully"),
  });

  const filtered = policies.filter((p: any) => {
    const matchType = typeFilter === "all" || p.type === typeFilter;
    const matchStatus = statusFilter === "all" || p.status === statusFilter;
    return matchType && matchStatus;
  });

  const activeCount = policies.filter((p: any) => p.status === "active").length;
  const totalViolations = policies.reduce((a: number, p: any) => a + (p.violations || 0), 0);
  const selected = policies.find((p: any) => p.id === selectedPolicy);

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="space-y-6">
      <PageHeader
        title="Security Policies"
        description="Define SLA rules, auto-triage logic, and compliance enforcement policies"
        actions={
          <Button size="sm" onClick={() => toast.info("Policy wizard coming soon")}>
            <Plus className="h-3.5 w-3.5 mr-1.5" />
            New Policy
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <KpiCard title="Total Policies" value={policies.length} icon={Lock} trend="flat" />
        <KpiCard title="Active" value={activeCount} icon={CheckCircle} trend="flat" />
        <KpiCard title="Draft" value={policies.length - activeCount} icon={AlignLeft} trend="flat" />
        <KpiCard title="SLA Violations" value={totalViolations} icon={AlertCircle} trend="down" />
      </div>

      <Tabs defaultValue="policies">
        <TabsList>
          <TabsTrigger value="policies">Policy Library</TabsTrigger>
          <TabsTrigger value="sla">SLA Rules</TabsTrigger>
          <TabsTrigger value="autotriage">Auto-Triage</TabsTrigger>
        </TabsList>

        {/* ── Policy Library ── */}
        <TabsContent value="policies" className="mt-4">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {/* Left: Policy List */}
            <div className="space-y-3">
              <div className="flex gap-2">
                <Select value={typeFilter} onValueChange={setTypeFilter}>
                  <SelectTrigger className="h-8 text-xs flex-1"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Types</SelectItem>
                    <SelectItem value="SLA">SLA</SelectItem>
                    <SelectItem value="Auto-Triage">Auto-Triage</SelectItem>
                    <SelectItem value="Compliance">Compliance</SelectItem>
                  </SelectContent>
                </Select>
                <Select value={statusFilter} onValueChange={setStatusFilter}>
                  <SelectTrigger className="h-8 text-xs flex-1"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Status</SelectItem>
                    <SelectItem value="active">Active</SelectItem>
                    <SelectItem value="draft">Draft</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              <div className="space-y-1.5 max-h-[calc(100vh-420px)] overflow-y-auto pr-1">
                {filtered.map((policy: any) => (
                  <button
                    key={policy.id}
                    onClick={() => setSelectedPolicy(policy.id)}
                    className={`w-full text-left rounded-lg border px-3 py-2.5 transition-all hover:border-border ${selectedPolicy === policy.id ? "border-primary/60 bg-primary/5" : "border-border/40 bg-card"}`}
                  >
                    <div className="flex items-center justify-between mb-1">
                      <p className="text-xs font-semibold truncate pr-2">{policy.name}</p>
                      <ChevronRight className="h-3 w-3 text-muted-foreground shrink-0" />
                    </div>
                    <div className="flex items-center gap-1.5">
                      <Badge variant={policy.status === "active" ? "success" : "secondary"} className="text-xs">{policy.status}</Badge>
                      <Badge variant="outline" className="text-xs">{policy.type}</Badge>
                      {policy.violations > 0 && <Badge variant="warning" className="text-xs">{policy.violations} violations</Badge>}
                    </div>
                  </button>
                ))}
              </div>
            </div>

            {/* Right: Policy Detail + YAML Editor */}
            <div className="lg:col-span-2 space-y-3">
              {selected ? (
                <>
                  <Card>
                    <CardHeader className="pb-2">
                      <div className="flex items-start justify-between">
                        <div>
                          <CardTitle className="text-sm">{selected.name}</CardTitle>
                          <CardDescription className="text-xs mt-1">{selected.description}</CardDescription>
                        </div>
                        <div className="flex items-center gap-1.5">
                          <Badge variant={selected.status === "active" ? "success" : "secondary"}>{selected.status}</Badge>
                          {selected.status === "active"
                            ? <ToggleRight className="h-5 w-5 text-green-400 cursor-pointer" onClick={() => toast.success("Policy disabled")} />
                            : <ToggleLeft className="h-5 w-5 text-muted-foreground cursor-pointer" onClick={() => toast.success("Policy enabled")} />
                          }
                        </div>
                      </div>
                    </CardHeader>
                    <CardContent>
                      <div className="grid grid-cols-3 gap-3 text-center">
                        <div className="rounded-md bg-muted/30 p-2">
                          <p className="text-sm font-semibold">{selected.type}</p>
                          <p className="text-xs text-muted-foreground">Type</p>
                        </div>
                        <div className="rounded-md bg-muted/30 p-2">
                          <p className="text-sm font-semibold capitalize">{selected.scope}</p>
                          <p className="text-xs text-muted-foreground">Scope</p>
                        </div>
                        <div className="rounded-md bg-muted/30 p-2">
                          <p className={`text-sm font-semibold ${selected.violations > 0 ? "text-yellow-400" : "text-green-400"}`}>{selected.violations}</p>
                          <p className="text-xs text-muted-foreground">Violations</p>
                        </div>
                      </div>
                    </CardContent>
                  </Card>

                  {/* YAML Editor */}
                  <Card>
                    <CardHeader className="pb-2">
                      <div className="flex items-center justify-between">
                        <CardTitle className="text-sm flex items-center gap-2"><AlignLeft className="h-4 w-4 text-primary" />Policy Definition (YAML)</CardTitle>
                        <Button size="sm" className="h-7 text-xs" onClick={() => saveMutation.mutate()}>
                          <Save className="h-3 w-3 mr-1" />
                          Save
                        </Button>
                      </div>
                    </CardHeader>
                    <CardContent className="p-0">
                      <textarea
                        value={editorContent}
                        onChange={(e) => setEditorContent(e.target.value)}
                        className="w-full bg-[#0d1117] text-green-300 font-mono text-xs p-4 rounded-b-lg border-0 resize-none focus:outline-none min-h-[320px] leading-5"
                        spellCheck={false}
                      />
                    </CardContent>
                  </Card>
                </>
              ) : (
                <div className="flex items-center justify-center h-64 text-muted-foreground">
                  <p className="text-sm">Select a policy to view details</p>
                </div>
              )}
            </div>
          </div>
        </TabsContent>

        {/* ── SLA Rules ── */}
        <TabsContent value="sla" className="mt-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {SLA_RULES.map((rule) => (
              <Card key={rule.severity} className="border-border/50">
                <CardHeader className="pb-2">
                  <CardTitle className={`text-base flex items-center gap-2 ${rule.color}`}>
                    <Clock className="h-4 w-4" />
                    {rule.severity} SLA
                  </CardTitle>
                </CardHeader>
                <CardContent className="grid grid-cols-3 gap-3 text-center">
                  <div className="rounded-lg bg-muted/30 p-3">
                    <p className="text-xl font-bold">{rule.triage_hours}h</p>
                    <p className="text-xs text-muted-foreground mt-0.5">Triage</p>
                  </div>
                  <div className="rounded-lg bg-muted/30 p-3">
                    <p className="text-xl font-bold">{rule.remediation_days}d</p>
                    <p className="text-xs text-muted-foreground mt-0.5">Remediate</p>
                  </div>
                  <div className="rounded-lg bg-muted/30 p-3">
                    <p className="text-xl font-bold">{rule.escalation_hours}h</p>
                    <p className="text-xs text-muted-foreground mt-0.5">Escalate</p>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        {/* ── Auto-Triage Rules ── */}
        <TabsContent value="autotriage" className="mt-4">
          <div className="space-y-3">
            {policies.filter((p: any) => p.type === "Auto-Triage").map((rule: any) => (
              <Card key={rule.id} className="border-border/50">
                <CardContent className="p-4 flex items-center justify-between gap-4">
                  <div className="flex items-center gap-3">
                    <Zap className={`h-5 w-5 ${rule.status === "active" ? "text-yellow-400" : "text-muted-foreground"}`} />
                    <div>
                      <p className="text-sm font-semibold">{rule.name}</p>
                      <p className="text-xs text-muted-foreground">{rule.description}</p>
                    </div>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <Badge variant={rule.status === "active" ? "success" : "secondary"}>{rule.status}</Badge>
                    <Button variant="ghost" size="sm" className="h-7 text-xs">Edit</Button>
                    {rule.status === "active"
                      ? <ToggleRight className="h-5 w-5 text-green-400 cursor-pointer" onClick={() => toast.success(`${rule.name} disabled`)} />
                      : <ToggleLeft className="h-5 w-5 text-muted-foreground cursor-pointer" onClick={() => toast.success(`${rule.name} enabled`)} />
                    }
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
