import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectTrigger, SelectContent, SelectItem, SelectValue } from "@/components/ui/select";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import {
  Layers, AlertTriangle, Clock, ChevronRight, Search, FileText,
  Link2, ArrowRight, Activity, CheckCircle2, X, User, Tag
} from "lucide-react";
import { findingsApi } from "@/lib/api";
import { toast } from "sonner";

// ── Types ──────────────────────────────────────────────────────────────────
type CaseLifecycle = "Open" | "Investigating" | "Resolving" | "Closed";

interface ExposureCase {
  id: string;
  title: string;
  cveId?: string;
  type: "Vulnerability" | "Misconfiguration" | "Secret Exposure" | "Supply Chain" | "Compliance Gap";
  severity: "Critical" | "High" | "Medium" | "Low";
  lifecycle: CaseLifecycle;
  affectedComponents: string[];
  linkedFindings: number;
  linkedDecisions: string[];
  assignee: string;
  assigneeInitials: string;
  assigneeColor: string;
  firstSeen: string;
  lastUpdated: string;
  description: string;
  daysOpen: number;
  rootCause?: string;
  businessImpact: string;
}

// ── Mock Data ──────────────────────────────────────────────────────────────
const MOCK_CASES: ExposureCase[] = [
  {
    id: "EC-1001", title: "Log4Shell Exposure Across Logging Stack", cveId: "CVE-2021-44228",
    type: "Vulnerability", severity: "Critical", lifecycle: "Resolving",
    affectedComponents: ["logging-service", "audit-svc", "report-exporter"],
    linkedFindings: 7, linkedDecisions: ["DEC-201: Upgrade log4j org-wide", "DEC-202: WAF rule for JNDI"],
    assignee: "Sophia Chen", assigneeInitials: "SC", assigneeColor: "bg-purple-500",
    firstSeen: "2025-06-08", lastUpdated: "2h ago", daysOpen: 2,
    description: "Log4j 2.x JNDI injection vulnerability affecting all services using the logging library.",
    rootCause: "Centralized logging library outdated across 3 microservices.",
    businessImpact: "Full RCE on production logging infrastructure, potential data exfiltration.",
  },
  {
    id: "EC-1002", title: "Hardcoded Secrets in CI/CD Pipeline", cveId: undefined,
    type: "Secret Exposure", severity: "Critical", lifecycle: "Investigating",
    affectedComponents: ["ci-pipeline", "deploy-scripts", "infra-as-code"],
    linkedFindings: 4, linkedDecisions: ["DEC-203: Migrate to Vault"],
    assignee: "James Kim", assigneeInitials: "JK", assigneeColor: "bg-orange-500",
    firstSeen: "2025-06-09", lastUpdated: "5h ago", daysOpen: 1,
    description: "AWS access keys and database credentials found hardcoded in Jenkins pipeline scripts.",
    rootCause: "No secrets management policy enforced at code review stage.",
    businessImpact: "Direct cloud account takeover risk, potential data breach.",
  },
  {
    id: "EC-1003", title: "Spring4Shell in API Gateway Cluster", cveId: "CVE-2022-22965",
    type: "Vulnerability", severity: "High", lifecycle: "Resolving",
    affectedComponents: ["api-gateway", "product-catalog-svc"],
    linkedFindings: 3, linkedDecisions: ["DEC-195: Framework upgrade sprint"],
    assignee: "Arjun Patel", assigneeInitials: "AP", assigneeColor: "bg-blue-500",
    firstSeen: "2025-06-05", lastUpdated: "1d ago", daysOpen: 5,
    description: "Spring Framework RCE via data binding on JDK 9+. Multiple services affected.",
    rootCause: "Spring Boot dependencies not updated during last patch cycle.",
    businessImpact: "Remote code execution on API gateway processing all external traffic.",
  },
  {
    id: "EC-1004", title: "Unauthenticated Prometheus Metrics Endpoint", cveId: undefined,
    type: "Misconfiguration", severity: "High", lifecycle: "Open",
    affectedComponents: ["metrics.corp.com", "k8s-metrics-server"],
    linkedFindings: 2, linkedDecisions: [],
    assignee: "Lena Müller", assigneeInitials: "LM", assigneeColor: "bg-teal-500",
    firstSeen: "2025-06-10", lastUpdated: "30m ago", daysOpen: 0,
    description: "Prometheus /metrics endpoint publicly accessible, leaking service topology and credentials.",
    businessImpact: "Infrastructure mapping by threat actors, leaked service credentials.",
  },
  {
    id: "EC-1005", title: "Insecure Deserialization in Message Broker", cveId: "CVE-2023-5432",
    type: "Vulnerability", severity: "Critical", lifecycle: "Open",
    affectedComponents: ["message-broker", "event-processor"],
    linkedFindings: 2, linkedDecisions: [],
    assignee: "Unassigned", assigneeInitials: "?", assigneeColor: "bg-muted",
    firstSeen: "2025-06-07", lastUpdated: "3d ago", daysOpen: 3,
    description: "Java ObjectInputStream deserialization accepting untrusted data, enabling RCE.",
    rootCause: "Legacy Java serialization pattern not updated since 2019.",
    businessImpact: "RCE on message processing layer handling all async workflows.",
  },
  {
    id: "EC-1006", title: "npm Supply Chain: lodash < 4.17.21", cveId: "CVE-2020-8203",
    type: "Supply Chain", severity: "Medium", lifecycle: "Resolving",
    affectedComponents: ["web-app-frontend", "admin-dashboard", "reporting-ui"],
    linkedFindings: 5, linkedDecisions: ["DEC-189: SCA policy enforcement"],
    assignee: "James Kim", assigneeInitials: "JK", assigneeColor: "bg-orange-500",
    firstSeen: "2025-05-28", lastUpdated: "2d ago", daysOpen: 13,
    description: "Prototype pollution vulnerability in lodash used across 3 frontend applications.",
    businessImpact: "Client-side data manipulation, potential XSS amplification.",
  },
  {
    id: "EC-1007", title: "PCI DSS Control Gap: Encryption at Rest", cveId: undefined,
    type: "Compliance Gap", severity: "High", lifecycle: "Investigating",
    affectedComponents: ["billing-db", "payment-archive"],
    linkedFindings: 1, linkedDecisions: ["DEC-210: PCI remediation plan"],
    assignee: "Rachel Okafor", assigneeInitials: "RO", assigneeColor: "bg-green-500",
    firstSeen: "2025-06-01", lastUpdated: "4d ago", daysOpen: 9,
    description: "PCI DSS Requirement 3.5: Payment card data not encrypted at rest in billing-db.",
    businessImpact: "PCI DSS non-compliance, potential $500K penalty, audit failure.",
  },
];

const severityConfig: Record<string, string> = {
  Critical: "bg-red-500/10 text-red-400 border-red-500/30",
  High:     "bg-orange-500/10 text-orange-400 border-orange-500/30",
  Medium:   "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
  Low:      "bg-blue-500/10 text-blue-400 border-blue-500/30",
};

const lifecycleConfig: Record<CaseLifecycle, { cls: string; step: number }> = {
  "Open":          { cls: "bg-muted text-muted-foreground border-border",            step: 0 },
  "Investigating": { cls: "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",   step: 1 },
  "Resolving":     { cls: "bg-blue-500/10 text-blue-400 border-blue-500/30",          step: 2 },
  "Closed":        { cls: "bg-green-500/10 text-green-400 border-green-500/30",       step: 3 },
};

const LIFECYCLE_STAGES: CaseLifecycle[] = ["Open", "Investigating", "Resolving", "Closed"];

const typeConfig: Record<string, string> = {
  "Vulnerability":    "bg-red-500/10 text-red-400 border-red-500/30",
  "Misconfiguration": "bg-orange-500/10 text-orange-400 border-orange-500/30",
  "Secret Exposure":  "bg-purple-500/10 text-purple-400 border-purple-500/30",
  "Supply Chain":     "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
  "Compliance Gap":   "bg-blue-500/10 text-blue-400 border-blue-500/30",
};

// ── Detail Panel ───────────────────────────────────────────────────────────
function CaseDetailPanel({ kase, onClose }: { kase: ExposureCase; onClose: () => void }) {
  const lcStep = lifecycleConfig[kase.lifecycle].step;
  return (
    <Card className="border-border/50 h-full flex flex-col">
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between gap-2">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap mb-1.5">
              <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${severityConfig[kase.severity]}`}>{kase.severity}</span>
              <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${typeConfig[kase.type]}`}>{kase.type}</span>
              <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${lifecycleConfig[kase.lifecycle].cls}`}>{kase.lifecycle}</span>
            </div>
            <CardTitle className="text-sm font-semibold">{kase.title}</CardTitle>
            {kase.cveId && <p className="text-xs font-mono text-orange-400 mt-0.5">{kase.cveId}</p>}
          </div>
          <Button size="sm" variant="ghost" className="h-6 w-6 p-0 shrink-0" onClick={onClose}><X className="h-3.5 w-3.5" /></Button>
        </div>
      </CardHeader>
      <CardContent className="flex-1 overflow-y-auto space-y-4">
        {/* Lifecycle tracker */}
        <div className="space-y-1.5">
          <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Lifecycle</p>
          <div className="flex items-center gap-1.5">
            {LIFECYCLE_STAGES.map((stage, i) => (
              <div key={stage} className="flex items-center gap-1.5">
                <div className={`flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs font-medium transition-colors ${i <= lcStep ? lifecycleConfig[stage].cls : "bg-muted text-muted-foreground border-border opacity-40"}`}>
                  {i < lcStep && <CheckCircle2 className="h-3 w-3" />}
                  {stage}
                </div>
                {i < LIFECYCLE_STAGES.length - 1 && <ArrowRight className="h-3 w-3 text-muted-foreground shrink-0" />}
              </div>
            ))}
          </div>
        </div>

        <p className="text-xs text-muted-foreground">{kase.description}</p>

        {kase.rootCause && (
          <div className="rounded-lg bg-orange-500/5 border border-orange-500/20 p-3">
            <p className="text-xs font-semibold text-orange-400 mb-1">Root Cause</p>
            <p className="text-xs text-muted-foreground">{kase.rootCause}</p>
          </div>
        )}

        <div className="rounded-lg bg-red-500/5 border border-red-500/20 p-3">
          <p className="text-xs font-semibold text-red-400 mb-1">Business Impact</p>
          <p className="text-xs text-muted-foreground">{kase.businessImpact}</p>
        </div>

        {/* Affected components */}
        <div>
          <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">Affected Components ({kase.affectedComponents.length})</p>
          <div className="flex flex-wrap gap-1.5">
            {kase.affectedComponents.map(c => (
              <span key={c} className="rounded bg-muted px-2 py-1 text-xs font-mono">{c}</span>
            ))}
          </div>
        </div>

        {/* Linked decisions */}
        {kase.linkedDecisions.length > 0 && (
          <div>
            <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider mb-2">Linked Decisions ({kase.linkedDecisions.length})</p>
            <div className="space-y-1">
              {kase.linkedDecisions.map(d => (
                <div key={d} className="flex items-center gap-2 text-xs rounded border border-border/50 p-2">
                  <FileText className="h-3 w-3 text-primary shrink-0" />
                  <span>{d}</span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Meta */}
        <div className="grid grid-cols-2 gap-3 text-xs">
          <div>
            <p className="text-muted-foreground">Assignee</p>
            <div className="flex items-center gap-1.5 mt-1">
              <div className={`h-5 w-5 rounded-full ${kase.assigneeColor} flex items-center justify-center text-white text-[9px] font-bold`}>{kase.assigneeInitials}</div>
              <span>{kase.assignee}</span>
            </div>
          </div>
          <div>
            <p className="text-muted-foreground">Days Open</p>
            <p className={`font-bold mt-1 ${kase.daysOpen > 7 ? "text-red-400" : kase.daysOpen > 3 ? "text-orange-400" : "text-foreground"}`}>{kase.daysOpen}d</p>
          </div>
          <div>
            <p className="text-muted-foreground">First Seen</p>
            <p className="mt-1">{kase.firstSeen}</p>
          </div>
          <div>
            <p className="text-muted-foreground">Last Updated</p>
            <p className="mt-1">{kase.lastUpdated}</p>
          </div>
        </div>

        <div className="flex gap-2 pt-2">
          <Button size="sm" className="flex-1" onClick={() => toast.success("Case advanced to next lifecycle stage")}>
            Advance Stage
          </Button>
          <Button size="sm" variant="outline" onClick={() => toast.info("Linking finding")}>
            <Link2 className="h-3.5 w-3.5 mr-1.5" /> Link
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

// ── Main Component ─────────────────────────────────────────────────────────
export default function ExposureCases() {
  const [selectedCase, setSelectedCase] = useState<ExposureCase | null>(MOCK_CASES[0]);
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("All");
  const [lifecycleFilter, setLifecycleFilter] = useState("All");

  const { data } = useQuery({
    queryKey: ["exposure-cases"],
    queryFn: () => findingsApi.list({ deduplicated: true }),
  });

  const cases: ExposureCase[] = (data as any)?.data ?? MOCK_CASES;

  const filtered = cases.filter(c => {
    const matchSearch = c.title.toLowerCase().includes(search.toLowerCase()) || (c.cveId?.includes(search) ?? false);
    const matchSev = severityFilter === "All" || c.severity === severityFilter;
    const matchLc  = lifecycleFilter === "All" || c.lifecycle === lifecycleFilter;
    return matchSearch && matchSev && matchLc;
  });

  const openCount         = cases.filter(c => c.lifecycle === "Open").length;
  const investigatingCount = cases.filter(c => c.lifecycle === "Investigating").length;
  const criticalOpen      = cases.filter(c => c.severity === "Critical" && c.lifecycle !== "Closed").length;
  const totalLinked       = cases.reduce((s, c) => s + c.linkedFindings, 0);

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="space-y-6">
      <PageHeader
        title="Exposure Cases"
        description="Deduplicated finding groups — lifecycle tracking from Open to Closed with decision linkage"
        badge="REMEDIATE"
        actions={
          <Button size="sm">
            <Layers className="h-3.5 w-3.5 mr-1.5" /> New Case
          </Button>
        }
      />

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Open Cases" value={openCount} icon={AlertTriangle} trend="down" change={-3} changeLabel="vs last week" />
        <KpiCard title="Investigating" value={investigatingCount} icon={Activity} trend="flat" />
        <KpiCard title="Critical Open" value={criticalOpen} icon={AlertTriangle} trend="down" change={-1} changeLabel="vs yesterday" />
        <KpiCard title="Linked Findings" value={totalLinked} icon={Link2} trend="flat" />
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
          <Input placeholder="Search cases, CVEs..." className="pl-8 h-8 text-sm" value={search} onChange={e => setSearch(e.target.value)} />
        </div>
        <Select value={severityFilter} onValueChange={setSeverityFilter}>
          <SelectTrigger className="w-36 h-8 text-xs"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="All">All Severities</SelectItem>
            {["Critical","High","Medium","Low"].map(s => <SelectItem key={s} value={s}>{s}</SelectItem>)}
          </SelectContent>
        </Select>
        <Select value={lifecycleFilter} onValueChange={setLifecycleFilter}>
          <SelectTrigger className="w-36 h-8 text-xs"><SelectValue /></SelectTrigger>
          <SelectContent>
            <SelectItem value="All">All Stages</SelectItem>
            {LIFECYCLE_STAGES.map(s => <SelectItem key={s} value={s}>{s}</SelectItem>)}
          </SelectContent>
        </Select>
      </div>

      <div className={`grid gap-6 ${selectedCase ? "grid-cols-1 xl:grid-cols-5" : "grid-cols-1"}`}>
        {/* Cases table */}
        <div className={selectedCase ? "xl:col-span-3" : ""}>
          <Card className="border-border/50 overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-border/50 bg-muted/30">
                    <th className="p-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">Case</th>
                    <th className="p-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">Severity</th>
                    <th className="p-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">Lifecycle</th>
                    <th className="p-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">Decisions</th>
                    <th className="p-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">Findings</th>
                    <th className="p-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">Days Open</th>
                    <th className="p-3 text-left text-xs font-semibold text-muted-foreground uppercase tracking-wider">Assignee</th>
                  </tr>
                </thead>
                <tbody>
                  {filtered.map(c => (
                    <tr
                      key={c.id}
                      className={`border-b border-border/50 hover:bg-muted/10 cursor-pointer transition-colors ${selectedCase?.id === c.id ? "bg-primary/5" : ""}`}
                      onClick={() => setSelectedCase(selectedCase?.id === c.id ? null : c)}
                    >
                      <td className="p-3">
                        <p className="text-sm font-medium line-clamp-1">{c.title}</p>
                        <p className="text-xs text-muted-foreground font-mono mt-0.5">{c.id} {c.cveId && `· ${c.cveId}`}</p>
                      </td>
                      <td className="p-3"><span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${severityConfig[c.severity]}`}>{c.severity}</span></td>
                      <td className="p-3"><span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${lifecycleConfig[c.lifecycle].cls}`}>{c.lifecycle}</span></td>
                      <td className="p-3"><span className="text-xs font-medium">{c.linkedDecisions.length}</span></td>
                      <td className="p-3"><span className="text-xs font-mono text-primary">{c.linkedFindings}</span></td>
                      <td className="p-3"><span className={`text-xs font-medium ${c.daysOpen > 7 ? "text-red-400" : c.daysOpen > 3 ? "text-orange-400" : ""}`}>{c.daysOpen}d</span></td>
                      <td className="p-3">
                        <div className="flex items-center gap-1.5">
                          <div className={`h-5 w-5 rounded-full ${c.assigneeColor} flex items-center justify-center text-white text-[9px] font-bold`}>{c.assigneeInitials}</div>
                          <span className="text-xs text-muted-foreground">{c.assignee.split(" ")[0]}</span>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        </div>

        {/* Detail panel */}
        {selectedCase && (
          <div className="xl:col-span-2">
            <CaseDetailPanel kase={selectedCase} onClose={() => setSelectedCase(null)} />
          </div>
        )}
      </div>
    </motion.div>
  );
}
