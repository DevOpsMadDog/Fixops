import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { motion, AnimatePresence } from "framer-motion";
import {
  Search, Filter, X, ChevronRight, AlertTriangle, Bug,
  BarChart2, Layers, SlidersHorizontal, RefreshCw, Download
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { DataTable } from "@/components/shared/data-table";
import { findingsApi } from "@/lib/api";
import { toast } from "sonner";

// ── Mock Data ──────────────────────────────────────────────────────────────────
const MOCK_FINDINGS = [
  { id: "F-20841", title: "SQL Injection in /api/users/search endpoint", severity: "critical", scanner: "Semgrep", app: "PaymentService", status: "open", age: "2d", exposureCase: "EC-4422" },
  { id: "F-20839", title: "Hardcoded AWS access key in Lambda function", severity: "critical", scanner: "TruffleHog", app: "InvoiceLambda", status: "open", age: "4d", exposureCase: "EC-4418" },
  { id: "F-20830", title: "Unauthenticated Redis instance exposed to internet", severity: "critical", scanner: "Trivy", app: "CacheLayer", status: "in-progress", age: "1d", exposureCase: "EC-4415" },
  { id: "F-20812", title: "SSRF vulnerability via user-controlled URL parameter", severity: "high", scanner: "CodeQL", app: "ReportBuilder", status: "open", age: "6d", exposureCase: "EC-4410" },
  { id: "F-20800", title: "Terraform S3 bucket with public ACL", severity: "high", scanner: "Checkov", app: "DataPipeline", status: "open", age: "9d", exposureCase: "EC-4405" },
  { id: "F-20795", title: "Container running as root with privileged flag", severity: "high", scanner: "Trivy", app: "AuthService", status: "in-progress", age: "12d", exposureCase: "EC-4401" },
  { id: "F-20780", title: "XSS in markdown rendering component", severity: "high", scanner: "Semgrep", app: "Dashboard", status: "open", age: "15d", exposureCase: "EC-4399" },
  { id: "F-20760", title: "Log4j 2.14.1 dependency detected (CVE-2021-44228)", severity: "critical", scanner: "OWASP Dep", app: "AnalyticsService", status: "resolved", age: "45d", exposureCase: "EC-4380" },
  { id: "F-20750", title: "Missing HSTS header on payment subdomain", severity: "medium", scanner: "Nuclei", app: "PaymentService", status: "open", age: "20d", exposureCase: "EC-4375" },
  { id: "F-20740", title: "Path traversal in file download endpoint", severity: "high", scanner: "Semgrep", app: "FileManager", status: "open", age: "22d", exposureCase: "EC-4370" },
  { id: "F-20735", title: "Weak JWT signing algorithm (HS256 → RS256 required)", severity: "medium", scanner: "CodeQL", app: "AuthService", status: "in-progress", age: "25d", exposureCase: "EC-4368" },
  { id: "F-20720", title: "GCP Cloud Storage bucket public read permission", severity: "high", scanner: "ScoutSuite", app: "DataWarehouse", status: "open", age: "28d", exposureCase: "EC-4360" },
  { id: "F-20705", title: "Unencrypted RDS instance without automated backups", severity: "medium", scanner: "CloudMapper", app: "UserDB", status: "open", age: "31d", exposureCase: "EC-4355" },
  { id: "F-20690", title: "Command injection in shell script executor", severity: "critical", scanner: "Semgrep", app: "CI-Executor", status: "open", age: "3d", exposureCase: "EC-4350" },
  { id: "F-20680", title: "Insecure deserialization in Java service", severity: "high", scanner: "CodeQL", app: "OrderProcessor", status: "open", age: "35d", exposureCase: "EC-4345" },
];

type Severity = "critical" | "high" | "medium" | "low";
type FindingStatus = "open" | "in-progress" | "resolved";

interface Finding {
  id: string;
  title: string;
  severity: string;
  scanner: string;
  app: string;
  status: string;
  age: string;
  exposureCase: string;
}

const SEVERITY_CONFIG: Record<Severity, { label: string; className: string }> = {
  critical: { label: "Critical", className: "text-red-400 bg-red-500/10 border-red-500/20" },
  high:     { label: "High",     className: "text-orange-400 bg-orange-500/10 border-orange-500/20" },
  medium:   { label: "Medium",   className: "text-yellow-400 bg-yellow-500/10 border-yellow-500/20" },
  low:      { label: "Low",      className: "text-blue-400 bg-blue-500/10 border-blue-500/20" },
};

const STATUS_CONFIG: Record<FindingStatus, { label: string; variant: "destructive" | "warning" | "success" }> = {
  "open":        { label: "Open",        variant: "destructive" },
  "in-progress": { label: "In Progress", variant: "warning" },
  "resolved":    { label: "Resolved",    variant: "success" },
};

function SeverityBadge({ severity }: { severity: string }) {
  const cfg = SEVERITY_CONFIG[severity as Severity] ?? SEVERITY_CONFIG.low;
  return (
    <span className={`inline-flex items-center rounded-md px-2 py-0.5 text-xs font-semibold border ${cfg.className}`}>
      {cfg.label}
    </span>
  );
}

function FindingSlideOver({ finding, onClose }: { finding: Finding; onClose: () => void }) {
  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="fixed inset-0 z-40 bg-black/40"
        onClick={onClose}
      />
      <motion.aside
        initial={{ x: "100%" }}
        animate={{ x: 0 }}
        exit={{ x: "100%" }}
        transition={{ type: "spring", stiffness: 300, damping: 30 }}
        className="fixed right-0 top-0 z-50 flex h-full w-[480px] flex-col bg-card border-l border-border/50 shadow-2xl"
      >
        <div className="flex items-center justify-between border-b border-border/50 p-5">
          <div>
            <p className="text-xs text-muted-foreground font-mono">{finding.id}</p>
            <h2 className="text-base font-semibold mt-1 max-w-sm leading-snug">{finding.title}</h2>
          </div>
          <button onClick={onClose} className="rounded-md p-1.5 hover:bg-muted/50 transition-colors">
            <X className="h-4 w-4" />
          </button>
        </div>
        <div className="flex-1 overflow-y-auto p-5 space-y-5">
          <div className="grid grid-cols-2 gap-4">
            {[
              { label: "Severity",       value: <SeverityBadge severity={finding.severity} /> },
              { label: "Status",         value: <Badge variant={STATUS_CONFIG[finding.status as FindingStatus]?.variant ?? "secondary"}>{finding.status}</Badge> },
              { label: "Scanner",        value: <span className="text-sm font-mono">{finding.scanner}</span> },
              { label: "Application",    value: <span className="text-sm">{finding.app}</span> },
              { label: "Age",            value: <span className="text-sm">{finding.age}</span> },
              { label: "Exposure Case",  value: <span className="text-sm font-mono text-primary">{finding.exposureCase}</span> },
            ].map(({ label, value }) => (
              <div key={label} className="space-y-1">
                <p className="text-xs text-muted-foreground uppercase tracking-wider">{label}</p>
                {value}
              </div>
            ))}
          </div>

          <div>
            <p className="text-xs text-muted-foreground uppercase tracking-wider mb-2">Description</p>
            <p className="text-sm text-muted-foreground leading-relaxed">
              This finding was identified by {finding.scanner} scanner during the last scan cycle. The vulnerability
              has been classified as {finding.severity} severity based on CVSS scoring and business context.
              Immediate remediation is recommended for production environments.
            </p>
          </div>

          <div>
            <p className="text-xs text-muted-foreground uppercase tracking-wider mb-2">Affected Location</p>
            <div className="rounded-md bg-muted/30 px-3 py-2 font-mono text-xs text-muted-foreground">
              src/api/controllers/UserController.ts:142
            </div>
          </div>

          <div>
            <p className="text-xs text-muted-foreground uppercase tracking-wider mb-2">Remediation Steps</p>
            <ol className="space-y-2">
              {["Validate and sanitize all user inputs before database queries", "Implement parameterized queries or ORM", "Add WAF rule to block common injection patterns", "Re-scan after fix is deployed"].map((step, i) => (
                <li key={i} className="flex gap-2 text-sm">
                  <span className="text-primary font-semibold">{i + 1}.</span>
                  <span className="text-muted-foreground">{step}</span>
                </li>
              ))}
            </ol>
          </div>

          <div className="flex gap-2 pt-2">
            <Button size="sm" onClick={() => toast.success("Assigned to remediation queue")}>Assign Fix</Button>
            <Button size="sm" variant="outline" onClick={() => toast.info("Suppression rule created")}>Suppress</Button>
            <Button size="sm" variant="ghost" onClick={() => toast.info("Exported to JIRA")}>Export</Button>
          </div>
        </div>
      </motion.aside>
    </AnimatePresence>
  );
}

export default function FindingExplorer() {
  const [search, setSearch] = useState("");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [scannerFilter, setScannerFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [groupByCase, setGroupByCase] = useState(false);
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

  const { data, isLoading } = useQuery({
    queryKey: ["findings", "explorer"],
    queryFn: () => findingsApi.list({ limit: 100 }),
  });

  const findings: Finding[] = data?.data ?? MOCK_FINDINGS;

  const filtered = findings.filter((f) => {
    const matchSearch = !search || f.title.toLowerCase().includes(search.toLowerCase()) || f.id.toLowerCase().includes(search.toLowerCase());
    const matchSeverity = severityFilter === "all" || f.severity === severityFilter;
    const matchScanner = scannerFilter === "all" || f.scanner === scannerFilter;
    const matchStatus = statusFilter === "all" || f.status === statusFilter;
    return matchSearch && matchSeverity && matchScanner && matchStatus;
  });

  const criticalCount = filtered.filter((f) => f.severity === "critical").length;
  const openCount = filtered.filter((f) => f.status === "open").length;
  const noiseReduction = Math.round(((MOCK_FINDINGS.length - filtered.length) / MOCK_FINDINGS.length) * 100);

  // Group by exposure case when toggled
  const grouped = groupByCase
    ? Object.entries(filtered.reduce<Record<string, Finding[]>>((acc, f) => {
        (acc[f.exposureCase] ??= []).push(f);
        return acc;
      }, {}))
    : null;

  const scanners = [...new Set(MOCK_FINDINGS.map((f) => f.scanner))];

  const columns = [
    { key: "id", header: "ID", render: (row: Finding) => <span className="font-mono text-xs text-muted-foreground">{row.id}</span> },
    { key: "title", header: "Title", render: (row: Finding) => <span className="text-sm font-medium max-w-xs truncate block">{row.title}</span> },
    { key: "severity", header: "Severity", render: (row: Finding) => <SeverityBadge severity={row.severity} /> },
    { key: "scanner", header: "Scanner", render: (row: Finding) => <span className="text-xs bg-muted/50 px-2 py-0.5 rounded font-mono">{row.scanner}</span> },
    { key: "app", header: "App", render: (row: Finding) => <span className="text-sm">{row.app}</span> },
    { key: "status", header: "Status", render: (row: Finding) => <Badge variant={STATUS_CONFIG[row.status as FindingStatus]?.variant ?? "secondary"}>{row.status}</Badge> },
    { key: "age", header: "Age", render: (row: Finding) => <span className="text-xs text-muted-foreground">{row.age}</span> },
    { key: "actions", header: "", render: (row: Finding) => (
      <button onClick={() => setSelectedFinding(row)} className="rounded p-1 hover:bg-muted/50">
        <ChevronRight className="h-4 w-4 text-muted-foreground" />
      </button>
    )},
  ];

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="space-y-6">
      <PageHeader
        title="Finding Explorer"
        description="Unified browser for all security findings across scanners, applications, and environments"
        badge="Live"
        actions={
          <>
            <Button variant="outline" size="sm" onClick={() => toast.success("Export started")}><Download className="h-4 w-4 mr-1.5" />Export</Button>
            <Button size="sm" onClick={() => toast.success("Scan triggered")}><RefreshCw className="h-4 w-4 mr-1.5" />Refresh</Button>
          </>
        }
      />

      {/* Stats bar */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Total Findings" value={filtered.length} change={-3} trend="down" changeLabel="vs last week" icon={Bug} />
        <KpiCard title="Critical" value={criticalCount} change={12} trend="up" changeLabel="last 24h" icon={AlertTriangle} />
        <KpiCard title="Open / Unresolved" value={openCount} trend="flat" icon={BarChart2} />
        <KpiCard title="Noise Reduction" value={`${noiseReduction}%`} change={8} trend="up" changeLabel="deduplicated" icon={Layers} />
      </div>

      {/* Filter bar */}
      <Card>
        <CardContent className="p-4">
          <div className="flex flex-wrap items-center gap-3">
            <div className="relative flex-1 min-w-[200px]">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search findings by title or ID..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="pl-9"
              />
            </div>
            <Select value={severityFilter} onValueChange={setSeverityFilter}>
              <SelectTrigger className="w-[130px]"><SelectValue placeholder="Severity" /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Severities</SelectItem>
                <SelectItem value="critical">Critical</SelectItem>
                <SelectItem value="high">High</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="low">Low</SelectItem>
              </SelectContent>
            </Select>
            <Select value={scannerFilter} onValueChange={setScannerFilter}>
              <SelectTrigger className="w-[130px]"><SelectValue placeholder="Scanner" /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Scanners</SelectItem>
                {scanners.map((s) => <SelectItem key={s} value={s}>{s}</SelectItem>)}
              </SelectContent>
            </Select>
            <Select value={statusFilter} onValueChange={setStatusFilter}>
              <SelectTrigger className="w-[130px]"><SelectValue placeholder="Status" /></SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Status</SelectItem>
                <SelectItem value="open">Open</SelectItem>
                <SelectItem value="in-progress">In Progress</SelectItem>
                <SelectItem value="resolved">Resolved</SelectItem>
              </SelectContent>
            </Select>
            <Button
              variant={groupByCase ? "default" : "outline"}
              size="sm"
              onClick={() => setGroupByCase(!groupByCase)}
            >
              <SlidersHorizontal className="h-4 w-4 mr-1.5" />
              Group by Case
            </Button>
            {(search || severityFilter !== "all" || scannerFilter !== "all" || statusFilter !== "all") && (
              <Button variant="ghost" size="sm" onClick={() => { setSearch(""); setSeverityFilter("all"); setScannerFilter("all"); setStatusFilter("all"); }}>
                <X className="h-4 w-4 mr-1" />Clear
              </Button>
            )}
            <span className="text-xs text-muted-foreground ml-auto">{filtered.length} findings</span>
          </div>
        </CardContent>
      </Card>

      {/* Table / Grouped view */}
      {isLoading ? (
        <div className="flex h-64 items-center justify-center">
          <div className="h-8 w-8 animate-spin rounded-full border-2 border-primary border-t-transparent" />
        </div>
      ) : grouped ? (
        <div className="space-y-4">
          {grouped.map(([caseId, caseFindings]) => (
            <Card key={caseId}>
              <CardHeader className="pb-3 pt-4 px-5">
                <div className="flex items-center gap-3">
                  <span className="font-mono text-sm text-primary font-semibold">{caseId}</span>
                  <Badge variant="secondary">{caseFindings.length} findings</Badge>
                  <SeverityBadge severity={caseFindings[0].severity} />
                </div>
              </CardHeader>
              <CardContent className="px-0 pb-0">
                <DataTable columns={columns} data={caseFindings} onRowClick={(row) => setSelectedFinding(row as Finding)} />
              </CardContent>
            </Card>
          ))}
        </div>
      ) : (
        <DataTable
          columns={columns}
          data={filtered}
          onRowClick={(row) => setSelectedFinding(row as Finding)}
          emptyMessage="No findings match the current filters"
        />
      )}

      {/* Slide-over detail panel */}
      {selectedFinding && (
        <FindingSlideOver finding={selectedFinding} onClose={() => setSelectedFinding(null)} />
      )}
    </motion.div>
  );
}
