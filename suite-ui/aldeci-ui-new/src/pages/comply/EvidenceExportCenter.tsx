import { useState, useMemo } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  Send,
  Download,
  CheckSquare,
  Square,
  Loader2,
  Clock,
  CheckCircle2,
  AlertCircle,
  FileArchive,
  Eye,
  Shield,
  Calendar,
  ArrowRight,
  Package,
  Mail,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Progress } from "@/components/ui/progress";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { evidenceApi, complianceApi, appsApi } from "@/lib/api";
import { toast } from "sonner";

// ─── Mock Data ───────────────────────────────────────────────────────────────

const MOCK_APPS = [
  { id: "app-checkout", name: "Checkout Service", env: "production" },
  { id: "app-auth", name: "Auth Service", env: "production" },
  { id: "app-payments", name: "Payments Gateway", env: "production" },
  { id: "app-iam", name: "IAM Platform", env: "production" },
  { id: "app-data-pipeline", name: "Data Pipeline", env: "production" },
  { id: "app-api-gw", name: "API Gateway", env: "production" },
  { id: "app-notification", name: "Notification Service", env: "staging" },
  { id: "app-reporting", name: "Reporting Engine", env: "production" },
];

interface FrameworkCoverage {
  framework: string;
  controlsCovered: number;
  controlsTotal: number;
  evidenceBundles: number;
  quantumSigned: number;
  lastGenerated: string;
}

const MOCK_COVERAGE: FrameworkCoverage[] = [
  { framework: "SOC 2", controlsCovered: 89, controlsTotal: 97, evidenceBundles: 12, quantumSigned: 10, lastGenerated: "2025-01-10" },
  { framework: "PCI-DSS", controlsCovered: 201, controlsTotal: 234, evidenceBundles: 24, quantumSigned: 20, lastGenerated: "2025-01-09" },
  { framework: "ISO 27001", controlsCovered: 91, controlsTotal: 93, evidenceBundles: 8, quantumSigned: 8, lastGenerated: "2025-01-07" },
  { framework: "HIPAA", controlsCovered: 48, controlsTotal: 66, evidenceBundles: 5, quantumSigned: 3, lastGenerated: "2025-01-06" },
  { framework: "NIST 800-53", controlsCovered: 287, controlsTotal: 323, evidenceBundles: 31, quantumSigned: 25, lastGenerated: "2025-01-08" },
];

interface ExportHistory {
  id: string;
  name: string;
  framework: string;
  appIds: string[];
  period: string;
  format: string;
  status: "ready" | "generating" | "failed" | "sent";
  createdAt: string;
  createdBy: string;
  sizeKb: number;
  sentToAuditor: boolean;
  auditorEmail?: string;
}

const MOCK_EXPORT_HISTORY: ExportHistory[] = [
  {
    id: "exp-001",
    name: "SOC 2 Q4 2024 Full Export",
    framework: "SOC 2",
    appIds: ["app-checkout", "app-auth", "app-payments", "app-iam"],
    period: "Q4 2024",
    format: "zip",
    status: "ready",
    createdAt: "2025-01-10T08:00:00Z",
    createdBy: "Sarah Chen",
    sizeKb: 48200,
    sentToAuditor: true,
    auditorEmail: "audit-team@deloitte.com",
  },
  {
    id: "exp-002",
    name: "PCI-DSS Annual Assessment Package",
    framework: "PCI-DSS",
    appIds: ["app-payments", "app-checkout"],
    period: "FY2024",
    format: "zip",
    status: "ready",
    createdAt: "2025-01-09T14:00:00Z",
    createdBy: "Marcus Williams",
    sizeKb: 31400,
    sentToAuditor: false,
  },
  {
    id: "exp-003",
    name: "HIPAA Gap Remediation Evidence",
    framework: "HIPAA",
    appIds: ["app-data-pipeline"],
    period: "Last 90 days",
    format: "zip",
    status: "generating",
    createdAt: "2025-01-10T10:30:00Z",
    createdBy: "Priya Patel",
    sizeKb: 0,
    sentToAuditor: false,
  },
  {
    id: "exp-004",
    name: "ISO 27001 Surveillance Audit Package",
    framework: "ISO 27001",
    appIds: ["app-iam", "app-api-gw"],
    period: "Last Year",
    format: "pdf",
    status: "failed",
    createdAt: "2025-01-07T11:00:00Z",
    createdBy: "James Thompson",
    sizeKb: 0,
    sentToAuditor: false,
  },
];

const ESTIMATED_TIMES: Record<string, string> = {
  soc2: "~3 minutes",
  "pci-dss": "~5 minutes",
  iso27001: "~2 minutes",
  hipaa: "~4 minutes",
  nist800: "~8 minutes",
};

// ─── Helpers ─────────────────────────────────────────────────────────────────

function ExportStatusBadge({ status }: { status: ExportHistory["status"] }) {
  switch (status) {
    case "ready":
      return <Badge variant="success">Ready</Badge>;
    case "generating":
      return (
        <Badge variant="warning" className="gap-1.5">
          <Loader2 className="h-3 w-3 animate-spin" />
          Generating
        </Badge>
      );
    case "failed":
      return <Badge variant="destructive">Failed</Badge>;
    case "sent":
      return <Badge variant="info">Sent to Auditor</Badge>;
  }
}

// ─── Main Component ──────────────────────────────────────────────────────────

export default function EvidenceExportCenter() {
  const [selectedFramework, setSelectedFramework] = useState("soc2");
  const [selectedApps, setSelectedApps] = useState<string[]>([
    "app-checkout", "app-auth", "app-payments", "app-iam",
  ]);
  const [period, setPeriod] = useState("last-quarter");
  const [format, setFormat] = useState("zip");
  const [includeSLSA, setIncludeSLSA] = useState(true);
  const [includeAuditLogs, setIncludeAuditLogs] = useState(true);
  const [includeReports, setIncludeReports] = useState(false);
  const [auditorEmail, setAuditorEmail] = useState("");

  const { data: appsData } = useQuery({
    queryKey: ["apps-list"],
    queryFn: () => appsApi.list(),
  });

  const { data: complianceData } = useQuery({
    queryKey: ["compliance-coverage"],
    queryFn: () => complianceApi.status(),
  });

  const { data: exportHistoryData } = useQuery({
    queryKey: ["export-history"],
    queryFn: () => evidenceApi.list({ type: "exports" }),
  });

  const exportMutation = useMutation({
    mutationFn: (payload: unknown) => evidenceApi.export(payload),
    onSuccess: () => {
      toast.success(
        "Export package generation started. Estimated time: " +
          ESTIMATED_TIMES[selectedFramework] +
          " — you'll be notified when ready."
      );
    },
    onError: () => {
      toast.error("Failed to initiate export. Check your configuration.");
    },
  });

  const apps = (appsData as { data?: typeof MOCK_APPS })?.data ?? MOCK_APPS;
  const coverage: FrameworkCoverage[] =
    (complianceData as { data?: FrameworkCoverage[] })?.data ?? MOCK_COVERAGE;
  const exports: ExportHistory[] =
    (exportHistoryData as { data?: ExportHistory[] })?.data ?? MOCK_EXPORT_HISTORY;

  const selectedCoverage = useMemo(
    () =>
      coverage.find(
        (c) =>
          c.framework.toLowerCase().replace(" ", "") ===
          selectedFramework.replace("-", "")
      ) ?? coverage[0],
    [coverage, selectedFramework]
  );

  const toggleApp = (appId: string) => {
    setSelectedApps((prev) =>
      prev.includes(appId) ? prev.filter((id) => id !== appId) : [...prev, appId]
    );
  };

  const coveragePct = selectedCoverage
    ? Math.round(
        (selectedCoverage.controlsCovered / selectedCoverage.controlsTotal) * 100
      )
    : 0;

  const handleGenerate = () => {
    if (selectedApps.length === 0) {
      toast.error("Select at least one application.");
      return;
    }
    exportMutation.mutate({
      framework: selectedFramework,
      app_ids: selectedApps,
      period,
      format,
      include_slsa: includeSLSA,
      include_audit_logs: includeAuditLogs,
      include_reports: includeReports,
    });
  };

  const handleSendToAuditor = (exportId: string) => {
    if (!auditorEmail) {
      toast.error("Enter an auditor email address first.");
      return;
    }
    toast.success(`Sending export to ${auditorEmail}...`);
    void exportId;
  };

  const readyExports = exports.filter((e) => e.status === "ready");

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      <PageHeader
        title="Evidence Export Center"
        description="Build, preview, and deliver compliance evidence packages to auditors and regulators"
        badge="Auditor Ready"
        actions={
          <Button size="sm" onClick={handleGenerate} disabled={exportMutation.isPending}>
            {exportMutation.isPending ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Generating...
              </>
            ) : (
              <>
                <Package className="mr-2 h-4 w-4" />
                Generate Export
              </>
            )}
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard
          title="Total Exports"
          value={exports.length}
          icon={FileArchive}
          trend="flat"
        />
        <KpiCard
          title="Ready for Download"
          value={readyExports.length}
          icon={CheckCircle2}
          trend="flat"
        />
        <KpiCard
          title="Sent to Auditors"
          value={exports.filter((e) => e.sentToAuditor).length}
          icon={Send}
          trend="flat"
        />
        <KpiCard
          title="Failed Exports"
          value={exports.filter((e) => e.status === "failed").length}
          icon={AlertCircle}
          trend="flat"
        />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        {/* Builder Form */}
        <div className="xl:col-span-2 space-y-4">
          <Card className="border-border/50">
            <CardHeader className="pb-3">
              <CardTitle className="text-base">Export Builder</CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {/* Framework + Period + Format */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
                <div className="space-y-1.5">
                  <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
                    Framework
                  </label>
                  <Select value={selectedFramework} onValueChange={setSelectedFramework}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="soc2">SOC 2 Type II</SelectItem>
                      <SelectItem value="pci-dss">PCI-DSS v4.0</SelectItem>
                      <SelectItem value="iso27001">ISO 27001:2022</SelectItem>
                      <SelectItem value="hipaa">HIPAA</SelectItem>
                      <SelectItem value="nist800">NIST 800-53</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-1.5">
                  <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
                    Period
                  </label>
                  <Select value={period} onValueChange={setPeriod}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="last-month">Last 30 days</SelectItem>
                      <SelectItem value="last-quarter">Last Quarter</SelectItem>
                      <SelectItem value="last-year">Last Year</SelectItem>
                      <SelectItem value="ytd">Year to Date</SelectItem>
                      <SelectItem value="fy2024">FY2024</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-1.5">
                  <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
                    Format
                  </label>
                  <Select value={format} onValueChange={setFormat}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="zip">ZIP Archive</SelectItem>
                      <SelectItem value="pdf">PDF Bundle</SelectItem>
                      <SelectItem value="json">JSON Manifest</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>

              {/* App selector */}
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
                    Applications ({selectedApps.length}/{apps.length} selected)
                  </label>
                  <div className="flex gap-2">
                    <button
                      onClick={() => setSelectedApps(apps.map((a) => a.id))}
                      className="text-xs text-primary hover:underline"
                    >
                      All
                    </button>
                    <span className="text-xs text-muted-foreground">/</span>
                    <button
                      onClick={() => setSelectedApps([])}
                      className="text-xs text-muted-foreground hover:underline"
                    >
                      None
                    </button>
                  </div>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-1.5">
                  {apps.map((app) => {
                    const isSelected = selectedApps.includes(app.id);
                    return (
                      <button
                        key={app.id}
                        onClick={() => toggleApp(app.id)}
                        className={`flex items-center gap-2.5 p-2.5 rounded-lg border text-left transition-all ${
                          isSelected
                            ? "border-primary/40 bg-primary/5"
                            : "border-border/50 hover:border-border/80"
                        }`}
                      >
                        {isSelected ? (
                          <CheckSquare className="h-4 w-4 text-primary shrink-0" />
                        ) : (
                          <Square className="h-4 w-4 text-muted-foreground shrink-0" />
                        )}
                        <div className="min-w-0">
                          <p className="text-xs font-medium truncate">{app.name}</p>
                          <p className="text-xs text-muted-foreground font-mono truncate">
                            {app.id}
                          </p>
                        </div>
                        <Badge
                          variant={app.env === "production" ? "default" : "secondary"}
                          className="text-xs ml-auto shrink-0"
                        >
                          {app.env}
                        </Badge>
                      </button>
                    );
                  })}
                </div>
              </div>

              {/* Include options */}
              <div className="space-y-2">
                <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
                  Include In Package
                </label>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                  {[
                    { label: "SLSA Provenance", value: includeSLSA, setter: setIncludeSLSA },
                    { label: "Audit Logs", value: includeAuditLogs, setter: setIncludeAuditLogs },
                    { label: "Reports", value: includeReports, setter: setIncludeReports },
                  ].map(({ label, value, setter }) => (
                    <button
                      key={label}
                      onClick={() => setter(!value)}
                      className={`flex items-center gap-2 p-2.5 rounded-lg border text-sm transition-all ${
                        value
                          ? "border-primary/40 bg-primary/5 text-primary"
                          : "border-border/50 text-muted-foreground"
                      }`}
                    >
                      {value ? (
                        <CheckSquare className="h-4 w-4 shrink-0" />
                      ) : (
                        <Square className="h-4 w-4 shrink-0" />
                      )}
                      {label}
                    </button>
                  ))}
                </div>
              </div>

              {/* Auditor email */}
              <div className="space-y-1.5">
                <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
                  Send to Auditor (optional)
                </label>
                <div className="flex gap-2">
                  <input
                    type="email"
                    placeholder="auditor@firm.com"
                    value={auditorEmail}
                    onChange={(e) => setAuditorEmail(e.target.value)}
                    className="flex-1 h-9 rounded-md border border-border/50 bg-background px-3 text-sm placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-primary"
                  />
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => handleSendToAuditor("exp-new")}
                    disabled={!auditorEmail}
                  >
                    <Mail className="h-4 w-4" />
                  </Button>
                </div>
              </div>

              {/* Generate button */}
              <Button
                className="w-full"
                onClick={handleGenerate}
                disabled={exportMutation.isPending}
              >
                {exportMutation.isPending ? (
                  <>
                    <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                    Generating Export...
                  </>
                ) : (
                  <>
                    <Package className="mr-2 h-4 w-4" />
                    Generate Export Package
                    <ArrowRight className="ml-2 h-4 w-4" />
                  </>
                )}
              </Button>
              {selectedFramework && (
                <p className="text-xs text-center text-muted-foreground">
                  Estimated time: {ESTIMATED_TIMES[selectedFramework] ?? "~5 minutes"}
                </p>
              )}
            </CardContent>
          </Card>
        </div>

        {/* Preview Panel */}
        <div className="space-y-4">
          <Card className="border-border/50">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm flex items-center gap-2">
                <Eye className="h-4 w-4 text-primary" />
                Control Coverage Preview
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {selectedCoverage ? (
                <>
                  <div className="flex items-center justify-between">
                    <span className="text-sm font-semibold">{selectedCoverage.framework}</span>
                    <Badge variant={coveragePct >= 90 ? "success" : coveragePct >= 70 ? "warning" : "destructive"}>
                      {coveragePct}% covered
                    </Badge>
                  </div>
                  <Progress value={coveragePct} className="h-2" />
                  <div className="space-y-2 text-xs">
                    {[
                      {
                        label: "Controls Covered",
                        value: `${selectedCoverage.controlsCovered}/${selectedCoverage.controlsTotal}`,
                        icon: Shield,
                      },
                      {
                        label: "Evidence Bundles",
                        value: selectedCoverage.evidenceBundles,
                        icon: FileArchive,
                      },
                      {
                        label: "Quantum-Signed",
                        value: `${selectedCoverage.quantumSigned}/${selectedCoverage.evidenceBundles}`,
                        icon: Shield,
                      },
                      {
                        label: "Last Generated",
                        value: selectedCoverage.lastGenerated,
                        icon: Calendar,
                      },
                    ].map(({ label, value, icon: Icon }) => (
                      <div key={label} className="flex items-center justify-between">
                        <span className="flex items-center gap-1.5 text-muted-foreground">
                          <Icon className="h-3.5 w-3.5" />
                          {label}
                        </span>
                        <span className="font-medium tabular-nums">{value}</span>
                      </div>
                    ))}
                  </div>
                  <div className="pt-2 border-t border-border/50">
                    <p className="text-xs font-medium mb-1.5">Selected Apps</p>
                    <div className="space-y-1">
                      {selectedApps.slice(0, 4).map((appId) => {
                        const app = apps.find((a) => a.id === appId);
                        return app ? (
                          <div key={appId} className="flex items-center gap-1.5">
                            <CheckCircle2 className="h-3.5 w-3.5 text-green-400 shrink-0" />
                            <span className="text-xs truncate">{app.name}</span>
                          </div>
                        ) : null;
                      })}
                      {selectedApps.length > 4 && (
                        <p className="text-xs text-muted-foreground pl-5">
                          +{selectedApps.length - 4} more apps
                        </p>
                      )}
                      {selectedApps.length === 0 && (
                        <p className="text-xs text-muted-foreground">No apps selected</p>
                      )}
                    </div>
                  </div>
                </>
              ) : (
                <p className="text-xs text-muted-foreground">Select a framework to preview coverage</p>
              )}
            </CardContent>
          </Card>

          {/* All framework coverage mini view */}
          <Card className="border-border/50">
            <CardHeader className="pb-2">
              <CardTitle className="text-xs uppercase tracking-wider text-muted-foreground">
                All Frameworks
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2.5">
              {coverage.map((c) => {
                const pct = Math.round((c.controlsCovered / c.controlsTotal) * 100);
                return (
                  <div key={c.framework} className="space-y-1">
                    <div className="flex justify-between text-xs">
                      <span className="font-medium">{c.framework}</span>
                      <span className="text-muted-foreground tabular-nums">{pct}%</span>
                    </div>
                    <Progress value={pct} className="h-1.5" />
                  </div>
                );
              })}
            </CardContent>
          </Card>
        </div>
      </div>

      {/* Export History */}
      <Card className="border-border/50">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-base">Export History</CardTitle>
            <span className="text-xs text-muted-foreground">{exports.length} exports</span>
          </div>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            {exports.map((exp) => (
              <div
                key={exp.id}
                className="flex items-start justify-between gap-4 p-4 rounded-lg border border-border/50 hover:border-border transition-colors"
              >
                <div className="flex items-start gap-3 min-w-0">
                  <div className="mt-0.5 h-8 w-8 rounded-lg bg-primary/10 flex items-center justify-center shrink-0">
                    <FileArchive className="h-4 w-4 text-primary" />
                  </div>
                  <div className="min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <p className="text-sm font-semibold truncate">{exp.name}</p>
                      <Badge variant="outline">{exp.framework}</Badge>
                      {exp.sentToAuditor && (
                        <Badge variant="success" className="gap-1">
                          <Send className="h-3 w-3" />
                          Sent
                        </Badge>
                      )}
                    </div>
                    <div className="flex items-center gap-3 mt-1 text-xs text-muted-foreground flex-wrap">
                      <span className="flex items-center gap-1">
                        <Clock className="h-3.5 w-3.5" />
                        {new Date(exp.createdAt).toLocaleString()}
                      </span>
                      <span>{exp.period}</span>
                      <span>{exp.createdBy}</span>
                      <span>{exp.appIds.length} apps</span>
                      <span className="uppercase">{exp.format}</span>
                      {exp.sizeKb > 0 && (
                        <span>{(exp.sizeKb / 1024).toFixed(1)} MB</span>
                      )}
                    </div>
                    {exp.sentToAuditor && exp.auditorEmail && (
                      <p className="text-xs text-muted-foreground mt-1">
                        Sent to: {exp.auditorEmail}
                      </p>
                    )}
                  </div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <ExportStatusBadge status={exp.status} />
                  {exp.status === "ready" && (
                    <>
                      <Button
                        variant="ghost"
                        size="sm"
                        onClick={() => toast.success(`Downloading ${exp.name}...`)}
                      >
                        <Download className="h-4 w-4" />
                      </Button>
                      {!exp.sentToAuditor && (
                        <Button
                          variant="ghost"
                          size="sm"
                          onClick={() => toast.info("Enter auditor email to send...")}
                        >
                          <Send className="h-4 w-4" />
                        </Button>
                      )}
                    </>
                  )}
                  {exp.status === "failed" && (
                    <Button
                      variant="ghost"
                      size="sm"
                      className="text-xs"
                      onClick={() => toast.info("Retrying export...")}
                    >
                      Retry
                    </Button>
                  )}
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
