import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { motion, AnimatePresence } from "framer-motion";
import {
  FileText,
  BarChart2,
  TrendingUp,
  Shield,
  Download,
  Eye,
  X,
  Loader2,
  Clock,
  CheckCircle2,
  AlertCircle,
  Sparkles,
  FileJson,
  FileSpreadsheet,
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
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { reportsApi } from "@/lib/api";
import { toast } from "sonner";

// ─── Mock Data ───────────────────────────────────────────────────────────────

interface Report {
  id: string;
  name: string;
  type: "executive" | "technical" | "compliance" | "trend";
  format: "pdf" | "csv" | "json";
  generatedAt: string;
  generatedBy: string;
  framework?: string;
  period: string;
  sizeKb: number;
  status: "ready" | "generating" | "failed";
  pages?: number;
}

const MOCK_REPORTS: Report[] = [
  {
    id: "rep-001",
    name: "Q4 2024 Executive Security Briefing",
    type: "executive",
    format: "pdf",
    generatedAt: "2025-01-10T09:00:00Z",
    generatedBy: "Sarah Chen",
    period: "Q4 2024",
    sizeKb: 1840,
    status: "ready",
    pages: 24,
  },
  {
    id: "rep-002",
    name: "SOC 2 Compliance Evidence Package",
    type: "compliance",
    format: "pdf",
    generatedAt: "2025-01-09T15:30:00Z",
    generatedBy: "Marcus Williams",
    framework: "SOC 2",
    period: "FY2025",
    sizeKb: 14200,
    status: "ready",
    pages: 187,
  },
  {
    id: "rep-003",
    name: "Vulnerability Technical Report — January 2025",
    type: "technical",
    format: "pdf",
    generatedAt: "2025-01-09T11:00:00Z",
    generatedBy: "James Thompson",
    period: "January 2025",
    sizeKb: 5600,
    status: "ready",
    pages: 62,
  },
  {
    id: "rep-004",
    name: "MTTR & SLA Trend Analysis — 90 Days",
    type: "trend",
    format: "pdf",
    generatedAt: "2025-01-08T14:20:00Z",
    generatedBy: "Priya Patel",
    period: "Oct–Dec 2024",
    sizeKb: 2100,
    status: "ready",
    pages: 31,
  },
  {
    id: "rep-005",
    name: "PCI-DSS Gap Analysis Export",
    type: "compliance",
    format: "csv",
    generatedAt: "2025-01-08T10:00:00Z",
    generatedBy: "Sarah Chen",
    framework: "PCI-DSS",
    period: "Q4 2024",
    sizeKb: 340,
    status: "ready",
  },
  {
    id: "rep-006",
    name: "Scanner Performance Raw Data",
    type: "technical",
    format: "json",
    generatedAt: "2025-01-07T16:00:00Z",
    generatedBy: "system",
    period: "December 2024",
    sizeKb: 8900,
    status: "ready",
  },
  {
    id: "rep-007",
    name: "ISO 27001 Surveillance Prep Package",
    type: "compliance",
    format: "pdf",
    generatedAt: "2025-01-07T09:00:00Z",
    generatedBy: "Marcus Williams",
    framework: "ISO 27001",
    period: "FY2025",
    sizeKb: 9800,
    status: "failed",
  },
];

const REPORT_TYPES = [
  {
    id: "executive",
    label: "Executive Summary",
    description: "High-level security posture overview for leadership and board",
    icon: Sparkles,
    color: "text-purple-400 bg-purple-500/10",
  },
  {
    id: "technical",
    label: "Technical Report",
    description: "Detailed vulnerability findings, CVSS scores, and remediation steps",
    icon: BarChart2,
    color: "text-blue-400 bg-blue-500/10",
  },
  {
    id: "compliance",
    label: "Compliance Report",
    description: "Framework-specific control coverage, gaps, and evidence mapping",
    icon: Shield,
    color: "text-green-400 bg-green-500/10",
  },
  {
    id: "trend",
    label: "Trend Analysis",
    description: "MTTR trends, noise reduction metrics, and SLA compliance over time",
    icon: TrendingUp,
    color: "text-teal-400 bg-teal-500/10",
  },
];

// ─── Helpers ─────────────────────────────────────────────────────────────────

function FormatIcon({ format }: { format: Report["format"] }) {
  switch (format) {
    case "pdf":
      return <FileText className="h-4 w-4 text-red-400" />;
    case "csv":
      return <FileSpreadsheet className="h-4 w-4 text-green-400" />;
    case "json":
      return <FileJson className="h-4 w-4 text-blue-400" />;
  }
}

function TypeBadge({ type }: { type: Report["type"] }) {
  const map: Record<string, string> = {
    executive: "bg-purple-500/10 text-purple-400 border-purple-500/30",
    technical: "bg-blue-500/10 text-blue-400 border-blue-500/30",
    compliance: "bg-green-500/10 text-green-400 border-green-500/30",
    trend: "bg-teal-500/10 text-teal-400 border-teal-500/30",
  };
  const labels: Record<string, string> = {
    executive: "Executive",
    technical: "Technical",
    compliance: "Compliance",
    trend: "Trend",
  };
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium border ${map[type]}`}
    >
      {labels[type]}
    </span>
  );
}

function ReportStatusBadge({ status }: { status: Report["status"] }) {
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
  }
}

// ─── Preview Modal ────────────────────────────────────────────────────────────

function ReportPreviewModal({
  report,
  onClose,
}: {
  report: Report;
  onClose: () => void;
}) {
  return (
    <motion.div
      initial={{ opacity: 0 }}
      animate={{ opacity: 1 }}
      exit={{ opacity: 0 }}
      className="fixed inset-0 z-50 flex items-center justify-center p-4"
    >
      <div className="absolute inset-0 bg-black/70" onClick={onClose} />
      <motion.div
        initial={{ scale: 0.95, opacity: 0 }}
        animate={{ scale: 1, opacity: 1 }}
        exit={{ scale: 0.95, opacity: 0 }}
        className="relative w-full max-w-2xl bg-card border border-border/50 rounded-xl shadow-2xl overflow-hidden"
      >
        <div className="flex items-start justify-between p-5 border-b border-border/50">
          <div className="space-y-1">
            <h2 className="text-base font-bold">{report.name}</h2>
            <div className="flex items-center gap-2">
              <TypeBadge type={report.type} />
              {report.framework && (
                <Badge variant="outline">{report.framework}</Badge>
              )}
            </div>
          </div>
          <Button variant="ghost" size="sm" onClick={onClose}>
            <X className="h-4 w-4" />
          </Button>
        </div>
        <div className="p-5 space-y-4">
          <div className="grid grid-cols-2 gap-3 text-sm">
            {[
              { label: "Period", value: report.period },
              { label: "Generated By", value: report.generatedBy },
              { label: "Generated At", value: new Date(report.generatedAt).toLocaleString() },
              { label: "Format", value: report.format.toUpperCase() },
              { label: "Size", value: `${(report.sizeKb / 1024).toFixed(2)} MB` },
              { label: "Pages", value: report.pages ? `${report.pages} pages` : "N/A" },
            ].map(({ label, value }) => (
              <div key={label} className="flex justify-between border-b border-border/30 pb-2">
                <span className="text-muted-foreground">{label}</span>
                <span className="font-medium">{value}</span>
              </div>
            ))}
          </div>
          {/* Simulated preview */}
          <div className="bg-muted/20 rounded-lg border border-border/50 p-6 text-center space-y-2">
            <FileText className="h-12 w-12 text-muted-foreground mx-auto opacity-40" />
            <p className="text-sm text-muted-foreground">Report preview available on download</p>
            <p className="text-xs text-muted-foreground">
              {report.pages ? `${report.pages} pages` : report.format.toUpperCase()} ·{" "}
              {(report.sizeKb / 1024).toFixed(2)} MB
            </p>
          </div>
          <div className="flex gap-3">
            <Button
              className="flex-1"
              onClick={() => {
                toast.success(`Downloading ${report.name}...`);
                onClose();
              }}
            >
              <Download className="mr-2 h-4 w-4" />
              Download Report
            </Button>
            <Button variant="outline" onClick={onClose}>
              Close
            </Button>
          </div>
        </div>
      </motion.div>
    </motion.div>
  );
}

// ─── Main Component ──────────────────────────────────────────────────────────

export default function Reports() {
  const [reportType, setReportType] = useState<string>("executive");
  const [framework, setFramework] = useState("soc2");
  const [period, setPeriod] = useState("last-quarter");
  const [format, setFormat] = useState("pdf");
  const [previewReport, setPreviewReport] = useState<Report | null>(null);

  const { data } = useQuery({
    queryKey: ["reports-list"],
    queryFn: () => reportsApi.list(),
  });

  const generateMutation = useMutation({
    mutationFn: (payload: unknown) => reportsApi.generate(payload),
    onSuccess: () => {
      toast.success("Report generation started — typically takes 1–3 minutes.");
    },
    onError: () => {
      toast.error("Failed to start report generation.");
    },
  });

  const reports: Report[] =
    (data as { data?: Report[] })?.data ?? MOCK_REPORTS;

  const readyCount = reports.filter((r) => r.status === "ready").length;
  const generatingCount = reports.filter((r) => r.status === "generating").length;

  const handleGenerate = () => {
    generateMutation.mutate({
      type: reportType,
      framework: reportType === "compliance" ? framework : undefined,
      period,
      format,
    });
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      <PageHeader
        title="Reports"
        description="Generate executive, technical, compliance, and trend analysis reports in multiple formats"
        actions={
          <Button size="sm" onClick={handleGenerate} disabled={generateMutation.isPending}>
            {generateMutation.isPending ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Generating...
              </>
            ) : (
              <>
                <Sparkles className="mr-2 h-4 w-4" />
                Quick Generate
              </>
            )}
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard
          title="Reports Generated"
          value={reports.length}
          change={3}
          changeLabel="this week"
          icon={FileText}
          trend="up"
        />
        <KpiCard title="Ready to Download" value={readyCount} icon={CheckCircle2} trend="flat" />
        <KpiCard title="Generating" value={generatingCount} icon={Loader2} trend="flat" />
        <KpiCard
          title="Failed"
          value={reports.filter((r) => r.status === "failed").length}
          icon={AlertCircle}
          trend="flat"
        />
      </div>

      <Tabs defaultValue="generate" className="space-y-4">
        <TabsList>
          <TabsTrigger value="generate">Generate Report</TabsTrigger>
          <TabsTrigger value="history">Report History</TabsTrigger>
        </TabsList>

        {/* Generate Tab */}
        <TabsContent value="generate" className="space-y-4">
          {/* Report type selector */}
          <div>
            <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground mb-3">
              Report Type
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-3">
              {REPORT_TYPES.map((rt) => {
                const Icon = rt.icon;
                const isSelected = reportType === rt.id;
                return (
                  <button
                    key={rt.id}
                    onClick={() => setReportType(rt.id)}
                    className={`flex flex-col items-start gap-2.5 p-4 rounded-lg border text-left transition-all duration-150 ${
                      isSelected
                        ? "border-primary/50 bg-primary/5 ring-1 ring-primary/20"
                        : "border-border/50 hover:border-border"
                    }`}
                  >
                    <div className={`h-8 w-8 rounded-lg flex items-center justify-center ${rt.color}`}>
                      <Icon className="h-4 w-4" />
                    </div>
                    <div>
                      <p className="text-sm font-semibold">{rt.label}</p>
                      <p className="text-xs text-muted-foreground mt-0.5 leading-relaxed">
                        {rt.description}
                      </p>
                    </div>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Options */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {reportType === "compliance" && (
              <div className="space-y-1.5">
                <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
                  Framework
                </label>
                <Select value={framework} onValueChange={setFramework}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="soc2">SOC 2 Type II</SelectItem>
                    <SelectItem value="pci-dss">PCI-DSS v4.0</SelectItem>
                    <SelectItem value="iso27001">ISO 27001:2022</SelectItem>
                    <SelectItem value="hipaa">HIPAA</SelectItem>
                    <SelectItem value="nist800">NIST 800-53</SelectItem>
                    <SelectItem value="all">All Frameworks</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            )}
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
                Period
              </label>
              <Select value={period} onValueChange={setPeriod}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="last-week">Last 7 days</SelectItem>
                  <SelectItem value="last-month">Last 30 days</SelectItem>
                  <SelectItem value="last-quarter">Last Quarter</SelectItem>
                  <SelectItem value="last-year">Last Year</SelectItem>
                  <SelectItem value="ytd">Year to Date</SelectItem>
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
                  <SelectItem value="pdf">PDF Document</SelectItem>
                  <SelectItem value="csv">CSV Spreadsheet</SelectItem>
                  <SelectItem value="json">JSON Data</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          <Button
            className="w-full sm:w-auto"
            onClick={handleGenerate}
            disabled={generateMutation.isPending}
          >
            {generateMutation.isPending ? (
              <>
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                Generating report...
              </>
            ) : (
              <>
                <Sparkles className="mr-2 h-4 w-4" />
                Generate{" "}
                {REPORT_TYPES.find((t) => t.id === reportType)?.label} Report (
                {format.toUpperCase()})
              </>
            )}
          </Button>
        </TabsContent>

        {/* History Tab */}
        <TabsContent value="history">
          <div className="space-y-2">
            {reports.map((report) => (
              <Card key={report.id} className="border-border/50">
                <CardContent className="p-4">
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex items-start gap-3 min-w-0">
                      <div className="mt-0.5">
                        <FormatIcon format={report.format} />
                      </div>
                      <div className="min-w-0">
                        <div className="flex items-center gap-2 flex-wrap">
                          <p className="text-sm font-semibold truncate">{report.name}</p>
                          <TypeBadge type={report.type} />
                          {report.framework && (
                            <Badge variant="outline">{report.framework}</Badge>
                          )}
                        </div>
                        <div className="flex items-center gap-3 mt-1 text-xs text-muted-foreground">
                          <span className="flex items-center gap-1">
                            <Clock className="h-3.5 w-3.5" />
                            {new Date(report.generatedAt).toLocaleString()}
                          </span>
                          <span>{report.period}</span>
                          <span>{report.generatedBy}</span>
                          {report.pages && <span>{report.pages} pages</span>}
                          <span>{(report.sizeKb / 1024).toFixed(1)} MB</span>
                        </div>
                      </div>
                    </div>
                    <div className="flex items-center gap-2 shrink-0">
                      <ReportStatusBadge status={report.status} />
                      {report.status === "ready" && (
                        <>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => setPreviewReport(report)}
                          >
                            <Eye className="h-4 w-4" />
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => toast.success(`Downloading ${report.name}...`)}
                          >
                            <Download className="h-4 w-4" />
                          </Button>
                        </>
                      )}
                      {report.status === "failed" && (
                        <Button
                          variant="ghost"
                          size="sm"
                          className="text-xs"
                          onClick={() => toast.info("Retrying report generation...")}
                        >
                          Retry
                        </Button>
                      )}
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>
      </Tabs>

      {/* Preview Modal */}
      <AnimatePresence>
        {previewReport && (
          <ReportPreviewModal
            report={previewReport}
            onClose={() => setPreviewReport(null)}
          />
        )}
      </AnimatePresence>
    </motion.div>
  );
}
