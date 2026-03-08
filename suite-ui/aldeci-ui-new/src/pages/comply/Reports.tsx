import { useState, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Checkbox } from "@/components/ui/checkbox";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Separator } from "@/components/ui/separator";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { motion } from "framer-motion";
import {
  FileText, BarChart2, TrendingUp, Shield, Users, Download,
  RefreshCw, Plus, Clock, Calendar, CheckCircle, Zap
} from "lucide-react";
import { useReports } from "@/hooks/use-api";

const REPORT_TEMPLATES = [
  {
    id: "executive",
    name: "Executive Summary",
    icon: Users,
    description: "High-level security posture overview for C-suite and board members. Includes risk heatmap, KPIs, and trend summaries.",
    color: "text-violet-400",
    bg: "bg-violet-900/20 border-violet-700/30",
  },
  {
    id: "technical",
    name: "Technical Deep-Dive",
    icon: Shield,
    description: "Detailed findings, remediation steps, CVSS scores, and scanner output for security engineers.",
    color: "text-blue-400",
    bg: "bg-blue-900/20 border-blue-700/30",
  },
  {
    id: "compliance",
    name: "Compliance Report",
    icon: FileText,
    description: "Framework-mapped control status, evidence bundles, and gap analysis for auditors.",
    color: "text-green-400",
    bg: "bg-green-900/20 border-green-700/30",
  },
  {
    id: "trend",
    name: "Trend Analysis",
    icon: TrendingUp,
    description: "6-month MTTR trends, noise reduction rates, scanner ROI, and SLA compliance over time.",
    color: "text-orange-400",
    bg: "bg-orange-900/20 border-orange-700/30",
  },
  {
    id: "board",
    name: "Board Briefing",
    icon: BarChart2,
    description: "Concise board-level presentation with risk summary, regulatory status, and investment recommendations.",
    color: "text-pink-400",
    bg: "bg-pink-900/20 border-pink-700/30",
  },
];

const FRAMEWORKS = ["SOC2", "PCI-DSS", "HIPAA", "ISO27001", "NIST"];
const FORMATS = ["PDF", "CSV", "JSON", "HTML"];

function GenerateReportDialog({ onGenerate }: { onGenerate: () => void }) {
  const [open, setOpen] = useState(false);
  const [templateId, setTemplateId] = useState("executive");
  const [dateFrom, setDateFrom] = useState("");
  const [dateTo, setDateTo] = useState("");
  const [selectedApps, setSelectedApps] = useState<string[]>([]);
  const [selectedFrameworks, setSelectedFrameworks] = useState<string[]>(["SOC2"]);
  const [format, setFormat] = useState("PDF");
  const [isGenerating, setIsGenerating] = useState(false);

  const toggleFramework = (fw: string) => {
    setSelectedFrameworks((prev) =>
      prev.includes(fw) ? prev.filter((f) => f !== fw) : [...prev, fw]
    );
  };

  const handleGenerate = async () => {
    setIsGenerating(true);
    await new Promise((resolve) => setTimeout(resolve, 1500));
    setIsGenerating(false);
    onGenerate();
    setOpen(false);
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size="sm" className="gap-2">
          <Plus className="h-4 w-4" />
          Generate Report
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <FileText className="h-4 w-4 text-primary" />
            Generate Report
          </DialogTitle>
        </DialogHeader>
        <div className="space-y-5">
          {/* Template */}
          <div>
            <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-2 block">Report Type</Label>
            <Select value={templateId} onValueChange={setTemplateId}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {REPORT_TEMPLATES.map((t) => (
                  <SelectItem key={t.id} value={t.id}>{t.name}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          {/* Date range */}
          <div className="grid grid-cols-2 gap-3">
            <div>
              <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-2 block">From</Label>
              <Input type="date" value={dateFrom} onChange={(e) => setDateFrom(e.target.value)} />
            </div>
            <div>
              <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-2 block">To</Label>
              <Input type="date" value={dateTo} onChange={(e) => setDateTo(e.target.value)} />
            </div>
          </div>

          {/* Frameworks */}
          <div>
            <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-3 block">Frameworks</Label>
            <div className="flex flex-wrap gap-2">
              {FRAMEWORKS.map((fw) => (
                <div key={fw} className="flex items-center gap-2">
                  <Checkbox
                    id={`fw-${fw}`}
                    checked={selectedFrameworks.includes(fw)}
                    onCheckedChange={() => toggleFramework(fw)}
                  />
                  <Label htmlFor={`fw-${fw}`} className="text-sm cursor-pointer">{fw}</Label>
                </div>
              ))}
            </div>
          </div>

          {/* Format */}
          <div>
            <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-2 block">Output Format</Label>
            <Select value={format} onValueChange={setFormat}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                {FORMATS.map((f) => (
                  <SelectItem key={f} value={f}>{f}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>

          <Separator />
          <div className="flex gap-2 justify-end">
            <Button variant="outline" onClick={() => setOpen(false)}>Cancel</Button>
            <Button onClick={handleGenerate} disabled={isGenerating} className="gap-2">
              <Zap className="h-3.5 w-3.5" />
              {isGenerating ? "Generating…" : "Generate"}
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

export default function Reports() {
  const reportsQuery = useReports();
  const refetch = useCallback(() => reportsQuery.refetch(), [reportsQuery]);

  if (reportsQuery.isLoading) return <PageSkeleton />;
  if (reportsQuery.isError) return <ErrorState message="Failed to load reports" onRetry={refetch} />;

  const reports: any[] = reportsQuery.data?.data ?? reportsQuery.data ?? [];

  const totalReports = reports.length;
  const pdfReports = reports.filter((r: any) => (r.format ?? r.output_format ?? "").toUpperCase() === "PDF").length;
  const thisMonth = reports.filter((r: any) => {
    if (!r.created_at && !r.date) return false;
    const d = new Date(r.created_at ?? r.date);
    const now = new Date();
    return d.getMonth() === now.getMonth() && d.getFullYear() === now.getFullYear();
  }).length;

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      <PageHeader
        title="Reports"
        description="Generate compliance, security, and trend reports for stakeholders and auditors"
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={refetch} className="gap-2">
          <RefreshCw className="h-4 w-4" />
          Refresh
        </Button>
        <GenerateReportDialog onGenerate={refetch} />
          </div>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Total Reports" value={totalReports} icon={FileText} />
        <KpiCard title="PDF Reports" value={pdfReports} icon={FileText} />
        <KpiCard title="This Month" value={thisMonth} icon={Calendar} />
        <KpiCard title="Templates" value={REPORT_TEMPLATES.length} icon={Zap} />
      </div>

      {/* Template gallery */}
      <div>
        <h2 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider mb-3">
          Report Templates
        </h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-4">
          {REPORT_TEMPLATES.map((template, i) => {
            const Icon = template.icon;
            return (
              <motion.div
                key={template.id}
                initial={{ opacity: 0, y: 12 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.05 }}
              >
                <Card className={`hover:shadow-md transition-all cursor-pointer border ${template.bg}`}>
                  <CardHeader className="pb-2">
                    <div className={`h-8 w-8 rounded-lg flex items-center justify-center mb-2 ${template.bg}`}>
                      <Icon className={`h-4 w-4 ${template.color}`} />
                    </div>
                    <CardTitle className="text-sm">{template.name}</CardTitle>
                  </CardHeader>
                  <CardContent className="pt-0">
                    <CardDescription className="text-xs leading-relaxed">{template.description}</CardDescription>
                  </CardContent>
                </Card>
              </motion.div>
            );
          })}
        </div>
      </div>

      {/* Generated reports list */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center justify-between">
            <span className="flex items-center gap-2">
              <FileText className="h-4 w-4 text-primary" />
              Generated Reports
            </span>
            <span className="text-sm font-normal text-muted-foreground">{reports.length} reports</span>
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent border-b border-border/40">
                <TableHead className="text-xs">Report Name</TableHead>
                <TableHead className="text-xs">Type</TableHead>
                <TableHead className="text-xs">Generated</TableHead>
                <TableHead className="text-xs">Format</TableHead>
                <TableHead className="text-xs">Size</TableHead>
                <TableHead className="text-xs text-right">Download</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {reports.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-center py-12 text-muted-foreground">
                    No reports generated yet. Use a template above to create your first report.
                  </TableCell>
                </TableRow>
              ) : (
                reports.slice(0, 30).map((report: any, i: number) => (
                  <TableRow key={report.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="text-sm font-medium">{report.name ?? report.title ?? `Report ${i + 1}`}</TableCell>
                    <TableCell>
                      <Badge variant="secondary" className="text-xs capitalize">
                        {report.type ?? report.report_type ?? "compliance"}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {report.created_at ?? report.date ?? "—"}
                    </TableCell>
                    <TableCell>
                      <Badge variant="outline" className="text-xs uppercase">
                        {report.format ?? report.output_format ?? "PDF"}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {report.size ?? "—"}
                    </TableCell>
                    <TableCell className="text-right">
                      <Button variant="ghost" size="icon" className="h-7 w-7">
                        <Download className="h-3.5 w-3.5" />
                      </Button>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </motion.div>
  );
}
