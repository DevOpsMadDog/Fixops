import { toArray } from "@/lib/api-utils";
import { useState, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Checkbox } from "@/components/ui/checkbox";
import { Progress } from "@/components/ui/progress";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { PageHeader } from "@/components/shared/page-header";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { motion } from "framer-motion";
import {
  Download, Send, FileText, RefreshCw, CheckCircle, Package,
  Layers, Calendar, Shield, Eye, Zap, Clock, Mail, History,
  ChevronRight, ChevronDown, Lock, AlertTriangle
} from "lucide-react";
import { useEvidenceBundles, useEvidenceSummary, useComplianceFrameworks, useApps } from "@/hooks/use-api";
import { evidenceApi } from "@/lib/api";
import { toast } from "sonner";

const FRAMEWORKS = ["SOC2", "PCI-DSS", "HIPAA", "ISO27001", "NIST"];

const CONTROL_TREE: Record<string, string[]> = {
  SOC2: ["CC1 – Control Environment", "CC2 – Communication", "CC3 – Risk Assessment", "CC4 – Monitoring", "CC5 – Control Activities", "A1 – Availability", "C1 – Confidentiality"],
  "PCI-DSS": ["Req 1 – Network Controls", "Req 2 – Secure Configs", "Req 3 – Account Data", "Req 4 – Encryption", "Req 6 – Secure Systems", "Req 8 – User Auth", "Req 10 – Logging"],
  HIPAA: ["§164.308 – Admin Safeguards", "§164.310 – Physical Safeguards", "§164.312 – Technical Safeguards", "§164.314 – Org Requirements"],
  ISO27001: ["A.5 – Policies", "A.6 – Organization", "A.8 – Asset Management", "A.9 – Access Control", "A.12 – Operations Security", "A.16 – Incident Management"],
  NIST: ["ID – Identify", "PR – Protect", "DE – Detect", "RS – Respond", "RC – Recover"],
};

const INCLUDE_OPTIONS = [
  { id: "mpte", label: "MPTE Results", desc: "Multi-Pipeline Test Engine verification results" },
  { id: "scan_history", label: "Scan History", desc: "Scanner outputs from all configured tools" },
  { id: "decision_log", label: "Decision Log", desc: "Triage decisions and analyst reasoning" },
  { id: "raw_findings", label: "Raw Findings", desc: "Unprocessed scanner findings data" },
];

const FORMATS = [
  { id: "pdf_json", label: "PDF + JSON", desc: "Human-readable PDF with machine-readable JSON" },
  { id: "pdf", label: "PDF Only", desc: "Formatted PDF report" },
  { id: "json", label: "JSON Only", desc: "Structured data bundle for integrations" },
];

// Helper to download any object as a JSON blob
function downloadBlob(data: any, filename: string) {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
  toast.success(`Downloaded ${filename}`);
}

function SendToAuditorDialog({ disabled, framework }: { disabled: boolean; framework: string }) {
  const [open, setOpen] = useState(false);
  const [email, setEmail] = useState("");
  const [message, setMessage] = useState(`Please find attached the ${framework} evidence package for your review.`);
  const [sending, setSending] = useState(false);
  const [sent, setSent] = useState(false);

  const handleSend = async () => {
    setSending(true);
    try {
      await evidenceApi.export({
        frameworks: [framework],
        send_to: email,
        message,
        format: "pdf_json",
      });
      setSent(true);
      toast.success(`Evidence sent to ${email}`);
      setTimeout(() => { setSent(false); setOpen(false); }, 1200);
    } catch (err: any) {
      toast.error(`Failed to send: ${err?.response?.data?.detail ?? err.message}`);
    } finally {
      setSending(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="outline" className="w-full gap-2" size="sm" disabled={disabled}>
          <Send className="h-3.5 w-3.5" />
          Send to Auditor
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Mail className="h-4 w-4 text-primary" />
            Send to Auditor
          </DialogTitle>
        </DialogHeader>
        <div className="space-y-4">
          <div>
            <Label className="text-xs text-muted-foreground mb-1.5 block">Auditor Email</Label>
            <Input
              type="email"
              placeholder="auditor@example.com"
              value={email}
              onChange={(e) => setEmail(e.target.value)}
            />
          </div>
          <div>
            <Label className="text-xs text-muted-foreground mb-1.5 block">Message</Label>
            <textarea
              className="w-full h-24 rounded-md border border-input bg-background px-3 py-2 text-sm text-muted-foreground resize-none focus:outline-none focus:ring-1 focus:ring-ring"
              value={message}
              onChange={(e) => setMessage(e.target.value)}
            />
          </div>
          <div className="p-3 rounded-lg bg-muted/30 border border-border/40 text-xs text-muted-foreground flex items-center gap-2">
            <Lock className="h-3.5 w-3.5 text-violet-400 shrink-0" />
            Package will be encrypted with quantum-safe key before transmission
          </div>
          <Separator />
          <div className="flex gap-2 justify-end">
            <Button variant="outline" size="sm" onClick={() => setOpen(false)}>Cancel</Button>
            <Button size="sm" onClick={handleSend} disabled={!email || sending} className="gap-2">
              {sent ? <><CheckCircle className="h-3.5 w-3.5" /> Sent!</> : sending ? "Sending…" : <><Send className="h-3.5 w-3.5" /> Send</>}
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

function ControlTreePanel({ framework, bundles }: { framework: string; bundles: any[] }) {
  const controls = CONTROL_TREE[framework] ?? [];
  const total = controls.length;
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const toggleExpand = (ctrl: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(ctrl)) next.delete(ctrl); else next.add(ctrl);
      return next;
    });
  };

  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between text-xs text-muted-foreground mb-3">
        <span>Control Coverage Preview</span>
        <Badge variant="outline" className="text-xs">{total} controls</Badge>
      </div>
      {controls.map((ctrl) => {
        const covered = bundles.filter((b: any) =>
          b.framework === framework && (b.control ?? "").toLowerCase().includes(ctrl.split(" ")[0].toLowerCase())
        ).length;
        const isExpanded = expanded.has(ctrl);
        return (
          <div key={ctrl}>
            <div
              className="flex items-center gap-2 cursor-pointer hover:bg-muted/30 rounded p-1.5"
              onClick={() => covered > 0 && toggleExpand(ctrl)}
            >
              <div className="w-3 h-3 rounded-full shrink-0 bg-primary/40 flex items-center justify-center">
                {covered > 0 && <div className="w-2 h-2 rounded-full bg-primary" />}
              </div>
              <span className="text-xs flex-1 text-muted-foreground">{ctrl}</span>
              <Badge variant={covered > 0 ? "default" : "outline"} className="text-xs">
                {covered > 0 ? `${covered} evidence` : "Missing"}
              </Badge>
              {covered > 0 && (
                isExpanded
                  ? <ChevronDown className="h-3 w-3 text-muted-foreground" />
                  : <ChevronRight className="h-3 w-3 text-muted-foreground" />
              )}
            </div>
            {isExpanded && covered > 0 && (
              <div className="ml-5 pl-3 border-l border-border/40 mt-1 space-y-1">
                {bundles
                  .filter((b: any) => b.framework === framework && (b.control ?? "").toLowerCase().includes(ctrl.split(" ")[0].toLowerCase()))
                  .slice(0, 3)
                  .map((b: any, i: number) => (
                    <div key={i} className="text-xs text-muted-foreground flex items-center gap-2 py-0.5">
                      <CheckCircle className="h-2.5 w-2.5 text-green-500 shrink-0" />
                      {b.bundle_id ?? b.id ?? `BND-00${i + 1}`}
                      {(b.quantum_signed || b.signed) && (
                        <Badge className="text-xs py-0 h-3.5 bg-violet-900/40 text-violet-300 border-violet-700">Q</Badge>
                      )}
                    </div>
                  ))
                }
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

export default function EvidenceExportCenter() {
  const bundlesQuery = useEvidenceBundles();
  const summaryQuery = useEvidenceSummary();
  const frameworksQuery = useComplianceFrameworks();
  const appsQuery = useApps();

  const refetchAll = useCallback(() => {
    bundlesQuery.refetch();
    summaryQuery.refetch();
    frameworksQuery.refetch();
    appsQuery.refetch();
  }, [bundlesQuery, summaryQuery, frameworksQuery, appsQuery]);

  const [selectedFrameworks, setSelectedFrameworks] = useState<string[]>(["SOC2"]);
  const [selectedApps, setSelectedApps] = useState<string[]>([]);
  const [period, setPeriod] = useState("last-30d");
  const [format, setFormat] = useState("pdf_json");
  const [includeOptions, setIncludeOptions] = useState<string[]>(["mpte", "scan_history"]);
  const [isGenerating, setIsGenerating] = useState(false);
  const [progress, setProgress] = useState(0);
  const [generationStage, setGenerationStage] = useState("");
  const [lastExport, setLastExport] = useState<any>(null);

  const isLoading = bundlesQuery.isLoading || appsQuery.isLoading;
  const isError = bundlesQuery.isError && summaryQuery.isError;

  if (isLoading) return <PageSkeleton />;
  if (isError) return <ErrorState message="Failed to load export data" onRetry={refetchAll} />;

  const summaryData: any = summaryQuery.data?.data ?? summaryQuery.data ?? {};
  const bundles: any[] = toArray(summaryData.bundles ?? summaryData).length > 0
    ? toArray(summaryData.bundles ?? summaryData)
    : toArray(bundlesQuery.data);
  const apps: any[] = toArray(appsQuery.data);
  const frameworks: string[] = toArray(frameworksQuery.data).map((f: any) => {
    if (typeof f === "string") return f;
    return f.name ?? f.framework ?? String(f.id ?? "");
  }).filter(Boolean);
  const allFrameworks = frameworks.length > 0 ? frameworks : FRAMEWORKS;

  const toggleApp = (appId: string) => {
    setSelectedApps((prev) =>
      prev.includes(appId) ? prev.filter((a) => a !== appId) : [...prev, appId]
    );
  };

  const toggleInclude = (id: string) => {
    setIncludeOptions((prev) =>
      prev.includes(id) ? prev.filter((o) => o !== id) : [...prev, id]
    );
  };

  const toggleFramework = (fw: string) => {
    setSelectedFrameworks((prev) =>
      prev.includes(fw) ? prev.filter((f) => f !== fw) : [...prev, fw]
    );
  };

  // Use first selected framework for control tree preview
  const primaryFramework = selectedFrameworks[0] ?? "SOC2";
  const frameworkBundles = bundles.filter((b: any) => b.framework === primaryFramework);
  const estimatedTime = 10 + (selectedApps.length * 5) + (includeOptions.length * 3) + (selectedFrameworks.length * 8);

  const GENERATION_STAGES = [
    "Collecting evidence bundles…",
    "Verifying quantum signatures…",
    "Mapping to controls…",
    "Generating PDF report…",
    "Packaging JSON bundle…",
    "Complete!",
  ];

  const handleGenerate = async () => {
    setIsGenerating(true);
    setProgress(0);
    setGenerationStage(GENERATION_STAGES[0]);
    try {
      setProgress(15);
      setGenerationStage(GENERATION_STAGES[0]);
      const res = await evidenceApi.export({
        frameworks: selectedFrameworks,
        apps: selectedApps.length > 0 ? selectedApps : undefined,
        period,
        format,
        include: includeOptions,
      });
      setProgress(60);
      setGenerationStage(GENERATION_STAGES[2]);
      const exportData = res.data?.data ?? res.data;
      setLastExport(exportData);
      setProgress(100);
      setGenerationStage(GENERATION_STAGES[5]);
      toast.success("Evidence package generated successfully");
    } catch (err: any) {
      toast.error(`Export failed: ${err?.response?.data?.detail ?? err.message}`);
      setProgress(0);
      setGenerationStage("");
    } finally {
      setIsGenerating(false);
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      <PageHeader
        title="Evidence Export Center"
        description="Build and download evidence packages for auditors and compliance reviews"
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={refetchAll} className="gap-2">
          <RefreshCw className="h-4 w-4" />
          Refresh
        </Button>
          </div>
        }
      />

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Configuration panel */}
        <div className="lg:col-span-2 space-y-5">
          {/* Multi-Framework selector */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm flex items-center gap-2">
                <Shield className="h-4 w-4 text-primary" />
                Compliance Frameworks
                <Badge variant="secondary" className="text-xs">{selectedFrameworks.length} selected</Badge>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex flex-wrap gap-2">
                {allFrameworks.map((fw) => (
                  <div
                    key={fw}
                    className={`px-3 py-1.5 rounded-lg border cursor-pointer text-sm font-medium transition-all ${
                      selectedFrameworks.includes(fw)
                        ? "border-primary/60 bg-primary/10 text-primary"
                        : "border-border/40 text-muted-foreground hover:border-border"
                    }`}
                    onClick={() => toggleFramework(fw)}
                  >
                    {fw}
                    {selectedFrameworks.includes(fw) && <CheckCircle className="h-3 w-3 inline ml-1.5" />}
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* App multi-select */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm flex items-center gap-2">
                <Layers className="h-4 w-4 text-primary" />
                Applications
                <Badge variant="secondary" className="text-xs">{selectedApps.length} selected</Badge>
              </CardTitle>
            </CardHeader>
            <CardContent>
              {apps.length === 0 ? (
                <p className="text-sm text-muted-foreground">No applications registered</p>
              ) : (
                <div className="grid grid-cols-2 gap-2">
                  {apps.map((app: any) => {
                    const appId = app.app_id ?? app.id;
                    return (
                      <div key={appId} className="flex items-center gap-2 p-2 rounded-lg hover:bg-muted/30 cursor-pointer"
                        onClick={() => toggleApp(appId)}>
                        <Checkbox
                          id={`app-${appId}`}
                          checked={selectedApps.includes(appId)}
                          onCheckedChange={() => toggleApp(appId)}
                        />
                        <Label htmlFor={`app-${appId}`} className="text-sm cursor-pointer">
                          {app.name ?? appId}
                        </Label>
                      </div>
                    );
                  })}
                </div>
              )}
            </CardContent>
          </Card>

          {/* Period + Format */}
          <div className="grid grid-cols-2 gap-4">
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Calendar className="h-4 w-4 text-primary" />
                  Period
                </CardTitle>
              </CardHeader>
              <CardContent>
                <Select value={period} onValueChange={setPeriod}>
                  <SelectTrigger>
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="last-7d">Last 7 days</SelectItem>
                    <SelectItem value="last-30d">Last 30 days</SelectItem>
                    <SelectItem value="last-90d">Last 90 days</SelectItem>
                    <SelectItem value="last-6m">Last 6 months</SelectItem>
                    <SelectItem value="last-1y">Last 1 year</SelectItem>
                  </SelectContent>
                </Select>
              </CardContent>
            </Card>
            <Card>
              <CardHeader className="pb-3">
                <CardTitle className="text-sm flex items-center gap-2">
                  <FileText className="h-4 w-4 text-primary" />
                  Format
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                {FORMATS.map((f) => (
                  <div key={f.id} className="flex items-center gap-2 cursor-pointer" onClick={() => setFormat(f.id)}>
                    <div className={`h-4 w-4 rounded-full border-2 flex items-center justify-center ${format === f.id ? "border-primary" : "border-muted-foreground"}`}>
                      {format === f.id && <div className="h-2 w-2 rounded-full bg-primary" />}
                    </div>
                    <div>
                      <p className="text-xs font-medium">{f.label}</p>
                      <p className="text-xs text-muted-foreground">{f.desc}</p>
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>
          </div>

          {/* Include options */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm flex items-center gap-2">
                <Package className="h-4 w-4 text-primary" />
                Include in Export
              </CardTitle>
            </CardHeader>
            <CardContent className="grid grid-cols-2 gap-3">
              {INCLUDE_OPTIONS.map((opt) => (
                <div key={opt.id}
                  className={`p-3 rounded-lg border cursor-pointer transition-all ${includeOptions.includes(opt.id) ? "border-primary/50 bg-primary/5" : "border-border/40 hover:border-border"}`}
                  onClick={() => toggleInclude(opt.id)}>
                  <div className="flex items-center gap-2 mb-1">
                    <Checkbox
                      id={`opt-${opt.id}`}
                      checked={includeOptions.includes(opt.id)}
                      onCheckedChange={() => toggleInclude(opt.id)}
                    />
                    <Label htmlFor={`opt-${opt.id}`} className="text-xs font-medium cursor-pointer">{opt.label}</Label>
                  </div>
                  <p className="text-xs text-muted-foreground ml-6">{opt.desc}</p>
                </div>
              ))}
            </CardContent>
          </Card>

          {/* Generate button */}
          <Card>
            <CardContent className="py-4">
              {isGenerating ? (
                <div className="space-y-3">
                  <div className="flex items-center gap-2 text-sm">
                    <Zap className="h-4 w-4 text-primary animate-pulse" />
                    <span>{generationStage || "Generating evidence package…"}</span>
                    <span className="ml-auto font-mono text-primary">{progress}%</span>
                  </div>
                  <Progress value={progress} className="h-2" />
                  <div className="flex gap-1.5 flex-wrap">
                    {GENERATION_STAGES.map((stage, i) => {
                      const stageProgress = (i + 1) * (100 / GENERATION_STAGES.length);
                      const done = progress >= stageProgress;
                      return (
                        <Badge
                          key={stage}
                          variant="outline"
                          className={`text-xs ${done ? "text-green-400 border-green-700" : "text-muted-foreground"}`}
                        >
                          {done ? <CheckCircle className="h-2.5 w-2.5 mr-1 inline" /> : null}
                          Stage {i + 1}
                        </Badge>
                      );
                    })}
                  </div>
                </div>
              ) : (
                <div className="flex items-center gap-4">
                  <div>
                    <p className="text-sm font-medium">Ready to export</p>
                    <p className="text-xs text-muted-foreground flex items-center gap-1 mt-0.5">
                      <Clock className="h-3 w-3" />
                      Estimated time: ~{estimatedTime}s · {selectedFrameworks.length} framework{selectedFrameworks.length !== 1 ? "s" : ""}
                    </p>
                  </div>
                  <div className="ml-auto flex gap-2">
                    <Button onClick={handleGenerate} className="gap-2">
                      <Zap className="h-4 w-4" />
                      Generate Export
                    </Button>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </div>

        {/* Preview panel */}
        <div className="space-y-4">
          <Card className="sticky top-6">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm flex items-center gap-2">
                <Eye className="h-4 w-4 text-primary" />
                Control Coverage Preview
                <Badge variant="secondary" className="text-xs">{primaryFramework}</Badge>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-80">
                <ControlTreePanel framework={primaryFramework} bundles={frameworkBundles} />
              </ScrollArea>
              <Separator className="my-4" />
              <div className="space-y-2 text-xs">
                <div className="flex justify-between text-muted-foreground">
                  <span>Total bundles available</span>
                  <span className="font-medium text-foreground">{frameworkBundles.length}</span>
                </div>
                <div className="flex justify-between text-muted-foreground">
                  <span>Quantum-signed</span>
                  <span className="font-medium text-foreground">
                    {frameworkBundles.filter((b: any) => b.quantum_signed || b.signed).length}
                  </span>
                </div>
                <div className="flex justify-between text-muted-foreground">
                  <span>Frameworks selected</span>
                  <span className="font-medium text-foreground">{selectedFrameworks.length}</span>
                </div>
                <div className="flex justify-between text-muted-foreground">
                  <span>Selected apps</span>
                  <span className="font-medium text-foreground">{selectedApps.length || "All"}</span>
                </div>
                <div className="flex justify-between text-muted-foreground">
                  <span>Include options</span>
                  <span className="font-medium text-foreground">{includeOptions.length}</span>
                </div>
              </div>
              <Separator className="my-4" />
              <div className="space-y-2">
                <Button className="w-full gap-2" size="sm" disabled={progress < 100}
                  onClick={() => {
                    if (lastExport) {
                      downloadBlob(lastExport, `evidence-${primaryFramework}-${period}.json`);
                    } else {
                      // Download bundles data as fallback
                      downloadBlob(frameworkBundles, `evidence-${primaryFramework}-bundles.json`);
                    }
                  }}
                >
                  <Download className="h-3.5 w-3.5" />
                  Download Package
                </Button>
                <SendToAuditorDialog disabled={progress < 100} framework={primaryFramework} />
              </div>
            </CardContent>
          </Card>
        </div>
      </div>

      {/* Export History */}
      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
      >
        <Card>
          <CardHeader>
            <CardTitle className="text-sm flex items-center gap-2">
              <History className="h-4 w-4 text-muted-foreground" />
              Evidence Bundles
              <Badge variant="secondary" className="text-xs ml-auto">{bundles.length} total</Badge>
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent border-b border-border/40">
                  <TableHead className="text-xs">Bundle ID</TableHead>
                  <TableHead className="text-xs">Framework</TableHead>
                  <TableHead className="text-xs">Control</TableHead>
                  <TableHead className="text-xs">Created</TableHead>
                  <TableHead className="text-xs">Signed</TableHead>
                  <TableHead className="text-xs text-right">Download</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {bundles.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={6} className="text-center py-8 text-muted-foreground">
                      No evidence bundles yet. Generate evidence from the Compliance dashboard.
                    </TableCell>
                  </TableRow>
                ) : (
                  bundles.slice(0, 20).map((b: any, i: number) => (
                    <TableRow key={b.id ?? b.bundle_id ?? i} className="hover:bg-muted/30">
                      <TableCell className="text-xs font-mono">{b.bundle_id ?? b.id ?? `BND-${i + 1}`}</TableCell>
                      <TableCell>
                        <Badge variant="outline" className="text-xs">{b.framework ?? "—"}</Badge>
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">{b.control ?? "—"}</TableCell>
                      <TableCell className="text-xs text-muted-foreground">{b.created_at ?? b.timestamp ?? "—"}</TableCell>
                      <TableCell>
                        {(b.quantum_signed || b.signed) ? (
                          <Badge className="text-xs bg-violet-900/40 text-violet-300 border-violet-700">Signed</Badge>
                        ) : (
                          <Badge variant="outline" className="text-xs text-muted-foreground">Unsigned</Badge>
                        )}
                      </TableCell>
                      <TableCell className="text-right">
                        <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => downloadBlob(b, `evidence-${b.bundle_id ?? b.id ?? i}.json`)}>
                          <Download className="h-3.5 w-3.5" />
                        </Button>
                      </TableCell>
                    </TableRow>
                  ))
                )}
              </TableBody>
            </Table>
            </div>
          </CardContent>
        </Card>
      </motion.div>
    </motion.div>
  );
}
