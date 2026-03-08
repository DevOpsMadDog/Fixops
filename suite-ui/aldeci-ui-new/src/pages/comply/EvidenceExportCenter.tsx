import { useState, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Checkbox } from "@/components/ui/checkbox";
import { Progress } from "@/components/ui/progress";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import { PageHeader } from "@/components/shared/page-header";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { motion } from "framer-motion";
import {
  Download, Send, FileText, RefreshCw, CheckCircle, Package,
  Layers, Calendar, Shield, Eye, Zap, Clock
} from "lucide-react";
import { useEvidenceBundles, useComplianceFrameworks, useApps } from "@/hooks/use-api";

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

function ControlTreePanel({ framework, bundles }: { framework: string; bundles: any[] }) {
  const controls = CONTROL_TREE[framework] ?? [];
  const total = controls.length;

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between text-xs text-muted-foreground mb-3">
        <span>Control Coverage Preview</span>
        <Badge variant="outline" className="text-xs">{total} controls</Badge>
      </div>
      {controls.map((ctrl) => {
        const covered = bundles.filter((b: any) =>
          b.framework === framework && (b.control ?? "").toLowerCase().includes(ctrl.split(" ")[0].toLowerCase())
        ).length;
        return (
          <div key={ctrl} className="flex items-center gap-3">
            <div className="w-3 h-3 rounded-full shrink-0 bg-primary/40 flex items-center justify-center">
              {covered > 0 && <div className="w-2 h-2 rounded-full bg-primary" />}
            </div>
            <span className="text-xs flex-1 text-muted-foreground">{ctrl}</span>
            <Badge variant={covered > 0 ? "default" : "outline"} className="text-xs">
              {covered > 0 ? `${covered} evidence` : "Missing"}
            </Badge>
          </div>
        );
      })}
    </div>
  );
}

export default function EvidenceExportCenter() {
  const bundlesQuery = useEvidenceBundles();
  const frameworksQuery = useComplianceFrameworks();
  const appsQuery = useApps();

  const refetchAll = useCallback(() => {
    bundlesQuery.refetch();
    frameworksQuery.refetch();
    appsQuery.refetch();
  }, [bundlesQuery, frameworksQuery, appsQuery]);

  const [selectedFramework, setSelectedFramework] = useState("SOC2");
  const [selectedApps, setSelectedApps] = useState<string[]>([]);
  const [period, setPeriod] = useState("last-30d");
  const [format, setFormat] = useState("pdf_json");
  const [includeOptions, setIncludeOptions] = useState<string[]>(["mpte", "scan_history"]);
  const [isGenerating, setIsGenerating] = useState(false);
  const [progress, setProgress] = useState(0);

  const isLoading = bundlesQuery.isLoading || appsQuery.isLoading;
  const isError = bundlesQuery.isError;

  if (isLoading) return <PageSkeleton />;
  if (isError) return <ErrorState message="Failed to load export data" onRetry={refetchAll} />;

  const bundles: any[] = bundlesQuery.data?.data ?? bundlesQuery.data ?? [];
  const apps: any[] = appsQuery.data?.data ?? appsQuery.data ?? [];
  const frameworks: string[] = (frameworksQuery.data?.data ?? []).map((f: any) => f.name ?? f).filter(Boolean);
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

  const frameworkBundles = bundles.filter((b: any) => b.framework === selectedFramework);
  const estimatedTime = 10 + (selectedApps.length * 5) + (includeOptions.length * 3);

  const handleGenerate = async () => {
    setIsGenerating(true);
    setProgress(0);
    const steps = [20, 45, 65, 80, 95, 100];
    for (const step of steps) {
      await new Promise((resolve) => setTimeout(resolve, 600));
      setProgress(step);
    }
    setIsGenerating(false);
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
          {/* Framework selector */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm flex items-center gap-2">
                <Shield className="h-4 w-4 text-primary" />
                Compliance Framework
              </CardTitle>
            </CardHeader>
            <CardContent>
              <Select value={selectedFramework} onValueChange={setSelectedFramework}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {allFrameworks.map((fw) => (
                    <SelectItem key={fw} value={fw}>{fw}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
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
                    <span>Generating evidence package…</span>
                    <span className="ml-auto font-mono text-primary">{progress}%</span>
                  </div>
                  <Progress value={progress} className="h-2" />
                  <p className="text-xs text-muted-foreground">Collecting evidence bundles, signing with quantum key…</p>
                </div>
              ) : (
                <div className="flex items-center gap-4">
                  <div>
                    <p className="text-sm font-medium">Ready to export</p>
                    <p className="text-xs text-muted-foreground flex items-center gap-1 mt-0.5">
                      <Clock className="h-3 w-3" />
                      Estimated time: ~{estimatedTime}s
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
                <Badge variant="secondary" className="text-xs">{selectedFramework}</Badge>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-80">
                <ControlTreePanel framework={selectedFramework} bundles={frameworkBundles} />
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
                <Button className="w-full gap-2" size="sm" disabled={!progress}>
                  <Download className="h-3.5 w-3.5" />
                  Download Package
                </Button>
                <Button variant="outline" className="w-full gap-2" size="sm" disabled={!progress}>
                  <Send className="h-3.5 w-3.5" />
                  Send to Auditor
                </Button>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </motion.div>
  );
}
