import { useState, useCallback, useMemo, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import { toast } from "sonner";
import axios, { AxiosError } from "axios";
import {
  Server, RefreshCw, Download, AlertTriangle, CheckCircle,
  ChevronDown, ChevronRight, Cloud, GitBranch, Settings,
  Shield, Layers, Activity, Upload, FileCode, XCircle, Loader2,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Accordion,
  AccordionContent,
  AccordionItem,
  AccordionTrigger,
} from "@/components/ui/accordion";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Skeleton } from "@/components/ui/skeleton";
import { Progress } from "@/components/ui/progress";
import { Separator } from "@/components/ui/separator";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { ErrorState } from "@/components/shared/ErrorState";
import { useFindings, useAutofix } from "@/hooks/use-api";
import { findingsApi } from "@/lib/api";
import { cn } from "@/lib/utils";

interface IaCFinding {
  id?: string;
  finding_id?: string;
  title?: string;
  severity?: string;
  status?: string;
  scanner?: string;
  resource?: string;
  resource_type?: string;
  rule?: string;
  framework?: string;
  provider?: string;
  fix_available?: boolean;
  description?: string;
  file?: string;
  line?: number;
  drift?: boolean;
  created_at?: string;
}

function SeverityBadge({ severity }: { severity?: string }) {
  const s = (severity || "").toLowerCase();
  const map: Record<string, string> = {
    critical: "bg-red-500/15 text-red-400 border-red-500/30",
    high: "bg-orange-500/15 text-orange-400 border-orange-500/30",
    medium: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
    low: "bg-blue-500/15 text-blue-400 border-blue-500/30",
  };
  return <Badge className={cn("border text-xs font-semibold uppercase", map[s] || "bg-slate-500/15 text-slate-400 border-slate-500/20")}>{severity || "Unknown"}</Badge>;
}

function ProviderBadge({ provider }: { provider?: string }) {
  const map: Record<string, string> = {
    terraform: "bg-purple-500/10 text-purple-400 border-purple-500/20",
    cloudformation: "bg-orange-500/10 text-orange-400 border-orange-500/20",
    kubernetes: "bg-blue-500/10 text-blue-400 border-blue-500/20",
    k8s: "bg-blue-500/10 text-blue-400 border-blue-500/20",
    helm: "bg-green-500/10 text-green-400 border-green-500/20",
    pulumi: "bg-pink-500/10 text-pink-400 border-pink-500/20",
  };
  const p = (provider || "").toLowerCase();
  return <Badge className={cn("border text-xs", map[p] || "bg-slate-500/10 text-slate-400 border-slate-500/20")}>{provider || "—"}</Badge>;
}

// Extract user-readable error from axios/fetch errors. Mirrors
// OnboardingWizard.tsx pattern (single source of truth lives there;
// duplicated locally because file-scope constraint forbids touching
// shared lib files in this commit).
function extractError(err: unknown): string {
  if (axios.isAxiosError(err)) {
    const ax = err as AxiosError<{ detail?: string | { msg?: string }[] }>;
    const detail = ax.response?.data?.detail;
    if (typeof detail === "string") return detail;
    if (Array.isArray(detail) && detail[0]?.msg) return detail[0].msg!;
    if (ax.message) return ax.message;
  }
  if (err instanceof Error) return err.message;
  return "Unknown error";
}

interface ScanResponse {
  scan_id?: string;
  total_findings?: number;
  files_scanned?: number;
  findings?: unknown[];
  results?: unknown[];
}

const CIS_CONTROLS = [
  { id: "CIS-1", name: "Inventory and Control of Enterprise Assets", pass: 0, total: 0 },
  { id: "CIS-4", name: "Secure Configuration of Enterprise Assets", pass: 0, total: 0 },
  { id: "CIS-12", name: "Network Infrastructure Management", pass: 0, total: 0 },
  { id: "CIS-14", name: "Data Protection", pass: 0, total: 0 },
];

export default function IaCScanning() {
  const navigate = useNavigate();
  const autofixMutation = useAutofix();
  const [providerFilter, setProviderFilter] = useState("all");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [detailFinding, setDetailFinding] = useState<IaCFinding | null>(null);

  const params = useMemo(() => {
    const p: Record<string, unknown> = { limit: 200, scanner: "iac" };
    if (severityFilter !== "all") p.severity = severityFilter;
    if (providerFilter !== "all") p.provider = providerFilter;
    return p;
  }, [severityFilter, providerFilter]);

  const query = useFindings(params);
  const refetch = useCallback(() => query.refetch(), [query]);

  // ── Scan-a-Terraform-file panel state (DoD #6) ─────────────────────────────
  const [scanContent, setScanContent] = useState("");
  const [scanFilename, setScanFilename] = useState("main.tf");
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState<ScanResponse | null>(null);
  const [scanError, setScanError] = useState<string | null>(null);
  const fileInputRef = useRef<HTMLInputElement | null>(null);

  const handleFileChange = useCallback((e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    if (file.size > 1024 * 1024) {
      setScanError("File too large (max 1 MB). Use repo_path or split the file.");
      return;
    }
    setScanError(null);
    setScanFilename(file.name);
    const reader = new FileReader();
    reader.onload = () => {
      const txt = typeof reader.result === "string" ? reader.result : "";
      setScanContent(txt);
    };
    reader.onerror = () => setScanError("Failed to read file");
    reader.readAsText(file);
  }, []);

  const handleScan = useCallback(async () => {
    if (!scanContent.trim()) {
      setScanError("Provide Terraform/IaC content (paste or upload a file).");
      return;
    }
    setScanError(null);
    setScanResult(null);
    setScanning(true);
    try {
      const baseURL = (import.meta.env.VITE_API_URL as string | undefined) || "";
      const res = await axios.post<ScanResponse>(
        `${baseURL}/api/v1/iac/scan`,
        { content: scanContent, filename: scanFilename || "main.tf" },
        { headers: { "Content-Type": "application/json" } },
      );
      setScanResult(res.data);
      const count =
        (res.data?.total_findings as number | undefined) ??
        (Array.isArray(res.data?.findings) ? res.data.findings.length : 0);
      toast.success(`Scan complete — ${count} finding${count === 1 ? "" : "s"}`);
      // Refresh the findings list so the new results appear
      refetch();
    } catch (err) {
      const msg = extractError(err);
      setScanError(msg);
      toast.error(`Scan failed: ${msg}`);
    } finally {
      setScanning(false);
    }
  }, [scanContent, scanFilename, refetch]);

  const handleClearScan = useCallback(() => {
    setScanContent("");
    setScanFilename("main.tf");
    setScanResult(null);
    setScanError(null);
    if (fileInputRef.current) fileInputRef.current.value = "";
  }, []);

  const allFindings: IaCFinding[] = useMemo(() => {
    const d = query.data;
    if (!d) return [];
    if (Array.isArray(d)) return d;
    if (Array.isArray(d?.findings)) return d.findings;
    if (Array.isArray(d?.cases)) return d.cases;
    if (Array.isArray(d?.items)) return d.items;
    if (Array.isArray(d?.data)) return d.data;
    return [];
  }, [query.data]);

  const filtered = useMemo(() => {
    let list = allFindings;
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      list = list.filter(
        (f) =>
          f.title?.toLowerCase().includes(q) ||
          f.resource?.toLowerCase().includes(q) ||
          f.rule?.toLowerCase().includes(q)
      );
    }
    return list;
  }, [allFindings, searchQuery]);

  const stats = useMemo(() => {
    const byProvider = allFindings.reduce<Record<string, number>>((acc, f) => {
      const p = (f.provider || "unknown").toLowerCase();
      acc[p] = (acc[p] || 0) + 1;
      return acc;
    }, {});
    const driftAlerts = allFindings.filter((f) => f.drift).length;
    const fixAvailable = allFindings.filter((f) => f.fix_available).length;
    return {
      total: allFindings.length,
      terraform: byProvider["terraform"] || 0,
      cloudformation: byProvider["cloudformation"] || 0,
      kubernetes: (byProvider["kubernetes"] || 0) + (byProvider["k8s"] || 0),
      drift: driftAlerts,
      fixAvailable,
    };
  }, [allFindings]);

  // Enrich CIS with real counts from findings
  const cisControls = useMemo(() => CIS_CONTROLS.map((c) => {
    const fail = allFindings.filter((f) => f.framework?.includes(c.id)).length;
    const pass = 0; // Real pass count requires CSPM API
    return { ...c, pass, total: fail, fail };
  }), [allFindings]);

  const driftAlerts = useMemo(() => allFindings.filter((f) => f.drift), [allFindings]);

  if (query.isLoading) {
    return (
      <div className="space-y-6 p-6">
        <Skeleton className="h-10 w-64" />
        <div className="grid grid-cols-4 gap-4">
          {Array.from({ length: 4 }).map((_, i) => <Skeleton key={i} className="h-28" />)}
        </div>
        <Skeleton className="h-80" />
      </div>
    );
  }

  if (query.isError) {
    return <ErrorState message="Failed to load IaC scan results." onRetry={refetch} />;
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      <PageHeader title="IaC Scanning" description="Infrastructure as Code security findings and compliance">
        <Button variant="outline" size="sm" onClick={() => query.refetch()} className="gap-2">
          <RefreshCw className="h-4 w-4" /> Refresh
        </Button>
        <Button variant="outline" size="sm" className="gap-2" onClick={() => {
          const blob = new Blob([JSON.stringify(allFindings, null, 2)], { type: "application/json" });
          const url = URL.createObjectURL(blob);
          const a = document.createElement("a"); a.href = url; a.download = "iac-findings.json"; a.click();
          URL.revokeObjectURL(url);
          toast.success(`Exported ${allFindings.length} IaC findings`);
        }}>
          <Download className="h-4 w-4" /> Export
        </Button>
      </PageHeader>

      {/* ── Scan a Terraform file panel (DoD #6) ─────────────────────────── */}
      <Card className="border-primary/20" id="iac-scan-panel">
        <CardHeader className="pb-3">
          <CardTitle className="text-base flex items-center gap-2">
            <FileCode className="h-4 w-4 text-primary" />
            Scan a Terraform file
            <Badge variant="outline" className="ml-2 text-[10px] uppercase tracking-wide">
              CSPM Engine
            </Badge>
          </CardTitle>
          <p className="text-xs text-muted-foreground mt-1">
            Upload a <code>.tf</code>, <code>.json</code>, or <code>.yaml</code> file (or paste the content)
            and run the native IaC scanner. Findings stream into the table below.
          </p>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
            <div className="md:col-span-2 space-y-1.5">
              <Label htmlFor="iac-file-input" className="text-xs">
                Upload file
              </Label>
              <Input
                id="iac-file-input"
                ref={fileInputRef}
                type="file"
                accept=".tf,.json,.yaml,.yml,.hcl"
                aria-label="Upload Terraform or IaC file to scan"
                onChange={handleFileChange}
                disabled={scanning}
                className="cursor-pointer file:mr-3 file:py-1 file:px-3 file:rounded-md file:border-0 file:bg-muted file:text-xs file:cursor-pointer"
              />
            </div>
            <div className="space-y-1.5">
              <Label htmlFor="iac-filename-input" className="text-xs">
                Filename hint
              </Label>
              <Input
                id="iac-filename-input"
                value={scanFilename}
                onChange={(e) => setScanFilename(e.target.value)}
                placeholder="main.tf"
                aria-label="Filename hint for format detection"
                disabled={scanning}
              />
            </div>
          </div>

          <div className="space-y-1.5">
            <Label htmlFor="iac-content-textarea" className="text-xs">
              …or paste IaC content
            </Label>
            <Textarea
              id="iac-content-textarea"
              value={scanContent}
              onChange={(e) => setScanContent(e.target.value)}
              placeholder={'resource "aws_s3_bucket" "example" {\n  bucket = "my-bucket"\n  acl    = "public-read"\n}'}
              aria-label="Paste Terraform or IaC content to scan"
              disabled={scanning}
              rows={6}
              className="font-mono text-xs"
            />
            <p className="text-[10px] text-muted-foreground">
              {scanContent.length.toLocaleString()} chars — max 1 MB
            </p>
          </div>

          <div className="flex flex-wrap items-center gap-2">
            <Button
              onClick={handleScan}
              disabled={scanning || !scanContent.trim()}
              className="gap-2"
              aria-label="Run IaC security scan on provided content"
            >
              {scanning ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Scanning…
                </>
              ) : (
                <>
                  <Upload className="h-4 w-4" />
                  Scan
                </>
              )}
            </Button>
            <Button
              variant="outline"
              size="sm"
              onClick={handleClearScan}
              disabled={scanning || (!scanContent && !scanResult && !scanError)}
              className="gap-1.5"
            >
              <XCircle className="h-3.5 w-3.5" />
              Clear
            </Button>
            <span className="text-[11px] text-muted-foreground ml-auto">
              POST <code>/api/v1/iac/scan</code>
            </span>
          </div>

          {/* Result + error region — aria-live so screen readers announce updates */}
          <div aria-live="polite" aria-atomic="true" className="min-h-0">
            {scanError && (
              <div className="flex items-start gap-2 rounded-md border border-red-500/30 bg-red-500/10 p-3 text-sm">
                <AlertTriangle className="h-4 w-4 text-red-400 shrink-0 mt-0.5" />
                <div className="flex-1">
                  <p className="font-semibold text-red-400">Scan failed</p>
                  <p className="text-xs text-red-300/90 break-words">{scanError}</p>
                </div>
              </div>
            )}
            {scanResult && !scanError && (
              <div className="flex flex-col sm:flex-row sm:items-center gap-3 rounded-md border border-green-500/30 bg-green-500/10 p-3 text-sm">
                <CheckCircle className="h-5 w-5 text-green-400 shrink-0" />
                <div className="flex-1">
                  <p className="font-semibold text-green-400">Scan complete</p>
                  <div className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-green-200/90 mt-0.5">
                    {scanResult.scan_id && (
                      <span>
                        scan_id:{" "}
                        <code className="text-[11px] font-mono text-green-100">{scanResult.scan_id}</code>
                      </span>
                    )}
                    <span>
                      findings:{" "}
                      <strong className="text-green-100">
                        {scanResult.total_findings ??
                          (Array.isArray(scanResult.findings) ? scanResult.findings.length : 0)}
                      </strong>
                    </span>
                    {typeof scanResult.files_scanned === "number" && (
                      <span>
                        files: <strong className="text-green-100">{scanResult.files_scanned}</strong>
                      </span>
                    )}
                  </div>
                </div>
                <Button
                  size="sm"
                  variant="outline"
                  onClick={() => query.refetch()}
                  className="gap-1.5 shrink-0"
                >
                  <RefreshCw className="h-3.5 w-3.5" />
                  Refresh table
                </Button>
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      {/* KPI Row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Total IaC Findings" value={stats.total} icon={Server} />
        <KpiCard title="Terraform" value={stats.terraform} icon={Cloud} />
        <KpiCard title="CloudFormation" value={stats.cloudformation} icon={Layers} />
        <KpiCard title="Kubernetes" value={stats.kubernetes} icon={GitBranch} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Main Table */}
        <div className="lg:col-span-2 space-y-4">
          {/* Filters */}
          <div className="flex flex-wrap gap-3">
            <div className="relative flex-1 min-w-[200px]">
              <Settings className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search resource, rule..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-9"
              />
            </div>
            <Select value={providerFilter} onValueChange={setProviderFilter}>
              <SelectTrigger className="w-40">
                <SelectValue placeholder="Provider" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Providers</SelectItem>
                <SelectItem value="terraform">Terraform</SelectItem>
                <SelectItem value="cloudformation">CloudFormation</SelectItem>
                <SelectItem value="kubernetes">Kubernetes</SelectItem>
                <SelectItem value="helm">Helm</SelectItem>
                <SelectItem value="pulumi">Pulumi</SelectItem>
              </SelectContent>
            </Select>
            <Select value={severityFilter} onValueChange={setSeverityFilter}>
              <SelectTrigger className="w-36">
                <SelectValue placeholder="Severity" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Severities</SelectItem>
                <SelectItem value="critical">Critical</SelectItem>
                <SelectItem value="high">High</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="low">Low</SelectItem>
              </SelectContent>
            </Select>
          </div>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm text-muted-foreground">{filtered.length} misconfigurations</CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead>Severity</TableHead>
                    <TableHead>Resource</TableHead>
                    <TableHead>Rule</TableHead>
                    <TableHead>Provider</TableHead>
                    <TableHead>Framework</TableHead>
                    <TableHead className="w-24 text-center">Fix Available</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filtered.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={6} className="text-center py-12 text-muted-foreground">
                        <div className="flex flex-col items-center gap-2">
                          <CheckCircle className="h-8 w-8 opacity-30 text-green-400" />
                          <p>No IaC findings found</p>
                        </div>
                      </TableCell>
                    </TableRow>
                  ) : (
                    filtered.map((finding, idx) => {
                      const id = finding.id || finding.finding_id || String(idx);
                      return (
                        <TableRow
                          key={id}
                          className="cursor-pointer hover:bg-muted/40"
                          onClick={() => setDetailFinding(finding)}
                        >
                          <TableCell><SeverityBadge severity={finding.severity} /></TableCell>
                          <TableCell className="font-mono text-xs max-w-[180px]">
                            <span className="truncate block">{finding.resource || finding.resource_type || "—"}</span>
                          </TableCell>
                          <TableCell className="text-xs max-w-[200px]">
                            <span className="truncate block">{finding.rule || finding.title || "—"}</span>
                          </TableCell>
                          <TableCell><ProviderBadge provider={finding.provider} /></TableCell>
                          <TableCell>
                            {finding.framework ? (
                              <Badge variant="outline" className="text-xs">{finding.framework}</Badge>
                            ) : <span className="text-muted-foreground text-xs">—</span>}
                          </TableCell>
                          <TableCell className="text-center">
                            {finding.fix_available ? (
                              <CheckCircle className="h-4 w-4 text-green-400 mx-auto" />
                            ) : (
                              <span className="text-muted-foreground text-xs">—</span>
                            )}
                          </TableCell>
                        </TableRow>
                      );
                    })
                  )}
                </TableBody>
              </Table>
              </div>
            </CardContent>
          </Card>

          {/* Drift Alerts */}
          {driftAlerts.length > 0 && (
            <Card className="border-orange-500/20">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Activity className="h-4 w-4 text-orange-400" />
                  Drift Detection Alerts
                  <Badge className="bg-orange-500/15 text-orange-400 border-orange-500/30">{driftAlerts.length}</Badge>
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-2">
                {driftAlerts.slice(0, 5).map((alert, i) => (
                  <div key={i} className="flex items-center gap-3 p-2 bg-orange-500/5 border border-orange-500/10 rounded-md">
                    <AlertTriangle className="h-4 w-4 text-orange-400 shrink-0" />
                    <div>
                      <p className="text-sm font-medium">{alert.resource || alert.title}</p>
                      <p className="text-xs text-muted-foreground">{alert.description || "Configuration drift detected"}</p>
                    </div>
                    <SeverityBadge severity={alert.severity} />
                  </div>
                ))}
              </CardContent>
            </Card>
          )}
        </div>

        {/* CIS Compliance Sidebar */}
        <div className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm flex items-center gap-2">
                <Shield className="h-4 w-4 text-primary" />
                CIS Benchmark Coverage
              </CardTitle>
            </CardHeader>
            <CardContent>
              <Accordion type="multiple" className="w-full">
                {cisControls.map((control) => {
                  const pct = control.total > 0 ? Math.round((control.pass / control.total) * 100) : 0;
                  return (
                    <AccordionItem key={control.id} value={control.id} className="border-b border-border/50">
                      <AccordionTrigger className="text-xs hover:no-underline py-3">
                        <div className="flex-1 text-left">
                          <div className="flex items-center justify-between mb-1">
                            <span className="font-semibold">{control.id}</span>
                            <span className={cn("text-xs font-bold", pct >= 80 ? "text-green-400" : pct >= 50 ? "text-yellow-400" : "text-red-400")}>
                              {pct}%
                            </span>
                          </div>
                          <Progress
                            value={pct}
                            className="h-1.5"
                          />
                        </div>
                      </AccordionTrigger>
                      <AccordionContent>
                        <div className="py-2 space-y-2">
                          <p className="text-xs text-muted-foreground">{control.name}</p>
                          <div className="flex gap-4 text-xs">
                            <span className="text-green-400">{control.pass} passing</span>
                            <span className="text-red-400">{control.total - control.pass} failing</span>
                            <span className="text-muted-foreground">{control.total} total</span>
                          </div>
                        </div>
                      </AccordionContent>
                    </AccordionItem>
                  );
                })}
              </Accordion>
            </CardContent>
          </Card>

          {/* Quick Stats */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm">Scan Summary</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {[
                { label: "Fix Available", value: stats.fixAvailable, color: "text-green-400" },
                { label: "Drift Alerts", value: stats.drift, color: "text-orange-400" },
                { label: "Critical", value: allFindings.filter((f) => f.severity?.toLowerCase() === "critical").length, color: "text-red-400" },
                { label: "High", value: allFindings.filter((f) => f.severity?.toLowerCase() === "high").length, color: "text-orange-400" },
              ].map(({ label, value, color }) => (
                <div key={label} className="flex items-center justify-between text-sm">
                  <span className="text-muted-foreground">{label}</span>
                  <span className={cn("font-mono font-bold", color)}>{value}</span>
                </div>
              ))}
            </CardContent>
          </Card>
        </div>
      </div>

      {/* Detail Dialog */}
      <Dialog open={!!detailFinding} onOpenChange={(open) => { if (!open) setDetailFinding(null); }}>
        <DialogContent className="max-w-xl">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-3">
              <SeverityBadge severity={detailFinding?.severity} />
              <span className="truncate">{detailFinding?.title || "IaC Finding"}</span>
            </DialogTitle>
          </DialogHeader>
          {detailFinding && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                {[
                  { label: "Provider", value: <ProviderBadge provider={detailFinding.provider} /> },
                  { label: "Framework", value: detailFinding.framework || "—" },
                  { label: "Resource", value: <code className="text-xs font-mono">{detailFinding.resource || "—"}</code> },
                  { label: "Rule", value: detailFinding.rule || "—" },
                  { label: "Fix Available", value: detailFinding.fix_available ? <span className="text-green-400">Yes</span> : <span className="text-muted-foreground">No</span> },
                  { label: "Drift", value: detailFinding.drift ? <span className="text-orange-400">Yes</span> : <span className="text-muted-foreground">No</span> },
                ].map(({ label, value }) => (
                  <div key={label}>
                    <p className="text-xs text-muted-foreground mb-1">{label}</p>
                    <div className="text-sm font-medium">{value}</div>
                  </div>
                ))}
              </div>
              <Separator />
              {detailFinding.description && (
                <div>
                  <p className="text-xs font-semibold text-muted-foreground mb-1">Description</p>
                  <p className="text-sm">{detailFinding.description}</p>
                </div>
              )}
              {detailFinding.file && (
                <div>
                  <p className="text-xs font-semibold text-muted-foreground mb-1">File</p>
                  <code className="text-xs font-mono text-blue-400 bg-muted/50 px-2 py-1 rounded block">
                    {detailFinding.file}{detailFinding.line ? `:${detailFinding.line}` : ""}
                  </code>
                </div>
              )}
              <div className="flex gap-2">
                <Button size="sm" onClick={() => {
                  const id = detailFinding.id || detailFinding.finding_id || "";
                  autofixMutation.mutate(id, {
                    onSuccess: () => { toast.success("AutoFix generated — check Remediation Center"); setDetailFinding(null); },
                    onError: () => toast.error("AutoFix generation failed"),
                  });
                }}>Apply Fix</Button>
                <Button size="sm" variant="outline" onClick={() => {
                  const title = detailFinding.title || detailFinding.rule || "IaC misconfiguration";
                  navigate(`/remediate/ticket-integration?title=${encodeURIComponent(title)}&source=iac`);
                }}>Create Ticket</Button>
                <Button size="sm" variant="outline" onClick={async () => {
                  try {
                    const id = detailFinding.id || detailFinding.finding_id || "";
                    await findingsApi.triage(id, "suppress");
                    toast.success("Finding suppressed");
                    setDetailFinding(null);
                    query.refetch();
                  } catch { toast.error("Suppress failed"); }
                }}>Suppress</Button>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </motion.div>
  );
}
