import { toArray } from "@/lib/api-utils";
import { useState, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import { Progress } from "@/components/ui/progress";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { motion } from "framer-motion";
import {
  Package, Lock, Clock, RefreshCw, Plus, Database, Shield,
  Calendar, CheckCircle, AlertTriangle, Layers, Download, Zap,
  ArrowLeftRight, GitMerge, Eye
} from "lucide-react";
import { useEvidenceBundles, useApps, useComplianceFrameworks, useGenerateEvidence } from "@/hooks/use-api";
import { toast } from "sonner";

const FRAMEWORKS = ["SOC2", "PCI-DSS", "HIPAA", "ISO27001", "NIST"];

function RetentionCountdown({ expiryDate }: { expiryDate?: string }) {
  if (!expiryDate) return <span className="text-xs text-muted-foreground">—</span>;
  const days = Math.ceil((new Date(expiryDate).getTime() - Date.now()) / (1000 * 60 * 60 * 24));
  if (days < 0) return (
    <span className="flex items-center gap-1 text-red-500 text-xs">
      <AlertTriangle className="h-3 w-3" /> Expired
    </span>
  );
  if (days <= 14) return (
    <div className="space-y-1">
      <span className="flex items-center gap-1 text-red-400 text-xs font-medium">
        <Clock className="h-3 w-3" /> {days}d left
      </span>
      <Progress value={(days / 365) * 100} className="h-1 w-20" />
    </div>
  );
  if (days <= 60) return (
    <div className="space-y-1">
      <span className="flex items-center gap-1 text-yellow-400 text-xs font-medium">
        <Clock className="h-3 w-3" /> {days}d left
      </span>
      <Progress value={(days / 365) * 100} className="h-1 w-20" />
    </div>
  );
  return (
    <span className="flex items-center gap-1 text-green-500 text-xs">
      <CheckCircle className="h-3 w-3" /> {days}d
    </span>
  );
}

function BundleCompareDialog({ bundles }: { bundles: any[] }) {
  const [open, setOpen] = useState(false);
  const [bundleA, setBundleA] = useState("");
  const [bundleB, setBundleB] = useState("");

  const a = bundles.find((b) => (b.bundle_id ?? b.id) === bundleA);
  const bItem = bundles.find((b) => (b.bundle_id ?? b.id) === bundleB);

  const diffFields = ["framework", "period", "quantum_signed", "worm_enabled", "controls", "app_id"];

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="outline" size="sm" className="gap-2">
          <GitMerge className="h-4 w-4" />
          Compare
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <ArrowLeftRight className="h-4 w-4 text-primary" />
            Bundle Diff Comparison
          </DialogTitle>
        </DialogHeader>
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <Label className="text-xs text-muted-foreground mb-2 block">Bundle A</Label>
              <Select value={bundleA} onValueChange={setBundleA}>
                <SelectTrigger><SelectValue placeholder="Select bundle…" /></SelectTrigger>
                <SelectContent>
                  {bundles.slice(0, 30).map((b: any) => (
                    <SelectItem key={b.bundle_id ?? b.id} value={b.bundle_id ?? b.id}>
                      {b.bundle_id ?? b.id}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label className="text-xs text-muted-foreground mb-2 block">Bundle B</Label>
              <Select value={bundleB} onValueChange={setBundleB}>
                <SelectTrigger><SelectValue placeholder="Select bundle…" /></SelectTrigger>
                <SelectContent>
                  {bundles.slice(0, 30).map((b: any) => (
                    <SelectItem key={b.bundle_id ?? b.id} value={b.bundle_id ?? b.id}>
                      {b.bundle_id ?? b.id}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          </div>

          {a && bItem && (
            <div className="rounded-lg border border-border/40 overflow-hidden">
              <div className="grid grid-cols-3 text-xs font-semibold text-muted-foreground uppercase tracking-wide bg-muted/40 px-4 py-2 border-b border-border/40">
                <span>Field</span>
                <span className="text-center">Bundle A</span>
                <span className="text-center">Bundle B</span>
              </div>
              <ScrollArea className="h-64">
                {diffFields.map((field) => {
                  const valA = String(a[field] ?? "—");
                  const valB = String(bItem[field] ?? "—");
                  const isDiff = valA !== valB;
                  return (
                    <div key={field} className={`grid grid-cols-3 px-4 py-2.5 text-xs border-b border-border/20 ${isDiff ? "bg-yellow-950/20" : ""}`}>
                      <span className="text-muted-foreground font-medium capitalize">{field.replace(/_/g, " ")}</span>
                      <span className={`text-center font-mono ${isDiff ? "text-orange-400" : ""}`}>{valA}</span>
                      <span className={`text-center font-mono ${isDiff ? "text-blue-400" : ""}`}>{valB}</span>
                    </div>
                  );
                })}
              </ScrollArea>
            </div>
          )}
          {(!a || !bItem) && bundleA && bundleB && (
            <p className="text-sm text-muted-foreground text-center py-4">Select two different bundles to compare</p>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}

function GenerateBundleDialog({ apps, frameworks, onGenerate }: {
  apps: any[];
  frameworks: string[];
  onGenerate: (payload: any) => void;
}) {
  const [open, setOpen] = useState(false);
  const [selectedApp, setSelectedApp] = useState("");
  const [selectedFramework, setSelectedFramework] = useState("");
  const [period, setPeriod] = useState("last-30d");
  const [includeControls, setIncludeControls] = useState<string[]>([]);
  const generateMutation = useGenerateEvidence();

  const availableControls = ["Access Control", "Encryption", "Audit Logging", "Change Management", "Incident Response", "Vulnerability Management"];

  const handleGenerate = () => {
    const payload = {
      app_id: selectedApp,
      framework: selectedFramework,
      period,
      controls: includeControls,
    };
    generateMutation.mutate(payload, {
      onSuccess: () => {
        onGenerate(payload);
        setOpen(false);
      },
    });
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button size="sm" className="gap-2">
          <Plus className="h-4 w-4" />
          Generate Bundle
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Package className="h-4 w-4 text-primary" />
            Generate Evidence Bundle
          </DialogTitle>
        </DialogHeader>
        <div className="space-y-5">
          <div>
            <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-2 block">App ID</Label>
            <Select value={selectedApp} onValueChange={setSelectedApp}>
              <SelectTrigger>
                <SelectValue placeholder="Select application…" />
              </SelectTrigger>
              <SelectContent>
                {apps.map((a: any) => (
                  <SelectItem key={a.app_id ?? a.id} value={a.app_id ?? a.id}>
                    {a.name ?? a.app_id ?? a.id}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div>
            <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-2 block">Framework</Label>
            <Select value={selectedFramework} onValueChange={setSelectedFramework}>
              <SelectTrigger>
                <SelectValue placeholder="Select framework…" />
              </SelectTrigger>
              <SelectContent>
                {(frameworks.length > 0 ? frameworks : FRAMEWORKS).map((f) => (
                  <SelectItem key={f} value={f}>{f}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div>
            <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-2 block">Period</Label>
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
          </div>
          <div>
            <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-3 block">Controls to Include</Label>
            <div className="grid grid-cols-2 gap-2">
              {availableControls.map((ctrl) => (
                <div key={ctrl} className="flex items-center gap-2">
                  <Checkbox
                    id={ctrl}
                    checked={includeControls.includes(ctrl)}
                    onCheckedChange={(checked) => {
                      if (checked) setIncludeControls((prev) => [...prev, ctrl]);
                      else setIncludeControls((prev) => prev.filter((c) => c !== ctrl));
                    }}
                  />
                  <Label htmlFor={ctrl} className="text-sm cursor-pointer">{ctrl}</Label>
                </div>
              ))}
            </div>
          </div>
          <Separator />
          <div className="flex gap-2 justify-end">
            <Button variant="outline" onClick={() => setOpen(false)}>Cancel</Button>
            <Button
              onClick={handleGenerate}
              disabled={!selectedApp || !selectedFramework || generateMutation.isPending}
              className="gap-2"
            >
              <Zap className="h-3.5 w-3.5" />
              {generateMutation.isPending ? "Generating…" : "Generate"}
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

export default function EvidenceBundles() {
  const [selectedApp, setSelectedApp] = useState("all");
  const bundlesQuery = useEvidenceBundles(selectedApp !== "all" ? { app_id: selectedApp } : {});
  const appsQuery = useApps();
  const frameworksQuery = useComplianceFrameworks();
  const generateMutation = useGenerateEvidence();

  const refetchAll = useCallback(() => {
    bundlesQuery.refetch();
    appsQuery.refetch();
  }, [bundlesQuery, appsQuery]);

  const isLoading = bundlesQuery.isLoading || appsQuery.isLoading;
  const isError = bundlesQuery.isError;

  if (isLoading) return <PageSkeleton />;
  if (isError) return <ErrorState message="Failed to load evidence bundles" onRetry={refetchAll} />;

  const bundles: any[] = toArray(bundlesQuery.data);
  const apps: any[] = toArray(appsQuery.data);
  const frameworks: string[] = toArray(frameworksQuery.data).map((f: any) => {
    if (typeof f === "string") return f;
    return f.name ?? f.framework ?? String(f.id ?? "");
  }).filter(Boolean);

  const totalBundles = bundles.length;
  const quantumSigned = bundles.filter((b: any) => b.quantum_signed || b.signed).length;
  const expiringSoon = bundles.filter((b: any) => {
    const d = b.expiry_date ?? b.expires_at;
    if (!d) return false;
    const days = Math.ceil((new Date(d).getTime() - Date.now()) / (1000 * 60 * 60 * 24));
    return days >= 0 && days <= 30;
  }).length;

  const handleBulkGenerate = () => {
    apps.forEach((app: any) => {
      generateMutation.mutate({ app_id: app.app_id ?? app.id, framework: "SOC2", period: "last-30d" });
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
        title="Evidence Bundles"
        description="Generate and manage evidence bundles per application with quantum-secure signatures"
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={refetchAll} className="gap-2">
          <RefreshCw className="h-4 w-4" />
          Refresh
        </Button>
        <Button variant="outline" size="sm" onClick={handleBulkGenerate} disabled={generateMutation.isPending} className="gap-2">
          <Zap className="h-4 w-4" />
          Bulk Generate All
        </Button>
        <GenerateBundleDialog apps={apps} frameworks={frameworks} onGenerate={() => bundlesQuery.refetch()} />
          </div>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Total Bundles" value={totalBundles} icon={Package} />
        <KpiCard title="Quantum-Signed" value={quantumSigned} icon={Lock} />
        <KpiCard title="Apps Covered" value={apps.length} icon={Database} />
        <KpiCard title="Expiring Soon" value={expiringSoon} icon={Clock} />
      </div>

      {/* Quantum Signature Verification Panel */}
      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.05 }}
      >
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm flex items-center gap-2">
              <Lock className="h-4 w-4 text-violet-400" />
              Quantum-Secure Signature Status
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
              {[
                { label: "Algorithm", value: "CRYSTALS-Dilithium", color: "text-violet-400" },
                { label: "Key Size", value: "2048-bit", color: "text-blue-400" },
                { label: "Signed Bundles", value: `${quantumSigned}/${totalBundles}`, color: totalBundles > 0 && quantumSigned === totalBundles ? "text-green-400" : "text-yellow-400" },
                { label: "Signature Valid", value: quantumSigned === totalBundles ? "All Valid" : `${totalBundles - quantumSigned} Unsigned`, color: quantumSigned === totalBundles ? "text-green-400" : "text-orange-400" },
              ].map(({ label, value, color }) => (
                <div key={label} className="p-3 rounded-lg bg-muted/30 border border-border/40">
                  <p className="text-xs text-muted-foreground mb-1">{label}</p>
                  <p className={`text-sm font-mono font-semibold ${color}`}>{value}</p>
                </div>
              ))}
            </div>
            {totalBundles > 0 && (
              <div className="mt-4">
                <div className="flex justify-between text-xs text-muted-foreground mb-1">
                  <span>Signature Coverage</span>
                  <span className="font-medium">{totalBundles > 0 ? Math.round((quantumSigned / totalBundles) * 100) : 0}%</span>
                </div>
                <Progress value={totalBundles > 0 ? (quantumSigned / totalBundles) * 100 : 0} className="h-2" />
              </div>
            )}
          </CardContent>
        </Card>
      </motion.div>

      {/* App filter + bundle list */}
      <div className="flex flex-col lg:flex-row gap-6">
        {/* App selector sidebar */}
        <Card className="lg:w-64 shrink-0">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm flex items-center gap-2">
              <Database className="h-4 w-4 text-primary" />
              Applications
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <div
              className={`px-4 py-2.5 cursor-pointer text-sm transition-colors ${selectedApp === "all" ? "bg-primary/10 text-primary font-medium" : "hover:bg-muted/40 text-muted-foreground"}`}
              onClick={() => setSelectedApp("all")}
            >
              All Applications
              <span className="ml-auto float-right text-xs text-muted-foreground">{totalBundles}</span>
            </div>
            {apps.map((app: any) => {
              const appId = app.app_id ?? app.id;
              const appBundles = bundles.filter((b: any) => (b.app_id ?? b.app) === appId).length;
              return (
                <div
                  key={appId}
                  className={`px-4 py-2.5 cursor-pointer text-sm transition-colors ${selectedApp === appId ? "bg-primary/10 text-primary font-medium" : "hover:bg-muted/40 text-muted-foreground"}`}
                  onClick={() => setSelectedApp(appId)}
                >
                  {app.name ?? appId}
                  <span className="ml-auto float-right text-xs text-muted-foreground">{appBundles}</span>
                </div>
              );
            })}
          </CardContent>
        </Card>

        {/* Bundle table */}
        <Card className="flex-1">
          <CardHeader>
            <CardTitle className="text-base flex items-center justify-between">
              <span className="flex items-center gap-2">
                <Package className="h-4 w-4 text-primary" />
                Bundles
                {selectedApp !== "all" && <Badge variant="secondary" className="text-xs">{selectedApp}</Badge>}
              </span>
              <div className="flex items-center gap-2">
                <BundleCompareDialog bundles={bundles} />
                <span className="text-sm font-normal text-muted-foreground">{bundles.length} total</span>
              </div>
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent border-b border-border/40">
                  <TableHead className="text-xs">Bundle ID</TableHead>
                  <TableHead className="text-xs">Framework</TableHead>
                  <TableHead className="text-xs">Period</TableHead>
                  <TableHead className="text-xs">Signed</TableHead>
                  <TableHead className="text-xs">WORM</TableHead>
                  <TableHead className="text-xs">Retention</TableHead>
                  <TableHead className="text-xs text-right">Actions</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {bundles.length === 0 ? (
                  <TableRow>
                    <TableCell colSpan={7} className="text-center py-12 text-muted-foreground">
                      No bundles found. Generate your first evidence bundle.
                    </TableCell>
                  </TableRow>
                ) : (
                  bundles.slice(0, 30).map((b: any, i: number) => (
                    <TableRow key={b.bundle_id ?? b.id ?? i} className="hover:bg-muted/30">
                      <TableCell className="font-mono text-xs text-primary">
                        {b.bundle_id ?? b.id ?? `BND-${String(i + 1).padStart(4, "0")}`}
                      </TableCell>
                      <TableCell>
                        <Badge variant="outline" className="text-xs">{b.framework ?? "—"}</Badge>
                      </TableCell>
                      <TableCell className="text-xs text-muted-foreground">
                        {b.period ?? b.time_range ?? "—"}
                      </TableCell>
                      <TableCell>
                        {(b.quantum_signed || b.signed) ? (
                          <span className="flex items-center gap-1 text-violet-400 text-xs">
                            <Lock className="h-3 w-3" /> Quantum
                          </span>
                        ) : (
                          <span className="text-xs text-muted-foreground">None</span>
                        )}
                      </TableCell>
                      <TableCell>
                        <Badge variant={b.worm_enabled ? "default" : "outline"} className="text-xs">
                          {b.worm_enabled ? "Immutable" : "Mutable"}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <RetentionCountdown expiryDate={b.expiry_date ?? b.expires_at} />
                      </TableCell>
                      <TableCell className="text-right">
                        <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => {
                          const content = JSON.stringify(b, null, 2);
                          const blob = new Blob([content], { type: "application/json" });
                          const url = URL.createObjectURL(blob);
                          const a = document.createElement("a");
                          a.href = url;
                          a.download = `evidence-${b.bundle_id ?? b.id ?? i}.json`;
                          document.body.appendChild(a);
                          a.click();
                          document.body.removeChild(a);
                          URL.revokeObjectURL(url);
                          toast.success(`Downloaded bundle ${b.bundle_id ?? b.id}`);
                        }}>
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
      </div>

      {/* Retention Management Panel */}
      <motion.div
        initial={{ opacity: 0, y: 12 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
      >
        <Card>
          <CardHeader>
            <CardTitle className="text-sm flex items-center gap-2">
              <Calendar className="h-4 w-4 text-orange-400" />
              Retention Management
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
              {[
                { label: "Standard Retention", value: "7 years", desc: "Default for all SOC2/PCI bundles", color: "text-blue-400" },
                { label: "HIPAA Retention", value: "6 years", desc: "PHI-related evidence bundles", color: "text-green-400" },
                { label: "Minimum Retention", value: "3 years", desc: "Internal operations data", color: "text-muted-foreground" },
              ].map(({ label, value, desc, color }) => (
                <div key={label} className="p-4 rounded-lg bg-muted/30 border border-border/40">
                  <p className="text-xs text-muted-foreground mb-1">{label}</p>
                  <p className={`text-xl font-bold ${color} mb-1`}>{value}</p>
                  <p className="text-xs text-muted-foreground">{desc}</p>
                </div>
              ))}
            </div>
            {expiringSoon > 0 && (
              <div className="mt-4 p-3 rounded-lg bg-yellow-950/30 border border-yellow-800/40 flex items-center gap-3">
                <AlertTriangle className="h-4 w-4 text-yellow-400 shrink-0" />
                <p className="text-xs text-yellow-300">
                  {expiringSoon} bundle{expiringSoon !== 1 ? "s" : ""} expiring within 30 days. Review and renew retention policies.
                </p>
              </div>
            )}
          </CardContent>
        </Card>
      </motion.div>
    </motion.div>
  );
}
