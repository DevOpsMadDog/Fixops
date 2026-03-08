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
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { motion } from "framer-motion";
import {
  Package, Lock, Clock, RefreshCw, Plus, Database, Shield,
  Calendar, CheckCircle, AlertTriangle, Layers, Download, Zap
} from "lucide-react";
import { useEvidenceBundles, useApps, useComplianceFrameworks, useGenerateEvidence } from "@/hooks/use-api";

const FRAMEWORKS = ["SOC2", "PCI-DSS", "HIPAA", "ISO27001", "NIST"];

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

  const bundles: any[] = bundlesQuery.data?.data ?? bundlesQuery.data ?? [];
  const apps: any[] = appsQuery.data?.data ?? appsQuery.data ?? [];
  const frameworks: string[] = (frameworksQuery.data?.data ?? []).map((f: any) => f.name ?? f);

  const totalBundles = bundles.length;
  const quantumSigned = bundles.filter((b: any) => b.quantum_signed || b.signed).length;
  const daysUntilExpiry = (b: any) => {
    if (!b.expiry_date && !b.expires_at) return null;
    const diff = new Date(b.expiry_date ?? b.expires_at).getTime() - Date.now();
    return Math.ceil(diff / (1000 * 60 * 60 * 24));
  };

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
        <KpiCard title="Frameworks" value={frameworks.length || FRAMEWORKS.length} icon={Shield} />
      </div>

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
              <span className="text-sm font-normal text-muted-foreground">{bundles.length} total</span>
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
                  <TableHead className="text-xs">Expiry</TableHead>
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
                  bundles.slice(0, 30).map((b: any, i: number) => {
                    const days = daysUntilExpiry(b);
                    return (
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
                          {days === null ? (
                            <span className="text-xs text-muted-foreground">—</span>
                          ) : days < 0 ? (
                            <span className="text-xs text-red-500 flex items-center gap-1">
                              <AlertTriangle className="h-3 w-3" /> Expired
                            </span>
                          ) : days <= 30 ? (
                            <span className="text-xs text-yellow-500 flex items-center gap-1">
                              <Clock className="h-3 w-3" /> {days}d
                            </span>
                          ) : (
                            <span className="text-xs text-green-500 flex items-center gap-1">
                              <CheckCircle className="h-3 w-3" /> {days}d
                            </span>
                          )}
                        </TableCell>
                        <TableCell className="text-right">
                          <Button variant="ghost" size="icon" className="h-7 w-7">
                            <Download className="h-3.5 w-3.5" />
                          </Button>
                        </TableCell>
                      </TableRow>
                    );
                  })
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      </div>
    </motion.div>
  );
}
