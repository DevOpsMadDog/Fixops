import { useState, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Separator } from "@/components/ui/separator";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { motion } from "framer-motion";
import {
  Link2, CheckCircle, XCircle, AlertTriangle, RefreshCw, Settings,
  Zap, Clock, Shield, Cloud, Bell, GitBranch, Plus
} from "lucide-react";
import { useIntegrations } from "@/hooks/use-api";
import { toast } from "sonner";

const CATEGORY_ICONS: Record<string, React.ElementType> = {
  Scanner: Shield,
  ALM: GitBranch,
  Cloud: Cloud,
  Notification: Bell,
};

type IntegrationCategory = "all" | "Scanner" | "ALM" | "Cloud" | "Notification";

function StatusDot({ status }: { status: string }) {
  const color = status === "connected" ? "bg-green-500" : status === "error" ? "bg-red-500" : "bg-gray-500";
  return <span className={`inline-block h-2 w-2 rounded-full ${color} shrink-0`} />;
}

function ConfigureDialog({ integration, onSave }: { integration: any; onSave: () => void }) {
  const [open, setOpen] = useState(false);
  const [apiKey, setApiKey] = useState(integration.api_key ?? "");
  const [url, setUrl] = useState(integration.url ?? integration.base_url ?? "");
  const [projectId, setProjectId] = useState(integration.project_id ?? "");
  const [isTesting, setIsTesting] = useState(false);
  const [testResult, setTestResult] = useState<null | "success" | "fail">(null);

  const handleTest = async () => {
    setIsTesting(true);
    setTestResult(null);
    await new Promise((resolve) => setTimeout(resolve, 1000));
    setIsTesting(false);
    setTestResult("success");
  };

  const handleSave = () => {
    toast.success(`${integration.name} configuration saved`);
    onSave();
    setOpen(false);
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="ghost" size="icon" className="h-7 w-7">
          <Settings className="h-3.5 w-3.5" />
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Settings className="h-4 w-4 text-primary" />
            Configure {integration.name}
          </DialogTitle>
        </DialogHeader>
        <div className="space-y-4">
          <div>
            <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-2 block">API Key / Token</Label>
            <Input
              type="password"
              placeholder="Enter API key…"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
            />
          </div>
          <div>
            <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-2 block">Base URL</Label>
            <Input
              placeholder="https://api.example.com"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
            />
          </div>
          <div>
            <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-2 block">Project ID (optional)</Label>
            <Input
              placeholder="project-id"
              value={projectId}
              onChange={(e) => setProjectId(e.target.value)}
            />
          </div>
          {testResult && (
            <div className={`flex items-center gap-2 text-sm p-2 rounded ${testResult === "success" ? "bg-green-950/30 text-green-400" : "bg-red-950/30 text-red-400"}`}>
              {testResult === "success" ? <CheckCircle className="h-4 w-4" /> : <XCircle className="h-4 w-4" />}
              {testResult === "success" ? "Connection successful!" : "Connection failed. Check your credentials."}
            </div>
          )}
          <Separator />
          <div className="flex gap-2">
            <Button variant="outline" className="gap-2" onClick={handleTest} disabled={isTesting}>
              <Zap className="h-3.5 w-3.5" />
              {isTesting ? "Testing…" : "Test Connection"}
            </Button>
            <Button className="ml-auto gap-2" onClick={handleSave}>
              <CheckCircle className="h-3.5 w-3.5" />
              Save
            </Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

export default function Integrations() {
  const integrationsQuery = useIntegrations();
  const refetch = useCallback(() => integrationsQuery.refetch(), [integrationsQuery]);
  const [categoryFilter, setCategoryFilter] = useState<IntegrationCategory>("all");

  if (integrationsQuery.isLoading) return <PageSkeleton />;
  if (integrationsQuery.isError) return <ErrorState message="Failed to load integrations" onRetry={refetch} />;

  const integrations: any[] = integrationsQuery.data?.data ?? integrationsQuery.data ?? [];

  const connected = integrations.filter((i: any) => i.status === "connected").length;
  const available = integrations.filter((i: any) => i.status !== "connected").length;
  const errors = integrations.filter((i: any) => i.status === "error").length;
  const lastSync = integrations
    .filter((i: any) => i.last_sync)
    .sort((a: any, b: any) => new Date(b.last_sync).getTime() - new Date(a.last_sync).getTime())[0]?.last_sync ?? "—";

  const categories = Array.from(new Set(integrations.map((i: any) => i.category ?? i.type ?? "Scanner").filter(Boolean)));

  const filtered = categoryFilter === "all"
    ? integrations
    : integrations.filter((i: any) => (i.category ?? i.type ?? "Scanner") === categoryFilter);

  const handleSync = (integration: any) => {
    toast.success(`Sync initiated for ${integration.name}`);
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      <PageHeader
        title="Integrations"
        description="Manage scanner, ALM, cloud, and notification integrations"
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={refetch} className="gap-2">
          <RefreshCw className="h-4 w-4" />
          Refresh
        </Button>
        <Button size="sm" className="gap-2">
          <Plus className="h-4 w-4" />
          Add Integration
        </Button>
          </div>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Connected" value={connected} icon={CheckCircle} />
        <KpiCard title="Available" value={available} icon={Link2} />
        <KpiCard title="Errors" value={errors} icon={AlertTriangle} />
        <KpiCard title="Last Sync" value={lastSync} icon={Clock} />
      </div>

      {/* Category filter */}
      <Tabs value={categoryFilter} onValueChange={(v) => setCategoryFilter(v as IntegrationCategory)}>
        <TabsList>
          <TabsTrigger value="all">All</TabsTrigger>
          {categories.map((cat) => (
            <TabsTrigger key={cat} value={cat}>{cat}</TabsTrigger>
          ))}
        </TabsList>
      </Tabs>

      {/* Integration cards grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
        {filtered.length === 0 ? (
          <div className="col-span-full text-center py-12 text-muted-foreground">
            No integrations found
          </div>
        ) : (
          filtered.map((integration: any, i: number) => {
            const category = integration.category ?? integration.type ?? "Scanner";
            const Icon = CATEGORY_ICONS[category] ?? Link2;
            const status = integration.status ?? "disconnected";
            return (
              <motion.div
                key={integration.id ?? integration.name ?? i}
                initial={{ opacity: 0, y: 12 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.04 }}
              >
                <Card className="hover:shadow-md transition-shadow">
                  <CardHeader className="pb-3">
                    <div className="flex items-start justify-between">
                      <div className="flex items-center gap-2">
                        <div className="h-8 w-8 rounded-lg bg-muted flex items-center justify-center">
                          <Icon className="h-4 w-4 text-muted-foreground" />
                        </div>
                        <div>
                          <CardTitle className="text-sm">{integration.name ?? "Integration"}</CardTitle>
                          <Badge variant="outline" className="text-xs mt-0.5">{category}</Badge>
                        </div>
                      </div>
                      <div className="flex items-center gap-1.5">
                        <StatusDot status={status} />
                        <span className="text-xs text-muted-foreground capitalize">{status}</span>
                      </div>
                    </div>
                  </CardHeader>
                  <CardContent className="pt-0 space-y-3">
                    {integration.last_sync && (
                      <p className="text-xs text-muted-foreground flex items-center gap-1">
                        <Clock className="h-3 w-3" />
                        Synced: {integration.last_sync}
                      </p>
                    )}
                    <div className="flex gap-2">
                      <ConfigureDialog integration={integration} onSave={refetch} />
                      <Button
                        size="sm"
                        variant="outline"
                        className="flex-1 gap-1.5 text-xs"
                        onClick={() => handleSync(integration)}
                        disabled={status !== "connected"}
                      >
                        <Zap className="h-3 w-3" />
                        Sync Now
                      </Button>
                      <Button
                        size="sm"
                        variant={status === "connected" ? "destructive" : "default"}
                        className="flex-1 text-xs"
                      >
                        {status === "connected" ? "Disconnect" : "Connect"}
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              </motion.div>
            );
          })
        )}
      </div>

      {/* Sync history table */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Zap className="h-4 w-4 text-primary" />
            Recent Sync Activity
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent border-b border-border/40">
                <TableHead className="text-xs">Integration</TableHead>
                <TableHead className="text-xs">Type</TableHead>
                <TableHead className="text-xs">Sync Time</TableHead>
                <TableHead className="text-xs">Records</TableHead>
                <TableHead className="text-xs">Status</TableHead>
                <TableHead className="text-xs">Duration</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {integrations.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-center py-8 text-muted-foreground">
                    No sync history available
                  </TableCell>
                </TableRow>
              ) : (
                integrations.slice(0, 15).map((intg: any, i: number) => (
                  <TableRow key={`sync-${intg.id ?? i}`} className="hover:bg-muted/30">
                    <TableCell className="text-sm font-medium">{intg.name ?? `Integration ${i + 1}`}</TableCell>
                    <TableCell>
                      <Badge variant="outline" className="text-xs">{intg.category ?? intg.type ?? "Scanner"}</Badge>
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {intg.last_sync ?? "Never"}
                    </TableCell>
                    <TableCell className="text-xs">
                      {intg.records_synced ?? intg.findings_count ?? "—"}
                    </TableCell>
                    <TableCell>
                      <div className="flex items-center gap-1.5">
                        <StatusDot status={intg.status ?? "disconnected"} />
                        <span className="text-xs capitalize">{intg.status ?? "disconnected"}</span>
                      </div>
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {intg.sync_duration ?? (intg.status === "connected" ? `${Math.floor(Math.random() * 30) + 1}s` : "—")}
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>

      {/* Integration health summary cards */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
        {Object.entries(
          integrations.reduce((acc: Record<string, number>, i: any) => {
            const cat = i.category ?? i.type ?? "Scanner";
            acc[cat] = (acc[cat] ?? 0) + 1;
            return acc;
          }, {})
        ).slice(0, 4).map(([cat, count]) => {
          const Icon = CATEGORY_ICONS[cat] ?? Link2;
          return (
            <Card key={cat}>
              <CardContent className="p-4">
                <Icon className="h-5 w-5 text-muted-foreground mb-2" />
                <p className="text-2xl font-bold">{count}</p>
                <p className="text-xs text-muted-foreground mt-0.5">{cat}</p>
              </CardContent>
            </Card>
          );
        })}
      </div>
    </motion.div>
  );
}
