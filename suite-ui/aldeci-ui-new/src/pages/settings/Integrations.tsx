import { toArray } from "@/lib/api-utils";
import { useState, useCallback, useMemo } from "react";
import { useNavigate } from "react-router-dom";
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
import { Switch } from "@/components/ui/switch";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { motion } from "framer-motion";
import {
  Link2, CheckCircle, XCircle, AlertTriangle, RefreshCw, Settings,
  Zap, Clock, Shield, Cloud, Bell, GitBranch, Plus,
  ArrowLeftRight, Webhook, Activity, TrendingUp
} from "lucide-react";
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer
} from "recharts";
import { useIntegrations, useTestIntegration, useSyncIntegration, useConfigureIntegration } from "@/hooks/use-api";
import { webhookEventsApi } from "@/lib/api";
import { useQuery } from "@tanstack/react-query";
import { toast } from "sonner";

function WebhookConfigCard({ integration }: { integration: any }) {
  const [webhookEnabled, setWebhookEnabled] = useState(false);
  const [webhookUrl, setWebhookUrl] = useState("");
  const [open, setOpen] = useState(false);
  const configureIntegration = useConfigureIntegration();

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="ghost" size="icon" className="h-7 w-7" title="Webhook Config">
          <Webhook className="h-3.5 w-3.5" />
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Webhook className="h-4 w-4 text-primary" />
            Webhook Config — {integration.name}
          </DialogTitle>
        </DialogHeader>
        <div className="space-y-4">
          <div className="flex items-start justify-between p-4 rounded-lg bg-muted/30 border border-border/40">
            <div>
              <p className="text-sm font-medium">Enable Webhook Push</p>
              <p className="text-xs text-muted-foreground mt-0.5">Receive real-time events from this integration</p>
            </div>
            <Switch checked={webhookEnabled} onCheckedChange={setWebhookEnabled} />
          </div>
          {webhookEnabled && (
            <>
              <div>
                <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-2 block">Webhook Endpoint (read-only)</Label>
                <div className="flex items-center gap-2">
                  <code className="flex-1 text-xs bg-muted p-2 rounded font-mono">
                    https://fixops.io/hooks/{integration.name?.toLowerCase()?.replace(/ /g, "-")}
                  </code>
                </div>
              </div>
              <div>
                <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-2 block">Target URL (outbound)</Label>
                <Input
                  placeholder="https://your-server.com/webhook"
                  value={webhookUrl}
                  onChange={(e) => setWebhookUrl(e.target.value)}
                />
              </div>
              <div className="flex items-center justify-between p-3 rounded-lg bg-muted/30 border border-border/40">
                <div className="flex items-center gap-2">
                  <ArrowLeftRight className="h-4 w-4 text-blue-400" />
                  <div>
                    <p className="text-sm font-medium">Bi-directional Sync</p>
                    <p className="text-xs text-muted-foreground">Push and pull events in both directions</p>
                  </div>
                </div>
                <Switch defaultChecked />
              </div>
            </>
          )}
          <Separator />
          <div className="flex gap-2 justify-end">
            <Button variant="outline" onClick={() => setOpen(false)}>Cancel</Button>
            <Button onClick={() => { configureIntegration.mutate({ id: integration.id ?? integration.name, data: { webhook_enabled: webhookEnabled, webhook_url: webhookUrl } }); setOpen(false); }}>Save</Button>
          </div>
        </div>
      </DialogContent>
    </Dialog>
  );
}

// Empty default — sync timeline is loaded exclusively from the webhook events API
const SYNC_TIMELINE_EMPTY: { time: string; name: string; event: string; status: string; records: number }[] = [];

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
  const testMutation = useTestIntegration();
  const configureMutation = useConfigureIntegration();

  const handleTest = async () => {
    setIsTesting(true);
    setTestResult(null);
    testMutation.mutate(integration.id ?? integration.name, {
      onSuccess: () => { setTestResult("success"); setIsTesting(false); },
      onError: () => { setTestResult("fail"); setIsTesting(false); },
    });
  };

  const handleSave = () => {
    configureMutation.mutate({ id: integration.id ?? integration.name, data: { api_key: apiKey, url, project_id: projectId } }, {
      onSuccess: () => { onSave(); setOpen(false); },
    });
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

  const webhookEventsQuery = useQuery({
    queryKey: ["webhooks", "events"],
    queryFn: async () => { const { data } = await webhookEventsApi.list({ limit: 10 }); return data; },
  });

  const SYNC_TIMELINE = useMemo(() => {
    const events = webhookEventsQuery.data?.events;
    if (!Array.isArray(events) || events.length === 0) return SYNC_TIMELINE_EMPTY;
    return events.slice(0, 8).map((e: Record<string, unknown>) => {
      const ts = e.received_at ?? e.created_at ?? e.timestamp;
      const d = ts ? new Date(ts as string) : new Date();
      return {
        time: `${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`,
        name: (e.integration_type as string) ?? (e.source as string) ?? "Unknown",
        event: (e.event_type as string) ?? (e.action as string) ?? "Webhook received",
        status: (e.processed as boolean) !== false ? "success" : "error",
        records: Number(e.record_count ?? e.findings_count ?? 1),
      };
    });
  }, [webhookEventsQuery.data]);

  const integrations: any[] = toArray(integrationsQuery.data);

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

  const navigate = useNavigate();
  const syncMutation = useSyncIntegration();
  const configureMutation = useConfigureIntegration();
  const handleSync = (integration: any) => {
    syncMutation.mutate(integration.id ?? integration.name);
  };
  const handleToggleConnection = (integration: any) => {
    const newStatus = integration.status === "connected" ? "disconnected" : "connected";
    configureMutation.mutate(
      { id: integration.id ?? integration.name, data: { status: newStatus } },
      {
        onSuccess: () => toast.success(`${integration.name} ${newStatus === "connected" ? "connected" : "disconnected"}`),
      }
    );
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
        <Button size="sm" className="gap-2" onClick={() => navigate("/settings/marketplace")}>
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
                    {integration.last_sync && (
                      <div className="flex items-center justify-between text-xs">
                        <span className="text-muted-foreground flex items-center gap-1">
                          <ArrowLeftRight className="h-3 w-3 text-blue-400" />
                          Bi-directional
                        </span>
                        <span className="text-muted-foreground">{integration.last_sync}</span>
                      </div>
                    )}
                    <div className="flex gap-1">
                      <ConfigureDialog integration={integration} onSave={refetch} />
                      <WebhookConfigCard integration={integration} />
                      <Button
                        size="sm"
                        variant="outline"
                        className="flex-1 gap-1.5 text-xs"
                        onClick={() => handleSync(integration)}
                        disabled={status !== "connected"}
                      >
                        <Zap className="h-3 w-3" />
                        Sync
                      </Button>
                      <Button
                        size="sm"
                        variant={status === "connected" ? "destructive" : "default"}
                        className="flex-1 text-xs"
                        onClick={() => handleToggleConnection(integration)}
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
          <div className="overflow-x-auto">
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
                      {intg.sync_duration ?? "—"}
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
          </div>
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

      {/* Sync Status Timeline */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Activity className="h-4 w-4 text-primary" />
            Sync Status Timeline
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="relative">
            <div className="absolute left-[5.5rem] top-0 bottom-0 w-px bg-border/40" />
            <div className="space-y-3">
              {SYNC_TIMELINE.length === 0 && (
                <p className="text-xs text-muted-foreground text-center py-6">No sync events yet. Webhook events from connected integrations will appear here.</p>
              )}
              {SYNC_TIMELINE.map((entry, i) => (
                <div key={i} className="flex items-start gap-4">
                  <span className="text-xs text-muted-foreground w-20 shrink-0 text-right pt-0.5">{entry.time}</span>
                  <div className="relative z-10">
                    <div className={`h-3 w-3 rounded-full border-2 mt-1 ${
                      entry.status === "success"
                        ? "bg-green-500 border-green-600"
                        : "bg-red-500 border-red-600"
                    }`} />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="text-sm font-medium">{entry.name}</span>
                      <span className="text-xs text-muted-foreground">{entry.event}</span>
                      {entry.records > 0 && (
                        <Badge variant="outline" className="text-xs ml-auto">{entry.records} records</Badge>
                      )}
                      {entry.status === "error" && (
                        <Badge variant="destructive" className="text-xs ml-auto">Failed</Badge>
                      )}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Integration health over time */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <TrendingUp className="h-4 w-4 text-primary" />
            Integration Health — Last 7 Days
          </CardTitle>
        </CardHeader>
        <CardContent>
          <ResponsiveContainer width="100%" height={140}>
            <AreaChart
              data={Array.from({ length: 7 }, (_, i) => ({
                day: ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"][i],
                success: [92, 88, 95, 90, 93, 85, 91][i],
                errors: [2, 3, 1, 2, 1, 4, 2][i],
              }))}
              margin={{ top: 4, right: 8, left: -20, bottom: 0 }}
            >
              <defs>
                <linearGradient id="successGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#22c55e" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#22c55e" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="day" tick={{ fontSize: 11, fill: "#94a3b8" }} axisLine={false} tickLine={false} />
              <YAxis tick={{ fontSize: 11, fill: "#94a3b8" }} axisLine={false} tickLine={false} />
              <Tooltip contentStyle={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: 8, fontSize: 11 }} />
              <Area type="monotone" dataKey="success" stroke="#22c55e" strokeWidth={2} fill="url(#successGrad)" name="Successful Syncs" />
              <Area type="monotone" dataKey="errors" stroke="#ef4444" strokeWidth={2} fill="transparent" name="Sync Errors" />
            </AreaChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>
    </motion.div>
  );
}
