import { toArray } from "@/lib/api-utils";
import { useState, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogFooter,
} from "@/components/ui/dialog";
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
import { PageHeader } from "@/components/shared/page-header";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { motion } from "framer-motion";
import {
  Puzzle,
  RefreshCw,
  CheckCircle,
  XCircle,
  AlertTriangle,
  Settings,
  Zap,
  Clock,
  ArrowRightLeft,
  ExternalLink,
  Plus,
  Loader2,
} from "lucide-react";
import { useIntegrations, useSyncIntegration, useTestIntegration, useConfigureIntegration } from "@/hooks/use-api";
import { cn } from "@/lib/utils";
import { toast } from "sonner";

interface Integration {
  id: string;
  name: string;
  type: "jira" | "servicenow" | "github" | "gitlab" | "pagerduty" | "slack";
  status: "connected" | "disconnected" | "error" | "syncing";
  last_sync?: string;
  items_synced?: number;
  sync_errors?: number;
  bidirectional?: boolean;
  url?: string;
  project?: string;
}

const INTEGRATION_ICONS: Record<string, string> = {
  jira: "J",
  servicenow: "SN",
  github: "GH",
  gitlab: "GL",
  pagerduty: "PD",
  slack: "SL",
};

const INTEGRATION_COLORS: Record<string, string> = {
  jira: "#0052CC",
  servicenow: "#62D84E",
  github: "#333",
  gitlab: "#E24329",
  pagerduty: "#06AC38",
  slack: "#4A154B",
};

const STATUS_CONFIG = {
  connected: { label: "Connected", color: "#22c55e", icon: <CheckCircle className="h-3.5 w-3.5" /> },
  disconnected: { label: "Disconnected", color: "#6b7280", icon: <XCircle className="h-3.5 w-3.5" /> },
  error: { label: "Error", color: "#ef4444", icon: <AlertTriangle className="h-3.5 w-3.5" /> },
  syncing: { label: "Syncing", color: "#3b82f6", icon: <Loader2 className="h-3.5 w-3.5 animate-spin" /> },
};

const AVAILABLE_INTEGRATIONS = [
  { type: "jira", name: "Jira", description: "Track findings as Jira issues" },
  { type: "servicenow", name: "ServiceNow", description: "ITSM incident management" },
  { type: "github", name: "GitHub Issues", description: "Track findings in GitHub" },
  { type: "gitlab", name: "GitLab Issues", description: "Track findings in GitLab" },
  { type: "pagerduty", name: "PagerDuty", description: "Incident alerting and on-call" },
  { type: "slack", name: "Slack", description: "Finding notifications to channels" },
];

function IntegrationStatusBadge({ status }: { status: string }) {
  const cfg = STATUS_CONFIG[status as keyof typeof STATUS_CONFIG] ?? STATUS_CONFIG.disconnected;
  return (
    <Badge variant="outline" style={{ borderColor: cfg.color + "44", color: cfg.color }} className="gap-1">
      {cfg.icon}
      {cfg.label}
    </Badge>
  );
}

function IntegrationCard({
  integration,
  onConfigure,
  onSync,
  onToggleBidirectional,
  onTestConnection,
}: {
  integration: Integration;
  onConfigure: (int: Integration) => void;
  onSync: (id: string) => void;
  onToggleBidirectional: (id: string, val: boolean) => void;
  onTestConnection: (id: string) => void;
}) {
  const color = INTEGRATION_COLORS[integration.type] ?? "#6b7280";
  const icon = INTEGRATION_ICONS[integration.type] ?? integration.type.slice(0, 2).toUpperCase();

  return (
    <Card className={cn("transition-all", integration.status === "disconnected" && "opacity-60")}>
      <CardContent className="pt-4">
        <div className="flex items-start gap-4">
          <div
            className="h-12 w-12 rounded-xl flex items-center justify-center text-white font-bold text-sm shrink-0"
            style={{ background: color }}
          >
            {icon}
          </div>
          <div className="flex-1 min-w-0">
            <div className="flex items-center justify-between gap-2">
              <h3 className="font-semibold">{integration.name}</h3>
              <IntegrationStatusBadge status={integration.status} />
            </div>
            {integration.url && (
              <a
                href={integration.url}
                target="_blank"
                rel="noopener noreferrer"
                className="text-xs text-muted-foreground hover:text-primary flex items-center gap-1 mt-0.5"
              >
                {integration.url}
                <ExternalLink className="h-2.5 w-2.5" />
              </a>
            )}
            <div className="grid grid-cols-3 gap-3 mt-3">
              <div>
                <p className="text-[10px] text-muted-foreground">Last Sync</p>
                <p className="text-xs font-medium">{integration.last_sync ?? "Never"}</p>
              </div>
              <div>
                <p className="text-[10px] text-muted-foreground">Items Synced</p>
                <p className="text-xs font-medium">{integration.items_synced ?? 0}</p>
              </div>
              <div>
                <p className="text-[10px] text-muted-foreground">Errors</p>
                <p className={cn("text-xs font-medium", (integration.sync_errors ?? 0) > 0 ? "text-destructive" : "")}>
                  {integration.sync_errors ?? 0}
                </p>
              </div>
            </div>
            <div className="flex items-center gap-4 mt-3">
              <label className="flex items-center gap-2 text-xs cursor-pointer">
                <Switch
                  checked={integration.bidirectional ?? false}
                  onCheckedChange={(v) => onToggleBidirectional(integration.id, v)}
                  disabled={integration.status === "disconnected"}
                />
                <ArrowRightLeft className="h-3 w-3" />
                Bi-directional sync
              </label>
            </div>
          </div>
        </div>
        <div className="flex items-center gap-2 mt-4 pt-3 border-t">
          <Button
            variant="outline"
            size="sm"
            disabled={integration.status === "disconnected"}
            onClick={() => onSync(integration.id)}
          >
            <RefreshCw className="h-3.5 w-3.5 mr-1" />
            Sync Now
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => onTestConnection(integration.id)}
          >
            <Zap className="h-3.5 w-3.5 mr-1" />
            Test
          </Button>
          <Button
            variant="outline"
            size="sm"
            className="ml-auto"
            onClick={() => onConfigure(integration)}
          >
            <Settings className="h-3.5 w-3.5 mr-1" />
            Configure
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

function ConfigureDialog({
  integration,
  open,
  onClose,
  onSave,
}: {
  integration: Integration | null;
  open: boolean;
  onClose: () => void;
  onSave: (config: Record<string, string>) => void;
}) {
  const [url, setUrl] = useState(integration?.url ?? "");
  const [token, setToken] = useState("");
  const [project, setProject] = useState(integration?.project ?? "");
  const [syncInterval, setSyncInterval] = useState("15");

  if (!integration) return null;
  const color = INTEGRATION_COLORS[integration.type] ?? "#6b7280";

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <div
              className="h-6 w-6 rounded flex items-center justify-center text-white text-[10px] font-bold"
              style={{ background: color }}
            >
              {INTEGRATION_ICONS[integration.type] ?? integration.name.slice(0, 2)}
            </div>
            Configure {integration.name}
          </DialogTitle>
        </DialogHeader>
        <div className="space-y-4">
          <div className="space-y-2">
            <Label>Instance URL</Label>
            <Input
              placeholder={`https://your-instance.${integration.type}.com`}
              value={url}
              onChange={(e) => setUrl(e.target.value)}
            />
          </div>
          <div className="space-y-2">
            <Label>API Token</Label>
            <Input
              type="password"
              placeholder="Paste API token..."
              value={token}
              onChange={(e) => setToken(e.target.value)}
            />
          </div>
          {["jira", "github", "gitlab"].includes(integration.type) && (
            <div className="space-y-2">
              <Label>Project / Repository</Label>
              <Input
                placeholder="e.g. SEC or org/repo"
                value={project}
                onChange={(e) => setProject(e.target.value)}
              />
            </div>
          )}
          <div className="space-y-2">
            <Label>Sync Interval</Label>
            <Select value={syncInterval} onValueChange={setSyncInterval}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="5">Every 5 minutes</SelectItem>
                <SelectItem value="15">Every 15 minutes</SelectItem>
                <SelectItem value="30">Every 30 minutes</SelectItem>
                <SelectItem value="60">Every hour</SelectItem>
                <SelectItem value="manual">Manual only</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="bg-muted/50 rounded-lg p-3 text-xs text-muted-foreground">
            Token is stored encrypted. Only use tokens with minimal required scopes.
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button onClick={() => { onSave({ url, project, sync_interval: syncInterval }); onClose(); }}>
            Save Configuration
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default function TicketIntegration() {
  const integrationsQuery = useIntegrations();

  const [localOverrides, setLocalOverrides] = useState<Record<string, Partial<Integration>>>({});
  const [configTarget, setConfigTarget] = useState<Integration | null>(null);
  const [configOpen, setConfigOpen] = useState(false);

  const refetch = useCallback(() => integrationsQuery.refetch(), [integrationsQuery]);

  if (integrationsQuery.isLoading) return <PageSkeleton />;
  if (integrationsQuery.isError)
    return <ErrorState message="Failed to load integrations" onRetry={refetch} />;

  const apiIntegrations: Record<string, unknown>[] =
    toArray(integrationsQuery.data);

  // Map API data to Integration shape, fill in defaults
  const integrations: Integration[] = apiIntegrations.map((int, idx) => ({
    id: (int.id as string) ?? `integration-${idx}`,
    name: (int.name as string) ?? (int.type as string) ?? "Unknown",
    type: (int.type as string) as Integration["type"],
    status: ((int.status as string) ?? "disconnected") as Integration["status"],
    last_sync: (int.last_sync as string) ?? (int.last_synced as string),
    items_synced: (int.items_synced as number) ?? (int.synced_count as number),
    sync_errors: (int.sync_errors as number) ?? (int.error_count as number),
    bidirectional: (int.bidirectional as boolean) ?? false,
    url: (int.url as string) ?? (int.instance_url as string),
    project: (int.project as string) ?? (int.project_key as string),
    ...localOverrides[(int.id as string) ?? ""],
  }));

  const connected = integrations.filter((i) => i.status === "connected").length;
  const totalItems = integrations.reduce((acc, i) => acc + (i.items_synced ?? 0), 0);
  const totalErrors = integrations.reduce((acc, i) => acc + (i.sync_errors ?? 0), 0);

  // Derive recent sync activity from all integrations
  const syncActivity = integrations
    .filter((i) => i.last_sync)
    .map((i) => ({
      service: i.name,
      type: i.type,
      timestamp: i.last_sync!,
      items: i.items_synced ?? 0,
      errors: i.sync_errors ?? 0,
      status: i.status,
    }))
    .sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime());

  const syncMutation = useSyncIntegration();
  const testMutation = useTestIntegration();
  const configureMutation = useConfigureIntegration();

  const handleSync = (id: string) => {
    syncMutation.mutate(id);
  };

  const handleTest = (id: string) => {
    testMutation.mutate(id);
  };

  const handleToggleBidirectional = (id: string, val: boolean) => {
    setLocalOverrides((prev) => ({
      ...prev,
      [id]: { ...prev[id], bidirectional: val },
    }));
    configureMutation.mutate({ id, data: { bidirectional: val } });
  };

  const handleSaveConfig = (id: string, config: Record<string, string>) => {
    setLocalOverrides((prev) => ({
      ...prev,
      [id]: { ...prev[id], url: config.url, project: config.project, status: "connected" },
    }));
    configureMutation.mutate({ id, data: config });
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      <PageHeader
        title="Ticket Integration"
        description="Connect Jira, ServiceNow, GitHub, and other ticketing systems for bi-directional finding sync"
      >
        <Button variant="outline" onClick={refetch}>
          <RefreshCw className="h-4 w-4 mr-2" />
          Refresh All
        </Button>
      </PageHeader>

      {/* Stats bar */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <Card>
          <CardContent className="pt-4 flex items-center gap-3">
            <CheckCircle className="h-5 w-5 text-green-500" />
            <div>
              <p className="text-xs text-muted-foreground">Connected Services</p>
              <p className="text-2xl font-bold">{connected}</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 flex items-center gap-3">
            <ArrowRightLeft className="h-5 w-5 text-primary" />
            <div>
              <p className="text-xs text-muted-foreground">Items Synced</p>
              <p className="text-2xl font-bold">{totalItems}</p>
            </div>
          </CardContent>
        </Card>
        <Card>
          <CardContent className="pt-4 flex items-center gap-3">
            <AlertTriangle className={cn("h-5 w-5", totalErrors > 0 ? "text-destructive" : "text-muted-foreground")} />
            <div>
              <p className="text-xs text-muted-foreground">Sync Errors</p>
              <p className={cn("text-2xl font-bold", totalErrors > 0 ? "text-destructive" : "")}>
                {totalErrors}
              </p>
            </div>
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="services">
        <TabsList>
          <TabsTrigger value="services">Connected Services</TabsTrigger>
          <TabsTrigger value="activity">Sync Activity</TabsTrigger>
          <TabsTrigger value="available">Available Integrations</TabsTrigger>
        </TabsList>

        <TabsContent value="services">
          {integrations.length === 0 ? (
            <Card>
              <CardContent className="flex flex-col items-center justify-center py-16 text-muted-foreground">
                <Puzzle className="h-8 w-8 mb-3 opacity-30" />
                <p className="text-sm">No integrations configured</p>
                <p className="text-xs mt-1">Add an integration to start syncing findings</p>
              </CardContent>
            </Card>
          ) : (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {integrations.map((int) => (
                <IntegrationCard
                  key={int.id}
                  integration={int}
                  onConfigure={(i) => {
                    setConfigTarget(i);
                    setConfigOpen(true);
                  }}
                  onSync={handleSync}
                  onToggleBidirectional={handleToggleBidirectional}
                  onTestConnection={handleTest}
                />
              ))}
            </div>
          )}
        </TabsContent>

        <TabsContent value="activity">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <Clock className="h-4 w-4" />
                Recent Sync Activity
              </CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Service</TableHead>
                    <TableHead>Timestamp</TableHead>
                    <TableHead>Items Synced</TableHead>
                    <TableHead>Errors</TableHead>
                    <TableHead>Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {syncActivity.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={5} className="text-center py-8 text-muted-foreground">
                        No sync activity recorded
                      </TableCell>
                    </TableRow>
                  ) : (
                    syncActivity.map((act, i) => {
                      const color = INTEGRATION_COLORS[act.type] ?? "#6b7280";
                      return (
                        <TableRow key={i}>
                          <TableCell>
                            <div className="flex items-center gap-2">
                              <div
                                className="h-5 w-5 rounded text-white text-[9px] font-bold flex items-center justify-center"
                                style={{ background: color }}
                              >
                                {INTEGRATION_ICONS[act.type] ?? act.service.slice(0, 2)}
                              </div>
                              <span className="text-sm">{act.service}</span>
                            </div>
                          </TableCell>
                          <TableCell className="text-xs text-muted-foreground">
                            {act.timestamp}
                          </TableCell>
                          <TableCell className="text-sm font-medium">
                            {act.items}
                          </TableCell>
                          <TableCell>
                            <span className={cn("text-sm", act.errors > 0 ? "text-destructive font-medium" : "text-muted-foreground")}>
                              {act.errors}
                            </span>
                          </TableCell>
                          <TableCell>
                            <IntegrationStatusBadge status={act.status} />
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
        </TabsContent>

        <TabsContent value="available">
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
            {AVAILABLE_INTEGRATIONS.map((avail) => {
              const isConfigured = integrations.some((i) => i.type === avail.type);
              const color = INTEGRATION_COLORS[avail.type] ?? "#6b7280";
              return (
                <Card key={avail.type} className="hover:border-primary/40 transition-all">
                  <CardContent className="pt-4">
                    <div className="flex items-start gap-3">
                      <div
                        className="h-10 w-10 rounded-xl flex items-center justify-center text-white font-bold text-xs shrink-0"
                        style={{ background: color }}
                      >
                        {INTEGRATION_ICONS[avail.type] ?? avail.name.slice(0, 2)}
                      </div>
                      <div className="flex-1">
                        <div className="flex items-center justify-between">
                          <h3 className="font-semibold text-sm">{avail.name}</h3>
                          {isConfigured && (
                            <Badge variant="secondary" className="text-[10px]">
                              Configured
                            </Badge>
                          )}
                        </div>
                        <p className="text-xs text-muted-foreground mt-0.5">
                          {avail.description}
                        </p>
                      </div>
                    </div>
                    <Button
                      variant="outline"
                      size="sm"
                      className="w-full mt-3"
                      onClick={() => {
                        const mockInt: Integration = {
                          id: `new_${avail.type}`,
                          name: avail.name,
                          type: avail.type as Integration["type"],
                          status: "disconnected",
                        };
                        setConfigTarget(mockInt);
                        setConfigOpen(true);
                      }}
                    >
                      <Plus className="h-3.5 w-3.5 mr-1" />
                      {isConfigured ? "Reconfigure" : "Connect"}
                    </Button>
                  </CardContent>
                </Card>
              );
            })}
          </div>
        </TabsContent>
      </Tabs>

      <ConfigureDialog
        integration={configTarget}
        open={configOpen}
        onClose={() => setConfigOpen(false)}
        onSave={(config) => {
          if (configTarget) handleSaveConfig(configTarget.id, config);
        }}
      />
    </motion.div>
  );
}
