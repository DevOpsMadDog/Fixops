import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectTrigger, SelectContent, SelectItem, SelectValue } from "@/components/ui/select";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { DataTable } from "@/components/shared/data-table";
import {
  Link2, RefreshCw, CheckCircle2, XCircle, Clock, AlertTriangle,
  Settings, ExternalLink, ArrowRightLeft, Activity, GitBranch, Ticket
} from "lucide-react";
import { integrationsApi } from "@/lib/api";
import { toast } from "sonner";

// ── Types ──────────────────────────────────────────────────────────────────
type IntegrationStatus = "connected" | "disconnected" | "error" | "syncing";
type SyncDirection = "bidirectional" | "aldeci_to_tool" | "tool_to_aldeci";

interface Integration {
  id: string;
  name: string;
  type: "jira" | "servicenow" | "github" | "linear" | "azure_devops";
  status: IntegrationStatus;
  lastSync: string;
  linkedTickets: number;
  syncDirection: SyncDirection;
  baseUrl?: string;
  project?: string;
  syncRules: string[];
  errorMessage?: string;
  version?: string;
}

interface LinkedTicket {
  id: string;
  aldeciFindingId: string;
  externalTicketId: string;
  externalUrl: string;
  integration: string;
  title: string;
  status: string;
  priority: string;
  assignee: string;
  createdAt: string;
  lastSynced: string;
  syncStatus: "synced" | "pending" | "conflict" | "error";
}

interface SyncLog {
  id: string;
  integration: string;
  direction: "inbound" | "outbound";
  itemsProcessed: number;
  itemsFailed: number;
  duration: string;
  status: "success" | "partial" | "failed";
  timestamp: string;
  detail: string;
}

// ── Mock Data ──────────────────────────────────────────────────────────────
const MOCK_INTEGRATIONS: Integration[] = [
  {
    id: "int-jira", name: "Jira Cloud", type: "jira", status: "connected", lastSync: "3m ago",
    linkedTickets: 147, syncDirection: "bidirectional",
    baseUrl: "https://corp.atlassian.net", project: "SEC",
    syncRules: ["Critical/High → P1/P2", "Status sync bidirectional", "CVSS score → Jira priority", "Auto-close on Verified"],
    version: "3.x Cloud"
  },
  {
    id: "int-snow", name: "ServiceNow ITSM", type: "servicenow", status: "connected", lastSync: "15m ago",
    linkedTickets: 34, syncDirection: "aldeci_to_tool",
    baseUrl: "https://corp.service-now.com", project: "SEC_INC",
    syncRules: ["Critical findings → P1 Incident", "Remediation tasks → Change Requests", "Compliance gaps → Risk Items"],
    version: "Tokyo"
  },
  {
    id: "int-gh", name: "GitHub Issues", type: "github", status: "connected", lastSync: "22m ago",
    linkedTickets: 89, syncDirection: "bidirectional",
    baseUrl: "https://github.com/corp", project: "security",
    syncRules: ["SCA findings → dependency issues", "Secret findings → security advisories", "AutoFix PRs linked"],
    version: "REST API v3"
  },
  {
    id: "int-linear", name: "Linear", type: "linear", status: "error", lastSync: "2h ago",
    linkedTickets: 12, syncDirection: "aldeci_to_tool",
    baseUrl: "https://linear.app/corp", project: "SECURITY",
    syncRules: ["High severity → Linear issues"],
    errorMessage: "OAuth token expired — re-authentication required",
  },
  {
    id: "int-ado", name: "Azure DevOps", type: "azure_devops", status: "disconnected", lastSync: "Never",
    linkedTickets: 0, syncDirection: "bidirectional",
    syncRules: [],
  },
];

const MOCK_TICKETS: LinkedTicket[] = [
  { id: "lt-1",  aldeciFindingId: "FIND-8821", externalTicketId: "SEC-1284", externalUrl: "https://corp.atlassian.net/browse/SEC-1284", integration: "Jira Cloud", title: "Log4Shell in logging-service",     status: "In Progress", priority: "P1", assignee: "Sophia Chen",   createdAt: "2025-06-08", lastSynced: "3m ago",  syncStatus: "synced" },
  { id: "lt-2",  aldeciFindingId: "FIND-8801", externalTicketId: "SEC-1285", externalUrl: "https://corp.atlassian.net/browse/SEC-1285", integration: "Jira Cloud", title: "SSRF in payment-svc",              status: "Open",        priority: "P1", assignee: "Arjun Patel",   createdAt: "2025-06-09", lastSynced: "3m ago",  syncStatus: "synced" },
  { id: "lt-3",  aldeciFindingId: "FIND-8690", externalTicketId: "SEC-1276", externalUrl: "https://corp.atlassian.net/browse/SEC-1276", integration: "Jira Cloud", title: "Spring4Shell in api-gateway",      status: "In Review",   priority: "P2", assignee: "Arjun Patel",   createdAt: "2025-06-05", lastSynced: "3m ago",  syncStatus: "synced" },
  { id: "lt-4",  aldeciFindingId: "FIND-8821", externalTicketId: "INC0012844",externalUrl: "https://corp.service-now.com/nav_to.do?uri=incident.do?sys_id=INC0012844", integration: "ServiceNow", title: "P1 Security Incident: Log4Shell", status: "In Progress", priority: "Critical", assignee: "Sophia Chen", createdAt: "2025-06-08", lastSynced: "15m ago", syncStatus: "synced" },
  { id: "lt-5",  aldeciFindingId: "FIND-8540", externalTicketId: "#8841",    externalUrl: "https://github.com/corp/security/issues/8841", integration: "GitHub Issues", title: "Bump lodash to 4.17.21",       status: "Open",        priority: "Medium", assignee: "James Kim", createdAt: "2025-06-08", lastSynced: "22m ago", syncStatus: "synced" },
  { id: "lt-6",  aldeciFindingId: "FIND-8850", externalTicketId: "#8845",    externalUrl: "https://github.com/corp/security/issues/8845", integration: "GitHub Issues", title: "Bump minimist to 1.2.6",       status: "Open",        priority: "High", assignee: "Unassigned",   createdAt: "2025-06-10", lastSynced: "22m ago", syncStatus: "pending" },
  { id: "lt-7",  aldeciFindingId: "FIND-8622", externalTicketId: "SEC-1290", externalUrl: "https://corp.atlassian.net/browse/SEC-1290", integration: "Jira Cloud", title: "Prometheus unauth endpoint",       status: "Open",        priority: "P2", assignee: "Lena Müller",   createdAt: "2025-06-10", lastSynced: "3m ago",  syncStatus: "conflict" },
];

const MOCK_SYNC_LOG: SyncLog[] = [
  { id: "sl-1", integration: "Jira Cloud",     direction: "outbound", itemsProcessed: 12, itemsFailed: 0, duration: "2.1s", status: "success", timestamp: "14:55:01", detail: "12 findings synced to Jira" },
  { id: "sl-2", integration: "GitHub Issues",  direction: "outbound", itemsProcessed: 5,  itemsFailed: 0, duration: "1.4s", status: "success", timestamp: "14:38:22", detail: "5 SCA findings → GitHub issues" },
  { id: "sl-3", integration: "Jira Cloud",     direction: "inbound",  itemsProcessed: 8,  itemsFailed: 0, duration: "1.8s", status: "success", timestamp: "14:52:10", detail: "8 Jira status updates pulled" },
  { id: "sl-4", integration: "ServiceNow",     direction: "outbound", itemsProcessed: 3,  itemsFailed: 0, duration: "3.2s", status: "success", timestamp: "14:40:00", detail: "3 incidents updated in ServiceNow" },
  { id: "sl-5", integration: "Linear",         direction: "outbound", itemsProcessed: 0,  itemsFailed: 2, duration: "5.0s", status: "failed",  timestamp: "12:30:15", detail: "OAuth token expired — 2 items failed" },
  { id: "sl-6", integration: "Jira Cloud",     direction: "inbound",  itemsProcessed: 15, itemsFailed: 0, duration: "2.3s", status: "success", timestamp: "12:22:05", detail: "15 ticket comments pulled" },
];

// ── Integration Type Icons ─────────────────────────────────────────────────
const intTypeIcon: Record<string, string> = {
  jira: "🔵",
  servicenow: "🟢",
  github: "⚫",
  linear: "🟣",
  azure_devops: "🔷",
};

const intStatusConfig: Record<IntegrationStatus, { label: string; cls: string }> = {
  connected:    { label: "Connected",    cls: "bg-green-500/10 text-green-400 border-green-500/30" },
  disconnected: { label: "Disconnected", cls: "bg-muted text-muted-foreground border-border" },
  error:        { label: "Error",        cls: "bg-red-500/10 text-red-400 border-red-500/30" },
  syncing:      { label: "Syncing...",   cls: "bg-blue-500/10 text-blue-400 border-blue-500/30" },
};

const syncDirLabels: Record<SyncDirection, string> = {
  bidirectional:    "↔ Bidirectional",
  aldeci_to_tool:   "→ Outbound",
  tool_to_aldeci:   "← Inbound",
};

const ticketSyncConfig = {
  synced:   "bg-green-500/10 text-green-400 border-green-500/30",
  pending:  "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
  conflict: "bg-orange-500/10 text-orange-400 border-orange-500/30",
  error:    "bg-red-500/10 text-red-400 border-red-500/30",
};

// ── Integration Card ───────────────────────────────────────────────────────
function IntegrationCard({ integration, onSync, onConfigure }: {
  integration: Integration;
  onSync: (id: string) => void;
  onConfigure: (id: string) => void;
}) {
  const scfg = intStatusConfig[integration.status];
  return (
    <Card className="border-border/50 hover:border-primary/40 transition-colors">
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between gap-2">
          <div className="flex items-center gap-2">
            <span className="text-2xl">{intTypeIcon[integration.type]}</span>
            <div>
              <CardTitle className="text-sm font-semibold">{integration.name}</CardTitle>
              {integration.version && <p className="text-xs text-muted-foreground">{integration.version}</p>}
            </div>
          </div>
          <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${scfg.cls}`}>{scfg.label}</span>
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        {integration.errorMessage && (
          <div className="rounded-lg bg-red-500/5 border border-red-500/20 p-2">
            <p className="text-xs text-red-400 flex items-center gap-1.5">
              <AlertTriangle className="h-3 w-3 shrink-0" /> {integration.errorMessage}
            </p>
          </div>
        )}
        <div className="grid grid-cols-2 gap-3 text-xs">
          <div>
            <p className="text-muted-foreground">Linked Tickets</p>
            <p className="font-bold text-base mt-0.5 tabular-nums">{integration.linkedTickets}</p>
          </div>
          <div>
            <p className="text-muted-foreground">Sync Direction</p>
            <p className="font-medium mt-0.5 text-primary">{syncDirLabels[integration.syncDirection]}</p>
          </div>
        </div>
        {integration.baseUrl && (
          <p className="text-xs font-mono text-muted-foreground truncate">{integration.baseUrl}</p>
        )}
        {integration.syncRules.length > 0 && (
          <div className="space-y-1">
            {integration.syncRules.slice(0, 2).map((rule, i) => (
              <p key={i} className="text-xs text-muted-foreground flex items-center gap-1.5">
                <span className="h-1 w-1 rounded-full bg-primary shrink-0" /> {rule}
              </p>
            ))}
            {integration.syncRules.length > 2 && (
              <p className="text-xs text-muted-foreground">+{integration.syncRules.length - 2} more rules</p>
            )}
          </div>
        )}
        <div className="flex items-center justify-between pt-1">
          <p className="text-xs text-muted-foreground flex items-center gap-1">
            <Clock className="h-3 w-3" /> {integration.lastSync}
          </p>
          <div className="flex gap-1.5">
            <Button size="sm" variant="outline" className="h-7 text-xs" onClick={() => onConfigure(integration.id)}>
              <Settings className="h-3 w-3 mr-1" /> Configure
            </Button>
            {integration.status !== "disconnected" && (
              <Button size="sm" className="h-7 text-xs" disabled={integration.status === "syncing"} onClick={() => onSync(integration.id)}>
                <RefreshCw className="h-3 w-3 mr-1" /> Sync
              </Button>
            )}
            {integration.status === "disconnected" && (
              <Button size="sm" variant="outline" className="h-7 text-xs" onClick={() => toast.info("Opening OAuth flow")}>
                Connect
              </Button>
            )}
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

// ── Main Component ─────────────────────────────────────────────────────────
export default function TicketIntegration() {
  const queryClient = useQueryClient();
  const [integrations, setIntegrations] = useState<Integration[]>(MOCK_INTEGRATIONS);

  const { data } = useQuery({
    queryKey: ["integrations"],
    queryFn: () => integrationsApi.list(),
  });

  const syncMutation = useMutation({
    mutationFn: (id: string) => integrationsApi.sync(id),
    onMutate: (id) => setIntegrations(prev => prev.map(i => i.id === id ? { ...i, status: "syncing" as const } : i)),
    onSuccess: (_, id) => {
      toast.success("Sync complete");
      setIntegrations(prev => prev.map(i => i.id === id ? { ...i, status: "connected" as const, lastSync: "Just now" } : i));
      queryClient.invalidateQueries({ queryKey: ["integrations"] });
    },
    onError: (_, id) => {
      toast.error("Sync failed");
      setIntegrations(prev => prev.map(i => i.id === id ? { ...i, status: "connected" as const } : i));
    },
  });

  const apiIntegrations: Integration[] = (data as any)?.data ?? integrations;
  const displayIntegrations = apiIntegrations.length > 0 ? apiIntegrations : integrations;

  const connectedCount = displayIntegrations.filter(i => i.status === "connected").length;
  const totalLinked    = displayIntegrations.reduce((s, i) => s + i.linkedTickets, 0);
  const errorCount     = displayIntegrations.filter(i => i.status === "error").length;

  const ticketColumns = [
    { key: "externalTicketId", header: "Ticket", render: (r: LinkedTicket) => (
      <div className="flex items-center gap-1.5">
        <span className="font-mono text-xs text-primary">{r.externalTicketId}</span>
        <a href={r.externalUrl} target="_blank" rel="noopener noreferrer" className="text-muted-foreground hover:text-primary">
          <ExternalLink className="h-3 w-3" />
        </a>
      </div>
    )},
    { key: "aldeciFindingId", header: "Finding", render: (r: LinkedTicket) => <span className="font-mono text-xs">{r.aldeciFindingId}</span> },
    { key: "title",        header: "Title", render: (r: LinkedTicket) => <span className="text-sm line-clamp-1">{r.title}</span> },
    { key: "integration",  header: "Integration" },
    { key: "status",       header: "Status",   render: (r: LinkedTicket) => <Badge variant="outline" className="text-xs">{r.status}</Badge> },
    { key: "priority",     header: "Priority", render: (r: LinkedTicket) => <span className="text-xs font-medium">{r.priority}</span> },
    { key: "assignee",     header: "Assignee", render: (r: LinkedTicket) => <span className="text-xs text-muted-foreground">{r.assignee}</span> },
    { key: "syncStatus",   header: "Sync",     render: (r: LinkedTicket) => <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${ticketSyncConfig[r.syncStatus]}`}>{r.syncStatus}</span> },
    { key: "lastSynced",   header: "Last Sync" },
  ];

  const logColumns = [
    { key: "integration",    header: "Integration" },
    { key: "direction",      header: "Direction", render: (r: SyncLog) => <span className={`text-xs font-medium ${r.direction === "inbound" ? "text-blue-400" : "text-green-400"}`}>{r.direction === "inbound" ? "← Inbound" : "→ Outbound"}</span> },
    { key: "itemsProcessed", header: "Processed", render: (r: SyncLog) => <span className="font-mono text-xs">{r.itemsProcessed}</span> },
    { key: "itemsFailed",    header: "Failed", render: (r: SyncLog) => <span className={`font-mono text-xs ${r.itemsFailed > 0 ? "text-red-400 font-bold" : "text-muted-foreground"}`}>{r.itemsFailed}</span> },
    { key: "status",         header: "Status", render: (r: SyncLog) => <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${r.status === "success" ? "bg-green-500/10 text-green-400 border-green-500/30" : r.status === "partial" ? "bg-yellow-500/10 text-yellow-400 border-yellow-500/30" : "bg-red-500/10 text-red-400 border-red-500/30"}`}>{r.status}</span> },
    { key: "detail",         header: "Detail", render: (r: SyncLog) => <span className="text-xs text-muted-foreground">{r.detail}</span> },
    { key: "duration",       header: "Duration" },
    { key: "timestamp",      header: "Time" },
  ];

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="space-y-6">
      <PageHeader
        title="Ticket Integration"
        description="Jira, ServiceNow, and GitHub bi-directional sync — keep external tickets in lockstep with findings"
        badge="REMEDIATE"
        actions={
          <Button size="sm" variant="outline" onClick={() => toast.info("Triggering full sync...")}>
            <RefreshCw className="h-3.5 w-3.5 mr-1.5" /> Sync All
          </Button>
        }
      />

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Connected" value={`${connectedCount}/${displayIntegrations.length}`} icon={Link2} trend="flat" />
        <KpiCard title="Linked Tickets" value={totalLinked} icon={Ticket} trend="up" change={23} changeLabel="this week" />
        <KpiCard title="Sync Errors" value={errorCount} icon={XCircle} trend="flat" />
        <KpiCard title="Last Sync" value="3m ago" icon={Clock} trend="flat" />
      </div>

      <Tabs defaultValue="integrations">
        <TabsList>
          <TabsTrigger value="integrations">Integration Status</TabsTrigger>
          <TabsTrigger value="tickets">Linked Tickets</TabsTrigger>
          <TabsTrigger value="log">Sync History</TabsTrigger>
        </TabsList>

        <TabsContent value="integrations" className="mt-4">
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
            {displayIntegrations.map(integration => (
              <IntegrationCard
                key={integration.id}
                integration={integration}
                onSync={id => syncMutation.mutate(id)}
                onConfigure={id => toast.info(`Opening configuration for ${id}`)}
              />
            ))}
          </div>
        </TabsContent>

        <TabsContent value="tickets" className="mt-4">
          <DataTable
            columns={ticketColumns}
            data={MOCK_TICKETS}
            emptyMessage="No linked tickets"
          />
        </TabsContent>

        <TabsContent value="log" className="mt-4">
          <DataTable
            columns={logColumns}
            data={MOCK_SYNC_LOG}
            emptyMessage="No sync events recorded"
          />
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
