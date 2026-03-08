import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  Plug,
  CheckCircle,
  XCircle,
  AlertCircle,
  RefreshCw,
  Settings2,
  CloudIcon,
  GitBranch,
  Ticket,
  Loader2,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { integrationsApi } from "@/lib/api";
import { toast } from "sonner";

// ─── Mock data ───────────────────────────────────────────────────────────────
const MOCK_SCANNERS = [
  { id: "snyk", name: "Snyk", category: "SAST/SCA", status: "connected", last_sync: "2m ago", findings: 1247, version: "1.1274.0" },
  { id: "trivy", name: "Trivy", category: "Container/IaC", status: "connected", last_sync: "5m ago", findings: 892, version: "0.49.1" },
  { id: "wiz", name: "Wiz", category: "CSPM", status: "connected", last_sync: "15m ago", findings: 2341, version: "API v2" },
  { id: "semgrep", name: "Semgrep", category: "SAST", status: "connected", last_sync: "8m ago", findings: 456, version: "1.58.0" },
  { id: "prisma", name: "Prisma Cloud", category: "CNAPP", status: "connected", last_sync: "12m ago", findings: 3102, version: "32.0.1" },
  { id: "checkov", name: "Checkov", category: "IaC", status: "connected", last_sync: "20m ago", findings: 234, version: "3.2.23" },
  { id: "sonarqube", name: "SonarQube", category: "SAST", status: "connected", last_sync: "30m ago", findings: 789, version: "10.4.0" },
  { id: "grype", name: "Grype", category: "SCA", status: "connected", last_sync: "1h ago", findings: 341, version: "0.74.0" },
  { id: "nuclei", name: "Nuclei", category: "DAST", status: "connected", last_sync: "45m ago", findings: 127, version: "3.2.4" },
  { id: "codeql", name: "CodeQL", category: "SAST", status: "connected", last_sync: "2h ago", findings: 678, version: "2.16.4" },
  { id: "gitleaks", name: "Gitleaks", category: "Secrets", status: "connected", last_sync: "3m ago", findings: 89, version: "8.18.2" },
  { id: "trufflehog", name: "TruffleHog", category: "Secrets", status: "warning", last_sync: "6h ago", findings: 43, version: "3.63.11" },
  { id: "tfsec", name: "tfsec", category: "IaC", status: "connected", last_sync: "1h ago", findings: 156, version: "1.28.11" },
  { id: "kics", name: "KICS", category: "IaC", status: "connected", last_sync: "2h ago", findings: 201, version: "2.1.1" },
  { id: "anchore", name: "Anchore", category: "Container", status: "disconnected", last_sync: "3d ago", findings: 0, version: "5.2.0" },
  { id: "bandit", name: "Bandit", category: "SAST", status: "connected", last_sync: "4h ago", findings: 312, version: "1.7.7" },
  { id: "owasp-zap", name: "OWASP ZAP", category: "DAST", status: "connected", last_sync: "2h ago", findings: 94, version: "2.15.0" },
  { id: "tenable", name: "Tenable.io", category: "Vuln Mgmt", status: "connected", last_sync: "1h ago", findings: 5671, version: "API v3" },
  { id: "qualys", name: "Qualys VMDR", category: "Vuln Mgmt", status: "warning", last_sync: "8h ago", findings: 4230, version: "API v2" },
];

const MOCK_ALM = [
  { id: "jira", name: "Jira", org: "acme.atlassian.net", status: "connected", projects: 14, tickets_created: 2847, last_sync: "1m ago" },
  { id: "servicenow", name: "ServiceNow", org: "acme.service-now.com", status: "connected", projects: 6, tickets_created: 1204, last_sync: "5m ago" },
  { id: "github", name: "GitHub", org: "github.com/acme-corp", status: "connected", projects: 87, tickets_created: 934, last_sync: "3m ago" },
  { id: "gitlab", name: "GitLab", org: "gitlab.acme.com", status: "warning", projects: 23, tickets_created: 456, last_sync: "2h ago" },
  { id: "linear", name: "Linear", org: "acme.linear.app", status: "connected", projects: 8, tickets_created: 312, last_sync: "15m ago" },
];

const MOCK_CLOUD = [
  { id: "aws", name: "Amazon Web Services", accounts: 12, regions: ["us-east-1", "us-west-2", "eu-west-1"], status: "connected", resources: 48291, last_sync: "10m ago" },
  { id: "azure", name: "Microsoft Azure", accounts: 4, regions: ["eastus", "westeurope"], status: "connected", resources: 12847, last_sync: "15m ago" },
  { id: "gcp", name: "Google Cloud Platform", accounts: 3, regions: ["us-central1", "europe-west1"], status: "connected", resources: 8934, last_sync: "20m ago" },
];

function StatusIcon({ status }: { status: string }) {
  if (status === "connected") return <CheckCircle className="h-4 w-4 text-green-400" />;
  if (status === "warning") return <AlertCircle className="h-4 w-4 text-yellow-400" />;
  return <XCircle className="h-4 w-4 text-red-400" />;
}

function statusBadge(status: string) {
  if (status === "connected") return <Badge variant="success">Connected</Badge>;
  if (status === "warning") return <Badge variant="warning">Degraded</Badge>;
  return <Badge variant="destructive">Disconnected</Badge>;
}

export default function Integrations() {
  const [testingId, setTestingId] = useState<string | null>(null);

  const { data } = useQuery({
    queryKey: ["integrations"],
    queryFn: () => integrationsApi.list(),
  });

  const scanners = (data?.data?.scanners) ?? MOCK_SCANNERS;
  const almTools = (data?.data?.alm) ?? MOCK_ALM;
  const cloudProviders = (data?.data?.cloud) ?? MOCK_CLOUD;

  const testMutation = useMutation({
    mutationFn: async (id: string) => {
      setTestingId(id);
      await new Promise((r) => setTimeout(r, 1200));
      return id;
    },
    onSuccess: (id) => {
      setTestingId(null);
      toast.success(`Connection test passed for ${id}`);
    },
    onError: () => {
      setTestingId(null);
      toast.error("Connection test failed");
    },
  });

  const connected = MOCK_SCANNERS.filter((s) => s.status === "connected").length;
  const totalFindings = MOCK_SCANNERS.reduce((a, s) => a + s.findings, 0);

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="space-y-6">
      <PageHeader
        title="Integrations"
        description="Manage scanner connections, ALM tools, and cloud provider access"
        badge="19 scanners"
        actions={
          <Button variant="outline" size="sm" onClick={() => toast.info("Syncing all integrations…")}>
            <RefreshCw className="h-3.5 w-3.5 mr-1.5" />
            Sync All
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <KpiCard title="Scanners Connected" value={connected} icon={Plug} trend="up" />
        <KpiCard title="Total Findings Ingested" value={totalFindings.toLocaleString()} icon={AlertCircle} trend="up" />
        <KpiCard title="ALM Tools" value={almTools.length} icon={Ticket} trend="flat" />
        <KpiCard title="Cloud Accounts" value={19} icon={CloudIcon} trend="up" />
      </div>

      <Tabs defaultValue="scanners">
        <TabsList className="grid grid-cols-3 w-fit">
          <TabsTrigger value="scanners">Scanners ({MOCK_SCANNERS.length})</TabsTrigger>
          <TabsTrigger value="alm">ALM Tools</TabsTrigger>
          <TabsTrigger value="cloud">Cloud Providers</TabsTrigger>
        </TabsList>

        {/* ── Scanners Tab ── */}
        <TabsContent value="scanners" className="mt-4">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {(scanners as any[]).map((scanner) => (
              <Card key={scanner.id} className="border-border/50 hover:border-border transition-colors">
                <CardContent className="p-4">
                  <div className="flex items-start justify-between mb-3">
                    <div>
                      <div className="flex items-center gap-2 mb-0.5">
                        <StatusIcon status={scanner.status} />
                        <p className="text-sm font-semibold">{scanner.name}</p>
                      </div>
                      <p className="text-xs text-muted-foreground">{scanner.category} · v{scanner.version}</p>
                    </div>
                    {statusBadge(scanner.status)}
                  </div>
                  <div className="flex items-center justify-between text-xs text-muted-foreground mb-3">
                    <span>Last sync: {scanner.last_sync}</span>
                    <span className="font-medium text-foreground">{scanner.findings.toLocaleString()} findings</span>
                  </div>
                  <div className="flex gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      className="h-7 text-xs flex-1"
                      disabled={testingId === scanner.id}
                      onClick={() => testMutation.mutate(scanner.id)}
                    >
                      {testingId === scanner.id ? (
                        <><Loader2 className="h-3 w-3 mr-1 animate-spin" />Testing…</>
                      ) : "Test Connection"}
                    </Button>
                    <Button variant="ghost" size="sm" className="h-7 w-7 p-0">
                      <Settings2 className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        {/* ── ALM Tools Tab ── */}
        <TabsContent value="alm" className="mt-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {(almTools as any[]).map((tool) => (
              <Card key={tool.id} className="border-border/50">
                <CardHeader className="pb-2">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <GitBranch className="h-4 w-4 text-primary" />
                      <CardTitle className="text-sm">{tool.name}</CardTitle>
                    </div>
                    {statusBadge(tool.status)}
                  </div>
                </CardHeader>
                <CardContent className="space-y-2">
                  <p className="text-xs text-muted-foreground font-mono">{tool.org}</p>
                  <div className="grid grid-cols-3 gap-2 text-center">
                    <div className="rounded-md bg-muted/30 p-1.5">
                      <p className="text-sm font-semibold">{tool.projects}</p>
                      <p className="text-xs text-muted-foreground">Projects</p>
                    </div>
                    <div className="rounded-md bg-muted/30 p-1.5">
                      <p className="text-sm font-semibold">{tool.tickets_created.toLocaleString()}</p>
                      <p className="text-xs text-muted-foreground">Tickets</p>
                    </div>
                    <div className="rounded-md bg-muted/30 p-1.5">
                      <p className="text-sm font-semibold">{tool.last_sync}</p>
                      <p className="text-xs text-muted-foreground">Sync</p>
                    </div>
                  </div>
                  <div className="flex gap-2 pt-1">
                    <Button variant="outline" size="sm" className="h-7 text-xs flex-1" onClick={() => testMutation.mutate(tool.id)}>
                      {testingId === tool.id ? <><Loader2 className="h-3 w-3 mr-1 animate-spin" />Testing…</> : "Test"}
                    </Button>
                    <Button variant="ghost" size="sm" className="h-7 text-xs flex-1">Configure</Button>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        {/* ── Cloud Providers Tab ── */}
        <TabsContent value="cloud" className="mt-4">
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            {(cloudProviders as any[]).map((cloud) => (
              <Card key={cloud.id} className="border-border/50">
                <CardHeader className="pb-2">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <CloudIcon className="h-4 w-4 text-primary" />
                      <CardTitle className="text-sm">{cloud.name}</CardTitle>
                    </div>
                    {statusBadge(cloud.status)}
                  </div>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="grid grid-cols-2 gap-2">
                    <div className="rounded-md bg-muted/30 p-2 text-center">
                      <p className="text-lg font-bold">{cloud.accounts}</p>
                      <p className="text-xs text-muted-foreground">Accounts</p>
                    </div>
                    <div className="rounded-md bg-muted/30 p-2 text-center">
                      <p className="text-lg font-bold">{cloud.resources.toLocaleString()}</p>
                      <p className="text-xs text-muted-foreground">Resources</p>
                    </div>
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {cloud.regions.map((r: string) => (
                      <Badge key={r} variant="secondary" className="text-xs">{r}</Badge>
                    ))}
                  </div>
                  <p className="text-xs text-muted-foreground">Last sync: {cloud.last_sync}</p>
                  <Button
                    variant="outline"
                    size="sm"
                    className="w-full h-7 text-xs"
                    onClick={() => testMutation.mutate(cloud.id)}
                  >
                    {testingId === cloud.id ? <><Loader2 className="h-3 w-3 mr-1 animate-spin" />Testing…</> : "Test Connection"}
                  </Button>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
