import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  PackagePlus,
  Download,
  Settings2,
  CheckCircle2,
  Clock,
  AlertCircle,
  Loader2,
  Archive,
  Play,
  Calendar,
  Layers,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { DataTable } from "@/components/shared/data-table";
import { evidenceApi, appsApi } from "@/lib/api";
import { toast } from "sonner";

// ─── Mock Data ───────────────────────────────────────────────────────────────

const MOCK_APPS = [
  { id: "app-checkout", name: "Checkout Service", env: "production", status: "active" },
  { id: "app-auth", name: "Auth Service", env: "production", status: "active" },
  { id: "app-payments", name: "Payments Gateway", env: "production", status: "active" },
  { id: "app-iam", name: "IAM Platform", env: "production", status: "active" },
  { id: "app-data-pipeline", name: "Data Pipeline", env: "production", status: "active" },
  { id: "app-api-gw", name: "API Gateway", env: "production", status: "active" },
  { id: "app-notification", name: "Notification Service", env: "staging", status: "active" },
  { id: "app-reporting", name: "Reporting Engine", env: "production", status: "inactive" },
];

interface BundleStatus {
  id: string;
  appId: string;
  appName: string;
  framework: string;
  requestedAt: string;
  completedAt: string | null;
  status: "completed" | "generating" | "failed" | "queued";
  artifacts: number;
  sizeKb: number;
}

const MOCK_BUNDLE_STATUS: BundleStatus[] = [
  {
    id: "bs-001",
    appId: "app-checkout",
    appName: "Checkout Service",
    framework: "SOC 2",
    requestedAt: "2025-01-10T08:00:00Z",
    completedAt: "2025-01-10T08:07:23Z",
    status: "completed",
    artifacts: 14,
    sizeKb: 2840,
  },
  {
    id: "bs-002",
    appId: "app-auth",
    appName: "Auth Service",
    framework: "PCI-DSS",
    requestedAt: "2025-01-10T09:30:00Z",
    completedAt: "2025-01-10T09:38:11Z",
    status: "completed",
    artifacts: 8,
    sizeKb: 1560,
  },
  {
    id: "bs-003",
    appId: "app-payments",
    appName: "Payments Gateway",
    framework: "PCI-DSS",
    requestedAt: "2025-01-10T10:00:00Z",
    completedAt: null,
    status: "generating",
    artifacts: 0,
    sizeKb: 0,
  },
  {
    id: "bs-004",
    appId: "app-iam",
    appName: "IAM Platform",
    framework: "ISO 27001",
    requestedAt: "2025-01-09T14:20:00Z",
    completedAt: "2025-01-09T14:28:44Z",
    status: "completed",
    artifacts: 6,
    sizeKb: 980,
  },
  {
    id: "bs-005",
    appId: "app-data-pipeline",
    appName: "Data Pipeline",
    framework: "HIPAA",
    requestedAt: "2025-01-09T11:00:00Z",
    completedAt: null,
    status: "failed",
    artifacts: 0,
    sizeKb: 0,
  },
  {
    id: "bs-006",
    appId: "app-api-gw",
    appName: "API Gateway",
    framework: "NIST 800-53",
    requestedAt: "2025-01-10T11:30:00Z",
    completedAt: null,
    status: "queued",
    artifacts: 0,
    sizeKb: 0,
  },
];

const RETENTION_POLICIES = [
  { value: "90", label: "90 days (Short-term)" },
  { value: "365", label: "1 year (Standard)" },
  { value: "730", label: "2 years (Extended)" },
  { value: "2190", label: "6 years (HIPAA)" },
  { value: "2555", label: "7 years (SOX/PCI)" },
];

// ─── Status Helpers ──────────────────────────────────────────────────────────

function BundleStatusBadge({ status }: { status: BundleStatus["status"] }) {
  switch (status) {
    case "completed":
      return <Badge variant="success">Completed</Badge>;
    case "generating":
      return (
        <Badge variant="warning" className="gap-1.5">
          <Loader2 className="h-3 w-3 animate-spin" />
          Generating
        </Badge>
      );
    case "failed":
      return <Badge variant="destructive">Failed</Badge>;
    case "queued":
      return <Badge variant="secondary">Queued</Badge>;
  }
}

function BundleStatusIcon({ status }: { status: BundleStatus["status"] }) {
  switch (status) {
    case "completed":
      return <CheckCircle2 className="h-4 w-4 text-green-400" />;
    case "generating":
      return <Loader2 className="h-4 w-4 text-yellow-400 animate-spin" />;
    case "failed":
      return <AlertCircle className="h-4 w-4 text-red-400" />;
    case "queued":
      return <Clock className="h-4 w-4 text-muted-foreground" />;
  }
}

// ─── Main Component ──────────────────────────────────────────────────────────

export default function EvidenceBundles() {
  const [selectedApps, setSelectedApps] = useState<string[]>([]);
  const [selectedFramework, setSelectedFramework] = useState("soc2");
  const [selectedPeriod, setSelectedPeriod] = useState("last-quarter");
  const [retentionPolicy, setRetentionPolicy] = useState("365");
  const [includeMetrics, setIncludeMetrics] = useState(true);
  const [includeLogs, setIncludeLogs] = useState(true);

  const { data: appsData } = useQuery({
    queryKey: ["apps-list"],
    queryFn: () => appsApi.list(),
  });

  const { data: bundlesData } = useQuery({
    queryKey: ["evidence-bundles"],
    queryFn: () => evidenceApi.list(),
  });

  const generateMutation = useMutation({
    mutationFn: (payload: unknown) => evidenceApi.generate(payload),
    onSuccess: () => {
      toast.success("Evidence bundle generation started — you'll be notified when complete.");
    },
    onError: () => {
      toast.error("Failed to start bundle generation. Check app connectivity.");
    },
  });

  const apps = (appsData as { data?: typeof MOCK_APPS })?.data ?? MOCK_APPS;
  const bundles: BundleStatus[] =
    (bundlesData as { data?: BundleStatus[] })?.data ?? MOCK_BUNDLE_STATUS;

  const completedCount = bundles.filter((b) => b.status === "completed").length;
  const generatingCount = bundles.filter((b) => b.status === "generating").length;
  const failedCount = bundles.filter((b) => b.status === "failed").length;

  const toggleApp = (appId: string) => {
    setSelectedApps((prev) =>
      prev.includes(appId) ? prev.filter((id) => id !== appId) : [...prev, appId]
    );
  };

  const selectAllApps = () =>
    setSelectedApps(apps.map((a) => a.id));

  const handleGenerate = () => {
    if (selectedApps.length === 0) {
      toast.error("Select at least one application.");
      return;
    }
    generateMutation.mutate({
      app_ids: selectedApps,
      framework: selectedFramework,
      period: selectedPeriod,
      retention_days: parseInt(retentionPolicy),
      include_metrics: includeMetrics,
      include_logs: includeLogs,
    });
  };

  const handleBulkExport = () => {
    const completed = bundles.filter((b) => b.status === "completed");
    if (completed.length === 0) {
      toast.error("No completed bundles to export.");
      return;
    }
    toast.success(`Exporting ${completed.length} completed bundles...`);
  };

  const statusColumns = [
    {
      key: "appName",
      header: "Application",
      render: (row: BundleStatus) => (
        <div className="flex items-center gap-2.5">
          <BundleStatusIcon status={row.status} />
          <div>
            <p className="text-sm font-medium">{row.appName}</p>
            <p className="text-xs text-muted-foreground font-mono">{row.appId}</p>
          </div>
        </div>
      ),
    },
    {
      key: "framework",
      header: "Framework",
      render: (row: BundleStatus) => (
        <Badge variant="outline">{row.framework}</Badge>
      ),
    },
    {
      key: "status",
      header: "Status",
      render: (row: BundleStatus) => <BundleStatusBadge status={row.status} />,
    },
    {
      key: "requestedAt",
      header: "Requested",
      render: (row: BundleStatus) => (
        <div className="flex items-center gap-1.5 text-xs text-muted-foreground">
          <Calendar className="h-3.5 w-3.5" />
          {new Date(row.requestedAt).toLocaleString()}
        </div>
      ),
    },
    {
      key: "artifacts",
      header: "Artifacts",
      render: (row: BundleStatus) =>
        row.artifacts > 0 ? (
          <span className="text-sm tabular-nums">{row.artifacts} files</span>
        ) : (
          <span className="text-xs text-muted-foreground">—</span>
        ),
    },
    {
      key: "actions",
      header: "",
      render: (row: BundleStatus) =>
        row.status === "completed" ? (
          <Button
            variant="ghost"
            size="sm"
            onClick={() => toast.success(`Downloading ${row.appName} bundle...`)}
          >
            <Download className="h-4 w-4" />
          </Button>
        ) : row.status === "failed" ? (
          <Button
            variant="ghost"
            size="sm"
            onClick={() => toast.info("Retrying bundle generation...")}
          >
            <Play className="h-4 w-4" />
          </Button>
        ) : null,
    },
  ];

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      <PageHeader
        title="Evidence Bundles"
        description="Generate and manage per-application compliance evidence bundles with configurable retention policies"
        actions={
          <Button variant="outline" size="sm" onClick={handleBulkExport}>
            <Archive className="mr-2 h-4 w-4" />
            Bulk Export
          </Button>
        }
      />

      {/* KPI Row */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Total Bundles" value={bundles.length} icon={Layers} trend="flat" />
        <KpiCard
          title="Completed"
          value={completedCount}
          change={8}
          changeLabel="this week"
          icon={CheckCircle2}
          trend="up"
        />
        <KpiCard
          title="In Progress"
          value={generatingCount}
          icon={Loader2}
          trend="flat"
        />
        <KpiCard
          title="Failed"
          value={failedCount}
          icon={AlertCircle}
          trend={failedCount > 0 ? "down" : "flat"}
        />
      </div>

      <Tabs defaultValue="generate" className="space-y-4">
        <TabsList>
          <TabsTrigger value="generate" className="gap-2">
            <PackagePlus className="h-4 w-4" />
            Generate Bundle
          </TabsTrigger>
          <TabsTrigger value="status" className="gap-2">
            <Clock className="h-4 w-4" />
            Bundle Status
          </TabsTrigger>
          <TabsTrigger value="retention" className="gap-2">
            <Settings2 className="h-4 w-4" />
            Retention Settings
          </TabsTrigger>
        </TabsList>

        {/* Generate Tab */}
        <TabsContent value="generate" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {/* App selector */}
            <Card className="border-border/50 lg:col-span-2">
              <CardHeader className="pb-3">
                <div className="flex items-center justify-between">
                  <CardTitle className="text-base">Select Applications</CardTitle>
                  <Button variant="ghost" size="sm" onClick={selectAllApps}>
                    Select All
                  </Button>
                </div>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                  {apps.map((app) => {
                    const isSelected = selectedApps.includes(app.id);
                    return (
                      <button
                        key={app.id}
                        onClick={() => toggleApp(app.id)}
                        className={`flex items-center justify-between p-3 rounded-lg border text-left transition-all duration-150 ${
                          isSelected
                            ? "border-primary/50 bg-primary/5"
                            : "border-border/50 hover:border-border hover:bg-muted/20"
                        }`}
                      >
                        <div>
                          <p className="text-sm font-medium">{app.name}</p>
                          <p className="text-xs text-muted-foreground font-mono">{app.id}</p>
                        </div>
                        <div className="flex items-center gap-2">
                          <Badge variant={app.env === "production" ? "default" : "secondary"} className="text-xs">
                            {app.env}
                          </Badge>
                          {isSelected && (
                            <CheckCircle2 className="h-4 w-4 text-primary shrink-0" />
                          )}
                        </div>
                      </button>
                    );
                  })}
                </div>
              </CardContent>
            </Card>

            {/* Config panel */}
            <Card className="border-border/50">
              <CardHeader className="pb-3">
                <CardTitle className="text-base">Bundle Configuration</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="space-y-1.5">
                  <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
                    Framework
                  </label>
                  <Select value={selectedFramework} onValueChange={setSelectedFramework}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="soc2">SOC 2 Type II</SelectItem>
                      <SelectItem value="pci-dss">PCI-DSS v4.0</SelectItem>
                      <SelectItem value="iso27001">ISO 27001:2022</SelectItem>
                      <SelectItem value="hipaa">HIPAA</SelectItem>
                      <SelectItem value="nist800">NIST 800-53</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-1.5">
                  <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
                    Period
                  </label>
                  <Select value={selectedPeriod} onValueChange={setSelectedPeriod}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="last-week">Last 7 days</SelectItem>
                      <SelectItem value="last-month">Last 30 days</SelectItem>
                      <SelectItem value="last-quarter">Last Quarter</SelectItem>
                      <SelectItem value="last-year">Last Year</SelectItem>
                      <SelectItem value="ytd">Year to Date</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-1.5">
                  <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
                    Retention Policy
                  </label>
                  <Select value={retentionPolicy} onValueChange={setRetentionPolicy}>
                    <SelectTrigger>
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      {RETENTION_POLICIES.map((p) => (
                        <SelectItem key={p.value} value={p.value}>
                          {p.label}
                        </SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2 pt-1">
                  <p className="text-xs font-medium text-muted-foreground uppercase tracking-wider">
                    Include
                  </p>
                  {[
                    { label: "Metrics & telemetry", value: includeMetrics, setter: setIncludeMetrics },
                    { label: "Audit logs", value: includeLogs, setter: setIncludeLogs },
                  ].map(({ label, value, setter }) => (
                    <button
                      key={label}
                      onClick={() => setter(!value)}
                      className="flex items-center gap-2.5 text-sm w-full"
                    >
                      <div
                        className={`h-4 w-4 rounded border flex items-center justify-center transition-colors ${
                          value ? "bg-primary border-primary" : "border-border"
                        }`}
                      >
                        {value && <CheckCircle2 className="h-3 w-3 text-white" />}
                      </div>
                      {label}
                    </button>
                  ))}
                </div>

                <Button
                  className="w-full mt-2"
                  onClick={handleGenerate}
                  disabled={generateMutation.isPending}
                >
                  {generateMutation.isPending ? (
                    <>
                      <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                      Generating...
                    </>
                  ) : (
                    <>
                      <PackagePlus className="mr-2 h-4 w-4" />
                      Generate Bundle ({selectedApps.length} apps)
                    </>
                  )}
                </Button>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Status Tab */}
        <TabsContent value="status">
          <DataTable
            columns={statusColumns}
            data={bundles as unknown as Record<string, unknown>[]}
            emptyMessage="No bundle generation jobs found"
          />
        </TabsContent>

        {/* Retention Tab */}
        <TabsContent value="retention">
          <Card className="border-border/50">
            <CardHeader>
              <CardTitle className="text-base">Retention Policy Settings</CardTitle>
              <p className="text-xs text-muted-foreground">
                Configure evidence retention periods per framework to meet regulatory requirements
              </p>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {[
                  { framework: "SOC 2 Type II", required: "1 year minimum", current: "365 days", status: "compliant" },
                  { framework: "PCI-DSS v4.0", required: "1 year minimum", current: "365 days", status: "compliant" },
                  { framework: "ISO 27001:2022", required: "3 years recommended", current: "365 days", status: "review" },
                  { framework: "HIPAA", required: "6 years minimum", current: "2190 days", status: "compliant" },
                  { framework: "NIST 800-53", required: "3 years minimum", current: "730 days", status: "compliant" },
                ].map((item) => (
                  <div
                    key={item.framework}
                    className="flex items-center justify-between p-4 rounded-lg border border-border/50"
                  >
                    <div>
                      <p className="text-sm font-medium">{item.framework}</p>
                      <p className="text-xs text-muted-foreground mt-0.5">
                        Required: {item.required}
                      </p>
                    </div>
                    <div className="flex items-center gap-3">
                      <div className="text-right">
                        <p className="text-sm font-medium tabular-nums">{item.current}</p>
                        <p className="text-xs text-muted-foreground">current policy</p>
                      </div>
                      {item.status === "compliant" ? (
                        <Badge variant="success">Compliant</Badge>
                      ) : (
                        <Badge variant="warning">Review</Badge>
                      )}
                      <Button variant="ghost" size="sm">
                        <Settings2 className="h-4 w-4" />
                      </Button>
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
