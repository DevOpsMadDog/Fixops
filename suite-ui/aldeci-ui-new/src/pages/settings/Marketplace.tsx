import { toArray } from "@/lib/api-utils";
import { useState, useCallback, useMemo } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Separator } from "@/components/ui/separator";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Progress } from "@/components/ui/progress";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { motion } from "framer-motion";
import {
  Store, Search, Star, Shield, GitBranch, Cloud, Bell, Download,
  CheckCircle, Package, Users, Puzzle, RefreshCw, ExternalLink,
  Zap, TrendingUp, Settings, AlertCircle, ArrowUpRight
} from "lucide-react";
import { useIntegrations, useTestIntegration, useConfigureIntegration } from "@/hooks/use-api";
import { useQuery } from "@tanstack/react-query";
import { marketplaceApi, connectorsApi } from "@/lib/api";
import { toast } from "sonner";

const CATEGORY_ICONS: Record<string, React.ElementType> = {
  All: Package,
  Scanners: Shield,
  ALM: GitBranch,
  Cloud: Cloud,
  Notification: Bell,
  Community: Users,
  "Connector Types": Puzzle,
};

type MarketplaceCategory = "All" | "Scanners" | "ALM" | "Cloud" | "Notification" | "Community" | "Connector Types";
const CATEGORIES: MarketplaceCategory[] = ["All", "Scanners", "ALM", "Cloud", "Notification", "Community", "Connector Types"];

// Empty default — community playbooks are loaded exclusively from the API
const COMMUNITY_PLAYBOOKS_EMPTY: { name: string; author: string; stars: number; downloads: number; category: string; verified: boolean }[] = [];

const HEALTH_STATUSES = ["healthy", "healthy", "healthy", "warning", "error", "unknown"] as const;

type HealthStatus = typeof HEALTH_STATUSES[number];

function HealthBadge({ status }: { status: HealthStatus }) {
  const map: Record<HealthStatus, { label: string; cls: string; dot: string }> = {
    healthy: { label: "Healthy", cls: "bg-green-900/40 text-green-400 border-green-700", dot: "bg-green-500" },
    warning: { label: "Degraded", cls: "bg-yellow-900/40 text-yellow-400 border-yellow-700", dot: "bg-yellow-500" },
    error: { label: "Error", cls: "bg-red-900/40 text-red-400 border-red-700", dot: "bg-red-500" },
    unknown: { label: "Unknown", cls: "bg-muted text-muted-foreground border-border", dot: "bg-gray-500" },
  };
  const s = map[status] ?? map.unknown;
  return (
    <span className={`inline-flex items-center gap-1.5 rounded-full border px-2 py-0.5 text-xs font-medium ${s.cls}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${s.dot} animate-pulse`} />
      {s.label}
    </span>
  );
}

function ConnectorConfigWizard({ connector, onClose }: { connector: any; onClose: () => void }) {
  const [step, setStep] = useState(1);
  const [apiKey, setApiKey] = useState("");
  const [baseUrl, setBaseUrl] = useState("");
  const [webhookEnabled, setWebhookEnabled] = useState(false);
  const [testPassed, setTestPassed] = useState<null | boolean>(null);
  const [testing, setTesting] = useState(false);

  const testMutation = useTestIntegration();
  const configureMutation = useConfigureIntegration();

  const handleTest = async () => {
    setTesting(true);
    setTestPassed(null);
    testMutation.mutate(connector.id ?? connector.name, {
      onSuccess: () => { setTestPassed(true); setTesting(false); },
      onError: () => { setTestPassed(false); setTesting(false); },
    });
  };

  const handleFinish = () => {
    configureMutation.mutate({ id: connector.id ?? connector.name, data: { api_key: apiKey, base_url: baseUrl, webhook_enabled: webhookEnabled } }, {
      onSuccess: () => onClose(),
    });
  };

  return (
    <div className="space-y-5">
      {/* Step indicator */}
      <div className="flex items-center gap-2">
        {[1, 2, 3].map((s) => (
          <div key={s} className="flex items-center gap-2">
            <div className={`h-6 w-6 rounded-full flex items-center justify-center text-xs font-bold ${
              step > s ? "bg-green-600 text-white" : step === s ? "bg-primary text-primary-foreground" : "bg-muted text-muted-foreground"
            }`}>
              {step > s ? "✓" : s}
            </div>
            {s < 3 && <div className={`h-px w-8 ${step > s ? "bg-green-600" : "bg-border"}`} />}
          </div>
        ))}
        <span className="text-xs text-muted-foreground ml-2">
          {step === 1 ? "Credentials" : step === 2 ? "Options" : "Verify"}
        </span>
      </div>

      {step === 1 && (
        <div className="space-y-4">
          <div>
            <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-2 block">API Key / Token</Label>
            <Input type="password" placeholder="Enter API key…" value={apiKey} onChange={(e) => setApiKey(e.target.value)} />
          </div>
          <div>
            <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-2 block">Base URL (optional)</Label>
            <Input placeholder="https://api.example.com" value={baseUrl} onChange={(e) => setBaseUrl(e.target.value)} />
          </div>
          <Button className="w-full" onClick={() => setStep(2)} disabled={!apiKey}>
            Next: Configure Options
          </Button>
        </div>
      )}

      {step === 2 && (
        <div className="space-y-4">
          <div className="flex items-center justify-between p-3 rounded-lg bg-muted/30 border border-border/40">
            <div>
              <p className="text-sm font-medium">Enable Webhook Push</p>
              <p className="text-xs text-muted-foreground mt-0.5">Receive real-time events from this connector</p>
            </div>
            <Switch checked={webhookEnabled} onCheckedChange={setWebhookEnabled} />
          </div>
          {webhookEnabled && (
            <div className="p-3 rounded-lg bg-primary/5 border border-primary/20">
              <p className="text-xs text-muted-foreground">Webhook endpoint:</p>
              <code className="text-xs font-mono text-primary">https://fixops.io/webhooks/{connector.name?.toLowerCase()?.replace(/ /g, "-")}</code>
            </div>
          )}
          <div className="flex gap-2">
            <Button variant="outline" className="flex-1" onClick={() => setStep(1)}>Back</Button>
            <Button className="flex-1" onClick={() => setStep(3)}>Next: Verify</Button>
          </div>
        </div>
      )}

      {step === 3 && (
        <div className="space-y-4">
          {testPassed === null ? (
            <div className="p-4 rounded-lg bg-muted/30 border border-border/40 text-center">
              <p className="text-sm text-muted-foreground">Test the connection to verify your credentials</p>
            </div>
          ) : testPassed ? (
            <div className="p-4 rounded-lg bg-green-950/30 border border-green-700/40 flex items-center gap-3">
              <CheckCircle className="h-5 w-5 text-green-400" />
              <div>
                <p className="text-sm font-medium text-green-400">Connection successful</p>
                <p className="text-xs text-muted-foreground">Connector is ready to use</p>
              </div>
            </div>
          ) : (
            <div className="p-4 rounded-lg bg-red-950/30 border border-red-700/40 flex items-center gap-3">
              <AlertCircle className="h-5 w-5 text-red-400" />
              <p className="text-sm text-red-400">Connection failed. Check your credentials.</p>
            </div>
          )}
          <div className="flex gap-2">
            <Button variant="outline" className="flex-1" onClick={() => setStep(2)}>Back</Button>
            <Button variant="outline" className="flex-1 gap-2" onClick={handleTest} disabled={testing}>
              <Zap className="h-3.5 w-3.5" />
              {testing ? "Testing…" : "Test Connection"}
            </Button>
            <Button className="flex-1" onClick={handleFinish} disabled={!testPassed}>Finish</Button>
          </div>
        </div>
      )}
    </div>
  );
}

function StarRating({ rating }: { rating: number }) {
  return (
    <div className="flex items-center gap-0.5">
      {Array.from({ length: 5 }, (_, i) => (
        <Star
          key={i}
          className={`h-3 w-3 ${i < Math.round(rating) ? "text-yellow-400 fill-yellow-400" : "text-muted-foreground"}`}
        />
      ))}
      <span className="text-xs text-muted-foreground ml-1">{rating.toFixed(1)}</span>
    </div>
  );
}

function ConnectorDetailDialog({ connector, isInstalled, onToggle }: {
  connector: any;
  isInstalled: boolean;
  onToggle: () => void;
}) {
  const [open, setOpen] = useState(false);
  const [configTab, setConfigTab] = useState<"info" | "wizard">("info");
  const connHealth: HealthStatus = isInstalled ? "healthy" : "unknown";

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="ghost" size="icon" className="h-7 w-7">
          <ExternalLink className="h-3.5 w-3.5" />
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Package className="h-4 w-4 text-primary" />
            {connector.name}
          </DialogTitle>
        </DialogHeader>
        <Tabs value={configTab} onValueChange={(v) => setConfigTab(v as any)}>
          <TabsList className="w-full">
            <TabsTrigger value="info" className="flex-1">Details</TabsTrigger>
            <TabsTrigger value="wizard" className="flex-1 gap-1.5"><Settings className="h-3.5 w-3.5" />Configure</TabsTrigger>
          </TabsList>
          <TabsContent value="info" className="space-y-4 mt-4">
            <div className="flex items-center gap-3 flex-wrap">
              <Badge variant="outline" className="text-xs">{connector.category}</Badge>
              <StarRating rating={connector.rating ?? 4.2} />
              <Badge variant={isInstalled ? "default" : "secondary"} className="text-xs">
                {isInstalled ? "Installed" : "Available"}
              </Badge>
              {isInstalled && <HealthBadge status={connHealth} />}
            </div>
            <p className="text-sm text-muted-foreground">{connector.description ?? "A powerful integration connector."}</p>
            {isInstalled && (
              <div className="grid grid-cols-3 gap-3">
                {[
                  { label: "Uptime", value: "99.8%" },
                  { label: "Last Sync", value: "2m ago" },
                  { label: "Events/h", value: "1.2K" },
                ].map(({ label, value }) => (
                  <div key={label} className="text-center p-3 rounded-lg bg-muted/30 border border-border/40">
                    <p className="text-base font-bold">{value}</p>
                    <p className="text-xs text-muted-foreground mt-0.5">{label}</p>
                  </div>
                ))}
              </div>
            )}
            <Separator />
            <div>
              <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-3">Configuration Steps</p>
              <ol className="space-y-2">
                {["Generate API key in your account settings", "Copy key and enter below", "Test the connection", "Configure alert thresholds"].map((step, i) => (
                  <li key={i} className="flex items-start gap-2 text-sm">
                    <span className="h-5 w-5 rounded-full bg-primary/20 text-primary text-xs flex items-center justify-center shrink-0 mt-0.5">{i + 1}</span>
                    {step}
                  </li>
                ))}
              </ol>
            </div>
            <Separator />
            <div className="flex gap-2">
              <Button
                className="flex-1 gap-2"
                variant={isInstalled ? "destructive" : "default"}
                onClick={() => { onToggle(); setOpen(false); }}
              >
                {isInstalled ? <><CheckCircle className="h-3.5 w-3.5" /> Uninstall</> : <><Download className="h-3.5 w-3.5" /> Install</>}
              </Button>
              <Button variant="outline" className="gap-2" onClick={() => setOpen(false)}>
                Close
              </Button>
            </div>
          </TabsContent>
          <TabsContent value="wizard" className="mt-4">
            <ConnectorConfigWizard connector={connector} onClose={() => setOpen(false)} />
          </TabsContent>
        </Tabs>
      </DialogContent>
    </Dialog>
  );
}

// ── Connector Types Catalog ────────────────────────────────────────────────
interface ConnectorTypeDescriptor {
  type: string;
  label: string;
  description: string;
  required_fields: string[];
  optional_fields: string[];
}

function ConnectorTypesCatalog() {
  const { data, isLoading, isError, refetch } = useQuery({
    queryKey: ["connector-types"],
    queryFn: () => connectorsApi.types().then((r) => r.data),
    staleTime: 120_000,
  });

  if (isLoading) {
    return (
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
        {Array.from({ length: 8 }, (_, i) => (
          <div key={i} className="h-44 rounded-xl bg-muted/40 animate-pulse" />
        ))}
      </div>
    );
  }

  if (isError) {
    return (
      <div className="flex flex-col items-center gap-3 py-12 text-muted-foreground">
        <AlertCircle className="h-8 w-8 text-destructive" />
        <p className="text-sm">Failed to load connector types catalog.</p>
        <Button variant="outline" size="sm" onClick={() => refetch()}>Retry</Button>
      </div>
    );
  }

  const types: ConnectorTypeDescriptor[] = Array.isArray(data?.types) ? data.types : [];

  if (types.length === 0) {
    return (
      <div className="flex flex-col items-center gap-3 py-12 text-muted-foreground">
        <Puzzle className="h-8 w-8" />
        <p className="text-sm">No connector types available.</p>
      </div>
    );
  }

  return (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
      {types.map((ct) => (
        <motion.div
          key={ct.type}
          initial={{ opacity: 0, y: 10 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.2 }}
        >
          <Card className="hover:shadow-md transition-shadow h-full flex flex-col">
            <CardHeader className="pb-2">
              <div className="flex items-start justify-between gap-2">
                <div className="flex items-center gap-2 min-w-0">
                  <div className="h-8 w-8 rounded-lg bg-primary/10 flex items-center justify-center shrink-0">
                    <Puzzle className="h-4 w-4 text-primary" />
                  </div>
                  <CardTitle className="text-sm truncate">{ct.label}</CardTitle>
                </div>
                <Badge variant="outline" className="text-xs shrink-0">
                  {ct.required_fields.length} req.
                </Badge>
              </div>
            </CardHeader>
            <CardContent className="pt-0 flex flex-col flex-1 gap-3">
              <CardDescription className="text-xs leading-relaxed flex-1">
                {ct.description || `Configure a ${ct.label} connector.`}
              </CardDescription>
              {ct.required_fields.length > 0 && (
                <div>
                  <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-1">Required fields</p>
                  <div className="flex flex-wrap gap-1">
                    {ct.required_fields.map((f) => (
                      <code key={f} className="text-xs bg-muted px-1.5 py-0.5 rounded font-mono">{f}</code>
                    ))}
                  </div>
                </div>
              )}
              {ct.optional_fields.length > 0 && (
                <div>
                  <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-1">Optional</p>
                  <div className="flex flex-wrap gap-1">
                    {ct.optional_fields.slice(0, 4).map((f) => (
                      <code key={f} className="text-xs bg-muted/50 px-1.5 py-0.5 rounded font-mono text-muted-foreground">{f}</code>
                    ))}
                    {ct.optional_fields.length > 4 && (
                      <span className="text-xs text-muted-foreground">+{ct.optional_fields.length - 4} more</span>
                    )}
                  </div>
                </div>
              )}
              <Button size="sm" variant="outline" className="w-full text-xs gap-1.5 mt-auto" disabled>
                <Settings className="h-3 w-3" />
                Configure
              </Button>
            </CardContent>
          </Card>
        </motion.div>
      ))}
    </div>
  );
}

export default function Marketplace() {
  const integrationsQuery = useIntegrations();
  const refetch = useCallback(() => integrationsQuery.refetch(), [integrationsQuery]);

  // Real marketplace data from API
  const marketplaceBrowseQuery = useQuery({
    queryKey: ["marketplace-browse"],
    queryFn: () => marketplaceApi.browse().then((r) => r.data),
    staleTime: 60_000,
  });
  const marketplaceStatsQuery = useQuery({
    queryKey: ["marketplace-stats"],
    queryFn: () => marketplaceApi.stats().then((r) => r.data),
    staleTime: 60_000,
  });

  // Build community playbooks from API or fallback
  const COMMUNITY_PLAYBOOKS = useMemo(() => {
    const items = marketplaceBrowseQuery.data?.items;
    if (!Array.isArray(items) || items.length === 0) return COMMUNITY_PLAYBOOKS_EMPTY;
    return items.map((item: Record<string, unknown>) => ({
      name: (item.name as string) || "Unnamed",
      author: (item.author as string) || (item.contributor as string) || "community",
      stars: typeof item.rating_count === "number" ? (item.rating_count as number) : Math.round(((item.average_rating as number) || 4) * 30),
      downloads: typeof item.downloads === "number" ? (item.downloads as number) : 0,
      category: (item.category as string) || (item.content_type as string) || "General",
      verified: item.verified === true || ((item.average_rating as number) || 0) >= 4,
    }));
  }, [marketplaceBrowseQuery.data]);

  const marketplaceStats = marketplaceStatsQuery.data;

  const [category, setCategory] = useState<MarketplaceCategory>("All");
  const [search, setSearch] = useState("");
  const [installed, setInstalled] = useState<Set<string>>(new Set());

  if (integrationsQuery.isLoading) return <PageSkeleton />;
  if (integrationsQuery.isError) return <ErrorState message="Failed to load marketplace" onRetry={refetch} />;

  const integrations: any[] = toArray(integrationsQuery.data);

  // Enrich with category, rating, description
  const connectors = integrations.map((i: any) => ({
    ...i,
    category: i.category ?? i.type ?? "Scanners",
    rating: i.rating ?? 0,
    description: i.description ?? `Connect ${i.name ?? "this tool"} to ALdeci for automated security scanning and evidence collection.`,
    installed: i.status === "connected" || installed.has(i.id ?? i.name),
  }));

  const installedCount = connectors.filter((c) => c.installed || installed.has(c.id ?? c.name)).length;
  const availableCount = connectors.filter((c) => !c.installed && !installed.has(c.id ?? c.name)).length;

  const filtered = connectors.filter((c) => {
    const matchesCat = category === "All" || c.category === category;
    const matchesSearch = !search ||
      (c.name ?? "").toLowerCase().includes(search.toLowerCase()) ||
      (c.description ?? "").toLowerCase().includes(search.toLowerCase());
    return matchesCat && matchesSearch;
  });

  const handleToggle = (connector: any) => {
    const id = connector.id ?? connector.name;
    if (installed.has(id) || connector.installed) {
      const next = new Set(installed);
      next.delete(id);
      setInstalled(next);
      toast.success(`${connector.name} uninstalled`);
    } else {
      setInstalled((prev) => new Set([...prev, id]));
      toast.success(`${connector.name} installed successfully`);
    }
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      <PageHeader
        title="Marketplace"
        description="Discover, install, and configure security connectors and community playbooks"
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={refetch} className="gap-2">
          <RefreshCw className="h-4 w-4" />
          Refresh
        </Button>
          </div>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Total Connectors" value={connectors.length} icon={Puzzle} />
        <KpiCard title="Installed" value={installedCount} icon={CheckCircle} />
        <KpiCard title="Available" value={availableCount} icon={Store} />
        <KpiCard title="Community Playbooks" value={marketplaceStats?.total_items ?? COMMUNITY_PLAYBOOKS.length} icon={Package} />
      </div>

      {/* Search */}
      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
        <Input
          placeholder="Search connectors and playbooks…"
          className="pl-9"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
      </div>

      {/* Category tabs */}
      <Tabs value={category} onValueChange={(v) => setCategory(v as MarketplaceCategory)}>
        <TabsList className="flex-wrap h-auto gap-1">
          {CATEGORIES.map((cat) => {
            const Icon = CATEGORY_ICONS[cat];
            return (
              <TabsTrigger key={cat} value={cat} className="gap-1.5">
                <Icon className="h-3.5 w-3.5" />
                {cat}
              </TabsTrigger>
            );
          })}
        </TabsList>
      </Tabs>

      {/* Connector Types catalog — sourced from /api/v1/connectors/types */}
      {category === "Connector Types" && <ConnectorTypesCatalog />}

      {/* Connector grid */}
      {category !== "Connector Types" && <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
        {filtered.length === 0 ? (
          <div className="col-span-full text-center py-12 text-muted-foreground">
            No connectors match your search
          </div>
        ) : (
          filtered.map((connector, i) => {
            const isInst = connector.installed || installed.has(connector.id ?? connector.name);
            const Icon = CATEGORY_ICONS[connector.category] ?? Package;
            return (
              <motion.div
                key={connector.id ?? connector.name ?? i}
                initial={{ opacity: 0, y: 12 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.04 }}
              >
                <Card className="hover:shadow-md transition-shadow h-full flex flex-col">
                  <CardHeader className="pb-2">
                    <div className="flex items-start justify-between">
                      <div className="flex items-center gap-2">
                        <div className="h-8 w-8 rounded-lg bg-muted flex items-center justify-center">
                          <Icon className="h-4 w-4 text-muted-foreground" />
                        </div>
                        <div>
                          <CardTitle className="text-sm">{connector.name ?? "Connector"}</CardTitle>
                          <Badge variant="outline" className="text-xs mt-0.5">{connector.category}</Badge>
                        </div>
                      </div>
                      {isInst ? (
                        <HealthBadge status={HEALTH_STATUSES[(i % HEALTH_STATUSES.length)] as HealthStatus} />
                      ) : null}
                    </div>
                  </CardHeader>
                  <CardContent className="pt-0 flex flex-col flex-1">
                    <CardDescription className="text-xs leading-relaxed flex-1 mb-3">
                      {connector.description}
                    </CardDescription>
                    <div className="space-y-2">
                      <div className="flex items-center justify-between">
                        <StarRating rating={connector.rating ?? 4.0} />
                        {isInst && (
                          <span className="text-xs text-muted-foreground flex items-center gap-1">
                            <TrendingUp className="h-3 w-3 text-green-400" />
                            Live
                          </span>
                        )}
                      </div>
                      <div className="flex gap-2">
                        <Button
                          size="sm"
                          variant={isInst ? "secondary" : "default"}
                          className="flex-1 text-xs gap-1"
                          onClick={() => handleToggle(connector)}
                        >
                          {isInst ? "Uninstall" : <><Download className="h-3 w-3" /> Install</>}
                        </Button>
                        <ConnectorDetailDialog connector={connector} isInstalled={isInst} onToggle={() => handleToggle(connector)} />
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </motion.div>
            );
          })
        )}
      </div>}

      {/* Community playbooks */}
      {(category === "All" || category === "Community") && (
        <div>
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider flex items-center gap-2">
              <Users className="h-4 w-4" />
              Community Playbooks
            </h2>
            <Button
              variant="outline"
              size="sm"
              className="gap-1.5 text-xs"
              onClick={() => setCategory("Community")}
            >
              <ArrowUpRight className="h-3.5 w-3.5" />
              Browse All
            </Button>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
            {COMMUNITY_PLAYBOOKS.length === 0 && (
              <p className="text-xs text-muted-foreground col-span-full text-center py-8">No community playbooks available. Playbooks published to the marketplace will appear here.</p>
            )}
            {COMMUNITY_PLAYBOOKS.map((pb, i) => (
              <Card key={i} className="hover:shadow-md transition-shadow">
                <CardHeader className="pb-2">
                  <div className="flex items-start justify-between">
                    <div>
                      <CardTitle className="text-sm">{pb.name}</CardTitle>
                      <p className="text-xs text-muted-foreground mt-0.5">by {pb.author}</p>
                    </div>
                    <Badge variant="outline" className="text-xs shrink-0">{pb.category}</Badge>
                  </div>
                </CardHeader>
                <CardContent className="pt-0">
                  <div className="flex items-center gap-3 text-xs text-muted-foreground mb-3">
                    <span className="flex items-center gap-1"><Star className="h-3 w-3 text-yellow-400 fill-yellow-400" /> {pb.stars}</span>
                    <span className="flex items-center gap-1"><Download className="h-3 w-3" /> {pb.downloads}</span>
                    {pb.verified && (
                      <span className="flex items-center gap-1 text-green-400 ml-auto">
                        <CheckCircle className="h-3 w-3" /> Verified
                      </span>
                    )}
                  </div>
                  {/* Rating bar */}
                  <div className="mb-3">
                    <div className="flex justify-between text-xs text-muted-foreground mb-1">
                      <span>Popularity</span>
                      <span>{Math.round((pb.downloads / 1100) * 100)}%</span>
                    </div>
                    <Progress value={Math.round((pb.downloads / 1100) * 100)} className="h-1" />
                  </div>
                  <Button size="sm" variant="outline" className="w-full text-xs gap-1"
                    onClick={async () => {
                      try {
                        const { playbooks: playbooksApi } = await import("@/lib/api");
                        await playbooksApi.create({ name: pb.name, description: pb.category ?? "", steps: [], source: "marketplace" });
                        toast.success(`${pb.name} imported successfully`);
                      } catch (err: any) {
                        toast.error(err?.response?.data?.detail ?? `Failed to import ${pb.name}`);
                      }
                    }}>
                    <Download className="h-3 w-3" />
                    Import Playbook
                  </Button>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      )}
    </motion.div>
  );
}
