import { useState, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Separator } from "@/components/ui/separator";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { motion } from "framer-motion";
import {
  Store, Search, Star, Shield, GitBranch, Cloud, Bell, Download,
  CheckCircle, Package, Users, Puzzle, RefreshCw, ExternalLink
} from "lucide-react";
import { useIntegrations } from "@/hooks/use-api";
import { toast } from "sonner";

const CATEGORY_ICONS: Record<string, React.ElementType> = {
  All: Package,
  Scanners: Shield,
  ALM: GitBranch,
  Cloud: Cloud,
  Notification: Bell,
  Community: Users,
};

type MarketplaceCategory = "All" | "Scanners" | "ALM" | "Cloud" | "Notification" | "Community";
const CATEGORIES: MarketplaceCategory[] = ["All", "Scanners", "ALM", "Cloud", "Notification", "Community"];

const COMMUNITY_PLAYBOOKS = [
  { name: "SOC2 Rapid Assessment", author: "security-team", stars: 128, downloads: 512 },
  { name: "OWASP Top 10 Coverage", author: "appsec-pros", stars: 94, downloads: 389 },
  { name: "Zero Trust Verification", author: "devsecops-io", stars: 211, downloads: 1024 },
  { name: "Container Hardening", author: "cloud-native", stars: 156, downloads: 743 },
];

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
  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button variant="ghost" size="icon" className="h-7 w-7">
          <ExternalLink className="h-3.5 w-3.5" />
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Package className="h-4 w-4 text-primary" />
            {connector.name}
          </DialogTitle>
        </DialogHeader>
        <div className="space-y-4">
          <div className="flex items-center gap-3 flex-wrap">
            <Badge variant="outline" className="text-xs">{connector.category}</Badge>
            <StarRating rating={connector.rating ?? 4.2} />
            <Badge variant={isInstalled ? "default" : "secondary"} className="text-xs">
              {isInstalled ? "Installed" : "Available"}
            </Badge>
          </div>
          <p className="text-sm text-muted-foreground">{connector.description ?? "A powerful integration connector."}</p>
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
        </div>
      </DialogContent>
    </Dialog>
  );
}

export default function Marketplace() {
  const integrationsQuery = useIntegrations();
  const refetch = useCallback(() => integrationsQuery.refetch(), [integrationsQuery]);

  const [category, setCategory] = useState<MarketplaceCategory>("All");
  const [search, setSearch] = useState("");
  const [installed, setInstalled] = useState<Set<string>>(new Set());

  if (integrationsQuery.isLoading) return <PageSkeleton />;
  if (integrationsQuery.isError) return <ErrorState message="Failed to load marketplace" onRetry={refetch} />;

  const integrations: any[] = integrationsQuery.data?.data ?? integrationsQuery.data ?? [];

  // Enrich with category, rating, description
  const connectors = integrations.map((i: any) => ({
    ...i,
    category: i.category ?? i.type ?? "Scanners",
    rating: i.rating ?? (3.5 + Math.random() * 1.5),
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
        <KpiCard title="Community Playbooks" value={COMMUNITY_PLAYBOOKS.length} icon={Package} />
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

      {/* Connector grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-4">
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
                      {isInst && (
                        <CheckCircle className="h-4 w-4 text-green-500 shrink-0" />
                      )}
                    </div>
                  </CardHeader>
                  <CardContent className="pt-0 flex flex-col flex-1">
                    <CardDescription className="text-xs leading-relaxed flex-1 mb-3">
                      {connector.description}
                    </CardDescription>
                    <div className="space-y-2">
                      <StarRating rating={connector.rating ?? 4.0} />
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
      </div>

      {/* Community playbooks */}
      {(category === "All" || category === "Community") && (
        <div>
          <h2 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider mb-3 flex items-center gap-2">
            <Users className="h-4 w-4" />
            Community Playbooks
          </h2>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
            {COMMUNITY_PLAYBOOKS.map((pb, i) => (
              <Card key={i} className="hover:shadow-md transition-shadow">
                <CardHeader className="pb-2">
                  <CardTitle className="text-sm">{pb.name}</CardTitle>
                  <p className="text-xs text-muted-foreground">by {pb.author}</p>
                </CardHeader>
                <CardContent className="pt-0">
                  <div className="flex items-center gap-3 text-xs text-muted-foreground mb-3">
                    <span className="flex items-center gap-1"><Star className="h-3 w-3 text-yellow-400 fill-yellow-400" /> {pb.stars}</span>
                    <span className="flex items-center gap-1"><Download className="h-3 w-3" /> {pb.downloads}</span>
                  </div>
                  <Button size="sm" variant="outline" className="w-full text-xs gap-1">
                    <Download className="h-3 w-3" />
                    Import
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
