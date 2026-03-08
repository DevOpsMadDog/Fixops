import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  Store,
  Search,
  Download,
  Trash2,
  Star,
  CheckCircle,
  Loader2,
  BookOpen,
  Filter,
  Zap,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { integrationsApi } from "@/lib/api";
import { toast } from "sonner";

// ─── Mock data ───────────────────────────────────────────────────────────────
const MOCK_CONNECTORS = [
  // Scanners
  { id: "snyk-connector", name: "Snyk", category: "Scanners", description: "Industry-leading developer security platform for SAST, SCA, and container scanning.", rating: 4.9, installs: 12400, installed: true, official: true, version: "2.3.1" },
  { id: "wiz-connector", name: "Wiz", category: "Scanners", description: "CNAPP with cloud security posture management and graph-based risk analysis.", rating: 4.8, installs: 9800, installed: true, official: true, version: "1.5.0" },
  { id: "semgrep-connector", name: "Semgrep OSS", category: "Scanners", description: "Open source static analysis with 2000+ rules for 30+ languages.", rating: 4.7, installs: 8200, installed: true, official: true, version: "1.2.4" },
  { id: "trivy-connector", name: "Trivy", category: "Scanners", description: "Comprehensive security scanner for containers, filesystems, and IaC.", rating: 4.8, installs: 11300, installed: true, official: true, version: "0.3.2" },
  { id: "prisma-connector", name: "Prisma Cloud", category: "Scanners", description: "Full-stack cloud-native application protection with CNAPP and CSPM.", rating: 4.6, installs: 7400, installed: false, official: true, version: "3.0.0" },
  { id: "sonarqube-connector", name: "SonarQube", category: "Scanners", description: "Continuous code quality and security analysis platform.", rating: 4.5, installs: 14200, installed: true, official: true, version: "1.1.0" },
  { id: "nuclei-connector", name: "Nuclei", category: "Scanners", description: "Fast, configurable vulnerability scanner with extensive template library.", rating: 4.6, installs: 5100, installed: false, official: false, version: "2.0.1" },
  { id: "tenable-connector", name: "Tenable.io", category: "Scanners", description: "Exposure management platform with continuous vulnerability assessment.", rating: 4.7, installs: 8900, installed: true, official: true, version: "2.1.0" },

  // ALM
  { id: "jira-connector", name: "Jira", category: "ALM", description: "Bi-directional ticket sync with Jira Cloud and Server. Auto-creates issues from findings.", rating: 4.8, installs: 18900, installed: true, official: true, version: "3.4.2" },
  { id: "servicenow-connector", name: "ServiceNow ITSM", category: "ALM", description: "Enterprise ITSM integration with automated incident and change management.", rating: 4.7, installs: 11200, installed: true, official: true, version: "2.2.0" },
  { id: "github-connector", name: "GitHub Issues", category: "ALM", description: "Create and track security issues directly in GitHub repositories.", rating: 4.6, installs: 15700, installed: true, official: true, version: "1.8.3" },
  { id: "linear-connector", name: "Linear", category: "ALM", description: "Modern issue tracking for engineering teams with fast workflow automation.", rating: 4.7, installs: 4200, installed: false, official: false, version: "1.0.4" },

  // Cloud
  { id: "aws-connector", name: "AWS Security Hub", category: "Cloud", description: "Central security dashboard with ASFF-normalized findings from AWS services.", rating: 4.9, installs: 22100, installed: true, official: true, version: "4.0.1" },
  { id: "azure-connector", name: "Azure Defender", category: "Cloud", description: "Microsoft Defender for Cloud integration with adaptive application controls.", rating: 4.7, installs: 16400, installed: true, official: true, version: "3.1.2" },
  { id: "gcp-connector", name: "Google SCC", category: "Cloud", description: "Google Security Command Center with asset inventory and threat intelligence.", rating: 4.6, installs: 9300, installed: true, official: true, version: "2.0.5" },

  // Notifications
  { id: "slack-connector", name: "Slack", category: "Notifications", description: "Real-time alerts with interactive buttons for triage and acknowledgment.", rating: 4.9, installs: 31200, installed: true, official: true, version: "2.6.0" },
  { id: "pagerduty-connector", name: "PagerDuty", category: "Notifications", description: "On-call alerting with incident lifecycle management and runbooks.", rating: 4.8, installs: 14800, installed: true, official: true, version: "1.9.2" },
  { id: "ms-teams-connector", name: "Microsoft Teams", category: "Notifications", description: "Adaptive Card notifications for critical findings and SLA alerts.", rating: 4.5, installs: 12100, installed: false, official: true, version: "1.4.0" },

  // Custom
  { id: "webhook-connector", name: "Generic Webhook", category: "Custom", description: "Send findings to any HTTP endpoint with customizable JSON payload templates.", rating: 4.4, installs: 7800, installed: false, official: true, version: "1.2.0" },
  { id: "splunk-connector", name: "Splunk SIEM", category: "Custom", description: "Stream findings and audit logs to Splunk for SIEM correlation and dashboards.", rating: 4.6, installs: 8900, installed: false, official: false, version: "2.3.0" },
];

const MOCK_PLAYBOOKS = [
  { id: "pb1", name: "Critical CVE Triage", author: "aldeci-team", downloads: 4200, rating: 4.8, description: "Auto-triage critical CVEs with EPSS scoring and asset criticality weighting." },
  { id: "pb2", name: "Log4Shell Response", author: "community", downloads: 8900, rating: 4.9, description: "Detect and remediate Log4Shell variants across JVM-based applications." },
  { id: "pb3", name: "Cloud Misconfiguration Sweep", author: "cloudguard", downloads: 3100, rating: 4.7, description: "Systematic scan and auto-fix for common cloud configuration misconfigurations." },
  { id: "pb4", name: "Secret Rotation Workflow", author: "aldeci-team", downloads: 2800, rating: 4.6, description: "Automated secret rotation for exposed credentials with audit trail generation." },
];

const CATEGORIES = ["All", "Scanners", "ALM", "Cloud", "Notifications", "Custom"];

export default function Marketplace() {
  const [search, setSearch] = useState("");
  const [category, setCategory] = useState("All");
  const [installingId, setInstallingId] = useState<string | null>(null);
  const [installed, setInstalled] = useState<Set<string>>(
    new Set(MOCK_CONNECTORS.filter((c) => c.installed).map((c) => c.id))
  );

  const { data } = useQuery({
    queryKey: ["integrations"],
    queryFn: () => integrationsApi.list(),
  });

  const installMutation = useMutation({
    mutationFn: async (id: string) => {
      setInstallingId(id);
      await new Promise((r) => setTimeout(r, 1400));
      return id;
    },
    onSuccess: (id) => {
      setInstallingId(null);
      setInstalled((prev) => new Set([...prev, id]));
      const c = MOCK_CONNECTORS.find((c) => c.id === id);
      toast.success(`${c?.name} connector installed`);
    },
  });

  const uninstallMutation = useMutation({
    mutationFn: async (id: string) => {
      await new Promise((r) => setTimeout(r, 600));
      return id;
    },
    onSuccess: (id) => {
      setInstalled((prev) => { const n = new Set(prev); n.delete(id); return n; });
      const c = MOCK_CONNECTORS.find((c) => c.id === id);
      toast.success(`${c?.name} uninstalled`);
    },
  });

  const filtered = MOCK_CONNECTORS.filter((c) => {
    const matchSearch = c.name.toLowerCase().includes(search.toLowerCase()) || c.description.toLowerCase().includes(search.toLowerCase());
    const matchCat = category === "All" || c.category === category;
    return matchSearch && matchCat;
  });

  const installedCount = installed.size;

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="space-y-6">
      <PageHeader
        title="Marketplace"
        description="Browse, install, and manage connectors and community playbooks"
        badge="New"
        actions={
          <Button variant="outline" size="sm" onClick={() => toast.info("Checking for connector updates…")}>
            <Zap className="h-3.5 w-3.5 mr-1.5" />
            Check Updates
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <KpiCard title="Available Connectors" value={MOCK_CONNECTORS.length} icon={Store} trend="flat" />
        <KpiCard title="Installed" value={installedCount} icon={CheckCircle} trend="up" />
        <KpiCard title="Community Playbooks" value={MOCK_PLAYBOOKS.length} icon={BookOpen} trend="up" />
        <KpiCard title="Official Partners" value={MOCK_CONNECTORS.filter((c) => c.official).length} icon={Star} trend="flat" />
      </div>

      <Tabs defaultValue="connectors">
        <TabsList>
          <TabsTrigger value="connectors">Connectors</TabsTrigger>
          <TabsTrigger value="playbooks">Community Playbooks</TabsTrigger>
        </TabsList>

        <TabsContent value="connectors" className="mt-4 space-y-4">
          {/* Search + Category Filter */}
          <div className="flex flex-col sm:flex-row gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-2.5 top-2 h-4 w-4 text-muted-foreground" />
              <Input placeholder="Search connectors..." value={search} onChange={(e) => setSearch(e.target.value)} className="pl-8 h-8 text-sm" />
            </div>
            <div className="flex gap-1.5 flex-wrap">
              {CATEGORIES.map((cat) => (
                <Button
                  key={cat}
                  variant={category === cat ? "default" : "outline"}
                  size="sm"
                  className="h-8 text-xs"
                  onClick={() => setCategory(cat)}
                >
                  {cat}
                </Button>
              ))}
            </div>
          </div>

          {/* Connectors Grid */}
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {filtered.map((connector) => {
              const isInstalled = installed.has(connector.id);
              const isInstalling = installingId === connector.id;
              return (
                <Card key={connector.id} className="border-border/50 hover:border-border transition-colors flex flex-col">
                  <CardHeader className="pb-2">
                    <div className="flex items-start justify-between gap-2">
                      <div>
                        <div className="flex items-center gap-1.5 mb-0.5">
                          <CardTitle className="text-sm">{connector.name}</CardTitle>
                          {connector.official && <Badge variant="info" className="text-xs">Official</Badge>}
                          {isInstalled && <CheckCircle className="h-3.5 w-3.5 text-green-400" />}
                        </div>
                        <Badge variant="secondary" className="text-xs">{connector.category}</Badge>
                      </div>
                    </div>
                  </CardHeader>
                  <CardContent className="flex-1 flex flex-col justify-between gap-3">
                    <CardDescription className="text-xs leading-relaxed">{connector.description}</CardDescription>
                    <div className="space-y-2">
                      <div className="flex items-center justify-between text-xs text-muted-foreground">
                        <span className="flex items-center gap-1">
                          <Star className="h-3 w-3 text-yellow-400 fill-yellow-400" />
                          {connector.rating}
                        </span>
                        <span>{connector.installs.toLocaleString()} installs</span>
                        <span>v{connector.version}</span>
                      </div>
                      {isInstalled ? (
                        <Button
                          variant="outline"
                          size="sm"
                          className="w-full h-7 text-xs text-destructive hover:text-destructive"
                          onClick={() => uninstallMutation.mutate(connector.id)}
                        >
                          <Trash2 className="h-3 w-3 mr-1" />
                          Uninstall
                        </Button>
                      ) : (
                        <Button
                          size="sm"
                          className="w-full h-7 text-xs"
                          disabled={isInstalling}
                          onClick={() => installMutation.mutate(connector.id)}
                        >
                          {isInstalling ? (
                            <><Loader2 className="h-3 w-3 mr-1 animate-spin" />Installing…</>
                          ) : (
                            <><Download className="h-3 w-3 mr-1" />Install</>
                          )}
                        </Button>
                      )}
                    </div>
                  </CardContent>
                </Card>
              );
            })}
          </div>
          {filtered.length === 0 && (
            <div className="flex flex-col items-center py-16 gap-3 text-muted-foreground">
              <Filter className="h-8 w-8 opacity-40" />
              <p className="text-sm">No connectors match your search</p>
            </div>
          )}
        </TabsContent>

        {/* Community Playbooks */}
        <TabsContent value="playbooks" className="mt-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {MOCK_PLAYBOOKS.map((pb) => (
              <Card key={pb.id} className="border-border/50 hover:border-border transition-colors">
                <CardHeader className="pb-2">
                  <div className="flex items-start justify-between">
                    <div>
                      <CardTitle className="text-sm">{pb.name}</CardTitle>
                      <p className="text-xs text-muted-foreground mt-0.5">by @{pb.author}</p>
                    </div>
                    <div className="flex items-center gap-1 text-xs">
                      <Star className="h-3 w-3 text-yellow-400 fill-yellow-400" />
                      <span>{pb.rating}</span>
                    </div>
                  </div>
                </CardHeader>
                <CardContent className="space-y-3">
                  <p className="text-xs text-muted-foreground">{pb.description}</p>
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-muted-foreground">{pb.downloads.toLocaleString()} downloads</span>
                    <div className="flex gap-2">
                      <Button variant="outline" size="sm" className="h-7 text-xs">Preview</Button>
                      <Button size="sm" className="h-7 text-xs">
                        <Download className="h-3 w-3 mr-1" />
                        Import
                      </Button>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
