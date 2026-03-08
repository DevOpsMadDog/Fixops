import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { motion, AnimatePresence } from "framer-motion";
import {
  ArrowRight, AlertTriangle, Shield, Target, Zap,
  ChevronRight, X, Globe, Server, Database, Lock,
  Activity, RefreshCw, Filter, Eye
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { knowledgeGraphApi } from "@/lib/api";
import { toast } from "sonner";

// ── Mock Data ──────────────────────────────────────────────────────────────────
interface PathNode {
  id: string;
  label: string;
  type: "internet" | "perimeter" | "service" | "vulnerability" | "data";
  detail: string;
}

interface AttackPath {
  id: string;
  title: string;
  riskScore: number;
  blastRadius: number;
  nodes: PathNode[];
  techniques: string[];
  reachability: "confirmed" | "probable" | "theoretical";
  affectedAssets: string[];
  mitigations: string[];
  status: "active" | "blocked" | "mitigated";
}

const MOCK_ATTACK_PATHS: AttackPath[] = [
  {
    id: "AP-1001",
    title: "Internet → Redis Cache → Internal DB exfiltration",
    riskScore: 96,
    blastRadius: 89,
    reachability: "confirmed",
    status: "active",
    techniques: ["T1190 - Exploit Public-Facing Application", "T1078 - Valid Accounts", "T1005 - Data from Local System"],
    affectedAssets: ["user-data-db", "payment-records", "session-cache", "all-services"],
    mitigations: ["Add Redis AUTH password", "Restrict Redis to VPC CIDR", "Enable TLS for Redis connections"],
    nodes: [
      { id: "n1", label: "Internet", type: "internet", detail: "0.0.0.0/0 unrestricted" },
      { id: "n2", label: "Redis :6379", type: "vulnerability", detail: "Unauthenticated Redis exposed on public IP" },
      { id: "n3", label: "Session Data", type: "data", detail: "200K user sessions stored in plaintext" },
      { id: "n4", label: "RDS Primary", type: "data", detail: "User PII and payment data accessible via session tokens" },
    ],
  },
  {
    id: "AP-1002",
    title: "Phishing → API Gateway → Payment Service → S3 exfil",
    riskScore: 82,
    blastRadius: 67,
    reachability: "probable",
    status: "active",
    techniques: ["T1566 - Phishing", "T1550.001 - Application Access Token", "T1567.002 - Exfiltration to Cloud Storage"],
    affectedAssets: ["payment-service", "s3://prod-data-lake", "invoices", "customer-pii"],
    mitigations: ["Implement SSRF protection on API Gateway", "Restrict S3 bucket ACL", "Enable MFA for service accounts"],
    nodes: [
      { id: "n1", label: "Internet", type: "internet", detail: "Phishing email with malicious link" },
      { id: "n2", label: "Auth Bypass", type: "vulnerability", detail: "JWT weak signing key (SAST-1041)" },
      { id: "n3", label: "API Gateway", type: "service", detail: "Internal API with payment routes" },
      { id: "n4", label: "Payment Svc", type: "service", detail: "Processes transactions, reads S3" },
      { id: "n5", label: "S3 Data Lake", type: "data", detail: "Public-read enabled bucket with PII" },
    ],
  },
  {
    id: "AP-1003",
    title: "CI/CD Pipeline → Code Injection → Production Deploy",
    riskScore: 74,
    blastRadius: 100,
    reachability: "probable",
    status: "active",
    techniques: ["T1195.001 - Supply Chain: Dev Tools", "T1059 - Command and Scripting Interpreter", "T1072 - Software Deployment Tools"],
    affectedAssets: ["all-production-services", "kubernetes-cluster", "secrets-manager"],
    mitigations: ["Enforce PR approvals for all merges", "Add SAST scan as blocking step", "Restrict CI service account permissions"],
    nodes: [
      { id: "n1", label: "Internet", type: "internet", detail: "Compromised developer account" },
      { id: "n2", label: "GitHub PR", type: "perimeter", detail: "Unsigned commits accepted without review" },
      { id: "n3", label: "CI Executor", type: "vulnerability", detail: "Command injection in build scripts (SAST-1036)" },
      { id: "n4", label: "K8s Cluster", type: "service", detail: "Production deployment target" },
      { id: "n5", label: "All Services", type: "data", detail: "Full cluster compromise" },
    ],
  },
  {
    id: "AP-1004",
    title: "Log4Shell → Analytics Service → Internal Pivot",
    riskScore: 61,
    blastRadius: 45,
    reachability: "theoretical",
    status: "mitigated",
    techniques: ["T1190 - Exploit Public-Facing Application", "T1210 - Exploitation of Remote Services", "T1021 - Remote Services"],
    affectedAssets: ["analytics-service", "internal-network"],
    mitigations: ["Upgrade log4j-core to 2.17.1+", "Add WAF rule for JNDI lookups", "Network segmentation applied"],
    nodes: [
      { id: "n1", label: "Internet", type: "internet", detail: "JNDI injection payload in HTTP header" },
      { id: "n2", label: "Analytics API", type: "vulnerability", detail: "log4j 2.14.1 - CVE-2021-44228 (Critical)" },
      { id: "n3", label: "Internal Net", type: "service", detail: "Analytics service on internal subnet" },
      { id: "n4", label: "LDAP Server", type: "data", detail: "Internal directory service reachable" },
    ],
  },
];

const REACHABILITY_CONFIG = {
  confirmed: { color: "text-red-400", bg: "bg-red-500/10 border-red-500/30", label: "Confirmed" },
  probable: { color: "text-orange-400", bg: "bg-orange-500/10 border-orange-500/30", label: "Probable" },
  theoretical: { color: "text-blue-400", bg: "bg-blue-500/10 border-blue-500/20", label: "Theoretical" },
};

const NODE_TYPE_ICON: Record<PathNode["type"], React.ComponentType<{ className?: string }>> = {
  internet: Globe,
  perimeter: Shield,
  service: Server,
  vulnerability: AlertTriangle,
  data: Database,
};

const NODE_TYPE_COLOR: Record<PathNode["type"], string> = {
  internet: "bg-gray-500/20 border-gray-500/40 text-gray-300",
  perimeter: "bg-blue-500/20 border-blue-500/40 text-blue-300",
  service: "bg-purple-500/20 border-purple-500/40 text-purple-300",
  vulnerability: "bg-red-500/20 border-red-500/40 text-red-300",
  data: "bg-orange-500/20 border-orange-500/40 text-orange-300",
};

function PathFlowDiagram({ path }: { path: AttackPath }) {
  return (
    <div className="flex items-start gap-2 overflow-x-auto pb-2 pt-1">
      {path.nodes.map((node, i) => {
        const Icon = NODE_TYPE_ICON[node.type];
        return (
          <div key={node.id} className="flex items-start gap-2 shrink-0">
            <div className={`rounded-lg border px-3 py-2 min-w-[100px] text-center ${NODE_TYPE_COLOR[node.type]}`}>
              <Icon className="h-4 w-4 mx-auto mb-1 opacity-80" />
              <p className="text-xs font-semibold leading-tight">{node.label}</p>
              <p className="text-xs opacity-60 mt-0.5 leading-tight max-w-[90px] mx-auto">{node.detail.slice(0, 30)}…</p>
            </div>
            {i < path.nodes.length - 1 && (
              <div className="flex flex-col items-center pt-5">
                <ArrowRight className="h-4 w-4 text-red-400 shrink-0" />
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

export default function AttackPaths() {
  const [selectedPath, setSelectedPath] = useState<AttackPath | null>(null);
  const [filterReachability, setFilterReachability] = useState("all");

  const { data } = useQuery({
    queryKey: ["knowledge-graph", "attack-paths"],
    queryFn: () => knowledgeGraphApi.paths({ limit: "20" }),
  });

  void data;

  const paths = MOCK_ATTACK_PATHS;
  const filtered = filterReachability === "all" ? paths : paths.filter((p) => p.reachability === filterReachability);
  const activePaths = paths.filter((p) => p.status === "active").length;
  const criticalPaths = paths.filter((p) => p.riskScore >= 80).length;
  const avgBlastRadius = Math.round(paths.reduce((a, p) => a + p.blastRadius, 0) / paths.length);

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="space-y-6">
      <PageHeader
        title="Attack Paths"
        description="Internet-to-data attack path visualization with blast radius and reachability analysis"
        badge="CTEM"
        actions={
          <>
            <Button variant="outline" size="sm"><Filter className="h-4 w-4 mr-1.5" />Filter</Button>
            <Button size="sm" onClick={() => toast.success("Attack path analysis rerun")}><RefreshCw className="h-4 w-4 mr-1.5" />Reanalyze</Button>
          </>
        }
      />

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Active Attack Paths" value={activePaths} change={1} trend="up" icon={Target} />
        <KpiCard title="Critical Risk Paths" value={criticalPaths} trend="flat" icon={AlertTriangle} />
        <KpiCard title="Avg Blast Radius" value={`${avgBlastRadius}%`} icon={Zap} />
        <KpiCard title="MITRE Techniques" value={12} change={2} trend="up" icon={Shield} />
      </div>

      {/* Filter bar */}
      <div className="flex items-center gap-2">
        <span className="text-sm text-muted-foreground">Reachability:</span>
        {["all", "confirmed", "probable", "theoretical"].map((r) => (
          <Button
            key={r}
            size="sm"
            variant={filterReachability === r ? "default" : "outline"}
            onClick={() => setFilterReachability(r)}
            className="capitalize"
          >
            {r}
          </Button>
        ))}
        <span className="ml-auto text-xs text-muted-foreground">{filtered.length} paths</span>
      </div>

      {/* Path cards */}
      <div className="space-y-4">
        {filtered.map((path) => {
          const rcfg = REACHABILITY_CONFIG[path.reachability];
          return (
            <Card key={path.id} className={`border ${path.status === "active" && path.riskScore >= 80 ? "border-red-500/30" : ""}`}>
              <CardHeader className="pb-3">
                <div className="flex items-start justify-between gap-3">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 flex-wrap">
                      <span className="font-mono text-xs text-muted-foreground">{path.id}</span>
                      <Badge variant={path.status === "active" ? "destructive" : path.status === "mitigated" ? "success" : "warning"}>
                        {path.status}
                      </Badge>
                      <span className={`text-xs font-semibold px-2 py-0.5 rounded-full border ${rcfg.bg} ${rcfg.color}`}>
                        {rcfg.label}
                      </span>
                    </div>
                    <CardTitle className="text-base mt-1.5">{path.title}</CardTitle>
                  </div>
                  <div className="shrink-0 text-right">
                    <div className={`text-2xl font-bold ${path.riskScore >= 80 ? "text-red-400" : path.riskScore >= 60 ? "text-orange-400" : "text-yellow-400"}`}>
                      {path.riskScore}
                    </div>
                    <p className="text-xs text-muted-foreground">Risk Score</p>
                  </div>
                </div>
              </CardHeader>

              <CardContent className="space-y-4">
                {/* Flow diagram */}
                <PathFlowDiagram path={path} />

                {/* Blast radius */}
                <div>
                  <div className="flex items-center justify-between text-xs mb-1.5">
                    <span className="text-muted-foreground flex items-center gap-1"><Zap className="h-3.5 w-3.5" />Blast Radius</span>
                    <span className={`font-semibold ${path.blastRadius >= 80 ? "text-red-400" : path.blastRadius >= 60 ? "text-orange-400" : "text-yellow-400"}`}>
                      {path.blastRadius}% of infrastructure
                    </span>
                  </div>
                  <Progress value={path.blastRadius} className="h-2" />
                </div>

                {/* Techniques & affected assets */}
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div>
                    <p className="text-xs text-muted-foreground uppercase tracking-wider mb-2">MITRE ATT&CK Techniques</p>
                    <div className="flex flex-wrap gap-1.5">
                      {path.techniques.map((t) => (
                        <span key={t} className="text-xs bg-purple-500/10 text-purple-400 border border-purple-500/20 px-2 py-0.5 rounded font-mono">
                          {t.split(" - ")[0]}
                        </span>
                      ))}
                    </div>
                  </div>
                  <div>
                    <p className="text-xs text-muted-foreground uppercase tracking-wider mb-2">Affected Assets ({path.affectedAssets.length})</p>
                    <div className="flex flex-wrap gap-1.5">
                      {path.affectedAssets.map((a) => (
                        <span key={a} className="text-xs bg-muted/30 text-muted-foreground px-2 py-0.5 rounded font-mono">{a}</span>
                      ))}
                    </div>
                  </div>
                </div>

                <div className="flex items-center gap-2 pt-1">
                  <Button size="sm" onClick={() => setSelectedPath(path)}><Eye className="h-4 w-4 mr-1.5" />View Details</Button>
                  <Button size="sm" variant="outline" onClick={() => toast.success("Mitigation playbook opened")}>
                    <Shield className="h-4 w-4 mr-1.5" />Mitigate
                  </Button>
                  <Button size="sm" variant="ghost" onClick={() => toast.info("Path exported to JIRA epic")}>Export</Button>
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* Detail slide-over */}
      <AnimatePresence>
        {selectedPath && (
          <>
            <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} exit={{ opacity: 0 }} className="fixed inset-0 z-40 bg-black/40" onClick={() => setSelectedPath(null)} />
            <motion.aside
              initial={{ x: "100%" }}
              animate={{ x: 0 }}
              exit={{ x: "100%" }}
              transition={{ type: "spring", stiffness: 300, damping: 30 }}
              className="fixed right-0 top-0 z-50 flex h-full w-[520px] flex-col bg-card border-l border-border/50 shadow-2xl"
            >
              <div className="flex items-center justify-between border-b border-border/50 p-5">
                <div>
                  <p className="text-xs font-mono text-muted-foreground">{selectedPath.id}</p>
                  <h2 className="text-sm font-semibold mt-1 max-w-sm leading-snug">{selectedPath.title}</h2>
                </div>
                <button onClick={() => setSelectedPath(null)} className="rounded-md p-1.5 hover:bg-muted/50">
                  <X className="h-4 w-4" />
                </button>
              </div>
              <div className="flex-1 overflow-y-auto p-5 space-y-5">
                <div className="grid grid-cols-3 gap-3 text-center">
                  {[
                    { label: "Risk Score", value: selectedPath.riskScore, color: "text-red-400" },
                    { label: "Blast Radius", value: `${selectedPath.blastRadius}%`, color: "text-orange-400" },
                    { label: "Nodes", value: selectedPath.nodes.length, color: "text-primary" },
                  ].map(({ label, value, color }) => (
                    <div key={label} className="rounded-lg bg-muted/30 p-3">
                      <p className={`text-xl font-bold ${color}`}>{value}</p>
                      <p className="text-xs text-muted-foreground">{label}</p>
                    </div>
                  ))}
                </div>

                <div>
                  <p className="text-xs text-muted-foreground uppercase tracking-wider mb-2">Attack Flow</p>
                  <div className="space-y-2">
                    {selectedPath.nodes.map((node, i) => {
                      const Icon = NODE_TYPE_ICON[node.type];
                      return (
                        <div key={node.id} className="flex items-start gap-3">
                          <div className="flex flex-col items-center">
                            <div className={`rounded-md p-1.5 border ${NODE_TYPE_COLOR[node.type]}`}>
                              <Icon className="h-3.5 w-3.5" />
                            </div>
                            {i < selectedPath.nodes.length - 1 && <div className="w-px h-4 bg-border/50 my-0.5" />}
                          </div>
                          <div className="pb-2">
                            <p className="text-sm font-medium">{node.label}</p>
                            <p className="text-xs text-muted-foreground">{node.detail}</p>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                </div>

                <div>
                  <p className="text-xs text-muted-foreground uppercase tracking-wider mb-2">Recommended Mitigations</p>
                  <ol className="space-y-2">
                    {selectedPath.mitigations.map((m, i) => (
                      <li key={i} className="flex gap-2 text-sm">
                        <span className="text-green-400 font-semibold">{i + 1}.</span>
                        <span className="text-muted-foreground">{m}</span>
                      </li>
                    ))}
                  </ol>
                </div>

                <div>
                  <p className="text-xs text-muted-foreground uppercase tracking-wider mb-2">MITRE ATT&CK</p>
                  <div className="space-y-1.5">
                    {selectedPath.techniques.map((t) => (
                      <div key={t} className="flex items-center gap-2 text-sm">
                        <code className="text-xs bg-purple-500/10 text-purple-400 px-1.5 py-0.5 rounded">{t.split(" - ")[0]}</code>
                        <span className="text-muted-foreground">{t.split(" - ")[1]}</span>
                      </div>
                    ))}
                  </div>
                </div>

                <div className="flex gap-2">
                  <Button size="sm" onClick={() => toast.success("Mitigation plan created")}>Create Mitigation Plan</Button>
                  <Button size="sm" variant="outline" onClick={() => toast.info("Exported to JIRA")}>Export to JIRA</Button>
                </div>
              </div>
            </motion.aside>
          </>
        )}
      </AnimatePresence>
    </motion.div>
  );
}
