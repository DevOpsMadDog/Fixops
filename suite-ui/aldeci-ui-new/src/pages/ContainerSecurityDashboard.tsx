/**
 * Container Security Dashboard
 *
 * Container inventory, vulnerability findings, runtime alerts, and K8s context.
 *   1. KPIs: Total Containers, Vulnerable, Critical Vulns, Privileged Containers
 *   2. Container inventory table: name, image, status, risk score, vuln count, privileged
 *   3. Vulnerability findings: CVE ID, container, severity, fix available
 *   4. Runtime alerts: anomaly type, container, description, timestamp
 *   5. K8s context panel: namespace, pod, node
 *
 * API: /api/v1/containers (POST endpoints — image analysis, policies, drift, CIS benchmark)
 * Inventory uses mock data fallback as API has no GET /containers list endpoint.
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Box,
  AlertTriangle,
  Shield,
  RefreshCw,
  Activity,
  Server,
  Bug,
  Cpu,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";

async function apiFetch(path: string, method = "GET", body?: unknown) {
  const res = await fetch(`${API_BASE}${path}`, {
    method,
    headers: { "X-API-Key": API_KEY, "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ── Mock data ──────────────────────────────────────────────────

const CONTAINERS = [
  { id: "cnt-001", name: "api-gateway",       image: "nginx:1.24-alpine",          status: "running", risk_score: 22, vuln_count: 2,  privileged: false, namespace: "prod",     node: "node-01" },
  { id: "cnt-002", name: "auth-service",      image: "aldeci/auth:2.1.4",          status: "running", risk_score: 38, vuln_count: 4,  privileged: false, namespace: "prod",     node: "node-01" },
  { id: "cnt-003", name: "brain-pipeline",    image: "aldeci/brain:3.0.1",         status: "running", risk_score: 61, vuln_count: 7,  privileged: false, namespace: "prod",     node: "node-02" },
  { id: "cnt-004", name: "redis-cache",       image: "redis:7.0",                  status: "running", risk_score: 14, vuln_count: 1,  privileged: false, namespace: "infra",    node: "node-02" },
  { id: "cnt-005", name: "legacy-scanner",    image: "scanner:1.0-debian9",        status: "running", risk_score: 88, vuln_count: 23, privileged: true,  namespace: "security", node: "node-03" },
  { id: "cnt-006", name: "trustgraph-mcp",    image: "aldeci/trustgraph:1.2.0",    status: "stopped", risk_score: 31, vuln_count: 3,  privileged: false, namespace: "ai",       node: "node-03" },
];

const VULNERABILITIES = [
  { id: "CVE-2024-21626", container: "legacy-scanner",  severity: "critical", fix_available: true,  description: "runc container escape — container breakout" },
  { id: "CVE-2023-44487", container: "api-gateway",     severity: "high",     fix_available: true,  description: "HTTP/2 rapid reset DDoS vulnerability" },
  { id: "CVE-2024-3094",  container: "legacy-scanner",  severity: "critical", fix_available: true,  description: "XZ utils backdoor in liblzma" },
  { id: "CVE-2023-46234", container: "brain-pipeline",  severity: "high",     fix_available: false, description: "Node.js crypto module timing attack" },
  { id: "CVE-2024-27983", container: "auth-service",    severity: "high",     fix_available: true,  description: "Node.js HTTP request smuggling" },
  { id: "CVE-2023-51385", container: "legacy-scanner",  severity: "medium",   fix_available: true,  description: "OpenSSH ProxyCommand injection" },
  { id: "CVE-2024-1086",  container: "legacy-scanner",  severity: "critical", fix_available: true,  description: "Linux kernel use-after-free in netfilter" },
  { id: "CVE-2023-4911",  container: "brain-pipeline",  severity: "high",     fix_available: true,  description: "glibc buffer overflow (Looney Tunables)" },
];

const RUNTIME_ALERTS = [
  { id: "RA-001", anomaly_type: "process_injection",   container: "legacy-scanner",  description: "Unexpected ptrace syscall detected",              ts: "14:47:22" },
  { id: "RA-002", anomaly_type: "file_modification",   container: "brain-pipeline",  description: "/etc/passwd modified at runtime",                 ts: "14:39:11" },
  { id: "RA-003", anomaly_type: "network_anomaly",     container: "auth-service",    description: "Outbound connection to 185.220.101.34:4444",      ts: "14:31:05" },
  { id: "RA-004", anomaly_type: "privilege_escalation",container: "legacy-scanner",  description: "setuid binary executed: /usr/bin/sudo",           ts: "14:22:48" },
];

const K8S_CONTEXTS = [
  { namespace: "prod",     pod_count: 12, node: "node-01,node-02", status: "healthy"  },
  { namespace: "security", pod_count: 4,  node: "node-03",          status: "warning"  },
  { namespace: "infra",    pod_count: 6,  node: "node-02",          status: "healthy"  },
  { namespace: "ai",       pod_count: 3,  node: "node-03",          status: "degraded" },
];

// ── Helpers ──────────────────────────────────────────────────

function ContainerStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    running: "border-green-500/30 text-green-400 bg-green-500/10",
    stopped: "border-slate-500/30 text-slate-400 bg-slate-500/10",
    failed:  "border-red-500/30 text-red-400 bg-red-500/10",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border")}>{status}</Badge>;
}

function SevBadge({ sev }: { sev: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-amber-500/30 text-amber-400 bg-amber-500/10",
    medium:   "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    low:      "border-slate-500/30 text-slate-400 bg-slate-500/10",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[sev] ?? "border-border")}>{sev}</Badge>;
}

function AlertTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    process_injection:    "border-red-500/30 text-red-400 bg-red-500/10",
    file_modification:    "border-amber-500/30 text-amber-400 bg-amber-500/10",
    network_anomaly:      "border-purple-500/30 text-purple-400 bg-purple-500/10",
    privilege_escalation: "border-orange-500/30 text-orange-400 bg-orange-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border font-mono", map[type] ?? "border-border text-muted-foreground")}>
      {type.replace(/_/g, " ")}
    </Badge>
  );
}

function K8sStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    healthy:  "border-green-500/30 text-green-400 bg-green-500/10",
    warning:  "border-amber-500/30 text-amber-400 bg-amber-500/10",
    degraded: "border-red-500/30 text-red-400 bg-red-500/10",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border")}>{status}</Badge>;
}

function RiskBar({ score, idx }: { score: number; idx: number }) {
  return (
    <div className="flex items-center gap-1.5">
      <div className="relative flex-1 h-1.5 rounded-full bg-muted/30 overflow-hidden min-w-[40px]">
        <motion.div
          initial={{ width: 0 }}
          animate={{ width: `${score}%` }}
          transition={{ duration: 0.5, delay: idx * 0.05 }}
          className={cn("h-full rounded-full", score >= 75 ? "bg-red-500" : score >= 50 ? "bg-amber-500" : "bg-green-500")}
        />
      </div>
      <span className={cn("text-xs font-bold tabular-nums w-5 text-right", score >= 75 ? "text-red-400" : score >= 50 ? "text-amber-400" : "text-green-400")}>
        {score}
      </span>
    </div>
  );
}

// ── Component ────────────────────────────────────────────────

export default function ContainerSecurityDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [policies, setPolicies] = useState<any[]>([]);
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);
  const [loading, setLoading] = useState(true);

  const loadData = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch("/api/v1/containers/policies"),
      apiFetch("/api/v1/k8s/posture"),
      apiFetch("/api/v1/k8s/findings?limit=50"),
    ]).then(([policiesRes, postureRes, findingsRes]) => {
      if (policiesRes.status === "fulfilled" && policiesRes.value?.policies) {
        setPolicies(policiesRes.value.policies);
      }
      const posture  = postureRes.status  === "fulfilled" ? postureRes.value  : null;
      const findings = findingsRes.status === "fulfilled" ? findingsRes.value : null;
      if (posture || findings) {
        setLiveData({ posture, findings });
      }
    }).finally(() => setDataLoading(false));
  };

  useEffect(() => { loadData(); 
    setLoading(false);}, []);

  // KPI values — live posture with mock fallback
  const totalContainers      = liveData?.posture?.total_checks      ?? CONTAINERS.length;
  const vulnerable           = liveData?.posture?.failed_checks     ?? CONTAINERS.filter((c) => c.vuln_count > 0).length;
  const criticalVulns        = liveData?.posture?.critical_findings  ?? VULNERABILITIES.filter((v) => v.severity === "critical").length;
  const privilegedContainers = liveData?.posture?.high_findings      ?? CONTAINERS.filter((c) => c.privileged).length;

  // Findings — map live findings to display shape, fall back to mock
  const displayVulns: typeof VULNERABILITIES = liveData?.findings?.findings?.length
    ? liveData.findings.findings.slice(0, 8).map((f: any) => ({
        id:            f.check_id ?? f.id ?? "FINDING",
        container:     f.resource_name ?? f.namespace ?? "unknown",
        severity:      f.severity ?? "medium",
        fix_available: f.remediation != null,
        description:   f.title ?? f.description ?? "",
      }))
    : VULNERABILITIES;

  const handleRefresh = () => {
    setRefreshing(true);
    loadData();
    setTimeout(() => setRefreshing(false), 800);
  };

  if (loading) return (
    <div className="space-y-4 p-6">
      {[1, 2, 3].map((i) => (
        <div key={i} className="h-24 rounded-lg bg-zinc-800/50 animate-pulse" />
      ))}
    </div>
  );

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      {/* Header */}
      <PageHeader
        title="Container Security"
        description="Container inventory, vulnerability findings, runtime alerts, and Kubernetes context"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title={liveData?.posture ? "Total Checks" : "Total Containers"}    value={totalContainers}      icon={Box}          trend="up"   />
        <KpiCard title={liveData?.posture ? "Failed Checks" : "Vulnerable"}         value={vulnerable}           icon={AlertTriangle} trend="up"   className="border-amber-500/20" />
        <KpiCard title="Critical Findings"                                           value={criticalVulns}        icon={Bug}          trend="up"   className="border-red-500/20" />
        <KpiCard title={liveData?.posture ? "High Findings" : "Privileged"}         value={privilegedContainers} icon={Shield}       trend="down" className="border-orange-500/20" />
      </div>

      {/* Container Inventory */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Box className="h-4 w-4 text-blue-400" />
              Container Inventory
            </CardTitle>
            <Badge className="text-[10px] border border-border text-muted-foreground">{totalContainers} containers</Badge>
          </div>
          <CardDescription className="text-xs">Running and stopped containers with risk score and vulnerability count</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Name</TableHead>
                  <TableHead className="text-[11px] h-8">Image</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8 min-w-[100px]">Risk Score</TableHead>
                  <TableHead className="text-[11px] h-8 text-center">Vulns</TableHead>
                  <TableHead className="text-[11px] h-8 text-center">Privileged</TableHead>
                  <TableHead className="text-[11px] h-8">Namespace</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {CONTAINERS.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  CONTAINERS.map((c, i) => (
                  <TableRow key={c.id} className="hover:bg-muted/30">
                    <TableCell className="py-2 text-xs font-medium font-mono">{c.name}</TableCell>
                    <TableCell className="py-2 font-mono text-[10px] text-muted-foreground max-w-[160px] truncate">{c.image}</TableCell>
                    <TableCell className="py-2"><ContainerStatusBadge status={c.status} /></TableCell>
                    <TableCell className="py-2 min-w-[100px]"><RiskBar score={c.risk_score} idx={i} /></TableCell>
                    <TableCell className="py-2 text-center">
                      <span className={cn("text-xs font-bold tabular-nums", c.vuln_count > 10 ? "text-red-400" : c.vuln_count > 3 ? "text-amber-400" : "text-muted-foreground")}>
                        {c.vuln_count}
                      </span>
                    </TableCell>
                    <TableCell className="py-2 text-center">
                      {c.privileged
                        ? <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">Yes</Badge>
                        : <span className="text-[10px] text-muted-foreground">No</span>
                      }
                    </TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground font-mono">{c.namespace}</TableCell>
                  </TableRow>
                ))
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Vulns + Runtime Alerts */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Vulnerability Findings */}
        <Card className="border-red-500/20">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
              <Bug className="h-4 w-4" />
              Vulnerability Findings
            </CardTitle>
            <CardDescription className="text-xs">CVEs detected across container images</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">CVE ID</TableHead>
                  <TableHead className="text-[11px] h-8">Container</TableHead>
                  <TableHead className="text-[11px] h-8">Severity</TableHead>
                  <TableHead className="text-[11px] h-8 text-center">Fix</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {displayVulns.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  displayVulns.map((v) => (
                  <TableRow key={v.id} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-mono text-[11px] text-blue-400">{v.id}</TableCell>
                    <TableCell className="py-2 font-mono text-[10px] text-muted-foreground">{v.container}</TableCell>
                    <TableCell className="py-2"><SevBadge sev={v.severity} /></TableCell>
                    <TableCell className="py-2 text-center">
                      {v.fix_available
                        ? <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">Available</Badge>
                        : <Badge className="text-[10px] border border-slate-500/30 text-slate-400 bg-slate-500/10">N/A</Badge>
                      }
                    </TableCell>
                  </TableRow>
                ))
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>

        {/* Runtime Alerts + K8s Context */}
        <div className="flex flex-col gap-4">
          {/* Runtime Alerts */}
          <Card className="border-amber-500/20">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold flex items-center gap-2 text-amber-400">
                <Activity className="h-4 w-4" />
                Runtime Alerts
              </CardTitle>
              <CardDescription className="text-xs">Anomalous behaviors detected at runtime</CardDescription>
            </CardHeader>
            <CardContent className="space-y-2">
              {RUNTIME_ALERTS.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                  <p className="text-lg font-medium">No data available</p>
                  <p className="text-sm">Data will appear here once available</p>
                </div>
              ) : (
                RUNTIME_ALERTS.map((a) => (
                <div key={a.id} className="rounded-lg border border-border bg-muted/20 p-3 space-y-1.5">
                  <div className="flex items-center justify-between gap-2">
                    <AlertTypeBadge type={a.anomaly_type} />
                    <span className="text-[10px] tabular-nums text-muted-foreground">{a.ts}</span>
                  </div>
                  <div className="font-mono text-[11px] text-blue-400">{a.container}</div>
                  <div className="text-[11px] text-muted-foreground">{a.description}</div>
                </div>
              ))
              )}
            </CardContent>
          </Card>

          {/* K8s Context */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <Cpu className="h-4 w-4 text-purple-400" />
                Kubernetes Context
              </CardTitle>
              <CardDescription className="text-xs">Namespace, pod count, and node assignments</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 gap-2">
                {K8S_CONTEXTS.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  K8S_CONTEXTS.map((ctx) => (
                  <div key={ctx.namespace} className="rounded-lg border border-border bg-muted/20 p-3 space-y-1.5">
                    <div className="flex items-center justify-between gap-1">
                      <span className="font-mono text-xs font-semibold">{ctx.namespace}</span>
                      <K8sStatusBadge status={ctx.status} />
                    </div>
                    <div className="flex items-center gap-1 text-[10px] text-muted-foreground">
                      <Server className="h-3 w-3" />
                      <span>{ctx.node}</span>
                    </div>
                    <div className="text-[10px] text-muted-foreground">
                      Pods: <span className="text-foreground font-semibold">{ctx.pod_count}</span>
                    </div>
                  </div>
                ))
                )}
              </div>
            </CardContent>
          </Card>
        </div>
      </div>

      {/* Runtime Policies (live from API if available) */}
      {policies.length > 0 && (
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Shield className="h-4 w-4 text-green-400" />
              Runtime Policies
            </CardTitle>
            <CardDescription className="text-xs">Active container security policies from /api/v1/containers/policies</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Policy Name</TableHead>
                  <TableHead className="text-[11px] h-8 text-center">Allow Root</TableHead>
                  <TableHead className="text-[11px] h-8 text-center">Signed Images</TableHead>
                  <TableHead className="text-[11px] h-8 text-center">Max Size (MB)</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {policies.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  policies.map((p: any) => (
                  <TableRow key={p.id ?? p.name} className="hover:bg-muted/30">
                    <TableCell className="py-2 text-xs font-medium">{p.name}</TableCell>
                    <TableCell className="py-2 text-center">
                      {p.allow_root_user
                        ? <Badge className="text-[10px] border border-amber-500/30 text-amber-400 bg-amber-500/10">Yes</Badge>
                        : <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">No</Badge>
                      }
                    </TableCell>
                    <TableCell className="py-2 text-center">
                      {p.require_signed_images
                        ? <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">Required</Badge>
                        : <Badge className="text-[10px] border border-slate-500/30 text-slate-400 bg-slate-500/10">Optional</Badge>
                      }
                    </TableCell>
                    <TableCell className="py-2 text-center text-xs tabular-nums text-muted-foreground">{p.max_image_size_mb ?? "—"}</TableCell>
                  </TableRow>
                ))
                )}
              </TableBody>
            </Table>
          </CardContent>
        </Card>
      )}
    </motion.div>
  );
}
