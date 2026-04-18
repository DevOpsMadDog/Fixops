/**
 * Container Posture Dashboard
 *
 * Kubernetes cluster security posture with findings tracking.
 *   1. KPIs: Clusters, Avg Posture Score, Open Findings, Clusters at Risk
 *   2. Findings table (cluster_id truncated, namespace, finding_type, severity, title, status)
 *
 * Route: /container-posture
 * API: GET /api/v1/container-posture
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Box, RefreshCw, AlertTriangle, ShieldAlert, Server, BarChart2 } from "lucide-react";

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
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string, opts?: RequestInit) {
  const res = await fetch(`${API_BASE}${path}`, {
    ...opts,
    headers: { "X-API-Key": API_KEY, "Content-Type": "application/json", ...(opts?.headers ?? {}) },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// == Mock data ==================================================

const MOCK_FINDINGS = [
  { id: "fin-001", cluster_id: "cluster-prod-us-east-1a2b3c4d", namespace: "kube-system",   finding_type: "RBAC Misconfiguration",     severity: "critical", title: "Cluster-admin binding to service account", status: "open"        },
  { id: "fin-002", cluster_id: "cluster-prod-us-east-1a2b3c4d", namespace: "default",       finding_type: "Privileged Container",       severity: "high",     title: "Container running as root",                status: "in_progress" },
  { id: "fin-003", cluster_id: "cluster-prod-eu-west-9f8e7d6c", namespace: "monitoring",    finding_type: "Image Vulnerability",        severity: "critical", title: "Log4Shell in prometheus-jmx:v1.2",         status: "open"        },
  { id: "fin-004", cluster_id: "cluster-staging-3c4d5e6f7a8b",  namespace: "ingress-nginx", finding_type: "Network Policy Gap",         severity: "high",     title: "No egress policy on ingress namespace",    status: "open"        },
  { id: "fin-005", cluster_id: "cluster-prod-eu-west-9f8e7d6c", namespace: "payment-svc",   finding_type: "Secret in ENV",              severity: "critical", title: "DB_PASSWORD exposed in pod spec",          status: "open"        },
  { id: "fin-006", cluster_id: "cluster-prod-us-east-1a2b3c4d", namespace: "api-gateway",   finding_type: "Resource Limit Missing",     severity: "medium",   title: "No CPU/memory limits on api-gateway pods", status: "resolved"    },
  { id: "fin-007", cluster_id: "cluster-dev-1a2b3c4d5e6f7a8b",  namespace: "test",          finding_type: "Image Pull Policy",          severity: "low",      title: "imagePullPolicy: Never in test namespace", status: "resolved"    },
  { id: "fin-008", cluster_id: "cluster-prod-us-east-1a2b3c4d", namespace: "data-pipeline", finding_type: "Host Path Mount",            severity: "high",     title: "hostPath volume mount to /etc",            status: "in_progress" },
  { id: "fin-009", cluster_id: "cluster-prod-eu-west-9f8e7d6c", namespace: "auth-service",  finding_type: "Pod Security Policy",        severity: "medium",   title: "PSP not enforced for auth namespace",      status: "open"        },
  { id: "fin-010", cluster_id: "cluster-staging-3c4d5e6f7a8b",  namespace: "ci-runners",    finding_type: "Writable Filesystem",        severity: "medium",   title: "readOnlyRootFilesystem not set",           status: "open"        },
];

const MOCK_STATS = {
  clusters: 8,
  avg_posture_score: 67.4,
  open_findings: 143,
  clusters_at_risk: 3,
};

// == Badge helpers ==============================================

function SeverityBadge({ severity }: { severity: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
    medium:   "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    low:      "border-zinc-500/30 text-zinc-400 bg-zinc-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[severity] ?? "border-border")}>
      {severity}
    </Badge>
  );
}

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    open:        "border-purple-500/30 text-purple-400 bg-purple-500/10",
    in_progress: "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    resolved:    "border-green-500/30 text-green-400 bg-green-500/10",
  };
  const label = status.replace(/_/g, " ");
  return (
    <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border")}>
      {label}
    </Badge>
  );
}

function truncateId(id: string) {
  return id.length > 20 ? `${id.slice(0, 18)}=` : id;
}

// == Component ==================================================

export default function ContainerPostureDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveFindings, setLiveFindings] = useState<any[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [liveStats, setLiveStats]       = useState<any | null>(null);

  useEffect(() => {
    Promise.allSettled([
      apiFetch(`/api/v1/container-posture/findings?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/container-posture/stats?org_id=${ORG_ID}`),
    ]).then(([findRes, statsRes]) => {
      if (findRes.status === "fulfilled")  setLiveFindings(findRes.value?.findings ?? findRes.value ?? null);
      if (statsRes.status === "fulfilled") setLiveStats(statsRes.value ?? null);
    })
      .finally(() => setLoading(false));
  }, []);

  const handleRefresh = () => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); };

  const findings = liveFindings ?? MOCK_FINDINGS;
  const stats    = liveStats    ?? MOCK_STATS;

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
      <PageHeader
        title="Container Posture"
        description="Kubernetes cluster security posture = RBAC misconfigs, image vulnerabilities, network policy gaps, and runtime findings"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Clusters"          value={stats.clusters}                        icon={Server}      trend="flat" className="border-purple-500/20" />
        <KpiCard title="Avg Posture Score" value={`${stats.avg_posture_score}/100`}      icon={ShieldAlert} trend="up"   className="border-violet-500/20" />
        <KpiCard title="Open Findings"     value={stats.open_findings}                   icon={AlertTriangle} trend="down" className="border-purple-500/20" />
        <KpiCard title="Clusters at Risk"  value={stats.clusters_at_risk}                icon={Box}         trend="down" className="border-violet-500/20" />
      </div>

      {/* Findings Table */}
      <Card className="border-purple-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-purple-400">
              <BarChart2 className="h-4 w-4" />
              Cluster Findings
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
              {findings.filter((f: any) => f.severity === "critical").length} critical
            </Badge>
          </div>
          <CardDescription className="text-xs">
            Security findings across Kubernetes clusters with namespace, finding type, severity, and remediation status
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Cluster ID</TableHead>
                  <TableHead className="text-[11px] h-8">Namespace</TableHead>
                  <TableHead className="text-[11px] h-8">Finding Type</TableHead>
                  <TableHead className="text-[11px] h-8">Severity</TableHead>
                  <TableHead className="text-[11px] h-8">Title</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {findings.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  findings.map((finding: any, i: number) => (
                  <TableRow key={finding.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-mono text-[10px] text-purple-300">
                      {truncateId(finding.cluster_id ?? "=")}
                    </TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-violet-300">
                      {finding.namespace ?? "="}
                    </TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">
                      {finding.finding_type ?? "="}
                    </TableCell>
                    <TableCell className="py-2">
                      <SeverityBadge severity={finding.severity ?? "low"} />
                    </TableCell>
                    <TableCell className="py-2 text-[11px] text-foreground max-w-[200px] truncate">
                      {finding.title ?? "="}
                    </TableCell>
                    <TableCell className="py-2 text-right">
                      <StatusBadge status={finding.status ?? "open"} />
                    </TableCell>
                  </TableRow>
                ))
              )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
