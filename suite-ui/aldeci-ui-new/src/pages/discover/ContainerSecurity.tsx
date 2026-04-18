/**
 * Container Security Dashboard
 *
 * Image scanning, runtime threats, and Kubernetes security posture:
 *   1. KPIs: Images Scanned, Critical Vulns, Running Containers, Policy Violations
 *   2. Image Vulnerability Table (10 rows)
 *   3. Runtime Threats feed (5 events)
 *   4. Kubernetes Security posture cards (RBAC, Pod Security, Network Policies)
 *   5. Policy Violations table
 *   6. Registry health grid
 *
 * Route: /discover/containers
 * API: GET /api/v1/container-security/images, GET /api/v1/container-security/runtime-threats (mock fallback)
 */

import { motion } from "framer-motion";
import {
  Shield, AlertTriangle, Container, Activity,
  Clock, CheckCircle2, XCircle, AlertCircle,
  Package, Server, Lock,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── Types ────────────────────────────────────────────────────────

type ImageStatus = "Clean" | "At Risk" | "Critical";
type ThreatSeverity = "critical" | "high" | "medium";
type ViolationSeverity = "high" | "medium" | "low";

interface ImageRow {
  image_name: string;
  tag: string;
  registry: string;
  critical_vulns: number;
  high_vulns: number;
  size_mb: number;
  last_scanned: string;
  status: ImageStatus;
}

interface RuntimeEvent {
  timestamp: string;
  container_id: string;
  threat_type: string;
  severity: ThreatSeverity;
  action: string;
}

interface K8sPosture {
  label: string;
  score: number;
  icon: typeof Shield;
}

interface PolicyViolation {
  container_name: string;
  violation_type: string;
  severity: ViolationSeverity;
  namespace: string;
}

// ── Mock Data ────────────────────────────────────────────────────

const IMAGES: ImageRow[] = [
  { image_name: "nginx",         tag: "latest",       registry: "Docker Hub",      critical_vulns: 3,  high_vulns: 7,  size_mb: 187,  last_scanned: "2026-04-16 08:14", status: "At Risk"  },
  { image_name: "python",        tag: "3.11",         registry: "Docker Hub",      critical_vulns: 0,  high_vulns: 2,  size_mb: 923,  last_scanned: "2026-04-16 07:45", status: "Clean"    },
  { image_name: "node",          tag: "18-alpine",    registry: "Docker Hub",      critical_vulns: 1,  high_vulns: 4,  size_mb: 174,  last_scanned: "2026-04-16 07:30", status: "At Risk"  },
  { image_name: "redis",         tag: "7",            registry: "Docker Hub",      critical_vulns: 0,  high_vulns: 0,  size_mb: 138,  last_scanned: "2026-04-16 06:58", status: "Clean"    },
  { image_name: "postgres",      tag: "15",           registry: "ECR",             critical_vulns: 0,  high_vulns: 2,  size_mb: 379,  last_scanned: "2026-04-16 06:20", status: "Clean"    },
  { image_name: "custom/api",    tag: "v2.1",         registry: "Internal Harbor", critical_vulns: 7,  high_vulns: 12, size_mb: 512,  last_scanned: "2026-04-15 23:41", status: "Critical" },
  { image_name: "grafana",       tag: "10.2.3",       registry: "GCR",             critical_vulns: 0,  high_vulns: 1,  size_mb: 461,  last_scanned: "2026-04-15 22:10", status: "Clean"    },
  { image_name: "prometheus",    tag: "v2.50.1",      registry: "GCR",             critical_vulns: 0,  high_vulns: 0,  size_mb: 245,  last_scanned: "2026-04-15 21:55", status: "Clean"    },
  { image_name: "elasticsearch", tag: "8.12.0",       registry: "ECR",             critical_vulns: 2,  high_vulns: 5,  size_mb: 1240, last_scanned: "2026-04-15 20:30", status: "At Risk"  },
  { image_name: "fluentd",       tag: "v1.16-debian", registry: "Docker Hub",      critical_vulns: 0,  high_vulns: 3,  size_mb: 868,  last_scanned: "2026-04-15 19:12", status: "Clean"    },
];

const RUNTIME_EVENTS: RuntimeEvent[] = [
  { timestamp: "2026-04-16 09:02", container_id: "a3f8e1b2c4d5", threat_type: "Privilege escalation", severity: "critical", action: "Killed"   },
  { timestamp: "2026-04-16 08:47", container_id: "7c9d2e4f6a1b", threat_type: "Cryptominer",          severity: "high",     action: "Killed"   },
  { timestamp: "2026-04-16 08:31", container_id: "b2e5f7a9c0d3", threat_type: "Shell spawn",          severity: "medium",   action: "Alerting" },
  { timestamp: "2026-04-16 07:55", container_id: "d4a1f3e8b6c9", threat_type: "Sensitive mount",      severity: "high",     action: "Alerting" },
  { timestamp: "2026-04-16 07:18", container_id: "e6c0d2a4f1b8", threat_type: "Reverse shell",        severity: "critical", action: "Killed"   },
];

const K8S_POSTURE: K8sPosture[] = [
  { label: "RBAC Score",        score: 72, icon: Lock    },
  { label: "Pod Security",      score: 58, icon: Shield  },
  { label: "Network Policies",  score: 43, icon: Server  },
];

const POLICY_VIOLATIONS: PolicyViolation[] = [
  { container_name: "custom-api-v2",    violation_type: "Running as root",      severity: "high",   namespace: "production" },
  { container_name: "legacy-worker",    violation_type: "Privileged",           severity: "high",   namespace: "default"    },
  { container_name: "log-aggregator",   violation_type: "No resource limits",   severity: "medium", namespace: "monitoring" },
  { container_name: "sidecar-proxy",    violation_type: "Missing readiness probe", severity: "low", namespace: "staging"    },
  { container_name: "batch-processor",  violation_type: "Running as root",      severity: "high",   namespace: "jobs"       },
];

const REGISTRIES = [
  { name: "Docker Hub",      type: "public",  secure: false },
  { name: "ECR",             type: "private", secure: true  },
  { name: "GCR",             type: "private", secure: true  },
  { name: "Internal Harbor", type: "private", secure: true  },
];

// ── Helpers ──────────────────────────────────────────────────────

const SEV_COLORS: Record<ThreatSeverity, string> = {
  critical: "bg-red-500/10 text-red-400 border-red-500/30",
  high:     "bg-orange-500/10 text-orange-400 border-orange-500/30",
  medium:   "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
};

const VSEV_COLORS: Record<ViolationSeverity, string> = {
  high:   "bg-red-500/10 text-red-400 border-red-500/30",
  medium: "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
  low:    "bg-blue-500/10 text-blue-400 border-blue-500/30",
};

const STATUS_COLORS: Record<ImageStatus, string> = {
  Clean:    "bg-green-500/10 text-green-400 border-green-500/20",
  "At Risk": "bg-orange-500/10 text-orange-400 border-orange-500/20",
  Critical: "bg-red-500/10 text-red-400 border-red-500/20",
};

function k8sColor(score: number): string {
  if (score >= 70) return "text-green-400";
  if (score >= 50) return "text-yellow-400";
  return "text-red-400";
}

function k8sBorder(score: number): string {
  if (score >= 70) return "border-green-500/30 bg-green-500/5";
  if (score >= 50) return "border-yellow-500/30 bg-yellow-500/5";
  return "border-red-500/30 bg-red-500/5";
}

// ── Component ────────────────────────────────────────────────────

export default function ContainerSecurity() {
  return (
    <div className="min-h-screen bg-slate-900 p-8 space-y-8">
      <PageHeader
        title="Container Security"
        description="Image scanning, runtime threats, and Kubernetes security posture"
      />

      {/* KPIs */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Images Scanned"      value={234} icon={Package}       />
        <KpiCard title="Critical Vulns"      value={18}  icon={AlertTriangle} />
        <KpiCard title="Running Containers"  value={847} icon={Container}     />
        <KpiCard title="Policy Violations"   value={23}  icon={AlertCircle}   />
      </div>

      {/* Image Vulnerability Table */}
      <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }}>
        <Card className="border-slate-700">
          <CardHeader className="border-b border-slate-700">
            <CardTitle className="flex items-center gap-2">
              <Package className="w-5 h-5 text-blue-400" />
              Image Vulnerability Scan
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <Table>
                <TableHeader className="bg-slate-800/50 border-b border-slate-700">
                  <TableRow>
                    <TableHead className="text-slate-300">Image</TableHead>
                    <TableHead className="text-slate-300">Tag</TableHead>
                    <TableHead className="text-slate-300">Registry</TableHead>
                    <TableHead className="text-slate-300 text-right">Critical</TableHead>
                    <TableHead className="text-slate-300 text-right">High</TableHead>
                    <TableHead className="text-slate-300 text-right">Size (MB)</TableHead>
                    <TableHead className="text-slate-300">Last Scanned</TableHead>
                    <TableHead className="text-slate-300">Status</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {IMAGES.map((img, idx) => (
                    <motion.tr
                      key={`${img.image_name}-${img.tag}`}
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      transition={{ delay: idx * 0.04 }}
                      className="border-b border-slate-700/50 hover:bg-slate-800/30 transition-colors"
                    >
                      <TableCell className="font-mono text-sm text-slate-200">{img.image_name}</TableCell>
                      <TableCell className="font-mono text-xs text-slate-400">{img.tag}</TableCell>
                      <TableCell className="text-sm text-slate-300">{img.registry}</TableCell>
                      <TableCell className="text-right font-mono text-sm">
                        <span className={img.critical_vulns > 0 ? "text-red-400 font-bold" : "text-slate-500"}>{img.critical_vulns}</span>
                      </TableCell>
                      <TableCell className="text-right font-mono text-sm">
                        <span className={img.high_vulns > 0 ? "text-orange-400" : "text-slate-500"}>{img.high_vulns}</span>
                      </TableCell>
                      <TableCell className="text-right font-mono text-xs text-slate-400">{img.size_mb}</TableCell>
                      <TableCell className="text-xs text-slate-400">
                        <div className="flex items-center gap-1">
                          <Clock className="w-3 h-3" />
                          {img.last_scanned}
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge className={cn("border text-xs", STATUS_COLORS[img.status])}>{img.status}</Badge>
                      </TableCell>
                    </motion.tr>
                  ))}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* Runtime Threats + K8s Posture */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Runtime Threats Feed */}
        <motion.div
          initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.2 }}
          className="lg:col-span-2"
        >
          <Card className="border-slate-700">
            <CardHeader className="border-b border-slate-700">
              <CardTitle className="flex items-center gap-2">
                <Activity className="w-5 h-5 text-red-400" />
                Runtime Threats
              </CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              <Table>
                <TableHeader className="bg-slate-800/50 border-b border-slate-700">
                  <TableRow>
                    <TableHead className="text-slate-300">Timestamp</TableHead>
                    <TableHead className="text-slate-300">Container</TableHead>
                    <TableHead className="text-slate-300">Threat Type</TableHead>
                    <TableHead className="text-slate-300">Severity</TableHead>
                    <TableHead className="text-slate-300">Action</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {RUNTIME_EVENTS.map((evt, idx) => (
                    <motion.tr
                      key={idx}
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      transition={{ delay: 0.2 + idx * 0.05 }}
                      className="border-b border-slate-700/50 hover:bg-slate-800/30 transition-colors"
                    >
                      <TableCell className="font-mono text-xs text-slate-400">{evt.timestamp}</TableCell>
                      <TableCell className="font-mono text-xs text-slate-300">{evt.container_id.slice(0, 8)}…</TableCell>
                      <TableCell className="text-sm text-slate-200">{evt.threat_type}</TableCell>
                      <TableCell>
                        <Badge className={cn("border text-xs capitalize", SEV_COLORS[evt.severity])}>{evt.severity}</Badge>
                      </TableCell>
                      <TableCell>
                        <Badge className={cn("border text-xs", evt.action === "Killed" ? "bg-red-500/10 text-red-400 border-red-500/30" : "bg-yellow-500/10 text-yellow-400 border-yellow-500/30")}>
                          {evt.action}
                        </Badge>
                      </TableCell>
                    </motion.tr>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </motion.div>

        {/* Kubernetes Security Posture */}
        <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.3 }}>
          <Card className="border-slate-700 h-full">
            <CardHeader className="border-b border-slate-700">
              <CardTitle className="flex items-center gap-2 text-base">
                <Shield className="w-5 h-5 text-cyan-400" />
                Kubernetes Posture
              </CardTitle>
            </CardHeader>
            <CardContent className="p-6 space-y-4">
              {K8S_POSTURE.map((item) => {
                const Icon = item.icon;
                return (
                  <div key={item.label} className={cn("p-4 rounded-lg border-2", k8sBorder(item.score))}>
                    <div className="flex items-center justify-between mb-2">
                      <div className="flex items-center gap-2">
                        <Icon className={cn("w-4 h-4", k8sColor(item.score))} />
                        <span className="text-sm font-semibold text-slate-200">{item.label}</span>
                      </div>
                      <span className={cn("text-2xl font-bold font-mono", k8sColor(item.score))}>{item.score}%</span>
                    </div>
                    <div className="w-full bg-slate-700 rounded-full h-2">
                      <div
                        className={cn("h-2 rounded-full transition-all", item.score >= 70 ? "bg-green-400" : item.score >= 50 ? "bg-yellow-400" : "bg-red-400")}
                        style={{ width: `${item.score}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </CardContent>
          </Card>
        </motion.div>
      </div>

      {/* Policy Violations + Registry Health */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Policy Violations */}
        <motion.div
          initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.4 }}
          className="lg:col-span-2"
        >
          <Card className="border-slate-700">
            <CardHeader className="border-b border-slate-700">
              <CardTitle className="flex items-center gap-2">
                <AlertTriangle className="w-5 h-5 text-orange-400" />
                Policy Violations
              </CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              <Table>
                <TableHeader className="bg-slate-800/50 border-b border-slate-700">
                  <TableRow>
                    <TableHead className="text-slate-300">Container</TableHead>
                    <TableHead className="text-slate-300">Violation</TableHead>
                    <TableHead className="text-slate-300">Severity</TableHead>
                    <TableHead className="text-slate-300">Namespace</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {POLICY_VIOLATIONS.map((v, idx) => (
                    <motion.tr
                      key={idx}
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      transition={{ delay: 0.4 + idx * 0.05 }}
                      className="border-b border-slate-700/50 hover:bg-slate-800/30 transition-colors"
                    >
                      <TableCell className="font-mono text-sm text-slate-200">{v.container_name}</TableCell>
                      <TableCell className="text-sm text-slate-300">{v.violation_type}</TableCell>
                      <TableCell>
                        <Badge className={cn("border text-xs capitalize", VSEV_COLORS[v.severity])}>{v.severity}</Badge>
                      </TableCell>
                      <TableCell className="font-mono text-xs text-slate-400">{v.namespace}</TableCell>
                    </motion.tr>
                  ))}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </motion.div>

        {/* Registry Health */}
        <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.5 }}>
          <Card className="border-slate-700 h-full">
            <CardHeader className="border-b border-slate-700">
              <CardTitle className="flex items-center gap-2 text-base">
                <Package className="w-5 h-5 text-purple-400" />
                Registry Health
              </CardTitle>
            </CardHeader>
            <CardContent className="p-6 space-y-3">
              {REGISTRIES.map((reg) => (
                <div key={reg.name} className={cn("p-3 rounded-lg border flex items-center justify-between", reg.secure ? "border-green-500/20 bg-green-500/5" : "border-red-500/20 bg-red-500/5")}>
                  <div>
                    <p className="text-sm font-semibold text-slate-200">{reg.name}</p>
                    <p className="text-xs text-slate-400 capitalize">{reg.type}</p>
                  </div>
                  {reg.secure ? (
                    <CheckCircle2 className="w-5 h-5 text-green-400" />
                  ) : (
                    <XCircle className="w-5 h-5 text-red-400" />
                  )}
                </div>
              ))}
            </CardContent>
          </Card>
        </motion.div>
      </div>
    </div>
  );
}
