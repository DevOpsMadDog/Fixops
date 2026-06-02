/**
 * Container Security Dashboard
 *
 * Image scanning, runtime threats, and Kubernetes security posture.
 *   1. KPIs: Images Scanned, Critical Vulns, Running Containers, Policy Violations
 *   2. Image Vulnerability Table
 *   3. Runtime Threats feed
 *   4. Kubernetes Security posture cards (RBAC, Pod Security, Network Policies)
 *   5. Policy Violations table
 *   6. Registry health grid
 *
 * Route: /discover/containers
 * API: GET /api/v1/container-security/summary
 *          /api/v1/container-security/images
 *          /api/v1/container-security/runtime-threats
 *          /api/v1/container-security/k8s-posture
 *          /api/v1/container-security/policy-violations
 *          /api/v1/container-security/registries
 */

import { useState, useEffect } from "react";
import { getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { motion } from "framer-motion";
import {
  Shield, AlertTriangle, Container, Activity,
  Clock, CheckCircle2, XCircle, AlertCircle,
  Package, Server, Lock,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { cn } from "@/lib/utils";

// ── API helpers ──────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  (getStoredAuthToken() ?? "");

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}`, { headers: { "X-API-Key": API_KEY } });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ── Static config (colour maps only — no image/registry/IP data) ─

type ThreatSeverity = "critical" | "high" | "medium";
type ViolationSeverity = "high" | "medium" | "low";
type ImageStatus = "Clean" | "At Risk" | "Critical";

const SEV_COLORS: Record<ThreatSeverity | string, string> = {
  critical: "bg-red-500/10 text-red-400 border-red-500/30",
  high:     "bg-orange-500/10 text-orange-400 border-orange-500/30",
  medium:   "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
};

const VSEV_COLORS: Record<ViolationSeverity | string, string> = {
  high:   "bg-red-500/10 text-red-400 border-red-500/30",
  medium: "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
  low:    "bg-blue-500/10 text-blue-400 border-blue-500/30",
};

const STATUS_COLORS: Record<ImageStatus | string, string> = {
  Clean:     "bg-green-500/10 text-green-400 border-green-500/20",
  "At Risk": "bg-orange-500/10 text-orange-400 border-orange-500/20",
  Critical:  "bg-red-500/10 text-red-400 border-red-500/20",
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
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);

  const load = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch("/api/v1/container-security/stats"),
      apiFetch("/api/v1/container-security/images"),
      apiFetch("/api/v1/container-security/runtime-threats"),
      apiFetch("/api/v1/container-security/k8s-posture"),
      apiFetch("/api/v1/container-security/policy-violations"),
      apiFetch("/api/v1/container-security/registries"),
    ]).then(([summaryR, imagesR, threatsR, postureR, violationsR, registriesR]) => {
      const summary    = summaryR.status    === "fulfilled" ? summaryR.value    : null;
      const images     = imagesR.status     === "fulfilled" ? imagesR.value     : null;
      const threats    = threatsR.status    === "fulfilled" ? threatsR.value    : null;
      const posture    = postureR.status    === "fulfilled" ? postureR.value    : null;
      const violations = violationsR.status === "fulfilled" ? violationsR.value : null;
      const registries = registriesR.status === "fulfilled" ? registriesR.value : null;
      if (summary || images || threats || posture || violations || registries) {
        setLiveData({ summary, images, threats, posture, violations, registries });
      }
    }).finally(() => setDataLoading(false));
  };

  useEffect(() => { load(); }, []); // eslint-disable-line react-hooks/exhaustive-deps

  // Resolve live arrays
  const images:     any[] = liveData?.images?.items     ?? liveData?.images     ?? [];
  const threats:    any[] = liveData?.threats?.items    ?? liveData?.threats    ?? [];
  const postureArr: any[] = liveData?.posture?.items    ?? liveData?.posture    ?? [];
  const violations: any[] = liveData?.violations?.items ?? liveData?.violations ?? [];
  const registries: any[] = liveData?.registries?.items ?? liveData?.registries ?? [];

  const summary = liveData?.summary;

  return (
    <div className="min-h-screen bg-slate-900 p-8 space-y-8">
      <div className="flex items-center justify-between">
        <PageHeader
          title="Container Security"
          description="Image scanning, runtime threats, and Kubernetes security posture"
        />
        <Button variant="outline" size="sm" onClick={load} disabled={dataLoading} className="gap-1.5">
          {dataLoading ? "Loading…" : "Refresh"}
        </Button>
      </div>

      {/* KPIs */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Images Scanned"      value={summary?.images_scanned      ?? images.length}     icon={Package}       />
        <KpiCard title="Critical Vulns"      value={summary?.critical_vulns      ?? "—"}               icon={AlertTriangle} />
        <KpiCard title="Running Containers"  value={summary?.running_containers  ?? "—"}               icon={Container}     />
        <KpiCard title="Policy Violations"   value={summary?.policy_violations   ?? violations.length} icon={AlertCircle}   />
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
            {images.length === 0
              ? <EmptyState icon={Package} title="No images scanned yet" description="Scanned container images will appear here once the scanner has run." />
              : (
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
                      {images.map((img: any, idx: number) => (
                        <motion.tr
                          key={img.id ?? `${img.image_name}-${img.tag}-${idx}`}
                          initial={{ opacity: 0 }}
                          animate={{ opacity: 1 }}
                          transition={{ delay: idx * 0.04 }}
                          className="border-b border-slate-700/50 hover:bg-slate-800/30 transition-colors"
                        >
                          <TableCell className="font-mono text-sm text-slate-200">{img.image_name ?? img.name}</TableCell>
                          <TableCell className="font-mono text-xs text-slate-400">{img.tag}</TableCell>
                          <TableCell className="text-sm text-slate-300">{img.registry}</TableCell>
                          <TableCell className="text-right font-mono text-sm">
                            <span className={(img.critical_vulns ?? 0) > 0 ? "text-red-400 font-bold" : "text-slate-500"}>
                              {img.critical_vulns ?? 0}
                            </span>
                          </TableCell>
                          <TableCell className="text-right font-mono text-sm">
                            <span className={(img.high_vulns ?? 0) > 0 ? "text-orange-400" : "text-slate-500"}>
                              {img.high_vulns ?? 0}
                            </span>
                          </TableCell>
                          <TableCell className="text-right font-mono text-xs text-slate-400">{img.size_mb ?? "—"}</TableCell>
                          <TableCell className="text-xs text-slate-400">
                            <div className="flex items-center gap-1">
                              <Clock className="w-3 h-3" />
                              {img.last_scanned ?? "—"}
                            </div>
                          </TableCell>
                          <TableCell>
                            <Badge className={cn("border text-xs", STATUS_COLORS[img.status] ?? STATUS_COLORS["At Risk"])}>
                              {img.status ?? "Unknown"}
                            </Badge>
                          </TableCell>
                        </motion.tr>
                      ))}
                    </TableBody>
                  </Table>
                </div>
              )
            }
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
              {threats.length === 0
                ? <EmptyState icon={Activity} title="No runtime threats detected" description="Container runtime threat events will appear here once the runtime agent is active." />
                : (
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
                      {threats.map((evt: any, idx: number) => (
                        <motion.tr
                          key={evt.id ?? idx}
                          initial={{ opacity: 0 }}
                          animate={{ opacity: 1 }}
                          transition={{ delay: 0.2 + idx * 0.05 }}
                          className="border-b border-slate-700/50 hover:bg-slate-800/30 transition-colors"
                        >
                          <TableCell className="font-mono text-xs text-slate-400">{evt.timestamp}</TableCell>
                          <TableCell className="font-mono text-xs text-slate-300">
                            {evt.container_id ? `${evt.container_id.slice(0, 8)}…` : (evt.container_name ?? "—")}
                          </TableCell>
                          <TableCell className="text-sm text-slate-200">{evt.threat_type}</TableCell>
                          <TableCell>
                            <Badge className={cn("border text-xs capitalize", SEV_COLORS[evt.severity] ?? SEV_COLORS.medium)}>
                              {evt.severity}
                            </Badge>
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
                )
              }
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
              {postureArr.length === 0
                ? <EmptyState icon={Shield} title="No posture data yet" description="Kubernetes security scores will appear once the K8s scanner has run." />
                : postureArr.map((item: any) => {
                    const score = item.score ?? 0;
                    const label = item.label ?? item.name ?? "—";
                    // Map label to icon
                    const Icon = label.toLowerCase().includes("rbac") ? Lock
                      : label.toLowerCase().includes("network") ? Server
                      : Shield;
                    return (
                      <div key={label} className={cn("p-4 rounded-lg border-2", k8sBorder(score))}>
                        <div className="flex items-center justify-between mb-2">
                          <div className="flex items-center gap-2">
                            <Icon className={cn("w-4 h-4", k8sColor(score))} />
                            <span className="text-sm font-semibold text-slate-200">{label}</span>
                          </div>
                          <span className={cn("text-2xl font-bold font-mono", k8sColor(score))}>{score}%</span>
                        </div>
                        <div className="w-full bg-slate-700 rounded-full h-2">
                          <div
                            className={cn("h-2 rounded-full transition-all", score >= 70 ? "bg-green-400" : score >= 50 ? "bg-yellow-400" : "bg-red-400")}
                            style={{ width: `${score}%` }}
                          />
                        </div>
                      </div>
                    );
                  })
              }
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
              {violations.length === 0
                ? <EmptyState icon={AlertTriangle} title="No policy violations" description="Container policy violations will appear here once enforcement policies are active." />
                : (
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
                      {violations.map((v: any, idx: number) => (
                        <motion.tr
                          key={v.id ?? idx}
                          initial={{ opacity: 0 }}
                          animate={{ opacity: 1 }}
                          transition={{ delay: 0.4 + idx * 0.05 }}
                          className="border-b border-slate-700/50 hover:bg-slate-800/30 transition-colors"
                        >
                          <TableCell className="font-mono text-sm text-slate-200">{v.container_name}</TableCell>
                          <TableCell className="text-sm text-slate-300">{v.violation_type}</TableCell>
                          <TableCell>
                            <Badge className={cn("border text-xs capitalize", VSEV_COLORS[v.severity] ?? VSEV_COLORS.medium)}>
                              {v.severity}
                            </Badge>
                          </TableCell>
                          <TableCell className="font-mono text-xs text-slate-400">{v.namespace}</TableCell>
                        </motion.tr>
                      ))}
                    </TableBody>
                  </Table>
                )
              }
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
              {registries.length === 0
                ? <EmptyState icon={Package} title="No registries connected" description="Connected container registries will appear here once configured." />
                : registries.map((reg: any) => (
                    <div
                      key={reg.id ?? reg.name}
                      className={cn("p-3 rounded-lg border flex items-center justify-between",
                        reg.secure ? "border-green-500/20 bg-green-500/5" : "border-red-500/20 bg-red-500/5"
                      )}
                    >
                      <div>
                        <p className="text-sm font-semibold text-slate-200">{reg.name}</p>
                        <p className="text-xs text-slate-400 capitalize">{reg.type}</p>
                      </div>
                      {reg.secure
                        ? <CheckCircle2 className="w-5 h-5 text-green-400" />
                        : <XCircle className="w-5 h-5 text-red-400" />
                      }
                    </div>
                  ))
              }
            </CardContent>
          </Card>
        </motion.div>
      </div>
    </div>
  );
}
