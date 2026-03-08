import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  Container, Shield, AlertTriangle, Activity, RefreshCw, Download,
  CheckCircle2, XCircle, Clock, Package, Server, Eye
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { DataTable } from "@/components/shared/data-table";
import { findingsApi } from "@/lib/api";
import { toast } from "sonner";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell
} from "recharts";

// ── Mock Data ──────────────────────────────────────────────────────────────────
const MOCK_IMAGE_SCANS = [
  { id: "IMG-3301", image: "payment-service:v2.14.1", registry: "gcr.io/corp", baseImage: "node:18-alpine", size: "142MB", critical: 3, high: 12, medium: 28, low: 45, lastScan: "8m ago", status: "vulnerable", runtime: "production" },
  { id: "IMG-3298", image: "auth-service:v1.9.3", registry: "ecr.us-east-1", baseImage: "python:3.11-slim", size: "89MB", critical: 0, high: 4, medium: 11, low: 22, lastScan: "15m ago", status: "warning", runtime: "production" },
  { id: "IMG-3295", image: "api-gateway:v3.2.0", registry: "docker.io/corp", baseImage: "nginx:1.25", size: "56MB", critical: 1, high: 6, medium: 9, low: 18, lastScan: "22m ago", status: "vulnerable", runtime: "production" },
  { id: "IMG-3291", image: "data-processor:v0.8.7", registry: "gcr.io/corp", baseImage: "golang:1.21-alpine", size: "31MB", critical: 0, high: 0, medium: 3, low: 7, lastScan: "1h ago", status: "clean", runtime: "staging" },
  { id: "IMG-3288", image: "analytics-svc:v2.1.0", registry: "ecr.us-east-1", baseImage: "openjdk:17-jre-slim", size: "227MB", critical: 5, high: 18, medium: 34, low: 56, lastScan: "2h ago", status: "critical", runtime: "production" },
  { id: "IMG-3284", image: "notification-svc:v1.4.2", registry: "docker.io/corp", baseImage: "ruby:3.2-slim", size: "118MB", critical: 0, high: 2, medium: 7, low: 14, lastScan: "3h ago", status: "warning", runtime: "production" },
  { id: "IMG-3280", image: "ml-inference:v4.0.1", registry: "gcr.io/corp", baseImage: "pytorch/pytorch:2.1", size: "4.2GB", critical: 2, high: 9, medium: 21, low: 44, lastScan: "4h ago", status: "vulnerable", runtime: "staging" },
];

const REGISTRY_CARDS = [
  { name: "GCR (Google)", host: "gcr.io/corp", images: 34, lastSync: "5m ago", status: "connected", criticalImages: 3 },
  { name: "ECR (AWS)", host: "ecr.us-east-1.amazonaws.com", images: 28, lastSync: "8m ago", status: "connected", criticalImages: 2 },
  { name: "Docker Hub", host: "docker.io/corp", images: 19, lastSync: "12m ago", status: "connected", criticalImages: 1 },
  { name: "Harbor (Private)", host: "registry.internal.corp", images: 47, lastSync: "1m ago", status: "connected", criticalImages: 5 },
];

const RUNTIME_PROTECTION = [
  { name: "k8s-prod-cluster-1", nodes: 24, protected: 24, threats: 2, status: "active" },
  { name: "k8s-prod-cluster-2", nodes: 16, protected: 16, threats: 0, status: "active" },
  { name: "k8s-staging-cluster", nodes: 8, protected: 6, threats: 1, status: "partial" },
  { name: "eks-ml-cluster", nodes: 12, protected: 12, threats: 3, status: "active" },
];

const BASE_IMAGE_VULNS = [
  { image: "node:18-alpine", cves: 47, critical: 3, lastUpdated: "12d ago", color: "#ef4444" },
  { image: "openjdk:17-jre-slim", cves: 112, critical: 5, lastUpdated: "45d ago", color: "#f97316" },
  { image: "python:3.11-slim", cves: 28, critical: 0, lastUpdated: "3d ago", color: "#eab308" },
  { image: "nginx:1.25", cves: 34, critical: 1, lastUpdated: "8d ago", color: "#f97316" },
  { image: "golang:1.21-alpine", cves: 10, critical: 0, lastUpdated: "5d ago", color: "#10b981" },
  { image: "ruby:3.2-slim", cves: 23, critical: 0, lastUpdated: "15d ago", color: "#eab308" },
];

export default function ContainerSecurity() {
  const [selectedImage, setSelectedImage] = useState<typeof MOCK_IMAGE_SCANS[0] | null>(null);

  const { data } = useQuery({
    queryKey: ["findings", "containers"],
    queryFn: () => findingsApi.list({ type: "container", limit: 50 }),
  });

  const images = data?.data ?? MOCK_IMAGE_SCANS;
  const criticalImages = images.filter((i) => i.status === "critical" || i.critical > 0).length;
  const totalCritical = images.reduce((a, i) => a + i.critical, 0);
  const productionImages = images.filter((i) => i.runtime === "production").length;

  const statusConfig = {
    critical: { badge: "destructive" as const, color: "text-red-400" },
    vulnerable: { badge: "warning" as const, color: "text-orange-400" },
    warning: { badge: "warning" as const, color: "text-yellow-400" },
    clean: { badge: "success" as const, color: "text-green-400" },
  };

  const columns = [
    { key: "id", header: "ID", render: (row: typeof MOCK_IMAGE_SCANS[0]) => <span className="font-mono text-xs text-muted-foreground">{row.id}</span> },
    { key: "image", header: "Image", render: (row: typeof MOCK_IMAGE_SCANS[0]) => (
      <div>
        <p className="font-mono text-sm font-medium">{row.image}</p>
        <p className="text-xs text-muted-foreground">{row.registry} · {row.size}</p>
      </div>
    )},
    { key: "baseImage", header: "Base Image", render: (row: typeof MOCK_IMAGE_SCANS[0]) => (
      <code className="text-xs font-mono text-muted-foreground bg-muted/30 px-2 py-0.5 rounded">{row.baseImage}</code>
    )},
    { key: "vulns", header: "Vulnerabilities", render: (row: typeof MOCK_IMAGE_SCANS[0]) => (
      <div className="flex items-center gap-2">
        {row.critical > 0 && <span className="text-xs font-semibold text-red-400">{row.critical}C</span>}
        {row.high > 0 && <span className="text-xs font-semibold text-orange-400">{row.high}H</span>}
        {row.medium > 0 && <span className="text-xs text-yellow-400">{row.medium}M</span>}
        <span className="text-xs text-muted-foreground">{row.low}L</span>
      </div>
    )},
    { key: "runtime", header: "Environment", render: (row: typeof MOCK_IMAGE_SCANS[0]) => (
      <Badge variant={row.runtime === "production" ? "default" : "secondary"}>{row.runtime}</Badge>
    )},
    { key: "status", header: "Status", render: (row: typeof MOCK_IMAGE_SCANS[0]) => (
      <Badge variant={statusConfig[row.status as keyof typeof statusConfig]?.badge ?? "secondary"}>
        {row.status}
      </Badge>
    )},
    { key: "lastScan", header: "Last Scan", render: (row: typeof MOCK_IMAGE_SCANS[0]) => (
      <span className="text-xs text-muted-foreground">{row.lastScan}</span>
    )},
    { key: "actions", header: "", render: (row: typeof MOCK_IMAGE_SCANS[0]) => (
      <Button size="sm" variant="ghost" onClick={() => setSelectedImage(row)}>
        <Eye className="h-4 w-4" />
      </Button>
    )},
  ];

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="space-y-6">
      <PageHeader
        title="Container Security"
        description="Image scanning, registry monitoring, and runtime threat protection for containerized workloads"
        badge="Runtime"
        actions={
          <>
            <Button variant="outline" size="sm" onClick={() => toast.success("Report exported")}><Download className="h-4 w-4 mr-1.5" />Export</Button>
            <Button size="sm" onClick={() => toast.success("Registry sync triggered")}><RefreshCw className="h-4 w-4 mr-1.5" />Sync Registries</Button>
          </>
        }
      />

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Images Scanned" value={images.length} change={4} trend="up" icon={Container} />
        <KpiCard title="Critical Findings" value={totalCritical} change={-2} trend="down" icon={AlertTriangle} />
        <KpiCard title="Prod Images at Risk" value={criticalImages} trend="flat" icon={Shield} />
        <KpiCard title="Runtime Alerts (24h)" value={6} change={50} trend="up" icon={Activity} />
      </div>

      <Tabs defaultValue="images">
        <TabsList>
          <TabsTrigger value="images">Image Scanning</TabsTrigger>
          <TabsTrigger value="registries">Registry Monitoring</TabsTrigger>
          <TabsTrigger value="runtime">Runtime Protection</TabsTrigger>
          <TabsTrigger value="base">Base Images</TabsTrigger>
        </TabsList>

        <TabsContent value="images" className="mt-4 space-y-4">
          {selectedImage ? (
            <Card>
              <CardHeader className="pb-3">
                <div className="flex items-start justify-between">
                  <div>
                    <CardTitle className="text-base font-mono">{selectedImage.image}</CardTitle>
                    <CardDescription>{selectedImage.registry} · Base: {selectedImage.baseImage}</CardDescription>
                  </div>
                  <Button variant="ghost" size="sm" onClick={() => setSelectedImage(null)}>← Back</Button>
                </div>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-4 gap-3">
                  {[
                    { label: "Critical", count: selectedImage.critical, color: "text-red-400 bg-red-500/10" },
                    { label: "High", count: selectedImage.high, color: "text-orange-400 bg-orange-500/10" },
                    { label: "Medium", count: selectedImage.medium, color: "text-yellow-400 bg-yellow-500/10" },
                    { label: "Low", count: selectedImage.low, color: "text-blue-400 bg-blue-500/10" },
                  ].map(({ label, count, color }) => (
                    <div key={label} className={`rounded-lg p-4 text-center ${color}`}>
                      <p className="text-2xl font-bold">{count}</p>
                      <p className="text-xs mt-1">{label}</p>
                    </div>
                  ))}
                </div>
                <div className="space-y-2">
                  <p className="text-xs text-muted-foreground uppercase tracking-wider">Top CVEs</p>
                  {[
                    { cve: "CVE-2023-44487", pkg: "openssl", severity: "critical", fixable: true },
                    { cve: "CVE-2023-38408", pkg: "openssh", severity: "critical", fixable: true },
                    { cve: "CVE-2023-5678", pkg: "libssl3", severity: "high", fixable: false },
                  ].map((cve) => (
                    <div key={cve.cve} className="flex items-center justify-between rounded-md bg-muted/30 px-3 py-2">
                      <div className="flex items-center gap-3">
                        <code className="text-xs font-mono text-primary">{cve.cve}</code>
                        <span className="text-xs text-muted-foreground">{cve.pkg}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge variant={cve.severity === "critical" ? "destructive" : "warning"}>{cve.severity}</Badge>
                        {cve.fixable
                          ? <Button size="sm" variant="outline" className="h-6 text-xs" onClick={() => toast.success("Update PR created")}>Fix</Button>
                          : <span className="text-xs text-muted-foreground">No fix</span>
                        }
                      </div>
                    </div>
                  ))}
                </div>
                <Button onClick={() => toast.success(`Rebuild triggered for ${selectedImage.image}`)}>
                  <RefreshCw className="h-4 w-4 mr-1.5" />Rebuild with Latest Base
                </Button>
              </CardContent>
            </Card>
          ) : (
            <DataTable columns={columns} data={images} onRowClick={(row) => setSelectedImage(row as typeof MOCK_IMAGE_SCANS[0])} />
          )}
        </TabsContent>

        <TabsContent value="registries" className="mt-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {REGISTRY_CARDS.map((reg) => (
              <Card key={reg.name}>
                <CardHeader className="pb-3">
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-base flex items-center gap-2">
                      <Package className="h-4 w-4 text-primary" />
                      {reg.name}
                    </CardTitle>
                    <Badge variant={reg.status === "connected" ? "success" : "destructive"}>{reg.status}</Badge>
                  </div>
                  <CardDescription className="font-mono text-xs">{reg.host}</CardDescription>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="grid grid-cols-3 gap-2 text-center">
                    <div className="rounded-md bg-muted/30 p-2">
                      <p className="text-lg font-bold">{reg.images}</p>
                      <p className="text-xs text-muted-foreground">Images</p>
                    </div>
                    <div className="rounded-md bg-red-500/10 p-2">
                      <p className="text-lg font-bold text-red-400">{reg.criticalImages}</p>
                      <p className="text-xs text-muted-foreground">Critical</p>
                    </div>
                    <div className="rounded-md bg-green-500/10 p-2">
                      <p className="text-lg font-bold text-green-400">{reg.images - reg.criticalImages}</p>
                      <p className="text-xs text-muted-foreground">Clean</p>
                    </div>
                  </div>
                  <p className="text-xs text-muted-foreground flex items-center gap-1"><Clock className="h-3 w-3" />Synced {reg.lastSync}</p>
                  <Button size="sm" variant="outline" className="w-full" onClick={() => toast.success(`${reg.name} rescan initiated`)}>
                    <RefreshCw className="h-3.5 w-3.5 mr-1.5" />Rescan All Images
                  </Button>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="runtime" className="mt-4">
          <div className="space-y-4">
            {RUNTIME_PROTECTION.map((cluster) => (
              <Card key={cluster.name}>
                <CardContent className="p-5">
                  <div className="flex items-center justify-between gap-4">
                    <div className="flex items-center gap-3">
                      <div className={`h-2.5 w-2.5 rounded-full ${cluster.status === "active" ? "bg-green-400" : "bg-yellow-400"}`} />
                      <div>
                        <p className="font-semibold text-sm font-mono">{cluster.name}</p>
                        <p className="text-xs text-muted-foreground">{cluster.nodes} nodes · {cluster.protected} protected</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-4">
                      <div>
                        <div className="flex justify-between text-xs mb-1">
                          <span className="text-muted-foreground">Coverage</span>
                          <span className="font-medium">{Math.round((cluster.protected / cluster.nodes) * 100)}%</span>
                        </div>
                        <Progress value={(cluster.protected / cluster.nodes) * 100} className="h-1.5 w-32" />
                      </div>
                      {cluster.threats > 0
                        ? <Badge variant="destructive"><AlertTriangle className="h-3 w-3 mr-1" />{cluster.threats} threats</Badge>
                        : <Badge variant="success"><CheckCircle2 className="h-3 w-3 mr-1" />Clean</Badge>
                      }
                      <Badge variant={cluster.status === "active" ? "success" : "warning"}>{cluster.status}</Badge>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
            <Card className="border-dashed">
              <CardContent className="flex items-center justify-between p-5">
                <div className="flex items-center gap-3">
                  <Server className="h-5 w-5 text-muted-foreground" />
                  <div>
                    <p className="font-medium text-sm">Add Cluster</p>
                    <p className="text-xs text-muted-foreground">Deploy the ALdeci runtime sensor to a new cluster</p>
                  </div>
                </div>
                <Button size="sm" onClick={() => toast.success("Sensor deployment wizard opened")}>Deploy Sensor</Button>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="base" className="mt-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Base Image Vulnerability Counts</CardTitle>
              </CardHeader>
              <CardContent>
                <ResponsiveContainer width="100%" height={240}>
                  <BarChart data={BASE_IMAGE_VULNS} layout="vertical" margin={{ left: 8, right: 16 }}>
                    <XAxis type="number" tick={{ fontSize: 11 }} />
                    <YAxis dataKey="image" type="category" tick={{ fontSize: 10 }} width={120} />
                    <Tooltip contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 8 }} />
                    <Bar dataKey="cves" radius={[0, 4, 4, 0]} name="Total CVEs">
                      {BASE_IMAGE_VULNS.map((entry, i) => <Cell key={i} fill={entry.color} />)}
                    </Bar>
                  </BarChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
            <Card>
              <CardHeader><CardTitle className="text-base">Base Image Update Status</CardTitle></CardHeader>
              <CardContent className="space-y-3">
                {BASE_IMAGE_VULNS.map((img) => (
                  <div key={img.image} className="flex items-center justify-between p-2 rounded-md bg-muted/20">
                    <div>
                      <code className="text-xs font-mono font-medium">{img.image}</code>
                      <p className="text-xs text-muted-foreground mt-0.5">Updated {img.lastUpdated}</p>
                    </div>
                    <div className="flex items-center gap-2">
                      {img.critical > 0
                        ? <Badge variant="destructive">{img.critical} critical</Badge>
                        : <Badge variant="success"><CheckCircle2 className="h-3 w-3 mr-1" />Safe</Badge>
                      }
                      {img.critical > 0 && (
                        <Button size="sm" variant="outline" className="h-6 text-xs" onClick={() => toast.success(`${img.image} update scheduled`)}>Update</Button>
                      )}
                    </div>
                  </div>
                ))}
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
