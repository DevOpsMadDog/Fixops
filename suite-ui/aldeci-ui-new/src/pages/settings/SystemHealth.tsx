import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  Activity,
  Server,
  Database,
  Layers,
  Cpu,
  CheckCircle,
  AlertCircle,
  XCircle,
  RefreshCw,
  Clock,
  HardDrive,
  Zap,
} from "lucide-react";
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from "recharts";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { systemApi } from "@/lib/api";
import { toast } from "sonner";

// ─── Mock data ───────────────────────────────────────────────────────────────
const MOCK_SERVICES = [
  { id: "api", name: "REST API", description: "FastAPI application server", status: "healthy", latency_ms: 42, uptime_pct: 99.97, version: "3.14.2", replicas: 4 },
  { id: "db", name: "PostgreSQL", description: "Primary database (WAL mode: enabled)", status: "healthy", latency_ms: 3, uptime_pct: 99.99, version: "16.2", replicas: 2 },
  { id: "queue", name: "Task Queue", description: "Celery + Redis — 3 workers", status: "healthy", latency_ms: 8, uptime_pct: 99.94, version: "5.3.6", replicas: 3 },
  { id: "scanner-ingest", name: "Scanner Ingestion", description: "SARIF/JSON normalization pipeline", status: "degraded", latency_ms: 184, uptime_pct: 98.72, version: "2.1.0", replicas: 2 },
  { id: "graph", name: "Knowledge Graph", description: "Neo4j graph database", status: "healthy", latency_ms: 67, uptime_pct: 99.91, version: "5.17.0", replicas: 1 },
  { id: "cache", name: "Redis Cache", description: "Session & hot-data cache", status: "healthy", latency_ms: 1, uptime_pct: 99.99, version: "7.2.4", replicas: 3 },
  { id: "ai", name: "AI / Copilot Engine", description: "LLM inference service", status: "healthy", latency_ms: 892, uptime_pct: 99.80, version: "1.3.1", replicas: 2 },
  { id: "audit", name: "Audit Chain Service", description: "Immutable audit log with hash chain", status: "healthy", latency_ms: 14, uptime_pct: 99.96, version: "1.0.8", replicas: 1 },
];

const MOCK_LATENCY_DATA = Array.from({ length: 24 }, (_, i) => ({
  time: `${String(i).padStart(2, "0")}:00`,
  api: Math.round(35 + Math.random() * 40 + (i === 14 || i === 15 ? 80 : 0)),
  db: Math.round(2 + Math.random() * 6),
  queue: Math.round(5 + Math.random() * 15),
}));

const MOCK_DB_STATS = {
  size_gb: 847.3,
  wal_mode: "enabled",
  connections: 42,
  max_connections: 200,
  slow_queries_24h: 3,
  replication_lag_ms: 8,
  last_vacuum: "2026-03-08 04:00 UTC",
  oldest_transaction_age: "0:00:02",
};

const MOCK_QUEUE_STATS = {
  depth: 34,
  max_depth: 10000,
  processing_rate: 412,
  failed_jobs_24h: 2,
  workers: 3,
  avg_job_duration_ms: 2300,
};

function ServiceStatusIcon({ status }: { status: string }) {
  if (status === "healthy") return <CheckCircle className="h-4 w-4 text-green-400" />;
  if (status === "degraded") return <AlertCircle className="h-4 w-4 text-yellow-400" />;
  return <XCircle className="h-4 w-4 text-red-400" />;
}

function statusVariant(status: string): "success" | "warning" | "destructive" {
  if (status === "healthy") return "success";
  if (status === "degraded") return "warning";
  return "destructive";
}

export default function SystemHealth() {
  const { data: healthData, isLoading, refetch } = useQuery({
    queryKey: ["system-health"],
    queryFn: () => systemApi.health(),
    refetchInterval: 30000,
  });

  const { data: metricsData } = useQuery({
    queryKey: ["system-metrics"],
    queryFn: () => systemApi.metrics(),
    refetchInterval: 30000,
  });

  const services = healthData?.data?.services ?? MOCK_SERVICES;
  const dbStats = metricsData?.data?.db ?? MOCK_DB_STATS;
  const queueStats = metricsData?.data?.queue ?? MOCK_QUEUE_STATS;

  const healthyCount = (services as any[]).filter((s) => s.status === "healthy").length;
  const degradedCount = (services as any[]).filter((s) => s.status === "degraded").length;
  const overallStatus = degradedCount > 0 ? "Degraded" : "All Systems Operational";
  const uptime = (services as any[]).reduce((a, s) => a + s.uptime_pct, 0) / services.length;

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="space-y-6">
      <PageHeader
        title="System Health"
        description="Real-time backend service status, database metrics, and performance data"
        badge={degradedCount > 0 ? "Degraded" : "Healthy"}
        actions={
          <Button variant="outline" size="sm" onClick={() => { refetch(); toast.info("Refreshing health data…"); }}>
            <RefreshCw className={`h-3.5 w-3.5 mr-1.5 ${isLoading ? "animate-spin" : ""}`} />
            Refresh
          </Button>
        }
      />

      {/* Overall Status Banner */}
      <div className={`rounded-lg border px-4 py-3 flex items-center gap-3 ${degradedCount > 0 ? "border-yellow-500/30 bg-yellow-500/5" : "border-green-500/30 bg-green-500/5"}`}>
        {degradedCount > 0
          ? <AlertCircle className="h-5 w-5 text-yellow-400 shrink-0" />
          : <CheckCircle className="h-5 w-5 text-green-400 shrink-0" />
        }
        <div>
          <p className={`text-sm font-semibold ${degradedCount > 0 ? "text-yellow-300" : "text-green-300"}`}>{overallStatus}</p>
          <p className="text-xs text-muted-foreground">{healthyCount}/{services.length} services healthy · {uptime.toFixed(2)}% aggregate uptime</p>
        </div>
      </div>

      {/* KPIs */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <KpiCard title="Services Healthy" value={`${healthyCount}/${services.length}`} icon={Server} trend={degradedCount > 0 ? "down" : "up"} />
        <KpiCard title="Avg Uptime" value={`${uptime.toFixed(2)}%`} icon={Activity} trend="up" />
        <KpiCard title="Queue Depth" value={queueStats.depth} icon={Layers} trend="flat" />
        <KpiCard title="DB Connections" value={`${dbStats.connections}/${dbStats.max_connections}`} icon={Database} trend="flat" />
      </div>

      {/* Service Status Grid */}
      <div>
        <h3 className="text-sm font-semibold mb-3">Backend Services</h3>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
          {(services as any[]).map((service) => (
            <Card key={service.id} className={`border-border/50 ${service.status === "degraded" ? "border-yellow-500/30" : ""}`}>
              <CardContent className="p-4">
                <div className="flex items-start justify-between mb-2">
                  <div className="flex items-center gap-1.5">
                    <ServiceStatusIcon status={service.status} />
                    <p className="text-sm font-semibold">{service.name}</p>
                  </div>
                  <Badge variant={statusVariant(service.status)} className="text-xs">{service.status}</Badge>
                </div>
                <p className="text-xs text-muted-foreground mb-3">{service.description}</p>
                <div className="grid grid-cols-2 gap-2 text-center">
                  <div className="rounded-md bg-muted/30 p-1.5">
                    <p className="text-sm font-bold">{service.latency_ms}ms</p>
                    <p className="text-xs text-muted-foreground">Latency</p>
                  </div>
                  <div className="rounded-md bg-muted/30 p-1.5">
                    <p className="text-sm font-bold">{service.uptime_pct}%</p>
                    <p className="text-xs text-muted-foreground">Uptime</p>
                  </div>
                </div>
                <div className="flex items-center justify-between mt-2 text-xs text-muted-foreground">
                  <span>v{service.version}</span>
                  <span>{service.replicas} replica{service.replicas !== 1 ? "s" : ""}</span>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* API Latency Chart */}
        <div className="lg:col-span-2">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-base flex items-center gap-2">
                <Zap className="h-4 w-4 text-primary" />
                API Latency — Last 24 Hours (ms)
              </CardTitle>
              <CardDescription>P50 latency by service component</CardDescription>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={240}>
                <AreaChart data={MOCK_LATENCY_DATA} margin={{ top: 4, right: 8, left: -16, bottom: 0 }}>
                  <defs>
                    <linearGradient id="apiGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#14b8a6" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#14b8a6" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="dbGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#3b82f6" stopOpacity={0} />
                    </linearGradient>
                    <linearGradient id="queueGrad" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#f59e0b" stopOpacity={0.3} />
                      <stop offset="95%" stopColor="#f59e0b" stopOpacity={0} />
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#ffffff08" />
                  <XAxis dataKey="time" tick={{ fill: "#9ca3af", fontSize: 10 }} tickLine={false} interval={3} />
                  <YAxis tick={{ fill: "#9ca3af", fontSize: 10 }} tickLine={false} />
                  <Tooltip
                    contentStyle={{ backgroundColor: "#1a1a2e", border: "1px solid #ffffff15", borderRadius: 6, fontSize: 12 }}
                    labelStyle={{ color: "#e2e8f0" }}
                  />
                  <Area type="monotone" dataKey="api" stroke="#14b8a6" fill="url(#apiGrad)" strokeWidth={1.5} name="API" dot={false} />
                  <Area type="monotone" dataKey="db" stroke="#3b82f6" fill="url(#dbGrad)" strokeWidth={1.5} name="DB" dot={false} />
                  <Area type="monotone" dataKey="queue" stroke="#f59e0b" fill="url(#queueGrad)" strokeWidth={1.5} name="Queue" dot={false} />
                </AreaChart>
              </ResponsiveContainer>
              <div className="flex items-center gap-4 mt-2 justify-center text-xs text-muted-foreground">
                <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-teal-400 inline-block" />REST API</span>
                <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-blue-400 inline-block" />Database</span>
                <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full bg-yellow-400 inline-block" />Queue</span>
              </div>
            </CardContent>
          </Card>
        </div>

        {/* DB + Queue Stats */}
        <div className="space-y-4">
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm flex items-center gap-2">
                <Database className="h-4 w-4 text-primary" />
                Database Status
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2.5">
              {[
                { label: "Size", value: `${dbStats.size_gb} GB` },
                { label: "WAL Mode", value: dbStats.wal_mode },
                { label: "Connections", value: `${dbStats.connections} / ${dbStats.max_connections}` },
                { label: "Slow Queries (24h)", value: String(dbStats.slow_queries_24h) },
                { label: "Replication Lag", value: `${dbStats.replication_lag_ms}ms` },
                { label: "Last VACUUM", value: dbStats.last_vacuum },
              ].map((row) => (
                <div key={row.label} className="flex justify-between text-xs">
                  <span className="text-muted-foreground">{row.label}</span>
                  <span className="font-medium">{row.value}</span>
                </div>
              ))}
              <div className="pt-1">
                <div className="flex justify-between text-xs mb-1">
                  <span className="text-muted-foreground">Connection utilization</span>
                  <span>{Math.round(dbStats.connections / dbStats.max_connections * 100)}%</span>
                </div>
                <Progress value={Math.round(dbStats.connections / dbStats.max_connections * 100)} className="h-1.5" />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm flex items-center gap-2">
                <Layers className="h-4 w-4 text-primary" />
                Task Queue
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2.5">
              {[
                { label: "Queue Depth", value: `${queueStats.depth} / ${queueStats.max_depth}` },
                { label: "Processing Rate", value: `${queueStats.processing_rate} jobs/min` },
                { label: "Workers Active", value: String(queueStats.workers) },
                { label: "Failed Jobs (24h)", value: String(queueStats.failed_jobs_24h) },
                { label: "Avg Job Duration", value: `${queueStats.avg_job_duration_ms}ms` },
              ].map((row) => (
                <div key={row.label} className="flex justify-between text-xs">
                  <span className="text-muted-foreground">{row.label}</span>
                  <span className="font-medium">{row.value}</span>
                </div>
              ))}
              <div className="pt-1">
                <div className="flex justify-between text-xs mb-1">
                  <span className="text-muted-foreground">Queue utilization</span>
                  <span>{((queueStats.depth / queueStats.max_depth) * 100).toFixed(2)}%</span>
                </div>
                <Progress value={(queueStats.depth / queueStats.max_depth) * 100} className="h-1.5" />
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm flex items-center gap-2">
                <Clock className="h-4 w-4 text-primary" />
                Uptime Summary
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              {(services as any[]).map((s) => (
                <div key={s.id} className="flex items-center gap-2">
                  <span className="text-xs text-muted-foreground w-24 truncate">{s.name}</span>
                  <Progress value={s.uptime_pct} className="h-1.5 flex-1" />
                  <span className="text-xs font-medium w-14 text-right">{s.uptime_pct}%</span>
                </div>
              ))}
            </CardContent>
          </Card>
        </div>
      </div>
    </motion.div>
  );
}
