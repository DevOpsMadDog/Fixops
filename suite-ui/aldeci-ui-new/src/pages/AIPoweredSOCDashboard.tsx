/**
 * AI-Powered SOC Dashboard
 *
 * AI/ML-driven Security Operations Center detections and model performance.
 *   1. KPI cards: Total Detections, Auto-Triaged, Active Models, Avg Model Accuracy
 *   2. Detections table
 *   3. AI Models table
 *
 * API: GET /api/v1/ai-soc/{stats,detections,models}
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Brain, RefreshCw, Cpu, Eye, TrendingUp, AlertTriangle,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── API helpers ────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "X-API-Key": API_KEY },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ── Mock data (fallback) ───────────────────────────────────────

const MOCK_STATS = {
  total_detections:   1843,
  auto_triaged_count: 1621,
  active_models:      7,
  avg_model_accuracy: 94.3,
};

const MOCK_DETECTIONS = [
  { detection_name: "Beaconing C2 Pattern",         model_type: "anomaly",     confidence_score: 0.97, severity: "critical", source_data_type: "netflow",  status: "escalated"  },
  { detection_name: "Credential Stuffing Attempt",  model_type: "classifier",  confidence_score: 0.92, severity: "high",     source_data_type: "auth_log", status: "auto_closed"},
  { detection_name: "Lateral Movement via WMI",     model_type: "sequence",    confidence_score: 0.88, severity: "high",     source_data_type: "edr",      status: "open"       },
  { detection_name: "Data Exfiltration via DNS",    model_type: "anomaly",     confidence_score: 0.95, severity: "critical", source_data_type: "dns",      status: "open"       },
  { detection_name: "Insider Privilege Abuse",      model_type: "behavioral",  confidence_score: 0.79, severity: "medium",   source_data_type: "dlp",      status: "reviewing"  },
  { detection_name: "Phishing Link Click",          model_type: "nlp",         confidence_score: 0.85, severity: "medium",   source_data_type: "email",    status: "auto_closed"},
  { detection_name: "Container Escape Attempt",     model_type: "classifier",  confidence_score: 0.91, severity: "high",     source_data_type: "syslog",   status: "open"       },
  { detection_name: "Crypto Mining Process",        model_type: "anomaly",     confidence_score: 0.99, severity: "medium",   source_data_type: "cpu_metrics",status: "auto_closed"},
];

const MOCK_MODELS = [
  { model_name: "NetFlow Anomaly Detector",  model_type: "anomaly",    accuracy_score: 96.2, false_positive_rate: 1.8, version: "v3.2.1", status: "active"     },
  { model_name: "Auth Log Classifier",       model_type: "classifier", accuracy_score: 94.7, false_positive_rate: 2.4, version: "v2.1.0", status: "active"     },
  { model_name: "Kill Chain Sequencer",      model_type: "sequence",   accuracy_score: 91.3, false_positive_rate: 4.1, version: "v1.8.3", status: "active"     },
  { model_name: "Behavioral UBA Engine",     model_type: "behavioral", accuracy_score: 89.5, false_positive_rate: 5.7, version: "v2.0.0", status: "active"     },
  { model_name: "Phishing NLP Model",        model_type: "nlp",        accuracy_score: 97.1, false_positive_rate: 1.2, version: "v4.0.2", status: "active"     },
  { model_name: "Container Escape Detector", model_type: "classifier", accuracy_score: 93.4, false_positive_rate: 2.9, version: "v1.3.0", status: "active"     },
  { model_name: "Crypto Mining Profiler",    model_type: "anomaly",    accuracy_score: 99.1, false_positive_rate: 0.4, version: "v2.5.1", status: "active"     },
  { model_name: "DNS Tunnel Detector v2",    model_type: "sequence",   accuracy_score: 87.6, false_positive_rate: 6.3, version: "v2.0.0-beta", status: "training"},
];

// ── Badge helpers ──────────────────────────────────────────────

function SeverityBadge({ severity }: { severity: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
    medium:   "border-amber-500/30 text-amber-400 bg-amber-500/10",
    low:      "border-blue-500/30 text-blue-400 bg-blue-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[severity] ?? "border-border text-muted-foreground")}>
      {severity}
    </Badge>
  );
}

function DetectionStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    escalated:  "border-red-500/30 text-red-400 bg-red-500/10",
    open:       "border-orange-500/30 text-orange-400 bg-orange-500/10",
    reviewing:  "border-blue-500/30 text-blue-400 bg-blue-500/10",
    auto_closed:"border-green-500/30 text-green-400 bg-green-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border", map[status] ?? "border-border text-muted-foreground")}>
      {status?.replace(/_/g, " ")}
    </Badge>
  );
}

function ModelTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    anomaly:    "border-purple-500/30 text-purple-400 bg-purple-500/10",
    classifier: "border-blue-500/30 text-blue-400 bg-blue-500/10",
    sequence:   "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
    behavioral: "border-orange-500/30 text-orange-400 bg-orange-500/10",
    nlp:        "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[type] ?? "border-border text-muted-foreground")}>
      {type}
    </Badge>
  );
}

function ModelStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    active:   "border-green-500/30 text-green-400 bg-green-500/10",
    training: "border-blue-500/30 text-blue-400 bg-blue-500/10",
    retired:  "border-gray-500/30 text-gray-400 bg-gray-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border text-muted-foreground")}>
      {status}
    </Badge>
  );
}

function accuracyColor(score: number): string {
  if (score >= 95) return "text-green-400";
  if (score >= 88) return "text-amber-400";
  return "text-red-400";
}

// ── Component ──────────────────────────────────────────────────

export default function AIPoweredSOCDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [dataLoading, setDataLoading] = useState(false);
  const [liveData, setLiveData] = useState<{
  const [loading, setLoading] = useState(true);
    stats: any | null;
    detections: any[] | null;
    models: any[] | null;
  }>({ stats: null, detections: null, models: null });

  const fetchData = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/ai-soc/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/ai-soc/detections?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/ai-soc/models?org_id=${ORG_ID}`),
    ]).then(([statsRes, detectionsRes, modelsRes]) => {
      setLiveData({
        stats:      statsRes.status      === "fulfilled" ? statsRes.value      : null,
        detections: detectionsRes.status === "fulfilled" ? detectionsRes.value : null,
        models:     modelsRes.status     === "fulfilled" ? modelsRes.value     : null,
      });
    }).finally(() => setDataLoading(false));
  };

  useEffect(() => { fetchData(); }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchData();
    setTimeout(() => setRefreshing(false), 800);
  };

  const stats      = liveData.stats      ?? MOCK_STATS;
  const detections = liveData.detections ?? MOCK_DETECTIONS;
  const models     = liveData.models     ?? MOCK_MODELS;

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
        title="AI-Powered SOC"
        description="Machine learning-driven threat detection, auto-triage, and model performance monitoring"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Detections"   value={stats.total_detections
    setLoading(false);}                         icon={Eye}          trend="up"   />
        <KpiCard title="Auto-Triaged"       value={stats.auto_triaged_count}                       icon={Brain}        trend="up"   className="border-blue-500/20" />
        <KpiCard title="Active Models"      value={stats.active_models}                            icon={Cpu}          trend="flat" className="border-purple-500/20" />
        <KpiCard title="Avg Accuracy"       value={`${stats.avg_model_accuracy}%`}                 icon={TrendingUp}   trend="up"   className="border-green-500/20" />
      </div>

      {/* Detections Table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Eye className="h-4 w-4 text-blue-400" />
              AI Detections
            </CardTitle>
            <Badge className="text-[10px] border border-border text-muted-foreground">
              {detections.filter((d: any) => d.status === "open" || d.status === "escalated").length} open
            </Badge>
          </div>
          <CardDescription className="text-xs">Real-time AI-generated threat detections with confidence scoring</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Detection</TableHead>
                  <TableHead className="text-[11px] h-8">Model Type</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Confidence</TableHead>
                  <TableHead className="text-[11px] h-8">Severity</TableHead>
                  <TableHead className="text-[11px] h-8">Source</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {detections.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  detections.map((d: any, i: number) => (
                  <TableRow key={i} className="hover:bg-muted/30">
                    <TableCell className="py-2 text-[11px] font-medium">{d.detection_name}</TableCell>
                    <TableCell className="py-2"><ModelTypeBadge type={d.model_type ?? "anomaly"} /></TableCell>
                    <TableCell className={cn("py-2 text-right text-[11px] font-semibold", accuracyColor((d.confidence_score ?? 0) * 100))}>
                      {((d.confidence_score ?? 0) * 100).toFixed(0)}%
                    </TableCell>
                    <TableCell className="py-2"><SeverityBadge severity={d.severity ?? "medium"} /></TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">{d.source_data_type}</TableCell>
                    <TableCell className="py-2"><DetectionStatusBadge status={d.status ?? "open"} /></TableCell>
                  </TableRow>
                ))}
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Models Table */}
      <Card className="border-purple-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-purple-400">
              <Brain className="h-4 w-4" />
              AI Models
            </CardTitle>
            <Badge className="text-[10px] border border-purple-500/30 text-purple-400 bg-purple-500/10">
              {models.filter((m: any) => m.status === "active").length} active
            </Badge>
          </div>
          <CardDescription className="text-xs">Deployed detection models with accuracy and false positive rates</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Model Name</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Accuracy</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">FP Rate</TableHead>
                  <TableHead className="text-[11px] h-8">Version</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {models.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  models.map((m: any, i: number) => (
                  <TableRow key={i} className="hover:bg-muted/30">
                    <TableCell className="py-2 text-[11px] font-medium">{m.model_name}</TableCell>
                    <TableCell className="py-2"><ModelTypeBadge type={m.model_type ?? "anomaly"} /></TableCell>
                    <TableCell className={cn("py-2 text-right text-[11px] font-semibold", accuracyColor(m.accuracy_score))}>{m.accuracy_score?.toFixed(1)}%</TableCell>
                    <TableCell className="py-2 text-right text-[11px] text-muted-foreground">{m.false_positive_rate?.toFixed(1)}%</TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">{m.version}</TableCell>
                    <TableCell className="py-2"><ModelStatusBadge status={m.status ?? "active"} /></TableCell>
                  </TableRow>
                ))}
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
