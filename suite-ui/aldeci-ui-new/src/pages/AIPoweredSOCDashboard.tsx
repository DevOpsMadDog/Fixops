/**
 * AI-Powered SOC Dashboard
 *
 * AI-driven threat detection with automated triage and ML model performance.
 *   1. KPI cards: Total Detections, Open/Escalated, Active Models, Automation Rate
 *   2. Detections table
 *   3. AI Models table
 *
 * API: GET /api/v1/ai-soc/{stats,detections,models}
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Brain, RefreshCw, AlertTriangle, Cpu, Zap } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// -- API helpers -----------------------------------------------
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

// -- Interfaces ------------------------------------------------

interface SOCStats {
  total_detections: number;
  open_detections: number;
  active_models: number;
  automation_rate: number;
}

interface SOCDetection {
  detection_id: string;
  threat_type: string;
  severity: string;
  confidence_score: number;
  status: string;
  triage_result: string;
}

interface SOCModel {
  model_name: string;
  model_type: string;
  accuracy: number;
  status: string;
  detections_processed: number;
}

// -- Mock data (fallback) --------------------------------------

const MOCK_STATS: SOCStats = {
  total_detections: 1247,
  open_detections:  89,
  active_models:    6,
  automation_rate:  78,
};

const MOCK_DETECTIONS: SOCDetection[] = [
  { detection_id: "DET-001", threat_type: "Lateral Movement",    severity: "critical", confidence_score: 97, status: "open",      triage_result: "malicious"   },
  { detection_id: "DET-002", threat_type: "Data Exfiltration",   severity: "high",     confidence_score: 89, status: "escalated", triage_result: "malicious"   },
  { detection_id: "DET-003", threat_type: "Credential Stuffing", severity: "high",     confidence_score: 82, status: "open",      triage_result: "suspicious"  },
  { detection_id: "DET-004", threat_type: "C2 Communication",    severity: "critical", confidence_score: 95, status: "open",      triage_result: "malicious"   },
  { detection_id: "DET-005", threat_type: "Privilege Escalation",severity: "high",     confidence_score: 78, status: "resolved",  triage_result: "malicious"   },
  { detection_id: "DET-006", threat_type: "Anomalous Login",     severity: "medium",   confidence_score: 65, status: "resolved",  triage_result: "benign"      },
];

const MOCK_MODELS: SOCModel[] = [
  { model_name: "ThreatNet-v3",    model_type: "neural_network",  accuracy: 96.4, status: "active",   detections_processed: 45230 },
  { model_name: "AnomalyDet-v2",   model_type: "autoencoder",     accuracy: 91.2, status: "active",   detections_processed: 32100 },
  { model_name: "BehaviorML-v1",   model_type: "random_forest",   accuracy: 88.7, status: "active",   detections_processed: 28400 },
  { model_name: "PhishGuard-v4",   model_type: "transformer",     accuracy: 94.1, status: "active",   detections_processed: 19800 },
  { model_name: "MalwareNet-v2",   model_type: "cnn",             accuracy: 97.3, status: "active",   detections_processed: 15600 },
  { model_name: "InsiderRisk-v1",  model_type: "gradient_boost",  accuracy: 85.9, status: "training", detections_processed: 8200  },
];

// -- Badge helpers ---------------------------------------------

function SeverityBadge({ severity }: { severity: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
    medium:   "border-amber-500/30 text-amber-400 bg-amber-500/10",
    low:      "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[severity] ?? "border-border text-muted-foreground")}>
      {severity}
    </Badge>
  );
}

function DetectionStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    open:     "border-red-500/30 text-red-400 bg-red-500/10",
    escalated:"border-purple-500/30 text-purple-400 bg-purple-500/10",
    resolved: "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border text-muted-foreground")}>
      {status}
    </Badge>
  );
}

function ModelStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    active:   "border-green-500/30 text-green-400 bg-green-500/10",
    training: "border-blue-500/30 text-blue-400 bg-blue-500/10",
    inactive: "border-gray-500/30 text-gray-400 bg-gray-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border text-muted-foreground")}>
      {status}
    </Badge>
  );
}

// -- Component -------------------------------------------------

export default function AIPoweredSOCDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [dataLoading, setDataLoading] = useState(false);
  const [liveData, setLiveData] = useState<{
    stats: SOCStats | null;
    detections: SOCDetection[] | null;
    models: SOCModel[] | null;
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
        description="AI-driven threat detection with automated triage and ML model performance monitoring"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Detections" value={stats.total_detections} icon={Brain}         trend="up"   />
        <KpiCard title="Open/Escalated"  value={stats.open_detections}  icon={AlertTriangle}  trend="down" className="border-red-500/20" />
        <KpiCard title="Active Models"   value={stats.active_models}    icon={Cpu}            trend="up"   className="border-blue-500/20" />
        <KpiCard title="Automation Rate" value={`${stats.automation_rate}%`} icon={Zap}       trend="up"   className="border-green-500/20" />
      </div>

      {/* Detections Table */}
      <Card className="border-red-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
              <AlertTriangle className="h-4 w-4" />
              Active Threat Detections
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
              {detections.filter((d: SOCDetection) => d.status === "open" || d.status === "escalated").length} open
            </Badge>
          </div>
          <CardDescription className="text-xs">AI-triaged threat detections with confidence scoring</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Detection ID</TableHead>
                  <TableHead className="text-[11px] h-8">Threat Type</TableHead>
                  <TableHead className="text-[11px] h-8">Severity</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Confidence</TableHead>
                  <TableHead className="text-[11px] h-8">Triage</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {detections.map((d: SOCDetection, i: number) => (
                  <TableRow key={d.detection_id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-mono text-[11px] text-blue-400">{d.detection_id}</TableCell>
                    <TableCell className="py-2 text-[11px] font-medium">{d.threat_type}</TableCell>
                    <TableCell className="py-2"><SeverityBadge severity={d.severity ?? "medium"} /></TableCell>
                    <TableCell className="py-2 text-[11px] text-right">
                      <span className={d.confidence_score >= 90 ? "text-red-400" : d.confidence_score >= 70 ? "text-amber-400" : "text-green-400"}>
                        {d.confidence_score}%
                      </span>
                    </TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground capitalize">{d.triage_result}</TableCell>
                    <TableCell className="py-2"><DetectionStatusBadge status={d.status ?? "open"} /></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* AI Models Table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Cpu className="h-4 w-4 text-blue-400" />
              AI Detection Models
            </CardTitle>
            <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">
              {models.filter((m: SOCModel) => m.status === "active").length} active
            </Badge>
          </div>
          <CardDescription className="text-xs">Machine learning models powering automated threat detection</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Model Name</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Accuracy</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Detections</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {models.map((m: SOCModel, i: number) => (
                  <TableRow key={m.model_name ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-mono text-[11px]">{m.model_name}</TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{m.model_type?.replace(/_/g, " ")}</TableCell>
                    <TableCell className="py-2 text-[11px] text-right">
                      <span className={m.accuracy >= 95 ? "text-green-400" : m.accuracy >= 85 ? "text-amber-400" : "text-red-400"}>
                        {m.accuracy?.toFixed(1)}%
                      </span>
                    </TableCell>
                    <TableCell className="py-2"><ModelStatusBadge status={m.status ?? "inactive"} /></TableCell>
                    <TableCell className="py-2 text-[11px] text-right text-muted-foreground">{m.detections_processed?.toLocaleString()}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
