/**
 * AI Governance Dashboard
 *
 * AI/ML model governance, risk management, and incident tracking.
 *   1. KPI cards: Total Models, Production Models, Open Incidents, Critical Risk Models
 *   2. Models table
 *   3. Incidents table
 *
 * API: GET /api/v1/ai-governance/{stats,models,incidents}
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Brain, RefreshCw, AlertTriangle, ShieldAlert, Activity } from "lucide-react";
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

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}`, { headers: { "X-API-Key": API_KEY } });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

const MOCK_STATS = {
  total_models: 18,
  production_models: 9,
  open_incidents: 5,
  critical_risk_models: 2,
};

const MOCK_MODELS = [
  { id: "mdl-001", name: "FraudDetector-v3",       type: "classification", vendor: "Internal",  deployment_status: "production",  risk_level: "high",     data_classification: "PII" },
  { id: "mdl-002", name: "ThreatPredictor-v2",      type: "regression",     vendor: "OpenAI",    deployment_status: "production",  risk_level: "critical", data_classification: "Confidential" },
  { id: "mdl-003", name: "AnomalyDetector-v1",      type: "clustering",     vendor: "Internal",  deployment_status: "staging",     risk_level: "medium",   data_classification: "Internal" },
  { id: "mdl-004", name: "NLPParser-v4",            type: "nlp",            vendor: "Anthropic", deployment_status: "production",  risk_level: "low",      data_classification: "Public" },
  { id: "mdl-005", name: "ImageClassifier-v1",      type: "vision",         vendor: "Google",    deployment_status: "development", risk_level: "medium",   data_classification: "Internal" },
];

const MOCK_INCIDENTS = [
  { id: "inc-001", model_name: "ThreatPredictor-v2", incident_type: "hallucination",     severity: "critical", status: "open" },
  { id: "inc-002", model_name: "FraudDetector-v3",   incident_type: "bias",              severity: "high",     status: "investigating" },
  { id: "inc-003", model_name: "NLPParser-v4",       incident_type: "data_leak",         severity: "high",     status: "open" },
  { id: "inc-004", model_name: "AnomalyDetector-v1", incident_type: "drift",             severity: "medium",   status: "resolved" },
];

function DeploymentBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    production:  "border-green-500/30 text-green-400 bg-green-500/10",
    staging:     "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    development: "border-blue-500/30 text-blue-400 bg-blue-500/10",
    retired:     "border-gray-500/30 text-gray-400 bg-gray-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border text-muted-foreground")}>
      {status}
    </Badge>
  );
}

function RiskBadge({ level }: { level: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
    medium:   "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    low:      "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[level] ?? "border-border text-muted-foreground")}>
      {level}
    </Badge>
  );
}

function SeverityBadge({ severity }: { severity: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
    medium:   "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    low:      "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[severity] ?? "border-border text-muted-foreground")}>
      {severity}
    </Badge>
  );
}

function IncidentStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    open:          "border-red-500/30 text-red-400 bg-red-500/10",
    investigating: "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    resolved:      "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border text-muted-foreground")}>
      {status}
    </Badge>
  );
}

export default function AIGovernanceDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [dataLoading, setDataLoading] = useState(false);
  const [liveData, setLiveData] = useState<{ stats: any | null; models: any[] | null; incidents: any[] | null }>({
    stats: null, models: null, incidents: null,
  });

  const fetchData = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/ai-governance/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/ai-governance/models?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/ai-governance/incidents?org_id=${ORG_ID}`),
    ]).then(([statsRes, modelsRes, incidentsRes]) => {
      setLiveData({
        stats:     statsRes.status     === "fulfilled" ? statsRes.value     : null,
        models:    modelsRes.status    === "fulfilled" ? modelsRes.value    : null,
        incidents: incidentsRes.status === "fulfilled" ? incidentsRes.value : null,
      });
    }).finally(() => setDataLoading(false));
  };

  useEffect(() => { fetchData();}, []);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchData();
    setTimeout(() => setRefreshing(false), 800);
  };

  const stats     = liveData.stats     ?? MOCK_STATS;
  const models    = liveData.models    ?? MOCK_MODELS;
  const incidents = liveData.incidents ?? MOCK_INCIDENTS;

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
        title="AI Governance"
        description="AI/ML model governance, risk management, and incident tracking"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Models"         value={stats.total_models}        icon={Brain}       trend="flat" />
        <KpiCard title="Production Models"    value={stats.production_models}   icon={Activity}    trend="up"   className="border-green-500/20" />
        <KpiCard title="Open Incidents"       value={stats.open_incidents}      icon={AlertTriangle} trend="down" className="border-red-500/20" />
        <KpiCard title="Critical Risk Models" value={stats.critical_risk_models} icon={ShieldAlert} trend="down" className="border-orange-500/20" />
      </div>

      {/* Models Table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Brain className="h-4 w-4 text-blue-400" />
              AI/ML Models
            </CardTitle>
            <Badge className="text-[10px] border border-border text-muted-foreground">
              {models.length} models
            </Badge>
          </div>
          <CardDescription className="text-xs">Registered AI/ML models, deployment status, and risk classification</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Model Name</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Vendor</TableHead>
                  <TableHead className="text-[11px] h-8">Deployment</TableHead>
                  <TableHead className="text-[11px] h-8">Risk Level</TableHead>
                  <TableHead className="text-[11px] h-8">Data Class.</TableHead>
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
                  <TableRow key={m.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 text-[12px] font-medium">{m.name}</TableCell>
                    <TableCell className="py-2">
                      <Badge className="text-[10px] border border-blue-500/30 text-blue-400 bg-blue-500/10 uppercase font-mono">
                        {m.type}
                      </Badge>
                    </TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{m.vendor}</TableCell>
                    <TableCell className="py-2"><DeploymentBadge status={m.deployment_status ?? "development"} /></TableCell>
                    <TableCell className="py-2"><RiskBadge level={m.risk_level ?? "low"} /></TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{m.data_classification}</TableCell>
                  </TableRow>
                ))
              )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Incidents Table */}
      <Card className="border-red-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
              <AlertTriangle className="h-4 w-4" />
              AI Incidents
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
              {incidents.filter((inc: any) => inc.status === "open").length} open
            </Badge>
          </div>
          <CardDescription className="text-xs">Model incidents including hallucinations, bias, data leaks, and adversarial events</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Model Name</TableHead>
                  <TableHead className="text-[11px] h-8">Incident Type</TableHead>
                  <TableHead className="text-[11px] h-8">Severity</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {incidents.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  incidents.map((inc: any, i: number) => (
                  <TableRow key={inc.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 text-[12px] font-medium">{inc.model_name}</TableCell>
                    <TableCell className="py-2">
                      <Badge className="text-[10px] border border-purple-500/30 text-purple-400 bg-purple-500/10 font-mono">
                        {(inc.incident_type ?? "").replace(/_/g, " ")}
                      </Badge>
                    </TableCell>
                    <TableCell className="py-2"><SeverityBadge severity={inc.severity ?? "medium"} /></TableCell>
                    <TableCell className="py-2"><IncidentStatusBadge status={inc.status ?? "open"} /></TableCell>
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
