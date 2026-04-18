/**
 * Threat Model Dashboard
 *
 * STRIDE auto-generation, risk rating, and mitigation tracking.
 *   1. KPIs: Active Models, Open Threats, Critical Risks, Mitigations In Progress
 *   2. Models table (8 rows)
 *   3. STRIDE heatmap (6 cells)
 *   4. Threats list for selected model (10 rows)
 *   5. Mitigations tracker (8 items)
 *
 * Route: /threat-models
 * API stubs: GET /api/v1/threat-modeling/models, /api/v1/threat-modeling/threats
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Layers, AlertTriangle, Shield, Wrench, RefreshCw,
  Cpu, Zap, CheckCircle, Clock,
} from "lucide-react";

// ── API helpers ────────────────────────────────────────────────
const apiKey = localStorage.getItem("aldeci_api_key") || import.meta.env.VITE_API_KEY || "dev-key";
const apiFetch = (path: string) => fetch(`/api/v1${path}`, { headers: { "X-API-Key": apiKey } });
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── Mock data ──────────────────────────────────────────────────

interface ThreatModel {
  id: string;
  name: string;
  system_type: string;
  methodology: "STRIDE" | "PASTA";
  data_class: string;
  status: string;
  threats: number;
}

const MODELS: ThreatModel[] = [
  { id: "tm1", name: "Customer Portal API",          system_type: "api",          methodology: "STRIDE", data_class: "Confidential",  status: "Active",   threats: 8  },
  { id: "tm2", name: "Finance Microservice",          system_type: "microservice", methodology: "STRIDE", data_class: "Secret",        status: "Review",   threats: 11 },
  { id: "tm3", name: "Mobile Banking App",            system_type: "mobile",       methodology: "PASTA",  data_class: "Confidential",  status: "Active",   threats: 6  },
  { id: "tm4", name: "Cloud Infrastructure",          system_type: "cloud_infra",  methodology: "STRIDE", data_class: "Internal",      status: "Active",   threats: 14 },
  { id: "tm5", name: "IoT Sensor Network",            system_type: "iot",          methodology: "STRIDE", data_class: "Restricted",    status: "Draft",    threats: 9  },
  { id: "tm6", name: "Identity Provider (IdP)",       system_type: "web_app",      methodology: "STRIDE", data_class: "Secret",        status: "Active",   threats: 7  },
  { id: "tm7", name: "Data Analytics Platform",       system_type: "api",          methodology: "PASTA",  data_class: "Confidential",  status: "Archived", threats: 5  },
  { id: "tm8", name: "Supply Chain Integration Hub",  system_type: "microservice", methodology: "STRIDE", data_class: "Restricted",    status: "Review",   threats: 12 },
];

const STRIDE_COUNTS = [
  { cat: "S", label: "Spoofing",               count: 8,  desc: "Identity spoofing" },
  { cat: "T", label: "Tampering",              count: 11, desc: "Data tampering"    },
  { cat: "R", label: "Repudiation",            count: 4,  desc: "Non-repudiation"   },
  { cat: "I", label: "Info Disclosure",        count: 14, desc: "Info disclosure"   },
  { cat: "D", label: "Denial of Service",      count: 6,  desc: "DoS / DDoS"       },
  { cat: "E", label: "Elevation of Privilege", count: 9,  desc: "Priv escalation"   },
];

const THREATS_BY_MODEL: Record<string, { stride: string; title: string; rating: string; status: string; mitigations: number }[]> = {
  tm1: [
    { stride: "S", title: "JWT token forgery via weak secret",        rating: "critical", status: "Open",        mitigations: 1 },
    { stride: "T", title: "API response tampering via MITM",          rating: "high",     status: "In Progress", mitigations: 2 },
    { stride: "I", title: "PII exposure in error messages",           rating: "high",     status: "Open",        mitigations: 0 },
    { stride: "E", title: "IDOR — access other user's resources",     rating: "critical", status: "Open",        mitigations: 1 },
    { stride: "D", title: "Rate limit bypass — exhaustion attack",    rating: "medium",   status: "Mitigated",   mitigations: 3 },
    { stride: "R", title: "Missing audit log for admin actions",      rating: "medium",   status: "In Progress", mitigations: 1 },
    { stride: "T", title: "SQL injection in filter parameters",       rating: "critical", status: "Open",        mitigations: 0 },
    { stride: "I", title: "Sensitive data in URL query strings",      rating: "low",      status: "Mitigated",   mitigations: 2 },
  ],
  tm2: [
    { stride: "E", title: "Privilege escalation via misconfigured role", rating: "critical", status: "Open",        mitigations: 1 },
    { stride: "I", title: "Financial data leak via log injection",        rating: "critical", status: "In Progress", mitigations: 2 },
    { stride: "T", title: "Message queue poisoning",                      rating: "high",     status: "Open",        mitigations: 0 },
    { stride: "S", title: "Service account impersonation",               rating: "high",     status: "Open",        mitigations: 1 },
    { stride: "D", title: "Thundering herd — upstream cascade failure",  rating: "medium",   status: "Mitigated",   mitigations: 2 },
  ],
};

const MITIGATIONS = [
  { title: "Enforce RS256 JWT signing",         type: "preventive",  status: "Done",        owner: "AppSec",   due: "2026-04-18", effort: "low"    },
  { title: "Enable TLS 1.3 on all API routes",  type: "preventive",  status: "In Progress", owner: "NetSec",   due: "2026-04-20", effort: "low"    },
  { title: "Add structured error sanitization", type: "corrective",  status: "In Progress", owner: "AppSec",   due: "2026-04-22", effort: "medium" },
  { title: "Implement ABAC for resource access",type: "preventive",  status: "Planned",     owner: "IAM Team", due: "2026-04-25", effort: "high"   },
  { title: "Deploy rate limiting middleware",   type: "detective",   status: "Done",        owner: "Platform", due: "2026-04-16", effort: "medium" },
  { title: "Add admin action audit logging",    type: "detective",   status: "In Progress", owner: "SecEng",   due: "2026-04-21", effort: "medium" },
  { title: "Parameterize all DB queries",       type: "preventive",  status: "In Progress", owner: "AppSec",   due: "2026-04-19", effort: "high"   },
  { title: "Redact sensitive URL params",       type: "corrective",  status: "Done",        owner: "AppSec",   due: "2026-04-17", effort: "low"    },
];

// ── Helpers ────────────────────────────────────────────────────

const SYSTEM_TYPE_COLORS: Record<string, string> = {
  web_app:      "border-blue-500/30 text-blue-400 bg-blue-500/10",
  api:          "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
  microservice: "border-purple-500/30 text-purple-400 bg-purple-500/10",
  mobile:       "border-green-500/30 text-green-400 bg-green-500/10",
  iot:          "border-orange-500/30 text-orange-400 bg-orange-500/10",
  cloud_infra:  "border-amber-500/30 text-amber-400 bg-amber-500/10",
};

const DATA_CLASS_COLORS: Record<string, string> = {
  Public:       "border-border text-muted-foreground",
  Internal:     "border-blue-500/30 text-blue-400 bg-blue-500/10",
  Confidential: "border-amber-500/30 text-amber-400 bg-amber-500/10",
  Restricted:   "border-orange-500/30 text-orange-400 bg-orange-500/10",
  Secret:       "border-red-500/30 text-red-400 bg-red-500/10",
};

const STATUS_COLORS: Record<string, string> = {
  Active:   "border-green-500/30 text-green-400 bg-green-500/10",
  Review:   "border-amber-500/30 text-amber-400 bg-amber-500/10",
  Draft:    "border-blue-500/30 text-blue-400 bg-blue-500/10",
  Archived: "border-border text-muted-foreground",
};

const RATING_COLORS: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high:     "bg-amber-500/20 text-amber-400 border-amber-500/30",
  medium:   "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low:      "bg-green-500/20 text-green-400 border-green-500/30",
};

const STRIDE_CAT_COLORS: Record<string, string> = {
  S: "bg-purple-500/20 text-purple-300 border-purple-500/40",
  T: "bg-red-500/20 text-red-300 border-red-500/40",
  R: "bg-amber-500/20 text-amber-300 border-amber-500/40",
  I: "bg-orange-500/20 text-orange-300 border-orange-500/40",
  D: "bg-blue-500/20 text-blue-300 border-blue-500/40",
  E: "bg-rose-500/20 text-rose-300 border-rose-500/40",
};

const MITIGATION_TYPE_COLORS: Record<string, string> = {
  preventive: "border-green-500/30 text-green-400 bg-green-500/10",
  detective:  "border-blue-500/30 text-blue-400 bg-blue-500/10",
  corrective: "border-amber-500/30 text-amber-400 bg-amber-500/10",
};

const MITIGATION_STATUS_COLORS: Record<string, string> = {
  Done:        "border-green-500/30 text-green-400 bg-green-500/10",
  "In Progress": "border-amber-500/30 text-amber-400 bg-amber-500/10",
  Planned:     "border-blue-500/30 text-blue-400 bg-blue-500/10",
};

const EFFORT_COLORS: Record<string, string> = {
  low:    "border-green-500/30 text-green-400",
  medium: "border-amber-500/30 text-amber-400",
  high:   "border-red-500/30 text-red-400",
};

const HEATMAP_MAX = Math.max(...STRIDE_COUNTS.map((c) => c.count));

// ── Component ──────────────────────────────────────────────────

export default function ThreatModelDashboard() {
  const [selected, setSelected] = useState<string>("tm1");
  const [refreshing, setRefreshing] = useState(false);
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);

  const fetchData = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/threat-model-generator/models?org_id=default&limit=20`).then((r) => r.json()),
      apiFetch(`/threat-model-generator/stats?org_id=default`).then((r) => r.json()),
    ]).then(([modelsRes, statsRes]) => {
      const models = modelsRes.status === "fulfilled" ? modelsRes.value : null;
      const stats  = statsRes.status  === "fulfilled" ? statsRes.value  : null;
      if (models || stats) setLiveData({ models, stats });
    }).finally(() => setDataLoading(false));
  };

  useEffect(() => { fetchData(); }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchData();
    setTimeout(() => setRefreshing(false), 800);
  };

  const displayModels: typeof MODELS = Array.isArray(liveData?.models?.items ?? liveData?.models) && (liveData?.models?.items ?? liveData?.models).length > 0
    ? (liveData.models.items ?? liveData.models).map((m: any) => ({
        id:          m.model_id ?? m.id ?? String(Math.random()),
        name:        m.name ?? m.system_name ?? "—",
        system_type: m.system_type ?? "api",
        methodology: m.methodology ?? "STRIDE",
        data_class:  m.data_classification ?? m.data_class ?? "Internal",
        status:      m.status ?? "Draft",
        threats:     m.threat_count ?? m.threats ?? 0,
      }))
    : MODELS;

  const threats = THREATS_BY_MODEL[selected] ?? [];

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      {/* Header */}
      <PageHeader
        title="Threat Models"
        description="STRIDE auto-generation, risk rating, and mitigation tracking"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Active Models"            value={liveData?.stats?.total_models ?? liveData?.stats?.active_models ?? 8}  icon={Layers}        trend="up"   />
        <KpiCard title="Open Threats"             value={liveData?.stats?.open_threats ?? liveData?.stats?.total_threats ?? 34} icon={AlertTriangle}  trend="up"  className="border-amber-500/20" />
        <KpiCard title="Critical Risks"           value={liveData?.stats?.critical_risks ?? liveData?.stats?.critical_count ?? 7}  icon={Zap}           trend="up"  className="border-red-500/20" />
        <KpiCard title="Mitigations In Progress"  value={liveData?.stats?.mitigations_in_progress ?? liveData?.stats?.open_mitigations ?? 12} icon={Wrench}        trend="up"  />
      </div>

      {/* Models table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Cpu className="h-4 w-4 text-purple-400" />
              Threat Models
            </CardTitle>
            <Badge className="text-[10px] border border-border">{displayModels.length} models</Badge>
          </div>
          <CardDescription className="text-xs">Click a row to view threats for that model</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Name</TableHead>
                  <TableHead className="text-[11px] h-8">System</TableHead>
                  <TableHead className="text-[11px] h-8">Method</TableHead>
                  <TableHead className="text-[11px] h-8">Data Class</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Threats</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {displayModels.map((m) => (
                  <TableRow
                    key={m.id}
                    onClick={() => setSelected(m.id)}
                    className={cn(
                      "cursor-pointer hover:bg-muted/30 transition-colors",
                      selected === m.id && "bg-primary/5 border-l-2 border-l-primary"
                    )}
                  >
                    <TableCell className="text-xs font-medium py-2.5">{m.name}</TableCell>
                    <TableCell className="py-2.5">
                      <Badge className={cn("text-[10px] border", SYSTEM_TYPE_COLORS[m.system_type])}>
                        {m.system_type.replace("_", " ")}
                      </Badge>
                    </TableCell>
                    <TableCell className="py-2.5">
                      <Badge className="text-[10px] border border-border">{m.methodology}</Badge>
                    </TableCell>
                    <TableCell className="py-2.5">
                      <Badge className={cn("text-[10px] border", DATA_CLASS_COLORS[m.data_class])}>{m.data_class}</Badge>
                    </TableCell>
                    <TableCell className="py-2.5">
                      <Badge className={cn("text-[10px] border", STATUS_COLORS[m.status])}>{m.status}</Badge>
                    </TableCell>
                    <TableCell className="text-xs tabular-nums py-2.5 text-right font-bold">{m.threats}</TableCell>
                    <TableCell className="py-2.5 text-right">
                      <Button variant="outline" size="sm" className="h-6 px-2 text-[10px]">
                        Generate
                      </Button>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* STRIDE heatmap + Threats list */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        {/* STRIDE heatmap */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Shield className="h-4 w-4 text-red-400" />
              STRIDE Heatmap
            </CardTitle>
            <CardDescription className="text-xs">Threat count per STRIDE category</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-2 gap-3">
              {STRIDE_COUNTS.map((s) => {
                const intensity = s.count / HEATMAP_MAX;
                return (
                  <div
                    key={s.cat}
                    className={cn(
                      "rounded-lg border p-3 flex flex-col gap-1 transition-all",
                      STRIDE_CAT_COLORS[s.cat]
                    )}
                    style={{ opacity: 0.4 + intensity * 0.6 }}
                  >
                    <div className="flex items-center justify-between">
                      <span className="text-lg font-black">{s.cat}</span>
                      <span className="text-xl font-bold tabular-nums">{s.count}</span>
                    </div>
                    <span className="text-[10px] opacity-80">{s.label}</span>
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>

        {/* Threats list */}
        <Card className="lg:col-span-2">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 text-amber-400" />
                Threats — {displayModels.find((m) => m.id === selected)?.name}
              </CardTitle>
              <Badge className="text-[10px] border border-amber-500/30 text-amber-400 bg-amber-500/10">
                {threats.length} threats
              </Badge>
            </div>
          </CardHeader>
          <CardContent className="p-0">
            {threats.length === 0 ? (
              <p className="text-xs text-muted-foreground py-6 text-center">No threats for this model. Click a row above to explore.</p>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8 w-8">Cat</TableHead>
                    <TableHead className="text-[11px] h-8">Title</TableHead>
                    <TableHead className="text-[11px] h-8">Rating</TableHead>
                    <TableHead className="text-[11px] h-8">Status</TableHead>
                    <TableHead className="text-[11px] h-8 text-right">Mitigations</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {threats.map((t, i) => (
                    <TableRow key={i} className="hover:bg-muted/30">
                      <TableCell className="py-2">
                        <Badge className={cn("text-[10px] border w-6 h-6 flex items-center justify-center p-0 font-bold", STRIDE_CAT_COLORS[t.stride])}>
                          {t.stride}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-xs py-2 max-w-[200px]">{t.title}</TableCell>
                      <TableCell className="py-2">
                        <Badge className={cn("text-[10px] border capitalize", RATING_COLORS[t.rating])}>{t.rating}</Badge>
                      </TableCell>
                      <TableCell className="py-2">
                        <Badge className={cn(
                          "text-[10px] border",
                          t.status === "Open"        ? "border-red-500/30 text-red-400 bg-red-500/10" :
                          t.status === "In Progress" ? "border-amber-500/30 text-amber-400 bg-amber-500/10" :
                                                       "border-green-500/30 text-green-400 bg-green-500/10"
                        )}>{t.status}</Badge>
                      </TableCell>
                      <TableCell className="text-xs tabular-nums py-2 text-right text-muted-foreground">{t.mitigations}</TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Mitigations tracker */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Wrench className="h-4 w-4 text-green-400" />
              Mitigations Tracker
            </CardTitle>
            <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">
              {MITIGATIONS.filter((m) => m.status === "Done").length} of {MITIGATIONS.length} done
            </Badge>
          </div>
          <CardDescription className="text-xs">Remediation controls with type, owner, effort, and due date</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Mitigation</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8">Owner</TableHead>
                  <TableHead className="text-[11px] h-8">Due</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Effort</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {MITIGATIONS.map((m, i) => (
                  <TableRow key={i} className="hover:bg-muted/30">
                    <TableCell className="text-xs py-2.5 font-medium flex items-center gap-2">
                      {m.status === "Done"
                        ? <CheckCircle className="h-3.5 w-3.5 text-green-500 shrink-0" />
                        : <Clock className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                      }
                      {m.title}
                    </TableCell>
                    <TableCell className="py-2.5">
                      <Badge className={cn("text-[10px] border capitalize", MITIGATION_TYPE_COLORS[m.type])}>{m.type}</Badge>
                    </TableCell>
                    <TableCell className="py-2.5">
                      <Badge className={cn("text-[10px] border", MITIGATION_STATUS_COLORS[m.status])}>{m.status}</Badge>
                    </TableCell>
                    <TableCell className="text-xs py-2.5 text-muted-foreground">{m.owner}</TableCell>
                    <TableCell className="text-xs tabular-nums py-2.5 text-muted-foreground">{m.due}</TableCell>
                    <TableCell className="py-2.5 text-right">
                      <Badge className={cn("text-[10px] border capitalize", EFFORT_COLORS[m.effort])}>{m.effort}</Badge>
                    </TableCell>
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
