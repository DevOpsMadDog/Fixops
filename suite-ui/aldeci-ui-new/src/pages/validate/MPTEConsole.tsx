import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Progress } from "@/components/ui/progress";
import { Select, SelectTrigger, SelectContent, SelectItem, SelectValue } from "@/components/ui/select";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { DataTable } from "@/components/shared/data-table";
import {
  Play, Shield, AlertTriangle, CheckCircle2, XCircle, Clock,
  Cpu, Target, Activity, ChevronRight, RefreshCw, BarChart3
} from "lucide-react";
import { mpteApi } from "@/lib/api";
import { toast } from "sonner";

// ── Types ──────────────────────────────────────────────────────────────────
type VerdictType = "VULNERABLE_VERIFIED" | "NOT_APPLICABLE" | "MITIGATED" | "INCONCLUSIVE";
type ScanStatus = "running" | "completed" | "queued" | "failed";

interface ActiveScan {
  id: string;
  target: string;
  scanType: string;
  phase: number;
  totalPhases: number;
  currentPhaseName: string;
  status: ScanStatus;
  startedAt: string;
  eta: string;
  verdict?: VerdictType;
  confidence?: number;
}

interface SessionRecord {
  id: string;
  target: string;
  scanType: string;
  verdict: VerdictType;
  confidence: number;
  duration: string;
  completedAt: string;
  findings: number;
}

// ── Mock Data ──────────────────────────────────────────────────────────────
const PHASES = [
  "Recon", "Port Discovery", "Service Fingerprint", "Auth Probe",
  "SQLi Fuzz", "XSS Fuzz", "SSRF Probe", "XXE Injection",
  "IDOR Scan", "CSRF Detection", "Business Logic", "API Abuse",
  "Priv Escalation", "Lateral Movement", "Data Exfil Sim",
  "Log Evasion", "Persistence Check", "Cleanup Detection", "Report Gen"
];

const MOCK_ACTIVE_SCANS: ActiveScan[] = [
  {
    id: "scan-001",
    target: "api.payments.corp.internal",
    scanType: "Full Pentest",
    phase: 11,
    totalPhases: 19,
    currentPhaseName: "Business Logic",
    status: "running",
    startedAt: "14:22:08",
    eta: "~18 min",
    confidence: 87,
  },
  {
    id: "scan-002",
    target: "auth-service.prod.corp",
    scanType: "Auth Bypass",
    phase: 4,
    totalPhases: 19,
    currentPhaseName: "Auth Probe",
    status: "running",
    startedAt: "14:51:33",
    eta: "~41 min",
    confidence: 63,
  },
  {
    id: "scan-003",
    target: "admin-portal.corp.internal",
    scanType: "Injection Suite",
    phase: 19,
    totalPhases: 19,
    currentPhaseName: "Report Gen",
    status: "completed",
    verdict: "VULNERABLE_VERIFIED",
    startedAt: "12:00:14",
    eta: "Complete",
    confidence: 94,
  },
];

const MOCK_SESSION_HISTORY: SessionRecord[] = [
  { id: "ses-1001", target: "user-api.corp.internal", scanType: "Full Pentest", verdict: "VULNERABLE_VERIFIED", confidence: 94, duration: "1h 12m", completedAt: "2025-06-10 13:44", findings: 7 },
  { id: "ses-1002", target: "reporting.corp.internal", scanType: "XSS Suite", verdict: "MITIGATED", confidence: 88, duration: "28m", completedAt: "2025-06-10 11:20", findings: 0 },
  { id: "ses-1003", target: "legacy-app.corp", scanType: "Full Pentest", verdict: "INCONCLUSIVE", confidence: 41, duration: "2h 05m", completedAt: "2025-06-09 16:30", findings: 2 },
  { id: "ses-1004", target: "billing-svc.corp.internal", scanType: "API Abuse", verdict: "NOT_APPLICABLE", confidence: 99, duration: "14m", completedAt: "2025-06-09 09:15", findings: 0 },
  { id: "ses-1005", target: "data-export.corp", scanType: "Injection Suite", verdict: "VULNERABLE_VERIFIED", confidence: 97, duration: "52m", completedAt: "2025-06-08 17:08", findings: 3 },
  { id: "ses-1006", target: "sso.corp.internal", scanType: "Auth Bypass", verdict: "MITIGATED", confidence: 91, duration: "35m", completedAt: "2025-06-08 14:22", findings: 0 },
];

// ── Verdict badge helper ───────────────────────────────────────────────────
function VerdictBadge({ verdict }: { verdict: VerdictType }) {
  const config: Record<VerdictType, { label: string; className: string }> = {
    VULNERABLE_VERIFIED: { label: "Vulnerable Verified", className: "bg-red-500/10 text-red-400 border-red-500/30" },
    NOT_APPLICABLE:      { label: "Not Applicable",      className: "bg-blue-500/10 text-blue-400 border-blue-500/30" },
    MITIGATED:           { label: "Mitigated",           className: "bg-green-500/10 text-green-400 border-green-500/30" },
    INCONCLUSIVE:        { label: "Inconclusive",        className: "bg-yellow-500/10 text-yellow-400 border-yellow-500/30" },
  };
  const c = config[verdict];
  return <span className={`inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-medium ${c.className}`}>{c.label}</span>;
}

// ── Confidence Gauge ───────────────────────────────────────────────────────
function ConfidenceGauge({ value }: { value: number }) {
  const color = value >= 80 ? "text-green-400" : value >= 50 ? "text-yellow-400" : "text-red-400";
  const barColor = value >= 80 ? "bg-green-400" : value >= 50 ? "bg-yellow-400" : "bg-red-400";
  return (
    <div className="space-y-1">
      <div className="flex justify-between text-xs">
        <span className="text-muted-foreground">Confidence</span>
        <span className={`font-bold tabular-nums ${color}`}>{value}%</span>
      </div>
      <div className="h-1.5 w-full rounded-full bg-muted">
        <div className={`h-1.5 rounded-full transition-all ${barColor}`} style={{ width: `${value}%` }} />
      </div>
    </div>
  );
}

// ── Active Scan Card ───────────────────────────────────────────────────────
function ActiveScanCard({ scan }: { scan: ActiveScan }) {
  const pct = Math.round((scan.phase / scan.totalPhases) * 100);
  return (
    <Card className="border-border/50">
      <CardHeader className="pb-3">
        <div className="flex items-start justify-between gap-2">
          <div>
            <CardTitle className="text-sm font-semibold">{scan.target}</CardTitle>
            <p className="text-xs text-muted-foreground mt-0.5">{scan.scanType}</p>
          </div>
          {scan.verdict ? (
            <VerdictBadge verdict={scan.verdict} />
          ) : (
            <Badge variant="outline" className="text-xs border-primary/40 text-primary animate-pulse">
              Running
            </Badge>
          )}
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        {/* 19-phase progress */}
        <div className="space-y-1.5">
          <div className="flex justify-between text-xs text-muted-foreground">
            <span>Phase {scan.phase}/{scan.totalPhases} — {scan.currentPhaseName}</span>
            <span>{pct}%</span>
          </div>
          <Progress value={pct} className="h-2" />
          {/* Phase dots */}
          <div className="flex gap-0.5 flex-wrap mt-1">
            {PHASES.map((p, i) => (
              <div
                key={p}
                title={p}
                className={`h-1.5 w-1.5 rounded-full transition-colors ${
                  i + 1 < scan.phase ? "bg-primary" :
                  i + 1 === scan.phase ? "bg-yellow-400 animate-pulse" :
                  "bg-muted"
                }`}
              />
            ))}
          </div>
        </div>
        {scan.confidence !== undefined && <ConfidenceGauge value={scan.confidence} />}
        <div className="flex items-center justify-between text-xs text-muted-foreground pt-1">
          <span className="flex items-center gap-1"><Clock className="h-3 w-3" /> Started {scan.startedAt}</span>
          <span>ETA {scan.eta}</span>
        </div>
      </CardContent>
    </Card>
  );
}

// ── Main Component ─────────────────────────────────────────────────────────
export default function MPTEConsole() {
  const queryClient = useQueryClient();
  const [targetApp, setTargetApp] = useState("");
  const [scanType, setScanType] = useState("full-pentest");

  const { data: sessionsData } = useQuery({
    queryKey: ["mpte-sessions"],
    queryFn: () => mpteApi.list(),
    refetchInterval: 10_000,
  });

  const { data: activeData } = useQuery({
    queryKey: ["mpte-active"],
    queryFn: () => mpteApi.verdicts({ status: "running" }),
    refetchInterval: 5_000,
  });

  const launchMutation = useMutation({
    mutationFn: (data: { target: string; scan_type: string }) => mpteApi.launch(data),
    onSuccess: () => {
      toast.success("Micro-pentest launched", { description: `Target: ${targetApp}` });
      queryClient.invalidateQueries({ queryKey: ["mpte-active"] });
      setTargetApp("");
    },
    onError: () => {
      toast.error("Failed to launch scan — using mock data");
    },
  });

  const scans = (activeData as any)?.data ?? MOCK_ACTIVE_SCANS;
  const sessions = (sessionsData as any)?.data ?? MOCK_SESSION_HISTORY;

  const verdictCounts = {
    VULNERABLE_VERIFIED: sessions.filter((s: SessionRecord) => s.verdict === "VULNERABLE_VERIFIED").length,
    MITIGATED: sessions.filter((s: SessionRecord) => s.verdict === "MITIGATED").length,
    INCONCLUSIVE: sessions.filter((s: SessionRecord) => s.verdict === "INCONCLUSIVE").length,
    NOT_APPLICABLE: sessions.filter((s: SessionRecord) => s.verdict === "NOT_APPLICABLE").length,
  };

  const sessionColumns = [
    { key: "target", header: "Target" },
    { key: "scanType", header: "Scan Type" },
    {
      key: "verdict", header: "Verdict",
      render: (row: SessionRecord) => <VerdictBadge verdict={row.verdict} />,
    },
    {
      key: "confidence", header: "Confidence",
      render: (row: SessionRecord) => (
        <span className={`font-mono text-xs font-bold ${row.confidence >= 80 ? "text-green-400" : row.confidence >= 50 ? "text-yellow-400" : "text-red-400"}`}>
          {row.confidence}%
        </span>
      ),
    },
    { key: "findings", header: "Findings", render: (row: SessionRecord) => <span className={`font-mono text-xs ${row.findings > 0 ? "text-red-400 font-bold" : "text-muted-foreground"}`}>{row.findings}</span> },
    { key: "duration", header: "Duration" },
    { key: "completedAt", header: "Completed" },
  ];

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="space-y-6">
      <PageHeader
        title="MPTE Console"
        description="Micro-Pentest Engine — automated 19-phase exploitation verification"
        badge="VALIDATE"
        actions={
          <Button size="sm" variant="outline" onClick={() => queryClient.invalidateQueries({ queryKey: ["mpte-active"] })}>
            <RefreshCw className="h-3.5 w-3.5 mr-1.5" /> Refresh
          </Button>
        }
      />

      {/* KPI Row */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Vulnerable Verified" value={verdictCounts.VULNERABLE_VERIFIED} icon={AlertTriangle} trend="down" change={-12} changeLabel="this week" />
        <KpiCard title="Mitigated" value={verdictCounts.MITIGATED} icon={CheckCircle2} trend="up" change={8} changeLabel="this week" />
        <KpiCard title="Inconclusive" value={verdictCounts.INCONCLUSIVE} icon={Activity} trend="flat" />
        <KpiCard title="Avg Confidence" value="83%" icon={BarChart3} trend="up" change={4} changeLabel="vs last month" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Launch Form */}
        <Card className="border-border/50">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Target className="h-4 w-4 text-primary" /> Launch Scan
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Target Application</label>
              <Input
                placeholder="api.corp.internal or https://..."
                value={targetApp}
                onChange={e => setTargetApp(e.target.value)}
                className="text-sm"
              />
            </div>
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Scan Type</label>
              <Select value={scanType} onValueChange={setScanType}>
                <SelectTrigger className="text-sm">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="full-pentest">Full Pentest (19 phases)</SelectItem>
                  <SelectItem value="auth-bypass">Auth Bypass</SelectItem>
                  <SelectItem value="injection-suite">Injection Suite</SelectItem>
                  <SelectItem value="api-abuse">API Abuse</SelectItem>
                  <SelectItem value="xss-suite">XSS Suite</SelectItem>
                  <SelectItem value="recon-only">Recon Only</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Scan Profile</label>
              <Select defaultValue="standard">
                <SelectTrigger className="text-sm"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="standard">Standard (Balanced)</SelectItem>
                  <SelectItem value="stealth">Stealth (Low noise)</SelectItem>
                  <SelectItem value="aggressive">Aggressive (Max coverage)</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <Button
              className="w-full"
              disabled={!targetApp || launchMutation.isPending}
              onClick={() => launchMutation.mutate({ target: targetApp, scan_type: scanType })}
            >
              <Play className="h-4 w-4 mr-2" />
              {launchMutation.isPending ? "Launching..." : "Launch Scan"}
            </Button>
          </CardContent>
        </Card>

        {/* Active Scans */}
        <div className="lg:col-span-2 space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold flex items-center gap-2">
              <Cpu className="h-4 w-4 text-primary" /> Active Scans
              <Badge variant="outline" className="text-xs ml-1">{scans.filter((s: ActiveScan) => s.status === "running").length} running</Badge>
            </h3>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
            {scans.map((scan: ActiveScan) => (
              <ActiveScanCard key={scan.id} scan={scan} />
            ))}
          </div>
        </div>
      </div>

      {/* Verdict Summary + Session History */}
      <Tabs defaultValue="history">
        <TabsList>
          <TabsTrigger value="history">Session History</TabsTrigger>
          <TabsTrigger value="verdicts">Verdict Summary</TabsTrigger>
        </TabsList>
        <TabsContent value="history" className="mt-4">
          <DataTable
            columns={sessionColumns}
            data={sessions}
            emptyMessage="No sessions recorded"
          />
        </TabsContent>
        <TabsContent value="verdicts" className="mt-4">
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
            {(["VULNERABLE_VERIFIED", "MITIGATED", "INCONCLUSIVE", "NOT_APPLICABLE"] as VerdictType[]).map(v => (
              <Card key={v} className="border-border/50 p-5">
                <VerdictBadge verdict={v} />
                <p className="text-3xl font-bold tabular-nums mt-3">
                  {sessions.filter((s: SessionRecord) => s.verdict === v).length}
                </p>
                <p className="text-xs text-muted-foreground mt-1">sessions</p>
              </Card>
            ))}
          </div>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
