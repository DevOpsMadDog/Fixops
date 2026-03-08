import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Select, SelectTrigger, SelectContent, SelectItem, SelectValue } from "@/components/ui/select";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { DataTable } from "@/components/shared/data-table";
import {
  Zap, AlertTriangle, Clock, BarChart3, AlertCircle, CheckCircle2,
  Play, Plus, Users, Timer, Activity, TrendingUp
} from "lucide-react";
import {
  RadarChart, Radar, PolarGrid, PolarAngleAxis, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis, Tooltip, Cell
} from "recharts";
import { failApi } from "@/lib/api";
import { toast } from "sonner";

// ── Types ──────────────────────────────────────────────────────────────────
interface ActiveDrill {
  id: string;
  name: string;
  component: string;
  cveId: string;
  severity: "Critical" | "High" | "Medium" | "Low";
  status: "running" | "detection" | "triage" | "remediation" | "grading";
  startedAt: string;
  teamLead: string;
  progress: number;
}

interface DrillRecord {
  id: string;
  name: string;
  component: string;
  cveId: string;
  severity: "Critical" | "High" | "Medium" | "Low";
  detection: number;
  triage: number;
  remediation: number;
  communication: number;
  overallScore: number;
  mttr: string;
  completedAt: string;
}

interface NeglectZone {
  id: string;
  component: string;
  team: string;
  daysSinceDrill: number;
  riskLevel: "Critical" | "High" | "Medium";
  openFindings: number;
}

// ── Mock Data ──────────────────────────────────────────────────────────────
const MOCK_ACTIVE_DRILLS: ActiveDrill[] = [
  { id: "d-1", name: "Log4Shell Variant", component: "logging-service", cveId: "CVE-2021-44228", severity: "Critical", status: "remediation", startedAt: "09:15", teamLead: "S. Chen", progress: 72 },
  { id: "d-2", name: "Spring4Shell Sim", component: "api-gateway", cveId: "CVE-2022-22965", severity: "High", status: "detection", startedAt: "11:30", teamLead: "A. Patel", progress: 31 },
  { id: "d-3", name: "ProxyLogon Clone", component: "mail-relay", cveId: "CVE-2021-26855", severity: "Critical", status: "triage", startedAt: "10:00", teamLead: "R. Okafor", progress: 55 },
];

const MOCK_TEAM_SCORES = [
  { dimension: "Detection",      score: 78, fullMark: 100 },
  { dimension: "Triage",         score: 65, fullMark: 100 },
  { dimension: "Remediation",    score: 82, fullMark: 100 },
  { dimension: "Communication",  score: 70, fullMark: 100 },
];

const MOCK_NEGLECT_ZONES: NeglectZone[] = [
  { id: "nz-1", component: "legacy-auth-svc", team: "Platform", daysSinceDrill: 142, riskLevel: "Critical", openFindings: 7 },
  { id: "nz-2", component: "data-warehouse-api", team: "Data Engineering", daysSinceDrill: 118, riskLevel: "High", openFindings: 4 },
  { id: "nz-3", component: "reporting-v1", team: "BI Team", daysSinceDrill: 97, riskLevel: "High", openFindings: 2 },
  { id: "nz-4", component: "backup-controller", team: "Ops", daysSinceDrill: 91, riskLevel: "Medium", openFindings: 1 },
];

const MOCK_DRILL_HISTORY: DrillRecord[] = [
  { id: "dh-1", name: "Log4Shell Full Drill", component: "logging-service", cveId: "CVE-2021-44228", severity: "Critical", detection: 85, triage: 70, remediation: 90, communication: 75, overallScore: 80, mttr: "1h 22m", completedAt: "2025-06-08" },
  { id: "dh-2", name: "SQLi Injection Drill", component: "user-api", cveId: "CVE-2023-1234", severity: "High", detection: 90, triage: 85, remediation: 88, communication: 92, overallScore: 89, mttr: "44m", completedAt: "2025-06-06" },
  { id: "dh-3", name: "SSRF Auth Bypass", component: "payment-svc", cveId: "CVE-2022-9876", severity: "Critical", detection: 45, triage: 60, remediation: 55, communication: 50, overallScore: 53, mttr: "3h 10m", completedAt: "2025-06-03" },
  { id: "dh-4", name: "Deserialization RCE", component: "message-broker", cveId: "CVE-2023-5432", severity: "High", detection: 72, triage: 68, remediation: 78, communication: 65, overallScore: 71, mttr: "1h 55m", completedAt: "2025-05-30" },
  { id: "dh-5", name: "XXE Injection Sim", component: "xml-processor", cveId: "CVE-2021-9999", severity: "Medium", detection: 88, triage: 82, remediation: 85, communication: 87, overallScore: 86, mttr: "52m", completedAt: "2025-05-25" },
];

const INDUSTRY_COMPARISON = [
  { name: "Detection",     yours: 78, industry: 65 },
  { name: "Triage",        yours: 65, industry: 60 },
  { name: "Remediation",   yours: 82, industry: 70 },
  { name: "Communication", yours: 70, industry: 58 },
];

const SCENARIOS = [
  "Log4Shell (CVE-2021-44228)",
  "ProxyLogon (CVE-2021-26855)",
  "Spring4Shell (CVE-2022-22965)",
  "MOVEit Transfer (CVE-2023-34362)",
  "CitrixBleed (CVE-2023-4966)",
  "OWASSRF (CVE-2022-41080)",
  "PaperCut Auth Bypass (CVE-2023-27350)",
  "VMware vCenter (CVE-2023-20887)",
];

const severityConfig = {
  Critical: "bg-red-500/10 text-red-400 border-red-500/30",
  High:     "bg-orange-500/10 text-orange-400 border-orange-500/30",
  Medium:   "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
  Low:      "bg-blue-500/10 text-blue-400 border-blue-500/30",
};

const drillStatusConfig = {
  running:     { label: "Injecting",   cls: "border-red-500/40 text-red-400" },
  detection:   { label: "Detection",   cls: "border-yellow-500/40 text-yellow-400" },
  triage:      { label: "Triage",      cls: "border-orange-500/40 text-orange-400" },
  remediation: { label: "Remediation", cls: "border-blue-500/40 text-blue-400" },
  grading:     { label: "Grading",     cls: "border-green-500/40 text-green-400" },
};

// ── New Drill Dialog ───────────────────────────────────────────────────────
function NewDrillDialog({ onClose, onLaunch }: { onClose: () => void; onLaunch: (scenario: string) => void }) {
  const [selected, setSelected] = useState(SCENARIOS[0]);
  const [team, setTeam] = useState("platform");
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <motion.div initial={{ opacity: 0, scale: 0.95 }} animate={{ opacity: 1, scale: 1 }} className="w-full max-w-md">
        <Card className="border-border/50">
          <CardHeader>
            <CardTitle className="text-base">New Fault Injection Drill</CardTitle>
            <CardDescription>Select a scenario and target team</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Scenario</label>
              <Select value={selected} onValueChange={setSelected}>
                <SelectTrigger className="text-sm"><SelectValue /></SelectTrigger>
                <SelectContent>
                  {SCENARIOS.map(s => <SelectItem key={s} value={s}>{s}</SelectItem>)}
                </SelectContent>
              </Select>
            </div>
            <div className="space-y-1.5">
              <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider">Target Team</label>
              <Select value={team} onValueChange={setTeam}>
                <SelectTrigger className="text-sm"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="platform">Platform Engineering</SelectItem>
                  <SelectItem value="backend">Backend Team</SelectItem>
                  <SelectItem value="security">Security Operations</SelectItem>
                  <SelectItem value="data">Data Engineering</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="flex gap-2 justify-end pt-2">
              <Button variant="outline" size="sm" onClick={onClose}>Cancel</Button>
              <Button size="sm" onClick={() => { onLaunch(selected); onClose(); }}>
                <Zap className="h-3.5 w-3.5 mr-1.5" /> Inject Drill
              </Button>
            </div>
          </CardContent>
        </Card>
      </motion.div>
    </div>
  );
}

// ── Main Component ─────────────────────────────────────────────────────────
export default function FAILEngine() {
  const queryClient = useQueryClient();
  const [showNewDrill, setShowNewDrill] = useState(false);

  const { data: drillsData } = useQuery({
    queryKey: ["fail-drills"],
    queryFn: () => failApi.getDrills({ status: "active" }),
    refetchInterval: 8_000,
  });

  const { data: neglectData } = useQuery({
    queryKey: ["fail-neglect"],
    queryFn: () => failApi.getNeglectZones(),
  });

  const { data: historyData } = useQuery({
    queryKey: ["fail-history"],
    queryFn: () => failApi.getHistory(),
  });

  const injectMutation = useMutation({
    mutationFn: (scenario: string) => failApi.inject({ scenario }),
    onSuccess: () => {
      toast.success("Drill injected", { description: "Team notified. Monitoring active." });
      queryClient.invalidateQueries({ queryKey: ["fail-drills"] });
    },
    onError: () => toast.error("Injection failed"),
  });

  const drills   = (drillsData as any)?.data ?? MOCK_ACTIVE_DRILLS;
  const neglect  = (neglectData as any)?.data ?? MOCK_NEGLECT_ZONES;
  const history  = (historyData as any)?.data ?? MOCK_DRILL_HISTORY;
  const avgScore = Math.round(MOCK_DRILL_HISTORY.reduce((s, r) => s + r.overallScore, 0) / MOCK_DRILL_HISTORY.length);

  const historyColumns = [
    { key: "name", header: "Drill Name" },
    { key: "component", header: "Component" },
    { key: "cveId", header: "CVE" },
    { key: "severity", header: "Severity", render: (r: DrillRecord) => <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${severityConfig[r.severity]}`}>{r.severity}</span> },
    { key: "detection", header: "Detection", render: (r: DrillRecord) => <span className="font-mono text-xs">{r.detection}</span> },
    { key: "triage", header: "Triage", render: (r: DrillRecord) => <span className="font-mono text-xs">{r.triage}</span> },
    { key: "remediation", header: "Remediation", render: (r: DrillRecord) => <span className="font-mono text-xs">{r.remediation}</span> },
    { key: "overallScore", header: "Score", render: (r: DrillRecord) => <span className={`font-mono font-bold text-sm ${r.overallScore >= 80 ? "text-green-400" : r.overallScore >= 60 ? "text-yellow-400" : "text-red-400"}`}>{r.overallScore}</span> },
    { key: "mttr", header: "MTTR" },
    { key: "completedAt", header: "Date" },
  ];

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="space-y-6">
      {showNewDrill && (
        <NewDrillDialog
          onClose={() => setShowNewDrill(false)}
          onLaunch={(s) => injectMutation.mutate(s)}
        />
      )}

      <PageHeader
        title="FAIL Engine"
        description="Fault Injection & Live Testing — inject synthetic CVEs to stress-test response readiness"
        badge="VALIDATE"
        actions={
          <Button size="sm" onClick={() => setShowNewDrill(true)}>
            <Plus className="h-3.5 w-3.5 mr-1.5" /> New Drill
          </Button>
        }
      />

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Active Drills" value={drills.length} icon={Zap} trend="flat" />
        <KpiCard title="Avg Score" value={`${avgScore}/100`} icon={BarChart3} trend="up" change={6} changeLabel="vs last quarter" />
        <KpiCard title="Neglect Zones" value={neglect.length} icon={AlertTriangle} trend="down" change={-2} changeLabel="vs last month" />
        <KpiCard title="Avg MTTR" value="1h 33m" icon={Timer} trend="down" change={-18} changeLabel="vs last quarter" />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        {/* Active Drills */}
        <div className="xl:col-span-2 space-y-3">
          <h3 className="text-sm font-semibold flex items-center gap-2">
            <Activity className="h-4 w-4 text-primary" /> Active Drills
          </h3>
          {drills.map((drill: ActiveDrill) => {
            const scfg = drillStatusConfig[drill.status];
            return (
              <Card key={drill.id} className="border-border/50">
                <CardContent className="p-4">
                  <div className="flex items-start justify-between gap-3 mb-3">
                    <div>
                      <p className="text-sm font-semibold">{drill.name}</p>
                      <p className="text-xs text-muted-foreground">{drill.component} · <span className="font-mono">{drill.cveId}</span></p>
                    </div>
                    <div className="flex gap-1.5">
                      <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${severityConfig[drill.severity]}`}>{drill.severity}</span>
                      <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${scfg.cls} animate-pulse`}>{scfg.label}</span>
                    </div>
                  </div>
                  <Progress value={drill.progress} className="h-1.5" />
                  <div className="flex justify-between text-xs text-muted-foreground mt-1.5">
                    <span className="flex items-center gap-1"><Users className="h-3 w-3" /> {drill.teamLead}</span>
                    <span className="flex items-center gap-1"><Clock className="h-3 w-3" /> Started {drill.startedAt}</span>
                    <span>{drill.progress}%</span>
                  </div>
                </CardContent>
              </Card>
            );
          })}
        </div>

        {/* Team Score Radar */}
        <Card className="border-border/50">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold">Team Score Card</CardTitle>
            <CardDescription className="text-xs">4-dimension readiness assessment</CardDescription>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={220}>
              <RadarChart data={MOCK_TEAM_SCORES} margin={{ top: 10, right: 20, bottom: 10, left: 20 }}>
                <PolarGrid stroke="rgba(255,255,255,0.1)" />
                <PolarAngleAxis dataKey="dimension" tick={{ fontSize: 11, fill: "hsl(var(--muted-foreground))" }} />
                <Radar name="Score" dataKey="score" stroke="hsl(var(--primary))" fill="hsl(var(--primary))" fillOpacity={0.2} />
              </RadarChart>
            </ResponsiveContainer>
            <div className="grid grid-cols-2 gap-2 mt-2">
              {MOCK_TEAM_SCORES.map(d => (
                <div key={d.dimension} className="text-center">
                  <p className="text-xs text-muted-foreground">{d.dimension}</p>
                  <p className={`text-lg font-bold tabular-nums ${d.score >= 80 ? "text-green-400" : d.score >= 60 ? "text-yellow-400" : "text-red-400"}`}>{d.score}</p>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      <Tabs defaultValue="neglect">
        <TabsList>
          <TabsTrigger value="neglect">Neglect Zones</TabsTrigger>
          <TabsTrigger value="history">Drill History</TabsTrigger>
          <TabsTrigger value="industry">Industry Comparison</TabsTrigger>
        </TabsList>

        <TabsContent value="neglect" className="mt-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {neglect.map((zone: NeglectZone) => (
              <Card key={zone.id} className="border-border/50">
                <CardContent className="p-4 flex items-center justify-between gap-3">
                  <div className="flex items-center gap-3">
                    <div className="rounded-lg bg-orange-500/10 p-2">
                      <AlertCircle className="h-4 w-4 text-orange-400" />
                    </div>
                    <div>
                      <p className="text-sm font-semibold">{zone.component}</p>
                      <p className="text-xs text-muted-foreground">{zone.team} · {zone.openFindings} open findings</p>
                    </div>
                  </div>
                  <div className="text-right shrink-0">
                    <p className="text-lg font-bold tabular-nums text-orange-400">{zone.daysSinceDrill}d</p>
                    <p className="text-xs text-muted-foreground">since drill</p>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="history" className="mt-4">
          <DataTable
            columns={historyColumns}
            data={history}
            emptyMessage="No drills completed"
          />
        </TabsContent>

        <TabsContent value="industry" className="mt-4">
          <Card className="border-border/50">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <TrendingUp className="h-4 w-4 text-primary" /> Industry Benchmark Comparison
              </CardTitle>
              <CardDescription className="text-xs">Your scores vs. industry median (Fortune 500 peer group)</CardDescription>
            </CardHeader>
            <CardContent>
              <ResponsiveContainer width="100%" height={220}>
                <BarChart data={INDUSTRY_COMPARISON} margin={{ top: 5, right: 20, left: 0, bottom: 5 }}>
                  <XAxis dataKey="name" tick={{ fontSize: 11, fill: "hsl(var(--muted-foreground))" }} axisLine={false} tickLine={false} />
                  <YAxis domain={[0, 100]} tick={{ fontSize: 11, fill: "hsl(var(--muted-foreground))" }} axisLine={false} tickLine={false} />
                  <Tooltip contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 8, fontSize: 12 }} />
                  <Bar dataKey="yours" name="Your Score" fill="hsl(var(--primary))" radius={[3, 3, 0, 0]} />
                  <Bar dataKey="industry" name="Industry Median" fill="hsl(var(--muted-foreground))" fillOpacity={0.4} radius={[3, 3, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
