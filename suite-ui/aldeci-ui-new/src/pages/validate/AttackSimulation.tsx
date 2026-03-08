import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { motion } from "framer-motion";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Select, SelectTrigger, SelectContent, SelectItem, SelectValue } from "@/components/ui/select";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { DataTable } from "@/components/shared/data-table";
import {
  Swords, ChevronRight, Play, Users, Clock, Shield, CheckCircle2,
  AlertTriangle, Target, Activity, BookOpen, Zap, ArrowRight
} from "lucide-react";
import { mpteApi } from "@/lib/api";
import { toast } from "sonner";

// ── Types ──────────────────────────────────────────────────────────────────
interface KillChainStage {
  id: string;
  tactic: string;
  technique: string;
  techniqueId: string;
  status: "blocked" | "detected" | "missed" | "pending";
}

interface TableTopExercise {
  id: string;
  name: string;
  scenario: string;
  difficulty: "Low" | "Medium" | "High" | "Critical";
  participants: number;
  duration: string;
  lastRun: string;
  successRate: number;
  status: "scheduled" | "active" | "completed";
}

interface SimulationResult {
  id: string;
  scenario: string;
  tactics: number;
  techniquesUsed: number;
  blocked: number;
  detected: number;
  missed: number;
  outcome: "STOPPED" | "PARTIAL" | "BREACH";
  completedAt: string;
  teamScore: number;
}

// ── Mock Data ──────────────────────────────────────────────────────────────
const MOCK_KILL_CHAIN: KillChainStage[] = [
  { id: "kc-1", tactic: "Reconnaissance", technique: "Active Scanning", techniqueId: "T1595", status: "blocked" },
  { id: "kc-2", tactic: "Initial Access", technique: "Phishing", techniqueId: "T1566", status: "detected" },
  { id: "kc-3", tactic: "Execution", technique: "PowerShell", techniqueId: "T1059.001", status: "missed" },
  { id: "kc-4", tactic: "Persistence", technique: "Scheduled Task", techniqueId: "T1053.005", status: "missed" },
  { id: "kc-5", tactic: "Privilege Escalation", technique: "Token Impersonation", techniqueId: "T1134", status: "detected" },
  { id: "kc-6", tactic: "Defense Evasion", technique: "Obfuscated Files", techniqueId: "T1027", status: "missed" },
  { id: "kc-7", tactic: "Credential Access", technique: "OS Credential Dumping", techniqueId: "T1003", status: "blocked" },
  { id: "kc-8", tactic: "Exfiltration", technique: "Exfil Over C2", techniqueId: "T1041", status: "pending" },
];

const MOCK_EXERCISES: TableTopExercise[] = [
  { id: "ex-1", name: "APT28 Simulation", scenario: "Nation-state lateral movement via spear phishing", difficulty: "Critical", participants: 8, duration: "4h", lastRun: "2025-06-08", successRate: 62, status: "completed" },
  { id: "ex-2", name: "Ransomware Response", scenario: "LockBit variant deployment and containment", difficulty: "High", participants: 12, duration: "3h", lastRun: "2025-06-05", successRate: 74, status: "completed" },
  { id: "ex-3", name: "Supply Chain Compromise", scenario: "3CX-style dependency hijack", difficulty: "High", participants: 6, duration: "2h", lastRun: "2025-05-28", successRate: 51, status: "scheduled" },
  { id: "ex-4", name: "Insider Threat Hunt", scenario: "Privileged user data exfiltration over 30 days", difficulty: "Medium", participants: 5, duration: "2.5h", lastRun: "2025-05-15", successRate: 83, status: "scheduled" },
  { id: "ex-5", name: "Zero-Day Response", scenario: "Unpatched RCE in edge device, 2h detection window", difficulty: "Critical", participants: 10, duration: "5h", lastRun: "2025-06-10", successRate: 45, status: "active" },
];

const MOCK_RESULTS: SimulationResult[] = [
  { id: "sim-1", scenario: "APT28 Full Kill Chain", tactics: 11, techniquesUsed: 24, blocked: 9, detected: 8, missed: 7, outcome: "PARTIAL", completedAt: "2025-06-08 16:44", teamScore: 68 },
  { id: "sim-2", scenario: "Ransomware Deployment", tactics: 8, techniquesUsed: 17, blocked: 14, detected: 2, missed: 1, outcome: "STOPPED", completedAt: "2025-06-05 14:20", teamScore: 91 },
  { id: "sim-3", scenario: "BEC + Financial Fraud", tactics: 5, techniquesUsed: 9, blocked: 2, detected: 3, missed: 4, outcome: "BREACH", completedAt: "2025-05-30 11:00", teamScore: 33 },
  { id: "sim-4", scenario: "Cloud Account Takeover", tactics: 7, techniquesUsed: 15, blocked: 11, detected: 3, missed: 1, outcome: "STOPPED", completedAt: "2025-05-22 09:30", teamScore: 88 },
];

// ── Helpers ────────────────────────────────────────────────────────────────
const statusConfig = {
  blocked:  { label: "Blocked",  cls: "bg-green-500/10 text-green-400 border-green-500/30" },
  detected: { label: "Detected", cls: "bg-yellow-500/10 text-yellow-400 border-yellow-500/30" },
  missed:   { label: "Missed",   cls: "bg-red-500/10 text-red-400 border-red-500/30" },
  pending:  { label: "Pending",  cls: "bg-muted text-muted-foreground border-border" },
};

const outcomeConfig = {
  STOPPED: { cls: "bg-green-500/10 text-green-400 border-green-500/30" },
  PARTIAL: { cls: "bg-yellow-500/10 text-yellow-400 border-yellow-500/30" },
  BREACH:  { cls: "bg-red-500/10 text-red-400 border-red-500/30" },
};

const difficultyConfig = {
  Low:      "bg-blue-500/10 text-blue-400 border-blue-500/30",
  Medium:   "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
  High:     "bg-orange-500/10 text-orange-400 border-orange-500/30",
  Critical: "bg-red-500/10 text-red-400 border-red-500/30",
};

// ── Kill Chain Visualization ───────────────────────────────────────────────
function KillChainFlow({ stages }: { stages: KillChainStage[] }) {
  return (
    <div className="overflow-x-auto pb-2">
      <div className="flex items-start gap-1 min-w-max">
        {stages.map((stage, i) => {
          const cfg = statusConfig[stage.status];
          return (
            <div key={stage.id} className="flex items-center gap-1">
              <div className={`rounded-lg border px-3 py-2 text-center min-w-[100px] ${cfg.cls}`}>
                <p className="text-[10px] font-semibold uppercase tracking-wider opacity-70">{stage.tactic}</p>
                <p className="text-xs font-medium mt-0.5">{stage.technique}</p>
                <p className="text-[10px] font-mono mt-1 opacity-60">{stage.techniqueId}</p>
                <span className={`inline-flex mt-1.5 items-center rounded-full border px-1.5 py-0.5 text-[10px] font-medium ${cfg.cls}`}>
                  {cfg.label}
                </span>
              </div>
              {i < stages.length - 1 && <ArrowRight className="h-3.5 w-3.5 text-muted-foreground shrink-0" />}
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── Exercise Card ──────────────────────────────────────────────────────────
function ExerciseCard({ ex, onRun }: { ex: TableTopExercise; onRun: (id: string) => void }) {
  const diffCls = difficultyConfig[ex.difficulty];
  const statusMap = { scheduled: "outline", active: "default", completed: "secondary" } as const;
  return (
    <Card className="border-border/50 hover:border-primary/40 transition-colors">
      <CardHeader className="pb-2">
        <div className="flex items-start justify-between gap-2">
          <div>
            <CardTitle className="text-sm font-semibold">{ex.name}</CardTitle>
            <CardDescription className="text-xs mt-0.5 line-clamp-2">{ex.scenario}</CardDescription>
          </div>
          <span className={`inline-flex shrink-0 items-center rounded-full border px-2 py-0.5 text-xs font-medium ${diffCls}`}>{ex.difficulty}</span>
        </div>
      </CardHeader>
      <CardContent className="space-y-3">
        <div className="flex gap-4 text-xs text-muted-foreground">
          <span className="flex items-center gap-1"><Users className="h-3 w-3" /> {ex.participants}</span>
          <span className="flex items-center gap-1"><Clock className="h-3 w-3" /> {ex.duration}</span>
          <span className="flex items-center gap-1"><CheckCircle2 className="h-3 w-3 text-green-400" /> {ex.successRate}%</span>
        </div>
        <div className="h-1.5 rounded-full bg-muted">
          <div className="h-1.5 rounded-full bg-primary transition-all" style={{ width: `${ex.successRate}%` }} />
        </div>
        <div className="flex items-center justify-between">
          <Badge variant={statusMap[ex.status]}>{ex.status}</Badge>
          <Button size="sm" variant="outline" onClick={() => onRun(ex.id)} className="h-7 text-xs">
            <Play className="h-3 w-3 mr-1" /> Run
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

// ── Main Component ─────────────────────────────────────────────────────────
export default function AttackSimulation() {
  const queryClient = useQueryClient();
  const [selectedScenario, setSelectedScenario] = useState("apt28");

  const { data } = useQuery({
    queryKey: ["attack-simulations"],
    queryFn: () => mpteApi.list({ type: "simulation" }),
  });

  const runMutation = useMutation({
    mutationFn: (id: string) => mpteApi.launch({ exercise_id: id }),
    onSuccess: () => {
      toast.success("Tabletop exercise launched");
      queryClient.invalidateQueries({ queryKey: ["attack-simulations"] });
    },
    onError: () => toast.error("Launch failed — check agent availability"),
  });

  const exercises = (data as any)?.data ?? MOCK_EXERCISES;
  const results   = MOCK_RESULTS;

  const totalBlocked  = results.reduce((s, r) => s + r.blocked, 0);
  const totalDetected = results.reduce((s, r) => s + r.detected, 0);
  const totalMissed   = results.reduce((s, r) => s + r.missed, 0);

  const resultColumns = [
    { key: "scenario", header: "Scenario" },
    { key: "tactics",  header: "Tactics" },
    { key: "techniquesUsed", header: "Techniques" },
    { key: "blocked",  header: "Blocked",  render: (r: SimulationResult) => <span className="text-green-400 font-mono font-bold text-xs">{r.blocked}</span> },
    { key: "detected", header: "Detected", render: (r: SimulationResult) => <span className="text-yellow-400 font-mono font-bold text-xs">{r.detected}</span> },
    { key: "missed",   header: "Missed",   render: (r: SimulationResult) => <span className="text-red-400 font-mono font-bold text-xs">{r.missed}</span> },
    {
      key: "outcome", header: "Outcome",
      render: (r: SimulationResult) => (
        <span className={`inline-flex items-center rounded-full border px-2 py-0.5 text-xs font-medium ${outcomeConfig[r.outcome].cls}`}>{r.outcome}</span>
      ),
    },
    { key: "teamScore", header: "Team Score", render: (r: SimulationResult) => <span className={`font-mono font-bold text-sm ${r.teamScore >= 80 ? "text-green-400" : r.teamScore >= 60 ? "text-yellow-400" : "text-red-400"}`}>{r.teamScore}</span> },
    { key: "completedAt", header: "Completed" },
  ];

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="space-y-6">
      <PageHeader
        title="Attack Simulation"
        description="MITRE ATT&CK scenario builder, kill chain analysis, and tabletop exercises"
        badge="VALIDATE"
        actions={
          <Button size="sm">
            <Swords className="h-3.5 w-3.5 mr-1.5" /> New Scenario
          </Button>
        }
      />

      {/* KPI Row */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Techniques Blocked" value={totalBlocked} icon={Shield} trend="up" change={7} changeLabel="vs last month" />
        <KpiCard title="Techniques Detected" value={totalDetected} icon={Activity} trend="up" change={3} changeLabel="vs last month" />
        <KpiCard title="Techniques Missed" value={totalMissed} icon={AlertTriangle} trend="down" change={-5} changeLabel="vs last month" />
        <KpiCard title="Avg Team Score" value="70" icon={Target} trend="up" change={12} changeLabel="vs last quarter" />
      </div>

      <Tabs defaultValue="killchain">
        <TabsList>
          <TabsTrigger value="killchain">Kill Chain Analysis</TabsTrigger>
          <TabsTrigger value="tabletop">Tabletop Exercises</TabsTrigger>
          <TabsTrigger value="results">Simulation Results</TabsTrigger>
        </TabsList>

        <TabsContent value="killchain" className="mt-4 space-y-4">
          <Card className="border-border/50">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <div>
                  <CardTitle className="text-sm font-semibold">Active Kill Chain — APT28 Simulation</CardTitle>
                  <CardDescription className="text-xs mt-0.5">
                    Real-time stage tracking across MITRE ATT&CK Kill Chain
                  </CardDescription>
                </div>
                <Select value={selectedScenario} onValueChange={setSelectedScenario}>
                  <SelectTrigger className="w-44 text-xs h-8">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="apt28">APT28 Campaign</SelectItem>
                    <SelectItem value="ransomware">Ransomware Chain</SelectItem>
                    <SelectItem value="bec">BEC + Fraud</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </CardHeader>
            <CardContent>
              <KillChainFlow stages={MOCK_KILL_CHAIN} />
              <div className="flex gap-4 mt-4 text-xs">
                {(["blocked","detected","missed","pending"] as const).map(s => (
                  <span key={s} className={`flex items-center gap-1.5 inline-flex items-center rounded-full border px-2.5 py-1 ${statusConfig[s].cls}`}>
                    {statusConfig[s].label}: {MOCK_KILL_CHAIN.filter(k => k.status === s).length}
                  </span>
                ))}
              </div>
            </CardContent>
          </Card>

          {/* Tactic breakdown */}
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            {MOCK_KILL_CHAIN.slice(0, 4).map(stage => (
              <Card key={stage.id} className="border-border/50 p-4">
                <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">{stage.tactic}</p>
                <p className="text-sm font-medium mt-1">{stage.technique}</p>
                <p className="text-xs font-mono text-muted-foreground mt-0.5">{stage.techniqueId}</p>
                <span className={`inline-flex mt-2 items-center rounded-full border px-2 py-0.5 text-xs font-medium ${statusConfig[stage.status].cls}`}>
                  {statusConfig[stage.status].label}
                </span>
              </Card>
            ))}
          </div>
        </TabsContent>

        <TabsContent value="tabletop" className="mt-4">
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
            {exercises.map((ex: TableTopExercise) => (
              <ExerciseCard key={ex.id} ex={ex} onRun={() => runMutation.mutate(ex.id)} />
            ))}
          </div>
        </TabsContent>

        <TabsContent value="results" className="mt-4">
          <DataTable
            columns={resultColumns}
            data={results}
            emptyMessage="No simulations completed"
          />
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
