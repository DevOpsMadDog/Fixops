import { toArray } from "@/lib/api-utils";
import { useState, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
  DialogFooter,
} from "@/components/ui/dialog";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { motion } from "framer-motion";
import {
  Swords,
  Play,
  Target,
  Activity,
  TrendingUp,
  Search,
  ChevronRight,
  AlertTriangle,
  CheckCircle,
  Clock,
} from "lucide-react";
import { useMpteResults, useRunMpteScan } from "@/hooks/use-api";

const MITRE_TECHNIQUES = {
  "Initial Access": [
    { id: "T1566", name: "Phishing" },
    { id: "T1190", name: "Exploit Public-Facing Application" },
    { id: "T1133", name: "External Remote Services" },
    { id: "T1078", name: "Valid Accounts" },
  ],
  Execution: [
    { id: "T1059", name: "Command and Scripting Interpreter" },
    { id: "T1203", name: "Exploitation for Client Execution" },
    { id: "T1569", name: "System Services" },
  ],
  Persistence: [
    { id: "T1547", name: "Boot or Logon Autostart Execution" },
    { id: "T1543", name: "Create or Modify System Process" },
    { id: "T1505", name: "Server Software Component" },
  ],
  "Privilege Escalation": [
    { id: "T1068", name: "Exploitation for Privilege Escalation" },
    { id: "T1134", name: "Access Token Manipulation" },
    { id: "T1548", name: "Abuse Elevation Control Mechanism" },
  ],
  "Defense Evasion": [
    { id: "T1036", name: "Masquerading" },
    { id: "T1055", name: "Process Injection" },
    { id: "T1070", name: "Indicator Removal" },
  ],
  "Lateral Movement": [
    { id: "T1021", name: "Remote Services" },
    { id: "T1550", name: "Use Alternate Authentication Material" },
    { id: "T1534", name: "Internal Spearphishing" },
  ],
  Exfiltration: [
    { id: "T1041", name: "Exfiltration Over C2 Channel" },
    { id: "T1048", name: "Exfiltration Over Alternative Protocol" },
    { id: "T1567", name: "Exfiltration Over Web Service" },
  ],
};

const KILL_CHAIN_PHASES = [
  { label: "Reconnaissance", color: "#6366f1" },
  { label: "Weaponization", color: "#8b5cf6" },
  { label: "Delivery", color: "#a855f7" },
  { label: "Exploitation", color: "#d946ef" },
  { label: "Installation", color: "#ec4899" },
  { label: "C2", color: "#f43f5e" },
  { label: "Actions", color: "#ef4444" },
];

function KillChainDiagram({ activePhase = -1 }: { activePhase?: number }) {
  return (
    <div className="flex items-center gap-0 overflow-x-auto pb-2">
      {KILL_CHAIN_PHASES.map((phase, i) => (
        <div key={phase.label} className="flex items-center">
          <div
            className={`relative flex flex-col items-center px-3 py-2 rounded-sm min-w-[90px] transition-all ${
              i <= activePhase
                ? "opacity-100"
                : "opacity-40"
            }`}
            style={{
              background:
                i <= activePhase
                  ? phase.color + "22"
                  : "hsl(var(--muted)/0.3)",
              border: `1px solid ${i <= activePhase ? phase.color + "66" : "transparent"}`,
            }}
          >
            <span
              className="text-[10px] font-semibold uppercase tracking-wide"
              style={{ color: i <= activePhase ? phase.color : "hsl(var(--muted-foreground))" }}
            >
              {phase.label}
            </span>
            {i <= activePhase && (
              <CheckCircle className="h-3 w-3 mt-1" style={{ color: phase.color }} />
            )}
          </div>
          {i < KILL_CHAIN_PHASES.length - 1 && (
            <ChevronRight
              className="h-4 w-4 shrink-0"
              style={{
                color: i < activePhase ? KILL_CHAIN_PHASES[i].color : "hsl(var(--muted-foreground))",
              }}
            />
          )}
        </div>
      ))}
    </div>
  );
}

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, { variant: "default" | "secondary" | "outline" | "destructive"; label: string }> = {
    running: { variant: "default", label: "Running" },
    completed: { variant: "secondary", label: "Completed" },
    failed: { variant: "destructive", label: "Failed" },
    queued: { variant: "outline", label: "Queued" },
    pending: { variant: "outline", label: "Pending" },
  };
  const cfg = map[status] ?? { variant: "outline" as const, label: status };
  return <Badge variant={cfg.variant}>{cfg.label}</Badge>;
}

function ScenarioBuilderCard({
  onRun,
}: {
  onRun: (p: unknown) => void;
}) {
  const [category, setCategory] = useState("");
  const [technique, setTechnique] = useState("");
  const [target, setTarget] = useState("");
  const [evasion, setEvasion] = useState("none");

  const techniques =
    MITRE_TECHNIQUES[category as keyof typeof MITRE_TECHNIQUES] ?? [];

  const handleRun = () => {
    onRun({ technique, target, evasion, category, scan_type: "attack_simulation" });
    setTarget("");
  };

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-sm font-medium flex items-center gap-2">
          <Swords className="h-4 w-4 text-primary" />
          Scenario Builder
        </CardTitle>
        <CardDescription className="text-xs">
          Configure a MITRE ATT&CK technique simulation
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <div className="space-y-2">
            <Label>ATT&CK Category</Label>
            <Select
              value={category}
              onValueChange={(v) => {
                setCategory(v);
                setTechnique("");
              }}
            >
              <SelectTrigger>
                <SelectValue placeholder="Select category..." />
              </SelectTrigger>
              <SelectContent>
                {Object.keys(MITRE_TECHNIQUES).map((cat) => (
                  <SelectItem key={cat} value={cat}>
                    {cat}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-2">
            <Label>Technique</Label>
            <Select
              value={technique}
              onValueChange={setTechnique}
              disabled={!category}
            >
              <SelectTrigger>
                <SelectValue placeholder="Select technique..." />
              </SelectTrigger>
              <SelectContent>
                {techniques.map((t) => (
                  <SelectItem key={t.id} value={t.id}>
                    {t.id} — {t.name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-2">
            <Label>Target</Label>
            <Input
              placeholder="IP, hostname, or CIDR range"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
            />
          </div>
          <div className="space-y-2">
            <Label>Evasion Level</Label>
            <Select value={evasion} onValueChange={setEvasion}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="none">None</SelectItem>
                <SelectItem value="low">Low</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="high">High (Stealth)</SelectItem>
              </SelectContent>
            </Select>
          </div>
        </div>
        <div className="flex justify-end gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              setCategory("");
              setTechnique("");
              setTarget("");
            }}
          >
            Reset
          </Button>
          <Button
            size="sm"
            disabled={!technique || !target}
            onClick={handleRun}
          >
            <Play className="h-4 w-4 mr-2" />
            Run Simulation
          </Button>
        </div>
      </CardContent>
    </Card>
  );
}

export default function AttackSimulation() {
  const resultsQuery = useMpteResults({ type: "attack_simulation" });
  const runSimulation = useRunMpteScan();

  const [search, setSearch] = useState("");
  const [statusFilter, setStatusFilter] = useState("all");
  const [selectedSim, setSelectedSim] = useState<Record<string, unknown> | null>(null);
  const [detailOpen, setDetailOpen] = useState(false);

  const refetch = useCallback(() => resultsQuery.refetch(), [resultsQuery]);

  if (resultsQuery.isLoading) return <PageSkeleton />;
  if (resultsQuery.isError)
    return <ErrorState message="Failed to load simulation data" onRetry={refetch} />;

  const simulations: Record<string, unknown>[] =
    toArray(resultsQuery.data);

  const active = simulations.filter(
    (s) => (s.status as string) === "running" || (s.status as string) === "queued"
  ).length;
  const completed = simulations.filter((s) => (s.status as string) === "completed").length;
  const findingsGenerated = simulations.reduce(
    (acc, s) => acc + ((s.findings_count as number) ?? 0),
    0
  );
  const avgScore =
    simulations.length > 0
      ? Math.round(
          simulations.reduce((acc, s) => acc + ((s.score as number) ?? 0), 0) /
            simulations.length
        )
      : 0;

  const filtered = simulations.filter((s) => {
    const matchSearch =
      !search ||
      (s.scenario as string)?.toLowerCase().includes(search.toLowerCase()) ||
      (s.target as string)?.toLowerCase().includes(search.toLowerCase());
    const matchStatus = statusFilter === "all" || s.status === statusFilter;
    return matchSearch && matchStatus;
  });

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      <PageHeader
        title="Attack Simulation"
        description="MITRE ATT&CK scenario-based adversary emulation and kill chain analysis"
      >
        <Button variant="outline" onClick={refetch}>
          <Activity className="h-4 w-4 mr-2" />
          Refresh
        </Button>
      </PageHeader>

      {/* KPI Row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard
          title="Active Simulations"
          value={active}
          icon={<Play className="h-4 w-4" />}
        />
        <KpiCard
          title="Completed"
          value={completed}
          icon={<CheckCircle className="h-4 w-4" />}
        />
        <KpiCard
          title="Findings Generated"
          value={findingsGenerated}
          icon={<AlertTriangle className="h-4 w-4" />}
        />
        <KpiCard
          title="Avg Score"
          value={`${avgScore}/100`}
          icon={<TrendingUp className="h-4 w-4" />}
        />
      </div>

      <Tabs defaultValue="builder">
        <TabsList>
          <TabsTrigger value="builder">Scenario Builder</TabsTrigger>
          <TabsTrigger value="history">Simulation History</TabsTrigger>
          <TabsTrigger value="killchain">Kill Chain View</TabsTrigger>
          <TabsTrigger value="techniques">ATT&CK Matrix</TabsTrigger>
        </TabsList>

        <TabsContent value="builder">
          <ScenarioBuilderCard onRun={(p) => runSimulation.mutate(p)} />
        </TabsContent>

        <TabsContent value="history" className="space-y-4">
          <Card>
            <CardContent className="pt-4">
              <div className="flex flex-wrap gap-3 items-center">
                <div className="relative flex-1 min-w-[200px]">
                  <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
                  <Input
                    className="pl-8"
                    placeholder="Search scenarios, targets..."
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                  />
                </div>
                <Select value={statusFilter} onValueChange={setStatusFilter}>
                  <SelectTrigger className="w-40">
                    <SelectValue placeholder="Status" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Statuses</SelectItem>
                    <SelectItem value="running">Running</SelectItem>
                    <SelectItem value="completed">Completed</SelectItem>
                    <SelectItem value="failed">Failed</SelectItem>
                    <SelectItem value="queued">Queued</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-0">
              <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Scenario</TableHead>
                    <TableHead>Technique</TableHead>
                    <TableHead>Target</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Score</TableHead>
                    <TableHead>Date</TableHead>
                    <TableHead className="text-right">Details</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filtered.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={7} className="text-center py-10 text-muted-foreground">
                        No simulations found
                      </TableCell>
                    </TableRow>
                  ) : (
                    filtered.map((sim, i) => (
                      <TableRow
                        key={(sim.id as string) ?? i}
                        className="hover:bg-muted/30"
                      >
                        <TableCell className="font-medium max-w-[180px] truncate">
                          {(sim.scenario as string) ?? "—"}
                        </TableCell>
                        <TableCell>
                          <Badge variant="outline" className="font-mono text-[10px]">
                            {(sim.technique as string) ?? "—"}
                          </Badge>
                        </TableCell>
                        <TableCell className="font-mono text-xs text-muted-foreground">
                          {(sim.target as string) ?? "—"}
                        </TableCell>
                        <TableCell>
                          <StatusBadge status={(sim.status as string) ?? "pending"} />
                        </TableCell>
                        <TableCell>
                          {(sim.score as number) !== undefined ? (
                            <div className="flex items-center gap-2">
                              <Progress
                                value={(sim.score as number)}
                                className="w-16 h-1.5"
                              />
                              <span className="text-xs tabular-nums">
                                {sim.score as number}
                              </span>
                            </div>
                          ) : (
                            <span className="text-muted-foreground text-xs">—</span>
                          )}
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground">
                          {(sim.created_at as string) ?? (sim.date as string) ?? "—"}
                        </TableCell>
                        <TableCell className="text-right">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => {
                              setSelectedSim(sim);
                              setDetailOpen(true);
                            }}
                          >
                            View
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="killchain">
          <div className="space-y-4">
            <Card>
              <CardHeader>
                <CardTitle className="text-sm font-medium">Cyber Kill Chain</CardTitle>
                <CardDescription className="text-xs">
                  Unified Kill Chain visualization for active simulations
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-6">
                {filtered.filter((s) => (s.status as string) === "running").length === 0 ? (
                  <div className="text-center py-10 text-muted-foreground text-sm">
                    No active simulations running
                  </div>
                ) : (
                  filtered
                    .filter((s) => (s.status as string) === "running")
                    .map((sim, i) => (
                      <div key={(sim.id as string) ?? i} className="space-y-2">
                        <div className="flex items-center justify-between">
                          <span className="text-sm font-medium">
                            {(sim.scenario as string) ?? `Simulation ${i + 1}`}
                          </span>
                          <Badge variant="outline" className="font-mono text-[10px]">
                            {(sim.technique as string) ?? "—"}
                          </Badge>
                        </div>
                        <KillChainDiagram
                          activePhase={(sim.kill_chain_phase as number) ?? -1}
                        />
                        <p className="text-xs text-muted-foreground">
                          Target: {(sim.target as string) ?? "—"}
                        </p>
                      </div>
                    ))
                )}
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle className="text-sm font-medium">Kill Chain Reference</CardTitle>
              </CardHeader>
              <CardContent>
                <KillChainDiagram activePhase={KILL_CHAIN_PHASES.length - 1} />
                <p className="text-xs text-muted-foreground mt-3">
                  The Cyber Kill Chain® model describes the stages of a cyber attack from reconnaissance to objectives.
                </p>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="techniques">
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
            {Object.entries(MITRE_TECHNIQUES).map(([category, techniques]) => (
              <Card key={category}>
                <CardHeader className="pb-2">
                  <CardTitle className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">
                    {category}
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-1.5">
                  {techniques.map((t) => (
                    <div
                      key={t.id}
                      className="flex items-center gap-2 p-2 rounded-md hover:bg-muted/40 transition-colors"
                    >
                      <Badge variant="outline" className="font-mono text-[10px] shrink-0">
                        {t.id}
                      </Badge>
                      <span className="text-xs">{t.name}</span>
                    </div>
                  ))}
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>
      </Tabs>

      {/* Detail Dialog */}
      <Dialog open={detailOpen} onOpenChange={setDetailOpen}>
        <DialogContent className="max-w-xl">
          <DialogHeader>
            <DialogTitle>Simulation Detail</DialogTitle>
          </DialogHeader>
          {selectedSim && (
            <div className="space-y-4">
              <div className="grid grid-cols-2 gap-4 text-sm">
                <div>
                  <p className="text-xs text-muted-foreground">Scenario</p>
                  <p className="font-medium">{(selectedSim.scenario as string) ?? "—"}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Technique</p>
                  <Badge variant="outline" className="font-mono text-xs">
                    {(selectedSim.technique as string) ?? "—"}
                  </Badge>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Target</p>
                  <p className="font-mono text-xs">{(selectedSim.target as string) ?? "—"}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Status</p>
                  <StatusBadge status={(selectedSim.status as string) ?? "pending"} />
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Score</p>
                  <p className="font-medium">{(selectedSim.score as number) ?? "—"}</p>
                </div>
                <div>
                  <p className="text-xs text-muted-foreground">Findings</p>
                  <p className="font-medium">{(selectedSim.findings_count as number) ?? 0}</p>
                </div>
              </div>
              <div>
                <p className="text-xs text-muted-foreground mb-2">Kill Chain Progress</p>
                <KillChainDiagram
                  activePhase={(selectedSim.kill_chain_phase as number) ?? -1}
                />
              </div>
              {!!selectedSim.notes && (
                <div>
                  <p className="text-xs text-muted-foreground mb-1">Notes</p>
                  <p className="text-sm">{String(selectedSim.notes)}</p>
                </div>
              )}
            </div>
          )}
          <DialogFooter>
            <Button variant="outline" onClick={() => setDetailOpen(false)}>
              Close
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </motion.div>
  );
}
