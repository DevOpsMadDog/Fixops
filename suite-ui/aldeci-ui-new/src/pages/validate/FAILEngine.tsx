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
  Flame,
  AlertTriangle,
  Clock,
  Shield,
  Play,
  Plus,
  Search,
  Zap,
  Users,
  BarChart2,
} from "lucide-react";
import {
  RadarChart,
  Radar,
  PolarGrid,
  PolarAngleAxis,
  ResponsiveContainer,
  Tooltip,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Cell,
} from "recharts";
import {
  useFailDrills,
  useFailReadiness,
  useFailHistory,
  useFailScenarios,
  useInjectFail,
} from "@/hooks/use-api";

const DRILL_STATUSES = ["Injected", "Detected", "Triaged", "Fixed"] as const;
type DrillStatus = (typeof DRILL_STATUSES)[number];

const STATUS_COLORS: Record<DrillStatus, string> = {
  Injected: "#ef4444",
  Detected: "#f59e0b",
  Triaged: "#3b82f6",
  Fixed: "#22c55e",
};

function DrillStatusBadge({ status }: { status: string }) {
  const color = STATUS_COLORS[status as DrillStatus];
  return (
    <Badge
      variant="outline"
      style={{ borderColor: color + "66", color }}
    >
      {status}
    </Badge>
  );
}

function DrillProgressBar({ status }: { status: string }) {
  const idx = DRILL_STATUSES.indexOf(status as DrillStatus);
  const pct = idx >= 0 ? Math.round(((idx + 1) / DRILL_STATUSES.length) * 100) : 0;
  return (
    <div className="space-y-1">
      <div className="flex justify-between text-[10px] text-muted-foreground">
        {DRILL_STATUSES.map((s, i) => (
          <span key={s} className={i <= idx ? "text-foreground font-medium" : ""}>
            {s}
          </span>
        ))}
      </div>
      <Progress value={pct} className="h-1.5" />
    </div>
  );
}

function NeglectZoneCard({ zone }: { zone: Record<string, unknown> }) {
  const days = (zone.days_since_drill as number) ?? 0;
  const severity = days > 180 ? "critical" : days > 90 ? "high" : "medium";
  const colors = { critical: "#ef4444", high: "#f59e0b", medium: "#3b82f6" };
  return (
    <div
      className="flex items-start gap-3 p-3 rounded-lg border"
      style={{ borderColor: colors[severity] + "44", background: colors[severity] + "11" }}
    >
      <AlertTriangle
        className="h-4 w-4 mt-0.5 shrink-0"
        style={{ color: colors[severity] }}
      />
      <div className="flex-1 min-w-0">
        <p className="text-sm font-medium truncate">
          {(zone.component as string) ?? "Unknown Component"}
        </p>
        <p className="text-xs text-muted-foreground">
          Last drill: {days} days ago
        </p>
        {!!zone.owner && (
          <p className="text-xs text-muted-foreground">Owner: {String(zone.owner)}</p>
        )}
      </div>
      <Badge
        variant="outline"
        style={{ borderColor: colors[severity] + "66", color: colors[severity] }}
        className="text-[10px] shrink-0"
      >
        {severity.toUpperCase()}
      </Badge>
    </div>
  );
}

function NewDrillDialog({
  scenarios,
  onInject,
}: {
  scenarios: Record<string, unknown>[];
  onInject: (payload: unknown) => void;
}) {
  const [open, setOpen] = useState(false);
  const [scenario, setScenario] = useState("");
  const [target, setTarget] = useState("");
  const [intensity, setIntensity] = useState("medium");

  const handleSubmit = () => {
    onInject({ scenario_id: scenario, target, intensity });
    setOpen(false);
    setTarget("");
    setScenario("");
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button>
          <Plus className="h-4 w-4 mr-2" />
          New Drill
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Inject FAIL Drill</DialogTitle>
        </DialogHeader>
        <div className="space-y-4">
          <div className="space-y-2">
            <Label>Scenario</Label>
            <Select value={scenario} onValueChange={setScenario}>
              <SelectTrigger>
                <SelectValue placeholder="Select scenario..." />
              </SelectTrigger>
              <SelectContent>
                {scenarios.map((s) => (
                  <SelectItem key={(s.id as string)} value={(s.id as string)}>
                    {(s.name as string) ?? (s.id as string)}
                  </SelectItem>
                ))}
                {scenarios.length === 0 && (
                  <SelectItem value="ransomware">Ransomware Simulation</SelectItem>
                )}
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-2">
            <Label>Target System / Team</Label>
            <Input
              placeholder="e.g. prod-api, security-team"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
            />
          </div>
          <div className="space-y-2">
            <Label>Intensity</Label>
            <Select value={intensity} onValueChange={setIntensity}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="low">Low</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="high">High</SelectItem>
                <SelectItem value="maximum">Maximum (Full Incident)</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="bg-amber-500/10 border border-amber-500/30 rounded-md p-3 text-xs text-amber-400">
            <Flame className="h-3 w-3 inline mr-1" />
            This will inject a live fault scenario into production-like systems. Ensure
            stakeholders are notified.
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => setOpen(false)}>Cancel</Button>
          <Button onClick={handleSubmit} disabled={!scenario || !target}>
            <Zap className="h-4 w-4 mr-2" />
            Inject Drill
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default function FAILEngine() {
  const drillsQuery = useFailDrills();
  const readinessQuery = useFailReadiness();
  const historyQuery = useFailHistory();
  const scenariosQuery = useFailScenarios();
  const injectFail = useInjectFail();

  const [search, setSearch] = useState("");

  const refetchAll = useCallback(() => {
    drillsQuery.refetch();
    readinessQuery.refetch();
    historyQuery.refetch();
    scenariosQuery.refetch();
  }, [drillsQuery, readinessQuery, historyQuery, scenariosQuery]);

  const isLoading =
    drillsQuery.isLoading || readinessQuery.isLoading || historyQuery.isLoading;
  const isError =
    drillsQuery.isError || readinessQuery.isError || historyQuery.isError;

  if (isLoading) return <PageSkeleton />;
  if (isError) return <ErrorState message="Failed to load FAIL Engine data" onRetry={refetchAll} />;

  const drills: Record<string, unknown>[] =
    toArray(drillsQuery.data);
  const readiness = readinessQuery.data?.data ?? readinessQuery.data ?? {};
  const history: Record<string, unknown>[] =
    toArray(historyQuery.data);
  const scenarios: Record<string, unknown>[] =
    toArray(scenariosQuery.data);

  const activeDrills = drills.filter(
    (d) => (d.status as string) !== "Fixed"
  ).length;
  const readinessScore = (readiness.overall_score as number) ?? (readiness.score as number) ?? (readiness.readiness_score as number) ?? 0;
  const avgDetectionTime = (readiness.avg_detection_time as string) ?? (readiness.detection_time as string) ?? "—";
  const neglectZones: Record<string, unknown>[] =
    (readiness.neglect_zones as Record<string, unknown>[]) ?? [];

  const teamScorecard = (readiness.scorecard as Record<string, number>) ?? {};
  const scorecardData = [
    { metric: "Detection Speed", value: teamScorecard.detection_speed ?? 0 },
    { metric: "Triage Accuracy", value: teamScorecard.triage_accuracy ?? 0 },
    { metric: "Remediation Speed", value: teamScorecard.remediation_speed ?? 0 },
    { metric: "Communication", value: teamScorecard.communication ?? 0 },
  ];

  const radarData = scorecardData.map((d) => ({ subject: d.metric, value: d.value, fullMark: 100 }));

  const filteredHistory = history.filter(
    (h) =>
      !search ||
      (h.scenario as string)?.toLowerCase().includes(search.toLowerCase()) ||
      (h.target as string)?.toLowerCase().includes(search.toLowerCase())
  );

  const industryComparison = (readiness.industry_comparison as Record<string, number>) ?? {};

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      <PageHeader
        title="FAIL Engine"
        description="Fault & Attack Injection Layer — drill-based resilience testing and team readiness"
      >
        <NewDrillDialog
          scenarios={scenarios}
          onInject={(p) => injectFail.mutate(p)}
        />
      </PageHeader>

      {/* KPI Row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard
          title="Active Drills"
          value={activeDrills}
          icon={<Flame className="h-4 w-4" />}
        />
        <KpiCard
          title="Readiness Score"
          value={`${readinessScore}/100`}
          icon={<Shield className="h-4 w-4" />}
          trend={readinessScore >= 70 ? "up" : "down"}
          trendLabel={readinessScore >= 70 ? "good" : "needs work"}
        />
        <KpiCard
          title="Avg Detection Time"
          value={avgDetectionTime}
          icon={<Clock className="h-4 w-4" />}
        />
        <KpiCard
          title="Neglect Zones"
          value={neglectZones.length}
          icon={<AlertTriangle className="h-4 w-4" />}
          trend="flat"
          trendLabel={neglectZones.length > 0 ? "attention needed" : "all clear"}
        />
      </div>

      <Tabs defaultValue="drills">
        <TabsList>
          <TabsTrigger value="drills">Active Drills</TabsTrigger>
          <TabsTrigger value="scorecard">Team Scorecard</TabsTrigger>
          <TabsTrigger value="neglect">Neglect Zones</TabsTrigger>
          <TabsTrigger value="history">Drill History</TabsTrigger>
          <TabsTrigger value="comparison">Industry Comparison</TabsTrigger>
        </TabsList>

        <TabsContent value="drills" className="space-y-4">
          {drills.length === 0 ? (
            <Card>
              <CardContent className="flex items-center justify-center py-16 text-muted-foreground text-sm">
                No active drills. Inject a new drill to begin.
              </CardContent>
            </Card>
          ) : (
            drills.map((drill, i) => (
              <Card key={(drill.drill_id as string) ?? (drill.id as string) ?? i}>
                <CardContent className="pt-4">
                  <div className="flex items-start justify-between gap-4 mb-3">
                    <div>
                      <p className="font-medium">{(drill.scenario_name as string) ?? (drill.name as string) ?? `Drill ${i + 1}`}</p>
                      <p className="text-xs text-muted-foreground mt-0.5">
                        Target: {(drill.target_component as string) ?? (drill.target as string) ?? "—"}
                      </p>
                      {!!drill.severity && (
                        <Badge variant="outline" className="mt-1 text-[10px]" style={{ borderColor: String(drill.severity) === 'critical' ? '#ef444466' : '#f59e0b66', color: String(drill.severity) === 'critical' ? '#ef4444' : '#f59e0b' }}>
                          {String(drill.severity).toUpperCase()}
                        </Badge>
                      )}
                    </div>
                    <DrillStatusBadge status={(drill.status as string) ?? "Injected"} />
                  </div>
                  <DrillProgressBar status={(drill.status as string) ?? "Injected"} />
                  <div className="flex items-center gap-6 mt-3 text-xs text-muted-foreground">
                    <span>
                      <Clock className="h-3 w-3 inline mr-1" />
                      Started: {(drill.injected_at as string) ?? (drill.started_at as string) ?? "—"}
                    </span>
                    {!!(drill.detection_time_ms || drill.detection_time) && (
                      <span>
                        <Zap className="h-3 w-3 inline mr-1" />
                        Detection: {String(drill.detection_time_ms ?? drill.detection_time)}
                      </span>
                    )}
                    {!!(drill.scenario_id || drill.scenario) && (
                      <span>
                        <Flame className="h-3 w-3 inline mr-1" />
                        Scenario: {String(drill.scenario_id ?? drill.scenario)}
                      </span>
                    )}
                  </div>
                </CardContent>
              </Card>
            ))
          )}
        </TabsContent>

        <TabsContent value="scorecard">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader>
                <CardTitle className="text-sm font-medium flex items-center gap-2">
                  <Users className="h-4 w-4" />
                  Team Scorecard
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {scorecardData.map((item) => (
                  <div key={item.metric} className="space-y-1.5">
                    <div className="flex items-center justify-between text-sm">
                      <span>{item.metric}</span>
                      <span className="font-semibold tabular-nums">{item.value}/100</span>
                    </div>
                    <Progress
                      value={item.value}
                      className="h-2"
                    />
                  </div>
                ))}
                {scorecardData.every((d) => d.value === 0) && (
                  <p className="text-center text-sm text-muted-foreground py-4">
                    No scorecard data available yet
                  </p>
                )}
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle className="text-sm font-medium">Radar Overview</CardTitle>
              </CardHeader>
              <CardContent>
                {radarData.every((d) => d.value === 0) ? (
                  <div className="flex items-center justify-center h-48 text-muted-foreground text-sm">
                    No data
                  </div>
                ) : (
                  <ResponsiveContainer width="100%" height={250}>
                    <RadarChart data={radarData}>
                      <PolarGrid stroke="hsl(var(--border))" />
                      <PolarAngleAxis
                        dataKey="subject"
                        tick={{ fontSize: 11, fill: "hsl(var(--muted-foreground))" }}
                      />
                      <Radar
                        dataKey="value"
                        stroke="hsl(var(--primary))"
                        fill="hsl(var(--primary))"
                        fillOpacity={0.2}
                      />
                      <Tooltip
                        contentStyle={{
                          background: "hsl(var(--card))",
                          border: "1px solid hsl(var(--border))",
                          borderRadius: "8px",
                        }}
                      />
                    </RadarChart>
                  </ResponsiveContainer>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="neglect">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 text-amber-500" />
                Neglect Zones
              </CardTitle>
              <CardDescription className="text-xs">
                Components with no security drills in the last 90+ days
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              {neglectZones.length === 0 ? (
                <div className="text-center py-10 text-sm text-muted-foreground">
                  No neglect zones detected — all components drilled recently
                </div>
              ) : (
                neglectZones.map((zone, i) => (
                  <NeglectZoneCard key={i} zone={zone} />
                ))
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="history" className="space-y-4">
          <Card>
            <CardContent className="pt-4">
              <div className="relative">
                <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
                <Input
                  className="pl-8"
                  placeholder="Search drill history..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                />
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardContent className="p-0">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Date</TableHead>
                    <TableHead>Scenario</TableHead>
                    <TableHead>Target</TableHead>
                    <TableHead>Score</TableHead>
                    <TableHead>MTTR</TableHead>
                    <TableHead>Outcome</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredHistory.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={6} className="text-center py-10 text-muted-foreground">
                        No drill history found
                      </TableCell>
                    </TableRow>
                  ) : (
                    filteredHistory.map((h, i) => (
                      <TableRow key={(h.id as string) ?? i} className="hover:bg-muted/30">
                        <TableCell className="text-xs text-muted-foreground">
                          {(h.date as string) ?? (h.created_at as string) ?? "—"}
                        </TableCell>
                        <TableCell className="font-medium">
                          {(h.scenario as string) ?? "—"}
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground">
                          {(h.target as string) ?? "—"}
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center gap-2">
                            <Progress value={(h.score as number) ?? 0} className="w-14 h-1.5" />
                            <span className="text-xs tabular-nums">{(h.score as number) ?? "—"}</span>
                          </div>
                        </TableCell>
                        <TableCell className="text-xs">
                          {(h.mttr as string) ?? "—"}
                        </TableCell>
                        <TableCell>
                          <Badge
                            variant={
                              (h.outcome as string) === "passed"
                                ? "secondary"
                                : (h.outcome as string) === "failed"
                                ? "destructive"
                                : "outline"
                            }
                          >
                            {(h.outcome as string) ?? "—"}
                          </Badge>
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="comparison">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader>
                <CardTitle className="text-sm font-medium flex items-center gap-2">
                  <BarChart2 className="h-4 w-4" />
                  Industry Comparison
                </CardTitle>
                <CardDescription className="text-xs">
                  Your readiness vs industry benchmarks
                </CardDescription>
              </CardHeader>
              <CardContent>
                {Object.keys(industryComparison).length === 0 ? (
                  <div className="flex items-center justify-center h-48 text-muted-foreground text-sm">
                    Comparison data unavailable
                  </div>
                ) : (
                  <ResponsiveContainer width="100%" height={250}>
                    <BarChart
                      data={Object.entries(industryComparison).map(([key, val]) => ({
                        name: key,
                        value: val,
                      }))}
                      margin={{ top: 4, right: 4, left: -16, bottom: 4 }}
                    >
                      <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" />
                      <XAxis
                        dataKey="name"
                        tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }}
                      />
                      <YAxis tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }} />
                      <Tooltip
                        contentStyle={{
                          background: "hsl(var(--card))",
                          border: "1px solid hsl(var(--border))",
                          borderRadius: "8px",
                        }}
                      />
                      <Bar dataKey="value" radius={[4, 4, 0, 0]}>
                        {Object.keys(industryComparison).map((key, i) => (
                          <Cell
                            key={key}
                            fill={i === 0 ? "hsl(var(--primary))" : "hsl(var(--muted-foreground))"}
                          />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                )}
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle className="text-sm font-medium">Readiness Breakdown</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center justify-between">
                  <span className="text-sm">Overall Readiness</span>
                  <span className="text-2xl font-bold">{readinessScore}</span>
                </div>
                <Progress value={readinessScore} className="h-3" />
                <div className="grid grid-cols-2 gap-3 mt-4">
                  {[
                    { label: "Active Drills", val: activeDrills },
                    { label: "Neglect Zones", val: neglectZones.length },
                    { label: "Avg Detection", val: avgDetectionTime },
                    { label: "Drills Run", val: history.length },
                  ].map((item) => (
                    <div key={item.label} className="bg-muted/30 rounded-lg p-3">
                      <p className="text-xs text-muted-foreground">{item.label}</p>
                      <p className="font-semibold mt-1">{item.val}</p>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
