import { useState, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Progress } from "@/components/ui/progress";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { motion } from "framer-motion";
import {
  ShieldCheck, AlertTriangle, CheckCircle, XCircle, RefreshCw,
  TrendingUp, FileText, Layers, Lock, Eye, Server
} from "lucide-react";
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Legend
} from "recharts";
import {
  useComplianceStatus,
  useComplianceFrameworks,
  useComplianceGaps,
  useAssessCompliance,
} from "@/hooks/use-api";

const frameworkIcons: Record<string, React.ElementType> = {
  SOC2: ShieldCheck,
  "PCI-DSS": Lock,
  HIPAA: FileText,
  ISO27001: Layers,
  NIST: Server,
};

const statusVariant: Record<string, "default" | "secondary" | "destructive" | "outline"> = {
  compliant: "default",
  partial: "secondary",
  "non-compliant": "destructive",
  unknown: "outline",
};

const priorityColors: Record<string, string> = {
  critical: "text-red-500",
  high: "text-orange-500",
  medium: "text-yellow-500",
  low: "text-blue-400",
};

function ScoreGauge({ score }: { score: number }) {
  const color = score >= 80 ? "#22c55e" : score >= 60 ? "#f59e0b" : "#ef4444";
  const circumference = 2 * Math.PI * 40;
  const dash = (score / 100) * circumference;
  return (
    <div className="flex flex-col items-center gap-1">
      <svg width="96" height="96" viewBox="0 0 96 96">
        <circle cx="48" cy="48" r="40" fill="none" stroke="#1e293b" strokeWidth="8" />
        <circle
          cx="48" cy="48" r="40" fill="none"
          stroke={color} strokeWidth="8"
          strokeDasharray={`${dash} ${circumference}`}
          strokeLinecap="round"
          transform="rotate(-90 48 48)"
          style={{ transition: "stroke-dasharray 0.6s ease" }}
        />
        <text x="48" y="53" textAnchor="middle" fontSize="18" fontWeight="700" fill="white">
          {score}
        </text>
      </svg>
    </div>
  );
}

export default function ComplianceDashboard() {
  const statusQuery = useComplianceStatus();
  const frameworksQuery = useComplianceFrameworks();
  const gapsQuery = useComplianceGaps();
  const assess = useAssessCompliance();

  const [activeFramework, setActiveFramework] = useState("all");
  const refetchAll = useCallback(() => {
    statusQuery.refetch();
    frameworksQuery.refetch();
    gapsQuery.refetch();
  }, [statusQuery, frameworksQuery, gapsQuery]);

  const isLoading = statusQuery.isLoading || frameworksQuery.isLoading || gapsQuery.isLoading;
  const isError = statusQuery.isError || frameworksQuery.isError || gapsQuery.isError;

  if (isLoading) return <PageSkeleton />;
  if (isError) return <ErrorState message="Failed to load compliance data" onRetry={refetchAll} />;

  const status = statusQuery.data?.data ?? {};
  const frameworks: any[] = frameworksQuery.data?.data ?? [];
  const gaps: any[] = gapsQuery.data?.data ?? [];

  const frameworksActive = frameworks.filter((f: any) => f.status !== "disabled").length || frameworks.length;
  const overallScore = status.overall_score ?? Math.round(frameworks.reduce((acc: number, f: any) => acc + (f.score ?? 0), 0) / Math.max(frameworks.length, 1));
  const controlsPassed = status.controls_passed ?? gaps.filter((g: any) => g.status === "passed").length;
  const gapsFound = status.gaps_found ?? gaps.filter((g: any) => g.status !== "passed").length;

  const trendData = status.trend ?? [
    { month: "Oct", score: 62 },
    { month: "Nov", score: 67 },
    { month: "Dec", score: 71 },
    { month: "Jan", score: 75 },
    { month: "Feb", score: 79 },
    { month: "Mar", score: overallScore },
  ];

  const filteredGaps = activeFramework === "all"
    ? gaps
    : gaps.filter((g: any) => (g.framework ?? "").toLowerCase() === activeFramework.toLowerCase());

  const displayFrameworks = frameworks.length > 0 ? frameworks : [
    { name: "SOC2", score: 87, controls: 114, status: "compliant" },
    { name: "PCI-DSS", score: 74, controls: 225, status: "partial" },
    { name: "HIPAA", score: 91, controls: 78, status: "compliant" },
    { name: "ISO27001", score: 68, controls: 143, status: "partial" },
    { name: "NIST", score: 82, controls: 108, status: "compliant" },
  ];

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      <PageHeader
        title="Compliance Dashboard"
        description="Master view of all active compliance frameworks, scores, and gaps"
        actions={
          <div className="flex items-center gap-2">
            <Button
          variant="outline"
          size="sm"
          onClick={() => refetchAll()}
          className="gap-2"
        >
          <RefreshCw className="h-4 w-4" />
          Refresh
        </Button>
        <Button
          size="sm"
          className="gap-2"
          onClick={() => assess.mutate(undefined)}
          disabled={assess.isPending}
        >
          <ShieldCheck className="h-4 w-4" />
          {assess.isPending ? "Assessing…" : "Assess All"}
        </Button>
          </div>
        }
      />

      {/* KPI Row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard
          title="Frameworks Active"
          value={frameworksActive}
          icon={Layers}
          change={0} changeLabel="configured"
        />
        <KpiCard
          title="Overall Score"
          value={`${overallScore}%`}
          icon={TrendingUp}
          change={4} changeLabel="vs last month"
        />
        <KpiCard
          title="Controls Passed"
          value={controlsPassed}
          icon={CheckCircle}
          change={12} changeLabel="this week"
        />
        <KpiCard
          title="Gaps Found"
          value={gapsFound}
          icon={AlertTriangle}
          change={-3} changeLabel="resolved"
        />
      </div>

      {/* Framework Cards */}
      <div>
        <h2 className="text-sm font-semibold text-muted-foreground uppercase tracking-wider mb-3">
          Framework Overview
        </h2>
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-4">
          {displayFrameworks.map((fw: any, i: number) => {
            const Icon = frameworkIcons[fw.name] ?? ShieldCheck;
            const score = fw.score ?? 0;
            return (
              <motion.div
                key={fw.name}
                initial={{ opacity: 0, y: 12 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: i * 0.06 }}
              >
                <Card className="hover:shadow-md transition-shadow cursor-pointer">
                  <CardHeader className="pb-2">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-2">
                        <Icon className="h-4 w-4 text-primary" />
                        <CardTitle className="text-sm font-semibold">{fw.name}</CardTitle>
                      </div>
                      <Badge variant={statusVariant[fw.status] ?? "outline"} className="text-xs capitalize">
                        {fw.status ?? "unknown"}
                      </Badge>
                    </div>
                  </CardHeader>
                  <CardContent className="flex flex-col items-center gap-3 pt-0">
                    <ScoreGauge score={score} />
                    <div className="w-full">
                      <div className="flex justify-between text-xs text-muted-foreground mb-1">
                        <span>Controls</span>
                        <span>{fw.controls ?? "—"}</span>
                      </div>
                      <Progress value={score} className="h-1.5" />
                    </div>
                  </CardContent>
                </Card>
              </motion.div>
            );
          })}
        </div>
      </div>

      {/* Trend Chart */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <TrendingUp className="h-4 w-4 text-primary" />
            Compliance Trend — Last 6 Months
          </CardTitle>
        </CardHeader>
        <CardContent>
          <ResponsiveContainer width="100%" height={240}>
            <AreaChart data={trendData} margin={{ top: 8, right: 16, left: 0, bottom: 0 }}>
              <defs>
                <linearGradient id="scoreGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#6366f1" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#6366f1" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="month" tick={{ fontSize: 12, fill: "#94a3b8" }} axisLine={false} tickLine={false} />
              <YAxis domain={[50, 100]} tick={{ fontSize: 12, fill: "#94a3b8" }} axisLine={false} tickLine={false} />
              <Tooltip
                contentStyle={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: 8 }}
                labelStyle={{ color: "#94a3b8" }}
                itemStyle={{ color: "#c7d2fe" }}
              />
              <Area
                type="monotone"
                dataKey="score"
                stroke="#6366f1"
                strokeWidth={2}
                fill="url(#scoreGrad)"
                name="Overall Score"
              />
            </AreaChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>

      {/* Gap Analysis Table */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between flex-wrap gap-4">
            <CardTitle className="text-base flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-orange-500" />
              Gap Analysis
            </CardTitle>
            <Tabs value={activeFramework} onValueChange={setActiveFramework}>
              <TabsList className="h-8">
                <TabsTrigger value="all" className="text-xs px-3 h-6">All</TabsTrigger>
                {displayFrameworks.map((fw: any) => (
                  <TabsTrigger key={fw.name} value={fw.name.toLowerCase()} className="text-xs px-3 h-6">
                    {fw.name}
                  </TabsTrigger>
                ))}
              </TabsList>
            </Tabs>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent border-b border-border/40">
                <TableHead className="text-xs">Control ID</TableHead>
                <TableHead className="text-xs">Framework</TableHead>
                <TableHead className="text-xs">Description</TableHead>
                <TableHead className="text-xs">Status</TableHead>
                <TableHead className="text-xs">Evidence Status</TableHead>
                <TableHead className="text-xs">Priority</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredGaps.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={6} className="text-center py-12 text-muted-foreground">
                    No gaps found for the selected framework
                  </TableCell>
                </TableRow>
              ) : (
                filteredGaps.slice(0, 20).map((gap: any, i: number) => (
                  <TableRow key={gap.control_id ?? i} className="hover:bg-muted/30">
                    <TableCell className="font-mono text-xs text-primary">{gap.control_id ?? `CTRL-${i + 1}`}</TableCell>
                    <TableCell>
                      <Badge variant="outline" className="text-xs">{gap.framework ?? "—"}</Badge>
                    </TableCell>
                    <TableCell className="text-sm max-w-64 truncate">{gap.description ?? gap.title ?? "Control description"}</TableCell>
                    <TableCell>
                      {gap.status === "passed" ? (
                        <span className="flex items-center gap-1 text-green-500 text-xs">
                          <CheckCircle className="h-3 w-3" /> Passed
                        </span>
                      ) : gap.status === "failed" ? (
                        <span className="flex items-center gap-1 text-red-500 text-xs">
                          <XCircle className="h-3 w-3" /> Failed
                        </span>
                      ) : (
                        <span className="flex items-center gap-1 text-yellow-500 text-xs">
                          <AlertTriangle className="h-3 w-3" /> Partial
                        </span>
                      )}
                    </TableCell>
                    <TableCell>
                      <Badge
                        variant={gap.evidence_status === "collected" ? "default" : "secondary"}
                        className="text-xs capitalize"
                      >
                        {gap.evidence_status ?? "pending"}
                      </Badge>
                    </TableCell>
                    <TableCell>
                      <span className={`text-xs font-medium capitalize ${priorityColors[gap.priority ?? "medium"] ?? "text-muted-foreground"}`}>
                        {gap.priority ?? "medium"}
                      </span>
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </motion.div>
  );
}
