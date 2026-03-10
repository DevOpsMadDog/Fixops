import { useState, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
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
  ShieldAlert,
  Play,
  CheckCircle,
  XCircle,
  Clock,
  Target,
  Zap,
  Search,
  ChevronDown,
  ChevronUp,
  AlertTriangle,
} from "lucide-react";
import {
  PieChart,
  Pie,
  Cell,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from "recharts";
import {
  useMpteStatus,
  useMpteStats,
  useMpteResults,
  useMpteRequests,
  useRunMpteScan,
} from "@/hooks/use-api";

/** Safely extract an array from API responses that might be { items: [...] }, { data: [...] }, or just [...] */
function toArray(d: unknown): Record<string, unknown>[] {
  if (Array.isArray(d)) return d;
  if (d && typeof d === 'object') {
    const obj = d as Record<string, unknown>;
    if (Array.isArray(obj.items)) return obj.items;
    if (Array.isArray(obj.data)) return obj.data;
    if (Array.isArray(obj.verifications)) return obj.verifications;
  }
  return [];
}

const VERDICT_CONFIG = {
  vulnerable: { label: "Vulnerable", variant: "destructive" as const, color: "#ef4444" },
  not_vulnerable: { label: "Not Vulnerable", variant: "secondary" as const, color: "#22c55e" },
  unverified: { label: "Unverified", variant: "outline" as const, color: "#f59e0b" },
  partial: { label: "Partial", variant: "secondary" as const, color: "#3b82f6" },
};

const SCAN_PHASES = [
  "Reconnaissance",
  "Enumeration",
  "Vulnerability Discovery",
  "Exploitation Attempt",
  "Privilege Escalation",
  "Lateral Movement",
  "Data Exfiltration Check",
  "Persistence Check",
  "Defense Evasion",
  "Command & Control",
  "Impact Assessment",
  "Evidence Collection",
  "False Positive Elimination",
  "Confidence Scoring",
  "Contextual Analysis",
  "Risk Correlation",
  "Remediation Mapping",
  "Report Generation",
  "Verification Complete",
];

function VerdictBadge({ verdict }: { verdict: string }) {
  const cfg = VERDICT_CONFIG[verdict as keyof typeof VERDICT_CONFIG] ?? {
    label: verdict,
    variant: "outline" as const,
  };
  return <Badge variant={cfg.variant}>{cfg.label}</Badge>;
}

function ScanDetailDialog({
  scan,
  open,
  onClose,
}: {
  scan: Record<string, unknown> | null;
  open: boolean;
  onClose: () => void;
}) {
  if (!scan) return null;
  const phases = (scan.phases_completed as number) ?? 0;
  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <ShieldAlert className="h-5 w-5 text-primary" />
            Scan Detail: {(scan.finding as string) ?? "Unknown Finding"}
          </DialogTitle>
        </DialogHeader>
        <div className="space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <p className="text-xs text-muted-foreground">Target</p>
              <p className="font-mono text-sm">{(scan.target as string) ?? "—"}</p>
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Verdict</p>
              <VerdictBadge verdict={(scan.verdict as string) ?? "unverified"} />
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Confidence</p>
              <div className="flex items-center gap-2">
                <Progress value={(scan.confidence as number) ?? 0} className="w-24 h-2" />
                <span className="text-sm font-medium">{(scan.confidence as number) ?? 0}%</span>
              </div>
            </div>
            <div>
              <p className="text-xs text-muted-foreground">Duration</p>
              <p className="text-sm">{(scan.duration as string) ?? "—"}</p>
            </div>
          </div>
          <div>
            <p className="text-xs text-muted-foreground mb-2">19-Phase Scan Progress</p>
            <div className="grid grid-cols-1 gap-1">
              {SCAN_PHASES.map((phase, i) => (
                <div key={phase} className="flex items-center gap-2 py-1 border-b border-border/30 last:border-0">
                  {i < phases ? (
                    <CheckCircle className="h-4 w-4 text-green-500 shrink-0" />
                  ) : (
                    <div className="h-4 w-4 rounded-full border border-muted-foreground/30 shrink-0" />
                  )}
                  <span className={`text-xs ${i < phases ? "text-foreground" : "text-muted-foreground"}`}>
                    Phase {i + 1}: {phase}
                  </span>
                  {i < phases && (
                    <Badge variant="secondary" className="ml-auto text-[10px] py-0">
                      Done
                    </Badge>
                  )}
                </div>
              ))}
            </div>
          </div>
          {!!scan.details && (
            <div>
              <p className="text-xs text-muted-foreground mb-1">Raw Details</p>
              <pre className="text-xs bg-muted p-3 rounded-md overflow-x-auto">
                {JSON.stringify(scan.details, null, 2)}
              </pre>
            </div>
          )}
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Close</Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function NewScanDialog({ onScan }: { onScan: (payload: unknown) => void }) {
  const [open, setOpen] = useState(false);
  const [target, setTarget] = useState("");
  const [scanType, setScanType] = useState("comprehensive");
  const [depth, setDepth] = useState("standard");

  const handleSubmit = () => {
    onScan({ target, scan_type: scanType, depth });
    setOpen(false);
    setTarget("");
  };

  return (
    <Dialog open={open} onOpenChange={setOpen}>
      <DialogTrigger asChild>
        <Button>
          <Play className="h-4 w-4 mr-2" />
          New Scan
        </Button>
      </DialogTrigger>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Launch MPTE Scan</DialogTitle>
        </DialogHeader>
        <div className="space-y-4">
          <div className="space-y-2">
            <Label>Target</Label>
            <Input
              placeholder="e.g. 192.168.1.0/24 or app.example.com"
              value={target}
              onChange={(e) => setTarget(e.target.value)}
            />
          </div>
          <div className="space-y-2">
            <Label>Scan Type</Label>
            <Select value={scanType} onValueChange={setScanType}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="comprehensive">Comprehensive</SelectItem>
                <SelectItem value="targeted">Targeted</SelectItem>
                <SelectItem value="quick">Quick Assessment</SelectItem>
                <SelectItem value="stealth">Stealth Mode</SelectItem>
                <SelectItem value="aggressive">Aggressive</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="space-y-2">
            <Label>Scan Depth</Label>
            <Select value={depth} onValueChange={setDepth}>
              <SelectTrigger>
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="shallow">Shallow (Fast)</SelectItem>
                <SelectItem value="standard">Standard</SelectItem>
                <SelectItem value="deep">Deep (Thorough)</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="rounded-md bg-muted/50 p-3 text-xs text-muted-foreground">
            <AlertTriangle className="h-3 w-3 inline mr-1" />
            MPTE will run up to 19 validation phases. Ensure you have authorization
            for the target.
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={() => setOpen(false)}>Cancel</Button>
          <Button onClick={handleSubmit} disabled={!target}>
            <Zap className="h-4 w-4 mr-2" />
            Launch Scan
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export default function MPTEConsole() {
  const statusQuery = useMpteStatus();
  const statsQuery = useMpteStats();
  const resultsQuery = useMpteResults();
  const requestsQuery = useMpteRequests();
  const runScan = useRunMpteScan();

  const [search, setSearch] = useState("");
  const [verdictFilter, setVerdictFilter] = useState("all");
  const [selectedScan, setSelectedScan] = useState<Record<string, unknown> | null>(null);
  const [detailOpen, setDetailOpen] = useState(false);
  const [sortField, setSortField] = useState<string>("confidence");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");

  const refetchAll = useCallback(() => {
    statusQuery.refetch();
    statsQuery.refetch();
    resultsQuery.refetch();
    requestsQuery.refetch();
  }, [statusQuery, statsQuery, resultsQuery, requestsQuery]);

  const isLoading = statusQuery.isLoading || statsQuery.isLoading || resultsQuery.isLoading;
  const isError = statusQuery.isError || statsQuery.isError || resultsQuery.isError;

  if (isLoading) return <PageSkeleton />;
  if (isError) return <ErrorState message="Failed to load MPTE console data" onRetry={refetchAll} />;

  const stats = statsQuery.data?.data ?? statsQuery.data ?? {};
  const results: Record<string, unknown>[] = toArray(resultsQuery.data?.data ?? resultsQuery.data);
  const status = statusQuery.data?.data ?? statusQuery.data ?? {};

  const totalScans = (stats.total_scans as number) ?? (results as unknown[]).length ?? 0;
  const verified = (stats.verified_vulnerable as number) ?? 0;
  const notVulnerable = (stats.not_vulnerable as number) ?? 0;
  const unverified = (stats.unverified as number) ?? 0;
  const avgConfidence = (stats.avg_confidence as number) ?? 0;

  const pieData = [
    { name: "Vulnerable", value: verified, color: "#ef4444" },
    { name: "Not Vulnerable", value: notVulnerable, color: "#22c55e" },
    { name: "Unverified", value: unverified, color: "#f59e0b" },
  ].filter((d) => d.value > 0);

  const filtered = results.filter((r) => {
    const matchSearch =
      !search ||
      (r.finding as string)?.toLowerCase().includes(search.toLowerCase()) ||
      (r.target as string)?.toLowerCase().includes(search.toLowerCase());
    const matchVerdict = verdictFilter === "all" || r.verdict === verdictFilter;
    return matchSearch && matchVerdict;
  });

  const sorted = [...filtered].sort((a, b) => {
    const av = a[sortField] as number | string;
    const bv = b[sortField] as number | string;
    if (typeof av === "number" && typeof bv === "number") {
      return sortDir === "desc" ? bv - av : av - bv;
    }
    return sortDir === "desc"
      ? String(bv).localeCompare(String(av))
      : String(av).localeCompare(String(bv));
  });

  const toggleSort = (field: string) => {
    if (sortField === field) setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    else { setSortField(field); setSortDir("desc"); }
  };

  const SortIcon = ({ field }: { field: string }) =>
    sortField === field ? (
      sortDir === "desc" ? <ChevronDown className="h-3 w-3" /> : <ChevronUp className="h-3 w-3" />
    ) : (
      <ChevronDown className="h-3 w-3 opacity-30" />
    );

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      <PageHeader
        title="MPTE Console"
        description="Micro-Pentest Engine — automated vulnerability validation across 19 phases"
        actions={<NewScanDialog onScan={(p) => runScan.mutate(p)} />}
      />

      {/* KPI Row */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
        <KpiCard
          title="Total Scans"
          value={totalScans}
          icon={Target}
        />
        <KpiCard
          title="Verified Vulnerable"
          value={verified}
          icon={ShieldAlert}
          trend={verified > 0 ? "up" : "flat"}
        />
        <KpiCard
          title="Not Vulnerable"
          value={notVulnerable}
          icon={CheckCircle}
        />
        <KpiCard
          title="Unverified"
          value={unverified}
          icon={Clock}
        />
        <KpiCard
          title="Avg Confidence"
          value={`${avgConfidence}%`}
          icon={Zap}
        />
      </div>

      <Tabs defaultValue="results">
        <TabsList>
          <TabsTrigger value="results">Scan Results</TabsTrigger>
          <TabsTrigger value="distribution">Verdict Distribution</TabsTrigger>
          <TabsTrigger value="requests">Scan Requests</TabsTrigger>
          <TabsTrigger value="engine">Engine Status</TabsTrigger>
        </TabsList>

        <TabsContent value="results" className="space-y-4">
          {/* Filters */}
          <Card>
            <CardContent className="pt-4">
              <div className="flex flex-wrap gap-3 items-center">
                <div className="relative flex-1 min-w-[200px]">
                  <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground" />
                  <Input
                    className="pl-8"
                    placeholder="Search findings, targets..."
                    value={search}
                    onChange={(e) => setSearch(e.target.value)}
                  />
                </div>
                <Select value={verdictFilter} onValueChange={setVerdictFilter}>
                  <SelectTrigger className="w-44">
                    <SelectValue placeholder="Verdict filter" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Verdicts</SelectItem>
                    <SelectItem value="vulnerable">Vulnerable</SelectItem>
                    <SelectItem value="not_vulnerable">Not Vulnerable</SelectItem>
                    <SelectItem value="unverified">Unverified</SelectItem>
                    <SelectItem value="partial">Partial</SelectItem>
                  </SelectContent>
                </Select>
                <span className="text-sm text-muted-foreground">
                  {sorted.length} result{sorted.length !== 1 ? "s" : ""}
                </span>
              </div>
            </CardContent>
          </Card>

          {/* Results Table */}
          <Card>
            <CardHeader className="pb-0">
              <CardTitle className="text-sm font-medium">Scan Results</CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead
                      className="cursor-pointer select-none"
                      onClick={() => toggleSort("finding")}
                    >
                      <span className="flex items-center gap-1">
                        Finding <SortIcon field="finding" />
                      </span>
                    </TableHead>
                    <TableHead>Target</TableHead>
                    <TableHead>Verdict</TableHead>
                    <TableHead
                      className="cursor-pointer select-none"
                      onClick={() => toggleSort("confidence")}
                    >
                      <span className="flex items-center gap-1">
                        Confidence <SortIcon field="confidence" />
                      </span>
                    </TableHead>
                    <TableHead
                      className="cursor-pointer select-none"
                      onClick={() => toggleSort("phases_completed")}
                    >
                      <span className="flex items-center gap-1">
                        Phases <SortIcon field="phases_completed" />
                      </span>
                    </TableHead>
                    <TableHead>Duration</TableHead>
                    <TableHead className="text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {sorted.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={7} className="text-center py-10 text-muted-foreground">
                        No scan results found
                      </TableCell>
                    </TableRow>
                  ) : (
                    sorted.map((row, i) => (
                      <TableRow
                        key={(row.id as string) ?? i}
                        className="hover:bg-muted/30 cursor-pointer"
                      >
                        <TableCell className="font-medium max-w-[200px] truncate">
                          {(row.finding as string) ?? "—"}
                        </TableCell>
                        <TableCell className="font-mono text-xs text-muted-foreground max-w-[160px] truncate">
                          {(row.target as string) ?? "—"}
                        </TableCell>
                        <TableCell>
                          <VerdictBadge verdict={(row.verdict as string) ?? "unverified"} />
                        </TableCell>
                        <TableCell>
                          <div className="flex items-center gap-2">
                            <Progress
                              value={(row.confidence as number) ?? 0}
                              className="w-16 h-1.5"
                            />
                            <span className="text-xs tabular-nums">
                              {(row.confidence as number) ?? 0}%
                            </span>
                          </div>
                        </TableCell>
                        <TableCell>
                          <span className="text-xs">
                            {(row.phases_completed as number) ?? 0}/19
                          </span>
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground">
                          {(row.duration as string) ?? "—"}
                        </TableCell>
                        <TableCell className="text-right">
                          <Button
                            variant="ghost"
                            size="sm"
                            onClick={() => {
                              setSelectedScan(row);
                              setDetailOpen(true);
                            }}
                          >
                            Details
                          </Button>
                        </TableCell>
                      </TableRow>
                    ))
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="distribution">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
            <Card>
              <CardHeader>
                <CardTitle className="text-sm font-medium">Verdict Distribution</CardTitle>
              </CardHeader>
              <CardContent>
                {pieData.length === 0 ? (
                  <div className="flex items-center justify-center h-64 text-muted-foreground text-sm">
                    No data available
                  </div>
                ) : (
                  <ResponsiveContainer width="100%" height={280}>
                    <PieChart>
                      <Pie
                        data={pieData}
                        cx="50%"
                        cy="50%"
                        innerRadius={70}
                        outerRadius={110}
                        paddingAngle={3}
                        dataKey="value"
                      >
                        {pieData.map((entry) => (
                          <Cell key={entry.name} fill={entry.color} />
                        ))}
                      </Pie>
                      <Tooltip
                        contentStyle={{
                          background: "hsl(var(--card))",
                          border: "1px solid hsl(var(--border))",
                          borderRadius: "8px",
                        }}
                      />
                      <Legend />
                    </PieChart>
                  </ResponsiveContainer>
                )}
              </CardContent>
            </Card>
            <Card>
              <CardHeader>
                <CardTitle className="text-sm font-medium">Breakdown</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {pieData.map((d) => (
                  <div key={d.name} className="flex items-center gap-3">
                    <div
                      className="h-3 w-3 rounded-full shrink-0"
                      style={{ background: d.color }}
                    />
                    <span className="flex-1 text-sm">{d.name}</span>
                    <span className="font-semibold tabular-nums">{d.value}</span>
                    <span className="text-xs text-muted-foreground tabular-nums w-12 text-right">
                      {totalScans > 0 ? Math.round((d.value / totalScans) * 100) : 0}%
                    </span>
                  </div>
                ))}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="requests">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm font-medium">Scan Requests</CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Request ID</TableHead>
                    <TableHead>Target</TableHead>
                    <TableHead>Type</TableHead>
                    <TableHead>Status</TableHead>
                    <TableHead>Created</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {toArray(requestsQuery.data?.data ?? requestsQuery.data).length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={5} className="text-center py-8 text-muted-foreground">
                        No scan requests
                      </TableCell>
                    </TableRow>
                  ) : (
                    toArray(requestsQuery.data?.data ?? requestsQuery.data).map(
                      (req, i) => (
                        <TableRow key={(req.id as string) ?? i}>
                          <TableCell className="font-mono text-xs">
                            {(req.id as string) ?? `REQ-${i + 1}`}
                          </TableCell>
                          <TableCell className="font-mono text-xs text-muted-foreground">
                            {(req.target_url as string) ?? (req.target as string) ?? "—"}
                          </TableCell>
                          <TableCell>
                            <Badge variant="outline">{(req.vulnerability_type as string) ?? (req.type as string) ?? "—"}</Badge>
                          </TableCell>
                          <TableCell>
                            <Badge
                              variant={
                                (req.status as string) === "completed"
                                  ? "secondary"
                                  : (req.status as string) === "running"
                                  ? "default"
                                  : "outline"
                              }
                            >
                              {(req.status as string) ?? "pending"}
                            </Badge>
                          </TableCell>
                          <TableCell className="text-xs text-muted-foreground">
                            {(req.created_at as string) ?? "—"}
                          </TableCell>
                        </TableRow>
                      )
                    )
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="engine">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm font-medium">Engine Status</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                {Object.entries(status).map(([key, val]) => (
                  <div key={key} className="bg-muted/30 rounded-lg p-3">
                    <p className="text-xs text-muted-foreground capitalize">
                      {key.replace(/_/g, " ")}
                    </p>
                    <p className="font-medium mt-1">{String(val)}</p>
                  </div>
                ))}
                {Object.keys(status).length === 0 && (
                  <div className="col-span-3 text-center py-8 text-muted-foreground text-sm">
                    Engine status unavailable
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      <ScanDetailDialog
        scan={selectedScan}
        open={detailOpen}
        onClose={() => setDetailOpen(false)}
      />
    </motion.div>
  );
}
