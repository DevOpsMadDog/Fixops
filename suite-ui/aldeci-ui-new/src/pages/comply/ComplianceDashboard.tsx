import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts";
import {
  ShieldCheck,
  Download,
  CheckCircle2,
  AlertTriangle,
  Clock,
  TrendingUp,
  FileText,
  Calendar,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { complianceApi } from "@/lib/api";
import { toast } from "sonner";

// ─── Mock Data ──────────────────────────────────────────────────────────────

const MOCK_FRAMEWORKS = [
  {
    id: "soc2",
    name: "SOC 2 Type II",
    controlsCovered: 89,
    controlsTotal: 97,
    lastAudit: "2024-11-15",
    nextAudit: "2025-11-15",
    status: "compliant",
    auditor: "Deloitte & Touche",
    certificateExpiry: "2025-11-15",
  },
  {
    id: "pci-dss",
    name: "PCI-DSS v4.0",
    controlsCovered: 201,
    controlsTotal: 234,
    lastAudit: "2024-09-01",
    nextAudit: "2025-09-01",
    status: "in-progress",
    auditor: "Verizon Business",
    certificateExpiry: "2025-09-01",
  },
  {
    id: "iso27001",
    name: "ISO 27001:2022",
    controlsCovered: 91,
    controlsTotal: 93,
    lastAudit: "2024-12-01",
    nextAudit: "2025-12-01",
    status: "compliant",
    auditor: "BSI Group",
    certificateExpiry: "2026-12-01",
  },
  {
    id: "hipaa",
    name: "HIPAA",
    controlsCovered: 48,
    controlsTotal: 66,
    lastAudit: "2024-08-20",
    nextAudit: "2025-08-20",
    status: "gap",
    auditor: "KPMG Healthcare",
    certificateExpiry: null,
  },
  {
    id: "nist800",
    name: "NIST 800-53 Rev5",
    controlsCovered: 287,
    controlsTotal: 323,
    lastAudit: "2024-10-10",
    nextAudit: "2025-10-10",
    status: "in-progress",
    auditor: "Internal",
    certificateExpiry: null,
  },
];

const MOCK_GAP_DATA = [
  { framework: "SOC 2", covered: 89, gap: 8, total: 97 },
  { framework: "PCI-DSS", covered: 201, gap: 33, total: 234 },
  { framework: "ISO 27001", covered: 91, gap: 2, total: 93 },
  { framework: "HIPAA", covered: 48, gap: 18, total: 66 },
  { framework: "NIST 800-53", covered: 287, gap: 36, total: 323 },
];

const MOCK_MILESTONES = [
  {
    id: "m1",
    date: "2025-01-15",
    event: "PCI-DSS Quarterly Scan Completed",
    framework: "PCI-DSS",
    status: "completed",
  },
  {
    id: "m2",
    date: "2025-02-01",
    event: "SOC 2 Evidence Collection Window Opens",
    framework: "SOC 2",
    status: "completed",
  },
  {
    id: "m3",
    date: "2025-03-10",
    event: "HIPAA Gap Remediation Deadline",
    framework: "HIPAA",
    status: "upcoming",
  },
  {
    id: "m4",
    date: "2025-04-01",
    event: "ISO 27001 Surveillance Audit",
    framework: "ISO 27001",
    status: "upcoming",
  },
  {
    id: "m5",
    date: "2025-05-15",
    event: "NIST 800-53 Control Assessment",
    framework: "NIST 800-53",
    status: "planned",
  },
  {
    id: "m6",
    date: "2025-09-01",
    event: "PCI-DSS Annual Assessment",
    framework: "PCI-DSS",
    status: "planned",
  },
];

// ─── Helpers ────────────────────────────────────────────────────────────────

function getStatusBadge(status: string) {
  switch (status) {
    case "compliant":
      return <Badge variant="success">Compliant</Badge>;
    case "in-progress":
      return <Badge variant="warning">In Progress</Badge>;
    case "gap":
      return <Badge variant="destructive">Gap Found</Badge>;
    default:
      return <Badge variant="secondary">{status}</Badge>;
  }
}

function getMilestoneIcon(status: string) {
  switch (status) {
    case "completed":
      return <CheckCircle2 className="h-4 w-4 text-green-400" />;
    case "upcoming":
      return <AlertTriangle className="h-4 w-4 text-yellow-400" />;
    default:
      return <Clock className="h-4 w-4 text-muted-foreground" />;
  }
}

const FRAMEWORK_COLORS: Record<string, string> = {
  "SOC 2": "#14b8a6",
  "PCI-DSS": "#f59e0b",
  "ISO 27001": "#22c55e",
  "HIPAA": "#ef4444",
  "NIST 800-53": "#8b5cf6",
};

// ─── Component ───────────────────────────────────────────────────────────────

export default function ComplianceDashboard() {
  const [selectedFramework, setSelectedFramework] = useState<string | null>(null);

  const { data } = useQuery({
    queryKey: ["compliance-status"],
    queryFn: () => complianceApi.status(),
  });

  const frameworks = (data as { data?: typeof MOCK_FRAMEWORKS })?.data ?? MOCK_FRAMEWORKS;

  const totalCompliant = frameworks.filter((f) => f.status === "compliant").length;
  const totalGaps = frameworks.reduce(
    (acc, f) => acc + (f.controlsTotal - f.controlsCovered),
    0
  );
  const avgCoverage = Math.round(
    frameworks.reduce((acc, f) => acc + (f.controlsCovered / f.controlsTotal) * 100, 0) /
      frameworks.length
  );

  const handleExport = (frameworkId: string, e: React.MouseEvent) => {
    e.stopPropagation();
    toast.success(`Exporting ${frameworkId.toUpperCase()} evidence package...`);
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      <PageHeader
        title="Compliance Dashboard"
        description="Multi-framework compliance posture across SOC 2, PCI-DSS, ISO 27001, HIPAA, and NIST 800-53"
        badge="5 Frameworks"
        actions={
          <Button variant="outline" size="sm" onClick={() => toast.success("Generating full compliance report...")}>
            <FileText className="mr-2 h-4 w-4" />
            Export All
          </Button>
        }
      />

      {/* KPI Row */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard
          title="Compliant Frameworks"
          value={`${totalCompliant}/${frameworks.length}`}
          change={5}
          changeLabel="vs last quarter"
          icon={ShieldCheck}
          trend="up"
        />
        <KpiCard
          title="Avg Control Coverage"
          value={`${avgCoverage}%`}
          change={3.2}
          changeLabel="vs last quarter"
          icon={TrendingUp}
          trend="up"
        />
        <KpiCard
          title="Total Control Gaps"
          value={totalGaps}
          change={-12}
          changeLabel="vs last quarter"
          icon={AlertTriangle}
          trend="up"
        />
        <KpiCard
          title="Next Audit"
          value="Mar 10, 2025"
          changeLabel="HIPAA Gap Deadline"
          icon={Calendar}
          trend="flat"
        />
      </div>

      {/* Framework Status Cards */}
      <div>
        <h2 className="text-sm font-semibold uppercase tracking-wider text-muted-foreground mb-3">
          Framework Status
        </h2>
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {frameworks.map((fw) => {
            const pct = Math.round((fw.controlsCovered / fw.controlsTotal) * 100);
            const isSelected = selectedFramework === fw.id;
            return (
              <Card
                key={fw.id}
                onClick={() => setSelectedFramework(isSelected ? null : fw.id)}
                className={`cursor-pointer transition-all duration-200 hover:border-primary/50 ${
                  isSelected ? "border-primary ring-1 ring-primary/30" : "border-border/50"
                }`}
              >
                <CardHeader className="pb-2">
                  <div className="flex items-start justify-between">
                    <div className="space-y-1">
                      <CardTitle className="text-base">{fw.name}</CardTitle>
                      <p className="text-xs text-muted-foreground">Auditor: {fw.auditor}</p>
                    </div>
                    {getStatusBadge(fw.status)}
                  </div>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="flex items-center justify-between text-sm">
                    <span className="text-muted-foreground">Controls Covered</span>
                    <span className="font-semibold tabular-nums">
                      {fw.controlsCovered}/{fw.controlsTotal}
                    </span>
                  </div>
                  <Progress value={pct} className="h-2" />
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-muted-foreground">{pct}% coverage</span>
                    <div className="flex items-center gap-2">
                      {fw.nextAudit && (
                        <span className="text-xs text-muted-foreground">
                          Next: {fw.nextAudit}
                        </span>
                      )}
                      <Button
                        variant="ghost"
                        size="sm"
                        className="h-7 px-2 text-xs"
                        onClick={(e) => handleExport(fw.id, e)}
                      >
                        <Download className="h-3.5 w-3.5 mr-1" />
                        Export
                      </Button>
                    </div>
                  </div>
                  {isSelected && (
                    <motion.div
                      initial={{ opacity: 0, height: 0 }}
                      animate={{ opacity: 1, height: "auto" }}
                      className="pt-2 border-t border-border/50 space-y-1"
                    >
                      <div className="flex justify-between text-xs">
                        <span className="text-muted-foreground">Last Audit</span>
                        <span>{fw.lastAudit}</span>
                      </div>
                      {fw.certificateExpiry && (
                        <div className="flex justify-between text-xs">
                          <span className="text-muted-foreground">Certificate Expires</span>
                          <span>{fw.certificateExpiry}</span>
                        </div>
                      )}
                      <div className="flex justify-between text-xs">
                        <span className="text-muted-foreground">Gap Controls</span>
                        <span className="text-red-400 font-medium">
                          {fw.controlsTotal - fw.controlsCovered} remaining
                        </span>
                      </div>
                    </motion.div>
                  )}
                </CardContent>
              </Card>
            );
          })}
        </div>
      </div>

      {/* Gap Analysis Chart */}
      <Card className="border-border/50">
        <CardHeader>
          <CardTitle className="text-base">Control Coverage Gap Analysis</CardTitle>
          <p className="text-xs text-muted-foreground">Controls covered vs. gap per framework</p>
        </CardHeader>
        <CardContent>
          <ResponsiveContainer width="100%" height={260}>
            <BarChart data={MOCK_GAP_DATA} margin={{ top: 4, right: 16, left: 0, bottom: 0 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
              <XAxis
                dataKey="framework"
                tick={{ fill: "#6b7280", fontSize: 12 }}
                axisLine={false}
                tickLine={false}
              />
              <YAxis
                tick={{ fill: "#6b7280", fontSize: 11 }}
                axisLine={false}
                tickLine={false}
              />
              <Tooltip
                contentStyle={{
                  backgroundColor: "#1a1a2e",
                  border: "1px solid rgba(255,255,255,0.1)",
                  borderRadius: "8px",
                  fontSize: "12px",
                }}
                labelStyle={{ color: "#e5e7eb" }}
                itemStyle={{ color: "#9ca3af" }}
              />
              <Bar dataKey="covered" name="Covered" stackId="a" radius={[0, 0, 4, 4]}>
                {MOCK_GAP_DATA.map((entry) => (
                  <Cell
                    key={entry.framework}
                    fill={FRAMEWORK_COLORS[entry.framework] ?? "#14b8a6"}
                    fillOpacity={0.85}
                  />
                ))}
              </Bar>
              <Bar dataKey="gap" name="Gap" stackId="a" fill="#ef4444" fillOpacity={0.4} radius={[4, 4, 0, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>

      {/* Compliance Milestones */}
      <Card className="border-border/50">
        <CardHeader>
          <CardTitle className="text-base">Compliance Milestones</CardTitle>
          <p className="text-xs text-muted-foreground">Upcoming audits, assessments, and deadlines</p>
        </CardHeader>
        <CardContent>
          <div className="relative">
            <div className="absolute left-[18px] top-0 bottom-0 w-px bg-border/50" />
            <div className="space-y-4">
              {MOCK_MILESTONES.map((m) => (
                <div key={m.id} className="flex items-start gap-4 pl-10 relative">
                  <div className="absolute left-[9px] top-1 bg-card">
                    {getMilestoneIcon(m.status)}
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center justify-between gap-2">
                      <p className="text-sm font-medium truncate">{m.event}</p>
                      <Badge variant="outline" className="text-xs shrink-0">
                        {m.framework}
                      </Badge>
                    </div>
                    <p className="text-xs text-muted-foreground mt-0.5">{m.date}</p>
                  </div>
                </div>
              ))}
            </div>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
