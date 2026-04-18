import { toArray } from "@/lib/api-utils";
import { useState, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Progress } from "@/components/ui/progress";
import { Switch } from "@/components/ui/switch";
import { Label } from "@/components/ui/label";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { motion } from "framer-motion";
import {
  ShieldCheck, CheckCircle, XCircle, AlertTriangle, RefreshCw,
  Eye, FileText, Lock, Activity, Shield, User, Layers
} from "lucide-react";
import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from "recharts";
import { useComplianceSoc2, useEvidenceBundles, useComplianceEvidenceRequests, useAssessCompliance } from "@/hooks/use-api";
import { toast } from "sonner";

const SOC2_CATEGORIES = [
  {
    id: "CC",
    name: "Common Criteria",
    icon: Shield,
    color: "text-blue-400",
    description: "Security, availability, processing integrity, confidentiality, privacy",
  },
  {
    id: "A",
    name: "Availability",
    icon: Activity,
    color: "text-green-400",
    description: "System availability for operation and use",
  },
  {
    id: "C",
    name: "Confidentiality",
    icon: Lock,
    color: "text-violet-400",
    description: "Protection of confidential information",
  },
  {
    id: "PI",
    name: "Processing Integrity",
    icon: CheckCircle,
    color: "text-orange-400",
    description: "Complete, valid, accurate, timely, and authorized processing",
  },
  {
    id: "P",
    name: "Privacy",
    icon: User,
    color: "text-pink-400",
    description: "Personal information collected, used, retained, and disclosed",
  },
];

const evidenceStatusVariant: Record<string, any> = {
  collected: "default",
  partial: "secondary",
  missing: "destructive",
  pending: "outline",
};

function CategoryProgressBar({ controls }: { controls: any[] }) {
  const total = controls.length;
  if (total === 0) return null;
  const passed = controls.filter((c) => c.status === "passed" || c.evidence_status === "collected").length;
  const pct = Math.round((passed / total) * 100);
  return (
    <div className="mt-2">
      <div className="flex justify-between text-xs text-muted-foreground mb-1">
        <span>{passed}/{total} controls evidenced</span>
        <span>{pct}%</span>
      </div>
      <Progress value={pct} className="h-2" />
    </div>
  );
}

export default function SOC2Evidence() {
  const soc2Query = useComplianceSoc2();
  const bundlesQuery = useEvidenceBundles({ framework: "SOC2" });
  const evidenceRequestsQuery = useComplianceEvidenceRequests({ org_id: "default" });
  const refetchAll = useCallback(() => {
    soc2Query.refetch();
    bundlesQuery.refetch();
    evidenceRequestsQuery.refetch();
  }, [soc2Query, bundlesQuery, evidenceRequestsQuery]);

  const [activeTab, setActiveTab] = useState("CC");
  const [auditorView, setAuditorView] = useState(false);

  const isLoading = soc2Query.isLoading || bundlesQuery.isLoading;
  const isError = soc2Query.isError && evidenceRequestsQuery.isError;

  if (isLoading) return <PageSkeleton />;
  if (isError) return <ErrorState message="Failed to load SOC2 evidence data" onRetry={refetchAll} />;

  const evidenceRequests: any[] = toArray(evidenceRequestsQuery.data);
  const soc2Data: any = soc2Query.data?.data ?? {};
  // Prefer live evidence requests for controls if available, fall back to soc2 engine data
  const controls: any[] = evidenceRequests.length > 0
    ? evidenceRequests.map((r: any) => ({
        control_id: r.control_id ?? r.id,
        title: r.control_name ?? r.description ?? "Evidence request",
        description: r.description ?? "",
        status: r.status === "approved" ? "passed" : r.status === "rejected" ? "failed" : "partial",
        evidence_status: r.status === "approved" ? "collected" : r.status === "submitted" ? "partial" : "pending",
        last_verified: r.updated_at ?? r.created_at ?? "",
        has_gap: r.status !== "approved",
        framework: r.framework ?? "SOC2",
      }))
    : (soc2Data.controls ?? soc2Data ?? []);
  const bundles: any[] = toArray(bundlesQuery.data);

  // Group controls by category
  const byCategory: Record<string, any[]> = {};
  SOC2_CATEGORIES.forEach((cat) => { byCategory[cat.id] = []; });
  (Array.isArray(controls) ? controls : []).forEach((ctrl: any) => {
    const prefix = (ctrl.control_id ?? ctrl.id ?? "").match(/^[A-Z]+/)?.[0] ?? "CC";
    if (byCategory[prefix]) byCategory[prefix].push(ctrl);
    else byCategory["CC"].push(ctrl);
  });

  const activeControls = byCategory[activeTab] ?? [];
  const totalControls = controls.length;
  const passedControls = (Array.isArray(controls) ? controls : []).filter((c: any) => c.status === "passed").length;
  const gapCount = (Array.isArray(controls) ? controls : []).filter((c: any) => c.status !== "passed").length;
  const bundleCount = bundles.length;

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      <PageHeader
        title="SOC 2 Evidence"
        description="SOC2 Trust Service Criteria control-by-control evidence mapping"
        actions={
          <div className="flex items-center gap-2">
            <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <Switch id="auditor" checked={auditorView} onCheckedChange={setAuditorView} />
            <Label htmlFor="auditor" className="text-sm cursor-pointer">
              <Eye className="h-3.5 w-3.5 inline mr-1" />
              Auditor View
            </Label>
          </div>
          <Button variant="outline" size="sm" onClick={refetchAll} className="gap-2">
            <RefreshCw className="h-4 w-4" />
            Refresh
          </Button>
          <Button size="sm" className="gap-2" onClick={() => {
            const exportData = {
              framework: "SOC2",
              controls: Array.isArray(controls) ? controls : [],
              bundles,
              summary: {
                totalControls,
                passedControls,
                gapCount,
                bundleCount,
                exportDate: new Date().toISOString(),
              },
            };
            const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: "application/json" });
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = `soc2-evidence-report-${new Date().toISOString().split("T")[0]}.json`;
            document.body.appendChild(a);
            a.click();
            document.body.removeChild(a);
            URL.revokeObjectURL(url);
            toast.success("SOC2 report exported");
          }}>
            <FileText className="h-4 w-4" />
            Export Report
          </Button>
        </div>
          </div>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Total Controls" value={totalControls} icon={Layers} />
        <KpiCard title="Controls Passed" value={passedControls} icon={CheckCircle} change={passedControls} changeLabel="compliant" />
        <KpiCard title="Gaps Found" value={gapCount} icon={AlertTriangle} />
        <KpiCard title="Evidence Bundles" value={bundleCount} icon={ShieldCheck} />
      </div>

      {/* Category overview cards */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-3">
        {SOC2_CATEGORIES.map((cat) => {
          const catControls = byCategory[cat.id] ?? [];
          const catPassed = catControls.filter((c) => c.status === "passed" || c.evidence_status === "collected").length;
          const catPct = catControls.length > 0 ? Math.round((catPassed / catControls.length) * 100) : 0;
          const Icon = cat.icon;
          return (
            <Card
              key={cat.id}
              className={`cursor-pointer transition-all hover:shadow-md ${activeTab === cat.id ? "ring-1 ring-primary" : ""}`}
              onClick={() => setActiveTab(cat.id)}
            >
              <CardContent className="p-4">
                <div className="flex items-center gap-2 mb-2">
                  <Icon className={`h-4 w-4 ${cat.color}`} />
                  <span className="text-xs font-semibold">{cat.id}</span>
                </div>
                <p className="text-xs text-muted-foreground mb-2 line-clamp-1">{cat.name}</p>
                <div className="text-lg font-bold mb-1">{catPct}%</div>
                <Progress value={catPct} className="h-1.5" />
                <p className="text-xs text-muted-foreground mt-1">{catPassed}/{catControls.length || "—"} controls</p>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* Control detail tab */}
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between flex-wrap gap-4">
            <CardTitle className="text-base flex items-center gap-2">
              <ShieldCheck className="h-4 w-4 text-primary" />
              {SOC2_CATEGORIES.find((c) => c.id === activeTab)?.name ?? "Controls"}
              <Badge variant="secondary" className="text-xs">{activeTab}</Badge>
            </CardTitle>
            <Tabs value={activeTab} onValueChange={setActiveTab}>
              <TabsList className="h-8">
                {SOC2_CATEGORIES.map((cat) => (
                  <TabsTrigger key={cat.id} value={cat.id} className="text-xs px-3 h-6">
                    {cat.id}
                  </TabsTrigger>
                ))}
              </TabsList>
            </Tabs>
          </div>
          <CategoryProgressBar controls={activeControls} />
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent border-b border-border/40">
                <TableHead className="text-xs">Control ID</TableHead>
                <TableHead className="text-xs">Description</TableHead>
                <TableHead className="text-xs">Status</TableHead>
                <TableHead className="text-xs">Evidence Status</TableHead>
                <TableHead className="text-xs">Last Verified</TableHead>
                {auditorView && <TableHead className="text-xs">Auditor Notes</TableHead>}
                <TableHead className="text-xs">Gap</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {activeControls.length === 0 ? (
                <TableRow>
                  <TableCell colSpan={auditorView ? 7 : 6} className="text-center py-12 text-muted-foreground">
                    No controls mapped for {activeTab}
                  </TableCell>
                </TableRow>
              ) : (
                activeControls.map((ctrl: any, i: number) => (
                  <TableRow key={ctrl.control_id ?? ctrl.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="font-mono text-xs text-primary">
                      {ctrl.control_id ?? ctrl.id ?? `${activeTab}-${String(i + 1).padStart(3, "0")}`}
                    </TableCell>
                    <TableCell className="text-sm max-w-xs">
                      <p className="font-medium text-xs">{ctrl.title ?? ctrl.name ?? "Control description"}</p>
                      {!auditorView && (
                        <p className="text-muted-foreground text-xs mt-0.5 line-clamp-1">
                          {ctrl.description ?? ""}
                        </p>
                      )}
                      {auditorView && (
                        <p className="text-muted-foreground text-xs mt-0.5">{ctrl.description ?? ""}</p>
                      )}
                    </TableCell>
                    <TableCell>
                      {ctrl.status === "passed" ? (
                        <span className="flex items-center gap-1 text-green-500 text-xs">
                          <CheckCircle className="h-3 w-3" /> Passed
                        </span>
                      ) : ctrl.status === "failed" ? (
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
                      <Badge variant={evidenceStatusVariant[ctrl.evidence_status ?? "pending"] ?? "outline"} className="text-xs capitalize">
                        {ctrl.evidence_status ?? "pending"}
                      </Badge>
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">
                      {ctrl.last_verified ?? ctrl.updated_at ?? "—"}
                    </TableCell>
                    {auditorView && (
                      <TableCell className="text-xs text-muted-foreground max-w-48">
                        {ctrl.auditor_notes ?? "No notes"}
                      </TableCell>
                    )}
                    <TableCell>
                      {ctrl.has_gap || ctrl.status !== "passed" ? (
                        <Badge variant="destructive" className="text-xs">Gap</Badge>
                      ) : (
                        <Badge variant="default" className="text-xs bg-green-900/40 text-green-400 border-green-700">Clear</Badge>
                      )}
                    </TableCell>
                  </TableRow>
                ))
              )}
            </TableBody>
          </Table>
          </div>
        </CardContent>
      </Card>

      {/* Evidence completeness trend chart */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Activity className="h-4 w-4 text-primary" />
            Evidence Completeness Trend — {SOC2_CATEGORIES.find((c) => c.id === activeTab)?.name}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <ResponsiveContainer width="100%" height={200}>
            <AreaChart
              data={[
                { month: "Current", completeness: Math.round(activeControls.length > 0 ? (activeControls.filter((c) => c.evidence_status === "collected" || c.status === "passed").length / activeControls.length) * 100 : 0) },
              ]}
              margin={{ top: 8, right: 16, left: 0, bottom: 0 }}
            >
              <defs>
                <linearGradient id="evGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor="#6366f1" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#6366f1" stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis dataKey="month" tick={{ fontSize: 11, fill: "#94a3b8" }} axisLine={false} tickLine={false} />
              <YAxis domain={[0, 100]} unit="%" tick={{ fontSize: 11, fill: "#94a3b8" }} axisLine={false} tickLine={false} />
              <Tooltip
                contentStyle={{ background: "#0f172a", border: "1px solid #1e293b", borderRadius: 8 }}
                labelStyle={{ color: "#94a3b8" }}
              />
              <Area type="monotone" dataKey="completeness" stroke="#6366f1" strokeWidth={2} fill="url(#evGrad)" name="Completeness %" />
            </AreaChart>
          </ResponsiveContainer>
        </CardContent>
      </Card>

      {/* All categories progress summary */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Layers className="h-4 w-4 text-primary" />
            All Categories — Evidence Progress
          </CardTitle>
        </CardHeader>
        <CardContent className="space-y-4">
          {SOC2_CATEGORIES.map((cat) => {
            const catControls = byCategory[cat.id] ?? [];
            const catPassed = catControls.filter((c) => c.status === "passed" || c.evidence_status === "collected").length;
            const catPct = catControls.length > 0 ? Math.round((catPassed / catControls.length) * 100) : 0;
            const Icon = cat.icon;
            return (
              <div key={cat.id}>
                <div className="flex items-center gap-3 mb-1.5">
                  <Icon className={`h-3.5 w-3.5 ${cat.color} shrink-0`} />
                  <span className="text-sm font-medium flex-1">{cat.name}</span>
                  <span className="text-xs text-muted-foreground">{catPassed}/{catControls.length || "—"}</span>
                  <span className="text-xs font-bold text-primary w-10 text-right">{catPct}%</span>
                </div>
                <Progress value={catPct} className="h-2" />
              </div>
            );
          })}
        </CardContent>
      </Card>

      {/* Evidence bundles linked to SOC2 */}
      {bundles.length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base flex items-center gap-2">
              <ShieldCheck className="h-4 w-4 text-primary" />
              SOC2 Evidence Bundles
              <Badge variant="secondary" className="text-xs">{bundles.length} bundles</Badge>
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent border-b border-border/40">
                  <TableHead className="text-xs">Bundle ID</TableHead>
                  <TableHead className="text-xs">Control</TableHead>
                  <TableHead className="text-xs">App</TableHead>
                  <TableHead className="text-xs">Signed Date</TableHead>
                  <TableHead className="text-xs">Quantum Signature</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {bundles.slice(0, 10).map((bundle: any, i: number) => (
                  <TableRow key={bundle.bundle_id ?? bundle.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="font-mono text-xs text-primary">
                      {bundle.bundle_id ?? bundle.id ?? `SOC2-BND-${i + 1}`}
                    </TableCell>
                    <TableCell className="text-xs text-muted-foreground">{bundle.control ?? "—"}</TableCell>
                    <TableCell className="text-xs font-medium">{bundle.app_id ?? bundle.app ?? "—"}</TableCell>
                    <TableCell className="text-xs text-muted-foreground">{bundle.signed_date ?? bundle.created_at ?? "—"}</TableCell>
                    <TableCell>
                      {(bundle.quantum_signed || bundle.signed) ? (
                        <Badge className="text-xs bg-violet-900/40 text-violet-300 border-violet-700">
                          <Lock className="h-2.5 w-2.5 mr-1" />Quantum
                        </Badge>
                      ) : (
                        <Badge variant="outline" className="text-xs">Standard</Badge>
                      )}
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
            </div>
          </CardContent>
        </Card>
      )}
    </motion.div>
  );
}
