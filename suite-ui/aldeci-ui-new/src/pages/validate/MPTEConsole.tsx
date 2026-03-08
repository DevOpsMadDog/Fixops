import { useState, useCallback } from "react";
import { motion } from "framer-motion";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { DataTable } from "@/components/shared/data-table";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { Play, Shield, AlertTriangle, CheckCircle2, Cpu, Target, RefreshCw, Activity } from "lucide-react";
import { useMpteStatus, useMpteStats, useMpteResults, useMpteConfigs, useRunMpteScan } from "@/hooks/use-api";
import { toast } from "sonner";

export default function MPTEConsole() {
  const [target, setTarget] = useState("");
  const status = useMpteStatus();
  const stats = useMpteStats();
  const results = useMpteResults();
  const configs = useMpteConfigs();
  const runScan = useRunMpteScan();
  const refetch = useCallback(() => { status.refetch(); stats.refetch(); results.refetch(); configs.refetch(); }, [status, stats, results, configs]);

  if (status.isLoading) return <PageSkeleton />;
  if (status.isError) return <ErrorState onRetry={refetch} />;

  const st = status.data ?? {};
  const stData = stats.data ?? {};
  const resultItems = results.data?.items ?? [];
  const configList = Array.isArray(configs.data) ? configs.data : configs.data?.configs ?? [];

  const handleScan = () => {
    if (!target.trim()) { toast.error("Enter a target to scan"); return; }
    runScan.mutate({ target: target.trim(), scan_type: "comprehensive" });
  };

  const resultCols = [
    { key: "id", header: "ID", render: (r: Record<string, unknown>) => <span className="font-mono text-xs">{String(r.id ?? r.result_id ?? "").slice(0, 12)}</span> },
    { key: "target", header: "Target", render: (r: Record<string, unknown>) => <span className="text-sm">{String(r.target ?? "")}</span> },
    { key: "verdict", header: "Verdict", render: (r: Record<string, unknown>) => <Badge variant={String(r.verdict ?? "").includes("VULNERABLE") ? "destructive" : "outline"}>{String(r.verdict ?? r.status ?? "—")}</Badge> },
    { key: "confidence", header: "Confidence", render: (r: Record<string, unknown>) => <span className="font-mono">{r.confidence != null ? `${Number(r.confidence).toFixed(0)}%` : "—"}</span> },
  ];

  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader title="MPTE Console" description="Multi-Phase Threat Exploitation engine" badge={st.status === "healthy" ? "ONLINE" : "OFFLINE"}
        actions={<Button variant="outline" size="sm" onClick={refetch}><RefreshCw className="mr-2 h-4 w-4" />Refresh</Button>} />

      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <KpiCard title="Engine Status" value={String(st.status ?? "unknown").toUpperCase()} icon={Cpu} />
        <KpiCard title="Total Requests" value={stData.total_requests ?? 0} icon={Target} />
        <KpiCard title="Total Results" value={stData.total_results ?? 0} icon={Shield} />
        <KpiCard title="Configs" value={st.configs_count ?? 0} icon={Activity} />
      </div>

      {/* Scan Launcher */}
      <Card>
        <CardHeader><CardTitle className="text-sm font-medium">Launch Verification Scan</CardTitle></CardHeader>
        <CardContent>
          <div className="flex gap-3">
            <Input placeholder="Enter target (CVE, finding ID, or URL)..." value={target} onChange={(e) => setTarget(e.target.value)} className="flex-1" />
            <Button onClick={handleScan} disabled={runScan.isPending}>
              <Play className="mr-2 h-4 w-4" />{runScan.isPending ? "Starting..." : "Start Scan"}
            </Button>
          </div>
        </CardContent>
      </Card>

      <Tabs defaultValue="results">
        <TabsList><TabsTrigger value="results">Results ({resultItems.length})</TabsTrigger><TabsTrigger value="configs">Configs ({configList.length})</TabsTrigger></TabsList>
        <TabsContent value="results">
          <Card><CardContent className="pt-6"><DataTable columns={resultCols} data={resultItems} emptyMessage="No scan results yet. Launch a verification scan above." /></CardContent></Card>
        </TabsContent>
        <TabsContent value="configs">
          <Card><CardContent className="pt-6">
            {configList.length > 0 ? <div className="space-y-2">{configList.map((c: Record<string, unknown>, i: number) => (
              <div key={i} className="flex items-center justify-between p-3 rounded-lg border border-border/50">
                <span className="font-medium text-sm">{String(c.name ?? c.id ?? `Config ${i + 1}`)}</span>
                <Badge variant="outline">{String(c.type ?? "default")}</Badge>
              </div>
            ))}</div> : <p className="text-sm text-muted-foreground text-center py-8">No MPTE configs. Default config is active.</p>}
          </CardContent></Card>
        </TabsContent>
      </Tabs>

      {/* Stats Breakdown */}
      {(Object.keys(stData.by_status ?? {}).length > 0 || Object.keys(stData.by_exploitability ?? {}).length > 0) && (
        <div className="grid gap-4 lg:grid-cols-2">
          <Card><CardHeader><CardTitle className="text-sm font-medium">By Status</CardTitle></CardHeader><CardContent>
            <div className="space-y-2">{Object.entries(stData.by_status ?? {}).map(([k, v]) => (
              <div key={k} className="flex justify-between text-sm"><span className="capitalize">{k}</span><span className="font-mono">{String(v)}</span></div>
            ))}</div>
          </CardContent></Card>
          <Card><CardHeader><CardTitle className="text-sm font-medium">By Exploitability</CardTitle></CardHeader><CardContent>
            <div className="space-y-2">{Object.entries(stData.by_exploitability ?? {}).map(([k, v]) => (
              <div key={k} className="flex justify-between text-sm"><span className="capitalize">{k}</span><span className="font-mono">{String(v)}</span></div>
            ))}</div>
          </CardContent></Card>
        </div>
      )}
    </div>
  );
}
