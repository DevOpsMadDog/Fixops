import { useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { DataTable } from "@/components/shared/data-table";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { Package, ShieldCheck, RefreshCw, FileText } from "lucide-react";
import { useEvidenceBundles } from "@/hooks/use-api";

export default function EvidenceBundles() {
  const bundles = useEvidenceBundles();
  const refetch = useCallback(() => bundles.refetch(), [bundles]);
  if (bundles.isLoading) return <PageSkeleton />;
  if (bundles.isError) return <ErrorState onRetry={refetch} />;
  const list = bundles.data?.bundles ?? [];
  const cols = [
    { key: "id", header: "Bundle ID", render: (r: Record<string, unknown>) => <span className="font-mono text-xs text-primary">{String(r.id)}</span> },
    { key: "framework", header: "Framework", render: (r: Record<string, unknown>) => <span className="text-sm">{((r.frameworks as string[]) ?? []).join(", ")}</span> },
    { key: "status", header: "Status", render: (r: Record<string, unknown>) => <Badge variant="outline" className="capitalize">{String(r.status)}</Badge> },
    { key: "finding_count", header: "Findings", render: (r: Record<string, unknown>) => <span className="font-mono">{Number(r.finding_count ?? 0)}</span> },
    { key: "signature_valid", header: "Signature", render: (r: Record<string, unknown>) => <Badge variant={r.signature_valid ? "default" : "destructive"}>{r.signature_valid ? "Valid" : "Invalid"}</Badge> },
    { key: "size_mb", header: "Size", render: (r: Record<string, unknown>) => <span className="text-sm">{r.size_mb}MB</span> },
  ];
  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader title="Evidence Bundles" description="Generated compliance evidence packages" actions={<Button variant="outline" size="sm" onClick={refetch}><RefreshCw className="mr-2 h-4 w-4" />Refresh</Button>} />
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3"><KpiCard title="Bundles" value={list.length} icon={Package} /><KpiCard title="Verified" value={list.filter((b: Record<string, unknown>) => b.signature_valid).length} icon={ShieldCheck} /><KpiCard title="Findings" value={list.reduce((a: number, b: Record<string, unknown>) => a + Number(b.finding_count ?? 0), 0)} icon={FileText} /></div>
      <Card><CardContent className="pt-6"><DataTable columns={cols} data={list} emptyMessage="No evidence bundles. Generate bundles from the Evidence Vault." /></CardContent></Card>
    </div>
  );
}
