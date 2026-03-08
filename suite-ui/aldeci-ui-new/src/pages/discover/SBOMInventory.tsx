import { useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { DataTable } from "@/components/shared/data-table";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { Shield, AlertTriangle, RefreshCw, Activity, Layers, Cloud, Container, Box, GitBranch, Radio, Globe } from "lucide-react";
import { useApps, useScannerParsers } from "@/hooks/use-api";

export default function SBOMInventory() {
  const apps = useApps();
  const parsers = useScannerParsers();
  const refetch = useCallback(() => { apps.refetch(); parsers.refetch(); }, [apps, parsers]);
  if (apps.isLoading) return <PageSkeleton />;
  if (apps.isError) return <ErrorState onRetry={refetch} />;
  const appList = Array.isArray(apps.data) ? apps.data : [];
  const parserList = Array.isArray(parsers.data) ? parsers.data : [];
  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader title="SBOM Inventory" description="Software Bill of Materials management" actions={<Button variant="outline" size="sm" onClick={refetch}><RefreshCw className="mr-2 h-4 w-4" />Refresh</Button>} />
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3"><KpiCard title="Applications" value={appList.length} icon={Box} /><KpiCard title="Parsers" value={parserList.length} icon={Layers} /><KpiCard title="Components" value={0} icon={GitBranch} /></div>
      <Card><CardHeader><CardTitle className="text-sm font-medium">SBOM Components</CardTitle></CardHeader><CardContent><p className="text-sm text-muted-foreground text-center py-8">No SBOM data yet. Ingest CycloneDX or SPDX documents to populate.</p></CardContent></Card>
    </div>
  );
}
