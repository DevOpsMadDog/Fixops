/**
 * SBOMExportPanel — tab "export" in SBOMProvenanceHub
 * Calls GET /api/v1/sbom-export/ → { projects: [...] }
 */
import { useEffect, useState } from "react";
import { FileDown, Package, AlertTriangle, CheckCircle } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { EmptyState } from "@/components/shared/EmptyState";
import { sbomExportApi } from "@/lib/api";

interface ExportProject {
  project_name: string;
  component_count: number;
  vuln_count?: number;
  last_exported_at?: string;
  ecosystem_breakdown?: Record<string, number>;
  license_breakdown?: Record<string, number>;
}

function severityBadge(count: number) {
  if (count === 0) return <Badge variant="outline" className="text-green-400 border-green-700">0 vulns</Badge>;
  if (count < 5) return <Badge className="bg-amber-600/20 text-amber-400 border-amber-700">{count} vulns</Badge>;
  return <Badge className="bg-red-600/20 text-red-400 border-red-700">{count} vulns</Badge>;
}

export function SBOMExportPanel() {
  const [projects, setProjects] = useState<ExportProject[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    sbomExportApi
      .list()
      .then((res) => {
        const data = res.data;
        setProjects(Array.isArray(data?.projects) ? data.projects : Array.isArray(data) ? data : []);
      })
      .catch((e: unknown) => setError(e instanceof Error ? e.message : "Failed to load"))
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4 mt-4">
        {Array.from({ length: 6 }).map((_, i) => (
          <div key={i} className="h-32 rounded-lg bg-muted/40 animate-pulse" />
        ))}
      </div>
    );
  }

  if (error) {
    return (
      <div className="mt-4 rounded-lg border border-red-800 bg-red-950/30 p-4 text-sm text-red-400">
        {error}
      </div>
    );
  }

  if (projects.length === 0) {
    return (
      <EmptyState
        icon={FileDown}
        title="No SBOM projects yet"
        description="Register components via POST /api/v1/sbom-export/components to start generating CycloneDX / SPDX exports."
      />
    );
  }

  return (
    <div className="mt-4 space-y-4">
      <p className="text-xs text-muted-foreground">{projects.length} project{projects.length !== 1 ? "s" : ""} tracked</p>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {projects.map((p) => (
          <Card key={p.project_name} className="bg-card/60 border-border/50 hover:border-border transition-colors">
            <CardHeader className="pb-2 flex flex-row items-start justify-between gap-2">
              <CardTitle className="text-sm font-medium truncate flex items-center gap-2">
                <Package className="h-4 w-4 text-indigo-400 shrink-0" />
                {p.project_name}
              </CardTitle>
              {severityBadge(p.vuln_count ?? 0)}
            </CardHeader>
            <CardContent className="space-y-2 text-xs text-muted-foreground">
              <div className="flex items-center gap-1">
                <CheckCircle className="h-3.5 w-3.5 text-green-400" />
                {p.component_count ?? 0} components
              </div>
              {p.last_exported_at && (
                <div className="flex items-center gap-1">
                  <FileDown className="h-3.5 w-3.5 text-sky-400" />
                  Last export: {new Date(p.last_exported_at).toLocaleDateString()}
                </div>
              )}
              {p.ecosystem_breakdown && Object.keys(p.ecosystem_breakdown).length > 0 && (
                <div className="flex flex-wrap gap-1 pt-1">
                  {Object.entries(p.ecosystem_breakdown).slice(0, 4).map(([eco, cnt]) => (
                    <Badge key={eco} variant="outline" className="text-[10px] px-1 py-0">
                      {eco}: {cnt}
                    </Badge>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        ))}
      </div>
    </div>
  );
}
