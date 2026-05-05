/**
 * PBOMPropagationPanel — tab "pbom-prop" in SBOMProvenanceHub
 * Calls GET /api/v1/pbom/artifact/{sha256}/provenance?org_id=default
 * User enters a SHA-256 digest; results show which runs produced that artifact.
 */
import { useState } from "react";
import { GitMerge, Search, GitBranch, CheckCircle, XCircle } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { EmptyState } from "@/components/shared/EmptyState";
import { pbomApi } from "@/lib/api";

interface ProvenanceRun {
  run_id?: string;
  org_id?: string;
  repo_ref?: string;
  ci_provider?: string;
  branch?: string;
  commit_sha?: string;
  trigger?: string;
  status?: string;
  started_at?: string;
  completed_at?: string;
}

interface ProvenanceResult {
  sha256: string;
  total: number;
  runs: ProvenanceRun[];
}

function statusBadge(status?: string) {
  switch (status) {
    case "success": return <Badge className="bg-green-600/20 text-green-400 border-green-700">{status}</Badge>;
    case "failed": return <Badge className="bg-red-600/20 text-red-400 border-red-700">{status}</Badge>;
    case "running": return <Badge className="bg-sky-600/20 text-sky-400 border-sky-700">{status}</Badge>;
    default: return <Badge variant="outline">{status ?? "unknown"}</Badge>;
  }
}

export function PBOMPropagationPanel() {
  const [digest, setDigest] = useState("");
  const [result, setResult] = useState<ProvenanceResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [searched, setSearched] = useState(false);

  function handleSearch() {
    const sha = digest.trim();
    if (!sha) return;
    setLoading(true);
    setError(null);
    setResult(null);
    setSearched(true);
    pbomApi
      .artifactProvenance(sha)
      .then((res) => setResult(res.data))
      .catch((e: unknown) => setError(e instanceof Error ? e.message : "Lookup failed"))
      .finally(() => setLoading(false));
  }

  return (
    <div className="mt-4 space-y-4">
      {/* Search bar */}
      <Card className="bg-card/60 border-border/50">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm flex items-center gap-2">
            <GitMerge className="h-4 w-4 text-indigo-400" />
            Artifact Propagation Lookup
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-xs text-muted-foreground mb-3">
            Enter a SHA-256 digest to see which pipeline runs produced this artifact and where it was deployed.
          </p>
          <div className="flex gap-2">
            <Input
              className="font-mono text-xs h-9 flex-1"
              placeholder="sha256:abc123… or full digest"
              value={digest}
              onChange={(e) => setDigest(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleSearch()}
            />
            <Button size="sm" onClick={handleSearch} disabled={loading || !digest.trim()} className="gap-1.5">
              <Search className="h-3.5 w-3.5" />
              {loading ? "Looking up…" : "Look up"}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Error */}
      {error && (
        <div className="rounded-lg border border-red-800 bg-red-950/30 p-4 text-sm text-red-400">
          {error}
        </div>
      )}

      {/* Results */}
      {result && result.total === 0 && (
        <EmptyState
          icon={GitMerge}
          title="No runs found for this digest"
          description="No pipeline run has recorded this artifact SHA-256. Verify the digest or register runs via POST /api/v1/pbom/run/start."
        />
      )}

      {result && result.runs.length > 0 && (
        <Card className="bg-card/60 border-border/50">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">
              {result.total} run{result.total !== 1 ? "s" : ""} produced{" "}
              <span className="font-mono text-indigo-400 text-xs">{result.sha256.slice(0, 16)}…</span>
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-border/50 text-muted-foreground">
                    <th className="text-left px-4 py-2 font-medium">Repo</th>
                    <th className="text-left px-4 py-2 font-medium">CI</th>
                    <th className="text-left px-4 py-2 font-medium">Branch</th>
                    <th className="text-left px-4 py-2 font-medium">Commit</th>
                    <th className="text-center px-4 py-2 font-medium">Status</th>
                    <th className="text-left px-4 py-2 font-medium">Started</th>
                  </tr>
                </thead>
                <tbody>
                  {result.runs.map((run, idx) => (
                    <tr key={run.run_id ?? idx} className="border-b border-border/30 hover:bg-muted/20 transition-colors">
                      <td className="px-4 py-2 truncate max-w-[160px]">{run.repo_ref ?? "—"}</td>
                      <td className="px-4 py-2 text-muted-foreground capitalize">{run.ci_provider ?? "—"}</td>
                      <td className="px-4 py-2">
                        {run.branch ? (
                          <span className="flex items-center gap-1">
                            <GitBranch className="h-3 w-3 text-muted-foreground" />
                            {run.branch}
                          </span>
                        ) : "—"}
                      </td>
                      <td className="px-4 py-2 font-mono text-muted-foreground">
                        {run.commit_sha ? run.commit_sha.slice(0, 8) : "—"}
                      </td>
                      <td className="px-4 py-2 text-center">{statusBadge(run.status)}</td>
                      <td className="px-4 py-2 text-muted-foreground">
                        {run.started_at ? new Date(run.started_at).toLocaleDateString() : "—"}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}

      {!searched && (
        <EmptyState
          icon={Search}
          title="Enter an artifact digest above"
          description="Trace any container image, binary, or package back to the exact pipeline run that produced it."
        />
      )}
    </div>
  );
}
