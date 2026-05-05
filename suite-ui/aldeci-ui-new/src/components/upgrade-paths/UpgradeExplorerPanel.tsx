/**
 * UpgradeExplorerPanel — tab "explorer" in UpgradePathsHub
 *
 * Step-by-step upgrade chain display.
 * Calls POST /api/v1/upgrade-path/resolve (same backend as UpgradeResolverPanel)
 * but renders the upgrade_path as a numbered hop chain rather than a KV summary.
 *
 * UX differentiator: shows each version hop with a colored connector, CVE badges,
 * and a "chain complete" indicator when safe_version is reached.
 */

import { useState } from "react";
import { Search, RefreshCw, ArrowRight, CheckCircle, AlertCircle } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { EmptyState } from "@/components/shared/EmptyState";
import { upgradePathApi, getStoredOrgId } from "@/lib/api";

interface ResolveResult {
  purl?: string;
  safe_version?: string;
  current_version?: string;
  upgrade_path?: string[];
  cve_ids?: string[];
  status?: string;
  [key: string]: unknown;
}

export function UpgradeExplorerPanel() {
  const orgId = getStoredOrgId();

  const [purl, setPurl] = useState("");
  const [cveInput, setCveInput] = useState("");
  const [resolving, setResolving] = useState(false);
  const [result, setResult] = useState<ResolveResult | null>(null);
  const [error, setError] = useState<string | null>(null);

  function handleExplore(e: React.FormEvent) {
    e.preventDefault();
    if (!purl.trim()) return;
    const cveIds = cveInput
      .split(/[\s,]+/)
      .map((s) => s.trim())
      .filter(Boolean);
    setResolving(true);
    setError(null);
    setResult(null);
    upgradePathApi
      .resolve(orgId, purl.trim(), cveIds)
      .then((r) => setResult(r.data as ResolveResult))
      .catch((e: unknown) => {
        const msg =
          (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail ??
          (e instanceof Error ? e.message : "Explore failed");
        setError(msg);
      })
      .finally(() => setResolving(false));
  }

  const hops: string[] = Array.isArray(result?.upgrade_path) ? result.upgrade_path : [];
  const cves: string[] = Array.isArray(result?.cve_ids) ? result.cve_ids : [];

  return (
    <div className="space-y-6">
      {/* Input form */}
      <Card className="bg-card/60 border-border/50">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm flex items-center gap-2">
            <Search className="h-4 w-4" />
            Explore Upgrade Chain
          </CardTitle>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleExplore} className="space-y-3">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div className="space-y-1">
                <label className="text-xs text-muted-foreground">
                  Package URL (purl) <span className="text-red-400">*</span>
                </label>
                <input
                  type="text"
                  required
                  value={purl}
                  onChange={(e) => setPurl(e.target.value)}
                  placeholder="pkg:pypi/django@3.2.0"
                  className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm font-mono outline-none focus:ring-2 focus:ring-ring"
                />
              </div>
              <div className="space-y-1">
                <label className="text-xs text-muted-foreground">
                  CVE IDs (comma/space — leave blank for all)
                </label>
                <input
                  type="text"
                  value={cveInput}
                  onChange={(e) => setCveInput(e.target.value)}
                  placeholder="CVE-2023-12345"
                  className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-ring"
                />
              </div>
            </div>
            <button
              type="submit"
              disabled={resolving || !purl.trim()}
              className="inline-flex items-center gap-2 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
            >
              {resolving ? (
                <RefreshCw className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Search className="h-3.5 w-3.5" />
              )}
              {resolving ? "Exploring…" : "Explore Chain"}
            </button>
          </form>
        </CardContent>
      </Card>

      {error && (
        <div className="rounded-lg border border-red-800 bg-red-950/30 p-4 text-sm text-red-400">
          {error}
        </div>
      )}

      {/* Chain visualization */}
      {result && hops.length > 0 && (
        <Card className="bg-card/60 border-border/50">
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm">Upgrade Chain</CardTitle>
              {result.status && (
                <Badge
                  variant="outline"
                  className={
                    result.status === "resolved"
                      ? "border-green-700 text-green-400"
                      : "border-amber-700 text-amber-400"
                  }
                >
                  {result.status}
                </Badge>
              )}
            </div>
          </CardHeader>
          <CardContent>
            {/* CVE context */}
            {cves.length > 0 && (
              <div className="mb-4 flex flex-wrap gap-1.5">
                {cves.map((c) => (
                  <Badge key={c} variant="outline" className="text-xs border-red-700 text-red-400">
                    {c}
                  </Badge>
                ))}
              </div>
            )}

            {/* Hop chain */}
            <div className="flex flex-wrap items-center gap-1 text-sm">
              {hops.map((version, idx) => {
                const isSafe = version === result?.safe_version;
                const isCurrent = version === result?.current_version || idx === 0;
                return (
                  <span key={idx} className="flex items-center gap-1">
                    <span
                      className={`inline-flex items-center gap-1 rounded-md border px-2.5 py-1 font-mono text-xs font-medium ${
                        isSafe
                          ? "border-green-700 bg-green-950/40 text-green-400"
                          : isCurrent
                          ? "border-amber-700 bg-amber-950/40 text-amber-400"
                          : "border-border bg-muted/30 text-foreground"
                      }`}
                    >
                      {isSafe && <CheckCircle className="h-3 w-3" />}
                      {version}
                    </span>
                    {idx < hops.length - 1 && (
                      <ArrowRight className="h-3.5 w-3.5 text-muted-foreground flex-shrink-0" />
                    )}
                  </span>
                );
              })}
            </div>

            {/* Summary */}
            <div className="mt-4 pt-4 border-t border-border/40 grid grid-cols-2 gap-x-8 gap-y-1.5 text-xs">
              {result.current_version && (
                <>
                  <span className="text-muted-foreground">Current version</span>
                  <span className="font-mono text-amber-400">{result.current_version}</span>
                </>
              )}
              {result.safe_version && (
                <>
                  <span className="text-muted-foreground">Safe version</span>
                  <span className="font-mono text-green-400">{result.safe_version}</span>
                </>
              )}
              <span className="text-muted-foreground">Hops required</span>
              <span>{hops.length > 1 ? hops.length - 1 : 0}</span>
            </div>
          </CardContent>
        </Card>
      )}

      {result && hops.length === 0 && (
        <div className="rounded-lg border border-amber-800 bg-amber-950/30 p-4 text-sm text-amber-400 flex items-center gap-2">
          <AlertCircle className="h-4 w-4 flex-shrink-0" />
          No upgrade path returned — package may already be at a safe version or no fix is available.
        </div>
      )}

      {!result && !error && !resolving && (
        <EmptyState
          icon={Search}
          title="No chain explored yet"
          description="Enter a purl above to visualize the step-by-step upgrade path to a safe version."
        />
      )}
    </div>
  );
}
