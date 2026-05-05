/**
 * VersionGraphPanel — tab "version-graph" in UpgradePathsHub
 *
 * Tabular safe-upgrade view for multiple packages.
 * Calls POST /api/v1/upgrade-path/bulk-resolve (upgradePathApi.bulkResolve).
 *
 * UX differentiator vs explorer: multi-package batch input, results as a
 * sortable table showing current→safe version delta + CVE count per row.
 */

import { useState } from "react";
import { TrendingUp, RefreshCw, Send, Plus, Trash2, AlertCircle } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { EmptyState } from "@/components/shared/EmptyState";
import { upgradePathApi, getStoredOrgId } from "@/lib/api";

interface Finding {
  purl: string;
  cve_ids: string[];
}

interface BulkResult {
  purl?: string;
  safe_version?: string;
  current_version?: string;
  upgrade_path?: string[];
  status?: string;
  cve_ids?: string[];
  [key: string]: unknown;
}

interface BulkResponse {
  results?: BulkResult[];
  resolved?: number;
  unresolved?: number;
  [key: string]: unknown;
}

const BLANK_FINDING: Finding = { purl: "", cve_ids: [] };

export function VersionGraphPanel() {
  const orgId = getStoredOrgId();

  const [rows, setRows] = useState<Finding[]>([{ ...BLANK_FINDING }]);
  const [cveInputs, setCveInputs] = useState<string[]>([""]);
  const [resolving, setResolving] = useState(false);
  const [response, setResponse] = useState<BulkResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  function addRow() {
    setRows((r) => [...r, { ...BLANK_FINDING }]);
    setCveInputs((c) => [...c, ""]);
  }

  function removeRow(i: number) {
    setRows((r) => r.filter((_, idx) => idx !== i));
    setCveInputs((c) => c.filter((_, idx) => idx !== i));
  }

  function updatePurl(i: number, val: string) {
    setRows((r) => r.map((row, idx) => (idx === i ? { ...row, purl: val } : row)));
  }

  function updateCves(i: number, val: string) {
    setCveInputs((c) => c.map((cv, idx) => (idx === i ? val : cv)));
    const ids = val
      .split(/[\s,]+/)
      .map((s) => s.trim())
      .filter(Boolean);
    setRows((r) => r.map((row, idx) => (idx === i ? { ...row, cve_ids: ids } : row)));
  }

  function handleResolve(e: React.FormEvent) {
    e.preventDefault();
    const findings = rows.filter((r) => r.purl.trim());
    if (findings.length === 0) return;
    setResolving(true);
    setError(null);
    setResponse(null);
    upgradePathApi
      .bulkResolve(orgId, findings)
      .then((r) => setResponse(r.data as BulkResponse))
      .catch((e: unknown) => {
        const msg =
          (e as { response?: { data?: { detail?: string } } })?.response?.data?.detail ??
          (e instanceof Error ? e.message : "Bulk resolve failed");
        setError(msg);
      })
      .finally(() => setResolving(false));
  }

  const results: BulkResult[] = Array.isArray(response?.results) ? response.results : [];

  return (
    <div className="space-y-6">
      {/* Batch input */}
      <Card className="bg-card/60 border-border/50">
        <CardHeader className="pb-2">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm flex items-center gap-2">
              <TrendingUp className="h-4 w-4" />
              Batch Version Graph
            </CardTitle>
            <button
              type="button"
              onClick={addRow}
              className="inline-flex items-center gap-1 rounded-md border border-border px-2 py-1 text-xs text-muted-foreground hover:bg-muted/40 transition-colors"
            >
              <Plus className="h-3.5 w-3.5" />
              Add package
            </button>
          </div>
        </CardHeader>
        <CardContent>
          <form onSubmit={handleResolve} className="space-y-3">
            <div className="space-y-2">
              {rows.map((row, i) => (
                <div key={i} className="flex items-center gap-2">
                  <input
                    type="text"
                    required={i === 0}
                    value={row.purl}
                    onChange={(e) => updatePurl(i, e.target.value)}
                    placeholder="pkg:npm/lodash@4.17.20"
                    className="flex-1 rounded-md border border-border bg-background px-3 py-2 text-xs font-mono outline-none focus:ring-2 focus:ring-ring"
                  />
                  <input
                    type="text"
                    value={cveInputs[i]}
                    onChange={(e) => updateCves(i, e.target.value)}
                    placeholder="CVE-…"
                    className="w-44 rounded-md border border-border bg-background px-3 py-2 text-xs outline-none focus:ring-2 focus:ring-ring"
                  />
                  {rows.length > 1 && (
                    <button
                      type="button"
                      onClick={() => removeRow(i)}
                      className="text-muted-foreground hover:text-red-400 transition-colors p-1"
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  )}
                </div>
              ))}
            </div>

            {error && (
              <div className="rounded-lg border border-red-800 bg-red-950/30 p-3 text-sm text-red-400">
                {error}
              </div>
            )}

            <button
              type="submit"
              disabled={resolving || rows.every((r) => !r.purl.trim())}
              className="inline-flex items-center gap-2 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
            >
              {resolving ? (
                <RefreshCw className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Send className="h-3.5 w-3.5" />
              )}
              {resolving ? "Resolving…" : "Resolve All"}
            </button>
          </form>
        </CardContent>
      </Card>

      {/* Results table */}
      {response && results.length > 0 && (
        <Card className="bg-card/60 border-border/50">
          <CardHeader className="pb-2">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm">Results</CardTitle>
              <div className="flex gap-3 text-xs text-muted-foreground">
                {response.resolved != null && (
                  <span className="text-green-400">
                    {response.resolved} resolved
                  </span>
                )}
                {response.unresolved != null && (
                  <span className="text-amber-400">
                    {response.unresolved} unresolved
                  </span>
                )}
              </div>
            </div>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-border/50 text-muted-foreground">
                    <th className="text-left px-4 py-2 font-medium">Package</th>
                    <th className="text-left px-4 py-2 font-medium">Current</th>
                    <th className="text-left px-4 py-2 font-medium">Safe version</th>
                    <th className="text-center px-4 py-2 font-medium">Hops</th>
                    <th className="text-left px-4 py-2 font-medium">Status</th>
                    <th className="text-left px-4 py-2 font-medium">CVEs</th>
                  </tr>
                </thead>
                <tbody>
                  {results.map((r, i) => {
                    const hops = Array.isArray(r.upgrade_path)
                      ? Math.max(0, r.upgrade_path.length - 1)
                      : "—";
                    return (
                      <tr
                        key={i}
                        className="border-b border-border/30 hover:bg-muted/20 transition-colors"
                      >
                        <td className="px-4 py-2 font-mono truncate max-w-[200px]">
                          {r.purl ?? "—"}
                        </td>
                        <td className="px-4 py-2 font-mono text-amber-400">
                          {r.current_version ?? "—"}
                        </td>
                        <td className="px-4 py-2 font-mono text-green-400">
                          {r.safe_version ?? "—"}
                        </td>
                        <td className="px-4 py-2 text-center">{String(hops)}</td>
                        <td className="px-4 py-2">
                          {r.status ? (
                            <Badge
                              variant="outline"
                              className={
                                r.status === "resolved"
                                  ? "border-green-700 text-green-400 text-xs"
                                  : "border-amber-700 text-amber-400 text-xs"
                              }
                            >
                              {r.status}
                            </Badge>
                          ) : "—"}
                        </td>
                        <td className="px-4 py-2">
                          {Array.isArray(r.cve_ids) && r.cve_ids.length > 0 ? (
                            <div className="flex flex-wrap gap-1">
                              {r.cve_ids.slice(0, 3).map((c) => (
                                <Badge
                                  key={c}
                                  variant="outline"
                                  className="text-xs border-red-800 text-red-400 py-0"
                                >
                                  {c}
                                </Badge>
                              ))}
                              {r.cve_ids.length > 3 && (
                                <span className="text-muted-foreground">+{r.cve_ids.length - 3}</span>
                              )}
                            </div>
                          ) : (
                            "—"
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}

      {response && results.length === 0 && (
        <div className="rounded-lg border border-amber-800 bg-amber-950/30 p-4 text-sm text-amber-400 flex items-center gap-2">
          <AlertCircle className="h-4 w-4 flex-shrink-0" />
          No results returned — check the purl format or try different CVE IDs.
        </div>
      )}

      {!response && !error && !resolving && (
        <EmptyState
          icon={TrendingUp}
          title="No packages queued"
          description="Add one or more package URLs above and click Resolve All to see the version graph."
        />
      )}
    </div>
  );
}
