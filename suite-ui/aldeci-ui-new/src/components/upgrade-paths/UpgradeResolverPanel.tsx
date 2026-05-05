/**
 * UpgradeResolverPanel — resolver tab for UpgradePathsHub.
 * Shows live stats from /api/v1/upgrade-path/stats and a single-package resolver form.
 */

import { useEffect, useState } from "react";
import { GitBranch, RefreshCw, Send } from "lucide-react";

import { upgradePathApi, getStoredOrgId } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { PageSkeleton } from "@/components/shared/PageSkeleton";

interface UpgradeStats {
  total_queries?: number;
  resolved?: number;
  unresolved?: number;
  resolution_rate?: number;
  [key: string]: unknown;
}

interface ResolveResult {
  purl?: string;
  safe_version?: string;
  current_version?: string;
  upgrade_path?: string[];
  cve_ids?: string[];
  status?: string;
  [key: string]: unknown;
}

export function UpgradeResolverPanel() {
  const orgId = getStoredOrgId();

  const [stats, setStats] = useState<UpgradeStats | null>(null);
  const [statsLoading, setStatsLoading] = useState(true);
  const [statsError, setStatsError] = useState<string | null>(null);

  const [purl, setPurl] = useState("");
  const [cveInput, setCveInput] = useState("");
  const [resolving, setResolving] = useState(false);
  const [result, setResult] = useState<ResolveResult | null>(null);
  const [resolveError, setResolveError] = useState<string | null>(null);

  function loadStats() {
    setStatsLoading(true);
    setStatsError(null);
    upgradePathApi
      .stats(orgId)
      .then((r) => setStats(r.data as UpgradeStats))
      .catch((e) => setStatsError(e?.response?.data?.detail ?? e?.message ?? "Failed to load stats"))
      .finally(() => setStatsLoading(false));
  }

  useEffect(() => {
    loadStats();
  }, [orgId]);

  function handleResolve(e: React.FormEvent) {
    e.preventDefault();
    if (!purl.trim()) return;
    const cveIds = cveInput
      .split(/[\s,]+/)
      .map((s) => s.trim())
      .filter(Boolean);
    setResolving(true);
    setResolveError(null);
    setResult(null);
    upgradePathApi
      .resolve(orgId, purl.trim(), cveIds)
      .then((r) => {
        setResult(r.data as ResolveResult);
        loadStats();
      })
      .catch((e) =>
        setResolveError(e?.response?.data?.detail ?? e?.message ?? "Resolve failed")
      )
      .finally(() => setResolving(false));
  }

  return (
    <div className="space-y-6">
      {/* Stats row */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        {statsLoading ? (
          <div className="col-span-4">
            <PageSkeleton />
          </div>
        ) : statsError ? (
          <div className="col-span-4 rounded-lg border border-destructive/40 bg-destructive/10 px-4 py-3 text-sm text-destructive">
            {statsError}
          </div>
        ) : (
          <>
            {[
              { label: "Total Queries", value: stats?.total_queries ?? 0 },
              { label: "Resolved", value: stats?.resolved ?? 0 },
              { label: "Unresolved", value: stats?.unresolved ?? 0 },
              {
                label: "Resolution Rate",
                value:
                  stats?.resolution_rate != null
                    ? `${(Number(stats.resolution_rate) * 100).toFixed(1)}%`
                    : "—",
              },
            ].map(({ label, value }) => (
              <div
                key={label}
                className="rounded-xl border border-border bg-card px-5 py-4 space-y-1"
              >
                <p className="text-xs text-muted-foreground">{label}</p>
                <p className="text-2xl font-semibold">{String(value)}</p>
              </div>
            ))}
          </>
        )}
      </div>

      {/* Resolve form */}
      <div className="rounded-xl border border-border bg-card p-5 space-y-4">
        <div className="flex items-center gap-2">
          <GitBranch className="h-4 w-4 text-muted-foreground" />
          <h3 className="text-sm font-semibold">Resolve Upgrade Path</h3>
        </div>
        <form onSubmit={handleResolve} className="space-y-3">
          <div className="space-y-1">
            <label className="text-xs text-muted-foreground" htmlFor="purl-input">
              Package URL (purl)
            </label>
            <input
              id="purl-input"
              type="text"
              value={purl}
              onChange={(e) => setPurl(e.target.value)}
              placeholder="pkg:pypi/django@3.2.0"
              className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-ring"
            />
          </div>
          <div className="space-y-1">
            <label className="text-xs text-muted-foreground" htmlFor="cve-input">
              CVE IDs (comma or space separated — leave blank to resolve all)
            </label>
            <input
              id="cve-input"
              type="text"
              value={cveInput}
              onChange={(e) => setCveInput(e.target.value)}
              placeholder="CVE-2023-12345, CVE-2023-67890"
              className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm outline-none focus:ring-2 focus:ring-ring"
            />
          </div>
          <button
            type="submit"
            disabled={resolving || !purl.trim()}
            className="inline-flex items-center gap-2 rounded-md bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
          >
            {resolving ? (
              <RefreshCw className="h-3.5 w-3.5 animate-spin" />
            ) : (
              <Send className="h-3.5 w-3.5" />
            )}
            {resolving ? "Resolving…" : "Resolve"}
          </button>
        </form>

        {resolveError && (
          <div className="rounded-lg border border-destructive/40 bg-destructive/10 px-4 py-3 text-sm text-destructive">
            {resolveError}
          </div>
        )}

        {result && (
          <div className="rounded-lg border border-border bg-muted/30 p-4 space-y-2">
            <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">
              Result
            </p>
            <div className="grid grid-cols-2 gap-x-6 gap-y-2 text-sm">
              {result.safe_version && (
                <>
                  <span className="text-muted-foreground">Safe version</span>
                  <span className="font-mono font-medium text-green-500">
                    {result.safe_version}
                  </span>
                </>
              )}
              {result.current_version && (
                <>
                  <span className="text-muted-foreground">Current version</span>
                  <span className="font-mono">{result.current_version}</span>
                </>
              )}
              {result.status && (
                <>
                  <span className="text-muted-foreground">Status</span>
                  <span>{result.status}</span>
                </>
              )}
              {Array.isArray(result.upgrade_path) && result.upgrade_path.length > 0 && (
                <>
                  <span className="text-muted-foreground">Upgrade path</span>
                  <span className="font-mono text-xs break-all">
                    {result.upgrade_path.join(" → ")}
                  </span>
                </>
              )}
            </div>
            {Object.keys(result).filter(
              (k) =>
                !["purl", "safe_version", "current_version", "status", "upgrade_path", "cve_ids"].includes(k)
            ).length > 0 && (
              <pre className="mt-2 text-xs text-muted-foreground overflow-auto max-h-40 rounded bg-muted/60 p-2">
                {JSON.stringify(result, null, 2)}
              </pre>
            )}
          </div>
        )}

        {!result && !resolveError && !resolving && (
          <EmptyState
            icon={GitBranch}
            title="No result yet"
            description="Enter a purl above and click Resolve to compute the safe upgrade path."
          />
        )}
      </div>
    </div>
  );
}
