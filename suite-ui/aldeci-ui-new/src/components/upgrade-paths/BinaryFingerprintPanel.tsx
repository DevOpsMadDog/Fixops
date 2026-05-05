/**
 * BinaryFingerprintPanel — binary-fp tab for UpgradePathsHub.
 * Wired to GET /api/v1/binary-fp/stats.
 */

import { useEffect, useState } from "react";
import { Fingerprint, RefreshCw } from "lucide-react";

import { binaryFpApi, getStoredOrgId } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { PageSkeleton } from "@/components/shared/PageSkeleton";

interface FpStats {
  total_fingerprints?: number;
  registered_artifacts?: number;
  known_bad?: number;
  queries_total?: number;
  matches_found?: number;
  [key: string]: unknown;
}

export function BinaryFingerprintPanel() {
  const orgId = getStoredOrgId();

  const [stats, setStats] = useState<FpStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  function load() {
    setLoading(true);
    setError(null);
    binaryFpApi
      .stats(orgId)
      .then((r) => setStats(r.data as FpStats))
      .catch((e) =>
        setError(e?.response?.data?.detail ?? e?.message ?? "Failed to load fingerprint stats")
      )
      .finally(() => setLoading(false));
  }

  useEffect(() => {
    load();
  }, [orgId]);

  if (loading) return <PageSkeleton />;

  if (error) {
    return (
      <div className="rounded-lg border border-destructive/40 bg-destructive/10 px-4 py-3 text-sm text-destructive">
        {error}
      </div>
    );
  }

  const hasStats = stats && Object.keys(stats).length > 0;

  if (!hasStats) {
    return (
      <EmptyState
        icon={Fingerprint}
        title="No fingerprint data"
        description="Register artifacts via POST /api/v1/binary-fp/register to begin tracking."
      />
    );
  }

  const displayKeys: Array<{ key: keyof FpStats; label: string }> = [
    { key: "total_fingerprints", label: "Total Fingerprints" },
    { key: "registered_artifacts", label: "Registered Artifacts" },
    { key: "known_bad", label: "Known-Bad Matches" },
    { key: "queries_total", label: "Total Queries" },
    { key: "matches_found", label: "Matches Found" },
  ];

  const knownKeys = new Set(displayKeys.map((d) => d.key as string));
  const extraKeys = Object.keys(stats).filter((k) => !knownKeys.has(k));

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold flex items-center gap-2">
          <Fingerprint className="h-4 w-4 text-muted-foreground" />
          Binary Fingerprint Registry
        </h3>
        <button
          onClick={load}
          className="inline-flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground"
        >
          <RefreshCw className="h-3 w-3" />
          Refresh
        </button>
      </div>

      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3">
        {displayKeys.map(({ key, label }) =>
          stats[key] != null ? (
            <div key={key} className="rounded-xl border border-border bg-card px-5 py-4 space-y-1">
              <p className="text-xs text-muted-foreground">{label}</p>
              <p className="text-2xl font-semibold">{String(stats[key])}</p>
            </div>
          ) : null
        )}
      </div>

      {extraKeys.length > 0 && (
        <div className="rounded-xl border border-border bg-card p-4 space-y-2">
          <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">
            Additional Metrics
          </p>
          <dl className="grid grid-cols-2 gap-x-6 gap-y-2 text-sm">
            {extraKeys.map((k) => (
              <div key={k} className="contents">
                <dt className="text-muted-foreground">{k.replace(/_/g, " ")}</dt>
                <dd className="font-mono">{String(stats[k])}</dd>
              </div>
            ))}
          </dl>
        </div>
      )}

      <div className="rounded-xl border border-border bg-card p-5 space-y-3">
        <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">
          How it works
        </p>
        <ul className="space-y-1.5 text-sm text-muted-foreground list-disc list-inside">
          <li>
            Upload a binary via <code className="font-mono text-xs bg-muted px-1 rounded">POST /api/v1/binary-fp/fingerprint</code> to compute its hash
          </li>
          <li>
            Register it with <code className="font-mono text-xs bg-muted px-1 rounded">POST /api/v1/binary-fp/register</code> to track in the org registry
          </li>
          <li>
            Use <code className="font-mono text-xs bg-muted px-1 rounded">POST /api/v1/binary-fp/check-bad</code> to test against known-malicious artifacts
          </li>
        </ul>
      </div>
    </div>
  );
}
