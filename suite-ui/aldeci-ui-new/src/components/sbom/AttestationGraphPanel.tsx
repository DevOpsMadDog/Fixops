/**
 * AttestationGraphPanel — tab "attestation" in SBOMProvenanceHub
 *
 * Detail-drilldown view of the attestation registry.
 * Lists all attestations from GET /api/v1/slsa/attestations with subject/builder
 * filters, then shows full attestation JSON on row click.
 *
 * Distinct from SLSAProvenancePanel (which shows aggregate stats + summary rows).
 */

import { useEffect, useState } from "react";
import { Network, RefreshCw, Search, ChevronDown, ChevronUp, CheckCircle, Clock } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { EmptyState } from "@/components/shared/EmptyState";
import { slsaApi } from "@/lib/api";

interface Attestation {
  id: string;
  subject_name?: string;
  subject_digest?: string;
  builder_id?: string;
  build_type?: string;
  slsa_level?: number;
  verified?: boolean;
  created_at?: string;
  status?: string;
  envelope?: unknown;
  predicate?: unknown;
  [key: string]: unknown;
}

function levelBadge(level: number | undefined) {
  if (level == null) return null;
  const cls =
    level >= 3
      ? "bg-green-600/20 text-green-400 border-green-700"
      : level === 2
      ? "bg-amber-600/20 text-amber-400 border-amber-700"
      : "bg-slate-600/20 text-slate-400 border-slate-600";
  return (
    <Badge variant="outline" className={cls}>
      L{level}
    </Badge>
  );
}

export function AttestationGraphPanel() {
  const [attestations, setAttestations] = useState<Attestation[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [subjectFilter, setSubjectFilter] = useState("");
  const [builderFilter, setBuilderFilter] = useState("");
  const [expanded, setExpanded] = useState<string | null>(null);
  const [detail, setDetail] = useState<Attestation | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  function load() {
    setLoading(true);
    setError(null);
    slsaApi
      .attestations("default", {
        subject_name: subjectFilter || undefined,
        builder_id: builderFilter || undefined,
      })
      .then((r) => {
        const raw = r.data;
        setAttestations(
          Array.isArray(raw) ? raw : Array.isArray(raw?.items) ? raw.items : []
        );
      })
      .catch((e: unknown) =>
        setError(e instanceof Error ? e.message : "Failed to load attestations")
      )
      .finally(() => setLoading(false));
  }

  useEffect(() => {
    load();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  function toggleRow(id: string) {
    if (expanded === id) {
      setExpanded(null);
      setDetail(null);
      return;
    }
    setExpanded(id);
    setDetail(null);
    setDetailLoading(true);
    slsaApi
      .getAttestation(id)
      .then((r) => setDetail(r.data as Attestation))
      .catch(() => setDetail(null))
      .finally(() => setDetailLoading(false));
  }

  return (
    <div className="mt-4 space-y-4">
      {/* Filter bar */}
      <div className="flex flex-wrap gap-2 items-end">
        <div className="flex flex-col gap-1">
          <label className="text-xs text-muted-foreground">Subject name</label>
          <div className="relative">
            <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
            <input
              type="text"
              value={subjectFilter}
              onChange={(e) => setSubjectFilter(e.target.value)}
              placeholder="my-app"
              className="pl-7 rounded-md border border-border bg-background px-3 py-1.5 text-sm w-48 outline-none focus:ring-2 focus:ring-ring"
            />
          </div>
        </div>
        <div className="flex flex-col gap-1">
          <label className="text-xs text-muted-foreground">Builder ID</label>
          <input
            type="text"
            value={builderFilter}
            onChange={(e) => setBuilderFilter(e.target.value)}
            placeholder="github-actions"
            className="rounded-md border border-border bg-background px-3 py-1.5 text-sm w-48 outline-none focus:ring-2 focus:ring-ring"
          />
        </div>
        <button
          onClick={load}
          disabled={loading}
          className="inline-flex items-center gap-1.5 rounded-md bg-primary px-3 py-1.5 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
          {loading ? "Loading…" : "Search"}
        </button>
      </div>

      {error && (
        <div className="rounded-lg border border-red-800 bg-red-950/30 p-4 text-sm text-red-400">
          {error}
        </div>
      )}

      {!loading && !error && attestations.length === 0 && (
        <EmptyState
          icon={Network}
          title="No attestations found"
          description="Generate attestations via POST /api/v1/slsa/attest — they will appear here with full chain detail."
        />
      )}

      {attestations.length > 0 && (
        <Card className="bg-card/60 border-border/50">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">
              Attestation Registry ({attestations.length})
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-border/50 text-muted-foreground">
                    <th className="text-left px-4 py-2 font-medium w-8" />
                    <th className="text-left px-4 py-2 font-medium">Subject</th>
                    <th className="text-left px-4 py-2 font-medium">Builder</th>
                    <th className="text-left px-4 py-2 font-medium">Build Type</th>
                    <th className="text-center px-4 py-2 font-medium">Level</th>
                    <th className="text-center px-4 py-2 font-medium">Verified</th>
                    <th className="text-left px-4 py-2 font-medium">Created</th>
                  </tr>
                </thead>
                <tbody>
                  {attestations.map((att) => (
                    <>
                      <tr
                        key={att.id}
                        className="border-b border-border/30 hover:bg-muted/20 transition-colors cursor-pointer"
                        onClick={() => toggleRow(att.id)}
                      >
                        <td className="px-4 py-2 text-muted-foreground">
                          {expanded === att.id ? (
                            <ChevronUp className="h-3.5 w-3.5" />
                          ) : (
                            <ChevronDown className="h-3.5 w-3.5" />
                          )}
                        </td>
                        <td className="px-4 py-2 font-mono truncate max-w-[180px]">
                          {att.subject_name ?? att.id}
                        </td>
                        <td className="px-4 py-2 text-muted-foreground truncate max-w-[140px]">
                          {att.builder_id ?? "—"}
                        </td>
                        <td className="px-4 py-2 text-muted-foreground truncate max-w-[140px]">
                          {att.build_type ?? "—"}
                        </td>
                        <td className="px-4 py-2 text-center">
                          {levelBadge(att.slsa_level)}
                        </td>
                        <td className="px-4 py-2 text-center">
                          {att.verified ? (
                            <CheckCircle className="h-3.5 w-3.5 text-green-400 mx-auto" />
                          ) : (
                            <Clock className="h-3.5 w-3.5 text-muted-foreground mx-auto" />
                          )}
                        </td>
                        <td className="px-4 py-2 text-muted-foreground">
                          {att.created_at
                            ? new Date(att.created_at).toLocaleDateString()
                            : "—"}
                        </td>
                      </tr>
                      {expanded === att.id && (
                        <tr key={`${att.id}-detail`} className="bg-muted/10">
                          <td colSpan={7} className="px-4 py-3">
                            {detailLoading ? (
                              <div className="h-6 w-32 rounded bg-muted/40 animate-pulse" />
                            ) : detail ? (
                              <div className="space-y-2">
                                {detail.subject_digest && (
                                  <p className="text-xs">
                                    <span className="text-muted-foreground">Digest: </span>
                                    <span className="font-mono">{String(detail.subject_digest)}</span>
                                  </p>
                                )}
                                <pre className="text-xs text-muted-foreground overflow-auto max-h-56 rounded bg-muted/60 p-2 leading-relaxed">
                                  {JSON.stringify(detail, null, 2)}
                                </pre>
                              </div>
                            ) : (
                              <p className="text-xs text-muted-foreground">No detail available.</p>
                            )}
                          </td>
                        </tr>
                      )}
                    </>
                  ))}
                </tbody>
              </table>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
