/**
 * SLSAProvenancePanel — tab "slsa" in SBOMProvenanceHub
 * Calls GET /api/v1/slsa/stats?org_id=default
 *   and GET /api/v1/slsa/attestations?org_id=default
 */
import { useEffect, useState } from "react";
import { ShieldCheck, CheckCircle, XCircle, Clock } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { EmptyState } from "@/components/shared/EmptyState";
import { slsaApi } from "@/lib/api";

interface SLSAStats {
  total_attestations?: number;
  by_level?: Record<string, number>;
  verification_pass?: number;
  verification_fail?: number;
  pass_rate?: number;
}

interface Attestation {
  id: string;
  subject_name?: string;
  builder_id?: string;
  slsa_level?: number;
  verified?: boolean;
  created_at?: string;
  status?: string;
}

function levelColor(level: number) {
  if (level >= 3) return "bg-green-600/20 text-green-400 border-green-700";
  if (level === 2) return "bg-amber-600/20 text-amber-400 border-amber-700";
  return "bg-slate-600/20 text-slate-400 border-slate-600";
}

export function SLSAProvenancePanel() {
  const [stats, setStats] = useState<SLSAStats | null>(null);
  const [attestations, setAttestations] = useState<Attestation[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setLoading(true);
    Promise.all([slsaApi.stats(), slsaApi.attestations()])
      .then(([statsRes, attRes]) => {
        setStats(statsRes.data ?? {});
        const raw = attRes.data;
        setAttestations(Array.isArray(raw) ? raw : Array.isArray(raw?.items) ? raw.items : []);
      })
      .catch((e: unknown) => setError(e instanceof Error ? e.message : "Failed to load"))
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="space-y-4 mt-4">
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="h-20 rounded-lg bg-muted/40 animate-pulse" />
          ))}
        </div>
        <div className="h-48 rounded-lg bg-muted/40 animate-pulse" />
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

  if (!stats?.total_attestations && attestations.length === 0) {
    return (
      <EmptyState
        icon={ShieldCheck}
        title="No SLSA attestations yet"
        description="Generate your first attestation via POST /api/v1/slsa/attest to start tracking build provenance."
      />
    );
  }

  const passRate = stats?.pass_rate != null
    ? `${Math.round(stats.pass_rate * 100)}%`
    : stats?.verification_pass != null && (stats.verification_pass + (stats.verification_fail ?? 0)) > 0
    ? `${Math.round((stats.verification_pass / (stats.verification_pass + (stats.verification_fail ?? 0))) * 100)}%`
    : "—";

  return (
    <div className="mt-4 space-y-4">
      {/* Stat cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <Card className="bg-card/60 border-border/50">
          <CardContent className="pt-4 pb-3">
            <p className="text-xs text-muted-foreground">Total Attestations</p>
            <p className="text-2xl font-semibold tabular-nums">{stats?.total_attestations ?? attestations.length}</p>
          </CardContent>
        </Card>
        <Card className="bg-card/60 border-border/50">
          <CardContent className="pt-4 pb-3">
            <p className="text-xs text-muted-foreground flex items-center gap-1">
              <CheckCircle className="h-3.5 w-3.5 text-green-400" /> Verified
            </p>
            <p className="text-2xl font-semibold tabular-nums text-green-400">{stats?.verification_pass ?? "—"}</p>
          </CardContent>
        </Card>
        <Card className="bg-card/60 border-border/50">
          <CardContent className="pt-4 pb-3">
            <p className="text-xs text-muted-foreground flex items-center gap-1">
              <XCircle className="h-3.5 w-3.5 text-red-400" /> Failed
            </p>
            <p className="text-2xl font-semibold tabular-nums text-red-400">{stats?.verification_fail ?? "—"}</p>
          </CardContent>
        </Card>
        <Card className="bg-card/60 border-border/50">
          <CardContent className="pt-4 pb-3">
            <p className="text-xs text-muted-foreground">Pass Rate</p>
            <p className="text-2xl font-semibold tabular-nums text-green-400">{passRate}</p>
          </CardContent>
        </Card>
      </div>

      {/* Attestations table */}
      {attestations.length > 0 && (
        <Card className="bg-card/60 border-border/50">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm">Recent Attestations</CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-border/50 text-muted-foreground">
                    <th className="text-left px-4 py-2 font-medium">Subject</th>
                    <th className="text-left px-4 py-2 font-medium">Builder</th>
                    <th className="text-center px-4 py-2 font-medium">SLSA Level</th>
                    <th className="text-center px-4 py-2 font-medium">Verified</th>
                    <th className="text-left px-4 py-2 font-medium">Created</th>
                  </tr>
                </thead>
                <tbody>
                  {attestations.slice(0, 20).map((att) => (
                    <tr key={att.id} className="border-b border-border/30 hover:bg-muted/20 transition-colors">
                      <td className="px-4 py-2 font-mono truncate max-w-[180px]">{att.subject_name ?? att.id}</td>
                      <td className="px-4 py-2 text-muted-foreground truncate max-w-[160px]">{att.builder_id ?? "—"}</td>
                      <td className="px-4 py-2 text-center">
                        {att.slsa_level != null ? (
                          <Badge variant="outline" className={levelColor(att.slsa_level)}>
                            L{att.slsa_level}
                          </Badge>
                        ) : "—"}
                      </td>
                      <td className="px-4 py-2 text-center">
                        {att.verified
                          ? <CheckCircle className="h-3.5 w-3.5 text-green-400 mx-auto" />
                          : <Clock className="h-3.5 w-3.5 text-muted-foreground mx-auto" />}
                      </td>
                      <td className="px-4 py-2 text-muted-foreground">
                        {att.created_at ? new Date(att.created_at).toLocaleDateString() : "—"}
                      </td>
                    </tr>
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
