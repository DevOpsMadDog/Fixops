/**
 * AirGapUpdateStatusPanel — Applied offline update package history
 * API: GET /api/v1/airgap/updates/history  (airgap_router.py list_applied_updates)
 */

import { useEffect, useState } from "react";
import { RefreshCw, Download, CheckCircle, FileArchive } from "lucide-react";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";

interface UpdatePackage {
  package_id?: string;
  package_type?: string;
  version?: string;
  applied_at?: string;
  file_count?: number;
  size_bytes?: number;
  checksum_sha256?: string;
}

const TYPE_LABEL: Record<string, string> = {
  vuln_db: "Vuln DB",
  signatures: "Signatures",
  compliance_rules: "Compliance",
  llm_model: "LLM Model",
  full_system: "Full System",
};

function fmtDate(s?: string) {
  if (!s) return "—";
  try { return new Date(s).toLocaleString(); } catch { return s; }
}

function fmtBytes(n?: number) {
  if (!n) return "—";
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

export function AirGapUpdateStatusPanel() {
  const [packages, setPackages] = useState<UpdatePackage[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const { default: axios } = await import("axios");
      const token = window.localStorage.getItem("aldeci.authToken") || "";
      const headers = token ? { "X-API-Key": token } : {};
      const res = await axios.get("/api/v1/airgap/updates/history", { headers });
      const d = res.data;
      setPackages(Array.isArray(d?.packages) ? d.packages : []);
    } catch (e: unknown) {
      setError(e instanceof Error ? e.message : "Failed to load update history");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => { load(); }, []);

  if (loading) {
    return (
      <div className="space-y-3 p-4">
        {[1, 2, 3].map(i => (
          <div key={i} className="h-16 rounded-lg bg-muted/40 animate-pulse" />
        ))}
      </div>
    );
  }
  if (error) return <ErrorState message={error} onRetry={load} />;

  return (
    <div className="space-y-4 p-1">
      <div className="flex items-center justify-between">
        <h3 className="text-sm font-semibold text-foreground">Applied Updates</h3>
        <button onClick={load} className="p-1.5 rounded hover:bg-muted/50 text-muted-foreground">
          <RefreshCw className="h-3.5 w-3.5" />
        </button>
      </div>

      {/* Summary stat */}
      <div className="rounded-lg border border-border bg-card p-3 flex items-center gap-3">
        <Download className="h-5 w-5 text-blue-400 shrink-0" />
        <div>
          <div className="text-lg font-bold text-foreground">{packages.length}</div>
          <div className="text-xs text-muted-foreground">packages applied</div>
        </div>
      </div>

      {packages.length === 0 ? (
        <EmptyState
          title="No updates applied"
          description="No offline update packages have been applied to this instance yet. Use POST /api/v1/airgap/updates/apply with a signed .zip package."
        />
      ) : (
        <div className="space-y-2">
          {packages.map((pkg, idx) => (
            <div
              key={pkg.package_id ?? idx}
              className="rounded-lg border border-border bg-card p-3 flex items-start gap-3"
            >
              <FileArchive className="h-4 w-4 text-muted-foreground shrink-0 mt-0.5" />
              <div className="flex-1 min-w-0 space-y-0.5">
                <div className="flex items-center gap-2">
                  <span className="text-xs font-medium text-foreground">
                    {TYPE_LABEL[pkg.package_type ?? ""] ?? pkg.package_type ?? "Unknown"}
                  </span>
                  <span className="text-xs text-muted-foreground">v{pkg.version ?? "—"}</span>
                  <CheckCircle className="h-3.5 w-3.5 text-green-400 ml-auto shrink-0" />
                </div>
                <div className="text-xs text-muted-foreground">
                  {fmtDate(pkg.applied_at)} · {pkg.file_count ?? 0} files · {fmtBytes(pkg.size_bytes)}
                </div>
                {pkg.checksum_sha256 && (
                  <div className="text-xs font-mono text-muted-foreground/60 truncate">
                    sha256: {pkg.checksum_sha256}
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
