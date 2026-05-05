/**
 * AccessMatrixPanel — Roles × Resource-Types permission grid
 * API: GET /api/v1/access-matrix/  (index) + /api/v1/access-matrix/matrix
 * First UI consumer of the access-matrix backend (commit 10874d63).
 */

import { useEffect, useState } from "react";
import { RefreshCw, ShieldAlert } from "lucide-react";
import { accessMatrixApi } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";

interface IndexData {
  service: string;
  org_id: string;
  resource_types: string[];
  stats: Record<string, unknown>;
}

interface MatrixData {
  org_id: string;
  roles: string[];
  resource_types: string[];
  matrix: Record<string, Record<string, string>>;
}

const LEVEL_COLORS: Record<string, string> = {
  owner: "bg-purple-700 text-purple-100",
  admin: "bg-red-700 text-red-100",
  write: "bg-amber-700 text-amber-100",
  read: "bg-green-800 text-green-100",
  none: "bg-gray-700 text-gray-400",
};

function levelClass(level: string): string {
  return LEVEL_COLORS[level] ?? LEVEL_COLORS.none;
}

export function AccessMatrixPanel() {
  const [index, setIndex] = useState<IndexData | null>(null);
  const [matrixData, setMatrixData] = useState<MatrixData | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const [idxRes, matRes] = await Promise.allSettled([
        accessMatrixApi.index(),
        accessMatrixApi.matrix(),
      ]);
      if (idxRes.status === "fulfilled") {
        setIndex(idxRes.value.data as IndexData);
      }
      if (matRes.status === "fulfilled") {
        setMatrixData(matRes.value.data as MatrixData);
      }
      if (idxRes.status === "rejected" && matRes.status === "rejected") {
        throw new Error((idxRes.reason as Error).message);
      }
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    load();
  }, []);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-500" />
      </div>
    );
  }

  if (error) {
    return <ErrorState message={error} onRetry={load} />;
  }

  if (!index && !matrixData) {
    return (
      <EmptyState
        icon={ShieldAlert}
        title="No access matrix data"
        description="Grant access rules via /api/v1/access-matrix/rules to populate this view."
      />
    );
  }

  const stats = index?.stats ?? {};
  const statEntries = (Object.entries(stats) as [string, unknown][]).filter(
    ([, v]) => typeof v === "number"
  );

  return (
    <div className="space-y-6">
      {/* Refresh + header */}
      <div className="flex items-center justify-between">
        <p className="text-sm text-muted-foreground">
          Live data — <span className="font-mono text-xs">/api/v1/access-matrix/</span>
        </p>
        <button
          onClick={load}
          className="flex items-center gap-2 px-3 py-1.5 bg-muted hover:bg-muted/80 rounded-lg text-xs"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          Refresh
        </button>
      </div>

      {/* Stats strip */}
      {statEntries.length > 0 && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {statEntries.slice(0, 4).map(([k, v]) => (
            <div key={k} className="bg-muted/60 rounded-lg p-4">
              <p className="text-muted-foreground text-xs capitalize">
                {k.replace(/_/g, " ")}
              </p>
              <p className="text-2xl font-bold mt-1 text-indigo-400">{String(v)}</p>
            </div>
          ))}
        </div>
      )}

      {/* Resource types pill row */}
      {index?.resource_types && index.resource_types.length > 0 && (
        <div>
          <p className="text-xs text-muted-foreground mb-2 uppercase tracking-wider font-medium">
            Resource Types ({index.resource_types.length})
          </p>
          <div className="flex flex-wrap gap-2">
            {index.resource_types.map((rt) => (
              <span
                key={rt}
                className="px-2 py-0.5 bg-muted rounded text-xs font-mono text-muted-foreground border border-border"
              >
                {rt}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Roles × Resource-Types matrix grid */}
      {matrixData && matrixData.roles.length > 0 && (
        <div className="bg-muted/40 rounded-lg overflow-hidden border border-border">
          <div className="px-4 py-3 border-b border-border">
            <h3 className="text-sm font-semibold">
              Roles × Resource-Types Matrix
            </h3>
            <p className="text-xs text-muted-foreground mt-0.5">
              Effective (wildcard) permissions per role across all resource types
            </p>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border">
                  <th className="px-4 py-2 text-left text-muted-foreground font-medium sticky left-0 bg-muted/40 min-w-[120px]">
                    Role
                  </th>
                  {matrixData.resource_types.map((rt) => (
                    <th
                      key={rt}
                      className="px-3 py-2 text-center text-muted-foreground font-medium whitespace-nowrap"
                    >
                      {rt.replace(/_/g, " ")}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {matrixData.roles.map((role) => {
                  const perms = matrixData.matrix[role] ?? {};
                  return (
                    <tr key={role} className="hover:bg-muted/30 transition-colors">
                      <td className="px-4 py-2 font-medium text-foreground sticky left-0 bg-muted/40 capitalize">
                        {role.replace(/_/g, " ")}
                      </td>
                      {matrixData.resource_types.map((rt) => {
                        const level = (perms[rt] ?? "none").toLowerCase();
                        return (
                          <td key={rt} className="px-3 py-2 text-center">
                            <span
                              className={`inline-block px-2 py-0.5 rounded text-[10px] font-medium ${levelClass(level)}`}
                            >
                              {level}
                            </span>
                          </td>
                        );
                      })}
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
