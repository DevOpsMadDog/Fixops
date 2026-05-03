/**
 * FIPS Mode Status — Live API
 * Multica: ce176fac-fbb9-414b-8834-8d8646235b08
 * API: GET /api/v1/system/fips-mode + POST /api/v1/system/fips-self-test
 *
 * Shows whether FIPS-140 mode is enforced, the OpenSSL/crypto provider,
 * the most recent self-test result, and a button to re-run it. NO MOCKS.
 */

import { useEffect, useState } from "react";
import { ShieldCheck, RefreshCw, PlayCircle, AlertTriangle } from "lucide-react";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { ErrorState } from "@/components/shared/ErrorState";

type FipsStatus = {
  enabled?: boolean;
  mode?: string;
  provider?: string;
  module_version?: string;
  last_self_test?: { status?: string; ran_at?: string; details?: unknown };
  notes?: string;
} & Record<string, unknown>;

async function apiCall<T>(path: string, init?: RequestInit): Promise<T> {
  const orgId = getStoredOrgId() || "verify-test";
  const url = buildApiUrl(path, { org_id: orgId });
  const res = await fetch(url, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      "X-API-Key": getStoredAuthToken(),
      "X-Org-ID": orgId,
      ...(init?.headers ?? {}),
    },
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(`${res.status} ${(json as { detail?: string }).detail ?? res.statusText}`);
    (err as { httpStatus?: number }).httpStatus = res.status;
    throw err;
  }
  return json as T;
}

export default function FIPSModeStatus() {
  const [status, setStatus] = useState<FipsStatus | null>(null);
  const [loading, setLoading] = useState(true);
  const [running, setRunning] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [comingSoon, setComingSoon] = useState(false);
  const [testResult, setTestResult] = useState<unknown>(null);

  const load = async () => {
    setLoading(true);
    setError(null);
    setComingSoon(false);
    try {
      const v = await apiCall<FipsStatus>("/api/v1/system/fips-mode");
      setStatus(v);
    } catch (e) {
      const httpStatus = (e as { httpStatus?: number }).httpStatus;
      if (httpStatus === 501) setComingSoon(true);
      else setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => {
    load();
  }, []);

  const runSelfTest = async () => {
    setRunning(true);
    setTestResult(null);
    try {
      const r = await apiCall<unknown>("/api/v1/system/fips-self-test", { method: "POST" });
      setTestResult(r);
      await load();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setRunning(false);
    }
  };

  const enabled = Boolean(status?.enabled);

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <ShieldCheck className="w-6 h-6 text-indigo-400" /> FIPS Mode Status
          </h1>
          <p className="text-gray-400 mt-1">Live data — /api/v1/system/fips-mode</p>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={runSelfTest}
            disabled={running || comingSoon}
            className="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-500 disabled:bg-gray-700 rounded-lg text-sm"
          >
            <PlayCircle className={`w-4 h-4 ${running ? "animate-pulse" : ""}`} /> Run self-test
          </button>
          <button
            onClick={load}
            className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} /> Refresh
          </button>
        </div>
      </div>

      {comingSoon ? (
        <div className="bg-amber-900/30 border border-amber-700 text-amber-100 rounded-lg p-6 max-w-2xl">
          <h2 className="font-semibold flex items-center gap-2">
            <AlertTriangle className="w-5 h-5" /> Coming soon
          </h2>
          <p className="text-sm mt-2">
            <code>/api/v1/system/fips-mode</code> returned <code>501 Not Implemented</code>. The
            Wave-C system router is mounted but the FIPS provider integration ships next.
          </p>
        </div>
      ) : loading ? (
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-500" />
        </div>
      ) : error ? (
        <ErrorState message={error} onRetry={load} />
      ) : (
        <>
          <div className="grid md:grid-cols-2 lg:grid-cols-4 gap-4">
            <div
              className={`rounded-lg p-5 ${
                enabled
                  ? "bg-emerald-900/20 border border-emerald-800"
                  : "bg-amber-900/20 border border-amber-800"
              }`}
            >
              <p className="text-gray-400 text-sm">FIPS-140 mode</p>
              <p
                className={`text-3xl font-bold mt-1 ${
                  enabled ? "text-emerald-300" : "text-amber-300"
                }`}
              >
                {enabled ? "enforced" : "off"}
              </p>
            </div>
            <div className="bg-gray-800 rounded-lg p-5">
              <p className="text-gray-400 text-sm">Mode</p>
              <p className="text-2xl font-semibold mt-1 text-gray-200">
                {status?.mode ?? "—"}
              </p>
            </div>
            <div className="bg-gray-800 rounded-lg p-5">
              <p className="text-gray-400 text-sm">Provider</p>
              <p className="text-base font-mono mt-1 text-gray-200 break-all">
                {status?.provider ?? "—"}
              </p>
            </div>
            <div className="bg-gray-800 rounded-lg p-5">
              <p className="text-gray-400 text-sm">Module version</p>
              <p className="text-base font-mono mt-1 text-gray-200 break-all">
                {status?.module_version ?? "—"}
              </p>
            </div>
          </div>

          <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold mb-2">Last self-test</h2>
            {status?.last_self_test ? (
              <div className="text-sm">
                <div>
                  <span className="text-gray-400">Status: </span>
                  <span
                    className={`font-semibold ${
                      status.last_self_test.status === "passed"
                        ? "text-emerald-300"
                        : "text-red-300"
                    }`}
                  >
                    {status.last_self_test.status ?? "—"}
                  </span>
                </div>
                <div className="text-gray-400 text-xs">
                  Ran at {status.last_self_test.ran_at ?? "—"}
                </div>
                {status.last_self_test.details != null && (
                  <pre className="mt-2 text-xs bg-gray-950 p-2 rounded max-h-40 overflow-auto">
                    {JSON.stringify(status.last_self_test.details, null, 2)}
                  </pre>
                )}
              </div>
            ) : (
              <p className="text-sm text-gray-500">No self-test recorded.</p>
            )}
          </div>

          {testResult != null && (
            <div className="bg-gray-800 rounded-lg p-6">
              <h2 className="text-lg font-semibold mb-2">Self-test invocation</h2>
              <pre className="text-xs bg-gray-950 p-2 rounded max-h-60 overflow-auto">
                {JSON.stringify(testResult, null, 2)}
              </pre>
            </div>
          )}

          {status?.notes && (
            <div className="bg-gray-800 rounded-lg p-4 text-xs text-gray-400">
              {status.notes}
            </div>
          )}
        </>
      )}
    </div>
  );
}
