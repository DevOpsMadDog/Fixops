/**
 * Rule DSL Validator — Live API
 * Multica: bf5c991a-45c5-433f-8112-6b5c2fe6b969
 * API: POST /api/v1/rules/dsl/validate
 *
 * Paste DSL text, click Validate, see the parser/AST result. Submits
 * the real `dsl_text` field. NO MOCKS.
 */

import { useState } from "react";
import { CheckCircle2, AlertTriangle, Play } from "lucide-react";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";

const SAMPLE = `when:
  finding.severity == "critical"
then:
  set finding.priority = "P0"
`;

async function apiPost<T>(path: string, body: unknown): Promise<T> {
  const orgId = getStoredOrgId() || "verify-test";
  const url = buildApiUrl(path, { org_id: orgId });
  const res = await fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "X-API-Key": getStoredAuthToken(),
      "X-Org-ID": orgId,
    },
    body: JSON.stringify(body),
  });
  const json = await res.json().catch(() => ({}));
  if (!res.ok) {
    const detail = (json as { detail?: string }).detail;
    const err = new Error(`${res.status} ${detail ?? res.statusText}`);
    (err as { httpStatus?: number }).httpStatus = res.status;
    (err as { payload?: unknown }).payload = json;
    throw err;
  }
  return json as T;
}

export default function RuleDSLValidator() {
  const [text, setText] = useState(SAMPLE);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<Record<string, unknown> | null>(null);
  const [error, setError] = useState<{ msg: string; payload?: unknown } | null>(null);
  const [comingSoon, setComingSoon] = useState(false);

  const validate = async () => {
    setRunning(true);
    setResult(null);
    setError(null);
    setComingSoon(false);
    try {
      const r = await apiPost<Record<string, unknown>>("/api/v1/rules/dsl/validate", {
        dsl_text: text,
      });
      setResult(r);
    } catch (e) {
      const status = (e as { httpStatus?: number }).httpStatus;
      const payload = (e as { payload?: unknown }).payload;
      if (status === 501) {
        setComingSoon(true);
      } else {
        setError({ msg: (e as Error).message, payload });
      }
    } finally {
      setRunning(false);
    }
  };

  const ok = result && (result.valid === true || result.ok === true || result.errors === undefined);

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <CheckCircle2 className="w-6 h-6 text-indigo-400" /> DSL Validator
        </h1>
        <p className="text-gray-400 mt-1">
          Live validation — POST /api/v1/rules/dsl/validate
        </p>
      </div>

      {comingSoon ? (
        <div className="bg-amber-900/30 border border-amber-700 text-amber-100 rounded-lg p-6 max-w-2xl">
          <h2 className="font-semibold flex items-center gap-2">
            <AlertTriangle className="w-5 h-5" /> Coming soon
          </h2>
          <p className="text-sm mt-2">
            The DSL validator endpoint returned <code>501 Not Implemented</code>. The route is
            wired but the parser is still in progress. Try again after the next backend deploy.
          </p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          <div className="bg-gray-800 rounded-lg p-4 space-y-3">
            <label className="block text-xs text-gray-400 uppercase">DSL text</label>
            <textarea
              value={text}
              onChange={(e) => setText(e.target.value)}
              rows={16}
              spellCheck={false}
              className="w-full bg-gray-950 border border-gray-700 rounded px-3 py-2 text-sm font-mono leading-5"
            />
            <button
              onClick={validate}
              disabled={running || !text.trim()}
              className="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-500 disabled:bg-gray-700 rounded-lg text-sm"
            >
              <Play className={`w-4 h-4 ${running ? "animate-pulse" : ""}`} /> Validate
            </button>
          </div>

          <div className="bg-gray-800 rounded-lg p-4">
            <h2 className="text-sm font-semibold text-gray-300 uppercase mb-3">Result</h2>
            {!result && !error && (
              <p className="text-sm text-gray-500">Run validation to see output.</p>
            )}
            {error && (
              <div className="bg-red-900/30 border border-red-800 text-red-200 rounded p-3 text-sm">
                <strong>Validation failed:</strong> {error.msg}
                {error.payload != null && (
                  <pre className="mt-2 text-xs whitespace-pre-wrap break-all">
                    {JSON.stringify(error.payload, null, 2)}
                  </pre>
                )}
              </div>
            )}
            {result && (
              <div
                className={`${
                  ok
                    ? "bg-emerald-900/20 border-emerald-800 text-emerald-100"
                    : "bg-amber-900/20 border-amber-800 text-amber-100"
                } border rounded p-3`}
              >
                <strong className="text-sm">{ok ? "OK" : "Issues"}</strong>
                <pre className="mt-2 text-xs whitespace-pre-wrap break-all">
                  {JSON.stringify(result, null, 2)}
                </pre>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
