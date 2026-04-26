/**
 * Waiver Request Modal — Live API
 * Multica: 86d29749-3947-4fe5-8b5c-7e3911c0c6bd
 * API: POST /api/v1/auto-waiver/rule (server expects rule_key + match clauses)
 *
 * Page-mode (rather than overlay-only) form for requesting a new waiver.
 * Submits a real rule. NO MOCKS.
 */

import { useState } from "react";
import { ShieldCheck, Send } from "lucide-react";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";

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
  const json = (await res.json().catch(() => ({}))) as Record<string, unknown>;
  if (!res.ok) throw new Error(`${res.status} ${(json.detail as string) ?? res.statusText}`);
  return json as T;
}

export default function WaiverRequestModal() {
  const [ruleKey, setRuleKey] = useState("");
  const [findingId, setFindingId] = useState("");
  const [reason, setReason] = useState("");
  const [expiresAt, setExpiresAt] = useState("");
  const [submitting, setSubmitting] = useState(false);
  const [result, setResult] = useState<Record<string, unknown> | null>(null);
  const [error, setError] = useState<string | null>(null);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSubmitting(true);
    setError(null);
    setResult(null);
    try {
      const body = {
        rule_key: ruleKey || `waiver-${Date.now()}`,
        match: findingId ? { finding_id: findingId } : {},
        reason,
        expires_at: expiresAt || null,
      };
      const r = await apiPost<Record<string, unknown>>("/api/v1/auto-waiver/rule", body);
      setResult(r);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white flex items-center gap-2">
          <ShieldCheck className="w-6 h-6 text-indigo-400" /> Request Waiver
        </h1>
        <p className="text-gray-400 mt-1">Live submit — POST /api/v1/auto-waiver/rule</p>
      </div>

      <form
        onSubmit={submit}
        className="bg-gray-800 rounded-lg p-6 space-y-4 max-w-2xl"
      >
        <div>
          <label className="block text-xs uppercase text-gray-400 mb-1">Rule key</label>
          <input
            type="text"
            value={ruleKey}
            onChange={(e) => setRuleKey(e.target.value)}
            placeholder="auto-generated if blank"
            className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-sm"
          />
        </div>
        <div>
          <label className="block text-xs uppercase text-gray-400 mb-1">Finding ID</label>
          <input
            type="text"
            value={findingId}
            onChange={(e) => setFindingId(e.target.value)}
            placeholder="optional — match clause"
            className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-sm"
          />
        </div>
        <div>
          <label className="block text-xs uppercase text-gray-400 mb-1">Reason</label>
          <textarea
            required
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            rows={3}
            className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-sm"
          />
        </div>
        <div>
          <label className="block text-xs uppercase text-gray-400 mb-1">Expires at</label>
          <input
            type="datetime-local"
            value={expiresAt}
            onChange={(e) => setExpiresAt(e.target.value)}
            className="bg-gray-900 border border-gray-700 rounded px-3 py-2 text-sm"
          />
        </div>
        <button
          type="submit"
          disabled={submitting}
          className="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-500 disabled:bg-gray-700 rounded-lg text-sm"
        >
          <Send className={`w-4 h-4 ${submitting ? "animate-pulse" : ""}`} /> Submit waiver
        </button>
      </form>

      {error && (
        <div className="bg-red-900/30 border border-red-800 text-red-200 rounded-lg p-4 max-w-2xl">
          <strong>Failed:</strong> {error}
        </div>
      )}
      {result && (
        <div className="bg-emerald-900/20 border border-emerald-800 text-emerald-100 rounded-lg p-4 max-w-2xl">
          <strong>Created:</strong>
          <pre className="mt-2 text-xs whitespace-pre-wrap break-all">
            {JSON.stringify(result, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}
