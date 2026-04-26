/**
 * Audit Log Explorer — Live API
 * Multica: 3e41a4c1-c081-4151-b5b6-49b8d625d30b (and dup c16b99dc-ea7e-4361-9256-8123e64c5743)
 * API: GET /api/v1/audit/logs (with filter params)
 *
 * Filterable explorer over the audit log: severity, event_type,
 * resource_type, free-text actor search. Renders a paginated table
 * with the live response. NO MOCKS.
 */

import { useEffect, useMemo, useState } from "react";
import { ScrollText, RefreshCw, Download } from "lucide-react";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";

type AuditLog = {
  id: string;
  event_type?: string;
  severity?: string;
  user_id?: string;
  resource_type?: string;
  resource_id?: string;
  action?: string;
  created_at?: string;
  details?: Record<string, unknown>;
};

async function apiFetch<T>(path: string, params?: Record<string, string>): Promise<T> {
  const orgId = getStoredOrgId() || "verify-test";
  const url = buildApiUrl(path, { org_id: orgId, ...params });
  const res = await fetch(url, {
    headers: { "X-API-Key": getStoredAuthToken(), "X-Org-ID": orgId },
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

const sevColor: Record<string, string> = {
  critical: "bg-red-700 text-red-100",
  high: "bg-orange-700 text-orange-100",
  medium: "bg-amber-700 text-amber-100",
  low: "bg-blue-700 text-blue-100",
  info: "bg-gray-600 text-gray-200",
};

export default function AuditLogExplorer() {
  const [logs, setLogs] = useState<AuditLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [severity, setSeverity] = useState<string>("");
  const [eventType, setEventType] = useState<string>("");
  const [actor, setActor] = useState<string>("");

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const params: Record<string, string> = {};
      if (severity) params.severity = severity;
      if (eventType) params.event_type = eventType;
      const v = await apiFetch<{ items?: AuditLog[]; logs?: AuditLog[] } | AuditLog[]>(
        "/api/v1/audit/logs",
        params,
      );
      const arr = Array.isArray(v) ? v : v.items ?? v.logs ?? [];
      setLogs(arr);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => {
    load();
  }, [severity, eventType]);

  const eventTypes = useMemo(() => {
    const s = new Set<string>();
    logs.forEach((l) => l.event_type && s.add(l.event_type));
    return Array.from(s).sort();
  }, [logs]);

  const filtered = useMemo(() => {
    if (!actor) return logs;
    const needle = actor.toLowerCase();
    return logs.filter(
      (l) =>
        (l.user_id ?? "").toLowerCase().includes(needle) ||
        (l.resource_id ?? "").toLowerCase().includes(needle) ||
        (l.action ?? "").toLowerCase().includes(needle),
    );
  }, [logs, actor]);

  const exportUrl = buildApiUrl("/api/v1/audit/logs/export", {
    org_id: getStoredOrgId() || "verify-test",
    ...(severity ? { severity } : {}),
    ...(eventType ? { event_type: eventType } : {}),
  });

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <ScrollText className="w-6 h-6 text-indigo-400" /> Audit Log Explorer
          </h1>
          <p className="text-gray-400 mt-1">Live data — /api/v1/audit/logs</p>
        </div>
        <div className="flex gap-2">
          <a
            href={exportUrl}
            className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm"
            target="_blank"
            rel="noreferrer"
          >
            <Download className="w-4 h-4" /> Export
          </a>
          <button
            onClick={load}
            className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm"
          >
            <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} /> Refresh
          </button>
        </div>
      </div>

      <div className="bg-gray-800 rounded-lg p-4 grid md:grid-cols-3 gap-3">
        <select
          value={severity}
          onChange={(e) => setSeverity(e.target.value)}
          className="bg-gray-900 border border-gray-700 rounded px-3 py-2 text-sm"
        >
          <option value="">All severities</option>
          {["critical", "high", "medium", "low", "info"].map((s) => (
            <option key={s} value={s}>
              {s}
            </option>
          ))}
        </select>
        <select
          value={eventType}
          onChange={(e) => setEventType(e.target.value)}
          className="bg-gray-900 border border-gray-700 rounded px-3 py-2 text-sm"
        >
          <option value="">All event types</option>
          {eventTypes.map((t) => (
            <option key={t} value={t}>
              {t}
            </option>
          ))}
        </select>
        <input
          type="text"
          value={actor}
          onChange={(e) => setActor(e.target.value)}
          placeholder="actor / resource / action…"
          className="bg-gray-900 border border-gray-700 rounded px-3 py-2 text-sm"
        />
      </div>

      {loading ? (
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-500" />
        </div>
      ) : error ? (
        <ErrorState message={error} onRetry={load} />
      ) : filtered.length === 0 ? (
        <EmptyState
          icon={ScrollText}
          title="No audit log entries match"
          description="Adjust the filters or wait for new events."
        />
      ) : (
        <div className="bg-gray-800 rounded-lg overflow-hidden">
          <div className="px-6 py-4 border-b border-gray-700">
            <h2 className="text-lg font-semibold text-white">Entries ({filtered.length})</h2>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-gray-700">
                  <th className="px-4 py-3 text-left text-xs uppercase text-gray-400">Time</th>
                  <th className="px-4 py-3 text-left text-xs uppercase text-gray-400">Sev</th>
                  <th className="px-4 py-3 text-left text-xs uppercase text-gray-400">Event</th>
                  <th className="px-4 py-3 text-left text-xs uppercase text-gray-400">Actor</th>
                  <th className="px-4 py-3 text-left text-xs uppercase text-gray-400">Action</th>
                  <th className="px-4 py-3 text-left text-xs uppercase text-gray-400">
                    Resource
                  </th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-700">
                {filtered.slice(0, 200).map((l) => (
                  <tr key={l.id} className="hover:bg-gray-750">
                    <td className="px-4 py-2 text-xs text-gray-400 whitespace-nowrap">
                      {l.created_at ?? "—"}
                    </td>
                    <td className="px-4 py-2">
                      <span
                        className={`px-2 py-0.5 rounded text-xs font-bold ${
                          sevColor[l.severity ?? "info"] ?? sevColor.info
                        }`}
                      >
                        {l.severity ?? "info"}
                      </span>
                    </td>
                    <td className="px-4 py-2 text-sm text-gray-300">{l.event_type ?? "—"}</td>
                    <td className="px-4 py-2 text-xs text-gray-400 font-mono truncate max-w-[12rem]">
                      {l.user_id ?? "—"}
                    </td>
                    <td className="px-4 py-2 text-sm text-gray-200 max-w-xs truncate">
                      {l.action ?? "—"}
                    </td>
                    <td className="px-4 py-2 text-xs text-gray-400 truncate max-w-[14rem]">
                      {l.resource_type ?? "—"} / {l.resource_id ?? "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  );
}
