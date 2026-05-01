// FOLDED into RulesCatalogHub hero (author tab) 2026-05-02 — preserve for git history
/**
 * Rule DSL Authoring Studio — Live API
 * Multica: 8813074c-7b02-478c-9a8b-ea093bd8bc79
 * API: GET /api/v1/rules/dsl + GET /api/v1/rules/dsl/schema
 *      POST /api/v1/rules/dsl/publish
 *
 * Authoring surface: list existing DSL rules, edit one, publish a new
 * version. Schema is fetched live to drive autocomplete hints. NO MOCKS.
 */

import { useEffect, useState } from "react";
import { Code2, RefreshCw, UploadCloud } from "lucide-react";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";

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
  if (!res.ok) throw new Error(`${res.status} ${(json as { detail?: string }).detail ?? res.statusText}`);
  return json as T;
}

type DSLRule = {
  key?: string;
  name?: string;
  version?: number;
  dsl_text?: string;
};

const DEFAULT_TEMPLATE = `# ALdeci Rule DSL — example
when:
  finding.severity in ["critical","high"]
  finding.cve_id is not null
then:
  set finding.priority = "P1"
  notify "security-alerts"
`;

export default function RuleDSLAuthoringStudio() {
  const [rules, setRules] = useState<DSLRule[]>([]);
  const [schema, setSchema] = useState<Record<string, unknown> | null>(null);
  const [selected, setSelected] = useState<DSLRule | null>(null);
  const [editorText, setEditorText] = useState(DEFAULT_TEMPLATE);
  const [editorKey, setEditorKey] = useState("");
  const [editorName, setEditorName] = useState("");
  const [loading, setLoading] = useState(true);
  const [publishing, setPublishing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [info, setInfo] = useState<string | null>(null);

  const load = async () => {
    setLoading(true);
    setError(null);
    try {
      const [rulesRes, schemaRes] = await Promise.allSettled([
        apiCall<DSLRule[] | { items?: DSLRule[] }>("/api/v1/rules/dsl"),
        apiCall<Record<string, unknown>>("/api/v1/rules/dsl/schema"),
      ]);
      if (rulesRes.status === "fulfilled") {
        const v = rulesRes.value;
        const list = Array.isArray(v) ? v : v.items ?? [];
        setRules(list);
        if (list[0]) {
          setSelected(list[0]);
          setEditorText(list[0].dsl_text ?? DEFAULT_TEMPLATE);
          setEditorKey(list[0].key ?? "");
          setEditorName(list[0].name ?? "");
        }
      }
      if (schemaRes.status === "fulfilled") setSchema(schemaRes.value);
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setLoading(false);
    }
  };
  useEffect(() => {
    load();
  }, []);

  const publish = async () => {
    setPublishing(true);
    setInfo(null);
    setError(null);
    try {
      const r = await apiCall<{ key?: string; version?: number }>(
        "/api/v1/rules/dsl/publish",
        {
          method: "POST",
          body: JSON.stringify({
            key: editorKey || `rule-${Date.now()}`,
            name: editorName || editorKey,
            dsl_text: editorText,
          }),
        },
      );
      setInfo(`Published ${r.key ?? editorKey} v${r.version ?? "?"}`);
      await load();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setPublishing(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      <div className="flex items-center justify-between flex-wrap gap-4">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Code2 className="w-6 h-6 text-indigo-400" /> Rule DSL Studio
          </h1>
          <p className="text-gray-400 mt-1">Live data — /api/v1/rules/dsl</p>
        </div>
        <button
          onClick={load}
          className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm"
        >
          <RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} /> Refresh
        </button>
      </div>

      {loading ? (
        <div className="flex items-center justify-center h-64">
          <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-indigo-500" />
        </div>
      ) : error ? (
        <ErrorState message={error} onRetry={load} />
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
          <aside className="bg-gray-800 rounded-lg p-4 lg:col-span-1">
            <h2 className="text-sm font-semibold text-gray-300 uppercase mb-2">
              Rules ({rules.length})
            </h2>
            {rules.length === 0 ? (
              <EmptyState
                icon={Code2}
                title="No DSL rules"
                description="Author one on the right and Publish."
              />
            ) : (
              <ul className="space-y-1">
                {rules.map((r) => (
                  <li key={r.key ?? r.name}>
                    <button
                      onClick={() => {
                        setSelected(r);
                        setEditorText(r.dsl_text ?? DEFAULT_TEMPLATE);
                        setEditorKey(r.key ?? "");
                        setEditorName(r.name ?? "");
                      }}
                      className={`w-full text-left px-2 py-1.5 rounded text-xs ${
                        selected?.key === r.key
                          ? "bg-indigo-600 text-white"
                          : "text-gray-300 hover:bg-gray-700"
                      }`}
                    >
                      {r.name ?? r.key} <span className="text-gray-500">v{r.version ?? "?"}</span>
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </aside>

          <section className="bg-gray-800 rounded-lg p-4 lg:col-span-3 space-y-3">
            <div className="grid md:grid-cols-2 gap-3">
              <div>
                <label className="block text-xs text-gray-400 uppercase mb-1">Key</label>
                <input
                  type="text"
                  value={editorKey}
                  onChange={(e) => setEditorKey(e.target.value)}
                  className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-sm font-mono"
                />
              </div>
              <div>
                <label className="block text-xs text-gray-400 uppercase mb-1">Name</label>
                <input
                  type="text"
                  value={editorName}
                  onChange={(e) => setEditorName(e.target.value)}
                  className="w-full bg-gray-900 border border-gray-700 rounded px-3 py-2 text-sm"
                />
              </div>
            </div>
            <div>
              <label className="block text-xs text-gray-400 uppercase mb-1">DSL text</label>
              <textarea
                value={editorText}
                onChange={(e) => setEditorText(e.target.value)}
                rows={18}
                spellCheck={false}
                className="w-full bg-gray-950 border border-gray-700 rounded px-3 py-2 text-sm font-mono leading-5"
              />
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={publish}
                disabled={publishing}
                className="flex items-center gap-2 px-4 py-2 bg-indigo-600 hover:bg-indigo-500 disabled:bg-gray-700 rounded-lg text-sm"
              >
                <UploadCloud className={`w-4 h-4 ${publishing ? "animate-pulse" : ""}`} />
                {publishing ? "Publishing…" : "Publish"}
              </button>
              {info && <span className="text-xs text-emerald-400">{info}</span>}
            </div>
            {schema && (
              <details className="text-xs text-gray-400 mt-2">
                <summary className="cursor-pointer text-indigo-300">DSL schema reference</summary>
                <pre className="mt-2 max-h-48 overflow-auto bg-gray-950 p-2 rounded">
                  {JSON.stringify(schema, null, 2)}
                </pre>
              </details>
            )}
          </section>
        </div>
      )}
    </div>
  );
}
