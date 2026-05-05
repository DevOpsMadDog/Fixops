/**
 * RuleDSLStudioPanel — author tab for RulesCatalogHub
 * Lists published DSL rules (GET /api/v1/rules/dsl) and shows
 * a schema hint sidebar from GET /api/v1/rules/dsl/schema.
 */

import { useEffect, useState } from "react";
import { Code2, RefreshCw, AlertCircle, CheckCircle2, XCircle } from "lucide-react";
import { dslRulesApi, type DslRule, type DslSchema } from "@/lib/api";

const STATUS_COLOR: Record<string, string> = {
  active: "text-green-500 bg-green-500/10",
  draft: "text-amber-500 bg-amber-500/10",
  retired: "text-slate-400 bg-slate-400/10",
};

const SEVERITY_COLOR: Record<string, string> = {
  critical: "text-red-500",
  high: "text-orange-500",
  medium: "text-amber-500",
  low: "text-blue-400",
  info: "text-slate-400",
};

const EXAMPLE_YAML = `key: custom.example.rule
name: Example Rule
severity: high
when:
  field: finding.cve_score
  operator: gte
  value: 7.0
actions:
  - tag: high-cvss
  - notify: security-team
`;

export function RuleDSLStudioPanel() {
  const [rules, setRules] = useState<DslRule[]>([]);
  const [schema, setSchema] = useState<DslSchema | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState("");

  const load = () => {
    setLoading(true);
    setError(null);
    Promise.all([
      dslRulesApi.list(statusFilter || undefined),
      dslRulesApi.schema().catch(() => ({ data: null })),
    ])
      .then(([rulesRes, schemaRes]) => {
        setRules(Array.isArray(rulesRes.data) ? rulesRes.data : []);
        if (schemaRes.data) setSchema(schemaRes.data as DslSchema);
      })
      .catch((err) => {
        setError(err?.response?.data?.detail ?? err?.message ?? "Failed to load DSL rules");
      })
      .finally(() => setLoading(false));
  };

  useEffect(() => { load(); }, [statusFilter]); // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className="flex flex-col gap-4 lg:flex-row lg:gap-6">
      {/* Left: rule list */}
      <div className="flex flex-1 flex-col gap-4">
        <div className="flex flex-wrap items-center gap-3">
          <select
            value={statusFilter}
            onChange={(e) => setStatusFilter(e.target.value)}
            className="rounded-md border border-border bg-card px-2 py-1 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-primary"
            aria-label="Filter by status"
          >
            <option value="">All statuses</option>
            <option value="active">Active</option>
            <option value="draft">Draft</option>
            <option value="retired">Retired</option>
          </select>
          <button
            onClick={load}
            disabled={loading}
            className="ml-auto flex items-center gap-1 rounded-md border border-border px-2.5 py-1 text-xs text-muted-foreground hover:text-foreground disabled:opacity-50"
            aria-label="Refresh DSL rules"
          >
            <RefreshCw className={`h-3.5 w-3.5 ${loading ? "animate-spin" : ""}`} />
            Refresh
          </button>
        </div>

        {error && !loading && (
          <div className="flex items-center gap-2 rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
            <AlertCircle className="h-4 w-4 shrink-0" />
            {error}
          </div>
        )}

        {loading && (
          <div className="space-y-2">
            {Array.from({ length: 5 }).map((_, i) => (
              <div key={i} className="h-12 animate-pulse rounded-lg bg-muted/40" />
            ))}
          </div>
        )}

        {!loading && !error && rules.length === 0 && (
          <div className="flex flex-col items-center gap-3 rounded-xl border border-border/60 bg-card py-14 text-center">
            <Code2 className="h-9 w-9 text-muted-foreground/40" />
            <p className="text-sm font-medium text-muted-foreground">No DSL rules yet</p>
            <p className="text-xs text-muted-foreground/60">
              Publish your first rule via POST /api/v1/rules/dsl/publish
            </p>
          </div>
        )}

        {!loading && rules.length > 0 && (
          <div className="overflow-x-auto rounded-xl border border-border/60">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-border/60 bg-muted/30 text-left text-muted-foreground">
                  <th className="px-3 py-2.5 font-medium">Key</th>
                  <th className="px-3 py-2.5 font-medium">Status</th>
                  <th className="px-3 py-2.5 font-medium">Severity</th>
                  <th className="px-3 py-2.5 font-medium">Version</th>
                  <th className="px-3 py-2.5 font-medium">Author</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/40">
                {rules.map((rule) => {
                  const statusCls = STATUS_COLOR[rule.status] ?? "text-slate-400 bg-slate-400/10";
                  const sevCls = SEVERITY_COLOR[rule.severity?.toLowerCase() ?? ""] ?? "text-slate-400";
                  return (
                    <tr key={rule.key} className="bg-card transition-colors hover:bg-muted/20">
                      <td className="max-w-[200px] truncate px-3 py-2 font-mono text-foreground" title={rule.key}>
                        {rule.key}
                      </td>
                      <td className="px-3 py-2">
                        <span className={`inline-flex items-center rounded px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide ${statusCls}`}>
                          {rule.status}
                        </span>
                      </td>
                      <td className={`px-3 py-2 font-medium ${sevCls}`}>
                        {rule.severity ?? "—"}
                      </td>
                      <td className="px-3 py-2 text-muted-foreground">v{rule.version ?? 1}</td>
                      <td className="px-3 py-2 text-muted-foreground">{rule.authored_by || "—"}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Right: schema hints */}
      <div className="w-full lg:w-72 shrink-0 flex flex-col gap-3">
        <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">Schema Reference</p>
        {schema?.fields && schema.fields.length > 0 ? (
          <div className="rounded-xl border border-border/60 bg-card divide-y divide-border/40 text-xs">
            {schema.fields.map((f) => (
              <div key={f.name} className="flex items-start gap-2 px-3 py-2">
                {f.required ? (
                  <CheckCircle2 className="h-3.5 w-3.5 shrink-0 text-green-500 mt-0.5" />
                ) : (
                  <XCircle className="h-3.5 w-3.5 shrink-0 text-muted-foreground/40 mt-0.5" />
                )}
                <div>
                  <p className="font-mono font-medium text-foreground">{f.name}</p>
                  <p className="text-muted-foreground">{f.type}{f.description ? ` — ${f.description}` : ""}</p>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="rounded-xl border border-border/60 bg-card px-3 py-4">
            <p className="text-xs text-muted-foreground mb-2 font-semibold">Example YAML</p>
            <pre className="font-mono text-[11px] text-muted-foreground/80 whitespace-pre-wrap leading-relaxed">
              {EXAMPLE_YAML}
            </pre>
          </div>
        )}
      </div>
    </div>
  );
}
