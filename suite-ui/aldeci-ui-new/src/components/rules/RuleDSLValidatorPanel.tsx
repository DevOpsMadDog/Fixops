/**
 * RuleDSLValidatorPanel — validate tab for RulesCatalogHub
 * Sends POST /api/v1/rules/dsl/validate with pasted DSL text
 * and shows the compiled JSON or error list.
 */

import { useState } from "react";
import { CheckCircle2, XCircle, Send, AlertCircle, Code2 } from "lucide-react";
import { dslRulesApi, type DslValidateResult } from "@/lib/api";

const PLACEHOLDER_YAML = `key: example.sql.injection
name: SQL Injection Detection
severity: critical
when:
  field: finding.rule_id
  operator: contains
  value: sql_injection
actions:
  - tag: critical-finding
  - escalate: security-team`;

export function RuleDSLValidatorPanel() {
  const [dslText, setDslText] = useState("");
  const [format, setFormat] = useState<"yaml" | "json">("yaml");
  const [result, setResult] = useState<DslValidateResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const validate = async () => {
    if (!dslText.trim()) return;
    setLoading(true);
    setResult(null);
    setError(null);
    try {
      const res = await dslRulesApi.validate(dslText, format);
      setResult(res.data);
    } catch (err: unknown) {
      const axiosErr = err as { response?: { data?: { detail?: string } }; message?: string };
      setError(
        axiosErr?.response?.data?.detail ?? axiosErr?.message ?? "Validation request failed"
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex flex-col gap-5">
      {/* Format picker + textarea */}
      <div className="flex flex-col gap-3">
        <div className="flex items-center gap-3">
          <label className="text-xs text-muted-foreground font-medium">Format:</label>
          {(["yaml", "json"] as const).map((f) => (
            <button
              key={f}
              onClick={() => setFormat(f)}
              className={`rounded-md px-3 py-1 text-xs font-medium transition-colors ${
                format === f
                  ? "bg-primary text-primary-foreground"
                  : "border border-border text-muted-foreground hover:text-foreground"
              }`}
              aria-pressed={format === f}
            >
              {f.toUpperCase()}
            </button>
          ))}
        </div>

        <textarea
          value={dslText}
          onChange={(e) => setDslText(e.target.value)}
          placeholder={PLACEHOLDER_YAML}
          rows={12}
          spellCheck={false}
          className="w-full rounded-xl border border-border bg-card px-4 py-3 font-mono text-xs text-foreground placeholder:text-muted-foreground/40 focus:outline-none focus:ring-2 focus:ring-primary/50 resize-y"
          aria-label="DSL rule text"
        />

        <button
          onClick={validate}
          disabled={loading || !dslText.trim()}
          className="self-start flex items-center gap-2 rounded-lg bg-primary px-4 py-2 text-sm font-medium text-primary-foreground hover:bg-primary/90 disabled:opacity-50 transition-colors"
        >
          <Send className="h-3.5 w-3.5" />
          {loading ? "Validating…" : "Validate"}
        </button>
      </div>

      {/* Network error */}
      {error && (
        <div className="flex items-start gap-2 rounded-lg border border-red-500/30 bg-red-500/10 px-4 py-3 text-sm text-red-400">
          <AlertCircle className="h-4 w-4 shrink-0 mt-0.5" />
          {error}
        </div>
      )}

      {/* Validation result */}
      {result && (
        <div
          className={`rounded-xl border px-5 py-4 flex flex-col gap-3 ${
            result.valid
              ? "border-green-500/30 bg-green-500/5"
              : "border-red-500/30 bg-red-500/5"
          }`}
        >
          <div className="flex items-center gap-2">
            {result.valid ? (
              <CheckCircle2 className="h-5 w-5 text-green-500" />
            ) : (
              <XCircle className="h-5 w-5 text-red-500" />
            )}
            <span className={`text-sm font-semibold ${result.valid ? "text-green-400" : "text-red-400"}`}>
              {result.valid ? "Valid DSL" : "Invalid DSL"}
            </span>
          </div>

          {result.errors && result.errors.length > 0 && (
            <div>
              <p className="text-xs font-semibold text-red-400 mb-1.5">Errors</p>
              <ul className="space-y-1">
                {result.errors.map((e, i) => (
                  <li key={i} className="flex items-start gap-1.5 text-xs text-red-300">
                    <XCircle className="h-3.5 w-3.5 shrink-0 mt-0.5 text-red-500" />
                    {e}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {result.warnings && result.warnings.length > 0 && (
            <div>
              <p className="text-xs font-semibold text-amber-400 mb-1.5">Warnings</p>
              <ul className="space-y-1">
                {result.warnings.map((w, i) => (
                  <li key={i} className="text-xs text-amber-300">{w}</li>
                ))}
              </ul>
            </div>
          )}

          {result.valid && result.compiled && (
            <div>
              <p className="text-xs font-semibold text-muted-foreground mb-1.5 flex items-center gap-1">
                <Code2 className="h-3.5 w-3.5" />
                Compiled AST
              </p>
              <pre className="overflow-x-auto rounded-lg bg-card border border-border/60 px-3 py-3 text-[11px] font-mono text-muted-foreground/90 leading-relaxed max-h-60">
                {JSON.stringify(result.compiled, null, 2)}
              </pre>
            </div>
          )}
        </div>
      )}

      {/* Idle hint */}
      {!result && !error && !loading && (
        <div className="flex flex-col items-center gap-3 rounded-xl border border-border/60 bg-card py-10 text-center">
          <Code2 className="h-9 w-9 text-muted-foreground/30" />
          <p className="text-xs text-muted-foreground/60">
            Paste DSL text above and click Validate to check the rule
          </p>
        </div>
      )}
    </div>
  );
}
