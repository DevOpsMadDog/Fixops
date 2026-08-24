/**
 * Teach it your model — the answer to a closed knowledge graph.
 *
 * A customer declares the entities and rules their risk model uses. The grammar
 * is published rather than discovered, and the limit is stated on screen: rules
 * move priority and attach labels, and can never assert a measurement.
 */

import { useEffect, useState } from "react";

import { apiGet, apiPost, type Result } from "../api";
import { Mono, Panel, Resolve } from "../primitives";

interface Vocab { match_fields?: string[]; actions?: string[]; notes?: string[] }
interface Rule { rule_id?: string; name?: string; match_field?: string; match_value?: string; action?: string; entity_type?: string }
interface EntityType { name?: string; description?: string }

export function DeclareScreen() {
  const [vocab, setVocab] = useState<Result<Vocab>>({ state: "loading", data: null, error: null, source: "/api/v1/graph/vocabulary" });
  const [types, setTypes] = useState<Result<{ total?: number; types?: EntityType[] }>>({ state: "loading", data: null, error: null, source: "/api/v1/graph/types" });
  const [rules, setRules] = useState<Result<{ total?: number; rules?: Rule[] }>>({ state: "loading", data: null, error: null, source: "/api/v1/graph/rules" });
  const [typeName, setTypeName] = useState("");
  const [msg, setMsg] = useState<string | null>(null);

  const reload = () => {
    apiGet<Vocab>("/api/v1/graph/vocabulary").then(setVocab);
    apiGet<{ total?: number; types?: EntityType[] }>("/api/v1/graph/types").then(setTypes);
    apiGet<{ total?: number; rules?: Rule[] }>("/api/v1/graph/rules").then(setRules);
  };
  useEffect(reload, []);

  async function declareType() {
    if (!typeName.trim()) return;
    const r = await apiPost("/api/v1/graph/types", { name: typeName.trim(), description: "" });
    setMsg(r.state === "error" ? r.error : `Declared ${typeName.trim()}`);
    setTypeName("");
    reload();
  }

  return (
    <div className="space-y-5">
      <Panel title="Declare an entity type" subtitle="A concept in your risk model that we did not think of">
        <div className="flex flex-wrap gap-2">
          <input
            value={typeName}
            onChange={(e) => setTypeName(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && declareType()}
            placeholder="cardholder_data_environment"
            className="min-w-64 flex-1 rounded border border-white/10 bg-[#0d1117] px-3 py-1.5 font-mono text-[12px] text-slate-200 outline-none placeholder:text-slate-600 focus-visible:ring-2 focus-visible:ring-cyan-400/40"
          />
          <button
            onClick={declareType}
            className="rounded border border-cyan-400/25 bg-cyan-400/10 px-3 py-1.5 text-[12px] font-medium text-cyan-200 transition hover:bg-cyan-400/15"
          >
            Declare
          </button>
        </div>
        {msg && <p className="mt-2 text-[11px] text-slate-400">{msg}</p>}
      </Panel>

      <div className="grid gap-4 lg:grid-cols-2">
        <Panel title="Your entity types" right={<Mono>{types.source}</Mono>}>
          <Resolve
            result={types}
            what="declared types"
            empty={{ headline: "You have not declared any types yet.", because: "Declare one above — it becomes available to rules immediately." }}
          >
            {(d) => (
              <ul className="space-y-1.5">
                {(d.types ?? []).map((t) => (
                  <li key={t.name} className="flex items-baseline gap-3">
                    <Mono>{t.name}</Mono>
                    <span className="truncate text-[11px] text-slate-600">{t.description}</span>
                  </li>
                ))}
              </ul>
            )}
          </Resolve>
        </Panel>

        <Panel title="Your rules" right={<Mono>{rules.source}</Mono>}>
          <Resolve
            result={rules}
            what="declared rules"
            empty={{ headline: "No rules yet.", because: "A rule says what a match means for you — escalate, deprioritise, or label." }}
          >
            {(d) => (
              <ul className="space-y-2">
                {(d.rules ?? []).map((r) => (
                  <li key={r.rule_id} className="rounded border border-white/8 bg-white/[0.02] p-2.5">
                    <div className="text-[12px] text-slate-200">{r.name}</div>
                    <div className="mt-1 text-[11px] text-slate-500">
                      when <Mono>{r.match_field}={r.match_value}</Mono> → {r.action}
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </Resolve>
        </Panel>
      </div>

      <Panel title="The grammar" subtitle="Published, so you never have to discover it by trial and error">
        <Resolve result={vocab} what="the rule grammar" empty={{ headline: "Grammar unavailable.", because: "The endpoint answered with nothing." }}>
          {(v) => (
            <div className="space-y-3">
              <div>
                <div className="text-[10px] uppercase tracking-wider text-slate-600">Match on</div>
                <div className="mt-1 flex flex-wrap gap-1.5">
                  {(v.match_fields ?? []).map((f) => (
                    <span key={f} className="rounded border border-white/8 bg-white/[0.03] px-2 py-0.5 font-mono text-[11px] text-slate-400">{f}</span>
                  ))}
                </div>
              </div>
              <div>
                <div className="text-[10px] uppercase tracking-wider text-slate-600">Actions</div>
                <div className="mt-1 flex flex-wrap gap-1.5">
                  {(v.actions ?? []).map((a) => (
                    <span key={a} className="rounded border border-cyan-400/20 bg-cyan-400/8 px-2 py-0.5 font-mono text-[11px] text-cyan-200">{a}</span>
                  ))}
                </div>
              </div>
              <ul className="space-y-1 border-t border-white/8 pt-3">
                {(v.notes ?? []).map((n) => (
                  <li key={n} className="text-[11px] leading-relaxed text-slate-500">{n}</li>
                ))}
              </ul>
            </div>
          )}
        </Resolve>
      </Panel>
    </div>
  );
}
