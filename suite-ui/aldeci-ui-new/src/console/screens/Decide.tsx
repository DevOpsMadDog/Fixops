/**
 * See the verdict — the product's thesis on one screen.
 *
 * Reachability answers "can this be reached in THIS deployment". Exploit
 * evidence answers "is anyone exploiting it out there". Each alone is a number
 * on a dashboard; together they are a decision. This screen shows the join, and
 * shows the confidence, because "act now" on a guessed EPSS is a weaker claim
 * than "act now" on the KEV catalogue.
 */

import { useEffect, useState } from "react";

import { apiGet, type Result } from "../api";
import { Metric, Mono, Panel, Resolve, Verdict } from "../primitives";

interface Finding {
  exploitability?: string;
  exploitability_confidence?: string;
  exploitability_evidence?: string[];
  reachability_verdict?: string;
  cve_id?: string;
  title?: string;
}

export function DecideScreen() {
  const [findings, setFindings] = useState<Result<{ findings?: Finding[]; items?: Finding[] }>>({
    state: "loading", data: null, error: null, source: "/api/v1/findings",
  });
  const [stages, setStages] = useState<Result<Record<string, unknown>>>({
    state: "loading", data: null, error: null, source: "/api/v1/pipeline/stages",
  });

  useEffect(() => {
    apiGet<{ findings?: Finding[]; items?: Finding[] }>("/api/v1/findings").then(setFindings);
    apiGet<Record<string, unknown>>("/api/v1/pipeline/stages").then(setStages);
  }, []);

  const rows = findings.data?.findings ?? findings.data?.items ?? [];
  const assessed = rows.filter((f) => f.exploitability);
  const measured = assessed.filter((f) => f.exploitability_confidence === "measured").length;
  const estimated = assessed.filter((f) => f.exploitability_confidence === "estimated").length;

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <Panel title="Assessed"><Metric value={assessed.length} label="carry a verdict" /></Panel>
        <Panel title="Measured">
          <Metric value={measured} label="KEV or real EPSS" tone={measured ? "good" : "muted"} />
        </Panel>
        <Panel title="Estimated">
          <Metric value={estimated} label="EPSS from severity" tone="muted" note="weaker evidence" />
        </Panel>
        <Panel title="Not assessed">
          {/* This said "no CVE to reason about" — which was FALSE for findings
              that carry a CVE but have never been through a pipeline run.
              Ingest alone does not compute a verdict. State the count; do not
              assert a cause the screen has not checked. */}
          <Metric
            value={rows.length - assessed.length}
            label="no verdict yet"
            tone="muted"
            note={
              rows.length - assessed.length > 0
                ? "a verdict needs a pipeline run, and a CVE to reason about"
                : undefined
            }
          />
        </Panel>
      </div>

      <Panel
        title="How the verdict was reached"
        subtitle="Reachability × exploit evidence, per finding, with the inputs it used"
        right={<Mono>{findings.source}</Mono>}
      >
        <Resolve
          result={findings}
          what="verdicts"
          empty={{
            headline: "Nothing to decide about yet.",
            because: "Verdicts are computed during a pipeline run over ingested findings. Ingest a scan first.",
          }}
        >
          {() =>
            assessed.length === 0 ? (
              <p className="py-4 text-[12px] leading-relaxed text-slate-500">
                {rows.length} finding{rows.length === 1 ? "" : "s"} are stored, but none carry a verdict yet.
                A verdict needs a CVE to reason about — findings without one are reported as not assessed
                rather than given a default.
              </p>
            ) : (
              <div className="-mx-4 overflow-x-auto">
                <table className="w-full min-w-[760px] border-collapse text-left">
                  <thead>
                    <tr className="border-b border-white/8 text-[10px] uppercase tracking-wider text-slate-600">
                      <th className="px-4 py-2 font-medium">Verdict</th>
                      <th className="px-4 py-2 font-medium">CVE</th>
                      <th className="px-4 py-2 font-medium">Reachability</th>
                      <th className="px-4 py-2 font-medium">Evidence used</th>
                    </tr>
                  </thead>
                  <tbody>
                    {assessed.slice(0, 60).map((f, i) => (
                      <tr key={i} className="border-b border-white/[0.04]">
                        <td className="px-4 py-2.5">
                          <Verdict verdict={f.exploitability} confidence={f.exploitability_confidence} />
                        </td>
                        <td className="px-4 py-2.5"><Mono>{f.cve_id ?? "—"}</Mono></td>
                        <td className="px-4 py-2.5 text-[12px] text-slate-400">
                          {f.reachability_verdict ?? "unavailable"}
                        </td>
                        <td className="px-4 py-2.5">
                          <Mono>{(f.exploitability_evidence ?? []).join(", ") || "—"}</Mono>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )
          }
        </Resolve>
      </Panel>

      <Panel title="Pipeline stages" right={<Mono>{stages.source}</Mono>}>
        <Resolve
          result={stages}
          what="pipeline stages"
          empty={{ headline: "No stages reported.", because: "The pipeline answered but listed no stages." }}
        >
          {(data) => (
            <pre className="max-h-56 overflow-auto font-mono text-[11px] leading-relaxed text-slate-500">
              {JSON.stringify(data, null, 2)}
            </pre>
          )}
        </Resolve>
      </Panel>
    </div>
  );
}
