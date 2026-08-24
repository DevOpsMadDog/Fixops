/** Track a framework — control coverage and the gaps an assessor will ask about. */

import { useEffect, useState } from "react";

import { apiGet, type Result } from "../api";
import { Metric, Mono, Panel, Resolve } from "../primitives";

export function ComplyScreen() {
  const [status, setStatus] = useState<Result<Record<string, unknown>>>({ state: "loading", data: null, error: null, source: "/api/v1/compliance/status" });
  const [gaps, setGaps] = useState<Result<Record<string, unknown>>>({ state: "loading", data: null, error: null, source: "/api/v1/compliance/gaps" });

  useEffect(() => {
    apiGet<Record<string, unknown>>("/api/v1/compliance/status").then(setStatus);
    apiGet<Record<string, unknown>>("/api/v1/compliance/gaps").then(setGaps);
  }, []);

  const gapCount = (() => {
    const d = gaps.data as { total?: number; gaps?: unknown[] } | null;
    return d?.total ?? d?.gaps?.length ?? 0;
  })();

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3">
        <Panel title="Open gaps"><Metric value={gapCount} label="controls needing evidence" tone={gapCount ? "urgent" : "good"} /></Panel>
        <Panel title="Frameworks"><Metric value={status.state === "data" ? "tracked" : "—"} label="assessment status" /></Panel>
        <Panel title="Evidence">
          <p className="text-[12px] leading-relaxed text-slate-500">
            Coverage is computed from ingested findings and generated bundles — never asserted when empty.
          </p>
        </Panel>
      </div>

      <Panel title="Control gaps" right={<Mono>{gaps.source}</Mono>}>
        <Resolve
          result={gaps}
          what="control gaps"
          empty={{ headline: "No gaps recorded.", because: "Either every tracked control has evidence, or no framework is being tracked yet." }}
        >
          {(d) => (
            <pre className="max-h-80 overflow-auto font-mono text-[11px] leading-relaxed text-slate-500">
              {JSON.stringify(d, null, 2)}
            </pre>
          )}
        </Resolve>
      </Panel>

      <Panel title="Framework status" right={<Mono>{status.source}</Mono>}>
        <Resolve result={status} what="framework status" empty={{ headline: "No framework tracked.", because: "Nothing has been assessed for this tenant yet." }}>
          {(d) => (
            <pre className="max-h-72 overflow-auto font-mono text-[11px] leading-relaxed text-slate-500">
              {JSON.stringify(d, null, 2)}
            </pre>
          )}
        </Resolve>
      </Panel>
    </div>
  );
}
