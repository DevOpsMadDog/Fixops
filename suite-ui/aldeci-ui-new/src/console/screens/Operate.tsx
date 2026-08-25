/**
 * Run the platform — the deployment's own state.
 *
 * Nothing here is a number we did not measure. The health endpoints report what
 * they observed; where a check has no result, this says so rather than showing
 * a comforting zero.
 */

import { useEffect, useState } from "react";

import { apiGet, type Result } from "../api";
import { Metric, Mono, Panel, Resolve } from "../primitives";

export function OperateScreen() {
  const [deep, setDeep] = useState<Result<Record<string, unknown>>>({ state: "loading", data: null, error: null, source: "/api/v1/health/deep" });
  const [db, setDb] = useState<Result<Record<string, unknown>>>({ state: "loading", data: null, error: null, source: "/api/v1/health/database" });
  const [orgs, setOrgs] = useState<Result<Record<string, unknown>>>({ state: "loading", data: null, error: null, source: "/api/v1/orgs" });

  useEffect(() => {
    apiGet<Record<string, unknown>>("/api/v1/health/deep").then(setDeep);
    apiGet<Record<string, unknown>>("/api/v1/health/database").then(setDb);
    apiGet<Record<string, unknown>>("/api/v1/orgs").then(setOrgs);
  }, []);

  const orgCount = (() => {
    // /api/v1/orgs returns a BARE ARRAY. Reading .total/.orgs/.items off an
    // array yields undefined, and the ?? chain then fell through to 0 — so a
    // deployment with 1,029 tenants displayed "0 organisations". A shape
    // mismatch that renders as a plausible number is worse than a crash,
    // because nobody investigates a zero.
    const d = orgs.data as unknown;
    if (Array.isArray(d)) return d.length;
    const o = d as { total?: number; orgs?: unknown[]; items?: unknown[] } | null;
    return o?.total ?? o?.orgs?.length ?? o?.items?.length ?? 0;
  })();
  const status = (deep.data as { status?: string } | null)?.status;

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3">
        <Panel title="Service">
          <Metric
            value={status ?? (deep.state === "error" ? "unreachable" : "—")}
            label="deep health"
            tone={status === "healthy" ? "good" : status ? "urgent" : "muted"}
          />
        </Panel>
        <Panel title="Tenants"><Metric value={orgCount} label="organisations" /></Panel>
        <Panel title="Storage">
          <Metric value={db.state === "data" ? "reachable" : db.state} label="database check" tone={db.state === "data" ? "good" : "muted"} />
        </Panel>
      </div>

      <Panel title="Deep health" right={<Mono>{deep.source}</Mono>}>
        <Resolve result={deep} what="deep health" empty={{ headline: "No health detail.", because: "The endpoint answered with nothing." }}>
          {(d) => (
            <pre className="max-h-96 overflow-auto font-mono text-[11px] leading-relaxed text-slate-500">
              {JSON.stringify(d, null, 2)}
            </pre>
          )}
        </Resolve>
      </Panel>
    </div>
  );
}
