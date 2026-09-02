/**
 * Work the queue — the spine, and what a customer actually pays for.
 *
 * The list leads with the VERDICT, not the severity. Severity is what every
 * scanner already gave them; the verdict is reachability crossed with exploit
 * evidence, and it is the only column that tells someone what to do tonight.
 */

import { useEffect, useState } from "react";

import { apiGet, type Result } from "../api";
import { Metric, Mono, Panel, Resolve, Severity, Verdict } from "../primitives";

interface Finding {
  id?: string;
  finding_id?: string;
  title?: string;
  severity?: string;
  status?: string;
  cve_id?: string;
  package_name?: string;
  asset_id?: string;
  source_tool?: string;
  exploitability?: string;
  exploitability_confidence?: string;
  epss_score?: number | null;
  kev_listed?: number | boolean | null;
  reachability_verdict?: string;
}

interface FindingsResponse {
  total?: number;
  findings?: Finding[];
  items?: Finding[];
}

function Evidence({
  epss,
  kev,
}: {
  epss?: number | null;
  kev?: number | boolean | null;
}) {
  const checked = epss !== null && epss !== undefined ? true : kev !== null && kev !== undefined;
  if (!checked) {
    return <span className="text-[11px] text-slate-600">not checked</span>;
  }
  const inKev = kev === true || kev === 1;
  return (
    <span className="flex items-center gap-2 text-[11px]">
      {inKev && (
        <span className="rounded border border-rose-400/30 bg-rose-400/12 px-1.5 py-0.5 font-medium text-rose-200">
          CISA KEV
        </span>
      )}
      {epss !== null && epss !== undefined ? (
        <span className="tabular-nums text-slate-400">EPSS {(epss * 100).toFixed(1)}%</span>
      ) : (
        <span className="text-slate-600">EPSS —</span>
      )}
    </span>
  );
}

export function TriageScreen() {
  const [findings, setFindings] = useState<Result<FindingsResponse>>({
    state: "loading", data: null, error: null, source: "/api/v1/findings",
  });
  const [dedup, setDedup] = useState<Result<Record<string, unknown>>>({
    state: "loading", data: null, error: null, source: "/api/v1/deduplication/stats",
  });

  useEffect(() => {
    apiGet<FindingsResponse>("/api/v1/findings").then(setFindings);
    apiGet<Record<string, unknown>>("/api/v1/deduplication/stats").then(setDedup);
  }, []);

  const rows = findings.data?.findings ?? findings.data?.items ?? [];
  const byVerdict = rows.reduce<Record<string, number>>((acc, f) => {
    const key = f.exploitability ?? "not_assessed";
    acc[key] = (acc[key] ?? 0) + 1;
    return acc;
  }, {});

  return (
    <div className="space-y-5">
      {/*
        COUNTERS ONLY WHEN THE FETCH ACTUALLY SUCCEEDED.
        These read findings.data directly, so a failed request left data null,
        rows [], and every tile rendered a confident 0 — "Act now: 0" reads as
        "nothing to do tonight" when the truth is "nothing loaded". Observed on
        127.0.0.1:8001, where /api/v1/findings answered 403 and the screen still
        showed four zeros with no indication anything was wrong.

        The list below always used Resolve; the tiles above it bypassed it,
        which is exactly how absence gets rendered as safety.
      */}
      {findings.state === "loading" || findings.state === "error" || findings.state === "unconfigured" ? (
        <Panel title="Queue summary">
          <Resolve
            result={findings}
            what="the queue summary"
            empty={{
              headline: "No findings yet.",
              because:
                "Nothing has been ingested for this tenant, so there is nothing to count.",
            }}
          >
            {() => null}
          </Resolve>
        </Panel>
      ) : (
        <div className="grid grid-cols-2 gap-4 sm:grid-cols-3 lg:grid-cols-5">
          <Panel title="Act now">
            <Metric
              value={byVerdict.act_now ?? 0}
              label="reachable and exploited"
              tone={byVerdict.act_now ? "urgent" : "muted"}
            />
          </Panel>
          <Panel title="Schedule">
            <Metric value={byVerdict.schedule ?? 0} label="reachable, not exploited" />
          </Panel>
          <Panel title="Watch">
            <Metric value={byVerdict.watch ?? 0} label="exploited, not reachable" />
          </Panel>
          {/*
            exploited_unknown_reach had NO tile, so a queue containing a
            MEASURED exploited CVE summarised as "Act now 0 / Schedule 0 /
            Watch 0" — three zeros above a finding that is being exploited in
            the wild. The row was listed below with its badge, but a reader
            scanning the summary concludes nothing needs attention. Absence of
            a tile is not absence of a threat.
          */}
          <Panel title="Exploited, reach unknown">
            <Metric
              value={byVerdict.exploited_unknown_reach ?? 0}
              label="exploited; reachability not yet analysed"
              tone={byVerdict.exploited_unknown_reach ? "urgent" : "muted"}
            />
          </Panel>
          <Panel title="Open total">
            <Metric
              value={findings.data?.total ?? rows.length}
              label="after deduplication"
              note={
                dedup.state === "data"
                  ? `dedup active`
                  : dedup.state === "error"
                    ? "dedup stats unavailable"
                    : undefined
              }
            />
          </Panel>
        </div>
      )}

      <Panel
        title="Open findings"
        subtitle="Ordered by what the platform measured, not by severity alone"
        right={<Mono>{findings.source}</Mono>}
      >
        <Resolve
          result={findings}
          what="the finding queue"
          empty={{
            headline: "No findings yet.",
            because:
              "Nothing has been ingested for this tenant. Upload scanner output in “Bring findings in” and this queue fills immediately.",
          }}
        >
          {(data) => {
            const list = data.findings ?? data.items ?? [];
            return (
              <div className="-mx-4 overflow-x-auto">
                <table className="w-full min-w-[860px] border-collapse text-left">
                  <thead>
                    <tr className="border-b border-white/8 text-[10px] uppercase tracking-wider text-slate-600">
                      <th className="px-4 py-2 font-medium">Verdict</th>
                      <th className="px-4 py-2 font-medium">Finding</th>
                      <th className="px-4 py-2 font-medium">CVE</th>
                      <th className="px-4 py-2 font-medium">Evidence</th>
                      <th className="px-4 py-2 font-medium">Component</th>
                      <th className="px-4 py-2 font-medium">Severity</th>
                      <th className="px-4 py-2 font-medium">Status</th>
                    </tr>
                  </thead>
                  <tbody>
                    {list.slice(0, 100).map((f, i) => (
                      <tr
                        key={f.id ?? f.finding_id ?? i}
                        className="border-b border-white/[0.04] transition hover:bg-white/[0.02]"
                      >
                        <td className="px-4 py-2.5">
                          <Verdict verdict={f.exploitability} confidence={f.exploitability_confidence} />
                        </td>
                        <td className="max-w-sm truncate px-4 py-2.5 text-[13px] text-slate-200">
                          {f.title ?? "—"}
                        </td>
                        <td className="px-4 py-2.5"><Mono>{f.cve_id ?? "—"}</Mono></td>
                        {/*
                          WHY the verdict says what it says. "Exploited" resting
                          on the CISA catalogue is a different claim from one
                          resting on an EPSS probability, and the person
                          deciding what to fix tonight has to see which.

                          null is rendered as "not checked", NOT as 0 or as a
                          blank cell. The store keeps those distinct on purpose
                          — a finding nobody enriched must not read as one that
                          was checked and came back clean.
                        */}
                        <td className="px-4 py-2.5">
                          <Evidence epss={f.epss_score} kev={f.kev_listed} />
                        </td>
                        <td className="px-4 py-2.5"><Mono>{f.package_name ?? f.asset_id ?? "—"}</Mono></td>
                        <td className="px-4 py-2.5"><Severity level={f.severity} /></td>
                        <td className="px-4 py-2.5 text-[12px] text-slate-400">{f.status ?? "open"}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {list.length > 100 && (
                  <p className="px-4 pt-3 text-[11px] text-slate-600">
                    Showing the first 100 of {list.length}.
                  </p>
                )}
              </div>
            );
          }}
        </Resolve>
      </Panel>
    </div>
  );
}
