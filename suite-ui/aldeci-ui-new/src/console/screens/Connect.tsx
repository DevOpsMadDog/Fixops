/** Connect systems — what is wired, and whether it is actually live. */

import { useEffect, useState } from "react";

import { apiGet, type Result } from "../api";
import { Mono, Panel, Resolve } from "../primitives";

const SOURCES = [
  { label: "Threat intel", path: "/api/v1/connectors/ti/status" },
  { label: "SIEM adapters", path: "/api/v1/connectors/siem/adapters" },
  { label: "CrowdStrike Falcon", path: "/api/v1/connectors/falcon/status" },
];

export function ConnectScreen() {
  const [results, setResults] = useState<Record<string, Result<Record<string, unknown>>>>({});

  useEffect(() => {
    SOURCES.forEach((s) => {
      apiGet<Record<string, unknown>>(s.path).then((r) => setResults((prev) => ({ ...prev, [s.path]: r })));
    });
  }, []);

  return (
    <div className="space-y-4">
      {SOURCES.map((s) => {
        const r = results[s.path] ?? { state: "loading" as const, data: null, error: null, source: s.path };
        return (
          <Panel key={s.path} title={s.label} right={<Mono>{s.path}</Mono>}>
            <Resolve
              result={r}
              what={s.label.toLowerCase()}
              empty={{
                headline: "Not configured.",
                because: "This connector answered, but has nothing wired. That is a configuration state, not a failure.",
              }}
            >
              {(d) => (
                <pre className="max-h-56 overflow-auto font-mono text-[11px] leading-relaxed text-slate-500">
                  {JSON.stringify(d, null, 2)}
                </pre>
              )}
            </Resolve>
          </Panel>
        );
      })}
    </div>
  );
}
