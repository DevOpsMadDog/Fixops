/**
 * What we actually scan — the first question any evaluator asks.
 *
 * This screen exists because of a measurement, not a design brief. The API had
 * 709 distinct capability prefixes and advertised 13; a competitor pitches
 * itself as "15-in-1" and we had built all fifteen while showing customers two.
 * Someone comparing the two products was reading our surface correctly and
 * concluding we were narrow.
 *
 * The temptation was eight new screens, one per newly-surfaced capability. That
 * is exactly how the last UI reached 300 pages: every subsystem got a page, so
 * the product's shape mirrored its implementation. One screen answers the
 * question instead.
 *
 * Every row's status is READ FROM A LIVE CALL. Nothing here is a static list of
 * things we claim to support — a capability that stopped answering shows as
 * unreachable on this screen, which is the entire point of putting it here.
 */

import { useEffect, useState } from "react";

import { apiGet, type Result } from "../api";
import { Metric, Mono, Panel } from "../primitives";

interface Capability {
  id: string;
  label: string;
  /** What it does, in the words of someone buying it. */
  what: string;
  endpoint: string;
  /** Pull a headline number out of the payload, when there is one. */
  read?: (data: Record<string, unknown>) => { value: number; unit: string } | null;
}

const CAPABILITIES: Capability[] = [
  {
    id: "sca",
    label: "Dependencies (SCA)",
    what: "Vulnerable open-source packages in what you ship",
    // Deliberately the same store Triage reads. /security-findings/summary is
    // a valid endpoint with the right shape, but it is a DIFFERENT store and
    // reports 0 for a tenant whose findings live here — so this screen would
    // have said "Ready" while Triage listed open findings two clicks away.
    // Two panels disagreeing about the same tenant is worse than either number.
    endpoint: "/api/v1/findings",
    read: (d) => (typeof d.total === "number" ? { value: d.total, unit: "findings" } : null),
  },
  {
    id: "sast",
    label: "Static analysis (SAST)",
    what: "Vulnerabilities in your own source code",
    endpoint: "/api/v1/sast/summary",
    read: (d) => (typeof d.total_findings === "number" ? { value: d.total_findings, unit: "findings" } : null),
  },
  {
    id: "secrets",
    label: "Secrets",
    what: "Credentials committed where they should not be",
    endpoint: "/api/v1/secrets/",
    read: (d) => (typeof d.total === "number" ? { value: d.total, unit: "detected" } : null),
  },
  {
    id: "iac",
    label: "Infrastructure as code",
    what: "Misconfiguration in Terraform, CloudFormation and friends",
    endpoint: "/api/v1/iac/summary",
    read: (d) => (typeof d.total_findings === "number" ? { value: d.total_findings, unit: "findings" } : null),
  },
  {
    id: "cspm",
    label: "Cloud posture (CSPM)",
    what: "Drift and misconfiguration in the accounts you run",
    endpoint: "/api/v1/cspm/posture",
  },
  {
    id: "dast",
    label: "Running app (DAST)",
    what: "What an attacker sees against the deployed thing",
    endpoint: "/api/v1/dast/stats",
    read: (d) => (typeof d.findings === "number" ? { value: d.findings, unit: "findings" } : null),
  },
  {
    id: "sbom",
    label: "SBOM",
    what: "The component inventory an auditor will ask you for",
    endpoint: "/api/v1/sbom/stats",
    read: (d) => (typeof d.total_components === "number" ? { value: d.total_components, unit: "components" } : null),
  },
  {
    id: "reachability",
    label: "Reachability",
    what: "Whether the vulnerable code is on a path your app can execute",
    endpoint: "/api/v1/reachability/stats",
    read: (d) => (typeof d.node_count === "number" ? { value: d.node_count, unit: "nodes" } : null),
  },
  {
    id: "autofix",
    label: "Remediation",
    what: "Generated fixes, raised as pull requests",
    endpoint: "/api/v1/autofix/stats",
    read: (d) => {
      const s = (d.stats ?? d) as Record<string, unknown>;
      return typeof s.total_prs_created === "number" ? { value: s.total_prs_created, unit: "PRs raised" } : null;
    },
  },
  {
    id: "graph",
    label: "Risk graph",
    what: "Your entities and correlation rules, declared by you",
    endpoint: "/api/v1/graph/types",
  },
];

type Status = "active" | "ready" | "unconfigured" | "unreachable" | "checking";

const PRESENTATION: Record<Status, { label: string; dot: string; text: string }> = {
  active: { label: "Active", dot: "bg-emerald-400", text: "text-emerald-300" },
  ready: { label: "Ready", dot: "bg-sky-400", text: "text-sky-300" },
  unconfigured: { label: "Needs a source", dot: "bg-slate-500", text: "text-slate-400" },
  unreachable: { label: "Unreachable", dot: "bg-amber-400", text: "text-amber-300" },
  checking: { label: "Checking", dot: "bg-slate-600 animate-pulse", text: "text-slate-500" },
};

/**
 * Turn a live response into a status.
 *
 * The subtle case is `{"status": "no_scan"}` returned with HTTP 200. It is a
 * populated object, so the generic emptiness check reads it as data — but the
 * payload is explicitly saying nothing has been scanned. Reporting that as
 * "Active" would be the product asserting coverage it has not delivered, which
 * is the failure this whole screen exists to prevent. Ask the payload.
 */
function classify(result: Result<Record<string, unknown>>, cap?: Capability): Status {
  if (result.state === "loading") return "checking";
  if (result.state === "unconfigured") return "unconfigured";
  if (result.state === "error") return "unreachable";
  if (result.state === "empty") return "ready";

  const d = result.data;
  if (!d) return "ready";
  if (typeof d.status === "string" && /^(no_scan|not_configured|no_data)$/.test(d.status)) {
    return d.status === "not_configured" ? "unconfigured" : "ready";
  }

  // A wrapper like {"status": "ok", "stats": {…all zeros}} survives the generic
  // emptiness check, because "ok" is a non-empty value — so a capability that
  // has produced nothing reported itself as Active while its own row read
  // "0 PRs raised". This panel defines Active as "holds your data"; a headline
  // of zero contradicts that in the same line of text. Trust the number.
  const headline = cap?.read?.(d);
  if (headline && headline.value === 0) return "ready";

  return "active";
}

export function CoverageScreen() {
  const [results, setResults] = useState<Record<string, Result<Record<string, unknown>>>>({});

  useEffect(() => {
    let live = true;
    CAPABILITIES.forEach((cap) => {
      apiGet<Record<string, unknown>>(cap.endpoint).then((r) => {
        if (live) setResults((prev) => ({ ...prev, [cap.id]: r }));
      });
    });
    return () => {
      live = false;
    };
  }, []);

  const statuses = CAPABILITIES.map((c) =>
    classify(results[c.id] ?? { state: "loading", data: null, error: null, source: c.endpoint }, c),
  );
  const settled = statuses.filter((s) => s !== "checking").length;
  const answering = statuses.filter((s) => s === "active" || s === "ready").length;
  const broken = statuses.filter((s) => s === "unreachable").length;

  return (
    <div className="space-y-5">
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-3">
        <Panel title="Capabilities">
          <Metric
            value={settled ? `${answering}/${CAPABILITIES.length}` : "—"}
            label="answering right now"
            tone={broken ? "urgent" : "good"}
            note="checked live, not listed from config"
          />
        </Panel>
        <Panel title="Awaiting a source">
          <Metric
            value={statuses.filter((s) => s === "unconfigured").length}
            label="need connecting"
            tone="muted"
            note="an onboarding step, not a fault"
          />
        </Panel>
        <Panel title="How to read this">
          <p className="text-[12px] leading-relaxed text-slate-500">
            <span className="text-emerald-300">Active</span> holds your data.{" "}
            <span className="text-sky-300">Ready</span> is wired and waiting for a first scan. Neither
            is inferred — both come from a call made when this screen loaded.
          </p>
        </Panel>
      </div>

      <Panel
        title="Coverage"
        subtitle="What this deployment can scan, and what it is doing about it today"
        right={<Mono>{CAPABILITIES.length} probed</Mono>}
      >
        <ul className="divide-y divide-white/5">
          {CAPABILITIES.map((cap) => {
            const result = results[cap.id] ?? { state: "loading" as const, data: null, error: null, source: cap.endpoint };
            const status = classify(result, cap);
            const p = PRESENTATION[status];
            const headline = status === "active" && cap.read && result.data ? cap.read(result.data) : null;

            return (
              <li key={cap.id} className="flex items-start gap-3 py-3 first:pt-0 last:pb-0">
                <span className={`mt-1.5 h-1.5 w-1.5 shrink-0 rounded-full ${p.dot}`} aria-hidden />
                <div className="min-w-0 flex-1">
                  <div className="flex flex-wrap items-baseline gap-x-2.5">
                    <span className="text-[13px] text-slate-200">{cap.label}</span>
                    <span className={`text-[11px] uppercase tracking-wider ${p.text}`}>{p.label}</span>
                    {headline && (
                      <span className="font-mono text-[11px] tabular-nums text-slate-400">
                        {headline.value.toLocaleString()} {headline.unit}
                      </span>
                    )}
                  </div>
                  <p className="mt-0.5 text-[12px] leading-relaxed text-slate-500">{cap.what}</p>
                  {status === "unreachable" && result.error && (
                    <p className="mt-1 text-[11px] text-amber-300/70">{result.error}</p>
                  )}
                  {status === "unconfigured" && result.error && (
                    <p className="mt-1 text-[11px] text-slate-500">{result.error}</p>
                  )}
                </div>
                <Mono>{cap.endpoint}</Mono>
              </li>
            );
          })}
        </ul>
      </Panel>
    </div>
  );
}
