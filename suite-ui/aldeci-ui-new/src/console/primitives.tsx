/**
 * The console's vocabulary.
 *
 * Small, sharp components used everywhere, so density and honesty are properties
 * of the system rather than decisions each screen re-makes.
 *
 * The load-state components exist because of a specific, repeated failure: a
 * screen that cannot distinguish "still loading", "nothing here yet", "nothing
 * matched" and "the call failed" ends up rendering all four as a blank panel.
 * A user reads a blank panel as "this product does nothing".
 */

import { AlertTriangle, ArrowRight, Loader2 } from "lucide-react";
import type { ReactNode } from "react";

import type { Result } from "./api";

/* ── surfaces ─────────────────────────────────────────────────────────── */

export function Panel({
  title,
  subtitle,
  right,
  children,
}: {
  title: string;
  subtitle?: string;
  right?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section className="rounded-lg border border-white/8 bg-[#0d1117] shadow-[0_1px_0_rgba(255,255,255,0.04)_inset]">
      <header className="flex items-baseline justify-between gap-4 border-b border-white/8 px-4 py-3">
        <div className="min-w-0">
          <h2 className="truncate text-[13px] font-medium tracking-wide text-slate-200">{title}</h2>
          {subtitle && <p className="mt-0.5 truncate text-[11px] text-slate-500">{subtitle}</p>}
        </div>
        {right && <div className="shrink-0 text-[11px] text-slate-500">{right}</div>}
      </header>
      <div className="p-4">{children}</div>
    </section>
  );
}

/** A number with its unit and — crucially — where it came from. */
export function Metric({
  value,
  label,
  tone = "neutral",
  note,
}: {
  value: ReactNode;
  label: string;
  tone?: "neutral" | "urgent" | "good" | "muted";
  note?: string;
}) {
  const tones = {
    neutral: "text-slate-100",
    urgent: "text-rose-300",
    good: "text-emerald-300",
    muted: "text-slate-500",
  } as const;
  return (
    <div className="min-w-0">
      <div className={`font-mono text-2xl leading-none tabular-nums ${tones[tone]}`}>{value}</div>
      <div className="mt-1.5 text-[11px] uppercase tracking-wider text-slate-500">{label}</div>
      {note && <div className="mt-0.5 text-[11px] text-slate-600">{note}</div>}
    </div>
  );
}

/* ── the four states, never conflated ─────────────────────────────────── */

export function Loading({ what }: { what: string }) {
  return (
    <div className="flex items-center gap-2 py-6 text-[12px] text-slate-500">
      <Loader2 className="h-3.5 w-3.5 animate-spin" />
      Reading {what}…
    </div>
  );
}

/**
 * Empty is a fact with a next action, never a shrug.
 *
 * "No findings" and "0 findings" render identically and mean opposite things.
 * This component forces the caller to say which, and to say what to do about it.
 */
export function Empty({
  headline,
  because,
  action,
}: {
  headline: string;
  because: string;
  action?: { label: string; onClick: () => void };
}) {
  return (
    <div className="py-6">
      <p className="text-[13px] text-slate-300">{headline}</p>
      <p className="mt-1 text-[12px] leading-relaxed text-slate-500">{because}</p>
      {action && (
        <button
          onClick={action.onClick}
          className="mt-3 inline-flex items-center gap-1.5 rounded border border-cyan-400/25 bg-cyan-400/10 px-2.5 py-1.5 text-[12px] font-medium text-cyan-200 transition hover:bg-cyan-400/15 focus:outline-none focus-visible:ring-2 focus-visible:ring-cyan-400/50"
        >
          {action.label}
          <ArrowRight className="h-3.5 w-3.5" />
        </button>
      )}
    </div>
  );
}

/** A failure names itself. It is never dressed up as an empty state. */
export function Failed({ error, source }: { error: string; source: string }) {
  return (
    <div className="flex gap-2.5 rounded border border-amber-400/20 bg-amber-400/[0.06] p-3">
      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-300" />
      <div className="min-w-0">
        <p className="text-[12px] text-amber-100">{error}</p>
        <p className="mt-1 font-mono text-[11px] text-amber-200/45">{source}</p>
      </div>
    </div>
  );
}

/**
 * Render a Result without letting the four states collapse into one another.
 * A screen cannot accidentally show an error as an empty panel.
 */
export function Resolve<T>({
  result,
  what,
  empty,
  children,
}: {
  result: Result<T>;
  what: string;
  empty: { headline: string; because: string; action?: { label: string; onClick: () => void } };
  children: (data: T) => ReactNode;
}) {
  if (result.state === "loading") return <Loading what={what} />;
  if (result.state === "error") return <Failed error={result.error ?? "Unknown error"} source={result.source} />;
  if (result.state === "empty" || result.data === null) return <Empty {...empty} />;
  return <>{children(result.data)}</>;
}

/* ── the verdict badge — the product's actual output ──────────────────── */

const VERDICTS: Record<string, { label: string; className: string }> = {
  act_now: { label: "Act now", className: "border-rose-400/30 bg-rose-400/12 text-rose-200" },
  schedule: { label: "Schedule", className: "border-amber-400/30 bg-amber-400/12 text-amber-200" },
  watch: { label: "Watch", className: "border-sky-400/30 bg-sky-400/12 text-sky-200" },
  defer: { label: "Defer", className: "border-slate-400/20 bg-slate-400/8 text-slate-300" },
  exploited_unknown_reach: {
    label: "Exploited · reach unknown",
    className: "border-orange-400/30 bg-orange-400/12 text-orange-200",
  },
  insufficient_evidence: {
    label: "Insufficient evidence",
    className: "border-slate-400/20 bg-slate-400/8 text-slate-400",
  },
};

export function Verdict({ verdict, confidence }: { verdict?: string; confidence?: string }) {
  if (!verdict) {
    // Not assessed is a real state. Inventing "low" here would be the product
    // asserting something it never measured.
    return <span className="text-[11px] text-slate-600">not assessed</span>;
  }
  const style = VERDICTS[verdict] ?? VERDICTS.defer;
  return (
    <span className="inline-flex items-center gap-2">
      <span className={`rounded border px-1.5 py-0.5 text-[11px] font-medium ${style.className}`}>
        {style.label}
      </span>
      {confidence && confidence !== "none" && (
        <span
          className="text-[10px] uppercase tracking-wider text-slate-500"
          title={
            confidence === "measured"
              ? "From the KEV catalogue or an EPSS score in the feed database."
              : "From an EPSS estimated from severity — weaker evidence."
          }
        >
          {confidence}
        </span>
      )}
    </span>
  );
}

export function Severity({ level }: { level?: string }) {
  const map: Record<string, string> = {
    critical: "text-rose-300",
    high: "text-orange-300",
    medium: "text-amber-300",
    low: "text-sky-300",
    info: "text-slate-400",
  };
  const key = (level ?? "info").toLowerCase();
  return (
    <span className={`text-[11px] uppercase tracking-wider ${map[key] ?? map.info}`}>
      {key}
    </span>
  );
}

export function Mono({ children }: { children: ReactNode }) {
  return <span className="font-mono text-[12px] text-slate-400">{children}</span>;
}
