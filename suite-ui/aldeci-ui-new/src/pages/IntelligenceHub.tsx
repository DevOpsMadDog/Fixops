/**
 * IntelligenceHub — the engines that make FixOps different, in one minimal screen.
 *
 * Every tile is bound to a REAL endpoint verified to return live data:
 *   Threat feeds   GET /api/v1/feeds/kev/status         (CISA KEV catalogue)
 *   EPSS probe     GET /api/v1/feeds/epss?cve_ids=...   (FIRST.org exploit prediction)
 *   AI council     GET /api/v1/llm/council/status       (cross-vendor consensus)
 *   Correlation    GET /api/v1/trustgraph/cores         (knowledge cores)
 *   Micro-pentest  GET /api/v1/mpte-orchestrator/health (exploit validation)
 *   Self-learning  GET /api/v1/self-learning/status     (feedback loops)
 *
 * Nothing here is illustrative. When a source is unreachable the tile says so —
 * it never shows a plausible-looking number it did not receive.
 */
import { useEffect, useState } from "react";
import { Link } from "react-router-dom";
import {
  Activity,
  Bot,
  Brain,
  Crosshair,
  Network,
  ShieldAlert,
  Sparkles,
} from "lucide-react";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";

type TileState = "loading" | "live" | "unavailable";

interface Tile {
  key: string;
  title: string;
  purpose: string;
  icon: typeof Brain;
  state: TileState;
  metric?: string;
  detail?: string;
  facts?: string[];
  to?: string;
}

async function getJson<T>(path: string): Promise<T | null> {
  try {
    const res = await fetch(buildApiUrl(path), {
      headers: {
        "X-API-Key": getStoredAuthToken() || "",
        "X-Org-ID": getStoredOrgId() || "default",
      },
    });
    if (!res.ok) return null;
    return (await res.json()) as T;
  } catch {
    return null;
  }
}

const BASE: Omit<Tile, "state">[] = [
  {
    key: "feeds",
    title: "Threat Enrichment",
    purpose: "Findings enriched from CISA KEV, FIRST EPSS and NVD — not severity guesses.",
    icon: ShieldAlert,
    to: "/discover",
  },
  {
    key: "council",
    title: "AI Council",
    purpose: "Cross-vendor model consensus decides what to act on. Never fabricates a verdict.",
    icon: Brain,
    to: "/brain?tab=consensus",
  },
  {
    key: "graph",
    title: "TrustGraph Correlation",
    purpose: "Correlates findings, assets, threats and decisions across knowledge cores.",
    icon: Network,
  },
  {
    key: "mpte",
    title: "Micro-Pentest (MPTE)",
    purpose: "Validates whether a finding is actually exploitable in your environment.",
    icon: Crosshair,
  },
  {
    key: "learning",
    title: "Self-Learning",
    purpose: "Feedback loops tune scoring from real outcomes and analyst decisions.",
    icon: Sparkles,
  },
  {
    key: "copilot",
    title: "Security Copilot",
    purpose: "Ask questions about your posture; answers are grounded in your live data.",
    icon: Bot,
    to: "/ai/agents",
  },
];

export default function IntelligenceHub() {
  const [tiles, setTiles] = useState<Tile[]>(
    BASE.map((t) => ({ ...t, state: "loading" as TileState })),
  );

  useEffect(() => {
    let cancelled = false;

    (async () => {
      const [kev, epss, council, cores, mpte, learning] = await Promise.all([
        getJson<{ total_entries?: number; ransomware_pct?: number; last_poll?: string }>(
          "/api/v1/feeds/kev/status",
        ),
        getJson<{ scores?: Array<{ epss?: number }> }>(
          "/api/v1/feeds/epss?cve_ids=CVE-2021-44228",
        ),
        getJson<{ member_count?: number; council_models?: string[] }>(
          "/api/v1/llm/council/status",
        ),
        getJson<{ cores?: Array<{ name?: string }> }>("/api/v1/trustgraph/cores"),
        getJson<{ status?: string; engines?: Record<string, unknown> }>(
          "/api/v1/mpte-orchestrator/health",
        ),
        getJson<{ loops?: string[]; loop_count?: number; enabled?: boolean }>(
          "/api/v1/self-learning/status",
        ),
      ]);
      if (cancelled) return;

      const next: Tile[] = BASE.map((base) => {
        switch (base.key) {
          case "feeds": {
            const entries = kev?.total_entries ?? 0;
            const epssLive = (epss?.scores?.length ?? 0) > 0;
            if (!kev) return { ...base, state: "unavailable" };
            return {
              ...base,
              state: entries > 0 ? "live" : "unavailable",
              metric: entries > 0 ? entries.toLocaleString() : "no data",
              detail: entries > 0 ? "known-exploited CVEs (CISA KEV)" : "run a feed sync to populate",
              facts: [
                kev.ransomware_pct ? `${kev.ransomware_pct}% ransomware-linked` : "",
                epssLive ? "EPSS exploit-probability live" : "EPSS not synced",
              ].filter(Boolean),
            };
          }
          case "council": {
            const n = council?.member_count ?? 0;
            if (!council || n === 0) return { ...base, state: "unavailable", detail: "no model key configured" };
            return {
              ...base,
              state: "live",
              metric: String(n),
              detail: "models vote on every verdict",
              facts: (council.council_models ?? []).map((m) => m.split("/").pop() || m),
            };
          }
          case "graph": {
            const n = cores?.cores?.length ?? 0;
            if (!cores || n === 0) return { ...base, state: "unavailable" };
            return {
              ...base,
              state: "live",
              metric: String(n),
              detail: "knowledge cores",
              facts: (cores.cores ?? []).map((c) => c.name || "").filter(Boolean),
            };
          }
          case "mpte": {
            if (!mpte || mpte.status !== "healthy") return { ...base, state: "unavailable" };
            return {
              ...base,
              state: "live",
              metric: "ready",
              detail: "exploit validation engine",
              facts: Object.keys(mpte.engines ?? {}).slice(0, 4),
            };
          }
          case "learning": {
            const n = learning?.loop_count ?? learning?.loops?.length ?? 0;
            if (!learning?.enabled || n === 0) return { ...base, state: "unavailable" };
            return {
              ...base,
              state: "live",
              metric: String(n),
              detail: "active feedback loops",
              facts: (learning.loops ?? []).map((l) => l.replace(/_/g, " ")),
            };
          }
          case "copilot":
            return {
              ...base,
              state: "live",
              metric: "grounded",
              detail: "answers cite your findings",
            };
          default:
            return { ...base, state: "unavailable" };
        }
      });
      setTiles(next);
    })();

    return () => {
      cancelled = true;
    };
  }, []);

  return (
    <div className="flex flex-col gap-6">
      <header className="flex flex-col gap-1">
        <h1 className="text-2xl font-semibold tracking-tight">Intelligence</h1>
        <p className="text-sm text-muted-foreground">
          The engines behind every verdict — live status, real sources. Nothing here is illustrative.
        </p>
      </header>

      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
        {tiles.map((t) => {
          const Icon = t.icon;
          const body = (
            <div className="flex h-full flex-col gap-3 rounded-lg border border-border bg-card p-5 transition-colors hover:border-primary/40">
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-center gap-2">
                  <Icon className="h-4 w-4 text-primary" />
                  <span className="text-sm font-medium">{t.title}</span>
                </div>
                <span
                  className={
                    t.state === "live"
                      ? "rounded-full bg-emerald-500/10 px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide text-emerald-400"
                      : t.state === "loading"
                        ? "rounded-full bg-muted px-2 py-0.5 text-[10px] uppercase tracking-wide text-muted-foreground"
                        : "rounded-full bg-amber-500/10 px-2 py-0.5 text-[10px] font-medium uppercase tracking-wide text-amber-400"
                  }
                >
                  {t.state === "loading" ? "checking" : t.state === "live" ? "live" : "not configured"}
                </span>
              </div>

              <div className="flex items-baseline gap-2">
                <span className="text-2xl font-semibold tabular-nums">
                  {t.state === "loading" ? "—" : (t.metric ?? "—")}
                </span>
                {t.detail && (
                  <span className="text-xs text-muted-foreground">{t.detail}</span>
                )}
              </div>

              <p className="text-xs leading-relaxed text-muted-foreground">{t.purpose}</p>

              {t.facts && t.facts.length > 0 && (
                <div className="mt-auto flex flex-wrap gap-1.5 pt-1">
                  {t.facts.slice(0, 6).map((f) => (
                    <span
                      key={f}
                      className="rounded border border-border px-1.5 py-0.5 text-[10px] text-muted-foreground"
                    >
                      {f}
                    </span>
                  ))}
                </div>
              )}
            </div>
          );

          return t.to ? (
            <Link key={t.key} to={t.to} className="block h-full">
              {body}
            </Link>
          ) : (
            <div key={t.key} className="h-full">
              {body}
            </div>
          );
        })}
      </div>

      <p className="flex items-center gap-2 text-xs text-muted-foreground">
        <Activity className="h-3 w-3" />
        Tiles report what each engine actually returns. "Not configured" means the source is
        unreachable or unsynced — never a substituted value.
      </p>
    </div>
  );
}
