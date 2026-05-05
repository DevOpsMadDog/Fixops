import { useState, useEffect, useRef, useCallback } from "react";
import { useNavigate } from "react-router-dom";
import { Search, X, AlertTriangle, Bug, HardDrive, Siren, ShieldCheck, Loader2 } from "lucide-react";
import { cn } from "@/lib/utils";
import { AnimatePresence, motion } from "framer-motion";
import api from "@/lib/api";

// ── Types ──────────────────────────────────────────────────────────────────

type EntityType = "alert" | "vulnerability" | "asset" | "incident" | "compliance";

interface SearchResult {
  id: string;
  title: string;
  subtitle?: string;
  type: EntityType;
  to: string;
}

interface RawAlert {
  alert_id: string;
  title: string;
  severity?: string;
}
interface RawVuln {
  vuln_id?: string;
  id?: string;
  title?: string;
  cve_id?: string;
  severity?: string;
}
interface RawAsset {
  asset_id?: string;
  id?: string;
  name?: string;
  hostname?: string;
  asset_type?: string;
}
interface RawIncident {
  incident_id?: string;
  id?: string;
  title?: string;
  severity?: string;
}
interface RawControl {
  control_id?: string;
  id?: string;
  title?: string;
  name?: string;
  framework?: string;
}

// ── Entity config ──────────────────────────────────────────────────────────

const ENTITY_CONFIG: Record<EntityType, { label: string; icon: typeof AlertTriangle; color: string; bg: string }> = {
  alert:         { label: "Alert",       icon: AlertTriangle, color: "text-red-400",     bg: "bg-red-500/10" },
  vulnerability: { label: "Vuln",        icon: Bug,           color: "text-orange-400",  bg: "bg-orange-500/10" },
  asset:         { label: "Asset",       icon: HardDrive,     color: "text-blue-400",    bg: "bg-blue-500/10" },
  incident:      { label: "Incident",    icon: Siren,         color: "text-yellow-400",  bg: "bg-yellow-500/10" },
  compliance:    { label: "Compliance",  icon: ShieldCheck,   color: "text-emerald-400", bg: "bg-emerald-500/10" },
};

// ── Debounce hook ──────────────────────────────────────────────────────────

function useDebounce<T>(value: T, delay: number): T {
  const [debounced, setDebounced] = useState(value);
  useEffect(() => {
    const t = setTimeout(() => setDebounced(value), delay);
    return () => clearTimeout(t);
  }, [value, delay]);
  return debounced;
}

// ── Search fetch ───────────────────────────────────────────────────────────

async function fetchSearchResults(query: string): Promise<SearchResult[]> {
  const orgId = window.localStorage.getItem("aldeci.orgId")?.trim() || "default";
  const q = encodeURIComponent(query);

  const safe = async <T,>(fn: () => Promise<T>): Promise<T | null> => {
    try { return await fn(); } catch { return null; }
  };

  const [alerts, vulns, assets, incidents, controls] = await Promise.all([
    safe(() =>
      api.get(`/api/v1/alert-triage/alerts`, { params: { org_id: orgId, limit: 5 } })
        .then((r) => r.data?.alerts as RawAlert[] ?? [])
    ),
    safe(() =>
      api.get(`/api/v1/vuln-lifecycle/vulnerabilities`, { params: { org_id: orgId, limit: 5, search: q } })
        .then((r) => r.data?.vulnerabilities as RawVuln[] ?? r.data?.items as RawVuln[] ?? [])
    ),
    safe(() =>
      api.get(`/api/v1/assets`, { params: { org_id: orgId, limit: 5, search: q } })
        .then((r) => r.data?.assets as RawAsset[] ?? r.data?.items as RawAsset[] ?? [])
    ),
    safe(() =>
      api.get(`/api/v1/incident-orchestration/incidents`, { params: { org_id: orgId, limit: 5 } })
        .then((r) => r.data?.incidents as RawIncident[] ?? [])
    ),
    safe(() =>
      api.get(`/api/v1/compliance/frameworks`, { params: { org_id: orgId } })
        .then((r) => r.data?.frameworks as RawControl[] ?? r.data as RawControl[] ?? [])
    ),
  ]);

  const lq = query.toLowerCase();
  const results: SearchResult[] = [];

  // Alerts — client-side filter by title
  for (const a of alerts ?? []) {
    if (!a.title.toLowerCase().includes(lq)) continue;
    results.push({ id: a.alert_id, title: a.title, subtitle: a.severity, type: "alert", to: "/mission-control/soc" });
  }

  // Vulnerabilities
  for (const v of vulns ?? []) {
    const id = v.vuln_id ?? v.id ?? "";
    const title = v.title ?? v.cve_id ?? id;
    if (!title.toLowerCase().includes(lq)) continue;
    results.push({ id, title, subtitle: v.severity, type: "vulnerability", to: "/vuln-lifecycle" });
  }

  // Assets
  for (const a of assets ?? []) {
    const id = a.asset_id ?? a.id ?? "";
    const title = a.name ?? a.hostname ?? id;
    if (!title.toLowerCase().includes(lq)) continue;
    results.push({ id, title, subtitle: a.asset_type, type: "asset", to: "/assets" });
  }

  // Incidents
  for (const i of incidents ?? []) {
    const id = i.incident_id ?? i.id ?? "";
    const title = i.title ?? id;
    if (!title.toLowerCase().includes(lq)) continue;
    results.push({ id, title, subtitle: i.severity, type: "incident", to: "/incidents" });
  }

  // Compliance controls
  for (const c of controls ?? []) {
    const id = c.control_id ?? c.id ?? "";
    const title = c.title ?? c.name ?? id;
    if (!title.toLowerCase().includes(lq)) continue;
    results.push({ id, title, subtitle: c.framework, type: "compliance", to: "/compliance" });
  }

  return results.slice(0, 12);
}

// ── Component ──────────────────────────────────────────────────────────────

export function GlobalSearch() {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [results, setResults] = useState<SearchResult[]>([]);
  const [loading, setLoading] = useState(false);
  const [activeIndex, setActiveIndex] = useState(0);

  const inputRef = useRef<HTMLInputElement>(null);
  const containerRef = useRef<HTMLDivElement>(null);
  const navigate = useNavigate();
  const debouncedQuery = useDebounce(query, 300);

  // Cmd+K / Ctrl+K shortcut
  useEffect(() => {
    function handleKeydown(e: KeyboardEvent) {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        setOpen((o) => !o);
      }
      if (e.key === "Escape") {
        setOpen(false);
      }
    }
    document.addEventListener("keydown", handleKeydown);
    return () => document.removeEventListener("keydown", handleKeydown);
  }, []);

  // Auto-focus input when opened
  useEffect(() => {
    if (open) {
      setTimeout(() => inputRef.current?.focus(), 50);
    } else {
      setQuery("");
      setResults([]);
      setActiveIndex(0);
    }
  }, [open]);

  // Fetch on debounced query
  useEffect(() => {
    if (!debouncedQuery.trim() || debouncedQuery.length < 2) {
      setResults([]);
      setLoading(false);
      return;
    }
    setLoading(true);
    fetchSearchResults(debouncedQuery).then((r) => {
      setResults(r);
      setActiveIndex(0);
      setLoading(false);
    });
  }, [debouncedQuery]);

  // Close on outside click
  useEffect(() => {
    function handle(e: MouseEvent) {
      if (containerRef.current && !containerRef.current.contains(e.target as Node)) {
        setOpen(false);
      }
    }
    if (open) document.addEventListener("mousedown", handle);
    return () => document.removeEventListener("mousedown", handle);
  }, [open]);

  const handleSelect = useCallback((result: SearchResult) => {
    navigate(result.to);
    setOpen(false);
  }, [navigate]);

  // Keyboard navigation within results
  function handleKeyNav(e: React.KeyboardEvent<HTMLInputElement>) {
    if (!results.length) return;
    if (e.key === "ArrowDown") {
      e.preventDefault();
      setActiveIndex((i) => Math.min(i + 1, results.length - 1));
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      setActiveIndex((i) => Math.max(i - 1, 0));
    } else if (e.key === "Enter") {
      e.preventDefault();
      const r = results[activeIndex];
      if (r) handleSelect(r);
    }
  }

  return (
    <>
      {/* Trigger button */}
      <button
        onClick={() => setOpen(true)}
        className="flex items-center gap-2 rounded-lg border border-border bg-muted/40 px-3 py-1.5 text-sm text-muted-foreground hover:bg-muted/70 hover:text-foreground transition-colors"
        aria-label="Open global search"
      >
        <Search className="h-3.5 w-3.5" />
        <span className="hidden sm:inline">Search...</span>
        <kbd className="hidden sm:inline-flex items-center gap-0.5 rounded bg-background px-1.5 py-0.5 text-[10px] font-mono border border-border text-muted-foreground">
          <span>⌘</span>K
        </kbd>
      </button>

      {/* Modal overlay */}
      <AnimatePresence>
        {open && (
          <>
            {/* Backdrop */}
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              transition={{ duration: 0.15 }}
              className="fixed inset-0 z-50 bg-black/50 backdrop-blur-sm"
              onClick={() => setOpen(false)}
            />

            {/* Search panel */}
            <motion.div
              ref={containerRef}
              initial={{ opacity: 0, scale: 0.96, y: -8 }}
              animate={{ opacity: 1, scale: 1, y: 0 }}
              exit={{ opacity: 0, scale: 0.96, y: -8 }}
              transition={{ duration: 0.15, ease: [0.16, 1, 0.3, 1] }}
              className="fixed left-1/2 top-[15%] z-50 w-full max-w-lg -translate-x-1/2 rounded-xl border border-border bg-card shadow-2xl overflow-hidden"
            >
              {/* Input row */}
              <div className="flex items-center gap-3 border-b border-border px-4 py-3">
                {loading ? (
                  <Loader2 className="h-4 w-4 shrink-0 text-muted-foreground animate-spin" />
                ) : (
                  <Search className="h-4 w-4 shrink-0 text-muted-foreground" />
                )}
                <input
                  ref={inputRef}
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  onKeyDown={handleKeyNav}
                  placeholder="Search alerts, vulnerabilities, assets, incidents..."
                  className="flex-1 bg-transparent text-sm text-foreground placeholder:text-muted-foreground outline-none"
                />
                {query && (
                  <button
                    onClick={() => setQuery("")}
                    className="text-muted-foreground hover:text-foreground transition-colors"
                    aria-label="Clear search"
                  >
                    <X className="h-3.5 w-3.5" />
                  </button>
                )}
                <kbd className="shrink-0 rounded bg-muted px-1.5 py-0.5 text-[10px] font-mono border border-border text-muted-foreground">
                  ESC
                </kbd>
              </div>

              {/* Results */}
              <div className="max-h-80 overflow-y-auto">
                {query.length >= 2 && !loading && results.length === 0 ? (
                  <div className="flex flex-col items-center justify-center gap-2 py-10 text-muted-foreground">
                    <Search className="h-7 w-7 opacity-30" />
                    <span className="text-sm">No results for &ldquo;{query}&rdquo;</span>
                  </div>
                ) : results.length > 0 ? (
                  <ul className="py-1">
                    {results.map((result, idx) => {
                      const cfg = ENTITY_CONFIG[result.type];
                      const Icon = cfg.icon;
                      return (
                        <li key={`${result.type}-${result.id}`}>
                          <button
                            className={cn(
                              "flex w-full items-center gap-3 px-4 py-2.5 text-left transition-colors",
                              idx === activeIndex
                                ? "bg-primary/10 text-foreground"
                                : "hover:bg-muted/40 text-foreground"
                            )}
                            onClick={() => handleSelect(result)}
                            onMouseEnter={() => setActiveIndex(idx)}
                          >
                            <span className={cn("flex h-6 w-6 shrink-0 items-center justify-center rounded-md", cfg.bg)}>
                              <Icon className={cn("h-3.5 w-3.5", cfg.color)} />
                            </span>
                            <span className="flex-1 min-w-0">
                              <span className="block truncate text-sm font-medium">{result.title}</span>
                              {result.subtitle && (
                                <span className="block truncate text-xs text-muted-foreground capitalize">
                                  {result.subtitle}
                                </span>
                              )}
                            </span>
                            <span
                              className={cn(
                                "shrink-0 rounded-sm px-1.5 py-0.5 text-[10px] font-medium",
                                cfg.bg,
                                cfg.color
                              )}
                            >
                              {cfg.label}
                            </span>
                          </button>
                        </li>
                      );
                    })}
                  </ul>
                ) : (
                  /* Empty / hint state */
                  <div className="px-4 py-6 text-center text-sm text-muted-foreground">
                    Start typing to search across alerts, vulnerabilities, assets, incidents and compliance controls.
                  </div>
                )}
              </div>

              {/* Footer hint */}
              {results.length > 0 && (
                <div className="flex items-center justify-between border-t border-border px-4 py-2 text-[11px] text-muted-foreground">
                  <span>{results.length} result{results.length !== 1 ? "s" : ""}</span>
                  <span className="flex items-center gap-3">
                    <span><kbd className="rounded border border-border bg-muted px-1 font-mono">↑↓</kbd> navigate</span>
                    <span><kbd className="rounded border border-border bg-muted px-1 font-mono">↵</kbd> open</span>
                  </span>
                </div>
              )}
            </motion.div>
          </>
        )}
      </AnimatePresence>
    </>
  );
}
