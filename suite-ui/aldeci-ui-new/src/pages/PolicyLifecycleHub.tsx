/**
 * PolicyLifecycleHub — Policy lifecycle unified hero
 * (Phase 3 UX consolidation, 2026-05-02 — combined 3-page hub)
 *
 * Folds 3 standalone policy-lifecycle pages into a single tabbed hero per
 * docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.27 (Policy Lifecycle sub-cluster).
 * Sibling to the existing PolicyAuthoringHub at /comply/policies/authoring;
 * authoring covers create/edit/hooks, lifecycle covers browse/inherit/stage-edit.
 *
 *   tab          | source page              | endpoint
 *   -------------|--------------------------|------------------------------------------
 *   library      | PolicyLibraryBrowser     | GET /api/v1/policies + /api/v1/policies/stats
 *   inheritance  | PolicyInheritanceView    | GET /api/v1/orgs + /api/v1/policies
 *   stage-edit   | PolicyStageEditor        | GET/PATCH /api/v1/policies/{id}
 *
 * Route: /comply/policies/lifecycle
 * Persona target: Policy Author (#15), Compliance Lead (#13), Security Architect (#3)
 * Plan: docs/UX_CONSOLIDATION_PLAN_2026-04-26.md §2.27
 */

import { useEffect, useMemo, useState, useCallback } from "react";
import { useSearchParams } from "react-router-dom";
import { motion, AnimatePresence } from "framer-motion";
import {
  BookOpen,
  Network,
  Pencil,
  Search,
  RefreshCw,
  ChevronRight,
  ChevronDown,
  Shield,
  ShieldCheck,
  ShieldOff,
  Save,
  AlertCircle,
  CheckCircle2,
  Loader2,
} from "lucide-react";

import { PageHeader } from "@/components/shared/page-header";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { API_BASE_URL, API_KEY, DEFAULT_ORG_ID } from "@/lib/api-config";

// ─────────────────────────────────────────────────────────────────────────────
// Shared fetch helper
// ─────────────────────────────────────────────────────────────────────────────

async function apiFetch<T>(path: string): Promise<T> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (API_KEY) headers["X-API-Key"] = API_KEY;
  const res = await fetch(`${API_BASE_URL}${path}`, { headers });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

async function apiPatch<T>(path: string, body: unknown): Promise<T> {
  const headers: Record<string, string> = { "Content-Type": "application/json" };
  if (API_KEY) headers["X-API-Key"] = API_KEY;
  const res = await fetch(`${API_BASE_URL}${path}`, {
    method: "PATCH",
    headers,
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

// ─────────────────────────────────────────────────────────────────────────────
// Domain types
// ─────────────────────────────────────────────────────────────────────────────

interface Policy {
  id: string;
  name: string;
  description: string;
  scope: string;
  language: string;
  enabled: boolean;
  org_id: string;
  decision_on_match: string;
  rules: Array<Record<string, unknown>>;
  created_at?: string;
  updated_at?: string;
}

interface PolicyStats {
  total_policies: number;
  enabled: number;
  disabled: number;
  evaluations_24h?: number;
  deny_rate?: number;
  scopes?: Record<string, number>;
}

interface Org {
  org_id: string;
  name: string;
  description?: string;
  parent_id?: string;
  created_at?: string;
}

// ─────────────────────────────────────────────────────────────────────────────
// Tab 1 — Policy Library Browser
// ─────────────────────────────────────────────────────────────────────────────

function PolicyLibraryPanel() {
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [stats, setStats] = useState<PolicyStats | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [search, setSearch] = useState("");
  const [scopeFilter, setScopeFilter] = useState<string>("all");

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [pols, st] = await Promise.all([
        apiFetch<Policy[]>(`/api/v1/policies?org_id=${DEFAULT_ORG_ID}`),
        apiFetch<PolicyStats>(`/api/v1/policies/stats?org_id=${DEFAULT_ORG_ID}`),
      ]);
      setPolicies(Array.isArray(pols) ? pols : []);
      setStats(st);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load policies");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  const scopes = useMemo(() => {
    const s = new Set<string>();
    policies.forEach(p => s.add(p.scope));
    return ["all", ...Array.from(s)];
  }, [policies]);

  const filtered = useMemo(() => {
    return policies.filter(p => {
      const matchScope = scopeFilter === "all" || p.scope === scopeFilter;
      const matchSearch =
        !search ||
        p.name.toLowerCase().includes(search.toLowerCase()) ||
        p.description.toLowerCase().includes(search.toLowerCase());
      return matchScope && matchSearch;
    });
  }, [policies, search, scopeFilter]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-48 gap-2 text-muted-foreground">
        <Loader2 className="h-5 w-5 animate-spin" />
        <span className="text-sm">Loading policy library…</span>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center h-48 gap-3 text-destructive">
        <AlertCircle className="h-6 w-6" />
        <p className="text-sm">{error}</p>
        <button
          onClick={() => void load()}
          className="text-xs underline text-muted-foreground hover:text-foreground"
        >
          Retry
        </button>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-4">
      {/* Stats row */}
      {stats && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          {[
            { label: "Total", value: stats.total_policies ?? policies.length },
            { label: "Enabled", value: stats.enabled ?? policies.filter(p => p.enabled).length },
            { label: "Disabled", value: stats.disabled ?? policies.filter(p => !p.enabled).length },
            {
              label: "Evaluations (24h)",
              value: stats.evaluations_24h != null ? stats.evaluations_24h.toLocaleString() : "—",
            },
          ].map(({ label, value }) => (
            <div
              key={label}
              className="rounded-lg bg-muted/40 border border-border/50 p-3 flex flex-col gap-0.5"
            >
              <span className="text-xs text-muted-foreground">{label}</span>
              <span className="text-lg font-semibold tabular-nums">{value}</span>
            </div>
          ))}
        </div>
      )}

      {/* Search + scope filter */}
      <div className="flex flex-col sm:flex-row gap-2">
        <div className="relative flex-1">
          <Search className="absolute left-2.5 top-2.5 h-4 w-4 text-muted-foreground pointer-events-none" />
          <input
            type="text"
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search policies…"
            className="w-full pl-8 pr-3 py-2 text-sm rounded-md bg-muted/40 border border-border/50 focus:outline-none focus:ring-1 focus:ring-primary"
          />
        </div>
        <select
          value={scopeFilter}
          onChange={e => setScopeFilter(e.target.value)}
          className="text-sm rounded-md bg-muted/40 border border-border/50 px-3 py-2 focus:outline-none focus:ring-1 focus:ring-primary"
        >
          {scopes.map(s => (
            <option key={s} value={s}>
              {s === "all" ? "All scopes" : s}
            </option>
          ))}
        </select>
        <button
          onClick={() => void load()}
          className="p-2 rounded-md bg-muted/40 border border-border/50 hover:bg-muted transition-colors"
          title="Refresh"
        >
          <RefreshCw className="h-4 w-4" />
        </button>
      </div>

      {/* Policy list */}
      {filtered.length === 0 ? (
        <div className="flex flex-col items-center justify-center h-32 gap-2 text-muted-foreground">
          <Shield className="h-8 w-8 opacity-30" />
          <p className="text-sm">No policies match your filter.</p>
        </div>
      ) : (
        <div className="flex flex-col gap-2">
          {filtered.map(policy => (
            <motion.div
              key={policy.id}
              initial={{ opacity: 0, y: 4 }}
              animate={{ opacity: 1, y: 0 }}
              className="rounded-lg border border-border/50 bg-card p-4 flex items-start gap-3 hover:border-primary/40 transition-colors"
            >
              <div className="mt-0.5 shrink-0">
                {policy.enabled ? (
                  <ShieldCheck className="h-5 w-5 text-green-500" />
                ) : (
                  <ShieldOff className="h-5 w-5 text-muted-foreground" />
                )}
              </div>
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="font-medium text-sm truncate">{policy.name}</span>
                  <span className="text-xs px-1.5 py-0.5 rounded bg-muted text-muted-foreground shrink-0">
                    {policy.scope}
                  </span>
                  <span
                    className={`text-xs px-1.5 py-0.5 rounded shrink-0 ${
                      policy.decision_on_match === "deny"
                        ? "bg-red-500/10 text-red-400"
                        : "bg-green-500/10 text-green-400"
                    }`}
                  >
                    {policy.decision_on_match}
                  </span>
                </div>
                {policy.description && (
                  <p className="text-xs text-muted-foreground mt-1 truncate">
                    {policy.description}
                  </p>
                )}
                <p className="text-xs text-muted-foreground/60 mt-0.5">
                  {policy.rules.length} rule{policy.rules.length !== 1 ? "s" : ""} · {policy.language}
                </p>
              </div>
              <span
                className={`text-xs px-2 py-0.5 rounded-full shrink-0 font-medium ${
                  policy.enabled
                    ? "bg-green-500/10 text-green-400"
                    : "bg-muted text-muted-foreground"
                }`}
              >
                {policy.enabled ? "active" : "disabled"}
              </span>
            </motion.div>
          ))}
        </div>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Tab 2 — Policy Inheritance View
// ─────────────────────────────────────────────────────────────────────────────

interface OrgNode extends Org {
  children: OrgNode[];
  policies: Policy[];
}

function buildTree(orgs: Org[], policies: Policy[]): OrgNode[] {
  const nodeMap = new Map<string, OrgNode>();
  orgs.forEach(org => {
    nodeMap.set(org.org_id, { ...org, children: [], policies: [] });
  });
  // Attach policies to their org
  policies.forEach(p => {
    const node = nodeMap.get(p.org_id);
    if (node) node.policies.push(p);
  });
  const roots: OrgNode[] = [];
  nodeMap.forEach(node => {
    if (node.parent_id && nodeMap.has(node.parent_id)) {
      nodeMap.get(node.parent_id)!.children.push(node);
    } else {
      roots.push(node);
    }
  });
  return roots;
}

function OrgTreeNode({ node, depth }: { node: OrgNode; depth: number }) {
  const [expanded, setExpanded] = useState(depth < 2);
  const hasChildren = node.children.length > 0;

  return (
    <div className={`${depth > 0 ? "ml-4 border-l border-border/40 pl-3" : ""}`}>
      <div
        className="flex items-center gap-2 py-2 cursor-pointer hover:bg-muted/30 rounded px-2 group"
        onClick={() => setExpanded(e => !e)}
      >
        <span className="shrink-0 text-muted-foreground">
          {hasChildren ? (
            expanded ? (
              <ChevronDown className="h-4 w-4" />
            ) : (
              <ChevronRight className="h-4 w-4" />
            )
          ) : (
            <ChevronRight className="h-4 w-4 opacity-0" />
          )}
        </span>
        <span className="font-medium text-sm">{node.name || node.org_id}</span>
        <span className="text-xs text-muted-foreground">({node.org_id})</span>
        <span className="ml-auto text-xs px-2 py-0.5 rounded-full bg-muted text-muted-foreground">
          {node.policies.length} polic{node.policies.length !== 1 ? "ies" : "y"}
        </span>
      </div>

      {/* Inline policy chips */}
      {expanded && node.policies.length > 0 && (
        <div className="ml-6 flex flex-wrap gap-1.5 pb-1">
          {node.policies.map(p => (
            <span
              key={p.id}
              className={`text-xs px-2 py-0.5 rounded border ${
                p.enabled
                  ? "border-green-500/30 text-green-400 bg-green-500/5"
                  : "border-border/40 text-muted-foreground bg-muted/20"
              }`}
            >
              {p.name}
            </span>
          ))}
        </div>
      )}

      {expanded &&
        node.children.map(child => (
          <OrgTreeNode key={child.org_id} node={child} depth={depth + 1} />
        ))}
    </div>
  );
}

function PolicyInheritancePanel() {
  const [tree, setTree] = useState<OrgNode[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [orgsRaw, policiesRaw] = await Promise.all([
        apiFetch<Org[] | { orgs: Org[] }>("/api/v1/orgs"),
        apiFetch<Policy[]>(`/api/v1/policies?org_id=${DEFAULT_ORG_ID}`),
      ]);
      const orgs = Array.isArray(orgsRaw)
        ? orgsRaw
        : (orgsRaw as { orgs: Org[] }).orgs ?? [];
      const policies = Array.isArray(policiesRaw) ? policiesRaw : [];
      setTree(buildTree(orgs, policies));
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load inheritance data");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  if (loading) {
    return (
      <div className="flex items-center justify-center h-48 gap-2 text-muted-foreground">
        <Loader2 className="h-5 w-5 animate-spin" />
        <span className="text-sm">Loading org tree…</span>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center h-48 gap-3 text-destructive">
        <AlertCircle className="h-6 w-6" />
        <p className="text-sm">{error}</p>
        <button
          onClick={() => void load()}
          className="text-xs underline text-muted-foreground hover:text-foreground"
        >
          Retry
        </button>
      </div>
    );
  }

  if (tree.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-48 gap-2 text-muted-foreground">
        <Network className="h-8 w-8 opacity-30" />
        <p className="text-sm">No organisations found. Create an org to see the inheritance tree.</p>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center justify-between">
        <p className="text-xs text-muted-foreground">
          Org hierarchy with inherited policy assignments. Click a node to expand.
        </p>
        <button
          onClick={() => void load()}
          className="p-1.5 rounded-md bg-muted/40 border border-border/50 hover:bg-muted transition-colors"
          title="Refresh"
        >
          <RefreshCw className="h-3.5 w-3.5" />
        </button>
      </div>
      <div className="rounded-lg border border-border/50 bg-card p-3">
        {tree.map(root => (
          <OrgTreeNode key={root.org_id} node={root} depth={0} />
        ))}
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Tab 3 — Policy Stage Editor
// ─────────────────────────────────────────────────────────────────────────────

const SEVERITY_LEVELS = ["critical", "high", "medium", "low", "info"] as const;
type Severity = (typeof SEVERITY_LEVELS)[number];

interface StageThresholds {
  [severity: string]: number;
}

function PolicyStageEditorPanel() {
  const [policies, setPolicies] = useState<Policy[]>([]);
  const [selectedId, setSelectedId] = useState<string>("");
  const [thresholds, setThresholds] = useState<StageThresholds>({
    critical: 0,
    high: 5,
    medium: 10,
    low: 20,
    info: 50,
  });
  const [loadingList, setLoadingList] = useState(true);
  const [saving, setSaving] = useState(false);
  const [saveStatus, setSaveStatus] = useState<"idle" | "success" | "error">("idle");
  const [error, setError] = useState<string | null>(null);

  const loadPolicies = useCallback(async () => {
    setLoadingList(true);
    setError(null);
    try {
      const pols = await apiFetch<Policy[]>(`/api/v1/policies?org_id=${DEFAULT_ORG_ID}`);
      const list = Array.isArray(pols) ? pols : [];
      setPolicies(list);
      if (list.length > 0 && !selectedId) {
        setSelectedId(list[0].id);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "Failed to load policies");
    } finally {
      setLoadingList(false);
    }
  }, [selectedId]);

  useEffect(() => { void loadPolicies(); }, [loadPolicies]);

  // Load selected policy's thresholds from its rules
  useEffect(() => {
    if (!selectedId) return;
    const policy = policies.find(p => p.id === selectedId);
    if (!policy) return;
    // Extract per-severity thresholds from rules if stored there
    const extracted: StageThresholds = { critical: 0, high: 5, medium: 10, low: 20, info: 50 };
    policy.rules.forEach(rule => {
      const sev = rule["severity"] as string | undefined;
      const thresh = rule["threshold"] as number | undefined;
      if (sev && thresh != null && SEVERITY_LEVELS.includes(sev as Severity)) {
        extracted[sev] = thresh;
      }
    });
    setThresholds(extracted);
    setSaveStatus("idle");
  }, [selectedId, policies]);

  const handleSave = async () => {
    if (!selectedId) return;
    const policy = policies.find(p => p.id === selectedId);
    if (!policy) return;
    setSaving(true);
    setSaveStatus("idle");
    try {
      // Merge thresholds into rules — one rule per severity with threshold field
      const updatedRules = SEVERITY_LEVELS.map(sev => ({
        severity: sev,
        threshold: thresholds[sev] ?? 0,
        action: policy.decision_on_match,
      }));
      await apiPatch(`/api/v1/policies/${selectedId}`, { rules: updatedRules });
      setSaveStatus("success");
      // Refresh list to reflect changes
      void loadPolicies();
    } catch (e) {
      setSaveStatus("error");
    } finally {
      setSaving(false);
    }
  };

  if (loadingList) {
    return (
      <div className="flex items-center justify-center h-48 gap-2 text-muted-foreground">
        <Loader2 className="h-5 w-5 animate-spin" />
        <span className="text-sm">Loading policies…</span>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center h-48 gap-3 text-destructive">
        <AlertCircle className="h-6 w-6" />
        <p className="text-sm">{error}</p>
        <button
          onClick={() => void loadPolicies()}
          className="text-xs underline text-muted-foreground hover:text-foreground"
        >
          Retry
        </button>
      </div>
    );
  }

  if (policies.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-48 gap-2 text-muted-foreground">
        <Pencil className="h-8 w-8 opacity-30" />
        <p className="text-sm">No policies available. Create a policy first.</p>
      </div>
    );
  }

  const selectedPolicy = policies.find(p => p.id === selectedId);

  return (
    <div className="flex flex-col gap-4 max-w-2xl">
      {/* Policy picker */}
      <div className="flex flex-col gap-1.5">
        <label className="text-xs font-medium text-muted-foreground">Select Policy</label>
        <select
          value={selectedId}
          onChange={e => setSelectedId(e.target.value)}
          className="text-sm rounded-md bg-muted/40 border border-border/50 px-3 py-2 focus:outline-none focus:ring-1 focus:ring-primary"
        >
          {policies.map(p => (
            <option key={p.id} value={p.id}>
              {p.name} ({p.scope})
            </option>
          ))}
        </select>
      </div>

      {selectedPolicy && (
        <>
          {/* Policy meta */}
          <div className="rounded-lg border border-border/50 bg-muted/20 p-3 text-xs text-muted-foreground flex flex-wrap gap-4">
            <span>Scope: <strong className="text-foreground">{selectedPolicy.scope}</strong></span>
            <span>Language: <strong className="text-foreground">{selectedPolicy.language}</strong></span>
            <span>Decision: <strong className="text-foreground">{selectedPolicy.decision_on_match}</strong></span>
            <span>
              Status:{" "}
              <strong className={selectedPolicy.enabled ? "text-green-400" : "text-muted-foreground"}>
                {selectedPolicy.enabled ? "enabled" : "disabled"}
              </strong>
            </span>
          </div>

          {/* Threshold sliders */}
          <div className="rounded-lg border border-border/50 bg-card p-4 flex flex-col gap-4">
            <p className="text-xs font-medium">Per-Severity Thresholds</p>
            {SEVERITY_LEVELS.map(sev => {
              const colorMap: Record<Severity, string> = {
                critical: "text-red-400",
                high: "text-orange-400",
                medium: "text-amber-400",
                low: "text-blue-400",
                info: "text-slate-400",
              };
              return (
                <div key={sev} className="flex items-center gap-3">
                  <span className={`w-16 text-xs font-medium capitalize ${colorMap[sev]}`}>
                    {sev}
                  </span>
                  <input
                    type="range"
                    min={0}
                    max={100}
                    value={thresholds[sev] ?? 0}
                    onChange={e =>
                      setThresholds(prev => ({ ...prev, [sev]: Number(e.target.value) }))
                    }
                    className="flex-1 accent-primary"
                  />
                  <span className="w-8 text-xs tabular-nums text-right text-muted-foreground">
                    {thresholds[sev] ?? 0}
                  </span>
                </div>
              );
            })}
          </div>

          {/* Save button + status */}
          <div className="flex items-center gap-3">
            <button
              onClick={() => void handleSave()}
              disabled={saving}
              className="flex items-center gap-2 px-4 py-2 rounded-md bg-primary text-primary-foreground text-sm font-medium hover:bg-primary/90 disabled:opacity-50 transition-colors"
            >
              {saving ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Save className="h-4 w-4" />
              )}
              {saving ? "Saving…" : "Save Thresholds"}
            </button>

            <AnimatePresence>
              {saveStatus === "success" && (
                <motion.span
                  initial={{ opacity: 0, x: -8 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0 }}
                  className="flex items-center gap-1.5 text-xs text-green-400"
                >
                  <CheckCircle2 className="h-4 w-4" />
                  Saved
                </motion.span>
              )}
              {saveStatus === "error" && (
                <motion.span
                  initial={{ opacity: 0, x: -8 }}
                  animate={{ opacity: 1, x: 0 }}
                  exit={{ opacity: 0 }}
                  className="flex items-center gap-1.5 text-xs text-destructive"
                >
                  <AlertCircle className="h-4 w-4" />
                  Save failed
                </motion.span>
              )}
            </AnimatePresence>
          </div>
        </>
      )}
    </div>
  );
}

// ─────────────────────────────────────────────────────────────────────────────
// Hub shell
// ─────────────────────────────────────────────────────────────────────────────

type TabKey = "library" | "inheritance" | "stage-edit";

const TABS: Array<{
  key: TabKey;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  description: string;
}> = [
  {
    key: "library",
    label: "Library",
    icon: BookOpen,
    description:
      "Browseable catalogue of policy definitions with name search and tag filter chips derived from live data (Folded from PolicyLibraryBrowser).",
  },
  {
    key: "inheritance",
    label: "Inheritance",
    icon: Network,
    description:
      "Parent → child organisation tree showing which policies apply at each level, using the Wave-C parent_id field (Folded from PolicyInheritanceView).",
  },
  {
    key: "stage-edit",
    label: "Stage Editor",
    icon: Pencil,
    description:
      "Pick a policy, edit per-stage thresholds for each severity, validate the JSON and PATCH the policy back to the live store (Folded from PolicyStageEditor).",
  },
];

const VALID_TABS = new Set<TabKey>(TABS.map(t => t.key));

function isTabKey(v: string | null): v is TabKey {
  return !!v && VALID_TABS.has(v as TabKey);
}

export default function PolicyLifecycleHub() {
  const [params, setParams] = useSearchParams();
  const initial: TabKey = isTabKey(params.get("tab"))
    ? (params.get("tab") as TabKey)
    : "library";
  const [tab, setTab] = useState<TabKey>(initial);

  // Single effect: sync tab state <-> URL param without object-identity churn.
  // deps use params.toString() (primitive) — avoids infinite replaceState loop.
  useEffect(() => {
    const urlTab = params.get("tab");
    if (urlTab !== tab) {
      if (isTabKey(urlTab)) {
        setTab(urlTab);
      } else {
        const next = new URLSearchParams(params.toString());
        next.set("tab", tab);
        setParams(next, { replace: true });
      }
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [tab, params.toString()]);

  const activeMeta = useMemo(() => TABS.find(t => t.key === tab) ?? TABS[0], [tab]);

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      <PageHeader
        title="Policy Lifecycle"
        description="Unified policy-lifecycle hero — browseable catalogue, org inheritance tree, and per-stage threshold editor."
        badge={activeMeta.label}
      />

      <Tabs value={tab} onValueChange={v => setTab(v as TabKey)} className="w-full">
        <TabsList className="h-auto flex-wrap gap-1 bg-muted/40 p-1">
          {TABS.map(t => {
            const Icon = t.icon;
            return (
              <TabsTrigger key={t.key} value={t.key} className="text-xs gap-1.5">
                <Icon className="h-3.5 w-3.5" />
                {t.label}
              </TabsTrigger>
            );
          })}
        </TabsList>

        <p className="text-xs text-muted-foreground mt-2 mb-1">{activeMeta.description}</p>

        <TabsContent value="library">
          <PolicyLibraryPanel />
        </TabsContent>
        <TabsContent value="inheritance">
          <PolicyInheritancePanel />
        </TabsContent>
        <TabsContent value="stage-edit">
          <PolicyStageEditorPanel />
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
