/**
 * Dynamic Rule DSL Dashboard
 *
 * Editable DSL for writing security detection rules. Load schema, browse
 * existing rules, edit/save and see stats.
 * Route: /dynamic-rule-dsl
 * API: GET /api/v1/rules/dsl/stats, /rules, /schema
 */

import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Code2, RefreshCw, Save, Play, Library, BookOpen } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Textarea } from "@/components/ui/textarea";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { cn } from "@/lib/utils";

interface Stats {
  total_rules?: number;
  active_rules?: number;
  matches_24h?: number;
  last_edit?: string;
}

interface Rule {
  id?: string;
  rule_id?: string;
  name?: string;
  dsl?: string;
  body?: string;
  enabled?: boolean;
  severity?: string;
  matches_count?: number;
  updated_at?: string;
}

interface SchemaField {
  name?: string;
  type?: string;
  description?: string;
  example?: string;
}

interface Schema {
  version?: string;
  fields?: SchemaField[];
  operators?: string[];
  functions?: string[];
}

async function apiFetch<T>(path: string, opts: RequestInit = {}): Promise<T> {
  const res = await fetch(buildApiUrl(path), {
    ...opts,
    headers: {
      "X-API-Key": getStoredAuthToken(),
      "X-Org-ID": getStoredOrgId(),
      "Content-Type": "application/json",
      ...(opts.headers ?? {}),
    },
  });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

const DEFAULT_DSL = `rule "Suspicious Admin Login"
  when
    event.type == "login"
    and user.role == "admin"
    and event.hour not in [9..17]
    and geo.country != home_country()
  then
    severity: high
    alert: "Off-hours admin login from unusual location"
end`;

function sevColor(s?: string) {
  const k = (s ?? "").toLowerCase();
  if (k === "critical") return "border-red-500/30 text-red-300 bg-red-500/10";
  if (k === "high")     return "border-orange-500/30 text-orange-300 bg-orange-500/10";
  if (k === "medium")   return "border-yellow-500/30 text-yellow-300 bg-yellow-500/10";
  return "border-green-500/30 text-green-300 bg-green-500/10";
}

function formatTs(ts?: string) {
  if (!ts) return "—";
  try { return new Date(ts).toLocaleString(undefined, { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" }); }
  catch { return ts; }
}

export default function DynamicRuleDSLDashboard() {
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [err, setErr] = useState<string | null>(null);
  const [stats, setStats] = useState<Stats | null>(null);
  const [rules, setRules] = useState<Rule[]>([]);
  const [schema, setSchema] = useState<Schema | null>(null);
  const [dsl, setDsl] = useState(DEFAULT_DSL);
  const [name, setName] = useState("My Custom Rule");
  const [testResult, setTestResult] = useState<{ ok?: boolean; matches?: number; error?: string } | null>(null);

  const load = async () => {
    setErr(null);
    setRefreshing(true);
    try {
      const [s, r, sc] = await Promise.allSettled([
        apiFetch<Stats>("/api/v1/rules/dsl/stats"),
        apiFetch<Rule[] | { rules?: Rule[]; items?: Rule[] }>("/api/v1/rules/dsl/rules"),
        apiFetch<Schema>("/api/v1/rules/dsl/schema"),
      ]);
      setStats(s.status === "fulfilled" ? s.value : null);
      if (r.status === "fulfilled") {
        const v = r.value;
        setRules(Array.isArray(v) ? v : (v.rules ?? v.items ?? []));
      } else { setRules([]); }
      setSchema(sc.status === "fulfilled" ? sc.value : null);
    } catch (e) { setErr((e as Error).message); }
    finally { setLoading(false); setRefreshing(false); }
  };

  useEffect(() => { load(); }, []);

  const handleSave = async () => {
    if (!dsl.trim() || !name.trim()) return;
    setSaving(true);
    try {
      await apiFetch("/api/v1/rules/dsl/rules", {
        method: "POST",
        body: JSON.stringify({ name: name.trim(), dsl }),
      });
      await load();
    } catch (e) { setErr((e as Error).message); }
    finally { setSaving(false); }
  };

  const handleTest = async () => {
    setTesting(true);
    setTestResult(null);
    try {
      const r = await apiFetch<{ ok?: boolean; matches?: number; error?: string }>(
        "/api/v1/rules/dsl/test",
        { method: "POST", body: JSON.stringify({ dsl }) }
      );
      setTestResult(r);
    } catch (e) {
      setTestResult({ ok: false, error: (e as Error).message });
    } finally { setTesting(false); }
  };

  const loadRule = (r: Rule) => {
    setName(r.name ?? "Untitled");
    setDsl(r.dsl ?? r.body ?? "");
    setTestResult(null);
  };

  const totalRules = stats?.total_rules ?? rules.length;
  const activeRules = stats?.active_rules ?? rules.filter(r => r.enabled).length;
  const matches24h = stats?.matches_24h ?? 0;

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Dynamic Rule DSL"
        description="Author security detection rules in a purpose-built DSL — live schema, test, save, deploy"
        actions={
          <Button variant="outline" size="sm" onClick={load} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Rules" value={totalRules} icon={Code2} />
        <KpiCard title="Active" value={activeRules} icon={Play} trend="up" />
        <KpiCard title="Matches (24h)" value={matches24h} icon={Library} />
        <KpiCard title="Last Edit" value={formatTs(stats?.last_edit)} icon={Save} />
      </div>

      <div className="grid grid-cols-1 gap-4 xl:grid-cols-4">
        {/* DSL Editor (3 cols) */}
        <Card className="xl:col-span-3">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2"><Code2 className="h-4 w-4" /> Rule Editor</CardTitle>
            <CardDescription className="text-xs">Write detection rules using the ALdeci DSL</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div>
              <label className="text-xs font-medium text-muted-foreground">Rule Name</label>
              <input
                value={name}
                onChange={e => setName(e.target.value)}
                className="mt-1 w-full rounded border border-border bg-background px-2 py-1.5 text-xs font-mono"
                placeholder="e.g. Suspicious Admin Login"
              />
            </div>
            <div>
              <label className="text-xs font-medium text-muted-foreground">DSL</label>
              <Textarea
                value={dsl}
                onChange={e => setDsl(e.target.value)}
                rows={14}
                className="mt-1 font-mono text-xs leading-relaxed"
                spellCheck={false}
              />
            </div>
            <div className="flex items-center gap-2">
              <Button size="sm" variant="outline" onClick={handleTest} disabled={testing || !dsl.trim()}>
                <Play className={cn("h-4 w-4 mr-2", testing && "animate-pulse")} />
                Test
              </Button>
              <Button size="sm" onClick={handleSave} disabled={saving || !dsl.trim() || !name.trim()}>
                <Save className={cn("h-4 w-4 mr-2", saving && "animate-pulse")} />
                Save Rule
              </Button>
              {testResult && (
                testResult.error ? (
                  <Badge className="text-[10px] border border-red-500/30 text-red-300 bg-red-500/10">Error</Badge>
                ) : (
                  <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">
                    {testResult.matches ?? 0} matches
                  </Badge>
                )
              )}
            </div>
            {testResult?.error && (
              <div className="rounded border border-red-500/30 bg-red-500/10 p-3 text-xs font-mono text-red-400">{testResult.error}</div>
            )}
          </CardContent>
        </Card>

        {/* Schema + Rules list (1 col) */}
        <div className="flex flex-col gap-4">
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold flex items-center gap-2"><BookOpen className="h-4 w-4" /> Schema</CardTitle>
              <CardDescription className="text-xs">{schema?.version ? `v${schema.version}` : "Available fields & operators"}</CardDescription>
            </CardHeader>
            <CardContent>
              {loading ? (
                <div className="text-xs text-muted-foreground">Loading…</div>
              ) : err ? (
                <ErrorState message={err} onRetry={load} />
              ) : !schema || (!schema.fields?.length && !schema.operators?.length) ? (
                <EmptyState icon={BookOpen} title="No schema" description="Schema not yet available." />
              ) : (
                <div className="max-h-64 overflow-y-auto space-y-2">
                  {(schema.fields ?? []).map((f, i) => (
                    <div key={i} className="rounded border border-border/50 bg-muted/20 p-2 text-[11px]">
                      <div className="flex items-center justify-between">
                        <span className="font-mono font-semibold">{f.name}</span>
                        <span className="text-muted-foreground">{f.type}</span>
                      </div>
                      {f.description && <div className="text-muted-foreground mt-1">{f.description}</div>}
                    </div>
                  ))}
                  {(schema.operators ?? []).length > 0 && (
                    <div className="pt-2">
                      <div className="text-[10px] font-semibold uppercase text-muted-foreground mb-1">Operators</div>
                      <div className="flex flex-wrap gap-1">
                        {(schema.operators ?? []).map(o => (
                          <span key={o} className="text-[10px] font-mono rounded bg-muted px-1.5 py-0.5">{o}</span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-semibold flex items-center gap-2"><Library className="h-4 w-4" /> Saved Rules</CardTitle>
            </CardHeader>
            <CardContent>
              {rules.length === 0 ? (
                <EmptyState icon={Library} title="No rules" description="Your saved rules will appear here." />
              ) : (
                <div className="max-h-64 overflow-y-auto space-y-1">
                  {rules.map((r, i) => (
                    <button
                      key={r.id ?? r.rule_id ?? i}
                      onClick={() => loadRule(r)}
                      className="w-full text-left rounded border border-border/50 bg-muted/20 px-2 py-1.5 text-[11px] hover:bg-muted/40 transition-colors"
                    >
                      <div className="flex items-center justify-between">
                        <span className="font-medium truncate">{r.name ?? "Untitled"}</span>
                        {r.severity && <Badge className={cn("text-[10px] border capitalize", sevColor(r.severity))}>{r.severity}</Badge>}
                      </div>
                      <div className="text-muted-foreground flex items-center gap-2 mt-0.5">
                        {r.enabled ? <span className="text-green-400">● active</span> : <span>○ disabled</span>}
                        <span>· {r.matches_count ?? 0} matches</span>
                      </div>
                    </button>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      </div>
    </motion.div>
  );
}
