/**
 * Cyber Threat Modeling Dashboard
 *
 * Threat models with STRIDE/PASTA/MITRE attack trees, mitigations, risk scoring.
 *   1. KPI cards: Total Models, Critical Models, Avg Risk Score, Unmitigated Trees
 *   2. Model list table
 *   3. Attack tree viewer with mitigate action
 *   4. Add model / add tree forms
 *
 * API: /api/v1/cyber-threat-models
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  GitBranch, ShieldAlert, CheckCircle2, XCircle, RefreshCw, Plus, Target,
} from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string, opts?: RequestInit) {
  const res = await fetch(`${API_BASE}${path}?org_id=default`, {
    headers: { "X-API-Key": API_KEY, "Content-Type": "application/json" },
    ...opts,
  });
  if (!res.ok) throw new Error(`API ${res.status}`);
  return res.json();
}

// ── Mock data ─────────────────────────────────────────────────────────────────

const MOCK_MODELS = [
  { id: "m1", model_name: "Payment Processing System", scope: "application", methodology: "STRIDE", risk_score: 3.8, risk_level: "critical", threat_count: 12, mitigated_count: 7, created_at: "2026-03-10" },
  { id: "m2", model_name: "Customer Data API", scope: "api", methodology: "MITRE", risk_score: 3.2, risk_level: "high", threat_count: 9, mitigated_count: 9, created_at: "2026-03-15" },
  { id: "m3", model_name: "Cloud IAM Architecture", scope: "infrastructure", methodology: "PASTA", risk_score: 2.9, risk_level: "high", threat_count: 8, mitigated_count: 5, created_at: "2026-03-22" },
  { id: "m4", model_name: "CI/CD Pipeline", scope: "devops", methodology: "STRIDE", risk_score: 3.5, risk_level: "critical", threat_count: 11, mitigated_count: 4, created_at: "2026-04-01" },
  { id: "m5", model_name: "Employee Onboarding Portal", scope: "application", methodology: "STRIDE", risk_score: 1.8, risk_level: "medium", threat_count: 6, mitigated_count: 6, created_at: "2026-04-08" },
  { id: "m6", model_name: "Network Segmentation Design", scope: "network", methodology: "MITRE", risk_score: 2.4, risk_level: "medium", threat_count: 7, mitigated_count: 7, created_at: "2026-04-12" },
];

const MOCK_TREES = [
  { id: "t1", model_id: "m1", tree_name: "Card Data Exfiltration", likelihood: "high", impact: "critical", risk_level: "critical", mitigated: false, path_steps: ["Attacker recon", "SQL injection probe", "ORM bypass", "Data dump via outbound HTTPS"], target_assets: ["payment-db", "pci-vault"], tactics: ["Initial Access", "Exfiltration"] },
  { id: "t2", model_id: "m1", tree_name: "Replay Attack on 3DS", likelihood: "medium", impact: "high", risk_level: "high", mitigated: true, path_steps: ["Intercept TLS", "Capture nonce", "Replay 3DS token"], target_assets: ["3ds-service"], tactics: ["Credential Access"] },
  { id: "t3", model_id: "m3", tree_name: "Privilege Escalation via Assume Role", likelihood: "high", impact: "critical", risk_level: "critical", mitigated: false, path_steps: ["Compromise EC2 instance", "Read IAM metadata", "AssumeRole to admin"], target_assets: ["aws-iam", "ec2-fleet"], tactics: ["Privilege Escalation", "Lateral Movement"] },
  { id: "t4", model_id: "m4", tree_name: "Malicious Pipeline Injection", likelihood: "medium", impact: "critical", risk_level: "critical", mitigated: false, path_steps: ["Fork repo", "Inject shell command", "Wait for PR merge", "Execute in build context"], target_assets: ["github-actions", "artifact-registry"], tactics: ["Execution", "Persistence"] },
  { id: "t5", model_id: "m2", tree_name: "BOLA on User Records", likelihood: "high", impact: "high", risk_level: "high", mitigated: true, path_steps: ["Enumerate user IDs", "Direct object reference", "Retrieve foreign records"], target_assets: ["user-api"], tactics: ["Discovery", "Collection"] },
  { id: "t6", model_id: "m4", tree_name: "Secrets in Environment Variables", likelihood: "high", impact: "high", risk_level: "high", mitigated: false, path_steps: ["Read pipeline logs", "Extract env vars", "Use credentials offline"], target_assets: ["ci-secrets", "prod-db"], tactics: ["Credential Access"] },
];

const CRITICAL_MODELS = MOCK_MODELS.filter(m => m.risk_level === "critical").length;
const AVG_RISK = (MOCK_MODELS.reduce((s, m) => s + m.risk_score, 0) / MOCK_MODELS.length).toFixed(1);
const UNMITIGATED = MOCK_TREES.filter(t => !t.mitigated).length;

// ── Helpers ───────────────────────────────────────────────────────────────────

function RiskBadge({ level }: { level: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
    medium:   "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    low:      "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[level] ?? "border-border text-muted-foreground")}>{level}</Badge>;
}

function MethodBadge({ m }: { m: string }) {
  const map: Record<string, string> = {
    STRIDE: "border-blue-500/30 text-blue-400 bg-blue-500/10",
    PASTA:  "border-purple-500/30 text-purple-400 bg-purple-500/10",
    MITRE:  "border-red-500/30 text-red-400 bg-red-500/10",
  };
  return <Badge className={cn("text-[10px] border font-mono", map[m] ?? "border-border text-muted-foreground")}>{m}</Badge>;
}

function ScopeBadge({ s }: { s: string }) {
  return <Badge className="text-[10px] border border-cyan-500/30 text-cyan-400 bg-cyan-500/10 capitalize">{s}</Badge>;
}

function LikelihoodBadge({ l }: { l: string }) {
  const map: Record<string, string> = {
    high:   "border-orange-500/30 text-orange-400 bg-orange-500/10",
    medium: "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    low:    "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[l] ?? "border-border text-muted-foreground")}>{l}</Badge>;
}

function RiskGauge({ score }: { score: number }) {
  const pct = (score / 4) * 100;
  const color = score >= 3.5 ? "bg-red-500" : score >= 2.5 ? "bg-orange-500" : score >= 1.5 ? "bg-yellow-500" : "bg-green-500";
  return (
    <div className="flex items-center gap-2">
      <div className="w-16 h-1.5 bg-muted rounded-full overflow-hidden">
        <div className={cn("h-full rounded-full", color)} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-[11px] font-semibold">{score}</span>
    </div>
  );
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function CyberThreatModelingDashboard() {
  const [selectedModel, setSelectedModel] = useState<string>("all");
  const [loading, setLoading] = useState(true);
  const [mitigatedTrees, setMitigatedTrees] = useState<Set<string>>(
    new Set(MOCK_TREES.filter(t => t.mitigated).map(t => t.id))
  );
  const [showModelForm, setShowModelForm] = useState(false);
  const [showTreeForm, setShowTreeForm] = useState(false);
  const [refreshing, setRefreshing] = useState(false);

  useEffect(() => {
    apiFetch(`/api/v1/cyber-threat-models/summary?org_id=${ORG_ID}`).catch((e) => setError(e?.message || 'Failed to load data'))
      .finally(() => setLoading(false));
  }, []);
  const [modelForm, setModelForm] = useState({ model_name: "", scope: "application", methodology: "STRIDE", risk_level: "high" });
  const [treeForm, setTreeForm] = useState({ tree_name: "", model_id: "m1", likelihood: "medium", impact: "high", risk_level: "high" });
  const [error, setError] = useState<string | null>(null);

  const handleMitigate = async (treeId: string) => {
    try {
      await apiFetch(`/api/v1/cyber-threat-models/trees/${treeId}/mitigate?org_id=${ORG_ID}`, { method: "POST" });
    } catch (_) { /* mock */ }
    setMitigatedTrees(s => new Set([...s, treeId]));
  };

  const visibleTrees = selectedModel === "all"
    ? MOCK_TREES
    : MOCK_TREES.filter(t => t.model_id === selectedModel);

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Cyber Threat Modeling"
        description="STRIDE, PASTA, and MITRE ATT&CK–based threat models with attack tree analysis"
        actions={
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={() => setRefreshing(v => { setTimeout(() => setRefreshing(false), 800); return true; })} disabled={refreshing}>
              <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
            </Button>
            <Button size="sm" variant="outline" onClick={() => setShowTreeForm(v => !v)}>
              <Plus className="h-4 w-4 mr-1" /> Tree
            </Button>
            <Button size="sm" onClick={() => setShowModelForm(v => !v)}>
              <Plus className="h-4 w-4 mr-1" /> Model
            </Button>
          </div>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Models"     value={MOCK_MODELS.length} icon={GitBranch}  trend="up" />
        <KpiCard title="Critical Models"  value={CRITICAL_MODELS}    icon={ShieldAlert} trend="flat" className="border-red-500/20" />
        <KpiCard title="Avg Risk Score"   value={`${AVG_RISK}/4`}    icon={Target}      trend="down" className="border-orange-500/20" />
        <KpiCard title="Unmitigated Trees" value={UNMITIGATED}        icon={XCircle}    trend="down" className="border-red-500/20" />
      </div>

      {/* Add Model Form */}
      {showModelForm && (
        <Card className="border-blue-500/20">
          <CardHeader className="pb-3"><CardTitle className="text-sm font-semibold">New Threat Model</CardTitle></CardHeader>
          <CardContent>
            <form className="grid grid-cols-2 gap-3 md:grid-cols-4" onSubmit={async e => {
              e.preventDefault();
              try { await apiFetch(`/api/v1/cyber-threat-models/models?org_id=${ORG_ID}`, { method: "POST", body: JSON.stringify({ ...modelForm, org_id: ORG_ID }) }); } catch (_) {}
              setShowModelForm(false);
            }}>
              <div className="flex flex-col gap-1 col-span-2">
                <label className="text-[10px] text-muted-foreground">Model Name</label>
                <input className="h-8 rounded-md border border-border bg-background px-3 text-xs" value={modelForm.model_name} onChange={e => setModelForm(f => ({ ...f, model_name: e.target.value }))} required />
              </div>
              {[["scope","Scope",["application","api","infrastructure","devops","network"]],["methodology","Methodology",["STRIDE","PASTA","MITRE"]],["risk_level","Risk Level",["critical","high","medium","low"]]].map(([k, label, opts]) => (
                <div key={k as string} className="flex flex-col gap-1">
                  <label className="text-[10px] text-muted-foreground">{label as string}</label>
                  <select className="h-8 rounded-md border border-border bg-background px-3 text-xs" value={(modelForm as any)[k as string]} onChange={e => setModelForm(f => ({ ...f, [k as string]: e.target.value }))}>
                    {(opts as string[]).map(o => <option key={o} value={o}>{o}</option>)}
                  </select>
                </div>
              ))}
              <div className="col-span-2 md:col-span-4 flex gap-2 justify-end">
                <Button variant="outline" size="sm" type="button" onClick={() => setShowModelForm(false)}>Cancel</Button>
                <Button size="sm" type="submit">Create Model</Button>
              </div>
            </form>
          </CardContent>
        </Card>
      )}

      {/* Add Tree Form */}
      {showTreeForm && (
        <Card className="border-purple-500/20">
          <CardHeader className="pb-3"><CardTitle className="text-sm font-semibold">New Attack Tree</CardTitle></CardHeader>
          <CardContent>
            <form className="grid grid-cols-2 gap-3 md:grid-cols-4" onSubmit={async e => {
              e.preventDefault();
              try { await apiFetch(`/api/v1/cyber-threat-models/trees?org_id=${ORG_ID}`, { method: "POST", body: JSON.stringify({ ...treeForm, org_id: ORG_ID }) }); } catch (_) {}
              setShowTreeForm(false);
            }}>
              <div className="flex flex-col gap-1 col-span-2">
                <label className="text-[10px] text-muted-foreground">Tree Name</label>
                <input className="h-8 rounded-md border border-border bg-background px-3 text-xs" value={treeForm.tree_name} onChange={e => setTreeForm(f => ({ ...f, tree_name: e.target.value }))} required />
              </div>
              {[["model_id","Model",MOCK_MODELS.map(m => m.id)],["likelihood","Likelihood",["high","medium","low"]],["impact","Impact",["critical","high","medium","low"]],["risk_level","Risk Level",["critical","high","medium","low"]]].map(([k, label, opts]) => (
                <div key={k as string} className="flex flex-col gap-1">
                  <label className="text-[10px] text-muted-foreground">{label as string}</label>
                  <select className="h-8 rounded-md border border-border bg-background px-3 text-xs" value={(treeForm as any)[k as string]} onChange={e => setTreeForm(f => ({ ...f, [k as string]: e.target.value }))}>
                    {(opts as string[]).map(o => <option key={o} value={o}>{o}</option>)}
                  </select>
                </div>
              ))}
              <div className="col-span-2 md:col-span-4 flex gap-2 justify-end">
                <Button variant="outline" size="sm" type="button" onClick={() => setShowTreeForm(false)}>Cancel</Button>
                <Button size="sm" type="submit">Create Tree</Button>
              </div>
            </form>
          </CardContent>
        </Card>
      )}

      {/* Model List */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <GitBranch className="h-4 w-4 text-blue-400" /> Threat Models
            </CardTitle>
            <Badge className="text-[10px] border border-border text-muted-foreground">{MOCK_MODELS.length} models</Badge>
          </div>
          <CardDescription className="text-xs">Click a model to filter attack trees below</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Model</TableHead>
                  <TableHead className="text-[11px] h-8">Scope</TableHead>
                  <TableHead className="text-[11px] h-8">Methodology</TableHead>
                  <TableHead className="text-[11px] h-8">Risk Score</TableHead>
                  <TableHead className="text-[11px] h-8">Risk Level</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Threats</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Mitigated</TableHead>
                  <TableHead className="text-[11px] h-8">Created</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {MOCK_MODELS.map(m => {
                  const hasUnmitigated = m.mitigated_count < m.threat_count;
                  return (
                    <TableRow
                      key={m.id}
                      className={cn("hover:bg-muted/30 cursor-pointer", selectedModel === m.id && "bg-muted/20")}
                      onClick={() => setSelectedModel(f => f === m.id ? "all" : m.id)}
                    >
                      <TableCell className="py-2 text-[11px] font-medium">{m.model_name}</TableCell>
                      <TableCell className="py-2"><ScopeBadge s={m.scope} /></TableCell>
                      <TableCell className="py-2"><MethodBadge m={m.methodology} /></TableCell>
                      <TableCell className="py-2"><RiskGauge score={m.risk_score} /></TableCell>
                      <TableCell className="py-2"><RiskBadge level={m.risk_level} /></TableCell>
                      <TableCell className="py-2 text-right text-[11px]">{m.threat_count}</TableCell>
                      <TableCell className="py-2 text-right text-[11px]">
                        <span className={cn(m.mitigated_count === m.threat_count ? "text-green-400" : "text-amber-400")}>
                          {m.mitigated_count}/{m.threat_count}
                        </span>
                        {hasUnmitigated && <Badge className="ml-1 text-[9px] border border-red-500/30 text-red-400 bg-red-500/10">!</Badge>}
                      </TableCell>
                      <TableCell className="py-2 text-[11px] text-muted-foreground">{m.created_at}</TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Attack Tree Viewer */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-red-400" /> Attack Trees
              {selectedModel !== "all" && (
                <Badge className="text-[10px] border border-blue-500/30 text-blue-400 bg-blue-500/10">
                  {MOCK_MODELS.find(m => m.id === selectedModel)?.model_name}
                </Badge>
              )}
            </CardTitle>
            <Badge className="text-[10px] border border-border text-muted-foreground">{visibleTrees.length} trees</Badge>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          {visibleTrees.map(tree => {
            const isMitigated = mitigatedTrees.has(tree.id);

            if (loading) return <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div></div>;

            return (
              <div key={tree.id} className={cn("rounded-lg border p-4 space-y-3", isMitigated ? "border-green-500/20 bg-green-500/5" : "border-red-500/20 bg-red-500/5")}>
                <div className="flex items-start justify-between gap-2">
                  <div className="flex items-center gap-2">
                    {isMitigated
                      ? <CheckCircle2 className="h-4 w-4 text-green-400 shrink-0" />
                      : <XCircle className="h-4 w-4 text-red-400 shrink-0" />}
                    <span className="text-[12px] font-semibold">{tree.tree_name}</span>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    <LikelihoodBadge l={tree.likelihood} />
                    <RiskBadge level={tree.risk_level} />
                    {!isMitigated && (
                      <Button size="sm" className="h-6 text-[10px] px-2" onClick={() => handleMitigate(tree.id)}>
                        Mitigate
                      </Button>
                    )}
                  </div>
                </div>
                {/* Path steps */}
                <div className="flex flex-wrap items-center gap-1">
                  {tree.path_steps.map((step, i) => (
                    <span key={i} className="flex items-center gap-1">
                      <span className="text-[10px] bg-muted px-2 py-0.5 rounded text-foreground/80">{step}</span>
                      {i < tree.path_steps.length - 1 && <span className="text-muted-foreground text-[10px]">→</span>}
                    </span>
                  ))}
                </div>
                {/* Assets + Tactics */}
                <div className="flex flex-wrap gap-3">
                  <div className="flex flex-wrap gap-1 items-center">
                    <span className="text-[9px] text-muted-foreground uppercase tracking-wide">Assets:</span>
                    {tree.target_assets.map(a => (
                      <Badge key={a} className="text-[9px] border border-blue-500/20 text-blue-300 bg-blue-500/5">{a}</Badge>
                    ))}
                  </div>
                  <div className="flex flex-wrap gap-1 items-center">
                    <span className="text-[9px] text-muted-foreground uppercase tracking-wide">Tactics:</span>
                    {tree.tactics.map(t => (
                      <Badge key={t} className="text-[9px] border border-purple-500/20 text-purple-300 bg-purple-500/5">{t}</Badge>
                    ))}
                  </div>
                </div>
              </div>
            );
          })}
          {visibleTrees.length === 0 && (
            <p className="text-center text-xs text-muted-foreground py-8">No attack trees for selected model.</p>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}
