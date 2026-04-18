/**
 * Vulnerability Intelligence Fusion Dashboard
 *
 * Multi-source CVE intelligence fusion — CVSS, EPSS, KEV, fusion scoring.
 *   1. KPI cards: total CVEs, KEV count (alert), critical count, avg fusion score
 *   2. CVE table (cvss badge, epss, kev badge, severity, fusion score bar, source count, affected assets)
 *   3. Source ingest panel (per-CVE source contributions)
 *   4. Asset impact table
 *   5. Priority queue (top 10 by fusion score)
 *   6. Ingest form
 *
 * API: /api/v1/vuln-intel-fusion
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  ShieldAlert, AlertTriangle, TrendingUp, Database, RefreshCw, Plus, Zap,
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
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "X-API-Key": API_KEY, "Content-Type": "application/json" },
    ...opts,
  });
  if (!res.ok) throw new Error(`API ${res.status}`);
  return res.json();
}

// ── Mock data ─────────────────────────────────────────────────────────────────

const MOCK_CVES = [
  { cve_id: "CVE-2024-3400",  cvss: 10.0, epss: 0.972, kev: true,  severity: "critical", fusion_score: 98, source_count: 5, affected_assets: 12 },
  { cve_id: "CVE-2024-21762", cvss: 9.8,  epss: 0.941, kev: true,  severity: "critical", fusion_score: 96, source_count: 4, affected_assets: 8  },
  { cve_id: "CVE-2024-6387",  cvss: 8.1,  epss: 0.887, kev: true,  severity: "high",     fusion_score: 91, source_count: 6, affected_assets: 34 },
  { cve_id: "CVE-2024-38063", cvss: 9.8,  epss: 0.621, kev: false, severity: "critical", fusion_score: 84, source_count: 3, affected_assets: 22 },
  { cve_id: "CVE-2024-49039", cvss: 8.8,  epss: 0.554, kev: false, severity: "high",     fusion_score: 79, source_count: 4, affected_assets: 15 },
  { cve_id: "CVE-2024-30051", cvss: 7.8,  epss: 0.812, kev: true,  severity: "high",     fusion_score: 87, source_count: 3, affected_assets: 19 },
  { cve_id: "CVE-2024-21338", cvss: 7.8,  epss: 0.432, kev: false, severity: "high",     fusion_score: 66, source_count: 2, affected_assets: 7  },
  { cve_id: "CVE-2024-0519",  cvss: 8.8,  epss: 0.712, kev: false, severity: "high",     fusion_score: 74, source_count: 3, affected_assets: 3  },
  { cve_id: "CVE-2023-48788", cvss: 9.8,  epss: 0.964, kev: true,  severity: "critical", fusion_score: 97, source_count: 5, affected_assets: 6  },
  { cve_id: "CVE-2023-22518", cvss: 9.1,  epss: 0.891, kev: true,  severity: "critical", fusion_score: 93, source_count: 4, affected_assets: 4  },
  { cve_id: "CVE-2024-1708",  cvss: 6.5,  epss: 0.281, kev: false, severity: "medium",   fusion_score: 48, source_count: 2, affected_assets: 2  },
  { cve_id: "CVE-2024-21893", cvss: 8.2,  epss: 0.523, kev: false, severity: "high",     fusion_score: 70, source_count: 3, affected_assets: 11 },
];

const MOCK_SOURCES: Record<string, any[]> = {
  "CVE-2024-3400": [
    { source_name: "NVD",     cvss: 10.0, epss: 0.972, kev: true,  vendor: "Palo Alto Networks", version: "PAN-OS < 11.1.2-h3" },
    { source_name: "CISA KEV",cvss: 10.0, epss: 0.972, kev: true,  vendor: "Palo Alto Networks", version: "all affected"       },
    { source_name: "GitHub",  cvss: 9.8,  epss: 0.951, kev: false, vendor: "Palo Alto Networks", version: "11.0.x"            },
    { source_name: "OSV.dev", cvss: 10.0, epss: 0.972, kev: false, vendor: "Palo Alto Networks", version: "PAN-OS"            },
    { source_name: "VulnDB",  cvss: 10.0, epss: 0.980, kev: true,  vendor: "Palo Alto Networks", version: "multiple"          },
  ],
  "CVE-2024-6387": [
    { source_name: "NVD",     cvss: 8.1,  epss: 0.887, kev: true,  vendor: "OpenBSD",    version: "OpenSSH < 9.8p1" },
    { source_name: "CISA KEV",cvss: 8.1,  epss: 0.887, kev: true,  vendor: "OpenBSD",    version: "all affected"    },
    { source_name: "GitHub",  cvss: 8.0,  epss: 0.860, kev: false, vendor: "OpenBSD",    version: "9.x"            },
    { source_name: "OSV.dev", cvss: 8.1,  epss: 0.887, kev: false, vendor: "OpenBSD",    version: "OpenSSH"        },
    { source_name: "VulnDB",  cvss: 8.2,  epss: 0.900, kev: false, vendor: "OpenBSD",    version: "multiple"       },
    { source_name: "RedHat",  cvss: 8.1,  epss: 0.880, kev: false, vendor: "OpenBSD",    version: "RHEL packages"  },
  ],
};

const MOCK_ASSETS: Record<string, any[]> = {
  "CVE-2024-3400":  [
    { asset_name: "fw-edge-01",    asset_type: "firewall",  business_impact: "critical", exploitable: true  },
    { asset_name: "fw-edge-02",    asset_type: "firewall",  business_impact: "critical", exploitable: true  },
    { asset_name: "fw-datacenter", asset_type: "firewall",  business_impact: "high",     exploitable: false },
  ],
  "CVE-2024-6387": [
    { asset_name: "bastion-01",    asset_type: "server",    business_impact: "critical", exploitable: true  },
    { asset_name: "ci-runner-03",  asset_type: "server",    business_impact: "high",     exploitable: true  },
    { asset_name: "k8s-node-07",   asset_type: "container", business_impact: "high",     exploitable: false },
  ],
};

const KEV_COUNT      = MOCK_CVES.filter(c => c.kev).length;
const CRITICAL_COUNT = MOCK_CVES.filter(c => c.severity === "critical").length;
const AVG_FUSION     = (MOCK_CVES.reduce((s, c) => s + c.fusion_score, 0) / MOCK_CVES.length).toFixed(1);
const PRIORITY_QUEUE = [...MOCK_CVES].sort((a, b) => b.fusion_score - a.fusion_score).slice(0, 10);

// ── Helpers ───────────────────────────────────────────────────────────────────

function CvssBadge({ score }: { score: number }) {
  const cls = score >= 9 ? "border-red-500/30 text-red-400 bg-red-500/10"
    : score >= 7 ? "border-orange-500/30 text-orange-400 bg-orange-500/10"
    : score >= 4 ? "border-yellow-500/30 text-yellow-400 bg-yellow-500/10"
    : "border-green-500/30 text-green-400 bg-green-500/10";
  return <Badge className={cn("text-[10px] border font-mono", cls)}>{score.toFixed(1)}</Badge>;
}

function SeverityBadge({ s }: { s: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
    medium:   "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    low:      "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[s] ?? "border-border text-muted-foreground")}>{s}</Badge>;
}

function ImpactBadge({ s }: { s: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-orange-500/30 text-orange-400 bg-orange-500/10",
    medium:   "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    low:      "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[s] ?? "border-border text-muted-foreground")}>{s}</Badge>;
}

function AssetTypeBadge({ t }: { t: string }) {
  return <Badge className="text-[10px] border border-blue-500/30 text-blue-400 bg-blue-500/10 capitalize">{t}</Badge>;
}

function FusionBar({ score }: { score: number }) {
  const color = score >= 90 ? "bg-red-500" : score >= 70 ? "bg-orange-500" : score >= 50 ? "bg-yellow-500" : "bg-green-500";
  return (
    <div className="flex items-center gap-2">
      {error && (
        <div className="bg-red-900/20 border border-red-500/30 rounded-lg p-4 flex items-center justify-between">
          <p className="text-red-400 text-sm">{error}</p>
          <button
            onClick={() => { setError(null); window.location.reload(); }}
            className="px-3 py-1 bg-red-600 hover:bg-red-700 text-white text-xs rounded transition-colors"
          >
            Retry
          </button>
        </div>
      )}
      <div className="flex-1 h-1.5 bg-muted rounded-full overflow-hidden">
        <div className={cn("h-full rounded-full", color)} style={{ width: `${score}%` }} />
      </div>
      <span className="text-[10px] font-semibold w-6 text-right">{score}</span>
    </div>
  );
}

// ── Component ─────────────────────────────────────────────────────────────────

export default function VulnIntelFusionDashboard() {
  const [selectedCve, setSelectedCve] = useState<string>("CVE-2024-3400");
  const [showForm, setShowForm] = useState(false);
  const [refreshing, setRefreshing] = useState(false);

  useEffect(() => {
    apiFetch(`/api/v1/vuln-intel-fusion/cves?org_id=${ORG_ID}`).catch(() => { setError('Failed to load data'); })
      .finally(() => setLoading(false));
  }, []);
  const [form, setForm] = useState({
  const [loading, setLoading] = useState(true);
    cve_id: "", source_name: "NVD", cvss: "", epss: "", kev: false, vendor: "", version: "",
  });

  const handleIngest = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await apiFetch(`/api/v1/vuln-intel-fusion/ingest?org_id=${ORG_ID}`, {
        method: "POST",
        body: JSON.stringify({ ...form, org_id: ORG_ID }),
      });
    } catch (_) {}
    setShowForm(false);
    setForm({ cve_id: "", source_name: "NVD", cvss: "", epss: "", kev: false, vendor: "", version: "" });
  };

  const sources = MOCK_SOURCES[selectedCve] ?? [];
  const assets  = MOCK_ASSETS[selectedCve] ?? [];

  if (loading) return (
    <div className="space-y-4 p-6">
      {[1, 2, 3].map((i) => (
        <div key={i} className="h-24 rounded-lg bg-zinc-800/50 animate-pulse" />
      ))}
    </div>
  );

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.3 }} className="flex flex-col gap-6">
      <PageHeader
        title="Vulnerability Intelligence Fusion"
        description="Multi-source CVE intelligence fusion — CVSS, EPSS, CISA KEV, and composite scoring"
        actions={
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={() => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); }} disabled={refreshing}>
              <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
            </Button>
            <Button size="sm" onClick={() => setShowForm(v => !v)}>
              <Plus className="h-4 w-4 mr-1" /> Ingest Source
            </Button>
          </div>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total CVEs"      value={MOCK_CVES.length} icon={Database}     trend="up" />
        <KpiCard title="CISA KEV"        value={KEV_COUNT}        icon={AlertTriangle} trend="up" className="border-red-500/20" />
        <KpiCard title="Critical Count"  value={CRITICAL_COUNT}   icon={ShieldAlert}   trend="flat" className="border-orange-500/20" />
        <KpiCard title="Avg Fusion Score" value={AVG_FUSION}      icon={TrendingUp}   trend="up" className="border-purple-500/20" />
      </div>

      {/* Ingest Form */}
      {showForm && (
        <Card className="border-blue-500/20">
          <CardHeader className="pb-3"><CardTitle className="text-sm font-semibold">Ingest CVE Intelligence Source</CardTitle></CardHeader>
          <CardContent>
            <form className="grid grid-cols-2 gap-3 md:grid-cols-4" onSubmit={handleIngest}>
              {[["cve_id","CVE ID"],["cvss","CVSS (0-10)"],["epss","EPSS (0-1)"],["vendor","Vendor"],["version","Version"]].map(([k, l]) => (
                <div key={k} className="flex flex-col gap-1">
                  <label className="text-[10px] text-muted-foreground">{l}</label>
                  <input className="h-8 rounded-md border border-border bg-background px-3 text-xs" value={(form as any)[k]} onChange={e => setForm(f => ({ ...f, [k]: e.target.value }))} required />
                </div>
              ))}
              <div className="flex flex-col gap-1">
                <label className="text-[10px] text-muted-foreground">Source</label>
                <select className="h-8 rounded-md border border-border bg-background px-3 text-xs" value={form.source_name} onChange={e => setForm(f => ({ ...f, source_name: e.target.value }))}>
                  {["NVD","CISA KEV","GitHub","OSV.dev","VulnDB","RedHat","Tenable","Qualys"].map(s => <option key={s} value={s}>{s}</option>)}
                </select>
              </div>
              <div className="flex flex-col gap-1 justify-end">
                <label className="text-[10px] text-muted-foreground">In CISA KEV?</label>
                <div className="flex items-center gap-2 h-8">
                  <input type="checkbox" checked={form.kev} onChange={e => setForm(f => ({ ...f, kev: e.target.checked }))} className="rounded" />
                  <span className="text-[11px]">{form.kev ? "Yes" : "No"}</span>
                </div>
              </div>
              <div className="col-span-2 md:col-span-4 flex gap-2 justify-end">
                <Button variant="outline" size="sm" type="button" onClick={() => setShowForm(false)}>Cancel</Button>
                <Button size="sm" type="submit">Ingest</Button>
              </div>
            </form>
          </CardContent>
        </Card>
      )}

      {/* CVE Table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-red-400" /> CVE Intelligence
            </CardTitle>
            <Badge className="text-[10px] border border-border text-muted-foreground">{MOCK_CVES.length} CVEs</Badge>
          </div>
          <CardDescription className="text-xs">Click a CVE to view source contributions and asset impact</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">CVE ID</TableHead>
                  <TableHead className="text-[11px] h-8">CVSS</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">EPSS</TableHead>
                  <TableHead className="text-[11px] h-8">KEV</TableHead>
                  <TableHead className="text-[11px] h-8">Severity</TableHead>
                  <TableHead className="text-[11px] h-8 min-w-[120px]">Fusion Score</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Sources</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Affected</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {MOCK_CVES.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  MOCK_CVES.map(c => (
                  <TableRow
                    key={c.cve_id}
                    className={cn("hover:bg-muted/30 cursor-pointer", selectedCve === c.cve_id && "bg-muted/20")}
                    onClick={() => setSelectedCve(c.cve_id)}
                  >
                    <TableCell className="py-2 font-mono text-[11px] text-blue-400 font-semibold">{c.cve_id}</TableCell>
                    <TableCell className="py-2"><CvssBadge score={c.cvss} /></TableCell>
                    <TableCell className="py-2 text-right text-[11px] text-muted-foreground">{(c.epss * 100).toFixed(1)}%</TableCell>
                    <TableCell className="py-2">
                      {c.kev
                        ? <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">KEV</Badge>
                        : <span className="text-[10px] text-muted-foreground">—</span>}
                    </TableCell>
                    <TableCell className="py-2"><SeverityBadge s={c.severity} /></TableCell>
                    <TableCell className="py-2 min-w-[120px]"><FusionBar score={c.fusion_score} /></TableCell>
                    <TableCell className="py-2 text-right text-[11px]">
                      <Badge className="text-[10px] border border-purple-500/30 text-purple-400 bg-purple-500/10">{c.source_count}</Badge>
                    </TableCell>
                    <TableCell className="py-2 text-right text-[11px] text-muted-foreground">{c.affected_assets}</TableCell>
                  </TableRow>
                ))}
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Source Contributions + Asset Impact side by side */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        {/* Source Ingest Panel */}
        <Card>
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <Database className="h-4 w-4 text-blue-400" /> Source Contributions
              </CardTitle>
              <Badge className="text-[10px] border border-blue-500/30 text-blue-400 bg-blue-500/10 font-mono">{selectedCve}</Badge>
            </div>
            <CardDescription className="text-xs">Intelligence sources contributing to fusion score</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            {sources.length > 0 ? (
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow className="hover:bg-transparent">
                      <TableHead className="text-[11px] h-8">Source</TableHead>
                      <TableHead className="text-[11px] h-8">CVSS</TableHead>
                      <TableHead className="text-[11px] h-8">EPSS</TableHead>
                      <TableHead className="text-[11px] h-8">KEV</TableHead>
                      <TableHead className="text-[11px] h-8">Vendor / Version</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {sources.length === 0 ? (
                      <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                        <p className="text-lg font-medium">No data available</p>
                        <p className="text-sm">Data will appear here once available</p>
                      </div>
                    ) : (
                      sources.map((s, i) => (
                      <TableRow key={i} className="hover:bg-muted/30">
                        <TableCell className="py-2 text-[11px] font-semibold">{s.source_name}</TableCell>
                        <TableCell className="py-2"><CvssBadge score={s.cvss} /></TableCell>
                        <TableCell className="py-2 text-[11px] text-muted-foreground">{(s.epss * 100).toFixed(1)}%</TableCell>
                        <TableCell className="py-2">
                          {s.kev
                            ? <Badge className="text-[9px] border border-red-500/30 text-red-400 bg-red-500/10">KEV</Badge>
                            : <span className="text-[10px] text-muted-foreground">—</span>}
                        </TableCell>
                        <TableCell className="py-2 text-[10px] text-muted-foreground">{s.vendor}<br /><span className="font-mono text-[9px]">{s.version}</span></TableCell>
                      </TableRow>
                    ))}
                    )}
                  </TableBody>
                </Table>
              </div>
            ) : (
              <p className="text-center text-xs text-muted-foreground py-8">No source data for {selectedCve}.</p>
            )}
          </CardContent>
        </Card>

        {/* Asset Impact */}
        <Card>
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <AlertTriangle className="h-4 w-4 text-orange-400" /> Asset Impact
              </CardTitle>
              <Badge className="text-[10px] border border-orange-500/30 text-orange-400 bg-orange-500/10 font-mono">{selectedCve}</Badge>
            </div>
            <CardDescription className="text-xs">Assets affected by the selected CVE</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            {assets.length > 0 ? (
              <div className="overflow-x-auto">
                <Table>
                  <TableHeader>
                    <TableRow className="hover:bg-transparent">
                      <TableHead className="text-[11px] h-8">Asset</TableHead>
                      <TableHead className="text-[11px] h-8">Type</TableHead>
                      <TableHead className="text-[11px] h-8">Business Impact</TableHead>
                      <TableHead className="text-[11px] h-8">Exploitable</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {assets.length === 0 ? (
                      <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                        <p className="text-lg font-medium">No data available</p>
                        <p className="text-sm">Data will appear here once available</p>
                      </div>
                    ) : (
                      assets.map((a, i) => (
                      <TableRow key={i} className="hover:bg-muted/30">
                        <TableCell className="py-2 font-mono text-[11px]">{a.asset_name}</TableCell>
                        <TableCell className="py-2"><AssetTypeBadge t={a.asset_type} /></TableCell>
                        <TableCell className="py-2"><ImpactBadge s={a.business_impact} /></TableCell>
                        <TableCell className="py-2">
                          <Badge className={cn("text-[10px] border", a.exploitable ? "border-red-500/30 text-red-400 bg-red-500/10" : "border-green-500/30 text-green-400 bg-green-500/10")}>
                            {a.exploitable ? "yes" : "no"}
                          </Badge>
                        </TableCell>
                      </TableRow>
                    ))}
                    )}
                  </TableBody>
                </Table>
              </div>
            ) : (
              <p className="text-center text-xs text-muted-foreground py-8">No asset impact data for {selectedCve}.</p>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Priority Queue */}
      <Card className="border-red-500/10">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
              <Zap className="h-4 w-4" /> Remediation Priority Queue
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">top 10 by fusion score</Badge>
          </div>
          <CardDescription className="text-xs">Ordered by composite fusion score — address in this sequence</CardDescription>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            {PRIORITY_QUEUE.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                <p className="text-lg font-medium">No data available</p>
                <p className="text-sm">Data will appear here once available</p>
              </div>
            ) : (
              PRIORITY_QUEUE.map((c, i) => (
              <div
                key={c.cve_id}
                className={cn(
                  "flex items-center gap-3 rounded-lg border px-3 py-2 cursor-pointer hover:bg-muted/30 transition-colors",
                  selectedCve === c.cve_id ? "border-blue-500/40 bg-blue-500/5" : "border-border"
                )}
                onClick={() => setSelectedCve(c.cve_id)}
              >
                <span className={cn(
                  "text-[11px] font-bold w-5 shrink-0 text-center",
                  i < 3 ? "text-red-400" : i < 6 ? "text-orange-400" : "text-muted-foreground"
                )}>#{i + 1}</span>
                <span className="font-mono text-[11px] text-blue-400 w-36 shrink-0">{c.cve_id}</span>
                <div className="flex-1"><FusionBar score={c.fusion_score} /></div>
                <div className="flex items-center gap-1.5 shrink-0">
                  <CvssBadge score={c.cvss} />
                  {c.kev && <Badge className="text-[9px] border border-red-500/30 text-red-400 bg-red-500/10">KEV</Badge>}
                  <SeverityBadge s={c.severity} />
                </div>
                <span className="text-[10px] text-muted-foreground shrink-0">{c.affected_assets} assets</span>
              </div>
            ))}
            )}
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
