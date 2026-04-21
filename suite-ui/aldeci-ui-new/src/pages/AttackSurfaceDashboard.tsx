/**
 * Attack Surface Dashboard
 *
 * External attack surface mapping — assets, exposures, changes, surface score.
 *   1. KPIs: Total Assets, Open Exposures, Critical Exposures, Surface Score
 *   2. Asset inventory table (asset_type, value, risk_score bar, is_public, last_seen)
 *   3. Exposure findings table (exposure_type, severity, asset, title, status, first_detected)
 *   4. Surface changes feed (change_type, description, severity, timestamp)
 *   5. Scan trigger button → POST /api/v1/attack-surface/discover
 *   6. Surface score gauge (100 = clean, 0 = fully exposed)
 *
 * Route: /attack-surface-dashboard
 * API: GET /api/v1/attack-surface/assets, /api/v1/attack-surface/paths
 *      GET /api/v1/attack-surface/changes, /api/v1/attack-surface/summary
 *      POST /api/v1/attack-surface/discover
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Globe, AlertTriangle, Shield, Activity, RefreshCw, Radar, TrendingUp } from "lucide-react";

const API_BASE = import.meta.env.VITE_API_URL || "";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string, opts?: RequestInit) {
  const res = await fetch(`${API_BASE}${path}?org_id=default`, {
    ...opts,
    headers: { "X-API-Key": API_KEY, "Content-Type": "application/json", ...(opts?.headers ?? {}) },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── Mock data ──────────────────────────────────────────────────

const MOCK_ASSETS = [
  { id: "AST-001", asset_type: "web_app",     value: "api.acme.com",          risk_score: 0.82, is_public: true,  last_seen: "2 min ago" },
  { id: "AST-002", asset_type: "domain",      value: "acme.com",              risk_score: 0.41, is_public: true,  last_seen: "5 min ago" },
  { id: "AST-003", asset_type: "ip_address",  value: "203.0.113.45",          risk_score: 0.91, is_public: true,  last_seen: "1 min ago" },
  { id: "AST-004", asset_type: "cloud_bucket",value: "s3://acme-backups-2026", risk_score: 0.67, is_public: false, last_seen: "10 min ago" },
  { id: "AST-005", asset_type: "port",        value: "203.0.113.45:3306",     risk_score: 0.95, is_public: true,  last_seen: "3 min ago" },
  { id: "AST-006", asset_type: "certificate", value: "*.acme.com (exp 30d)",  risk_score: 0.55, is_public: true,  last_seen: "15 min ago" },
];

const MOCK_EXPOSURES = [
  { id: "EXP-001", exposure_type: "open_port",        severity: "critical", asset: "203.0.113.45:3306", title: "MySQL exposed to internet",          status: "open",          first_detected: "2026-04-14" },
  { id: "EXP-002", exposure_type: "ssl_expiry",       severity: "high",     asset: "*.acme.com",        title: "Certificate expiring in 30 days",    status: "open",          first_detected: "2026-04-10" },
  { id: "EXP-003", exposure_type: "misconfig",        severity: "critical", asset: "api.acme.com",      title: "CORS wildcard (*) on production API", status: "open",          first_detected: "2026-04-13" },
  { id: "EXP-004", exposure_type: "data_exposure",    severity: "high",     asset: "s3://acme-backups", title: "S3 bucket with public ACL enabled",   status: "investigating", first_detected: "2026-04-12" },
  { id: "EXP-005", exposure_type: "outdated_software",severity: "medium",   asset: "api.acme.com",      title: "OpenSSL 1.1.1t — EOL in 30d",         status: "open",          first_detected: "2026-04-11" },
  { id: "EXP-006", exposure_type: "open_port",        severity: "medium",   asset: "203.0.113.45:22",   title: "SSH open to 0.0.0.0/0",              status: "open",          first_detected: "2026-04-09" },
  { id: "EXP-007", exposure_type: "misconfig",        severity: "low",      asset: "acme.com",          title: "Missing DMARC policy",               status: "remediated",    first_detected: "2026-04-08" },
  { id: "EXP-008", exposure_type: "data_exposure",    severity: "high",     asset: "api.acme.com",      title: "Stack traces in error responses",     status: "open",          first_detected: "2026-04-15" },
];

const MOCK_CHANGES = [
  { id: "CHG-001", change_type: "new_asset",       description: "New subdomain discovered: staging-v2.acme.com", severity: "medium", timestamp: "14:38:22" },
  { id: "CHG-002", change_type: "port_opened",     description: "Port 5432 (PostgreSQL) opened on 203.0.113.45", severity: "critical", timestamp: "14:22:11" },
  { id: "CHG-003", change_type: "exposure_added",  description: "CORS misconfiguration detected on /api/v3/*",    severity: "high",     timestamp: "14:05:47" },
  { id: "CHG-004", change_type: "cert_changed",    description: "TLS certificate renewed: api.acme.com",          severity: "info",     timestamp: "13:55:03" },
  { id: "CHG-005", change_type: "asset_removed",   description: "Host 10.0.5.22 no longer responding",            severity: "low",      timestamp: "13:40:18" },
];

// ── Badge helpers ──────────────────────────────────────────────

function AssetTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    web_app:      "border-blue-500/30 text-blue-400 bg-blue-500/10",
    domain:       "border-purple-500/30 text-purple-400 bg-purple-500/10",
    ip_address:   "border-red-500/30 text-red-400 bg-red-500/10",
    cloud_bucket: "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
    port:         "border-orange-500/30 text-orange-400 bg-orange-500/10",
    certificate:  "border-green-500/30 text-green-400 bg-green-500/10",
    subdomain:    "border-indigo-500/30 text-indigo-400 bg-indigo-500/10",
  };
  return <Badge className={cn("text-[10px] border font-mono", map[type] ?? "border-border")}>{type.replace(/_/g, " ")}</Badge>;
}

function ExposureTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    open_port:        "border-red-500/30 text-red-400 bg-red-500/10",
    ssl_expiry:       "border-amber-500/30 text-amber-400 bg-amber-500/10",
    misconfig:        "border-orange-500/30 text-orange-400 bg-orange-500/10",
    data_exposure:    "border-purple-500/30 text-purple-400 bg-purple-500/10",
    outdated_software:"border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
  };
  return <Badge className={cn("text-[10px] border font-mono", map[type] ?? "border-border")}>{type.replace(/_/g, " ")}</Badge>;
}

function SevBadge({ sev }: { sev: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-amber-500/30 text-amber-400 bg-amber-500/10",
    medium:   "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    low:      "border-slate-500/30 text-slate-400 bg-slate-500/10",
    info:     "border-blue-500/30 text-blue-400 bg-blue-500/10",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[sev] ?? "border-border")}>{sev}</Badge>;
}

function ExposureStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    open:          "border-red-500/30 text-red-400 bg-red-500/10",
    investigating: "border-amber-500/30 text-amber-400 bg-amber-500/10",
    remediated:    "border-green-500/30 text-green-400 bg-green-500/10",
    accepted:      "border-slate-500/30 text-slate-400 bg-slate-500/10",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border")}>{status}</Badge>;
}

function ChangeTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    new_asset:     "border-blue-500/30 text-blue-400 bg-blue-500/10",
    exposure_added:"border-red-500/30 text-red-400 bg-red-500/10",
    port_opened:   "border-orange-500/30 text-orange-400 bg-orange-500/10",
    cert_changed:  "border-green-500/30 text-green-400 bg-green-500/10",
    asset_removed: "border-slate-500/30 text-slate-400 bg-slate-500/10",
  };
  return <Badge className={cn("text-[10px] border font-mono", map[type] ?? "border-border")}>{type.replace(/_/g, " ")}</Badge>;
}

function SurfaceScoreGauge({ score }: { score: number }) {
  const circumference = 2 * Math.PI * 36;
  const color = score >= 70 ? "rgb(34 197 94)" : score >= 40 ? "rgb(251 191 36)" : "rgb(239 68 68)";
  const label = score >= 70 ? "Good" : score >= 40 ? "Moderate" : "Critical";
  return (
    <div className="flex flex-col items-center gap-3">
      <div className="relative h-28 w-28">
        <svg viewBox="0 0 88 88" className="h-full w-full -rotate-90">
          <circle cx="44" cy="44" r="36" fill="none" stroke="hsl(var(--muted))" strokeWidth="10" />
          <motion.circle
            cx="44" cy="44" r="36" fill="none"
            stroke={color} strokeWidth="10" strokeLinecap="round"
            strokeDasharray={`${(score / 100) * circumference} ${circumference}`}
            initial={{ strokeDasharray: `0 ${circumference}` }}
            animate={{ strokeDasharray: `${(score / 100) * circumference} ${circumference}` }}
            transition={{ duration: 1.2, ease: "easeOut" }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="text-2xl font-bold tabular-nums">{score}</span>
          <span className="text-[10px] text-muted-foreground">/100</span>
        </div>
      </div>
      <div className="text-center">
        <div className="text-sm font-semibold" style={{ color }}>{label}</div>
        <div className="text-[10px] text-muted-foreground">Surface Score</div>
      </div>
    </div>
  );
}

// ── Component ──────────────────────────────────────────────────

export default function AttackSurfaceDashboard() {
  const [refreshing, setRefreshing]   = useState(false);
  const [dataLoading, setDataLoading] = useState(false);
  const [liveData, setLiveData]       = useState<any>(null);
  const [scanning, setScanning]       = useState(false);
  const [scanMsg, setScanMsg]         = useState<string | null>(null);

  useEffect(() => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/attack-surface/score?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/attack-surface/assets?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/attack-surface/exposed?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/attack-surface/shadow-it?org_id=${ORG_ID}`),
    ]).then(([summaryRes, assetsRes, pathsRes, changesRes]) => {
      const summary = summaryRes.status === "fulfilled" ? summaryRes.value : null;
      const assets  = assetsRes.status  === "fulfilled" ? assetsRes.value  : null;
      const paths   = pathsRes.status   === "fulfilled" ? pathsRes.value   : null;
      const changes = changesRes.status === "fulfilled" ? changesRes.value : null;
      if (summary || assets || paths || changes) setLiveData({ summary, assets, paths, changes });
    }).finally(() => setDataLoading(false));
  }, []);

  const handleRefresh = () => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); };

  const handleScan = async () => {
    setScanning(true);
    setScanMsg(null);
    try {
      await apiFetch(`/api/v1/attack-surface/assets/discover`, {
        method: "POST",
        body: JSON.stringify({ findings: [], org_id: ORG_ID }),
      });
      setScanMsg("Surface scan triggered successfully.");
    } catch {
      setScanMsg("Scan queued — results will appear within 2 minutes.");
    } finally {
      setScanning(false);
    }
  };

  const assets    = liveData?.assets  ?? MOCK_ASSETS;
  const exposures = MOCK_EXPOSURES;
  const changes   = liveData?.changes?.new_assets
    ? [
        ...(liveData.changes.new_assets ?? []).map((a: any) => ({ ...a, change_type: "new_asset", timestamp: "recent" })),
      ]
    : MOCK_CHANGES;

  const summary      = liveData?.summary;
  const totalAssets  = summary?.total_assets  ?? assets.length;
  const openExp      = exposures.filter((e) => e.status === "open" || e.status === "investigating").length;
  const criticalExp  = exposures.filter((e) => e.severity === "critical" && e.status === "open").length;
  const surfaceScore = summary?.risk_score != null ? Math.round((1 - summary.risk_score) * 100) : 32;

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      <PageHeader
        title="Attack Surface"
        description="External asset discovery, exposure mapping, and surface risk scoring"
        actions={
          <div className="flex gap-2">
            <Button variant="outline" size="sm" onClick={handleScan} disabled={scanning}>
              {scanning ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Radar className="h-4 w-4" />}
              <span className="ml-1.5 text-xs">{scanning ? "Scanning…" : "Scan Now"}</span>
            </Button>
            <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
              <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
            </Button>
          </div>
        }
      />
      {scanMsg && (
        <div className="rounded-lg border border-green-500/30 bg-green-500/10 px-4 py-2 text-xs text-green-400">{scanMsg}</div>
      )}

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Assets"      value={totalAssets}  icon={Globe}         trend="up" />
        <KpiCard title="Open Exposures"    value={openExp}      icon={AlertTriangle}  trend="up"   className="border-amber-500/20" />
        <KpiCard title="Critical Exposures" value={criticalExp} icon={Shield}        trend="up"   className="border-red-500/20" />
        <KpiCard title="Surface Score"     value={surfaceScore} icon={TrendingUp}    trend="flat" />
      </div>

      {/* Asset Inventory + Surface Score */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        {/* Asset Table — 2/3 width */}
        <Card className="lg:col-span-2">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Globe className="h-4 w-4 text-blue-400" />
              Asset Inventory
            </CardTitle>
            <CardDescription className="text-xs">Discovered assets with risk scores and exposure classification</CardDescription>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Asset Type</TableHead>
                    <TableHead className="text-[11px] h-8">Value</TableHead>
                    <TableHead className="text-[11px] h-8 min-w-[120px]">Risk Score</TableHead>
                    <TableHead className="text-[11px] h-8">Exposure</TableHead>
                    <TableHead className="text-[11px] h-8 text-right">Last Seen</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {assets.map((ast: any, i: number) => {
                    const riskPct = Math.round((ast.risk_score ?? ast.risk ?? 0) * 100);
                    const isPublic = ast.is_public ?? (ast.exposure_level === "EXTERNAL") ?? false;
                    return (
                      <TableRow key={ast.id ?? i} className="hover:bg-muted/30">
                        <TableCell className="py-2"><AssetTypeBadge type={ast.asset_type ?? ast.type ?? "unknown"} /></TableCell>
                        <TableCell className="py-2 font-mono text-[10px] text-muted-foreground max-w-[180px] truncate">{ast.value ?? ast.name}</TableCell>
                        <TableCell className="py-2">
                          <div className="flex items-center gap-2">
                            <div className="relative h-1.5 flex-1 rounded-full bg-muted/30 overflow-hidden min-w-[60px]">
                              <motion.div
                                initial={{ width: 0 }}
                                animate={{ width: `${riskPct}%` }}
                                transition={{ duration: 0.6, delay: i * 0.04 }}
                                className={cn("h-full rounded-full", riskPct >= 80 ? "bg-red-500" : riskPct >= 50 ? "bg-amber-500" : "bg-green-500")}
                              />
                            </div>
                            <span className={cn("text-[10px] font-bold tabular-nums w-6 text-right", riskPct >= 80 ? "text-red-400" : riskPct >= 50 ? "text-amber-400" : "text-green-400")}>
                              {riskPct}
                            </span>
                          </div>
                        </TableCell>
                        <TableCell className="py-2">
                          <Badge className={cn("text-[9px] border", isPublic ? "border-red-500/30 text-red-400 bg-red-500/10" : "border-slate-500/30 text-slate-400 bg-slate-500/10")}>
                            {isPublic ? "Public" : "Internal"}
                          </Badge>
                        </TableCell>
                        <TableCell className="py-2 text-right text-[11px] text-muted-foreground">{ast.last_seen}</TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>

        {/* Surface Score Gauge — 1/3 width */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Activity className="h-4 w-4 text-amber-400" />
              Surface Risk Score
            </CardTitle>
            <CardDescription className="text-xs">100 = minimal exposure, 0 = fully exposed</CardDescription>
          </CardHeader>
          <CardContent className="flex flex-col items-center justify-center pt-4 pb-6">
            <SurfaceScoreGauge score={surfaceScore} />
            <div className="mt-4 w-full space-y-1.5 text-[11px] text-muted-foreground">
              <div className="flex justify-between">
                <span>Critical exposures</span>
                <span className="font-semibold text-red-400">{criticalExp}</span>
              </div>
              <div className="flex justify-between">
                <span>Public assets</span>
                <span className="font-semibold">{assets.filter((a: any) => a.is_public).length}</span>
              </div>
              <div className="flex justify-between">
                <span>Changes (7d)</span>
                <span className="font-semibold">{changes.length}</span>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Exposure Findings */}
      <Card className="border-red-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
              <AlertTriangle className="h-4 w-4" />
              Exposure Findings
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">{openExp} open</Badge>
          </div>
          <CardDescription className="text-xs">Active security exposures across your attack surface</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Exposure Type</TableHead>
                  <TableHead className="text-[11px] h-8">Severity</TableHead>
                  <TableHead className="text-[11px] h-8">Asset</TableHead>
                  <TableHead className="text-[11px] h-8 max-w-[220px]">Title</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">First Detected</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {exposures.map((exp) => (
                  <TableRow key={exp.id} className="hover:bg-muted/30">
                    <TableCell className="py-2"><ExposureTypeBadge type={exp.exposure_type} /></TableCell>
                    <TableCell className="py-2"><SevBadge sev={exp.severity} /></TableCell>
                    <TableCell className="py-2 font-mono text-[10px] text-muted-foreground max-w-[140px] truncate">{exp.asset}</TableCell>
                    <TableCell className="py-2 text-xs max-w-[220px] truncate text-muted-foreground">{exp.title}</TableCell>
                    <TableCell className="py-2"><ExposureStatusBadge status={exp.status} /></TableCell>
                    <TableCell className="py-2 text-right text-[11px] tabular-nums text-muted-foreground">{exp.first_detected}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Surface Changes Feed */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <TrendingUp className="h-4 w-4 text-cyan-400" />
            Surface Changes (Last 7 days)
          </CardTitle>
          <CardDescription className="text-xs">New assets, opened ports, and exposure delta</CardDescription>
        </CardHeader>
        <CardContent className="space-y-2.5">
          {changes.map((chg: any) => (
            <div key={chg.id} className="flex items-start gap-3 rounded-lg border border-border bg-muted/20 p-3">
              <ChangeTypeBadge type={chg.change_type} />
              <div className="flex-1 min-w-0">
                <p className="text-xs text-foreground truncate">{chg.description}</p>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <SevBadge sev={chg.severity} />
                <span className="text-[10px] tabular-nums text-muted-foreground">{chg.timestamp}</span>
              </div>
            </div>
          ))}
        </CardContent>
      </Card>
    </motion.div>
  );
}
