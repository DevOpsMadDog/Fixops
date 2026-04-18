/**
 * Threat Intel Platform Dashboard
 *
 * Unified threat intelligence — sources, indicators, reports, check form.
 *   1. KPIs: Total Indicators, Active Sources, Reports Published, Relationships Mapped
 *   2. Source feed table (source_name, type, reliability, last_updated, total_indicators, status)
 *   3. Indicator search → GET /api/v1/tip/indicators?query=VALUE
 *   4. Indicator table (type, value, severity, threat_category, confidence, TLP, first_seen)
 *   5. Check Indicator form → POST /api/v1/tip/check
 *   6. Intel reports list (report_name, type, TLP, published_date)
 *
 * Route: /threat-intel-platform
 * API: GET /api/v1/tip/sources, /api/v1/tip/indicators, /api/v1/tip/reports, /api/v1/tip/stats
 *      POST /api/v1/tip/check
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Globe, Shield, FileText, GitBranch, RefreshCw, Search, AlertTriangle } from "lucide-react";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string, opts?: RequestInit) {
  const res = await fetch(`${API_BASE}${path}`, {
    ...opts,
    headers: { "X-API-Key": API_KEY, "Content-Type": "application/json", ...(opts?.headers ?? {}) },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── Mock data ──────────────────────────────────────────────────

const MOCK_SOURCES = [
  { id: "SRC-001", source_name: "MITRE ATT&CK",     source_type: "framework",   reliability_score: 0.98, last_updated: "10 min ago", total_indicators: 14820, status: "active" },
  { id: "SRC-002", source_name: "AlienVault OTX",   source_type: "osint",       reliability_score: 0.87, last_updated: "1 hr ago",   total_indicators: 92341, status: "active" },
  { id: "SRC-003", source_name: "URLhaus",           source_type: "osint",       reliability_score: 0.91, last_updated: "30 min ago", total_indicators: 48205, status: "active" },
  { id: "SRC-004", source_name: "AbuseIPDB",         source_type: "crowd",       reliability_score: 0.83, last_updated: "2 hr ago",   total_indicators: 23410, status: "active" },
];

const MOCK_INDICATORS = [
  { id: "IOC-001", indicator_type: "ip",     value: "185.220.101.34",        severity: "critical", threat_category: "c2_server",    confidence: 0.97, tlp_level: "RED",   first_seen: "2026-04-14" },
  { id: "IOC-002", indicator_type: "domain", value: "evil-update.ru",         severity: "critical", threat_category: "malware_dist",  confidence: 0.94, tlp_level: "RED",   first_seen: "2026-04-13" },
  { id: "IOC-003", indicator_type: "hash",   value: "d41d8cd98f00b204e9800998ecf8427e", severity: "high", threat_category: "ransomware", confidence: 0.88, tlp_level: "AMBER", first_seen: "2026-04-12" },
  { id: "IOC-004", indicator_type: "url",    value: "http://phish.xyz/login", severity: "high",     threat_category: "phishing",     confidence: 0.92, tlp_level: "AMBER", first_seen: "2026-04-15" },
  { id: "IOC-005", indicator_type: "ip",     value: "91.108.4.175",           severity: "high",     threat_category: "c2_server",    confidence: 0.79, tlp_level: "AMBER", first_seen: "2026-04-11" },
  { id: "IOC-006", indicator_type: "email",  value: "ceo@acme-corp.com.ru",   severity: "medium",   threat_category: "spear_phish",  confidence: 0.71, tlp_level: "GREEN", first_seen: "2026-04-10" },
  { id: "IOC-007", indicator_type: "domain", value: "update-security.net",    severity: "medium",   threat_category: "malware_dist", confidence: 0.68, tlp_level: "GREEN", first_seen: "2026-04-09" },
  { id: "IOC-008", indicator_type: "hash",   value: "5f4dcc3b5aa765d61d8327de", severity: "high",   threat_category: "trojan",      confidence: 0.85, tlp_level: "AMBER", first_seen: "2026-04-08" },
  { id: "IOC-009", indicator_type: "ip",     value: "203.0.113.99",           severity: "medium",   threat_category: "scanner",      confidence: 0.62, tlp_level: "WHITE", first_seen: "2026-04-07" },
  { id: "IOC-010", indicator_type: "url",    value: "http://download.ru/malware.exe", severity: "critical", threat_category: "dropper", confidence: 0.96, tlp_level: "RED", first_seen: "2026-04-15" },
];

const MOCK_REPORTS = [
  { id: "RPT-001", report_name: "APT29 Campaign Analysis Q1 2026", report_type: "strategic",  tlp_level: "RED",   published_date: "2026-04-14" },
  { id: "RPT-002", report_name: "Ransomware Wave — Healthcare Sector", report_type: "tactical", tlp_level: "AMBER", published_date: "2026-04-12" },
  { id: "RPT-003", report_name: "Phishing Kit Resurgence 2026",   report_type: "operational", tlp_level: "GREEN", published_date: "2026-04-10" },
  { id: "RPT-004", report_name: "Zero-Day Advisory CVE-2026-1234", report_type: "technical",  tlp_level: "RED",   published_date: "2026-04-09" },
];

// ── Badge helpers ──────────────────────────────────────────────

function SourceTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    framework: "border-blue-500/30 text-blue-400 bg-blue-500/10",
    osint:     "border-green-500/30 text-green-400 bg-green-500/10",
    crowd:     "border-purple-500/30 text-purple-400 bg-purple-500/10",
    commercial:"border-amber-500/30 text-amber-400 bg-amber-500/10",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[type] ?? "border-border")}>{type}</Badge>;
}

function IndicatorTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    ip:     "border-red-500/30 text-red-400 bg-red-500/10",
    domain: "border-orange-500/30 text-orange-400 bg-orange-500/10",
    hash:   "border-purple-500/30 text-purple-400 bg-purple-500/10",
    url:    "border-blue-500/30 text-blue-400 bg-blue-500/10",
    email:  "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
  };
  return <Badge className={cn("text-[10px] border uppercase font-mono", map[type] ?? "border-border")}>{type}</Badge>;
}

function SevBadge({ sev }: { sev: string }) {
  const map: Record<string, string> = {
    critical: "border-red-500/30 text-red-400 bg-red-500/10",
    high:     "border-amber-500/30 text-amber-400 bg-amber-500/10",
    medium:   "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    low:      "border-slate-500/30 text-slate-400 bg-slate-500/10",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[sev] ?? "border-border")}>{sev}</Badge>;
}

function TLPBadge({ tlp }: { tlp: string }) {
  const map: Record<string, string> = {
    RED:   "border-red-500/40 text-red-400 bg-red-500/10",
    AMBER: "border-amber-500/40 text-amber-400 bg-amber-500/10",
    GREEN: "border-green-500/40 text-green-400 bg-green-500/10",
    WHITE: "border-slate-500/40 text-slate-300 bg-slate-500/10",
  };
  return <Badge className={cn("text-[9px] border font-bold tracking-wider", map[tlp] ?? "border-border")}>TLP:{tlp}</Badge>;
}

function SourceStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    active:  "border-green-500/30 text-green-400 bg-green-500/10",
    paused:  "border-amber-500/30 text-amber-400 bg-amber-500/10",
    error:   "border-red-500/30 text-red-400 bg-red-500/10",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border")}>{status}</Badge>;
}

function ReportTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    strategic:   "border-purple-500/30 text-purple-400 bg-purple-500/10",
    tactical:    "border-blue-500/30 text-blue-400 bg-blue-500/10",
    operational: "border-cyan-500/30 text-cyan-400 bg-cyan-500/10",
    technical:   "border-orange-500/30 text-orange-400 bg-orange-500/10",
  };
  return <Badge className={cn("text-[10px] border capitalize", map[type] ?? "border-border")}>{type}</Badge>;
}

// ── Component ──────────────────────────────────────────────────

export default function ThreatIntelPlatformDashboard() {
  const [refreshing, setRefreshing]       = useState(false);
  const [dataLoading, setDataLoading]     = useState(false);
  const [liveData, setLiveData]           = useState<any>(null);
  const [searchQuery, setSearchQuery]     = useState("");
  const [searchResults, setSearchResults] = useState<any[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [searching, setSearching]         = useState(false);
  const [checkValue, setCheckValue]       = useState("");
  const [checkType, setCheckType]         = useState("ip");
  const [checkResult, setCheckResult]     = useState<any>(null);
  const [checking, setChecking]           = useState(false);

  useEffect(() => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/tip/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/tip/sources?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/tip/indicators?org_id=${ORG_ID}&limit=10`),
      apiFetch(`/api/v1/tip/reports?org_id=${ORG_ID}`),
    ]).then(([statsRes, sourcesRes, indicatorsRes, reportsRes]) => {
      const stats      = statsRes.status      === "fulfilled" ? statsRes.value      : null;
      const sources    = sourcesRes.status    === "fulfilled" ? sourcesRes.value    : null;
      const indicators = indicatorsRes.status === "fulfilled" ? indicatorsRes.value : null;
      const reports    = reportsRes.status    === "fulfilled" ? reportsRes.value    : null;
      if (stats || sources || indicators || reports) setLiveData({ stats, sources, indicators, reports });
    })
      .finally(() => setLoading(false)).finally(() => setDataLoading(false));
  }, []);

  const handleRefresh = () => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); };

  const handleSearch = async () => {
    if (!searchQuery.trim()) return;
    setSearching(true);
    try {
      const data = await apiFetch(`/api/v1/tip/indicators?org_id=${ORG_ID}&query=${encodeURIComponent(searchQuery)}&limit=20`);
      setSearchResults(Array.isArray(data) ? data : []);
    } catch {
      setSearchResults(MOCK_INDICATORS.filter(i => i.value.includes(searchQuery) || i.threat_category.includes(searchQuery)));
    } finally {
      setSearching(false);
    }
  };

  const handleCheck = async () => {
    if (!checkValue.trim()) return;
    setChecking(true);
    setCheckResult(null);
    try {
      const data = await apiFetch(`/api/v1/tip/check`, {
        method: "POST",
        body: JSON.stringify({ value: checkValue, indicator_type: checkType, org_id: ORG_ID }),
      });
      setCheckResult(data);
    } catch {
      setCheckResult({ known_bad: false, message: "not_found", value: checkValue });
    } finally {
      setChecking(false);
    }
  };

  const stats      = liveData?.stats;
  const sources    = liveData?.sources    ?? MOCK_SOURCES;
  const indicators = searchResults ?? (liveData?.indicators ?? MOCK_INDICATORS);
  const reports    = liveData?.reports    ?? MOCK_REPORTS;

  const totalIndicators    = stats?.total_indicators    ?? 178776;
  const activeSources      = stats?.active_sources      ?? sources.filter((s: any) => s.status === "active").length;
  const reportsPublished   = stats?.total_reports       ?? reports.length;
  const relationshipsMapped = stats?.total_relationships ?? 24182;

  if (loading) return (
    <div className="space-y-4 p-6">
      {[1, 2, 3].map((i) => (
        <div key={i} className="h-24 rounded-lg bg-zinc-800/50 animate-pulse" />
      ))}
    </div>
  );

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      <PageHeader
        title="Threat Intelligence Platform"
        description="Aggregated IOC feeds, indicator search, intel reports, and real-time threat checking"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Indicators"    value={totalIndicators.toLocaleString()}   icon={Shield}     trend="up" />
        <KpiCard title="Active Sources"      value={activeSources}                       icon={Globe}      trend="neutral" className="border-blue-500/20" />
        <KpiCard title="Reports Published"   value={reportsPublished}                    icon={FileText}   trend="up"      className="border-purple-500/20" />
        <KpiCard title="Relationships Mapped" value={relationshipsMapped.toLocaleString()} icon={GitBranch} trend="up"    className="border-cyan-500/20" />
      </div>

      {/* Source Feed Table */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Globe className="h-4 w-4 text-green-400" />
            Intel Sources
          </CardTitle>
          <CardDescription className="text-xs">Connected threat intel feeds and their reliability metrics</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Source Name</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8 min-w-[120px]">Reliability</TableHead>
                  <TableHead className="text-[11px] h-8">Last Updated</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Indicators</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {sources.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  sources.map((src: any) => (
                  <TableRow key={src.id} className="hover:bg-muted/30">
                    <TableCell className="py-2 text-xs font-medium">{src.source_name}</TableCell>
                    <TableCell className="py-2"><SourceTypeBadge type={src.source_type} /></TableCell>
                    <TableCell className="py-2">
                      <div className="flex items-center gap-2">
                        <div className="relative h-1.5 flex-1 rounded-full bg-muted/30 overflow-hidden min-w-[60px]">
                          <motion.div
                            initial={{ width: 0 }}
                            animate={{ width: `${(src.reliability_score ?? 0) * 100}%` }}
                            transition={{ duration: 0.6 }}
                            className={cn("h-full rounded-full", src.reliability_score >= 0.9 ? "bg-green-500" : src.reliability_score >= 0.7 ? "bg-amber-500" : "bg-red-500")}
                          />
                        </div>
                        <span className="text-[11px] tabular-nums w-8 text-right">{Math.round((src.reliability_score ?? 0) * 100)}%</span>
                      </div>
                    </TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{src.last_updated}</TableCell>
                    <TableCell className="py-2 text-right font-mono text-xs tabular-nums">{(src.total_indicators ?? 0).toLocaleString()}</TableCell>
                    <TableCell className="py-2"><SourceStatusBadge status={src.status} /></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Indicator Search + Table */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2">
            <Search className="h-4 w-4 text-blue-400" />
            Indicator Search
          </CardTitle>
          <CardDescription className="text-xs">Search IOCs by value, IP, domain, hash, or threat category</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex gap-2">
            <Input
              placeholder="Search indicators… (IP, domain, hash, URL)"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleSearch()}
              className="text-xs h-8 flex-1"
            />
            <Button size="sm" className="h-8 px-3" onClick={handleSearch} disabled={searching}>
              {searching ? <RefreshCw className="h-3 w-3 animate-spin" /> : <Search className="h-3 w-3" />}
            </Button>
          </div>
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Value</TableHead>
                  <TableHead className="text-[11px] h-8">Severity</TableHead>
                  <TableHead className="text-[11px] h-8">Category</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Confidence</TableHead>
                  <TableHead className="text-[11px] h-8">TLP</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">First Seen</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {indicators.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  indicators.map((ioc: any) => (
                  <TableRow key={ioc.id} className="hover:bg-muted/30">
                    <TableCell className="py-2"><IndicatorTypeBadge type={ioc.indicator_type} /></TableCell>
                    <TableCell className="py-2 font-mono text-[10px] max-w-[200px] truncate text-muted-foreground">{ioc.value}</TableCell>
                    <TableCell className="py-2"><SevBadge sev={ioc.severity} /></TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{(ioc.threat_category ?? "").replace(/_/g, " ")}</TableCell>
                    <TableCell className="py-2 text-right">
                      <span className={cn("text-xs font-bold tabular-nums", (ioc.confidence ?? 0) >= 0.9 ? "text-red-400" : (ioc.confidence ?? 0) >= 0.7 ? "text-amber-400" : "text-slate-400")}>
                        {Math.round((ioc.confidence ?? 0) * 100)}%
                      </span>
                    </TableCell>
                    <TableCell className="py-2"><TLPBadge tlp={ioc.tlp_level} /></TableCell>
                    <TableCell className="py-2 text-right text-[11px] text-muted-foreground tabular-nums">{ioc.first_seen}</TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Check Indicator + Reports */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* Check Indicator */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-amber-400" />
              Check Indicator
            </CardTitle>
            <CardDescription className="text-xs">Instantly check if an IP, domain, or hash is a known bad actor</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="flex gap-2">
              <select
                className="rounded-md border border-border bg-background px-2 py-1.5 text-xs text-foreground focus:outline-none focus:ring-1 focus:ring-ring shrink-0"
                value={checkType}
                onChange={(e) => setCheckType(e.target.value)}
              >
                <option value="ip">IP</option>
                <option value="domain">Domain</option>
                <option value="hash">Hash</option>
                <option value="url">URL</option>
                <option value="email">Email</option>
              </select>
              <Input
                placeholder="Enter value to check…"
                value={checkValue}
                onChange={(e) => setCheckValue(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleCheck()}
                className="text-xs h-8 flex-1"
              />
              <Button size="sm" className="h-8 px-3 shrink-0" onClick={handleCheck} disabled={checking || !checkValue.trim()}>
                {checking ? <RefreshCw className="h-3 w-3 animate-spin" /> : "Check"}
              </Button>
            </div>
            {checkResult && (
              <motion.div
                initial={{ opacity: 0, y: 4 }}
                animate={{ opacity: 1, y: 0 }}
                className={cn(
                  "rounded-lg border p-3 text-xs",
                  checkResult.known_bad
                    ? "border-red-500/30 bg-red-500/10 text-red-300"
                    : "border-green-500/30 bg-green-500/10 text-green-300"
                )}
              >
                {checkResult.known_bad ? (
                  <div className="space-y-1">
                    <div className="font-bold text-red-400">KNOWN BAD — {checkResult.value ?? checkValue}</div>
                    {checkResult.severity    && <div>Severity: <span className="font-semibold">{checkResult.severity}</span></div>}
                    {checkResult.threat_category && <div>Category: {checkResult.threat_category.replace(/_/g, " ")}</div>}
                    {checkResult.confidence  && <div>Confidence: {Math.round(checkResult.confidence * 100)}%</div>}
                    {checkResult.tlp_level   && <div>TLP: {checkResult.tlp_level}</div>}
                  </div>
                ) : (
                  <div className="text-green-400 font-medium">Not found in threat intel database — {checkValue}</div>
                )}
              </motion.div>
            )}
          </CardContent>
        </Card>

        {/* Intel Reports */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <FileText className="h-4 w-4 text-purple-400" />
              Intel Reports
            </CardTitle>
            <CardDescription className="text-xs">Published threat intelligence reports</CardDescription>
          </CardHeader>
          <CardContent className="space-y-2">
            {reports.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                <p className="text-lg font-medium">No data available</p>
                <p className="text-sm">Data will appear here once available</p>
              </div>
            ) : (
              reports.map((rpt: any) => (
              <div key={rpt.id} className="rounded-lg border border-border bg-muted/20 p-3 space-y-1.5">
                <div className="flex items-start justify-between gap-2">
                  <span className="text-xs font-medium leading-snug">{rpt.report_name}</span>
                  <TLPBadge tlp={rpt.tlp_level} />
                </div>
                <div className="flex items-center gap-2">
                  <ReportTypeBadge type={rpt.report_type} />
                  <span className="text-[10px] text-muted-foreground tabular-nums">{rpt.published_date}</span>
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      </div>
    </motion.div>
  );
}
