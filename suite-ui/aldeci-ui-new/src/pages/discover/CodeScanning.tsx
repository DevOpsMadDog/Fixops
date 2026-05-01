import { useState, useCallback, useMemo } from "react";
import { useNavigate } from "react-router-dom";
import { motion } from "framer-motion";
import { toast } from "sonner";
import {
  Code2, FileCode, RefreshCw, Download, ChevronRight, ChevronDown,
  Bug, Layers, Zap, AlertTriangle, CheckCircle, Filter,
  Github, GitBranch, Lock, PlayCircle, Loader2,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { Skeleton } from "@/components/ui/skeleton";
import { Separator } from "@/components/ui/separator";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { ErrorState } from "@/components/shared/ErrorState";
import { useFindings, useScannerParsers, useAutofix } from "@/hooks/use-api";
import api, { findingsApi } from "@/lib/api";
import { cn } from "@/lib/utils";
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Cell,
} from "recharts";

interface Finding {
  id?: string;
  finding_id?: string;
  title?: string;
  severity?: string;
  status?: string;
  scanner?: string;
  rule?: string;
  file?: string;
  line?: number;
  language?: string;
  description?: string;
  code_snippet?: string;
  fix_suggestion?: string;
  diff?: string;
  component?: string;
  created_at?: string;
}

function SeverityBadge({ severity }: { severity?: string }) {
  const s = (severity || "").toLowerCase();
  const variants: Record<string, string> = {
    critical: "bg-red-500/15 text-red-400 border-red-500/30",
    high: "bg-orange-500/15 text-orange-400 border-orange-500/30",
    medium: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
    low: "bg-blue-500/15 text-blue-400 border-blue-500/30",
    info: "bg-slate-500/15 text-slate-400 border-slate-500/30",
  };
  return (
    <Badge className={cn("border text-xs font-semibold uppercase tracking-wide", variants[s] || variants["info"])}>
      {severity || "Unknown"}
    </Badge>
  );
}

function ScannerBadge({ scanner }: { scanner?: string }) {
  const colors: Record<string, string> = {
    semgrep: "bg-purple-500/15 text-purple-400 border-purple-500/30",
    sonarqube: "bg-blue-500/15 text-blue-400 border-blue-500/30",
    bandit: "bg-green-500/15 text-green-400 border-green-500/30",
  };
  const s = (scanner || "").toLowerCase();
  return (
    <Badge className={cn("border text-xs", colors[s] || "bg-slate-500/15 text-slate-400 border-slate-500/20")}>
      {scanner || "Unknown"}
    </Badge>
  );
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#3b82f6",
};

const SCANNER_COLORS: Record<string, string> = {
  semgrep: "#a855f7",
  sonarqube: "#3b82f6",
  bandit: "#22c55e",
  other: "#6b7280",
};

export default function CodeScanning() {
  const navigate = useNavigate();
  const autofixMutation = useAutofix();
  const [activeTab, setActiveTab] = useState("findings");
  const [scannerFilter, setScannerFilter] = useState("all");
  const [severityFilter, setSeverityFilter] = useState("all");
  const [langFilter, setLangFilter] = useState("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [expandedRow, setExpandedRow] = useState<string | null>(null);
  const [detailFinding, setDetailFinding] = useState<Finding | null>(null);

  // ── DoD #7: Connect GitHub repo + scan trigger ─────────────────────────
  const [provider, setProvider] = useState<"github" | "gitlab">("github");
  const [repoUrl, setRepoUrl] = useState("");
  const [accessToken, setAccessToken] = useState("");
  const [orgId, setOrgId] = useState("");
  const [installationId, setInstallationId] = useState("");
  const [appId, setAppId] = useState("");
  const [scanLoading, setScanLoading] = useState(false);
  const [scanResult, setScanResult] = useState<
    | null
    | {
        ok: boolean;
        registered?: boolean;
        scanId?: string;
        queuedFindings?: number;
        message?: string;
      }
  >(null);

  const params = useMemo(() => {
    const p: Record<string, unknown> = { limit: 200, type: "sast" };
    if (scannerFilter !== "all") p.scanner = scannerFilter;
    if (severityFilter !== "all") p.severity = severityFilter;
    return p;
  }, [scannerFilter, severityFilter]);

  const query = useFindings(params);
  const scannersQuery = useScannerParsers();
  const refetch = useCallback(() => query.refetch(), [query]);

  const handleConnectAndScan = useCallback(async () => {
    if (!repoUrl.trim()) {
      toast.error("Repository URL is required");
      return;
    }
    setScanLoading(true);
    setScanResult(null);
    try {
      // Step 1: register installation (GitHub only — GitLab path skipped server-side until parity)
      let registered = false;
      if (provider === "github" && orgId && installationId && appId && accessToken) {
        try {
          await api.post("/api/v1/github-app/register", {
            org_id: orgId.trim(),
            app_id: appId.trim(),
            installation_id: installationId.trim(),
            webhook_secret: accessToken, // hashed server-side (sha256), never stored raw
            app_slug: "aldeci-aspm",
          });
          registered = true;
        } catch (e: unknown) {
          // Non-fatal — proceed to scan even if registration is skipped (e.g. already registered)
          const msg = e instanceof Error ? e.message : "registration failed";
          toast.message(`GitHub registration skipped: ${msg}`);
        }
      }

      // Step 2: trigger SAST/repo scan via Trivy repo endpoint (canonical git-URL → findings path)
      const scanResp = await api.post<{
        scan_id?: string;
        scanId?: string;
        findings?: unknown[];
        results?: { findings?: unknown[] };
        status?: string;
      }>("/api/v1/scan/trivy/repo", {
        repo_url: repoUrl.trim(),
      });
      const scanData = scanResp.data || {};
      const scanId =
        scanData.scan_id || scanData.scanId || `scan-${Date.now().toString(36)}`;
      const queuedFindings =
        (Array.isArray(scanData.findings) && scanData.findings.length) ||
        (Array.isArray(scanData.results?.findings) && scanData.results.findings.length) ||
        0;

      setScanResult({
        ok: true,
        registered,
        scanId,
        queuedFindings,
        message: `Scan queued for ${repoUrl.trim()}`,
      });
      toast.success(
        `Scan queued · ${queuedFindings} findings ingested · scan_id=${scanId}`
      );
      // Refresh the findings table so new findings surface immediately
      query.refetch();
    } catch (err: unknown) {
      const msg =
        err instanceof Error ? err.message : "Failed to connect or trigger scan";
      setScanResult({ ok: false, message: msg });
      toast.error(msg);
    } finally {
      setScanLoading(false);
    }
  }, [provider, repoUrl, accessToken, orgId, installationId, appId, query]);

  const allFindings: Finding[] = useMemo(() => {
    const d = query.data;
    if (!d) return [];
    if (Array.isArray(d)) return d;
    if (Array.isArray(d?.findings)) return d.findings;
    if (Array.isArray(d?.cases)) return d.cases;
    if (Array.isArray(d?.items)) return d.items;
    if (Array.isArray(d?.data)) return d.data;
    return [];
  }, [query.data]);

  const filtered = useMemo(() => {
    let list = allFindings;
    if (langFilter !== "all") {
      list = list.filter((f) => f.language?.toLowerCase() === langFilter);
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      list = list.filter(
        (f) =>
          f.title?.toLowerCase().includes(q) ||
          f.rule?.toLowerCase().includes(q) ||
          f.file?.toLowerCase().includes(q)
      );
    }
    return list;
  }, [allFindings, langFilter, searchQuery]);

  const stats = useMemo(() => {
    const bySeverity = filtered.reduce<Record<string, number>>((acc, f) => {
      const s = (f.severity || "info").toLowerCase();
      acc[s] = (acc[s] || 0) + 1;
      return acc;
    }, {});

    const byScanner = filtered.reduce<Record<string, number>>((acc, f) => {
      const s = (f.scanner || "other").toLowerCase();
      acc[s] = (acc[s] || 0) + 1;
      return acc;
    }, {});

    const byLanguage = filtered.reduce<Record<string, number>>((acc, f) => {
      if (f.language) acc[f.language] = (acc[f.language] || 0) + 1;
      return acc;
    }, {});

    return { bySeverity, byScanner, byLanguage, total: filtered.length };
  }, [filtered]);

  const severityChartData = useMemo(() =>
    Object.entries(stats.bySeverity).map(([name, count]) => ({
      name: name.charAt(0).toUpperCase() + name.slice(1),
      count,
      color: SEVERITY_COLORS[name] || "#6b7280",
    })),
    [stats.bySeverity]
  );

  const scannerChartData = useMemo(() =>
    Object.entries(stats.byScanner).map(([name, count]) => ({
      name: name.charAt(0).toUpperCase() + name.slice(1),
      count,
      color: SCANNER_COLORS[name] || "#6b7280",
    })),
    [stats.byScanner]
  );

  const languages = useMemo(() =>
    Array.from(new Set(allFindings.map((f) => f.language).filter(Boolean))),
    [allFindings]
  );

  if (query.isLoading) {
    return (
      <div className="space-y-6 p-6">
        <Skeleton className="h-10 w-64" />
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
          {Array.from({ length: 3 }).map((_, i) => <Skeleton key={i} className="h-28" />)}
        </div>
        <Skeleton className="h-80" />
        <Skeleton className="h-96" />
      </div>
    );
  }

  if (query.isError) {
    return <ErrorState message="Failed to load SAST findings." onRetry={refetch} />;
  }

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      <PageHeader title="Code Scanning" description="SAST results from all connected code scanners">
        <Button variant="outline" size="sm" onClick={() => query.refetch()} className="gap-2">
          <RefreshCw className="h-4 w-4" /> Refresh
        </Button>
        <Button variant="outline" size="sm" className="gap-2" onClick={() => {
          const blob = new Blob([JSON.stringify(allFindings, null, 2)], { type: "application/json" });
          const url = URL.createObjectURL(blob);
          const a = document.createElement("a"); a.href = url; a.download = "code-scanning-findings.json"; a.click();
          URL.revokeObjectURL(url);
          toast.success(`Exported ${allFindings.length} code scanning findings`);
        }}>
          <Download className="h-4 w-4" /> Export
        </Button>
      </PageHeader>

      {/* KPI Row */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Total SAST Findings" value={stats.total} icon={Bug} />
        <KpiCard title="Languages" value={Object.keys(stats.byLanguage).length} icon={Code2} />
        <KpiCard title="Rules Triggered" value={new Set(allFindings.map((f) => f.rule).filter(Boolean)).size} icon={Zap} />
        <KpiCard title="Scanners Active" value={Object.keys(stats.byScanner).length} icon={Layers} />
      </div>

      {/* DoD #7 — Connect GitHub repo + scan trigger */}
      <Card className="border-primary/20 bg-gradient-to-br from-primary/5 to-transparent">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between gap-3 flex-wrap">
            <div className="flex items-center gap-2">
              <Github className="h-5 w-5 text-primary" aria-hidden="true" />
              <CardTitle className="text-base">Connect repository &amp; scan</CardTitle>
            </div>
            <Badge variant="outline" className="text-[10px] uppercase tracking-wide">
              ASPM Founder DoD #7
            </Badge>
          </div>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-12 gap-3 items-end">
            <div className="lg:col-span-2">
              <label htmlFor="dod7-provider" className="text-xs font-medium text-muted-foreground mb-1 block">
                Provider
              </label>
              <Select
                value={provider}
                onValueChange={(v: string) => setProvider(v === "gitlab" ? "gitlab" : "github")}
              >
                <SelectTrigger id="dod7-provider" aria-label="Repository provider">
                  <SelectValue placeholder="Provider" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="github">GitHub</SelectItem>
                  <SelectItem value="gitlab">GitLab</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="lg:col-span-4">
              <label htmlFor="dod7-repo-url" className="text-xs font-medium text-muted-foreground mb-1 block">
                Repository URL
              </label>
              <div className="relative">
                <GitBranch
                  className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground"
                  aria-hidden="true"
                />
                <Input
                  id="dod7-repo-url"
                  type="url"
                  inputMode="url"
                  autoComplete="off"
                  placeholder="https://github.com/org/repo.git"
                  value={repoUrl}
                  onChange={(e) => setRepoUrl(e.target.value)}
                  className="pl-9"
                  aria-required="true"
                />
              </div>
            </div>
            <div className="lg:col-span-3">
              <label htmlFor="dod7-token" className="text-xs font-medium text-muted-foreground mb-1 block">
                Access token / webhook secret
              </label>
              <div className="relative">
                <Lock
                  className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground"
                  aria-hidden="true"
                />
                <Input
                  id="dod7-token"
                  type="password"
                  autoComplete="new-password"
                  placeholder="ghp_xxx or webhook secret"
                  value={accessToken}
                  onChange={(e) => setAccessToken(e.target.value)}
                  className="pl-9 font-mono"
                />
              </div>
            </div>
            <div className="lg:col-span-3 flex justify-end">
              <Button
                type="button"
                onClick={handleConnectAndScan}
                disabled={scanLoading || !repoUrl.trim()}
                className="gap-2 w-full sm:w-auto"
                aria-busy={scanLoading}
              >
                {scanLoading ? (
                  <>
                    <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
                    Scanning…
                  </>
                ) : (
                  <>
                    <PlayCircle className="h-4 w-4" aria-hidden="true" />
                    Connect &amp; scan
                  </>
                )}
              </Button>
            </div>
          </div>

          {/* Optional GitHub App registration fields (collapsed when GitLab) */}
          {provider === "github" && (
            <div className="mt-3 grid grid-cols-1 sm:grid-cols-3 gap-3">
              <div>
                <label htmlFor="dod7-org" className="text-[11px] font-medium text-muted-foreground mb-1 block">
                  Org ID (optional)
                </label>
                <Input
                  id="dod7-org"
                  placeholder="acme-corp"
                  value={orgId}
                  onChange={(e) => setOrgId(e.target.value)}
                  className="text-xs"
                />
              </div>
              <div>
                <label htmlFor="dod7-app-id" className="text-[11px] font-medium text-muted-foreground mb-1 block">
                  App ID (optional)
                </label>
                <Input
                  id="dod7-app-id"
                  placeholder="123456"
                  value={appId}
                  onChange={(e) => setAppId(e.target.value)}
                  className="text-xs"
                />
              </div>
              <div>
                <label htmlFor="dod7-inst-id" className="text-[11px] font-medium text-muted-foreground mb-1 block">
                  Installation ID (optional)
                </label>
                <Input
                  id="dod7-inst-id"
                  placeholder="987654"
                  value={installationId}
                  onChange={(e) => setInstallationId(e.target.value)}
                  className="text-xs"
                />
              </div>
            </div>
          )}

          {/* Result panel — aria-live so screen readers announce */}
          <div
            aria-live="polite"
            aria-atomic="true"
            className="mt-3 min-h-[1.25rem]"
          >
            {scanResult && (
              <div
                className={cn(
                  "rounded-md border px-3 py-2 text-sm flex items-start gap-2",
                  scanResult.ok
                    ? "bg-green-500/10 border-green-500/30 text-green-300"
                    : "bg-red-500/10 border-red-500/30 text-red-300"
                )}
                role={scanResult.ok ? "status" : "alert"}
              >
                {scanResult.ok ? (
                  <CheckCircle className="h-4 w-4 mt-0.5 shrink-0" aria-hidden="true" />
                ) : (
                  <AlertTriangle className="h-4 w-4 mt-0.5 shrink-0" aria-hidden="true" />
                )}
                <div className="flex-1 min-w-0">
                  <p className="font-medium truncate">{scanResult.message}</p>
                  {scanResult.ok && (
                    <p className="text-xs opacity-80 mt-0.5 font-mono break-all">
                      {scanResult.registered ? "registered=true · " : ""}
                      scan_id={scanResult.scanId} · queued_findings={scanResult.queuedFindings}
                    </p>
                  )}
                </div>
              </div>
            )}
          </div>
        </CardContent>
      </Card>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="findings">Findings</TabsTrigger>
          <TabsTrigger value="comparison">Scanner Comparison</TabsTrigger>
        </TabsList>

        {/* Findings Tab */}
        <TabsContent value="findings" className="space-y-4 mt-4">
          {/* Filters */}
          <div className="flex flex-wrap gap-3">
            <div className="relative flex-1 min-w-[200px]">
              <Code2 className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search rule, file path..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-9"
              />
            </div>
            <Select value={scannerFilter} onValueChange={setScannerFilter}>
              <SelectTrigger className="w-36">
                <SelectValue placeholder="Scanner" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Scanners</SelectItem>
                <SelectItem value="semgrep">Semgrep</SelectItem>
                <SelectItem value="sonarqube">SonarQube</SelectItem>
                <SelectItem value="bandit">Bandit</SelectItem>
              </SelectContent>
            </Select>
            <Select value={severityFilter} onValueChange={setSeverityFilter}>
              <SelectTrigger className="w-36">
                <SelectValue placeholder="Severity" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Severities</SelectItem>
                <SelectItem value="critical">Critical</SelectItem>
                <SelectItem value="high">High</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="low">Low</SelectItem>
              </SelectContent>
            </Select>
            {languages.length > 0 && (
              <Select value={langFilter} onValueChange={setLangFilter}>
                <SelectTrigger className="w-36">
                  <SelectValue placeholder="Language" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Languages</SelectItem>
                  {languages.map((l) => (
                    <SelectItem key={l} value={l!}>{l}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            )}
          </div>

          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm text-muted-foreground">{filtered.length} findings</CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="w-8" />
                    <TableHead>Severity</TableHead>
                    <TableHead>Rule</TableHead>
                    <TableHead>File Path</TableHead>
                    <TableHead className="w-16">Line</TableHead>
                    <TableHead>Scanner</TableHead>
                    <TableHead>Language</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filtered.length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={7} className="text-center py-12 text-muted-foreground">
                        <div className="flex flex-col items-center gap-2">
                          <CheckCircle className="h-8 w-8 opacity-30 text-green-400" />
                          <p>No SAST findings found</p>
                        </div>
                      </TableCell>
                    </TableRow>
                  ) : (
                    filtered.map((finding, idx) => {
                      const id = finding.id || finding.finding_id || String(idx);
                      const isExpanded = expandedRow === id;
                      return (
                        <>
                          <TableRow
                            key={id}
                            className="cursor-pointer hover:bg-muted/40"
                            onClick={() => setExpandedRow(isExpanded ? null : id)}
                          >
                            <TableCell>
                              {isExpanded
                                ? <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" />
                                : <ChevronRight className="h-3.5 w-3.5 text-muted-foreground" />}
                            </TableCell>
                            <TableCell><SeverityBadge severity={finding.severity} /></TableCell>
                            <TableCell className="font-mono text-xs max-w-[200px]">
                              <span className="truncate block">{finding.rule || finding.title || "—"}</span>
                            </TableCell>
                            <TableCell className="font-mono text-xs max-w-[250px]">
                              <span className="truncate block text-blue-400">{finding.file || "—"}</span>
                            </TableCell>
                            <TableCell className="font-mono text-xs text-muted-foreground">
                              {finding.line || "—"}
                            </TableCell>
                            <TableCell><ScannerBadge scanner={finding.scanner} /></TableCell>
                            <TableCell className="text-xs text-muted-foreground">{finding.language || "—"}</TableCell>
                          </TableRow>
                          {isExpanded && (
                            <TableRow key={`${id}-detail`} className="hover:bg-transparent">
                              <TableCell colSpan={7} className="bg-muted/20 border-l-2 border-primary/30">
                                <div className="py-3 px-2 space-y-4">
                                  {/* Description */}
                                  {finding.description && (
                                    <div>
                                      <p className="text-xs font-semibold text-muted-foreground mb-1 uppercase tracking-wide">Description</p>
                                      <p className="text-sm">{finding.description}</p>
                                    </div>
                                  )}
                                  {/* Code Snippet */}
                                  {(finding.code_snippet || finding.file) && (
                                    <div>
                                      <p className="text-xs font-semibold text-muted-foreground mb-2 uppercase tracking-wide flex items-center gap-1">
                                        <FileCode className="h-3 w-3" /> Code Context
                                      </p>
                                      <pre className="bg-black/60 border border-white/10 rounded-md p-4 overflow-x-auto text-xs font-mono text-green-300 leading-relaxed">
                                        <code>{finding.code_snippet || `// ${finding.file}:${finding.line}\n// Code context unavailable`}</code>
                                      </pre>
                                    </div>
                                  )}
                                  {/* Fix Suggestion */}
                                  {finding.fix_suggestion && (
                                    <div>
                                      <p className="text-xs font-semibold text-muted-foreground mb-2 uppercase tracking-wide">Fix Suggestion</p>
                                      <div className="bg-green-500/5 border border-green-500/20 rounded-md p-3">
                                        <p className="text-sm text-green-300">{finding.fix_suggestion}</p>
                                      </div>
                                    </div>
                                  )}
                                  {/* Diff */}
                                  {finding.diff && (
                                    <div>
                                      <p className="text-xs font-semibold text-muted-foreground mb-2 uppercase tracking-wide">Suggested Diff</p>
                                      <pre className="bg-black/60 border border-white/10 rounded-md p-4 overflow-x-auto text-xs font-mono leading-relaxed">
                                        <code>
                                          {finding.diff.split("\n").map((line, i) => (
                                            <span
                                              key={i}
                                              className={cn(
                                                "block",
                                                line.startsWith("+") ? "text-green-400 bg-green-500/10" : "",
                                                line.startsWith("-") ? "text-red-400 bg-red-500/10" : "text-muted-foreground"
                                              )}
                                            >
                                              {line}
                                            </span>
                                          ))}
                                        </code>
                                      </pre>
                                    </div>
                                  )}
                                  <div className="flex gap-2 pt-1">
                                    <Button size="sm" variant="outline" onClick={() => setDetailFinding(finding)}>
                                      View Full Detail
                                    </Button>
                                    <Button size="sm" variant="outline" onClick={() => {
                                      const f = finding as Record<string, unknown>;
                                      const title = (f.title || f.rule || f.cve || "Code finding") as string;
                                      navigate(`/remediate/ticket-integration?title=${encodeURIComponent(title)}&source=sast`);
                                    }}>Create Ticket</Button>
                                  </div>
                                </div>
                              </TableCell>
                            </TableRow>
                          )}
                        </>
                      );
                    })
                  )}
                </TableBody>
              </Table>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Scanner Comparison Tab */}
        <TabsContent value="comparison" className="space-y-4 mt-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <Card>
              <CardHeader>
                <CardTitle className="text-sm">Findings by Scanner</CardTitle>
              </CardHeader>
              <CardContent>
                {scannerChartData.length === 0 ? (
                  <div className="h-48 flex items-center justify-center text-muted-foreground text-sm">
                    No data available
                  </div>
                ) : (
                  <ResponsiveContainer width="100%" height={220}>
                    <BarChart data={scannerChartData} margin={{ top: 0, right: 8, left: -10, bottom: 0 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
                      <XAxis dataKey="name" tick={{ fontSize: 11 }} stroke="rgba(255,255,255,0.2)" />
                      <YAxis tick={{ fontSize: 11 }} stroke="rgba(255,255,255,0.2)" />
                      <Tooltip
                        contentStyle={{ background: "hsl(var(--popover))", border: "1px solid hsl(var(--border))", borderRadius: 8, fontSize: 12 }}
                        cursor={{ fill: "rgba(255,255,255,0.04)" }}
                      />
                      <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                        {scannerChartData.map((entry, i) => (
                          <Cell key={i} fill={entry.color} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                )}
              </CardContent>
            </Card>

            <Card>
              <CardHeader>
                <CardTitle className="text-sm">Findings by Severity</CardTitle>
              </CardHeader>
              <CardContent>
                {severityChartData.length === 0 ? (
                  <div className="h-48 flex items-center justify-center text-muted-foreground text-sm">
                    No data available
                  </div>
                ) : (
                  <ResponsiveContainer width="100%" height={220}>
                    <BarChart data={severityChartData} margin={{ top: 0, right: 8, left: -10, bottom: 0 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,0.06)" />
                      <XAxis dataKey="name" tick={{ fontSize: 11 }} stroke="rgba(255,255,255,0.2)" />
                      <YAxis tick={{ fontSize: 11 }} stroke="rgba(255,255,255,0.2)" />
                      <Tooltip
                        contentStyle={{ background: "hsl(var(--popover))", border: "1px solid hsl(var(--border))", borderRadius: 8, fontSize: 12 }}
                        cursor={{ fill: "rgba(255,255,255,0.04)" }}
                      />
                      <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                        {severityChartData.map((entry, i) => (
                          <Cell key={i} fill={entry.color} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Scanner breakdown table */}
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Scanner Breakdown</CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead>Scanner</TableHead>
                    <TableHead className="text-right">Findings</TableHead>
                    <TableHead className="text-right">Critical</TableHead>
                    <TableHead className="text-right">High</TableHead>
                    <TableHead className="text-right">Medium</TableHead>
                    <TableHead className="text-right">Low</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {Object.entries(stats.byScanner).length === 0 ? (
                    <TableRow>
                      <TableCell colSpan={6} className="text-center py-8 text-muted-foreground">
                        No scanner data available
                      </TableCell>
                    </TableRow>
                  ) : (
                    Object.entries(stats.byScanner).map(([scanner, count]) => {
                      const scannerFindings = allFindings.filter((f) => f.scanner?.toLowerCase() === scanner);
                      return (
                        <TableRow key={scanner}>
                          <TableCell><ScannerBadge scanner={scanner} /></TableCell>
                          <TableCell className="text-right font-mono text-sm">{count}</TableCell>
                          {["critical", "high", "medium", "low"].map((sev) => (
                            <TableCell key={sev} className="text-right font-mono text-sm text-muted-foreground">
                              {scannerFindings.filter((f) => f.severity?.toLowerCase() === sev).length}
                            </TableCell>
                          ))}
                        </TableRow>
                      );
                    })
                  )}
                </TableBody>
              </Table>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Full Detail Dialog */}
      <Dialog open={!!detailFinding} onOpenChange={(open) => { if (!open) setDetailFinding(null); }}>
        <DialogContent className="max-w-3xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-3">
              <SeverityBadge severity={detailFinding?.severity} />
              <span className="truncate">{detailFinding?.title || detailFinding?.rule}</span>
            </DialogTitle>
          </DialogHeader>
          {detailFinding && (
            <div className="space-y-4">
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
                {[
                  { label: "Scanner", value: <ScannerBadge scanner={detailFinding.scanner} /> },
                  { label: "Language", value: detailFinding.language || "—" },
                  { label: "Rule", value: <code className="text-xs font-mono">{detailFinding.rule || "—"}</code> },
                ].map(({ label, value }) => (
                  <div key={label}>
                    <p className="text-xs text-muted-foreground mb-1">{label}</p>
                    <div className="text-sm font-medium">{value}</div>
                  </div>
                ))}
              </div>
              <Separator />
              <div>
                <p className="text-xs font-semibold text-muted-foreground mb-1">Location</p>
                <code className="text-xs font-mono text-blue-400 bg-muted/50 px-2 py-1 rounded block">
                  {detailFinding.file || "—"}{detailFinding.line ? `:${detailFinding.line}` : ""}
                </code>
              </div>
              {detailFinding.description && (
                <div>
                  <p className="text-xs font-semibold text-muted-foreground mb-1">Description</p>
                  <p className="text-sm">{detailFinding.description}</p>
                </div>
              )}
              {detailFinding.code_snippet && (
                <div>
                  <p className="text-xs font-semibold text-muted-foreground mb-2">Code Context</p>
                  <pre className="bg-black/70 border rounded-md p-4 overflow-x-auto text-xs font-mono text-green-300 leading-relaxed">
                    <code>{detailFinding.code_snippet}</code>
                  </pre>
                </div>
              )}
              {detailFinding.fix_suggestion && (
                <div>
                  <p className="text-xs font-semibold text-muted-foreground mb-2">Fix Suggestion</p>
                  <div className="bg-green-500/5 border border-green-500/20 rounded-md p-3">
                    <p className="text-sm text-green-300">{detailFinding.fix_suggestion}</p>
                  </div>
                </div>
              )}
              <div className="flex gap-2">
                <Button size="sm" onClick={() => {
                  const id = detailFinding.id || detailFinding.finding_id || "";
                  autofixMutation.mutate(id, {
                    onSuccess: () => { toast.success("Fix accepted — check Remediation Center"); setDetailFinding(null); },
                    onError: () => toast.error("AutoFix failed"),
                  });
                }}>Accept Fix</Button>
                <Button size="sm" variant="outline" onClick={() => {
                  const title = detailFinding.title || detailFinding.rule || "Code finding";
                  navigate(`/remediate/ticket-integration?title=${encodeURIComponent(title)}&source=sast`);
                }}>Create Ticket</Button>
                <Button size="sm" variant="outline" onClick={async () => {
                  try {
                    const id = detailFinding.id || detailFinding.finding_id || "";
                    await findingsApi.triage(id, "false_positive");
                    toast.success("Marked as false positive");
                    setDetailFinding(null);
                    query.refetch();
                  } catch { toast.error("Failed to mark as false positive"); }
                }}>Mark False Positive</Button>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </motion.div>
  );
}
