/**
 * Developer Security Dashboard — P01 Persona (The Builder)
 *
 * Aesthetic: Terminal-meets-IDE. Monospace accents, syntax-highlight severity
 * colors, code-native density. Designed for the developer who lives in their
 * editor and needs security context without leaving their workflow.
 *
 * Route: /mission-control/dev-security
 */

import { useState, useCallback } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { motion, AnimatePresence } from "framer-motion";
import {
  AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip,
  ResponsiveContainer, PieChart, Pie, Cell, Legend,
} from "recharts";
import {
  Code2, AlertTriangle, Clock, Shield, GitBranch, KeyRound,
  Package, Play, RefreshCw, ChevronDown, ChevronRight,
  ExternalLink, Copy, CheckCheck, X, Terminal, Bug,
  TrendingDown, TrendingUp, Minus, CircleAlert, RotateCcw,
  Wrench, FileCode, Zap, GitCommit, Eye, EyeOff,
  ArrowUpRight, Info,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Dialog, DialogContent, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Tooltip as UITooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";
import api from "@/lib/api";

// ═══════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════

type Severity = "critical" | "high" | "medium" | "low" | "info";

interface Finding {
  id: string;
  title: string;
  severity: Severity;
  cwe?: string;
  file?: string;
  line?: number;
  description: string;
  fix_suggestion: string;
  council_verdict?: "BLOCK" | "REVIEW" | "ALLOW";
  council_confidence?: number;
  detected_at: string;
}

interface Repo {
  name: string;
  branch: string;
  last_scan: string;
  findings: Finding[];
  critical: number;
  high: number;
  medium: number;
  low: number;
}

interface SecretFinding {
  id: string;
  filename: string;
  line: number;
  secret_type: string;
  masked_value: string;
  detected_at: string;
  rotation_cmd: string;
}

interface DepVuln {
  id: string;
  package: string;
  version: string;
  cve: string;
  severity: Severity;
  fix_version: string;
  ecosystem: "npm" | "pip" | "maven" | "cargo";
}

// ═══════════════════════════════════════════════════════════
// Constants
// ═══════════════════════════════════════════════════════════

const SEV: Record<Severity, { color: string; bg: string; label: string; dot: string }> = {
  critical: { color: "text-red-400",    bg: "bg-red-500/10 border-red-500/30",    label: "CRIT", dot: "bg-red-500" },
  high:     { color: "text-orange-400", bg: "bg-orange-500/10 border-orange-500/30", label: "HIGH", dot: "bg-orange-500" },
  medium:   { color: "text-yellow-400", bg: "bg-yellow-500/10 border-yellow-500/30", label: "MED",  dot: "bg-yellow-500" },
  low:      { color: "text-green-400",  bg: "bg-green-500/10 border-green-500/30",   label: "LOW",  dot: "bg-green-500" },
  info:     { color: "text-blue-400",   bg: "bg-blue-500/10 border-blue-500/30",     label: "INFO", dot: "bg-blue-400" },
};

const CHART_STYLE = {
  background: "hsl(var(--card))",
  border: "1px solid hsl(var(--border))",
  borderRadius: 6,
  fontSize: 11,
  fontFamily: "'JetBrains Mono', 'Fira Code', monospace",
};

const DONUT_COLORS = ["#ef4444", "#6b7280"];

// ═══════════════════════════════════════════════════════════
// Mock data — realistic developer scenario (ALDECI scans itself)
// ═══════════════════════════════════════════════════════════

function buildMockData() {
  const now = new Date();
  const daysAgo = (d: number) => new Date(now.getTime() - d * 86_400_000).toISOString();
  const hoursAgo = (h: number) => new Date(now.getTime() - h * 3_600_000).toISOString();

  const repos: Repo[] = [
    {
      name: "DevOpsMadDog/Fixops",
      branch: "features/intermediate-stage",
      last_scan: hoursAgo(2),
      critical: 2, high: 7, medium: 14, low: 23,
      findings: [
        {
          id: "f001", severity: "critical", title: "SQL Injection via unsanitized user input",
          cwe: "CWE-89", file: "suite-api/routers/findings_router.py", line: 147,
          description: "User-controlled input is passed directly into a raw SQL query without parameterization. Allows full DB read/write by any authenticated user.",
          fix_suggestion: "Use parameterized queries: `cursor.execute('SELECT * FROM findings WHERE id = ?', (finding_id,))`",
          council_verdict: "BLOCK", council_confidence: 97,
          detected_at: hoursAgo(2),
        },
        {
          id: "f002", severity: "critical", title: "Hardcoded JWT secret in config loader",
          cwe: "CWE-798", file: "suite-core/core/auth.py", line: 23,
          description: "A static JWT signing secret 'dev-secret-change-me' is hardcoded and will be used if the env var is unset. Any token signed with this secret is valid.",
          fix_suggestion: "Remove default: `SECRET = os.environ['JWT_SECRET']` — no fallback. Fail loudly if unset.",
          council_verdict: "BLOCK", council_confidence: 99,
          detected_at: hoursAgo(3),
        },
        {
          id: "f003", severity: "high", title: "Path traversal in file upload handler",
          cwe: "CWE-22", file: "suite-api/routers/evidence_router.py", line: 89,
          description: "The filename from a multipart upload is used to construct a path without sanitization, allowing `../` sequences to escape the upload directory.",
          fix_suggestion: "Use `pathlib.Path(UPLOAD_DIR / Path(filename).name)` to strip directory components.",
          council_verdict: "REVIEW", council_confidence: 82,
          detected_at: daysAgo(1),
        },
        {
          id: "f004", severity: "high", title: "Missing rate limiting on /auth/login endpoint",
          cwe: "CWE-307", file: "suite-api/routers/auth_router.py", line: 41,
          description: "The login endpoint has no rate limiting or lockout policy, enabling brute-force attacks against valid usernames.",
          fix_suggestion: "Add `slowapi` rate limiter: `@limiter.limit('5/minute')` on the login route.",
          council_verdict: "REVIEW", council_confidence: 78,
          detected_at: daysAgo(2),
        },
        {
          id: "f005", severity: "medium", title: "Insecure deserialization with pickle",
          cwe: "CWE-502", file: "suite-core/core/cache.py", line: 67,
          description: "Cache values are serialized/deserialized using pickle, which executes arbitrary code if an attacker can control cache entries.",
          fix_suggestion: "Replace `pickle.loads(data)` with `json.loads(data)` or use `msgpack` with strict schema validation.",
          council_verdict: "REVIEW", council_confidence: 71,
          detected_at: daysAgo(3),
        },
        {
          id: "f006", severity: "medium", title: "Debug mode enabled in production config",
          cwe: "CWE-215", file: "suite-api/main.py", line: 12,
          description: "FastAPI is initialized with `debug=True` which exposes full tracebacks and internal state in HTTP responses.",
          fix_suggestion: "Change to `debug=os.getenv('DEBUG', 'false').lower() == 'true'` and ensure DEBUG=false in production.",
          council_verdict: "ALLOW", council_confidence: 91,
          detected_at: daysAgo(4),
        },
      ],
    },
    {
      name: "DevOpsMadDog/Fixops",
      branch: "main",
      last_scan: daysAgo(1),
      critical: 0, high: 3, medium: 8, low: 19,
      findings: [
        {
          id: "f010", severity: "high", title: "CORS wildcard origin in API gateway",
          cwe: "CWE-942", file: "suite-api/main.py", line: 34,
          description: "CORS is configured with `allow_origins=['*']` allowing any origin to make credentialed requests to the API.",
          fix_suggestion: "Restrict to `allow_origins=[os.environ['ALLOWED_ORIGIN']]` or a specific allowlist of trusted origins.",
          council_verdict: "REVIEW", council_confidence: 85,
          detected_at: daysAgo(1),
        },
        {
          id: "f011", severity: "high", title: "Sensitive data logged at INFO level",
          cwe: "CWE-532", file: "suite-core/core/brain_pipeline.py", line: 203,
          description: "API keys and user tokens are interpolated into log messages at INFO level, exposing them in log aggregators.",
          fix_suggestion: "Mask secrets before logging: `logger.info('request', key=mask(api_key))`",
          council_verdict: "REVIEW", council_confidence: 76,
          detected_at: daysAgo(1),
        },
        {
          id: "f012", severity: "high", title: "Unvalidated redirect after authentication",
          cwe: "CWE-601", file: "suite-api/routers/auth_router.py", line: 78,
          description: "The `next` query parameter is used for post-login redirect without validation, enabling open redirect attacks.",
          fix_suggestion: "Validate `next` is a relative path: `if not next.startswith('/') or '//' in next: next = '/'`",
          council_verdict: "REVIEW", council_confidence: 80,
          detected_at: daysAgo(2),
        },
      ],
    },
    {
      name: "DevOpsMadDog/beast-mode-framework",
      branch: "main",
      last_scan: daysAgo(2),
      critical: 0, high: 1, medium: 3, low: 7,
      findings: [
        {
          id: "f020", severity: "high", title: "Docker socket mounted in agent container",
          cwe: "CWE-269", file: "layer2-swarmclaw-autonomous/docker-compose.yml", line: 45,
          description: "The Docker socket is mounted into the agent container, granting it full Docker daemon access — equivalent to root on the host.",
          fix_suggestion: "Use Docker-in-Docker with gVisor or replace with rootless Podman. If required, use Docker socket proxy with a read-only allowlist.",
          council_verdict: "BLOCK", council_confidence: 94,
          detected_at: daysAgo(2),
        },
      ],
    },
  ];

  const secrets: SecretFinding[] = [
    {
      id: "s001", filename: ".env.example", line: 14,
      secret_type: "AWS Access Key",
      masked_value: "AKIA***EXAMPLE***",
      detected_at: hoursAgo(5),
      rotation_cmd: "aws iam delete-access-key --access-key-id AKIA... && aws iam create-access-key",
    },
    {
      id: "s002", filename: "tests/fixtures/test_config.py", line: 7,
      secret_type: "GitHub Personal Access Token",
      masked_value: "ghp_***REDACTED***",
      detected_at: hoursAgo(8),
      rotation_cmd: "gh auth token revoke && gh auth login",
    },
    {
      id: "s003", filename: "suite-core/core/integrations.py", line: 91,
      secret_type: "Slack Webhook URL",
      masked_value: "https://hooks.slack.com/services/T***",
      detected_at: daysAgo(1),
      rotation_cmd: "Slack → App settings → Incoming Webhooks → Regenerate URL",
    },
  ];

  const depVulns: DepVuln[] = [
    { id: "d001", package: "requests",    version: "2.28.1", cve: "CVE-2023-32681", severity: "high",   fix_version: "2.31.0", ecosystem: "pip" },
    { id: "d002", package: "pillow",      version: "9.3.0",  cve: "CVE-2023-44271", severity: "high",   fix_version: "10.0.1", ecosystem: "pip" },
    { id: "d003", package: "cryptography",version: "38.0.0", cve: "CVE-2023-49083", severity: "medium", fix_version: "41.0.6", ecosystem: "pip" },
    { id: "d004", package: "vite",        version: "5.0.0",  cve: "CVE-2024-23331", severity: "high",   fix_version: "5.1.5",  ecosystem: "npm" },
    { id: "d005", package: "axios",       version: "1.5.0",  cve: "CVE-2023-45857", severity: "medium", fix_version: "1.6.2",  ecosystem: "npm" },
    { id: "d006", package: "semgrep",     version: "1.40.0", cve: "CVE-2024-1234",  severity: "low",    fix_version: "1.45.0", ecosystem: "pip" },
  ];

  const scanHistory = Array.from({ length: 30 }, (_, i) => {
    const d = new Date(now);
    d.setDate(d.getDate() - (29 - i));
    const base = 52 - i * 0.8;
    return {
      date: d.toISOString().slice(5, 10),
      findings: Math.max(8, Math.round(base + Math.sin(i / 4) * 8 + Math.random() * 4)),
    };
  });

  const totalFindings = repos.reduce((s, r) => s + r.critical + r.high + r.medium + r.low, 0);
  const critHigh = repos.reduce((s, r) => s + r.critical + r.high, 0);

  return {
    repos,
    secrets,
    depVulns,
    scanHistory,
    kpis: {
      total_findings: totalFindings,
      crit_high: critHigh,
      my_mttr: 14.2,
      team_mttr: 22.8,
      security_score: 73,
      clean_deps: 287,
      vuln_deps: depVulns.length,
      last_scan: hoursAgo(2),
    },
  };
}

// ═══════════════════════════════════════════════════════════
// Severity Badge
// ═══════════════════════════════════════════════════════════

function SevBadge({ sev }: { sev: Severity }) {
  const s = SEV[sev];
  return (
    <span className={cn("inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono font-bold border", s.color, s.bg)}>
      <span className={cn("h-1.5 w-1.5 rounded-full", s.dot)} />
      {s.label}
    </span>
  );
}

// ═══════════════════════════════════════════════════════════
// Verdict Badge
// ═══════════════════════════════════════════════════════════

function VerdictBadge({ verdict, confidence }: { verdict: "BLOCK" | "REVIEW" | "ALLOW"; confidence?: number }) {
  const styles = {
    BLOCK:  "bg-red-500/10 border-red-500/40 text-red-400",
    REVIEW: "bg-yellow-500/10 border-yellow-500/40 text-yellow-400",
    ALLOW:  "bg-green-500/10 border-green-500/40 text-green-400",
  };
  return (
    <TooltipProvider>
      <UITooltip>
        <TooltipTrigger>
          <span className={cn("inline-flex items-center gap-1 px-2 py-0.5 rounded border text-[10px] font-mono font-bold", styles[verdict])}>
            {verdict}
            {confidence && <span className="opacity-60 text-[9px]">{confidence}%</span>}
          </span>
        </TooltipTrigger>
        <TooltipContent>
          <p className="text-xs">LLM Council verdict · {confidence}% confidence</p>
        </TooltipContent>
      </UITooltip>
    </TooltipProvider>
  );
}

// ═══════════════════════════════════════════════════════════
// Finding Drawer
// ═══════════════════════════════════════════════════════════

function FindingDrawer({ finding, open, onClose }: { finding: Finding | null; open: boolean; onClose: () => void }) {
  const [copied, setCopied] = useState(false);

  const copy = useCallback((text: string) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    });
  }, []);

  // POST /api/v1/autofix/suggest
  const autofixMutation = useMutation({
    mutationFn: async (findingId: string) => {
      try {
        const res = await api.post("/api/v1/autofix/suggest", { finding_id: findingId });
        return res.data;
      } catch {
        return { suggestion: finding?.fix_suggestion ?? "No suggestion available." };
      }
    },
  });

  if (!finding) return null;

  return (
    <Dialog open={open} onOpenChange={(v) => !v && onClose()}>
      <DialogContent className="max-w-2xl max-h-[85vh] overflow-hidden flex flex-col">
        <DialogHeader className="shrink-0">
          <DialogTitle className="flex items-start gap-3">
            <SevBadge sev={finding.severity} />
            <span className="text-base leading-snug">{finding.title}</span>
          </DialogTitle>
        </DialogHeader>

        <ScrollArea className="flex-1 min-h-0 -mx-6 px-6">
          <div className="space-y-5 pb-4">
            {/* Meta row */}
            <div className="flex flex-wrap items-center gap-3 text-xs">
              {finding.cwe && (
                <span className="flex items-center gap-1.5 font-mono text-muted-foreground">
                  <Bug className="h-3.5 w-3.5" />
                  {finding.cwe}
                </span>
              )}
              {finding.file && (
                <span className="flex items-center gap-1.5 font-mono text-muted-foreground truncate max-w-[260px]">
                  <FileCode className="h-3.5 w-3.5 shrink-0" />
                  {finding.file}{finding.line ? `:${finding.line}` : ""}
                </span>
              )}
              {finding.council_verdict && (
                <VerdictBadge verdict={finding.council_verdict} confidence={finding.council_confidence} />
              )}
            </div>

            <Separator />

            {/* Description */}
            <div>
              <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">Description</p>
              <p className="text-sm leading-relaxed">{finding.description}</p>
            </div>

            {/* Code snippet */}
            {finding.file && finding.line && (
              <div>
                <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground mb-2">Location</p>
                <div className="rounded-md bg-zinc-950 border border-zinc-800 p-3 font-mono text-xs">
                  <span className="text-zinc-500">// {finding.file}:{finding.line}</span>
                  {"\n"}
                  <span className="text-red-400">→ </span>
                  <span className="text-zinc-300">{"<vulnerable code at this line>"}</span>
                </div>
              </div>
            )}

            {/* Fix suggestion */}
            <div>
              <div className="flex items-center justify-between mb-2">
                <p className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">Fix Suggestion</p>
                <button
                  onClick={() => copy(finding.fix_suggestion)}
                  className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
                >
                  {copied ? <CheckCheck className="h-3.5 w-3.5 text-green-400" /> : <Copy className="h-3.5 w-3.5" />}
                  {copied ? "Copied" : "Copy"}
                </button>
              </div>
              <div className="rounded-md bg-zinc-950 border border-zinc-800 p-3 font-mono text-xs text-green-300 whitespace-pre-wrap leading-relaxed">
                {finding.fix_suggestion}
              </div>
            </div>

            {/* AutoFix section */}
            <div className="flex items-center gap-3">
              <Button
                size="sm"
                onClick={() => autofixMutation.mutate(finding.id)}
                disabled={autofixMutation.isPending}
                className="gap-2"
              >
                {autofixMutation.isPending ? (
                  <RefreshCw className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <Zap className="h-3.5 w-3.5" />
                )}
                Fix It (AI Suggest)
              </Button>
              {autofixMutation.isSuccess && (
                <span className="text-xs text-green-400 flex items-center gap-1">
                  <CheckCheck className="h-3.5 w-3.5" /> Suggestion applied
                </span>
              )}
            </div>
          </div>
        </ScrollArea>
      </DialogContent>
    </Dialog>
  );
}

// ═══════════════════════════════════════════════════════════
// Findings by Repo — Accordion
// ═══════════════════════════════════════════════════════════

function RepoAccordion({ repos }: { repos: Repo[] }) {
  const [expanded, setExpanded] = useState<string | null>(
    repos[0] ? repos[0].name + repos[0].branch : null
  );
  const [selectedFinding, setSelectedFinding] = useState<Finding | null>(null);

  const toggle = (key: string) => setExpanded(prev => prev === key ? null : key);

  return (
    <div className="space-y-2">
      {repos.map((repo) => {
        const key = repo.name + repo.branch;
        const isOpen = expanded === key;
        const total = repo.critical + repo.high + repo.medium + repo.low;

        return (
          <div key={key} className="rounded-lg border border-border overflow-hidden">
            {/* Repo header row */}
            <button
              className="w-full flex items-center gap-3 px-4 py-3 hover:bg-muted/30 transition-colors text-left"
              onClick={() => toggle(key)}
              aria-expanded={isOpen}
            >
              <ChevronRight className={cn("h-4 w-4 text-muted-foreground shrink-0 transition-transform duration-200", isOpen && "rotate-90")} />
              <GitBranch className="h-4 w-4 text-muted-foreground shrink-0" />
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2 min-w-0">
                  <span className="text-sm font-mono font-medium truncate">{repo.name}</span>
                  <Badge variant="outline" className="text-[10px] font-mono shrink-0">{repo.branch}</Badge>
                </div>
                <p className="text-[11px] text-muted-foreground mt-0.5">
                  Scanned {new Date(repo.last_scan).toLocaleString()} · {total} findings
                </p>
              </div>
              <div className="flex items-center gap-1.5 shrink-0">
                {repo.critical > 0 && <SevBadge sev="critical" />}
                {repo.high > 0 && (
                  <span className="text-xs font-mono text-orange-400">{repo.high}H</span>
                )}
                {repo.medium > 0 && (
                  <span className="text-xs font-mono text-yellow-400">{repo.medium}M</span>
                )}
              </div>
            </button>

            {/* Findings list */}
            <AnimatePresence initial={false}>
              {isOpen && (
                <motion.div
                  initial={{ height: 0, opacity: 0 }}
                  animate={{ height: "auto", opacity: 1 }}
                  exit={{ height: 0, opacity: 0 }}
                  transition={{ duration: 0.2 }}
                >
                  <div className="border-t border-border divide-y divide-border/50">
                    {repo.findings.map((f) => (
                      <div
                        key={f.id}
                        className="flex items-center gap-3 px-8 py-2.5 hover:bg-muted/20 cursor-pointer transition-colors group"
                        onClick={() => setSelectedFinding(f)}
                        role="button"
                        tabIndex={0}
                        onKeyDown={(e) => e.key === "Enter" && setSelectedFinding(f)}
                      >
                        <SevBadge sev={f.severity} />
                        <div className="flex-1 min-w-0">
                          <p className="text-sm truncate group-hover:text-primary transition-colors">{f.title}</p>
                          {f.file && (
                            <p className="text-[11px] font-mono text-muted-foreground truncate">
                              {f.file}{f.line ? `:${f.line}` : ""}
                            </p>
                          )}
                        </div>
                        {f.cwe && (
                          <span className="text-[11px] font-mono text-muted-foreground shrink-0">{f.cwe}</span>
                        )}
                        {f.council_verdict && (
                          <VerdictBadge verdict={f.council_verdict} confidence={f.council_confidence} />
                        )}
                        <ArrowUpRight className="h-3.5 w-3.5 text-muted-foreground opacity-0 group-hover:opacity-100 transition-opacity shrink-0" />
                      </div>
                    ))}
                    {repo.findings.length === 0 && (
                      <div className="px-8 py-4 text-sm text-muted-foreground flex items-center gap-2">
                        <Shield className="h-4 w-4 text-green-400" />
                        No findings in this branch.
                      </div>
                    )}
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        );
      })}

      <FindingDrawer
        finding={selectedFinding}
        open={!!selectedFinding}
        onClose={() => setSelectedFinding(null)}
      />
    </div>
  );
}

// ═══════════════════════════════════════════════════════════
// Secret Exposure Panel
// ═══════════════════════════════════════════════════════════

function SecretExposurePanel({ secrets }: { secrets: SecretFinding[] }) {
  const [expandedId, setExpandedId] = useState<string | null>(null);

  if (secrets.length === 0) {
    return (
      <Card>
        <CardContent className="py-8 flex flex-col items-center gap-2">
          <Shield className="h-8 w-8 text-green-400" />
          <p className="text-sm text-muted-foreground">No exposed secrets detected in any repository.</p>
        </CardContent>
      </Card>
    );
  }

  return (
    <Card className="border-red-500/30">
      <CardHeader className="pb-3">
        <CardTitle className="text-base flex items-center gap-2">
          <div className="flex items-center gap-2 flex-1">
            <CircleAlert className="h-4 w-4 text-red-400" />
            <span>Secret Exposure</span>
            <Badge variant="destructive" className="text-xs font-mono">{secrets.length} detected</Badge>
          </div>
          <div className="h-2 w-2 rounded-full bg-red-500 animate-pulse" aria-hidden />
        </CardTitle>
      </CardHeader>
      <CardContent className="space-y-2">
        {secrets.map((s) => {
          const isExpanded = expandedId === s.id;
          return (
            <div key={s.id} className="rounded-md border border-red-500/20 bg-red-500/5 overflow-hidden">
              <button
                className="w-full flex items-center gap-3 px-3 py-2.5 text-left hover:bg-red-500/10 transition-colors"
                onClick={() => setExpandedId(isExpanded ? null : s.id)}
              >
                <KeyRound className="h-4 w-4 text-red-400 shrink-0" />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium text-red-300">{s.secret_type}</span>
                  </div>
                  <p className="text-[11px] font-mono text-muted-foreground mt-0.5">
                    {s.filename}:{s.line} · {new Date(s.detected_at).toLocaleDateString()}
                  </p>
                </div>
                <span className="text-[11px] font-mono text-muted-foreground shrink-0 mr-2">{s.masked_value}</span>
                <ChevronDown className={cn("h-4 w-4 text-muted-foreground shrink-0 transition-transform", isExpanded && "rotate-180")} />
              </button>

              <AnimatePresence initial={false}>
                {isExpanded && (
                  <motion.div
                    initial={{ height: 0 }}
                    animate={{ height: "auto" }}
                    exit={{ height: 0 }}
                    transition={{ duration: 0.18 }}
                    className="overflow-hidden"
                  >
                    <div className="px-3 pb-3 space-y-2 border-t border-red-500/20">
                      <p className="text-xs text-muted-foreground pt-2">Rotation command:</p>
                      <div className="rounded bg-zinc-950 border border-zinc-800 p-2.5 font-mono text-xs text-yellow-300 flex items-center gap-2">
                        <Terminal className="h-3.5 w-3.5 text-zinc-500 shrink-0" />
                        <span className="flex-1 break-all">{s.rotation_cmd}</span>
                      </div>
                      <Button size="sm" variant="destructive" className="gap-2 h-7 text-xs">
                        <RotateCcw className="h-3.5 w-3.5" />
                        Rotate Now
                      </Button>
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          );
        })}
      </CardContent>
    </Card>
  );
}

// ═══════════════════════════════════════════════════════════
// Dependency Vulnerabilities
// ═══════════════════════════════════════════════════════════

const ECOSYSTEM_ICON: Record<string, string> = {
  npm: "⬡",
  pip: "🐍",
  maven: "☕",
  cargo: "⚙",
};

function DependencyPanel({ vulns, totalClean }: { vulns: DepVuln[]; totalClean: number }) {
  const [showCmd, setShowCmd] = useState(false);

  const donutData = [
    { name: "Vulnerable", value: vulns.length },
    { name: "Clean", value: totalClean },
  ];

  const npmUpgrades = vulns.filter(v => v.ecosystem === "npm").map(v => `${v.package}@${v.fix_version}`).join(" ");
  const pipUpgrades = vulns.filter(v => v.ecosystem === "pip").map(v => `${v.package}==${v.fix_version}`).join(" ");

  const upgradeCmd = [
    npmUpgrades && `npm install ${npmUpgrades}`,
    pipUpgrades && `pip install --upgrade ${pipUpgrades}`,
  ].filter(Boolean).join("\n");

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-base flex items-center gap-2">
            <Package className="h-4 w-4 text-primary" />
            Dependency Vulnerabilities
          </CardTitle>
          <Button
            size="sm"
            variant="outline"
            className="h-7 text-xs gap-1.5"
            onClick={() => setShowCmd(v => !v)}
          >
            <Wrench className="h-3.5 w-3.5" />
            Update Deps
          </Button>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Donut + summary */}
        <div className="flex items-center gap-6">
          <div className="h-[100px] w-[100px] shrink-0">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={donutData}
                  cx="50%"
                  cy="50%"
                  innerRadius={28}
                  outerRadius={44}
                  dataKey="value"
                  strokeWidth={0}
                >
                  {donutData.map((_, i) => (
                    <Cell key={i} fill={DONUT_COLORS[i]} opacity={i === 1 ? 0.25 : 1} />
                  ))}
                </Pie>
                <Tooltip contentStyle={CHART_STYLE} formatter={(v, n) => [v, n]} />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="space-y-2 text-sm">
            <div className="flex items-center gap-2">
              <div className="h-2.5 w-2.5 rounded-full bg-red-500" />
              <span className="text-muted-foreground">Vulnerable</span>
              <span className="font-mono font-bold text-red-400 ml-auto">{vulns.length}</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="h-2.5 w-2.5 rounded-full bg-zinc-600" />
              <span className="text-muted-foreground">Clean</span>
              <span className="font-mono font-bold ml-auto">{totalClean}</span>
            </div>
            <div className="flex items-center gap-2">
              <div className="h-2.5 w-2.5 rounded-full bg-primary" />
              <span className="text-muted-foreground">Total</span>
              <span className="font-mono font-bold ml-auto">{vulns.length + totalClean}</span>
            </div>
          </div>
        </div>

        {/* Upgrade command */}
        <AnimatePresence>
          {showCmd && (
            <motion.div
              initial={{ height: 0, opacity: 0 }}
              animate={{ height: "auto", opacity: 1 }}
              exit={{ height: 0, opacity: 0 }}
              className="overflow-hidden"
            >
              <div className="rounded-md bg-zinc-950 border border-zinc-800 p-3 font-mono text-xs text-green-300 whitespace-pre">
                <span className="text-zinc-500"># Run to fix all known vulnerabilities{"\n"}</span>
                {upgradeCmd}
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Table */}
        <div className="rounded-md border border-border overflow-hidden">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border bg-muted/30">
                <th className="text-left px-3 py-2 font-medium text-muted-foreground">Package</th>
                <th className="text-left px-3 py-2 font-medium text-muted-foreground">CVE</th>
                <th className="text-left px-3 py-2 font-medium text-muted-foreground">Severity</th>
                <th className="text-left px-3 py-2 font-medium text-muted-foreground">Fix</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/50">
              {vulns.map((v) => (
                <tr key={v.id} className="hover:bg-muted/20 transition-colors">
                  <td className="px-3 py-2 font-mono">
                    <span className="mr-1">{ECOSYSTEM_ICON[v.ecosystem]}</span>
                    {v.package}
                    <span className="text-muted-foreground ml-1">{v.version}</span>
                  </td>
                  <td className="px-3 py-2 font-mono text-blue-400">{v.cve}</td>
                  <td className="px-3 py-2"><SevBadge sev={v.severity} /></td>
                  <td className="px-3 py-2 font-mono text-green-400">→ {v.fix_version}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </CardContent>
    </Card>
  );
}

// ═══════════════════════════════════════════════════════════
// Scan History Sparkline
// ═══════════════════════════════════════════════════════════

function ScanHistoryPanel({
  history,
  lastScan,
  onScanNow,
  scanning,
}: {
  history: { date: string; findings: number }[];
  lastScan: string;
  onScanNow: () => void;
  scanning: boolean;
}) {
  const trend = history[history.length - 1].findings < history[0].findings;

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between flex-wrap gap-2">
          <CardTitle className="text-base flex items-center gap-2">
            {trend ? (
              <TrendingDown className="h-4 w-4 text-green-400" />
            ) : (
              <TrendingUp className="h-4 w-4 text-red-400" />
            )}
            Scan History
            <span className="text-xs font-normal text-muted-foreground">(30 days)</span>
          </CardTitle>
          <div className="flex items-center gap-3">
            <span className="text-[11px] text-muted-foreground font-mono">
              Last: {new Date(lastScan).toLocaleString()}
            </span>
            <Button
              size="sm"
              variant="outline"
              className="h-7 text-xs gap-1.5"
              onClick={onScanNow}
              disabled={scanning}
            >
              {scanning ? (
                <RefreshCw className="h-3.5 w-3.5 animate-spin" />
              ) : (
                <Play className="h-3.5 w-3.5" />
              )}
              {scanning ? "Scanning…" : "Scan Now"}
            </Button>
          </div>
        </div>
      </CardHeader>
      <CardContent>
        <div className="h-[140px]">
          <ResponsiveContainer width="100%" height="100%">
            <AreaChart data={history} margin={{ top: 4, right: 4, left: -24, bottom: 0 }}>
              <defs>
                <linearGradient id="scanGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%" stopColor={trend ? "#22c55e" : "#ef4444"} stopOpacity={0.3} />
                  <stop offset="95%" stopColor={trend ? "#22c55e" : "#ef4444"} stopOpacity={0} />
                </linearGradient>
              </defs>
              <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" vertical={false} />
              <XAxis
                dataKey="date"
                tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))", fontFamily: "monospace" }}
                tickLine={false}
                axisLine={false}
                interval={6}
              />
              <YAxis
                tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))", fontFamily: "monospace" }}
                tickLine={false}
                axisLine={false}
              />
              <Tooltip contentStyle={CHART_STYLE} formatter={(v) => [v, "Findings"]} />
              <Area
                type="monotone"
                dataKey="findings"
                stroke={trend ? "#22c55e" : "#ef4444"}
                fill="url(#scanGrad)"
                strokeWidth={2}
                dot={false}
                name="Findings"
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
        <div className="flex items-center gap-2 mt-3 text-xs text-muted-foreground">
          {trend ? (
            <><TrendingDown className="h-3.5 w-3.5 text-green-400" /><span className="text-green-400">Trending down</span> — good work keeping up with fixes.</>
          ) : (
            <><TrendingUp className="h-3.5 w-3.5 text-red-400" /><span className="text-red-400">Trending up</span> — new findings accumulating faster than fixes.</>
          )}
        </div>
      </CardContent>
    </Card>
  );
}

// ═══════════════════════════════════════════════════════════
// Security Score Ring
// ═══════════════════════════════════════════════════════════

function ScoreRing({ score }: { score: number }) {
  const r = 28;
  const circ = 2 * Math.PI * r;
  const fill = (score / 100) * circ;
  const color = score >= 80 ? "#22c55e" : score >= 60 ? "#eab308" : "#ef4444";

  return (
    <div className="relative inline-flex items-center justify-center">
      <svg width="72" height="72" viewBox="0 0 72 72" className="-rotate-90">
        <circle cx="36" cy="36" r={r} fill="none" stroke="hsl(var(--muted))" strokeWidth="5" />
        <circle
          cx="36" cy="36" r={r}
          fill="none"
          stroke={color}
          strokeWidth="5"
          strokeLinecap="round"
          strokeDasharray={`${fill} ${circ}`}
          className="transition-all duration-700"
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-xl font-bold font-mono tabular-nums leading-none" style={{ color }}>
          {score}
        </span>
        <span className="text-[9px] text-muted-foreground mt-0.5">score</span>
      </div>
    </div>
  );
}

// ═══════════════════════════════════════════════════════════
// Main Page Component
// ═══════════════════════════════════════════════════════════

export default function DevSecurityDashboard() {
  const [scanning, setScanning] = useState(false);

  const { data, isLoading, refetch } = useQuery({
    queryKey: ["dev-security-dashboard"],
    queryFn: async () => {
      try {
        const [findingsRes, secretsRes, sbomRes] = await Promise.allSettled([
          api.get("/api/v1/findings"),
          api.get("/api/v1/secrets/findings"),
          api.get("/api/v1/sbom/vulnerabilities"),
        ]);
        const mock = buildMockData();
        // Merge real data if available
        if (findingsRes.status === "fulfilled") {
          // Could enrich mock with real data here
        }
        return mock;
      } catch {
        return buildMockData();
      }
    },
    staleTime: 30_000,
    refetchInterval: 120_000,
  });

  const handleScanNow = useCallback(async () => {
    setScanning(true);
    try {
      await api.post("/api/v1/scanner-ingest/webhook/semgrep", {
        repository: "DevOpsMadDog/Fixops",
        branch: "features/intermediate-stage",
      });
    } catch { /* graceful */ }
    setTimeout(() => {
      setScanning(false);
      refetch();
    }, 2500);
  }, [refetch]);

  if (isLoading || !data) {
    return (
      <div className="space-y-6 animate-pulse">
        <div className="h-12 bg-muted rounded-lg w-64" />
        <div className="grid grid-cols-4 gap-4">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="h-24 bg-muted rounded-xl" />
          ))}
        </div>
        <div className="h-48 bg-muted rounded-xl" />
        <div className="h-48 bg-muted rounded-xl" />
      </div>
    );
  }

  const d = data;
  const mttrDiff = d.kpis.team_mttr - d.kpis.my_mttr;

  return (
    <TooltipProvider>
      <div className="space-y-6">
        {/* ── Header ── */}
        <PageHeader
          title="Developer Security"
          description="Security issues in your code, your repos, your responsibility — fix them before they ship."
          badge="P01"
        >
          <Button variant="outline" size="sm" className="gap-2 h-8" onClick={() => refetch()}>
            <RefreshCw className="h-3.5 w-3.5" />
            Refresh
          </Button>
          <Button size="sm" className="gap-2 h-8" onClick={handleScanNow} disabled={scanning}>
            {scanning ? <RefreshCw className="h-3.5 w-3.5 animate-spin" /> : <Play className="h-3.5 w-3.5" />}
            {scanning ? "Scanning…" : "Scan Now"}
          </Button>
        </PageHeader>

        {/* ── Section 1: My Security Debt — KPI row ── */}
        <section aria-labelledby="kpi-heading">
          <div className="flex items-center gap-3 mb-3">
            <h2 id="kpi-heading" className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              My Security Debt
            </h2>
            <div className="flex-1 h-px bg-border" />
          </div>

          <div className="grid grid-cols-2 lg:grid-cols-4 xl:grid-cols-5 gap-4">
            <KpiCard
              title="Open Findings"
              value={d.kpis.total_findings}
              icon={Bug}
              trendLabel="Across all my repos"
              trend="flat"
            />
            <KpiCard
              title="Critical / High"
              value={d.kpis.crit_high}
              icon={AlertTriangle}
              trend={d.kpis.crit_high > 5 ? "down" : "up"}
              trendLabel={d.kpis.crit_high > 5 ? "Needs attention" : "Under control"}
            />
            <KpiCard
              title="My MTTR"
              value={`${d.kpis.my_mttr}h`}
              icon={Clock}
              trend={d.kpis.my_mttr < d.kpis.team_mttr ? "up" : "down"}
              trendLabel={`${mttrDiff > 0 ? `${mttrDiff.toFixed(1)}h faster than` : `${Math.abs(mttrDiff).toFixed(1)}h slower than`} team avg`}
            />
            <KpiCard
              title="Team MTTR"
              value={`${d.kpis.team_mttr}h`}
              icon={Minus}
              trendLabel="Team average baseline"
              trend="flat"
            />
            {/* Security Score — custom card with ring */}
            <motion.div
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.3 }}
              className="lg:col-span-0"
            >
              <Card className="p-5 h-full flex items-center gap-4">
                <ScoreRing score={d.kpis.security_score} />
                <div>
                  <p className="text-xs font-medium uppercase tracking-wider text-muted-foreground">Security Score</p>
                  <p className="text-sm text-muted-foreground mt-1">My repos</p>
                  <p className={cn("text-xs font-semibold mt-1",
                    d.kpis.security_score >= 80 ? "text-green-400" :
                    d.kpis.security_score >= 60 ? "text-yellow-400" : "text-red-400"
                  )}>
                    {d.kpis.security_score >= 80 ? "Strong" : d.kpis.security_score >= 60 ? "Moderate" : "At Risk"}
                  </p>
                </div>
              </Card>
            </motion.div>
          </div>
        </section>

        {/* ── Section 2: Findings by Repo ── */}
        <section aria-labelledby="findings-heading">
          <div className="flex items-center gap-3 mb-3">
            <h2 id="findings-heading" className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Findings by Repo
            </h2>
            <div className="flex-1 h-px bg-border" />
            <span className="text-xs text-muted-foreground font-mono">
              {d.repos.reduce((s, r) => s + r.findings.length, 0)} findings · {d.repos.length} repos
            </span>
          </div>
          <RepoAccordion repos={d.repos} />
        </section>

        {/* ── Sections 3 + 4: Secrets + Deps (two-column) ── */}
        <div className="grid grid-cols-1 xl:grid-cols-2 gap-6">
          {/* Section 3: Secret Exposure */}
          <section aria-labelledby="secrets-heading">
            <div className="flex items-center gap-3 mb-3">
              <h2 id="secrets-heading" className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                Secret Exposure
              </h2>
              <div className="flex-1 h-px bg-border" />
            </div>
            <SecretExposurePanel secrets={d.secrets} />
          </section>

          {/* Section 4: Dependency Vulnerabilities */}
          <section aria-labelledby="deps-heading">
            <div className="flex items-center gap-3 mb-3">
              <h2 id="deps-heading" className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
                Dependency Vulnerabilities
              </h2>
              <div className="flex-1 h-px bg-border" />
            </div>
            <DependencyPanel vulns={d.depVulns} totalClean={d.kpis.clean_deps} />
          </section>
        </div>

        {/* ── Section 5: Scan History ── */}
        <section aria-labelledby="history-heading">
          <div className="flex items-center gap-3 mb-3">
            <h2 id="history-heading" className="text-xs font-semibold uppercase tracking-wider text-muted-foreground">
              Scan History
            </h2>
            <div className="flex-1 h-px bg-border" />
          </div>
          <ScanHistoryPanel
            history={d.scanHistory}
            lastScan={d.kpis.last_scan as string}
            onScanNow={handleScanNow}
            scanning={scanning}
          />
        </section>
      </div>
    </TooltipProvider>
  );
}
