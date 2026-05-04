/**
 * Developer Security Portal — P10 Persona
 *
 * Self-service security hub for developers: own your repos, own your findings,
 * fix with AI-generated suggestions. Dark-first, terminal-aesthetic, high signal.
 *
 * Route: /developer
 */

import { useState, useEffect, useMemo } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  GitBranch, ShieldAlert, Clock, Star, TrendingUp, TrendingDown,
  Minus, ChevronDown, ChevronRight, Code2, BookOpen, ExternalLink,
  Filter, ArrowUpDown, RefreshCw, CheckCircle2, XCircle,
  AlertTriangle, Flame, Bug, KeyRound, Package, Server,
  ChevronUp, Terminal, Lightbulb, FileCode2, Lock,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Separator } from "@/components/ui/separator";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ═══════════════════════════════════════════════════════════
// API helpers
// ═══════════════════════════════════════════════════════════

const API_BASE = import.meta.env.VITE_API_URL || "";
const API_KEY_VAL =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "dev-key";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}?org_id=default`, {
    headers: { "X-API-Key": API_KEY_VAL },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ═══════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════

type Grade = "A" | "B" | "C" | "D" | "F";
type Severity = "critical" | "high" | "medium" | "low";
type Trend = "up" | "down" | "flat";

interface Repo {
  id: string;
  name: string;
  language: string;
  grade: Grade;
  findings: number;
  lastScan: Date;
  trend: Trend;
  trendDelta: number;
  branch: string;
}

interface Finding {
  id: string;
  severity: Severity;
  title: string;
  repo: string;
  type: "sast" | "secret" | "sca" | "iac" | "container";
  fixAvailable: boolean;
  age: number; // days
  cve?: string;
  fixSuggestion?: FixSuggestion;
}

interface FixSuggestion {
  description: string;
  before: string;
  after: string;
  effort: "trivial" | "low" | "medium";
  docs?: { label: string; url: string }[];
}

interface LearningResource {
  title: string;
  type: "article" | "guide" | "video" | "cwe";
  url: string;
  findingType: Finding["type"] | "general";
  tag: string;
}

// ═══════════════════════════════════════════════════════════
// Mock data
// ═══════════════════════════════════════════════════════════

const now = new Date();
const daysAgo = (d: number) => new Date(now.getTime() - d * 86_400_000);


const LEARNING_RESOURCES: LearningResource[] = [
  {
    title: "OWASP Top 10 for Developers",
    type: "guide",
    url: "https://owasp.org/www-project-top-ten/",
    findingType: "general",
    tag: "OWASP",
  },
  {
    title: "Detecting Secrets in Code",
    type: "article",
    url: "https://docs.github.com/en/code-security/secret-scanning",
    findingType: "secret",
    tag: "Secret Scanning",
  },
  {
    title: "SQL Injection Prevention Cheat Sheet",
    type: "guide",
    url: "https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html",
    findingType: "sast",
    tag: "SAST",
  },
  {
    title: "Terraform Security Best Practices",
    type: "guide",
    url: "https://developer.hashicorp.com/terraform/cloud-docs/recommended-practices",
    findingType: "iac",
    tag: "IaC",
  },
  {
    title: "Container Security Fundamentals",
    type: "article",
    url: "https://snyk.io/learn/container-security/",
    findingType: "container",
    tag: "Container",
  },
  {
    title: "SCA: Managing Open Source Risk",
    type: "guide",
    url: "https://owasp.org/www-project-dependency-check/",
    findingType: "sca",
    tag: "SCA",
  },
  {
    title: "CWE Top 25 Most Dangerous Weaknesses",
    type: "cwe",
    url: "https://cwe.mitre.org/top25/archive/2024/2024_cwe_top25.html",
    findingType: "general",
    tag: "CWE",
  },
  {
    title: "Secure Coding in Python",
    type: "article",
    url: "https://realpython.com/python-security/",
    findingType: "sast",
    tag: "Python",
  },
];

// ═══════════════════════════════════════════════════════════
// Grade utilities
// ═══════════════════════════════════════════════════════════

const GRADE_CONFIG: Record<Grade, { bg: string; text: string; border: string }> = {
  A: { bg: "bg-emerald-950/60", text: "text-emerald-400", border: "border-emerald-700/50" },
  B: { bg: "bg-sky-950/60",     text: "text-sky-400",     border: "border-sky-700/50" },
  C: { bg: "bg-amber-950/60",   text: "text-amber-400",   border: "border-amber-700/50" },
  D: { bg: "bg-orange-950/60",  text: "text-orange-400",  border: "border-orange-700/50" },
  F: { bg: "bg-red-950/60",     text: "text-red-400",     border: "border-red-700/50" },
};

function GradeBadge({ grade, size = "sm" }: { grade: Grade; size?: "sm" | "lg" }) {
  const cfg = GRADE_CONFIG[grade];
  return (
    <span
      className={cn(
        "font-mono font-bold border rounded",
        cfg.bg, cfg.text, cfg.border,
        size === "sm" ? "px-2 py-0.5 text-xs" : "px-3 py-1 text-base"
      )}
    >
      {grade}
    </span>
  );
}

// ═══════════════════════════════════════════════════════════
// Severity utilities
// ═══════════════════════════════════════════════════════════

const SEV_CONFIG: Record<Severity, { label: string; icon: typeof Flame; dot: string; text: string; bg: string }> = {
  critical: { label: "Critical", icon: Flame,         dot: "bg-red-500",    text: "text-red-400",    bg: "bg-red-950/40" },
  high:     { label: "High",     icon: AlertTriangle,  dot: "bg-orange-500", text: "text-orange-400", bg: "bg-orange-950/40" },
  medium:   { label: "Medium",   icon: ShieldAlert,    dot: "bg-amber-500",  text: "text-amber-400",  bg: "bg-amber-950/40" },
  low:      { label: "Low",      icon: Bug,            dot: "bg-blue-500",   text: "text-blue-400",   bg: "bg-blue-950/40" },
};

function SevBadge({ severity }: { severity: Severity }) {
  const cfg = SEV_CONFIG[severity];
  return (
    <span className={cn("inline-flex items-center gap-1.5 rounded px-2 py-0.5 text-xs font-medium", cfg.text, cfg.bg)}>
      <span className={cn("h-1.5 w-1.5 rounded-full shrink-0", cfg.dot)} />
      {cfg.label}
    </span>
  );
}

// ═══════════════════════════════════════════════════════════
// Type icon map
// ═══════════════════════════════════════════════════════════

const TYPE_ICON: Record<Finding["type"], typeof Code2> = {
  sast:      Code2,
  secret:    KeyRound,
  sca:       Package,
  iac:       Server,
  container: Bug,
};

const TYPE_LABEL: Record<Finding["type"], string> = {
  sast:      "SAST",
  secret:    "Secret",
  sca:       "SCA",
  iac:       "IaC",
  container: "Container",
};

// ═══════════════════════════════════════════════════════════
// Trend arrow
// ═══════════════════════════════════════════════════════════

function TrendIcon({ trend, delta }: { trend: Trend; delta: number }) {
  if (trend === "up") return (
    <span className="inline-flex items-center gap-0.5 text-xs text-emerald-400 font-medium">
      <TrendingUp className="h-3 w-3" />+{delta}
    </span>
  );
  if (trend === "down") return (
    <span className="inline-flex items-center gap-0.5 text-xs text-red-400 font-medium">
      <TrendingDown className="h-3 w-3" />-{delta}
    </span>
  );
  return <Minus className="h-3 w-3 text-muted-foreground" />;
}

// ═══════════════════════════════════════════════════════════
// Fix Suggestion Diff Panel
// ═══════════════════════════════════════════════════════════

function FixPanel({ suggestion, findingId }: { suggestion: FixSuggestion; findingId: string }) {
  const effortColor = {
    trivial: "text-emerald-400 bg-emerald-950/40 border-emerald-700/40",
    low:     "text-sky-400 bg-sky-950/40 border-sky-700/40",
    medium:  "text-amber-400 bg-amber-950/40 border-amber-700/40",
  }[suggestion.effort];

  return (
    <motion.div
      key={findingId}
      initial={{ opacity: 0, height: 0 }}
      animate={{ opacity: 1, height: "auto" }}
      exit={{ opacity: 0, height: 0 }}
      transition={{ duration: 0.2, ease: "easeOut" }}
      className="overflow-hidden"
    >
      <div className="mt-3 rounded-lg border border-border/60 bg-card/50 p-4 space-y-3">
        {/* Header */}
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <Terminal className="h-3.5 w-3.5 text-primary" />
            <span className="text-xs font-semibold text-foreground uppercase tracking-wider">AI Fix Suggestion</span>
          </div>
          <span className={cn("rounded border px-2 py-0.5 text-[10px] font-mono font-medium", effortColor)}>
            effort: {suggestion.effort}
          </span>
        </div>

        <p className="text-xs text-muted-foreground leading-relaxed">{suggestion.description}</p>

        {/* Diff */}
        <div className="space-y-2 font-mono text-xs">
          {/* Before */}
          <div className="rounded-md border border-red-900/40 bg-red-950/20 overflow-hidden">
            <div className="flex items-center gap-2 border-b border-red-900/30 px-3 py-1.5 bg-red-950/30">
              <XCircle className="h-3 w-3 text-red-500" />
              <span className="text-[10px] font-semibold text-red-400 uppercase tracking-wider">Before</span>
            </div>
            <pre className="p-3 text-red-300/80 overflow-x-auto whitespace-pre leading-relaxed">
              {suggestion.before}
            </pre>
          </div>

          {/* After */}
          <div className="rounded-md border border-emerald-900/40 bg-emerald-950/20 overflow-hidden">
            <div className="flex items-center gap-2 border-b border-emerald-900/30 px-3 py-1.5 bg-emerald-950/30">
              <CheckCircle2 className="h-3 w-3 text-emerald-500" />
              <span className="text-[10px] font-semibold text-emerald-400 uppercase tracking-wider">After</span>
            </div>
            <pre className="p-3 text-emerald-300/80 overflow-x-auto whitespace-pre leading-relaxed">
              {suggestion.after}
            </pre>
          </div>
        </div>

        {/* Docs */}
        {suggestion.docs && suggestion.docs.length > 0 && (
          <div className="flex flex-wrap gap-2">
            {suggestion.docs.map((doc) => (
              <a
                key={doc.url}
                href={doc.url}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1.5 rounded border border-border/60 px-2.5 py-1 text-xs text-muted-foreground hover:text-foreground hover:border-primary/40 transition-colors"
              >
                <ExternalLink className="h-3 w-3" />
                {doc.label}
              </a>
            ))}
          </div>
        )}
      </div>
    </motion.div>
  );
}

// ═══════════════════════════════════════════════════════════
// Repos Table
// ═══════════════════════════════════════════════════════════

type RepoSortKey = "grade" | "findings" | "lastScan";

function ReposTable({ repos }: { repos: Repo[] }) {
  const [sortKey, setSortKey] = useState<RepoSortKey>("findings");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");

  const sorted = useMemo(() => {
    return [...repos].sort((a, b) => {
      let av: number, bv: number;
      if (sortKey === "grade") {
        const order = { A: 1, B: 2, C: 3, D: 4, F: 5 };
        av = order[a.grade]; bv = order[b.grade];
      } else if (sortKey === "findings") {
        av = a.findings; bv = b.findings;
      } else {
        av = a.lastScan.getTime(); bv = b.lastScan.getTime();
      }
      return sortDir === "desc" ? bv - av : av - bv;
    });
  }, [repos, sortKey, sortDir]);

  function toggleSort(key: RepoSortKey) {
    if (sortKey === key) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir("desc");
    }
  }

  function SortBtn({ k, label }: { k: RepoSortKey; label: string }) {
    const active = sortKey === k;
    return (
      <button
        onClick={() => toggleSort(k)}
        className={cn(
          "inline-flex items-center gap-1 text-xs font-medium transition-colors",
          active ? "text-primary" : "text-muted-foreground hover:text-foreground"
        )}
      >
        {label}
        {active ? (
          sortDir === "desc" ? <ChevronDown className="h-3 w-3" /> : <ChevronUp className="h-3 w-3" />
        ) : (
          <ArrowUpDown className="h-3 w-3 opacity-50" />
        )}
      </button>
    );
  }

  const langDot: Record<string, string> = {
    Python: "bg-blue-400",
    TypeScript: "bg-sky-400",
    HCL: "bg-purple-400",
    Go: "bg-cyan-400",
  };

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm font-semibold">My Repositories</CardTitle>
          <div className="flex items-center gap-3 text-xs text-muted-foreground">
            Sort:
            <SortBtn k="grade" label="Score" />
            <SortBtn k="findings" label="Findings" />
            <SortBtn k="lastScan" label="Last Scan" />
          </div>
        </div>
      </CardHeader>
      <CardContent className="p-0">
        <div className="overflow-x-auto">
          <table className="w-full text-xs">
            <thead>
              <tr className="border-b border-border/50 text-muted-foreground">
                <th className="px-4 py-2.5 text-left font-medium">Repository</th>
                <th className="px-4 py-2.5 text-center font-medium">Score</th>
                <th className="px-4 py-2.5 text-center font-medium">Findings</th>
                <th className="px-4 py-2.5 text-left font-medium">Last Scan</th>
                <th className="px-4 py-2.5 text-center font-medium">Trend</th>
              </tr>
            </thead>
            <tbody>
              {sorted.map((repo, i) => (
                <motion.tr
                  key={repo.id}
                  initial={{ opacity: 0, x: -8 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ delay: i * 0.04 }}
                  className="border-b border-border/30 hover:bg-muted/20 transition-colors"
                >
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-2.5">
                      <div className={cn("h-2 w-2 rounded-full shrink-0", langDot[repo.language] ?? "bg-muted-foreground")} />
                      <div>
                        <div className="font-mono text-xs font-medium text-foreground">{repo.name}</div>
                        <div className="flex items-center gap-1.5 mt-0.5 text-[10px] text-muted-foreground">
                          <GitBranch className="h-2.5 w-2.5" />
                          {repo.branch}
                          <span className="text-muted-foreground/50">·</span>
                          {repo.language}
                        </div>
                      </div>
                    </div>
                  </td>
                  <td className="px-4 py-3 text-center">
                    <GradeBadge grade={repo.grade} />
                  </td>
                  <td className="px-4 py-3 text-center">
                    <span className={cn(
                      "font-mono font-bold",
                      repo.findings >= 10 ? "text-red-400" :
                      repo.findings >= 5 ? "text-orange-400" :
                      repo.findings >= 1 ? "text-amber-400" : "text-emerald-400"
                    )}>
                      {repo.findings}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-muted-foreground">
                    {repo.lastScan.toDateString() === now.toDateString()
                      ? "Today"
                      : `${Math.round((now.getTime() - repo.lastScan.getTime()) / 86_400_000)}d ago`}
                  </td>
                  <td className="px-4 py-3 text-center">
                    <TrendIcon trend={repo.trend} delta={repo.trendDelta} />
                  </td>
                </motion.tr>
              ))}
            </tbody>
          </table>
        </div>
      </CardContent>
    </Card>
  );
}

// ═══════════════════════════════════════════════════════════
// Findings Table
// ═══════════════════════════════════════════════════════════

type FindingSortKey = "severity" | "age";

function FindingsTable({
  findings,
  repoFilter,
  severityFilter,
}: {
  findings: Finding[];
  repoFilter: string;
  severityFilter: string;
}) {
  const [expandedId, setExpandedId] = useState<string | null>(null);
  const [sortKey, setSortKey] = useState<FindingSortKey>("severity");
  const [sortDir, setSortDir] = useState<"asc" | "desc">("desc");

  const SEV_ORDER: Record<Severity, number> = { critical: 4, high: 3, medium: 2, low: 1 };

  const filtered = useMemo(() => {
    return findings
      .filter((f) => repoFilter === "all" || f.repo === repoFilter)
      .filter((f) => severityFilter === "all" || f.severity === severityFilter)
      .sort((a, b) => {
        let av: number, bv: number;
        if (sortKey === "severity") { av = SEV_ORDER[a.severity]; bv = SEV_ORDER[b.severity]; }
        else { av = a.age; bv = b.age; }
        return sortDir === "desc" ? bv - av : av - bv;
      });
  }, [findings, repoFilter, severityFilter, sortKey, sortDir]);

  function toggleSort(key: FindingSortKey) {
    if (sortKey === key) setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    else { setSortKey(key); setSortDir("desc"); }
  }

  function SortBtn({ k, label }: { k: FindingSortKey; label: string }) {
    const active = sortKey === k;
    return (
      <button
        onClick={() => toggleSort(k)}
        className={cn(
          "inline-flex items-center gap-1 text-xs font-medium transition-colors",
          active ? "text-primary" : "text-muted-foreground hover:text-foreground"
        )}
      >
        {label}
        {active ? (
          sortDir === "desc" ? <ChevronDown className="h-3 w-3" /> : <ChevronUp className="h-3 w-3" />
        ) : (
          <ArrowUpDown className="h-3 w-3 opacity-50" />
        )}
      </button>
    );
  }

  return (
    <Card>
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm font-semibold">
            My Findings
            <span className="ml-2 font-mono text-xs text-muted-foreground font-normal">
              ({filtered.length}/{findings.length})
            </span>
          </CardTitle>
          <div className="flex items-center gap-3 text-xs text-muted-foreground">
            Sort:
            <SortBtn k="severity" label="Severity" />
            <SortBtn k="age" label="Age" />
          </div>
        </div>
      </CardHeader>
      <CardContent className="p-0">
        <div className="divide-y divide-border/30">
          {filtered.length === 0 ? (
            <div className="px-4 py-8 text-center text-sm text-muted-foreground">
              No findings match the current filter.
            </div>
          ) : (
            filtered.map((finding, i) => {
              const TypeIcon = TYPE_ICON[finding.type];
              const isExpanded = expandedId === finding.id;

              return (
                <motion.div
                  key={finding.id}
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: i * 0.03 }}
                  className="px-4 py-3"
                >
                  <div
                    className={cn(
                      "flex items-start gap-3 cursor-pointer group",
                      finding.fixAvailable && "hover:opacity-90"
                    )}
                    onClick={() => {
                      if (finding.fixAvailable && finding.fixSuggestion) {
                        setExpandedId(isExpanded ? null : finding.id);
                      }
                    }}
                    role={finding.fixAvailable ? "button" : undefined}
                    tabIndex={finding.fixAvailable ? 0 : undefined}
                    onKeyDown={finding.fixAvailable ? (e) => {
                      if (e.key === "Enter" || e.key === " ") {
                        e.preventDefault();
                        setExpandedId(isExpanded ? null : finding.id);
                      }
                    } : undefined}
                    aria-expanded={finding.fixAvailable ? isExpanded : undefined}
                  >
                    {/* Severity dot */}
                    <div className={cn(
                      "mt-1 flex h-5 w-5 shrink-0 items-center justify-center rounded",
                      SEV_CONFIG[finding.severity].bg
                    )}>
                      <TypeIcon className={cn("h-3 w-3", SEV_CONFIG[finding.severity].text)} />
                    </div>

                    {/* Content */}
                    <div className="flex-1 min-w-0">
                      <div className="flex items-start gap-2 flex-wrap">
                        <SevBadge severity={finding.severity} />
                        <span className="inline-flex items-center gap-1 rounded border border-border/40 px-1.5 py-0.5 text-[10px] font-mono text-muted-foreground">
                          <TypeIcon className="h-2.5 w-2.5" />
                          {TYPE_LABEL[finding.type]}
                        </span>
                        {finding.cve && (
                          <span className="rounded border border-border/40 px-1.5 py-0.5 text-[10px] font-mono text-muted-foreground">
                            {finding.cve}
                          </span>
                        )}
                      </div>
                      <div className="mt-1 text-sm font-medium text-foreground leading-snug">
                        {finding.title}
                      </div>
                      <div className="mt-1 flex items-center gap-3 text-[10px] text-muted-foreground flex-wrap">
                        <span className="font-mono">{finding.repo}</span>
                        <span className="text-muted-foreground/40">·</span>
                        <span className="flex items-center gap-1">
                          <Clock className="h-2.5 w-2.5" />
                          {finding.age === 0 ? "Today" : `${finding.age}d ago`}
                        </span>
                        <span className="text-muted-foreground/40">·</span>
                        <span className="flex items-center gap-1 font-medium">
                          {finding.id}
                        </span>
                      </div>
                    </div>

                    {/* Fix available + expand */}
                    <div className="flex items-center gap-2 shrink-0 mt-0.5">
                      {finding.fixAvailable ? (
                        <span className="inline-flex items-center gap-1 rounded border border-emerald-700/40 bg-emerald-950/40 px-2 py-0.5 text-[10px] font-medium text-emerald-400">
                          <CheckCircle2 className="h-2.5 w-2.5" />
                          Fix Available
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 rounded border border-border/30 px-2 py-0.5 text-[10px] text-muted-foreground">
                          <XCircle className="h-2.5 w-2.5" />
                          Manual
                        </span>
                      )}
                      {finding.fixAvailable && finding.fixSuggestion && (
                        <div className={cn(
                          "transition-transform duration-200",
                          isExpanded && "rotate-180"
                        )}>
                          <ChevronDown className="h-3.5 w-3.5 text-muted-foreground group-hover:text-foreground transition-colors" />
                        </div>
                      )}
                    </div>
                  </div>

                  {/* Expandable fix panel */}
                  <AnimatePresence>
                    {isExpanded && finding.fixSuggestion && (
                      <FixPanel suggestion={finding.fixSuggestion} findingId={finding.id} />
                    )}
                  </AnimatePresence>
                </motion.div>
              );
            })
          )}
        </div>
      </CardContent>
    </Card>
  );
}

// ═══════════════════════════════════════════════════════════
// Learning Resources Sidebar
// ═══════════════════════════════════════════════════════════

const RESOURCE_TYPE_STYLE: Record<LearningResource["type"], string> = {
  article: "bg-sky-950/40 text-sky-400 border-sky-800/40",
  guide:   "bg-emerald-950/40 text-emerald-400 border-emerald-800/40",
  video:   "bg-purple-950/40 text-purple-400 border-purple-800/40",
  cwe:     "bg-amber-950/40 text-amber-400 border-amber-800/40",
};

function LearningSidebar({ resources }: { resources: LearningResource[] }) {
  return (
    <Card className="sticky top-4">
      <CardHeader className="pb-3">
        <CardTitle className="flex items-center gap-2 text-sm font-semibold">
          <BookOpen className="h-4 w-4 text-primary" />
          Learning Resources
        </CardTitle>
      </CardHeader>
      <CardContent className="p-0">
        <div className="divide-y divide-border/30">
          {resources.map((res, i) => (
            <motion.a
              key={res.url}
              href={res.url}
              target="_blank"
              rel="noopener noreferrer"
              initial={{ opacity: 0, x: 8 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: i * 0.05 }}
              className="flex items-start gap-3 px-4 py-3 hover:bg-muted/20 transition-colors group"
            >
              <div className={cn(
                "mt-0.5 rounded border px-1.5 py-0.5 text-[9px] font-mono font-semibold uppercase shrink-0",
                RESOURCE_TYPE_STYLE[res.type]
              )}>
                {res.type}
              </div>
              <div className="flex-1 min-w-0">
                <div className="text-xs font-medium text-foreground group-hover:text-primary transition-colors leading-snug">
                  {res.title}
                </div>
                <div className="mt-0.5 flex items-center gap-1 text-[10px] text-muted-foreground">
                  <span>{res.tag}</span>
                  <ExternalLink className="h-2.5 w-2.5 opacity-0 group-hover:opacity-100 transition-opacity" />
                </div>
              </div>
            </motion.a>
          ))}
        </div>
      </CardContent>
    </Card>
  );
}

// ═══════════════════════════════════════════════════════════
// Main Page
// ═══════════════════════════════════════════════════════════

export default function DeveloperPortal() {
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [repoFilter, setRepoFilter] = useState<string>("all");
  const [isRefreshing, setIsRefreshing] = useState(false);

  const [repos, setRepos] = useState<Repo[]>([]);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const loadData = () => {
    setLoading(true);
    setError(null);
    Promise.allSettled([
      apiFetch(`/api/v1/developer-portal/repos?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/developer-portal/findings?org_id=${ORG_ID}`),
    ]).then(([reposResult, findingsResult]) => {
      if (reposResult.status === "fulfilled") {
        const items = Array.isArray(reposResult.value) ? reposResult.value : reposResult.value?.repos;
        if (Array.isArray(items) && items.length > 0) {
          setRepos(
            items.map((r: any) => ({
              id: r.id ?? `r-${Date.now()}`,
              name: r.name ?? r.repo_name ?? "unknown",
              language: r.language ?? r.primary_language ?? "Unknown",
              grade: (r.grade ?? r.security_grade ?? "C") as Grade,
              findings: r.findings ?? r.finding_count ?? 0,
              lastScan: r.last_scan ? new Date(r.last_scan) : (r.lastScan ? new Date(r.lastScan) : new Date()),
              trend: (r.trend ?? "flat") as Trend,
              trendDelta: r.trend_delta ?? r.trendDelta ?? 0,
              branch: r.branch ?? r.default_branch ?? "main",
            }))
          );
        }
      }
      if (findingsResult.status === "fulfilled") {
        const items = Array.isArray(findingsResult.value) ? findingsResult.value : findingsResult.value?.findings;
        if (Array.isArray(items) && items.length > 0) {
          setFindings(
            items.map((f: any) => ({
              id: f.id ?? f.finding_id ?? `FND-${Date.now()}`,
              severity: (f.severity ?? "medium") as Severity,
              title: f.title ?? f.description ?? "Untitled finding",
              repo: f.repo ?? f.repo_name ?? "unknown",
              type: (f.type ?? f.finding_type ?? "sast") as Finding["type"],
              fixAvailable: f.fix_available ?? f.fixAvailable ?? false,
              age: f.age ?? (f.created_at ? Math.round((Date.now() - new Date(f.created_at).getTime()) / 86_400_000) : 0),
              cve: f.cve ?? f.cve_id ?? undefined,
              fixSuggestion: f.fix_suggestion ?? f.fixSuggestion ?? undefined,
            }))
          );
        }
      }
      if (reposResult.status === "rejected" && findingsResult.status === "rejected") {
        setError("Could not reach the API server. Showing demo data.");
      }
    }).finally(() => setLoading(false));
  };

  useEffect(() => { loadData(); }, []);

  // KPI computation
  const totalFixed = 47;
  const avgFixTime = "2.1d";
  const reposOwned = repos.length;
  const secScore = Math.round(
    (repos.reduce((sum, r) => {
      const scoreMap: Record<Grade, number> = { A: 95, B: 80, C: 60, D: 40, F: 20 };
      return sum + scoreMap[r.grade];
    }, 0) / Math.max(repos.length, 1))
  );

  const criticalCount = findings.filter((f) => f.severity === "critical").length;
  const fixableCount  = findings.filter((f) => f.fixAvailable).length;

  const repoNames = [...new Set(findings.map((f) => f.repo))];

  function handleRefresh() {
    setIsRefreshing(true);
    loadData();
    setTimeout(() => setIsRefreshing(false), 1200);
  }

  return (
    <div className="space-y-6">
      {/* ── Header ── */}
      <PageHeader
        title="Developer Security Portal"
        description="Own your security posture. View your repos, fix your findings, ship with confidence."
        badge="P10"
        actions={
          <Button
            variant="outline"
            size="sm"
            onClick={handleRefresh}
            disabled={isRefreshing}
          >
            <RefreshCw className={cn("h-3.5 w-3.5 mr-2", isRefreshing && "animate-spin")} />
            Refresh
          </Button>
        }
      />

      {/* -- Loading state -- */}
      {loading && (
        <div className="p-6 rounded-lg border border-border/40 bg-muted/10">
          <div className="animate-pulse space-y-4">
            <div className="h-4 bg-muted rounded w-1/4" />
            <div className="grid grid-cols-4 gap-4">
              <div className="h-20 bg-muted rounded-lg" />
              <div className="h-20 bg-muted rounded-lg" />
              <div className="h-20 bg-muted rounded-lg" />
              <div className="h-20 bg-muted rounded-lg" />
            </div>
            <div className="h-40 bg-muted rounded-lg" />
          </div>
        </div>
      )}

      {/* -- Error state -- */}
      {error && !loading && (
        <div className="flex items-center gap-3 p-3 rounded-lg border border-amber-500/30 bg-amber-950/20 text-amber-400 text-xs">
          <AlertTriangle className="h-4 w-4 shrink-0" />
          <span>{error}</span>
          <Button variant="ghost" size="sm" className="ml-auto h-6 text-xs text-amber-400 hover:text-amber-300" onClick={loadData}>
            <RefreshCw className="h-3 w-3 mr-1" /> Retry
          </Button>
        </div>
      )}

      {/* -- KPI Bar -- */}
      <div className="grid grid-cols-2 gap-4 sm:grid-cols-4">
        <KpiCard
          title="Findings Fixed"
          value={totalFixed}
          icon={CheckCircle2}         trend="up"
          trendLabel="+12 this sprint"
        />
        <KpiCard
          title="Avg Fix Time"
          value={avgFixTime}
          icon={Clock}         trend="up"
          trendLabel="↓ 0.4d vs last sprint"
        />
        <KpiCard
          title="Repos Owned"
          value={reposOwned}
          icon={GitBranch}
          description={`${criticalCount} with critical findings`}
        />
        <KpiCard
          title="Security Score"
          value={`${secScore}`}
          icon={Star}         trend={secScore >= 70 ? "up" : "down"}
          trendLabel={secScore >= 70 ? "Good standing" : "Needs attention"}
        />
      </div>

      {/* ── Alert strip for criticals ── */}
      {criticalCount > 0 && (
        <motion.div
          initial={{ opacity: 0, y: -4 }}
          animate={{ opacity: 1, y: 0 }}
          className="flex items-center gap-3 rounded-lg border border-red-900/50 bg-red-950/20 px-4 py-3"
        >
          <Flame className="h-4 w-4 text-red-400 shrink-0" />
          <span className="text-sm font-medium text-red-300">
            {criticalCount} critical finding{criticalCount > 1 ? "s" : ""} require immediate attention
          </span>
          <span className="ml-auto text-xs text-muted-foreground">
            {fixableCount} of {findings.length} total have AI fix suggestions — click to expand
          </span>
        </motion.div>
      )}

      {/* -- Empty state -- */}
      {!loading && repos.length === 0 && findings.length === 0 && (
        <Card>
          <CardContent className="py-12 text-center">
            <GitBranch className="h-8 w-8 text-muted-foreground mx-auto mb-3" />
            <p className="text-sm font-medium text-muted-foreground">No data available</p>
            <p className="text-xs text-muted-foreground mt-1">No repositories or findings found. Connect your repos to get started.</p>
          </CardContent>
        </Card>
      )}

      {/* -- Repos Table -- */}
      <ReposTable repos={repos} />

      {/* ── Findings + Sidebar ── */}
      <div className="grid grid-cols-1 gap-6 xl:grid-cols-[1fr_280px]">
        {/* Left: findings with filters */}
        <div className="space-y-4">
          {/* Filter bar */}
          <div className="flex flex-wrap items-center gap-3">
            <div className="flex items-center gap-2 text-xs text-muted-foreground">
              <Filter className="h-3.5 w-3.5" />
              Filter:
            </div>
            <Select value={severityFilter} onValueChange={setSeverityFilter}>
              <SelectTrigger className="h-8 w-36 text-xs">
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
            <Select value={repoFilter} onValueChange={setRepoFilter}>
              <SelectTrigger className="h-8 w-52 text-xs">
                <SelectValue placeholder="Repository" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Repos</SelectItem>
                {repoNames.map((name) => (
                  <SelectItem key={name} value={name}>
                    {name}
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
            {(severityFilter !== "all" || repoFilter !== "all") && (
              <Button
                variant="ghost"
                size="sm"
                className="h-8 text-xs text-muted-foreground hover:text-foreground"
                onClick={() => { setSeverityFilter("all"); setRepoFilter("all"); }}
              >
                Clear filters
              </Button>
            )}

            {/* Severity summary pills */}
            <div className="flex items-center gap-2 ml-auto">
              {(["critical", "high", "medium", "low"] as Severity[]).map((sev) => {
                const count = findings.filter((f) => f.severity === sev).length;
                return count > 0 ? (
                  <button
                    key={sev}
                    onClick={() => setSeverityFilter(severityFilter === sev ? "all" : sev)}
                    className={cn(
                      "inline-flex items-center gap-1.5 rounded border px-2 py-0.5 text-[10px] font-medium transition-colors",
                      severityFilter === sev
                        ? `${SEV_CONFIG[sev].bg} ${SEV_CONFIG[sev].text} border-current`
                        : "border-border/40 text-muted-foreground hover:text-foreground"
                    )}
                  >
                    <span className={cn("h-1.5 w-1.5 rounded-full", SEV_CONFIG[sev].dot)} />
                    {count} {SEV_CONFIG[sev].label}
                  </button>
                ) : null;
              })}
            </div>
          </div>

          <FindingsTable
            findings={findings}
            repoFilter={repoFilter}
            severityFilter={severityFilter}
          />
        </div>

        {/* Right: Learning Resources */}
        <LearningSidebar resources={LEARNING_RESOURCES} />
      </div>
    </div>
  );
}
