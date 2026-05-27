/**
 * AI Security Advisor
 *
 * LLM-powered security consultant — proactive recommendations,
 * incident analysis, and threat briefings.
 *   1. KPIs: Sessions, Critical Recs, Implemented, Avg Impact
 *   2. Ask the Advisor — live chat POSTing to /api/v1/ai-advisor/ask
 *   3. AI-Generated Recommendations — from /api/v1/ai-advisor/recommendations
 *   4. Quick Analysis Panels — posture, threat, incident
 *   5. Session History — from /api/v1/ai-advisor/sessions
 *
 * API:
 *   GET  /api/v1/ai-advisor/stats
 *   GET  /api/v1/ai-advisor/recommendations
 *   GET  /api/v1/ai-advisor/sessions
 *   POST /api/v1/ai-advisor/ask  (body: {question})
 */

import { useState, useEffect, useRef } from "react";
import { motion } from "framer-motion";

// ── API helpers ────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "dev-key";

async function apiFetch(path: string, options?: RequestInit) {
  const res = await fetch(`${API_BASE}${path}`, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      "X-API-Key": API_KEY,
      ...(options?.headers ?? {}),
    },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

import {
  Brain,
  Bot,
  User,
  Send,
  RefreshCw,
  CheckCircle,
  XCircle,
  Clock,
  Shield,
  AlertTriangle,
  Activity,
  FileText,
  Zap,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── Types ──────────────────────────────────────────────────────

type Priority = "critical" | "high" | "medium" | "low";
type RecStatus = "pending" | "accepted" | "rejected" | "implemented";
type SessionStatus = "completed" | "failed" | "pending";

interface ChatMessage {
  role: "user" | "assistant";
  content: string;
  ts?: string;
}

interface Recommendation {
  id: string;
  priority: Priority;
  category: string;
  title: string;
  rationale?: string;
  description?: string;
  effort_days?: number;
  effort?: string;
  impact_score?: number;
  impact?: number;
  status: RecStatus;
}

interface Session {
  id: string;
  session_type?: string;
  type?: string;
  status: SessionStatus;
  recommendation_count?: number;
  recsCount?: number;
  created_at?: string;
  createdAt?: string;
  completed_at?: string;
  duration?: string;
}

interface AdvisorStats {
  session_count?: number;
  total_recommendations?: number;
  recommendations_by_priority?: Record<string, number>;
  recommendations_by_status?: Record<string, number>;
  implemented_count?: number;
  total_impact_score?: number;
}

// ── Helpers ────────────────────────────────────────────────────

function PriorityBadge({ p }: { p: Priority }) {
  const cls =
    p === "critical" ? "border-red-500/30 text-red-400 bg-red-500/10" :
    p === "high"     ? "border-amber-500/30 text-amber-400 bg-amber-500/10" :
    p === "medium"   ? "border-yellow-500/30 text-yellow-400 bg-yellow-500/10" :
                       "border-border text-muted-foreground";
  return <Badge className={cn("text-[10px] border capitalize", cls)}>{p}</Badge>;
}

function CategoryBadge({ cat }: { cat: string }) {
  return (
    <Badge className="text-[10px] border border-purple-500/30 text-purple-400 bg-purple-500/10">
      {cat.replace(/_/g, " ")}
    </Badge>
  );
}

function StatusBadge({ s }: { s: RecStatus | SessionStatus }) {
  const cls =
    s === "implemented" || s === "completed" ? "border-green-500/30 text-green-400 bg-green-500/10" :
    s === "accepted"                          ? "border-blue-500/30 text-blue-400 bg-blue-500/10" :
    s === "rejected"  || s === "failed"       ? "border-red-500/30 text-red-400 bg-red-500/10" :
                                                "border-yellow-500/30 text-yellow-400 bg-yellow-500/10";
  return <Badge className={cn("text-[10px] border capitalize", cls)}>{s}</Badge>;
}

function SessionTypeBadge({ t }: { t: string }) {
  const label = t.replace(/_/g, " ");
  return (
    <Badge className="text-[10px] border border-indigo-500/30 text-indigo-400 bg-indigo-500/10 capitalize">
      {label}
    </Badge>
  );
}

function ImpactDots({ score }: { score: number }) {
  return (
    <div className="flex items-center gap-0.5">
      {Array.from({ length: 10 }).map((_, i) => (
        <div
          key={i}
          className={cn(
            "w-1.5 h-1.5 rounded-full",
            i < score
              ? score >= 9 ? "bg-red-500" : score >= 7 ? "bg-amber-500" : "bg-purple-500"
              : "bg-muted/40"
          )}
        />
      ))}
      <span className="ml-1 text-[10px] text-muted-foreground tabular-nums">{score}/10</span>
    </div>
  );
}

// ── Component ──────────────────────────────────────────────────

export default function AISecurityAdvisor() {
  const [refreshing, setRefreshing] = useState(false);
  const [question, setQuestion] = useState("");
  const [stats, setStats] = useState<AdvisorStats | null>(null);
  const [dataLoading, setDataLoading] = useState(false);
  const [recs, setRecs] = useState<Recommendation[]>([]);
  const [sessions, setSessions] = useState<Session[]>([]);
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([]);
  const [chatLoading, setChatLoading] = useState(false);
  const chatBottomRef = useRef<HTMLDivElement>(null);

  const fetchAll = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch("/api/v1/ai-advisor/stats?org_id=default"),
      apiFetch("/api/v1/ai-advisor/recommendations?org_id=default"),
      apiFetch("/api/v1/ai-advisor/sessions?org_id=default"),
    ]).then(([statsRes, recsRes, sessionsRes]) => {
      if (statsRes.status === "fulfilled") setStats(statsRes.value);
      if (recsRes.status === "fulfilled") {
        const d = recsRes.value;
        const arr = Array.isArray(d) ? d : (d.items ?? d.recommendations ?? []);
        setRecs(arr);
      }
      if (sessionsRes.status === "fulfilled") {
        const d = sessionsRes.value;
        const arr = Array.isArray(d) ? d : (d.items ?? d.sessions ?? []);
        setSessions(arr);
      }
    }).finally(() => setDataLoading(false));
  };

  useEffect(() => { fetchAll(); }, []);

  useEffect(() => {
    chatBottomRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [chatMessages]);

  const handleSend = async () => {
    const q = question.trim();
    if (!q || chatLoading) return;
    setQuestion("");
    const userMsg: ChatMessage = { role: "user", content: q, ts: new Date().toLocaleTimeString() };
    setChatMessages((prev) => [...prev, userMsg]);
    setChatLoading(true);
    try {
      const resp = await apiFetch("/api/v1/ai-advisor/ask?org_id=default", {
        method: "POST",
        body: JSON.stringify({ question: q }),
      });
      const answer = resp?.answer ?? resp?.response ?? resp?.content ?? JSON.stringify(resp);
      setChatMessages((prev) => [...prev, { role: "assistant", content: answer, ts: new Date().toLocaleTimeString() }]);
    } catch {
      setChatMessages((prev) => [...prev, {
        role: "assistant",
        content: "Unable to reach the AI advisor at this time. Please check your API connection.",
        ts: new Date().toLocaleTimeString(),
      }]);
    } finally {
      setChatLoading(false);
    }
  };

  const handleRefresh = () => {
    setRefreshing(true);
    fetchAll();
    setTimeout(() => setRefreshing(false), 800);
  };

  // Derive KPI values from stats
  const totalRecs = stats?.total_recommendations ??
    (stats?.recommendations_by_priority
      ? Object.values(stats.recommendations_by_priority).reduce((a, b) => a + b, 0)
      : recs.length);
  const criticalCount = stats?.recommendations_by_priority?.critical ?? recs.filter((r) => r.priority === "critical").length;
  const implementedCount = stats?.implemented_count ?? recs.filter((r) => r.status === "implemented").length;
  const sessionCount = stats?.session_count ?? sessions.length;

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      {/* Header */}
      <PageHeader
        title="AI Security Advisor"
        description="LLM-powered security intelligence — proactive recommendations, incident analysis, and threat briefings"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Recommendations" value={totalRecs}       icon={Brain}    trend="up"   className="border-purple-500/20" />
        <KpiCard title="Critical Findings"     value={criticalCount}   icon={Shield}   trend="up"   className="border-red-500/20" />
        <KpiCard title="Implemented"           value={implementedCount} icon={Activity} trend="up"   className="border-green-500/20" />
        <KpiCard title="Advisor Sessions"      value={sessionCount}    icon={FileText} trend="flat" className="border-indigo-500/20" />
      </div>

      {/* Section 1: Ask the Advisor */}
      <Card className="border-purple-500/20">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold flex items-center gap-2 text-purple-400">
            <Brain className="h-4 w-4" />
            Ask the Advisor
          </CardTitle>
          <CardDescription className="text-xs">
            Query your AI security consultant — powered by LLM consensus across 4 models
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Chat history */}
          <div
            className={cn(
              "space-y-3 max-h-[420px] overflow-y-auto rounded-lg border border-muted/20 p-3",
              "bg-black/20 shadow-inner"
            )}
          >
            {chatMessages.length === 0 && (
              <div className="flex flex-col items-center justify-center py-8 text-muted-foreground gap-2">
                <Bot className="h-8 w-8 opacity-30" />
                <p className="text-xs">Ask a security question to get started</p>
                <p className="text-[10px] opacity-60">e.g. "What are our top 3 critical priorities?" or "Is our SOC2 audit ready?"</p>
              </div>
            )}
            {chatMessages.map((msg, idx) => (
              <div key={idx} className="flex items-start gap-2">
                {msg.role === "user" ? (
                  <div className="shrink-0 w-6 h-6 rounded-full bg-muted/40 flex items-center justify-center">
                    <User className="h-3 w-3 text-muted-foreground" />
                  </div>
                ) : (
                  <div className="shrink-0 w-6 h-6 rounded-full bg-purple-600/30 border border-purple-500/30 flex items-center justify-center">
                    <Bot className="h-3 w-3 text-purple-400" />
                  </div>
                )}
                <div className={cn(
                  "flex-1 rounded-md px-3 py-2 text-xs text-foreground leading-relaxed",
                  msg.role === "user"
                    ? "bg-muted/20"
                    : "border border-purple-500/20 bg-purple-500/5"
                )}>
                  {msg.content}
                  {msg.ts && <span className="ml-2 text-[10px] text-muted-foreground">{msg.ts}</span>}
                </div>
              </div>
            ))}
            {chatLoading && (
              <div className="flex items-start gap-2">
                <div className="shrink-0 w-6 h-6 rounded-full bg-purple-600/30 border border-purple-500/30 flex items-center justify-center">
                  <Bot className="h-3 w-3 text-purple-400 animate-pulse" />
                </div>
                <div className="flex-1 rounded-md border border-purple-500/20 bg-purple-500/5 px-3 py-2 text-xs text-muted-foreground italic">
                  Analyzing...
                </div>
              </div>
            )}
            <div ref={chatBottomRef} />
          </div>

          {/* Input */}
          <div className="flex gap-2">
            <textarea
              value={question}
              onChange={(e) => setQuestion(e.target.value)}
              onKeyDown={(e) => { if (e.key === "Enter" && !e.shiftKey) { e.preventDefault(); handleSend(); } }}
              placeholder="Ask your security question... e.g. 'What's our biggest risk right now?' or 'How do we handle this CVE?'"
              className={cn(
                "flex-1 min-h-[60px] max-h-[100px] resize-none rounded-md border border-purple-500/20 bg-purple-500/5",
                "px-3 py-2 text-xs text-foreground placeholder:text-muted-foreground",
                "focus:outline-none focus:ring-1 focus:ring-purple-500/50 shadow-inner"
              )}
            />
            <Button
              size="sm"
              onClick={handleSend}
              disabled={chatLoading || !question.trim()}
              className="self-end h-9 px-4 bg-gradient-to-r from-purple-600 to-violet-600 hover:from-purple-500 hover:to-violet-500 text-white border-0"
            >
              <Send className="h-3.5 w-3.5 mr-1.5" />
              {chatLoading ? "Thinking..." : "Generate Insight"}
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Section 2: AI-Generated Recommendations */}
      <Card className="border-purple-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-sm font-semibold flex items-center gap-2 text-purple-400">
                <Zap className="h-4 w-4" />
                AI-Generated Recommendations
              </CardTitle>
              <CardDescription className="text-xs">
                LLM-analysed security improvements ranked by risk impact
              </CardDescription>
            </div>
            <Badge className="text-[10px] border border-purple-500/30 text-purple-400 bg-purple-500/10">
              {recs.length} recommendations
            </Badge>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          {recs.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-14 text-muted-foreground gap-2">
              <Zap className="h-8 w-8 opacity-30" />
              <p className="text-sm">No recommendations yet</p>
              <p className="text-xs">Start an advisor session to generate recommendations</p>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="hover:bg-transparent">
                    <TableHead className="text-[11px] h-8">Priority</TableHead>
                    <TableHead className="text-[11px] h-8">Category</TableHead>
                    <TableHead className="text-[11px] h-8">Recommendation</TableHead>
                    <TableHead className="text-[11px] h-8">Effort</TableHead>
                    <TableHead className="text-[11px] h-8">Impact</TableHead>
                    <TableHead className="text-[11px] h-8">Status</TableHead>
                    <TableHead className="text-[11px] h-8 text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {recs.map((rec) => {
                    const effort = rec.effort ?? (rec.effort_days != null ? `${rec.effort_days}d` : "—");
                    const impact = rec.impact ?? Math.round(rec.impact_score ?? 0);
                    const rationale = rec.rationale ?? rec.description ?? "";
                    return (
                      <TableRow key={rec.id} className="hover:bg-muted/30">
                        <TableCell className="py-2.5"><PriorityBadge p={rec.priority} /></TableCell>
                        <TableCell className="py-2.5"><CategoryBadge cat={rec.category} /></TableCell>
                        <TableCell className="py-2.5 max-w-[280px]">
                          <p className="text-xs font-medium truncate">{rec.title}</p>
                          {rationale && <p className="text-[10px] text-muted-foreground truncate mt-0.5">{rationale}</p>}
                        </TableCell>
                        <TableCell className="text-xs py-2.5 tabular-nums text-muted-foreground font-medium">{effort}</TableCell>
                        <TableCell className="py-2.5"><ImpactDots score={impact} /></TableCell>
                        <TableCell className="py-2.5"><StatusBadge s={rec.status} /></TableCell>
                        <TableCell className="py-2.5 text-right">
                          <div className="flex items-center justify-end gap-1">
                            {rec.status === "pending" && (
                              <Button variant="outline" size="sm" className="h-6 px-2 text-[10px] border-green-500/30 text-green-400 hover:bg-green-500/10">
                                Accept
                              </Button>
                            )}
                            <Button variant="outline" size="sm" className="h-6 px-2 text-[10px]">
                              View Details
                            </Button>
                          </div>
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Section 3: Quick Analysis Panels */}
      <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
        {/* Posture Review */}
        <Card className="border-blue-500/20">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-blue-400">
              <Shield className="h-4 w-4" />
              Posture Review
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs text-muted-foreground">Advisor sessions available</p>
                <p className="text-2xl font-bold tabular-nums">{sessionCount}</p>
              </div>
            </div>
            <Button size="sm" className="w-full h-7 text-xs bg-blue-600/20 hover:bg-blue-600/30 text-blue-400 border border-blue-500/20">
              Run Full Analysis
            </Button>
          </CardContent>
        </Card>

        {/* Threat Briefing */}
        <Card className="border-red-500/20">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-red-400">
              <AlertTriangle className="h-4 w-4" />
              Threat Briefing
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div>
              <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10 mb-1">
                {criticalCount > 0 ? "Critical findings present" : "No critical findings"}
              </Badge>
              <p className="text-xs text-muted-foreground">{criticalCount} critical recommendations</p>
            </div>
            <Button size="sm" className="w-full h-7 text-xs bg-red-600/20 hover:bg-red-600/30 text-red-400 border border-red-500/20">
              Generate Briefing
            </Button>
          </CardContent>
        </Card>

        {/* Incident Analyzer */}
        <Card className="border-amber-500/20">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-amber-400">
              <Activity className="h-4 w-4" />
              Incident Analyzer
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3">
            <div>
              <p className="text-xs text-muted-foreground">Pending recommendations</p>
              <p className="text-2xl font-bold tabular-nums">
                {recs.filter((r) => r.status === "pending").length}
                <span className="text-sm text-muted-foreground font-normal"> pending</span>
              </p>
            </div>
            <Button size="sm" className="w-full h-7 text-xs bg-amber-600/20 hover:bg-amber-600/30 text-amber-400 border border-amber-500/20">
              Analyze Now
            </Button>
          </CardContent>
        </Card>
      </div>

      {/* Section 4: Session History */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <div>
              <CardTitle className="text-sm font-semibold flex items-center gap-2">
                <Clock className="h-4 w-4 text-muted-foreground" />
                Session History
              </CardTitle>
              <CardDescription className="text-xs">Previous advisor sessions and generated outputs</CardDescription>
            </div>
            <Badge className="text-[10px] border border-border text-muted-foreground">
              {sessions.length} sessions
            </Badge>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          {sessions.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-14 text-muted-foreground gap-2">
              <Clock className="h-8 w-8 opacity-30" />
              <p className="text-sm">No advisor sessions yet</p>
            </div>
          ) : (
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Session ID</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Status</TableHead>
                  <TableHead className="text-[11px] h-8">Recommendations</TableHead>
                  <TableHead className="text-[11px] h-8">Created</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Action</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {sessions.map((s) => {
                  const sid       = s.id ?? "—";
                  const stype     = s.session_type ?? s.type ?? "posture_review";
                  const sstatus   = s.status ?? "completed";
                  const recsCount = s.recommendation_count ?? s.recsCount ?? 0;
                  const created   = s.created_at ?? s.createdAt ?? "—";
                  return (
                    <TableRow key={sid} className="hover:bg-muted/30">
                      <TableCell className="text-xs font-mono py-2.5">{sid.slice(0, 8).toUpperCase()}</TableCell>
                      <TableCell className="py-2.5"><SessionTypeBadge t={stype} /></TableCell>
                      <TableCell className="py-2.5">
                        <div className="flex items-center gap-1">
                          {sstatus === "completed" ? <CheckCircle className="h-3 w-3 text-green-400" /> :
                           sstatus === "failed"    ? <XCircle className="h-3 w-3 text-red-400" /> :
                                                     <Clock className="h-3 w-3 text-yellow-400" />}
                          <StatusBadge s={sstatus as SessionStatus} />
                        </div>
                      </TableCell>
                      <TableCell className="text-xs py-2.5 tabular-nums text-center">{recsCount}</TableCell>
                      <TableCell className="text-xs py-2.5 tabular-nums text-muted-foreground">
                        {typeof created === "string" ? created.slice(0, 16).replace("T", " ") : "—"}
                      </TableCell>
                      <TableCell className="py-2.5 text-right">
                        <Button variant="outline" size="sm" className="h-6 px-2 text-[10px]" disabled={sstatus !== "completed"}>
                          View
                        </Button>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </motion.div>
  );
}
