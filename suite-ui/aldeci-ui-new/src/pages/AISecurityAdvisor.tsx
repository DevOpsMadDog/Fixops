/**
 * AI Security Advisor
 *
 * LLM-powered security consultant — proactive recommendations,
 * incident analysis, and threat briefings.
 *   1. KPIs: Recommendations Generated, Critical Findings Addressed,
 *            Avg Risk Reduction, Briefings Delivered
 *   2. Ask the Advisor — chat interface with seeded Q&A
 *   3. AI-Generated Recommendations — priority table (12 rows)
 *   4. Quick Analysis Panels — Posture Review, Threat Briefing, Incident Analyzer
 *   5. Session History
 *
 * API stub: GET /api/v1/ai-advisor/recommendations, /api/v1/ai-advisor/sessions
 */

import { useState, useEffect, useRef } from "react";
import { motion } from "framer-motion";

// ── API helpers ────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "dev-key";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string, options?: RequestInit) {
  const res = await fetch(`${API_BASE}${path}?org_id=default`, {
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
type SessionType = "posture_review" | "incident_analysis" | "threat_briefing" | "remediation_plan";
type SessionStatus = "completed" | "failed" | "pending";

interface ChatMessage {
  role: "user" | "assistant";
  content: string;
  ts?: string;
}

// ── Mock data ──────────────────────────────────────────────────

const QA_EXCHANGES = [
  {
    q: "What are our top 3 critical remediation priorities?",
    a: "Based on current posture data, your top priorities are: (1) Patch CVE-2024-3400 in PAN-OS affecting 12 internet-facing devices — CVSS 10.0 with active exploitation; (2) Remediate 847 expired service account credentials across cloud workloads; (3) Enable MFA for 23 privileged admin accounts in Azure AD. Estimated risk reduction: 41%.",
  },
  {
    q: "Is our SOC2 Type II audit ready?",
    a: "Current compliance posture shows 78% SOC2 readiness. 6 controls need evidence collection (CC6.1, CC6.3, CC7.2, CC9.1, A1.1, A1.2). Primary gap: access review documentation for Q1 is incomplete. Estimated 3 weeks to audit-ready state with current remediation velocity.",
  },
  {
    q: "What threat actors are targeting our sector?",
    a: "Your industry (Financial Services) faces active campaigns from 3 tracked APT groups: Lazarus Group (DPRK) targeting SWIFT infrastructure, TA505 deploying Clop ransomware via phishing, and FIN7 using advanced LOLBins. 14 IOCs from these groups match assets in your environment. Immediate action: block IPs 185.220.101.0/24.",
  },
  {
    q: "Analyze last week's failed login surge",
    a: "The 340% spike in failed auth events (Mon–Wed) indicates a credential stuffing attack targeting your customer portal. Source IPs concentrate in 3 ASNs (AS209588, AS60781, AS62240) with 94% matching known proxy networks. Recommend: implement CAPTCHA + rate limiting on /auth/login. No successful compromises detected — attack was unsuccessful.",
  },
  {
    q: "Generate remediation plan for Log4Shell exposure",
    a: "Found 3 vulnerable Log4j instances: app-server-prod-02 (Log4j 2.14.1), analytics-pipeline-01 (Log4j 2.15.0), legacy-api-gateway (Log4j 2.12.0). Remediation plan: (1) Emergency patch to 2.17.1 — 4h effort; (2) WAF rule deployment — 30min; (3) Network egress blocking for JNDI — 1h; (4) Scan for exploitation artifacts in /var/log — 2h. Total: 7.5h. RCA: log4j-core version in Maven pom.xml not pinned.",
  },
];

interface Recommendation {
  id: string;
  priority: Priority;
  category: string;
  title: string;
  rationale: string;
  effort: string;
  impact: number;
  status: RecStatus;
}

const RECOMMENDATIONS: Recommendation[] = [
  { id: "REC-001", priority: "critical", category: "vulnerability",      title: "Emergency patch for actively exploited CVE-2024-3400",                  rationale: "CVSS 10.0, active exploitation in the wild, 12 internet-facing PAN-OS devices exposed.",       effort: "1d",  impact: 10, status: "pending"     },
  { id: "REC-002", priority: "critical", category: "access_control",     title: "Rotate all service account credentials post-breach indicator",            rationale: "Breach indicator detected in SIEM; 847 stale service accounts present lateral movement risk.",  effort: "2d",  impact: 9,  status: "accepted"    },
  { id: "REC-003", priority: "critical", category: "incident_response",  title: "Isolate 3 hosts with confirmed C2 beacon activity",                       rationale: "ThreatGraph correlation confirmed C2 callbacks to 185.220.101.47 from prod segment.",           effort: "4h",  impact: 10, status: "pending"     },
  { id: "REC-004", priority: "high",     category: "architecture",       title: "Implement network micro-segmentation for crown jewel assets",              rationale: "Lateral movement paths identified from DMZ to internal DB tier — 0 segmentation controls.",      effort: "14d", impact: 8,  status: "pending"     },
  { id: "REC-005", priority: "high",     category: "access_control",     title: "Enable MFA for all 23 privileged Azure AD admin accounts",                 rationale: "Admin accounts without MFA represent highest-risk single point of compromise.",                  effort: "3d",  impact: 8,  status: "accepted"    },
  { id: "REC-006", priority: "high",     category: "monitoring",         title: "Deploy UEBA baseline for insider threat detection",                         rationale: "No behavioral baselining active; 3 anomalous after-hours data access events undetected.",         effort: "5d",  impact: 7,  status: "pending"     },
  { id: "REC-007", priority: "high",     category: "compliance",         title: "Collect missing SOC2 evidence for 6 controls before audit",                rationale: "CC6.1, CC6.3, CC7.2, CC9.1, A1.1, A1.2 have no linked evidence — audit fails without them.",    effort: "7d",  impact: 7,  status: "implemented" },
  { id: "REC-008", priority: "medium",   category: "vulnerability",      title: "Patch OpenSSL 3.0.x to 3.0.9 across 34 servers",                           rationale: "CVE-2023-0464 (high) present; servers exposed internally — not internet-facing.",               effort: "4d",  impact: 6,  status: "pending"     },
  { id: "REC-009", priority: "medium",   category: "monitoring",         title: "Integrate CloudTrail logs into SIEM for AWS workloads",                     rationale: "38% of AWS API activity has no SIEM coverage — blind spot for cloud-native attacks.",            effort: "3d",  impact: 6,  status: "accepted"    },
  { id: "REC-010", priority: "medium",   category: "architecture",       title: "Enforce TLS 1.3 minimum — deprecate TLS 1.0 and 1.1",                      rationale: "4 internal services still negotiating TLS 1.0; BEAST and POODLE attacks remain feasible.",        effort: "5d",  impact: 5,  status: "pending"     },
  { id: "REC-011", priority: "low",      category: "compliance",         title: "Automate quarterly access reviews for all SaaS applications",               rationale: "Manual review process creates 6–8 week lag; SOX requires timely recertification.",               effort: "10d", impact: 4,  status: "pending"     },
  { id: "REC-012", priority: "low",      category: "access_control",     title: "Implement just-in-time (JIT) privileged access for cloud console",          rationale: "Standing admin access to AWS/Azure consoles violates least-privilege — JIT reduces blast radius.", effort: "14d", impact: 4,  status: "rejected"    },
];

interface Session {
  id: string;
  type: SessionType;
  status: SessionStatus;
  recsCount: number;
  createdAt: string;
  duration: string;
}

const SESSIONS: Session[] = [
  { id: "SES-0024", type: "posture_review",      status: "completed", recsCount: 8,  createdAt: "2026-04-16 14:30", duration: "3m 42s" },
  { id: "SES-0023", type: "incident_analysis",   status: "completed", recsCount: 5,  createdAt: "2026-04-16 12:15", duration: "2m 18s" },
  { id: "SES-0022", type: "threat_briefing",      status: "completed", recsCount: 12, createdAt: "2026-04-16 09:00", duration: "4m 55s" },
  { id: "SES-0021", type: "remediation_plan",     status: "completed", recsCount: 7,  createdAt: "2026-04-15 17:45", duration: "5m 10s" },
  { id: "SES-0020", type: "posture_review",       status: "completed", recsCount: 9,  createdAt: "2026-04-15 11:00", duration: "3m 28s" },
  { id: "SES-0019", type: "incident_analysis",    status: "failed",    recsCount: 0,  createdAt: "2026-04-15 08:30", duration: "0m 12s" },
  { id: "SES-0018", type: "threat_briefing",      status: "completed", recsCount: 6,  createdAt: "2026-04-14 16:00", duration: "4m 03s" },
  { id: "SES-0017", type: "remediation_plan",     status: "completed", recsCount: 11, createdAt: "2026-04-14 10:20", duration: "6m 30s" },
];

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

function SessionTypeBadge({ t }: { t: SessionType }) {
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
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);
  const [liveRecs, setLiveRecs] = useState<Recommendation[] | null>(null);
  const [liveSessions, setLiveSessions] = useState<Session[] | null>(null);
  const [chatMessages, setChatMessages] = useState<ChatMessage[]>([]);
  const [chatLoading, setChatLoading] = useState(false);
  const chatBottomRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/ai-advisor/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/ai-advisor/recommendations?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/ai-advisor/sessions?org_id=${ORG_ID}`),
    ]).then(([statsRes, recsRes, sessionsRes]) => {
      if (statsRes.status === "fulfilled") setLiveData(statsRes.value);
      if (recsRes.status === "fulfilled") {
        const recs = recsRes.value?.items ?? recsRes.value?.recommendations ?? recsRes.value;
        if (Array.isArray(recs) && recs.length > 0) setLiveRecs(recs);
      }
      if (sessionsRes.status === "fulfilled") {
        const sess = sessionsRes.value?.items ?? sessionsRes.value?.sessions ?? sessionsRes.value;
        if (Array.isArray(sess) && sess.length > 0) setLiveSessions(sess);
      }
    }).finally(() => setDataLoading(false));
  }, []);

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
      const resp = await apiFetch(`/api/v1/ai-advisor/ask?org_id=${ORG_ID}`, {
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
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/ai-advisor/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/ai-advisor/recommendations?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/ai-advisor/sessions?org_id=${ORG_ID}`),
    ]).then(([statsRes, recsRes, sessionsRes]) => {
      if (statsRes.status === "fulfilled") setLiveData(statsRes.value);
      if (recsRes.status === "fulfilled") {
        const recs = recsRes.value?.items ?? recsRes.value?.recommendations ?? recsRes.value;
        if (Array.isArray(recs) && recs.length > 0) setLiveRecs(recs);
      }
      if (sessionsRes.status === "fulfilled") {
        const sess = sessionsRes.value?.items ?? sessionsRes.value?.sessions ?? sessionsRes.value;
        if (Array.isArray(sess) && sess.length > 0) setLiveSessions(sess);
      }
    }).finally(() => { setRefreshing(false); setDataLoading(false); });
  };

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
        <KpiCard title="Recommendations Generated" value={liveData?.total_recommendations ?? liveData?.recommendations_generated ?? 127} icon={Brain}    trend="up"   trendLabel="↑ 12 this week"           className="border-purple-500/20" />
        <KpiCard title="Critical Findings Addressed" value={liveData?.critical_addressed ?? liveData?.accepted_recommendations ?? 18}  icon={Shield}   trend="up"   trendLabel="85% acceptance rate"       className="border-green-500/20" />
        <KpiCard title="Avg Risk Reduction"          value={liveData?.avg_risk_reduction != null ? `${liveData.avg_risk_reduction}%` : "34%"} icon={Activity} trend="up"   trendLabel="per recommendation"        className="border-blue-500/20" />
        <KpiCard title="Briefings Delivered"         value={liveData?.total_sessions ?? liveData?.briefings_delivered ?? 24}  icon={FileText} trend="flat" trendLabel="last 30 days"              className="border-indigo-500/20" />
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
            {/* Seeded Q&A when no live messages yet */}
            {chatMessages.length === 0 && QA_EXCHANGES.map((item, idx) => (
              <div key={idx} className="space-y-2">
                <div className="flex items-start gap-2">
                  <div className="shrink-0 w-6 h-6 rounded-full bg-muted/40 flex items-center justify-center">
                    <User className="h-3 w-3 text-muted-foreground" />
                  </div>
                  <div className="flex-1 rounded-md bg-muted/20 px-3 py-2 text-xs text-foreground">
                    {item.q}
                  </div>
                </div>
                <div className="flex items-start gap-2">
                  <div className="shrink-0 w-6 h-6 rounded-full bg-purple-600/30 border border-purple-500/30 flex items-center justify-center">
                    <Bot className="h-3 w-3 text-purple-400" />
                  </div>
                  <div className="flex-1 rounded-md border border-purple-500/20 bg-purple-500/5 px-3 py-2 text-xs text-foreground leading-relaxed">
                    {item.a}
                  </div>
                </div>
              </div>
            ))}
            {/* Live chat messages */}
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
              {(liveRecs ?? RECOMMENDATIONS).length} recommendations
            </Badge>
          </div>
        </CardHeader>
        <CardContent className="p-0">
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
                {(liveRecs ?? RECOMMENDATIONS).map((rec: any) => (
                  <TableRow key={rec.id} className="hover:bg-muted/30">
                    <TableCell className="py-2.5"><PriorityBadge p={rec.priority} /></TableCell>
                    <TableCell className="py-2.5"><CategoryBadge cat={rec.category} /></TableCell>
                    <TableCell className="py-2.5 max-w-[280px]">
                      <p className="text-xs font-medium truncate">{rec.title}</p>
                      <p className="text-[10px] text-muted-foreground truncate mt-0.5">{rec.rationale}</p>
                    </TableCell>
                    <TableCell className="text-xs py-2.5 tabular-nums text-muted-foreground font-medium">{rec.effort}</TableCell>
                    <TableCell className="py-2.5"><ImpactDots score={rec.impact} /></TableCell>
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
                ))}
              </TableBody>
            </Table>
          </div>
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
                <p className="text-2xl font-bold tabular-nums">72<span className="text-sm text-muted-foreground font-normal">/100</span></p>
                <p className="text-xs text-muted-foreground">Grade: <span className="text-blue-400 font-semibold">B</span></p>
              </div>
              <div className="text-right space-y-1">
                <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">3 critical findings</Badge>
                <p className="text-[10px] text-green-400">↑ Trend: improving</p>
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
            <div className="flex items-center justify-between">
              <div>
                <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10 mb-1">Threat Level: HIGH</Badge>
                <p className="text-xs text-muted-foreground">3 active APT campaigns</p>
                <p className="text-xs text-muted-foreground">14 matched IOCs</p>
              </div>
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
            <div className="flex items-center justify-between">
              <div>
                <p className="text-2xl font-bold tabular-nums">2 <span className="text-sm text-muted-foreground font-normal">open</span></p>
                <p className="text-xs text-muted-foreground">Last analysis: <span className="text-amber-400">2h ago</span></p>
              </div>
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
              {(liveSessions ?? SESSIONS).length} sessions
            </Badge>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow className="hover:bg-transparent">
                <TableHead className="text-[11px] h-8">Session ID</TableHead>
                <TableHead className="text-[11px] h-8">Type</TableHead>
                <TableHead className="text-[11px] h-8">Status</TableHead>
                <TableHead className="text-[11px] h-8">Recommendations</TableHead>
                <TableHead className="text-[11px] h-8">Duration</TableHead>
                <TableHead className="text-[11px] h-8">Created</TableHead>
                <TableHead className="text-[11px] h-8 text-right">Action</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {(liveSessions ?? SESSIONS).map((s: any) => {
                const sid      = s.id ?? s.session_id ?? "—";
                const stype    = s.type ?? s.session_type ?? "posture_review";
                const sstatus  = s.status ?? "completed";
                const recsCount= s.recsCount ?? s.recommendations_count ?? s.rec_count ?? 0;
                const duration = s.duration ?? s.duration_seconds != null ? `${s.duration_seconds}s` : "—";
                const created  = s.createdAt ?? s.created_at ?? "—";
                return (
                <TableRow key={sid} className="hover:bg-muted/30">
                  <TableCell className="text-xs font-mono py-2.5">{sid}</TableCell>
                  <TableCell className="py-2.5"><SessionTypeBadge t={stype as SessionType} /></TableCell>
                  <TableCell className="py-2.5">
                    <div className="flex items-center gap-1">
                      {sstatus === "completed" ? <CheckCircle className="h-3 w-3 text-green-400" /> :
                       sstatus === "failed"    ? <XCircle className="h-3 w-3 text-red-400" /> :
                                                 <Clock className="h-3 w-3 text-yellow-400" />}
                      <StatusBadge s={sstatus as SessionStatus} />
                    </div>
                  </TableCell>
                  <TableCell className="text-xs py-2.5 tabular-nums text-center">{recsCount}</TableCell>
                  <TableCell className="text-xs py-2.5 tabular-nums text-muted-foreground">{duration}</TableCell>
                  <TableCell className="text-xs py-2.5 tabular-nums text-muted-foreground">{created}</TableCell>
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
        </CardContent>
      </Card>
    </motion.div>
  );
}
