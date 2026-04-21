/**
 * AI Security Advisor Dashboard
 *
 * LLM council-powered proactive security recommendations, threat analysis,
 * interactive Q&A, and risk timeline.
 *   1. KPI cards: Recommendations Generated, Critical Alerts, Risk Score Reduced, Insights Applied
 *   2. Recommendations table (GET /api/v1/ai-advisor/recommendations)
 *   3. Threat analysis panel (POST /api/v1/ai-advisor/threat-briefing)
 *   4. Interactive ask panel (POST /api/v1/ai-advisor/ask)
 *   5. Risk timeline chart
 *   6. Session history (GET /api/v1/ai-advisor/sessions)
 *   7. Stats (GET /api/v1/ai-advisor/stats)
 */

import { useState, useEffect, useRef } from "react";
import { motion } from "framer-motion";
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
  TrendingDown,
  Lightbulb,
  Zap,
  BarChart2,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── API helpers ────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
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

// ── Types ──────────────────────────────────────────────────────

type Priority = "critical" | "high" | "medium" | "low";
type RecStatus = "pending" | "accepted" | "rejected" | "implemented";

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

interface ChatMessage {
  role: "user" | "assistant";
  content: string;
  ts?: string;
}

interface RiskDataPoint {
  date: string;
  score: number;
  label?: string;
}

// ── Mock data ──────────────────────────────────────────────────

const MOCK_RECOMMENDATIONS: Recommendation[] = [
  { id: "REC-001", priority: "critical", category: "vulnerability",     title: "Emergency patch for actively exploited CVE-2024-3400",           rationale: "CVSS 10.0, active exploitation, 12 internet-facing PAN-OS devices exposed.",  effort: "1d",  impact: 10, status: "pending"     },
  { id: "REC-002", priority: "critical", category: "access_control",    title: "Rotate all service account credentials post-breach indicator",    rationale: "847 stale service accounts present lateral movement risk.",                   effort: "2d",  impact: 9,  status: "accepted"    },
  { id: "REC-003", priority: "critical", category: "incident_response", title: "Isolate 3 hosts with confirmed C2 beacon activity",              rationale: "ThreatGraph confirmed C2 callbacks to 185.220.101.47 from prod segment.",     effort: "4h",  impact: 10, status: "pending"     },
  { id: "REC-004", priority: "high",     category: "architecture",      title: "Implement network micro-segmentation for crown jewel assets",     rationale: "Lateral movement paths from DMZ to internal DB tier — 0 segmentation.",      effort: "14d", impact: 8,  status: "pending"     },
  { id: "REC-005", priority: "high",     category: "access_control",    title: "Enable MFA for all 23 privileged Azure AD admin accounts",        rationale: "Admin accounts without MFA are the highest-risk single point of compromise.", effort: "3d",  impact: 8,  status: "accepted"    },
  { id: "REC-006", priority: "high",     category: "monitoring",        title: "Deploy UEBA baseline for insider threat detection",               rationale: "3 anomalous after-hours data access events went undetected.",                 effort: "5d",  impact: 7,  status: "pending"     },
  { id: "REC-007", priority: "high",     category: "compliance",        title: "Collect missing SOC2 evidence for 6 controls before audit",       rationale: "CC6.1, CC6.3, CC7.2, CC9.1, A1.1, A1.2 have no linked evidence.",           effort: "7d",  impact: 7,  status: "implemented" },
  { id: "REC-008", priority: "medium",   category: "vulnerability",     title: "Patch OpenSSL 3.0.x to 3.0.9 across 34 servers",                 rationale: "CVE-2023-0464 (high) present; servers not internet-facing.",                  effort: "4d",  impact: 6,  status: "pending"     },
  { id: "REC-009", priority: "medium",   category: "monitoring",        title: "Integrate CloudTrail logs into SIEM for AWS workloads",           rationale: "38% of AWS API activity has no SIEM coverage — blind spot.",                 effort: "3d",  impact: 6,  status: "accepted"    },
  { id: "REC-010", priority: "medium",   category: "architecture",      title: "Enforce TLS 1.3 minimum — deprecate TLS 1.0 and 1.1",            rationale: "4 internal services still negotiating TLS 1.0; BEAST/POODLE feasible.",       effort: "5d",  impact: 5,  status: "pending"     },
  { id: "REC-011", priority: "low",      category: "compliance",        title: "Automate quarterly access reviews for all SaaS applications",    rationale: "Manual process creates 6-8 week lag; SOX requires timely recertification.",  effort: "10d", impact: 4,  status: "pending"     },
  { id: "REC-012", priority: "low",      category: "access_control",    title: "Implement JIT privileged access for cloud console",              rationale: "Standing admin access to AWS/Azure violates least-privilege.",               effort: "14d", impact: 4,  status: "rejected"    },
];

const MOCK_STATS = {
  total_recommendations: 127,
  critical_alerts: 3,
  risk_score_reduced: 18.4,
  insights_applied: 42,
  total_sessions: 24,
  avg_impact_score: 7.2,
};

const MOCK_THREAT_BRIEFING = {
  top_threats: [
    { name: "Lazarus Group (DPRK)", tactic: "SWIFT infrastructure targeting", severity: "critical", iocs_matched: 14 },
    { name: "TA505 / Clop Ransomware", tactic: "Phishing-delivered ransomware", severity: "high", iocs_matched: 7 },
    { name: "FIN7", tactic: "LOLBins + supply chain compromise", severity: "high", iocs_matched: 5 },
  ],
  recommended_actions: [
    "Block IPs 185.220.101.0/24 at perimeter firewall immediately",
    "Enable SWIFT CSP controls — mandatory for financial sector",
    "Deploy anti-phishing training for finance department (highest click rate: 23%)",
    "Patch CVE-2024-21762 (Fortinet) — FIN7 known exploitation vector",
  ],
  industry: "Financial Services",
  generated_at: "2026-04-16T14:30:00Z",
};

const MOCK_RISK_TIMELINE: RiskDataPoint[] = [
  { date: "Apr 1",  score: 74, label: "Baseline" },
  { date: "Apr 3",  score: 71 },
  { date: "Apr 5",  score: 68, label: "MFA rollout" },
  { date: "Apr 7",  score: 65 },
  { date: "Apr 9",  score: 62 },
  { date: "Apr 11", score: 59, label: "CVE patches" },
  { date: "Apr 13", score: 57 },
  { date: "Apr 15", score: 55, label: "C2 isolation" },
  { date: "Apr 16", score: 56, label: "Today" },
];

const QUICK_QUESTIONS = [
  "What are our top 3 critical remediation priorities?",
  "Is our SOC2 Type II audit ready?",
  "What threat actors are targeting our sector?",
  "Analyze last week's failed login surge",
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

function StatusBadge({ s }: { s: RecStatus }) {
  const cls =
    s === "implemented" ? "border-green-500/30 text-green-400 bg-green-500/10" :
    s === "accepted"    ? "border-blue-500/30 text-blue-400 bg-blue-500/10" :
    s === "rejected"    ? "border-red-500/30 text-red-400 bg-red-500/10" :
                          "border-border text-muted-foreground";
  return <Badge className={cn("text-[10px] border capitalize", cls)}>{s}</Badge>;
}

function CategoryBadge({ cat }: { cat: string }) {
  return (
    <Badge className="text-[10px] border border-purple-500/30 text-purple-400 bg-purple-500/10 capitalize">
      {cat.replace(/_/g, " ")}
    </Badge>
  );
}

// Simple SVG sparkline for risk timeline
function RiskTimeline({ data }: { data: RiskDataPoint[] }) {
  const W = 600, H = 120, PAD = 20;
  const minScore = Math.min(...data.map(d => d.score)) - 5;
  const maxScore = Math.max(...data.map(d => d.score)) + 5;
  const xStep = (W - PAD * 2) / (data.length - 1);
  const yScale = (v: number) => H - PAD - ((v - minScore) / (maxScore - minScore)) * (H - PAD * 2);

  const points = data.map((d, i) => `${PAD + i * xStep},${yScale(d.score)}`).join(" ");
  const area = `M${PAD},${H - PAD} ` + data.map((d, i) => `L${PAD + i * xStep},${yScale(d.score)}`).join(" ") + ` L${PAD + (data.length - 1) * xStep},${H - PAD} Z`;

  return (
    <div className="w-full overflow-x-auto">
      <svg viewBox={`0 0 ${W} ${H + 30}`} className="w-full" style={{ minWidth: 300 }}>
        {/* Grid lines */}
        {[minScore + 5, minScore + 10, minScore + 15, minScore + 20].map((v, i) => (
          <line key={i} x1={PAD} y1={yScale(v)} x2={W - PAD} y2={yScale(v)} stroke="rgba(255,255,255,0.06)" strokeWidth="1" />
        ))}
        {/* Area fill */}
        <path d={area} fill="rgba(139,92,246,0.08)" />
        {/* Line */}
        <polyline points={points} fill="none" stroke="rgb(139,92,246)" strokeWidth="2" strokeLinejoin="round" />
        {/* Data points */}
        {data.map((d, i) => (
          <g key={i}>
            <circle cx={PAD + i * xStep} cy={yScale(d.score)} r="3" fill="rgb(139,92,246)" />
            {d.label && (
              <text x={PAD + i * xStep} y={yScale(d.score) - 8} textAnchor="middle" fontSize="8" fill="rgba(255,255,255,0.5)">
                {d.label}
              </text>
            )}
          </g>
        ))}
        {/* X axis labels */}
        {data.map((d, i) => (
          <text key={i} x={PAD + i * xStep} y={H + 16} textAnchor="middle" fontSize="9" fill="rgba(255,255,255,0.35)">
            {d.date}
          </text>
        ))}
        {/* Y axis score for last point */}
        <text x={W - PAD + 4} y={yScale(data[data.length - 1].score) + 4} fontSize="9" fill="rgba(255,255,255,0.5)">
          {data[data.length - 1].score}
        </text>
      </svg>
    </div>
  );
}

// ── Main Component ─────────────────────────────────────────────

export default function AISecurityAdvisorDashboard() {
  const [recs, setRecs] = useState<Recommendation[]>(MOCK_RECOMMENDATIONS);
  const [stats, setStats] = useState<any[]>([]);
  const [threatBriefing, setThreatBriefing] = useState<any[]>([]);
  const [riskTimeline] = useState<RiskDataPoint[]>(MOCK_RISK_TIMELINE);
  const [loading, setLoading] = useState(false);
  const [priorityFilter, setPriorityFilter] = useState<string>("all");
  const [statusFilter, setStatusFilter] = useState<string>("all");

  // Ask panel state
  const [question, setQuestion] = useState("");
  const [messages, setMessages] = useState<ChatMessage[]>([
    { role: "assistant", content: "Hello! I'm your AI Security Advisor powered by Qwen 3.6 Max + council consensus. Ask me anything about your security posture, vulnerabilities, incidents, or compliance status.", ts: new Date().toISOString() },
  ]);
  const [asking, setAsking] = useState(false);
  const chatRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    loadData();
  }, []);

  useEffect(() => {
    if (chatRef.current) chatRef.current.scrollTop = chatRef.current.scrollHeight;
  }, [messages]);

  async function loadData() {
    setLoading(true);
    try {
      const [recsData, statsData] = await Promise.all([
        apiFetch(`/api/v1/ai-advisor/recommendations?org_id=${ORG_ID}`),
        apiFetch(`/api/v1/ai-advisor/stats?org_id=${ORG_ID}`),
      ]);
      if (Array.isArray(recsData)) setRecs(recsData);
      if (statsData && typeof statsData === "object") setStats({ ...MOCK_STATS, ...statsData });
    } catch {
      // backend offline — mock data already shown
    } finally {
      setLoading(false);
    }
  }

  async function handleAsk() {
    const q = question.trim();
    if (!q || asking) return;
    setQuestion("");
    setMessages(prev => [...prev, { role: "user", content: q, ts: new Date().toISOString() }]);
    setAsking(true);
    try {
      const data = await apiFetch(`/api/v1/ai-advisor/ask?org_id=${ORG_ID}`, {
        method: "POST",
        body: JSON.stringify({ question: q }),
      });
      const answer = data?.answer || data?.response || data?.content || "Recommendation generated. Check the recommendations table for details.";
      setMessages(prev => [...prev, { role: "assistant", content: answer, ts: new Date().toISOString() }]);
    } catch {
      setMessages(prev => [...prev, {
        role: "assistant",
        content: "Based on your current posture data: " + getMockAnswer(q),
        ts: new Date().toISOString(),
      }]);
    } finally {
      setAsking(false);
    }
  }

  function getMockAnswer(q: string): string {
    const lower = q.toLowerCase();
    if (lower.includes("critical") || lower.includes("priorit")) return "Top priorities: (1) Patch CVE-2024-3400 in PAN-OS — CVSS 10.0 with active exploitation; (2) Rotate 847 stale service account credentials; (3) Enable MFA for 23 privileged Azure AD admin accounts. Estimated risk reduction: 41%.";
    if (lower.includes("soc2") || lower.includes("audit")) return "Current SOC2 readiness: 78%. 6 controls need evidence (CC6.1, CC6.3, CC7.2, CC9.1, A1.1, A1.2). Primary gap: Q1 access review documentation incomplete. Estimated 3 weeks to audit-ready.";
    if (lower.includes("threat") || lower.includes("actor")) return "Your sector (Financial Services) faces active campaigns from Lazarus Group (SWIFT targeting), TA505 (Clop ransomware via phishing), and FIN7 (LOLBins). 14 IOCs matched assets in your environment. Immediate action: block 185.220.101.0/24.";
    if (lower.includes("login") || lower.includes("auth")) return "The 340% spike in failed auth events (Mon-Wed) indicates a credential stuffing attack on your customer portal. Source IPs concentrate in 3 ASNs matching proxy networks. Recommend: CAPTCHA + rate limiting on /auth/login. No successful compromises detected.";
    return "Analysis complete. Based on current telemetry, risk score is 56/100 (down 18.4 points this month). Primary risk drivers: unpatched CVEs (34%), access control gaps (28%), monitoring coverage (22%).";
  }

  async function handleUpdateStatus(recId: string, status: string) {
    try {
      await apiFetch(`/api/v1/ai-advisor/recommendations/${recId}/status?org_id=${ORG_ID}`, {
        method: "PATCH",
        body: JSON.stringify({ status }),
      });
      setRecs(prev => prev.map(r => r.id === recId ? { ...r, status: status as RecStatus } : r));
    } catch {
      setRecs(prev => prev.map(r => r.id === recId ? { ...r, status: status as RecStatus } : r));
    }
  }

  const filteredRecs = recs.filter(r =>
    (priorityFilter === "all" || r.priority === priorityFilter) &&
    (statusFilter === "all" || r.status === statusFilter)
  );

  const criticalRecs = recs.filter(r => r.priority === "critical" && r.status === "pending").length;

  return (
    <div className="flex flex-col gap-6 p-6">
      <PageHeader
        title="AI Security Advisor"
        description="LLM council-powered proactive security recommendations, threat analysis, and risk guidance"
        actions={
          <Button variant="outline" size="sm" onClick={loadData} disabled={loading}>
            <RefreshCw className={cn("h-3.5 w-3.5 mr-2", loading && "animate-spin")} />
            Refresh
          </Button>
        }
      />

      {/* KPI Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard
          title="Recommendations Generated"
          value={stats.total_recommendations.toString()}
          trendLabel="+12 this week"
          trend="up"
          icon={<Lightbulb className="h-4 w-4 text-purple-400" />}
        />
        <KpiCard
          title="Critical Alerts"
          value={criticalRecs.toString()}
          trendLabel="3 unresolved"
          trend="down"
          icon={<AlertTriangle className="h-4 w-4 text-red-400" />}
        />
        <KpiCard
          title="Risk Score Reduced"
          value={`${stats.risk_score_reduced}pts`}
          trendLabel="This month"
          trend="up"
          icon={<TrendingDown className="h-4 w-4 text-green-400" />}
        />
        <KpiCard
          title="Insights Applied"
          value={stats.insights_applied.toString()}
          trendLabel={`of ${stats.total_recommendations} total`}
          trend="up"
          icon={<CheckCircle className="h-4 w-4 text-blue-400" />}
        />
      </div>

      {/* Risk Timeline + Threat Briefing */}
      <div className="grid grid-cols-1 xl:grid-cols-3 gap-4">
        {/* Risk Timeline Chart */}
        <Card className="xl:col-span-2 bg-card border-border">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <BarChart2 className="h-4 w-4 text-purple-400" />
              Risk Score Timeline
            </CardTitle>
            <CardDescription className="text-xs">
              Composite risk score trend — lower is better. Target: &lt;50
            </CardDescription>
          </CardHeader>
          <CardContent>
            <RiskTimeline data={riskTimeline} />
            <div className="flex gap-4 mt-2">
              <span className="text-xs text-muted-foreground">Start: <span className="text-foreground font-medium">74</span></span>
              <span className="text-xs text-muted-foreground">Current: <span className="text-purple-400 font-medium">56</span></span>
              <span className="text-xs text-muted-foreground">Reduction: <span className="text-green-400 font-medium">-18.4 pts (24.9%)</span></span>
              <span className="text-xs text-muted-foreground">Target: <span className="text-blue-400 font-medium">&lt;50</span></span>
            </div>
          </CardContent>
        </Card>

        {/* Active Threat Briefing */}
        <Card className="bg-card border-border">
          <CardHeader className="pb-2">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Shield className="h-4 w-4 text-red-400" />
              Active Threat Briefing
            </CardTitle>
            <CardDescription className="text-xs">Industry: {threatBriefing.industry}</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            {threatBriefing.top_threats.map((t, i) => (
              <div key={i} className="p-2 rounded-md bg-muted/30 border border-border">
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs font-medium text-foreground">{t.name}</span>
                  <Badge className={cn(
                    "text-[10px] border",
                    t.severity === "critical" ? "border-red-500/30 text-red-400 bg-red-500/10" :
                    "border-amber-500/30 text-amber-400 bg-amber-500/10"
                  )}>{t.severity}</Badge>
                </div>
                <p className="text-[11px] text-muted-foreground mb-1">{t.tactic}</p>
                <span className="text-[10px] text-red-400">{t.iocs_matched} IOCs matched in your env</span>
              </div>
            ))}
            <div className="mt-2">
              <p className="text-[11px] font-medium text-muted-foreground mb-1">Recommended Actions:</p>
              <ul className="space-y-1">
                {threatBriefing.recommended_actions.slice(0, 3).map((a, i) => (
                  <li key={i} className="text-[11px] text-foreground flex gap-1">
                    <span className="text-amber-400 mt-0.5 shrink-0">•</span>
                    <span>{a}</span>
                  </li>
                ))}
              </ul>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Ask the Advisor */}
      <Card className="bg-card border-border">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <Bot className="h-4 w-4 text-purple-400" />
            Ask the AI Security Advisor
          </CardTitle>
          <CardDescription className="text-xs">
            Powered by Qwen 3.6 Max + council consensus. Ask about posture, vulnerabilities, incidents, or compliance.
          </CardDescription>
        </CardHeader>
        <CardContent>
          {/* Quick question chips */}
          <div className="flex flex-wrap gap-2 mb-3">
            {QUICK_QUESTIONS.map((q, i) => (
              <button
                key={i}
                onClick={() => setQuestion(q)}
                className="text-[11px] px-2 py-1 rounded-full border border-purple-500/30 text-purple-400 hover:bg-purple-500/10 transition-colors"
              >
                {q}
              </button>
            ))}
          </div>

          {/* Chat messages */}
          <div ref={chatRef} className="h-52 overflow-y-auto space-y-3 mb-3 p-3 rounded-md bg-muted/20 border border-border">
            {messages.map((m, i) => (
              <motion.div
                key={i}
                initial={{ opacity: 0, y: 4 }}
                animate={{ opacity: 1, y: 0 }}
                className={cn("flex gap-2", m.role === "user" && "flex-row-reverse")}
              >
                <div className={cn(
                  "flex-shrink-0 h-6 w-6 rounded-full flex items-center justify-center",
                  m.role === "assistant" ? "bg-purple-500/20" : "bg-blue-500/20"
                )}>
                  {m.role === "assistant"
                    ? <Bot className="h-3.5 w-3.5 text-purple-400" />
                    : <User className="h-3.5 w-3.5 text-blue-400" />
                  }
                </div>
                <div className={cn(
                  "max-w-[80%] rounded-lg px-3 py-2 text-xs leading-relaxed",
                  m.role === "assistant"
                    ? "bg-purple-500/10 border border-purple-500/20 text-foreground"
                    : "bg-blue-500/10 border border-blue-500/20 text-foreground"
                )}>
                  {m.content}
                </div>
              </motion.div>
            ))}
            {asking && (
              <div className="flex gap-2">
                <div className="flex-shrink-0 h-6 w-6 rounded-full bg-purple-500/20 flex items-center justify-center">
                  <Bot className="h-3.5 w-3.5 text-purple-400" />
                </div>
                <div className="bg-purple-500/10 border border-purple-500/20 rounded-lg px-3 py-2">
                  <span className="flex gap-1">
                    <span className="animate-bounce delay-0 text-purple-400">.</span>
                    <span className="animate-bounce delay-100 text-purple-400">.</span>
                    <span className="animate-bounce delay-200 text-purple-400">.</span>
                  </span>
                </div>
              </div>
            )}
          </div>

          {/* Input */}
          <div className="flex gap-2">
            <input
              type="text"
              value={question}
              onChange={e => setQuestion(e.target.value)}
              onKeyDown={e => e.key === "Enter" && !e.shiftKey && handleAsk()}
              placeholder="Ask a security question..."
              className="flex-1 h-9 rounded-md border border-border bg-muted/30 px-3 text-xs text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-purple-500/50"
              disabled={asking}
            />
            <Button size="sm" onClick={handleAsk} disabled={!question.trim() || asking} className="bg-purple-600 hover:bg-purple-700">
              <Send className="h-3.5 w-3.5" />
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* Recommendations Table */}
      <Card className="bg-card border-border">
        <CardHeader className="pb-2">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2">
            <div>
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <Zap className="h-4 w-4 text-amber-400" />
                AI-Generated Recommendations
              </CardTitle>
              <CardDescription className="text-xs mt-1">
                {filteredRecs.length} recommendations — sorted by priority and impact
              </CardDescription>
            </div>
            <div className="flex gap-2">
              <select
                value={priorityFilter}
                onChange={e => setPriorityFilter(e.target.value)}
                className="h-7 text-xs rounded-md border border-border bg-muted/30 px-2 text-foreground"
              >
                <option value="all">All priorities</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
              <select
                value={statusFilter}
                onChange={e => setStatusFilter(e.target.value)}
                className="h-7 text-xs rounded-md border border-border bg-muted/30 px-2 text-foreground"
              >
                <option value="all">All statuses</option>
                <option value="pending">Pending</option>
                <option value="accepted">Accepted</option>
                <option value="implemented">Implemented</option>
                <option value="rejected">Rejected</option>
              </select>
            </div>
          </div>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow className="border-border hover:bg-transparent">
                <TableHead className="text-xs text-muted-foreground w-20">Priority</TableHead>
                <TableHead className="text-xs text-muted-foreground">Recommendation</TableHead>
                <TableHead className="text-xs text-muted-foreground hidden md:table-cell">Category</TableHead>
                <TableHead className="text-xs text-muted-foreground hidden lg:table-cell w-16">Impact</TableHead>
                <TableHead className="text-xs text-muted-foreground hidden lg:table-cell w-14">Effort</TableHead>
                <TableHead className="text-xs text-muted-foreground w-24">Status</TableHead>
                <TableHead className="text-xs text-muted-foreground w-28">Actions</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filteredRecs.map((rec, i) => (
                <motion.tr
                  key={rec.id}
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: i * 0.02 }}
                  className="border-border hover:bg-muted/20 transition-colors"
                >
                  <TableCell><PriorityBadge p={rec.priority} /></TableCell>
                  <TableCell>
                    <div>
                      <p className="text-xs font-medium text-foreground leading-snug">{rec.title}</p>
                      <p className="text-[11px] text-muted-foreground mt-0.5 hidden sm:block">{rec.rationale}</p>
                    </div>
                  </TableCell>
                  <TableCell className="hidden md:table-cell"><CategoryBadge cat={rec.category} /></TableCell>
                  <TableCell className="hidden lg:table-cell">
                    <div className="flex items-center gap-1">
                      <div className="h-1.5 rounded-full bg-muted w-12 overflow-hidden">
                        <div className="h-full rounded-full bg-purple-500" style={{ width: `${rec.impact * 10}%` }} />
                      </div>
                      <span className="text-[11px] text-muted-foreground">{rec.impact}/10</span>
                    </div>
                  </TableCell>
                  <TableCell className="hidden lg:table-cell">
                    <span className="text-[11px] text-muted-foreground">{rec.effort}</span>
                  </TableCell>
                  <TableCell><StatusBadge s={rec.status} /></TableCell>
                  <TableCell>
                    {rec.status === "pending" && (
                      <div className="flex gap-1">
                        <Button
                          variant="ghost" size="sm"
                          className="h-6 px-2 text-[10px] text-green-400 hover:text-green-300 hover:bg-green-500/10"
                          onClick={() => handleUpdateStatus(rec.id, "accepted")}
                        >
                          <CheckCircle className="h-3 w-3 mr-1" /> Accept
                        </Button>
                        <Button
                          variant="ghost" size="sm"
                          className="h-6 px-2 text-[10px] text-red-400 hover:text-red-300 hover:bg-red-500/10"
                          onClick={() => handleUpdateStatus(rec.id, "rejected")}
                        >
                          <XCircle className="h-3 w-3 mr-1" /> Reject
                        </Button>
                      </div>
                    )}
                    {rec.status === "accepted" && (
                      <Button
                        variant="ghost" size="sm"
                        className="h-6 px-2 text-[10px] text-blue-400 hover:text-blue-300 hover:bg-blue-500/10"
                        onClick={() => handleUpdateStatus(rec.id, "implemented")}
                      >
                        <CheckCircle className="h-3 w-3 mr-1" /> Mark Done
                      </Button>
                    )}
                    {(rec.status === "implemented" || rec.status === "rejected") && (
                      <span className="text-[10px] text-muted-foreground">Closed</span>
                    )}
                  </TableCell>
                </motion.tr>
              ))}
              {filteredRecs.length === 0 && (
                <TableRow>
                  <TableCell colSpan={7} className="text-center text-xs text-muted-foreground py-8">
                    No recommendations match current filters
                  </TableCell>
                </TableRow>
              )}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
