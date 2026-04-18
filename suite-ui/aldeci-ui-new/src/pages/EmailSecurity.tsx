/**
 * Email Security Dashboard
 *
 * DMARC enforcement, phishing detection, and email authentication monitoring:
 *   1. KPIs: DMARC Pass Rate, Blocked Phishing Today, Spoofing Attempts, Email Volume
 *   2. Domain Authentication status (3 domains — DMARC/SPF/DKIM badges + Enforce button)
 *   3. DMARC Reports chart: 30-day trend bar chart (pass/fail/quarantine/reject)
 *   4. Top Email Threats table (8 rows)
 *   5. Lookalike Domain Detection (5 suspicious domains)
 *   6. Best Practice Recommendations (4 cards)
 *
 * Route: /email-security
 * API: GET /api/v1/email-security/dmarc-reports, /api/v1/email-security/threats (mock fallback)
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";

// ── API helpers ────────────────────────────────────────────────
const API_KEY = localStorage.getItem("aldeci_api_key") || import.meta.env.VITE_API_KEY || "dev-key";
const ORG_ID = "default";

async function apiFetch(path: string) {
  const res = await fetch(`/api/v1${path}`, {
    headers: { "X-API-Key": API_KEY },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}
import {
  Mail,
  Shield,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  AlertCircle,
  Globe,
  Clock,
  TrendingUp,
  Zap,
  Lock,
  Eye,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ══════════════════════════════════════════════════════════════
// Types
// ══════════════════════════════════════════════════════════════

type AuthStatus = "Pass" | "Fail" | "SoftFail" | "None";
type DmarcPolicy = "none" | "quarantine" | "reject";
type ThreatType = "Phishing" | "Spoofing" | "BEC" | "Malware attachment" | "Spam";
type ActionTaken = "Blocked" | "Quarantined" | "Delivered";

interface DomainAuth {
  id: string;
  domain: string;
  dmarc: AuthStatus;
  spf: AuthStatus;
  dkim: AuthStatus;
  policy: DmarcPolicy;
}

interface DmarcBar {
  date: string;
  pass: number;
  fail: number;
  quarantine: number;
  reject: number;
}

interface EmailThreat {
  id: string;
  timestamp: string;
  from_address: string;
  subject_preview: string;
  threat_type: ThreatType;
  action_taken: ActionTaken;
  similarity: string;
}

interface LookalikeDomain {
  id: string;
  suspicious: string;
  legitimate: string;
  registrar: string;
  registration_date: string;
  hosting_country: string;
  risk_score: number;
}

interface Recommendation {
  id: string;
  title: string;
  description: string;
  impact: "HIGH" | "MEDIUM" | "LOW";
  icon: typeof Shield;
}

// ══════════════════════════════════════════════════════════════
// Mock Data
// ══════════════════════════════════════════════════════════════

const MOCK_DOMAINS: DomainAuth[] = [
  { id: "d1", domain: "domain1.com", dmarc: "Pass", spf: "Pass", dkim: "Pass", policy: "quarantine" },
  { id: "d2", domain: "domain2.com", dmarc: "Fail", spf: "SoftFail", dkim: "Fail", policy: "none" },
  { id: "d3", domain: "subdomain.domain.com", dmarc: "None", spf: "Pass", dkim: "Pass", policy: "none" },
];

const MOCK_DMARC_BARS: DmarcBar[] = [
  { date: "Mar 17", pass: 1820, fail: 120, quarantine: 45, reject: 30 },
  { date: "Mar 21", pass: 2100, fail: 95, quarantine: 60, reject: 20 },
  { date: "Mar 25", pass: 1950, fail: 140, quarantine: 55, reject: 35 },
  { date: "Mar 29", pass: 2350, fail: 88, quarantine: 40, reject: 25 },
  { date: "Apr 02", pass: 2050, fail: 165, quarantine: 70, reject: 42 },
  { date: "Apr 06", pass: 1780, fail: 200, quarantine: 85, reject: 55 },
  { date: "Apr 10", pass: 2420, fail: 75, quarantine: 38, reject: 18 },
  { date: "Apr 14", pass: 2680, fail: 110, quarantine: 52, reject: 28 },
];

const MOCK_THREATS: EmailThreat[] = [
  {
    id: "T001", timestamp: "2026-04-16 09:14",
    from_address: "support@a1deci.io",
    subject_preview: "Urgent: Verify your ALDECI account",
    threat_type: "Phishing", action_taken: "Blocked", similarity: "94%",
  },
  {
    id: "T002", timestamp: "2026-04-16 08:52",
    from_address: "ceo@domain1-secure.net",
    subject_preview: "Wire transfer approval needed ASAP",
    threat_type: "BEC", action_taken: "Quarantined", similarity: "81%",
  },
  {
    id: "T003", timestamp: "2026-04-16 08:31",
    from_address: "noreply@aldec-i.io",
    subject_preview: "Your invoice is attached",
    threat_type: "Malware attachment", action_taken: "Blocked", similarity: "91%",
  },
  {
    id: "T004", timestamp: "2026-04-16 07:48",
    from_address: "admin@domain2.com.spoofed.xyz",
    subject_preview: "Password reset request",
    threat_type: "Spoofing", action_taken: "Blocked", similarity: "78%",
  },
  {
    id: "T005", timestamp: "2026-04-16 07:22",
    from_address: "bulk@promo-service.biz",
    subject_preview: "You've been selected! Claim your reward",
    threat_type: "Spam", action_taken: "Quarantined", similarity: "12%",
  },
  {
    id: "T006", timestamp: "2026-04-16 06:55",
    from_address: "security@aldec1.io",
    subject_preview: "Action required: Security alert",
    threat_type: "Phishing", action_taken: "Blocked", similarity: "96%",
  },
  {
    id: "T007", timestamp: "2026-04-16 06:10",
    from_address: "finance@domaln1.com",
    subject_preview: "Q1 financial statements for review",
    threat_type: "BEC", action_taken: "Quarantined", similarity: "88%",
  },
  {
    id: "T008", timestamp: "2026-04-16 05:33",
    from_address: "it-support@domain1.co",
    subject_preview: "Update your credentials immediately",
    threat_type: "Phishing", action_taken: "Blocked", similarity: "83%",
  },
];

const MOCK_LOOKALIKES: LookalikeDomain[] = [
  { id: "L1", suspicious: "aldec1.io", legitimate: "aldeci.io", registrar: "Namecheap", registration_date: "2026-03-12", hosting_country: "RU", risk_score: 94 },
  { id: "L2", suspicious: "a1deci.io", legitimate: "aldeci.io", registrar: "GoDaddy", registration_date: "2026-03-28", hosting_country: "CN", risk_score: 91 },
  { id: "L3", suspicious: "aldec-i.io", legitimate: "aldeci.io", registrar: "PDR Ltd.", registration_date: "2026-04-01", hosting_country: "US", risk_score: 87 },
  { id: "L4", suspicious: "domaln1.com", legitimate: "domain1.com", registrar: "Namecheap", registration_date: "2026-02-19", hosting_country: "NG", risk_score: 79 },
  { id: "L5", suspicious: "domain1-secure.net", legitimate: "domain1.com", registrar: "GoDaddy", registration_date: "2026-04-08", hosting_country: "BR", risk_score: 72 },
];

const RECOMMENDATIONS: Recommendation[] = [
  {
    id: "R1", title: "Enable DMARC reject policy",
    description: "domain2.com and subdomain.domain.com have p=none. Move to p=reject to prevent spoofing.",
    impact: "HIGH", icon: Shield,
  },
  {
    id: "R2", title: "Add DKIM to 3 domains",
    description: "domain2.com is missing DKIM signatures. Configure DKIM keys in DNS to authenticate outbound mail.",
    impact: "HIGH", icon: Lock,
  },
  {
    id: "R3", title: "Configure MTA-STS",
    description: "Enforce TLS for inbound mail by publishing an MTA-STS policy to prevent downgrade attacks.",
    impact: "MEDIUM", icon: TrendingUp,
  },
  {
    id: "R4", title: "Enable BIMI",
    description: "Brand Indicators for Message Identification adds your logo to authenticated emails, improving trust.",
    impact: "LOW", icon: Eye,
  },
];

// ══════════════════════════════════════════════════════════════
// Styling helpers
// ══════════════════════════════════════════════════════════════

const AUTH_BADGE: Record<AuthStatus, string> = {
  Pass: "bg-green-500/10 text-green-400 border-green-500/30",
  Fail: "bg-red-500/10 text-red-400 border-red-500/30",
  SoftFail: "bg-yellow-500/10 text-yellow-400 border-yellow-500/30",
  None: "bg-slate-500/10 text-slate-400 border-slate-500/30",
};

const POLICY_BADGE: Record<DmarcPolicy, string> = {
  none: "bg-red-500/10 text-red-400",
  quarantine: "bg-yellow-500/10 text-yellow-400",
  reject: "bg-green-500/10 text-green-400",
};

const ACTION_BADGE: Record<ActionTaken, string> = {
  Blocked: "bg-red-500/10 text-red-400",
  Quarantined: "bg-yellow-500/10 text-yellow-400",
  Delivered: "bg-blue-500/10 text-blue-400",
};

const THREAT_BADGE: Record<ThreatType, string> = {
  Phishing: "bg-orange-500/10 text-orange-400",
  Spoofing: "bg-purple-500/10 text-purple-400",
  BEC: "bg-red-500/10 text-red-400",
  "Malware attachment": "bg-pink-500/10 text-pink-400",
  Spam: "bg-slate-500/10 text-slate-400",
};

const IMPACT_COLORS: Record<"HIGH" | "MEDIUM" | "LOW", string> = {
  HIGH: "border-l-red-500 bg-red-500/5",
  MEDIUM: "border-l-yellow-500 bg-yellow-500/5",
  LOW: "border-l-blue-500 bg-blue-500/5",
};

const IMPACT_TEXT: Record<"HIGH" | "MEDIUM" | "LOW", string> = {
  HIGH: "text-red-400",
  MEDIUM: "text-yellow-400",
  LOW: "text-blue-400",
};

// ══════════════════════════════════════════════════════════════
// Sub-components
// ══════════════════════════════════════════════════════════════

function AuthStatusBadge({ status }: { status: AuthStatus }) {
  return (
    <Badge className={cn("text-xs font-semibold border", AUTH_BADGE[status])}>
      {status === "Pass" && <CheckCircle2 className="w-3 h-3 mr-1 inline" />}
      {(status === "Fail" || status === "None") && <XCircle className="w-3 h-3 mr-1 inline" />}
      {status === "SoftFail" && <AlertCircle className="w-3 h-3 mr-1 inline" />}
      {status}
    </Badge>
  );
}

function RiskScoreBadge({ score }: { score: number }) {
  const color = score >= 90 ? "text-red-400" : score >= 75 ? "text-orange-400" : "text-yellow-400";
  return <span className={cn("font-bold tabular-nums", color)}>{score}</span>;
}

// ══════════════════════════════════════════════════════════════
// Main Component
// ══════════════════════════════════════════════════════════════

export default function EmailSecurity() {
  const [enforcing, setEnforcing] = useState<Set<string>>(new Set());
  const [liveData, setLiveData] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.allSettled([
      apiFetch(`/threat-feeds/stats?org_id=${ORG_ID}`),
      apiFetch(`/threat-feeds/items?org_id=${ORG_ID}&feed_type=phishing&limit=20`),
    ]).then(([statsRes, itemsRes]) => {
      const feedStats = statsRes.status === "fulfilled" ? statsRes.value : null;
      const feedItems = itemsRes.status === "fulfilled" ? itemsRes.value : null;
      // Map threat-feed shape to what the template expects
      const stats = feedStats
        ? {
            dmarc_pass_rate: feedStats.feed_health_pct ?? null,
            blocked_count:   feedStats.total_items ?? feedStats.total ?? null,
            spoofing_count:  feedStats.by_type?.spoofing ?? null,
            total_volume:    feedStats.total_items ?? null,
          
    setLoading(false);}
        : null;
      const items = Array.isArray(feedItems)
        ? feedItems
        : (Array.isArray(feedItems?.items) ? feedItems.items : null);
      const threats = items
        ? items.map((item: any) => ({
            id:             item.id ?? item.ioc_id,
            timestamp:      item.last_seen ?? item.created_at ?? "",
            from_address:   item.value ?? item.indicator ?? "",
            subject_preview: item.description ?? item.title ?? "",
            threat_type:    item.feed_type === "phishing" ? "Phishing" : (item.threat_type ?? "Phishing"),
            action_taken:   item.status === "blocked" ? "Blocked" : (item.status === "quarantined" ? "Quarantined" : "Blocked"),
            similarity:     item.confidence != null ? `${item.confidence}%` : "—",
          }))
        : null;
      if (stats || threats) {
        setLiveData({ stats, threats, reports: null, domains: null });
      }
    });
  }, []);

  const handleEnforce = (domainId: string) => {
    setEnforcing((prev) => new Set(prev).add(domainId));
  };

  // Bar chart max for scaling
  const dmarcBars = liveData?.reports ?? MOCK_DMARC_BARS;
  const maxTotal = Math.max(
    ...dmarcBars.map((b: any) => (b.pass ?? b.pass_count ?? 0) + (b.fail ?? b.fail_count ?? 0) + (b.quarantine ?? b.quarantine_count ?? 0) + (b.reject ?? b.reject_count ?? 0))
  );

  if (loading) return (
    <div className="space-y-4 p-6">
      {[1, 2, 3].map((i) => (
        <div key={i} className="h-24 rounded-lg bg-zinc-800/50 animate-pulse" />
      ))}
    </div>
  );

  return (
    <div className="min-h-screen bg-slate-900 p-8 space-y-8">
      {/* Header */}
      <PageHeader
        title="Email Security"
        description="DMARC enforcement, phishing detection, and email authentication monitoring"
      />

      {/* KPIs */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard
          title="DMARC Pass Rate"
          value={liveData?.stats?.dmarc_pass_rate != null ? `${liveData.stats.dmarc_pass_rate.toFixed(0)}%` : "87%"}
          icon={Shield}
          trend="up"
          trendLabel="+2.1% this week"
        />
        <KpiCard
          title="Blocked Phishing Today"
          value={liveData?.stats?.blocked_count ?? liveData?.threats?.filter((t: any) => t.status === "blocked").length ?? 234}
          icon={AlertTriangle}
          trend="down"
          trendLabel="-18 vs yesterday"
        />
        <KpiCard
          title="Spoofing Attempts"
          value={liveData?.stats?.spoofing_count ?? liveData?.threats?.filter((t: any) => t.threat_type === "spoofing").length ?? 12}
          icon={AlertCircle}
          trend="up"
          trendLabel="+3 vs yesterday"
        />
        <KpiCard
          title="Email Volume"
          value={liveData?.stats?.total_volume ?? "45,234"}
          icon={Mail}
          description="Last 24 hours"
        />
      </div>

      {/* Domain Authentication */}
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.1 }}
      >
        <Card className="border-slate-700">
          <CardHeader className="border-b border-slate-700">
            <CardTitle className="flex items-center gap-2">
              <Globe className="w-5 h-5 text-blue-400" />
              Domain Authentication
            </CardTitle>
          </CardHeader>
          <CardContent className="p-6">
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {MOCK_DOMAINS.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                  <p className="text-lg font-medium">No data available</p>
                  <p className="text-sm">Data will appear here once available</p>
                </div>
              ) : (
                MOCK_DOMAINS.map((domain, idx) => (
                <motion.div
                  key={domain.id}
                  initial={{ opacity: 0, scale: 0.97 }}
                  animate={{ opacity: 1, scale: 1 }}
                  transition={{ delay: 0.1 + idx * 0.06 }}
                  className="rounded-lg border border-slate-700 bg-slate-800/40 p-5 space-y-4"
                >
                  <div className="flex items-start justify-between">
                    <span className="font-semibold text-slate-200 text-sm font-mono">
                      {domain.domain}
                    </span>
                    <Badge className={cn("text-xs capitalize", POLICY_BADGE[domain.policy])}>
                      p={domain.policy}
                    </Badge>
                  </div>
                  <div className="grid grid-cols-3 gap-2">
                    <div className="space-y-1 text-center">
                      <p className="text-xs text-slate-500 uppercase tracking-wide">DMARC</p>
                      <AuthStatusBadge status={domain.dmarc} />
                    </div>
                    <div className="space-y-1 text-center">
                      <p className="text-xs text-slate-500 uppercase tracking-wide">SPF</p>
                      <AuthStatusBadge status={domain.spf} />
                    </div>
                    <div className="space-y-1 text-center">
                      <p className="text-xs text-slate-500 uppercase tracking-wide">DKIM</p>
                      <AuthStatusBadge status={domain.dkim} />
                    </div>
                  </div>
                  {domain.policy === "none" && (
                    <Button
                      size="sm"
                      variant="outline"
                      className="w-full border-orange-500/40 text-orange-400 hover:bg-orange-500/10 hover:text-orange-300 text-xs"
                      onClick={() => handleEnforce(domain.id)}
                      disabled={enforcing.has(domain.id)}
                    >
                      <Zap className="w-3 h-3 mr-1" />
                      {enforcing.has(domain.id) ? "Enforcing..." : "Enforce DMARC"}
                    </Button>
                  )}
                </motion.div>
              ))}
              )}
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* DMARC Reports Chart */}
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.2 }}
      >
        <Card className="border-slate-700">
          <CardHeader className="border-b border-slate-700">
            <div className="flex items-center justify-between">
              <CardTitle className="flex items-center gap-2">
                <TrendingUp className="w-5 h-5 text-cyan-400" />
                DMARC Reports — 30-Day Trend
              </CardTitle>
              <div className="flex items-center gap-4 text-xs text-slate-400">
                <span className="flex items-center gap-1.5"><span className="w-3 h-3 rounded-sm bg-green-500/70 inline-block" />Pass</span>
                <span className="flex items-center gap-1.5"><span className="w-3 h-3 rounded-sm bg-red-500/70 inline-block" />Fail</span>
                <span className="flex items-center gap-1.5"><span className="w-3 h-3 rounded-sm bg-yellow-500/70 inline-block" />Quarantine</span>
                <span className="flex items-center gap-1.5"><span className="w-3 h-3 rounded-sm bg-orange-500/70 inline-block" />Reject</span>
              </div>
            </div>
          </CardHeader>
          <CardContent className="p-6">
            <div className="flex items-end gap-2 h-40">
              {dmarcBars.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                  <p className="text-lg font-medium">No data available</p>
                  <p className="text-sm">Data will appear here once available</p>
                </div>
              ) : (
                dmarcBars.map((bar: any, idx: number) => {
                const total = (bar.pass ?? bar.pass_count ?? 0) + (bar.fail ?? bar.fail_count ?? 0) + (bar.quarantine ?? bar.quarantine_count ?? 0) + (bar.reject ?? bar.reject_count ?? 0);
                const scale = maxTotal > 0 ? (total / maxTotal) * 100 : 0;
                const passV = bar.pass ?? bar.pass_count ?? 0;
                const failV = bar.fail ?? bar.fail_count ?? 0;
                const quarV = bar.quarantine ?? bar.quarantine_count ?? 0;
                const rejV  = bar.reject ?? bar.reject_count ?? 0;
                const passH = total > 0 ? (passV / total) * scale : 0;
                const failH = total > 0 ? (failV / total) * scale : 0;
                const quarH = total > 0 ? (quarV / total) * scale : 0;
                const rejH  = total > 0 ? (rejV  / total) * scale : 0;
                return (
                  <div key={idx} className="flex-1 flex flex-col items-center gap-1">
                    <div className="w-full flex flex-col justify-end" style={{ height: "120px" }}>
                      <div
                        className="w-full flex flex-col rounded-sm overflow-hidden gap-px"
                        style={{ height: `${scale}%` }}
                        title={`Pass: ${bar.pass}, Fail: ${bar.fail}, Q: ${bar.quarantine}, R: ${bar.reject}`}
                      >
                        <div className="bg-orange-500/70" style={{ height: `${rejH}%` }} />
                        <div className="bg-yellow-500/70" style={{ height: `${quarH}%` }} />
                        <div className="bg-red-500/70" style={{ height: `${failH}%` }} />
                        <div className="bg-green-500/70 flex-1" />
                      </div>
                    </div>
                    <span className="text-xs text-slate-500 whitespace-nowrap">{bar.date ?? bar.report_date ?? ""}</span>
                  </div>
                );
              })}
              )}
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* Top Email Threats Table */}
      <motion.div
        initial={{ opacity: 0, y: 8 }}
        animate={{ opacity: 1, y: 0 }}
        transition={{ delay: 0.25 }}
      >
        <Card className="border-slate-700">
          <CardHeader className="border-b border-slate-700">
            <CardTitle className="flex items-center gap-2">
              <AlertTriangle className="w-5 h-5 text-orange-400" />
              Top Email Threats
            </CardTitle>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <Table>
                <TableHeader className="bg-slate-800/50 border-b border-slate-700">
                  <TableRow>
                    <TableHead className="text-slate-300">Timestamp</TableHead>
                    <TableHead className="text-slate-300">From Address</TableHead>
                    <TableHead className="text-slate-300">Subject</TableHead>
                    <TableHead className="text-slate-300">Threat Type</TableHead>
                    <TableHead className="text-slate-300">Action</TableHead>
                    <TableHead className="text-slate-300 text-right">Similarity</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {(liveData?.threats ?? MOCK_THREATS).map((threat: any, idx: number) => {
                    const threatType = (threat.threat_type ?? "Phishing") as ThreatType;
                    const actionTaken = (threat.action_taken ?? threat.status ?? "Blocked") as ActionTaken;
                    const simScore = threat.similarity_score != null ? `${Math.round(threat.similarity_score * 100)}%` : (threat.similarity ?? "—");
                    return (
                    <motion.tr
                      key={threat.id ?? idx}
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      transition={{ delay: 0.25 + idx * 0.04 }}
                      className="border-b border-slate-700/50 hover:bg-slate-800/30 transition-colors"
                    >
                      <TableCell className="text-slate-400 font-mono text-xs whitespace-nowrap">
                        <Clock className="w-3 h-3 inline mr-1.5 text-slate-500" />
                        {threat.timestamp ?? threat.detected_at ?? ""}
                      </TableCell>
                      <TableCell className="text-slate-300 text-sm font-mono">
                        {threat.from_address ?? threat.sender ?? ""}
                      </TableCell>
                      <TableCell className="text-slate-400 text-sm max-w-[200px] truncate">
                        {threat.subject_preview ?? ""}
                      </TableCell>
                      <TableCell>
                        <Badge className={cn("text-xs", THREAT_BADGE[threatType] ?? "bg-slate-500/10 text-slate-400")}>
                          {threatType}
                        </Badge>
                      </TableCell>
                      <TableCell>
                        <Badge className={cn("text-xs", ACTION_BADGE[actionTaken] ?? "bg-blue-500/10 text-blue-400")}>
                          {actionTaken}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-right">
                        <span className={cn(
                          "font-bold tabular-nums text-sm",
                          parseInt(simScore) >= 90 ? "text-red-400" :
                          parseInt(simScore) >= 75 ? "text-orange-400" : "text-slate-400"
                        )}>
                          {simScore}
                        </span>
                      </TableCell>
                    </motion.tr>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>
      </motion.div>

      {/* Lookalike Domain Detection + Recommendations */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Lookalike Domains */}
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.3 }}
          className="lg:col-span-2"
        >
          <Card className="border-slate-700 h-full">
            <CardHeader className="border-b border-slate-700">
              <CardTitle className="flex items-center gap-2">
                <Eye className="w-5 h-5 text-purple-400" />
                Lookalike Domain Detection
              </CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              <Table>
                <TableHeader className="bg-slate-800/50 border-b border-slate-700">
                  <TableRow>
                    <TableHead className="text-slate-300">Suspicious Domain</TableHead>
                    <TableHead className="text-slate-300">Impersonating</TableHead>
                    <TableHead className="text-slate-300">Registrar</TableHead>
                    <TableHead className="text-slate-300">Registered</TableHead>
                    <TableHead className="text-slate-300">Country</TableHead>
                    <TableHead className="text-slate-300 text-right">Risk</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {MOCK_LOOKALIKES.length === 0 ? (
                    <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                      <p className="text-lg font-medium">No data available</p>
                      <p className="text-sm">Data will appear here once available</p>
                    </div>
                  ) : (
                    MOCK_LOOKALIKES.map((d, idx) => (
                    <motion.tr
                      key={d.id}
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      transition={{ delay: 0.3 + idx * 0.05 }}
                      className="border-b border-slate-700/50 hover:bg-slate-800/30 transition-colors"
                    >
                      <TableCell className="text-red-400 font-mono text-sm font-semibold">
                        {d.suspicious}
                      </TableCell>
                      <TableCell className="text-slate-400 font-mono text-sm">
                        {d.legitimate}
                      </TableCell>
                      <TableCell className="text-slate-400 text-sm">{d.registrar}</TableCell>
                      <TableCell className="text-slate-400 text-sm whitespace-nowrap">
                        {d.registration_date}
                      </TableCell>
                      <TableCell>
                        <Badge variant="secondary" className="text-xs font-mono">
                          {d.hosting_country}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-right">
                        <RiskScoreBadge score={d.risk_score} />
                      </TableCell>
                    </motion.tr>
                  ))}
                  )}
                </TableBody>
              </Table>
            </CardContent>
          </Card>
        </motion.div>

        {/* Best Practice Recommendations */}
        <motion.div
          initial={{ opacity: 0, y: 8 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ delay: 0.35 }}
        >
          <Card className="border-slate-700 h-full">
            <CardHeader className="border-b border-slate-700">
              <CardTitle className="flex items-center gap-2 text-base">
                <Zap className="w-5 h-5 text-yellow-400" />
                Recommendations
              </CardTitle>
            </CardHeader>
            <CardContent className="p-4 space-y-3">
              {RECOMMENDATIONS.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                  <p className="text-lg font-medium">No data available</p>
                  <p className="text-sm">Data will appear here once available</p>
                </div>
              ) : (
                RECOMMENDATIONS.map((rec, idx) => {
                const Icon = rec.icon;
                return (
                  <motion.div
                    key={rec.id}
                    initial={{ opacity: 0, x: -4 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: 0.35 + idx * 0.06 }}
                    className={cn(
                      "p-3 rounded-lg border-l-4 space-y-1.5",
                      IMPACT_COLORS[rec.impact]
                    )}
                  >
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2">
                        <Icon className="w-4 h-4 text-slate-400 shrink-0" />
                        <span className="text-sm font-semibold text-slate-200">{rec.title}</span>
                      </div>
                      <Badge className={cn("text-xs shrink-0", IMPACT_TEXT[rec.impact])}>
                        {rec.impact}
                      </Badge>
                    </div>
                    <p className="text-xs text-slate-400 leading-relaxed">{rec.description}</p>
                  </motion.div>
                );
              })}
              )}
            </CardContent>
          </Card>
        </motion.div>
      </div>
    </div>
  );
}
