/**
 * Identity Governance (IGA) Dashboard
 *
 * Single-page dashboard for access certification, orphan detection, and privilege management:
 *   1. KPI row — pending certifications, orphaned accounts, SoD violations, campaign progress
 *   2. Active Certification Campaigns — table with progress bars and status
 *   3. Access Review Queue — certify/revoke/escalate per user+role pair
 *   4. Orphaned Accounts — red alert panel with disable CTA
 *   5. SoD Violations — conflict cards with recommended actions
 *   6. Joiner/Mover/Leaver status — 3-column provisioning state grid
 *
 * API stubs: GET /api/v1/iga/reviews, /api/v1/iga/orphaned-accounts, /api/v1/iga/sod-violations
 * Fallback: mock data when API is unavailable
 */

import { useState, useEffect } from "react";
import { useQuery } from "@tanstack/react-query";
import { motion, AnimatePresence } from "framer-motion";
import {
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Clock,
  Shield,
  Users,
  UserX,
  UserCheck,
  UserMinus,
  UserPlus,
  AlertCircle,
  ChevronRight,
  Calendar,
  Activity,
  Lock,
  RefreshCw,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { ScrollArea } from "@/components/ui/scroll-area";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

const API_BASE = import.meta.env.VITE_API_URL || "";
const _API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "dev-key";
const ORG_ID = "default";

// ═══════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════

type RiskLevel = "HIGH" | "MEDIUM" | "LOW";
type CampaignStatus = "active" | "overdue" | "completed" | "pending";
type ReviewDecision = "certify" | "revoke" | "escalate" | null;

interface Campaign {
  id: string;
  campaign_name: string;
  scope: string;
  reviewer: string;
  deadline: string;
  certified_count: number;
  total_count: number;
  status: CampaignStatus;
}

interface AccessReviewItem {
  id: string;
  user: string;
  role: string;
  system: string;
  last_used: string;
  risk_level: RiskLevel;
}

interface OrphanedAccount {
  id: string;
  username: string;
  system: string;
  last_login: string;
}

interface SoDViolation {
  id: string;
  user: string;
  conflicting_role_1: string;
  conflicting_role_2: string;
  violation_type: string;
  recommended_action: string;
}

// ═══════════════════════════════════════════════════════════
// Mock data
// ═══════════════════════════════════════════════════════════

const MOCK_CAMPAIGNS: Campaign[] = [
  {
    id: "c1",
    campaign_name: "Q2 2026 Privileged Access Review",
    scope: "All admin & privileged roles",
    reviewer: "Jane Smith (IAM Lead)",
    deadline: "2026-04-30",
    certified_count: 29,
    total_count: 47,
    status: "active",
  },
  {
    id: "c2",
    campaign_name: "Production DB Access Certification",
    scope: "Database admin roles — prod env",
    reviewer: "Bob Chen (DBA Lead)",
    deadline: "2026-04-22",
    certified_count: 6,
    total_count: 12,
    status: "overdue",
  },
  {
    id: "c3",
    campaign_name: "Cloud IAM Quarterly Review",
    scope: "AWS/GCP/Azure IAM roles",
    reviewer: "Alice Torres (Cloud Sec)",
    deadline: "2026-05-15",
    certified_count: 0,
    total_count: 88,
    status: "pending",
  },
];

const MOCK_REVIEW_QUEUE: AccessReviewItem[] = [
  {
    id: "r1",
    user: "david.morgan",
    role: "db_admin (prod)",
    system: "PostgreSQL Prod",
    last_used: "2026-04-14",
    risk_level: "HIGH",
  },
  {
    id: "r2",
    user: "sarah.kim",
    role: "s3:FullAccess",
    system: "AWS S3",
    last_used: "2026-03-01",
    risk_level: "HIGH",
  },
  {
    id: "r3",
    user: "raj.patel",
    role: "root (EC2)",
    system: "AWS EC2",
    last_used: "2026-02-10",
    risk_level: "HIGH",
  },
  {
    id: "r4",
    user: "emily.watson",
    role: "finance_reader",
    system: "ERP System",
    last_used: "2026-04-10",
    risk_level: "MEDIUM",
  },
  {
    id: "r5",
    user: "carlos.rivera",
    role: "k8s_cluster_admin",
    system: "Kubernetes Prod",
    last_used: "2026-04-15",
    risk_level: "HIGH",
  },
  {
    id: "r6",
    user: "lisa.chen",
    role: "ci_deployer",
    system: "GitHub Actions",
    last_used: "2026-04-12",
    risk_level: "MEDIUM",
  },
  {
    id: "r7",
    user: "tom.nguyen",
    role: "read_only",
    system: "Splunk SIEM",
    last_used: "2026-04-08",
    risk_level: "LOW",
  },
  {
    id: "r8",
    user: "anna.bell",
    role: "secrets_manager_admin",
    system: "HashiCorp Vault",
    last_used: "2026-01-20",
    risk_level: "HIGH",
  },
];

const MOCK_ORPHANED: OrphanedAccount[] = [
  {
    id: "o1",
    username: "jsmith_old",
    system: "Active Directory",
    last_login: "2025-11-03",
  },
  {
    id: "o2",
    username: "contractor_bob",
    system: "VPN Gateway",
    last_login: "2025-09-17",
  },
  {
    id: "o3",
    username: "svc_legacyapp",
    system: "Legacy ERP",
    last_login: "2025-07-22",
  },
  {
    id: "o4",
    username: "intern_2025",
    system: "GitHub Org",
    last_login: "2025-08-31",
  },
  {
    id: "o5",
    username: "dev_sandbox_user",
    system: "AWS Dev Account",
    last_login: "2025-12-01",
  },
  {
    id: "o6",
    username: "old_siem_svc",
    system: "Splunk",
    last_login: "2026-01-05",
  },
  {
    id: "o7",
    username: "vendor_acme",
    system: "Confluence",
    last_login: "2025-10-14",
  },
  {
    id: "o8",
    username: "test_admin01",
    system: "Kubernetes Staging",
    last_login: "2025-06-30",
  },
];

const MOCK_SOD_VIOLATIONS: SoDViolation[] = [
  {
    id: "s1",
    user: "marcus.tate",
    conflicting_role_1: "payment_initiator",
    conflicting_role_2: "payment_approver",
    violation_type: "Financial Controls Conflict",
    recommended_action: "Remove payment_approver role immediately",
  },
  {
    id: "s2",
    user: "nina.ford",
    conflicting_role_1: "audit_log_reader",
    conflicting_role_2: "audit_log_deleter",
    violation_type: "Audit Integrity Conflict",
    recommended_action: "Revoke audit_log_deleter — assign to auditor only",
  },
  {
    id: "s3",
    user: "oscar.lane",
    conflicting_role_1: "code_committer",
    conflicting_role_2: "prod_deployer",
    violation_type: "Change Management Conflict",
    recommended_action: "Separate duties: assign prod_deployer to ops team",
  },
];

// ═══════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════

function riskBadgeClass(level: RiskLevel): string {
  const map: Record<RiskLevel, string> = {
    HIGH: "bg-red-500/15 text-red-400 border-red-500/30",
    MEDIUM: "bg-amber-500/15 text-amber-400 border-amber-500/30",
    LOW: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
  };
  return map[level];
}

function campaignStatusClass(status: CampaignStatus): string {
  const map: Record<CampaignStatus, string> = {
    active: "bg-blue-500/15 text-blue-400 border-blue-500/30",
    overdue: "bg-red-500/15 text-red-400 border-red-500/30",
    completed: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
    pending: "bg-slate-500/15 text-slate-400 border-slate-500/30",
  };
  return map[status];
}

function progressColor(pct: number): string {
  if (pct >= 80) return "text-emerald-400";
  if (pct >= 50) return "text-amber-400";
  return "text-orange-400";
}

function formatDateAgo(dateStr: string): string {
  const d = new Date(dateStr);
  const now = new Date();
  const diffDays = Math.floor(
    (now.getTime() - d.getTime()) / (1000 * 60 * 60 * 24)
  );
  if (diffDays === 0) return "Today";
  if (diffDays === 1) return "Yesterday";
  if (diffDays < 30) return `${diffDays}d ago`;
  if (diffDays < 365) return `${Math.floor(diffDays / 30)}mo ago`;
  return `${Math.floor(diffDays / 365)}yr ago`;
}

function formatDeadline(dateStr: string): string {
  const d = new Date(dateStr);
  const now = new Date();
  const diffDays = Math.floor(
    (d.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)
  );
  if (diffDays < 0) return `${Math.abs(diffDays)}d overdue`;
  if (diffDays === 0) return "Due today";
  if (diffDays === 1) return "Due tomorrow";
  return `Due in ${diffDays}d`;
}

function deadlineColor(dateStr: string): string {
  const d = new Date(dateStr);
  const now = new Date();
  const diffDays = Math.floor(
    (d.getTime() - now.getTime()) / (1000 * 60 * 60 * 24)
  );
  if (diffDays < 0) return "text-red-400";
  if (diffDays <= 3) return "text-orange-400";
  if (diffDays <= 7) return "text-amber-400";
  return "text-slate-400";
}

function apiKey(): string {
  return localStorage.getItem("aldeci_api_key") ?? "";
}

// ═══════════════════════════════════════════════════════════
// API fetch helpers
// ═══════════════════════════════════════════════════════════

// ── Real API helpers (correct endpoints: /api/v1/identity-governance/) ──────

function _igaHeaders() {
  const key = _API_KEY || apiKey();
  return { "X-API-Key": key };
}

async function fetchReviews(): Promise<Campaign[]> {
  const res = await fetch(
    `${API_BASE}/api/v1/identity-governance/reviews?org_id=${ORG_ID}`,
    { headers: _igaHeaders() },
  );
  if (!res.ok) throw new Error(`${res.status}`);
  const data = await res.json();
  return Array.isArray(data) ? data : data.reviews ?? MOCK_CAMPAIGNS;
}

async function fetchOrphanedAccounts(): Promise<OrphanedAccount[]> {
  const res = await fetch(
    `${API_BASE}/api/v1/identity-governance/entitlements?org_id=${ORG_ID}&is_orphaned=true`,
    { headers: _igaHeaders() },
  );
  if (!res.ok) throw new Error(`${res.status}`);
  const data = await res.json();
  // Engine returns a list of entitlements; map to OrphanedAccount shape
  const items: any[] = Array.isArray(data) ? data : data.entitlements ?? [];
  return items.length > 0
    ? items.map((e: any) => ({
        id: e.id ?? e.identity_id,
        username: e.identity_name ?? e.identity_id ?? "unknown",
        system: e.system ?? "unknown",
        last_login: e.last_used ?? "",
      }))
    : MOCK_ORPHANED;
}

async function fetchIgaStats(): Promise<any> {
  const res = await fetch(
    `${API_BASE}/api/v1/identity-governance/stats?org_id=${ORG_ID}`,
    { headers: _igaHeaders() },
  );
  if (!res.ok) throw new Error(`${res.status}`);
  return res.json();
}

async function fetchSoDViolations(): Promise<SoDViolation[]> {
  // No dedicated SoD endpoint yet in the engine — use mock fallback
  // TODO: wire when /api/v1/identity-governance/sod-violations is deployed
  return MOCK_SOD_VIOLATIONS;
}

// ═══════════════════════════════════════════════════════════
// Main Component
// ═══════════════════════════════════════════════════════════

export default function IdentityGovernance() {
  const [decisions, setDecisions] = useState<Record<string, ReviewDecision>>(
    {}
  );
  const [loading, setLoading] = useState(true);
  const [disabledAccounts, setDisabledAccounts] = useState<Set<string>>(
    new Set()
  );
  const [igaStats, setIgaStats] = useState<any>(null);
  const [identityAnalytics, setIdentityAnalytics] = useState<any>(null);

  // Fetch governance stats + identity-analytics data
  useEffect(() => {
    const key =
      (typeof window !== "undefined" && window.localStorage.getItem("aldeci_api_key")) ||
      _API_KEY ||
      "dev-key";
    const iaFetch = (path: string) =>
      fetch(`/api/v1${path}`, { headers: { "X-API-Key": key } }).then((r) => {
        if (!r.ok) throw new Error(`${r.status}`);
        return r.json();
      });
    Promise.allSettled([
      fetchIgaStats(),
      iaFetch(`/identity-analytics/sessions?org_id=${ORG_ID}&limit=20`),
      iaFetch(`/identity-analytics/stats?org_id=${ORG_ID}`),
    ]).then(([statsRes, sessionsRes, iaStatsRes]) => {
      if (statsRes.status === "fulfilled") setIgaStats(statsRes.value);
      const sessions  = sessionsRes.status  === "fulfilled" ? sessionsRes.value  : null;
      const iaStats   = iaStatsRes.status   === "fulfilled" ? iaStatsRes.value   : null;
      if (sessions || iaStats) setIdentityAnalytics({ sessions, stats: iaStats });
    });
    setLoading(false);
  }, []);

  const reviewsQuery = useQuery({
    queryKey: ["iga-reviews"],
    queryFn: fetchReviews,
    staleTime: 60000,
  });

  const orphanedQuery = useQuery({
    queryKey: ["iga-orphaned-accounts"],
    queryFn: fetchOrphanedAccounts,
    staleTime: 60000,
  });

  const sodQuery = useQuery({
    queryKey: ["iga-sod-violations"],
    queryFn: fetchSoDViolations,
    staleTime: 60000,
  });

  // Use live reviews as campaigns if available, fallback to mock
  const liveCampaigns: Campaign[] = reviewsQuery.data
    ? (reviewsQuery.data as unknown as Campaign[])
    : MOCK_CAMPAIGNS;
  const reviewQueue = MOCK_REVIEW_QUEUE;
  const orphanedAccounts = orphanedQuery.data ?? MOCK_ORPHANED;
  const sodViolations = sodQuery.data ?? MOCK_SOD_VIOLATIONS;

  const totalCertified = liveCampaigns.reduce(
    (sum, c) => sum + (c.certified_count ?? 0),
    0
  );
  const totalItems = liveCampaigns.reduce((sum, c) => sum + (c.total_count ?? 1), 0);
  const certCampaignProgress = totalItems > 0 ? Math.round((totalCertified / totalItems) * 100) : 62;

  function setDecision(id: string, decision: ReviewDecision) {
    setDecisions((prev) => ({ ...prev, [id]: decision }));
  }

  function handleDisable(id: string) {
    setDisabledAccounts((prev) => new Set(prev).add(id));
  }

  return (
    <>
      <PageHeader
        title="Identity Governance"
        description="Access certification, orphan detection, and privilege management"
      />

      <div className="space-y-6 p-6">
        {/* KPI Row */}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <KpiCard
            title="Pending Certifications"
            value={igaStats?.pending_reviews ?? igaStats?.pending_certifications ?? 47}
            icon={Clock}
          />
          <KpiCard
            title="Orphaned Accounts"
            value={igaStats?.orphaned_entitlements ?? orphanedAccounts.filter((a) => !disabledAccounts.has(a.id)).length}
            icon={UserX}
            className="border-orange-500/20"
          />
          <KpiCard
            title="SoD Violations"
            value={igaStats?.sod_violations ?? sodViolations.length}
            icon={AlertTriangle}
            className="border-red-500/20"
          />
          <KpiCard
            title="Cert Campaign Progress"
            value={igaStats?.revocation_rate != null ? `${igaStats.revocation_rate}%` : `${certCampaignProgress}%`}
            icon={Activity}
            className="border-blue-500/20"
          />
        </div>

        {/* Active Certification Campaigns */}
        <Card className="border-slate-700 bg-slate-800/50">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <CheckCircle2 className="h-5 w-5 text-blue-400" />
              Active Certification Campaigns
            </CardTitle>
          </CardHeader>
          <CardContent>
            <Table>
              <TableHeader>
                <TableRow className="border-slate-700 hover:bg-transparent">
                  <TableHead className="text-slate-300">Campaign</TableHead>
                  <TableHead className="text-slate-300">Scope</TableHead>
                  <TableHead className="text-slate-300">Reviewer</TableHead>
                  <TableHead className="text-slate-300">Deadline</TableHead>
                  <TableHead className="text-slate-300">Progress</TableHead>
                  <TableHead className="text-slate-300">Status</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {liveCampaigns.map((campaign) => {
                  const pct =
                    campaign.total_count > 0
                      ? Math.round(
                          (campaign.certified_count / campaign.total_count) *
                            100
                        )
                      : 0;
                  return (
                    <TableRow
                      key={campaign.id}
                      className="border-slate-700 hover:bg-slate-700/30"
                    >
                      <TableCell className="font-medium text-slate-100">
                        {campaign.campaign_name}
                      </TableCell>
                      <TableCell className="text-slate-300 text-sm">
                        {campaign.scope}
                      </TableCell>
                      <TableCell className="text-slate-300 text-sm">
                        {campaign.reviewer}
                      </TableCell>
                      <TableCell>
                        <span
                          className={cn(
                            "text-sm font-medium",
                            deadlineColor(campaign.deadline)
                          )}
                        >
                          {formatDeadline(campaign.deadline)}
                        </span>
                      </TableCell>
                      <TableCell className="min-w-[160px]">
                        <div className="flex items-center gap-2">
                          <Progress value={pct} className="h-2 flex-1" />
                          <span
                            className={cn(
                              "text-xs font-semibold w-10 text-right",
                              progressColor(pct)
                            )}
                          >
                            {pct}%
                          </span>
                          <span className="text-xs text-slate-500 whitespace-nowrap">
                            {campaign.certified_count}/{campaign.total_count}
                          </span>
                        </div>
                      </TableCell>
                      <TableCell>
                        <Badge
                          variant="outline"
                          className={campaignStatusClass(campaign.status)}
                        >
                          {campaign.status.charAt(0).toUpperCase() +
                            campaign.status.slice(1)}
                        </Badge>
                      </TableCell>
                    </TableRow>
                  );
                })}
              </TableBody>
            </Table>
          </CardContent>
        </Card>

        {/* Access Review Queue */}
        <Card className="border-slate-700 bg-slate-800/50">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <UserCheck className="h-5 w-5 text-amber-400" />
              Access Review Queue
              <Badge
                variant="outline"
                className="ml-2 bg-amber-500/15 text-amber-400 border-amber-500/30 text-xs"
              >
                {
                  reviewQueue.filter((r) => decisions[r.id] === undefined).length
                }{" "}
                pending
              </Badge>
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ScrollArea className="h-[420px]">
              <Table>
                <TableHeader>
                  <TableRow className="border-slate-700 hover:bg-transparent">
                    <TableHead className="text-slate-300">User</TableHead>
                    <TableHead className="text-slate-300">Role / Permission</TableHead>
                    <TableHead className="text-slate-300">System</TableHead>
                    <TableHead className="text-slate-300">Last Used</TableHead>
                    <TableHead className="text-slate-300">Risk</TableHead>
                    <TableHead className="text-right text-slate-300">
                      Decision
                    </TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {reviewQueue.map((item) => {
                    const decision = decisions[item.id];
                    return (
                      <TableRow
                        key={item.id}
                        className={cn(
                          "border-slate-700 transition-colors",
                          decision === "certify" && "bg-emerald-500/5",
                          decision === "revoke" && "bg-red-500/5",
                          decision === "escalate" && "bg-amber-500/5",
                          !decision && "hover:bg-slate-700/30"
                        )}
                      >
                        <TableCell className="font-medium text-slate-100 font-mono text-sm">
                          {item.user}
                        </TableCell>
                        <TableCell className="text-slate-200 text-sm">
                          {item.role}
                        </TableCell>
                        <TableCell className="text-slate-300 text-sm">
                          {item.system}
                        </TableCell>
                        <TableCell className="text-slate-400 text-sm">
                          {formatDateAgo(item.last_used)}
                        </TableCell>
                        <TableCell>
                          <Badge
                            variant="outline"
                            className={riskBadgeClass(item.risk_level)}
                          >
                            {item.risk_level}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-right">
                          {decision ? (
                            <div className="flex items-center justify-end gap-2">
                              <Badge
                                variant="outline"
                                className={cn(
                                  decision === "certify" &&
                                    "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
                                  decision === "revoke" &&
                                    "bg-red-500/15 text-red-400 border-red-500/30",
                                  decision === "escalate" &&
                                    "bg-amber-500/15 text-amber-400 border-amber-500/30"
                                )}
                              >
                                {decision.charAt(0).toUpperCase() +
                                  decision.slice(1)}
                                {decision === "certify" && (
                                  <CheckCircle2 className="ml-1 h-3 w-3" />
                                )}
                                {decision === "revoke" && (
                                  <XCircle className="ml-1 h-3 w-3" />
                                )}
                                {decision === "escalate" && (
                                  <AlertCircle className="ml-1 h-3 w-3" />
                                )}
                              </Badge>
                              <Button
                                size="sm"
                                variant="ghost"
                                className="h-6 px-2 text-xs text-slate-400 hover:text-slate-200"
                                onClick={() => setDecision(item.id, null)}
                              >
                                Undo
                              </Button>
                            </div>
                          ) : (
                            <div className="flex items-center justify-end gap-1">
                              <Button
                                size="sm"
                                variant="ghost"
                                className="h-7 px-3 text-xs text-emerald-400 hover:text-emerald-300 hover:bg-emerald-500/10 border border-emerald-500/20"
                                onClick={() => setDecision(item.id, "certify")}
                              >
                                Certify
                              </Button>
                              <Button
                                size="sm"
                                variant="ghost"
                                className="h-7 px-3 text-xs text-red-400 hover:text-red-300 hover:bg-red-500/10 border border-red-500/20"
                                onClick={() => setDecision(item.id, "revoke")}
                              >
                                Revoke
                              </Button>
                              <Button
                                size="sm"
                                variant="ghost"
                                className="h-7 px-3 text-xs text-amber-400 hover:text-amber-300 hover:bg-amber-500/10 border border-amber-500/20"
                                onClick={() =>
                                  setDecision(item.id, "escalate")
                                }
                              >
                                Escalate
                              </Button>
                            </div>
                          )}
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </ScrollArea>
          </CardContent>
        </Card>

        {/* Bottom grid: Orphaned Accounts + SoD Violations */}
        <div className="grid gap-6 lg:grid-cols-2">
          {/* Orphaned Accounts Alert Panel */}
          <Card className="border-red-500/30 bg-red-500/5">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-red-300">
                <UserX className="h-5 w-5 text-red-400" />
                Orphaned Accounts
                <Badge
                  variant="outline"
                  className="ml-1 bg-red-500/15 text-red-400 border-red-500/30 text-xs"
                >
                  {
                    orphanedAccounts.filter(
                      (a) => !disabledAccounts.has(a.id)
                    ).length
                  }{" "}
                  active
                </Badge>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-[340px]">
                <div className="space-y-2">
                  <AnimatePresence>
                    {orphanedAccounts.map((account, idx) => {
                      const isDisabled = disabledAccounts.has(account.id);

                      if (loading) return <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div></div>;

                      return (
                        <motion.div
                          key={account.id}
                          initial={{ opacity: 0, x: -10 }}
                          animate={{
                            opacity: isDisabled ? 0.4 : 1,
                            x: 0,
                          }}
                          transition={{ delay: idx * 0.04 }}
                          className={cn(
                            "flex items-center justify-between rounded-lg border p-3 transition-colors",
                            isDisabled
                              ? "border-slate-700/50 bg-slate-800/30"
                              : "border-red-500/20 bg-red-500/5 hover:bg-red-500/10"
                          )}
                        >
                          <div className="flex-1 min-w-0">
                            <p className="text-sm font-medium text-slate-100 font-mono">
                              {account.username}
                            </p>
                            <p className="text-xs text-slate-400">
                              {account.system} &bull; Last login:{" "}
                              {formatDateAgo(account.last_login)}
                            </p>
                          </div>
                          <Button
                            size="sm"
                            variant="ghost"
                            disabled={isDisabled}
                            onClick={() => handleDisable(account.id)}
                            className={cn(
                              "ml-3 h-7 px-3 text-xs flex-shrink-0",
                              isDisabled
                                ? "text-slate-500 cursor-not-allowed"
                                : "text-red-400 hover:text-red-300 hover:bg-red-500/15 border border-red-500/30"
                            )}
                          >
                            {isDisabled ? (
                              <>
                                <CheckCircle2 className="mr-1 h-3 w-3" />
                                Disabled
                              </>
                            ) : (
                              <>
                                <Lock className="mr-1 h-3 w-3" />
                                Disable Account
                              </>
                            )}
                          </Button>
                        </motion.div>
                      );
                    })}
                  </AnimatePresence>
                </div>
              </ScrollArea>
            </CardContent>
          </Card>

          {/* SoD Violations */}
          <Card className="border-slate-700 bg-slate-800/50">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <AlertTriangle className="h-5 w-5 text-orange-400" />
                Segregation of Duties Violations
                <Badge
                  variant="outline"
                  className="ml-1 bg-orange-500/15 text-orange-400 border-orange-500/30 text-xs"
                >
                  {sodViolations.length} conflicts
                </Badge>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                {sodViolations.map((violation, idx) => (
                  <motion.div
                    key={violation.id}
                    initial={{ opacity: 0, y: 8 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: idx * 0.08 }}
                    className="rounded-lg border border-orange-500/20 bg-orange-500/5 p-4"
                  >
                    <div className="flex items-start justify-between gap-2">
                      <div className="flex-1">
                        <div className="flex items-center gap-2 mb-2">
                          <span className="text-sm font-semibold text-slate-100 font-mono">
                            {violation.user}
                          </span>
                          <Badge
                            variant="outline"
                            className="text-xs bg-orange-500/15 text-orange-400 border-orange-500/30"
                          >
                            {violation.violation_type}
                          </Badge>
                        </div>
                        <div className="flex items-center gap-2 text-xs text-slate-300 mb-1">
                          <span className="rounded bg-slate-700/60 px-2 py-0.5 font-mono">
                            {violation.conflicting_role_1}
                          </span>
                          <span className="text-red-400 font-bold">+</span>
                          <span className="rounded bg-slate-700/60 px-2 py-0.5 font-mono">
                            {violation.conflicting_role_2}
                          </span>
                        </div>
                        <p className="text-xs text-amber-300/80 mt-2">
                          <span className="font-semibold">Recommended: </span>
                          {violation.recommended_action}
                        </p>
                      </div>
                      <Button
                        size="sm"
                        variant="ghost"
                        className="flex-shrink-0 h-7 px-3 text-xs text-orange-400 hover:text-orange-300 hover:bg-orange-500/10 border border-orange-500/20"
                      >
                        Remediate
                        <ChevronRight className="ml-1 h-3 w-3" />
                      </Button>
                    </div>
                  </motion.div>
                ))}
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Joiner / Mover / Leaver Status */}
        <Card className="border-slate-700 bg-slate-800/50">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Users className="h-5 w-5 text-purple-400" />
              Joiner / Mover / Leaver Status
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
              {/* Joiners */}
              <div className="rounded-lg border border-blue-500/20 bg-blue-500/5 p-4">
                <div className="flex items-center gap-3 mb-3">
                  <div className="rounded-full bg-blue-500/20 p-2">
                    <UserPlus className="h-5 w-5 text-blue-400" />
                  </div>
                  <div>
                    <p className="text-xs text-slate-400 uppercase tracking-wide">
                      Joiners
                    </p>
                    <p className="text-2xl font-bold text-blue-400">2</p>
                  </div>
                </div>
                <p className="text-sm text-slate-300">
                  New employees not yet provisioned
                </p>
                <div className="mt-3 space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-400 font-mono">
                      priya.sharma
                    </span>
                    <span className="text-blue-400">Day 1 today</span>
                  </div>
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-400 font-mono">
                      kevin.wright
                    </span>
                    <span className="text-blue-400">Starts Apr 21</span>
                  </div>
                </div>
                <Button
                  size="sm"
                  className="mt-3 w-full text-xs bg-blue-600/30 hover:bg-blue-600/50 text-blue-200 border border-blue-500/30"
                  variant="ghost"
                >
                  Provision Access
                </Button>
              </div>

              {/* Movers */}
              <div className="rounded-lg border border-amber-500/20 bg-amber-500/5 p-4">
                <div className="flex items-center gap-3 mb-3">
                  <div className="rounded-full bg-amber-500/20 p-2">
                    <RefreshCw className="h-5 w-5 text-amber-400" />
                  </div>
                  <div>
                    <p className="text-xs text-slate-400 uppercase tracking-wide">
                      Movers
                    </p>
                    <p className="text-2xl font-bold text-amber-400">5</p>
                  </div>
                </div>
                <p className="text-sm text-slate-300">
                  Employees who changed roles with old access still active
                </p>
                <div className="mt-3 space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-400 font-mono">
                      jennifer.lee
                    </span>
                    <span className="text-amber-400">3 stale roles</span>
                  </div>
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-400 font-mono">
                      dan.brooks
                    </span>
                    <span className="text-amber-400">1 stale role</span>
                  </div>
                  <div className="text-xs text-slate-500">+ 3 more</div>
                </div>
                <Button
                  size="sm"
                  className="mt-3 w-full text-xs bg-amber-600/20 hover:bg-amber-600/40 text-amber-200 border border-amber-500/30"
                  variant="ghost"
                >
                  Review Stale Access
                </Button>
              </div>

              {/* Leavers */}
              <div className="rounded-lg border border-red-500/20 bg-red-500/5 p-4">
                <div className="flex items-center gap-3 mb-3">
                  <div className="rounded-full bg-red-500/20 p-2">
                    <UserMinus className="h-5 w-5 text-red-400" />
                  </div>
                  <div>
                    <p className="text-xs text-slate-400 uppercase tracking-wide">
                      Leavers
                    </p>
                    <p className="text-2xl font-bold text-red-400">1</p>
                  </div>
                </div>
                <p className="text-sm text-slate-300">
                  Departed employees with active accounts
                </p>
                <div className="mt-3 space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-slate-400 font-mono">
                      alex.turner
                    </span>
                    <span className="text-red-400">Left Apr 10 — URGENT</span>
                  </div>
                </div>
                <Button
                  size="sm"
                  className="mt-3 w-full text-xs bg-red-600/20 hover:bg-red-600/40 text-red-200 border border-red-500/30"
                  variant="ghost"
                >
                  Offboard Now
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </>
  );
}
