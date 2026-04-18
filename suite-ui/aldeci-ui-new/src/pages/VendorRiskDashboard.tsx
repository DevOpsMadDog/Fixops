/**
 * Vendor Risk Assessment Dashboard — Third-Party Risk Management
 *
 * Single-page dashboard showing vendor risk assessment data:
 *   1. Summary stats — total vendors, critical/high risk counts, pending assessments
 *   2. Vendor Risk Register — table with vendor name, tier, risk score, last assessed, status, action button
 *   3. Risk by Domain — breakdown of 5 security domains with progress bars
 *   4. High Risk Vendors Alert — banner showing critical vendors if any exist
 *   5. Recent Assessments — activity feed of latest vendor assessments
 *
 * API: GET /api/v1/vendor-risk/risk-register and /api/v1/vendor-risk/vendors
 * Fallback: mock data when API is unavailable
 */

import { useState, useEffect } from "react";
import { motion, AnimatePresence } from "framer-motion";
import {
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Clock,
  TrendingUp,
  TrendingDown,
  Shield,
  Lock,
  Zap,
  RefreshCw,
  ExternalLink,
  AlertCircle,
  ChevronRight,
  Building2,
  Calendar,
  Activity,
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
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { cn } from "@/lib/utils";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";

// ═══════════════════════════════════════════════════════════
// Types
// ═══════════════════════════════════════════════════════════

type VendorTier = "Tier 1" | "Tier 2" | "Tier 3";
type RiskLevel = "critical" | "high" | "medium" | "low";
type VendorStatus = "active" | "inactive" | "pending";

interface Vendor {
  id: string;
  name: string;
  tier: VendorTier;
  overall_score: number;
  risk_level: RiskLevel;
  last_assessed: string;
  status: VendorStatus;
  data_access: string;
  incident_history: number;
}

interface RiskDomain {
  name: string;
  score: number;
}

interface Assessment {
  id: string;
  vendor_name: string;
  timestamp: string;
  score: number;
  assessor: string;
}

// ═══════════════════════════════════════════════════════════
// Mock data
// ═══════════════════════════════════════════════════════════

const MOCK_VENDORS: Vendor[] = [
  {
    id: "v1",
    name: "AWS",
    tier: "Tier 1",
    overall_score: 94,
    risk_level: "low",
    last_assessed: "2026-04-10",
    status: "active",
    data_access: "Full Cloud Infrastructure",
    incident_history: 0,
  },
  {
    id: "v2",
    name: "Salesforce",
    tier: "Tier 1",
    overall_score: 87,
    risk_level: "low",
    last_assessed: "2026-04-05",
    status: "active",
    data_access: "Customer Data CRM",
    incident_history: 1,
  },
  {
    id: "v3",
    name: "Okta",
    tier: "Tier 1",
    overall_score: 92,
    risk_level: "low",
    last_assessed: "2026-04-08",
    status: "active",
    data_access: "Identity & Access",
    incident_history: 0,
  },
  {
    id: "v4",
    name: "Slack",
    tier: "Tier 2",
    overall_score: 78,
    risk_level: "medium",
    last_assessed: "2026-03-28",
    status: "active",
    data_access: "Internal Communications",
    incident_history: 0,
  },
  {
    id: "v5",
    name: "Jira",
    tier: "Tier 2",
    overall_score: 81,
    risk_level: "medium",
    last_assessed: "2026-04-02",
    status: "active",
    data_access: "Project & Issue Tracking",
    incident_history: 0,
  },
  {
    id: "v6",
    name: "GitHub",
    tier: "Tier 1",
    overall_score: 65,
    risk_level: "high",
    last_assessed: "2026-03-15",
    status: "active",
    data_access: "Source Code Repository",
    incident_history: 2,
  },
  {
    id: "v7",
    name: "Zoom",
    tier: "Tier 2",
    overall_score: 72,
    risk_level: "high",
    last_assessed: "2026-02-20",
    status: "pending",
    data_access: "Video Conference",
    incident_history: 1,
  },
  {
    id: "v8",
    name: "HubSpot",
    tier: "Tier 3",
    overall_score: 55,
    risk_level: "critical",
    last_assessed: "2026-01-10",
    status: "pending",
    data_access: "Marketing Automation",
    incident_history: 3,
  },
];

const MOCK_RISK_DOMAINS: RiskDomain[] = [
  { name: "Data Security", score: 82 },
  { name: "Access Control", score: 76 },
  { name: "Incident Response", score: 71 },
  { name: "Compliance", score: 88 },
  { name: "Business Continuity", score: 69 },
];

const MOCK_ASSESSMENTS: Assessment[] = [
  {
    id: "a1",
    vendor_name: "AWS",
    timestamp: "2026-04-10T14:32:00Z",
    score: 94,
    assessor: "Security Team",
  },
  {
    id: "a2",
    vendor_name: "Okta",
    timestamp: "2026-04-08T10:15:00Z",
    score: 92,
    assessor: "IAM Analyst",
  },
  {
    id: "a3",
    vendor_name: "Salesforce",
    timestamp: "2026-04-05T09:45:00Z",
    score: 87,
    assessor: "Third-Party Team",
  },
  {
    id: "a4",
    vendor_name: "Jira",
    timestamp: "2026-04-02T16:20:00Z",
    score: 81,
    assessor: "Security Team",
  },
  {
    id: "a5",
    vendor_name: "Slack",
    timestamp: "2026-03-28T11:05:00Z",
    score: 78,
    assessor: "Infrastructure Team",
  },
];

// ═══════════════════════════════════════════════════════════
// Helpers
// ═══════════════════════════════════════════════════════════

function riskColor(level: RiskLevel): string {
  const map: Record<RiskLevel, string> = {
    critical: "text-red-400 bg-red-500/10",
    high: "text-orange-400 bg-orange-500/10",
    medium: "text-amber-400 bg-amber-500/10",
    low: "text-emerald-400 bg-emerald-500/10",
  };
  return map[level];
}

function riskBadgeClass(level: RiskLevel): string {
  const map: Record<RiskLevel, string> = {
    critical: "bg-red-500/15 text-red-400 border-red-500/30",
    high: "bg-orange-500/15 text-orange-400 border-orange-500/30",
    medium: "bg-amber-500/15 text-amber-400 border-amber-500/30",
    low: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
  };
  return map[level];
}

function tierBadgeClass(tier: VendorTier): string {
  const map: Record<VendorTier, string> = {
    "Tier 1": "bg-blue-500/15 text-blue-400 border-blue-500/30",
    "Tier 2": "bg-purple-500/15 text-purple-400 border-purple-500/30",
    "Tier 3": "bg-slate-500/15 text-slate-400 border-slate-500/30",
  };
  return map[tier];
}

function scoreColor(score: number): string {
  if (score >= 85) return "text-emerald-400";
  if (score >= 70) return "text-amber-400";
  if (score >= 50) return "text-orange-400";
  return "text-red-400";
}

function formatDate(dateStr: string): string {
  const d = new Date(dateStr);
  const now = new Date();
  const diffMs = now.getTime() - d.getTime();
  const diffDays = Math.floor(diffMs / (1000 * 60 * 60 * 24));

  if (diffDays === 0) return "Today";
  if (diffDays === 1) return "Yesterday";
  if (diffDays < 7) return `${diffDays} days ago`;
  if (diffDays < 30) return `${Math.floor(diffDays / 7)} weeks ago`;
  return `${Math.floor(diffDays / 30)} months ago`;
}

function formatAssessmentTime(isoStr: string): string {
  const d = new Date(isoStr);
  const now = new Date();
  const diffMs = now.getTime() - d.getTime();
  const diffHours = Math.floor(diffMs / (1000 * 60 * 60));

  if (diffHours < 1) return "Just now";
  if (diffHours < 24) return `${diffHours}h ago`;
  const diffDays = Math.floor(diffHours / 24);
  if (diffDays < 7) return `${diffDays}d ago`;
  return `${Math.floor(diffDays / 7)}w ago`;
}

// ═══════════════════════════════════════════════════════════
// API fetch helpers
// ═══════════════════════════════════════════════════════════

const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "dev-key";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "X-API-Key": API_KEY },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// ═══════════════════════════════════════════════════════════
// Main Component
// ═══════════════════════════════════════════════════════════

export default function VendorRiskDashboard() {
  const [liveData, setLiveData] = useState<any>(null);
  const [dataLoading, setDataLoading] = useState(false);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/vendor-risk/vendors?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/vendor-risk/risk-register?org_id=${ORG_ID}`),
    ]).then(([vendorsResult, registerResult]) => {
      const vendorsRaw  = vendorsResult.status  === "fulfilled" ? vendorsResult.value  : null;
      const registerRaw = registerResult.status === "fulfilled" ? registerResult.value : null;
      if (vendorsRaw || registerRaw) {
        const vendors = vendorsRaw
          ? (Array.isArray(vendorsRaw) ? vendorsRaw : vendorsRaw.vendors ?? vendorsRaw.items ?? null)
          : null;
        const register = registerRaw
          ? (Array.isArray(registerRaw) ? registerRaw : registerRaw.risk_register ?? registerRaw.vendors ?? registerRaw.items ?? null)
          : null;
        setLiveData({ vendors: vendors ?? register, register });
      }
    })
      .finally(() => setLoading(false)).finally(() => setDataLoading(false));
  }, []);

  const vendors = liveData?.vendors ?? MOCK_VENDORS;

  // Calculate stats
  const totalVendors = vendors.length;
  const criticalCount = vendors.filter(
    (v) => v.risk_level === "critical"
  ).length;
  const highCount = vendors.filter((v) => v.risk_level === "high").length;
  const pendingCount = vendors.filter(
    (v) => v.status === "pending"
  ).length;

  const hasHighRiskVendors = criticalCount > 0 || highCount > 0;
  const highRiskVendors = vendors.filter(
    (v) => v.risk_level === "critical" || v.risk_level === "high"
  );

  if (loading) return (
    <div className="space-y-4 p-6">
      {[1, 2, 3].map((i) => (
        <div key={i} className="h-24 rounded-lg bg-zinc-800/50 animate-pulse" />
      ))}
    </div>
  );

  return (
    <>
      <PageHeader
        title="Vendor Risk Assessment"
        subtitle="Third-party security posture tracking and assessment"
        icon={Building2}
      />

      <div className="space-y-6 p-6">
        {/* High Risk Alert Banner */}
        <AnimatePresence>
          {hasHighRiskVendors && (
            <motion.div
              initial={{ opacity: 0, y: -10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={{ opacity: 0, y: -10 }}
              className="rounded-lg border border-red-500/30 bg-red-500/10 p-4"
            >
              <div className="flex items-start gap-3">
                <AlertTriangle className="mt-1 h-5 w-5 text-red-400 flex-shrink-0" />
                <div className="flex-1">
                  <h3 className="text-sm font-semibold text-red-300">
                    High-Risk Vendors Detected
                  </h3>
                  <p className="mt-1 text-sm text-red-200">
                    {highRiskVendors.length} vendor
                    {highRiskVendors.length !== 1 ? "s" : ""} with critical or
                    high risk levels require immediate attention.
                  </p>
                  <div className="mt-2 flex flex-wrap gap-2">
                    {highRiskVendors.length === 0 ? (
                      <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                        <p className="text-lg font-medium">No data available</p>
                        <p className="text-sm">Data will appear here once available</p>
                      </div>
                    ) : (
                      highRiskVendors.map((v) => (
                      <Badge
                        key={v.id}
                        variant="outline"
                        className={riskBadgeClass(v.risk_level)}
                      >
                        {v.name} ({v.overall_score})
                      </Badge>
                    ))}
                    )}
                  </div>
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Summary Stats */}
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <KpiCard
            label="Total Vendors"
            value={totalVendors}
            icon={Building2}
            trend={null}
          />
          <KpiCard
            label="Critical Risk"
            value={criticalCount}
            icon={AlertTriangle}
            trendColor={criticalCount > 0 ? "red" : "green"}
          />
          <KpiCard
            label="High Risk"
            value={highCount}
            icon={AlertCircle}
            trendColor={highCount > 0 ? "orange" : "green"}
          />
          <KpiCard
            label="Assessments Pending"
            value={pendingCount}
            icon={Clock}
            trendColor={pendingCount > 0 ? "yellow" : "green"}
          />
        </div>

        {/* Main Content Grid */}
        <div className="grid gap-6 lg:grid-cols-3">
          {/* Vendor Risk Register */}
          <div className="lg:col-span-2">
            <Card className="border-slate-700 bg-slate-800/50">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Shield className="h-5 w-5 text-blue-400" />
                  Vendor Risk Register
                </CardTitle>
              </CardHeader>
              <CardContent>
                <ScrollArea className="h-[500px]">
                  <Table>
                    <TableHeader>
                      <TableRow className="border-slate-700 hover:bg-transparent">
                        <TableHead className="text-slate-300">Vendor</TableHead>
                        <TableHead className="text-slate-300">Tier</TableHead>
                        <TableHead className="text-right text-slate-300">
                          Score
                        </TableHead>
                        <TableHead className="text-slate-300">
                          Risk Level
                        </TableHead>
                        <TableHead className="text-slate-300">
                          Last Assessed
                        </TableHead>
                        <TableHead className="text-right text-slate-300">
                          Action
                        </TableHead>
                      </TableRow>
                    </TableHeader>
                    <TableBody>
                      {vendors.length === 0 ? (
                        <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                          <p className="text-lg font-medium">No data available</p>
                          <p className="text-sm">Data will appear here once available</p>
                        </div>
                      ) : (
                        vendors.map((vendor) => (
                        <TableRow
                          key={vendor.id}
                          className="border-slate-700 hover:bg-slate-700/30"
                        >
                          <TableCell className="font-medium text-slate-100">
                            {vendor.name}
                          </TableCell>
                          <TableCell>
                            <Badge
                              variant="outline"
                              className={tierBadgeClass(vendor.tier)}
                            >
                              {vendor.tier}
                            </Badge>
                          </TableCell>
                          <TableCell className="text-right">
                            <span className={scoreColor(vendor.overall_score)}>
                              {vendor.overall_score}
                            </span>
                          </TableCell>
                          <TableCell>
                            <Badge
                              variant="outline"
                              className={riskBadgeClass(vendor.risk_level)}
                            >
                              {vendor.risk_level.charAt(0).toUpperCase() +
                                vendor.risk_level.slice(1)}
                            </Badge>
                          </TableCell>
                          <TableCell className="text-slate-300">
                            {formatDate(vendor.last_assessed)}
                          </TableCell>
                          <TableCell className="text-right">
                            <Button
                              size="sm"
                              variant="ghost"
                              className="text-blue-400 hover:text-blue-300 hover:bg-blue-500/10"
                            >
                              Assess
                              <ChevronRight className="ml-1 h-4 w-4" />
                            </Button>
                          </TableCell>
                        </TableRow>
                      ))}
                      )}
                    </TableBody>
                  </Table>
                </ScrollArea>
              </CardContent>
            </Card>
          </div>

          {/* Risk by Domain */}
          <div>
            <Card className="border-slate-700 bg-slate-800/50">
              <CardHeader>
                <CardTitle className="flex items-center gap-2 text-base">
                  <Zap className="h-5 w-5 text-amber-400" />
                  Risk by Domain
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                {MOCK_RISK_DOMAINS.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  MOCK_RISK_DOMAINS.map((domain, idx) => (
                  <div key={idx}>
                    <div className="flex items-center justify-between mb-2">
                      <span className="text-sm font-medium text-slate-200">
                        {domain.name}
                      </span>
                      <span
                        className={cn(
                          "text-sm font-semibold",
                          domain.score >= 80
                            ? "text-emerald-400"
                            : domain.score >= 70
                              ? "text-amber-400"
                              : "text-orange-400"
                        )}
                      >
                        {domain.score}%
                      </span>
                    </div>
                    <Progress
                      value={domain.score}
                      className="h-2"
                      color={
                        domain.score >= 80
                          ? "emerald"
                          : domain.score >= 70
                            ? "amber"
                            : "orange"
                      }
                    />
                  </div>
                ))}
                )}
              </CardContent>
            </Card>
          </div>
        </div>

        {/* Recent Assessments */}
        <Card className="border-slate-700 bg-slate-800/50">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Activity className="h-5 w-5 text-green-400" />
              Recent Assessments
            </CardTitle>
          </CardHeader>
          <CardContent>
            <ScrollArea className="h-[280px]">
              <div className="space-y-3">
                {MOCK_ASSESSMENTS.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  MOCK_ASSESSMENTS.map((assessment, idx) => (
                  <motion.div
                    key={assessment.id}
                    initial={{ opacity: 0, x: -10 }}
                    animate={{ opacity: 1, x: 0 }}
                    transition={{ delay: idx * 0.05 }}
                    className="flex items-center justify-between rounded-lg border border-slate-700 bg-slate-700/20 p-3 hover:bg-slate-700/40 transition-colors"
                  >
                    <div className="flex-1">
                      <p className="text-sm font-medium text-slate-100">
                        {assessment.vendor_name}
                      </p>
                      <p className="text-xs text-slate-400">
                        Assessed by {assessment.assessor}
                      </p>
                    </div>
                    <div className="text-right">
                      <p
                        className={cn(
                          "text-sm font-semibold",
                          scoreColor(assessment.score)
                        )}
                      >
                        {assessment.score}
                      </p>
                      <p className="text-xs text-slate-400">
                        {formatAssessmentTime(assessment.timestamp)}
                      </p>
                    </div>
                  </motion.div>
                ))}
                )}
              </div>
            </ScrollArea>
          </CardContent>
        </Card>
      </div>
    </>
  );
}
