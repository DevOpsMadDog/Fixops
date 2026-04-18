/**
 * Risk Acceptance Workflow — Formal risk acceptance management page
 *
 * Design:
 * - Header: "Risk Acceptance Workflow" with subtitle
 * - Top stats: Pending Approvals, Accepted Risks, Expired Acceptances, Due This Week
 * - "Pending Approvals" table with actions (Approve/Reject)
 * - "Active Risk Acceptances" table with colored days_remaining
 * - "Approval Request" button → modal form
 * - "Expired Risks" collapsed section
 * - Filter tabs: All / Pending / Active / Expired
 *
 * API: GET /api/v1/risk-acceptance/list, /api/v1/risk-acceptance/pending
 * Falls back to mock data on failure.
 */

import { useState, useCallback } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";
import { motion, AnimatePresence } from "framer-motion";
import {
  AlertTriangle,
  CheckCircle2,
  Clock,
  FileText,
  Filter,
  Plus,
  Shield,
  ThumbsDown,
  ThumbsUp,
  XCircle,
  Calendar,
  User,
  ChevronDown,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Separator } from "@/components/ui/separator";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";

// ══════════════════════════════════════════════════════════════
// Types
// ══════════════════════════════════════════════════════════════

type RiskLevel = "critical" | "high" | "medium" | "low";
type FilterTab = "all" | "pending" | "active" | "expired";

interface RiskAcceptance {
  id: string;
  finding: string;
  risk_level: RiskLevel;
  approved_by: string;
  expiry_date: string;
  days_remaining: number;
  status: "pending" | "approved" | "rejected" | "expired";
}

interface PendingApproval {
  id: string;
  finding: string;
  severity: RiskLevel;
  business_justification: string;
  requested_by: string;
  expiry_date: string;
  compensating_controls: string;
}

interface RiskAcceptanceData {
  pending_count: number;
  accepted_count: number;
  expired_count: number;
  due_this_week: number;
  pending_approvals: PendingApproval[];
  active_acceptances: RiskAcceptance[];
  expired_acceptances: RiskAcceptance[];
}

// ══════════════════════════════════════════════════════════════
// Mock Data
// ══════════════════════════════════════════════════════════════

const MOCK_DATA: RiskAcceptanceData = {
  pending_count: 4,
  accepted_count: 12,
  expired_count: 2,
  due_this_week: 3,
  pending_approvals: [
    {
      id: "PA-001",
      finding: "FIND-847: RCE in log4j library v2.14",
      severity: "critical",
      business_justification: "Legacy app requires lib for production support. Patch window scheduled for Q2.",
      requested_by: "alice@acme.com",
      expiry_date: "2026-05-14",
      compensating_controls: "Network segmentation, WAF rules, 24/7 monitoring",
    },
    {
      id: "PA-002",
      finding: "FIND-901: SQL injection in /api/users endpoint",
      severity: "high",
      business_justification: "Fixing in current sprint (Sprint 15). Temporary input validation applied.",
      requested_by: "bob@acme.com",
      expiry_date: "2026-04-28",
      compensating_controls: "Rate limiting, parameter validation, query timeouts",
    },
    {
      id: "PA-003",
      finding: "FIND-512: Unauth RCE in Redis cluster",
      severity: "critical",
      business_justification: "Migrating to VPC-only Redis. Network isolation blocks external access.",
      requested_by: "carol@acme.com",
      expiry_date: "2026-06-14",
      compensating_controls: "VPC security groups, NACLs, private subnet only",
    },
    {
      id: "PA-004",
      finding: "FIND-630: Path traversal in file upload",
      severity: "high",
      business_justification: "Accepting risk for internal tool. External users blocked by auth layer.",
      requested_by: "dave@acme.com",
      expiry_date: "2026-05-14",
      compensating_controls: "Access control enforcement, audit logging, file type validation",
    },
  ],
  active_acceptances: [
    {
      id: "RA-001",
      finding: "FIND-233: Outdated TLS 1.0 on legacy DB",
      risk_level: "low",
      approved_by: "security-team@acme.com",
      expiry_date: "2026-07-14",
      days_remaining: 91,
      status: "approved",
    },
    {
      id: "RA-002",
      finding: "FIND-155: Insecure cookie flags on auth service",
      risk_level: "medium",
      approved_by: "ciso@acme.com",
      expiry_date: "2026-05-14",
      days_remaining: 30,
      status: "approved",
    },
    {
      id: "RA-003",
      finding: "FIND-392: Open redirect in OAuth2 flow",
      risk_level: "high",
      approved_by: "security-team@acme.com",
      expiry_date: "2026-04-20",
      days_remaining: 6,
      status: "approved",
    },
    {
      id: "RA-004",
      finding: "FIND-058: Hardcoded test credentials in CI/CD",
      risk_level: "critical",
      approved_by: "ciso@acme.com",
      expiry_date: "2026-04-21",
      days_remaining: 7,
      status: "approved",
    },
    {
      id: "RA-005",
      finding: "FIND-711: Broken access control on /admin endpoint",
      risk_level: "medium",
      approved_by: "security-team@acme.com",
      expiry_date: "2026-06-30",
      days_remaining: 77,
      status: "approved",
    },
    {
      id: "RA-006",
      finding: "FIND-244: Missing X-Frame-Options header",
      risk_level: "low",
      approved_by: "ciso@acme.com",
      expiry_date: "2026-08-14",
      days_remaining: 122,
      status: "approved",
    },
  ],
  expired_acceptances: [
    {
      id: "RA-EX-001",
      finding: "FIND-120: Weak SSL/TLS cipher suite",
      risk_level: "high",
      approved_by: "security-team@acme.com",
      expiry_date: "2026-02-14",
      days_remaining: -59,
      status: "expired",
    },
    {
      id: "RA-EX-002",
      finding: "FIND-256: Default credentials on monitoring service",
      risk_level: "critical",
      approved_by: "ciso@acme.com",
      expiry_date: "2026-03-15",
      days_remaining: -30,
      status: "expired",
    },
  ],
};

// ══════════════════════════════════════════════════════════════
// Helpers
// ══════════════════════════════════════════════════════════════

const RISK_BADGE: Record<RiskLevel, "critical" | "high" | "medium" | "low"> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
};

const getDaysRemainingColor = (days: number): string => {
  if (days < 7) return "text-red-400";
  if (days < 30) return "text-yellow-400";
  return "text-green-400";
};

// ══════════════════════════════════════════════════════════════
// Approval Request Modal
// ══════════════════════════════════════════════════════════════

interface ApprovalModalProps {
  isOpen: boolean;
  onClose: () => void;
}

function ApprovalRequestModal({ isOpen, onClose }: ApprovalModalProps) {
  const [formData, setFormData] = useState({
    finding_id: "",
    business_justification: "",
    requested_expiry: "",
    compensating_controls: "",
  });

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    try {
      await fetch(`${API_BASE}/api/v1/risk-acceptance/request`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          finding_id: formData.finding_id,
          justification: formData.business_justification,
          business_reason: formData.business_justification,
          compensating_controls: formData.compensating_controls,
          requested_by: "analyst@aldeci.local",
          expires_at: formData.requested_expiry || new Date(Date.now() + 90 * 86400000).toISOString(),
        }),
      });
    } catch {
      // API unavailable - form closes gracefully
    }
    onClose();
  };

  if (!isOpen) return null;

  return (
    <AnimatePresence>
      {isOpen && (
        <motion.div
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          className="fixed inset-0 bg-black/50 z-50 flex items-center justify-center p-4"
          onClick={onClose}
        >
          <motion.div
            initial={{ scale: 0.95, opacity: 0 }}
            animate={{ scale: 1, opacity: 1 }}
            exit={{ scale: 0.95, opacity: 0 }}
            className="bg-slate-900 border border-slate-700 rounded-lg max-w-2xl w-full max-h-[90vh] overflow-y-auto"
            onClick={(e) => e.stopPropagation()}
          >
            {/* Header */}
            <div className="sticky top-0 bg-slate-900 border-b border-slate-700 px-6 py-4 flex items-center justify-between">
              <div className="flex items-center gap-3">
                <FileText className="w-5 h-5 text-blue-400" />
                <h2 className="text-lg font-semibold">New Risk Acceptance Request</h2>
              </div>
              <button
                onClick={onClose}
                className="text-gray-400 hover:text-white transition-colors"
              >
                <XCircle className="w-5 h-5" />
              </button>
            </div>

            {/* Form */}
            <form onSubmit={handleSubmit} className="p-6 space-y-5">
              {/* Finding ID */}
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Finding ID (required)
                </label>
                <input
                  type="text"
                  placeholder="e.g., FIND-847"
                  value={formData.finding_id}
                  onChange={(e) => setFormData({ ...formData, finding_id: e.target.value })}
                  className="w-full bg-slate-800 border border-slate-700 rounded px-3 py-2 text-white placeholder-gray-500 focus:outline-none focus:border-blue-500"
                  required
                />
              </div>

              {/* Business Justification */}
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Business Justification (required)
                </label>
                <textarea
                  placeholder="Explain why this risk is acceptable and for how long..."
                  value={formData.business_justification}
                  onChange={(e) => setFormData({ ...formData, business_justification: e.target.value })}
                  className="w-full h-24 bg-slate-800 border border-slate-700 rounded px-3 py-2 text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 resize-none"
                  required
                />
              </div>

              {/* Requested Expiry */}
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Requested Expiry Date (required)
                </label>
                <input
                  type="date"
                  value={formData.requested_expiry}
                  onChange={(e) => setFormData({ ...formData, requested_expiry: e.target.value })}
                  className="w-full bg-slate-800 border border-slate-700 rounded px-3 py-2 text-white focus:outline-none focus:border-blue-500"
                  required
                />
              </div>

              {/* Compensating Controls */}
              <div>
                <label className="block text-sm font-medium text-gray-300 mb-2">
                  Compensating Controls (required)
                </label>
                <textarea
                  placeholder="List controls that mitigate this risk (e.g., WAF rules, network segmentation, monitoring)..."
                  value={formData.compensating_controls}
                  onChange={(e) => setFormData({ ...formData, compensating_controls: e.target.value })}
                  className="w-full h-24 bg-slate-800 border border-slate-700 rounded px-3 py-2 text-white placeholder-gray-500 focus:outline-none focus:border-blue-500 resize-none"
                  required
                />
              </div>

              {/* Actions */}
              <div className="flex gap-3 pt-4">
                <Button
                  type="submit"
                  className="flex-1 bg-blue-600 hover:bg-blue-700"
                >
                  <Plus className="w-4 h-4 mr-2" />
                  Submit Request
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  onClick={onClose}
                  className="flex-1"
                >
                  Cancel
                </Button>
              </div>
            </form>
          </motion.div>
        </motion.div>
      )}
    </AnimatePresence>
  );
}

// ══════════════════════════════════════════════════════════════
// Main Page Component
// ══════════════════════════════════════════════════════════════

export default function RiskAcceptancePage() {
  const queryClient = useQueryClient();
  const [activeTab, setActiveTab] = useState<FilterTab>("all");
  const [showApprovalModal, setShowApprovalModal] = useState(false);
  const [expandedExpired, setExpandedExpired] = useState(false);

  // Fetch data
  const { data: riskData = MOCK_DATA, isLoading, error } = useQuery({
    queryKey: ["risk-acceptance"],
    queryFn: async () => {
      try {
        const response = await fetch(`${API_BASE}/api/v1/risk-acceptance/list`);
        if (!response.ok) throw new Error("Failed to fetch risk acceptance data");
        return response.json();
      } catch {
        return MOCK_DATA;
      }
    },
  });

  // Approve/Reject mutations
  const approveMutation = useMutation({
    mutationFn: async (id: string) => {
      const response = await fetch(`${API_BASE}/api/v1/risk-acceptance/${id}/approve`, {
        method: "POST",
      });
      if (!response.ok) throw new Error("Failed to approve");
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["risk-acceptance"] });
    },
  });

  const rejectMutation = useMutation({
    mutationFn: async (id: string) => {
      const response = await fetch(`${API_BASE}/api/v1/risk-acceptance/${id}/reject`, {
        method: "POST",
      });
      if (!response.ok) throw new Error("Failed to reject");
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ["risk-acceptance"] });
    },
  });

  // Filter tabs
  const tabs: { label: string; value: FilterTab; icon: typeof Shield }[] = [
    { label: "All", value: "all", icon: Shield },
    { label: "Pending", value: "pending", icon: Clock },
    { label: "Active", value: "active", icon: CheckCircle2 },
    { label: "Expired", value: "expired", icon: AlertTriangle },
  ];

  return (
    <div className="space-y-6 pb-8">
      {/* Page Header */}
      <PageHeader
        title="Risk Acceptance Workflow"
        description="Manage accepted risks and exceptions with formal approval tracking"
        icon={Shield}
      />

      {/* KPI Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard
          title="Pending Approvals"
          value={riskData.pending_count}
          icon={Clock}
          valueClassName="text-orange-400"
          trend={riskData.pending_count > 0 ? "neutral" : "positive"}
        />
        <KpiCard
          title="Accepted Risks"
          value={riskData.accepted_count}
          icon={CheckCircle2}
          valueClassName="text-green-400"
          trend="positive"
        />
        <KpiCard
          title="Expired Acceptances"
          value={riskData.expired_count}
          icon={AlertTriangle}
          valueClassName="text-red-400"
          trend={riskData.expired_count > 0 ? "negative" : "positive"}
        />
        <KpiCard
          title="Due This Week"
          value={riskData.due_this_week}
          icon={Calendar}
          valueClassName="text-yellow-400"
          trend="neutral"
        />
      </div>

      {/* Filter Tabs + Action Button */}
      <div className="flex items-center justify-between gap-4 flex-wrap">
        <div className="flex gap-2">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            return (
              <button
                key={tab.value}
                onClick={() => setActiveTab(tab.value)}
                className={cn(
                  "px-4 py-2 rounded-lg font-medium text-sm transition-all flex items-center gap-2",
                  activeTab === tab.value
                    ? "bg-blue-600/20 text-blue-400 border border-blue-600/30"
                    : "bg-slate-700/30 text-gray-400 border border-transparent hover:bg-slate-600/30"
                )}
              >
                <Icon className="w-4 h-4" />
                {tab.label}
              </button>
            );
          })}
        </div>
        <Button
          onClick={() => setShowApprovalModal(true)}
          className="bg-blue-600 hover:bg-blue-700 flex items-center gap-2"
        >
          <Plus className="w-4 h-4" />
          Approval Request
        </Button>
      </div>

      {/* Pending Approvals Section */}
      {(activeTab === "all" || activeTab === "pending") && (
        <Card className="border-slate-700/50">
          <CardHeader className="border-b border-slate-700/50">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <Clock className="w-5 h-5 text-orange-400" />
                <CardTitle>Pending Approvals</CardTitle>
              </div>
              <Badge variant="secondary" className="bg-orange-600/20 text-orange-400 border-orange-600/30">
                {riskData.pending_approvals.length} pending
              </Badge>
            </div>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="border-slate-700/50 hover:bg-transparent">
                    <TableHead className="text-gray-400">Finding</TableHead>
                    <TableHead className="text-gray-400">Severity</TableHead>
                    <TableHead className="text-gray-400">Business Justification</TableHead>
                    <TableHead className="text-gray-400">Requested By</TableHead>
                    <TableHead className="text-gray-400">Expiry</TableHead>
                    <TableHead className="text-gray-400 text-right">Actions</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {riskData.pending_approvals.map((item) => (
                    <motion.tr
                      key={item.id}
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      className="border-slate-700/30 hover:bg-slate-800/40 transition-colors"
                    >
                      <TableCell className="font-mono text-[12px] text-blue-400">
                        {item.finding}
                      </TableCell>
                      <TableCell>
                        <Badge variant={RISK_BADGE[item.severity]} className="text-[10px] uppercase">
                          {item.severity}
                        </Badge>
                      </TableCell>
                      <TableCell className="max-w-xs">
                        <p className="text-sm text-gray-300 truncate" title={item.business_justification}>
                          {item.business_justification}
                        </p>
                      </TableCell>
                      <TableCell className="text-sm text-gray-400">
                        <div className="flex items-center gap-2">
                          <User className="w-3 h-3 text-gray-500" />
                          {item.requested_by}
                        </div>
                      </TableCell>
                      <TableCell className="text-sm text-gray-400">
                        <div className="flex items-center gap-2">
                          <Calendar className="w-3 h-3 text-gray-500" />
                          {new Date(item.expiry_date).toLocaleDateString()}
                        </div>
                      </TableCell>
                      <TableCell>
                        <div className="flex justify-end gap-2">
                          <Button
                            size="sm"
                            className="bg-green-600/20 text-green-400 border border-green-600/30 hover:bg-green-600/30"
                            onClick={() => approveMutation.mutate(item.id)}
                            disabled={approveMutation.isPending}
                          >
                            <ThumbsUp className="w-3 h-3 mr-1" />
                            Approve
                          </Button>
                          <Button
                            size="sm"
                            className="bg-red-600/20 text-red-400 border border-red-600/30 hover:bg-red-600/30"
                            onClick={() => rejectMutation.mutate(item.id)}
                            disabled={rejectMutation.isPending}
                          >
                            <ThumbsDown className="w-3 h-3 mr-1" />
                            Reject
                          </Button>
                        </div>
                      </TableCell>
                    </motion.tr>
                  ))}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Active Risk Acceptances Section */}
      {(activeTab === "all" || activeTab === "active") && (
        <Card className="border-slate-700/50">
          <CardHeader className="border-b border-slate-700/50">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <CheckCircle2 className="w-5 h-5 text-green-400" />
                <CardTitle>Active Risk Acceptances</CardTitle>
              </div>
              <Badge variant="secondary" className="bg-green-600/20 text-green-400 border-green-600/30">
                {riskData.active_acceptances.length} active
              </Badge>
            </div>
          </CardHeader>
          <CardContent className="p-0">
            <div className="overflow-x-auto">
              <Table>
                <TableHeader>
                  <TableRow className="border-slate-700/50 hover:bg-transparent">
                    <TableHead className="text-gray-400">Finding</TableHead>
                    <TableHead className="text-gray-400">Risk Level</TableHead>
                    <TableHead className="text-gray-400">Approved By</TableHead>
                    <TableHead className="text-gray-400">Expiry Date</TableHead>
                    <TableHead className="text-gray-400">Days Remaining</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {riskData.active_acceptances.map((item) => (
                    <motion.tr
                      key={item.id}
                      initial={{ opacity: 0 }}
                      animate={{ opacity: 1 }}
                      className="border-slate-700/30 hover:bg-slate-800/40 transition-colors"
                    >
                      <TableCell className="font-mono text-[12px] text-blue-400">
                        {item.finding}
                      </TableCell>
                      <TableCell>
                        <Badge variant={RISK_BADGE[item.risk_level]} className="text-[10px] uppercase">
                          {item.risk_level}
                        </Badge>
                      </TableCell>
                      <TableCell className="text-sm text-gray-400">
                        <div className="flex items-center gap-2">
                          <User className="w-3 h-3 text-gray-500" />
                          {item.approved_by}
                        </div>
                      </TableCell>
                      <TableCell className="text-sm text-gray-400">
                        <div className="flex items-center gap-2">
                          <Calendar className="w-3 h-3 text-gray-500" />
                          {new Date(item.expiry_date).toLocaleDateString()}
                        </div>
                      </TableCell>
                      <TableCell>
                        <span className={cn("font-medium text-sm", getDaysRemainingColor(item.days_remaining))}>
                          {item.days_remaining > 0 ? `${item.days_remaining}d` : "Expired"}
                        </span>
                      </TableCell>
                    </motion.tr>
                  ))}
                </TableBody>
              </Table>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Expired Risks - Collapsible Section */}
      {(activeTab === "all" || activeTab === "expired") && riskData.expired_acceptances.length > 0 && (
        <Card className="border-slate-700/50">
          <CardHeader
            className="border-b border-slate-700/50 cursor-pointer"
            onClick={() => setExpandedExpired(!expandedExpired)}
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <AlertTriangle className="w-5 h-5 text-red-400" />
                <CardTitle>Expired Risks</CardTitle>
              </div>
              <div className="flex items-center gap-3">
                <Badge variant="secondary" className="bg-red-600/20 text-red-400 border-red-600/30">
                  {riskData.expired_acceptances.length} expired
                </Badge>
                <ChevronDown
                  className={cn(
                    "w-5 h-5 text-gray-400 transition-transform",
                    expandedExpired && "rotate-180"
                  )}
                />
              </div>
            </div>
          </CardHeader>
          <AnimatePresence>
            {expandedExpired && (
              <motion.div
                initial={{ opacity: 0, height: 0 }}
                animate={{ opacity: 1, height: "auto" }}
                exit={{ opacity: 0, height: 0 }}
              >
                <CardContent className="p-0">
                  <div className="overflow-x-auto">
                    <Table>
                      <TableHeader>
                        <TableRow className="border-slate-700/50 hover:bg-transparent">
                          <TableHead className="text-gray-400">Finding</TableHead>
                          <TableHead className="text-gray-400">Risk Level</TableHead>
                          <TableHead className="text-gray-400">Approved By</TableHead>
                          <TableHead className="text-gray-400">Expiry Date</TableHead>
                          <TableHead className="text-gray-400">Days Overdue</TableHead>
                        </TableRow>
                      </TableHeader>
                      <TableBody>
                        {riskData.expired_acceptances.map((item) => (
                          <motion.tr
                            key={item.id}
                            initial={{ opacity: 0 }}
                            animate={{ opacity: 1 }}
                            className="border-slate-700/30 hover:bg-slate-800/40 transition-colors"
                          >
                            <TableCell className="font-mono text-[12px] text-blue-400">
                              {item.finding}
                            </TableCell>
                            <TableCell>
                              <Badge variant={RISK_BADGE[item.risk_level]} className="text-[10px] uppercase">
                                {item.risk_level}
                              </Badge>
                            </TableCell>
                            <TableCell className="text-sm text-gray-400">
                              <div className="flex items-center gap-2">
                                <User className="w-3 h-3 text-gray-500" />
                                {item.approved_by}
                              </div>
                            </TableCell>
                            <TableCell className="text-sm text-gray-400">
                              <div className="flex items-center gap-2">
                                <Calendar className="w-3 h-3 text-gray-500" />
                                {new Date(item.expiry_date).toLocaleDateString()}
                              </div>
                            </TableCell>
                            <TableCell>
                              <span className="font-medium text-sm text-red-400">
                                {Math.abs(item.days_remaining)}d overdue
                              </span>
                            </TableCell>
                          </motion.tr>
                        ))}
                      </TableBody>
                    </Table>
                  </div>
                </CardContent>
              </motion.div>
            )}
          </AnimatePresence>
        </Card>
      )}

      {/* Empty State */}
      {!isLoading && activeTab === "pending" && riskData.pending_approvals.length === 0 && (
        <Card className="border-slate-700/50">
          <CardContent className="p-12 text-center">
            <CheckCircle2 className="w-12 h-12 text-green-400/30 mx-auto mb-3" />
            <p className="text-gray-400">No pending approvals. All risk acceptance requests are processed.</p>
          </CardContent>
        </Card>
      )}

      {/* Approval Request Modal */}
      <ApprovalRequestModal
        isOpen={showApprovalModal}
        onClose={() => setShowApprovalModal(false)}
      />
    </div>
  );
}
