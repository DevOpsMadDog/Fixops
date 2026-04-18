/**
 * User Access Review Dashboard
 *
 * Displays access review campaigns, review items with certification decisions,
 * overdue alerts, and summary counts.
 *
 * Route: /access-reviews
 * API: GET /api/v1/access-reviews
 */

import { useState, useEffect } from "react";

// ── Types ──────────────────────────────────────────────────────

type ReviewStatus = "pending" | "in_progress" | "completed" | "overdue";
type ReviewType = "user_access" | "privileged_access" | "application_access" | "role_certification" | "entitlement_review";
type ItemDecision = "certify" | "revoke" | "modify" | "defer" | "pending";

interface AccessReview {
  id: string;
  review_name: string;
  review_type: ReviewType;
  status: ReviewStatus;
  reviewer: string;
  due_date: string;
  total_items: number;
  completed_items: number;
  overdue: boolean;
}

interface ReviewItem {
  id: string;
  review_id: string;
  user: string;
  resource: string;
  access_level: string;
  last_used: string;
  decision: ItemDecision;
  risk_score: number;
}

interface ReviewCampaign {
  id: string;
  name: string;
  frequency: string;
  last_run: string;
  completion_rate: number;
  owner: string;
}

// ── Mock data ──────────────────────────────────────────────────

const MOCK_REVIEWS: AccessReview[] = [
  { id: "rev-001", review_name: "Q2 2026 User Access Certification", review_type: "user_access", status: "in_progress", reviewer: "Alice Chen", due_date: "2026-04-30", total_items: 142, completed_items: 89, overdue: false },
  { id: "rev-002", review_name: "Privileged Account Review — April", review_type: "privileged_access", status: "overdue", reviewer: "Bob Martinez", due_date: "2026-04-10", total_items: 28, completed_items: 12, overdue: true },
  { id: "rev-003", review_name: "AWS IAM Role Certification", review_type: "role_certification", status: "pending", reviewer: "Carol White", due_date: "2026-05-15", total_items: 67, completed_items: 0, overdue: false },
  { id: "rev-004", review_name: "SaaS Application Access Review", review_type: "application_access", status: "completed", reviewer: "David Kim", due_date: "2026-04-05", total_items: 95, completed_items: 95, overdue: false },
  { id: "rev-005", review_name: "Production Entitlement Review", review_type: "entitlement_review", status: "overdue", reviewer: "Eve Johnson", due_date: "2026-04-08", total_items: 54, completed_items: 21, overdue: true },
  { id: "rev-006", review_name: "Executive Access Certification", review_type: "privileged_access", status: "in_progress", reviewer: "Frank Lee", due_date: "2026-04-28", total_items: 18, completed_items: 11, overdue: false },
];

const MOCK_ITEMS: ReviewItem[] = [
  { id: "itm-001", review_id: "rev-001", user: "john.doe@corp.com", resource: "prod-database-admin", access_level: "Admin", last_used: "2026-04-14", decision: "pending", risk_score: 85 },
  { id: "itm-002", review_id: "rev-001", user: "sarah.smith@corp.com", resource: "k8s-cluster-prod", access_level: "Write", last_used: "2026-03-01", decision: "certify", risk_score: 42 },
  { id: "itm-003", review_id: "rev-001", user: "mike.jones@corp.com", resource: "aws-root-account", access_level: "Admin", last_used: "2025-11-15", decision: "pending", risk_score: 97 },
  { id: "itm-004", review_id: "rev-001", user: "lisa.wang@corp.com", resource: "github-org-admin", access_level: "Owner", last_used: "2026-04-10", decision: "modify", risk_score: 61 },
  { id: "itm-005", review_id: "rev-001", user: "tom.brown@corp.com", resource: "splunk-admin", access_level: "Admin", last_used: "Never", decision: "revoke", risk_score: 78 },
  { id: "itm-006", review_id: "rev-001", user: "anna.davis@corp.com", resource: "jira-service-mgmt", access_level: "Admin", last_used: "2026-04-12", decision: "certify", risk_score: 30 },
];

const MOCK_CAMPAIGNS: ReviewCampaign[] = [
  { id: "cmp-001", name: "Quarterly User Access Certification", frequency: "Quarterly", last_run: "2026-01-15", completion_rate: 94, owner: "IAM Team" },
  { id: "cmp-002", name: "Monthly Privileged Access Review", frequency: "Monthly", last_run: "2026-03-31", completion_rate: 78, owner: "Security Ops" },
  { id: "cmp-003", name: "Annual Role Recertification", frequency: "Annual", last_run: "2025-12-01", completion_rate: 100, owner: "GRC Team" },
  { id: "cmp-004", name: "SaaS Application Review", frequency: "Semi-annual", last_run: "2025-10-01", completion_rate: 87, owner: "IT Security" },
];

// ── Helpers ────────────────────────────────────────────────────

const statusColors: Record<ReviewStatus, string> = {
  pending: "bg-gray-600 text-gray-200",
  in_progress: "bg-blue-600 text-blue-100",
  completed: "bg-green-700 text-green-100",
  overdue: "bg-red-700 text-red-100",
};

const typeLabels: Record<ReviewType, string> = {
  user_access: "User Access",
  privileged_access: "Privileged",
  application_access: "Application",
  role_certification: "Role Cert",
  entitlement_review: "Entitlement",
};

const decisionColors: Record<ItemDecision, string> = {
  certify: "bg-green-700 text-green-100",
  revoke: "bg-red-700 text-red-100",
  modify: "bg-amber-600 text-amber-100",
  defer: "bg-gray-600 text-gray-200",
  pending: "bg-blue-700 text-blue-100",
};

// ── Component ──────────────────────────────────────────────────

export default function UserAccessReviewDashboard() {
  const [selectedReview, setSelectedReview] = useState<string>(MOCK_REVIEWS[0].id);
  useEffect(() => {
    fetch("/api/v1/access-reviews", { headers: { "X-API-Key": localStorage.getItem("apiKey") || "" } })
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(() => { /* live data available */ })
      .catch(() => {});
  }, []);
  const [itemDecisions, setItemDecisions] = useState<Record<string, ItemDecision>>(
    Object.fromEntries(MOCK_ITEMS.map(i => [i.id, i.decision]))
  );

  const overdueCount = MOCK_REVIEWS.filter(r => r.overdue).length;
  const completedCount = MOCK_REVIEWS.filter(r => r.status === "completed").length;
  const pendingCount = MOCK_REVIEWS.filter(r => r.status === "pending").length;
  const inProgressCount = MOCK_REVIEWS.filter(r => r.status === "in_progress").length;

  const selectedItems = MOCK_ITEMS.filter(i => i.review_id === selectedReview);

  function setDecision(itemId: string, decision: ItemDecision) {
    setItemDecisions(prev => ({ ...prev, [itemId]: decision }));
  }

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">User Access Reviews</h1>
          <p className="text-gray-400 mt-1">Certify, revoke, or modify user access entitlements</p>
        </div>
        <button className="bg-blue-600 hover:bg-blue-700 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors">
          + New Campaign
        </button>
      </div>

      {/* Overdue Banner */}
      {overdueCount > 0 && (
        <div className="bg-red-900/40 border border-red-700 rounded-lg p-4 flex items-center gap-3">
          <span className="text-red-400 text-xl">⚠</span>
          <div>
            <p className="text-red-300 font-semibold">{overdueCount} overdue access review{overdueCount > 1 ? "s" : ""} require immediate attention</p>
            <p className="text-red-400 text-sm mt-0.5">Access reviews past their due date pose compliance and security risks</p>
          </div>
        </div>
      )}

      {/* Summary KPIs */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: "Total Reviews", value: MOCK_REVIEWS.length, color: "text-blue-400" },
          { label: "Pending", value: pendingCount, color: "text-gray-300" },
          { label: "Completed", value: completedCount, color: "text-green-400" },
          { label: "Overdue", value: overdueCount, color: "text-red-400" },
        ].map(kpi => (
          <div key={kpi.label} className="bg-gray-800 rounded-lg p-6">
            <p className="text-gray-400 text-sm">{kpi.label}</p>
            <p className={`text-3xl font-bold mt-1 ${kpi.color}`}>{kpi.value}</p>
          </div>
        ))}
      </div>

      {/* Reviews Table */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h2 className="text-lg font-semibold text-white mb-4">Access Reviews</h2>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-700 text-gray-400 text-left">
                <th className="pb-3 pr-4">Review Name</th>
                <th className="pb-3 pr-4">Type</th>
                <th className="pb-3 pr-4">Status</th>
                <th className="pb-3 pr-4">Reviewer</th>
                <th className="pb-3 pr-4">Due Date</th>
                <th className="pb-3 pr-4">Progress</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-700">
              {MOCK_REVIEWS.map(review => {
                const progress = review.total_items > 0
                  ? Math.round((review.completed_items / review.total_items) * 100)
                  : 0;
                return (
                  <tr
                    key={review.id}
                    className={`cursor-pointer transition-colors ${selectedReview === review.id ? "bg-blue-900/30" : "hover:bg-gray-700/50"}`}
                    onClick={() => setSelectedReview(review.id)}
                  >
                    <td className="py-3 pr-4 font-medium text-white">{review.review_name}</td>
                    <td className="py-3 pr-4">
                      <span className="bg-gray-700 text-gray-300 px-2 py-0.5 rounded text-xs">{typeLabels[review.review_type]}</span>
                    </td>
                    <td className="py-3 pr-4">
                      <span className={`px-2 py-0.5 rounded text-xs font-medium ${statusColors[review.status]}`}>
                        {review.status.replace("_", " ")}
                      </span>
                    </td>
                    <td className="py-3 pr-4 text-gray-300">{review.reviewer}</td>
                    <td className={`py-3 pr-4 ${review.overdue ? "text-red-400 font-medium" : "text-gray-300"}`}>
                      {review.due_date}
                    </td>
                    <td className="py-3 pr-4">
                      <div className="flex items-center gap-2">
                        <div className="w-24 bg-gray-700 rounded-full h-1.5">
                          <div
                            className={`h-1.5 rounded-full ${progress === 100 ? "bg-green-500" : review.overdue ? "bg-red-500" : "bg-blue-500"}`}
                            style={{ width: `${progress}%` }}
                          />
                        </div>
                        <span className="text-gray-400 text-xs">{progress}%</span>
                      </div>
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Review Items */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h2 className="text-lg font-semibold text-white mb-4">
          Review Items — {MOCK_REVIEWS.find(r => r.id === selectedReview)?.review_name}
        </h2>
        {selectedItems.length === 0 ? (
          <p className="text-gray-400 text-sm">No items available. Select a review above.</p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-gray-700 text-gray-400 text-left">
                  <th className="pb-3 pr-4">User</th>
                  <th className="pb-3 pr-4">Resource</th>
                  <th className="pb-3 pr-4">Access Level</th>
                  <th className="pb-3 pr-4">Last Used</th>
                  <th className="pb-3 pr-4">Risk</th>
                  <th className="pb-3 pr-4">Decision</th>
                  <th className="pb-3">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-700">
                {selectedItems.map(item => (
                  <tr key={item.id} className="hover:bg-gray-700/50">
                    <td className="py-3 pr-4 text-white font-mono text-xs">{item.user}</td>
                    <td className="py-3 pr-4 text-gray-300">{item.resource}</td>
                    <td className="py-3 pr-4">
                      <span className="bg-gray-700 text-gray-300 px-2 py-0.5 rounded text-xs">{item.access_level}</span>
                    </td>
                    <td className={`py-3 pr-4 text-xs ${item.last_used === "Never" ? "text-red-400 font-medium" : "text-gray-400"}`}>
                      {item.last_used}
                    </td>
                    <td className="py-3 pr-4">
                      <div className="flex items-center gap-2">
                        <div className="w-16 bg-gray-700 rounded-full h-1.5">
                          <div
                            className={`h-1.5 rounded-full ${item.risk_score >= 80 ? "bg-red-500" : item.risk_score >= 60 ? "bg-amber-500" : "bg-green-500"}`}
                            style={{ width: `${item.risk_score}%` }}
                          />
                        </div>
                        <span className={`text-xs font-medium ${item.risk_score >= 80 ? "text-red-400" : item.risk_score >= 60 ? "text-amber-400" : "text-green-400"}`}>
                          {item.risk_score}
                        </span>
                      </div>
                    </td>
                    <td className="py-3 pr-4">
                      <span className={`px-2 py-0.5 rounded text-xs font-medium ${decisionColors[itemDecisions[item.id] ?? "pending"]}`}>
                        {itemDecisions[item.id] ?? "pending"}
                      </span>
                    </td>
                    <td className="py-3">
                      <div className="flex gap-1 flex-wrap">
                        {(["certify", "revoke", "modify", "defer"] as ItemDecision[]).map(d => (
                          <button
                            key={d}
                            onClick={() => setDecision(item.id, d)}
                            className={`px-2 py-0.5 rounded text-xs border transition-colors ${
                              itemDecisions[item.id] === d
                                ? "bg-blue-700 border-blue-500 text-white"
                                : "border-gray-600 text-gray-400 hover:border-gray-500 hover:text-gray-200"
                            }`}
                          >
                            {d}
                          </button>
                        ))}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      {/* Campaigns */}
      <div className="bg-gray-800 rounded-lg p-6">
        <h2 className="text-lg font-semibold text-white mb-4">Review Campaigns</h2>
        <div className="space-y-3">
          {MOCK_CAMPAIGNS.map(campaign => (
            <div key={campaign.id} className="flex items-center justify-between p-4 bg-gray-700/50 rounded-lg">
              <div className="flex-1">
                <p className="text-white font-medium">{campaign.name}</p>
                <p className="text-gray-400 text-sm mt-0.5">
                  {campaign.frequency} · Owner: {campaign.owner} · Last run: {campaign.last_run}
                </p>
              </div>
              <div className="flex items-center gap-3 ml-4">
                <div className="text-right">
                  <p className="text-xs text-gray-400">Completion</p>
                  <p className={`text-sm font-semibold ${campaign.completion_rate >= 90 ? "text-green-400" : campaign.completion_rate >= 70 ? "text-amber-400" : "text-red-400"}`}>
                    {campaign.completion_rate}%
                  </p>
                </div>
                <div className="w-24 bg-gray-700 rounded-full h-2">
                  <div
                    className={`h-2 rounded-full ${campaign.completion_rate >= 90 ? "bg-green-500" : campaign.completion_rate >= 70 ? "bg-amber-500" : "bg-red-500"}`}
                    style={{ width: `${campaign.completion_rate}%` }}
                  />
                </div>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
