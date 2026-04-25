/**
 * User Access Review Dashboard - Live API
 * Route: /access-reviews
 * API: GET /api/v1/access-reviews/reviews
 */

import { useState, useEffect } from "react";
import { ClipboardCheck, RefreshCw } from "lucide-react";
import { buildApiUrl, getStoredAuthToken, getStoredOrgId } from "@/lib/api";
import { EmptyState } from "@/components/shared/EmptyState";
import { ErrorState } from "@/components/shared/ErrorState";

async function apiFetch<T>(path: string): Promise<T> {
  const orgId = getStoredOrgId() || "verify-test";
  const url = buildApiUrl(path, { org_id: orgId });
  const res = await fetch(url, { headers: { "X-API-Key": getStoredAuthToken(), "X-Org-ID": orgId } });
  if (!res.ok) throw new Error(`${res.status} ${res.statusText}`);
  return res.json() as Promise<T>;
}

const statusColors: Record<string, string> = {
  pending: "bg-gray-600 text-gray-200",
  in_progress: "bg-blue-600 text-blue-100",
  completed: "bg-green-700 text-green-100",
  overdue: "bg-red-700 text-red-100",
};
const typeLabels: Record<string, string> = {
  user_access: "User Access",
  privileged_access: "Privileged",
  application_access: "Application",
  role_certification: "Role Cert",
  entitlement_review: "Entitlement",
};
const decisionColors: Record<string, string> = {
  certify: "bg-green-700 text-green-100",
  revoke: "bg-red-700 text-red-100",
  modify: "bg-amber-600 text-amber-100",
  defer: "bg-gray-600 text-gray-200",
  pending: "bg-blue-700 text-blue-100",
};

export default function UserAccessReviewDashboard() {
  const [reviews, setReviews] = useState<any[]>([]);
  const [items, setItems] = useState<any[]>([]);
  const [campaigns, setCampaigns] = useState<any[]>([]);
  const [selectedReview, setSelectedReview] = useState<string>("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    setLoading(true); setError(null);
    try {
      const [revRes, itemRes, cmpRes] = await Promise.allSettled([
        apiFetch<any>("/api/v1/access-reviews/reviews"),
        apiFetch<any>("/api/v1/access-reviews/items"),
        apiFetch<any>("/api/v1/access-reviews/campaigns"),
      ]);
      if (revRes.status === "fulfilled") {
        const v = revRes.value;
        const arr = Array.isArray(v) ? v : (v.reviews ?? v.items ?? []);
        setReviews(arr);
        if (arr.length && !selectedReview) setSelectedReview(arr[0].id);
      }
      if (itemRes.status === "fulfilled") {
        const v = itemRes.value;
        setItems(Array.isArray(v) ? v : (v.items ?? []));
      }
      if (cmpRes.status === "fulfilled") {
        const v = cmpRes.value;
        setCampaigns(Array.isArray(v) ? v : (v.campaigns ?? v.items ?? []));
      }
    } catch (e) { setError((e as Error).message); }
    finally { setLoading(false); }
  };
  useEffect(() => { load(); }, []);

  const overdueCount = reviews.filter(r => r.overdue || r.status === "overdue").length;
  const completedCount = reviews.filter(r => r.status === "completed").length;
  const pendingCount = reviews.filter(r => r.status === "pending").length;
  const selectedItems = items.filter(i => i.review_id === selectedReview);

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">User Access Reviews</h1>
          <p className="text-gray-400 mt-1">Certify, revoke, or modify user access entitlements</p>
        </div>
        <button onClick={load} className="flex items-center gap-2 px-4 py-2 bg-gray-700 hover:bg-gray-600 rounded-lg text-sm"><RefreshCw className={`w-4 h-4 ${loading ? "animate-spin" : ""}`} /> Refresh</button>
      </div>

      {loading ? <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div></div>
        : error ? <ErrorState message={error} onRetry={load} />
        : reviews.length === 0 ? <EmptyState icon={ClipboardCheck} title="No access reviews" description="Create an access review campaign to begin certifying user entitlements." />
        : <>
          {overdueCount > 0 && (
            <div className="bg-red-900/40 border border-red-700 rounded-lg p-4 flex items-center gap-3">
              <span className="text-red-400 text-xl">⚠</span>
              <div>
                <p className="text-red-300 font-semibold">{overdueCount} overdue access review{overdueCount > 1 ? "s" : ""} require immediate attention</p>
                <p className="text-red-400 text-sm mt-0.5">Access reviews past their due date pose compliance and security risks</p>
              </div>
            </div>
          )}

          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            {[
              { label: "Total Reviews", value: reviews.length, color: "text-blue-400" },
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

          <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold text-white mb-4">Access Reviews</h2>
            <div className="overflow-x-auto"><table className="w-full text-sm">
              <thead><tr className="border-b border-gray-700 text-gray-400 text-left">
                <th className="pb-3 pr-4">Review Name</th><th className="pb-3 pr-4">Type</th><th className="pb-3 pr-4">Status</th><th className="pb-3 pr-4">Reviewer</th><th className="pb-3 pr-4">Due Date</th><th className="pb-3 pr-4">Progress</th>
              </tr></thead>
              <tbody className="divide-y divide-gray-700">{reviews.map(review => {
                const total = review.total_items ?? 0;
                const completed = review.completed_items ?? 0;
                const progress = total > 0 ? Math.round((completed / total) * 100) : 0;
                return (
                  <tr key={review.id} className={`cursor-pointer ${selectedReview === review.id ? "bg-blue-900/30" : "hover:bg-gray-700/50"}`} onClick={() => setSelectedReview(review.id)}>
                    <td className="py-3 pr-4 font-medium text-white">{review.review_name ?? review.name}</td>
                    <td className="py-3 pr-4"><span className="bg-gray-700 text-gray-300 px-2 py-0.5 rounded text-xs">{typeLabels[review.review_type] ?? review.review_type ?? "—"}</span></td>
                    <td className="py-3 pr-4"><span className={`px-2 py-0.5 rounded text-xs font-medium ${statusColors[review.status] ?? "bg-gray-600"}`}>{(review.status ?? "").replace("_", " ")}</span></td>
                    <td className="py-3 pr-4 text-gray-300">{review.reviewer ?? "—"}</td>
                    <td className={`py-3 pr-4 ${review.overdue ? "text-red-400 font-medium" : "text-gray-300"}`}>{review.due_date ?? "—"}</td>
                    <td className="py-3 pr-4"><div className="flex items-center gap-2"><div className="w-24 bg-gray-700 rounded-full h-1.5"><div className={`h-1.5 rounded-full ${progress === 100 ? "bg-green-500" : review.overdue ? "bg-red-500" : "bg-blue-500"}`} style={{ width: `${progress}%` }} /></div><span className="text-gray-400 text-xs">{progress}%</span></div></td>
                  </tr>
                );
              })}</tbody>
            </table></div>
          </div>

          <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold text-white mb-4">Review Items — {reviews.find(r => r.id === selectedReview)?.review_name ?? ""}</h2>
            {selectedItems.length === 0 ? <p className="text-gray-400 text-sm">No items available. Select a review above.</p>
              : <div className="overflow-x-auto"><table className="w-full text-sm">
                <thead><tr className="border-b border-gray-700 text-gray-400 text-left">
                  <th className="pb-3 pr-4">User</th><th className="pb-3 pr-4">Resource</th><th className="pb-3 pr-4">Access Level</th><th className="pb-3 pr-4">Last Used</th><th className="pb-3 pr-4">Risk</th><th className="pb-3 pr-4">Decision</th>
                </tr></thead>
                <tbody className="divide-y divide-gray-700">{selectedItems.map(item => (
                  <tr key={item.id} className="hover:bg-gray-700/50">
                    <td className="py-3 pr-4 text-white font-mono text-xs">{item.user}</td>
                    <td className="py-3 pr-4 text-gray-300">{item.resource}</td>
                    <td className="py-3 pr-4"><span className="bg-gray-700 text-gray-300 px-2 py-0.5 rounded text-xs">{item.access_level}</span></td>
                    <td className={`py-3 pr-4 text-xs ${item.last_used === "Never" ? "text-red-400 font-medium" : "text-gray-400"}`}>{item.last_used ?? "—"}</td>
                    <td className="py-3 pr-4"><div className="flex items-center gap-2"><div className="w-16 bg-gray-700 rounded-full h-1.5"><div className={`h-1.5 rounded-full ${(item.risk_score ?? 0) >= 80 ? "bg-red-500" : (item.risk_score ?? 0) >= 60 ? "bg-amber-500" : "bg-green-500"}`} style={{ width: `${item.risk_score ?? 0}%` }} /></div><span className={`text-xs font-medium ${(item.risk_score ?? 0) >= 80 ? "text-red-400" : (item.risk_score ?? 0) >= 60 ? "text-amber-400" : "text-green-400"}`}>{item.risk_score ?? 0}</span></div></td>
                    <td className="py-3 pr-4"><span className={`px-2 py-0.5 rounded text-xs font-medium ${decisionColors[item.decision ?? "pending"]}`}>{item.decision ?? "pending"}</span></td>
                  </tr>
                ))}</tbody>
              </table></div>}
          </div>

          {campaigns.length > 0 && <div className="bg-gray-800 rounded-lg p-6">
            <h2 className="text-lg font-semibold text-white mb-4">Review Campaigns</h2>
            <div className="space-y-3">{campaigns.map(campaign => (
              <div key={campaign.id} className="flex items-center justify-between p-4 bg-gray-700/50 rounded-lg">
                <div className="flex-1">
                  <p className="text-white font-medium">{campaign.name}</p>
                  <p className="text-gray-400 text-sm mt-0.5">{campaign.frequency} · Owner: {campaign.owner} · Last run: {campaign.last_run}</p>
                </div>
                <div className="flex items-center gap-3 ml-4">
                  <div className="text-right"><p className="text-xs text-gray-400">Completion</p><p className={`text-sm font-semibold ${(campaign.completion_rate ?? 0) >= 90 ? "text-green-400" : (campaign.completion_rate ?? 0) >= 70 ? "text-amber-400" : "text-red-400"}`}>{campaign.completion_rate ?? 0}%</p></div>
                  <div className="w-24 bg-gray-700 rounded-full h-2"><div className={`h-2 rounded-full ${(campaign.completion_rate ?? 0) >= 90 ? "bg-green-500" : (campaign.completion_rate ?? 0) >= 70 ? "bg-amber-500" : "bg-red-500"}`} style={{ width: `${campaign.completion_rate ?? 0}%` }} /></div>
                </div>
              </div>
            ))}</div>
          </div>}
        </>}
    </div>
  );
}
