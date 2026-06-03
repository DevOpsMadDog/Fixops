import { useState, useEffect, useCallback } from "react";
import { getStoredOrgId } from "@/lib/api";

const API_BASE = "/api/v1/arch-review";
const getHeaders = () => ({
  "X-API-Key": localStorage.getItem("aldeci.authToken") || "",
  "Content-Type": "application/json",
});

// NO-MOCKS (CLAUDE.md): all reviews/findings/controls below are loaded from the
// live /api/v1/arch-review API on mount — there is no hardcoded fixture data.

const REVIEW_TYPES = ["full", "partial", "threat-model", "compliance", "vendor"];
const FINDING_TYPES = [
  "design-flaw",
  "missing-control",
  "weak-implementation",
  "configuration",
  "dependency-risk",
  "data-exposure",
];

const riskBadge = (level: string) => {
  const map: Record<string, string> = { critical: "bg-red-600", high: "bg-orange-500", medium: "bg-yellow-500", low: "bg-green-600" };
  return <span className={`${map[level] || "bg-gray-600"} text-white text-xs px-2 py-0.5 rounded-full`}>{level || "—"}</span>;
};

const statusBadge = (s: string) => {
  const map: Record<string, string> = { draft: "bg-gray-600", in_progress: "bg-blue-600", completed: "bg-green-600", open: "bg-red-500", remediated: "bg-green-600" };
  return <span className={`${map[s] || "bg-gray-600"} text-white text-xs px-2 py-0.5 rounded`}>{(s || "").replace("_", " ")}</span>;
};

const severityBadge = (s: string) => {
  const map: Record<string, string> = { critical: "bg-red-600", high: "bg-orange-500", medium: "bg-yellow-500", low: "bg-green-600", info: "bg-blue-500" };
  return <span className={`${map[s] || "bg-gray-600"} text-white text-xs px-2 py-0.5 rounded`}>{s}</span>;
};

const implBadge = (s: string) => {
  const map: Record<string, string> = { implemented: "bg-green-600", partial: "bg-yellow-500", not_implemented: "bg-red-600", compensating: "bg-blue-500" };
  return <span className={`${map[s] || "bg-gray-600"} text-white text-xs px-2 py-0.5 rounded`}>{(s || "").replace("_", " ")}</span>;
};

const EmptyState = ({ title, hint }: { title: string; hint: string }) => (
  <div className="p-12 text-center">
    <p className="text-gray-300 font-medium">{title}</p>
    <p className="text-gray-500 text-sm mt-1">{hint}</p>
  </div>
);

const ORG_ID = (getStoredOrgId() ?? "default");
export default function ArchReviewDashboard() {
  const [activeTab, setActiveTab] = useState<"reviews" | "findings" | "controls" | "gaps">("reviews");
  const [loading, setLoading] = useState(true);
  const [filterReview, setFilterReview] = useState("all");
  const [showAddReview, setShowAddReview] = useState(false);
  const [showAddFinding, setShowAddFinding] = useState(false);
  const [newReview, setNewReview] = useState({ review_name: "", system_name: "", review_type: "threat-model", reviewer: "" });
  const [newFinding, setNewFinding] = useState({ review_id: "", component: "", finding_type: "design-flaw", title: "", severity: "high", recommendation: "" });
  const [reviews, setReviews] = useState<any[]>([]);
  const [findings, setFindings] = useState<any[]>([]);
  const [controls, setControls] = useState<any[]>([]);
  const [gaps, setGaps] = useState<any[]>([]);
  const [summary, setSummary] = useState<any | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [saving, setSaving] = useState(false);

  const loadData = useCallback(async () => {
    setError(null);
    try {
      const [reviewsRes, summaryRes, gapsRes] = await Promise.all([
        fetch(`${API_BASE}/reviews?org_id=${ORG_ID}`, { headers: getHeaders() }),
        fetch(`${API_BASE}/summary?org_id=${ORG_ID}`, { headers: getHeaders() }),
        fetch(`${API_BASE}/control-gaps?org_id=${ORG_ID}`, { headers: getHeaders() }),
      ]);
      const reviewList = reviewsRes.ok ? await reviewsRes.json() : [];
      setReviews(Array.isArray(reviewList) ? reviewList : []);
      if (summaryRes.ok) setSummary(await summaryRes.json());
      if (gapsRes.ok) {
        const g = await gapsRes.json();
        setGaps(Array.isArray(g) ? g : []);
      }

      // Reviews list endpoint returns summaries only; the per-review detail
      // endpoint carries the nested findings + controls. Fan out and flatten.
      const details = await Promise.all(
        (Array.isArray(reviewList) ? reviewList : []).map((r: any) =>
          fetch(`${API_BASE}/reviews/${r.id}?org_id=${ORG_ID}`, { headers: getHeaders() })
            .then((d) => (d.ok ? d.json() : null))
            .catch(() => null)
        )
      );
      const allFindings: any[] = [];
      const allControls: any[] = [];
      details.filter(Boolean).forEach((d: any) => {
        (d.findings || []).forEach((f: any) => allFindings.push({ ...f, review_id: f.review_id || d.id }));
        (d.controls || []).forEach((c: any) => allControls.push({ ...c, review_id: c.review_id || d.id }));
      });
      setFindings(allFindings);
      setControls(allControls);
    } catch (e: any) {
      setError(e?.message || "Failed to load architecture reviews");
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadData();
  }, [loadData]);

  const saveReview = async () => {
    if (!newReview.review_name || !newReview.system_name) return;
    setSaving(true);
    try {
      const res = await fetch(`${API_BASE}/reviews?org_id=${ORG_ID}`, {
        method: "POST",
        headers: getHeaders(),
        body: JSON.stringify(newReview),
      });
      if (!res.ok) throw new Error(`Create failed (${res.status})`);
      setShowAddReview(false);
      setNewReview({ review_name: "", system_name: "", review_type: "threat-model", reviewer: "" });
      await loadData();
    } catch (e: any) {
      setError(e?.message || "Failed to create review");
    } finally {
      setSaving(false);
    }
  };

  const saveFinding = async () => {
    if (!newFinding.review_id || !newFinding.title || !newFinding.component) {
      setError("Select a review and provide a component + title for the finding");
      return;
    }
    setSaving(true);
    try {
      const { review_id, ...body } = newFinding;
      const res = await fetch(`${API_BASE}/reviews/${review_id}/findings?org_id=${ORG_ID}`, {
        method: "POST",
        headers: getHeaders(),
        body: JSON.stringify(body),
      });
      if (!res.ok) throw new Error(`Add finding failed (${res.status})`);
      setShowAddFinding(false);
      setNewFinding({ review_id: "", component: "", finding_type: "design-flaw", title: "", severity: "high", recommendation: "" });
      await loadData();
    } catch (e: any) {
      setError(e?.message || "Failed to add finding");
    } finally {
      setSaving(false);
    }
  };

  const completeReview = async (reviewId: string) => {
    try {
      const res = await fetch(`${API_BASE}/reviews/${reviewId}/complete?org_id=${ORG_ID}`, {
        method: "POST",
        headers: getHeaders(),
      });
      if (!res.ok) throw new Error(`Complete failed (${res.status})`);
      await loadData();
    } catch (e: any) {
      setError(e?.message || "Failed to complete review");
    }
  };

  const totalReviews = summary?.total_reviews ?? reviews.length;
  const criticalFindings = summary?.critical_finding_count ?? findings.filter((f) => f.severity === "critical").length;
  const avgScore = summary?.avg_score != null
    ? Math.round(summary.avg_score)
    : (reviews.length ? Math.round(reviews.reduce((a, r) => a + (r.overall_score || 0), 0) / reviews.length) : 0);
  const openControls = controls.filter((c) => c.implementation_status !== "implemented").length;

  const filteredFindings = filterReview === "all" ? findings : findings.filter((f) => f.review_id === filterReview);
  const filteredControls = filterReview === "all" ? controls : controls.filter((c) => c.review_id === filterReview);
  const gapControls = (gaps.length ? gaps : controls.filter((c) => c.implementation_status === "not_implemented"))
    .slice()
    .sort((a, b) => (a.effectiveness || 0) - (b.effectiveness || 0));

  if (loading) return <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div></div>;

  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6">
      <div className="max-w-7xl mx-auto">
        <div className="mb-6">
          <h1 className="text-2xl font-bold text-white">Architecture Security Reviews</h1>
          <p className="text-gray-400 text-sm mt-1">System design reviews, security findings, and control assessments</p>
        </div>

        {error && (
          <div className="mb-4 bg-red-900/40 border border-red-700 text-red-200 text-sm rounded px-4 py-2">{error}</div>
        )}

        {/* Summary Cards */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
          {[
            { label: "Total Reviews", value: totalReviews, color: "text-blue-400" },
            { label: "Critical Findings", value: criticalFindings, color: "text-red-400" },
            { label: "Avg Score", value: `${avgScore}/100`, color: "text-yellow-400" },
            { label: "Open Controls", value: openControls, color: "text-orange-400" },
          ].map(c => (
            <div key={c.label} className="bg-gray-800 rounded-lg p-6">
              <p className="text-gray-400 text-sm">{c.label}</p>
              <p className={`text-3xl font-bold mt-1 ${c.color}`}>{c.value}</p>
            </div>
          ))}
        </div>

        {/* Tabs */}
        <div className="flex gap-2 mb-4 border-b border-gray-700">
          {(["reviews", "findings", "controls", "gaps"] as const).map(t => (
            <button key={t} onClick={() => setActiveTab(t)}
              className={`px-4 py-2 text-sm font-medium capitalize transition-colors ${activeTab === t ? "border-b-2 border-blue-500 text-blue-400" : "text-gray-400 hover:text-gray-200"}`}>
              {t === "gaps" ? "Control Gaps" : t}
            </button>
          ))}
        </div>

        {/* Reviews Tab */}
        {activeTab === "reviews" && (
          <div className="bg-gray-800 rounded-lg overflow-hidden">
            <div className="flex justify-between items-center p-4 border-b border-gray-700">
              <h2 className="font-semibold">Architecture Reviews</h2>
              <button onClick={() => setShowAddReview(!showAddReview)} className="bg-blue-600 hover:bg-blue-700 text-white text-sm px-3 py-1 rounded">+ Add Review</button>
            </div>
            {showAddReview && (
              <div className="p-4 bg-gray-900 border-b border-gray-700 grid grid-cols-2 gap-3">
                <input className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm" placeholder="Review name" value={newReview.review_name} onChange={e => setNewReview({ ...newReview, review_name: e.target.value })} />
                <input className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm" placeholder="System name" value={newReview.system_name} onChange={e => setNewReview({ ...newReview, system_name: e.target.value })} />
                <select className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm" value={newReview.review_type} onChange={e => setNewReview({ ...newReview, review_type: e.target.value })}>
                  {REVIEW_TYPES.map(t => <option key={t} value={t}>{t.replace("-", " ")}</option>)}
                </select>
                <input className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm" placeholder="Reviewer" value={newReview.reviewer} onChange={e => setNewReview({ ...newReview, reviewer: e.target.value })} />
                <div className="col-span-2 flex gap-2">
                  <button disabled={saving} className="bg-green-600 hover:bg-green-700 disabled:opacity-50 text-white text-sm px-4 py-1.5 rounded" onClick={saveReview}>{saving ? "Saving…" : "Save Review"}</button>
                  <button className="bg-gray-600 hover:bg-gray-700 text-white text-sm px-4 py-1.5 rounded" onClick={() => setShowAddReview(false)}>Cancel</button>
                </div>
              </div>
            )}
            {reviews.length === 0 ? (
              <EmptyState title="No architecture reviews yet" hint="Create your first review to start tracking security findings and control assessments." />
            ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="bg-gray-900 text-gray-400">
                  <tr>{["Review Name", "System", "Type", "Reviewer", "Findings", "Critical", "Score", "Risk", "Status", "Action"].map(h => <th key={h} className="text-left px-4 py-2">{h}</th>)}</tr>
                </thead>
                <tbody className="divide-y divide-gray-700">
                  {reviews.map(r => (
                    <tr key={r.id} className="hover:bg-gray-750">
                      <td className="px-4 py-3 font-medium">{r.review_name}</td>
                      <td className="px-4 py-3 text-gray-400 font-mono text-xs">{r.system_name}</td>
                      <td className="px-4 py-3"><span className="bg-purple-700 text-purple-100 text-xs px-2 py-0.5 rounded">{(r.review_type || "").replace("-", " ")}</span></td>
                      <td className="px-4 py-3 text-gray-300">{r.reviewer || "—"}</td>
                      <td className="px-4 py-3"><span className="bg-gray-700 text-white text-xs px-2 py-0.5 rounded-full">{r.finding_count ?? 0}</span></td>
                      <td className="px-4 py-3">{(r.critical_count ?? 0) > 0 ? <span className="bg-red-600 text-white text-xs px-2 py-0.5 rounded-full">{r.critical_count}</span> : <span className="text-gray-500">—</span>}</td>
                      <td className="px-4 py-3 min-w-[120px]">
                        <div className="flex items-center gap-2">
                          <div className="flex-1 bg-gray-700 rounded-full h-2">
                            <div className={`h-2 rounded-full ${(r.overall_score || 0) >= 80 ? "bg-green-500" : (r.overall_score || 0) >= 60 ? "bg-yellow-500" : "bg-red-500"}`} style={{ width: `${r.overall_score || 0}%` }} />
                          </div>
                          <span className="text-xs text-gray-400 w-8">{r.overall_score ?? 0}</span>
                        </div>
                      </td>
                      <td className="px-4 py-3">{riskBadge(r.risk_level)}</td>
                      <td className="px-4 py-3">{statusBadge(r.status)}</td>
                      <td className="px-4 py-3">{r.status !== "completed" && <button onClick={() => completeReview(r.id)} className="bg-green-700 hover:bg-green-600 text-white text-xs px-2 py-1 rounded">Complete</button>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            )}
          </div>
        )}

        {/* Findings Tab */}
        {activeTab === "findings" && (
          <div className="bg-gray-800 rounded-lg overflow-hidden">
            <div className="flex justify-between items-center p-4 border-b border-gray-700">
              <div className="flex items-center gap-3">
                <h2 className="font-semibold">Findings</h2>
                <select className="bg-gray-700 border border-gray-600 rounded px-2 py-1 text-sm" value={filterReview} onChange={e => setFilterReview(e.target.value)}>
                  <option value="all">All Reviews</option>
                  {reviews.map(r => <option key={r.id} value={r.id}>{r.review_name}</option>)}
                </select>
              </div>
              <button onClick={() => setShowAddFinding(!showAddFinding)} className="bg-blue-600 hover:bg-blue-700 text-white text-sm px-3 py-1 rounded">+ Add Finding</button>
            </div>
            {showAddFinding && (
              <div className="p-4 bg-gray-900 border-b border-gray-700 grid grid-cols-2 gap-3">
                <select className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm" value={newFinding.review_id} onChange={e => setNewFinding({ ...newFinding, review_id: e.target.value })}>
                  <option value="">Select review…</option>
                  {reviews.map(r => <option key={r.id} value={r.id}>{r.review_name}</option>)}
                </select>
                <input className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm" placeholder="Component" value={newFinding.component} onChange={e => setNewFinding({ ...newFinding, component: e.target.value })} />
                <input className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm col-span-2" placeholder="Finding title" value={newFinding.title} onChange={e => setNewFinding({ ...newFinding, title: e.target.value })} />
                <select className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm" value={newFinding.finding_type} onChange={e => setNewFinding({ ...newFinding, finding_type: e.target.value })}>
                  {FINDING_TYPES.map(s => <option key={s} value={s}>{s.replace("-", " ")}</option>)}
                </select>
                <select className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm" value={newFinding.severity} onChange={e => setNewFinding({ ...newFinding, severity: e.target.value })}>
                  {["critical", "high", "medium", "low", "info"].map(s => <option key={s} value={s}>{s}</option>)}
                </select>
                <input className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm col-span-2" placeholder="Recommendation" value={newFinding.recommendation} onChange={e => setNewFinding({ ...newFinding, recommendation: e.target.value })} />
                <div className="col-span-2 flex gap-2">
                  <button disabled={saving} className="bg-green-600 hover:bg-green-700 disabled:opacity-50 text-white text-sm px-4 py-1.5 rounded" onClick={saveFinding}>{saving ? "Saving…" : "Save Finding"}</button>
                  <button className="bg-gray-600 hover:bg-gray-700 text-white text-sm px-4 py-1.5 rounded" onClick={() => setShowAddFinding(false)}>Cancel</button>
                </div>
              </div>
            )}
            {filteredFindings.length === 0 ? (
              <EmptyState title="No findings recorded" hint="Findings appear here once they are added to a review, or run a review to surface them." />
            ) : (
            <div className="divide-y divide-gray-700">
              {filteredFindings.map(f => (
                <div key={f.id} className="p-4 hover:bg-gray-750">
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="font-mono text-xs bg-gray-700 text-gray-300 px-2 py-0.5 rounded">{f.component}</span>
                        <span className="bg-indigo-700 text-indigo-100 text-xs px-2 py-0.5 rounded">{(f.finding_type || "").replace("-", " ")}</span>
                        {severityBadge(f.severity)}
                      </div>
                      <p className="font-medium text-sm">{f.title}</p>
                      {f.recommendation && <p className="text-gray-400 text-xs mt-1">Recommendation: {f.recommendation}</p>}
                    </div>
                    <div>{statusBadge(f.status)}</div>
                  </div>
                </div>
              ))}
            </div>
            )}
          </div>
        )}

        {/* Controls Tab */}
        {activeTab === "controls" && (
          <div className="bg-gray-800 rounded-lg overflow-hidden">
            <div className="flex items-center gap-3 p-4 border-b border-gray-700">
              <h2 className="font-semibold">Security Controls</h2>
              <select className="bg-gray-700 border border-gray-600 rounded px-2 py-1 text-sm" value={filterReview} onChange={e => setFilterReview(e.target.value)}>
                <option value="all">All Reviews</option>
                {reviews.map(r => <option key={r.id} value={r.id}>{r.review_name}</option>)}
              </select>
            </div>
            {filteredControls.length === 0 ? (
              <EmptyState title="No control assessments yet" hint="Control assessments are captured during a review and listed here once added." />
            ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="bg-gray-900 text-gray-400">
                  <tr>{["Control", "Domain", "Implementation", "Effectiveness", "Gaps"].map(h => <th key={h} className="text-left px-4 py-2">{h}</th>)}</tr>
                </thead>
                <tbody className="divide-y divide-gray-700">
                  {filteredControls.map(c => (
                    <tr key={c.id} className="hover:bg-gray-750">
                      <td className="px-4 py-3 font-medium">{c.control_name}</td>
                      <td className="px-4 py-3"><span className="bg-teal-700 text-teal-100 text-xs px-2 py-0.5 rounded">{(c.domain || "").replace("_", " ")}</span></td>
                      <td className="px-4 py-3">{implBadge(c.implementation_status)}</td>
                      <td className="px-4 py-3 min-w-[140px]">
                        <div className="flex items-center gap-2">
                          <div className="flex-1 bg-gray-700 rounded-full h-2">
                            <div className={`h-2 rounded-full ${(c.effectiveness || 0) >= 80 ? "bg-green-500" : (c.effectiveness || 0) >= 60 ? "bg-yellow-500" : "bg-red-500"}`} style={{ width: `${c.effectiveness || 0}%` }} />
                          </div>
                          <span className="text-xs text-gray-400 w-8">{c.effectiveness ?? 0}</span>
                        </div>
                      </td>
                      <td className="px-4 py-3 text-gray-400 text-xs">{c.gaps || <span className="text-green-500">None</span>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            )}
          </div>
        )}

        {/* Gaps Tab */}
        {activeTab === "gaps" && (
          <div className="bg-gray-800 rounded-lg overflow-hidden">
            <div className="p-4 border-b border-gray-700">
              <h2 className="font-semibold">Control Gaps — Not Implemented (sorted by effectiveness asc)</h2>
            </div>
            {gapControls.length === 0 ? (
              <EmptyState title="No control gaps" hint="No not-implemented controls were found across your reviews." />
            ) : (
            <div className="divide-y divide-gray-700">
              {gapControls.map(c => (
                <div key={c.id} className="p-4 flex items-center gap-4">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="font-medium">{c.control_name}</span>
                      <span className="bg-teal-700 text-teal-100 text-xs px-2 py-0.5 rounded">{(c.domain || "").replace("_", " ")}</span>
                      {implBadge(c.implementation_status)}
                    </div>
                    <p className="text-red-400 text-xs">{c.gaps}</p>
                  </div>
                  <div className="text-right">
                    <div className="text-xs text-gray-400 mb-1">Effectiveness</div>
                    <div className="flex items-center gap-2">
                      <div className="w-24 bg-gray-700 rounded-full h-2">
                        <div className="h-2 rounded-full bg-red-500" style={{ width: `${c.effectiveness || 0}%` }} />
                      </div>
                      <span className="text-red-400 font-bold text-sm">{c.effectiveness ?? 0}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
