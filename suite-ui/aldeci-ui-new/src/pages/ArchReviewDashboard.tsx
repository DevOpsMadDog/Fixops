import { useState, useEffect } from "react";

const API_BASE = "/api/v1/arch-review";
const getHeaders = () => ({ "X-API-Key": localStorage.getItem("apiKey") || "" });

const reviews = [
  { id: "rev-001", review_name: "Payment Service Architecture Review", system_name: "payment-svc", review_type: "threat_model", reviewer: "Alice Chen", finding_count: 8, critical_count: 2, overall_score: 62, risk_level: "high", status: "completed" },
  { id: "rev-002", review_name: "API Gateway Security Review", system_name: "api-gateway", review_type: "security_design", reviewer: "Bob Martinez", finding_count: 5, critical_count: 0, overall_score: 81, risk_level: "medium", status: "completed" },
  { id: "rev-003", review_name: "Auth Service Review", system_name: "auth-svc", review_type: "code_review", reviewer: "Carol Patel", finding_count: 12, critical_count: 3, overall_score: 48, risk_level: "critical", status: "in_progress" },
  { id: "rev-004", review_name: "Data Lake Architecture Review", system_name: "data-lake", review_type: "compliance_review", reviewer: "Dan Kim", finding_count: 3, critical_count: 0, overall_score: 90, risk_level: "low", status: "completed" },
  { id: "rev-005", review_name: "Microservices Mesh Review", system_name: "service-mesh", review_type: "threat_model", reviewer: "Eva Singh", finding_count: 7, critical_count: 1, overall_score: 70, risk_level: "high", status: "draft" },
];

const findings = [
  { id: "f-001", review_id: "rev-001", component: "TokenProcessor", finding_type: "injection", title: "SQL injection in token validation", severity: "critical", recommendation: "Use parameterized queries for all DB calls.", status: "open" },
  { id: "f-002", review_id: "rev-001", component: "SessionHandler", finding_type: "auth_bypass", title: "Session fixation vulnerability", severity: "high", recommendation: "Regenerate session ID on privilege escalation.", status: "open" },
  { id: "f-003", review_id: "rev-002", component: "RateLimiter", finding_type: "misconfiguration", title: "Rate limiting too permissive", severity: "medium", recommendation: "Reduce threshold to 100 req/min per IP.", status: "remediated" },
  { id: "f-004", review_id: "rev-003", component: "JWTValidator", finding_type: "crypto_weakness", title: "Algorithm confusion attack possible", severity: "critical", recommendation: "Pin algorithm to RS256, reject none/HS256.", status: "open" },
  { id: "f-005", review_id: "rev-003", component: "UserStore", finding_type: "data_exposure", title: "PII returned in error messages", severity: "high", recommendation: "Strip sensitive fields from error payloads.", status: "open" },
  { id: "f-006", review_id: "rev-005", component: "ServiceMesh", finding_type: "missing_control", title: "mTLS not enforced on all east-west traffic", severity: "medium", recommendation: "Enable strict mTLS in Istio PeerAuthentication.", status: "open" },
];

const controls = [
  { id: "c-001", review_id: "rev-001", control_name: "Input Validation", domain: "application_security", implementation_status: "partial", effectiveness: 55, gaps: "Missing validation on 3 API endpoints" },
  { id: "c-002", review_id: "rev-001", control_name: "Encryption at Rest", domain: "data_protection", implementation_status: "implemented", effectiveness: 90, gaps: "" },
  { id: "c-003", review_id: "rev-002", control_name: "API Authentication", domain: "identity", implementation_status: "implemented", effectiveness: 85, gaps: "" },
  { id: "c-004", review_id: "rev-003", control_name: "Secrets Management", domain: "key_management", implementation_status: "not_implemented", effectiveness: 20, gaps: "Hardcoded secrets found in 4 config files" },
  { id: "c-005", review_id: "rev-003", control_name: "Audit Logging", domain: "logging", implementation_status: "partial", effectiveness: 60, gaps: "Auth events not logged" },
  { id: "c-006", review_id: "rev-004", control_name: "Data Classification", domain: "data_protection", implementation_status: "compensating", effectiveness: 75, gaps: "Manual tagging instead of automated" },
  { id: "c-007", review_id: "rev-005", control_name: "Network Segmentation", domain: "network_security", implementation_status: "not_implemented", effectiveness: 15, gaps: "All services in flat network" },
];

const riskBadge = (level: string) => {
  const map: Record<string, string> = { critical: "bg-red-600", high: "bg-orange-500", medium: "bg-yellow-500", low: "bg-green-600" };
  return <span className={`${map[level] || "bg-gray-600"} text-white text-xs px-2 py-0.5 rounded-full`}>{level}</span>;
};

const statusBadge = (s: string) => {
  const map: Record<string, string> = { draft: "bg-gray-600", in_progress: "bg-blue-600", completed: "bg-green-600", open: "bg-red-500", remediated: "bg-green-600" };
  return <span className={`${map[s] || "bg-gray-600"} text-white text-xs px-2 py-0.5 rounded`}>{s.replace("_", " ")}</span>;
};

const severityBadge = (s: string) => {
  const map: Record<string, string> = { critical: "bg-red-600", high: "bg-orange-500", medium: "bg-yellow-500", low: "bg-green-600", info: "bg-blue-500" };
  return <span className={`${map[s] || "bg-gray-600"} text-white text-xs px-2 py-0.5 rounded`}>{s}</span>;
};

const implBadge = (s: string) => {
  const map: Record<string, string> = { implemented: "bg-green-600", partial: "bg-yellow-500", not_implemented: "bg-red-600", compensating: "bg-blue-500" };
  return <span className={`${map[s] || "bg-gray-600"} text-white text-xs px-2 py-0.5 rounded`}>{s.replace("_", " ")}</span>;
};

export default function ArchReviewDashboard() {
  const [activeTab, setActiveTab] = useState<"reviews" | "findings" | "controls" | "gaps">("reviews");
  const [loading, setLoading] = useState(true);
  const [filterReview, setFilterReview] = useState("all");
  const [showAddReview, setShowAddReview] = useState(false);
  const [showAddFinding, setShowAddFinding] = useState(false);
  const [newReview, setNewReview] = useState({ review_name: "", system_name: "", review_type: "threat_model", reviewer: "" });
  const [newFinding, setNewFinding] = useState({ review_id: "rev-001", component: "", finding_type: "injection", title: "", severity: "high", recommendation: "" });
  const [liveReviews, setLiveReviews] = useState(reviews);
  const [liveFindings, setLiveFindings] = useState(findings);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    fetch(`${API_BASE}/reviews?org_id=default`, { headers: getHeaders() })
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(d => { if (Array.isArray(d)) setLiveReviews(d); })
      .catch((e) => setError(e?.message || 'Failed to load data'));
    fetch(`${API_BASE}/control-gaps?org_id=default`, { headers: getHeaders() })
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(d => { if (Array.isArray(d)) setLiveFindings(d); })
      .catch((e) => setError(e?.message || 'Failed to load data'));
    setLoading(false);
  }, []);

  const totalReviews = reviews.length;
  const criticalFindings = findings.filter(f => f.severity === "critical").length;
  const avgScore = Math.round(reviews.reduce((a, r) => a + r.overall_score, 0) / reviews.length);
  const openControls = controls.filter(c => c.implementation_status !== "implemented").length;

  const filteredFindings = filterReview === "all" ? findings : findings.filter(f => f.review_id === filterReview);
  const filteredControls = filterReview === "all" ? controls : controls.filter(c => c.review_id === filterReview);
  const gapControls = controls.filter(c => c.implementation_status === "not_implemented").sort((a, b) => a.effectiveness - b.effectiveness);


  if (loading) return <div className="flex items-center justify-center h-64"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500"></div></div>;


  return (
    <div className="min-h-screen bg-[#0f172a] text-gray-100 p-6">
      <div className="max-w-7xl mx-auto">
        <div className="mb-6">
          <h1 className="text-2xl font-bold text-white">Architecture Security Reviews</h1>
          <p className="text-gray-400 text-sm mt-1">System design reviews, security findings, and control assessments</p>
        </div>

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
                  <option value="threat_model">Threat Model</option>
                  <option value="security_design">Security Design</option>
                  <option value="code_review">Code Review</option>
                  <option value="compliance_review">Compliance Review</option>
                </select>
                <input className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm" placeholder="Reviewer" value={newReview.reviewer} onChange={e => setNewReview({ ...newReview, reviewer: e.target.value })} />
                <div className="col-span-2 flex gap-2">
                  <button className="bg-green-600 hover:bg-green-700 text-white text-sm px-4 py-1.5 rounded" onClick={() => setShowAddReview(false)}>Save Review</button>
                  <button className="bg-gray-600 hover:bg-gray-700 text-white text-sm px-4 py-1.5 rounded" onClick={() => setShowAddReview(false)}>Cancel</button>
                </div>
              </div>
            )}
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
                      <td className="px-4 py-3"><span className="bg-purple-700 text-purple-100 text-xs px-2 py-0.5 rounded">{r.review_type.replace("_", " ")}</span></td>
                      <td className="px-4 py-3 text-gray-300">{r.reviewer}</td>
                      <td className="px-4 py-3"><span className="bg-gray-700 text-white text-xs px-2 py-0.5 rounded-full">{r.finding_count}</span></td>
                      <td className="px-4 py-3">{r.critical_count > 0 ? <span className="bg-red-600 text-white text-xs px-2 py-0.5 rounded-full">{r.critical_count}</span> : <span className="text-gray-500">—</span>}</td>
                      <td className="px-4 py-3 min-w-[120px]">
                        <div className="flex items-center gap-2">
                          <div className="flex-1 bg-gray-700 rounded-full h-2">
                            <div className={`h-2 rounded-full ${r.overall_score >= 80 ? "bg-green-500" : r.overall_score >= 60 ? "bg-yellow-500" : "bg-red-500"}`} style={{ width: `${r.overall_score}%` }} />
                          </div>
                          <span className="text-xs text-gray-400 w-8">{r.overall_score}</span>
                        </div>
                      </td>
                      <td className="px-4 py-3">{riskBadge(r.risk_level)}</td>
                      <td className="px-4 py-3">{statusBadge(r.status)}</td>
                      <td className="px-4 py-3">{r.status !== "completed" && <button className="bg-green-700 hover:bg-green-600 text-white text-xs px-2 py-1 rounded">Complete</button>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
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
                  {reviews.map(r => <option key={r.id} value={r.id}>{r.review_name}</option>)}
                </select>
                <input className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm" placeholder="Component" value={newFinding.component} onChange={e => setNewFinding({ ...newFinding, component: e.target.value })} />
                <input className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm col-span-2" placeholder="Finding title" value={newFinding.title} onChange={e => setNewFinding({ ...newFinding, title: e.target.value })} />
                <select className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm" value={newFinding.severity} onChange={e => setNewFinding({ ...newFinding, severity: e.target.value })}>
                  {["critical", "high", "medium", "low"].map(s => <option key={s} value={s}>{s}</option>)}
                </select>
                <input className="bg-gray-800 border border-gray-600 rounded px-3 py-1.5 text-sm" placeholder="Recommendation" value={newFinding.recommendation} onChange={e => setNewFinding({ ...newFinding, recommendation: e.target.value })} />
                <div className="col-span-2 flex gap-2">
                  <button className="bg-green-600 hover:bg-green-700 text-white text-sm px-4 py-1.5 rounded" onClick={() => setShowAddFinding(false)}>Save Finding</button>
                  <button className="bg-gray-600 hover:bg-gray-700 text-white text-sm px-4 py-1.5 rounded" onClick={() => setShowAddFinding(false)}>Cancel</button>
                </div>
              </div>
            )}
            <div className="divide-y divide-gray-700">
              {filteredFindings.map(f => (
                <div key={f.id} className="p-4 hover:bg-gray-750">
                  <div className="flex items-start justify-between gap-4">
                    <div className="flex-1">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="font-mono text-xs bg-gray-700 text-gray-300 px-2 py-0.5 rounded">{f.component}</span>
                        <span className="bg-indigo-700 text-indigo-100 text-xs px-2 py-0.5 rounded">{f.finding_type.replace("_", " ")}</span>
                        {severityBadge(f.severity)}
                      </div>
                      <p className="font-medium text-sm">{f.title}</p>
                      <p className="text-gray-400 text-xs mt-1">Recommendation: {f.recommendation}</p>
                    </div>
                    <div>{statusBadge(f.status)}</div>
                  </div>
                </div>
              ))}
            </div>
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
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="bg-gray-900 text-gray-400">
                  <tr>{["Control", "Domain", "Implementation", "Effectiveness", "Gaps"].map(h => <th key={h} className="text-left px-4 py-2">{h}</th>)}</tr>
                </thead>
                <tbody className="divide-y divide-gray-700">
                  {filteredControls.map(c => (
                    <tr key={c.id} className="hover:bg-gray-750">
                      <td className="px-4 py-3 font-medium">{c.control_name}</td>
                      <td className="px-4 py-3"><span className="bg-teal-700 text-teal-100 text-xs px-2 py-0.5 rounded">{c.domain.replace("_", " ")}</span></td>
                      <td className="px-4 py-3">{implBadge(c.implementation_status)}</td>
                      <td className="px-4 py-3 min-w-[140px]">
                        <div className="flex items-center gap-2">
                          <div className="flex-1 bg-gray-700 rounded-full h-2">
                            <div className={`h-2 rounded-full ${c.effectiveness >= 80 ? "bg-green-500" : c.effectiveness >= 60 ? "bg-yellow-500" : "bg-red-500"}`} style={{ width: `${c.effectiveness}%` }} />
                          </div>
                          <span className="text-xs text-gray-400 w-8">{c.effectiveness}</span>
                        </div>
                      </td>
                      <td className="px-4 py-3 text-gray-400 text-xs">{c.gaps || <span className="text-green-500">None</span>}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Gaps Tab */}
        {activeTab === "gaps" && (
          <div className="bg-gray-800 rounded-lg overflow-hidden">
            <div className="p-4 border-b border-gray-700">
              <h2 className="font-semibold">Control Gaps — Not Implemented (sorted by effectiveness asc)</h2>
            </div>
            <div className="divide-y divide-gray-700">
              {gapControls.map(c => (
                <div key={c.id} className="p-4 flex items-center gap-4">
                  <div className="flex-1">
                    <div className="flex items-center gap-2 mb-1">
                      <span className="font-medium">{c.control_name}</span>
                      <span className="bg-teal-700 text-teal-100 text-xs px-2 py-0.5 rounded">{c.domain.replace("_", " ")}</span>
                      {implBadge(c.implementation_status)}
                    </div>
                    <p className="text-red-400 text-xs">{c.gaps}</p>
                  </div>
                  <div className="text-right">
                    <div className="text-xs text-gray-400 mb-1">Effectiveness</div>
                    <div className="flex items-center gap-2">
                      <div className="w-24 bg-gray-700 rounded-full h-2">
                        <div className="h-2 rounded-full bg-red-500" style={{ width: `${c.effectiveness}%` }} />
                      </div>
                      <span className="text-red-400 font-bold text-sm">{c.effectiveness}</span>
                    </div>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
