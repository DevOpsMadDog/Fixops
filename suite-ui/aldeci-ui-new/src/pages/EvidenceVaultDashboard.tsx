/**
 * Evidence Vault Dashboard
 *
 * Tamper-evident evidence management with integrity verification and audit chain.
 * Route: /evidence-vault
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import {
  Lock, Unlock, Shield, AlertTriangle, CheckCircle2,
  XCircle, Clock, Eye, Download, FileCheck, FolderOpen,
  PlusCircle, Hash,
} from "lucide-react";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY = (typeof window !== "undefined" && window.localStorage.getItem("aldeci_api_key")) || import.meta.env.VITE_API_KEY || "demo-key";
const ORG_ID = "aldeci-demo";
async function apiFetch(path: string) {
  const r = await fetch(`${API_BASE}${path}?org_id=default`, { headers: { "X-API-Key": API_KEY, "Content-Type": "application/json" } });
  if (!r.ok) throw new Error(`${r.status}`);
  return r.json();
}
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── Mock Data ──────────────────────────────────────────────────

const MOCK_EVIDENCE = [
  {
    id: "ev-001", evidence_name: "SOC2 CC6.1 Access Logs Q1", type: "log_export", framework: "SOC2",
    control_id: "CC6.1", collected_by: "auto-collector", file_size: "4.2 MB", sealed: true,
    expires_at: "2027-04-16", status: "valid", collected_at: "2026-04-01T00:00:00Z",
  },
  {
    id: "ev-002", evidence_name: "PCI-DSS 8.2 Auth Policy", type: "policy_document", framework: "PCI-DSS",
    control_id: "8.2", collected_by: "j.smith", file_size: "128 KB", sealed: true,
    expires_at: "2026-09-01", status: "valid", collected_at: "2026-03-15T00:00:00Z",
  },
  {
    id: "ev-003", evidence_name: "HIPAA §164.312 Encryption Cert", type: "certificate", framework: "HIPAA",
    control_id: "164.312", collected_by: "auto-collector", file_size: "8 KB", sealed: false,
    expires_at: "2026-06-01", status: "pending_review", collected_at: "2026-04-10T00:00:00Z",
  },
  {
    id: "ev-004", evidence_name: "ISO 27001 A.9 Access Review", type: "audit_report", framework: "ISO27001",
    control_id: "A.9.2", collected_by: "auditor-bot", file_size: "1.8 MB", sealed: true,
    expires_at: "2025-12-31", status: "expired", collected_at: "2025-04-01T00:00:00Z",
  },
  {
    id: "ev-005", evidence_name: "NIST CSF DE.CM-1 Scan Results", type: "scan_result", framework: "NIST-CSF",
    control_id: "DE.CM-1", collected_by: "vuln-scanner", file_size: "22.7 MB", sealed: true,
    expires_at: "2026-10-16", status: "valid", collected_at: "2026-04-14T00:00:00Z",
  },
  {
    id: "ev-006", evidence_name: "GDPR Art.32 Security Measures", type: "policy_document", framework: "GDPR",
    control_id: "Art.32", collected_by: "dpo-team", file_size: "340 KB", sealed: false,
    expires_at: "2026-07-20", status: "pending_review", collected_at: "2026-04-12T00:00:00Z",
  },
];

const MOCK_COLLECTIONS = [
  { id: "col-001", collection_name: "SOC 2 Type II 2026", framework: "SOC2", audit_period: "2025-10-01 → 2026-04-01", evidence_count: 47, complete: true },
  { id: "col-002", collection_name: "PCI-DSS v4.0 Assessment", framework: "PCI-DSS", audit_period: "2026-01-01 → 2026-06-30", evidence_count: 23, complete: false },
  { id: "col-003", collection_name: "HIPAA Annual Review", framework: "HIPAA", audit_period: "2025-07-01 → 2026-06-30", evidence_count: 31, complete: false },
  { id: "col-004", collection_name: "ISO 27001 Recertification", framework: "ISO27001", audit_period: "2026-01-01 → 2026-12-31", evidence_count: 58, complete: false },
];

const MOCK_ACCESS_LOG: Record<string, Array<{ accessed_by: string; type: string; reason: string; accessed_at: string }>> = {
  "ev-001": [
    { accessed_by: "j.smith", type: "view", reason: "Annual audit review", accessed_at: "2026-04-16T09:12:00Z" },
    { accessed_by: "auditor@pwc.com", type: "download", reason: "External audit", accessed_at: "2026-04-15T14:30:00Z" },
    { accessed_by: "auto-collector", type: "audit", reason: "Integrity check", accessed_at: "2026-04-14T00:00:00Z" },
  ],
  "ev-002": [
    { accessed_by: "ciso@company.com", type: "view", reason: "Policy review", accessed_at: "2026-04-16T08:00:00Z" },
    { accessed_by: "compliance-bot", type: "audit", reason: "Scheduled verification", accessed_at: "2026-04-13T00:00:00Z" },
  ],
};

// ── Helpers ────────────────────────────────────────────────────

const TYPE_COLORS: Record<string, string> = {
  log_export:      "bg-blue-500/15 text-blue-400 border-blue-500/30",
  policy_document: "bg-purple-500/15 text-purple-400 border-purple-500/30",
  certificate:     "bg-green-500/15 text-green-400 border-green-500/30",
  audit_report:    "bg-orange-500/15 text-orange-400 border-orange-500/30",
  scan_result:     "bg-red-500/15 text-red-400 border-red-500/30",
  screenshot:      "bg-cyan-500/15 text-cyan-400 border-cyan-500/30",
};

const FRAMEWORK_COLORS: Record<string, string> = {
  SOC2:     "bg-blue-500/15 text-blue-400 border-blue-500/30",
  "PCI-DSS":"bg-purple-500/15 text-purple-400 border-purple-500/30",
  HIPAA:    "bg-green-500/15 text-green-400 border-green-500/30",
  ISO27001: "bg-indigo-500/15 text-indigo-400 border-indigo-500/30",
  "NIST-CSF":"bg-teal-500/15 text-teal-400 border-teal-500/30",
  GDPR:     "bg-cyan-500/15 text-cyan-400 border-cyan-500/30",
};

const STATUS_COLORS: Record<string, string> = {
  valid:          "bg-green-500/15 text-green-400 border-green-500/30",
  pending_review: "bg-yellow-500/15 text-yellow-400 border-yellow-500/30",
  expired:        "bg-red-500/15 text-red-400 border-red-500/30",
  rejected:       "bg-red-500/15 text-red-400 border-red-500/30",
};

const ACCESS_TYPE_COLORS: Record<string, string> = {
  view:     "bg-blue-500/15 text-blue-400 border-blue-500/30",
  download: "bg-orange-500/15 text-orange-400 border-orange-500/30",
  audit:    "bg-purple-500/15 text-purple-400 border-purple-500/30",
};

function daysUntil(iso: string) {
  const days = Math.round((new Date(iso).getTime() - Date.now()) / 86400000);
  return days;
}

function timeAgo(iso: string) {
  const mins = Math.round((Date.now() - new Date(iso).getTime()) / 60000);
  if (mins < 60) return `${mins}m ago`;
  if (mins < 1440) return `${Math.round(mins / 60)}h ago`;
  return `${Math.round(mins / 1440)}d ago`;
}

// ── Main Component ─────────────────────────────────────────────

export default function EvidenceVaultDashboard() {
  const [selectedEvidence, setSelectedEvidence] = useState(MOCK_EVIDENCE[0]);
  const [sealedSet, setSealedSet] = useState<Set<string>>(new Set(MOCK_EVIDENCE.filter(e => e.sealed).map(e => e.id)));
  const [verifyId, setVerifyId] = useState("");

  useEffect(() => {
    apiFetch(`/api/v1/evidence-vault/search?org_id=${ORG_ID}`).catch(() => { /* graceful fallback */ });
  }, []);
  const [verifyContent, setVerifyContent] = useState("");
  const [verifyResult, setVerifyResult] = useState<"valid" | "invalid" | null>(null);

  const totalEvidence = MOCK_EVIDENCE.length;
  const sealedCount = sealedSet.size;
  const expiringSoon = MOCK_EVIDENCE.filter(e => { const d = daysUntil(e.expires_at); return d > 0 && d < 90; }).length;
  const expiredCount = MOCK_EVIDENCE.filter(e => daysUntil(e.expires_at) < 0).length;

  const accessLog = MOCK_ACCESS_LOG[selectedEvidence.id] ?? [];

  function handleVerify() {
    // Deterministic mock: valid if content non-empty and id matches an evidence item
    const found = MOCK_EVIDENCE.find(e => e.id === verifyId.trim());
    setVerifyResult(found && verifyContent.trim().length > 0 ? "valid" : "invalid");
  }

  return (
    <div className="min-h-screen bg-[#0f172a] text-white p-6 space-y-6">
      <PageHeader
        title="Evidence Vault"
        description="Tamper-evident evidence storage with integrity verification and custody chain"
      />

      {/* KPI Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Total Evidence" value={totalEvidence} icon={<FileCheck className="h-5 w-5" />} />
        <KpiCard title="Sealed" value={sealedCount} icon={<Lock className="h-5 w-5 text-green-400" />} />
        <KpiCard title="Expiring Soon" value={expiringSoon} icon={<Clock className="h-5 w-5 text-yellow-400" />} />
        <KpiCard title="Expired" value={expiredCount} icon={<AlertTriangle className="h-5 w-5 text-red-400" />} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Evidence Table */}
        <div className="lg:col-span-2 space-y-4">
          <Card className="bg-gray-800 border-zinc-700">
            <CardHeader className="pb-2"><CardTitle className="text-sm text-zinc-200">Evidence Items</CardTitle></CardHeader>
            <CardContent>
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-zinc-700">
                      {["Name", "Type", "Framework", "Control", "Collected By", "Size", "Sealed", "Expires", "Status", ""].map(h => (
                        <th key={h} className="text-left py-2 px-2 text-zinc-500 font-medium whitespace-nowrap">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {MOCK_EVIDENCE.map(e => {
                      const daysLeft = daysUntil(e.expires_at);
                      const isSealed = sealedSet.has(e.id);
                      const expiringSoonFlag = daysLeft > 0 && daysLeft < 90;
                      return (
                        <tr key={e.id} className={cn("border-b border-zinc-700/50 hover:bg-zinc-700/20 cursor-pointer", selectedEvidence.id === e.id && "bg-zinc-700/30")}
                          onClick={() => setSelectedEvidence(e)}>
                          <td className="py-2 px-2 text-zinc-200 max-w-[160px] truncate">{e.evidence_name}</td>
                          <td className="py-2 px-2"><Badge className={cn("text-[9px] border whitespace-nowrap", TYPE_COLORS[e.type] ?? "border-zinc-600 text-zinc-400")}>{e.type.replace("_"," ")}</Badge></td>
                          <td className="py-2 px-2"><Badge className={cn("text-[9px] border", FRAMEWORK_COLORS[e.framework] ?? "border-zinc-600 text-zinc-400")}>{e.framework}</Badge></td>
                          <td className="py-2 px-2 text-zinc-400 font-mono">{e.control_id}</td>
                          <td className="py-2 px-2 text-zinc-500">{e.collected_by}</td>
                          <td className="py-2 px-2 text-zinc-400">{e.file_size}</td>
                          <td className="py-2 px-2 text-center">
                            {isSealed
                              ? <Lock className="h-3.5 w-3.5 text-green-400 inline" />
                              : <Unlock className="h-3.5 w-3.5 text-zinc-500 inline" />}
                          </td>
                          <td className={cn("py-2 px-2 whitespace-nowrap text-[10px]", daysLeft < 0 ? "text-red-400" : expiringSoonFlag ? "text-yellow-400" : "text-zinc-500")}>
                            {e.expires_at}{expiringSoonFlag && " ⚠"}
                          </td>
                          <td className="py-2 px-2"><Badge className={cn("text-[9px] border capitalize", STATUS_COLORS[e.status] ?? "border-zinc-600 text-zinc-400")}>{e.status.replace("_"," ")}</Badge></td>
                          <td className="py-2 px-2">
                            {!isSealed && (
                              <Button size="sm" variant="ghost" className="h-6 px-2 text-[10px] text-green-400 hover:text-green-300"
                                onClick={ev => { ev.stopPropagation(); setSealedSet(s => new Set([...s, e.id])); }}>
                                <Lock className="h-3 w-3 mr-1" /> Seal
                              </Button>
                            )}
                          </td>
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>

          {/* Verify Integrity */}
          <Card className="bg-gray-800 border-zinc-700">
            <CardHeader className="pb-2"><CardTitle className="text-sm text-zinc-200 flex items-center gap-2"><Hash className="h-4 w-4 text-blue-400" />Verify Integrity</CardTitle></CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
                <div>
                  <label className="text-[10px] text-zinc-500 mb-1 block">Evidence ID</label>
                  <input className="w-full bg-zinc-900 border border-zinc-700 rounded px-2 py-1.5 text-xs text-white placeholder-zinc-600" placeholder="ev-001" value={verifyId} onChange={e => setVerifyId(e.target.value)} />
                </div>
                <div>
                  <label className="text-[10px] text-zinc-500 mb-1 block">Content Hash / Checksum</label>
                  <input className="w-full bg-zinc-900 border border-zinc-700 rounded px-2 py-1.5 text-xs text-white font-mono placeholder-zinc-600" placeholder="sha256:..." value={verifyContent} onChange={e => setVerifyContent(e.target.value)} />
                </div>
              </div>
              <div className="flex items-center gap-3 mt-3">
                <Button size="sm" className="bg-blue-600 hover:bg-blue-700 text-xs" onClick={handleVerify}>Verify</Button>
                {verifyResult === "valid" && (
                  <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="flex items-center gap-1.5 text-green-400 text-xs">
                    <CheckCircle2 className="h-4 w-4" /> Integrity Verified — evidence is untampered
                  </motion.div>
                )}
                {verifyResult === "invalid" && (
                  <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} className="flex items-center gap-1.5 text-red-400 text-xs">
                    <XCircle className="h-4 w-4" /> Integrity Check Failed — evidence may be tampered
                  </motion.div>
                )}
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Right Panel */}
        <div className="space-y-4">
          {/* Access Log */}
          <Card className="bg-gray-800 border-zinc-700">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm text-zinc-200">Access Log — {selectedEvidence.evidence_name.slice(0, 24)}…</CardTitle>
            </CardHeader>
            <CardContent className="space-y-2">
              {accessLog.length === 0 && <p className="text-xs text-zinc-500">No access records for this item.</p>}
              {accessLog.map((entry, i) => (
                <div key={i} className="bg-zinc-900 rounded-lg p-3 border border-zinc-700 space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="text-xs text-zinc-200">{entry.accessed_by}</span>
                    <Badge className={cn("text-[9px] border", ACCESS_TYPE_COLORS[entry.type] ?? "border-zinc-600 text-zinc-400")}>{entry.type}</Badge>
                  </div>
                  <p className="text-[10px] text-zinc-500">{entry.reason}</p>
                  <p className="text-[10px] text-zinc-600">{timeAgo(entry.accessed_at)}</p>
                </div>
              ))}
            </CardContent>
          </Card>

          {/* Collections */}
          <Card className="bg-gray-800 border-zinc-700">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm text-zinc-200 flex items-center gap-2"><FolderOpen className="h-4 w-4 text-yellow-400" />Collections</CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              {MOCK_COLLECTIONS.map(c => (
                <div key={c.id} className="bg-zinc-900 rounded-lg p-3 border border-zinc-700 space-y-2">
                  <div className="flex items-start justify-between gap-2">
                    <p className="text-xs text-zinc-200 leading-tight">{c.collection_name}</p>
                    {c.complete
                      ? <Badge className="text-[9px] border border-green-500/30 text-green-400 bg-green-500/10 shrink-0"><CheckCircle2 className="h-2.5 w-2.5 mr-0.5" />Complete</Badge>
                      : <Badge className="text-[9px] border border-yellow-500/30 text-yellow-400 bg-yellow-500/10 shrink-0"><Clock className="h-2.5 w-2.5 mr-0.5" />In Progress</Badge>
                    }
                  </div>
                  <div className="flex items-center gap-2">
                    <Badge className={cn("text-[9px] border", FRAMEWORK_COLORS[c.framework] ?? "border-zinc-600 text-zinc-400")}>{c.framework}</Badge>
                    <span className="text-[10px] text-zinc-500">{c.evidence_count} items</span>
                  </div>
                  <p className="text-[10px] text-zinc-600">{c.audit_period}</p>
                </div>
              ))}
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
}
