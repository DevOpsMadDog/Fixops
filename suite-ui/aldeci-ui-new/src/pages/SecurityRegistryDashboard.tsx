/**
 * Security Registry Dashboard
 *
 * Artifact registry for policies, procedures, standards, guidelines, runbooks,
 * playbooks, templates, and checklists.
 *   1. KPIs: Total Artifacts, Active, Pending Review, Deprecated
 *   2. Registry table with status badges and review history
 *   3. Registry stats by artifact type
 *   4. Recent reviews feed
 *
 * Route: /security-registry
 * API: GET /api/v1/security-registry
 */

import { useState } from "react";
import { motion } from "framer-motion";
import { BookOpen, CheckCircle2, Clock, Archive, RefreshCw, FileText, BookMarked, ClipboardList } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── Types ──────────────────────────────────────────────────────

type ArtifactType = "policy" | "procedure" | "standard" | "guideline" | "runbook" | "playbook" | "template" | "checklist";
type ArtifactStatus = "draft" | "review" | "active" | "deprecated";

interface RegistryArtifact {
  id: string;
  title: string;
  artifact_type: ArtifactType;
  status: ArtifactStatus;
  version: string;
  owner: string;
  last_reviewed: string;
  next_review: string;
  review_count: number;
  tags: string[];
}

// ── Mock data ──────────────────────────────────────────────────

const MOCK_ARTIFACTS: RegistryArtifact[] = [
  { id: "reg-001", title: "Information Security Policy",           artifact_type: "policy",    status: "active",     version: "3.2", owner: "CISO",           last_reviewed: "2026-03-01", next_review: "2026-09-01", review_count: 12, tags: ["iso27001", "soc2"] },
  { id: "reg-002", title: "Incident Response Procedure",           artifact_type: "procedure", status: "active",     version: "2.1", owner: "SOC Lead",        last_reviewed: "2026-02-15", next_review: "2026-08-15", review_count: 8,  tags: ["incident", "soc"] },
  { id: "reg-003", title: "Encryption Standard AES-256",           artifact_type: "standard",  status: "active",     version: "1.4", owner: "Crypto Team",     last_reviewed: "2026-01-10", next_review: "2026-07-10", review_count: 5,  tags: ["crypto", "pci"] },
  { id: "reg-004", title: "Secure Coding Guidelines",              artifact_type: "guideline", status: "review",     version: "2.0", owner: "AppSec",          last_reviewed: "2025-11-20", next_review: "2026-05-20", review_count: 7,  tags: ["devsecops", "appsec"] },
  { id: "reg-005", title: "K8s Cluster Hardening Runbook",         artifact_type: "runbook",   status: "active",     version: "1.1", owner: "Platform Eng",   last_reviewed: "2026-04-01", next_review: "2026-10-01", review_count: 3,  tags: ["kubernetes", "hardening"] },
  { id: "reg-006", title: "Ransomware Response Playbook",          artifact_type: "playbook",  status: "active",     version: "1.3", owner: "IR Team",         last_reviewed: "2026-03-20", next_review: "2026-09-20", review_count: 6,  tags: ["ransomware", "incident"] },
  { id: "reg-007", title: "Cloud Security Assessment Template",     artifact_type: "template",  status: "active",     version: "2.0", owner: "Cloud Security",  last_reviewed: "2026-02-01", next_review: "2026-08-01", review_count: 4,  tags: ["cloud", "assessment"] },
  { id: "reg-008", title: "Vendor Security Assessment Checklist",  artifact_type: "checklist", status: "active",     version: "1.6", owner: "Procurement",     last_reviewed: "2026-03-10", next_review: "2026-09-10", review_count: 9,  tags: ["vendor", "third-party"] },
  { id: "reg-009", title: "BYOD Acceptable Use Policy",            artifact_type: "policy",    status: "review",     version: "2.1", owner: "HR / Security",   last_reviewed: "2025-10-01", next_review: "2026-04-01", review_count: 11, tags: ["byod", "mobile"] },
  { id: "reg-010", title: "Legacy Access Control Policy v1",       artifact_type: "policy",    status: "deprecated", version: "1.0", owner: "IAM Team",        last_reviewed: "2024-01-01", next_review: "N/A",        review_count: 15, tags: ["iam", "legacy"] },
  { id: "reg-011", title: "AWS Hardening Runbook",                 artifact_type: "runbook",   status: "active",     version: "1.0", owner: "Cloud Ops",       last_reviewed: "2026-04-10", next_review: "2026-10-10", review_count: 2,  tags: ["aws", "cloud"] },
  { id: "reg-012", title: "Penetration Test Report Template",      artifact_type: "template",  status: "draft",      version: "0.9", owner: "Red Team",        last_reviewed: "2026-04-14", next_review: "2026-04-30", review_count: 1,  tags: ["pentest", "report"] },
];

const TYPE_STATS: { type: ArtifactType; count: number; icon: React.ReactNode; color: string }[] = [
  { type: "policy",    count: 3,  icon: <BookOpen className="w-4 h-4" />,      color: "text-blue-400" },
  { type: "procedure", count: 1,  icon: <ClipboardList className="w-4 h-4" />, color: "text-purple-400" },
  { type: "standard",  count: 1,  icon: <FileText className="w-4 h-4" />,      color: "text-cyan-400" },
  { type: "guideline", count: 1,  icon: <BookMarked className="w-4 h-4" />,    color: "text-yellow-400" },
  { type: "runbook",   count: 2,  icon: <FileText className="w-4 h-4" />,      color: "text-green-400" },
  { type: "playbook",  count: 1,  icon: <BookOpen className="w-4 h-4" />,      color: "text-red-400" },
  { type: "template",  count: 2,  icon: <FileText className="w-4 h-4" />,      color: "text-orange-400" },
  { type: "checklist", count: 1,  icon: <CheckCircle2 className="w-4 h-4" />,  color: "text-teal-400" },
];

// ── Helpers ────────────────────────────────────────────────────

const STATUS_CONFIG: Record<ArtifactStatus, { cls: string; label: string }> = {
  active:     { cls: "bg-green-500/10 text-green-400 border-green-500/20",   label: "Active" },
  review:     { cls: "bg-yellow-500/10 text-yellow-400 border-yellow-500/20", label: "In Review" },
  draft:      { cls: "bg-gray-500/10 text-gray-400 border-gray-500/20",       label: "Draft" },
  deprecated: { cls: "bg-red-500/10 text-red-400 border-red-500/20",          label: "Deprecated" },
};

const TYPE_COLORS: Record<ArtifactType, string> = {
  policy:    "bg-blue-500/10 text-blue-400",
  procedure: "bg-purple-500/10 text-purple-400",
  standard:  "bg-cyan-500/10 text-cyan-400",
  guideline: "bg-yellow-500/10 text-yellow-400",
  runbook:   "bg-green-500/10 text-green-400",
  playbook:  "bg-red-500/10 text-red-400",
  template:  "bg-orange-500/10 text-orange-400",
  checklist: "bg-teal-500/10 text-teal-400",
};

function StatusBadge({ status }: { status: ArtifactStatus }) {
  const { cls, label } = STATUS_CONFIG[status];
  return <Badge className={cn("border text-xs", cls)}>{label}</Badge>;
}

function TypeBadge({ type }: { type: ArtifactType }) {
  return (
    <span className={cn("inline-block px-2 py-0.5 rounded text-xs font-medium capitalize", TYPE_COLORS[type])}>
      {type}
    </span>
  );
}

// ── Main Component ─────────────────────────────────────────────

export default function SecurityRegistryDashboard() {
  const [filterStatus, setFilterStatus] = useState<ArtifactStatus | "all">("all");

  const filtered = filterStatus === "all"
    ? MOCK_ARTIFACTS
    : MOCK_ARTIFACTS.filter((a) => a.status === filterStatus);

  const totalArtifacts = MOCK_ARTIFACTS.length;
  const activeCount = MOCK_ARTIFACTS.filter((a) => a.status === "active").length;
  const pendingReview = MOCK_ARTIFACTS.filter((a) => a.status === "review").length;
  const deprecatedCount = MOCK_ARTIFACTS.filter((a) => a.status === "deprecated").length;

  return (
    <div className="flex flex-col gap-6 p-6 min-h-0">
      <PageHeader
        title="Security Registry"
        description="Centralized artifact registry for policies, procedures, standards, runbooks, and playbooks"
        badge="Live"
        actions={
          <Button size="sm" variant="outline" className="gap-2">
            <RefreshCw className="w-3.5 h-3.5" />
            Refresh
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <KpiCard title="Total Artifacts"  value={totalArtifacts}  icon={BookOpen}     trend="up"   trendLabel="in registry" />
        <KpiCard title="Active"           value={activeCount}     icon={CheckCircle2} trend="up"   trendLabel="approved & live" />
        <KpiCard title="Pending Review"   value={pendingReview}   icon={Clock}        trend="down" trendLabel="awaiting approval" />
        <KpiCard title="Deprecated"       value={deprecatedCount} icon={Archive}      trend="down" trendLabel="archived" />
      </div>

      {/* Type Stats */}
      <div className="grid grid-cols-4 sm:grid-cols-8 gap-3">
        {TYPE_STATS.map((ts, i) => (
          <motion.div
            key={ts.type}
            initial={{ opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.05 }}
            className="bg-gray-800/50 border border-gray-700/50 rounded-lg p-3 text-center"
          >
            <div className={cn("flex justify-center mb-1", ts.color)}>{ts.icon}</div>
            <p className="text-lg font-bold text-gray-100">{ts.count}</p>
            <p className="text-xs text-gray-500 capitalize">{ts.type}s</p>
          </motion.div>
        ))}
      </div>

      {/* Filter Tabs */}
      <div className="flex gap-2 flex-wrap">
        {(["all", "active", "review", "draft", "deprecated"] as const).map((s) => (
          <button
            key={s}
            onClick={() => setFilterStatus(s)}
            className={cn(
              "px-3 py-1.5 rounded text-xs font-medium capitalize transition-colors",
              filterStatus === s
                ? "bg-blue-600 text-white"
                : "bg-gray-800 text-gray-400 hover:text-gray-200 border border-gray-700"
            )}
          >
            {s === "all" ? "All Artifacts" : STATUS_CONFIG[s as ArtifactStatus]?.label ?? s}
          </button>
        ))}
      </div>

      {/* Registry Table */}
      <Card>
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-semibold">
            Registry
            <span className="ml-2 text-xs font-normal text-gray-400">({filtered.length} artifacts)</span>
          </CardTitle>
        </CardHeader>
        <CardContent className="p-0">
          <Table>
            <TableHeader>
              <TableRow className="border-gray-700/50">
                <TableHead className="text-gray-400 text-xs">Title</TableHead>
                <TableHead className="text-gray-400 text-xs">Type</TableHead>
                <TableHead className="text-gray-400 text-xs">Status</TableHead>
                <TableHead className="text-gray-400 text-xs">Version</TableHead>
                <TableHead className="text-gray-400 text-xs">Owner</TableHead>
                <TableHead className="text-gray-400 text-xs">Last Reviewed</TableHead>
                <TableHead className="text-gray-400 text-xs">Next Review</TableHead>
                <TableHead className="text-gray-400 text-xs text-right">Reviews</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {filtered.map((artifact, i) => (
                <motion.tr
                  key={artifact.id}
                  initial={{ opacity: 0 }}
                  animate={{ opacity: 1 }}
                  transition={{ delay: i * 0.03 }}
                  className="border-b border-gray-700/50 hover:bg-gray-800/30"
                >
                  <TableCell className="text-sm text-gray-200 max-w-[240px]">
                    <p className="truncate">{artifact.title}</p>
                    <div className="flex gap-1 mt-1 flex-wrap">
                      {artifact.tags.slice(0, 2).map((tag) => (
                        <span key={tag} className="px-1.5 py-0.5 bg-gray-700/50 border border-gray-600/50 rounded text-xs text-gray-400">#{tag}</span>
                      ))}
                    </div>
                  </TableCell>
                  <TableCell><TypeBadge type={artifact.artifact_type} /></TableCell>
                  <TableCell><StatusBadge status={artifact.status} /></TableCell>
                  <TableCell className="font-mono text-xs text-gray-400">v{artifact.version}</TableCell>
                  <TableCell className="text-xs text-gray-400">{artifact.owner}</TableCell>
                  <TableCell className="text-xs text-gray-400">{artifact.last_reviewed}</TableCell>
                  <TableCell className="text-xs">
                    <span className={cn(
                      artifact.next_review === "N/A" ? "text-gray-500" :
                      artifact.next_review < "2026-05-01" ? "text-yellow-400" : "text-gray-400"
                    )}>
                      {artifact.next_review}
                    </span>
                  </TableCell>
                  <TableCell className="text-right text-sm text-gray-300">{artifact.review_count}</TableCell>
                </motion.tr>
              ))}
            </TableBody>
          </Table>
        </CardContent>
      </Card>
    </div>
  );
}
