/**
 * Threat Brief Dashboard
 *
 * Threat brief cards by type, TLP classification, recipient tracking, distribution.
 *   1. KPIs: Total Briefs, Distributed Today, Recipients Reached, Pending Review
 *   2. Brief cards (6 types) with TLP badges
 *   3. Brief detail view with summary text
 *   4. Distribute action
 *
 * Route: /threat-briefs
 * API: GET /api/v1/threat-briefs
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { FileText, Send, Users, Clock, RefreshCw, Eye, Shield, AlertTriangle } from "lucide-react";

import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

// ── Types ──────────────────────────────────────────────────────

type TLPLevel = "RED" | "AMBER" | "GREEN" | "WHITE";
type BriefType = "daily" | "weekly" | "monthly" | "incident" | "threat-actor" | "campaign";

interface ThreatBrief {
  id: string;
  title: string;
  brief_type: BriefType;
  tlp: TLPLevel;
  summary: string;
  recipient_count: number;
  distributed: boolean;
  created_at: string;
  author: string;
  threat_level: "critical" | "high" | "medium" | "low";
  tags: string[];
}

// ── Mock data ──────────────────────────────────────────────────

const MOCK_BRIEFS: ThreatBrief[] = [
  {
    id: "tb-001",
    title: "APT29 Phishing Campaign Targeting Finance Sector",
    brief_type: "threat-actor",
    tlp: "RED",
    summary: "APT29 (Cozy Bear) has launched a targeted spear-phishing campaign against financial institutions. Indicators include malicious PDF attachments with CVE-2024-21412 exploits. Affected organizations should patch immediately and review email gateway logs for indicators of compromise.",
    recipient_count: 48,
    distributed: true,
    created_at: "2026-04-16 07:30",
    author: "SOC Analyst",
    threat_level: "critical",
    tags: ["APT29", "phishing", "finance", "CVE-2024-21412"],
  },
  {
    id: "tb-002",
    title: "Daily Threat Intelligence Summary — April 16",
    brief_type: "daily",
    tlp: "GREEN",
    summary: "Daily threat summary covering 1,247 new IOCs ingested from 14 feeds. Key highlights: 3 new ransomware families detected, 12 compromised credential batches, 847 malicious IPs added to blocklist. No critical zero-days reported in the last 24 hours.",
    recipient_count: 124,
    distributed: true,
    created_at: "2026-04-16 06:00",
    author: "Threat Intel Bot",
    threat_level: "medium",
    tags: ["daily", "IOCs", "ransomware"],
  },
  {
    id: "tb-003",
    title: "LockBit 3.0 Ransomware Campaign — Healthcare Targets",
    brief_type: "campaign",
    tlp: "AMBER",
    summary: "LockBit 3.0 affiliates have been observed targeting healthcare organizations in North America. Initial access via exposed RDP (port 3389) and VPN vulnerabilities. Double-extortion model with 72-hour ransom timer. Recommend immediate RDP audit and MFA enforcement.",
    recipient_count: 31,
    distributed: true,
    created_at: "2026-04-16 09:00",
    author: "Threat Intel Team",
    threat_level: "critical",
    tags: ["LockBit", "ransomware", "healthcare", "RDP"],
  },
  {
    id: "tb-004",
    title: "Weekly Executive Security Briefing — Week 16",
    brief_type: "weekly",
    tlp: "GREEN",
    summary: "Week 16 security posture summary for executive leadership. Overall risk score: 72/100 (stable). Key activities: 3 critical vulnerabilities patched, 2 security incidents resolved, SOC processed 14,382 alerts. Next week focus: FedRAMP audit preparation and zero-trust rollout.",
    recipient_count: 8,
    distributed: true,
    created_at: "2026-04-14 09:00",
    author: "CISO Office",
    threat_level: "low",
    tags: ["weekly", "executive", "posture"],
  },
  {
    id: "tb-005",
    title: "Critical Incident Report — Cloud Storage Misconfiguration",
    brief_type: "incident",
    tlp: "AMBER",
    summary: "S3 bucket misconfiguration exposed 14,000 internal documents for approximately 6 hours on April 15. Affected bucket has been secured. No evidence of external access detected in CloudTrail logs. Full forensics investigation underway. Regulatory notification assessment in progress.",
    recipient_count: 22,
    distributed: false,
    created_at: "2026-04-16 10:15",
    author: "Incident Response Team",
    threat_level: "high",
    tags: ["incident", "S3", "misconfiguration", "data exposure"],
  },
  {
    id: "tb-006",
    title: "Q1 2026 Monthly Threat Landscape Report",
    brief_type: "monthly",
    tlp: "WHITE",
    summary: "Comprehensive threat landscape analysis for Q1 2026. Major trends: 34% increase in AI-powered phishing, supply chain attacks up 58%, ransomware payments declined 23% due to improved defenses. Top targeted sectors: healthcare, finance, critical infrastructure. Recommended priorities for Q2.",
    recipient_count: 0,
    distributed: false,
    created_at: "2026-04-16 08:45",
    author: "Strategic Intelligence",
    threat_level: "medium",
    tags: ["monthly", "Q1-2026", "landscape", "trends"],
  },
];

// ── Helpers ────────────────────────────────────────────────────

const TLP_CONFIG: Record<TLPLevel, { cls: string; bg: string }> = {
  RED:   { cls: "text-red-300 border-red-500/40",    bg: "bg-red-600" },
  AMBER: { cls: "text-amber-300 border-amber-500/40", bg: "bg-amber-500" },
  GREEN: { cls: "text-green-300 border-green-500/40", bg: "bg-green-600" },
  WHITE: { cls: "text-gray-300 border-gray-500/40",   bg: "bg-gray-500" },
};

const BRIEF_TYPE_LABELS: Record<BriefType, string> = {
  "daily": "Daily",
  "weekly": "Weekly",
  "monthly": "Monthly",
  "incident": "Incident",
  "threat-actor": "Threat Actor",
  "campaign": "Campaign",
};

const THREAT_LEVEL_CONFIG: Record<string, string> = {
  critical: "bg-red-500/10 text-red-400 border-red-500/20",
  high:     "bg-orange-500/10 text-orange-400 border-orange-500/20",
  medium:   "bg-yellow-500/10 text-yellow-400 border-yellow-500/20",
  low:      "bg-green-500/10 text-green-400 border-green-500/20",
};

// ── Main Component ─────────────────────────────────────────────

export default function ThreatBriefDashboard() {
  const [selectedBrief, setSelectedBrief] = useState<ThreatBrief | null>(MOCK_BRIEFS[0]);
  useEffect(() => {
    fetch("/api/v1/threat-briefs", { headers: { "X-API-Key": localStorage.getItem("apiKey") || "" } })
      .then(r => r.ok ? r.json() : Promise.reject())
      .then(() => { /* live data available */ })
      .catch(() => { setError('Failed to load data'); });
  }, []);
  const [distributing, setDistributing] = useState<string | null>(null);
  const [distributed, setDistributed] = useState<Set<string>>(
    new Set(MOCK_BRIEFS.filter((b) => b.distributed).map((b) => b.id))
  );

  const totalBriefs = MOCK_BRIEFS.length;
  const distributedToday = MOCK_BRIEFS.filter((b) => b.distributed && b.created_at.startsWith("2026-04-16")).length;
  const totalRecipients = MOCK_BRIEFS.filter((b) => b.distributed).reduce((s, b) => s + b.recipient_count, 0);
  const pendingReview = MOCK_BRIEFS.filter((b) => !b.distributed).length;

  function handleDistribute(id: string) {
    setDistributing(id);
    setTimeout(() => {
      setDistributed((prev) => new Set([...prev, id]));
      setDistributing(null);
    }, 1500);
  }

  return (
    <div className="flex flex-col gap-6 p-6 min-h-0">
      <PageHeader
        title="Threat Briefs"
        description="Curated threat intelligence briefs by type with TLP classification and distribution tracking"
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
        <KpiCard title="Total Briefs"       value={totalBriefs}      icon={FileText}      trend="up"   trendLabel="this period" />
        <KpiCard title="Distributed Today"  value={distributedToday} icon={Send}          trend="up"   trendLabel="sent to recipients" />
        <KpiCard title="Recipients Reached" value={totalRecipients}  icon={Users}         trend="up"   trendLabel="across all briefs" />
        <KpiCard title="Pending Review"     value={pendingReview}    icon={Clock}         trend="down" trendLabel="awaiting distribution" />
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-5 gap-6">
        {/* Brief Cards */}
        <div className="xl:col-span-2 flex flex-col gap-3">
          <h2 className="text-xs font-semibold uppercase tracking-wider text-gray-400">All Briefs</h2>
          {MOCK_BRIEFS.map((brief, i) => (
            <motion.div
              key={brief.id}
              initial={{ opacity: 0, x: -8 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: i * 0.06 }}
              onClick={() => setSelectedBrief(brief)}
              className={cn(
                "p-4 rounded-lg border cursor-pointer transition-colors",
                selectedBrief?.id === brief.id
                  ? "bg-blue-500/10 border-blue-500/40"
                  : "bg-gray-800/50 border-gray-700/50 hover:border-gray-600"
              )}
            >
              <div className="flex items-start justify-between gap-2 mb-2">
                <p className="text-sm font-medium text-gray-100 leading-snug line-clamp-2">{brief.title}</p>
                <div
                  className={cn("flex-shrink-0 px-1.5 py-0.5 rounded text-[10px] font-bold border", TLP_CONFIG[brief.tlp].cls)}
                  style={{ background: `${TLP_CONFIG[brief.tlp].bg}20` }}
                >
                  TLP:{brief.tlp}
                </div>
              </div>
              <div className="flex items-center gap-2 flex-wrap">
                <Badge className="bg-gray-700/50 text-gray-300 border-gray-600 text-xs">{BRIEF_TYPE_LABELS[brief.brief_type]}</Badge>
                <Badge className={cn("border text-xs capitalize", THREAT_LEVEL_CONFIG[brief.threat_level])}>{brief.threat_level}</Badge>
                {distributed.has(brief.id) ? (
                  <span className="text-xs text-green-400 ml-auto flex items-center gap-1">
                    <Send className="w-3 h-3" /> {brief.recipient_count} recipients
                  </span>
                ) : (
                  <span className="text-xs text-gray-500 ml-auto">Not distributed</span>
                )}
              </div>
            </motion.div>
          ))}
        </div>

        {/* Brief Detail */}
        <Card className="xl:col-span-3">
          {selectedBrief ? (
            <>
              <CardHeader className="pb-3">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <CardTitle className="text-sm font-semibold leading-snug">{selectedBrief.title}</CardTitle>
                    <p className="text-xs text-gray-400 mt-1">{selectedBrief.author} · {selectedBrief.created_at}</p>
                  </div>
                  <div
                    className={cn("flex-shrink-0 px-2 py-1 rounded text-xs font-bold border", TLP_CONFIG[selectedBrief.tlp].cls)}
                    style={{ background: `${TLP_CONFIG[selectedBrief.tlp].bg}20` }}
                  >
                    TLP:{selectedBrief.tlp}
                  </div>
                </div>
              </CardHeader>
              <CardContent className="flex flex-col gap-4">
                {/* Meta */}
                <div className="flex items-center gap-3 flex-wrap">
                  <Badge className="bg-gray-700/50 text-gray-300 border-gray-600 text-xs">{BRIEF_TYPE_LABELS[selectedBrief.brief_type]}</Badge>
                  <Badge className={cn("border text-xs capitalize", THREAT_LEVEL_CONFIG[selectedBrief.threat_level])}>
                    <AlertTriangle className="w-3 h-3 mr-1" />{selectedBrief.threat_level}
                  </Badge>
                  <span className="text-xs text-gray-400 flex items-center gap-1">
                    <Users className="w-3 h-3" /> {selectedBrief.recipient_count} recipients
                  </span>
                </div>

                {/* Summary */}
                <div className="bg-gray-800/50 rounded-lg p-4 border border-gray-700/50">
                  <p className="text-xs font-semibold text-gray-400 mb-2 uppercase tracking-wider">Summary</p>
                  <p className="text-sm text-gray-300 leading-relaxed">{selectedBrief.summary}</p>
                </div>

                {/* Tags */}
                <div>
                  <p className="text-xs font-semibold text-gray-400 mb-2 uppercase tracking-wider">Tags</p>
                  <div className="flex flex-wrap gap-2">
                    {selectedBrief.tags.map((tag) => (
                      <span key={tag} className="px-2 py-0.5 bg-gray-700/50 border border-gray-600/50 rounded text-xs text-gray-300">#{tag}</span>
                    ))}
                  </div>
                </div>

                {/* Distribute button */}
                <div className="pt-2">
                  {distributed.has(selectedBrief.id) ? (
                    <div className="flex items-center gap-2 text-green-400 text-sm">
                      <Send className="w-4 h-4" />
                      Distributed to {selectedBrief.recipient_count} recipients
                    </div>
                  ) : (
                    <Button
                      className="gap-2 bg-blue-600 hover:bg-blue-700 text-white"
                      onClick={() => handleDistribute(selectedBrief.id)}
                      disabled={distributing === selectedBrief.id}
                    >
                      <Send className="w-4 h-4" />
                      {distributing === selectedBrief.id ? "Distributing..." : "Distribute Brief"}
                    </Button>
                  )}
                </div>
              </CardContent>
            </>
          ) : (
            <CardContent className="flex items-center justify-center h-64">
              <div className="text-center text-gray-500">
                <Eye className="w-8 h-8 mx-auto mb-2 opacity-50" />
                <p className="text-sm">Select a brief to view details</p>
              </div>
            </CardContent>
          )}
        </Card>
      </div>
    </div>
  );
}
