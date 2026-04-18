/**
 * Digital Identity Dashboard
 *
 * NIST 800-63 identity proofing and verification.
 *   1. KPI cards: Total Profiles, Verified Identities, Suspended Count, Pending Verification
 *   2. Identity Profiles table
 *
 * API: GET /api/v1/digital-identity/{stats,profiles}
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Fingerprint, RefreshCw, CheckCircle, UserX, Clock } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { cn } from "@/lib/utils";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "nr0fzLuDiBu8u8f9dw10RVKnG2wjfHkmWM94tDnx2es";
const ORG_ID = "aldeci-demo";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}`, { headers: { "X-API-Key": API_KEY } });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

const MOCK_STATS = {
  total_profiles: 2841,
  verified_identities: 2314,
  suspended_count: 47,
  pending_verification: 480,
};

const MOCK_PROFILES = [
  { user_id: "uid-a1b2c3d4e5f6", identity_level: "IAL3", verification_status: "verified",   verification_method: "In-Person Proofing",  assurance_level: "AAL3", verified_at: "2026-03-15" },
  { user_id: "uid-f6e5d4c3b2a1", identity_level: "IAL2", verification_status: "verified",   verification_method: "Remote Proofing",     assurance_level: "AAL2", verified_at: "2026-02-28" },
  { user_id: "uid-1a2b3c4d5e6f", identity_level: "IAL1", verification_status: "pending",    verification_method: "Email Verification",  assurance_level: "AAL1", verified_at: "" },
  { user_id: "uid-6f5e4d3c2b1a", identity_level: "IAL2", verification_status: "suspended",  verification_method: "Remote Proofing",     assurance_level: "AAL2", verified_at: "2025-11-10" },
  { user_id: "uid-2b3c4d5e6f1a", identity_level: "IAL1", verification_status: "unverified", verification_method: "Self-Attestation",    assurance_level: "AAL1", verified_at: "" },
  { user_id: "uid-3c4d5e6f1a2b", identity_level: "IAL3", verification_status: "verified",   verification_method: "Biometric Proofing",  assurance_level: "AAL3", verified_at: "2026-04-01" },
];

function IALBadge({ level }: { level: string }) {
  const map: Record<string, string> = {
    IAL1: "border-gray-500/30 text-gray-400 bg-gray-500/10",
    IAL2: "border-blue-500/30 text-blue-400 bg-blue-500/10",
    IAL3: "border-purple-500/30 text-purple-400 bg-purple-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border font-mono", map[level] ?? "border-border text-muted-foreground")}>
      {level}
    </Badge>
  );
}

function VerificationStatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    verified:   "border-green-500/30 text-green-400 bg-green-500/10",
    pending:    "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    unverified: "border-gray-500/30 text-gray-400 bg-gray-500/10",
    suspended:  "border-red-500/30 text-red-400 bg-red-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[status] ?? "border-border text-muted-foreground")}>
      {status}
    </Badge>
  );
}

export default function DigitalIdentityDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [dataLoading, setDataLoading] = useState(false);
  const [liveData, setLiveData] = useState<{ stats: any | null; profiles: any[] | null }>({
    stats: null, profiles: null,
  });

  const fetchData = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/digital-identity/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/digital-identity/profiles?org_id=${ORG_ID}`),
    ]).then(([statsRes, profilesRes]) => {
      setLiveData({
        stats:    statsRes.status    === "fulfilled" ? statsRes.value    : null,
        profiles: profilesRes.status === "fulfilled" ? profilesRes.value : null,
      });
    }).finally(() => setDataLoading(false));
  };

  useEffect(() => { fetchData(); }, []);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchData();
    setTimeout(() => setRefreshing(false), 800);
  };

  const stats    = liveData.stats    ?? MOCK_STATS;
  const profiles = liveData.profiles ?? MOCK_PROFILES;

  if (loading) return (
    <div className="space-y-4 p-6">
      {[1, 2, 3].map((i) => (
        <div key={i} className="h-24 rounded-lg bg-zinc-800/50 animate-pulse" />
      ))}
    </div>
  );

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="flex flex-col gap-6"
    >
      <PageHeader
        title="Digital Identity Management"
        description="NIST 800-63 identity proofing and verification"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Profiles"       value={stats.total_profiles}       icon={Fingerprint}  trend="up"   />
        <KpiCard title="Verified Identities"  value={stats.verified_identities}  icon={CheckCircle}  trend="up"   className="border-green-500/20" />
        <KpiCard title="Suspended"            value={stats.suspended_count}      icon={UserX}        trend="down" className="border-red-500/20" />
        <KpiCard title="Pending Verification" value={stats.pending_verification} icon={Clock}        trend="flat" className="border-yellow-500/20" />
      </div>

      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Fingerprint className="h-4 w-4 text-purple-400" />
              Identity Profiles
            </CardTitle>
            <Badge className="text-[10px] border border-border text-muted-foreground">
              {profiles.length} profiles
            </Badge>
          </div>
          <CardDescription className="text-xs">NIST 800-63 identity assurance levels and proofing status</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">User ID</TableHead>
                  <TableHead className="text-[11px] h-8">Identity Level</TableHead>
                  <TableHead className="text-[11px] h-8">Verification Status</TableHead>
                  <TableHead className="text-[11px] h-8">Method</TableHead>
                  <TableHead className="text-[11px] h-8">Assurance</TableHead>
                  <TableHead className="text-[11px] h-8">Verified At</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {profiles.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  profiles.map((p: any, i: number) => (
                  <TableRow key={p.user_id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-mono text-[11px] text-muted-foreground">
                      {(p.user_id ?? "").slice(0, 14)}…
                    </TableCell>
                    <TableCell className="py-2"><IALBadge level={p.identity_level ?? "IAL1"} /></TableCell>
                    <TableCell className="py-2"><VerificationStatusBadge status={p.verification_status ?? "unverified"} /></TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{p.verification_method}</TableCell>
                    <TableCell className="py-2">
                      <Badge className="text-[10px] border border-blue-500/30 text-blue-400 bg-blue-500/10 font-mono">
                        {p.assurance_level}
                      </Badge>
                    </TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{p.verified_at || "—"}</TableCell>
                  </TableRow>
                ))
              )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
