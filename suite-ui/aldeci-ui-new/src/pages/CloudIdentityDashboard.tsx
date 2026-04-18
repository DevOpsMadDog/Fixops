/**
 * Cloud Identity Dashboard
 *
 * Cross-cloud IAM, federated access, and permission analysis.
 *   1. KPI cards: Total Identities, Admin Count, MFA Disabled (alert), Federated Identities
 *   2. Identities table
 *   3. Access Reviews table
 *
 * API: GET /api/v1/cloud-identity/{stats,identities,reviews}
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Cloud, RefreshCw, ShieldAlert, Users, CheckCircle, XCircle, Link } from "lucide-react";
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
  total_identities: 384,
  admin_count: 17,
  mfa_disabled: 23,
  federated_identities: 142,
};

const MOCK_IDENTITIES = [
  { id: "cid-001", name: "alice@corp.com",         type: "user",            cloud_provider: "aws",        privilege_level: "admin",  mfa_enabled: true,  federated: false },
  { id: "cid-002", name: "sa-dataproc@project.iam", type: "service_account", cloud_provider: "gcp",        privilege_level: "write",  mfa_enabled: false, federated: false },
  { id: "cid-003", name: "AzureDevOpsGroup",        type: "group",           cloud_provider: "azure",      privilege_level: "read",   mfa_enabled: true,  federated: true  },
  { id: "cid-004", name: "lambda-execution-role",   type: "role",            cloud_provider: "aws",        privilege_level: "write",  mfa_enabled: false, federated: false },
  { id: "cid-005", name: "build-bot-machine",       type: "machine",         cloud_provider: "multi_cloud",privilege_level: "none",   mfa_enabled: false, federated: true  },
  { id: "cid-006", name: "bob@corp.com",            type: "user",            cloud_provider: "azure",      privilege_level: "read",   mfa_enabled: true,  federated: true  },
];

const MOCK_REVIEWS = [
  { id: "rev-001", identity_name: "alice@corp.com",          review_type: "Quarterly Access Review", outcome: "approved",  reviewed_at: "2026-04-10T14:30:00Z" },
  { id: "rev-002", identity_name: "sa-dataproc@project.iam", review_type: "Permission Audit",        outcome: "revoked",   reviewed_at: "2026-04-12T09:15:00Z" },
  { id: "rev-003", identity_name: "lambda-execution-role",   review_type: "Role Entitlement Review", outcome: "modified",  reviewed_at: "2026-04-14T11:00:00Z" },
  { id: "rev-004", identity_name: "bob@corp.com",            review_type: "Annual User Review",      outcome: "no_action", reviewed_at: "2026-04-15T16:45:00Z" },
];

function IdentityTypeBadge({ type }: { type: string }) {
  const map: Record<string, string> = {
    user:            "border-blue-500/30 text-blue-400 bg-blue-500/10",
    service_account: "border-purple-500/30 text-purple-400 bg-purple-500/10",
    role:            "border-orange-500/30 text-orange-400 bg-orange-500/10",
    group:           "border-teal-500/30 text-teal-400 bg-teal-500/10",
    machine:         "border-gray-500/30 text-gray-400 bg-gray-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border font-mono", map[type] ?? "border-border text-muted-foreground")}>
      {type.replace(/_/g, " ")}
    </Badge>
  );
}

function CloudProviderBadge({ provider }: { provider: string }) {
  const map: Record<string, string> = {
    aws:        "border-orange-500/30 text-orange-400 bg-orange-500/10",
    azure:      "border-blue-500/30 text-blue-400 bg-blue-500/10",
    gcp:        "border-green-500/30 text-green-400 bg-green-500/10",
    multi_cloud:"border-purple-500/30 text-purple-400 bg-purple-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border uppercase font-mono", map[provider] ?? "border-border text-muted-foreground")}>
      {provider.replace(/_/g, " ")}
    </Badge>
  );
}

function PrivilegeBadge({ level }: { level: string }) {
  const map: Record<string, string> = {
    admin: "border-red-500/30 text-red-400 bg-red-500/10",
    write: "border-orange-500/30 text-orange-400 bg-orange-500/10",
    read:  "border-green-500/30 text-green-400 bg-green-500/10",
    none:  "border-gray-500/30 text-gray-400 bg-gray-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[level] ?? "border-border text-muted-foreground")}>
      {level}
    </Badge>
  );
}

function ReviewOutcomeBadge({ outcome }: { outcome: string }) {
  const map: Record<string, string> = {
    approved:  "border-green-500/30 text-green-400 bg-green-500/10",
    revoked:   "border-red-500/30 text-red-400 bg-red-500/10",
    modified:  "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    no_action: "border-gray-500/30 text-gray-400 bg-gray-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[outcome] ?? "border-border text-muted-foreground")}>
      {outcome.replace(/_/g, " ")}
    </Badge>
  );
}

function fmtTime(ts: string): string {
  try { return new Date(ts).toLocaleString(); } catch { return ts; }
}

export default function CloudIdentityDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [dataLoading, setDataLoading] = useState(false);
  const [liveData, setLiveData] = useState<{ stats: any | null; identities: any[] | null; reviews: any[] | null }>({
  const [loading, setLoading] = useState(true);
    stats: null, identities: null, reviews: null,
  });

  const fetchData = () => {
    setDataLoading(true);
    Promise.allSettled([
      apiFetch(`/api/v1/cloud-identity/stats?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/cloud-identity/identities?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/cloud-identity/reviews?org_id=${ORG_ID}`),
    ]).then(([statsRes, identitiesRes, reviewsRes]) => {
      setLiveData({
        stats:      statsRes.status      === "fulfilled" ? statsRes.value      : null,
        identities: identitiesRes.status === "fulfilled" ? identitiesRes.value : null,
        reviews:    reviewsRes.status    === "fulfilled" ? reviewsRes.value    : null,
      });
    }).finally(() => setDataLoading(false));
  };

  useEffect(() => { fetchData(); 
    setLoading(false);}, []);

  const handleRefresh = () => {
    setRefreshing(true);
    fetchData();
    setTimeout(() => setRefreshing(false), 800);
  };

  const stats      = liveData.stats      ?? MOCK_STATS;
  const identities = liveData.identities ?? MOCK_IDENTITIES;
  const reviews    = liveData.reviews    ?? MOCK_REVIEWS;

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
        title="Cloud Identity Management"
        description="Cross-cloud IAM, federated access, and permission analysis"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing || dataLoading}>
            <RefreshCw className={cn("h-4 w-4", (refreshing || dataLoading) && "animate-spin")} />
          </Button>
        }
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Total Identities"    value={stats.total_identities}    icon={Users
    setLoading(false);}       trend="flat" />
        <KpiCard title="Admin Count"         value={stats.admin_count}         icon={ShieldAlert} trend="flat" className="border-orange-500/20" />
        <KpiCard
          title="MFA Disabled"
          value={stats.mfa_disabled}
          icon={XCircle}
          trend="down"
          className={stats.mfa_disabled > 0 ? "border-red-500/20" : "border-green-500/20"}
        />
        <KpiCard title="Federated"           value={stats.federated_identities} icon={Link}       trend="up"   className="border-blue-500/20" />
      </div>

      {/* Identities Table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Cloud className="h-4 w-4 text-blue-400" />
              Cloud Identities
            </CardTitle>
            <Badge className="text-[10px] border border-border text-muted-foreground">
              {identities.length} identities
            </Badge>
          </div>
          <CardDescription className="text-xs">Users, service accounts, roles, and machine identities across cloud providers</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Identity Name</TableHead>
                  <TableHead className="text-[11px] h-8">Type</TableHead>
                  <TableHead className="text-[11px] h-8">Cloud Provider</TableHead>
                  <TableHead className="text-[11px] h-8">Privilege</TableHead>
                  <TableHead className="text-[11px] h-8 text-center">MFA</TableHead>
                  <TableHead className="text-[11px] h-8 text-center">Federated</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {identities.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  identities.map((ident: any, i: number) => (
                  <TableRow key={ident.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 text-[12px] font-mono">{ident.name}</TableCell>
                    <TableCell className="py-2"><IdentityTypeBadge type={ident.type ?? "user"} /></TableCell>
                    <TableCell className="py-2"><CloudProviderBadge provider={ident.cloud_provider ?? "aws"} /></TableCell>
                    <TableCell className="py-2"><PrivilegeBadge level={ident.privilege_level ?? "read"} /></TableCell>
                    <TableCell className="py-2 text-center">
                      {ident.mfa_enabled
                        ? <CheckCircle className="h-3.5 w-3.5 text-green-400 inline" />
                        : <XCircle    className="h-3.5 w-3.5 text-red-400 inline" />}
                    </TableCell>
                    <TableCell className="py-2 text-center">
                      {ident.federated
                        ? <CheckCircle className="h-3.5 w-3.5 text-blue-400 inline" />
                        : <XCircle    className="h-3.5 w-3.5 text-gray-500 inline" />}
                    </TableCell>
                  </TableRow>
                ))}
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>

      {/* Access Reviews Table */}
      <Card className="border-blue-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-blue-400">
              <CheckCircle className="h-4 w-4" />
              Access Reviews
            </CardTitle>
            <Badge className="text-[10px] border border-blue-500/30 text-blue-400 bg-blue-500/10">
              {reviews.length} reviews
            </Badge>
          </div>
          <CardDescription className="text-xs">Identity access reviews with outcomes and reviewer decisions</CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">Identity</TableHead>
                  <TableHead className="text-[11px] h-8">Review Type</TableHead>
                  <TableHead className="text-[11px] h-8">Outcome</TableHead>
                  <TableHead className="text-[11px] h-8">Reviewed At</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {reviews.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  reviews.map((rev: any, i: number) => (
                  <TableRow key={rev.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 text-[11px] font-mono text-muted-foreground">{rev.identity_name ?? rev.id}</TableCell>
                    <TableCell className="py-2 text-[11px]">{rev.review_type}</TableCell>
                    <TableCell className="py-2"><ReviewOutcomeBadge outcome={rev.outcome ?? "no_action"} /></TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">{fmtTime(rev.reviewed_at)}</TableCell>
                  </TableRow>
                ))}
                )}
              </TableBody>
            </Table>
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
