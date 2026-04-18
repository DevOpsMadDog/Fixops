/**
 * Cloud Access Security Dashboard
 *
 * Cloud app discovery, sanctioning, and risk monitoring (CASB-style).
 *   1. KPIs: Cloud Apps, Unsanctioned Apps, High Risk Apps, Unique Users
 *   2. Cloud apps table (name, app_category, vendor, risk_level, users_count, sanctioned)
 *
 * Route: /cloud-access-security
 * API: GET /api/v1/cloud-access-security
 */

import { useState, useEffect } from "react";
import { motion } from "framer-motion";
import { Cloud, RefreshCw, ShieldAlert, Users, AlertTriangle, CheckSquare } from "lucide-react";

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

async function apiFetch(path: string, opts?: RequestInit) {
  const res = await fetch(`${API_BASE}${path}`, {
    ...opts,
    headers: { "X-API-Key": API_KEY, "Content-Type": "application/json", ...(opts?.headers ?? {}) },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// == Mock data ==================================================

const MOCK_APPS = [
  { id: "app-001", name: "Slack",          app_category: "collaboration",  vendor: "Salesforce",  risk_level: "low",    users_count: 1240, sanctioned: true  },
  { id: "app-002", name: "Dropbox",        app_category: "file_storage",   vendor: "Dropbox Inc", risk_level: "medium", users_count: 387,  sanctioned: false },
  { id: "app-003", name: "GitHub",         app_category: "devtools",       vendor: "Microsoft",   risk_level: "low",    users_count: 892,  sanctioned: true  },
  { id: "app-004", name: "Mega.nz",        app_category: "file_storage",   vendor: "Mega Ltd",    risk_level: "high",   users_count: 43,   sanctioned: false },
  { id: "app-005", name: "Zoom",           app_category: "conferencing",   vendor: "Zoom Video",  risk_level: "low",    users_count: 1105, sanctioned: true  },
  { id: "app-006", name: "Telegram",       app_category: "messaging",      vendor: "Telegram FZ", risk_level: "high",   users_count: 78,   sanctioned: false },
  { id: "app-007", name: "Google Drive",   app_category: "file_storage",   vendor: "Google",      risk_level: "low",    users_count: 1352, sanctioned: true  },
  { id: "app-008", name: "WeTransfer",     app_category: "file_transfer",  vendor: "WeTransfer",  risk_level: "medium", users_count: 122,  sanctioned: false },
  { id: "app-009", name: "Notion",         app_category: "productivity",   vendor: "Notion Labs", risk_level: "low",    users_count: 634,  sanctioned: true  },
  { id: "app-010", name: "Proton Mail",    app_category: "email",          vendor: "Proton AG",   risk_level: "medium", users_count: 29,   sanctioned: false },
];

const MOCK_STATS = { cloud_apps: 284, unsanctioned_apps: 91, high_risk_apps: 17, unique_users: 1847 };

// == Badge helpers ==============================================

function RiskBadge({ level }: { level: string }) {
  const map: Record<string, string> = {
    high:   "border-red-500/30 text-red-400 bg-red-500/10",
    medium: "border-yellow-500/30 text-yellow-400 bg-yellow-500/10",
    low:    "border-green-500/30 text-green-400 bg-green-500/10",
  };
  return (
    <Badge className={cn("text-[10px] border capitalize", map[level] ?? "border-border")}>
      {level}
    </Badge>
  );
}

function SanctionedBadge({ sanctioned }: { sanctioned: boolean }) {
  return sanctioned ? (
    <Badge className="text-[10px] border border-green-500/30 text-green-400 bg-green-500/10">Yes</Badge>
  ) : (
    <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">No</Badge>
  );
}

// == Component ==================================================

export default function CloudAccessSecurityDashboard() {
  const [refreshing, setRefreshing] = useState(false);
  const [liveApps, setLiveApps] = useState<any[] | null>(null);
  const [liveStats, setLiveStats] = useState<any | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    Promise.allSettled([
      apiFetch(`/api/v1/cloud-access-security/apps?org_id=${ORG_ID}`),
      apiFetch(`/api/v1/cloud-access-security/stats?org_id=${ORG_ID}`),
    ]).then(([appsRes, statsRes]) => {
      if (appsRes.status === "fulfilled") setLiveApps(appsRes.value?.apps ?? appsRes.value ?? null);
      if (statsRes.status === "fulfilled") setLiveStats(statsRes.value ?? null);
    })
      .finally(() => setLoading(false));
  }, []);

  const handleRefresh = () => { setRefreshing(true); setTimeout(() => setRefreshing(false), 800); };

  const apps  = liveApps  ?? MOCK_APPS;
  const stats = liveStats ?? MOCK_STATS;

  if (loading) return (
    <div className="space-y-4 p-6">
      {[1, 2, 3].map((i) => (
        <div key={i} className="h-24 rounded-lg bg-zinc-800/50 animate-pulse" />
      )))}
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
        title="Cloud Access Security"
        description="Shadow IT discovery, cloud app risk scoring, and sanctioning controls for CASB-style visibility"
        actions={
          <Button variant="outline" size="sm" onClick={handleRefresh} disabled={refreshing}>
            <RefreshCw className={cn("h-4 w-4", refreshing && "animate-spin")} />
          </Button>
        }
      />

      {/* KPIs */}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <KpiCard title="Cloud Apps"       value={stats.cloud_apps}        icon={Cloud}        trend="flat" className="border-cyan-500/20" />
        <KpiCard title="Unsanctioned"     value={stats.unsanctioned_apps} icon={ShieldAlert}  trend="down" className="border-sky-500/20" />
        <KpiCard title="High Risk Apps"   value={stats.high_risk_apps}    icon={AlertTriangle} trend="down" className="border-cyan-500/20" />
        <KpiCard title="Unique Users"     value={stats.unique_users}      icon={Users}        trend="up"   className="border-sky-500/20" />
      </div>

      {/* Apps Table */}
      <Card className="border-cyan-500/20">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2 text-cyan-400">
              <CheckSquare className="h-4 w-4" />
              Cloud Application Inventory
            </CardTitle>
            <Badge className="text-[10px] border border-red-500/30 text-red-400 bg-red-500/10">
              {apps.filter((a: any) => !a.sanctioned).length} unsanctioned
            </Badge>
          </div>
          <CardDescription className="text-xs">
            Discovered cloud apps with risk level, usage stats, and sanctioning status
          </CardDescription>
        </CardHeader>
        <CardContent className="p-0">
          <div className="overflow-x-auto">
            <Table>
              <TableHeader>
                <TableRow className="hover:bg-transparent">
                  <TableHead className="text-[11px] h-8">App Name</TableHead>
                  <TableHead className="text-[11px] h-8">Category</TableHead>
                  <TableHead className="text-[11px] h-8">Vendor</TableHead>
                  <TableHead className="text-[11px] h-8">Risk Level</TableHead>
                  <TableHead className="text-[11px] h-8">Users</TableHead>
                  <TableHead className="text-[11px] h-8 text-right">Sanctioned</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {apps.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16 text-zinc-500">
                    <p className="text-lg font-medium">No data available</p>
                    <p className="text-sm">Data will appear here once available</p>
                  </div>
                ) : (
                  apps.map((app: any, i: number) => (
                  <TableRow key={app.id ?? i} className="hover:bg-muted/30">
                    <TableCell className="py-2 font-semibold text-[11px] text-cyan-300">
                      {app.name ?? "="}
                    </TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground capitalize">
                      {(app.app_category ?? "=").replace(/_/g, " ")}
                    </TableCell>
                    <TableCell className="py-2 text-[11px] text-muted-foreground">
                      {app.vendor ?? "="}
                    </TableCell>
                    <TableCell className="py-2">
                      <RiskBadge level={app.risk_level ?? "low"} />
                    </TableCell>
                    <TableCell className="py-2 font-mono text-[11px] text-sky-300">
                      {app.users_count?.toLocaleString() ?? "="}
                    </TableCell>
                    <TableCell className="py-2 text-right">
                      <SanctionedBadge sanctioned={!!app.sanctioned} />
                    </TableCell>
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
