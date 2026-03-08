import { useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  Key, RotateCcw, AlertTriangle, GitBranch, Clock, CheckCircle2,
  XCircle, Eye, EyeOff, RefreshCw, Download, Filter
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { DataTable } from "@/components/shared/data-table";
import { findingsApi } from "@/lib/api";
import { toast } from "sonner";
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell
} from "recharts";

// ── Mock Data ──────────────────────────────────────────────────────────────────
type RotationStatus = "rotated" | "pending" | "overdue" | "active";

const MOCK_SECRETS = [
  { id: "SEC-4412", type: "AWS Access Key", value: "AKIA...KX8F", repo: "payment-service", branch: "main", author: "jsmith@corp.com", detectedAt: "2h ago", rotationStatus: "overdue" as RotationStatus, severity: "critical", commit: "a4f2c1d" },
  { id: "SEC-4408", type: "Stripe Secret Key", value: "sk_live_...9Zm3", repo: "billing-api", branch: "main", author: "alee@corp.com", detectedAt: "5h ago", rotationStatus: "pending" as RotationStatus, severity: "critical", commit: "b8e3f2a" },
  { id: "SEC-4401", type: "GitHub PAT", value: "ghp_...xK3p", repo: "devops-scripts", branch: "feature/deploy", author: "rchen@corp.com", detectedAt: "12h ago", rotationStatus: "rotated" as RotationStatus, severity: "high", commit: "c2d1a9e" },
  { id: "SEC-4395", type: "Database Password", value: "postgres://...@prod", repo: "auth-service", branch: "develop", author: "mwilson@corp.com", detectedAt: "1d ago", rotationStatus: "overdue" as RotationStatus, severity: "critical", commit: "d3f4b2c" },
  { id: "SEC-4388", type: "Slack Webhook URL", value: "https://hooks.slack.com/...8Kd", repo: "notification-svc", branch: "main", author: "tpatel@corp.com", detectedAt: "2d ago", rotationStatus: "rotated" as RotationStatus, severity: "medium", commit: "e1a9c7b" },
  { id: "SEC-4375", type: "SendGrid API Key", value: "SG....cXpN", repo: "email-service", branch: "main", author: "jsmith@corp.com", detectedAt: "3d ago", rotationStatus: "pending" as RotationStatus, severity: "high", commit: "f2b8d4a" },
  { id: "SEC-4362", type: "JWT Private Key", value: "-----BEGIN RSA PRIVATE...", repo: "identity-provider", branch: "hotfix/jwt", author: "alee@corp.com", detectedAt: "4d ago", rotationStatus: "overdue" as RotationStatus, severity: "critical", commit: "g3c7e5b" },
  { id: "SEC-4350", type: "GCP Service Account", value: "{\"type\":\"service_account\"...}", repo: "data-pipeline", branch: "main", author: "rchen@corp.com", detectedAt: "5d ago", rotationStatus: "active" as RotationStatus, severity: "high", commit: "h4d6f3a" },
  { id: "SEC-4341", type: "OpenAI API Key", value: "sk-...mN7K", repo: "ai-features", branch: "main", author: "mwilson@corp.com", detectedAt: "6d ago", rotationStatus: "rotated" as RotationStatus, severity: "medium", commit: "i5e5g2c" },
  { id: "SEC-4329", type: "NPM Token", value: "npm_...xR9K", repo: "frontend-app", branch: "ci/deploy", author: "tpatel@corp.com", detectedAt: "8d ago", rotationStatus: "rotated" as RotationStatus, severity: "low", commit: "j6f4h1d" },
];

const SECRET_TYPE_BREAKDOWN = [
  { type: "AWS Keys", count: 24, color: "#f97316" },
  { type: "DB Passwords", count: 19, color: "#ef4444" },
  { type: "API Keys", count: 31, color: "#a855f7" },
  { type: "Tokens", count: 18, color: "#3b82f6" },
  { type: "Certificates", count: 7, color: "#10b981" },
  { type: "Webhooks", count: 12, color: "#f59e0b" },
];

const ROTATION_TIMELINE = [
  { month: "Sep", rotated: 12, detected: 18 },
  { month: "Oct", rotated: 19, detected: 22 },
  { month: "Nov", rotated: 15, detected: 14 },
  { month: "Dec", rotated: 28, detected: 31 },
  { month: "Jan", rotated: 22, detected: 19 },
  { month: "Feb", rotated: 31, detected: 27 },
];

const ROTATION_CONFIG: Record<RotationStatus, { label: string; variant: "success" | "warning" | "destructive" | "secondary"; icon: React.ComponentType<{ className?: string }> }> = {
  rotated:  { label: "Rotated",  variant: "success",     icon: CheckCircle2 },
  pending:  { label: "Pending",  variant: "warning",     icon: Clock },
  overdue:  { label: "Overdue",  variant: "destructive", icon: XCircle },
  active:   { label: "Active",   variant: "secondary",   icon: Eye },
};

export default function SecretsDetection() {
  const [showValues, setShowValues] = useState(false);

  const { data } = useQuery({
    queryKey: ["findings", "secrets"],
    queryFn: () => findingsApi.list({ type: "secret", limit: 50 }),
  });

  const secrets = data?.data ?? MOCK_SECRETS;

  const overdueCount = secrets.filter((s) => s.rotationStatus === "overdue").length;
  const pendingCount = secrets.filter((s) => s.rotationStatus === "pending").length;
  const criticalCount = secrets.filter((s) => s.severity === "critical").length;
  const rotatedCount = secrets.filter((s) => s.rotationStatus === "rotated").length;
  const rotationRate = Math.round((rotatedCount / secrets.length) * 100);
  const uniqueRepos = new Set(secrets.map((s) => s.repo)).size;

  const columns = [
    { key: "id", header: "ID", render: (row: typeof MOCK_SECRETS[0]) => <span className="font-mono text-xs text-muted-foreground">{row.id}</span> },
    { key: "type", header: "Secret Type", render: (row: typeof MOCK_SECRETS[0]) => (
      <div className="flex items-center gap-2">
        <Key className="h-4 w-4 text-yellow-400 shrink-0" />
        <span className="text-sm font-medium">{row.type}</span>
      </div>
    )},
    { key: "value", header: "Value", render: (row: typeof MOCK_SECRETS[0]) => (
      <code className="font-mono text-xs text-muted-foreground bg-muted/30 px-2 py-0.5 rounded">
        {showValues ? row.value : "•".repeat(16)}
      </code>
    )},
    { key: "repo", header: "Repository", render: (row: typeof MOCK_SECRETS[0]) => (
      <div>
        <div className="flex items-center gap-1.5">
          <GitBranch className="h-3.5 w-3.5 text-muted-foreground" />
          <span className="text-sm">{row.repo}</span>
        </div>
        <p className="text-xs text-muted-foreground font-mono mt-0.5">{row.branch} · {row.commit}</p>
      </div>
    )},
    { key: "author", header: "Author", render: (row: typeof MOCK_SECRETS[0]) => <span className="text-sm">{row.author}</span> },
    { key: "detectedAt", header: "Detected", render: (row: typeof MOCK_SECRETS[0]) => (
      <span className="text-xs text-muted-foreground">{row.detectedAt}</span>
    )},
    { key: "rotationStatus", header: "Rotation", render: (row: typeof MOCK_SECRETS[0]) => {
      const cfg = ROTATION_CONFIG[row.rotationStatus];
      const Icon = cfg.icon;
      return (
        <div className="flex items-center gap-1.5">
          <Icon className={`h-3.5 w-3.5 ${row.rotationStatus === "rotated" ? "text-green-400" : row.rotationStatus === "overdue" ? "text-red-400" : row.rotationStatus === "pending" ? "text-yellow-400" : "text-muted-foreground"}`} />
          <Badge variant={cfg.variant}>{cfg.label}</Badge>
        </div>
      );
    }},
    { key: "actions", header: "", render: (row: typeof MOCK_SECRETS[0]) => (
      row.rotationStatus !== "rotated" ? (
        <Button size="sm" variant="outline" onClick={() => toast.success(`Rotation initiated for ${row.id}`)}>
          <RotateCcw className="h-3.5 w-3.5 mr-1" />Rotate
        </Button>
      ) : (
        <Button size="sm" variant="ghost" disabled>
          <CheckCircle2 className="h-3.5 w-3.5 mr-1 text-green-400" />Done
        </Button>
      )
    )},
  ];

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="space-y-6">
      <PageHeader
        title="Secrets Detection"
        description="Monitor and remediate leaked credentials, API keys, tokens, and certificates across all repositories"
        badge="Active"
        actions={
          <>
            <Button variant="outline" size="sm" onClick={() => setShowValues(!showValues)}>
              {showValues ? <EyeOff className="h-4 w-4 mr-1.5" /> : <Eye className="h-4 w-4 mr-1.5" />}
              {showValues ? "Hide" : "Reveal"} Values
            </Button>
            <Button variant="outline" size="sm" onClick={() => toast.success("Report exported")}><Download className="h-4 w-4 mr-1.5" />Export</Button>
            <Button size="sm" onClick={() => toast.success("Secrets scan started")}><RefreshCw className="h-4 w-4 mr-1.5" />Scan Now</Button>
          </>
        }
      />

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <KpiCard title="Secrets Detected" value={secrets.length} change={12} trend="up" icon={Key} />
        <KpiCard title="Critical / Overdue" value={overdueCount} change={3} trend="up" icon={AlertTriangle} />
        <KpiCard title="Pending Rotation" value={pendingCount} trend="flat" icon={Clock} />
        <KpiCard title="Repos Affected" value={uniqueRepos} change={2} trend="up" icon={GitBranch} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Rotation rate card */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base">Rotation Status</CardTitle>
            <CardDescription>Overall secret rotation health</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <div className="flex justify-between text-sm mb-2">
                <span className="text-muted-foreground">Rotated</span>
                <span className="font-semibold text-green-400">{rotationRate}%</span>
              </div>
              <Progress value={rotationRate} className="h-2" />
            </div>
            <div className="grid grid-cols-2 gap-3">
              {[
                { label: "Rotated", count: rotatedCount, color: "text-green-400" },
                { label: "Overdue", count: overdueCount, color: "text-red-400" },
                { label: "Pending", count: pendingCount, color: "text-yellow-400" },
                { label: "Critical", count: criticalCount, color: "text-red-400" },
              ].map(({ label, count, color }) => (
                <div key={label} className="rounded-md bg-muted/30 p-3 text-center">
                  <p className={`text-xl font-bold ${color}`}>{count}</p>
                  <p className="text-xs text-muted-foreground">{label}</p>
                </div>
              ))}
            </div>
            <Button className="w-full" size="sm" variant="outline" onClick={() => toast.success("Bulk rotation initiated for all overdue secrets")}>
              <RotateCcw className="h-4 w-4 mr-1.5" />Rotate All Overdue ({overdueCount})
            </Button>
          </CardContent>
        </Card>

        {/* Type breakdown */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base">Secret Type Breakdown</CardTitle>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={160}>
              <BarChart data={SECRET_TYPE_BREAKDOWN} layout="vertical" margin={{ left: 0, right: 16 }}>
                <XAxis type="number" tick={{ fontSize: 11 }} />
                <YAxis dataKey="type" type="category" tick={{ fontSize: 11 }} width={80} />
                <Tooltip contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 8 }} />
                <Bar dataKey="count" radius={[0, 4, 4, 0]}>
                  {SECRET_TYPE_BREAKDOWN.map((entry, i) => (
                    <Cell key={i} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>

        {/* Rotation timeline */}
        <Card>
          <CardHeader className="pb-3">
            <CardTitle className="text-base">Rotation Timeline</CardTitle>
            <CardDescription>Detected vs rotated over 6 months</CardDescription>
          </CardHeader>
          <CardContent>
            <ResponsiveContainer width="100%" height={160}>
              <BarChart data={ROTATION_TIMELINE} margin={{ top: 4, right: 4, bottom: 0, left: -20 }}>
                <XAxis dataKey="month" tick={{ fontSize: 11 }} />
                <YAxis tick={{ fontSize: 11 }} />
                <Tooltip contentStyle={{ background: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: 8 }} />
                <Bar dataKey="detected" fill="#ef4444" opacity={0.7} radius={[4, 4, 0, 0]} name="Detected" />
                <Bar dataKey="rotated" fill="#10b981" opacity={0.9} radius={[4, 4, 0, 0]} name="Rotated" />
              </BarChart>
            </ResponsiveContainer>
          </CardContent>
        </Card>
      </div>

      {/* Secrets table */}
      <Card>
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-base">Leaked Secrets Inventory</CardTitle>
            <div className="flex items-center gap-2">
              <Badge variant="destructive">{overdueCount} overdue</Badge>
              <Button variant="ghost" size="sm"><Filter className="h-4 w-4" /></Button>
            </div>
          </div>
        </CardHeader>
        <CardContent className="px-0 pb-0">
          <DataTable
            columns={columns}
            data={secrets}
            emptyMessage="No secrets detected"
          />
        </CardContent>
      </Card>
    </motion.div>
  );
}
