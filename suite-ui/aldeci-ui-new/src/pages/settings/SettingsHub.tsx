import { useState } from "react";
import { useQuery, useMutation } from "@tanstack/react-query";
import { motion } from "framer-motion";
import {
  Key,
  Bell,
  Database,
  Shield,
  Users,
  Link2,
  Activity,
  FileText,
  Store,
  Copy,
  RefreshCw,
  CheckCircle,
  AlertCircle,
  Info,
  ChevronRight,
  Settings,
  Lock,
} from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { PageHeader } from "@/components/shared/page-header";
import { KpiCard } from "@/components/shared/kpi-card";
import { systemApi } from "@/lib/api";
import { toast } from "sonner";

// ─── Mock data ───────────────────────────────────────────────────────────────
const MOCK_CONFIG = {
  version: "3.14.2",
  build: "20260301-a4f9b",
  mode: "Enterprise",
  license: "ALdeci Enterprise Unlimited",
  license_expiry: "2027-01-31",
  org: "Acme Corp Security",
  api_keys: [
    { id: "ak_prod_8f3k2j", name: "Production Integration", created: "2025-11-01", last_used: "2026-03-08", status: "active" },
    { id: "ak_ci_7d2p1m", name: "CI/CD Pipeline", created: "2025-12-15", last_used: "2026-03-07", status: "active" },
    { id: "ak_staging_9b1x", name: "Staging Environment", created: "2026-01-20", last_used: "2026-02-28", status: "active" },
    { id: "ak_dev_3c8n2", name: "Dev Workspace", created: "2026-02-01", last_used: "2026-03-01", status: "revoked" },
  ],
  notifications: {
    critical_alerts: true,
    weekly_digest: true,
    slack_webhook: "https://hooks.slack.com/services/T04XX/B07YY/xxxx",
    email_recipients: ["security-team@acme.com", "ciso@acme.com"],
    pagerduty_key: "pd_key_prod_**************",
  },
  data_retention: {
    findings: 365,
    audit_logs: 730,
    scan_results: 180,
    evidence: 2190,
  },
};

const QUICK_LINKS = [
  { label: "Integrations", path: "/settings/integrations", icon: Link2, description: "Manage scanner & tool connections", badge: "19 connected" },
  { label: "Users & Roles", path: "/settings/users", icon: Users, description: "User management & RBAC", badge: "42 users" },
  { label: "Teams", path: "/settings/teams", icon: Shield, description: "Team ownership mapping", badge: "8 teams" },
  { label: "Marketplace", path: "/settings/marketplace", icon: Store, description: "Browse & install connectors", badge: "New" },
  { label: "Policies", path: "/settings/policies", icon: Lock, description: "Security policies & SLA rules", badge: "12 active" },
  { label: "System Health", path: "/settings/health", icon: Activity, description: "Service status & metrics" },
  { label: "Log Viewer", path: "/settings/logs", icon: FileText, description: "Application & audit logs" },
];

// ─── Component ────────────────────────────────────────────────────────────────
export default function SettingsHub() {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [newKeyName, setNewKeyName] = useState("");

  const { data: configData } = useQuery({
    queryKey: ["system-config"],
    queryFn: () => systemApi.config(),
  });

  const { data: healthData } = useQuery({
    queryKey: ["system-health"],
    queryFn: () => systemApi.health(),
  });

  const config = configData?.data ?? MOCK_CONFIG;
  const health = healthData?.data ?? { status: "healthy", uptime_pct: 99.97 };

  const rotateMutation = useMutation({
    mutationFn: async () => {
      await new Promise((r) => setTimeout(r, 800));
    },
    onSuccess: () => toast.success("API key rotated successfully"),
  });

  const copyKey = (key: string) => {
    navigator.clipboard.writeText(key);
    setCopiedKey(key);
    setTimeout(() => setCopiedKey(null), 2000);
    toast.success("API key copied to clipboard");
  };

  const createKey = () => {
    if (!newKeyName.trim()) return toast.error("Key name is required");
    toast.success(`API key "${newKeyName}" created`);
    setNewKeyName("");
  };

  return (
    <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="space-y-6">
      <PageHeader
        title="Settings"
        description="Platform configuration, integrations, and system management"
        badge="v3.14.2"
        actions={
          <Button variant="outline" size="sm" onClick={() => toast.info("Checking for updates…")}>
            <RefreshCw className="h-3.5 w-3.5 mr-1.5" />
            Check Updates
          </Button>
        }
      />

      {/* KPI Row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <KpiCard title="API Keys Active" value={config.api_keys.filter((k: any) => k.status === "active").length} icon={Key} trend="flat" />
        <KpiCard title="Uptime" value={`${health.uptime_pct ?? 99.97}%`} icon={Activity} trend="up" />
        <KpiCard title="Connected Tools" value={19} icon={Link2} change={2} trend="up" changeLabel="this month" />
        <KpiCard title="Active Users" value={42} icon={Users} trend="flat" />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* API Key Management */}
        <div className="lg:col-span-2 space-y-4">
          <Card>
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <Key className="h-4 w-4 text-primary" />
                  <CardTitle className="text-base">API Key Management</CardTitle>
                </div>
                <Badge variant="info">{config.api_keys.filter((k: any) => k.status === "active").length} active</Badge>
              </div>
              <CardDescription>Rotate or revoke keys at any time. Keys are shown once at creation.</CardDescription>
            </CardHeader>
            <CardContent className="space-y-3">
              {(config.api_keys as any[]).map((key) => (
                <div key={key.id} className="flex items-center justify-between rounded-lg border border-border/50 bg-muted/20 px-3 py-2.5">
                  <div className="min-w-0">
                    <p className="text-sm font-medium truncate">{key.name}</p>
                    <p className="text-xs text-muted-foreground font-mono">{key.id} · Last used {key.last_used}</p>
                  </div>
                  <div className="flex items-center gap-2 ml-3 shrink-0">
                    <Badge variant={key.status === "active" ? "success" : "destructive"}>{key.status}</Badge>
                    {key.status === "active" && (
                      <>
                        <Button variant="ghost" size="sm" className="h-7 w-7 p-0" onClick={() => copyKey(key.id)}>
                          {copiedKey === key.id ? <CheckCircle className="h-3.5 w-3.5 text-green-400" /> : <Copy className="h-3.5 w-3.5" />}
                        </Button>
                        <Button variant="ghost" size="sm" className="h-7 px-2 text-xs" onClick={() => rotateMutation.mutate()}>
                          Rotate
                        </Button>
                      </>
                    )}
                  </div>
                </div>
              ))}

              <div className="flex gap-2 pt-1">
                <Input
                  placeholder="New key name (e.g., Staging Pipeline)"
                  value={newKeyName}
                  onChange={(e) => setNewKeyName(e.target.value)}
                  className="h-8 text-sm"
                />
                <Button size="sm" className="h-8 shrink-0" onClick={createKey}>
                  Create Key
                </Button>
              </div>
            </CardContent>
          </Card>

          {/* Notification Preferences */}
          <Card>
            <CardHeader className="pb-3">
              <div className="flex items-center gap-2">
                <Bell className="h-4 w-4 text-primary" />
                <CardTitle className="text-base">Notification Preferences</CardTitle>
              </div>
            </CardHeader>
            <CardContent className="space-y-3">
              {[
                { label: "Critical Alerts", value: config.notifications.critical_alerts, sub: "Immediate Slack + email for CRITICAL findings" },
                { label: "Weekly Digest", value: config.notifications.weekly_digest, sub: "Sunday 08:00 UTC summary to security-team@acme.com" },
              ].map((item) => (
                <div key={item.label} className="flex items-center justify-between rounded-lg border border-border/50 bg-muted/20 px-3 py-2">
                  <div>
                    <p className="text-sm font-medium">{item.label}</p>
                    <p className="text-xs text-muted-foreground">{item.sub}</p>
                  </div>
                  <Badge variant={item.value ? "success" : "secondary"}>{item.value ? "Enabled" : "Disabled"}</Badge>
                </div>
              ))}
              <div className="rounded-lg border border-border/50 bg-muted/20 px-3 py-2 space-y-1">
                <p className="text-xs text-muted-foreground">Slack Webhook</p>
                <p className="text-xs font-mono text-muted-foreground truncate">{config.notifications.slack_webhook}</p>
              </div>
            </CardContent>
          </Card>

          {/* Data Retention */}
          <Card>
            <CardHeader className="pb-3">
              <div className="flex items-center gap-2">
                <Database className="h-4 w-4 text-primary" />
                <CardTitle className="text-base">Data Retention Policy</CardTitle>
              </div>
              <CardDescription>Configure how long each data type is retained before automatic purge.</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 gap-3">
                {Object.entries(config.data_retention).map(([key, days]) => (
                  <div key={key} className="rounded-lg border border-border/50 bg-muted/20 px-3 py-2">
                    <p className="text-xs text-muted-foreground capitalize">{key.replace(/_/g, " ")}</p>
                    <p className="text-sm font-semibold tabular-nums">{days as number} days</p>
                    <p className="text-xs text-muted-foreground">{Math.round((days as number) / 365 * 10) / 10} yr{(days as number) >= 730 ? "s" : ""}</p>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Right Column: System Info + Quick Links */}
        <div className="space-y-4">
          {/* System Info */}
          <Card>
            <CardHeader className="pb-3">
              <div className="flex items-center gap-2">
                <Info className="h-4 w-4 text-primary" />
                <CardTitle className="text-base">System Information</CardTitle>
              </div>
            </CardHeader>
            <CardContent className="space-y-2.5">
              {[
                { label: "Version", value: config.version },
                { label: "Build", value: config.build },
                { label: "Mode", value: config.mode },
                { label: "Organization", value: config.org },
                { label: "License", value: config.license },
                { label: "License Expiry", value: config.license_expiry },
              ].map((row) => (
                <div key={row.label} className="flex justify-between text-sm">
                  <span className="text-muted-foreground">{row.label}</span>
                  <span className="font-medium text-right max-w-[180px] truncate">{row.value}</span>
                </div>
              ))}
              <div className="flex items-center gap-1.5 pt-1">
                <CheckCircle className="h-3.5 w-3.5 text-green-400" />
                <span className="text-xs text-green-400 font-medium">License valid</span>
              </div>
            </CardContent>
          </Card>

          {/* Quick Links */}
          <Card>
            <CardHeader className="pb-3">
              <div className="flex items-center gap-2">
                <Settings className="h-4 w-4 text-primary" />
                <CardTitle className="text-base">Settings Sections</CardTitle>
              </div>
            </CardHeader>
            <CardContent className="space-y-1">
              {QUICK_LINKS.map((link) => {
                const Icon = link.icon;
                return (
                  <a
                    key={link.path}
                    href={link.path}
                    className="flex items-center justify-between rounded-lg px-2.5 py-2 hover:bg-muted/40 transition-colors group"
                  >
                    <div className="flex items-center gap-2.5 min-w-0">
                      <Icon className="h-4 w-4 text-muted-foreground shrink-0" />
                      <div className="min-w-0">
                        <p className="text-sm font-medium">{link.label}</p>
                        <p className="text-xs text-muted-foreground truncate">{link.description}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-1.5 shrink-0 ml-2">
                      {link.badge && <Badge variant={link.badge === "New" ? "new" : "secondary"} className="text-xs">{link.badge}</Badge>}
                      <ChevronRight className="h-3.5 w-3.5 text-muted-foreground group-hover:text-foreground transition-colors" />
                    </div>
                  </a>
                );
              })}
            </CardContent>
          </Card>

          {/* Security Notice */}
          <Card className="border-yellow-500/30 bg-yellow-500/5">
            <CardContent className="p-4 flex gap-3">
              <AlertCircle className="h-4 w-4 text-yellow-400 shrink-0 mt-0.5" />
              <div>
                <p className="text-sm font-medium text-yellow-300">MFA Enforcement</p>
                <p className="text-xs text-muted-foreground mt-0.5">3 users have not enabled MFA. Enable enforced MFA in Users settings.</p>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </motion.div>
  );
}
