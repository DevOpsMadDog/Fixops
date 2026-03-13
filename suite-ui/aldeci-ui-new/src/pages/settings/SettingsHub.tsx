import { useState, useCallback } from "react";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Separator } from "@/components/ui/separator";
import { PageHeader } from "@/components/shared/page-header";
import { PageSkeleton } from "@/components/shared/PageSkeleton";
import { ErrorState } from "@/components/shared/ErrorState";
import { motion } from "framer-motion";
import {
  Settings, Bell, Shield, Key, Monitor, Save, RefreshCw, Copy,
  Eye, EyeOff, AlertTriangle, CheckCircle, RotateCcw, Slack,
  Plus, Trash2, Server, Clock, GitCommit, Zap, Users, Activity
} from "lucide-react";
import { useSystemHealth } from "@/hooks/use-api";
import {
  systemApi,
  auditApi,
  getStoredAuthStrategy,
  getStoredAuthToken,
  getStoredOrgId,
  setStoredAuthStrategy,
  setStoredAuthToken,
  setStoredOrgId,
} from "@/lib/api";
import { toast } from "sonner";

function SectionHeader({ icon: Icon, title, description }: { icon: React.ElementType; title: string; description: string }) {
  return (
    <div className="flex items-start gap-3 mb-5">
      <div className="h-8 w-8 rounded-lg bg-primary/10 flex items-center justify-center shrink-0">
        <Icon className="h-4 w-4 text-primary" />
      </div>
      <div>
        <h3 className="text-sm font-semibold">{title}</h3>
        <p className="text-xs text-muted-foreground mt-0.5">{description}</p>
      </div>
    </div>
  );
}

export default function SettingsHub() {
  const healthQuery = useSystemHealth();
  const refetch = useCallback(() => healthQuery.refetch(), [healthQuery]);

  const [tab, setTab] = useState("general");
  const [orgName, setOrgName] = useState("Acme Security Corp");
  const [orgId, setOrgId] = useState(getStoredOrgId());
  const [slaLow, setSlaLow] = useState("30");
  const [slaMedium, setSlaMedium] = useState("14");
  const [slaHigh, setSlaHigh] = useState("7");
  const [slaCritical, setSlaCritical] = useState("1");

  // Notifications
  const [emailEnabled, setEmailEnabled] = useState(true);
  const [slackEnabled, setSlackEnabled] = useState(false);
  const [pagerDutyEnabled, setPagerDutyEnabled] = useState(false);
  const [slackWebhook, setSlackWebhook] = useState("");
  const [pdKey, setPdKey] = useState("");

  // API Keys
  const [showKey, setShowKey] = useState(false);
  const [apiKey] = useState("sk-aldeci-••••••••••••••••••••••••••••••••");
  const [authStrategy, setAuthStrategy] = useState<"token" | "jwt">(getStoredAuthStrategy());
  const [authToken, setAuthToken] = useState(getStoredAuthToken());
  const [keyUsage] = useState({ calls: 12847, limit: 50000, period: "month" });
  const [additionalKeys, setAdditionalKeys] = useState([
    { id: "key-1", name: "CI/CD Pipeline", created: "2025-11-12", lastUsed: "2h ago", calls: 4821 },
    { id: "key-2", name: "Slack Bot", created: "2025-12-01", lastUsed: "5m ago", calls: 1204 },
  ]);
  const [newKeyName, setNewKeyName] = useState("");

  // Display
  const [theme, setTheme] = useState("dark");
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [homeSpace, setHomeSpace] = useState("mission-control");

  const [isSaving, setIsSaving] = useState(false);

  if (healthQuery.isLoading) return <PageSkeleton />;
  if (healthQuery.isError) return <ErrorState message="Failed to load settings" onRetry={refetch} />;

  const handleSave = async () => {
    setIsSaving(true);
    setStoredOrgId(orgId);
    setStoredAuthStrategy(authStrategy);
    setStoredAuthToken(authToken);
    await new Promise((resolve) => setTimeout(resolve, 800));
    setIsSaving(false);
    toast.success("Settings saved successfully. New auth and org scope will be used on the next request.");
  };

  const handleCopyKey = () => {
    navigator.clipboard.writeText(apiKey);
    toast.success("API key copied to clipboard");
  };

  const handleRotateKey = () => {
    toast.info("API key rotation not yet wired — rotation API pending");
  };

  const handleGenerateKey = () => {
    if (!newKeyName) return;
    const id = `key-${Date.now()}`;
    setAdditionalKeys((prev) => [...prev, {
      id,
      name: newKeyName,
      created: new Date().toISOString().split("T")[0],
      lastUsed: "Never",
      calls: 0,
    }]);
    setNewKeyName("");
    toast.info(`API key "${newKeyName}" created locally — persist API pending`);
  };

  const handleRevokeKey = (id: string, name: string) => {
    setAdditionalKeys((prev) => prev.filter((k) => k.id !== id));
    toast.info(`API key "${name}" revoked locally — persist API pending`);
  };

  return (
    <motion.div
      initial={{ opacity: 0, y: 8 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.3 }}
      className="space-y-6"
    >
      <PageHeader
        title="Settings"
        description="Configure organization preferences, notifications, API keys, and display"
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={refetch} className="gap-2">
          <RefreshCw className="h-4 w-4" />
          Refresh
        </Button>
        <Button size="sm" onClick={handleSave} disabled={isSaving} className="gap-2">
          <Save className="h-4 w-4" />
          {isSaving ? "Saving…" : "Save Changes"}
        </Button>
          </div>
        }
      />

      <Tabs value={tab} onValueChange={setTab} className="space-y-6">
        <TabsList className="flex-wrap h-auto gap-1">
          <TabsTrigger value="general" className="gap-1.5"><Settings className="h-3.5 w-3.5" />General</TabsTrigger>
          <TabsTrigger value="notifications" className="gap-1.5"><Bell className="h-3.5 w-3.5" />Notifications</TabsTrigger>
          <TabsTrigger value="security" className="gap-1.5"><Shield className="h-3.5 w-3.5" />Security</TabsTrigger>
          <TabsTrigger value="apikeys" className="gap-1.5"><Key className="h-3.5 w-3.5" />API Keys</TabsTrigger>
          <TabsTrigger value="display" className="gap-1.5"><Monitor className="h-3.5 w-3.5" />Display</TabsTrigger>
        </TabsList>

        {/* General Tab */}
        <TabsContent value="general">
          <Card>
            <CardContent className="pt-6">
              <SectionHeader icon={Settings} title="Organization Settings" description="Configure your organization's name and global defaults" />
              <div className="space-y-5 max-w-md">
                <div>
                  <Label htmlFor="org-name" className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">
                    Organization Name
                  </Label>
                  <Input
                    id="org-name"
                    value={orgName}
                    onChange={(e) => setOrgName(e.target.value)}
                    className="mt-2"
                  />
                </div>
                <div>
                  <Label htmlFor="org-id" className="text-xs font-semibold text-muted-foreground uppercase tracking-wide">
                    Organization ID
                  </Label>
                  <Input
                    id="org-id"
                    value={orgId}
                    onChange={(e) => setOrgId(e.target.value)}
                    className="mt-2"
                    placeholder="default"
                  />
                  <p className="mt-2 text-xs text-muted-foreground">
                    Sent on every request via <span className="font-mono">X-Org-ID</span> for multi-tenant isolation.
                  </p>
                </div>
                <Separator />
                <div>
                  <p className="text-sm font-medium mb-3">Default SLA Deadlines (days)</p>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '1rem' }}>
                    {[
                      { label: "Critical", value: slaCritical, set: setSlaCritical, color: "#ef4444" },
                      { label: "High", value: slaHigh, set: setSlaHigh, color: "#f97316" },
                      { label: "Medium", value: slaMedium, set: setSlaMedium, color: "#eab308" },
                      { label: "Low", value: slaLow, set: setSlaLow, color: "#60a5fa" },
                    ].map(({ label, value, set, color }) => (
                      <div key={label} style={{ display: 'flex', flexDirection: 'column', gap: '0.5rem' }}>
                        <span style={{ fontSize: '0.75rem', fontWeight: 600, color }}>{label}</span>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '0.5rem' }}>
                          <Input type="number" value={value} onChange={(e) => set(e.target.value)} className="w-20 text-center" min="1" />
                          <span className="text-xs text-muted-foreground">days</span>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Notifications Tab */}
        <TabsContent value="notifications">
          <Card>
            <CardContent className="pt-6">
              <SectionHeader icon={Bell} title="Notification Channels" description="Choose where to receive security alerts and status updates" />
              <div className="space-y-6 max-w-lg">
                {/* Email */}
                <div className="flex items-start justify-between p-4 rounded-lg bg-muted/30 border border-border/40">
                  <div>
                    <p className="text-sm font-medium">Email Notifications</p>
                    <p className="text-xs text-muted-foreground mt-0.5">Receive alerts via email for critical findings and SLA breaches</p>
                  </div>
                  <Switch checked={emailEnabled} onCheckedChange={setEmailEnabled} />
                </div>

                {/* Slack */}
                <div className="p-4 rounded-lg bg-muted/30 border border-border/40 space-y-3">
                  <div className="flex items-start justify-between">
                    <div className="flex items-center gap-2">
                      <Slack className="h-4 w-4 text-[#4A154B]" />
                      <div>
                        <p className="text-sm font-medium">Slack</p>
                        <p className="text-xs text-muted-foreground mt-0.5">Post alerts to a Slack channel via webhook</p>
                      </div>
                    </div>
                    <Switch checked={slackEnabled} onCheckedChange={setSlackEnabled} />
                  </div>
                  {slackEnabled && (
                    <div>
                      <Label className="text-xs text-muted-foreground mb-1.5 block">Webhook URL</Label>
                      <Input
                        placeholder="https://hooks.slack.com/services/…"
                        value={slackWebhook}
                        onChange={(e) => setSlackWebhook(e.target.value)}
                      />
                    </div>
                  )}
                </div>

                {/* PagerDuty */}
                <div className="p-4 rounded-lg bg-muted/30 border border-border/40 space-y-3">
                  <div className="flex items-start justify-between">
                    <div>
                      <p className="text-sm font-medium">PagerDuty</p>
                      <p className="text-xs text-muted-foreground mt-0.5">Create incidents for critical security events</p>
                    </div>
                    <Switch checked={pagerDutyEnabled} onCheckedChange={setPagerDutyEnabled} />
                  </div>
                  {pagerDutyEnabled && (
                    <div>
                      <Label className="text-xs text-muted-foreground mb-1.5 block">Integration Key</Label>
                      <Input
                        type="password"
                        placeholder="PagerDuty routing key…"
                        value={pdKey}
                        onChange={(e) => setPdKey(e.target.value)}
                      />
                    </div>
                  )}
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Security Tab */}
        <TabsContent value="security">
          <Card>
            <CardContent className="pt-6">
              <SectionHeader icon={Shield} title="Security Configuration" description="Session management, MFA, and access control settings" />
              <div className="space-y-4 max-w-lg">
                <div className="p-4 rounded-lg bg-muted/30 border border-border/40 space-y-3">
                  <div>
                    <p className="text-sm font-medium">Authentication Strategy</p>
                    <p className="text-xs text-muted-foreground mt-0.5">Choose whether the UI authenticates with a service token or a JWT bearer token.</p>
                  </div>
                  <Select value={authStrategy} onValueChange={(value: "token" | "jwt") => setAuthStrategy(value)}>
                    <SelectTrigger>
                      <SelectValue placeholder="Select auth strategy" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="token">API Token</SelectItem>
                      <SelectItem value="jwt">JWT Bearer</SelectItem>
                    </SelectContent>
                  </Select>
                  <div>
                    <Label className="text-xs text-muted-foreground mb-1.5 block">
                      {authStrategy === "jwt" ? "JWT Access Token" : "API Token"}
                    </Label>
                    <Input
                      type={showKey ? "text" : "password"}
                      value={authToken}
                      onChange={(e) => setAuthToken(e.target.value)}
                      placeholder={authStrategy === "jwt" ? "Paste bearer token" : "Paste API token"}
                    />
                    <p className="mt-2 text-xs text-muted-foreground">
                      Stored locally in this browser only. SSE live feeds will automatically reuse this credential.
                    </p>
                  </div>
                </div>
                {[
                  { label: "Require MFA for all users", desc: "Enforce multi-factor authentication organization-wide" },
                  { label: "Session timeout (1 hour)", desc: "Automatically log out inactive sessions" },
                  { label: "IP allowlist enforcement", desc: "Restrict access to approved IP ranges only" },
                  { label: "Audit all API calls", desc: "Log every API request for compliance purposes" },
                  { label: "SSO enforcement", desc: "Require SAML/OIDC single sign-on for all users" },
                ].map(({ label, desc }) => (
                  <div key={label} className="flex items-start justify-between p-4 rounded-lg bg-muted/30 border border-border/40">
                    <div>
                      <p className="text-sm font-medium">{label}</p>
                      <p className="text-xs text-muted-foreground mt-0.5">{desc}</p>
                    </div>
                    <Switch defaultChecked={label.includes("MFA") || label.includes("Audit")} />
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* API Keys Tab */}
        <TabsContent value="apikeys">
          <Card>
            <CardContent className="pt-6">
              <SectionHeader icon={Key} title="API Key Management" description="Manage API keys for external integrations" />
              <div className="space-y-5 max-w-lg">
                <div className="p-4 rounded-lg bg-muted/30 border border-border/40">
                  <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-3 block">
                    Current API Key
                  </Label>
                  <div className="flex items-center gap-2">
                    <code className="flex-1 text-xs font-mono bg-muted p-2 rounded">
                      {showKey ? "sk-aldeci-xK9mN2pQ7rL4wV8tJ1dF3sB6cH0uE5aG" : apiKey}
                    </code>
                    <Button variant="ghost" size="icon" className="h-8 w-8 shrink-0" onClick={() => setShowKey(!showKey)}>
                      {showKey ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                    </Button>
                    <Button variant="ghost" size="icon" className="h-8 w-8 shrink-0" onClick={handleCopyKey}>
                      <Copy className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                </div>
                <div className="p-4 rounded-lg bg-muted/30 border border-border/40">
                  <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-3">Usage This Month</p>
                  <div className="space-y-2">
                    <div className="flex justify-between text-sm">
                      <span>{keyUsage.calls.toLocaleString()} calls</span>
                      <span className="text-muted-foreground">of {keyUsage.limit.toLocaleString()}</span>
                    </div>
                    <div className="h-2 rounded-full bg-muted overflow-hidden">
                      <div
                        className="h-full bg-primary rounded-full transition-all"
                        style={{ width: `${(keyUsage.calls / keyUsage.limit) * 100}%` }}
                      />
                    </div>
                    <p className="text-xs text-muted-foreground">{Math.round((keyUsage.calls / keyUsage.limit) * 100)}% of monthly limit used</p>
                  </div>
                </div>
                <Button variant="destructive" className="gap-2" onClick={handleRotateKey}>
                  <RotateCcw className="h-3.5 w-3.5" />
                  Rotate API Key
                </Button>

                {/* Additional API Keys */}
                <Separator />
                <div>
                  <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-3">Additional API Keys</p>
                  <div className="space-y-2 mb-3">
                    {additionalKeys.map((key) => (
                      <div key={key.id} className="flex items-center gap-3 p-3 rounded-lg bg-muted/30 border border-border/40">
                        <div className="flex-1 min-w-0">
                          <p className="text-sm font-medium">{key.name}</p>
                          <p className="text-xs text-muted-foreground">Created {key.created} · Last used: {key.lastUsed} · {key.calls.toLocaleString()} calls</p>
                        </div>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7 text-red-400 hover:text-red-300 shrink-0"
                          onClick={() => handleRevokeKey(key.id, key.name)}
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </Button>
                      </div>
                    ))}
                  </div>
                  <div className="flex gap-2">
                    <Input
                      placeholder="Key name (e.g. Terraform runner)"
                      value={newKeyName}
                      onChange={(e) => setNewKeyName(e.target.value)}
                      className="flex-1"
                    />
                    <Button variant="outline" className="gap-2 shrink-0" onClick={handleGenerateKey} disabled={!newKeyName}>
                      <Plus className="h-3.5 w-3.5" />
                      Generate
                    </Button>
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Display Tab */}
        <TabsContent value="display">
          <Card>
            <CardContent className="pt-6">
              <SectionHeader icon={Monitor} title="Display Preferences" description="Customize your interface appearance and defaults" />
              <div className="space-y-5 max-w-md">
                <div>
                  <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-2 block">Theme</Label>
                  <Select value={theme} onValueChange={setTheme}>
                    <SelectTrigger className="w-48">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="dark">Dark (default)</SelectItem>
                      <SelectItem value="light">Light</SelectItem>
                      <SelectItem value="system">System preference</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="flex items-center justify-between p-4 rounded-lg bg-muted/30 border border-border/40">
                  <div>
                    <p className="text-sm font-medium">Sidebar collapsed by default</p>
                    <p className="text-xs text-muted-foreground mt-0.5">Start with a minimized sidebar for more screen space</p>
                  </div>
                  <Switch checked={sidebarCollapsed} onCheckedChange={setSidebarCollapsed} />
                </div>
                <div>
                  <Label className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-2 block">Home Space</Label>
                  <Select value={homeSpace} onValueChange={setHomeSpace}>
                    <SelectTrigger className="w-56">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="mission-control">Mission Control</SelectItem>
                      <SelectItem value="nerve-center">Nerve Center</SelectItem>
                      <SelectItem value="comply">Compliance Dashboard</SelectItem>
                      <SelectItem value="discover">Discover</SelectItem>
                      <SelectItem value="ai">AI Copilot</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Environment Info Card */}
      <Card className="bg-muted/20 border-border/40">
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Server className="h-4 w-4 text-primary" />
            Environment Information
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
            {[
              { label: "Version", value: "v2.14.1", icon: GitCommit },
              { label: "Environment", value: "Production", icon: Server },
              { label: "Uptime", value: "14d 7h 23m", icon: Clock },
              { label: "Region", value: "us-east-1", icon: Activity },
            ].map(({ label, value, icon: Icon }) => (
              <div key={label} className="flex items-center gap-3 p-3 rounded-lg bg-background/50 border border-border/30">
                <Icon className="h-4 w-4 text-muted-foreground shrink-0" />
                <div>
                  <p className="text-xs text-muted-foreground">{label}</p>
                  <p className="text-sm font-medium font-mono">{value}</p>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {/* Quick Actions Grid */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2">
            <Zap className="h-4 w-4 text-primary" />
            Quick Actions
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            {[
              { label: "Force Re-sync", desc: "Sync all integrations", icon: RefreshCw, action: () => toast.info("Re-sync not yet wired") },
              { label: "Export Config", desc: "Download org config", icon: Key, action: async () => {
                try {
                  const res = await systemApi.config();
                  const content = JSON.stringify(res.data?.data ?? res.data, null, 2);
                  const blob = new Blob([content], { type: "application/json" });
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement("a");
                  a.href = url;
                  a.download = `aldeci-config-${new Date().toISOString().split("T")[0]}.json`;
                  document.body.appendChild(a);
                  a.click();
                  document.body.removeChild(a);
                  URL.revokeObjectURL(url);
                  toast.success("Config exported successfully");
                } catch (err: any) {
                  toast.error(`Config export failed: ${err?.response?.data?.detail ?? err.message}`);
                }
              } },
              { label: "Clear Cache", desc: "Flush Redis cache", icon: Trash2, action: () => toast.info("Cache clear not yet wired") },
              { label: "Audit Export", desc: "Export audit log CSV", icon: Activity, action: async () => {
                try {
                  const res = await auditApi.list({ limit: 1000 });
                  const entries: any[] = Array.isArray(res.data) ? res.data : (res.data?.data ?? res.data?.entries ?? []);
                  const headers = ["id", "action", "user", "resource", "timestamp", "details"];
                  const rows = entries.map((e: any) =>
                    headers.map((h) => String((e as any)[h] ?? "").replace(/,/g, ";")).join(",")
                  );
                  const csv = [headers.join(","), ...rows].join("\n");
                  const blob = new Blob([csv], { type: "text/csv" });
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement("a");
                  a.href = url;
                  a.download = `audit-log-${new Date().toISOString().split("T")[0]}.csv`;
                  document.body.appendChild(a);
                  a.click();
                  document.body.removeChild(a);
                  URL.revokeObjectURL(url);
                  toast.success(`Exported ${entries.length} audit entries`);
                } catch (err: any) {
                  toast.error(`Audit export failed: ${err?.response?.data?.detail ?? err.message}`);
                }
              } },
              { label: "Rotate All Keys", desc: "Rotate all API keys", icon: RotateCcw, action: () => toast.info("Key rotation not yet wired") },
              { label: "User Sync", desc: "Sync SSO users", icon: Users, action: () => toast.info("SSO sync not yet wired") },
              { label: "Health Check", desc: "Run system diagnostics", icon: CheckCircle, action: () => toast.info("Health check not yet wired") },
              { label: "Send Test Alert", desc: "Test notification config", icon: Bell, action: () => toast.info("Test alert not yet wired") },
            ].map(({ label, desc, icon: Icon, action }) => (
              <button
                key={label}
                onClick={action}
                className="flex items-start gap-3 p-3 rounded-lg bg-muted/30 border border-border/40 hover:bg-muted/50 hover:border-primary/30 transition-all text-left group"
              >
                <div className="h-7 w-7 rounded-md bg-primary/10 flex items-center justify-center shrink-0 group-hover:bg-primary/20 transition-colors">
                  <Icon className="h-3.5 w-3.5 text-primary" />
                </div>
                <div>
                  <p className="text-xs font-medium">{label}</p>
                  <p className="text-xs text-muted-foreground mt-0.5">{desc}</p>
                </div>
              </button>
            ))}
          </div>
        </CardContent>
      </Card>
    </motion.div>
  );
}
