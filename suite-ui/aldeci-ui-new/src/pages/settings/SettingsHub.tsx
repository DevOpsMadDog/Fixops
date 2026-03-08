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
  Eye, EyeOff, AlertTriangle, CheckCircle, RotateCcw, Slack
} from "lucide-react";
import { useSystemHealth } from "@/hooks/use-api";
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
  const [keyUsage] = useState({ calls: 12847, limit: 50000, period: "month" });

  // Display
  const [theme, setTheme] = useState("dark");
  const [sidebarCollapsed, setSidebarCollapsed] = useState(false);
  const [homeSpace, setHomeSpace] = useState("mission-control");

  const [isSaving, setIsSaving] = useState(false);

  if (healthQuery.isLoading) return <PageSkeleton />;
  if (healthQuery.isError) return <ErrorState message="Failed to load settings" onRetry={refetch} />;

  const handleSave = async () => {
    setIsSaving(true);
    await new Promise((resolve) => setTimeout(resolve, 800));
    setIsSaving(false);
    toast.success("Settings saved successfully");
  };

  const handleCopyKey = () => {
    navigator.clipboard.writeText(apiKey);
    toast.success("API key copied to clipboard");
  };

  const handleRotateKey = () => {
    toast.success("API key rotation initiated. You will receive a confirmation email.");
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
                <Separator />
                <div>
                  <p className="text-sm font-medium mb-3">Default SLA Deadlines (days)</p>
                  <div className="grid grid-cols-2 gap-3">
                    {[
                      { label: "Critical", value: slaCritical, set: setSlaCritical, color: "text-red-500" },
                      { label: "High", value: slaHigh, set: setSlaHigh, color: "text-orange-500" },
                      { label: "Medium", value: slaMedium, set: setSlaMedium, color: "text-yellow-500" },
                      { label: "Low", value: slaLow, set: setSlaLow, color: "text-blue-400" },
                    ].map(({ label, value, set, color }) => (
                      <div key={label}>
                        <Label className={`text-xs font-semibold mb-1.5 block ${color}`}>{label}</Label>
                        <div className="flex items-center gap-2">
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
    </motion.div>
  );
}
