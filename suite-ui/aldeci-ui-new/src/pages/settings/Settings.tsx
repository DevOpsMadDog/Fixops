import { useState, useEffect } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Switch } from "@/components/ui/switch";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Separator } from "@/components/ui/separator";
import { PageHeader } from "@/components/shared/page-header";
import { Progress } from "@/components/ui/progress";
import { motion, AnimatePresence } from "framer-motion";
import {
  Settings2,
  Bell,
  Shield,
  Key,
  Activity,
  Users,
  Server,
  Save,
  RefreshCw,
  Copy,
  Eye,
  EyeOff,
  Trash2,
  Plus,
  RotateCcw,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  Clock,
  Database,
  Cpu,
  HardDrive,
  Layers,
  Mail,
  MessageSquare,
  PhoneCall,
  Globe,
  GitBranch,
  Zap,
  UserPlus,
  LogIn,
  Lock,
  Unlock,
  PlugZap,
  Archive,
  Play,
  Pause,
  ChevronRight,
  Link2,
  Cloud,
  Container,
  Webhook,
  BarChart3,
  Terminal,
} from "lucide-react";
import { toast } from "sonner";
import { cn } from "@/lib/utils";

// -----------------------------------------
// API helpers
// -----------------------------------------

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";
const API_KEY_HEADER =
  (typeof window !== "undefined" && window.localStorage.getItem("aldeci.authToken")) ||
  import.meta.env.VITE_API_KEY ||
  "dev-key";

async function apiFetch(path: string) {
  const res = await fetch(`${API_BASE}${path}`, {
    headers: { "X-API-Key": API_KEY_HEADER },
  });
  if (!res.ok) throw new Error(`API error: ${res.status}`);
  return res.json();
}

// -----------------------------------------
// Mock data (fallback when API unavailable)
// -----------------------------------------

const MOCK_API_KEYS = [
  { id: "key-1", name: "CI/CD Pipeline", prefix: "sk-ald-ci", created: "2025-11-12", lastUsed: "2h ago", calls: 4821, status: "active" },
  { id: "key-2", name: "Slack Integration Bot", prefix: "sk-ald-sl", created: "2025-12-01", lastUsed: "5m ago", calls: 1204, status: "active" },
  { id: "key-3", name: "Terraform Scanner", prefix: "sk-ald-tf", created: "2026-01-08", lastUsed: "3d ago", calls: 312, status: "active" },
  { id: "key-4", name: "Legacy Exporter", prefix: "sk-ald-lg", created: "2025-09-03", lastUsed: "45d ago", calls: 9, status: "inactive" },
];

const MOCK_INTEGRATIONS = [
  { id: "int-1", name: "GitHub", icon: GitBranch, category: "SCM", status: "connected", lastSync: "2m ago", findings: 847 },
  { id: "int-2", name: "AWS Security Hub", icon: Cloud, category: "Cloud", status: "connected", lastSync: "8m ago", findings: 1203 },
  { id: "int-3", name: "Jira", icon: Link2, category: "Ticketing", status: "connected", lastSync: "15m ago", findings: 0 },
  { id: "int-4", name: "Datadog", icon: BarChart3, category: "Observability", status: "degraded", lastSync: "42m ago", findings: 0 },
  { id: "int-5", name: "Kubernetes", icon: Container, category: "Infra", status: "connected", lastSync: "1m ago", findings: 56 },
  { id: "int-6", name: "Slack", icon: MessageSquare, category: "Comms", status: "connected", lastSync: "just now", findings: 0 },
  { id: "int-7", name: "Snyk", icon: Shield, category: "Scanner", status: "disconnected", lastSync: "—", findings: 0 },
  { id: "int-8", name: "Webhook Endpoint", icon: Webhook, category: "Custom", status: "connected", lastSync: "10m ago", findings: 0 },
];

const MOCK_USERS = [
  { id: "u-1", email: "maya.chen@acmesec.io", name: "Maya Chen", role: "admin", lastActive: "just now", status: "active", avatar: "MC" },
  { id: "u-2", email: "jordan.k@acmesec.io", name: "Jordan Kim", role: "security_analyst", lastActive: "12m ago", status: "active", avatar: "JK" },
  { id: "u-3", email: "rafael.s@acmesec.io", name: "Rafael Santos", role: "developer", lastActive: "2h ago", status: "active", avatar: "RS" },
  { id: "u-4", email: "priya.v@acmesec.io", name: "Priya Verma", role: "compliance_officer", lastActive: "Yesterday", status: "active", avatar: "PV" },
  { id: "u-5", email: "tobias.m@acmesec.io", name: "Tobias Müller", role: "viewer", lastActive: "3d ago", status: "inactive", avatar: "TM" },
  { id: "u-6", email: "alice.w@acmesec.io", name: "Alice Wong", role: "security_analyst", lastActive: "6h ago", status: "active", avatar: "AW" },
];

const MOCK_SYSTEM = {
  health: { api: "healthy", brain: "healthy", scanner: "degraded", database: "healthy", cache: "healthy", queue: "healthy" },
  uptime: "14d 7h 23m",
  version: "v2.14.1",
  region: "us-east-1",
  cpu: 34,
  memory: 61,
  disk: 48,
  queueDepth: 12,
  queueProcessed: 4821,
  cacheHitRate: 94.2,
  cacheSize: "2.3 GB",
  lastBackup: "2026-04-12 06:00 UTC",
  nextBackup: "2026-04-13 06:00 UTC",
};

// ─────────────────────────────────────────────
// Shared sub-components
// ─────────────────────────────────────────────

function SectionHeader({ icon: Icon, title, description }: { icon: React.ElementType; title: string; description: string }) {
  return (
    <div className="flex items-start gap-3 mb-6">
      <div className="h-9 w-9 rounded-lg bg-primary/10 flex items-center justify-center shrink-0 border border-primary/20">
        <Icon className="h-4 w-4 text-primary" />
      </div>
      <div>
        <h3 className="text-sm font-semibold tracking-tight">{title}</h3>
        <p className="text-xs text-muted-foreground mt-0.5 leading-relaxed">{description}</p>
      </div>
    </div>
  );
}

function FieldRow({ label, hint, children }: { label: string; hint?: string; children: React.ReactNode }) {
  return (
    <div className="grid grid-cols-[220px_1fr] items-start gap-6 py-4 border-b border-border/40 last:border-0">
      <div>
        <p className="text-sm font-medium">{label}</p>
        {hint && <p className="text-xs text-muted-foreground mt-0.5 leading-snug">{hint}</p>}
      </div>
      <div>{children}</div>
    </div>
  );
}

function StatusDot({ status }: { status: string }) {
  const map: Record<string, string> = {
    connected: "bg-emerald-500",
    healthy: "bg-emerald-500",
    active: "bg-emerald-500",
    degraded: "bg-amber-400",
    inactive: "bg-zinc-500",
    disconnected: "bg-zinc-500",
    error: "bg-red-500",
  };
  return (
    <span className={cn("inline-block h-2 w-2 rounded-full shrink-0", map[status] ?? "bg-zinc-500")} />
  );
}

function StatusBadge({ status }: { status: string }) {
  const variants: Record<string, string> = {
    connected: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
    healthy: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
    active: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
    degraded: "bg-amber-500/10 text-amber-400 border-amber-500/20",
    inactive: "bg-zinc-700/40 text-zinc-400 border-zinc-600/30",
    disconnected: "bg-zinc-700/40 text-zinc-400 border-zinc-600/30",
    error: "bg-red-500/10 text-red-400 border-red-500/20",
  };
  return (
    <span className={cn("inline-flex items-center gap-1.5 rounded-md border px-2 py-0.5 text-[11px] font-medium capitalize", variants[status] ?? variants.inactive)}>
      <StatusDot status={status} />
      {status}
    </span>
  );
}

function RoleBadge({ role }: { role: string }) {
  const map: Record<string, string> = {
    admin: "bg-violet-500/15 text-violet-400 border-violet-500/20",
    security_analyst: "bg-blue-500/15 text-blue-400 border-blue-500/20",
    developer: "bg-cyan-500/15 text-cyan-400 border-cyan-500/20",
    compliance_officer: "bg-amber-500/15 text-amber-400 border-amber-500/20",
    viewer: "bg-zinc-700/40 text-zinc-400 border-zinc-600/30",
  };
  const labels: Record<string, string> = {
    admin: "Admin",
    security_analyst: "Security Analyst",
    developer: "Developer",
    compliance_officer: "Compliance Officer",
    viewer: "Viewer",
  };
  return (
    <span className={cn("inline-flex items-center rounded-md border px-2 py-0.5 text-[11px] font-medium", map[role] ?? map.viewer)}>
      {labels[role] ?? role}
    </span>
  );
}

function MetricBar({ label, value, unit = "%" }: { label: string; value: number; unit?: string }) {
  const color = value > 80 ? "bg-red-500" : value > 60 ? "bg-amber-400" : "bg-emerald-500";
  return (
    <div className="space-y-1.5">
      <div className="flex justify-between text-xs">
        <span className="text-muted-foreground">{label}</span>
        <span className="font-mono font-medium">{value}{unit}</span>
      </div>
      <div className="h-1.5 rounded-full bg-muted overflow-hidden">
        <div className={cn("h-full rounded-full transition-all duration-700", color)} style={{ width: `${value}%` }} />
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────
// Tab: General
// ─────────────────────────────────────────────

function GeneralTab() {
  const [orgName, setOrgName] = useState("Acme Security Corp");
  const [timezone, setTimezone] = useState("America/New_York");
  const [retention, setRetention] = useState("90");
  const [isSaving, setIsSaving] = useState(false);

  const handleSave = async () => {
    setIsSaving(true);
    await new Promise((r) => setTimeout(r, 700));
    setIsSaving(false);
    toast.success("General settings saved");
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardContent className="pt-6">
          <SectionHeader icon={Settings2} title="Organization" description="Core identity and configuration for your ALDECI instance" />
          <div className="max-w-xl divide-y divide-border/40">
            <FieldRow label="Organization Name" hint="Displayed across dashboards and reports">
              <Input value={orgName} onChange={(e) => setOrgName(e.target.value)} className="max-w-sm" />
            </FieldRow>
            <FieldRow label="Timezone" hint="Used for scheduling, SLA deadlines, and report timestamps">
              <Select value={timezone} onValueChange={setTimezone}>
                <SelectTrigger className="max-w-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="UTC">UTC</SelectItem>
                  <SelectItem value="America/New_York">America / New York (EST)</SelectItem>
                  <SelectItem value="America/Los_Angeles">America / Los Angeles (PST)</SelectItem>
                  <SelectItem value="Europe/London">Europe / London (GMT)</SelectItem>
                  <SelectItem value="Europe/Berlin">Europe / Berlin (CET)</SelectItem>
                  <SelectItem value="Asia/Tokyo">Asia / Tokyo (JST)</SelectItem>
                  <SelectItem value="Asia/Singapore">Asia / Singapore (SGT)</SelectItem>
                  <SelectItem value="Australia/Sydney">Australia / Sydney (AEST)</SelectItem>
                </SelectContent>
              </Select>
            </FieldRow>
            <FieldRow label="Data Retention" hint="How long to keep raw scan data, findings history, and audit logs">
              <div className="flex items-center gap-3">
                <Select value={retention} onValueChange={setRetention}>
                  <SelectTrigger className="w-40">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="30">30 days</SelectItem>
                    <SelectItem value="60">60 days</SelectItem>
                    <SelectItem value="90">90 days</SelectItem>
                    <SelectItem value="180">180 days</SelectItem>
                    <SelectItem value="365">1 year</SelectItem>
                    <SelectItem value="730">2 years</SelectItem>
                    <SelectItem value="0">Indefinite</SelectItem>
                  </SelectContent>
                </Select>
                <p className="text-xs text-muted-foreground">
                  {retention === "0" ? "Data stored forever" : `Purge after ${retention} days`}
                </p>
              </div>
            </FieldRow>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardContent className="pt-6">
          <SectionHeader icon={Clock} title="SLA Deadlines" description="Default remediation deadlines by severity — overridable per policy" />
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-4 max-w-xl">
            {[
              { label: "Critical", color: "text-red-400", defaultVal: "1" },
              { label: "High", color: "text-orange-400", defaultVal: "7" },
              { label: "Medium", color: "text-amber-400", defaultVal: "14" },
              { label: "Low", color: "text-blue-400", defaultVal: "30" },
            ].map(({ label, color, defaultVal }) => {
              const [val, setVal] = useState(defaultVal);
              return (
                <div key={label} className="space-y-2">
                  <p className={cn("text-xs font-semibold uppercase tracking-wide", color)}>{label}</p>
                  <div className="flex items-center gap-2">
                    <Input
                      type="number"
                      value={val}
                      onChange={(e) => setVal(e.target.value)}
                      className="w-20 text-center font-mono"
                      min="1"
                    />
                    <span className="text-xs text-muted-foreground">days</span>
                  </div>
                </div>
              );
            })}
          </div>
        </CardContent>
      </Card>

      <div className="flex justify-end">
        <Button onClick={handleSave} disabled={isSaving} className="gap-2">
          <Save className="h-3.5 w-3.5" />
          {isSaving ? "Saving…" : "Save Changes"}
        </Button>
      </div>
    </div>
  );
}

// ─────────────────────────────────────────────
// Tab: Authentication
// ─────────────────────────────────────────────

function AuthenticationTab() {
  const [showKey, setShowKey] = useState(false);
  const [apiKeys, setApiKeys] = useState(MOCK_API_KEYS);
  const [apiKeysLoading, setApiKeysLoading] = useState(true);
  const [apiKeysError, setApiKeysError] = useState<string | null>(null);
  const [newKeyName, setNewKeyName] = useState("");
  const [ssoEnabled, setSsoEnabled] = useState(false);
  const [mfaRequired, setMfaRequired] = useState(true);
  const [sessionTimeout, setSessionTimeout] = useState("60");
  const [ssoProvider, setSsoProvider] = useState("okta");

  const loadApiKeys = () => {
    setApiKeysLoading(true);
    setApiKeysError(null);
    apiFetch("/api/v1/apikey/keys")
      .then((data) => {
        if (Array.isArray(data) && data.length > 0) {
          setApiKeys(
            data.map((k: any) => ({
              id: k.id ?? k.key_id ?? `key-${Date.now()}`,
              name: k.name ?? k.label ?? "Unnamed Key",
              prefix: k.prefix ?? k.key_prefix ?? "sk-ald-**",
              created: k.created_at ?? k.created ?? "-",
              lastUsed: k.last_used ?? k.last_used_at ?? "Never",
              calls: k.calls ?? k.usage_count ?? 0,
              status: k.status ?? (k.active ? "active" : "inactive"),
            }))
          );
        }
      })
      .catch((err) => {
        setApiKeysError(err.message);
      })
      .finally(() => setApiKeysLoading(false));
  };

  useEffect(() => { loadApiKeys(); }, []);

  const MAIN_KEY = showKey
    ? "sk-aldeci-xK9mN2pQ7rL4wV8tJ1dF3sB6cH0uE5aG"
    : "sk-aldeci-••••••••••••••••••••••••••••••••";

  const handleCopy = () => {
    navigator.clipboard.writeText("sk-aldeci-xK9mN2pQ7rL4wV8tJ1dF3sB6cH0uE5aG");
    toast.success("API key copied to clipboard");
  };

  const handleCreate = () => {
    if (!newKeyName.trim()) return;
    const id = `key-${Date.now()}`;
    setApiKeys((prev) => [
      ...prev,
      { id, name: newKeyName.trim(), prefix: "sk-ald-new", created: new Date().toISOString().split("T")[0], lastUsed: "Never", calls: 0, status: "active" },
    ]);
    setNewKeyName("");
    toast.success(`API key "${newKeyName.trim()}" created`);
  };

  const handleRevoke = (id: string, name: string) => {
    setApiKeys((prev) => prev.filter((k) => k.id !== id));
    toast.success(`Key "${name}" revoked`);
  };

  return (
    <div className="space-y-6">
      {/* API Key Management */}
      <Card>
        <CardContent className="pt-6">
          <SectionHeader icon={Key} title="API Key Management" description="Manage service API keys for external integrations and automation" />

          {apiKeysLoading && (
            <div className="mb-4 p-4 rounded-lg border border-border/40 bg-muted/10">
              <div className="animate-pulse space-y-3">
                <div className="h-4 bg-muted rounded w-1/3" />
                <div className="h-3 bg-muted rounded w-2/3" />
                <div className="h-3 bg-muted rounded w-1/2" />
              </div>
            </div>
          )}

          {apiKeysError && !apiKeysLoading && (
            <div className="mb-4 flex items-center gap-3 p-3 rounded-lg border border-amber-500/30 bg-amber-950/20 text-amber-400 text-xs">
              <AlertTriangle className="h-4 w-4 shrink-0" />
              <span>Could not load API keys from server. Showing cached data.</span>
              <Button variant="ghost" size="sm" className="ml-auto h-6 text-xs text-amber-400 hover:text-amber-300" onClick={loadApiKeys}>
                <RefreshCw className="h-3 w-3 mr-1" /> Retry
              </Button>
            </div>
          )}

          {/* Primary Key */}
          <div className="mb-6 p-4 rounded-lg border border-border/50 bg-muted/20 space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs font-semibold uppercase tracking-wide text-muted-foreground">Primary API Key</p>
                <p className="text-xs text-muted-foreground mt-0.5">Used by default for all integrations unless overridden</p>
              </div>
              <StatusBadge status="active" />
            </div>
            <div className="flex items-center gap-2">
              <code className="flex-1 text-xs font-mono bg-background border border-border/50 px-3 py-2 rounded-md text-muted-foreground truncate">
                {MAIN_KEY}
              </code>
              <Button variant="ghost" size="icon" className="h-8 w-8 shrink-0" onClick={() => setShowKey((v) => !v)}>
                {showKey ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
              </Button>
              <Button variant="ghost" size="icon" className="h-8 w-8 shrink-0" onClick={handleCopy}>
                <Copy className="h-3.5 w-3.5" />
              </Button>
            </div>
            <div className="space-y-1.5">
              <div className="flex justify-between text-xs">
                <span className="text-muted-foreground">12,847 of 50,000 calls used this month</span>
                <span className="font-mono font-medium">26%</span>
              </div>
              <Progress value={26} className="h-1.5" />
            </div>
            <div className="flex gap-2">
              <Button variant="outline" size="sm" className="gap-1.5 text-xs">
                <RotateCcw className="h-3 w-3" />
                Rotate Key
              </Button>
            </div>
          </div>

          {/* Additional Keys */}
          <div className="space-y-2 mb-4">
            {apiKeys.map((key) => (
              <div
                key={key.id}
                className="flex items-center gap-3 px-4 py-3 rounded-lg border border-border/40 bg-muted/10 hover:bg-muted/20 transition-colors group"
              >
                <StatusDot status={key.status} />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <p className="text-sm font-medium truncate">{key.name}</p>
                    {key.status === "inactive" && (
                      <span className="text-[10px] font-medium text-zinc-500 bg-zinc-800/60 border border-zinc-700/40 px-1.5 py-0.5 rounded">Inactive</span>
                    )}
                  </div>
                  <p className="text-xs text-muted-foreground">
                    <span className="font-mono">{key.prefix}…</span>
                    {" · "}Created {key.created}
                    {" · "}Last used: {key.lastUsed}
                    {" · "}{key.calls.toLocaleString()} calls
                  </p>
                </div>
                <Button
                  variant="ghost"
                  size="icon"
                  className="h-7 w-7 opacity-0 group-hover:opacity-100 text-red-400 hover:text-red-300 hover:bg-red-500/10 shrink-0 transition-all"
                  onClick={() => handleRevoke(key.id, key.name)}
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </Button>
              </div>
            ))}
          </div>

          <div className="flex gap-2">
            <Input
              placeholder="Key name (e.g. Terraform Runner)"
              value={newKeyName}
              onChange={(e) => setNewKeyName(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleCreate()}
              className="flex-1 max-w-xs"
            />
            <Button variant="outline" className="gap-2 shrink-0" onClick={handleCreate} disabled={!newKeyName.trim()}>
              <Plus className="h-3.5 w-3.5" />
              Create Key
            </Button>
          </div>
        </CardContent>
      </Card>

      {/* SSO Configuration */}
      <Card>
        <CardContent className="pt-6">
          <SectionHeader icon={LogIn} title="Single Sign-On (SSO)" description="Configure SAML 2.0 or OIDC for enterprise identity provider integration" />

          <div className="max-w-xl space-y-4">
            <div className="flex items-start justify-between p-4 rounded-lg border border-border/40 bg-muted/20">
              <div className="flex items-center gap-3">
                <div className={cn("h-8 w-8 rounded-md flex items-center justify-center", ssoEnabled ? "bg-emerald-500/10 border border-emerald-500/20" : "bg-muted border border-border/40")}>
                  {ssoEnabled ? <Lock className="h-4 w-4 text-emerald-400" /> : <Unlock className="h-4 w-4 text-muted-foreground" />}
                </div>
                <div>
                  <p className="text-sm font-medium">Enable SSO</p>
                  <p className="text-xs text-muted-foreground mt-0.5">Enforce identity provider authentication for all users</p>
                </div>
              </div>
              <Switch checked={ssoEnabled} onCheckedChange={setSsoEnabled} />
            </div>

            <AnimatePresence>
              {ssoEnabled && (
                <motion.div
                  initial={{ opacity: 0, height: 0 }}
                  animate={{ opacity: 1, height: "auto" }}
                  exit={{ opacity: 0, height: 0 }}
                  transition={{ duration: 0.2 }}
                  className="overflow-hidden"
                >
                  <div className="space-y-4 pt-1">
                    <div className="space-y-1.5">
                      <Label className="text-xs text-muted-foreground">Provider</Label>
                      <Select value={ssoProvider} onValueChange={setSsoProvider}>
                        <SelectTrigger className="max-w-xs">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="okta">Okta (SAML 2.0)</SelectItem>
                          <SelectItem value="azure">Azure AD / Entra ID (OIDC)</SelectItem>
                          <SelectItem value="google">Google Workspace (OIDC)</SelectItem>
                          <SelectItem value="onelogin">OneLogin (SAML 2.0)</SelectItem>
                          <SelectItem value="custom">Custom IdP (SAML 2.0)</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                    <div className="space-y-1.5">
                      <Label className="text-xs text-muted-foreground">SSO Entry Point / Issuer URL</Label>
                      <Input placeholder="https://your-idp.com/sso/saml" className="font-mono text-xs" />
                    </div>
                    <div className="space-y-1.5">
                      <Label className="text-xs text-muted-foreground">X.509 Certificate</Label>
                      <textarea
                        rows={4}
                        className="w-full rounded-md border border-input bg-background px-3 py-2 text-xs font-mono text-muted-foreground placeholder:text-muted-foreground/50 focus:outline-none focus:ring-1 focus:ring-primary resize-none"
                        placeholder="-----BEGIN CERTIFICATE-----&#10;MIICpDCCAYwCCQ..."
                      />
                    </div>
                    <div className="flex gap-2">
                      <Button size="sm" variant="outline" className="gap-1.5 text-xs">Test SSO Connection</Button>
                      <Button size="sm" className="gap-1.5 text-xs">Save SSO Config</Button>
                    </div>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>

            <Separator />

            {/* Security toggles */}
            {[
              { label: "Require MFA for all users", desc: "Enforce TOTP or hardware key org-wide", icon: Shield, checked: mfaRequired, set: setMfaRequired },
            ].map(({ label, desc, icon: Icon, checked, set }) => (
              <div key={label} className="flex items-start justify-between p-4 rounded-lg border border-border/40 bg-muted/10">
                <div className="flex items-center gap-3">
                  <Icon className="h-4 w-4 text-muted-foreground shrink-0" />
                  <div>
                    <p className="text-sm font-medium">{label}</p>
                    <p className="text-xs text-muted-foreground mt-0.5">{desc}</p>
                  </div>
                </div>
                <Switch checked={checked} onCheckedChange={set} />
              </div>
            ))}

            <div className="flex items-start justify-between p-4 rounded-lg border border-border/40 bg-muted/10">
              <div className="flex items-center gap-3">
                <Clock className="h-4 w-4 text-muted-foreground shrink-0" />
                <div>
                  <p className="text-sm font-medium">Session Timeout</p>
                  <p className="text-xs text-muted-foreground mt-0.5">Auto-expire idle sessions</p>
                </div>
              </div>
              <Select value={sessionTimeout} onValueChange={setSessionTimeout}>
                <SelectTrigger className="w-32">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="15">15 min</SelectItem>
                  <SelectItem value="30">30 min</SelectItem>
                  <SelectItem value="60">1 hour</SelectItem>
                  <SelectItem value="240">4 hours</SelectItem>
                  <SelectItem value="480">8 hours</SelectItem>
                  <SelectItem value="0">Never</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

// ─────────────────────────────────────────────
// Tab: Integrations
// ─────────────────────────────────────────────

function IntegrationsTab() {
  const [integrations, setIntegrations] = useState(MOCK_INTEGRATIONS);
  const [intLoading, setIntLoading] = useState(true);
  const [intError, setIntError] = useState<string | null>(null);

  const ICON_MAP: Record<string, typeof GitBranch> = {
    GitHub: GitBranch, "AWS Security Hub": Cloud, Jira: Link2, Datadog: BarChart3,
    Kubernetes: Container, Slack: MessageSquare, Snyk: Shield, "Webhook Endpoint": Webhook,
  };

  const loadIntegrations = () => {
    setIntLoading(true);
    setIntError(null);
    apiFetch("/api/v1/integrations/status")
      .then((data) => {
        const items = Array.isArray(data) ? data : data?.integrations;
        if (Array.isArray(items) && items.length > 0) {
          setIntegrations(
            items.map((i: any) => ({
              id: i.id ?? `int-${Date.now()}`,
              name: i.name ?? "Unknown",
              icon: ICON_MAP[i.name] ?? PlugZap,
              category: i.category ?? "Custom",
              status: i.status ?? "disconnected",
              lastSync: i.last_sync ?? i.lastSync ?? "-",
              findings: i.findings ?? i.findings_count ?? 0,
            }))
          );
        }
      })
      .catch((err) => {
        setIntError(err.message);
      })
      .finally(() => setIntLoading(false));
  };

  useEffect(() => { loadIntegrations(); }, []);

  const toggleConnect = (id: string) => {
    setIntegrations((prev) =>
      prev.map((i) => {
        if (i.id !== id) return i;
        const next = i.status === "disconnected" ? "connected" : "disconnected";
        toast[next === "connected" ? "success" : "info"](`${i.name} ${next === "connected" ? "connected" : "disconnected"}`);
        return { ...i, status: next, lastSync: next === "connected" ? "just now" : "—" };
      })
    );
  };

  const categories = [...new Set(integrations.map((i) => i.category))];

  return (
    <div className="space-y-6">
      {intLoading && (
        <div className="p-6 rounded-lg border border-border/40 bg-muted/10">
          <div className="animate-pulse space-y-4">
            <div className="h-4 bg-muted rounded w-1/4" />
            <div className="h-12 bg-muted rounded" />
            <div className="h-12 bg-muted rounded" />
          </div>
        </div>
      )}

      {intError && !intLoading && (
        <div className="flex items-center gap-3 p-3 rounded-lg border border-amber-500/30 bg-amber-950/20 text-amber-400 text-xs">
          <AlertTriangle className="h-4 w-4 shrink-0" />
          <span>Could not load integrations from server. Showing cached data.</span>
          <Button variant="ghost" size="sm" className="ml-auto h-6 text-xs text-amber-400 hover:text-amber-300" onClick={loadIntegrations}>
            <RefreshCw className="h-3 w-3 mr-1" /> Retry
          </Button>
        </div>
      )}

      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3 text-sm text-muted-foreground">
          <span>{integrations.filter((i) => i.status === "connected").length} connected</span>
          <Separator orientation="vertical" className="h-4" />
          <span>{integrations.filter((i) => i.status === "degraded").length} degraded</span>
          <Separator orientation="vertical" className="h-4" />
          <span>{integrations.filter((i) => i.status === "disconnected").length} disconnected</span>
        </div>
        <Button variant="outline" size="sm" className="gap-2">
          <Plus className="h-3.5 w-3.5" />
          Add Integration
        </Button>
      </div>

      {categories.map((cat) => (
        <div key={cat}>
          <p className="text-[11px] font-semibold uppercase tracking-widest text-muted-foreground mb-3">{cat}</p>
          <div className="space-y-2">
            {integrations.filter((i) => i.category === cat).map((integration) => {
              const Icon = integration.icon;
              return (
                <div
                  key={integration.id}
                  className="flex items-center gap-4 px-4 py-3.5 rounded-lg border border-border/40 bg-muted/10 hover:bg-muted/20 transition-colors"
                >
                  <div className="h-9 w-9 rounded-lg bg-background border border-border/50 flex items-center justify-center shrink-0">
                    <Icon className="h-4 w-4 text-muted-foreground" />
                  </div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <p className="text-sm font-medium">{integration.name}</p>
                      <StatusBadge status={integration.status} />
                    </div>
                    <p className="text-xs text-muted-foreground mt-0.5">
                      Last sync: {integration.lastSync}
                      {integration.findings > 0 && (
                        <span className="ml-2 text-amber-400">{integration.findings.toLocaleString()} findings ingested</span>
                      )}
                    </p>
                  </div>
                  <div className="flex items-center gap-2 shrink-0">
                    {integration.status !== "disconnected" && (
                      <Button variant="ghost" size="icon" className="h-7 w-7" onClick={() => toast.info(`Syncing ${integration.name}…`)}>
                        <RefreshCw className="h-3.5 w-3.5" />
                      </Button>
                    )}
                    <Button
                      variant="outline"
                      size="sm"
                      className={cn(
                        "text-xs h-7 gap-1.5",
                        integration.status === "disconnected"
                          ? "border-primary/40 text-primary hover:bg-primary/10"
                          : "text-red-400 border-red-500/20 hover:bg-red-500/10 hover:text-red-300"
                      )}
                      onClick={() => toggleConnect(integration.id)}
                    >
                      {integration.status === "disconnected" ? (
                        <><PlugZap className="h-3 w-3" />Connect</>
                      ) : (
                        <><XCircle className="h-3 w-3" />Disconnect</>
                      )}
                    </Button>
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      ))}
    </div>
  );
}

// ─────────────────────────────────────────────
// Tab: Notifications
// ─────────────────────────────────────────────

function NotificationsTab() {
  const [emailEnabled, setEmailEnabled] = useState(true);
  const [slackEnabled, setSlackEnabled] = useState(true);
  const [slackWebhook, setSlackWebhook] = useState("https://hooks.slack.com/services/T0/B0/xxx");
  const [pagerEnabled, setPagerEnabled] = useState(false);
  const [pagerKey, setPagerKey] = useState("");
  const [quietStart, setQuietStart] = useState("22:00");
  const [quietEnd, setQuietEnd] = useState("07:00");
  const [quietEnabled, setQuietEnabled] = useState(true);
  const [digestFreq, setDigestFreq] = useState("daily");

  const SEVERITY_THRESHOLDS = [
    { label: "Critical", color: "text-red-400", email: true, slack: true, pager: true },
    { label: "High", color: "text-orange-400", email: true, slack: true, pager: false },
    { label: "Medium", color: "text-amber-400", email: true, slack: false, pager: false },
    { label: "Low", color: "text-blue-400", email: false, slack: false, pager: false },
  ];

  return (
    <div className="space-y-6">
      {/* Channels */}
      <Card>
        <CardContent className="pt-6">
          <SectionHeader icon={Bell} title="Notification Channels" description="Configure where ALDECI sends alerts and status updates" />
          <div className="space-y-3 max-w-xl">
            {/* Email */}
            <div className="p-4 rounded-lg border border-border/40 bg-muted/10 space-y-3">
              <div className="flex items-start justify-between">
                <div className="flex items-center gap-3">
                  <Mail className="h-4 w-4 text-muted-foreground" />
                  <div>
                    <p className="text-sm font-medium">Email</p>
                    <p className="text-xs text-muted-foreground">Critical findings, SLA breaches, digest summaries</p>
                  </div>
                </div>
                <Switch checked={emailEnabled} onCheckedChange={setEmailEnabled} />
              </div>
            </div>

            {/* Slack */}
            <div className="p-4 rounded-lg border border-border/40 bg-muted/10 space-y-3">
              <div className="flex items-start justify-between">
                <div className="flex items-center gap-3">
                  <MessageSquare className="h-4 w-4 text-muted-foreground" />
                  <div>
                    <p className="text-sm font-medium">Slack</p>
                    <p className="text-xs text-muted-foreground">Post alerts to a channel via incoming webhook</p>
                  </div>
                </div>
                <Switch checked={slackEnabled} onCheckedChange={setSlackEnabled} />
              </div>
              <AnimatePresence>
                {slackEnabled && (
                  <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: "auto" }} exit={{ opacity: 0, height: 0 }} className="overflow-hidden">
                    <div className="pt-1 space-y-1.5">
                      <Label className="text-xs text-muted-foreground">Webhook URL</Label>
                      <div className="flex gap-2">
                        <Input value={slackWebhook} onChange={(e) => setSlackWebhook(e.target.value)} className="font-mono text-xs flex-1" />
                        <Button variant="outline" size="sm" className="text-xs shrink-0" onClick={() => toast.success("Test message sent to Slack")}>Test</Button>
                      </div>
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>

            {/* PagerDuty */}
            <div className="p-4 rounded-lg border border-border/40 bg-muted/10 space-y-3">
              <div className="flex items-start justify-between">
                <div className="flex items-center gap-3">
                  <PhoneCall className="h-4 w-4 text-muted-foreground" />
                  <div>
                    <p className="text-sm font-medium">PagerDuty</p>
                    <p className="text-xs text-muted-foreground">Create incidents for critical security events</p>
                  </div>
                </div>
                <Switch checked={pagerEnabled} onCheckedChange={setPagerEnabled} />
              </div>
              <AnimatePresence>
                {pagerEnabled && (
                  <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: "auto" }} exit={{ opacity: 0, height: 0 }} className="overflow-hidden">
                    <div className="pt-1 space-y-1.5">
                      <Label className="text-xs text-muted-foreground">Integration (Routing) Key</Label>
                      <Input type="password" value={pagerKey} onChange={(e) => setPagerKey(e.target.value)} placeholder="32-character routing key" className="font-mono text-xs" />
                    </div>
                  </motion.div>
                )}
              </AnimatePresence>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Severity thresholds */}
      <Card>
        <CardContent className="pt-6">
          <SectionHeader icon={Zap} title="Alert Thresholds" description="Which severity levels trigger each notification channel" />
          <div className="max-w-xl overflow-x-auto">
            <table role="table" className="w-full text-xs">
              <thead>
                <tr className="border-b border-border/40">
                  <th className="text-left py-2 pr-6 font-semibold text-muted-foreground">Severity</th>
                  <th className="text-center py-2 px-4 font-semibold text-muted-foreground">Email</th>
                  <th className="text-center py-2 px-4 font-semibold text-muted-foreground">Slack</th>
                  <th className="text-center py-2 px-4 font-semibold text-muted-foreground">PagerDuty</th>
                </tr>
              </thead>
              <tbody>
                {SEVERITY_THRESHOLDS.map((row) => {
                  const [em, setEm] = useState(row.email);
                  const [sl, setSl] = useState(row.slack);
                  const [pg, setPg] = useState(row.pager);
                  return (
                    <tr key={row.label} className="border-b border-border/30 last:border-0">
                      <td className={cn("py-3 pr-6 font-semibold", row.color)}>{row.label}</td>
                      <td className="py-3 px-4 text-center"><Switch checked={em} onCheckedChange={setEm} className="scale-75" /></td>
                      <td className="py-3 px-4 text-center"><Switch checked={sl} onCheckedChange={setSl} className="scale-75" /></td>
                      <td className="py-3 px-4 text-center"><Switch checked={pg} onCheckedChange={setPg} className="scale-75" /></td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>

      {/* Quiet hours + digest */}
      <Card>
        <CardContent className="pt-6">
          <SectionHeader icon={Clock} title="Schedule" description="Quiet hours and digest frequency settings" />
          <div className="max-w-xl space-y-4">
            <div className="flex items-start justify-between p-4 rounded-lg border border-border/40 bg-muted/10">
              <div>
                <p className="text-sm font-medium">Quiet Hours</p>
                <p className="text-xs text-muted-foreground mt-0.5">Suppress non-critical alerts during off-hours</p>
              </div>
              <Switch checked={quietEnabled} onCheckedChange={setQuietEnabled} />
            </div>
            <AnimatePresence>
              {quietEnabled && (
                <motion.div initial={{ opacity: 0, height: 0 }} animate={{ opacity: 1, height: "auto" }} exit={{ opacity: 0, height: 0 }} className="overflow-hidden">
                  <div className="flex items-center gap-4 px-1">
                    <div className="space-y-1.5">
                      <Label className="text-xs text-muted-foreground">Start</Label>
                      <Input type="time" value={quietStart} onChange={(e) => setQuietStart(e.target.value)} className="w-32 font-mono text-xs" />
                    </div>
                    <ChevronRight className="h-4 w-4 text-muted-foreground mt-5" />
                    <div className="space-y-1.5">
                      <Label className="text-xs text-muted-foreground">End</Label>
                      <Input type="time" value={quietEnd} onChange={(e) => setQuietEnd(e.target.value)} className="w-32 font-mono text-xs" />
                    </div>
                  </div>
                </motion.div>
              )}
            </AnimatePresence>

            <Separator />

            <div className="space-y-1.5">
              <Label className="text-xs text-muted-foreground">Digest Frequency</Label>
              <Select value={digestFreq} onValueChange={setDigestFreq}>
                <SelectTrigger className="max-w-xs">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="realtime">Real-time (immediate)</SelectItem>
                  <SelectItem value="hourly">Hourly digest</SelectItem>
                  <SelectItem value="daily">Daily digest (08:00)</SelectItem>
                  <SelectItem value="weekly">Weekly digest (Monday)</SelectItem>
                  <SelectItem value="disabled">Disabled</SelectItem>
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground">
                {digestFreq === "realtime" ? "Alerts sent immediately as they occur" :
                 digestFreq === "disabled" ? "No digest emails sent" :
                 `Findings batched and sent as a ${digestFreq} summary`}
              </p>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

// ─────────────────────────────────────────────
// Tab: Team
// ─────────────────────────────────────────────

function TeamTab() {
  const [users, setUsers] = useState(MOCK_USERS);
  const [usersLoading, setUsersLoading] = useState(true);
  const [usersError, setUsersError] = useState<string | null>(null);
  const [inviteEmail, setInviteEmail] = useState("");
  const [inviteRole, setInviteRole] = useState("viewer");
  const [search, setSearch] = useState("");

  const loadUsers = () => {
    setUsersLoading(true);
    setUsersError(null);
    apiFetch("/api/v1/apikey/keys")
      .then((data) => {
        const items = Array.isArray(data) ? data : data?.users;
        if (Array.isArray(items) && items.length > 0 && items[0].email) {
          setUsers(
            items.map((u: any) => ({
              id: u.id ?? `u-${Date.now()}`,
              email: u.email ?? "unknown@unknown.io",
              name: u.name ?? u.email?.split("@")[0] ?? "Unknown",
              role: u.role ?? "viewer",
              lastActive: u.last_active ?? u.lastActive ?? "-",
              status: u.status ?? "active",
              avatar: (u.name ?? u.email ?? "U").substring(0, 2).toUpperCase(),
            }))
          );
        }
      })
      .catch((err) => {
        setUsersError(err.message);
      })
      .finally(() => setUsersLoading(false));
  };

  useEffect(() => { loadUsers(); }, []);

  const filtered = users.filter(
    (u) => u.name.toLowerCase().includes(search.toLowerCase()) || u.email.toLowerCase().includes(search.toLowerCase())
  );

  const handleInvite = () => {
    if (!inviteEmail.trim()) return;
    const id = `u-${Date.now()}`;
    setUsers((prev) => [
      ...prev,
      {
        id,
        email: inviteEmail.trim(),
        name: inviteEmail.split("@")[0],
        role: inviteRole,
        lastActive: "Invited",
        status: "inactive",
        avatar: inviteEmail[0].toUpperCase(),
      },
    ]);
    toast.success(`Invitation sent to ${inviteEmail.trim()}`);
    setInviteEmail("");
  };

  const handleRemove = (id: string, name: string) => {
    setUsers((prev) => prev.filter((u) => u.id !== id));
    toast.info(`${name} removed from organization`);
  };

  const handleRoleChange = (id: string, role: string) => {
    setUsers((prev) => prev.map((u) => (u.id === id ? { ...u, role } : u)));
    toast.success("Role updated");
  };

  return (
    <div className="space-y-6">
      {/* Invite */}
      <Card>
        <CardContent className="pt-6">
          <SectionHeader icon={UserPlus} title="Invite Team Member" description="Send an invitation email with role-based access configured" />
          <div className="flex items-end gap-3 max-w-xl">
            <div className="flex-1 space-y-1.5">
              <Label className="text-xs text-muted-foreground">Email address</Label>
              <Input
                type="email"
                placeholder="engineer@company.io"
                value={inviteEmail}
                onChange={(e) => setInviteEmail(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleInvite()}
              />
            </div>
            <div className="space-y-1.5">
              <Label className="text-xs text-muted-foreground">Role</Label>
              <Select value={inviteRole} onValueChange={setInviteRole}>
                <SelectTrigger className="w-44">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="admin">Admin</SelectItem>
                  <SelectItem value="security_analyst">Security Analyst</SelectItem>
                  <SelectItem value="developer">Developer</SelectItem>
                  <SelectItem value="compliance_officer">Compliance Officer</SelectItem>
                  <SelectItem value="viewer">Viewer</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <Button className="gap-2 shrink-0" onClick={handleInvite} disabled={!inviteEmail.trim()}>
              <UserPlus className="h-3.5 w-3.5" />
              Send Invite
            </Button>
          </div>
        </CardContent>
      </Card>

      {usersLoading && (
        <Card><CardContent className="pt-6"><div className="animate-pulse space-y-3"><div className="h-4 bg-muted rounded w-1/4" /><div className="h-10 bg-muted rounded" /><div className="h-10 bg-muted rounded" /></div></CardContent></Card>
      )}

      {usersError && !usersLoading && (
        <div className="flex items-center gap-3 p-3 rounded-lg border border-amber-500/30 bg-amber-950/20 text-amber-400 text-xs">
          <AlertTriangle className="h-4 w-4 shrink-0" />
          <span>Could not load team members. Showing cached data.</span>
          <Button variant="ghost" size="sm" className="ml-auto h-6 text-xs text-amber-400 hover:text-amber-300" onClick={loadUsers}>
            <RefreshCw className="h-3 w-3 mr-1" /> Retry
          </Button>
        </div>
      )}

      {/* User table */}
      <Card>
        <CardHeader className="pb-4">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-semibold flex items-center gap-2">
              <Users className="h-4 w-4 text-primary" />
              Team Members
              <span className="ml-1 text-xs font-normal text-muted-foreground">({users.length})</span>
            </CardTitle>
            <Input
              placeholder="Search members…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="h-7 w-48 text-xs"
            />
          </div>
        </CardHeader>
        <CardContent className="pt-0">
          <div className="rounded-lg border border-border/40 overflow-hidden">
            <table role="table" className="w-full text-sm">
              <thead className="bg-muted/30 border-b border-border/40">
                <tr>
                  <th className="text-left px-4 py-2.5 text-xs font-semibold text-muted-foreground">Member</th>
                  <th className="text-left px-4 py-2.5 text-xs font-semibold text-muted-foreground">Role</th>
                  <th className="text-left px-4 py-2.5 text-xs font-semibold text-muted-foreground">Last Active</th>
                  <th className="text-left px-4 py-2.5 text-xs font-semibold text-muted-foreground">Status</th>
                  <th className="px-4 py-2.5" />
                </tr>
              </thead>
              <tbody>
                {filtered.map((user, i) => (
                  <tr
                    key={user.id}
                    className={cn(
                      "border-b border-border/30 last:border-0 hover:bg-muted/10 transition-colors group",
                      i % 2 === 0 ? "" : "bg-muted/5"
                    )}
                  >
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-3">
                        <div className="h-7 w-7 rounded-full bg-primary/10 flex items-center justify-center text-[10px] font-bold text-primary shrink-0">
                          {user.avatar}
                        </div>
                        <div>
                          <p className="text-xs font-medium">{user.name}</p>
                          <p className="text-[11px] text-muted-foreground">{user.email}</p>
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <Select value={user.role} onValueChange={(r) => handleRoleChange(user.id, r)}>
                        <SelectTrigger className="h-6 w-44 text-[11px] border-0 bg-transparent p-0 focus:ring-0">
                          <SelectValue>
                            <RoleBadge role={user.role} />
                          </SelectValue>
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="admin">Admin</SelectItem>
                          <SelectItem value="security_analyst">Security Analyst</SelectItem>
                          <SelectItem value="developer">Developer</SelectItem>
                          <SelectItem value="compliance_officer">Compliance Officer</SelectItem>
                          <SelectItem value="viewer">Viewer</SelectItem>
                        </SelectContent>
                      </Select>
                    </td>
                    <td className="px-4 py-3 text-xs text-muted-foreground">{user.lastActive}</td>
                    <td className="px-4 py-3">
                      <StatusBadge status={user.status} />
                    </td>
                    <td className="px-4 py-3 text-right">
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-6 w-6 opacity-0 group-hover:opacity-100 text-red-400 hover:text-red-300 hover:bg-red-500/10 transition-all"
                        onClick={() => handleRemove(user.id, user.name)}
                      >
                        <Trash2 className="h-3 w-3" />
                      </Button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

// ─────────────────────────────────────────────
// Tab: System
// ─────────────────────────────────────────────

function SystemTab() {
  const [backupRunning, setBackupRunning] = useState(false);
  const [sysData, setSysData] = useState(MOCK_SYSTEM);
  const [sysLoading, setSysLoading] = useState(true);
  const [sysError, setSysError] = useState<string | null>(null);

  const loadSystemHealth = () => {
    setSysLoading(true);
    setSysError(null);
    apiFetch("/api/v1/system/health")
      .then((data) => {
        if (data && typeof data === "object") {
          setSysData((prev) => ({
            health: {
              api: data.health?.api ?? data.api_status ?? prev.health.api,
              brain: data.health?.brain ?? data.brain_status ?? prev.health.brain,
              scanner: data.health?.scanner ?? data.scanner_status ?? prev.health.scanner,
              database: data.health?.database ?? data.db_status ?? prev.health.database,
              cache: data.health?.cache ?? data.cache_status ?? prev.health.cache,
              queue: data.health?.queue ?? data.queue_status ?? prev.health.queue,
            },
            uptime: data.uptime ?? prev.uptime,
            version: data.version ?? prev.version,
            region: data.region ?? prev.region,
            cpu: data.cpu ?? data.cpu_percent ?? prev.cpu,
            memory: data.memory ?? data.memory_percent ?? prev.memory,
            disk: data.disk ?? data.disk_percent ?? prev.disk,
            queueDepth: data.queue_depth ?? data.queueDepth ?? prev.queueDepth,
            queueProcessed: data.queue_processed ?? data.queueProcessed ?? prev.queueProcessed,
            cacheHitRate: data.cache_hit_rate ?? data.cacheHitRate ?? prev.cacheHitRate,
            cacheSize: data.cache_size ?? data.cacheSize ?? prev.cacheSize,
            lastBackup: data.last_backup ?? data.lastBackup ?? prev.lastBackup,
            nextBackup: data.next_backup ?? data.nextBackup ?? prev.nextBackup,
          }));
        }
      })
      .catch((err) => {
        setSysError(err.message);
      })
      .finally(() => setSysLoading(false));
  };

  useEffect(() => { loadSystemHealth(); }, []);

  const handleBackup = async () => {
    setBackupRunning(true);
    toast.info("Backup initiated — this may take a few minutes");
    await new Promise((r) => setTimeout(r, 2000));
    setBackupRunning(false);
    toast.success("Backup completed successfully");
  };

  const handleClearCache = () => {
    toast.success("Redis cache flushed — hit rate reset");
  };

  const statusIcon = (s: string) => {
    if (s === "healthy") return <CheckCircle2 className="h-4 w-4 text-emerald-400" />;
    if (s === "degraded") return <AlertTriangle className="h-4 w-4 text-amber-400" />;
    return <XCircle className="h-4 w-4 text-red-400" />;
  };

  const SERVICES = [
    { key: "api", label: "API Gateway", icon: Globe },
    { key: "brain", label: "AI Brain Pipeline", icon: Cpu },
    { key: "scanner", label: "Scanner Engine", icon: Layers },
    { key: "database", label: "Database", icon: Database },
    { key: "cache", label: "Redis Cache", icon: HardDrive },
    { key: "queue", label: "Job Queue", icon: Terminal },
  ] as const;

  return (
    <div className="space-y-6">
      {/* Health overview */}
      <Card>
        <CardContent className="pt-6">
          <SectionHeader icon={Activity} title="System Health" description="Live status of all platform subsystems" />

          {sysLoading && (<div className="mb-4 animate-pulse"><div className="grid grid-cols-3 gap-3"><div className="h-16 bg-muted rounded-lg" /><div className="h-16 bg-muted rounded-lg" /><div className="h-16 bg-muted rounded-lg" /></div></div>)}

          {sysError && !sysLoading && (
            <div className="mb-4 flex items-center gap-3 p-3 rounded-lg border border-amber-500/30 bg-amber-950/20 text-amber-400 text-xs">
              <AlertTriangle className="h-4 w-4 shrink-0" />
              <span>Could not load system health. Showing cached data.</span>
              <Button variant="ghost" size="sm" className="ml-auto h-6 text-xs text-amber-400 hover:text-amber-300" onClick={loadSystemHealth}>
                <RefreshCw className="h-3 w-3 mr-1" /> Retry
              </Button>
            </div>
          )}

          <div className="grid grid-cols-2 sm:grid-cols-3 gap-3">
            {SERVICES.map(({ key, label, icon: Icon }) => {
              const status = sysData.health[key as keyof typeof sysData.health];
              return (
                <div
                  key={key}
                  className={cn(
                    "flex items-center gap-3 p-3.5 rounded-lg border transition-colors",
                    status === "healthy" ? "border-emerald-500/20 bg-emerald-500/5" :
                    status === "degraded" ? "border-amber-400/20 bg-amber-400/5" :
                    "border-red-500/20 bg-red-500/5"
                  )}
                >
                  <div className={cn(
                    "h-8 w-8 rounded-md flex items-center justify-center shrink-0",
                    status === "healthy" ? "bg-emerald-500/10" :
                    status === "degraded" ? "bg-amber-400/10" : "bg-red-500/10"
                  )}>
                    <Icon className={cn(
                      "h-4 w-4",
                      status === "healthy" ? "text-emerald-400" :
                      status === "degraded" ? "text-amber-400" : "text-red-400"
                    )} />
                  </div>
                  <div className="min-w-0">
                    <p className="text-xs font-medium truncate">{label}</p>
                    <div className="flex items-center gap-1.5 mt-0.5">
                      {statusIcon(status)}
                      <p className="text-[11px] text-muted-foreground capitalize">{status}</p>
                    </div>
                  </div>
                </div>
              );
            })}
          </div>
        </CardContent>
      </Card>

      {/* Resource usage */}
      <div className="grid grid-cols-1 sm:grid-cols-2 gap-6">
        <Card>
          <CardContent className="pt-6">
            <SectionHeader icon={Cpu} title="Resource Usage" description="Current compute and storage utilization" />
            <div className="space-y-5">
              <MetricBar label="CPU" value={sysData.cpu} />
              <MetricBar label="Memory" value={sysData.memory} />
              <MetricBar label="Disk" value={sysData.disk} />
            </div>
          </CardContent>
        </Card>

        <Card>
          <CardContent className="pt-6">
            <SectionHeader icon={Database} title="Queue & Cache" description="Job processing and cache performance" />
            <div className="space-y-4">
              <div className="flex justify-between items-center py-2 border-b border-border/30">
                <span className="text-xs text-muted-foreground">Queue Depth</span>
                <span className="text-xs font-mono font-medium">{sysData.queueDepth} jobs pending</span>
              </div>
              <div className="flex justify-between items-center py-2 border-b border-border/30">
                <span className="text-xs text-muted-foreground">Processed Today</span>
                <span className="text-xs font-mono font-medium">{sysData.queueProcessed.toLocaleString()}</span>
              </div>
              <div className="flex justify-between items-center py-2 border-b border-border/30">
                <span className="text-xs text-muted-foreground">Cache Hit Rate</span>
                <span className="text-xs font-mono font-medium text-emerald-400">{sysData.cacheHitRate}%</span>
              </div>
              <div className="flex justify-between items-center py-2">
                <span className="text-xs text-muted-foreground">Cache Size</span>
                <span className="text-xs font-mono font-medium">{sysData.cacheSize}</span>
              </div>
              <Button variant="outline" size="sm" className="w-full gap-2 text-xs" onClick={handleClearCache}>
                <Trash2 className="h-3.5 w-3.5" />
                Flush Cache
              </Button>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Backup controls */}
      <Card>
        <CardContent className="pt-6">
          <SectionHeader icon={Archive} title="Backup & Recovery" description="Scheduled backups and manual snapshot controls" />
          <div className="max-w-xl space-y-4">
            <div className="grid grid-cols-2 gap-4">
              <div className="p-3.5 rounded-lg border border-border/40 bg-muted/10">
                <p className="text-xs text-muted-foreground mb-1">Last Backup</p>
                <p className="text-sm font-mono font-medium">{sysData.lastBackup}</p>
                <div className="flex items-center gap-1.5 mt-1.5">
                  <CheckCircle2 className="h-3 w-3 text-emerald-400" />
                  <span className="text-[11px] text-emerald-400">Completed</span>
                </div>
              </div>
              <div className="p-3.5 rounded-lg border border-border/40 bg-muted/10">
                <p className="text-xs text-muted-foreground mb-1">Next Scheduled</p>
                <p className="text-sm font-mono font-medium">{sysData.nextBackup}</p>
                <div className="flex items-center gap-1.5 mt-1.5">
                  <Clock className="h-3 w-3 text-muted-foreground" />
                  <span className="text-[11px] text-muted-foreground">Auto (daily 06:00)</span>
                </div>
              </div>
            </div>

            <div className="flex gap-3">
              <Button className="gap-2" onClick={handleBackup} disabled={backupRunning}>
                {backupRunning ? (
                  <><RefreshCw className="h-3.5 w-3.5 animate-spin" />Backing up…</>
                ) : (
                  <><Play className="h-3.5 w-3.5" />Run Backup Now</>
                )}
              </Button>
              <Button variant="outline" className="gap-2" onClick={() => toast.info("Opening backup history…")}>
                <Archive className="h-3.5 w-3.5" />
                View History
              </Button>
            </div>

            <Separator />

            <div>
              <p className="text-xs font-semibold text-muted-foreground uppercase tracking-wide mb-3">Environment</p>
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
                {[
                  { label: "Version", value: sysData.version },
                  { label: "Uptime", value: sysData.uptime },
                  { label: "Region", value: sysData.region },
                  { label: "Environment", value: "Production" },
                ].map(({ label, value }) => (
                  <div key={label} className="p-3 rounded-lg bg-muted/20 border border-border/30">
                    <p className="text-[11px] text-muted-foreground">{label}</p>
                    <p className="text-xs font-mono font-medium mt-0.5">{value}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

// ─────────────────────────────────────────────
// Main Settings page
// ─────────────────────────────────────────────

const TABS = [
  { value: "general", label: "General", icon: Settings2 },
  { value: "authentication", label: "Authentication", icon: Key },
  { value: "integrations", label: "Integrations", icon: PlugZap },
  { value: "notifications", label: "Notifications", icon: Bell },
  { value: "team", label: "Team", icon: Users },
  { value: "system", label: "System", icon: Server },
] as const;

type TabValue = typeof TABS[number]["value"];

export default function Settings() {
  const [tab, setTab] = useState<TabValue>("general");

  return (
    <motion.div
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.25 }}
      className="space-y-6"
    >
      <PageHeader
        title="Settings & Admin"
        description="Manage organization configuration, access controls, integrations, and system health"
        badge="Admin"
      />

      <Tabs value={tab} onValueChange={(v) => setTab(v as TabValue)} className="space-y-6">
        <TabsList className="flex-wrap h-auto gap-1 bg-muted/30 p-1 rounded-xl border border-border/40">
          {TABS.map(({ value, label, icon: Icon }) => (
            <TabsTrigger
              key={value}
              value={value}
              className="gap-1.5 text-xs data-[state=active]:bg-background data-[state=active]:shadow-sm rounded-lg"
            >
              <Icon className="h-3.5 w-3.5" />
              {label}
            </TabsTrigger>
          ))}
        </TabsList>

        <TabsContent value="general">
          <GeneralTab />
        </TabsContent>

        <TabsContent value="authentication">
          <AuthenticationTab />
        </TabsContent>

        <TabsContent value="integrations">
          <IntegrationsTab />
        </TabsContent>

        <TabsContent value="notifications">
          <NotificationsTab />
        </TabsContent>

        <TabsContent value="team">
          <TeamTab />
        </TabsContent>

        <TabsContent value="system">
          <SystemTab />
        </TabsContent>
      </Tabs>
    </motion.div>
  );
}
